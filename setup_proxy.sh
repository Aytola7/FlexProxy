#!/bin/bash

# بررسی دسترسی root
if [ "$EUID" -ne 0 ]; then
    echo "[-] خطا: این اسکریپت باید با دسترسی root (sudo) اجرا شود."
    exit 1
fi

# تابع برای اجرای امن دستورات apt
safe_apt() {
    local cmd="$1"
    local timeout=300
    echo "[*] اجرای $cmd..."
    if ! timeout "$timeout" bash -c "$cmd"; then
        echo "[-] خطا: اجرای $cmd شکست خورد یا تایم‌آوت شد."
        exit 1
    fi
    return 0
}

# تابع برای اعتبارسنجی IP
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for i in {1..4}; do
            if [ "${BASH_REMATCH[$i]}" -gt 255 ]; then
                echo "[-] خطا: IP نامعتبر است: $ip (هر بخش باید بین 0 تا 255 باشد)"
                return 1
            fi
        done
        return 0
    else
        echo "[-] خطا: فرمت IP نامعتبر است: $ip"
        return 1
    fi
}

# تابع برای اعتبارسنجی پورت
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        echo "[-] خطا: پورت نامعتبر است: $port"
        return 1
    fi
}

# تابع برای نمایش لاگ‌ها
show_logs() {
    echo "[*] نمایش لاگ‌های Nginx..."
    journalctl -u nginx --no-pager -n 50
    echo -e "\n[*] نمایش لاگ‌های سرویس‌های GOST..."
    journalctl -u gost_*.service --no-pager -n 50
    echo "[*] برای نمایش لاگ‌های زنده، از دستور زیر استفاده کنید:"
    echo "  journalctl -u nginx -f"
    echo "  journalctl -u gost_*.service -f"
}

# بررسی ماژول stream در Nginx
check_stream_module() {
    if ! nginx -V 2>&1 | grep -q "stream"; then
        echo "[-] خطا: ماژول stream در Nginx فعال نیست. لطفاً Nginx را با پشتیبانی از stream نصب کنید."
        exit 1
    fi
}

# بررسی نصب پکیج
check_package() {
    local package=$1
    if dpkg -l | grep -q "$package"; then
        echo "[*] $package از قبل نصب شده است."
        return 0
    else
        echo "[+] نصب $package..."
        safe_apt "apt update && apt install -y $package"
        return $?
    fi
}

# بررسی نصب certbot
check_certbot() {
    if command -v certbot >/dev/null 2>&1; then
        echo "[*] certbot از قبل نصب شده است."
        return 0
    else
        echo "[+] نصب certbot..."
        if check_package python3-certbot-nginx; then
            return 0
        elif snap install --classic certbot; then
            ln -sf /snap/bin/certbot /usr/bin/certbot
            echo "[✓] certbot از طریق Snap نصب شد."
            return 0
        else
            echo "[-] خطا: نصب certbot شکست خورد."
            return 1
        fi
    fi
}

# بررسی وجود گواهی SSL برای دامین
check_ssl_cert() {
    local domain=$1
    if [ -d "/etc/letsencrypt/live/$domain" ]; then
        echo "[*] گواهی SSL برای $domain از قبل وجود دارد."
        return 0
    else
        return 1
    fi
}

# بررسی نصب wget
check_wget() {
    if command -v wget >/dev/null 2>&1; then
        echo "[*] wget از قبل نصب شده است."
        return 0
    else
        echo "[+] نصب wget..."
        safe_apt "apt update && apt install -y wget"
        return $?
    fi
}

# بررسی عملیات فایل‌سیستمی
check_file_op() {
    local cmd="$1"
    local desc="$2"
    if ! eval "$cmd"; then
        echo "[-] خطا: $desc شکست خورد."
        exit 1
    fi
}

# پرسیدن برای پاک‌سازی فایل‌های قبلی
read -p "[?] می‌خوای اسکریپت قبلی رو پاکسازی کنم؟ (y/N): " cleanup
if [[ "$cleanup" =~ ^[yY]$ ]]; then
    echo "[*] پاک‌سازی فایل‌های تنظیمات قبلی..."
    check_file_op "rm -f /etc/nginx/stream.d/proxy_tcp_*" "حذف فایل‌های تنظیمات TCP"
    check_file_op "rm -f /etc/nginx/sites-available/ws_proxy_*" "حذف فایل‌های تنظیمات WebSocket (sites-available)"
    check_file_op "rm -f /etc/nginx/sites-enabled/ws_proxy_*" "حذف فایل‌های تنظیمات WebSocket (sites-enabled)"
    check_file_op "rm -f /etc/gost/gost_*.json" "حذف فایل‌های تنظیمات GOST"
    for service in /etc/systemd/system/gost_*.service; do
        if [ -f "$service" ]; then
            service_name=$(basename "$service")
            systemctl stop "$service_name" 2>/dev/null
            systemctl disable "$service_name" 2>/dev/null
            check_file_op "rm -f $service" "حذف سرویس $service_name"
        fi
    done
    systemctl daemon-reload
    echo "[✓] فایل‌های قبلی پاک شدند."
fi

# گرفتن ورودی‌های کاربر
echo "[+] وارد کردن اطلاعات سرور..."

# گرفتن دامین‌ها و سرورهای ریموت
declare -A DOMAINS
while true; do
    read -p "دامین (مثل domain1.com، برای اتمام خالی بذارید): " domain
    if [[ -z "$domain" ]]; then
        break
    fi
    read -p "IP سرور ریموت برای $domain (مثل 1.2.3.4): " remote_ip
    if ! validate_ip "$remote_ip"; then
        exit 1
    fi
    DOMAINS["$domain"]="$remote_ip"
done

# گرفتن پورت‌ها
echo "[+] وارد کردن پورت‌ها (مثل 443 8443 10000، با فاصله جدا کنید):"
read -a PORTS
if [ ${#PORTS[@]} -eq 0 ]; then
    echo "[-] خطا: حداقل یک پورت باید وارد شود."
    exit 1
fi
for port in "${PORTS[@]}"; do
    if ! validate_port "$port"; then
        exit 1
    fi
done

# گرفتن نوع کانکشن
echo "[+] نوع کانکشن‌ها را انتخاب کنید (چند گزینه می‌تونید انتخاب کنید):"
echo "1) TCP"
echo "2) UDP"
echo "3) WebSocket"
echo "4) همه موارد"
read -p "انتخاب (مثل 1 2 3): " -a CONNECTION_TYPES
connection_check=$(IFS=,; echo "${CONNECTION_TYPES[*]}")
if ! [[ $connection_check =~ [1-4] ]]; then
    echo "[-] خطا: انتخاب نامعتبر!"
    exit 1
fi

# بررسی پورت‌ها برای TCP
if [[ $connection_check =~ 1 || $connection_check =~ 4 ]]; then
    if [ ${#PORTS[@]} -eq 0 ]; then
        echo "[-] خطا: برای TCP حداقل یک پورت باید وارد شود."
        exit 1
    fi
fi

# بررسی و نصب Nginx
check_package nginx

# بررسی و نصب certbot
check_certbot

# بررسی و نصب wget
check_wget

# اطمینان از وجود دایرکتوری sites-enabled و sites-available
check_file_op "mkdir -p /etc/nginx/sites-available" "ایجاد دایرکتوری sites-available"
check_file_op "mkdir -p /etc/nginx/sites-enabled" "ایجاد دایرکتوری sites-enabled"

# اطمینان از وجود include sites-enabled در nginx.conf
if ! grep -q "include /etc/nginx/sites-enabled/*.conf;" /etc/nginx/nginx.conf; then
    echo "[*] اضافه کردن include sites-enabled به nginx.conf..."
    check_file_op "echo 'include /etc/nginx/sites-enabled/*.conf;' >> /etc/nginx/nginx.conf" "اضافه کردن include sites-enabled"
fi

# فعال‌سازی stream module
check_file_op "mkdir -p /etc/nginx/stream.d" "ایجاد دایرکتوری stream.d"

# اطمینان از وجود بلاک stream در nginx.conf
STREAM_INCLUDE="/etc/nginx/stream.conf"
if ! awk '/stream[[:space:]]*{/{f=1} f&&/}/{f=0} f' /etc/nginx/nginx.conf | grep -q "stream"; then
    echo "[*] اضافه کردن بلاک stream به nginx.conf..."
    cat <<EOF > $STREAM_INCLUDE
stream {
    include /etc/nginx/stream.d/*.conf;
}
EOF
    check_file_op "cat > $STREAM_INCLUDE" "ایجاد فایل stream.conf"
    if ! grep -q "include $STREAM_INCLUDE;" /etc/nginx/nginx.conf; then
        check_file_op "echo 'include $STREAM_INCLUDE;' >> /etc/nginx/nginx.conf" "اضافه کردن include stream.conf"
    fi
else
    echo "[*] بلاک stream از قبل در nginx.conf وجود دارد."
    # اطمینان از وجود include در بلاک stream
    if ! grep -q "include /etc/nginx/stream.d/*.conf;" /etc/nginx/stream.conf; then
        check_file_op "echo 'include /etc/nginx/stream.d/*.conf;' >> /etc/nginx/stream.conf" "اضافه کردن include به stream.conf"
    fi
fi

# بررسی ماژول stream
if [[ $connection_check =~ 1 || $connection_check =~ 4 ]]; then
    check_stream_module
fi

# تولید تنظیمات Nginx برای هر دامین
for domain in "${!DOMAINS[@]}"; do
    remote_ip=${DOMAINS[$domain]}
    
    # تنظیمات TCP (اگه انتخاب شده)
    if [[ $connection_check =~ 1 || $connection_check =~ 4 ]]; then
        echo "[*] پیکربندی TCP برای $domain..."
        STREAM_CONF="/etc/nginx/stream.d/proxy_tcp_$domain.conf"
        if [ -f "$STREAM_CONF" ]; then
            echo "[!] پیکربندی TCP برای $domain قبلاً وجود دارد، از آن عبور می‌کنیم..."
        else
            cat <<EOF > $STREAM_CONF
# تنظیمات TCP برای $domain
EOF
            for port in "${PORTS[@]}"; do
                echo "[•] فوروارد TCP پورت $port برای $domain به $remote_ip:$port"
                cat <<EOF >> $STREAM_CONF
server {
    listen $port;
    proxy_pass $remote_ip:$port;
    proxy_timeout 10s;
    proxy_connect_timeout 5s;
}
EOF
            done
            check_file_op "cat > $STREAM_CONF" "ایجاد فایل تنظیمات TCP برای $domain"
        fi
    fi

    # تنظیمات WebSocket (اگه انتخاب شده)
    if [[ $connection_check =~ 3 || $connection_check =~ 4 ]]; then
        echo "[*] پیکربندی WebSocket برای $domain..."
        WS_CONF="/etc/nginx/sites-available/ws_proxy_$domain"
        if [ -f "$WS_CONF" ]; then
            echo "[!] پیکربندی WebSocket برای $domain قبلاً وجود دارد، از آن عبور می‌کنیم..."
        else
            # توقف موقت Nginx برای Certbot
            echo "[*] توقف موقت Nginx برای Certbot..."
            systemctl stop nginx
            # بررسی وجود گواهی SSL
            echo "[+] تلاش برای گرفتن یا به‌روزرسانی گواهی SSL برای $domain..."
            if check_ssl_cert "$domain"; then
                if certbot certonly --standalone -d "$domain" --non-interactive --agree-tos --email admin@$domain --force-renewal; then
                    echo "[✓] گواهی SSL برای $domain به‌روزرسانی شد."
                    USE_SSL=true
                else
                    echo "⚠️ به‌روزرسانی گواهی SSL برای $domain شکست خورد. پیکربندی WebSocket فقط با HTTP انجام می‌شود."
                    USE_SSL=false
                fi
            else
                if certbot certonly --standalone -d "$domain" --non-interactive --agree-tos --email admin@$domain; then
                    echo "[✓] گواهی SSL برای $domain با موفقیت صادر شد."
                    USE_SSL=true
                else
                    echo "⚠️ گرفتن گواهی SSL برای $domain شکست خورد. پیکربندی WebSocket فقط با HTTP انجام می‌شود."
                    USE_SSL=false
                fi
            fi
            # راه‌اندازی دوباره Nginx
            echo "[*] راه‌اندازی دوباره Nginx..."
            systemctl start nginx

            # پیکربندی WebSocket با یا بدون SSL
            if [ "$USE_SSL" = true ]; then
                cat <<EOF > $WS_CONF
server {
    listen 80;
    server_name $domain;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name $domain;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

    location / {
        root /var/www/$domain;
        index index.html;
    }

    location ~ ^/ray {
        proxy_pass http://$remote_ip:80;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
            else
                cat <<EOF > $WS_CONF
server {
    listen 80;
    server_name $domain;

    location / {
        root /var/www/$domain;
        index index.html;
    }

    location ~ ^/ray {
        proxy_pass http://$remote_ip:80;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
            fi
            check_file_op "cat > $WS_CONF" "ایجاد فایل تنظیمات WebSocket برای $domain"
            check_file_op "ln -sf $WS_CONF /etc/nginx/sites-enabled/ws_proxy_$domain" "ایجاد لینک سمبولیک WebSocket برای $domain"
            check_file_op "mkdir -p /var/www/$domain" "ایجاد دایرکتوری وب برای $domain"
            check_file_op "echo '<h1>Welcome to $domain</h1>' > /var/www/$domain/index.html" "ایجاد فایل index.html برای $domain"
            echo "[•] فوروارد WebSocket مسیر /ray برای $domain به $remote_ip:80"
        fi
    fi
done

# تست و ری‌لود Nginx
echo "[*] تست تنظیمات Nginx..."
if ! nginx -t; then
    echo "[-] خطا: تنظیمات Nginx نامعتبر است. لطفاً لاگ‌های Nginx را بررسی کنید:"
    echo "  journalctl -u nginx"
    read -p "[?] می‌خواهید ادامه دهید؟ (y/N): " continue_on_error
    if [[ ! "$continue_on_error" =~ ^[yY]$ ]]; then
        exit 1
    fi
else
    systemctl reload nginx
    echo "[✓] Nginx با موفقیت تنظیم شد."
fi

# نصب GOST (برای UDP)
if [[ $connection_check =~ 2 || $connection_check =~ 4 ]]; then
    echo "[+] بررسی نصب gost..."
    if ! command -v gost &> /dev/null; then
        echo "[+] نصب gost برای UDP..."
        GOST_VERSION="3.1.0"
        ARCH=$(uname -m)
        case $ARCH in
            x86_64)
                if grep -q -E 'avx2|sse4_2' /proc/cpuinfo; then
                    GOST_ARCH="amd64v3"
                else
                    GOST_ARCH="amd64"
                fi
                ;;
            aarch64)
                GOST_ARCH="arm64"
                ;;
            armv7l|armv6l|armv5l)
                GOST_ARCH="armv5"
                ;;
            *)
                echo "[-] خطا: معماری سیستم ($ARCH) پشتیبانی نمی‌شود."
                exit 1
                ;;
        esac
        GOST_URL="https://github.com/go-gost/gost/releases/download/v$GOST_VERSION/gost_${GOST_VERSION}_linux_${GOST_ARCH}.tar.gz"
        echo "[*] دانلود GOST از $GOST_URL..."
        if ! wget -q "$GOST_URL" -O gost.tar.gz; then
            echo "[-] خطا: دانلود GOST شکست خورد. لطفاً اتصال شبکه یا URL را بررسی کنید."
            exit 1
        fi
        if ! tar -xzf gost.tar.gz; then
            echo "[-] خطا: استخراج فایل GOST شکست خورد."
            exit 1
        fi
        # پیدا کردن فایل اجرایی gost
        GOST_EXEC=$(find . -type f -name "gost" -o -name "gost_*" | head -n 1)
        if [ -z "$GOST_EXEC" ]; then
            echo "[-] خطا: فایل اجرایی GOST پیدا نشد."
            exit 1
        fi
        check_file_op "mv $GOST_EXEC /usr/local/bin/gost" "انتقال فایل اجرایی GOST"
        check_file_op "chmod +x /usr/local/bin/gost" "تنظیم مجوز اجرایی GOST"
        # پاکسازی فایل‌های موقت
        check_file_op "rm -rf gost_* *.tar.gz" "پاکسازی فایل‌های موقت GOST"
        if ! [ -f /usr/local/bin/gost ]; then
            echo "[-] خطا: فایل GOST در /usr/local/bin/gost ایجاد نشد."
            exit 1
        fi
        if ! /usr/local/bin/gost -h >/dev/null 2>&1; then
            echo "[-] خطا: فایل GOST قابل اجرا نیست. لطفاً نصب را بررسی کنید."
            exit 1
        fi
        echo "[✓] GOST با موفقیت نصب شد."
    else
        echo "[*] gost از قبل نصب شده است."
    fi

    # ساخت فایل کانفیگ JSON برای GOST
    for domain in "${!DOMAINS[@]}"; do
        remote_ip=${DOMAINS[$domain]}
        clean_domain=$(echo "$domain" | tr '.' '_')
        echo "[*] ایجاد فایل کانفیگ GOST برای $domain..."
        GOST_CONFIG="/etc/gost/gost_$clean_domain.json"
        if [ -f "$GOST_CONFIG" ]; then
            echo "[!] فایل کانفیگ GOST برای $domain قبلاً وجود دارد، از آن عبور می‌کنیم..."
            continue
        fi
        check_file_op "mkdir -p /etc/gost" "ایجاد دایرکتوری GOST"
        # ساخت آرایه موقت برای سرویس‌ها
        declare -a services
        for port in "${PORTS[@]}"; do
            echo "[•] فوروارد UDP پورت $port برای $domain به $remote_ip:$port"
            services+=("
    {
      \"Name\": \"udp_$port\",
      \"Addr\": \":$port\",
      \"Handler\": {
        \"Type\": \"udp\",
        \"Chain\": \"\"
      },
      \"Listener\": {
        \"Type\": \"udp\",
        \"Chain\": \"\"
      },
      \"Forwarder\": {
        \"Nodes\": [
          {
            \"Name\": \"target_$port\",
            \"Addr\": \"$remote_ip:$port\"
          }
        ]
      }
    }")
        done
        # تولید فایل JSON
        printf '{\n  "Services": [\n%s\n  ]\n}' "$(IFS=','; echo "${services[*]}")" > "$GOST_CONFIG"
        check_file_op "printf > $GOST_CONFIG" "ایجاد فایل JSON GOST برای $domain"
        # بررسی صحت فایل JSON
        if ! jq empty "$GOST_CONFIG" >/dev/null 2>&1; then
            echo "[-] خطا: فایل JSON GOST برای $domain نامعتبر است."
            exit 1
        fi

        # ساخت سرویس systemd برای GOST
        echo "[*] ایجاد سرویس GOST برای $domain..."
        GOST_SERVICE="/etc/systemd/system/gost_$clean_domain.service"
        if [ -f "$GOST_SERVICE" ]; then
            echo "[!] سرویس GOST برای $domain قبلاً وجود دارد، از آن عبور می‌کنیم..."
            continue
        fi
        cat <<EOF > $GOST_SERVICE
[Unit]
Description=GOST UDP Relay for $domain
After=network.target

[Service]
ExecStart=/usr/local/bin/gost -C $GOST_CONFIG -L log://stdout?level=info
Restart=always
[Install]
WantedBy=multi-user.target
EOF
        check_file_op "cat > $GOST_SERVICE" "ایجاد سرویس GOST برای $domain"
        systemctl daemon-reload
        systemctl enable "gost_$clean_domain"
        if ! systemctl restart "gost_$clean_domain"; then
            echo "[-] خطا: سرویس GOST برای $domain اجرا نشد. وضعیت سرویس:"
            systemctl status "gost_$clean_domain"
            read -p "[?] می‌خواهید ادامه دهید؟ (y/N): " continue_on_error
            if [[ ! "$continue_on_error" =~ ^[yY]$ ]]; then
                exit 1
            fi
        else
            echo "[✓] GOST برای $domain در حال اجراست."
        fi
    done
fi

# تنظیم فایروال
echo "[*] تنظیم فایروال..."
if command -v ufw &> /dev/null; then
    echo "[*] ufw از قبل نصب شده است."
    if ufw status | grep -q "Status: active"; then
        echo "[*] ufw از قبل فعال است."
    else
        check_file_op "ufw --force enable" "فعال‌سازی ufw"
        echo "[✓] ufw فعال شد."
    fi
    for port in "${PORTS[@]}"; do
        check_file_op "ufw allow $port" "باز کردن پورت $port"
    done
    check_file_op "ufw allow 22" "باز کردن پورت SSH (22)"
    check_file_op "ufw allow 80" "باز کردن پورت HTTP (80)"
    check_file_op "ufw allow 443" "باز کردن پورت HTTPS (443)"
    echo "[✓] فایروال تنظیم شد."
else
    echo "[+] نصب ufw..."
    safe_apt "apt update && apt install -y ufw"
    for port in "${PORTS[@]}"; do
        check_file_op "ufw allow $port" "باز کردن پورت $port"
    done
    check_file_op "ufw allow 22" "باز کردن پورت SSH (22)"
    check_file_op "ufw allow 80" "باز کردن پورت HTTP (80)"
    check_file_op "ufw allow 443" "باز کردن پورت HTTPS (443)"
    check_file_op "ufw --force enable" "فعال‌سازی ufw"
    echo "[✓] فایروال تنظیم و فعال شد."
fi

# پرسیدن برای نمایش لاگ‌ها
read -p "[?] می‌خوای لاگ‌های Nginx و GOST رو ببینی؟ (y/N): " show_logs
if [[ "$show_logs" =~ ^[yY]$ ]]; then
    show_logs
fi

# پایان
echo -e "\n✅ تنظیمات کامل شد! سرور حالا ترافیک انتخاب‌شده رو برای دامین‌ها به سرورهای ریموت منتقل می‌کنه."