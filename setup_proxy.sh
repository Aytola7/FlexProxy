#!/bin/bash

# تابع برای اعتبارسنجی IP
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        return 0
    else
        echo "[-] خطا: IP نامعتبر است: $ip"
        exit 1
    fi
}

# تابع برای اعتبارسنجی پورت
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ ]] && [ $port -ge 1 ] && [ $port -le 65535 ]; then
        return 0
    else
        echo "[-] خطا: پورت نامعتبر است: $port"
        exit 1
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

# پرسیدن برای پاک‌سازی فایل‌های قبلی
read -p "[?] می‌خوای اسکریپت قبلی رو پاکسازی کنم؟ (y/N): " cleanup
if [[ "$cleanup" =~ ^[yY]$ ]]; then
    echo "[*] پاک‌سازی فایل‌های تنظیمات قبلی..."
    rm -f /etc/nginx/stream.d/proxy_tcp_*
    rm -f /etc/nginx/sites-available/ws_proxy_*
    rm -f /etc/nginx/sites-enabled/ws_proxy_*
    rm -f /etc/gost/gost_*.json
    for service in /etc/systemd/system/gost_*.service; do
        if [ -f "$service" ]; then
            service_name=$(basename "$service")
            systemctl stop "$service_name"
            systemctl disable "$service_name"
            rm -f "$service"
        fi
    done
    systemctl daemon-reexec
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
    validate_ip "$remote_ip"
    DOMAINS["$domain"]="$remote_ip"
done

# گرفتن پورت‌ها
echo "[+] وارد کردن پورت‌ها (مثل 443 8443 10000، با فاصله جدا کنید):"
read -a PORTS
for port in "${PORTS[@]}"; do
    validate_port "$port"
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

# نصب Nginx
echo "[+] نصب nginx..."
apt update && apt install -y nginx

# نصب certbot برای SSL
echo "[+] نصب certbot برای SSL..."
apt install -y certbot python3-certbot-nginx

# اطمینان از وجود دایرکتوری sites-enabled
mkdir -p /etc/nginx/sites-enabled

# فعال‌سازی stream module
mkdir -p /etc/nginx/stream.d

# اطمینان از وجود بلاک stream در nginx.conf
STREAM_INCLUDE="/etc/nginx/stream.conf"
if ! grep -q "include /etc/nginx/stream.d/\*.conf;" /etc/nginx/nginx.conf; then
    echo "[*] اضافه کردن بلاک stream به nginx.conf..."
    cat <<EOF > $STREAM_INCLUDE
stream {
    include /etc/nginx/stream.d/*.conf;
}
EOF
    if ! grep -q "include $STREAM_INCLUDE;" /etc/nginx/nginx.conf; then
        sed -i "/^http {/i include $STREAM_INCLUDE;" /etc/nginx/nginx.conf
    fi
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
            echo "stream {" > $STREAM_CONF
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
            echo "}" >> $STREAM_CONF
        fi
    fi

    # تنظیمات WebSocket (اگه انتخاب شده)
    if [[ $connection_check =~ 3 || $connection_check =~ 4 ]]; then
        echo "[*] پیکربندی WebSocket برای $domain..."
        WS_CONF="/etc/nginx/sites-available/ws_proxy_$domain"
        if [ -f "$WS_CONF" ]; then
            echo "[!] پیکربندی WebSocket برای $domain قبلاً وجود دارد، از آن عبور می‌کنیم..."
        else
            # گرفتن گواهی SSL
            echo "[+] تلاش برای گرفتن گواهی SSL برای $domain..."
            if certbot --nginx -d "$domain" --non-interactive --agree-tos --email admin@$domain; then
                echo "[✓] گواهی SSL برای $domain با موفقیت صادر شد."
                USE_SSL=true
            else
                echo "⚠️ گرفتن گواهی SSL برای $domain شکست خورد. پیکربندی WebSocket فقط با HTTP انجام می‌شود."
                USE_SSL=false
            fi

            # پیکربندی WebSocket با یا بدون SSL
            if [ "$USE_SSL" = true ]; then
                cat <<EOF > $WS_CONF
server {
    listen 80;
    server_name $domain;
    return 301 https://\$host\$request_uri;
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
            echo "[•] فوروارد WebSocket مسیر /ray برای $domain به $remote_ip:80"
            ln -sf $WS_CONF /etc/nginx/sites-enabled/ws_proxy_$domain
            mkdir -p /var/www/$domain
            echo "<h1>Welcome to $domain</h1>" > /var/www/$domain/index.html
        fi
    fi
done

# تست و ری‌لود Nginx
nginx -t && systemctl reload nginx
echo "[✓] Nginx با موفقیت تنظیم شد."

# نصب GOST (برای UDP)
if [[ $connection_check =~ 2 || $connection_check =~ 4 ]]; then
    echo "[+] بررسی نصب gost..."
    if ! command -v gost &> /dev/null; then
        echo "[+] نصب gost برای UDP..."
        GOST_VERSION="3.0.0-beta.12"
        wget -q https://github.com/go-gost/gost/releases/download/v$GOST_VERSION/gost-linux-amd64-$GOST_VERSION.gz
        gunzip gost-linux-amd64-$GOST_VERSION.gz
        chmod +x gost-linux-amd64-$GOST_VERSION
        mv gost-linux-amd64-$GOST_VERSION /usr/local/bin/gost
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
        mkdir -p /etc/gost
        cat <<EOF > $GOST_CONFIG
{
  "Services": [
EOF
        for port in "${PORTS[@]}"; do
            echo "[•] فوروارد UDP پورت $port برای $domain به $remote_ip:$port"
            cat <<EOF >> $GOST_CONFIG
    {
      "Name": "udp_$port",
      "Addr": ":$port",
      "Handler": {
        "Type": "udp",
        "Chain": ""
      },
      "Listener": {
        "Type": "udp",
        "Chain": ""
      },
      "Forwarder": {
        "Nodes": [
          {
            "Name": "target_$port",
            "Addr": "$remote_ip:$port"
          }
        ]
      }
    },
EOF
        done
        # حذف کاما آخر و بستن JSON
        sed -i '$ s/,$//' $GOST_CONFIG
        echo "  ]" >> $GOST_CONFIG
        echo "}" >> $GOST_CONFIG

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
        systemctl daemon-reexec
        systemctl daemon-reload
        systemctl enable gost_$clean_domain
        systemctl restart gost_$clean_domain
        echo "[✓] GOST برای $domain در حال اجراست."
    done
fi

# تنظیم فایروال
echo "[*] تنظیم فایروال..."
if command -v ufw &> /dev/null; then
    for port in "${PORTS[@]}"; do
        ufw allow $port
    done
    ufw allow 80
    ufw allow 443
    ufw --force enable
    echo "[✓] فایروال تنظیم و فعال شد."
else
    echo "[-] خطا: ufw نصب نیست. لطفاً به‌صورت دستی پورت‌ها را باز کنید."
fi

# پرسیدن برای نمایش لاگ‌ها
read -p "[?] می‌خوای لاگ‌های Nginx و GOST رو ببینی؟ (y/N): " show_logs
if [[ "$show_logs" =~ ^[yY]$ ]]; then
    show_logs
fi

# پایان
echo -e "\n✅ تنظیمات کامل شد! سرور حالا ترافیک انتخاب‌شده رو برای دامین‌ها به سرورهای ریموت منتقل می‌کنه."
