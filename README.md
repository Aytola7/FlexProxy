# FlexProxy

🔒 یک ابزار منعطف و خودکار برای فوروارد ترافیک TCP, UDP و WebSocket با استفاده از **NGINX** و **GOST**، همراه با گواهی SSL خودکار.

---

## 🎯 ویژگی‌ها

- فوروارد خودکار TCP با ماژول `stream` در NGINX  
- انتقال UDP با کمک `GOST`  
- پشتیبانی از WebSocket با SSL واقعی (Let's Encrypt)  
- مدیریت چندین دامین و چندین پورت همزمان  
- حذف و پاک‌سازی خودکار تنظیمات قدیمی  
- ایجاد و مدیریت سرویس‌های systemd برای GOST  
- فعال‌سازی خودکار فایروال (ufw)  
- محیط تعاملی برای وارد کردن داده‌ها

---

## 🚀 نصب سریع

```bash
chmod +x flexproxy.sh
sudo ./flexproxy.sh
```

اسکریپت به صورت تعاملی از شما می‌پرسد:

1. دامین‌ها و IP سرور مقصد
2. پورت‌هایی که می‌خواهید فوروارد شوند (مثلاً 443 8443)
3. نوع اتصال (TCP, UDP, WebSocket یا همه)

---

## 📦 وابستگی‌ها

- سیستم عامل Ubuntu یا Debian-based  
- دسترسی ریشه (root)  
- ابزارهای:
  - `nginx`
  - `certbot` و `python3-certbot-nginx`
  - `systemd`
  - `ufw` (در صورت فعال بودن فایروال)

---

## 🧱 ابزارهای مورد استفاده

- [NGINX](https://nginx.org/)
- [GOST](https://github.com/go-gost/gost)
- [Certbot (Let's Encrypt)](https://certbot.eff.org/)
- Bash scripting

---

## 🔍 نمونه کاربردها

- ساخت نودهای انتقال ترافیک شبیه CDN  
- عبور از فیلترینگ با رله کردن ترافیک از سرور اول به دوم  
- پنهان‌سازی سرویس‌های V2Ray، Hysteria، Trojan، Shadowsocks و غیره پشت دامین معتبر

---

## 📂 ساختار تولیدشده

```text
/etc/nginx/sites-available/ws_proxy_DOMAIN
/etc/nginx/stream.d/proxy_tcp_DOMAIN.conf
/etc/gost/gost_DOMAIN.json
/etc/systemd/system/gost_DOMAIN.service
/var/www/DOMAIN/index.html
```
---

# 1. دریافت پروژه از GitHub
```
git clone https://github.com/Aytola7/FlexProxy.git
```

# 2. وارد پوشه پروژه شو
```
cd FlexProxy
```

# 3. اجرای اسکریپت اصلی
```
chmod +x setup_proxy.sh
```
```
./setup_proxy.sh
```

---

## 📄 مجوز

MIT License – استفاده، ویرایش و توسعه آزاد است.

---

**طراح و توسعه‌دهنده:** [شما 😎]  
