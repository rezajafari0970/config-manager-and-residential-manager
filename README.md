# Config manager and residential manager

مدیریت لینک‌ها و کانفیگ‌های VPN، تبدیل و آزمایش مستقل کانفیگ‌ها، و مدیریت خروجی‌های Residential در یک پنل فارسی.

بخش Smart، تولید خروجی ترکیبی Smart، API، تنظیمات، صف‌ها و سرویس اختصاصی آن حذف شده‌اند. کانفیگ‌های اصلی، خروجی‌های عادی و فرایند Residential مستقل باقی می‌مانند. مهاجرت دیتابیس نسخهٔ ۴۱ فقط داده‌های اختصاصی بخش حذف‌شده را پاک می‌کند.

## نصب با یک دستور

روی **سرور تازه، با کاربر root** اجرا کنید:

```bash
bash -c 'set -e; apt-get update; apt-get install -y curl ca-certificates; f=$(mktemp); trap "rm -f -- \"$f\"" EXIT; curl -qfsSL --connect-timeout 8 --max-time 45 --speed-limit 1 --speed-time 20 --retry 2 --retry-delay 1 --retry-max-time 60 https://raw.githubusercontent.com/rezajafari0970/config-manager-and-residential-manager/main/install.sh -o "$f"; bash "$f"'
```

نصب‌کننده کد منبع، Go، نسخه‌های قفل‌شدهٔ Xray و sing-box، Python، HTTP/3، Nginx و پیش‌نیازهای جداسازی پردازش را نصب می‌کند. دانلودها به دسترسی اینترنت نیاز دارند؛ مسدود بودن GitHub یا مخازن بسته مانع نصب می‌شود.

دانلود هر فایل با نام مرحله و نتیجه نمایش داده می‌شود. انتقالِ بدون دریافت داده برای ۲۰ ثانیه قطع می‌شود؛ نصب‌کننده با HTTP/1.1 و IPv4 دوباره تلاش می‌کند و برای سورس، مسیر جایگزین رسمی گیت‌هاب نیز دارد. بودجهٔ کل تلاش دانلود سورس ۱۲۰ ثانیه و هر فایل وابستگی ۳۰۰ ثانیه است. فایل ناقص یا دارای هش اشتباه جایگزین فایل معتبر نمی‌شود. برای انتخاب صریح خانوادهٔ IP می‌توانید پیش از نصب `export CMRM_IP_VERSION=4` یا `export CMRM_IP_VERSION=6` اجرا کنید؛ حالت پیش‌فرض `auto` است.

پشتیبانی این نسخه: **Ubuntu 24.04/26.04 و Debian 12/13، معماری amd64/x86_64، systemd و cgroup v2**. حداقل ۱ گیگابایت RAM و ۲ گیگابایت فضای آزاد برای ساخت لازم است؛ ۲ گیگابایت RAM و فضای اضافه برای داده‌ها پیشنهاد می‌شود. Windows، ARM و کانتینر فاقد مجوز namespace/cgroup پشتیبانی نمی‌شوند. نصب‌کننده امکانات واقعی sandbox را قبل از راه‌اندازی بررسی می‌کند.

در پایان، آدرس پنل، کاربر `admin` و رمز تصادفی نمایش داده می‌شود. اطلاعات ورود روی همان سرور در `/etc/config-repair/access.txt` با دسترسی root ذخیره می‌شود. پورت پیش‌فرض **18443/TCP** است؛ آن را در فایروال ارائه‌دهنده باز کنید. پنل داخلی فقط روی loopback گوش می‌دهد.

برای تعیین دامنه یا IP عمومی، پیش از دستور نصب اجرا کنید:

```bash
export CMRM_HOST=panel.example.com CMRM_PORT=18443
```

بدون این گزینه، آدرس رابط پیش‌فرض سرور استفاده می‌شود؛ در سرور NAT باید IP یا دامنهٔ عمومی را تعیین کنید. گواهی پیش‌فرض خودامضاست. برای اشتراک قابل‌اعتماد در کلاینت‌ها از گواهی معتبر دامنه استفاده کنید: پیش از نصب `CMRM_TLS_CERT` و `CMRM_TLS_KEY` را به مسیر فایل‌های گواهی و کلید موجود تنظیم کنید. نصب بدون دامنه هم ممکن است؛ صدور خودکار گواهی عمومی در این نسخه انجام نمی‌شود.

## عملکرد

پروتکل‌های مجاز برای دریافت، آزمون و انتشار VLESS، VMess، Trojan، Shadowsocks و WireGuard هستند. پروفایل Custom یا JSON با یک خروجی هیستریا، حتی اگر آن خروجی انتخاب نشده باشد، به‌طور کامل رد می‌شود. کانفیگ‌های مستقلِ مجاز در همان اشتراک پردازش می‌شوند.

- دریافت زمان‌بندی‌شدهٔ لینک‌ها، حفظ ورودی خام و حذف تکراری‌ها؛
- تبدیل مستقل، ثبت شواهد سلامت و خروجی تکی/اشتراک با گردش مستقل؛
- بررسی مستقل مسیر Google Ads در برابر مقاصد کنترل؛
- بازآزمایی Residential، کنترل سلامت، کشور و سیاست خروج ایران؛
- جداسازی تست‌ها با network namespace، nftables، cgroup و bubblewrap؛
- محدودسازی منابع و بازیابی خودکار سرویس‌ها با systemd؛
- حفاظت پنل با رمز مدیریت در Nginx؛ اشتراک‌های دارای توکن مستقل از رمز پنل قابل دریافت‌اند.

انتشار رزیدنتال به جدایی مسیر و تأیید شبکهٔ دسترسی خروجی هر شش مقصد Ads در نسخهٔ خام و قالب نیاز دارد. مشاهدهٔ یک خروجی دیتاسنتری مانند Vultr در هر دامنه، انتشار رزیدنتال همان کانفیگ را متوقف می‌کند. نوع اشتراک یک خانوار و موقعیت یک رویداد واقعی AdMob شواهد جداگانه می‌خواهند. [روش تشخیص و معیارهای انتشار](docs/ADS-EXIT-NETWORK.md)

## نگهداری

اجرای دوبارهٔ همان دستور، نصب متعلق به این پروژه را شناسایی می‌کند؛ کلید، رمز و دیتابیس را نگه می‌دارد. تغییر نسخه با پشتیبانِ متوقف‌شدهٔ داده و تنظیمات انجام می‌شود. نصب‌های قدیمیِ فاقد نشان مالکیت به‌صورت خودکار بازنویسی نمی‌شوند؛ [راهنمای عملیات](docs/OPERATIONS.md) را بخوانید.

```bash
systemctl status config-repair config-repair-prober config-repair-egress
journalctl -u config-repair -u config-repair-prober -u config-repair-egress --since '10 minutes ago'
cat /etc/config-repair/access.txt
```

دادهٔ کشور روزانه به‌روزرسانی می‌شود. اختلال دانلود دادهٔ کشور به‌وضوح گزارش می‌شود و تصمیم‌های نیازمند آن fail-closed باقی می‌مانند. منابع و مجوزهای داده در [THIRD_PARTY.md](THIRD_PARTY.md) آمده‌اند.

## توسعه و آزمون

Go 1.27.1، Python 3.11+ و Node.js برای تست‌های JavaScript لازم‌اند. `go test ./...` تست‌های Go را اجرا می‌کند. `scripts/check.sh` مجموعهٔ گسترده‌تر و race detector را اجرا می‌کند. تست‌های شبکه/اندروید نیازمند محیط و مجوزهای واقعی‌اند و به‌صورت ضمنی در نصب عادی اجرا نمی‌شوند.

[گزارش اعتبارسنجی](docs/VALIDATION.md) | [راهنمای عملیات](docs/OPERATIONS.md)

## Datacenter and CDN

The **Datacenter** page adds 10 named hosting providers plus Unknown, five CDN providers, Non-CDN and CDN Unknown. Every group has raw and independently rotating single-template URLs. Classification runs automatically in the background. See [the evidence model and operating limits](docs/DATACENTER.md).

Preparation and native output: [pipeline contracts](docs/PIPELINE.md) and [OpenAPI](docs/openapi-preparation.json). Preparation runs independently; public templates require fresh exact-byte core and connection proof. Counts reconcile every canonical input, and sing-box output has separate links.
