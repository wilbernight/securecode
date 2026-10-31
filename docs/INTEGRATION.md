# SecureCode — راهنمای یکپارچه‌سازی | Integration Guide

> **فارسی:** این داکیومنت برای توسعه‌دهنده‌ای است که می‌خواهد نرم‌افزار خودش را با
> سیستم لایسنس SecureCode محافظت کند — یعنی برنامه‌ای که بدون سریالِ امضاشده اجرا
> نمی‌شود و سریال به سخت‌افزارِ یک ماشین قفل است. ۱۰۰٪ آفلاین.
>
> **English:** This guide is for a developer who wants to protect their own
> application with the SecureCode licensing system: software that refuses to
> run without a signed serial, where each serial is hardware-locked to one
> machine. Fully offline.

---

## 1) سیستم چطور کار می‌کند؟ | How the system works

**فارسی:** دو طرف داریم:

- **سمت فروشنده (شما):** برنامه `protector` — با کلید خصوصی Ed25519ِ محافظت‌شده
  با passphrase، سریال تولید می‌کند و در دیتابیس رمزنگاری‌شده ثبت می‌کند.
- **سمت مشتری (برنامه محافظت‌شده):** بسته `protection` (SDK) — سریال را با
  کلید عمومیِ داخل برنامه تأیید می‌کند، کد سخت‌افزاری ماشین را می‌سنجد،
  تاریخ انقضا و ساعت سیستم را کنترل می‌کند و فایل لایسنسِ رمزنگاری‌شده را
  به‌صورت محلی نگه می‌دارد. هیچ اتصال شبکه‌ای در کار نیست.

**English:** Two sides:

- **Vendor side (you):** the `protector` app — issues serials signed with
  your Ed25519 private key (passphrase-wrapped keystore) and records them
  in an encrypted database.
- **Customer side (the protected app):** the `protection` package (SDK) —
  verifies serials against the public key embedded in the build, checks the
  hardware machine code, expiry, and clock consistency, and stores the
  encrypted license file locally. No network, ever.

```
شما/You                        مشتری/Customer
┌──────────────────┐    سریال    ┌─────────────────────────┐
│ Protector GUI    │ ────────▶  │ برنامه محافظت‌شده        │
│ (Ed25519 sign)   │  serial    │ (verify + hardware lock)│
└──────────────────┘            └─────────────────────────┘
     ▲ fingerprint code ◀──────────────┘
```

---

## 2) پیش‌نیازها | Prerequisites

> **فارسی / English:** این راهنما مخصوص محافظت از برنامه‌های **ویندوزی
> (پایتون)** است. برای اندروید/iOS/macOS (یا Flutter) به SDKهای بومی در
> `sdks/` و راهنمای `docs/PLATFORMS.md` بروید — سریال‌ها در همه‌جا یکسان
> verify می‌شوند.
>
> This guide covers protecting a **Windows (Python)** application. For
> Android/iOS/macOS (or Flutter) apps use the native SDKs in `sdks/` and
> `docs/PLATFORMS.md` — the serials verify identically everywhere.

| | |
|---|---|
| OS | Windows 10/11 (x64) |
| Python | 3.10+ (تست‌شده روی 3.14 / tested on 3.14) |
| Dependencies | `pyside6`, `cryptography`, `wmi`, `pywin32`, `py-cpuinfo` |
| Build | `nuitka`, `zstandard` (فقط برای کامپایل EXE / build only) |
| Repo | این مخزن: `shared/`, `target_demo/protection/`, `protector/` |

```bash
pip install -r requirements.txt
```

---

## 3) پنج مرحله یکپارچه‌سازی | The five integration steps

**فارسی:** مسیر یکپارچه‌سازی از برنامه‌ی خامِ شما تا EXE محافظت‌شده:

**English:** The path from your raw application to a protected EXE:

```
① کپی SDK      ② کلید خودتان   ③ wrapper نقطه ورود   ④ رشته‌ها + منیفست   ⑤ بیلد Nuitka
copy SDK        your key        entry-point wrapper   strings + manifest   build
```

### مرحله ① — کپی SDK به پروژه | Copy the SDK into your project

**فارسی:** این دو بسته را عیناً داخل پروژه خودتان کپی کنید (SDK وابستگی‌ای
فراتر از وابستگی‌های مجاز ندارد):

```text
your_app/
├── shared/          ← از این مخزن کپی کنید (payload_schema, codec, secure_buffer, exceptions)
├── protection/      ← target_demo/protection را کپی کنید (نه محتوایش را، کل بسته را)
└── main.py          ← برنامه شما
```

**English:** Copy these two packages verbatim into your project:

- `shared/` — payload schema, Base32 codec, SecureBuffer, exceptions
- `protection/` — the whole client SDK (copy of `target_demo/protection/`)

### مرحله ② — کلید عمومی خودتان را embed کنید | Embed YOUR public key

**فارسی:** فایل `protection/pubkey_blob.py` با کلید دمو پر شده. باید با
**کلید عمومی keystore خودتان** بازنویسی شود، وگرنه سریال‌هایی که پروتکتور
شما صادر می‌کند هرگز در محصولتان تأیید نمی‌شوند. ابزار آماده:

```bash
python protector/tools/export_pubkey_blob.py path/to/your_app/protection
# → keystore passphrase را می‌پرسد؛ فایل pubkey_blob.py را می‌نویسد
#   و key id را نشان می‌دهد (باید با نمایش‌داده‌شده در پروتکتور یکی باشد)
```

**English:** replace `protection/pubkey_blob.py` (currently the demo key)
with YOUR keystore's public key using the tool above — it asks for the
keystore passphrase (never an argument, never logged) and prints the key
id, which must match the one shown in the protector. The integrity layer
cross-checks the key against its SHA-256 digest at every startup, so
hand-editing is both unnecessary and detected.

### مرحله ③ — نقطه ورود را wrap کنید | Wrap your entry point

**فارسی:** کل جریان لایسنس در نقطه ورودِ برنامه اتفاق می‌افتد — چهار حالت:
معتبر → اجرا / بدون لایسنس → پنجره فعال‌سازی / خطا → صفحه خطا. الگوی دقیق
(همان چیزی که `target_demo/main.py` استفاده می‌کند):

```python
import os
from your_app.protection import (
    LicenseClient, LicenseState, ProtectionConfig, ProtectionRuntime,
)

config = ProtectionConfig(
    product_id="«UUID محصول شما از Protector → Settings → Products»",
    product_name="MyApp",          # نام پوشه‌های داده
    company_name="YourCompany",    # %PROGRAMDATA%\YourCompany\MyApp
    vm_detection_enabled=False,    # پیش‌فرض خاموش (توضیح در SECURITY.md)
)
runtime = ProtectionRuntime.bootstrap(config)   # ← اولین خطِ واقعی main()
client = LicenseClient(config, clock_guard=runtime.clock_guard)

while True:
    status = client.verify_installed(degraded=runtime.degraded or False)

    if status.state is LicenseState.VALID:            # ① سریال معتبر
        launch_my_app(status.payload)                 # ← برنامه شما اینجاست
        break

    if status.state is LicenseState.MISSING:           # ② فعال‌سازی
        from your_app.ui.activation import ActivationDialog
        dialog = ActivationDialog(client)
        dialog.exec()
        if dialog.activated:
            continue          # بعد از فعال‌سازی دوباره تأیید کن
        break

    error = build_license_error(status, client.machine_code())  # ③ خطا
    error.exec()
    if not error.retry_requested:
        break
```

**English:** the whole licensing flow lives in your entry point — four
states: valid → run / missing → activation dialog / else → error screen.
The pattern above is exactly what the demo uses; only
`launch_my_app(status.payload)` is your own code.

**قواعد طلایی | Golden rules:**
1. `ProtectionRuntime.bootstrap()` باید **اولین کار** بعد از setup لاگ باشد —
   قبل از هر import سنگین، قبل از هر پنجره‌ای.
2. **هیچ‌وقت** با `SC_DEV=1` یا `dev_mode=True` build نگیرید — فقط برای
   دیباگ تحت IDE است.
3. در حالت توسعه، `SC_DEV=1` بگذارید تا آنتی-دیباگ و چک یکپارچگی خاموش شود.

### مرحله ④ — لایه رشته‌ها و منیفست یکپارچگی | Strings layer + integrity manifest

**فارسی:** بعد از کپی SDK، دو ابزار زیر را با نام شرکت/محصول **خودتان** اجرا
کنید (رشته‌های حساس رمز می‌شوند؛ منیفستِ هش ماژول‌ها ساخته می‌شود):

```bash
# 1) لایه رشته‌های رمزنگاری‌شده (نام‌های پوشه‌های داده + رجیستری را با
#    همان company/product پر می‌کند که در ProtectionConfig گذاشتید):
python protector/tools/build_strings_table.py ^
    --sdk-dir path/to/your_app/protection ^
    --sdk-import-name protection ^
    --company YourCompany --product MyApp

# 2) منیفست یکپارچگی (ماژول‌ها را از خود پوشه کشف می‌کند):
python protector/tools/make_integrity_manifest.py ^
    --sdk-dir path/to/your_app/protection ^
    --sdk-import-name protection
```

⚠️ نکته ۱: اجرای ابزار رشته‌ها، master secretها را می‌چرخاند — اگر قبلاً
لایسنسی صادر/فعال کرده بودید، دوباره صادر کنید (برای محصول تازه‌کپی مهم
نیست). نکته ۲: در حالت توسعه با `SC_DEV=1` این چک‌ها skip می‌شوند؛ برای
**بیلد نهایی** الزامی‌اند و بعد از هر تغییری در `shared/` یا `protection/`
دوباره اجرا شوند.

**English:** run both tools with YOUR company/product names after copying
the SDK (they encrypt sensitive strings and build the module-hash
manifest; the manifest tool discovers modules from the directory itself).
The strings tool ROTATES master secrets — re-issue any previously
activated serials afterwards (irrelevant for a fresh product). Dev runs
skip these checks via `SC_DEV=1`; **release builds must** regenerate them,
and re-run them after ANY later change to `shared/` or `protection/`.

### مرحله ⑤ — بیلد با Nuitka | Build with Nuitka

**فارسی:** از `build.bat` ریشه مخزن به‌عنوان الگو استفاده کنید — فقط مسیر
پروژه و metadata را عوض کنید:

```bash
python -m nuitka ^
  --onefile --standalone --enable-plugin=pyside6 ^
  --windows-console-mode=disable ^
  --company-name="YourCompany" --product-name="MyApp" ^
  --windows-icon-from-ico=assets\app.ico ^
  --include-package=shared --include-package=your_app ^
  your_app\main.py
```

**English:** clone `build.bat` from the repo root, change the paths and
version metadata. Nuitka compiles to native code — zero `.pyc` bytecode in
the artifact, so decompilers find nothing to decompile.

---

## 4) داخل برنامه: استفاده از payload | Inside your app: using the payload

**فارسی:** بعد از فعال‌سازی موفق، `status.payload` اطلاعات امضاشده را دارد —
بدون هیچ تماسی با شما، محلی و تأییدشده:

```python
payload = status.payload
payload.customer          # نام مشتری که موقع صدور نوشتید
payload.expires_at        # Unix timestamp (یا is_lifetime)
payload.feature_flags     # {"core": True, "pro_module": False, ...}
payload.seconds_left      # ثانیه باقی‌مانده
```

قفل امکانات با feature flags — همان چیزی که در Protector → Generate تنظیم
می‌کنید، در برنامه مشتری قابل خواندن است:

```python
if payload.feature_flags.get("pro_module"):
    enable_pro_module()   # ماژول Pro فقط با سریالی که این flag را دارد
```

**English:** `status.payload` carries the signed license data — read
`customer`, `expires_at`, `feature_flags` to gate modules locally.

---

## 5) API مرجع | API reference

### `ProtectionConfig` (فیلدهای پرکاربرد | commonly used)

| فیلد | پیش‌فرض | توضیح / Description |
|---|---|---|
| `product_id` | demo UUID | UUID محصول — باید با Protector یکی باشد / must match the protector's product list |
| `product_name` | `"SecureNotepad"` | نام پوشه داده / data directory name |
| `company_name` | `"SecureCode"` | نام شرکت / `%PROGRAMDATA%\Company\Product` |
| `vm_detection_enabled` | `False` | اجرا در VM را می‌بندد / refuse VMs (خاموش توصیه می‌شود) |
| `on_detect` | `EXIT` | رفتار هنگام کشف دیباگر: خروج بی‌صدا یا `DEGRADE` |
| `fingerprint_tolerance` | `1` | چند قطعه سخت‌افزار ممکن است عوض شود / tolerated component swaps |
| `default_rollback_allowance` | `3` | تعداد تحمل عقب‌کشیدن ساعت / tolerated clock rollbacks |
| `dev_mode` | `False` | فقط برای دیباگ — **هرگز ship نکنید** |

### `LicenseClient`

| متد | خروجی | توضیح |
|---|---|---|
| `machine_code()` | `XXXX-XXXX-XXXX-XXXX` | کد سخت‌افزاری این ماشین — همان که مشتری برایتان می‌فرستد |
| `activate(serial_text)` | `ActivationResult(ok, state, message)` | تأیید امضا + قفل سخت‌افزار + نوشتن لایسنس محلی |
| `verify_installed(degraded=False)` | `LicenseStatus(state, message, payload, seconds_left)` | تأیید بی‌صدا در هر اجرا |
| `make_deactivation_request(path)` | `Path` | درخواست انتقال به ماشین جدید (امضاشده، جعلی‌ناپذیر) |
| `deactivate_with_permit(permit_path)` | `(bool, str)` | ابطال محلی با مجوز فروشنده |

### `LicenseState` (حالت‌های نهایی | terminal states)

`VALID` · `MISSING` · `INVALID` · `EXPIRED` · `WRONG_MACHINE` · `REVOKED`
· `CLOCK_TAMPERED` · `DAMAGED` · `DEGRADED`

---

## 6) چرخه کاری فروشنده | Vendor workflow

**فارسی:** روزمره‌ترین کار شما با Protector:

1. مشتری برنامه را اجرا می‌کند → کد ۱۶ کاراکتری `XXXX-XXXX-XXXX-XXXX` را از
   پنجره فعال‌سازی (یا فایل `fingerprint.txt`) برایتان می‌فرستد.
2. Protector → **Fingerprint Reader** → کد را paste/validate کنید.
3. دکمه **Generate serial for this machine** → صفحه Generate → نام مشتری،
   مدت (۳۰ روز تا Lifetime یا تاریخ دلخواه روی تقویم هجری شمسی)، feature
   flags → **Issue serial key**.
4. سریال را Copy کنید و با هر کانالی (ایمیل، پیام‌رسان…) بفرستید. چون امضاشده
   و قفل‌شده است، انتقالش از اینترنت خطری ندارد.
5. مشتری پیست می‌کند → Activate → تمام.

مدیریت بعدی در **Serial Manager**: جست‌وجو، تمدید (Extend)، ابطال (Revoke →
خروجی `blacklist.sec` امضاشده که در پوشه ProgramData مشتری می‌گذارید)، و
انتقال ماشین (Deactivation request → Permit).

**English:** customer sends the machine code → validate in Fingerprint
Reader → Generate → Issue → deliver the serial through any channel →
customer activates. Manage later in Serial Manager (extend / revoke /
transfer permit).

---

## 7) چک‌لیست تست قبل از انتشار | Pre-release test checklist

- [ ] `SC_DEV` **ست نیست** در محیط بیلد (کد با `os.environ.get("SC_DEV")` چک کنید)
- [ ] `python protector/tools/build_strings_table.py` اجرا شده
- [ ] `python protector/tools/make_integrity_manifest.py` اجرا شده
- [ ] EXE بدون لایسنس → پنجره فعال‌سازی با کد ماشین می‌آید
- [ ] سریال معتبر → فعال می‌شود؛ اجرای مجدد → بدون پنجره، مستقیم برنامه
- [ ] سریالِ ماشین دیگر → «bound to another computer»
- [ ] ساعت سیستم +۲ سال جلو / عقب → صفحه انقضا / clock-tamper
- [ ] `tests/e2e_licensing.py` → ۲۸/۲۸ PASS (روی کپی SDK خودتان هم قابل اجراست)

---

## 8) سؤالات پرتکرار | FAQ

**ماشین مشتری سوخت / تعویض شد چه؟ | Customer's machine died / was replaced?**
فارسی: تا `fingerprint_tolerance` قطعه عوض شود مشکلی نیست. بیشتر از آن یا
تعویض کامل ماشین → مشتری از برنامه **Deactivation request** بگیرد و برایتان
بفرستد؛ شما در Protector مجوز انتقال صادر می‌کنید؛ مشتری Permit را import
می‌کند و با سریال جدید روی ماشین جدید فعال می‌شود.
English: within `fingerprint_tolerance` component swaps are fine. For a
full machine change: customer exports a deactivation request → you issue
a transfer permit → new serial activates on the new machine.

**مشتری فایل لایسنس را پاک کرد. | Customer deleted the license file.**
فارسی: فقط از Serial Manager دوباره سریال را تحویل بدهید (یا همان سریال —
هزینه‌ای ندارد چون همه‌چیز امضاشده است).
English: simply re-deliver the same serial — everything re-verifies from
scratch.

**کلید خصوصی لو رفت / می‌خواهم عوض کنم. | Private key leaked / rotation?**
فارسی: در Protector کلید جدید بسازید → `pubkey_blob.py` جدید (مرحله ②) →
بیلد جدید → از آن به بعد سریال‌های قدیمی در بیلد جدید رد می‌شوند (رفتار
مورد انتظار). با ابطال (blacklist) سریال‌های مشکوک را جمع کنید.
English: new keystore → new `pubkey_blob.py` → new build. Old serials stop
verifying against the new build; blacklist the suspicious ones.

**مجوز استفاده | License note:** Doran (Jalali calendar core, MIT © Doran
Contributors) is ported in `protector/core/jalali.py`; Vazirmatn font is
SIL OFL 1.1. هر دو برای استفاده تجاری آزادند / both free for commercial use.

---

*برای مدل تهدید صادقانه، لایه‌های محافظتی و محدودیت‌ها: `docs/SECURITY.md` —
For the honest threat model and protection layers: `docs/SECURITY.md`.
جریان گام‌به‌گام سمت فروشنده: `docs/WORKFLOW.md`.*
