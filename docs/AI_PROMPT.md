# SecureCode — پرامپت آماده برای هوش مصنوعی | Ready-to-use AI prompts

> **فارسی:** این فایل دو پرامپت آماده دارد (انگلیسی + فارسی) که می‌توانید
> عیناً کپی کنید و به هر دستیار هوش مصنوعی (Claude، ChatGPT، Cursor،
> Copilot، …) بدهید تا سیستم فعال‌سازی سریال SecureCode را به برنامه شما
> یکپارچه کند. پرامپت را کامل بفرستید — عمداً همه جزئیات لازم داخلش است تا
> AI هیچ‌چیز را از خودش حدس نزند.
>
> **English:** two copy-paste prompts (English + Persian) to hand to any AI
> coding assistant so it integrates the SecureCode serial-activation system
> into your application. Send the prompt verbatim — it deliberately contains
> every fact the AI needs, so it invents nothing.

---

## 🇬🇧 English prompt (copy everything inside the fence)

```text
You are helping me integrate an EXISTING offline serial-activation system
called SecureCode into my Python application. IMPORTANT: do NOT invent a
new licensing scheme, do NOT add network activation, do NOT create your own
crypto. The system already exists and is complete — your ONLY job is to
wire my application to it, following the rules below exactly.

## What I have
1. A vendor-side GUI app called "protector" that issues hardware-locked,
   Ed25519-signed serial keys (Base32 text, ~500-600 chars, grouped in
   5-char blocks). Serials are bound to a 16-char machine code of the
   form XXXX-XXXX-XXXX-XXXX.
2. A client-side SDK package `protection/` (plus a `shared/` package it
   depends on) that I have already copied into my project at:
   <PATH_TO_MY_APP/protection> and <PATH_TO_MY_APP/shared>.
   It contains these modules (do not reimplement them):
   - anti_debug.py, clock_guard.py, integrity.py, fingerprint.py
   - license_client.py  -> LicenseClient, LicenseState, LicenseStatus,
     ActivationResult
   - pubkey_blob.py     -> my embedded Ed25519 public key (already generated)
   - __init__.py        -> ProtectionConfig, ProtectionRuntime,
     LicenseClient, LicenseState, machine_code
3. My application is a PySide6 desktop app whose entry point is
   <PATH_TO_MY_APP/main.py> and my main window class is < MyClass >.

## The exact integration contract
1. In my entry point, AFTER logging setup but BEFORE creating any window or
   importing heavy modules:
     config = ProtectionConfig(
         product_id="<MY_PRODUCT_UUID>",      # from protector Settings->Products
         product_name="<MyApp>",              # data dir %PROGRAMDATA%\Company\MyApp
         company_name="<MyCompany>",
         vm_detection_enabled=False,
     )
     runtime = ProtectionRuntime.bootstrap(config)   # anti-debug + integrity
2. Then:
     client = LicenseClient(config, clock_guard=runtime.clock_guard)
     status = client.verify_installed(degraded=runtime.degraded or False)
3. Branch on status.state (LicenseState enum with values: VALID, MISSING,
   INVALID, EXPIRED, WRONG_MACHINE, REVOKED, CLOCK_TAMPERED, DAMAGED,
   DEGRADED):
   - VALID -> launch my main window, passing status.payload (it has
     .customer, .expires_at, .is_lifetime, .feature_flags dict,
     .seconds_left). Use payload.feature_flags to gate optional modules:
     e.g. only enable the "pro" module when feature_flags.get("pro").
   - MISSING -> show an activation dialog containing:
     a) the machine code (client.machine_code()) with a "copy" button and a
        "save fingerprint.txt" button,
     b) a multi-line text box for pasting the serial,
     c) an Activate button that calls client.activate(serial_text) and
        treats result.ok == True as success (on success close the dialog
        and re-run verify_installed in a retry loop; on failure show
        result.message).
   - any other state -> show a professional license-error screen with
     status.message, the machine code (for support), and Exit (+ optional
     Retry that re-enters the verification loop).
4. Wrap the three states in ONE retry loop so Retry/activation falls back
   into verification.
5. Style the dialogs dark-professional, keep all user-facing strings in
   English, add a short Persian subtitle line under each title (I have the
   Vazirmatn font available; set font-family 'Vazirmatn' for Persian text).

## Hard rules
- Never disable or bypass anti_debug / integrity / clock_guard.
- bootstrap() must be the FIRST real statement of main() (after logging).
- Never reference dev_mode=True or the SC_DEV environment variable in
  shipped code paths.
- Do not store or log the serial or any key material; logging gets ids and
  states only.
- The license file location is decided by the SDK (license_path()) — do not
  move or rename it.
- If you need an async UI action (verification on a background thread),
  keep ALL widget updates on the GUI thread (queued signal hop), never
  touch widgets from a worker thread.

## Deliverables
1. The new entry-point flow for <PATH_TO_MY_APP/main.py>.
2. An activation dialog class (PySide6) implementing the contract above.
3. A license-error dialog class.
4. A short list of anything I must fill in myself (placeholders like
   product UUID, paths, class names).

Ask me before doing anything outside this contract.
```

---

## 🇮🇷 پرامپت فارسی (همه‌چیز داخل کادر را کپی کنید)

```text
می‌خواهم سیستم فعال‌سازیِ آفلاینِ موجودی به نام SecureCode را به برنامه
پایتونم وصل کنی. نکته مهم: سیستم از قبل کامل است — هیچ طرح لایسنسی
جدید نساز، فعال‌سازی اینترنتی اضافه نکن، رمزنگاری خودت را پیاده نکن.
تنها کار توئیست که برنامه مرا مطابق قرارداد زیر دقیقاً به این سیستم
وصل کنی.

## آنچه دارم
۱) برنامه فروشنده (پروتکتور) که سریال‌های امضاشده با Ed25519 و قفل‌شده به
   سخت‌افزار صادر می‌کند (متن Base32 حدود ۵۰۰ تا ۶۰۰ کاراکتر، گروه‌های
   ۵تایی). هر سریال به کد ماشین ۱۶ کاراکری به شکل XXXX-XXXX-XXXX-XXXX
   گره خورده است.
۲) بسته SDK سمت مشتری به نام protection (همراه بسته shared که به آن
   وابسته است) که قبلاً داخل پروژه‌ام کپی کرده‌ام در:
   <مسیر_پروژه_من/protection> و <مسیر_پروژه_من/shared>
   داخلش این ماژول‌ها هست (بازنویسی‌شان نکن):
   - anti_debug.py, clock_guard.py, integrity.py, fingerprint.py
   - license_client.py  -> کلاس‌های LicenseClient و LicenseState و
     LicenseStatus و ActivationResult
   - pubkey_blob.py     -> کلید عمومی Ed25519 من (از قبل تولید شده)
   - __init__.py        -> ProtectionConfig و ProtectionRuntime و
     LicenseClient و LicenseState و machine_code
۳) برنامه من یک اپ دسکتاپ PySide6 است؛ نقطه ورودش
   <مسیر_پروژه_من/main.py> و پنجره اصلی‌ام کلاس <MyClass> است.

## قرارداد دقیق یکپارچه‌سازی
۱) در نقطه ورود، بعد از راه‌اندازی لاگ ولی قبل از ساختن هر پنجره یا
   import سنگین:
     config = ProtectionConfig(
         product_id="<UUID محصول من>",   # از Protector → Settings → Products
         product_name="<MyApp>",
         company_name="<MyCompany>",
         vm_detection_enabled=False,
     )
     runtime = ProtectionRuntime.bootstrap(config)   # آنتی‌دیباگ + یکپارچگی
۲) بعد:
     client = LicenseClient(config, clock_guard=runtime.clock_guard)
     status = client.verify_installed(degraded=runtime.degraded or False)
۳) با status.state شاخه بزن (مقادیر LicenseState عبارت‌اند از: VALID،
   MISSING، INVALID، EXPIRED، WRONG_MACHINE، REVOKED، CLOCK_TAMPERED،
   DAMAGED، DEGRADED):
   - VALID → پنجره اصلی برنامه را اجرا کن و status.payload را به آن بده
     (دارد: .customer و .expires_at و .is_lifetime و دیکشنری
     .feature_flags و .seconds_left). برای قفل ماژول‌های اختیاری از
     feature_flags استفاده کن؛ مثلاً ماژول «pro» فقط وقتی فعال شود که
     feature_flags.get("pro") درست باشد.
   - MISSING → پنجره فعال‌سازی نشان بده که شامل:
     أ) کد ماشین (client.machine_code()) با دکمه «کپی» و دکمه
        «ذخیره fingerprint.txt»،
     ب) یک کادر متن چندخطی برای پیست کردن سریال،
     ج) دکمه Activate که client.activate(serial_text) را صدا بزند؛
        اگر result.ok == True بود پنجره بسته شود و حلقه تأیید از اول
        اجرا شود؛ اگر نه، result.message را نشان بده.
   - بقیه حالت‌ها → صفحه خطای حرفه‌ای لایسنس با status.message و کد
     ماشین (برای پشتیبانی) و دکمه خروج (+ دکمه «تلاش دوباره» که به
     حلقه تأیید برمی‌گردد).
۴) هر سه حالت را داخل یک حلقه retry واحد بپیچ تا «تلاش دوباره» و
   فعال‌سازی هر دو به تأیید برگردند.
۵) دیالوگ‌ها را حرفه‌ای و تیره طراحی کن؛ متن‌های اصلی انگلیسی و زیر
   هر تیتر یک زیرنویس فارسی کوتاه (فونت وزیرمتن «Vazirmatn» برای متن
   فارسی ست کن).

## قواعد سخت‌گیرانه
- آنتی‌دیباگ، چک یکپارچگی و clock_guard را هرگز غیرفعال یا دور نزن.
- bootstrap() باید اولین دستور واقعی main() باشد (بعد از لاگ).
- به dev_mode=True یا متغیر محیطی SC_DEV در کد نهایی هیچ ارجاعی نده.
- سریال و هر ماده کلیدی را هیچ‌جا ذخیره یا لاگ نکن؛ در لاگ فقط شناسه
  و وضعیت.
- محل فایل لایسنس را SDK تعیین می‌کند (license_path()) — جابه‌جایش نکن.
- اگر کاری در پس‌زمینه (thread) لازم شد، هر تغییر widget فقط روی
  thread اصلی GUI انجام شود (اتصال سیگنال صف‌شده)، هرگز از thread
  کارگر به widget دست نزن.

## خروجی‌های مورد انتظار
۱) جریان جدید نقطه ورود برای <مسیر_پروژه_من/main.py>.
۲) کلاس پنجره فعال‌سازی (PySide6) مطابق قرارداد بالا.
۳) کلاس صفحه خطای لایسنس.
۴) فهرست کوتاه چیزهایی که خودم باید پر کنم (UUID محصول، مسیرها،
   نام کلاس‌ها و...).

قبل از هر کاری خارج از این قرارداد، از من بپرس.
```

---

## 💡 نکته‌ها | Tips

- **فارسی:** جای‌نگهدارهای داخل `<>` را قبل از ارسال پر کنید (UUID محصول از
  Protector → Settings → Products، مسیر واقعی پروژه، نام کلاس پنجره اصلی).
  بعد از تحویل کد AI، چک‌لیست بخش ۷ `docs/INTEGRATION.md` را اجرا کنید.
- **English:** fill every `<placeholder>` before sending (product UUID from
  Protector → Settings → Products, real paths, your window class). After the
  AI delivers code, run the checklist in section 7 of `docs/INTEGRATION.md`.
