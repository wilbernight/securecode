"""
protector.ui.i18n — UI language (English / Persian) with a one-click switch.

Every user-visible string is written in English in the source and passed
through ``tr()``. In Persian mode ``tr()`` returns the translation from
``FA`` (falling back to the English text when an entry is missing), the
application switches to right-to-left layout and the Vazirmatn font leads
the font stack. Changing the language rebuilds the shell window, so no
widget has to support live re-translation.

    tr("Dashboard")             -> "داشبورد" (fa) / "Dashboard" (en)
    tr("{n} serials", n=3)      -> formatted after translation
    num(1234)                   -> "۱٬۲۳۴" (fa) / "1,234" (en)
"""

from __future__ import annotations

from PySide6.QtCore import Qt

LANGUAGES: tuple[tuple[str, str], ...] = (("en", "English"), ("fa", "فارسی"))

_lang = "en"


def language() -> str:
    return _lang


def set_language(code: str) -> None:
    global _lang
    _lang = "fa" if code == "fa" else "en"


def is_rtl() -> bool:
    return _lang == "fa"


def direction() -> Qt.LayoutDirection:
    return Qt.RightToLeft if is_rtl() else Qt.LeftToRight


def tr(text: str, **kwargs) -> str:
    """Translate an English UI string to the active language."""
    out = FA.get(text, text) if _lang == "fa" else text
    if kwargs:
        out = out.format(**{k: (num(v) if isinstance(v, int) and _lang == "fa" else v)
                            for k, v in kwargs.items()})
    return out


_FA_DIGITS = str.maketrans("0123456789,", "۰۱۲۳۴۵۶۷۸۹٬")


def digits(text: str) -> str:
    """Persian digits in Persian mode (dates, counters)."""
    return text.translate(_FA_DIGITS) if _lang == "fa" else text


def num(value: int) -> str:
    return digits(f"{value:,}")


def ltr(text: str) -> str:
    """Isolate a Latin run (date, key id, path) inside Persian text so the
    bidi algorithm cannot reorder it (2026-10-26 must not become 26-10-2026)."""
    return f"\u2066{text}\u2069" if _lang == "fa" else text


def arrow() -> str:
    """Icon name of a "forward" arrow in the current reading direction."""
    return "arrow-left" if _lang == "fa" else "arrow-right"


#: English -> Persian. Keys are the exact English source strings.
FA: dict[str, str] = {
    # --- shell -------------------------------------------------------------
    "SecureCode Protector": "محافظ SecureCode",
    "Protector · licensing console": "محافظ · کنسول مجوزدهی",
    "OVERVIEW": "نمای کلی",
    "LICENSING": "مجوزها",
    "TOOLS": "ابزارها",
    "GENERAL": "عمومی",
    "Dashboard": "داشبورد",
    "Generate Serial": "صدور سریال",
    "Serial Manager": "مدیریت سریال‌ها",
    "Fingerprint Reader": "خواندن اثر انگشت",
    "Build Protection": "ساخت نسخه محافظت‌شده",
    "Settings": "تنظیمات",
    "Live counters and issuance activity": "شمارنده‌های زنده و فعالیت صدور سریال",
    "Issue a new hardware-locked serial key": "صدور سریال جدیدِ قفل‌شده به سخت‌افزار",
    "All issued serials: search, revoke, extend, export":
        "همه سریال‌ها: جست‌وجو، ابطال، تمدید، خروجی",
    "Validate a customer machine code / export file":
        "بررسی کد ماشین مشتری / فایل خروجی",
    "Wrap a Python project with the protection SDK + Nuitka":
        "بسته‌بندی پروژه پایتون با SDK محافظت + Nuitka",
    "Keystore, products, theme, backups": "کلید امضا، محصولات، تم، پشتیبان‌ها",
    "Fully offline": "کاملاً آفلاین",
    "No network access · v1.0.0": "بدون دسترسی شبکه · نسخه ۱٫۰٫۰",
    "100% offline": "۱۰۰٪ آفلاین",
    "Signing key {key}": "کلید امضا {key}",
    "key · {key}": "کلید · {key}",
    "Toggle dark / light theme (Ctrl+T)": "تغییر تم روشن / تیره (Ctrl+T)",
    "Switch language — فارسی / English (Ctrl+L)": "تغییر زبان — English / فارسی (Ctrl+L)",
    "Minimize": "کوچک کردن",
    "Maximize / restore": "بزرگ کردن / بازگردانی",
    "Close": "بستن",
    "This application never performs network access.":
        "این برنامه هرگز به شبکه متصل نمی‌شود.",
    "Public key fingerprint of the active Ed25519 signing key. It must match the key compiled into your protected EXE.":
        "اثر انگشت کلید عمومی Ed25519 فعال — باید با کلید داخل EXE محافظت‌شده یکسان باشد.",
    "Working…": "در حال انجام…",
    # --- common ------------------------------------------------------------
    "Refresh": "بازخوانی",
    "Copy": "کپی",
    "Copied": "کپی شد",
    "Saved": "ذخیره شد",
    "Add": "افزودن",
    "Remove": "حذف",
    "Delete": "حذف",
    "Clear": "پاک کردن",
    "Cancel": "انصراف",
    "(unnamed)": "(بی‌نام)",
    "Active": "فعال",
    "Lifetime": "همیشگی",
    "Expiring": "در حال انقضا",
    "Expired": "منقضی",
    "Revoked": "ابطال‌شده",
    "lifetime": "همیشگی",
    "No selection": "موردی انتخاب نشده",
    "Select a serial row first.": "ابتدا یک سریال را انتخاب کنید.",
    "Invalid file": "فایل نامعتبر",
    # --- dashboard -----------------------------------------------------------
    "Licensing activity at a glance — counters refresh on every visit.":
        "نمای کلی فعالیت مجوزدهی — شمارنده‌ها با هر بازدید به‌روز می‌شوند.",
    "New serial": "سریال جدید",
    "Total serials": "کل سریال‌ها",
    "Expiring < 30 days": "انقضا تا ۳۰ روز",
    "{pct}% of total": "{pct}٪ از کل",
    "Serials issued per month": "سریال‌های صادرشده در هر ماه",
    "Monthly issuance over the last year": "صدور ماهانه در یک سال گذشته",
    "{n} in 12 months": "{n} در ۱۲ ماه",
    "Recent activity": "فعالیت‌های اخیر",
    "Latest issued serials": "آخرین سریال‌های صادرشده",
    "View all": "مشاهده همه",
    "No serials yet": "هنوز سریالی صادر نشده",
    "Issued keys show up here.": "سریال‌های صادرشده اینجا نمایش داده می‌شوند.",
    "Loading dashboard…": "در حال بارگذاری داشبورد…",
    "Reload counters, chart and recent activity (F5)":
        "بارگذاری دوباره شمارنده‌ها، نمودار و فعالیت‌ها (F5)",
    "Issue a new serial key (Ctrl+G)": "صدور سریال جدید (Ctrl+G)",
    "Open the Serial Manager (Ctrl+3)": "باز کردن مدیریت سریال‌ها (Ctrl+3)",
    "No serials issued yet — generate your first key to see activity.":
        "هنوز سریالی صادر نشده — اولین کلید را بسازید تا فعالیت نمایش داده شود.",
    # --- generate ------------------------------------------------------------
    "Generate serial": "صدور سریال",
    "One serial = one machine. The key never leaves this app unsigned.":
        "یک سریال = یک ماشین. کلید بدون امضا هرگز از این برنامه خارج نمی‌شود.",
    "Customer & product": "مشتری و محصول",
    "Who the key is for and what it unlocks": "سریال برای چه کسی است و چه چیزی را باز می‌کند",
    "Customer (optional)": "مشتری (اختیاری)",
    "Product": "محصول",
    "e.g. Acme Corp / john@example.com": "مثلاً شرکت آلفا / ali@example.com",
    "Target machine": "ماشین مقصد",
    "Hardware fingerprint exported by the customer": "اثر انگشت سخت‌افزاری ارسال‌شده توسط مشتری",
    "Machine code": "کد ماشین",
    "Load file…": "بارگذاری فایل…",
    "Paste or load a fingerprint code.": "کد اثر انگشت را بچسبانید یا از فایل بارگذاری کنید.",
    "Invalid code — {msg}": "کد نامعتبر — {msg}",
    "Valid machine code ({info})": "کد ماشین معتبر ({info})",
    "Validity": "مدت اعتبار",
    "The client blocks after this date": "برنامه مشتری پس از این تاریخ قفل می‌شود",
    "Duration": "مدت",
    "30 days": "۳۰ روز",
    "6 months": "۶ ماه",
    "1 year": "۱ سال",
    "2 years": "۲ سال",
    "Custom date…": "تاریخ دلخواه…",
    "Never expires": "بدون انقضا",
    "Expires on {date}": "انقضا در {date}",
    "Advanced options": "گزینه‌های پیشرفته",
    "Tolerance, clock rollbacks, feature flags": "تحمل سخت‌افزار، عقب‌گرد ساعت، قابلیت‌ها",
    "Fingerprint tolerance": "تحمل اثر انگشت",
    "Components allowed to change (1 recommended)": "تعداد قطعات مجاز به تغییر (۱ توصیه می‌شود)",
    "Rollback allowance": "مجوز عقب‌گرد ساعت",
    "Clock rollbacks tolerated (24h grace each)": "تعداد عقب‌گردهای مجاز ساعت (هر بار ۲۴ ساعت)",
    "Feature flags": "قابلیت‌ها (Feature flags)",
    "Embedded in the payload; the client enables modules from them.":
        "داخل سریال قرار می‌گیرد؛ برنامه مشتری ماژول‌ها را بر اساس آن فعال می‌کند.",
    "MODULE": "ماژول",
    "ENABLED": "فعال",
    "Add a feature flag": "افزودن قابلیت",
    "Remove the selected flag rows": "حذف قابلیت‌های انتخاب‌شده",
    "Notes": "یادداشت",
    "Internal notes stored encrypted in the database (never leaves this app).":
        "یادداشت داخلی، رمزنگاری‌شده در پایگاه داده (هرگز از برنامه خارج نمی‌شود).",
    "Signed with Ed25519 key {key}": "امضا با کلید Ed25519 ‏{key}",
    "Issue serial key": "صدور سریال",
    "Result": "نتیجه",
    "Deliver the serial through any channel": "سریال را از هر راهی به مشتری تحویل دهید",
    "Waiting": "در انتظار",
    "Signed": "امضا شد",
    "Verified": "تأیید شد",
    "Invalid": "نامعتبر",
    "The generated serial key appears here — copy or save it, then deliver it to the customer.":
        "سریال تولیدشده اینجا نمایش داده می‌شود — آن را کپی یا ذخیره کنید و به مشتری بدهید.",
    "Record": "رکورد",
    "Customer": "مشتری",
    "Expires": "انقضا",
    "Expires (Solar Hijri)": "انقضا (هجری شمسی)",
    "Nonce": "شناسه یکتا (Nonce)",
    "Save .lic": "ذخیره ‎.lic",
    "Verify": "بررسی امضا",
    "Copy the serial to the clipboard.": "کپی سریال در کلیپ‌بورد.",
    "Save the serial as a .lic text file for delivery.": "ذخیره سریال به‌صورت فایل ‎.lic برای تحویل.",
    "Re-parse and re-verify the signature — exactly what the client does.":
        "بررسی دوباره امضا — دقیقاً همان کاری که برنامه مشتری انجام می‌دهد.",
    "The serial is hardware-locked to the machine code and valid for the selected period. It works fully offline — no activation server is ever contacted.":
        "سریال به کد ماشین قفل است و در مدت انتخاب‌شده معتبر است. کاملاً آفلاین کار می‌کند — هیچ سرور فعال‌سازی‌ای لازم نیست.",
    "Signing serial…": "در حال امضای سریال…",
    "Verifying…": "در حال بررسی…",
    "Serial issued": "سریال صادر شد",
    "Record #{id} stored in the encrypted database.": "رکورد #{id} در پایگاه داده رمزنگاری‌شده ذخیره شد.",
    "Signature valid": "امضا معتبر است",
    "The serial verifies against the active public key.": "سریال با کلید عمومی فعال تأیید شد.",
    "Verification failed": "بررسی ناموفق بود",
    "Invalid fingerprint": "اثر انگشت نامعتبر",
    "Paste a valid 16-character machine code first.": "ابتدا یک کد ماشین ۱۶ کاراکتری معتبر وارد کنید.",
    "No product": "محصولی وجود ندارد",
    "Add a product in Settings first.": "ابتدا در تنظیمات یک محصول اضافه کنید.",
    "Invalid date": "تاریخ نامعتبر",
    "Custom expiry must be in the future.": "تاریخ انقضا باید در آینده باشد.",
    "Serial copied to clipboard.": "سریال در کلیپ‌بورد کپی شد.",
    "Add feature flag": "افزودن قابلیت",
    "Module/feature name (e.g. 'pro_module', 'export_pdf'):": "نام ماژول/قابلیت (مثلاً pro_module):",
    "Sign the payload with the keystore's Ed25519 key (Ctrl+G).": "امضای سریال با کلید Ed25519 (Ctrl+G).",
    "Read a fingerprint.txt exported by the client app.": "خواندن فایل fingerprint.txt خروجی برنامه مشتری.",
    # --- manager -------------------------------------------------------------
    "Every key ever issued — stored AES-256-GCM encrypted on this machine.":
        "همه سریال‌های صادرشده — با AES-256-GCM روی همین سیستم رمزنگاری شده‌اند.",
    "Export signed blacklist": "خروجی لیست سیاه امضاشده",
    "Search customer, machine code or serial…": "جست‌وجوی مشتری، کد ماشین یا سریال…",
    "All statuses": "همه وضعیت‌ها",
    "All products": "همه محصولات",
    "STATUS": "وضعیت",
    "CUSTOMER": "مشتری",
    "PRODUCT": "محصول",
    "MACHINE CODE": "کد ماشین",
    "ISSUED": "صدور",
    "EXPIRES": "انقضا",
    "DAYS": "روز",
    "NONCE": "شناسه",
    "{n} serials": "{n} سریال",
    "Revoke / Restore": "ابطال / بازگردانی",
    "Extend…": "تمدید…",
    "Transfer permit…": "مجوز انتقال…",
    "Copy serial": "کپی سریال",
    "Export .lic": "خروجی ‎.lic",
    "No serials match": "سریالی پیدا نشد",
    "Try another search or filter, or issue a new serial.":
        "جست‌وجو یا فیلتر دیگری را امتحان کنید یا سریال جدیدی صادر کنید.",
    "Loading serials…": "در حال بارگذاری سریال‌ها…",
    "Double-click a row for details": "برای جزئیات روی ردیف دوبار کلیک کنید",
    "Serial key": "کلید سریال",
    "Serial key copied.": "سریال کپی شد.",
    "Nothing to export": "چیزی برای خروجی نیست",
    "No serial is currently revoked.": "در حال حاضر هیچ سریالی ابطال نشده است.",
    "Blacklist exported": "لیست سیاه ذخیره شد",
    "Serial extended": "سریال تمدید شد",
    "The re-signed serial is in your clipboard — deliver it to the customer.":
        "سریال جدید در کلیپ‌بورد است — آن را به مشتری تحویل دهید.",
    "Serial revoked": "سریال ابطال شد",
    "Serial restored": "سریال بازگردانی شد",
    "Remember to export and distribute the updated blacklist.":
        "فراموش نکنید لیست سیاه جدید را خروجی گرفته و توزیع کنید.",
    "Permit saved": "مجوز ذخیره شد",
    "Deleted": "حذف شد",
    "Exported": "ذخیره شد",
    "Tolerance / rollbacks": "تحمل / عقب‌گرد",
    "Issued": "تاریخ صدور",
    "Status": "وضعیت",
    # --- fingerprint -----------------------------------------------------------
    "Customers send you a machine code — validate it here, then issue a serial locked to exactly that machine.":
        "مشتری کد ماشین را برایتان می‌فرستد — اینجا بررسی‌اش کنید و سریالی مخصوص همان ماشین صادر کنید.",
    "Machine code input": "ورود کد ماشین",
    "Paste the code or the whole fingerprint.txt export": "کد یا کل محتوای فایل fingerprint.txt را بچسبانید",
    "Paste the 16-character machine code (XXXX-XXXX-XXXX-XXXX)\n…or the complete contents of their fingerprint.txt export.":
        "کد ماشین ۱۶ کاراکتری را بچسبانید (XXXX-XXXX-XXXX-XXXX)\n…یا کل محتوای فایل fingerprint.txt مشتری را.",
    "Open fingerprint file…": "باز کردن فایل اثر انگشت…",
    "Validate": "بررسی",
    "Analysis": "تحلیل",
    "Recorded hardware components": "قطعات سخت‌افزاری ثبت‌شده",
    "Nothing validated yet.": "هنوز چیزی بررسی نشده است.",
    "Paste a machine code or load a fingerprint file first.":
        "ابتدا کد ماشین را وارد یا فایل اثر انگشت را بارگذاری کنید.",
    "Valid machine code": "کد ماشین معتبر",
    "CPU (ProcessorId)": "پردازنده (ProcessorId)",
    "Motherboard serial": "سریال مادربرد",
    "Primary disk serial": "سریال دیسک اصلی",
    "Machine GUID (registry)": "GUID ماشین (رجیستری)",
    # --- component labels of the mobile/desktop platform SDKs ----------------
    "Widevine DRM device ID": "شناسه Widevine دستگاه",
    "SSAID (Settings.Secure.ANDROID_ID)": "SSAID (شناسه اندروید)",
    "Keystore key digest (optional)": "هش کلید Keystore (اختیاری)",
    "Keychain UUID (vendor-persistent)": "UUID کی‌چین (ماندگار بین نصب‌ها)",
    "IDFV (identifierForVendor)": "IDFV (شناسه فروشنده)",
    "MAC address (en0)": "آدرس MAC (en0)",
    "Mac serial (IOPlatformSerialNumber)": "سریال مک (IOPlatformSerialNumber)",
    "IOPlatformUUID": "IOPlatformUUID (شناسه سخت‌افزاری)",
    "Windows": "ویندوز",
    "Android": "اندروید",
    "Recorded": "ثبت شده",
    "Not recorded": "ثبت نشده",
    "Missing components lower the fingerprint's stability — consider tolerance ≥ 1.":
        "نبود قطعات پایداری اثر انگشت را کم می‌کند — تحمل ≥ ۱ را در نظر بگیرید.",
    "Generate serial for this machine": "صدور سریال برای این ماشین",
    "How it works": "روند کار",
    "Customer runs the app and exports the machine code.":
        "مشتری برنامه را اجرا و کد ماشین را خروجی می‌گیرد.",
    "You validate the code here.": "شما کد را اینجا بررسی می‌کنید.",
    "Issue a serial locked to that machine and send it back.":
        "سریالِ قفل‌شده به همان ماشین را صادر و برای مشتری ارسال می‌کنید.",
    # --- build ---------------------------------------------------------------
    "Wrap your Python project with the offline licensing SDK and produce the Nuitka build script — no placeholders, fully automated.":
        "پروژه پایتون خود را با SDK مجوزدهی آفلاین بسته‌بندی و اسکریپت ساخت Nuitka را تولید کنید — کاملاً خودکار.",
    "Project": "پروژه",
    "The folder containing your Python entry point": "پوشه‌ای که فایل اصلی پایتون شما در آن است",
    "No project selected": "پروژه‌ای انتخاب نشده",
    "Choose folder…": "انتخاب پوشه…",
    "Analyze project": "تحلیل پروژه",
    "Scan the project and write protection_report.txt": "اسکن پروژه و نوشتن protection_report.txt",
    "Inject SDK": "تزریق SDK",
    "Copy shared/ + protection/ and show the bootstrap": "کپی shared/ و protection/ و نمایش کد راه‌انداز",
    "Generate build.bat": "ساخت build.bat",
    "Write the exact Nuitka onefile command": "نوشتن دستور دقیق Nuitka برای فایل تکی",
    "Run": "اجرا",
    "Output": "خروجی",
    "Report, bootstrap snippet and build command": "گزارش، کد راه‌انداز و دستور ساخت",
    "The generated protection_report.txt / bootstrap snippet / build command appear here.":
        "گزارش protection_report.txt، کد راه‌انداز و دستور ساخت اینجا نمایش داده می‌شوند.",
    "Step {n}": "مرحله {n}",
    "No project": "پروژه‌ای انتخاب نشده",
    "Choose a project folder first.": "ابتدا پوشه پروژه را انتخاب کنید.",
    "Report written": "گزارش نوشته شد",
    "SDK injected": "SDK اضافه شد",
    "build.bat generated": "build.bat ساخته شد",
    "Analyzing project…": "در حال تحلیل پروژه…",
    "Copying SDK…": "در حال کپی SDK…",
    "Generating build.bat…": "در حال ساخت build.bat…",
    # --- settings -------------------------------------------------------------
    "Keystore, product catalog, appearance and data backups.":
        "کلید امضا، فهرست محصولات، ظاهر و پشتیبان‌گیری.",
    "Appearance": "ظاهر",
    "Theme, accent color and language": "تم، رنگ اصلی و زبان",
    "Theme": "تم",
    "Light": "روشن",
    "Dark": "تیره",
    "Accent color": "رنگ اصلی",
    "Language": "زبان",
    "Signing keystore": "کلید امضا",
    "The Ed25519 key that signs every serial": "کلید Ed25519 که همه سریال‌ها را امضا می‌کند",
    "Active signing key": "کلید امضای فعال",
    "Change passphrase…": "تغییر رمز عبور…",
    "Export private key…": "خروجی کلید خصوصی…",
    "Import key export…": "ورود کلید…",
    "Regenerate keypair": "ساخت جفت‌کلید جدید",
    "Import shipped demo keypair…": "ورود جفت‌کلید دمو…",
    "Product catalog": "فهرست محصولات",
    "Products the Generate page can issue serials for": "محصولاتی که برایشان سریال صادر می‌شود",
    "NAME": "نام",
    "PRODUCT ID (UUID)": "شناسه محصول (UUID)",
    "VERSION": "نسخه",
    "Product name (e.g. MyTool Pro)": "نام محصول (مثلاً MyTool Pro)",
    "Version (e.g. 1.0)": "نسخه (مثلاً 1.0)",
    "Add product": "افزودن محصول",
    "Click to copy the product UUID.": "برای کپی کردن UUID محصول کلیک کنید.",
    "Product UUID copied to clipboard.": "UUID محصول در کلیپ‌بورد کپی شد.",
    "Wrong backup passphrase — this is the passphrase you chose when CREATING the backup, not the keystore passphrase.":
        "رمز عبور بکاپ اشتباه است — این همان رمزی است که موقع «ساخت بکاپ» انتخاب کردید، نه رمز keystore.",
    "This file is not a valid SecureCode backup.":
        "این فایل یک بکاپ معتبر SecureCode نیست.",
    "No new records — this backup's records are already in the database.":
        "رکورد جدیدی وارد نشد — رکوردهای این بکاپ از قبل در دیتابیس هستند.",
    "The product UUID must match the product_id compiled into that product's EXE (its protection config).":
        "شناسه UUID محصول باید با product_id داخل EXE آن محصول یکسان باشد.",
    "Database backup": "پشتیبان پایگاه داده",
    "Encrypted, passphrase-protected backup and restore": "پشتیبان‌گیری و بازیابی رمزنگاری‌شده با رمز عبور",
    "Create encrypted backup…": "ساخت پشتیبان رمزنگاری‌شده…",
    "Restore from backup…": "بازیابی از پشتیبان…",
    "Backups are passphrase-wrapped containers (AES-256-GCM, PBKDF2 600k) — safe to store on any medium.":
        "پشتیبان‌ها با رمز عبور محافظت می‌شوند (AES-256-GCM، PBKDF2 600k) — نگهداری روی هر رسانه‌ای امن است.",
    "About": "درباره",
    "SecureCode Protector 1.0.0 — offline serial generation and EXE protection toolkit. 100% offline: no network access is performed by this application, ever.":
        "SecureCode Protector نسخه ۱٫۰٫۰ — ابزار صدور سریال آفلاین و محافظت از EXE. کاملاً آفلاین: این برنامه هرگز به شبکه دسترسی ندارد.",
    "Product added": "محصول اضافه شد",
    "Passphrase changed": "رمز عبور تغییر کرد",
    "Key imported": "کلید وارد شد",
    "Import failed": "ورود ناموفق بود",
    "Backup created": "پشتیبان ساخته شد",
    "Restored": "بازیابی شد",
    "Restore failed": "بازیابی ناموفق بود",
    "Keypair regenerated": "جفت‌کلید جدید ساخته شد",
    "All existing serials are now invalid.": "همه سریال‌های قبلی اکنون نامعتبرند.",
    # --- extra entries (tooltips, toasts) ------------------------------------
    "Last 12 months": "۱۲ ماه اخیر",
    "Invalid folder": "پوشه نامعتبر",
    "Pick the project you want to protect. Copy your source there first — nothing in your project folder is modified until you press 'Inject protection SDK'.":
        "پروژه‌ای را که می‌خواهید محافظت کنید انتخاب کنید. تا وقتی «تزریق SDK» را نزنید هیچ چیزی در پوشه پروژه تغییر نمی‌کند.",
    "The folder containing your Python entry point (e.g. main.py).":
        "پوشه‌ای که فایل اصلی پایتون (مثلاً main.py) در آن است.",
    "Add the bootstrap snippet to your entry point (shown here).":
        "کد راه‌انداز (نمایش‌داده‌شده) را به فایل اصلی برنامه اضافه کنید.",
    "Check the code's structure and decode its component mask.":
        "بررسی ساختار کد و استخراج قطعات سخت‌افزاری ثبت‌شده.",
    "Jump to the Generate tab with this machine code pre-filled.":
        "رفتن به صفحه صدور سریال با همین کد ماشین.",
    "Permanently delete the record (cannot be undone).": "حذف دائمی رکورد (برگشت‌پذیر نیست).",
    "The customer runs 'Deactivate with vendor permit' on the OLD machine.":
        "مشتری روی ماشین قدیمی گزینه «غیرفعال‌سازی با مجوز فروشنده» را اجرا می‌کند.",
    "Writes blacklist.sec containing every revoked nonce. Distribute it to customers (any offline channel) — clients verify its signature.":
        "فایل blacklist.sec شامل همه سریال‌های ابطال‌شده را می‌سازد. آن را به مشتریان بدهید — برنامه مشتری امضایش را بررسی می‌کند.",
    "Keep this file OFFLINE and safe — it can issue serials.":
        "این فایل را آفلاین و امن نگه دارید — با آن می‌توان سریال صادر کرد.",
    "SecureCode Protector · v1.0.0": "SecureCode Protector · نسخه ۱٫۰٫۰",
    "The keystore was re-wrapped.": "کلید امضا با رمز جدید ذخیره شد.",
    "Toggle the revocation flag; revoked nonces go into the blacklist.":
        "ابطال یا بازگردانی سریال؛ سریال‌های ابطال‌شده وارد لیست سیاه می‌شوند.",
    "Re-sign the serial with a new validity period (same machine binding).":
        "امضای دوباره سریال با مدت اعتبار جدید (برای همان ماشین).",
    "Issue the signed permit that removes the license from the OLD machine.":
        "صدور مجوز امضاشده برای حذف لایسنس از ماشین قدیمی.",
    "Copy the selected record's serial key.": "کپی سریال ردیف انتخاب‌شده.",
    "Save the selected serial as .lic.": "ذخیره سریال انتخاب‌شده به‌صورت ‎.lic.",
    "Re-wrap the keystore under a new passphrase.": "ذخیره کلید امضا با رمز عبور جدید.",
    "Passphrase-wrapped offline backup (AES-256-GCM). Store it in a safe.":
        "پشتیبان آفلاین محافظت‌شده با رمز (AES-256-GCM). در جای امن نگه دارید.",
    "Restore a signing key from an encrypted export.": "بازیابی کلید امضا از فایل رمزنگاری‌شده.",
    "Creates a NEW key. All previously issued serials stop verifying!":
        "کلید جدید می‌سازد. همه سریال‌های قبلی نامعتبر می‌شوند!",
    "Free-form customer identifier embedded in the signed payload.":
        "شناسه آزاد مشتری که داخل سریال امضاشده قرار می‌گیرد.",
    "Product this serial unlocks (Settings → Products).": "محصولی که این سریال باز می‌کند (تنظیمات ← محصولات).",
    "Machine code exported by the customer (Fingerprint Reader tab validates it).":
        "کد ماشین ارسالی مشتری (در صفحه خواندن اثر انگشت بررسی می‌شود).",
    "Updating…": "در حال به‌روزرسانی…",
    "Re-signing…": "در حال امضای دوباره…",
    "Signing permit…": "در حال امضای مجوز…",
    "Deleting…": "در حال حذف…",
    "Signing blacklist…": "در حال امضای لیست سیاه…",
    "Re-wrapping keystore…": "در حال ذخیره کلید امضا…",
    "Exporting…": "در حال خروجی گرفتن…",
    "Importing key…": "در حال ورود کلید…",
    "Generating keypair…": "در حال ساخت جفت‌کلید…",
    "Exporting database…": "در حال خروجی پایگاه داده…",
    "Importing database…": "در حال ورود پایگاه داده…",
    "Selected: {path}": "انتخاب شد: {path}",
}


__all__ = ["FA", "LANGUAGES", "arrow", "digits", "direction", "is_rtl", "language",
           "ltr", "num", "set_language", "tr"]
