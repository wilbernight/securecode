# SecureCode — پرامپت ممیزی امنیت و کیفیت کد | Security & Code-Quality Audit Prompt

> **فارسی:** این پرامپت را عیناً کپی کنید و به یک دستیار هوش مصنوعی (Claude،
> ChatGPT، Cursor، Copilot، …) بدهید تا کل این مخزن را از نظر **امنیت** و
> **تمیزی/کیفیت کد** ممیزی کند. پرامپت عمداً خودکفاست: همه حقایق لازم داخلش
> است، قواعد تغییرناپذیر مشخص شده، و خروجی با قالب مشخص (شدت + مدرک +
> راه‌حل) خواسته شده تا نتیجه قابل پیگیری باشد.
>
> **English:** copy this prompt verbatim and hand it to an AI coding
> assistant to audit the whole repository for **security** and **code
> quality/cleanliness**. It is deliberately self-contained: every fact the
> auditor needs is inside, the invariants are stated up front, and a strict
> report format (severity + evidence + concrete fix) is requested.

---

## 🇬🇧 English prompt (copy everything inside the fence)

```text
You are performing a PROFESSIONAL SECURITY & CODE-QUALITY AUDIT of the
SecureCode repository at the path I give you. You are an experienced
application-security reviewer: skeptical, evidence-driven, and allergic to
theater. You do NOT rewrite code during the audit — you REPORT findings;
you only implement fixes when I explicitly ask you to act on them.

## What this project is (facts you must rely on — do not guess)
- An OFFLINE software licensing/anti-piracy toolkit. NO network/phone-home
  anywhere, by hard requirement.
- Two Python apps (PySide6): `protector/` (vendor serial-generator; holds
  the ONLY Ed25519 private key, wrapped in a passphrase keystore) and
  `target_demo/` (protected demo app; embeds the public key only).
- `shared/` = the wire-format contract both sides share.
- `sdks/` = native ports of the same client stack:
  `sdks/android/securecode-sdk` (pure Kotlin, Java-friendly Builder, minSdk
  24, hand-implemented RFC-8032 Ed25519 because java.security needs API 33),
  `sdks/apple/SecureCodeKit` (SwiftPM, iOS 13+/macOS 10.15+, CryptoKit,
  manual RFC-5869 HKDF), `sdks/flutter/securecode` (Dart plugin over those
  two; native trees are COPIES synced by sdks/sync_native.py — never
  hand-edit the copies).
- Serial = Base32(canonical JSON payload || 64B Ed25519 sig). Fingerprint
  machine code = 16 chars from mask+SHA-256[:9]. License file = b"SCLIC1"
  + AES-256-GCM(HKDF-derived machine key, canonical JSON), no AAD.
  HKDF: ikm = per-platform master + "|" + machine_code, salt = product_id,
  info = context ("license-file-v1", "clock-store-v1").

## Invariants — an audit finding that requires breaking these is WRONG
1. The wire format is FROZEN: canonical JSON must stay byte-identical to
   Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)
   (lowercase-hex \uXXXX, surrogate pairs, keys sorted by code point).
   Base32 = RFC 4648 with the documented repair heuristic (strip 0/1/8/9).
2. No network access may be introduced, ever.
3. The Ed25519 private key exists ONLY inside the protector's keystore.
4. Dependencies stay pinned (requirements.txt); the Python client may use
   only the listed packages; Kotlin/Swift SDKs stay zero-dependency.
5. The shipped demo keypair + sdks/gen_strings_masters.json masters are
   DEMO-GRADE BY DESIGN (documented) — flag their existence only if you
   find a place where they are confused with production keys.
6. SC_DEV=1 / devMode exists on purpose (debugging), documented as
   never-in-release.
7. Wire format frozen also means: the optional "platform" key in
   fingerprint EXPORT files is UI metadata only and is never signed into
   the payload.

## Audit checklist (cover every item; cite file:line evidence)
A. Crypto & key handling
   - Randomness: every security-relevant value from a CSPRNG (`secrets` /
     SecureRandom / CryptoKit), never `random`/`Random` (jitter delays in
     anti-debug are the ONE allowed exception).
   - Ed25519: verification cannot be bypassed; hand-rolled ports match
     RFC 8032 (L = 2^252 + 27742317777372353535851937790883648493, hash h
     little-endian); no custom crypto anywhere else.
   - AES-GCM: unique nonces, no AAD confusion between contexts, auth
     failures mapped to clean states, no padding-oracle-style paths.
   - Key lifetime: unwrapped key material wiped (SecureBuffer / secureZero
     / equivalent); keys never logged, never in exception messages.
B. Input handling (all untrusted inputs: pasted serials, fingerprint.txt,
   license.dat, blacklist.sec, transfer permits, method-channel args)
   - Every parse validates size (caps exist: license 1 MiB, blacklist
     16 MiB, permit 1 MiB, clock store 4096 B, fingerprint export 1 MiB —
     verify they are enforced on EVERY platform port, Python included).
   - Type/shape validation before use; malformed -> controlled exception
     or clean state enum, never an unhandled crash.
   - No path traversal / no unvalidated file paths from user input.
   - JSON parsed with bounded depth and size (no billion-laughs concerns;
     document if unbounded).
C. Injection & shell
   - No shell=True / string-concatenated subprocess calls; PowerShell CIM
     queries use fixed obfuscated command ids only.
   - SQL only via parameterized queries (check db.py).
   - No eval/exec/pickle/marshal on data.
D. Logic & state machine
   - LicenseState transitions: verify the nine states (VALID, MISSING,
     INVALID, EXPIRED, WRONG_MACHINE, REVOKED, CLOCK_TAMPERED, DAMAGED,
     DEGRADED) are reachable exactly as documented and none can be
     skipped by crafted inputs.
   - Clock guard: monotonic fallback, allowance from the SIGNED payload,
     rollback accounting cannot be reset by deleting one store.
   - Tolerance mechanism: dropping up to N components cannot be abused to
     accept a different machine (verify mask handling).
   - Blacklist: signed-file-only application; corrupt file ignored, never
     bricks; oversized file ignored.
E. Anti-RE layers (report design gaps, not moral judgments)
   - anti_debug, integrity, strings obfuscation: behavior on detection
     (delayed exit vs degrade), watchdog intervals, false-positive risks.
F. Hygiene & cleanliness
   - No secrets/PII in logs (log statements reviewed one by one).
   - No dead code, unused imports, commented-out blocks, TODO/FIXME debt.
   - Exceptions: consistent hierarchy (shared/exceptions.py), user_message
     never leaks internals; broad `except Exception` only on
     availability-critical fallback paths (documented pattern).
   - Naming/style consistency per platform (PEP8-ish Python, Kotlin
     conventions, Swift API Design Guidelines), docstrings on public APIs.
   - i18n: every user-facing English string in the protector is in the FA
     table in protector/ui/i18n.py (flag missing keys).
   - Docs match code (any stale claims).
G. Tests as a gate
   - tests/e2e_licensing.py (28 checks), tests/platform_fingerprint_test.py,
     tests/cross_platform_vectors.py --check, sdks/sync_native.py --check
     all pass. If you propose changes, re-run these and show the output.

## Report format (mandatory)
1. Executive verdict: 2-4 sentences (is this codebase production-sane?).
2. Findings table sorted by severity, each with:
   | ID | Severity (Critical/High/Medium/Low/Info) | Title | Location
   (file:line) | Evidence (quote the code) | Why it matters | Concrete fix |
3. "Considered and accepted" list: risks you evaluated and deliberately
   judged non-issues (e.g., timing side channels on PUBLIC values such as
   machine codes, broad exception catches on fallback paths) — say WHY.
4. Cleanliness report: per-area notes (hygiene items found, dead code, …).
5. A prioritized fix plan (what to do first and what it costs).

Rules of engagement: read the actual code, quote it, never speculate about
files you have not opened; if something is ambiguous, list it as a question
instead of a finding. Do not propose security theater (adding hash maps of
randomness, obfuscation for its own sake, network callbacks "for safety").
```

---

## 🇮🇷 پرامپت فارسی (همه‌ی داخل کادر را کپی کنید)

```text
داری مخزن SecureCode را در مسیری که بهت می‌دهم به‌صورت حرفه‌ای ممیزی
امنیتی + کیفیت کد می‌کنی. تو یک بازرس امنیت نرم‌افزار باتجربه‌ای هستی:
شکاک، مدرک‌محور و ضد تئاترِ امنیتی. در مرحله ممیزی فقط «گزارش» بده؛
اصلاح کد فقط وقتی که صریحاً ازت خواستم روی یافته‌ها عمل کنی.

## این پروژه چیست (حقایق — حدس نزن)
- یک تولکیت لایسنس/ضدکپی کاملاً آفلاین. هیچ اتصال شبکه‌ای مجاز نیست.
- دو برنامه پایتونی (PySide6): `protector/` (ابزار صدور سریال فروشنده؛
  تنها جای پروژه که کلید خصوصی Ed25519 هست، داخل keystore رمزشده با
  passphrase) و `target_demo/` (برنامه دموِ محافظت‌شده؛ فقط کلید عمومی).
- `shared/` = قرارداد فرمت سیم بین دو طرف.
- `sdks/` = پورت‌های بومی همان استک: اندروید (Kotlin خالص، API جاوا با
  Builder، minSdk 24، پیاده‌سازی دستی Ed25519 مطابق RFC 8032 چون
  java.security به API 33 نیاز دارد)، اپل (SwiftPM، iOS 13+/macOS 10.15+،
  CryptoKit، HKDF دستی مطابق RFC 5869)، Flutter (پلاگین Dart روی همان دو
  SDK؛ فایل‌های native کپی‌اند و با sdks/sync_native.py همگام می‌شوند —
  کپی‌ها را هرگز دستی ویرایش نکن).
- سریال = Base32(JSON کانونیکال payload || امضای ۶۴ بایتی Ed25519).
  کد ماشین = ۱۶ کاراکتر از mask+SHA-256[:9]. فایل لایسنس = b"SCLIC1" +
  AES-256-GCM(کلید ماشینِ مشتق از HKDF، JSON کانونیکال)، بدون AAD.
  HKDF: ikm = masterِ هر پلتفرم + "|" + کد ماشین، salt = شناسه محصول،
  info = context («license-file-v1»، «clock-store-v1»).

## تغییرناپذیرها — یافته‌ای که بشکند این‌ها را، غلط است
۱. فرمت سیم FROZEN است: JSON کانونیکال باید بایت‌به‌بایت معادل
   json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)
   پایتون بماند (\uXXXX با حروف کوچک، جفت surrogate، مرتب‌سازی کلید بر
   اساس code point). Base32 مطابق RFC 4648 با heuristic ترمیم مستند.
۲. هرگز اتصال شبکه‌ای اضافه نشود.
۳. کلید خصوصی فقط داخل keystore محافظ می‌ماند.
۴. وابستگی‌ها pinned می‌مانند؛ کلاینت پایتون فقط پکیج‌های لیست‌شده؛
   SDKهای Kotlin/Swift بدون وابستگی می‌مانند.
۵. کلید دمو و masterهای sdks/gen_strings_masters.json عمداً DEMO-Grade
   اند (مستند شده) — فقط وقتی پرچم بزن که جایی با کلید تولیدی اشتباه
   گرفته شده باشند.
۶. SC_DEV=1 / devMode عمداً برای دیباگ هست؛ مستند است «هرگز در release».
۷. کلید اختیاری «platform» در فایل‌های export فقط متادیتای UI است و
   هرگز داخل payload امضاشده نمی‌رود.

## چک‌لیست ممیزی (همه را پوشش بده؛ مدرک را با فایل:خط بده)
الف) رمزنگاری و کلیدها
   - تصادفِ مقادیر امنیتی فقط از CSPRNG (`secrets`/SecureRandom/
     CryptoKit)؛ `random`/`Random` فقط برای تأخیر jitter در anti-debug.
   - Ed25519: دور زدن verify ممکن نباشد؛ پورت دستی با RFC 8032 بخواند
     (L = 2^252 + 27742317777372353535851937790883648493 و هش h
     little-endian)؛ غیر از این‌جا هیچ crypto سفارشی نباشد.
   - AES-GCM: nonce یکتا، AAD بین contextها قاطی نشود، شکست احراز به
     state تمیز نگاشت شود، مسیر padding-oracle نباشد.
   - طول عمر کلید: متریال unwiped → پاک شود (SecureBuffer/secureZero)؛
     کلید هرگز log یا داخل پیام استثنا نباشد.
ب) اعتبارسنجی ورودی (همه ورودی‌های غیرمطمئن: سریال paste‌شده،
   fingerprint.txt، license.dat، blacklist.sec، permit، آرگومان‌های کانال)
   - هر parse قبل از خواندن، سایز را کپ کند (موجود: لایسنس 1MiB،
     blacklist 16MiB، permit 1MiB، clock store 4096B، export فینگرپرینت
     1MiB — بررسی کن در «همه» پورت‌ها از جمله پایتون اعمال شده باشد).
   - اعتبارسنجی نوع/شکل قبل از استفاده؛ بدشکل → استثنای کنترل‌شده یا
     state تمیز، نه کرش ناپایدار.
   - path traversal نباشد؛ مسیر فایل از ورودی کاربر اعتبارسنجی شود.
   - JSON با عمق/سایز محدود parse شود.
ج) تزریق و شل
   - بدون shell=True و بدون الحاق رشته در subprocess؛ کوئری‌های CIM
     پاورشل فقط با شناسه‌های ثابتِ مبهم‌شده.
   - SQL فقط با پارامتر (db.py را چک کن).
   - بدون eval/exec/pickle/marshal روی داده.
د) منطق و ماشین حالت
   - ۹ حالت LicenseState دقیقاً مطابق مستندات قابل دسترس باشند و هیچ‌کدام
     با ورودی ساختگی قابل رد شدن نباشند.
   - گارد ساعت: fallback مونوتونیک، allowance از payload امضاشده، حذف یک
     store شمارش rollback را صفر نکند.
   - مکانیزم tolerance: drop کردن تا N جزء نتواند ماشین متفاوتی را بپذیرد
     (mask را بررسی کن).
   - blacklist: فقط فایل امضاشده اعمال شود؛ خراب → نادیده (آجر نشود)؛
     بزرگ → نادیده.
هـ) لایه‌های ضد مهندسی معکوس (شکاف طراحی را گزارش کن، نه قضاوت اخلاقی)
   - anti_debug، integrity، obfuscation رشته‌ها: رفتار هنگام کشف (خروج
     تأخیری یا degrade)، بازه watchdog، ریسک false-positive.
و) بهداشت و تمیزی
   - هیچ راز/PII در logها (گزاره‌های log را دونه‌دونه ببین).
   - بدون کد مرده، import بلااستفاده، بلوک کامنت‌شده، بدهی TODO/FIXME.
   - استثناها: سلسله‌مراتب یکدست (shared/exceptions.py)، user_message
     جزئیات داخلی نشود؛ `except Exception` عام فقط روی مسیرهای fallback
     حیاتیِ مستندشده.
   - سبک/نام‌گذاری هر پلتفرم یکدست؛ docstring روی APIهای عمومی.
   - i18n: هر رشته انگلیسیِ UI محافظ در جدول FA (protector/ui/i18n.py)
     باشد (کلید جاافتاده را پرچم بزن).
   - مستندات با کد هم‌خوان باشد (ادعای کهنه = یافته).
ز) تست به‌عنوان گیت
   - tests/e2e_licensing.py (۲۸ چک)، tests/platform_fingerprint_test.py،
     tests/cross_platform_vectors.py --check و sdks/sync_native.py --check
     همه پاس. اگر تغییری پیشنهاد می‌کنی، این‌ها را دوباره اجرا و خروجی را
     نشان بده.

## قالب گزارش (الزامی)
۱. جمع‌بندی اجرایی: ۲-۴ جمله (این کدبیس برای production سالم است؟).
۲. جدول یافته‌ها مرتب بر اساس شدت؛ هر ردیف:
   | ID | شدت (بحرانی/بالا/متوسط/کم/اطلاعی) | عنوان | مکان (فایل:خط) |
   مدرک (نقل کد) | چرا مهم است | راه‌حل مشخص |
۳. فهرست «بررسی و پذیرفته‌شده»: ریسک‌هایی که سنجیدی و عمداً غیرمسئله
   تشخیص دادی (مثل timing side-channel روی مقادیر عمومی مثل کد ماشین،
   یا except عام روی مسیرهای fallback) — با دلیل.
۴. گزارش تمیزی: یادداشت هر حوزه (کدهای بهداشتی، کد مرده و…).
۵. برنامه اصلاح اولویت‌بندی‌شده (اول چه، هزینه‌اش چه).

قواعد: کد واقعی را بخوان و نقل کن؛ درباره فایلی که باز نکردی حدس نزن؛
ابهام را به‌صورت سؤال بیاور نه یافته. تئاتر امنیتی ممنوع (نقشه هش از
تصادف، obfuscation برای خودش، کال‌بک شبکه «برای امنیت»).
```

---

## استفاده | Usage

1. پرامپت را با مسیر مخزن به AI بده | Give the prompt plus the repo path.
2. گزارش را مرور کن؛ یافته‌های بحرانی/بالا را فوراً، متوسط را در چرخه
   بعدی اصلاح کن | Review the report; fix Critical/High immediately.
3. بعد از هر اصلاح، گیت‌های تست (بخش «ز»/G) را اجرا کن و بعد
   `python protector\tools\make_integrity_manifest.py` را بازتولید کن
   (چون سورس کلاینت عوض شده) | After fixes, re-run the test gates and
   regenerate the integrity manifest whenever client sources changed.

> **سابقه | Track record:** همین ممیزی (v3.1) اجرا شد و به این اصلاحات
> انجامید: کپ سایز همه فایل‌های ورودی در هر ۴ پیاده‌سازی، سخت‌سازی
> parse فایل export، پاک‌سازی glue کاتلین پلاگین Flutter، ترجمه‌های FA،
> و بازتولید مانیفست یکپارچگی. جزئیات: `DECISIONS.md` (بخش audit).
