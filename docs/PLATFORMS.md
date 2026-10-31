# SecureCode — پلتفرم‌های پشتیبانی‌شده | Supported Platforms

> **فارسی:** از نسخه ۳.۱، سیستم لایسنس SecureCode فقط محدود به ویندوز نیست.
> همان سریال‌هایی که محافظ (protector) صادر می‌کند، روی **اندروید (Kotlin، Java،
> Flutter/Dart)**، **iOS** و **macOS** هم تأیید می‌شوند — چون فرمت سیم (wire format)
> در همه پلتفرم‌ها مو‌به‌مو یکسان بازتولید شده است. خود محافظ هم حالا روی
> **ویندوز و macOS** اجرا و build می‌شود.
>
> **English:** Since v3.1 the SecureCode licensing system is no longer
> Windows-only. The exact same serials the protector issues also verify on
> **Android (Kotlin, Java, Flutter/Dart)**, **iOS** and **macOS** — because every
> SDK reproduces the wire format byte-for-byte. The protector itself now runs
> and builds on **Windows and macOS**.

---

## 1) ماتریس پلتفرم‌ها | Platform matrix

| Component | Windows | Android | iOS | macOS |
|---|---|---|---|---|
| Client SDK | `target_demo/protection/` (Python, reference) | `sdks/android/securecode-sdk/` (Kotlin + Java API) | `sdks/apple/SecureCodeKit/` (Swift) | `sdks/apple/SecureCodeKit/` (Swift) |
| Flutter client | — | ✅ via `sdks/flutter/securecode/` | ✅ | ✅ |
| Serial verify (Ed25519) | ✅ | ✅ (hand-implemented, RFC 8032) | ✅ (CryptoKit) | ✅ (CryptoKit) |
| Hardware lock (fingerprint) | ✅ WMI cpu/board/disk + MachineGuid | ✅ Widevine ID + SSAID (+optional Keystore) | ✅ Keychain UUID + IDFV | ✅ en0 MAC + Mac serial + IOPlatformUUID |
| Encrypted local license store | ✅ AES-256-GCM + ACL | ✅ AES-256-GCM (Keystore-wrapped key) | ✅ AES-256-GCM (Keychain) | ✅ AES-256-GCM (Keychain) |
| Expiry + clock guard | ✅ registry + decoy + uptime | ✅ monotonic + persist stores | ✅ (system uptime + GCM stores) | ✅ (system uptime + GCM stores) |
| Anti-debug | ✅ `IsDebuggerPresent` + tracer PID | ✅ tracer PID + `Debug.isDebuggerConnected` | ✅ `sysctl` `P_TRACED` | ✅ `sysctl` `P_TRACED` |
| Signed blacklist | ✅ | ✅ | ✅ | ✅ |
| Integrity self-check | ✅ (Nuitka `__compiled__` etc.) | ✅ (constants + signature module digest) | ✅ (constants + code signature) | ✅ (SecCode + constants) |
| Protector (vendor tool) | ✅ (`build_protector.bat`) | — | — | ✅ (`build_protector.sh`) |
| Network access | ❌ never | ❌ never | ❌ never | ❌ never |

---

## 2) فرمت سیم ثابت | The frozen wire format

**فارسی:** مهم‌ترین تصمیم معماری: فرمت سریال و fingerprint در هیچ پلتفرمی «بومی»
بازتعریف نشده — همه SDKها خروجی پایتون را **بایت‌به‌بایت** بازتولید می‌کنند:

- **JSON کانونی:** مثل `json.dumps(sort_keys=True, separators=(",",":"),
  ensure_ascii=True)` پایتون — کلیدها بر اساس code point مرتب، همه کاراکترهای
  خارج از U+0020..U+007E به‌صورت `\uXXXX` با حروف کوچک هگز، جفت‌های surrogate
  برای کاراکترهای خارج از BMP (astral)، فرم‌های کوتاه `\b \t \n \f \r` فقط
  همین پنج‌تا.
- **Base32:** دقیقاً الفبای RFC 4648؛ دیکدر نسبت به حروف بزرگ/کوچک، خط تیره و
  ارقام 0/1/8/9 (که در Base32 استفاده نمی‌شوند) تحمل‌پذیر است.
- **Ed25519:** امضای ۶۴ بایتی RFC 8032 روی همان بایت‌های JSON کانونی.
- **Fingerprint:** ۱۰ بایت = `mask + SHA-256[:9]` → ۱۶ کاراکتر Base32
  (`XXXX-XXXX-XXXX-XXXX`). چهار «جایگاه هش» با نام‌های ثابت
  `cpu/board/disk/guid` در همه پلتفرم‌ها هستند — هر پلتفرم شناسه‌های خودش را
  در آن‌ها می‌ریزد (جدول بعدی).
- **HKDF:** `ikm = master + "|" + machine_code`، `salt = product_id`،
  `info = context`، طول ۳۲ (RFC 5869). برای فایل لایسنس از context
  `license-file-v1` استفاده می‌شود؛ فایل لایسنس = `SCLIC1` +
  AES-256-GCM(کلید ماشین، JSON رکورد) **بدون AAD**.

**English:** The key architectural decision: no platform "reinterprets" the
serial format — every SDK reproduces the Python output byte-for-byte:

- **Canonical JSON:** exactly like Python's `json.dumps(sort_keys=True,
  separators=(",",":"), ensure_ascii=True)` — keys sorted by code point,
  everything outside U+0020..U+007E escaped as lowercase-hex `\uXXXX`,
  surrogate pairs for astral characters, short forms `\b \t \n \f \r` only.
- **Base32:** the RFC 4648 alphabet; the decoder tolerates case, dashes and
  the digits 0/1/8/9 (never legal in Base32).
- **Ed25519:** the 64-byte RFC 8032 signature over those exact canonical bytes.
- **Fingerprint:** 10 bytes = `mask + SHA-256[:9]` → 16 Base32 chars
  (`XXXX-XXXX-XXXX-XXXX`). The four hash **slot names** `cpu/board/disk/guid`
  are stable everywhere — each platform pours its own identifiers into them
  (next table).
- **HKDF:** `ikm = master + "|" + machine_code`, `salt = product_id`,
  `info = context`, 32 bytes (RFC 5869 exact). License files use context
  `license-file-v1`; license file = `SCLIC1` + AES-256-GCM(machineKey,
  canonical JSON record), **no AAD**.

نتیجه: سریالی که در ویندوز صادر شده، در یک گوشی اندرویدی بدون هیچ تغییری
verify می‌شود — و بالعکس. | A serial issued on Windows verifies unchanged on
an Android phone — and vice versa.

---

## 3) شناسه‌های هر پلتفرم | Per-platform identifiers

| Slot | Windows | Android | iOS | macOS |
|---|---|---|---|---|
| `cpu` | WMI `ProcessorId` | **Widevine MediaDrm device ID** (hardware-backed, factory-provisioned; stable across reinstalls *and* factory resets on most devices, no permission) | **Keychain UUID** (persists across app reinstalls; only a full device erase resets it) | **en0 MAC address** (built-in ethernet, hardware-stable) |
| `board` | `Win32_BaseBoard` serial | **SSAID** (`Settings.Secure.ANDROID_ID`; per device+signing key since Android 8, survives reinstall, resets on factory reset) | **IDFV** (identifierForVendor; changes only when *all* of the vendor's apps are removed) | **IOPlatformSerialNumber** (the Mac serial) |
| `disk` | first `Win32_DiskDrive` serial | *optional* Android Keystore key digest — **off by default** so a reinstall keeps the same machine code | — | — |
| `guid` | `HKLM\...\MachineGuid` | — | — | **IOPlatformUUID** |

**فارسی:** انتخاب‌ها طوری شده‌اند که همان تجربه ویندوز حفظ شود: در اندرویدِ
پیش‌فرض (cpu+board) حذف و نصب مجدد برنامه همان کد ماشین را می‌دهد، پس مشتری
می‌تواند با **همان سریال** دوباره activate کند. `tolerance` (پیش‌فرض ۱) تغییر
SSAID پس از factory reset یا تغییر IDFV را هم جذب می‌کند.

**English:** The picks preserve the Windows UX: with the default Android
profile (cpu+board), an uninstall + reinstall yields the SAME machine code, so
the customer re-activates with the SAME serial. The tolerance (default 1)
absorbs an SSAID factory reset or an IDFV change too.

---

## 4) فیلد `platform` در فایل export | The `platform` export field

فایل `fingerprint.txt` که مشتری برای فروشنده می‌فرستد حالا یک فیلد اختیاری
`platform` دارد (`windows` / `android` / `ios` / `macos`). فایل‌های قدیمی که
این فیلد را ندارند، ویندوز فرض می‌شوند. این فیلد **فقط متادیتا برای UI
محافظ است** — در payload سریال ذخیره نمی‌شود و فرمت سیم را تغییر نمی‌دهد:
برچسب اجزای سخت‌افزاری در صفحه Fingerprint Reader بر اساس پلتفرم عوض می‌شود
(مثلاً «SSAID» به‌جای «Motherboard serial»).

The customer's `fingerprint.txt` export now carries an optional `platform`
field (`windows` / `android` / `ios` / `macos`). Legacy exports without it are
assumed Windows. The field is **UI metadata for the protector only** — it is
never encoded in the serial payload and does not change the wire format: the
component labels in the Fingerprint Reader page swap per platform (e.g.
"SSAID" instead of "Motherboard serial").

---

## 5) کدام SDK را بردارم؟ | Which SDK do I use?

| Your app | SDK | Quick start |
|---|---|---|
| Android (Kotlin) | `sdks/android/securecode-sdk/` | `sdks/android/securecode-sdk/README.md` |
| Android (Java) | same (Builder-based Java API) | same README, Java snippet |
| iOS / macOS (Swift) | `sdks/apple/SecureCodeKit/` | `sdks/apple/SecureCodeKit/README.md` |
| Flutter (any platform) | `sdks/flutter/securecode/` | `sdks/flutter/securecode/README.md` |
| Windows (Python/Nuitka) | `target_demo/protection/` | `docs/INTEGRATION.md` |

**نکته مهم برای Flutter:** فایل‌های native داخل پلاگین با `python
sdks/sync_native.py` از SDKهای اصلی کپی می‌شوند — هرگز دستی ویرایششان نکنید؛
بعد از هر تغییر SDK اصلی دوباره اسکریپت را اجرا کنید (با `--check` صحت
همگامی را بگیرید).

**Flutter note:** the plugin's native sources are copied in from the main
SDKs by `python sdks/sync_native.py` — never hand-edit them; re-run the script
after touching either native SDK (`--check` verifies sync).

---

## 6) چطور درستی پورت‌ها را ثابت کرده‌ایم؟ | How the ports are verified

**فارسی:** چون فرمت سیم ثابت است، درستی هر SDK با **بردارهای همگرایی**
(conformance vectors) اثبات می‌شود:

- `python -m tests.cross_platform_vectors` فایل `sdks/vectors.json` را
  می‌سازد: سریال‌های واقعی، کدهای fingerprint، جفت‌های
  پیام/امضا/کلید Ed25519، آزمون‌های HKDF، Base32 و JSON کانونی — با کلید
  دمو (private key دموی مخزن).
- هر SDK آزمون‌هایی دارد که این فایل را می‌خواند (Kotlin: 
  `VectorConformanceTest`، Swift: `Tests/SecureCodeKitTests`) و **گزارش
  selftest** به شکل `{sdk, all_ok, results:[...]}` چاپ می‌کند.
- گزارش هر پلتفرم را با `python -m tests.cross_platform_vectors --check
  <file>` اعتبارسنجی کنید.

**English:** Because the wire format is frozen, SDK correctness is proven with
conformance vectors:

- `python -m tests.cross_platform_vectors` generates `sdks/vectors.json`:
  real serials, fingerprint codes, Ed25519 message/signature/key triples,
  HKDF/Base32/canonical-JSON cases — signed with the repo demo key.
- Each SDK consumes that file (Kotlin: `VectorConformanceTest`, Swift:
  `Tests/SecureCodeKitTests`) and prints a **selftest report**:
  `{sdk, all_ok, results:[{name, ok, detail}]}`.
- Validate any platform's report with `python -m tests.cross_platform_vectors
  --check <file>`.

از آن‌جا که Ed25519 اندروید برای سازگاری با minSdk 24 دستی پیاده‌ شده، الگوریتم
قبل از پورت، مقابل OpenSSL تأیید شد (امضاها متقابلاً verify می‌شوند).
Because the Android Ed25519 is hand-implemented (java.security Ed25519 needs
API 33), the algorithm was parity-proven against OpenSSL before porting.

---

## 7) محافظ روی macOS | Protector on macOS

```bash
# 1) install (Python 3.11+, macOS 12+)
python3 -m pip install -r requirements.txt
#    ^ env markers skip the Windows-only wmi/pywin32/py-cpuinfo automatically

# 2) self-test + run
python3 -m tests.e2e_licensing
python3 -m protector.main

# 3) protected build (Nuitka .app bundle)
./build_protector.sh
```

مسیر وضعیت محافظ در macOS: `~/Library/Application Support/SecureCode/
Protector/` (keystore.dat، settings.dat، licenses.db، logs). در ویندوز همان
`%APPDATA%\SecureCode\Protector\` قبلی است. | Protector state on macOS lives
under `~/Library/Application Support/SecureCode/Protector/`; on Windows the
existing `%APPDATA%\SecureCode\Protector\` path is unchanged.

فونت‌ها هم خودکار macOS-native می‌شوند (Helvetica Neue / Menlo به‌جای
Segoe UI / Cascadia) و سخت‌سازی ACL فایل keystore در macOS معادل `chmod 600`
است. | Fonts fall back to macOS-native families (Helvetica Neue / Menlo
instead of Segoe UI / Cascadia), and keystore hardening maps `icacls` ACLs to
`chmod 600` on POSIX.

---

## 8) محدودیت‌های صادقانه | Honest limitations

- **تولید و امضا فقط سمت فروشنده:** همه SDKها فقط **verify** می‌کنند؛
  کلید خصوصی هرگز خارج از محافظ نیست. | All SDKs only **verify**; the
  private key never leaves the protector.
- **دسترسی root/jailbreak:** مثل هر قفل سخت‌افزاری، یک دستگاه jailbreak/route
  شده می‌تواند binderهای syscall را هوک کند؛ لایه‌ها سد هزینه‌اند نه مانع
  مطلق (مدل تهدید کامل: `docs/SECURITY.md`). | As with any hardware lock, a
  jailbroken/rooted device can hook syscalls; the layers raise cost, they are
  not an absolute barrier (full threat model: `docs/SECURITY.md`).
- **شبیه‌سازها:** Widevine ID روی اکثر emulatorها خالی است (آن جزء گم می‌شود؛
  با tolerance و SSAID جبران می‌شود). | Widevine ID is empty on most
  emulators (that slot drops; SSAID + tolerance still work).
- **کد SDK اپل/اندروید روی این ماشین ویندوزی compile نشده** (JDK/kotlinc/
  swift در دسترس نبود) — درستی از مسیر بردارها و پورت سطر‌به‌سطر تأمین شده؛
  قبل از انتشار، `gradle test` و `swift test` را روی ماشین مربوطه اجرا
  کنید. | The Apple/Android SDK code was not compiled on this Windows
  machine — correctness rests on vectors + line-by-line porting; run
  `gradle test` / `swift test` on a proper machine before shipping.
- **iOS Keychain:** UUID داخل Keychain با پاک‌کردن کامل دستگاه ریست می‌شود؛
  `tolerance` این تغییر را پوشش نمی‌دهد چون دو جزء با هم عوض می‌شوند —
  سریال جدید لازم است (همان سیاست transfer ویندوز). | A full device erase
  resets the Keychain UUID and IDFV together — that is beyond tolerance, so
  the customer needs a new serial (same policy as the Windows transfer flow).
