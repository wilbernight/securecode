# SecureCode Cross-Platform SDKs

> **فارسی:** این پوشه پورت‌های بومیِ همان لایه محافظتی است که در ویندوز داخل
> `target_demo/protection/` قرار دارد. یک سریال که محافظ صادر می‌کند روی
> ویندوز، اندروید، iOS و macOS بدون هیچ تغییری verify می‌شود.
>
> **English:** This directory holds the native ports of the same protection
> stack that ships as Python in `target_demo/protection/`. A serial issued by
> the protector verifies unchanged on Windows, Android, iOS and macOS.

| SDK | Package / layout | Language(s) | Platform |
|---|---|---|---|
| Android | `android/securecode-sdk/` (Gradle module) | Kotlin + Java | Android 7.0+ (minSdk 24) |
| Apple | `apple/SecureCodeKit/` (SwiftPM package) | Swift | iOS 13+ / macOS 10.15+ |
| Flutter | `flutter/securecode/` (pub package) | Dart (+ native glue) | Android / iOS / macOS |

Per-SDK usage guides: `android/securecode-sdk/README.md`,
`apple/SecureCodeKit/README.md`, `flutter/securecode/README.md`.
Platform overview (identifiers per OS, wire-format contract):
**`../docs/PLATFORMS.md`**.

## What's identical everywhere

* Serial / fingerprint / blacklist / transfer-permit **wire format** — byte-exact
  (canonical JSON, RFC 4648 Base32, RFC 8032 Ed25519, RFC 5869 HKDF,
  `SCLIC1` + AES-256-GCM license files).
* The **state machine** (`VALID / MISSING / INVALID / EXPIRED / WRONG_MACHINE /
  REVOKED / CLOCK_TAMPERED / DAMAGED / DEGRADED`), tolerance handling,
  clock-rollback allowance, anti-debug/integrity behavior and defaults.
* Zero network access, zero third-party runtime dependencies (pure Kotlin /
  pure Swift+CryptoKit).

## Files here

| File | Purpose |
|---|---|
| `vectors.json` | Cross-platform conformance vectors — **generated**, do not hand-edit. Every SDK test suite consumes this exact file. |
| `gen_strings.py` | Generates the obfuscated string tables (`SecureStrings.kt` / `SecureStrings.swift`) **and the per-platform random master secrets** recorded in `gen_strings_masters.json`. Regenerate (and keep the masters file private!) before a real release. |
| `gen_strings_masters.json` | One random 32-hex master per platform; DEMO-grade. Rotate for production — see the script header. Never commit regenerated masters. |
| `sync_native.py` | Copies the two native SDKs into the Flutter plugin (which must be self-contained). `--check` verifies both copies are in sync. |

## Verify a port (any machine with the SDK's toolchain)

```bash
# reference side (this repo, any OS): regenerate + self-test the vectors
python -m tests.cross_platform_vectors

# Android:  cd sdks/android/securecode-sdk && gradle test
# Apple:    cd sdks/apple/SecureCodeKit    && swift test
# Flutter:  cd sdks/flutter/securecode    && flutter test
```

Each SDK's vector test prints a selftest report
`{"sdk": "...", "all_ok": true, "results": [...]}` — validate any of those
reports with:

```bash
python -m tests.cross_platform_vectors --check <report.json>
```

## Demo keys

Every SDK embeds the **demo public key** as its default
(`dcb2c1a8…14a5b`), so serials issued by a protector with the shipped demo
keypair verify out of the box. For a real product, export your real public key
from the protector keystore (`protector/tools/export_pubkey_blob.py`) and pass
it via `ProtectionConfig` — see each SDK's README.
