# SecureCode Android SDK (`com.securecode.protection`)

> **فارسی:** پورت کامل لایه محافظت برای اندروید — همان سریال‌های Ed25519 امضاشده
> که محافظ ویندوزی صادر می‌کند، با قفل سخت‌افزاری، انقضا، گارد ساعت،
> anti-debug، blacklist و چک یکپارچگی. **صفر وابستگی خارجی، صفر دسترسی
> شبکه.** API برای Kotlin و Java (الگوی Builder).
>
> **English:** the complete protection stack ported to Android — the same
> Ed25519-signed serials the protector issues, with hardware lock, expiry,
> clock guard, anti-debug, blacklist and integrity checks. **Zero third-party
> dependencies, zero network.** Java-friendly API (Builder pattern).

* `minSdk 24` (Android 7.0+), `compileSdk` whatever your app uses.
* Pure Kotlin + `javax.crypto` / `java.security` only. Ed25519 is
  **hand-implemented (RFC 8032)** because `java.security` Ed25519 needs API 33.
* Package: `com.securecode.protection` (single module, no AndroidX needed).

## Install

### Gradle (Kotlin DSL) — module dependency

```kotlin
// settings.gradle.kts
include(":securecode-sdk")

// app/build.gradle.kts
dependencies {
    implementation(project(":securecode-sdk"))
}
```

Copy the `securecode-sdk/` folder next to your app module (or publish it to a
private Maven repo with the included `build.gradle.kts`).

### Device identifiers (what the machine code is made of)

| Slot | Android source | Notes |
|---|---|---|
| `cpu` | Widevine MediaDrm device ID | hardware-backed, no permission, stable across reinstalls AND factory resets on most devices |
| `board` | SSAID (`ANDROID_ID`) | per device+signing key since Android 8; survives reinstall |
| `disk` | Android Keystore key digest | **optional, OFF by default** (on = serial dies with the install) |

With the default profile, uninstall + reinstall produces the SAME machine code
→ the customer re-activates with the SAME serial. `tolerance=1` absorbs a
factory-reset SSAID change.

## Usage — Kotlin

```kotlin
import com.securecode.protection.DetectAction
import com.securecode.protection.LicenseState
import com.securecode.protection.ProtectionConfig
import com.securecode.protection.ProtectionRuntime

class MyApp : Application() {
    lateinit var runtime: ProtectionRuntime.Handle

    override fun onCreate() {
        super.onCreate()
        val config = ProtectionConfig.Builder(productId = "7e9a6cec-c185-45bb-a2fb-d31e96484f7e")
            .productName("MyApp")
            .publicKeyHex("…your Ed25519 public key hex (protector export)…") // demo key is the default
            .expectedSignerCertSha256("…SHA-256 of your APK signing cert (optional repack pin)…")
            .devMode(BuildConfig.DEBUG)   // NEVER in release!
            .build()
        runtime = ProtectionRuntime.bootstrap(this, config)   // anti-debug + integrity + clock wiring
    }
}
```

```kotlin
// Activation screen
val client = runtime.licenseClient(this)          // share one client
val machineCode = client.machineCode()            // XXXX-XXXX-XXXX-XXXX → send to vendor
val result = client.activate(serialFromUser)      // writes the encrypted license file
if (result.state == LicenseState.VALID) { /* unlock the app: result.payload has customer/expiry/flags */ }

// Every launch
when (client.verifyInstalled(degraded = runtime.degraded).state) {
    LicenseState.VALID -> { /* start the real app */ }
    else -> { /* activation / error screen */ }
}
```

`verifyInstalled()` returns a `LicenseStatus` (state/message/payload/secondsLeft)
with the same nine states as the Windows client: `VALID, MISSING, INVALID,
EXPIRED, WRONG_MACHINE, REVOKED, CLOCK_TAMPERED, DAMAGED, DEGRADED`.

## Usage — Java

```java
import com.securecode.protection.DetectAction;
import com.securecode.protection.LicenseState;
import com.securecode.protection.ProtectionConfig;
import com.securecode.protection.ProtectionRuntime;

ProtectionConfig config = new ProtectionConfig.Builder("7e9a6cec-c185-45bb-a2fb-d31e96484f7e")
        .productName("MyApp")
        .publicKeyHex("…")
        .onDetect(DetectAction.EXIT)
        .build();
ProtectionRuntime.Handle runtime = ProtectionRuntime.bootstrap(context, config);

String machineCode = runtime.licenseClient(context).machineCode();
ActivationResult result = runtime.licenseClient(context).activate(serialText);
if (result.getState() == LicenseState.VALID) { /* unlock */ }
```

## Verify the port (conformance)

```bash
cd sdks/android/securecode-sdk
gradle test          # runs VectorConformanceTest against ../../vectors.json
```

The test prints a selftest report; validate it anywhere with:

```bash
python -m tests.cross_platform_vectors --check <report.json>
```

## Before release

1. **Embed YOUR public key** (default is the DEMO key): export it from the
   protector (`protector/tools/export_pubkey_blob.py`) and pass `.publicKeyHex(…)`.
2. **Rotate the string layer + masters**: `python sdks/gen_strings.py`
   regenerates `SecureStrings.kt` with fresh random masters — do NOT commit
   the regenerated `sdks/gen_strings_masters.json`.
3. `devMode` must be `false` (anti-debug + integrity active).
4. Consider `.useKeystoreComponent(true)` only if serials should NOT survive
   an uninstall/reinstall (per-install binding).
5. `emulatorChecks` stays OFF unless your product model requires it (same
   rationale as the Windows client — false positives on real devices).

## State locations (all app-private)

| What | Where |
|---|---|
| License file (AES-256-GCM, machine-bound) | `filesDir/<company>/<product>/license.dat` |
| Clock-guard stores | `filesDir/<company>/<product>/` (obfuscated, GCM-protected) |
| Optional blacklist `blacklist.sec` | same folder (drop-in, signed by vendor) |
| Keystore component key (if enabled) | Android Keystore (`"securecode"` alias) |
