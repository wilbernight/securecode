# SecureCodeKit — iOS / macOS licensing SDK (Swift)

> **فارسی:** پورت کامل لایه محافظت برای iOS و macOS با CryptoKit — همان سریال‌های
> Ed25519 که محافظ صادر می‌کند، با قفل سخت‌افزاری، انقضا، گارد ساعت، anti-debug،
> blacklist و چک یکپارچگی. **بدون هیچ وابستگی خارجی، بدون هیچ دسترسی شبکه.**
>
> **English:** the complete protection stack ported to Swift/CryptoKit for iOS
> and macOS — the same Ed25519-signed serials the protector issues, with
> hardware lock, expiry, clock guard, anti-debug, blacklist and integrity
> checks. **No third-party dependencies, no network, ever.**

* SwiftPM package `SecureCodeKit` — iOS 13+ / macOS 10.15+.
* CryptoKit for Ed25519 + AES-GCM; manual HKDF (CryptoKit's HKDF needs
  iOS 14 — the port targets iOS 13 and implements RFC 5869 itself).
* License/clock stores: AES-GCM files under sandboxed
  `Application Support/<company>/<product>/` (the Keychain carries the
  persistent device UUID + the clock watermark).

## Install

Xcode → File → Add Package Dependencies → point at this folder (or your
fork), or in `Package.swift`:

```swift
dependencies: [
    .package(path: "../sdks/apple/SecureCodeKit"),
],
targets: [
    .target(name: "YourApp", dependencies: ["SecureCodeKit"]),
]
```

## Device identifiers

| Slot | macOS | iOS |
|---|---|---|
| `cpu` | built-in **en0 MAC** (hardware-stable) | **Keychain UUID** — survives app reinstalls; only a full device erase resets it |
| `board` | **IOPlatformSerialNumber** (the Mac serial) | **IDFV** — changes only when ALL of the vendor's apps are removed |
| `guid` | **IOPlatformUUID** | — |

`tolerance=1` absorbs an IDFV change or a fresh Keychain entry; two different
physical devices NEVER produce the same machine code. A full device erase
resets both iOS slots → the customer needs a new serial (same policy as the
Windows machine-transfer flow).

## Usage

```swift
import SecureCodeKit

// app launch (background queue recommended — methods do file I/O + crypto)
let config = ProtectionConfig(
    productId: "7e9a6cec-c185-45bb-a2fb-d31e96484f7e",
    productName: "MyApp",
    publicKey: ProtectionConfig.publicKey(fromHex: "…your key…"), // demo key is the default
    requireCodeSignature: true,   // macOS production builds
    devMode: false
)
let runtime = ProtectionRuntime.bootstrap(config)   // anti-debug + integrity + clock wiring
let client = runtime.licenseClient(config)

// activation screen
let machineCode = client.machineCode()      // XXXX-XXXX-XXXX-XXXX → send to the vendor
let result = client.activate(serialText)
if result.ok { /* unlock: result.payload?.customer / .expiresAtUnix / .featureFlags */ }

// every launch
let status = client.verifyInstalled(degraded: runtime.degraded)
if status.isValid {
    // start the real app (status.secondsLeft, status.payload…)
} else {
    // activation / error screen (status.state/message)
}
```

`LicenseState` mirrors the Windows client: `.valid, .missing, .invalid,
.expired, .wrongMachine, .revoked, .clockTampered, .damaged, .degraded`.

Machine transfer (deactivation request → vendor permit):

```swift
let requestURL = try client.makeDeactivationRequest(to: desktopURL)
// vendor issues a permit file; then:
let (ok, message) = client.deactivateWithPermit(at: permitURL)
```

## Verify the port (conformance)

```bash
cd sdks/apple/SecureCodeKit
swift test        # VectorConformanceTests against Tests/…/vectors.json
```

The suite also runs `SecureCodeSelfTest` and prints a report you can validate
from the repo root:

```bash
python -m tests.cross_platform_vectors --check <report.json>
```

## Before release

1. **Embed YOUR public key** (default is the DEMO key) — export from the
   protector and pass `publicKey:`.
2. **macOS: enable `requireCodeSignature`** for production (unsigned dev
   builds would fail — that's why it's opt-in).
3. **Rotate the string layer + masters**: `python sdks/gen_strings.py`
   regenerates `SecureStrings.swift`; do NOT commit the regenerated
   `sdks/gen_strings_masters.json`.
4. `devMode` must be `false` in release (anti-debug + integrity active).
5. Call `runtime.handle.shutdown()` (`Handle.shutdown()`) on clean app exit
   to stop watchdog threads.
