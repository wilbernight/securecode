"""Verify the platform-aware fingerprint parsing (protector side).

The optional "platform" key in fingerprint export files (written by the
Android/iOS/macOS SDKs and, since v3.1, the Windows client too) must:
  1. select the correct human component labels per platform,
  2. default to "windows" for legacy exports and bare pasted codes,
  3. be rejected when unknown, and
  4. never change the underlying code/mask decoding (wire format frozen).

Run from the repository root:  python tests/platform_fingerprint_test.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protector.core.fingerprint import (  # noqa: E402
    FingerprintParseError,
    parse_fingerprint,
    platform_display_name,
    platform_slots,
    read_fingerprint_file,
)
from shared.payload_schema import (  # noqa: E402
    KNOWN_PLATFORMS,
    PLATFORM_COMPONENT_LABELS,
)
from tests.cross_platform_vectors import VECTORS_PATH  # noqa: E402

failures = 0


def check(ok: bool, label: str) -> None:
    global failures
    mark = "OK " if ok else "FAIL"
    if not ok:
        failures += 1
    print(f"  [{mark}] {label}")


# --- take a real full-4-component code from the conformance vectors -------------
vectors = json.loads(VECTORS_PATH.read_text("utf-8"))
code = next(c["code"] for c in vectors["fingerprint"] if c["mask"] == 0x0F)

print("SecureCode — platform-aware fingerprint test")
print("=" * 52)

# 1) schema tables are complete and consistent
check(KNOWN_PLATFORMS == ("windows", "android", "ios", "macos"),
      "KNOWN_PLATFORMS = windows/android/ios/macos")
check(set(PLATFORM_COMPONENT_LABELS) == set(KNOWN_PLATFORMS),
      "labels table covers exactly the known platforms")
expected_slots = {"windows": ["cpu", "board", "disk", "guid"],
                  "android": ["cpu", "board", "disk"],
                  "ios": ["cpu", "board"],
                  "macos": ["cpu", "board", "guid"]}
check(all(platform_slots(p) == s for p, s in expected_slots.items()),
      "platform_slots() per OS (unused slots hidden)")

# 2) bare code -> windows defaults; decoding identical for every platform
base = parse_fingerprint(code)
check(base.platform == "windows" and base.mask == 0x0F,
      "bare code defaults to platform=windows")
per_platform = {p: parse_fingerprint(code, p) for p in KNOWN_PLATFORMS}
check(all(i.code == base.code and i.mask == base.mask
          for i in per_platform.values()),
      "platform never changes code/mask decoding (frozen wire format)")
check("Widevine DRM device ID" in per_platform["android"].present_names
      and "SSAID (Settings.Secure.ANDROID_ID)" in
      per_platform["android"].present_names,
      "android labels (Widevine + SSAID)")
check(per_platform["ios"].present_names == ["Keychain UUID (vendor-persistent)",
                                            "IDFV (identifierForVendor)"],
      "ios labels (Keychain UUID + IDFV only)")
check("Mac serial (IOPlatformSerialNumber)" in per_platform["macos"].present_names
      and "IOPlatformUUID" in per_platform["macos"].present_names,
      "macos labels (en0 + serial + platform UUID)")
# slots the platform never fills must not appear as "missing"
check(all(not info.missing_names for info in per_platform.values()),
      "unused slots are not reported missing")

# 3) export files: platform key, legacy default, unknown rejection
with tempfile.TemporaryDirectory() as tmp:
    def export(payload: dict) -> Path:
        path = Path(tmp) / "fingerprint.txt"
        base_payload = {"format": "securecode-fingerprint", "version": 1,
                        "code": code, "present": {}, "product_id": "x",
                        "created": 0}
        base_payload.update(payload)
        path.write_text(json.dumps(base_payload), "utf-8")
        return path

    info = read_fingerprint_file(export({"platform": "macos"}))
    check(info.platform == "macos" and "MAC address (en0)" in info.present_names,
          "export with platform=macos parses with macos labels")
    info = read_fingerprint_file(export({}))
    check(info.platform == "windows",
          "legacy export (no platform key) -> windows")
    try:
        read_fingerprint_file(export({"platform": "plan9"}))
        check(False, "unknown platform rejected")
    except FingerprintParseError:
        check(True, "unknown platform rejected")

    # 3b) hardening: malformed/oversized exports fail with CONTROLLED errors
    bad = Path(tmp) / "bad_created.txt"
    bad.write_text(json.dumps({"format": "securecode-fingerprint",
                               "platform": "android", "code": code,
                               "created": "not-a-number"}), "utf-8")
    try:
        read_fingerprint_file(bad)
        check(False, "non-numeric created -> controlled error")
    except FingerprintParseError:
        check(True, "non-numeric created -> controlled error")

    arr = Path(tmp) / "array.txt"
    arr.write_text("[1, 2, 3]", "utf-8")
    try:
        read_fingerprint_file(arr)
        check(False, "non-object JSON -> controlled error")
    except FingerprintParseError:
        check(True, "non-object JSON -> controlled error")

    huge = Path(tmp) / "huge.txt"
    huge.write_text('{"format": "securecode-fingerprint", "code": "' +
                    "A" * (2 << 20) + '"}', "utf-8")
    try:
        read_fingerprint_file(huge)
        check(False, "oversized export -> controlled error")
    except FingerprintParseError as exc:
        check("large" in exc.user_message.lower() or
              "suspiciously" in exc.user_message.lower(),
              "oversized export -> controlled error")

# 4) display names for the UI badge
check([platform_display_name(p) for p in KNOWN_PLATFORMS] ==
      ["Windows", "Android", "iOS", "macOS"],
      "platform_display_name for badges")

print("=" * 52)
print("RESULT:", "ALL PASSED" if failures == 0 else f"{failures} FAILED")
sys.exit(1 if failures else 0)
