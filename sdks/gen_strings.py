"""
sdks.gen_strings — generates the obfuscated string tables (anti-RE Layer 2)
for the mobile client SDKs, mirroring protector/tools/build_strings_table.py
concept for the native (Kotlin/Swift) ports.

    * Plaintext constants (user-facing messages, file names, the embedded
      machine-key master secret) never appear as readable strings in the
      shipped binary — they are stored as XOR-masked byte literals.
    * The mask key is derived at RUNTIME from three scattered byte parts
      (SHA-256), never as one contiguous blob.
    * Per-entry keystream: SHA256(key || entry_id || block_index), so the
      same key never masks two entries the same way.
    * No caching: every S() call re-derives.

Regenerate after editing ENTRIES (run from the repo root):
    python -m sdks.gen_strings [--masters-only]

The generated files are checked in (sdks/android/securecode-sdk/src/main/
kotlin/.../SecureStrings.kt and sdks/apple/SecureCodeKit/Sources/
SecureCodeKit/SecureStrings.swift). The masters are random per platform and
NOT the Windows master — a license file from one platform can never be
decrypted on another (each platform only ever reads its own files anyway).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sys

# ---------------------------------------------------------------------------
# Entry table (single source of truth for BOTH generated files)
# ---------------------------------------------------------------------------
MESSAGES: dict[str, str] = {
    "msg_malformed": "The serial key is malformed. Please re-enter it exactly as issued.",
    "msg_invalid": "This serial key is not valid for this product.",
    "msg_product": "This serial key was issued for a different product.",
    "msg_other_machine": "This serial key is bound to another device.",
    "msg_expired": "This license has expired.",
    "msg_future": "The device clock is set incorrectly (serial issued in the future).",
    "msg_revoked": "This serial key has been revoked.",
    "msg_not_installed": "No license is installed on this device.",
    "msg_clock": "Clock tampering detected. Set the correct date and time, then restart.",
    "msg_damaged": "The local license data is damaged. Re-activation required.",
}

FILE_NAMES: dict[str, str] = {
    "license_name": "license.dat",
    "blacklist_name": "blacklist.sec",
    "decoy_name": "cache.bin",
    "receipt_name": "deactivation_receipt.txt",
    "prefs_name": "sc_sync",
    "prefs_key": "sync_ts",
    "keystore_alias": "sc-fp-key",
    "fp_export_format": "securecode-fingerprint",
    "deact_request_format": "securecode-deactivation-request",
    "deact_permit_action": "transfer",
}

#: Default embedded Ed25519 public key (the SHIPPED DEMO keypair — matches
#: demo-assets/demo_keypair.sec, same as the Windows demo client).
DEMO_PUBKEY_HEX = (
    "dcb2c1a8a2ecf13907613e0263d62ac382e331caec10587a21d29785a4014a5b")

MASTERS_FILE = "sdks/gen_strings_masters.json"


def _load_or_create_masters() -> dict[str, str]:
    """Per-platform master secrets — created once, stable afterwards."""
    from pathlib import Path

    path = Path(MASTERS_FILE)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    masters = {
        "android_master": secrets.token_hex(16),
        "apple_master": secrets.token_hex(16),
    }
    path.write_text(json.dumps(masters, indent=2), encoding="utf-8")
    return masters


# ---------------------------------------------------------------------------
# Obfuscation core (shared construction for both target languages)
# ---------------------------------------------------------------------------
def _platform_parts(platform_master: str) -> list[bytes]:
    """Three scattered 16-byte parts, derived from the platform master so
    regeneration is deterministic for a given master (no separate state)."""
    digest = hashlib.sha256(platform_master.encode("ascii")).digest()
    digest2 = hashlib.sha256(("scramble" + platform_master).encode("ascii")).digest()
    return [digest[:16], digest[16:32], digest2[:16]]


def _mask_key(parts: list[bytes]) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def _keystream(key: bytes, entry_id: str, length: int) -> bytearray:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(
            key + entry_id.encode("ascii") + bytes([counter])).digest()
        counter += 1
    return out[:length]


def _xor_mask(parts: list[bytes], entry_id: str, plaintext: bytes) -> bytes:
    ks = _keystream(_mask_key(parts), entry_id, len(plaintext))
    return bytes(a ^ b for a, b in zip(plaintext, ks))


# ---------------------------------------------------------------------------
# Kotlin generator
# ---------------------------------------------------------------------------
def gen_kotlin() -> str:
    masters = _load_or_create_masters()
    parts = _platform_parts(masters["android_master"])
    entries = {**MESSAGES, **FILE_NAMES,
               "license_master": masters["android_master"],
               "pubkey": DEMO_PUBKEY_HEX}

    lines = [
        "// GENERATED by sdks/gen_strings.py — DO NOT EDIT BY HAND.",
        "// Obfuscated string layer (anti-RE Layer 2). Regenerate via",
        "//   python -m sdks.gen_strings",
        "package com.securecode.protection",
        "",
        "/** Obfuscated constants store — see sdks/gen_strings.py. */",
        "internal object SecureStrings {",
        "    private val ka = byteArrayOf(" + _kotlin_bytes(parts[0]) + ")",
        "    private val kb = byteArrayOf(" + _kotlin_bytes(parts[1]) + ")",
        "    private val kc = byteArrayOf(" + _kotlin_bytes(parts[2]) + ")",
        "",
        "    @Suppress(" + json.dumps("unused") + ")",
        "    private val entries: Map<String, ByteArray> = mapOf(",
    ]
    for eid, plain in entries.items():
        masked = _xor_mask(parts, eid, plain.encode("utf-8"))
        lines.append(
            f"        {json.dumps(eid)} to byteArrayOf({_kotlin_bytes(masked)}),")
    lines += [
        "    )",
        "",
        "    private fun maskKey(): ByteArray {",
        "        val d = java.security.MessageDigest.getInstance(\"SHA-256\")",
        "        d.update(ka); d.update(kb); d.update(kc)",
        "        return d.digest()",
        "    }",
        "",
        "    /** Decrypt-on-call string entry (no caching, Layer-5 hygiene). */",
        "    fun s(id: String): String = String(bytes(id))",
        "",
        "    /** Decrypt-on-call raw bytes (callers should zero their copy). */",
        "    fun bytes(id: String): ByteArray {",
        "        val masked = entries[id] ?: return ByteArray(0)",
        "        val key = maskKey()",
        "        val out = ByteArray(masked.size)",
        "        var counter = 0",
        "        var filled = 0",
        "        while (filled < masked.size) {",
        "            val block = java.security.MessageDigest.getInstance(\"SHA-256\")",
        "                .let { d ->",
        "                    d.update(key); d.update(id.toByteArray(Charsets.US_ASCII))",
        "                    d.update(counter.toByte()); d.digest()",
        "                }",
        "            var i = 0",
        "            while (i < block.size && filled < masked.size) {",
        "                out[filled] = (masked[filled].toInt() xor block[i].toInt()).toByte()",
        "                i++; filled++",
        "            }",
        "            counter++",
        "        }",
        "        return out",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def _kotlin_bytes(data: bytes) -> str:
    return ", ".join(f"0x{b:02x}" for b in data)


# ---------------------------------------------------------------------------
# Swift generator
# ---------------------------------------------------------------------------
def gen_swift() -> str:
    masters = _load_or_create_masters()
    parts = _platform_parts(masters["apple_master"])
    entries = {**MESSAGES, **FILE_NAMES,
               "license_master": masters["apple_master"],
               "pubkey": DEMO_PUBKEY_HEX}

    lines = [
        "// GENERATED by sdks/gen_strings.py — DO NOT EDIT BY HAND.",
        "// Obfuscated string layer (anti-RE Layer 2). Regenerate via",
        "//   python -m sdks.gen_strings",
        "import Foundation",
        "import CryptoKit",
        "",
        "/// Obfuscated constants store — see sdks/gen_strings.py.",
        "enum SecureStrings {",
        "    private static let ka: [UInt8] = [" + _swift_bytes(parts[0]) + "]",
        "    private static let kb: [UInt8] = [" + _swift_bytes(parts[1]) + "]",
        "    private static let kc: [UInt8] = [" + _swift_bytes(parts[2]) + "]",
        "",
        "    private static let entries: [String: [UInt8]] = [",
    ]
    for eid, plain in entries.items():
        masked = _xor_mask(parts, eid, plain.encode("utf-8"))
        lines.append(
            f"        {json.dumps(eid)}: [{_swift_bytes(masked)}],")
    lines += [
        "    ]",
        "",
        "    private static func maskKey() -> [UInt8] {",
        "        var d = SHA256()",
        "        d.update(data: Data(ka)); d.update(data: Data(kb)); d.update(data: Data(kc))",
        "        return Array(d.finalize())",
        "    }",
        "",
        "    /// Decrypt-on-call string entry (no caching).",
        "    static func s(_ id: String) -> String {",
        "        String(data: Data(bytes(id)), encoding: .utf8) ?? \"\"",
        "    }",
        "",
        "    /// Decrypt-on-call raw bytes (callers should zero their copy).",
        "    static func bytes(_ id: String) -> [UInt8] {",
        "        guard let masked = entries[id] else { return [] }",
        "        let key = maskKey()",
        "        var out = [UInt8](repeating: 0, count: masked.count)",
        "        var counter = 0",
        "        var filled = 0",
        "        while filled < masked.count {",
        "            var d = SHA256()",
        "            d.update(data: Data(key))",
        "            id.utf8.forEach { d.update(data: Data([$0])) }",
        "            d.update(data: Data([UInt8(counter & 0xff)]))",
        "            let block = Array(d.finalize())",
        "            var i = 0",
        "            while i < block.count && filled < masked.count {",
        "                out[filled] = masked[filled] ^ block[i]",
        "                i += 1; filled += 1",
        "            }",
        "            counter += 1",
        "        }",
        "        return out",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def _swift_bytes(data: bytes) -> str:
    return ", ".join(f"0x{b:02x}" for b in data)


def main(argv: list[str]) -> int:
    from pathlib import Path

    if "--masters-only" in argv:
        _load_or_create_masters()
        print("masters ensured in", MASTERS_FILE)
        return 0
    kotlin_path = (Path("sdks") / "android" / "securecode-sdk" / "src" /
                  "main" / "kotlin" / "com" / "securecode" / "protection" /
                  "SecureStrings.kt")
    swift_path = (Path("sdks") / "apple" / "SecureCodeKit" / "Sources" /
                  "SecureCodeKit" / "SecureStrings.swift")
    kotlin_path.parent.mkdir(parents=True, exist_ok=True)
    swift_path.parent.mkdir(parents=True, exist_ok=True)
    kotlin_path.write_text(gen_kotlin(), encoding="utf-8")
    swift_path.write_text(gen_swift(), encoding="utf-8")
    print(f"wrote {kotlin_path}")
    print(f"wrote {swift_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
