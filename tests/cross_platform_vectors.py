"""
tests.cross_platform_vectors — byte-exact compatibility vectors for every
SecureCode client SDK (Windows/Python, Android/Kotlin, Apple/Swift,
Flutter/Dart).

Generates ``sdks/vectors.json``: fixed inputs + expected outputs for the
wire-format primitives that MUST behave identically on every platform:

    * Base32 encode/decode (incl. the 0/1/8/9 repair heuristic)
    * hardware-fingerprint digest + machine-code derivation
    * canonical JSON payload bytes (byte-identical to Python's
      json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    * full serial envelopes (Base32 body||Ed25519 signature) signed with the
      shipped DEMO keypair — the same key embedded in every demo SDK build
    * Ed25519 verify vectors (valid + tampered)
    * HKDF-SHA256 machine-key derivation (parity with
      target_demo/protection/crypto_utils.derive_machine_key, with an
      explicit test master instead of the embedded secret)

Usage:
    python -m tests.cross_platform_vectors            # regenerate + selftest
    python -m tests.cross_platform_vectors --check out.json
        # validate an SDK self-test report (see sdks/*/README.md)

The file is checked in; regenerate after ANY change to shared/payload_schema
or shared/codec (that should essentially never happen — the format is frozen).
"""

from __future__ import annotations

import base64
import json
import sys
import time
import uuid
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.codec import b32_decode, b32_encode, decode_envelope, encode_envelope
from shared.exceptions import SerialFormatError
from shared.payload_schema import LicensePayload, compute_fingerprint_digest

VECTORS_PATH = _REPO_ROOT / "sdks" / "vectors.json"

#: Explicit TEST master secret for HKDF vectors (NOT the embedded one —
#: each SDK tests its hkdf() primitive, not the shipped secret).
TEST_MASTER = "SC-VECTOR-MASTER-2026"


def _derive_test_key(master: str, machine_code: str, product_id: str,
                     context: str) -> bytes:
    """Identical construction to crypto_utils.derive_machine_key, with the
    master as an explicit parameter (the embedded S() secret stays secret)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    ikm = master.encode("ascii") + b"|" + machine_code.encode("ascii")
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=product_id.encode("ascii"),
                info=context.encode("utf-8")).derive(ikm)

DEMO_PRODUCT_ID = "7e9a6cec-c185-45bb-a2fb-d31e96484f7e"


def _load_demo_key() -> tuple[bytes, bytes]:
    """Unwrap the shipped demo keypair (matches every SDK's default pubkey)."""
    from protector.core.crypto_engine import unwrap_container

    blob = (_REPO_ROOT / "demo-assets" / "demo_keypair.sec").read_bytes()
    demo = unwrap_container("demo-demo-demo", blob)
    seed = base64.b64decode(demo["private_key"])
    pub = base64.b64decode(demo["public_key"])
    return seed, pub


# ---------------------------------------------------------------------------
# Vector builders
# ---------------------------------------------------------------------------
def _base32_vectors() -> list[dict]:
    cases = [
        b"",
        b"\x00",
        b"\xff" * 10,
        b"SecureCode-v1.0/fp-salt",
        bytes(range(32)),
        b"The quick brown fox jumps over the lazy dog",
    ]
    vectors = [
        {"hex": c.hex(), "text": b32_encode(c)}
        for c in cases
    ]
    # Decode-only repair cases (transcription errors a customer might make).
    vectors.append(
        {"hex": b"license.dat".hex(),
         "text": b32_encode(b"license.dat"), "repaired": "l1cense.dat"})
    return vectors


def _fingerprint_vectors() -> list[dict]:
    """(cpu, board, disk, guid) -> mask + material + code.

    Includes: all-present, missing components, unicode values, trailing
    NULs/whitespace/casing (normalize_component is exercised).
    """
    cases = [
        {"cpu": "BFEBFBFF000906EA", "board": "M80-5A", "disk": "S6XPNZ0R",
         "guid": "d4f9b6e2-4a8f-4f0f-9d8b-1a2b3c4d5e6f"},
        {"cpu": "", "board": "M80-5A", "disk": "", "guid": "d4f9b6e2-..."},
        {"cpu": "  BFEBFBFF000906EA  \x00 ", "board": "m80-5a",
         "disk": "S6XPNZ0R", "guid": "D4F9B6E2-4A8F-4F0F-9D8B-1A2B3C4D5E6F"},
        {"cpu": "آزمون-سخت-افزار-۱", "board": "بردة-مادر",
         "disk": "دیسک", "guid": "گویید"},
        {"cpu": "widevine:6vN0bWFgSC1ndW1t", "board": "18f7a2bc9d34e5f0",
         "disk": "", "guid": ""},
        {"cpu": "widevine:6vN0bWFgSC1ndW1t", "board": "18f7a2bc9d34e5f0",
         "disk": "keystore:9f:aa:03:cb", "guid": ""},
        {"cpu": "keychain:4711beef-dead", "board": "idfv:8C123...", "disk": "",
         "guid": ""},
        {"cpu": "en0:a4:83:e7:11:22:33", "board": "C02X1234ABCD",
         "disk": "", "guid": "3A6B1F9E-2C4D-4E5F-9A0B-7C8D9E0F1A2B"},
    ]
    vectors = []
    for comp in cases:
        mask, material = compute_fingerprint_digest(comp)
        vectors.append({
            "components": {k: (v if v else None) for k, v in comp.items()},
            "mask": mask,
            "material_hex": material.hex(),
            "code": "-".join(b32_encode(material)[i:i + 4]
                             for i in range(0, 16, 4)),
        })
    return vectors


def _payload_dicts() -> list[dict]:
    return [
        {  # plain
            "v": 1, "fp": "AB234567CDEFGHIJ", "pid": DEMO_PRODUCT_ID,
            "iat": 1_770_000_000, "exp": 1_803_542_400, "cust": "E2E Test Corp",
            "n": "00112233445566778899aabbccddeeff", "fl": {"core": True},
            "tol": 1, "rb": 3,
        },
        {  # lifetime + no customer + no flags
            "v": 1, "fp": "AB234567CDEFGHIJ", "pid": DEMO_PRODUCT_ID,
            "iat": 1_770_000_000, "exp": 0, "cust": "", "n": "",
            "fl": {}, "tol": 1, "rb": 3,
        },
        {  # tricky strings: quotes, backslash, control chars, DEL, unicode
            "v": 1, "fp": "AB234567CDEFGHIJ", "pid": DEMO_PRODUCT_ID,
            "iat": 1_770_000_000, "exp": 1_803_542_400,
            "cust": 'شرکت "نمونه"\n\\tab￿\x1f\x7f',
            "n": "ffeeddccbbaa99887766554433221100",
            "fl": {"م导读": False, "z_last": True, "a_first": True,
                   "emoji\U0001F600": True},
            "tol": 2, "rb": 0,
        },
    ]


def _canonical_json_vectors() -> list[dict]:
    return [
        {"payload": p,
         "canonical_hex": LicensePayload.from_dict(p).canonical_bytes().hex()}
        for p in _payload_dicts()
    ]


def _serial_vectors(pub: bytes) -> list[dict]:
    return [
        {"payload": p, "public_key_hex": pub.hex(),
         "body_hex": LicensePayload.from_dict(p).canonical_bytes().hex()}
        for p in _payload_dicts()
    ]


def _ed25519_vectors(seed: bytes) -> list[dict]:
    vectors = []
    for data in (b"", b"attack at dawn", bytes(range(64)), "تأیید".encode()):
        sig = Ed25519PrivateKey.from_private_bytes(seed).sign(data)
        vectors.append({"message_hex": data.hex(), "signature_hex": sig.hex(),
                        "public_key_hex": _PUB.hex(), "valid": True})
        # Tampered: flip one message bit -> must fail.
        bad = bytearray(data)
        if bad:
            bad[0] ^= 0x01
        else:
            bad.append(0x00)
        vectors.append({"message_hex": bytes(bad).hex(),
                        "signature_hex": sig.hex(),
                        "public_key_hex": _PUB.hex(), "valid": False})
    return vectors


def _hkdf_vectors() -> list[dict]:
    vectors = []
    for code in ("AB234567CDEFGHIJ", "AB234567CDEFGHIJ"):
        for context in ("license-file-v1", "clock-store-v1", "keystore-v1"):
            key = _derive_test_key(TEST_MASTER, code, DEMO_PRODUCT_ID, context)
            vectors.append({
                "master": TEST_MASTER, "machine_code": code,
                "product_id": DEMO_PRODUCT_ID, "context": context,
                "key_hex": key.hex(),
            })
    return vectors


# ---------------------------------------------------------------------------
# Generate / validate
# ---------------------------------------------------------------------------
def generate() -> dict:
    seed, pub = _load_demo_key()
    global _PUB
    _PUB = pub

    # Sign each serial vector body with the demo key (deterministic Ed25519).
    serials = _serial_vectors(pub)
    for v in serials:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        sig = Ed25519PrivateKey.from_private_bytes(seed).sign(
            bytes.fromhex(v["body_hex"]))
        v["serial"] = encode_envelope(bytes.fromhex(v["body_hex"]), sig)
        # Round-trip sanity (fails loudly if the format drifted).
        body, s2 = decode_envelope(v["serial"])
        assert body == bytes.fromhex(v["body_hex"]) and s2 == sig

    return {
        "format": "securecode-vectors",
        "version": 1,
        "generated_at": int(time.time()),
        "notes": (
            "Byte-exact conformance vectors for all SecureCode client SDKs. "
            "Every SDK ships a self-test that consumes this file (see "
            "sdks/README.md). fingerprint.code uses 4x4 grouping; serials "
            "use 5-char groups."
        ),
        "base32": _base32_vectors(),
        "fingerprint": _fingerprint_vectors(),
        "canonical_json": _canonical_json_vectors(),
        "serial": serials,
        "ed25519": _ed25519_vectors(seed),
        "hkdf": _hkdf_vectors(),
    }


def selftest(vectors: dict) -> None:
    """Prove the freshly generated vectors round-trip through the Python
    client stack itself (the reference implementation)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    for v in vectors["serial"]:
        body, sig = decode_envelope(v["serial"])
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(v["public_key_hex"])).verify(sig, body)
        LicensePayload.from_dict(json.loads(body.decode("utf-8")))
    for v in vectors["fingerprint"]:
        assert len(v["code"]) == 19 and v["code"].count("-") == 3
    for v in vectors["base32"]:
        assert b32_decode(v["text"]) == bytes.fromhex(v["hex"])



def main(argv: list[str]) -> int:
    if "--check" in argv:
        idx = argv.index("--check")
        report_path = Path(argv[idx + 1])
        report = json.loads(report_path.read_text(encoding="utf-8"))
        results = report.get("results", [])
        bad = [r for r in results if not r.get("ok")]
        for r in bad:
            print(f"  ⛔ {r.get('name')}: {r.get('detail', '')}")
        print(f"{report.get('sdk', '?')}: {len(results) - len(bad)}/{len(results)}"
              f" vectors passed -> {'OK' if not bad and results else 'FAILED'}")
        return 0 if (not bad and results) else 1

    vectors = generate()
    selftest(vectors)
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(
        json.dumps(vectors, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {VECTORS_PATH} "
          f"({len(vectors['serial'])} serials, "
          f"{len(vectors['fingerprint'])} fingerprints, "
          f"{len(vectors['ed25519'])} ed25519 cases)")
    print("reference self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
