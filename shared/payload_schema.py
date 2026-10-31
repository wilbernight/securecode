"""
shared.payload_schema — Canonical license payload schema + hardware-fingerprint
code format. THE contract between the protector (signing) and the protected
client (verifying).

Serial key wire format
----------------------
    serial_text = Base32( canonical_payload_bytes || Ed25519_signature(64B) )

* canonical_payload_bytes = minified, key-sorted, ASCII JSON of the payload
  dict (see LicensePayload.canonical_bytes). The signature is computed over
  exactly these bytes, so both sides must produce byte-identical JSON.
* Display form groups Base32 characters in blocks of 5 separated by '-'
  (e.g. ABCDE-FGHij-...). Decoders accept any casing, spacing and dashes.

Hardware fingerprint code format (the "XXXX-XXXX-XXXX-XXXX" machine code)
-------------------------------------------------------------------------
    code = Base32( mask_byte(1B) || SHA256(salt || mask || components)[:9] )

* mask_byte low nibble: bit0=CPU present, bit1=motherboard, bit2=disk,
  bit3=machine-guid. A component that could not be read is substituted with
  an empty string BEFORE hashing, so a machine that later loses a component
  (e.g. disk swap) can still re-derive the same code through the tolerance
  mechanism implemented in target_demo/protection/fingerprint.py.
* 80 bits of material (10 bytes -> exactly 16 Base32 chars) is collision-safe
  for a realistic customer base while staying human-typeable.

No secrets are defined here. The fingerprint salt is a *public* domain
separator: it prevents cross-vendor fingerprint collisions. Its obfuscated
composition below only avoids trivially greppable constants in the shipped
binary (it provides no cryptographic secrecy and does not need to).
"""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

from .exceptions import SerialFormatError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Domain-separation salt for fingerprint hashing. Compiled into BOTH apps.
#: Deliberately assembled from parts at import time (see module docstring).
_FINGERPRINT_SALT_PARTS: tuple[bytes, ...] = (
    b"\x53\x65\x63\x75\x72\x65",      # "Secure"
    b"\x43\x6f\x64\x65",              # "Code"
    b"\x2d\x76\x31\x2e\x30",          # "-v1.0"
    b"\x2f\x66\x70\x2d\x73\x61\x6c\x74",  # "/fp-salt"
)
FINGERPRINT_SALT: bytes = b"".join(_FINGERPRINT_SALT_PARTS)

#: Fingerprint component order — MUST stay stable across releases, because
#: it defines both the mask bit positions and the hash input order.
COMPONENT_ORDER: tuple[str, ...] = ("cpu", "board", "disk", "guid")

#: Bit position (in the mask byte's low nibble) for each component.
COMPONENT_MASK_BITS: dict[str, int] = {
    "cpu": 0x01,
    "board": 0x02,
    "disk": 0x04,
    "guid": 0x08,
}

#: Current payload schema version ("v" field). Bump on breaking changes.
PAYLOAD_VERSION: int = 1

#: Serial Base32 display group size.
SERIAL_GROUP_SIZE: int = 5

#: Ed25519 signature length in bytes (fixed by RFC 8032).
SIGNATURE_LEN: int = 64

#: Minimum/maximum sane unix timestamps accepted in payloads
#: (2020-01-01 .. 2100-01-01).
_MIN_TS: int = 1_577_836_800
_MAX_TS: int = 4_102_444_800

#: Lifetime licenses are encoded as exp == 0.
EXP_LIFETIME: int = 0


# ---------------------------------------------------------------------------
# Duration presets (used by the protector "Generate Serial" page)
# ---------------------------------------------------------------------------
DURATION_PRESETS: tuple[tuple[str, int], ...] = (
    ("30 days", 30),
    ("6 months", 182),
    ("1 year", 365),
    ("2 years", 730),
    ("Lifetime", 0),  # sentinel -> exp = EXP_LIFETIME
)


# ---------------------------------------------------------------------------
# Platform registry (which OS a fingerprint export came from)
# ---------------------------------------------------------------------------
#: Canonical platform identifiers. The optional "platform" key in
#: fingerprint export files identifies the OS the code was recorded on;
#: exports WITHOUT the key are legacy Windows exports ("windows").
#: NOTE: this is metadata only — the serial/wire format is UNCHANGED. Every
#: platform reuses the same four hash slots (cpu/board/disk/guid) and maps
#: its own identifiers onto them (see PLATFORM_COMPONENT_LABELS).
KNOWN_PLATFORMS: tuple[str, ...] = ("windows", "android", "ios", "macos")

#: Display names for the platform badges in the protector UI.
PLATFORM_DISPLAY_NAMES: dict[str, str] = {
    "windows": "Windows",
    "android": "Android",
    "ios": "iOS",
    "macos": "macOS",
}

#: What each hash slot means on each platform (keys follow COMPONENT_ORDER;
#: "" marks slots the platform leaves empty). The protector uses these for
#: human-readable component labels so vendors see the right identifiers
#: (e.g. "board" is the motherboard serial on Windows but SSAID on Android).
PLATFORM_COMPONENT_LABELS: dict[str, dict[str, str]] = {
    "windows": {
        "cpu": "CPU (ProcessorId)",
        "board": "Motherboard serial",
        "disk": "Primary disk serial",
        "guid": "Machine GUID (registry)",
    },
    "android": {
        "cpu": "Widevine DRM device ID",
        "board": "SSAID (Settings.Secure.ANDROID_ID)",
        "disk": "Keystore key digest (optional)",
        "guid": "",
    },
    "ios": {
        "cpu": "Keychain UUID (vendor-persistent)",
        "board": "IDFV (identifierForVendor)",
        "disk": "",
        "guid": "",
    },
    "macos": {
        "cpu": "MAC address (en0)",
        "board": "Mac serial (IOPlatformSerialNumber)",
        "disk": "",
        "guid": "IOPlatformUUID",
    },
}


# ---------------------------------------------------------------------------
# Hardware fingerprint code helpers (shared by protector + client)
# ---------------------------------------------------------------------------
def normalize_component(value: str | None) -> str:
    """Normalize a hardware identifier before hashing.

    WMI/registry serials inconsistently contain whitespace, trailing NULs
    (older BIOS serials) and mixed casing. Normalization makes the code
    stable across reboots and WMI providers.
    """
    if not value:
        return ""
    return value.strip().strip("\x00").strip().lower()


def compute_fingerprint_digest(components: Mapping[str, str]) -> tuple[int, bytes]:
    """Compute (mask, digest) for a normalized component mapping.

    Args:
        components: mapping with any subset of keys from COMPONENT_ORDER.
            Values are raw (not yet normalized) identifiers.

    Returns:
        (mask, 10-byte material) where ``material = mask_byte || digest[:9]``
        — ready to be Base32-encoded into the 16-char machine code.
    """
    mask = 0
    parts: list[bytes] = [FINGERPRINT_SALT]
    for name in COMPONENT_ORDER:
        norm = normalize_component(components.get(name))
        if norm:
            mask |= COMPONENT_MASK_BITS[name]
        parts.append(f"{name}={norm};".encode("utf-8"))
    # Include the mask in the hash so different presence combinations always
    # produce different codes.
    parts.append(b"mask=%d" % mask)
    digest = hashlib.sha256(b"".join(parts)).digest()
    return mask, bytes([mask]) + digest[:9]


def parse_component_mask(mask: int) -> dict[str, bool]:
    """Decode a mask byte into {component: present} for display purposes."""
    return {
        name: bool(mask & COMPONENT_MASK_BITS[name])
        for name in COMPONENT_ORDER
    }


# ---------------------------------------------------------------------------
# Payload dataclass
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class LicensePayload:
    """The signed body of a serial key.

    Field name abbreviations keep serials compact (JSON keys are stored in
    every serial). Full names are exposed as read-only properties below.
    """

    fingerprint: str                 # machine code "XXXX-XXXX-XXXX-XXXX"
    product_id: str                  # product UUID string (lowercase)
    issued_at: int                   # unix ts (seconds)
    expires_at: int                  # unix ts; 0 = lifetime
    customer: str = ""               # free-form customer name/ID (optional)
    nonce: str = ""                  # 16-byte hex; uniqueness + revocation id
    feature_flags: dict[str, bool] = field(default_factory=dict)
    tolerance: int = 1               # missing-fingerprint-components allowed
    rollback_allowance: int = 3      # clock rollbacks tolerated
    version: int = PAYLOAD_VERSION

    # -------------------------------------------------- serialization
    def to_dict(self) -> dict[str, Any]:
        """Serialize to the compact wire dict (short keys)."""
        return {
            "v": self.version,
            "fp": self.fingerprint,
            "pid": str(self.product_id),
            "iat": int(self.issued_at),
            "exp": int(self.expires_at),
            "cust": self.customer,
            "n": self.nonce,
            "fl": {str(k): bool(v) for k, v in self.feature_flags.items()},
            "tol": int(self.tolerance),
            "rb": int(self.rollback_allowance),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LicensePayload:
        """Parse the compact wire dict back into a dataclass, with validation."""
        try:
            payload = cls(
                version=int(data["v"]),
                fingerprint=str(data["fp"]),
                product_id=str(data["pid"]),
                issued_at=int(data["iat"]),
                expires_at=int(data["exp"]),
                customer=str(data.get("cust", "")),
                nonce=str(data.get("n", "")),
                feature_flags={str(k): bool(v)
                               for k, v in dict(data.get("fl") or {}).items()},
                tolerance=int(data.get("tol", 1)),
                rollback_allowance=int(data.get("rb", 3)),
            )
        except KeyError as exc:
            raise SerialFormatError(f"payload missing required field: {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise SerialFormatError(f"payload field has invalid type: {exc}") from exc
        payload.validate()
        return payload

    def canonical_bytes(self) -> bytes:
        """Byte-exact JSON used for BOTH signing (protector) and verifying
        (client). sort_keys + compact separators make the encoding canonical."""
        import json
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    # -------------------------------------------------- validation
    def validate(self) -> None:
        """Structural validation (no crypto involved). Raises SerialFormatError."""
        if self.version != PAYLOAD_VERSION:
            raise SerialFormatError(f"unsupported payload version {self.version}")
        if self.expires_at != EXP_LIFETIME and not (_MIN_TS <= self.expires_at <= _MAX_TS):
            raise SerialFormatError("expires_at out of sane range")
        if not (_MIN_TS <= self.issued_at <= _MAX_TS):
            raise SerialFormatError("issued_at out of sane range")
        if self.expires_at != EXP_LIFETIME and self.expires_at < self.issued_at:
            raise SerialFormatError("expires_at before issued_at")
        try:
            uuid.UUID(self.product_id)
        except (ValueError, AttributeError) as exc:
            raise SerialFormatError("product_id is not a UUID") from exc
        # Fingerprint codes are 16 base32 chars; dashes optional.
        compact = self.fingerprint.replace("-", "").strip().upper()
        if len(compact) != 16 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in compact):
            raise SerialFormatError("fingerprint field is not a valid machine code")
        if self.nonce and (len(self.nonce) != 32 or not all(c in "0123456789abcdef" for c in self.nonce.lower())):
            raise SerialFormatError("nonce must be 16 bytes of hex")
        # Bound the binding-relaxation knobs: a tolerance >= the number of
        # fingerprint components would let the machine-match succeed with all
        # components dropped (i.e. no hardware binding at all). Keep it strictly
        # below the component count, and keep rollback allowance non-negative.
        if not (0 <= self.tolerance < len(COMPONENT_ORDER)):
            raise SerialFormatError("tolerance out of range")
        if self.rollback_allowance < 0:
            raise SerialFormatError("rollback_allowance must be non-negative")

    # -------------------------------------------------- convenience
    @property
    def is_lifetime(self) -> bool:
        """True when this license never expires."""
        return self.expires_at == EXP_LIFETIME

    def seconds_left(self, now: int | None = None) -> int:
        """Seconds until expiry (negative if already expired; huge if lifetime)."""
        if self.is_lifetime:
            return _MAX_TS - int(now or time.time())
        return self.expires_at - int(now or time.time())

    @staticmethod
    def new_nonce() -> str:
        """Generate a fresh 16-byte (32 hex char) revocation nonce."""
        return secrets.token_hex(16)


__all__ = [
    "COMPONENT_ORDER",
    "COMPONENT_MASK_BITS",
    "DURATION_PRESETS",
    "EXP_LIFETIME",
    "FINGERPRINT_SALT",
    "LicensePayload",
    "PAYLOAD_VERSION",
    "SERIAL_GROUP_SIZE",
    "SIGNATURE_LEN",
    "compute_fingerprint_digest",
    "normalize_component",
    "parse_component_mask",
]
