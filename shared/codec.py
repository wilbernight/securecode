"""
shared.codec — Base32 encode/decode for serial keys, blacklist files, and
transfer permits, plus the generic signed-envelope format.

All protected artifacts exchanged between the protector and the client use
one envelope format:

    artifact_text = Base32( body_bytes || Ed25519_signature(64B) )

where body_bytes is canonical JSON produced by the signing side. The
verifying side splits the last 64 bytes as the signature (Ed25519 signatures
are fixed-length by RFC 8032, so no length prefix is needed).

Base32 (RFC 4648, uppercase, padding stripped) is used instead of Base64
because it survives manual transcription: no confusing 0/O or 1/l pairs in
the standard alphabet (the alphabet excludes 0, 1, 8 and 9 entirely) and it
is case-insensitive.
"""

from __future__ import annotations

import base64
import binascii

from .exceptions import SerialFormatError
from .payload_schema import SERIAL_GROUP_SIZE, SIGNATURE_LEN

_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


# ---------------------------------------------------------------------------
# Raw Base32 helpers
# ---------------------------------------------------------------------------
def b32_encode(data: bytes) -> str:
    """Encode bytes as RFC 4648 Base32 (upper, '=' padding stripped)."""
    return base64.b32encode(data).decode("ascii").rstrip("=")


def b32_decode(text: str) -> bytes:
    """Decode Base32 text; accepts dashes, spaces, newlines, any casing.

    Raises SerialFormatError (not binascii.Error) so GUI callers get a
    controlled, user-presentable exception.
    """
    compact = "".join(
        ch for ch in text.upper() if ch.isalnum()
    ).replace("0", "").replace("1", "").replace("8", "").replace("9", "")
    # ^ Avid customers sometimes swap O/0 or I/1 — Base32 alphabet has no
    #   0/1/8/9 so stripping them is a safe repair heuristic.
    if compact and not all(c in _BASE32_ALPHABET for c in compact):
        raise SerialFormatError("serial contains characters outside Base32 alphabet")
    padded = compact + "=" * (-len(compact) % 8)
    try:
        return base64.b32decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise SerialFormatError(f"Base32 decode failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Display formatting
# ---------------------------------------------------------------------------
def group_blocks(text: str, size: int = SERIAL_GROUP_SIZE, sep: str = "-") -> str:
    """Group a flat string into '-'-separated blocks for display."""
    return sep.join(text[i : i + size] for i in range(0, len(text), size)) or text


def flatten(text: str) -> str:
    """Remove all separators/whitespace (user pastes often include newlines)."""
    return "".join(ch for ch in str(text).upper() if ch.isalnum())


# ---------------------------------------------------------------------------
# Signed envelope (serial keys, blacklists, transfer permits all share it)
# ---------------------------------------------------------------------------
def encode_envelope(body_bytes: bytes, signature: bytes) -> str:
    """Produce the display text for body||signature."""
    if len(signature) != SIGNATURE_LEN:
        raise ValueError(f"Ed25519 signature must be {SIGNATURE_LEN} bytes")
    return group_blocks(b32_encode(body_bytes + signature))


def decode_envelope(text: str) -> tuple[bytes, bytes]:
    """Split artifact text into (body_bytes, signature_bytes).

    Raises SerialFormatError when the text is too short to hold a signature.
    """
    raw = b32_decode(text)
    if len(raw) < SIGNATURE_LEN:
        raise SerialFormatError("serial is too short to contain a valid signature")
    return raw[:-SIGNATURE_LEN], raw[-SIGNATURE_LEN:]


__all__ = [
    "b32_decode",
    "b32_encode",
    "decode_envelope",
    "encode_envelope",
    "flatten",
    "group_blocks",
]
