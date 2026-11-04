"""
protector.core.serial_factory — Serial issuance, verification, revocation
blacklists and transfer permits (the admin-side of the licensing protocol).

This module NEVER sees the private key directly: it takes a Signer callable
(injected by the GUI from the unlocked KeyStore) so it stays testable and
the key lifetime stays under the keystore's control.

Artifacts produced (all Ed25519-signed envelopes, see shared/codec.py):

    serial      — payload||sig, Base32 block-grouped (the customer-facing key)
    blacklist   — {"v":1,"generated_at":…,"revoked":[nonce,…]}||sig
    permit      — {"v":1,"action":"transfer","old_nonce":…,
                   "old_fingerprint":…,"issued_at":…}||sig
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from shared.codec import decode_envelope, encode_envelope
from shared.exceptions import SerialFormatError, SignatureError
from shared.payload_schema import EXP_LIFETIME, LicensePayload
from .crypto_engine import verify_blob

log = logging.getLogger("protector.serials")

#: Signer protocol: bytes -> 64-byte Ed25519 signature.
Signer = Callable[[bytes], bytes]


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class SerialRequest:
    """Everything the Generate page collects for one serial.

    Attributes:
        customer: free-form customer identifier (goes into the payload).
        fingerprint: target machine code "XXXX-XXXX-XXXX-XXXX".
        product_id: UUID of the licensed product.
        duration_days: 0 = lifetime; otherwise validity in days from NOW.
        expires_at: explicit override (unix ts) — takes precedence over
            duration_days when not None (custom date picker).
        feature_flags: per-module enable/disable booleans stored in payload.
        tolerance: missing hardware components tolerated at verification.
        rollback_allowance: clock rollbacks tolerated before blocking.
    """

    customer: str
    fingerprint: str
    product_id: str
    duration_days: int = 365
    expires_at: int | None = None
    feature_flags: dict[str, bool] = field(default_factory=dict)
    tolerance: int = 1
    rollback_allowance: int = 3

    def resolved_expires_at(self, now: int | None = None) -> int:
        """Final expiry timestamp (EXP_LIFETIME for lifetime serials)."""
        now = int(now or time.time())
        if self.expires_at is not None:
            return int(self.expires_at)
        if self.duration_days == 0:
            return EXP_LIFETIME
        return now + self.duration_days * 86400


@dataclass(frozen=True, slots=True)
class IssuedSerial:
    """Result of a successful issuance."""

    serial: str            # grouped display form ("ABCDE-FGH…")
    serial_flat: str       # flat normalized form (what gets hashed/stored)
    payload: LicensePayload


def issue_serial(request: SerialRequest, signer: Signer) -> IssuedSerial:
    """Build, sign and encode one serial key.

    Raises:
        SerialFormatError: on invalid request fields (validation from
            LicensePayload.validate()).
    """
    now = int(time.time())
    payload = LicensePayload(
        fingerprint=request.fingerprint,
        product_id=request.product_id,
        issued_at=now,
        expires_at=request.resolved_expires_at(now),
        customer=request.customer,
        nonce=LicensePayload.new_nonce(),
        feature_flags=dict(request.feature_flags),
        tolerance=request.tolerance,
        rollback_allowance=request.rollback_allowance,
    )
    payload.validate()
    body = payload.canonical_bytes()
    signature = signer(body)
    serial = encode_envelope(body, signature)
    # Customer name is personal data: it is stored encrypted in the license
    # DB and must not end up in the plaintext log. Log the nonce prefix only.
    log.info("issued serial (nonce=%s…, exp=%s, flags=%d)",
             payload.nonce[:8], payload.expires_at or "lifetime",
             len(payload.feature_flags))
    return IssuedSerial(serial=serial, serial_flat=serial.replace("-", ""),
                         payload=payload)


# ---------------------------------------------------------------------------
# Verification (admin side: validate customer-submitted serials/requests)
# ---------------------------------------------------------------------------
def verify_serial(serial_text: str, public_key: bytes) -> LicensePayload:
    """Fully verify a serial (signature + structure). Raises SerialFormatError
    / SignatureError. Used when the admin imports deactivation requests."""
    body, signature = decode_envelope(serial_text)
    if not verify_blob(public_key, body, signature):
        raise SignatureError("serial signature is invalid")
    return LicensePayload.from_dict(json.loads(body.decode("utf-8")))


# ---------------------------------------------------------------------------
# Revocation blacklist
# ---------------------------------------------------------------------------
def build_blacklist(nonces: list[str], signer: Signer) -> str:
    """Create the signed revocation blacklist file content."""
    body = json.dumps({
        "v": 1,
        "generated_at": int(time.time()),
        "revoked": sorted({n for n in nonces if n}),
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return encode_envelope(body, signer(body))


def parse_blacklist(text: str, public_key: bytes) -> set[str]:
    """Verify + parse a blacklist (round-trip helper for the Settings page)."""
    body, signature = decode_envelope(text)
    if not verify_blob(public_key, body, signature):
        raise SignatureError("blacklist signature is invalid")
    data = json.loads(body.decode("utf-8"))
    if data.get("v") != 1:
        raise SerialFormatError("unsupported blacklist version")
    return {str(n) for n in data.get("revoked", [])}


# ---------------------------------------------------------------------------
# Transfer permits
# ---------------------------------------------------------------------------
def build_transfer_permit(old_nonce: str, old_fingerprint: str,
                          signer: Signer, *, note: str = "") -> str:
    """Create the signed machine-transfer permit (consumed on the OLD machine
    by LicenseClient.deactivate_with_permit)."""
    body = json.dumps({
        "v": 1,
        "action": "transfer",
        "old_nonce": old_nonce,
        "old_fingerprint": old_fingerprint,
        "issued_at": int(time.time()),
        "note": note,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return encode_envelope(body, signer(body))


def parse_transfer_permit(text: str, public_key: bytes) -> dict:
    """Verify + parse a transfer permit (for admin-side inspection)."""
    body, signature = decode_envelope(text)
    if not verify_blob(public_key, body, signature):
        raise SignatureError("permit signature is invalid")
    data = json.loads(body.decode("utf-8"))
    if data.get("v") != 1 or data.get("action") != "transfer":
        raise SerialFormatError("not a transfer permit")
    return data


__all__ = [
    "IssuedSerial",
    "SerialRequest",
    "Signer",
    "build_blacklist",
    "build_transfer_permit",
    "issue_serial",
    "parse_blacklist",
    "parse_transfer_permit",
    "verify_serial",
]
