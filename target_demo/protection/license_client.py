"""
target_demo.protection.license_client — the offline license client.

Implements the full verification flow required by the architecture spec:

    ACTIVATION (user pastes serial)
        1. Decode Base32 envelope, split payload || 64-byte Ed25519 signature
        2. Verify signature against the EMBEDDED (digest-checked) public key
        3. Parse + structurally validate the payload; check product id
        4. Compare this machine's fingerprint (with tolerance) -> lock
        5. Check issued_at sanity (future-dated serials => clock problem)
        6. Check expires_at (expired serials are refused)
        7. Check the optional signed revocation blacklist (by nonce)
        8. Write the encrypted local license file (AES-256-GCM, key derived
           from an embedded master + this machine's code — see
           crypto_utils.derive_machine_key) into
           %PROGRAMDATA%\\<Company>\\<Product>\\license.dat (ACL-hardened)
        9. Seed the clock-guard stores

    EVERY LAUNCH (verify_installed, 100% offline)
        1. Read + decrypt the local license file (machine-bound key)
        2. Re-verify the Ed25519 signature of the STORED serial text
        3. Re-check fingerprint, expiry
        4. Clock guard evaluation (multi-store rollback watermark)
        5. Re-read the signed blacklist if present
        6. Update last-seen watermark everywhere

    MACHINE TRANSFER (fully offline, via signed file exchange)
        * make_deactivation_request(): customer exports a request file
          containing the (itself signed) serial + machine code; the vendor
          validates it in the protector and issues a signed transfer permit
        * deactivate_with_permit(): the OLD machine consumes the vendor's
          permit, removes the local license + clock stores and writes a
          receipt; the vendor issues a NEW serial for the new machine's
          fingerprint

All user-facing failure messages come from the encrypted string layer (S()).
No message ever reveals which check failed to an attacker beyond what the
workflow requires (spec: graceful, non-obvious degradation).
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from shared.codec import decode_envelope, flatten
from shared.exceptions import (
    LicenseExpiredError,
    LicenseRevokedError,
    SerialFormatError,
    SignatureError,
)
from shared.payload_schema import EXP_LIFETIME, LicensePayload
from .crypto_utils import (
    derive_machine_key,
    ensure_private_dir,
    gcm_decrypt,
    gcm_encrypt,
)
from .fingerprint import machine_code, matches as fingerprint_matches
from .pubkey_blob import public_key_bytes
from .strings import S

log = logging.getLogger("protection.license")

_LICENSE_MAGIC = b"SCLIC1"  # format tag inside license.dat (fast sanity check)
_REVOCATION_MAGIC = b"SCREV1"  # format tag of the sticky revocation store
_REVOCATION_CONTEXT = "revocation-store-v1"
_MAX_REVOCATION_BYTES = 4 << 20     # 4 MiB
_CLOCK_CONTEXT = "clock-store-v1"

#: Size caps before reading local artifacts (resource-exhaustion hardening:
#: a dropped multi-GB file must fail fast with a clean state, never as an
#: out-of-memory crash). Real sizes: license ~2 KB, permit ~1 KB; a legit
#: vendor blacklist of ~100k revoked nonces is ~4-5 MB, hence the headroom.
_MAX_LICENSE_BYTES = 1 << 20        # 1 MiB
_MAX_BLACKLIST_BYTES = 16 << 20     # 16 MiB
_MAX_PERMIT_BYTES = 1 << 20          # 1 MiB


def _capped_read_bytes(path: Path, cap: int, what: str) -> bytes:
    """read_bytes() with a pre-read size cap (raises ValueError past cap)."""
    if path.stat().st_size > cap:
        raise ValueError(f"{what} is too large")
    return path.read_bytes()


class LicenseState(Enum):
    """Every terminal state of the local license evaluation."""
    VALID = "valid"
    MISSING = "missing"            # never activated on this machine
    INVALID = "invalid"            # signature/structure failure
    EXPIRED = "expired"
    WRONG_MACHINE = "wrong_machine"
    REVOKED = "revoked"
    CLOCK_TAMPERED = "clock_tampered"
    DAMAGED = "damaged"            # unreadable local store
    DEGRADED = "degraded"          # silent anti-RE degrade mode active


@dataclass(frozen=True, slots=True)
class LicenseStatus:
    """Result of verify_installed(): state + presentable message."""

    state: LicenseState
    message: str
    payload: LicensePayload | None = None
    seconds_left: int = -1

    @property
    def is_valid(self) -> bool:
        return self.state is LicenseState.VALID


@dataclass(frozen=True, slots=True)
class ActivationResult:
    """Result of activate(): ok flag + state + presentable message."""

    ok: bool
    state: LicenseState
    message: str
    payload: LicensePayload | None = None


@dataclass(slots=True)
class _LicenseFile:
    """Decrypted contents of the local license file (internal)."""

    serial: str
    payload: dict[str, Any]
    activated_at: int
    last_seen: int
    rollbacks: int
    machine_code: str
    blacklist_ver: int = 0
    revoked: bool = False  # sticky: set once a signed blacklist named this serial


class LicenseClient:
    """Offline license client bound to one ProtectionConfig."""

    def __init__(self, config, clock_guard=None) -> None:
        self._config = config
        self._clock_guard_ref = clock_guard
        self._machine_code: str | None = None
        self._pubkey: bytes = b""
        self._file_key_cache: bytes | None = None

    # ================================================================ helpers
    def machine_code(self) -> str:
        """This machine's fingerprint code (cached per client instance)."""
        if self._machine_code is None:
            self._machine_code = machine_code()
        return self._machine_code

    def _public_key(self) -> bytes:
        """Embedded, integrity-checked public key (refreshed per use —
        short-lived buffers, Layer 5 hygiene)."""
        return public_key_bytes()

    def _file_key(self) -> bytes:
        """Machine-bound AES key for the local license file."""
        if self._file_key_cache is None:
            self._file_key_cache = derive_machine_key(
                self.machine_code(), self._config.product_id, "license-file-v1"
            )
        return self._file_key_cache

    def _clock_guard(self):
        if self._clock_guard_ref is None:
            from .clock_guard import ClockGuard

            self._clock_guard_ref = ClockGuard(self._config)
        return self._clock_guard_ref

    # ================================================================ serials
    def parse_serial(self, serial_text: str) -> LicensePayload:
        """Decode + SIGNATURE-VERIFY a serial. Raises SerialFormatError /
        SignatureError (both carry user-presentable messages)."""
        body, signature = decode_envelope(serial_text)  # SerialFormatError
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SerialFormatError(f"payload is not JSON: {exc}") from exc
        payload = LicensePayload.from_dict(data)  # SerialFormatError
        try:
            Ed25519PublicKey.from_public_bytes(self._public_key()).verify(
                signature, body)
        except InvalidSignature as exc:
            raise SignatureError("signature mismatch") from exc
        return payload

    # ================================================================ blacklist
    def _load_blacklist(self) -> set[str]:
        return self._load_blacklist_with_version()[0]

    def _load_blacklist_with_version(self) -> tuple[set[str], int]:
        """Nonces on the signed revocation blacklist (empty if no file).

        The blacklist is an Ed25519-signed envelope distributed by the
        vendor through any offline channel (USB, e-mail). A corrupt or
        forged file is IGNORED (never brick the app on a bad file — but a
        correctly signed file always applies).
        """
        path = self._config.blacklist_path()
        try:
            if path.stat().st_size > _MAX_BLACKLIST_BYTES:
                log.warning("blacklist file implausibly large — ignored")
                return set(), 0
            raw = path.read_bytes()
        except OSError:
            return set(), 0
        try:
            body, signature = decode_envelope(raw.decode("utf-8", errors="replace"))
            Ed25519PublicKey.from_public_bytes(self._public_key()).verify(
                signature, body)
            data = json.loads(body.decode("utf-8"))
            if data.get("v") != 1:
                return set(), 0
            return ({str(n) for n in data.get("revoked", [])},
                    int(data.get("generated_at", 0) or 0))
        except Exception:
            log.warning("ignoring unreadable blacklist file")
            return set(), 0

    # ======================================================= sticky revocation
    # A signed blacklist is the only way a revocation reaches an offline
    # client, and the customer controls that file. Once a correctly signed
    # blacklist has named a serial, the revocation is remembered in two
    # machine-bound, AES-GCM-authenticated places (the license file itself and
    # this separate store, kept in both data directories) so that deleting or
    # swapping blacklist.sec — or deleting license.dat and re-activating the
    # same serial — does not bring a revoked serial back.
    def _revocation_paths(self) -> tuple[Path, Path]:
        return (self._config.program_data_dir() / "state.dat",
                self._config.local_data_dir() / "cache" / "state.dat")

    def _revocation_key(self) -> bytes:
        return derive_machine_key(
            self.machine_code(), self._config.product_id, _REVOCATION_CONTEXT)

    def _load_revoked_store(self) -> set[str]:
        nonces: set[str] = set()
        for path in self._revocation_paths():
            try:
                blob = _capped_read_bytes(path, _MAX_REVOCATION_BYTES, "state")
                if not blob.startswith(_REVOCATION_MAGIC):
                    continue
                plain = gcm_decrypt(self._revocation_key(),
                                    blob[len(_REVOCATION_MAGIC):])
                nonces |= {str(n) for n in json.loads(plain.decode("utf-8"))}
            except Exception:
                continue  # missing / foreign / tampered store: ignore that copy
        return nonces

    def _remember_revoked(self, nonces: set[str]) -> None:
        if not nonces:
            return
        known = self._load_revoked_store()
        if nonces <= known:
            return
        plain = json.dumps(sorted(known | nonces)).encode("utf-8")
        blob = _REVOCATION_MAGIC + gcm_encrypt(self._revocation_key(), plain)
        for path in self._revocation_paths():
            try:
                ensure_private_dir(path.parent)
                tmp = path.with_suffix(".tmp")
                tmp.write_bytes(blob)
                tmp.replace(path)
            except OSError:
                log.debug("revocation store unwritable", exc_info=True)

    def _is_revoked(self, nonce: str) -> tuple[bool, int]:
        """(revoked?, blacklist generated_at). Records any fresh revocation."""
        if not nonce:
            return False, 0
        listed, version = self._load_blacklist_with_version()
        if nonce in listed:
            self._remember_revoked({nonce})
            return True, version
        return nonce in self._load_revoked_store(), version

    # ================================================================ activation
    def activate(self, serial_text: str) -> ActivationResult:
        """Full activation flow (see module docstring steps 1-9)."""
        serial = flatten(serial_text)  # normalized storage form (no dashes)
        if not serial:
            return ActivationResult(False, LicenseState.MISSING, S("msg_malformed"))
        try:
            payload = self.parse_serial(serial)
        except SerialFormatError:
            return ActivationResult(False, LicenseState.INVALID, S("msg_malformed"))
        except SignatureError:
            return ActivationResult(False, LicenseState.INVALID, S("msg_invalid"))

        if payload.product_id != self._config.product_id:
            return ActivationResult(False, LicenseState.INVALID, S("msg_product"))

        if not fingerprint_matches(payload.fingerprint, payload.tolerance):
            return ActivationResult(False, LicenseState.WRONG_MACHINE,
                                    S("msg_other_machine"))

        now = int(time.time())
        # Issued in the future beyond clock-skew tolerance -> clock problem.
        if payload.issued_at - now > self._config.clock_tolerance_hours * 3600:
            return ActivationResult(False, LicenseState.CLOCK_TAMPERED,
                                    S("msg_future"))
        # Already-expired serials are refused at activation too.
        if payload.expires_at != EXP_LIFETIME and now >= payload.expires_at:
            return ActivationResult(False, LicenseState.EXPIRED, S("msg_expired"))

        if self._is_revoked(payload.nonce)[0]:
            return ActivationResult(False, LicenseState.REVOKED, S("msg_revoked"))

        self._write_license_file(_LicenseFile(
            serial=serial,
            payload=payload.to_dict(),
            activated_at=now,
            last_seen=now,
            rollbacks=0,
            machine_code=self.machine_code(),
        ))
        # Fresh clock watermark for the new license.
        self._clock_guard().reset_stores(self.machine_code(), last_seen=now)
        # Customer name deliberately NOT logged (personal data; log files are
        # readable by anyone with access to the user profile).
        log.info("license activated (expires=%s)", payload.expires_at or "lifetime")
        return ActivationResult(True, LicenseState.VALID, "", payload)

    # ================================================================ verification
    def verify_installed(self, *, degraded: bool = False) -> LicenseStatus:
        """Launch-time verification of the local license (offline)."""
        if degraded:
            # Silent degrade requested by the anti-RE layer: generic damage
            # message, no hint about the real reason (spec Layer 3).
            return LicenseStatus(LicenseState.DEGRADED, S("msg_damaged"))

        try:
            record = self._read_license_file()
        except FileNotFoundError:
            return LicenseStatus(LicenseState.MISSING, S("msg_not_installed"))
        except Exception:
            log.warning("license file unreadable")
            return LicenseStatus(LicenseState.DAMAGED, S("msg_damaged"))

        # 1) Re-verify the STORED serial signature on every launch — a
        #    locally forged/edited license file never gets past this.
        try:
            payload = self.parse_serial(record.serial)
        except SerialFormatError:
            return LicenseStatus(LicenseState.DAMAGED, S("msg_damaged"))
        except SignatureError:
            return LicenseStatus(LicenseState.INVALID, S("msg_invalid"))

        # 2) Machine binding.
        if record.machine_code != self.machine_code() or not fingerprint_matches(
                payload.fingerprint, payload.tolerance):
            return LicenseStatus(LicenseState.WRONG_MACHINE, S("msg_other_machine"))

        # 3) Expiry.
        now = int(time.time())
        if payload.expires_at != EXP_LIFETIME and now >= payload.expires_at:
            return LicenseStatus(LicenseState.EXPIRED, S("msg_expired"), payload)

        # 4) Anti-clock-rollback (allowance comes from the SIGNED payload).
        decision = self._clock_guard().evaluate(
            self.machine_code(),
            license_last_seen=record.last_seen,
            license_rollbacks=record.rollbacks,
            allowance=payload.rollback_allowance,
        )
        record.last_seen = decision.last_seen
        record.rollbacks = decision.rollbacks
        if not decision.ok:
            log.warning("clock tampering beyond allowance")
            return LicenseStatus(LicenseState.CLOCK_TAMPERED, S("msg_clock"), payload)

        # 5) Revocation: sticky flag in the authenticated license file, the
        #    sticky revocation store, and the signed blacklist (re-read every
        #    launch). Deleting blacklist.sec never un-revokes a serial.
        revoked, bl_version = self._is_revoked(payload.nonce)
        if revoked or record.revoked:
            record.revoked = True
            record.blacklist_ver = max(record.blacklist_ver, bl_version)
            self._remember_revoked({payload.nonce} if payload.nonce else set())
            self._write_license_file(record)
            return LicenseStatus(LicenseState.REVOKED, S("msg_revoked"), payload)
        record.blacklist_ver = max(record.blacklist_ver, bl_version)

        # 6) Persist watermark back into the authenticated license file.
        self._write_license_file(record)

        return LicenseStatus(
            LicenseState.VALID, "", payload,
            seconds_left=payload.seconds_left(now),
        )

    # ================================================================ transfer
    def make_deactivation_request(self, path: str | Path) -> Path:
        """Export the (signed) serial + machine code for a machine transfer.

        The vendor can validate authenticity of the embedded serial in the
        protector (Serial Manager -> verify serial) because the serial
        itself is Ed25519-signed — a forged request file with an invalid
        serial is rejected there.
        """
        record = self._read_license_file()
        out = Path(path)
        out.write_text(json.dumps({
            "format": "securecode-deactivation-request",
            "version": 1,
            "product_id": self._config.product_id,
            "machine_code": self.machine_code(),
            "serial": record.serial,
            "nonce": record.payload.get("n", ""),
            "created": int(time.time()),
        }, indent=2), encoding="utf-8")
        return out

    def deactivate_with_permit(self, permit_path: str | Path) -> tuple[bool, str]:
        """Consume the vendor's signed transfer permit on the OLD machine.

        Verifies: signature, action, nonce matches the installed license.
        On success the local license + clock stores are wiped and a receipt
        file is written (the customer sends it back as proof of removal).
        """
        permit_file = Path(permit_path)
        try:
            if permit_file.stat().st_size > _MAX_PERMIT_BYTES:
                return False, "Permit file is malformed."
            body, signature = decode_envelope(
                permit_file.read_text(encoding="utf-8").strip())
        except OSError:
            return False, "Permit file could not be read."
        except SerialFormatError:
            return False, "Permit file is malformed."
        try:
            Ed25519PublicKey.from_public_bytes(self._public_key()).verify(
                signature, body)
            permit = json.loads(body.decode("utf-8"))
        except Exception:
            return False, "Permit signature is invalid."
        if permit.get("v") != 1 or permit.get("action") != "transfer":
            return False, "Permit is not a transfer permit."

        try:
            record = self._read_license_file()
        except FileNotFoundError:
            return False, "No license is installed on this computer."
        except Exception:
            return False, "The local license file is damaged."
        if permit.get("old_nonce") != record.payload.get("n"):
            return False, "Permit does not match the installed serial."

        # Wipe license + clock evidence, keep a signed receipt.
        self._config.license_path().unlink(missing_ok=True)
        self._clock_guard().reset_stores(self.machine_code(), last_seen=0)
        receipt = self._config.local_data_dir() / "deactivation_receipt.txt"
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(json.dumps({
            "format": "securecode-deactivation-receipt",
            "version": 1,
            "nonce": permit.get("old_nonce", ""),
            "deactivated_at": int(time.time()),
        }, indent=2), encoding="utf-8")
        log.info("license deactivated via transfer permit")
        return True, "License removed. You can now activate on the new machine."

    # ================================================================ license file I/O
    def _read_license_file(self) -> _LicenseFile:
        """Read + decrypt license.dat. Raises FileNotFoundError when not
        activated yet; any other failure signals corruption/tampering."""
        path = self._config.license_path()
        blob = _capped_read_bytes(path, _MAX_LICENSE_BYTES,
                                  "license file")  # FileNotFoundError propagates
        if not blob.startswith(_LICENSE_MAGIC):
            raise ValueError("bad magic")
        plain = gcm_decrypt(self._file_key(), blob[len(_LICENSE_MAGIC):])
        data = json.loads(plain.decode("utf-8"))
        return _LicenseFile(
            serial=str(data["serial"]),
            payload=dict(data["payload"]),
            activated_at=int(data.get("activated_at", 0)),
            last_seen=int(data.get("last_seen", 0)),
            rollbacks=int(data.get("rollbacks", 0)),
            machine_code=str(data.get("machine_code", "")),
            blacklist_ver=int(data.get("blacklist_ver", 0)),
            revoked=bool(data.get("revoked", False)),
        )

    def _write_license_file(self, record: _LicenseFile) -> None:
        """Encrypt + atomically write license.dat with ACL hardening."""
        directory = self._config.program_data_dir()
        ensure_private_dir(directory)
        plain = json.dumps({
            "v": 1,
            "serial": record.serial,
            "payload": record.payload,
            "activated_at": record.activated_at,
            "last_seen": record.last_seen,
            "rollbacks": record.rollbacks,
            "machine_code": record.machine_code,
            "blacklist_ver": record.blacklist_ver,
            "revoked": record.revoked,
        }, sort_keys=True).encode("utf-8")
        blob = _LICENSE_MAGIC + gcm_encrypt(self._file_key(), plain)
        path = self._config.license_path()
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        tmp.replace(path)
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        if os.name == "nt":
            # Best-effort ACL hardening of the license file itself.
            import subprocess
            subprocess.run(
                ["icacls", str(path), "/inheritance:r",
                 "/grant:r", f"{os.environ.get('USERNAME', '')}:(R,W)"],
                capture_output=True, timeout=5, check=False)

    # ================================================================ utilities
    def installed_customer(self) -> str:
        """Customer string of the locally installed license (or '')."""
        try:
            return str(self._read_license_file().payload.get("cust", "") or "")
        except Exception:
            return ""

    def installed_expires_at(self) -> int:
        """Expiry unix timestamp of the installed license (or 0)."""
        try:
            return int(self._read_license_file().payload.get("exp", 0) or 0)
        except Exception:
            return 0


__all__ = [
    "ActivationResult",
    "LicenseClient",
    "LicenseState",
    "LicenseStatus",
]
