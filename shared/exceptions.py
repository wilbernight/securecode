"""
shared.exceptions — Custom exception hierarchy for the licensing system.

Every module in both applications raises exceptions from this hierarchy so
callers (especially the GUI) can distinguish user-facing validation errors
from internal integrity/crypto failures without string matching.

Design rule: exception *messages* must never contain secrets (serials,
keys, fingerprints beyond their short public code) because messages can end
up in log files or crash reports.
"""

from __future__ import annotations


class SecureCodeError(Exception):
    """Base class for every error raised by the licensing system."""

    user_message: str = "An unexpected error occurred."

    def __init__(self, detail: str = "", *, user_message: str | None = None) -> None:
        super().__init__(detail or self.__class__.__name__)
        if user_message:
            self.user_message = user_message


# ---------------------------------------------------------------------------
# Serial / codec errors (raised when *parsing* a serial key)
# ---------------------------------------------------------------------------
class SerialFormatError(SecureCodeError):
    """The serial string is not well-formed Base32 / has a bad structure."""
    user_message = "The serial key is malformed. Please paste it exactly as received."


class SignatureError(SecureCodeError):
    """The Ed25519 signature over the payload is missing or invalid."""
    user_message = "Invalid serial key (signature check failed)."


# ---------------------------------------------------------------------------
# License state errors (raised while *evaluating* an activated license)
# ---------------------------------------------------------------------------
class LicenseError(SecureCodeError):
    """Base class for license-state problems."""


class LicenseExpiredError(LicenseError):
    """The license validity window has passed."""
    user_message = "Your license has expired. Please renew to continue using the product."


class FingerprintMismatchError(LicenseError):
    """The serial is bound to a different machine."""
    user_message = "This serial key is bound to another computer."


class LicenseRevokedError(LicenseError):
    """The serial nonce appears on a signed revocation blacklist."""
    user_message = "This serial key has been revoked by the vendor."


class ClockTamperError(LicenseError):
    """System clock rollback beyond the configured tolerance was detected."""
    user_message = (
        "A system clock inconsistency was detected. "
        "Please set the correct date and time, then restart the application."
    )


class TamperError(LicenseError):
    """Runtime integrity self-checks failed (patching / memory tampering)."""
    user_message = "A required component could not be verified. Please reinstall the application."


class IntegrityManifestError(SecureCodeError):
    """The embedded integrity manifest does not match the running code."""
    user_message = "Application integrity verification failed. Please reinstall."


# ---------------------------------------------------------------------------
# Storage / keystore errors (protector side mostly)
# ---------------------------------------------------------------------------
class StorageError(SecureCodeError):
    """Base class for local-storage failures (keystore, DB, license file)."""


class KeystoreError(StorageError):
    """The encrypted keystore could not be created, read, or unlocked."""
    user_message = "The encrypted key storage could not be accessed."


class WrongPassphraseError(KeystoreError):
    """AES-GCM authentication failed while unwrapping the keystore."""
    user_message = "Wrong passphrase. Please try again."


class LicenseFileError(StorageError):
    """The local (activated) license file is missing, unreadable, or forged."""
    user_message = "The local license file is damaged. Please activate again."
