"""
protector.core.crypto_engine — Ed25519 + AES-256-GCM crypto core of the
protector (the serial-generator admin tool).

This is the ONLY place in the whole project where the Ed25519 *private* key
is ever handled. The protected client EXE embeds the public key only; even a
full compromise of the distributed binary cannot produce valid serials.

Responsibilities
----------------
* KeyStore: a passphrase-wrapped local store for {Ed25519 keypair, DB master
  key}. Wrapped with AES-256-GCM; KEK derived via PBKDF2-HMAC-SHA256
  (600k iterations, 16-byte random salt). Brute-force cost of the
  passphrase is the last line of defense if the admin's machine is breached.
* Private-key export/import (also passphrase-wrapped) for key migration and
  for the shipped demo keypair (demo-assets/demo_keypair.sec).
* Stateless helpers: sign/verify, AES-GCM encrypt/decrypt, HKDF.

Security notes
--------------
* Unwrapped key material is held in SecureBuffer objects and wiped on close.
* Nothing in this module ever logs key bytes; only short public key ids.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from shared.exceptions import KeystoreError, SignatureError, WrongPassphraseError
from shared.payload_schema import SIGNATURE_LEN
from shared.secure_buffer import SecureBuffer

log = logging.getLogger("protector.crypto")

# ---------------------------------------------------------------------------
# Format constants (also used by target_demo/tools/gen_demo_keypair.py)
# ---------------------------------------------------------------------------
KEYSTORE_FORMAT = "securecode-keystore"
KEYEXPORT_FORMAT = "securecode-keyexport"
CONTAINER_FORMAT = "securecode-encrypted-container"

PBKDF2_ITERATIONS = 600_000
PBKDF2_SALT_LEN = 16
AES_NONCE_LEN = 12
KEY_ID_LEN = 16  # hex chars of the public key fingerprint


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------
def b64(data: bytes) -> str:
    """Encode bytes as standard (non-URL) Base64 for JSON storage."""
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    """Decode Base64 stored in JSON containers."""
    return base64.b64decode(text.encode("ascii"))


def derive_kek(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a 256-bit key-encryption-key from a passphrase (PBKDF2-HMAC-SHA256)."""
    if not passphrase or len(passphrase.encode("utf-8")) < 4:
        raise KeystoreError("passphrase too short (minimum 4 characters)")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(passphrase.encode("utf-8"))


def aes_gcm_encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> bytes:
    """AES-256-GCM encrypt (fresh 12-byte nonce prepended to the output)."""
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    nonce = secrets.token_bytes(AES_NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad if aad else None)


def aes_gcm_decrypt(key: bytes, blob: bytes, *, aad: bytes = b"") -> bytes:
    """AES-256-GCM decrypt of a nonce-prefixed blob. Raises WrongPassphraseError
    on authentication failure (callers use this to detect bad passphrases)."""
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    if len(blob) < AES_NONCE_LEN + 16:
        raise WrongPassphraseError("ciphertext too short")
    nonce, body = blob[:AES_NONCE_LEN], blob[AES_NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, body, aad if aad else None)
    except Exception as exc:  # InvalidTag -> generic; never leak tag details
        raise WrongPassphraseError("authentication failed") from exc


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair.

    Returns:
        (private_seed_32B, public_key_32B) as raw bytes.
    """
    private = Ed25519PrivateKey.generate()
    pub_bytes = private.public_key().public_bytes_raw()
    seed = private.private_bytes_raw()
    return seed, pub_bytes


def sign_blob(private_seed: bytes, message: bytes) -> bytes:
    """Sign arbitrary bytes with a raw Ed25519 seed (64-byte signature)."""
    key = Ed25519PrivateKey.from_private_bytes(private_seed)
    return key.sign(message)


def verify_blob(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature. Returns False instead of raising."""
    if len(signature) != SIGNATURE_LEN or len(public_key) != 32:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except Exception:
        return False


def public_key_id(public_key: bytes) -> str:
    """Short public fingerprint: first 16 hex chars of SHA-256(pub)."""
    import hashlib
    return hashlib.sha256(public_key).hexdigest()[:KEY_ID_LEN]


# ---------------------------------------------------------------------------
# Passphrase-wrapped container (shared by keystore + key export)
# ---------------------------------------------------------------------------
def wrap_container(passphrase: str, payload_dict: dict[str, Any]) -> bytes:
    """Encrypt a JSON payload dict into a passphrase-wrapped container file."""
    salt = secrets.token_bytes(PBKDF2_SALT_LEN)
    kek = derive_kek(passphrase, salt)
    blob = aes_gcm_encrypt(kek, json.dumps(payload_dict).encode("utf-8"))
    container = {
        "format": CONTAINER_FORMAT,
        "version": 1,
        "kdf": {"name": "pbkdf2-sha256", "iterations": PBKDF2_ITERATIONS, "salt": b64(salt)},
        "data": b64(blob),
    }
    return json.dumps(container, indent=2).encode("utf-8")


def unwrap_container(passphrase: str, container_bytes: bytes) -> dict[str, Any]:
    """Decrypt a container produced by wrap_container.

    Raises:
        WrongPassphraseError: wrong passphrase or corrupted file.
        KeystoreError: unrecognized container format.
    """
    try:
        container = json.loads(container_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KeystoreError("not a valid SecureCode container") from exc
    if container.get("format") != CONTAINER_FORMAT or container.get("version") != 1:
        raise KeystoreError("unsupported container format")
    kdf = container.get("kdf", {})
    if kdf.get("name") != "pbkdf2-sha256":
        raise KeystoreError("unsupported KDF")
    kek = derive_kek(passphrase, unb64(kdf["salt"]), int(kdf.get("iterations", PBKDF2_ITERATIONS)))
    plain = aes_gcm_decrypt(kek, unb64(container["data"]))
    return json.loads(plain.decode("utf-8"))


# ---------------------------------------------------------------------------
# KeyStore
# ---------------------------------------------------------------------------
class KeyStore:
    """Passphrase-encrypted store holding the signing keypair + DB master key.

    While unlocked, secrets live in SecureBuffer instances; ``close()`` wipes
    them. The on-disk file is always fully encrypted with AES-256-GCM.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._priv: SecureBuffer | None = None
        self._pub: bytes = b""
        self._db_master: SecureBuffer | None = None
        self._key_id: str = ""
        self._created: int = 0

    # -------------------------------------------------- lifecycle
    @property
    def exists(self) -> bool:
        """True when a keystore file is present on disk."""
        return self._path.is_file()

    @property
    def path(self) -> Path:
        """Location of the encrypted keystore file."""
        return self._path

    @property
    def unlocked(self) -> bool:
        """True while key material is resident in memory."""
        return self._priv is not None

    @property
    def key_id(self) -> str:
        """Public fingerprint of the active keypair (safe to display/log)."""
        return self._key_id

    def create(self, passphrase: str, *, overwrite: bool = False) -> None:
        """Generate a NEW keypair + DB master key and write the keystore."""
        if self.exists and not overwrite:
            raise KeystoreError("keystore already exists (refusing to overwrite)")
        seed, pub = generate_keypair()
        db_master = secrets.token_bytes(32)
        self._load_secrets(seed, pub, db_master, int(time.time()))
        self._save(passphrase)
        log.info("created new keystore at %s (key id %s)", self._path, self._key_id)

    def unlock(self, passphrase: str) -> None:
        """Read and decrypt the keystore; raises WrongPassphraseError if bad."""
        if not self.exists:
            raise KeystoreError(f"keystore not found at {self._path}")
        try:
            payload = unwrap_container(passphrase, self._path.read_bytes())
        except WrongPassphraseError:
            raise
        if payload.get("format") != KEYSTORE_FORMAT:
            raise KeystoreError("container is not a keystore")
        seed = unb64(payload["private_key"])
        pub = unb64(payload["public_key"])
        db_master = unb64(payload["db_master"])
        if not verify_blob(pub, b"selftest", sign_blob(seed, b"selftest")):
            raise KeystoreError("keypair failed self-test")
        self._load_secrets(seed, pub, db_master, int(payload.get("created", 0)))
        log.info("unlocked keystore (key id %s)", self._key_id)

    def close(self) -> None:
        """Wipe all resident secrets."""
        if self._priv:
            self._priv.wipe()
        if self._db_master:
            self._db_master.wipe()
        self._priv = None
        self._db_master = None
        self._pub = b""
        self._key_id = ""

    def _load_secrets(self, seed: bytes, pub: bytes, db_master: bytes, created: int) -> None:
        self.close()
        self._priv = SecureBuffer(seed)
        seed = b"\x00" * len(seed)  # wipe caller-side copy quickly
        self._pub = bytes(pub)
        self._db_master = SecureBuffer(db_master)
        db_master = b"\x00" * len(db_master)
        self._key_id = public_key_id(pub)
        self._created = created

    def _save(self, passphrase: str) -> None:
        if not self.unlocked:
            raise KeystoreError("keystore is locked; nothing to save")
        payload = {
            "format": KEYSTORE_FORMAT,
            "version": 1,
            "private_key": b64(self._priv.read()),
            "public_key": b64(self._pub),
            "db_master": b64(self._db_master.read()),
            "created": self._created or int(time.time()),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: temp file + os.replace so a crash never truncates the store.
        tmp = self._path.with_suffix(".tmp")
        tmp.write_bytes(wrap_container(passphrase, payload))
        os.replace(tmp, self._path)
        if os.name == "nt":  # Windows: best-effort ACL hardening (owner-only)
            try:
                import subprocess
                subprocess.run(
                    ["icacls", str(self._path), "/inheritance:r", "/grant:r",
                     f"{os.environ.get('USERNAME', '')}:(R,W)"],
                    capture_output=True, timeout=5, check=False)
            except Exception:  # non-fatal
                log.debug("icacls hardening skipped", exc_info=True)
        else:
            # POSIX (macOS/Linux): user-scoped location + 0600 is the
            # equivalent best-effort hardening (no admin needed).
            try:
                os.chmod(self._path, 0o600)
            except OSError:  # non-fatal (e.g. exotic filesystems)
                log.debug("chmod 0600 hardening skipped", exc_info=True)

    # -------------------------------------------------- key operations
    def change_passphrase(self, old: str, new: str) -> None:
        """Re-wrap the keystore under a new passphrase (secrets unchanged)."""
        self.unlock(old)  # verifies old passphrase
        self._save(new)
        log.info("keystore passphrase changed")

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the resident private key."""
        if not self.unlocked:
            raise KeystoreError("keystore is locked")
        return sign_blob(self._priv.read(), message)

    @property
    def public_key(self) -> bytes:
        """Raw 32-byte public key (safe to distribute)."""
        if not self.unlocked:
            raise KeystoreError("keystore is locked")
        return self._pub

    @property
    def db_master(self) -> bytes:
        """Raw 32-byte database/settings master key (read-copy; wipe quickly)."""
        if not self.unlocked:
            raise KeystoreError("keystore is locked")
        return self._db_master.read()

    # -------------------------------------------------- export / import
    def export_private_key(self, export_passphrase: str, *, label: str = "") -> bytes:
        """Produce a passphrase-wrapped private-key export (for offline backup
        or moving the signing identity to another admin machine)."""
        if not self.unlocked:
            raise KeystoreError("keystore is locked")
        if len(export_passphrase.encode("utf-8")) < 8:
            raise KeystoreError("export passphrase too short (minimum 8 characters)")
        payload = {
            "format": KEYEXPORT_FORMAT,
            "version": 1,
            "private_key": b64(self._priv.read()),
            "public_key": b64(self._pub),
            "created": int(time.time()),
            "key_id": self._key_id,
            "label": label,
        }
        return wrap_container(export_passphrase, payload)

    def import_private_key(self, blob: bytes, export_passphrase: str, *,
                           store_passphrase: str, label: str = "") -> None:
        """Import a wrapped private key export and re-wrap into this keystore.

        The imported keypair REPLACES the resident signing key. The DB
        master key is PRESERVED (settings + license DB stay readable) —
        rotating it here would silently brick settings.dat and the license
        store, which is exactly what happened in early testing.
        """
        payload = unwrap_container(export_passphrase, blob)
        if payload.get("format") != KEYEXPORT_FORMAT:
            raise KeystoreError("file is not a private key export")
        seed = unb64(payload["private_key"])
        pub = unb64(payload["public_key"])
        if len(seed) != 32 or len(pub) != 32:
            raise KeystoreError("key material has wrong length")
        # Self-test the imported pair before accepting it.
        if not verify_blob(pub, b"selftest", sign_blob(seed, b"selftest")):
            raise KeystoreError("imported keypair failed self-test")
        db_master = (self._db_master.read()
                     if self.unlocked else secrets.token_bytes(32))
        self._load_secrets(seed, pub, db_master, int(payload.get("created", 0)))
        self._save(store_passphrase)
        log.warning("imported keypair %s (DB master key preserved)",
                    public_key_id(pub))


__all__ = [
    "KeyStore",
    "aes_gcm_decrypt",
    "aes_gcm_encrypt",
    "derive_kek",
    "generate_keypair",
    "public_key_id",
    "sign_blob",
    "verify_blob",
    "unwrap_container",
    "wrap_container",
]
