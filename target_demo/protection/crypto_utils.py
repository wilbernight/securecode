"""
target_demo.protection.crypto_utils — Machine-bound key derivation and
small crypto helpers used by the license file, clock stores and blacklist.

Key design
----------
Every local artifact (license.dat, registry clock value, decoy file) is
encrypted with a key derived from:

    HKDF-SHA256( ikm = embedded_master_secret || machine_code,
                 salt = product_id, info = purpose_context )

Because the machine code participates in the IKM, artifacts are bound to
the machine: copying license.dat to another PC fails AES-GCM authentication
before any license logic even runs. The master secret itself is stored only
in obfuscated form (strings layer) and is compiled to native code by Nuitka.

Also provides secure_zero() for bytearray hygiene (Layer 5).
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .strings import S


def derive_machine_key(machine_code: str, product_id: str, context: str) -> bytes:
    """Derive a 32-byte purpose-bound key (see module docstring).

    Args:
        machine_code: this machine's fingerprint code ("XXXX-XXXX-...").
        product_id: UUID string — domain separation between products.
        context: purpose string, e.g. "license-file-v1", "clock-store-v1".
    """
    ikm = S("license_master").encode("ascii") + b"|" + machine_code.encode("ascii")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=product_id.encode("ascii"),
        info=context.encode("utf-8"),
    )
    return hkdf.derive(ikm)


def gcm_encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> bytes:
    """AES-256-GCM with a fresh random 12-byte nonce prepended."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad or None)


def gcm_decrypt(key: bytes, blob: bytes, *, aad: bytes = b"") -> bytes:
    """Inverse of gcm_encrypt; raises cryptography.exceptions.InvalidTag."""
    nonce, body = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, body, aad or None)


def obfuscate(machine_code: str, product_id: str, context: str, data: bytes) -> bytes:
    """Deterministic AES-256-CTR "at-rest" obfuscation for the clock stores.

    Deterministic on purpose: the same plaintext always maps to the same
    ciphertext, which makes silent re-writes idempotent and cheap. These
    stores are tamper-evident, not secret (integrity comes from the encrypted
    license file itself; these are tripwires against clock rollback).
    """
    key = derive_machine_key(machine_code, product_id, context)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"sc-obf-iv:" + context.encode())
    iv_bytes = digest.finalize()[:16]
    enc = Cipher(algorithms.AES(key), modes.CTR(iv_bytes)).encryptor()
    return enc.update(data) + enc.finalize()


def deobfuscate(machine_code: str, product_id: str, context: str,
                blob: bytes) -> bytes:
    """Inverse of obfuscate(). Raises on any mismatch (key/IV/corruption)."""
    key = derive_machine_key(machine_code, product_id, context)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"sc-obf-iv:" + context.encode())
    iv_bytes = digest.finalize()[:16]
    dec = Cipher(algorithms.AES(key), modes.CTR(iv_bytes)).decryptor()
    return dec.update(blob) + dec.finalize()


def pack_u64(value: int) -> bytes:
    """Pack a non-negative integer into 8 big-endian bytes (clock stores)."""
    if value < 0:
        raise ValueError("pack_u64 expects a non-negative int")
    return int(value).to_bytes(8, "big")


def unpack_u64(data: bytes) -> int:
    """Inverse of pack_u64 (tolerates trailing bytes)."""
    return int.from_bytes(data[:8], "big")


def secure_zero(buffer: bytearray) -> None:
    """Best-effort zeroization of a mutable buffer (Layer 5 hygiene).

    For immutable bytes() the only honest advice is: keep the lifetime short
    (re-derive per use, never store derived keys longer than needed).
    """
    if buffer:
        ctypes.memmove(
            (ctypes.c_char * len(buffer)).from_buffer(buffer),
            ctypes.create_string_buffer(len(buffer)),
            len(buffer),
        )


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` (and parents) and harden ACLs on Windows (best effort).

    Uses icacls to disable inheritance and grant access only to the current
    user, SYSTEM and Administrators — the closest thing to a protected store
    available without running elevated.
    """
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        import subprocess
        user = os.environ.get("USERNAME", "")
        try:
            subprocess.run(
                ["icacls", str(path), "/inheritance:r",
                 "/grant:r", f"{user}:(OI)(CI)F", "/grant:r", "SYSTEM:(OI)(CI)F",
                 "/grant:r", "Administrators:(OI)(CI)F"],
                capture_output=True, timeout=5, check=False)
        except Exception:
            pass


__all__ = [
    "deobfuscate",
    "derive_machine_key",
    "ensure_private_dir",
    "gcm_decrypt",
    "gcm_encrypt",
    "obfuscate",
    "pack_u64",
    "secure_zero",
    "unpack_u64",
]
