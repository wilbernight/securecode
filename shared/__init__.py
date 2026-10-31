"""
shared — Canonical licensing format definitions shared by BOTH applications.

This package is the single source of truth for:
  * The license payload schema (dataclass <-> compact JSON mapping)
  * The serial key encoding format (Base32 of payload||Ed25519 signature)
  * The hardware fingerprint code format (mask byte + truncated SHA-256)
  * Shared exception hierarchy
  * SecureBuffer (zeroizable memory)

Both `protector` (the admin/serial-generator tool) and `target_demo`
(the protected client SDK) import from this package so their formats can
NEVER drift apart. When building a customer EXE with Nuitka this package is
compiled into native code alongside the protection SDK
(see build.bat: --include-package=shared).

This module contains no secrets and performs no I/O.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = [
    "payload_schema",
    "codec",
    "secure_buffer",
    "exceptions",
]
