"""
shared.secure_buffer — Zeroizable in-memory secret storage (anti-dump layer).

Python strings and bytes are immutable and cannot be reliably wiped: copies
created by slicing/interpolation linger until garbage collection, and CPython
may not even reuse the pages afterwards. This class is the standard workaround:

* The secret lives in a fixed ctypes buffer (raw malloc'd memory, outside the
  interned/immutable object graph).
* `wipe()` overwrites the buffer with zeros via ctypes.memset and also drops
  the reference so the address space can be reclaimed.
* Context-manager support guarantees the wipe happens even on exceptions.
* Optional VirtualLock paging: on Windows, VirtualLock pins the pages in RAM
  so the secret is *less* likely to leak into the pagefile/hiberfil. (Best
  effort — it cannot prevent a full memory dump by an admin-level tool.)

Honest limitation (documented in docs/SECURITY.md): once a secret must be
*used* (e.g. passed to a crypto API as bytes) it necessarily exists as an
immutable Python bytes object for a short window. The class keeps that
window as short as possible and is the correct tool for key material that
lingers across a session (e.g. the protector's unwrapped private key).
"""

from __future__ import annotations

import ctypes
import os
import threading
from ctypes import wintypes
from typing import Iterator

_IS_WINDOWS = os.name == "nt"

if _IS_WINDOWS:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.VirtualLock.argtypes = [wintypes.LPVOID, ctypes.c_size_t]
    _kernel32.VirtualLock.restype = wintypes.BOOL
    _kernel32.VirtualUnlock.argtypes = [wintypes.LPVOID, ctypes.c_size_t]
    _kernel32.VirtualUnlock.restype = wintypes.BOOL


class SecureBuffer:
    """A fixed-size, explicitly zeroable buffer for secret key material."""

    __slots__ = ("_buf", "_lock", "_lock_count")

    def __init__(self, data: bytes, *, lock_pages: bool = True) -> None:
        """Store ``data`` in a ctypes buffer, optionally page-locked.

        Args:
            data: the secret bytes (copied in; caller should wipe its copy).
            lock_pages: attempt VirtualLock on Windows to reduce paging.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("SecureBuffer expects bytes")
        self._buf = ctypes.create_string_buffer(bytes(data), len(data))
        self._lock_count = 0
        if lock_pages and _IS_WINDOWS and len(data) > 0:
            if _kernel32.VirtualLock(self._buf, len(data)):
                self._lock_count = len(data)

    # ---------------------------------------------------------------- API
    @property
    def size(self) -> int:
        """Current buffer size in bytes."""
        return len(self._buf)

    def read(self) -> bytes:
        """Return a copy of the current contents (use immediately, discard fast)."""
        return ctypes.string_at(self._buf, len(self._buf))

    def wipe(self) -> None:
        """Overwrite contents with zeros and unlock pages. Idempotent."""
        n = len(self._buf)
        if n:
            ctypes.memset(self._buf, 0, n)
        if self._lock_count:
            _kernel32.VirtualUnlock(self._buf, self._lock_count)
            self._lock_count = 0

    def __len__(self) -> int:
        return len(self._buf)

    def __enter__(self) -> SecureBuffer:
        return self

    def __exit__(self, *exc: object) -> None:
        self.wipe()

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:  # pragma: no cover - destructor must never raise
            pass

    def __repr__(self) -> str:  # never leak contents via repr/logs
        return f"<SecureBuffer size={len(self._buf)} wiped={self._lock_count == -1}>"


__all__ = ["SecureBuffer"]
