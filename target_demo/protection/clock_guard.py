"""
target_demo.protection.clock_guard — Layer: anti-clock-rollback (offline
expiry enforcement).

Threat: with no internet time source, a customer (or attacker) can set the
system clock back to before ``expires_at`` and keep using an expired
license. Defense: a monotonically increasing "last seen" watermark is kept
in THREE independent local stores:

    1. the encrypted license file itself (managed by LicenseClient)
    2. HKCU\\Software\\<Company>\\<Product> — obfuscated value name
    3. a decoy file in %LOCALAPPDATA%\\<Company>\\<Product>\\cache\\

On every run the guard reads all stores, takes the MAXIMUM timestamp, and
compares with the current wall clock:

    now < max_last_seen - tolerance(24h default)
        -> rollback event: rollback counter incremented (in all stores);
           while counter <= payload.rollback_allowance the app still runs
           (documented grace: legit users flying across timezones), after
           that -> ClockTamperError (license screen, reactivation needed).

    otherwise: last_seen = max(now, stored) written back to all stores.

Store payloads are encrypted with a machine-bound AES key
(crypto_utils.derive_machine_key) so they cannot be trivially edited —
editing breaks decryption, which the guard treats as a reset (but then the
license file, which is AES-GCM authenticated, still holds its own copy of
the true watermark, so the attacker must defeat at least the GCM store).

Session cross-check: GetTickCount64-based uptime — if within one session
the wall clock moves backwards while uptime moves forward, that is a
mid-session clock change and is treated as a rollback event too.
"""

from __future__ import annotations

import ctypes
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

try:  # Windows-only: the registry store degrades to a no-op elsewhere
    import winreg
except ImportError:  # macOS/Linux dev + reference client
    winreg = None  # type: ignore[assignment]

from .crypto_utils import deobfuscate, obfuscate, pack_u64, unpack_u64
from .strings import S

log = logging.getLogger("protection.clock")

_REG_VALUE_KIND = winreg.REG_BINARY if winreg is not None else 3  # REG_BINARY


@dataclass(frozen=True, slots=True)
class ClockDecision:
    """Outcome of a clock-guard evaluation.

    Attributes:
        ok: False when the rollback allowance was exceeded.
        last_seen: the new authoritative watermark (seconds, unix).
        rollbacks: rollback events recorded so far (after this evaluation).
        rolled_back_now: True when this evaluation itself detected a
            rollback (license layer bumps counters / can inform the user).
    """

    ok: bool
    last_seen: int
    rollbacks: int
    rolled_back_now: bool


class ClockGuard:
    """Multi-store monotonic time watermark (one per process)."""

    def __init__(self, config) -> None:  # ProtectionConfig (avoids import cycle)
        self._config = config
        self._context = "clock-store-v1"
        self._session_wall: float | None = None
        self._session_tick: int | None = None

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def now() -> int:
        """Current wall-clock time (unix seconds)."""
        return int(time.time())

    @staticmethod
    def uptime_ms() -> int:
        """Milliseconds since boot via kernel32.GetTickCount64 (ctypes only)."""
        if os.name != "nt":
            return 0
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetTickCount64.restype = ctypes.c_ulonglong
        return int(kernel32.GetTickCount64())

    # ---------------------------------------------------------------- stores
    def _reg_key_path(self) -> str:
        return S("reg_clock_key")

    def _read_registry(self, machine_code: str) -> tuple[int, int] | None:
        """Read (last_seen, rollbacks) from the HKCU store; None if absent."""
        if winreg is None:  # non-Windows: registry store unavailable
            return None
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._reg_key_path(), 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                blob, _ = winreg.QueryValueEx(key, S("reg_clock_value"))
            raw = deobfuscate(machine_code, self._config.product_id,
                              self._context, bytes(blob))
            return unpack_u64(raw[:8]), unpack_u64(raw[8:16])
        except OSError:
            return None
        except Exception:
            # Undecipherable store (key moved machines / tampered): treat as
            # absent — the GCM license file remains authoritative.
            log.debug("clock registry store unreadable", exc_info=True)
            return None

    def _write_registry(self, machine_code: str, last_seen: int, rollbacks: int) -> None:
        if winreg is None:  # non-Windows: registry store unavailable
            return
        try:
            raw = pack_u64(last_seen) + pack_u64(rollbacks)
            blob = obfuscate(machine_code, self._config.product_id,
                             self._context, raw)
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self._reg_key_path(),
                                    0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                winreg.SetValueEx(key, S("reg_clock_value"), 0, _REG_VALUE_KIND, blob)
        except OSError:
            log.debug("clock registry store unwritable", exc_info=True)

    def _decoy_file(self) -> Path:
        """Decoy store path: %LOCALAPPDATA%\\<Company>\\<Product>\\<obfuscated>."""
        return self._config.local_data_dir() / S("decoy_rel")

    def _read_decoy_file(self, machine_code: str) -> tuple[int, int] | None:
        path = self._decoy_file()
        try:
            # Size cap: the real store is exactly 16 bytes; anything huge is
            # garbage/tampering — fail fast instead of reading it into memory.
            if path.stat().st_size > 4096:
                return None
            blob = path.read_bytes()
            raw = deobfuscate(machine_code, self._config.product_id,
                              self._context, blob)
            return unpack_u64(raw[:8]), unpack_u64(raw[8:16])
        except FileNotFoundError:
            return None
        except Exception:
            log.debug("clock decoy store unreadable", exc_info=True)
            return None

    def _write_decoy_file(self, machine_code: str, last_seen: int, rollbacks: int) -> None:
        try:
            raw = pack_u64(last_seen) + pack_u64(rollbacks)
            blob = obfuscate(machine_code, self._config.product_id,
                             self._context, raw)
            path = self._decoy_file()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
        except OSError:
            log.debug("clock decoy store unwritable", exc_info=True)

    # ---------------------------------------------------------------- API
    def reset_stores(self, machine_code: str, last_seen: int = 0) -> None:
        """Clear/re-seed all stores (fresh activation or deactivation)."""
        self._write_registry(machine_code, last_seen, 0)
        self._write_decoy_file(machine_code, last_seen, 0)

    def session_check(self) -> bool:
        """Mid-session clock-change detection via uptime cross-check.

        True == clean. Call periodically (the anti-debug watchdog already
        runs a thread; LicenseClient calls this on every verification).
        """
        now = time.time()
        tick = self.uptime_ms()
        if self._session_wall is None:
            self._session_wall, self._session_tick = now, tick
            return True
        wall_delta = now - self._session_wall
        tick_delta = (tick - (self._session_tick or 0)) / 1000.0
        self._session_wall, self._session_tick = now, tick
        # Wall clock rewound while the monotonic clock advanced: someone
        # changed the system time during THIS session.
        return not (wall_delta < -1.0 and tick_delta > 1.0)

    def evaluate(self, machine_code: str, *, license_last_seen: int,
                 license_rollbacks: int,
                 allowance: int | None = None) -> ClockDecision:
        """Full anti-rollback evaluation (see module docstring).

        Args:
            machine_code: this machine's fingerprint code.
            license_last_seen: watermark stored inside the (authenticated)
                license file — the authoritative store.
            license_rollbacks: rollback counter from the license file.
            allowance: rollbacks tolerated — comes from the SIGNED payload
                (payload.rollback_allowance); falls back to the config
                default when omitted (no license payload available yet).

        Returns:
            ClockDecision with the new watermark/counter for the caller to
            persist into the license file (stores are already updated here).
        """
        tolerance = self._config.clock_tolerance_hours * 3600
        if allowance is None:
            allowance = self._config.default_rollback_allowance

        stored: list[tuple[int, int]] = [
            v for v in (
                self._read_registry(machine_code),
                self._read_decoy_file(machine_code),
            ) if v is not None
        ]
        stored.append((license_last_seen, license_rollbacks))

        last_seen = max(ts for ts, _ in stored)
        rollbacks = max(rb for _, rb in stored)
        now = self.now()

        if now < last_seen - tolerance:
            rollbacks += 1
            rolled_back = True
            ok = rollbacks <= allowance
            log.warning("clock rollback event #%d recorded", rollbacks)
        else:
            rolled_back = False
            ok = True
            last_seen = max(now, last_seen)

        # Persist everywhere (even on failure, so the evidence survives).
        self._write_registry(machine_code, last_seen, rollbacks)
        self._write_decoy_file(machine_code, last_seen, rollbacks)
        return ClockDecision(ok=ok, last_seen=last_seen,
                             rollbacks=rollbacks, rolled_back_now=rolled_back)


__all__ = ["ClockDecision", "ClockGuard"]
