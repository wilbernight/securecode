"""
target_demo.protection — REUSABLE offline licensing + anti-RE client SDK.

Drop this package (plus the shared/ package and protection/config.py values)
into ANY PySide6/Python project to wrap it with:

    1. Hardware-locked, time-limited, Ed25519-signed offline serials
       (license_client.py) — 100% offline, no phone-home, ever.
    2. Anti-debugging + VM detection (anti_debug.py, ctypes-only).
    3. Self-integrity checks (integrity.py) — embedded public key digest +
       import-module manifest + critical-constant digest.
    4. Anti-clock-rollback (clock_guard.py) — multi-store monotonic
       last-seen timestamps with rollback allowance.
    5. Secure memory hygiene (shared.secure_buffer.SecureBuffer, plus
       crypto_utils.secure_zero).

Typical integration (see target_demo/main.py for a full example):

    from target_demo.protection import ProtectionConfig, ProtectionRuntime

    cfg = ProtectionConfig(product_id="...", product_name="MyApp")
    ProtectionRuntime.bootstrap(cfg)              # anti-RE layer 3/4
    client = LicenseClient(cfg)
    status = client.verify_installed()
    if status.state is not LicenseState.VALID:
        ... show activation dialog / error screen ...

Dev mode: set ``dev_mode=True`` (or env SC_DEV=1) to disable anti-debug and
integrity hard-fails while developing under an IDE/debugger.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .anti_debug import AntiDebug, DetectAction
from .clock_guard import ClockGuard
from .fingerprint import machine_code
from .integrity import run_integrity_checks
from .license_client import (
    ActivationResult,
    LicenseClient,
    LicenseState,
    LicenseStatus,
)

#: Product UUID this SDK build authorizes. The payload's "pid" field must
#: equal this value (DEMO PRODUCT — SecureNotepad).
DEMO_PRODUCT_ID = "7e9a6cec-c185-45bb-a2fb-d31e96484f7e"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ProtectionConfig:
    """All knobs of the protection stack, per protected application.

    Attributes:
        product_id: UUID — must match the payload's "pid" field.
        product_name / company_name: used for directory + registry naming.
        anti_debug_enabled: master switch for Layer 3 (debugger detection).
        vm_detection_enabled: refuse to run inside VMs (default OFF — see
            docs/SECURITY.md: false positives on legit users' machines are
            costlier than the marginal protection gain).
        timing_checks: rdtsc-style timing-based debugger detection.
        on_detect: DetectAction.EXIT (silent delayed exit — looks like a
            normal crash/close) or DetectAction.DEGRADE (licensing checks
            begin failing silently).
        detect_delay_range: min/max seconds before a silent exit after
            detection (randomized so behavior is not obviously causal).
        integrity_checks: Layer 4 self-integrity (pubkey digest, module
            manifest, critical constants). Disable only in dev mode.
        fingerprint_tolerance: how many hardware components may go missing
            (vs. what was recorded at serial-issuance time) before the
            machine code no longer matches.
        clock_tolerance_hours: allowed system-clock setback before it is
            counted as tampering.
        dev_mode: disables anti-debug + integrity hard-fails + window-title
            checks (for development under a real debugger). NEVER ship a
            build with dev_mode enabled.
    """

    product_id: str = DEMO_PRODUCT_ID
    product_name: str = "SecureNotepad"
    company_name: str = "SecureCode"

    anti_debug_enabled: bool = True
    vm_detection_enabled: bool = False
    timing_checks: bool = True
    on_detect: DetectAction = DetectAction.EXIT
    detect_delay_range: tuple[float, float] = (2.0, 8.0)
    watchdog_interval_range: tuple[float, float] = (20.0, 45.0)

    integrity_checks: bool = True
    fingerprint_tolerance: int = 1
    clock_tolerance_hours: int = 24
    default_rollback_allowance: int = 3

    dev_mode: bool = False

    # -------------------------------------------------- paths
    def dev_mode_active(self) -> bool:
        """True when running in development mode (config flag or SC_DEV env)."""
        return self.dev_mode or os.environ.get("SC_DEV") == "1"

    def program_data_dir(self) -> Path:
        """Protected license directory: %PROGRAMDATA%\\<Company>\\<Product>."""
        base = os.environ.get("PROGRAMDATA", str(Path.home() / "AppData" / "Local"))
        return Path(base) / self.company_name / self.product_name

    def local_data_dir(self) -> Path:
        """Decoy + fallback directory: %LOCALAPPDATA%\\<Company>\\<Product>."""
        base = os.environ.get("LOCALAPPDATA", str(Path.home() / ".local" / "share"))
        return Path(base) / self.company_name / self.product_name

    def license_path(self) -> Path:
        """Full path of the encrypted local license file."""
        return self.program_data_dir() / "license.dat"

    def blacklist_path(self) -> Path:
        """Optional signed revocation blacklist (distributed by the vendor)."""
        return self.program_data_dir() / "blacklist.sec"


# ---------------------------------------------------------------------------
# Runtime handle
# ---------------------------------------------------------------------------
class ProtectionRuntime:
    """Owns the background anti-RE threads for one process.

    Call ``bootstrap()`` ONCE as the very first statement of main(); it
    never returns a rejected state — on hard integrity failure it exits
    the process silently (by design: graceful, non-obvious termination).
    """

    def __init__(self, anti_debug: AntiDebug, clock_guard: ClockGuard,
                 config: ProtectionConfig) -> None:
        self._anti_debug = anti_debug
        self._clock_guard = clock_guard
        self._config = config

    @classmethod
    def bootstrap(cls, config: ProtectionConfig) -> ProtectionRuntime:
        """Start Layer 3 (anti-debug watchdog) and Layer 4 (integrity).

        Integrity failure -> immediate silent exit (os._exit(0)): looks
        exactly like a normal termination, gives the attacker no feedback
        about which check fired.
        """
        if config.integrity_checks and not config.dev_mode_active():
            ok, reasons = run_integrity_checks()
            if not ok:
                # Silent, non-obvious termination (documented decision).
                os._exit(0)

        anti = AntiDebug(config)
        clock = ClockGuard(config)
        runtime = cls(anti, clock, config)
        if config.anti_debug_enabled and not config.dev_mode_active():
            anti.initial_scan()
            anti.start_watchdog()
        return runtime

    def shutdown(self) -> None:
        """Stop watchdog threads on clean application exit."""
        self._anti_debug.stop_watchdog()

    @property
    def degraded(self) -> bool:
        """True when anti-debug switched to silent-degrade mode."""
        return self._anti_debug.degraded

    @property
    def clock_guard(self) -> ClockGuard:
        """The shared ClockGuard instance (used by LicenseClient)."""
        return self._clock_guard


__all__ = [
    "DEMO_PRODUCT_ID",
    "ActivationResult",
    "AntiDebug",
    "ClockGuard",
    "DetectAction",
    "LicenseClient",
    "LicenseState",
    "LicenseStatus",
    "ProtectionConfig",
    "ProtectionRuntime",
    "machine_code",
]
