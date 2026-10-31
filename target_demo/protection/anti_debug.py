"""
target_demo.protection.anti_debug — Layer 3: runtime anti-debugging (Windows).

ctypes-only implementation — NO third-party dependencies. Detection surfaces:

    1. kernel32.IsDebuggerPresent            — PEB BeingDebugged flag
    2. kernel32.CheckRemoteDebuggerPresent   — handles remote attach
    3. ntdll.NtQueryInformationProcess       — ProcessDebugPort (7) and
       ProcessDebugObjectHandle (0x1E): reveals any native debug object,
       including when the PEB flag has been manually cleared
    4. Process enumeration via Toolhelp32Snapshot — matches running
       processes against an obfuscated list of debugger/RE tool names
       (x64dbg, IDA, Ghidra, Wireshark, Process Hacker, ...)
    5. Timing-based detection (rdtsc-style): a calibration loop is timed
       with QueryPerformanceCounter; single-stepping or breakpoints inflate
       the delta by orders of magnitude. Conservative multi-sample logic
       keeps the false-positive rate negligible on preemptive schedulers.
    6. Optional VM detection (OFF by default): registry artifacts left by
       VMware Tools / VirtualBox Guest Additions / Hyper-V integration /
       Parallels Tools + BIOS firmware strings.

On detection the class NEVER shows a message. Configurable responses:
    * DetectAction.EXIT    — terminate after a randomized 2-8 s delay,
      exit code 0 (indistinguishable from a normal close).
    * DetectAction.DEGRADE — set a flag; LicenseClient then fails its
      checks with a generic error (functionality silently degraded).

Threading: checks run in a daemon watchdog thread at jittered intervals so
an attacker cannot correlate scan moments with process events.
"""

from __future__ import annotations

import ctypes
import os
import random
import threading
import time
from ctypes import wintypes
from enum import Enum

from .strings import S

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None
_NTDLL = ctypes.WinDLL("ntdll", use_last_error=True) if os.name == "nt" else None

if os.name == "nt":
    _KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
    _KERNEL32.IsDebuggerPresent.restype = wintypes.BOOL
    _KERNEL32.CheckRemoteDebuggerPresent.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    _KERNEL32.CheckRemoteDebuggerPresent.restype = wintypes.BOOL
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.QueryPerformanceCounter.argtypes = [ctypes.POINTER(wintypes.LARGE_INTEGER)]
    _KERNEL32.QueryPerformanceCounter.restype = wintypes.BOOL
    _NTDLL.NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE, wintypes.ULONG, wintypes.LPVOID, wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    _NTDLL.NtQueryInformationProcess.restype = wintypes.LONG

# Toolhelp32Snapshot constants
_TH32CS_SNAPPROCESS = 0x00000002
_INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

# NtQueryInformationProcess info classes
_PROCESS_DEBUG_PORT = 7
_PROCESS_DEBUG_OBJECT_HANDLE = 0x1E


class DetectAction(Enum):
    """What to do when a debugger/RE tool is detected."""
    EXIT = "exit"        # silent, delayed, exit-code-0 termination
    DEGRADE = "degrade"  # licensing checks silently start failing


class PROCESSENTRY32W(ctypes.Structure):
    """Toolhelp32 process entry (Unicode), used for the process-name scan."""

    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class AntiDebug:
    """Layer 3 runtime guard. Instantiate via ProtectionRuntime.bootstrap()."""

    def __init__(self, config) -> None:  # ProtectionConfig (avoid import cycle)
        self._config = config
        self._degraded = threading.Event()
        self._stop = threading.Event()
        self._watchdog: threading.Thread | None = None
        self._dbg_names: tuple[str, ...] = tuple(
            name.strip().lower() for name in S("dbg_procs").split("|") if name.strip()
        )

    # ---------------------------------------------------------------- state
    @property
    def degraded(self) -> bool:
        """True after a detection in DEGRADE mode (or DEGRADE was triggered)."""
        return self._degraded.is_set()

    # ---------------------------------------------------------------- checks
    def _check_is_debugger_present(self) -> bool:
        """PEB BeingDebugged flag (catches easy usermode attach)."""
        return bool(_KERNEL32.IsDebuggerPresent())

    def _check_remote_debugger(self) -> bool:
        """Catches debuggers attached to the process from outside."""
        flag = wintypes.BOOL(False)
        ok = _KERNEL32.CheckRemoteDebuggerPresent(
            _KERNEL32.GetCurrentProcess(), ctypes.byref(flag))
        return bool(ok and flag.value)

    def _check_debug_object(self) -> bool:
        """NtQueryInformationProcess debug-port/object queries — the strong
        native check (bypassing it requires kernel-level hiding)."""
        for info_class in (_PROCESS_DEBUG_PORT, _PROCESS_DEBUG_OBJECT_HANDLE):
            value = ctypes.c_ulonglong(0)
            status = _NTDLL.NtQueryInformationProcess(
                _KERNEL32.GetCurrentProcess(), info_class,
                ctypes.byref(value), ctypes.sizeof(value), None)
            if status == 0 and value.value != 0:
                return True
        return False

    def _scan_processes(self) -> bool:
        """True when a known debugger/RE tool is running (any session)."""
        snap = _KERNEL32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        if snap in (None, _INVALID_HANDLE_VALUE, -1):
            return False
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            # Keep the raw prototype lookups local: declaring argtypes at
            # import time for these two is fine too, but the snapshot handle
            # differs between Python builds' HANDLE size — call via winDLL
            # generic marshalling deliberately.
            if not _KERNEL32.Process32FirstW(snap, ctypes.byref(entry)):
                return False
            while True:
                name = entry.szExeFile.lower()
                if name in self._dbg_names:
                    return True
                if not _KERNEL32.Process32NextW(snap, ctypes.byref(entry)):
                    return False
        finally:
            _KERNEL32.CloseHandle(snap)

    def _timing_check(self, samples: int = 7, inflation_factor: float = 12.0) -> bool:
        """Timing-based debugger detection (rdtsc-style via QPC).

        Calibrates a fixed arithmetic loop, then re-times it over several
        samples. Single-stepping/breakpoints inflate per-iteration cost by
        10-1000x; the conservative inflation factor (12x on the MINIMUM of
        all samples) keeps false positives near zero even on heavily loaded
        machines, while still catching breakpoints placed inside the loop.
        """

        def _measure() -> int:
            counter = wintypes.LARGE_INTEGER(0)
            start = wintypes.LARGE_INTEGER(0)
            _KERNEL32.QueryPerformanceCounter(ctypes.byref(start))
            # Deterministic workload (must be identical every call).
            acc = 0
            for i in range(50_000):
                acc += i * 3 % 7
            _KERNEL32.QueryPerformanceCounter(ctypes.byref(counter))
            # touch acc so CPython cannot constant-fold the loop away
            return (counter.value - start.value) + (acc & 0)

        calibration = min(_measure() for _ in range(3))
        if calibration <= 0:
            return False
        try:
            observed = min(_measure() for _ in range(samples))
        except Exception:
            return False
        return observed > calibration * inflation_factor

    def _check_vm(self) -> bool:
        """Registry-based VM artifact detection (guest-safe keys only)."""
        import winreg

        for key_path in (k for k in S("vm_keys").split("|") if k):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
                    return True
            except OSError:
                continue

        # Firmware strings: BIOS version frequently contains the hypervisor
        # vendor name on VMware/VBox/QEMU guests.
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, S("vm_bios_key"), 0,
                               winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                bios, _ = winreg.QueryValueEx(key, S("vm_bios_value"))
            bios_text = str(bios).lower()
            return any(token in bios_text for token in S("vm_tokens").split("|"))
        except OSError:
            return False

    def run_all_checks(self) -> bool:
        """Run every enabled check once. True == ENVIRONMENT CLEAN.

        Returns False when a debugger/RE-tool/VM was detected (the response
        has already been scheduled by ``_on_detection``).
        """
        if _KERNEL32 is None:  # non-Windows: this layer is a no-op (clean)
            return True
        detected = False
        try:
            if self._check_is_debugger_present():
                detected = True
            elif self._check_remote_debugger():
                detected = True
            elif self._check_debug_object():
                detected = True
            elif self._scan_processes():
                detected = True
            elif self._config.timing_checks and self._timing_check():
                detected = True
            elif self._config.vm_detection_enabled and self._check_vm():
                detected = True
        except Exception:
            # A failing check must never crash the protected app: treat
            # native-interop anomalies as clean (availability over paranoia)
            # but degrade, so a tamper-induced failure is still penalized.
            self._on_detection(quiet=True)
            return False
        if detected:
            self._on_detection()
            return False
        return True

    # ---------------------------------------------------------------- response
    def _on_detection(self, quiet: bool = False) -> None:
        """React to a detection. NEVER raises, NEVER shows UI."""
        action = self._config.on_detect
        if action == DetectAction.DEGRADE:
            self._degraded.set()
            return
        # EXIT (default): delayed, randomized, exit code 0 — mimics a normal
        # application close. threading.Timer keeps this independent of the
        # GUI event loop so it fires even if the attacker froze the main
        # thread in a debugger.
        low, high = self._config.detect_delay_range
        delay = random.uniform(low, high)

        def _terminate() -> None:
            time.sleep(delay)
            os._exit(0)

        threading.Thread(target=_terminate, daemon=True).start()

    # ---------------------------------------------------------------- watchdog
    def initial_scan(self) -> None:
        """One blocking full scan at process start (see bootstrap)."""
        self.run_all_checks()

    def start_watchdog(self) -> None:
        """Spawn the daemon watchdog with jittered intervals."""
        if self._watchdog is not None and self._watchdog.is_alive():
            return

        def _loop() -> None:
            while not self._stop.is_set():
                low, high = self._config.watchdog_interval_range
                if self._stop.wait(random.uniform(low, high)):
                    break
                if not self.run_all_checks():
                    return  # response already scheduled

        self._watchdog = threading.Thread(target=_loop, daemon=True,
                                          name="gc-manager")  # bland name
        self._watchdog.start()

    def stop_watchdog(self) -> None:
        """Signal the watchdog to stop (called on clean shutdown)."""
        self._stop.set()


__all__ = ["AntiDebug", "DetectAction"]
