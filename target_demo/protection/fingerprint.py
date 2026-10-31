"""
target_demo.protection.fingerprint — Layer: hardware fingerprinting (client).

Computes the machine code "XXXX-XXXX-XXXX-XXXX" that serials are bound to
(see shared/payload_schema.py for the format). Component collection uses a
layered fallback chain so the code survives missing tools/drivers:

    CPU  : wmi module (DCOM)  -> PowerShell Get-CimInstance -> py-cpuinfo hash
    BOARD: wmi module         -> PowerShell Get-CimInstance
    DISK : wmi module         -> PowerShell Get-CimInstance (first disk by Index)
    GUID : winreg HKLM\\...\\Cryptography\\MachineGuid  (always available, no
           dependency — the strongest stable identifier on Windows)

Notes
-----
* wmic.exe is DEPRECATED and removed in Windows 11 24H2+, so the primary
  path is the `wmi` python package (raw DCOM via pywin32) and the secondary
  is PowerShell CIM — never wmic.exe.
* Values are normalized (shared.payload_schema.normalize_component) so BIOS
  serials with trailing spaces/NULs and case differences stay stable.
* Components that cannot be read are simply missing (mask bit 0) — the
  tolerance mechanism in matches() allows the serial to survive up to N
  component changes between activation and later runs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any

try:  # Windows-only; POSIX uses the fallbacks in _guid_component()
    import winreg
except ImportError:  # macOS/Linux dev + reference client
    winreg = None  # type: ignore[assignment]

from shared.codec import b32_encode, flatten, group_blocks
from shared.payload_schema import (
    COMPONENT_ORDER,
    compute_fingerprint_digest,
    normalize_component,
    parse_component_mask,
)
from .strings import S

log = logging.getLogger("protection.fingerprint")

#: Display grouping of the machine code (4 chars x 4 blocks = 16 base32 chars)
CODE_GROUP_SIZE = 4

_PS_TIMEOUT = 6  # seconds — CIM is slow on first call, generous ceiling
_CACHE_TTL = 30.0  # components rarely change within one session; avoid rescans


# ---------------------------------------------------------------------------
# Component collectors
# ---------------------------------------------------------------------------
def _ps_cim(query_id: str) -> str:
    """Run an obfuscated PowerShell CIM query, return stdout stripped."""
    cmd = [S("ps_shell"), "-NoProfile", "-NonInteractive", "-Command", S(query_id)]
    out = subprocess.run(
        cmd, capture_output=True, timeout=_PS_TIMEOUT, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
    )
    return out.stdout.strip() if out.returncode == 0 else ""


def _wmi_first_class(class_name: str, prop: str) -> str:
    """Read a property of the first instance via the wmi DCOM package."""
    import wmi  # provided by requirements (pywin32 underneath)

    conn = wmi.WMI()
    instances = getattr(conn, class_name)()
    if not instances:
        return ""
    return str(getattr(instances[0], prop) or "")


def _cpu_component() -> str:
    """CPU identifier: ProcessorId, with CIM + cpuinfo fallbacks."""
    try:
        value = _wmi_first_class("Win32_Processor", S("wmi_cpu_prop"))
        if value:
            return value
    except Exception:
        log.debug("cpu via wmi unavailable", exc_info=True)
    try:
        value = _ps_cim("ps_cpu")
        if value:
            return value
    except Exception:
        log.debug("cpu via cim unavailable", exc_info=True)
    # py-cpuinfo fallback: same physical CPU yields the same fields, so a
    # stable digest is still possible when DCOM/CIM are blocked (kiosk/AV).
    try:
        import cpuinfo
        info = cpuinfo.get_cpu_info()
        material = "|".join(str(info.get(k, "")) for k in
                            ("brand_raw", "family", "model", "stepping", "l3_cache_size"))
        return hashlib.sha256(material.encode("utf-8")).hexdigest() if material.strip("|") else ""
    except Exception:
        return ""


def _board_component() -> str:
    """Motherboard serial: Win32_BaseBoard.SerialNumber (WMI -> CIM)."""
    try:
        value = _wmi_first_class("Win32_BaseBoard", S("wmi_board_prop"))
        if value:
            return value
    except Exception:
        log.debug("board via wmi unavailable", exc_info=True)
    try:
        return _ps_cim("ps_board")
    except Exception:
        return ""


def _disk_component() -> str:
    """Primary disk serial: first Win32_DiskDrive by Index (WMI -> CIM)."""
    try:
        import wmi
        conn = wmi.WMI()
        disks = sorted(
            conn.Win32_DiskDrive(),
            key=lambda d: int(getattr(d, "Index", 0) or 0),
        )
        if disks:
            return str(getattr(disks[0], S("wmi_disk_prop")) or "")
    except Exception:
        log.debug("disk via wmi unavailable", exc_info=True)
    try:
        return _ps_cim("ps_disk")
    except Exception:
        return ""


def _guid_component() -> str:
    """Stable machine GUID. Windows: HKLM\\...\\Cryptography\\MachineGuid
    (no dependency, most stable). macOS/Linux: a platform-native stable id so
    the pure-Python reference client works cross-platform for development and
    the offline self-tests (the shipped native SDKs use their own identifiers).
    """
    if winreg is not None:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, S("reg_guid_key"), 0,
                               winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                value, _ = winreg.QueryValueEx(key, S("reg_guid_value"))
                return str(value)
        except OSError:
            return ""
        return ""
    return _posix_guid_component()


def _posix_guid_component() -> str:
    """Best-effort stable machine id on macOS/Linux (no secrets, no PII)."""
    import sys

    if sys.platform == "darwin":
        try:
            out = subprocess.run(
                ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, timeout=_PS_TIMEOUT, text=True)
            for line in out.stdout.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
        except Exception:
            log.debug("macOS IOPlatformUUID unavailable", exc_info=True)
        return ""
    # Linux/other POSIX: the systemd/D-Bus machine id is stable per install.
    for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            text = Path(candidate).read_text(encoding="utf-8").strip()
            if text:
                return text
        except OSError:
            continue
    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
_collectors = {
    "cpu": _cpu_component,
    "board": _board_component,
    "disk": _disk_component,
    "guid": _guid_component,
}

_components_cache: dict[str, str] | None = None
_components_cache_at: float = 0.0


def collect_components(refresh: bool = False) -> dict[str, str]:
    """Collect raw hardware identifiers (cached per session).

    Returns a dict with any subset of keys: cpu / board / disk / guid.
    """
    global _components_cache, _components_cache_at
    now = time.monotonic()
    if not refresh and _components_cache is not None and (now - _components_cache_at) < _CACHE_TTL:
        return dict(_components_cache)
    collected = {name: fn() for name, fn in _collectors.items()}
    _components_cache, _components_cache_at = collected, now
    return dict(collected)


def machine_code() -> str:
    """The machine code of this PC: 'XXXX-XXXX-XXXX-XXXX'."""
    _, material = compute_fingerprint_digest(collect_components())
    return group_blocks(b32_encode(material), CODE_GROUP_SIZE, "-")


def machine_mask() -> int:
    """Bitmask of currently-present components (see payload_schema)."""
    mask, _ = compute_fingerprint_digest(collect_components())
    return mask


def matches(target_code: str, tolerance: int = 1) -> bool:
    """Fingerprint matching WITH hardware-change tolerance.

    Strategy: compute our code; if it differs, systematically pretend each
    present component (or pair, up to ``tolerance``) went missing and check
    whether the resulting candidate matches the target. This models exactly
    the scenario "customer swapped the disk": the other 3 components still
    hash to the value recorded at activation time.

    Args:
        target_code: fingerprint code from the signed license payload.
        tolerance: how many components may have changed/disappeared.

    Returns:
        True when this machine can still be considered the licensed one.
    """
    from itertools import combinations

    target = flatten(target_code)
    ours = collect_components()

    def _code_with_drop(drop: tuple[str, ...]) -> str:
        subset = {k: ("" if k in drop else v) for k, v in ours.items()}
        _, material = compute_fingerprint_digest(subset)
        return b32_encode(material)

    present = [name for name in COMPONENT_ORDER if ours.get(name)]
    if _code_with_drop(()) == target:
        return True
    for k in range(1, min(tolerance, len(present)) + 1):
        for drop in combinations(present, k):
            if _code_with_drop(drop) == target:
                return True
    return False


def export_fingerprint_file(path: str | Path, product_id: str) -> Path:
    """Write the fingerprint export file the customer sends to the vendor.

    Contains ONLY the machine code and which components were present — no
    raw hardware serials (privacy: the file travels over email/support).
    """
    import sys

    platform = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "windows")
    data: dict[str, Any] = {
        "format": S("fp_export_format"),
        "version": 1,
        "platform": platform,  # see shared.payload_schema.KNOWN_PLATFORMS
        "code": machine_code(),
        "present": parse_component_mask(machine_mask()),
        "product_id": product_id,
        "created": int(time.time()),
    }
    out = Path(path)
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return out


__all__ = [
    "CODE_GROUP_SIZE",
    "collect_components",
    "export_fingerprint_file",
    "machine_code",
    "machine_mask",
    "matches",
]
