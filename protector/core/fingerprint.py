"""
protector.core.fingerprint — admin-side fingerprint code parsing.

The protector never reads hardware itself (it runs on the VENDOR's machine);
it parses the machine code the CUSTOMER exported (paste or fingerprint.txt),
validates its format and decodes which hardware components were recorded
(mask nibble). "Generate serial for this machine" pre-fills the Generate
page from here.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

from shared.codec import b32_decode, flatten, group_blocks
from shared.exceptions import SecureCodeError
from shared.payload_schema import (
    COMPONENT_ORDER,
    KNOWN_PLATFORMS,
    PLATFORM_COMPONENT_LABELS,
    PLATFORM_DISPLAY_NAMES,
    parse_component_mask,
)

log = logging.getLogger("protector.fingerprint")

#: The fingerprint export format written by the client
#: (target_demo.protection.fingerprint.export_fingerprint_file).
FP_EXPORT_FORMAT = "securecode-fingerprint"

#: Sanity cap on customer-supplied export files (a real export is ~250 B).
#: Guards the vendor tool against absurdly large files (resource exhaustion).
MAX_EXPORT_BYTES = 1 << 20  # 1 MiB


class FingerprintParseError(SecureCodeError, ValueError):
    """Raised when a pasted machine code / export file is malformed.

    Inherits ValueError for backward compatibility with callers that catch
    it as a plain validation error, and SecureCodeError so the specific
    user-facing reason can be attached via ``user_message=`` (the generic
    class default is used otherwise).
    """

    user_message: str = "The fingerprint code is malformed. Expected a 16-character code like XXXX-XXXX-XXXX-XXXX."


@dataclass(frozen=True, slots=True)
class MachineInfo:
    """Decoded view of one fingerprint code."""

    code: str                 # normalized display code (dashed)
    mask: int                 # raw mask byte
    present: dict[str, bool]  # per-component presence
    present_names: list[str]  # human labels
    is_full: bool             # True when all 4 components were recorded
    platform: str = "windows"  # OS the code was recorded on (export metadata)

    @property
    def missing_names(self) -> list[str]:
        labels = component_labels(self.platform)
        return [labels[k] for k in COMPONENT_ORDER
                if not self.present[k] and labels[k]]


def component_labels(platform: str = "windows") -> dict[str, str]:
    """Human labels for the hash slots on the given platform.

    Unknown platforms fall back to the Windows labels (the generic slot
    names cpu/board/disk/guid are always valid as a fallback display).
    """
    return PLATFORM_COMPONENT_LABELS.get(platform,
                                         PLATFORM_COMPONENT_LABELS["windows"])


def platform_slots(platform: str = "windows") -> list[str]:
    """Hash slots actually used by the platform, in canonical order.

    Platforms leave slots they have no identifier for empty (e.g. iOS never
    fills disk/guid), so the UI only shows the ones that can be recorded.
    """
    labels = component_labels(platform)
    return [k for k in COMPONENT_ORDER if labels[k]]


def platform_display_name(platform: str = "windows") -> str:
    """Human display name ("Android", "macOS", ...)."""
    return PLATFORM_DISPLAY_NAMES.get(platform, "Windows")


def parse_fingerprint(code: str, platform: str = "windows") -> MachineInfo:
    """Validate and decode a machine code (see shared.payload_schema).

    Args:
        code: pasted machine code (dashed or flat, case-insensitive).
        platform: OS the code was recorded on — only affects the human
            labels ("windows" when pasted without an export file).
    """
    if platform not in KNOWN_PLATFORMS:
        raise FingerprintParseError(f"unknown platform: {platform!r}")
    flat = flatten(code)
    try:
        raw = b32_decode(flat)
    except Exception as exc:
        raise FingerprintParseError("not valid Base32") from exc
    if len(raw) != 10:
        raise FingerprintParseError(
            f"fingerprint material must be 10 bytes, got {len(raw)}")
    mask = raw[0]
    if mask & 0xF0:
        raise FingerprintParseError("invalid fingerprint mask")
    present = parse_component_mask(mask)
    labels = component_labels(platform)
    return MachineInfo(
        code=group_blocks(flat, 4, "-"),
        mask=mask,
        present=present,
        present_names=[labels[k] for k in COMPONENT_ORDER
                       if present[k] and labels[k]],
        is_full=all(present.values()),
        platform=platform,
    )


def read_fingerprint_file(path: str | Path) -> MachineInfo:
    """Parse a fingerprint.txt exported by the client.

    The optional "platform" key (written by the Android/iOS/macOS SDKs)
    identifies which OS recorded the code; exports without it are legacy
    Windows exports.

    Raises:
        FingerprintParseError: unreadable, wrong format, or bad code.
    """
    file_path = Path(path)
    try:
        if file_path.stat().st_size > MAX_EXPORT_BYTES:
            raise FingerprintParseError(
                user_message="The fingerprint export is suspiciously large — "
                              "expected a small JSON file.")
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise FingerprintParseError("file could not be read") from exc
    except json.JSONDecodeError as exc:
        raise FingerprintParseError("file is not valid JSON") from exc
    if not isinstance(data, dict):
        raise FingerprintParseError(
            user_message="The fingerprint export is malformed. "
                         "Expected a JSON object.")
    if data.get("format") != FP_EXPORT_FORMAT:
        raise FingerprintParseError(
            "file is not a SecureCode fingerprint export",
            user_message="This file is not a SecureCode fingerprint export.")
    platform = str(data.get("platform", "windows"))
    if platform not in KNOWN_PLATFORMS:
        raise FingerprintParseError(
            f"unknown platform in export: {platform!r}",
            user_message=f"Unknown platform in export: {platform!r} "
                         f"(expected one of {', '.join(KNOWN_PLATFORMS)}).")
    info = parse_fingerprint(str(data.get("code", "")), platform)
    try:
        created = int(data.get("created", 0))
    except (TypeError, ValueError):
        raise FingerprintParseError(
            "invalid created timestamp",
            user_message="The fingerprint export is malformed "
                         "(bad created timestamp).") from None
    age_days = max(0, (time.time() - created) // 86400)
    if age_days > 90:
        log.warning("fingerprint file is %d days old", age_days)
    return info


__all__ = ["FP_EXPORT_FORMAT", "FingerprintParseError", "MachineInfo",
           "component_labels", "parse_fingerprint", "platform_display_name",
           "platform_slots", "read_fingerprint_file"]
