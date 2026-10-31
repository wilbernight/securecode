"""
target_demo.protection.payload_view — tiny presentation helpers turning a
LicensePayload into human-readable rows (About box / status badge).

Kept separate from license_client so the client stays pure logic and this
module can freely import Qt-free formatting utilities.
"""

from __future__ import annotations

from datetime import datetime, timezone

from shared.payload_schema import LicensePayload, parse_component_mask


def payload_display_rows(payload: LicensePayload) -> list[tuple[str, str]]:
    """Human-readable (label, value) rows for a license payload.

    Only NON-secret, customer-facing data is shown. The nonce is truncated
    (support can correlate it with the vendor DB without exposing the full
    revocation identifier in screenshots).
    """
    def _ts(ts: int) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")

    rows: list[tuple[str, str]] = [
        ("Customer", payload.customer or "(unnamed)"),
        ("Product ID", payload.product_id),
        ("Machine code", payload.fingerprint),
        ("Issued", _ts(payload.issued_at)),
        ("Expires", "lifetime" if payload.is_lifetime else _ts(payload.expires_at)),
        ("Nonce", (payload.nonce[:8] + "…") if payload.nonce else "—"),
        ("Fingerprint tolerance", str(payload.tolerance)),
        ("Rollback allowance", str(payload.rollback_allowance)),
    ]
    if payload.feature_flags:
        flags = ", ".join(
            f"{name}={'on' if enabled else 'off'}"
            for name, enabled in sorted(payload.feature_flags.items())
        )
        rows.append(("Feature flags", flags))
    return rows


def fingerprint_presence_text(mask: int) -> str:
    """One-line description of which components a fingerprint mask records."""
    present = parse_component_mask(mask)
    order = ["cpu", "board", "disk", "guid"]
    labels = {"cpu": "CPU", "board": "motherboard", "disk": "primary disk",
             "guid": "machine GUID"}
    included = [labels[k] for k in order if present[k]]
    return ", ".join(included) if included else "no components"


__all__ = ["fingerprint_presence_text", "payload_display_rows"]
