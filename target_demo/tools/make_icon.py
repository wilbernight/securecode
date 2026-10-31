"""
target_demo.tools.make_icon — DEVELOPMENT-TIME tool (never shipped).

Generates assets/app.ico programmatically (no Pillow dependency): a rounded
blue square with a white padlock — the default SecureCode icon used by the
Nuitka `--windows-icon-from-ico` flag in build.bat.

ICO format: uncompressed 32-bpp BMP entries (256/48/32/16 px), written with
nothing but the stdlib (struct).
"""

from __future__ import annotations

import struct
from pathlib import Path

OUTPUT = Path(__file__).resolve().parents[1] / "assets" / "app.ico"
SIZES = (256, 48, 32, 16)

ACCENT = (59, 130, 246)     # #3B82F6
ACCENT_DARK = (37, 99, 235)  # #2563EB
WHITE = (255, 255, 255)


def _pixel(x: int, y: int, size: int) -> tuple[int, int, int, int]:
    """Render one pixel (BGRA tuple) of the lock glyph at a given size."""
    cx = cy = (size - 1) / 2
    radius = size * 0.46
    # rounded-square mask
    dx = abs(x - cx) / radius
    dy = abs(y - cy) / radius
    corner = 0.62
    if dx > 1 or dy > 1:
        return (0, 0, 0, 0)
    # rounded corner cut (superellipse-ish)
    if (max(dx, 0) ** corner + max(dy, 0) ** corner) > 1:
        return (0, 0, 0, 0)

    # gradient body
    body = tuple(
        int(a + (b - a) * (y / max(size - 1, 1)))
        for a, b in zip(ACCENT, ACCENT_DARK)
    )

    # ---- padlock geometry (in unit space u,v in [-1,1]) ------------------
    u = (x - cx) / radius
    v = (y - cy) / radius
    # shackle: ring centered above center
    ring_r, ring_w = 0.34, 0.11
    ru, rv = u, v + 0.28
    ring_dist = (ru * ru + rv * rv) ** 0.5
    if abs(ring_dist - ring_r) < ring_w and rv < -0.1:
        return (*WHITE, 255)
    # body: horizontal bar below center
    if -0.55 <= v <= 0.48 and -0.52 <= u <= 0.52:
        # keyhole
        hu, hv = u, v + 0.02
        hole_r = (hu * hu + hv * hv) ** 0.5
        if hole_r < 0.10 or (
                abs(hu) < 0.05 and -0.08 < hv < 0.30):
            return (*body, 255)
        return (*WHITE, 255)
    return (*body, 255)


def _render(size: int) -> bytes:
    """32-bpp BMP pixel data (bottom-up rows, BGRA)."""
    rows = []
    for y in range(size - 1, -1, -1):
        row = bytearray()
        for x in range(size):
            b, g, r, a = _pixel(x, y, size)
            row += bytes((b, g, r, a))
        rows.append(bytes(row))
    return b"".join(rows)


def _bmp_entry(size: int) -> tuple[int, bytes]:
    """(width_field, bmp_bytes) — 256 is stored as 0 in the ICO directory."""
    pixels = _render(size)
    header = struct.pack(
        "<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
        len(pixels), 0, 0, 0, 0)
    return (size if size < 256 else 0), header + pixels


def main() -> int:
    """Write assets/app.ico."""
    entries = [_bmp_entry(size) for size in SIZES]
    directory_size = 6 + 16 * len(entries)
    offsets = []
    cursor = directory_size
    for _, blob in entries:
        offsets.append(cursor)
        cursor += len(blob)

    out = bytearray()
    out += struct.pack("<HHH", 0, 1, len(entries))  # ICO header
    for (width, blob), offset in zip(entries, offsets):
        out += struct.pack("<BBBBHHII", width, width, 0, 0, 1, 32,
                           len(blob), offset)
    for _, blob in entries:
        out += blob

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(bytes(out))
    print(f"[ok] icon written -> {OUTPUT} ({len(out)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
