"""
sdks.sync_native — keeps the Flutter plugin's embedded native sources in
sync with the single source of truth:

    sdks/android/securecode-sdk/src/main/kotlin/com/securecode/protection
        ->  sdks/flutter/securecode/android/src/main/kotlin/com/securecode/protection
    sdks/apple/SecureCodeKit/Sources/SecureCodeKit
        ->  sdks/flutter/securecode/darwin/Classes/SecureCodeKit

A Flutter plugin must be self-contained (it is consumed as a unit — the
same reason published plugins embed their native code), so we COPY rather
than reference. The plugin's own glue files live in SIBLING directories
(com/securecode/securecode on Android, Classes/SecurecodePlugin.swift on
Apple) and are never touched.

Idempotent; run after ANY change to the native SDKs:

    python sdks/sync_native.py [--check]

--check exits non-zero when the copies are stale (CI guard).
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent  # the securecode/ repo root

SYNCS: list[tuple[Path, Path]] = [
    (
        REPO / "sdks" / "android" / "securecode-sdk" / "src" / "main" / "kotlin" / "com" / "securecode" / "protection",
        REPO / "sdks" / "flutter" / "securecode" / "android" / "src" / "main" / "kotlin" / "com" / "securecode" / "protection",
    ),
    (
        REPO / "sdks" / "apple" / "SecureCodeKit" / "Sources" / "SecureCodeKit",
        REPO / "sdks" / "flutter" / "securecode" / "darwin" / "Classes" / "SecureCodeKit",
    ),
]


def _is_in_sync(src: Path, dst: Path) -> bool:
    if not dst.is_dir():
        return False
    src_files = {f.relative_to(src) for f in src.rglob("*") if f.is_file()}
    dst_files = {f.relative_to(dst) for f in dst.rglob("*") if f.is_file()}
    if src_files != dst_files:
        return False
    for rel in src_files:
        if not filecmp.cmp(src / rel, dst / rel, shallow=False):
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="only report whether copies are in sync")
    args = parser.parse_args(argv)

    all_ok = True
    for src, dst in SYNCS:
        if args.check:
            ok = _is_in_sync(src, dst)
            all_ok &= ok
            print(f"{'OK  ' if ok else 'STALE'} {src.relative_to(REPO)} -> {dst.relative_to(REPO)}")
        else:
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            count = sum(1 for f in dst.rglob('*') if f.is_file())
            print(f"synced {count} files -> {dst.relative_to(REPO)}")

    if args.check:
        if not all_ok:
            print("stale — run: python sdks/sync_native.py")
            return 1
        print("all in sync")
    else:
        print("(glue files untouched; build the Flutter plugin as usual)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
