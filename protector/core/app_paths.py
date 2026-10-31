"""
protector.core.app_paths — canonical filesystem locations of the protector.

All state lives in a user-scoped directory (no elevation needed):

    Windows : %APPDATA%\\SecureCode\\Protector\\
    macOS   : ~/Library/Application Support/SecureCode/Protector/
    other   : ${XDG_CONFIG_HOME:-~/.config}/SecureCode/Protector/

    keystore.dat   — passphrase-wrapped Ed25519 keypair + DB master key
    licenses.db    — encrypted SQLite license store
    settings.dat   — encrypted application settings
    logs/          — rotating log files (never contain secrets)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DIR_NAME = "SecureCode"
PROTECTOR_DIR_NAME = "Protector"


def _appdata() -> Path:
    # Windows: classic roaming profile path.
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        if base:
            return Path(base) / APP_DIR_NAME / PROTECTOR_DIR_NAME
        return Path.home() / f".{APP_DIR_NAME.lower()}" / PROTECTOR_DIR_NAME.lower()
    # macOS: the standard Application Support location for user state.
    if sys.platform == "darwin":
        return (Path.home() / "Library" / "Application Support"
                / APP_DIR_NAME / PROTECTOR_DIR_NAME)
    # Linux/BSD: XDG config home (protector is vendor software, runs anywhere).
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / APP_DIR_NAME / PROTECTOR_DIR_NAME


BASE_DIR: Path = _appdata()
KEYSTORE_PATH: Path = BASE_DIR / "keystore.dat"
DB_PATH: Path = BASE_DIR / "licenses.db"
SETTINGS_PATH: Path = BASE_DIR / "settings.dat"
LOGS_DIR: Path = BASE_DIR / "logs"

#: Convenient starting directory for file dialogs.
SAVE_HINT: Path = Path.home() / "Documents"

#: Shipped demo keypair (see target_demo/tools/gen_demo_keypair.py).
REPO_ROOT: Path = Path(__file__).resolve().parents[2]
DEMO_KEYPAIR_FILE: Path = REPO_ROOT / "demo-assets" / "demo_keypair.sec"

#: Optional, human-readable location of the current theme snapshot.
THEME_SNAPSHOT: Path = REPO_ROOT / "protector" / "assets" / "theme_snapshot.qss"


def ensure_dirs() -> None:
    """Create the state directories if missing."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    BASE_DIR.mkdir(parents=True, exist_ok=True)


__all__ = [
    "BASE_DIR",
    "DB_PATH",
    "DEMO_KEYPAIR_FILE",
    "KEYSTORE_PATH",
    "LOGS_DIR",
    "REPO_ROOT",
    "SAVE_HINT",
    "SETTINGS_PATH",
    "THEME_SNAPSHOT",
    "ensure_dirs",
]
