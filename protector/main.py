"""
protector.main — application entry point.

Boot order:
    1. state directories + rotating file logging (never logs secrets)
    2. DPI/font setup, QApplication
    3. keystore gate (UnlockDialog: create or unlock)
    4. decrypt + open settings + license database (DB master key from keystore)
    5. ShellWindow + event loop
    6. on exit: keystore wiped (Layer 5)

Run:  python -m protector.main
"""

from __future__ import annotations

import logging
import logging.handlers
import sys

# --- make repo root importable (shared package) -----------------------------
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from protector.core.app_paths import (  # noqa: E402
    DB_PATH,
    KEYSTORE_PATH,
    LOGS_DIR,
    SETTINGS_PATH,
    ensure_dirs,
)
from protector.core.crypto_engine import KeyStore  # noqa: E402
from protector.core.db import DBError, LicenseDB  # noqa: E402
from protector.core.settings import AppSettings, SettingsError  # noqa: E402
from protector.ui.main_window import ShellWindow  # noqa: E402
from protector.ui.services import Services  # noqa: E402
from protector.ui.theme import ThemeManager, load_fonts  # noqa: E402
from protector.ui.unlock_dialog import UnlockDialog  # noqa: E402

import os


def setup_logging() -> None:
    """Rotating file handler; secrets (serials, keys, passphrases) are never
    logged anywhere by design — logging calls receive ids and statuses only."""
    ensure_dirs()
    handler = logging.handlers.RotatingFileHandler(
        LOGS_DIR / "protector.log", maxBytes=512 * 1024, backupCount=4,
        encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    if os.environ.get("SC_DEV"):
        root.addHandler(logging.StreamHandler())


def main() -> int:
    """Application bootstrap."""
    setup_logging()
    log = logging.getLogger("protector.main")

    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QMessageBox

    # Crisp DPI scaling on Windows (Qt6 enables it by default; make the
    # rounding policy explicit so 125%/150% stay sharp).
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setApplicationName("SecureCode Protector")
    app.setOrganizationName("SecureCode")
    app.setStyle("Fusion")  # neutral base; custom QSS does the real theming

    # Bundled Vazirmatn must be registered BEFORE any Persian text renders
    # (the unlock dialog is bilingual and shows before the theme engine).
    load_fonts()

    # The gate follows the Windows light/dark mode; the saved theme lives in
    # the encrypted settings and restyles everything right after unlock.
    theme = ThemeManager(ThemeManager.system_mode(app))
    theme.apply(app)

    # ------------------------------------------------------------------ keystore
    keystore = KeyStore(KEYSTORE_PATH)
    dialog = UnlockDialog.run(keystore)
    if dialog is None:
        log.info("no unlock — exiting")
        return 0

    # Optional demo-key import chosen in the create dialog — runs BEFORE
    # settings/DB are opened: import re-wraps the keystore, and (with the DB
    # master key preserved) this keeps all stores consistent from the start.
    if dialog.first_run and dialog.import_demo_key:
        from protector.core.app_paths import DEMO_KEYPAIR_FILE
        if DEMO_KEYPAIR_FILE.is_file():
            try:
                with open(DEMO_KEYPAIR_FILE, "rb") as handle:
                    blob = handle.read()
                keystore.import_private_key(
                    blob, "demo-demo-demo",
                    store_passphrase=dialog.pass_edit.text())
                log.info("imported demo keypair %s", keystore.key_id)
            except Exception:
                log.exception("demo key import failed")
        else:
            QMessageBox.information(
                None, "Demo keypair missing",
                f"Run target_demo/tools/gen_demo_keypair.py to create it.\n"
                "A fresh keypair was generated instead.")

    try:
        settings = AppSettings(SETTINGS_PATH, keystore.db_master)
    except SettingsError as exc:
        log.exception("settings unusable")
        QMessageBox.critical(None, "Settings error", str(exc))
        return 1

    # Live theme + UI language from the (just decrypted) settings.
    from protector.ui import i18n

    i18n.set_language(settings.language)
    theme.restyle(app, mode=settings.theme, accent=settings.accent)

    # ------------------------------------------------------------------
    try:
        db = LicenseDB(DB_PATH, keystore.db_master)
    except DBError as exc:
        log.exception("database unusable")
        QMessageBox.critical(None, "Database error", str(exc))
        return 1

    services = Services(app=app, keystore=keystore, db=db,
                        settings=settings, theme=theme)
    services.window = ShellWindow(services)
    services.window.show()

    log.info("protector started (key id %s)", keystore.key_id)
    code = app.exec()
    log.info("protector exited (%d)", code)
    # Explicit exit: Python/Qt teardown after app.exec() can abort the
    # process on Windows (fail-fast during object destruction). Secrets are
    # already wiped by ShellWindow.closeEvent; flush logs, then exit hard.
    for handler in logging.getLogger().handlers:
        handler.flush()
    os._exit(code)


if __name__ == "__main__":
    raise SystemExit(main())
