"""
target_demo.ui.main_window — SecureNotepad: the PROTECTED APPLICATION BODY.

*** THIS IS WHERE YOUR OWN CODE GOES ***
Everything above the marked line (see main.py: bootstrap -> verify ->
activation) is the licensing/protection wrapper; everything in this module
is ordinary application code. Licensing state is surfaced via the status-bar
badge ("Licensed to <customer> — expires YYYY-MM-DD / lifetime").

SecureNotepad itself: a small notepad with Open/Save/Save As/About.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QTextEdit,
    QToolBar,
)

from ..protection.license_client import LicenseClient, LicensePayload
from ..protection.payload_view import payload_display_rows  # small helper
from .styles import DEMO_QSS

log = logging.getLogger("demo.notepad")


def _format_expiry(payload: LicensePayload) -> str:
    """Human expiry string for the status badge."""
    if payload.is_lifetime:
        return "lifetime license"
    return "expires " + datetime.fromtimestamp(
        payload.expires_at, tz=timezone.utc).strftime("%Y-%m-%d")


class SecureNotepadWindow(QMainWindow):
    """Main application window (demo product)."""

    def __init__(self, client: LicenseClient, payload: LicensePayload) -> None:
        super().__init__()
        self._client = client
        self._payload = payload
        self._current_file: Path | None = None
        self._modified = False

        self.setWindowTitle("SecureNotepad — protected demo")
        self.resize(820, 560)
        self.setStyleSheet(DEMO_QSS)

        # --- central editor ------------------------------------------------
        self.editor = QTextEdit()
        self.editor.setFont(QFont("Consolas", 11))
        self.editor.setPlaceholderText(
            "This editor only runs with a valid, hardware-locked serial.\n"
            "Type anything — Open/Save work as usual.")
        self.editor.textChanged.connect(lambda: setattr(self, "_modified", True))
        self.setCentralWidget(self.editor)

        # --- toolbar ---------------------------------------------------------
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        toolbar.setStyleSheet("QToolBar { background: #10131A; spacing: 6px; padding: 4px; }")
        self.addToolBar(toolbar)

        act_open = QAction("📂 Open", self)
        act_open.setShortcut("Ctrl+O")
        act_open.triggered.connect(self._open)
        act_save = QAction("💾 Save", self)
        act_save.setShortcut("Ctrl+S")
        act_save.triggered.connect(self._save)
        act_saveas = QAction("Save As…", self)
        act_saveas.setShortcut("Ctrl+Shift+S")
        act_saveas.triggered.connect(self._save_as)
        act_about = QAction("🛡 About / License", self)
        act_about.triggered.connect(self._about)
        toolbar.addAction(act_open)
        toolbar.addAction(act_save)
        toolbar.addAction(act_saveas)
        toolbar.addSeparator()
        toolbar.addAction(act_about)

        # --- status bar: the license badge (required by spec) -----------------
        badge_text = (f"🟢 Licensed to {payload.customer or 'this computer'} "
                      f"— {_format_expiry(payload)}")
        badge = QLabel(badge_text)
        badge.setStyleSheet("color: #22C55E; padding: 0 8px;")
        self.statusBar().addWidget(badge)
        if not payload.is_lifetime:
            days = max(0, payload.seconds_left() // 86400)
            if days <= 30:
                warn = QLabel(f"⏳ {days} days remaining")
                warn.setStyleSheet("color: #F59E0B; padding: 0 8px;")
                self.statusBar().addPermanentWidget(warn)

    # ---------------------------------------------------------------- file ops
    def _open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open text file", "", "Text files (*.txt);;All files (*)")
        if not path:
            return
        try:
            self.editor.setPlainText(Path(path).read_text(encoding="utf-8"))
            self._current_file = Path(path)
            self._modified = False
        except OSError:
            QMessageBox.critical(self, "Open failed", f"Could not read {path}")

    def _save(self) -> None:
        if self._current_file is None:
            return self._save_as()
        self._current_file.write_text(self.editor.toPlainText(), encoding="utf-8")
        self._modified = False

    def _save_as(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save text file", "", "Text files (*.txt);;All files (*)")
        if not path:
            return
        self._current_file = Path(path)
        self._save()

    # ---------------------------------------------------------------- about
    def _about(self) -> None:
        rows = payload_display_rows(self._payload)
        info = "SecureNotepad 1.0 — protected demo\n\n"
        info += "\n".join(f"{k:<22}{v}" for k, v in rows)
        info += "\n\nProtected by SecureCode:\n• Ed25519-signed offline serial\n" \
                "• Hardware-locked & time-limited\n• Anti-debug + self-integrity"
        QMessageBox.information(self, "About / License", info)

    # ---------------------------------------------------------------- shutdown
    def closeEvent(self, event) -> None:  # noqa: N802 (Qt naming)
        if self._modified:
            answer = QMessageBox.question(
                self, "Unsaved changes",
                "You have unsaved changes. Close anyway?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                event.ignore()
                return
        event.accept()
