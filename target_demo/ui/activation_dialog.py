"""
target_demo.ui.activation_dialog — first-launch activation screen.

Shows:
    * the serial key input (paste box, monospace)
    * THIS machine's fingerprint code + "Save fingerprint file" button so the
      customer can send it to the vendor (the vendor generates the serial)
    * license activation feedback (invalid / other machine / expired / ...)
    * a "Deactivate with vendor permit file" path for machine transfers

On successful activation the dialog calls back into the host application,
which then opens the main window.
"""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..protection.fingerprint import export_fingerprint_file
from ..protection.license_client import ActivationResult, LicenseClient
from ..protection.strings import S
from .styles import DEMO_QSS

log = logging.getLogger("demo.activation")


class ActivationDialog(QDialog):
    """Modal activation dialog shown when no valid license is installed."""

    def __init__(self, client: LicenseClient, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._client = client
        self.activated = False
        self.setWindowTitle("Activate SecureNotepad")
        self.setModal(True)
        self.setMinimumWidth(560)
        self.setStyleSheet(DEMO_QSS)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)

        title = QLabel("Activate your license")
        title.setStyleSheet("font-size: 20px; font-weight: 700; color: #E6E9EF;")
        subtitle = QLabel(
            "Paste the serial key you received from the vendor. "
            "It is valid for this computer only."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #8B93A7;")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        # --- machine fingerprint card -------------------------------------
        from PySide6.QtWidgets import QFrame

        card = QFrame()
        card.setObjectName("fpCard")
        card.setStyleSheet("""
            QFrame#fpCard { background: #1B202B; border: 1px solid #2A3140;
                           border-radius: 8px; }
        """)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(6)

        fp_label = QLabel("This computer's fingerprint code (send this to the vendor):")
        fp_label.setStyleSheet("color: #8B93A7; font-size: 12px;")
        fp_code = QLabel(client.machine_code())
        fp_code.setStyleSheet(
            "font-family: 'Cascadia Mono', 'Consolas', monospace;"
            "font-size: 20px; font-weight: 700; color: #22C55E;"
            "letter-spacing: 3px; background: transparent;"
        )
        fp_code.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card_layout.addWidget(fp_label)
        card_layout.addWidget(fp_code)

        fp_buttons = QHBoxLayout()
        save_fp = QPushButton("Save fingerprint file…")
        save_fp.setProperty("flatButton", True)
        save_fp.setToolTip(
            "Exports fingerprint.txt — e-mail it to the vendor so they can "
            "issue a serial locked to this machine.")
        save_fp.clicked.connect(self._save_fingerprint)
        fp_buttons.addWidget(save_fp)
        fp_buttons.addStretch(1)
        card_layout.addLayout(fp_buttons)
        layout.addWidget(card)

        # --- serial input ---------------------------------------------------
        serial_label = QLabel("Serial key:")
        serial_label.setStyleSheet("color: #8B93A7; font-size: 12px;")
        layout.addWidget(serial_label)

        self.serial_edit = QTextEdit()
        self.serial_edit.setPlaceholderText("XXXXX-XXXXX-XXXXX-…")
        self.serial_edit.setStyleSheet(
            DEMO_QSS + "QTextEdit { font-family: 'Cascadia Mono', Consolas, monospace; }")
        self.serial_edit.setFixedHeight(96)
        self.serial_edit.setAcceptRichText(False)
        layout.addWidget(self.serial_edit)

        # --- status + actions -------------------------------------------------
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet("color: #F87171;")
        layout.addWidget(self.status_label)

        buttons = QHBoxLayout()
        activate_btn = QPushButton("Activate")
        activate_btn.setMinimumWidth(140)
        activate_btn.clicked.connect(self._activate)
        deactivate_btn = QPushButton("Deactivate with vendor permit…")
        deactivate_btn.setProperty("flatButton", True)
        deactivate_btn.setToolTip(
            "Moving to a new computer? Use the transfer permit file your "
            "vendor sent you to remove the license from this machine.")
        deactivate_btn.clicked.connect(self._deactivate_with_permit)
        buttons.addWidget(deactivate_btn)
        buttons.addStretch(1)
        buttons.addWidget(activate_btn)
        layout.addLayout(buttons)

    # ------------------------------------------------------------------ actions
    def _save_fingerprint(self) -> None:
        default = Path.home() / "fingerprint.txt"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save fingerprint file", str(default), "Text files (*.txt)")
        if not path:
            return
        try:
            out = export_fingerprint_file(path, self._client._config.product_id)
            QMessageBox.information(
                self, "Fingerprint saved",
                f"Send this file to your vendor:\n{out}")
        except Exception:
            log.exception("fingerprint export failed")
            QMessageBox.critical(self, "Error", "Could not write the fingerprint file.")

    def _activate(self) -> None:
        serial = self.serial_edit.toPlainText().strip()
        if not serial:
            self.status_label.setText("Please paste the serial key first.")
            return
        result: ActivationResult = self._client.activate(serial)
        if result.ok:
            self.activated = True
            self.accept()
            return
        self.status_label.setText(result.message)

    def _deactivate_with_permit(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open vendor transfer permit", "", "Permit files (*.sec *.txt);;All files (*)")
        if not path:
            return
        ok, message = self._client.deactivate_with_permit(path)
        box = (QMessageBox.information if ok else QMessageBox.warning)
        box(self, "Deactivation", message)
        if ok:
            self.status_label.setText(
                "License removed. Activate with the new serial on this machine.")
