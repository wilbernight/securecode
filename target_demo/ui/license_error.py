"""
target_demo.ui.license_error — the "license problem" full-screen page.

Shown when silent verification at launch fails in a way the user cannot fix
by pasting a serial (expired / revoked / clock tampered / damaged). Gives
professional, actionable instructions plus this machine's fingerprint code
(the support script) and a "Retry" button.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from ..protection.license_client import LicenseState, LicenseStatus
from .styles import DEMO_QSS

#: Short explanation per state (titles kept actionable for legit customers).
_STATE_TITLES: dict[LicenseState, str] = {
    LicenseState.EXPIRED: "License expired",
    LicenseState.REVOKED: "License revoked",
    LicenseState.CLOCK_TAMPERED: "System clock problem detected",
    LicenseState.DAMAGED: "License data damaged",
    LicenseState.WRONG_MACHINE: "License bound to another computer",
    LicenseState.INVALID: "Invalid license",
    LicenseState.DEGRADED: "Application data damaged",
}

#: What the customer should do, per state.
_STATE_HINTS: dict[LicenseState, str] = {
    LicenseState.EXPIRED:
        "Your subscription period has ended.\n"
        "Renew with your vendor to receive a new serial key.",
    LicenseState.REVOKED:
        "This serial key has been revoked by the vendor.\n"
        "Contact support if you believe this is a mistake.",
    LicenseState.CLOCK_TAMPERED:
        "The system clock was set back repeatedly. Set the correct date "
        "and time in Windows settings, then click Retry.\n"
        "If the problem persists, contact support to reactivate.",
    LicenseState.DAMAGED:
        "The local license file is unreadable. Save your fingerprint code "
        "below and contact support to re-activate.",
    LicenseState.WRONG_MACHINE:
        "This license belongs to a different computer.\n"
        "Use the transfer workflow (vendor permit) to move it here.",
    LicenseState.INVALID:
        "The installed license failed verification.\n"
        "Please reinstall the application and activate again.",
    LicenseState.DEGRADED:
        "A required application component could not be verified.\n"
        "Please reinstall the application.",
}


class LicenseErrorDialog(QDialog):
    """Blocking dialog with state-specific guidance + retry option."""

    def __init__(self, status: LicenseStatus, machine_code: str,
                 parent=None) -> None:
        super().__init__(parent)
        self.retry_requested = False
        self.setWindowTitle(_STATE_TITLES.get(status.state, "License problem"))
        self.setStyleSheet(DEMO_QSS)
        self.setModal(True)
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 30, 32, 26)
        layout.setSpacing(14)

        icon = QLabel("⛔")
        icon.setStyleSheet("font-size: 42px; background: transparent;")
        icon.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon)

        title = QLabel(_STATE_TITLES.get(status.state, "License problem"))
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        hint = QLabel(_STATE_HINTS.get(status.state, status.message))
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #8B93A7;")
        hint.setAlignment(Qt.AlignCenter)
        layout.addWidget(hint)

        if status.message:
            detail = QLabel(status.message)
            detail.setWordWrap(True)
            detail.setStyleSheet("color: #E6E9EF; font-size: 13px;")
            detail.setAlignment(Qt.AlignCenter)
            layout.addWidget(detail)

        fp = QLabel(f"This computer's fingerprint:  {machine_code}")
        fp.setStyleSheet(
            "font-family: 'Cascadia Mono', Consolas, monospace;"
            "color: #22C55E; letter-spacing: 2px;")
        fp.setTextInteractionFlags(Qt.TextSelectableByMouse)
        fp.setAlignment(Qt.AlignCenter)
        layout.addWidget(fp)

        buttons = QHBoxLayout()
        retry = QPushButton("Retry")
        retry.clicked.connect(self._retry)
        close = QPushButton("Close application")
        close.setProperty("flatButton", True)
        close.clicked.connect(self.reject)
        buttons.addStretch(1)
        buttons.addWidget(retry)
        buttons.addWidget(close)
        buttons.addStretch(1)
        layout.addLayout(buttons)

    def _retry(self) -> None:
        self.retry_requested = True
        self.accept()
