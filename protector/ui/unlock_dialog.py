"""
protector.ui.unlock_dialog — keystore gate shown before the main window.

Two modes:
    * UNLOCK  (keystore exists): passphrase entry. Wrong passphrase -> a
      friendly error; the app never proceeds with an unwrapped keystore.
    * CREATE  (first run): passphrase + confirmation, plus an optional
      import of the shipped demo keypair so the whole stack works
      end-to-end out of the box (matches the key embedded in target_demo).

The dialog never stores passphrases; they exist only inside the unlock call.
Rejecting (Esc / ✕ / Quit) asks for confirmation first — an accidental key
press must not kill the session.

Visual: styled by the global theme QSS (object names #gate, #gateHero,
#gateTitle, #gateInput, #gateError). main.py applies the theme in the
Windows light/dark mode before showing it — the user's saved theme and
language live in the encrypted settings, unreadable until unlock — so the
gate stays bilingual (English + Persian).
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core.app_paths import DEMO_KEYPAIR_FILE, KEYSTORE_PATH
from ..core.crypto_engine import KeyStore
from .theme import bind_icon, current_palette
from .theme.icons import icon as make_icon
from .widgets.sidebar import logo_mark


class UnlockDialog(QDialog):
    """Gatekeeper dialog; returns Accepted only with an unlocked keystore."""

    def __init__(self, keystore: KeyStore, parent=None) -> None:
        super().__init__(parent)
        self.keystore = keystore
        self.import_demo_key = False
        self.first_run = not keystore.exists
        self._error: str | None = None

        self.setObjectName("gate")
        self.setWindowTitle("SecureCode Protector — Unlock")
        self.setModal(True)
        self.setFixedWidth(460)
        self.setLayoutDirection(Qt.LeftToRight)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # --- hero ---------------------------------------------------------
        hero = QWidget()
        hero.setObjectName("gateHero")
        hero.setAttribute(Qt.WA_StyledBackground, True)
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(32, 30, 32, 24)
        hero_layout.setSpacing(6)
        hero_layout.addWidget(logo_mark(52, 28), 0, Qt.AlignHCenter)
        hero_layout.addSpacing(8)
        title = QLabel("Create your keystore" if self.first_run else "Welcome back")
        title.setObjectName("gateTitle")
        title.setAlignment(Qt.AlignCenter)
        hero_layout.addWidget(title)
        sub = QLabel("SecureCode Protector · offline licensing console")
        sub.setProperty("class", "subtle")
        sub.setAlignment(Qt.AlignCenter)
        hero_layout.addWidget(sub)
        layout.addWidget(hero)

        # --- body ----------------------------------------------------------
        body = QWidget()
        form = QVBoxLayout(body)
        form.setContentsMargins(32, 22, 32, 26)
        form.setSpacing(10)

        mode_text = (
            "Create a passphrase for your signing keystore. It protects the "
            "Ed25519 key that issues every serial — do NOT lose it."
            if self.first_run else
            f"Enter your passphrase to unlock the signing keystore ({KEYSTORE_PATH.name}).")
        info = QLabel(mode_text)
        info.setProperty("class", "muted")
        info.setWordWrap(True)
        form.addWidget(info)

        fa_info = QLabel(
            "رمز عبور، کلید امضای سریال‌های شما را محافظت می‌کند — آن را گم نکنید."
            if self.first_run else
            "برای ادامه، رمز عبور کلید امضا را وارد کنید.")
        fa_info.setProperty("class", "faMuted")
        fa_info.setWordWrap(True)
        fa_info.setLayoutDirection(Qt.RightToLeft)  # Persian reads right-aligned
        fa_info.setAlignment(Qt.AlignLeading | Qt.AlignVCenter)
        form.addWidget(fa_info)
        form.addSpacing(6)

        lock = make_icon("lock", current_palette().text_subtle, 16)
        self.pass_edit = QLineEdit()
        self.pass_edit.setObjectName("gateInput")
        self.pass_edit.setEchoMode(QLineEdit.Password)
        self.pass_edit.setPlaceholderText("Passphrase · رمز عبور")
        self.pass_edit.addAction(lock, QLineEdit.LeadingPosition)
        form.addWidget(self.pass_edit)

        self.confirm_edit = QLineEdit()
        self.confirm_edit.setObjectName("gateInput")
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        self.confirm_edit.setPlaceholderText("Confirm passphrase · تکرار رمز")
        self.confirm_edit.addAction(lock, QLineEdit.LeadingPosition)
        if not self.first_run:
            self.confirm_edit.hide()
        form.addWidget(self.confirm_edit)

        if self.first_run:
            self.demo_check = QCheckBox(
                "Import the shipped demo keypair (issues serials the demo "
                "EXE accepts)")
            self.demo_check.setToolTip(
                f"Equivalent to Settings → Import shipped demo keypair. "
                f"Reads {DEMO_KEYPAIR_FILE.name} (passphrase: demo-demo-demo).")
            form.addWidget(self.demo_check)

        self.error_label = QLabel("")
        self.error_label.setObjectName("gateError")
        self.error_label.setWordWrap(True)
        form.addWidget(self.error_label)

        self.action_btn = QPushButton(
            "  Create keystore" if self.first_run else "  Unlock")
        self.action_btn.setProperty("size", "lg")
        self.action_btn.setCursor(Qt.PointingHandCursor)
        bind_icon(self.action_btn, "key" if self.first_run else "lock", "on_accent", 16)
        self.action_btn.clicked.connect(self._try_unlock)
        form.addWidget(self.action_btn)

        buttons = QHBoxLayout()
        foot = QLabel("100% offline · no network access")
        foot.setProperty("class", "subtle")
        buttons.addWidget(foot)
        buttons.addStretch(1)
        quit_btn = QPushButton("Quit")
        quit_btn.setObjectName("gateQuit")
        quit_btn.setProperty("class", "ghost")
        quit_btn.setCursor(Qt.PointingHandCursor)
        quit_btn.clicked.connect(self.reject)
        buttons.addWidget(quit_btn)
        form.addLayout(buttons)

        self.pass_edit.returnPressed.connect(self._try_unlock)
        self.confirm_edit.returnPressed.connect(self._try_unlock)

        layout.addWidget(body)

    # ------------------------------------------------------------------ logic
    def _fail(self, message: str) -> None:
        self.error_label.setText(message)

    def reject(self) -> None:
        """Confirm before dismissing the gate.

        Esc / the window's ✕ / the Quit button all land here, and rejecting
        makes the WHOLE app exit ("no unlock — exiting"). An accidental key
        press must not kill the session — ask first.
        """
        from PySide6.QtWidgets import QMessageBox

        answer = QMessageBox.question(
            self, "Quit SecureCode Protector?",
            "Close the protector without unlocking?\n"
            "(Nothing is lost — you can launch it again at any time.)\n\n"
            "بدون باز کردن قفل بسته شود؟ (چیزی از دست نمی‌رود)",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer == QMessageBox.Yes:
            super().reject()

    def _try_unlock(self) -> None:
        from ..core.crypto_engine import WrongPassphraseError

        passphrase = self.pass_edit.text()
        if len(passphrase) < 8:
            self._fail("Passphrase must be at least 8 characters. "
                       "(رمز عبور باید حداقل ۸ کاراکتر باشد)")
            self.pass_edit.setFocus()
            return
        try:
            if self.first_run:
                if passphrase != self.confirm_edit.text():
                    self._fail("Passphrases do not match. · رمزها یکسان نیستند")
                    return
                self.keystore.create(passphrase)
                self.import_demo_key = (
                    hasattr(self, "demo_check") and self.demo_check.isChecked())
            else:
                self.keystore.unlock(passphrase)
        except WrongPassphraseError:
            self._fail("Wrong passphrase — try again. · رمز عبور اشتباه است")
            # Select the wrong text so retyping needs no backspacing.
            self.pass_edit.setFocus()
            self.pass_edit.selectAll()
            return
        except Exception as exc:
            self._fail(f"Keystore error: {exc}")
            return
        self.accept()

    @staticmethod
    def run(keystore: KeyStore, parent=None) -> "UnlockDialog | None":
        """Convenience: show the dialog until unlocked or user quits."""
        while True:
            dialog = UnlockDialog(keystore, parent)
            if dialog.exec() != QDialog.Accepted:
                return None
            return dialog


__all__ = ["UnlockDialog"]
