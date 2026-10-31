"""
protector.ui.widgets.title_bar — the custom frameless-window title bar.

Contains: breadcrumb "SecureCode Protector › <page>" (left), the signing-key
chip, theme toggle (sun/moon) and minimize / maximize-restore / close
buttons (right). All glyphs are vector icons tinted from the live palette.

Window dragging, edge-resize and Aero Snap are handled NATIVELY by the
shell window via WM_NCHITTEST (see main_window.py); it asks
``is_caption_point()`` whether a point is draggable (anything but a button).
"""

from __future__ import annotations

from PySide6.QtCore import QPoint, QSize, Qt, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QAbstractButton,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QWidget,
)

from ..i18n import is_rtl, ltr, tr
from ..theme import bind_pixmap, on_theme
from ..theme.icons import icon as make_icon
from ..theme.icons import pixmap

#: NOTE on styling: no local stylesheets here. Everything is painted by the
#: global theme QSS via object names (#titleBar, #keyChip, #btnMin, ...).


class TitleBar(QWidget):
    """Custom title bar for the frameless main window."""

    #: Emitted when the user clicks the theme quick-toggle (sun/moon).
    theme_toggle_requested = Signal()
    #: Emitted when the user clicks the language switch (FA / EN).
    language_toggle_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("titleBar")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setFixedHeight(44)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 0, 6, 0)
        layout.setSpacing(8)

        self.title_label = QLabel(tr("SecureCode Protector"))
        self.title_label.setObjectName("titleApp")
        chevron = bind_pixmap(QLabel(), "chevron-left" if is_rtl() else "chevron-right",
                              "text_subtle", 14)
        self.page_label = QLabel("")
        self.page_label.setObjectName("titlePage")

        layout.addWidget(self.title_label)
        layout.addWidget(chevron)
        layout.addWidget(self.page_label)
        layout.addStretch(1)

        self.key_chip = QLabel("")
        self.key_chip.setObjectName("keyChip")
        self.key_chip.setToolTip(tr(
            "Public key fingerprint of the active Ed25519 signing key. "
            "It must match the key compiled into your protected EXE."))
        layout.addWidget(self.key_chip, 0, Qt.AlignVCenter)
        layout.addSpacing(6)

        self.lang_btn = QPushButton("EN" if is_rtl() else "FA")
        self.lang_btn.setObjectName("langToggle")
        self.lang_btn.setToolTip(tr("Switch language — فارسی / English (Ctrl+L)"))
        self.lang_btn.setCursor(Qt.PointingHandCursor)
        self.lang_btn.clicked.connect(self.language_toggle_requested.emit)
        layout.addWidget(self.lang_btn)

        self.theme_btn = QPushButton()
        self.theme_btn.setObjectName("themeToggle")
        self.theme_btn.setToolTip(tr("Toggle dark / light theme (Ctrl+T)"))
        self.theme_btn.setCursor(Qt.PointingHandCursor)
        self.theme_btn.setIconSize(QSize(17, 17))
        self.theme_btn.clicked.connect(self.theme_toggle_requested.emit)
        layout.addWidget(self.theme_btn)

        sep = QWidget()
        sep.setFixedSize(1, 18)
        sep.setObjectName("titleSep")
        sep.setAttribute(Qt.WA_StyledBackground, True)
        on_theme(sep, lambda w, p: w.setStyleSheet(
            f"QWidget#titleSep {{ background: {p.border}; }}"))
        layout.addSpacing(4)
        layout.addWidget(sep)
        layout.addSpacing(4)

        self.btn_min = QPushButton()
        self.btn_min.setObjectName("btnMin")
        self.btn_max = QPushButton()
        self.btn_max.setObjectName("btnMax")
        self.btn_close = QPushButton()
        self.btn_close.setObjectName("btnClose")
        for btn, tip in ((self.btn_min, "Minimize"), (self.btn_max, "Maximize / restore"),
                         (self.btn_close, "Close")):
            btn.setToolTip(tr(tip))
            btn.setIconSize(QSize(15, 15))
            layout.addWidget(btn)
        self.btn_min.clicked.connect(self._minimize)
        self.btn_max.clicked.connect(self._toggle_maximize)
        self.btn_close.clicked.connect(self._close)

        on_theme(self, TitleBar._retint)

    # -------------------------------------------------- theming
    def _retint(self, p) -> None:
        dark = p.mode == "dark"
        self.theme_btn.setIcon(make_icon("sun" if dark else "moon", p.text_muted, 17))
        self.btn_min.setIcon(make_icon("minimize", p.text_muted, 15))
        maximized = self.window() is not None and self.window().isMaximized()
        self.btn_max.setIcon(make_icon("restore" if maximized else "maximize",
                                       p.text_muted, 15))
        close = make_icon("close", p.text_muted, 15)
        close.addPixmap(pixmap("close", "#FFFFFF", 15), QIcon.Active)
        self.btn_close.setIcon(close)
        self._palette = p

    def refresh_max_icon(self) -> None:
        """Called by the shell on window-state changes."""
        if hasattr(self, "_palette"):
            self._retint(self._palette)

    # -------------------------------------------------- window controls
    def is_caption_point(self, local: QPoint) -> bool:
        """True when ``local`` (title-bar coords) is a draggable spot."""
        child = self.childAt(local)
        while child is not None and child is not self:
            if isinstance(child, QAbstractButton):
                return False
            child = child.parentWidget()
        return True

    def _minimize(self) -> None:
        window = self.window()
        if window is not None:
            window.showMinimized()

    def _toggle_maximize(self) -> None:
        window = self.window()
        if window is None:
            return
        if window.isMaximized():
            window.showNormal()
        else:
            window.showMaximized()

    def _close(self) -> None:
        window = self.window()
        if window is not None:
            window.close()

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802
        """Non-Windows fallback (Windows gets this natively via HTCAPTION)."""
        if self.is_caption_point(event.position().toPoint()):
            self._toggle_maximize()

    # -------------------------------------------------- public API
    def set_page_title(self, title: str) -> None:
        """Show the current section name next to the app name."""
        self.page_label.setText(title)

    def set_key_id(self, key_id: str) -> None:
        """Show the active signing key fingerprint chip."""
        self.key_chip.setText(tr("key · {key}", key=ltr(key_id)) if key_id else "")
        self.key_chip.setVisible(bool(key_id))


__all__ = ["TitleBar"]
