"""
protector.ui.main_window — ShellWindow: the frameless commercial-grade shell.

Structure:

    ┌ TitleBar ──────────────────────────────────────────────────┐
    ├ Sidebar ─┬ QStackedWidget (6 pages) ────────────────────── ┤
    │          │                                                 │
    └──────────┴─────────────────────────────────────────────────┘

Features:
    * frameless with NATIVE Windows hit-testing (WM_NCHITTEST): drag from
      the title bar, resize from all 8 edges, Aero Snap, double-click
      maximize — exactly like a first-class Win32 app
    * sidebar navigation + QStackedWidget pages (Ctrl+1..6, F5 refresh)
    * Ctrl+T quick theme toggle; toasts anchored bottom-right
    * status bar with key id + "100% offline" badge
    * on close: secrets wiped (keystore.close()), geometry persisted
"""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtGui import QCloseEvent, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QHBoxLayout,
    QMainWindow,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from ..core.app_paths import DB_PATH
from .pages.build import BuildPage
from .pages.dashboard import DashboardPage
from .pages.fingerprint_reader import FingerprintReaderPage
from .pages.generate import GeneratePage
from .pages.manager import ManagerPage
from .pages.settings_page import SettingsPage
from . import i18n
from .i18n import tr
from .services import Services
from .widgets.sidebar import NAV_ENTRIES, Sidebar
from .widgets.title_bar import TitleBar
from .widgets.toast import ToastManager

# Windows hit-test constants
_HTCLIENT = 1
_HTCAPTION = 2
_HTLEFT = 10
_HTRIGHT = 11
_HTTOP = 12
_HTTOPLEFT = 13
_HTTOPRIGHT = 14
_HTBOTTOM = 15
_HTBOTTOMLEFT = 16
_HTBOTTOMRIGHT = 17
_WM_NCHITTEST = 0x0084
_BORDER = 6


class _MSG(ctypes.Structure):
    """Win32 MSG, used to decode nativeEvent messages."""

    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("message", wintypes.UINT),
        ("wParam", wintypes.WPARAM),
        ("lParam", wintypes.LPARAM),
        ("time", wintypes.DWORD),
        ("pt", wintypes.POINT),
    ]


class ShellWindow(QMainWindow):
    """The main application shell."""

    def __init__(self, services: Services, start_page: str | None = None) -> None:
        super().__init__()
        self.services = services
        self._rebuilding = False
        self.setLayoutDirection(i18n.direction())
        self.setObjectName("shell")
        self.setWindowTitle("SecureCode Protector")
        self.setMinimumSize(1020, 640)

        # Frameless + native hit-testing on Windows; plain frame elsewhere.
        if os.name == "nt":
            self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        else:  # pragma: no cover - dev portability
            self.setWindowFlags(Qt.Window)

        self._build_central()
        self._build_status_bar()
        self._wire_navigation()
        self._install_shortcuts()
        self._restore_geometry()

        # Initial page + first refresh shortly after the event loop starts.
        self.title_bar.set_key_id(services.keystore.key_id)
        first = start_page or self.sidebar_first_key()
        QTimer.singleShot(30, lambda: self._goto(first))

    # ================================================================ layout
    def _build_central(self) -> None:
        central = QWidget()
        central.setObjectName("shellBody")
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.title_bar = TitleBar()
        self.title_bar.theme_toggle_requested.connect(self._toggle_theme)
        self.title_bar.language_toggle_requested.connect(
            lambda: self.switch_language("en" if i18n.is_rtl() else "fa"))
        root.addWidget(self.title_bar)

        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        self.sidebar = Sidebar()
        body_layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        body_layout.addWidget(self.stack, 1)

        root.addWidget(body, 1)
        self.setCentralWidget(central)

    def _build_status_bar(self) -> None:
        from datetime import datetime, timezone

        from PySide6.QtWidgets import QLabel

        from ..core.jalali import DoranDate
        from .theme import bind_pixmap

        bar = QStatusBar()
        bar.setSizeGripEnabled(False)
        self.setStatusBar(bar)

        def _item(icon: str, text: str, role: str = "text_subtle",
                  name: str | None = None) -> QWidget:
            holder = QWidget()
            row = QHBoxLayout(holder)
            row.setContentsMargins(10, 0, 10, 0)
            row.setSpacing(6)
            row.addWidget(bind_pixmap(QLabel(), icon, role, 13))
            label = QLabel(text)
            if name:
                label.setObjectName(name)
            row.addWidget(label)
            return holder

        self.status_key = _item("key", tr("Signing key {key}",
                                          key=i18n.ltr(self.services.keystore.key_id)))
        bar.addWidget(self.status_key)
        today = DoranDate.now()
        gregorian = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        bar.addWidget(_item(
            "calendar",
            f"{today.format('D MMMM YYYY', fa=True)}  ·  {i18n.ltr(gregorian)}"
            if i18n.is_rtl()
            else f"{gregorian}  ·  {today.format('D MMMM YYYY', fa=True)}"))
        db_item = _item("database", DB_PATH.name)
        db_item.setToolTip(str(DB_PATH))
        bar.addPermanentWidget(db_item)
        offline = _item("offline", tr("100% offline"), "success", "onlineDot")
        offline.setToolTip(tr("This application never performs network access."))
        bar.addPermanentWidget(offline)

    def _wire_navigation(self) -> None:
        # Pages (order matches NAV_ENTRIES).
        pages = {
            "dashboard": DashboardPage(self.services),
            "generate": GeneratePage(self.services),
            "manager": ManagerPage(self.services),
            "fingerprint": FingerprintReaderPage(self.services),
            "build": BuildPage(self.services),
            "settings": SettingsPage(self.services),
        }
        self._pages = pages
        for key, page in pages.items():
            self.stack.addWidget(page)

        self.sidebar.navigated.connect(self._goto)

        # Late service wiring (needs both pages and toast manager).
        self.services.toast = ToastManager(self)
        self.services.navigate = self._goto

        def _prefill(fingerprint: str, customer: str | None,
                    platform: str = "windows") -> None:
            self._goto("generate")
            self._pages["generate"].prefill(fingerprint, customer, platform)

        self.services.prefill_generate = _prefill
        self.services.set_language = self.switch_language

        def _refresh_visible() -> None:
            current = self.stack.currentWidget()
            if current is not None and hasattr(current, "refresh"):
                current.refresh()

        self.services.refresh_hook = _refresh_visible

    def _install_shortcuts(self) -> None:
        for index, entry in enumerate(NAV_ENTRIES, start=1):
            QShortcut(QKeySequence(f"Ctrl+{index}"), self).activated.connect(
                lambda key=entry.key: self._goto(key))
        QShortcut(QKeySequence("F5"), self).activated.connect(
            self._refresh_current)
        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(
            self._toggle_theme)
        QShortcut(QKeySequence("Ctrl+L"), self).activated.connect(
            lambda: self.switch_language("en" if i18n.is_rtl() else "fa"))
        QShortcut(QKeySequence("Ctrl+F"), self).activated.connect(
            lambda: self._goto("manager"))
        QShortcut(QKeySequence("Ctrl+G"), self).activated.connect(
            lambda: self._goto("generate"))

    # ================================================================ helpers
    def sidebar_first_key(self) -> str:
        return NAV_ENTRIES[0].key

    def _goto(self, key: str) -> None:
        if key not in self._pages:
            return
        self.stack.setCurrentWidget(self._pages[key])
        self.sidebar.select(key)
        for entry in NAV_ENTRIES:
            if entry.key == key:
                self.title_bar.set_page_title(tr(entry.label))
                break
        page = self._pages[key]
        if hasattr(page, "refresh"):
            page.refresh()

    def _refresh_current(self) -> None:
        page = self.stack.currentWidget()
        if page is not None and hasattr(page, "refresh"):
            page.refresh()

    def _toggle_theme(self) -> None:
        new_mode = "light" if self.services.settings.theme == "dark" else "dark"
        self.services.settings.theme = new_mode
        self.services.theme.restyle(self.services.app, mode=new_mode)
        self._refresh_current()

    def current_page_key(self) -> str:
        current = self.stack.currentWidget()
        for key, page in self._pages.items():
            if page is current:
                return key
        return self.sidebar_first_key()

    def switch_language(self, code: str) -> None:
        """Switch EN/FA: persist, re-theme (font + direction), rebuild shell."""
        if code == i18n.language():
            return
        self.services.settings.language = code
        i18n.set_language(code)
        self.services.theme.apply(self.services.app)
        replacement = ShellWindow(self.services, start_page=self.current_page_key())
        replacement.setGeometry(self.geometry())
        if self.isMaximized():
            replacement.showMaximized()
        else:
            replacement.show()
        self.services.window = replacement
        self._rebuilding = True
        self.setAttribute(Qt.WA_DeleteOnClose, True)
        self.close()
        replacement.services.toast.show(
            "info", "فارسی" if code == "fa" else "English",
            "زبان برنامه تغییر کرد." if code == "fa" else "Interface language changed.")

    # ================================================================ geometry
    def _restore_geometry(self) -> None:
        import base64

        saved = self.services.settings.load_geometry()
        if saved:
            try:
                self.restoreGeometry(base64.b64decode(saved))
                return
            except Exception:
                pass
        self.resize(1180, 720)

    def changeEvent(self, event) -> None:  # noqa: N802
        super().changeEvent(event)
        if event.type() == event.Type.WindowStateChange:
            self.title_bar.refresh_max_icon()

    # ================================================================ close
    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        import base64

        if self._rebuilding:  # language switch: the session continues
            super().closeEvent(event)
            return
        self.services.settings.save_geometry(
            base64.b64encode(self.saveGeometry()).decode("ascii"))
        try:
            self.services.db.close()
        except Exception:
            pass
        # Layer 5 hygiene: wipe unwrapped key material on exit.
        self.services.keystore.close()
        super().closeEvent(event)

    # ================================================================ native
    def nativeEvent(self, eventType, message):  # noqa: N802
        """WM_NCHITTEST handling: native drag, 8-edge resize, Aero Snap."""
        if os.name == "nt" and eventType == b"windows_generic_MSG":
            msg = _MSG.from_address(int(message))
            if msg.message == _WM_NCHITTEST:
                result = self._hit_test(msg.lParam)
                if result is not None:
                    return True, result
        return super().nativeEvent(eventType, message)

    def _hit_test(self, l_param: int) -> int | None:
        """Map a screen point to a Win32 hit-test code (None = Qt handles)."""
        if self.isMaximized():
            return None
        x = ctypes.c_short(l_param & 0xFFFF).value
        y = ctypes.c_short((l_param >> 16) & 0xFFFF).value
        origin = self.mapToGlobal(QPoint(0, 0))
        local_x, local_y = x - origin.x(), y - origin.y()
        width, height = self.width(), self.height()

        left = local_x < _BORDER
        right = local_x >= width - _BORDER
        top = local_y < _BORDER
        bottom = local_y >= height - _BORDER

        if top and left:
            return _HTTOPLEFT
        if top and right:
            return _HTTOPRIGHT
        if bottom and left:
            return _HTBOTTOMLEFT
        if bottom and right:
            return _HTBOTTOMRIGHT
        if left:
            return _HTLEFT
        if right:
            return _HTRIGHT
        if top:
            return _HTTOP
        if bottom:
            return _HTBOTTOM

        # Caption (drag) zone: the custom title bar, minus its buttons.
        if 0 <= local_y <= self.title_bar.height():
            if self.title_bar.is_caption_point(QPoint(local_x, local_y)):
                return _HTCAPTION
        return _HTCLIENT


__all__ = ["ShellWindow"]
