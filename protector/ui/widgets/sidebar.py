"""
protector.ui.widgets.sidebar — grouped navigation rail.

Brand block (accent logo mark + name), titled groups ("Overview /
Licensing / Tools / General"), checkable entries with vector icons that
switch to the accent tint when selected, and a footer card showing the
offline state + version. Keyboard shortcuts Ctrl+1..N are registered by
the shell. Tooltips are bilingual (English + Persian).

Styling: no local color stylesheets — the global theme QSS paints it via
object names (#navRail, #navBrand, #logoMark, #navFooter) and properties
(navButton, class="navGroup"); icons re-tint through on_theme().
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..i18n import tr
from ..theme import bind_icon, bind_pixmap
from ..theme.icons import pixmap


@dataclass(frozen=True, slots=True)
class NavEntry:
    """One sidebar entry."""

    key: str            # page key used by the shell
    label: str          # sidebar label
    icon: str           # vector icon name (theme/icons.py)
    shortcut: str       # e.g. "Ctrl+1"
    tooltip: str        # English tooltip (bilingual rendering is added here)
    tooltip_fa: str     # Persian tooltip line


#: Flat order matters (the shell maps Ctrl+1..N onto these, in order).
NAV_ENTRIES: tuple[NavEntry, ...] = (
    NavEntry("dashboard", "Dashboard", "dashboard", "Ctrl+1",
             "Live counters and issuance activity",
             "شمارنده‌های زنده و فعالیت صدور سریال"),
    NavEntry("generate", "Generate Serial", "key", "Ctrl+2",
             "Issue a new hardware-locked serial key",
             "صدور سریال جدیدِ قفل‌شده به سخت‌افزار"),
    NavEntry("manager", "Serial Manager", "list", "Ctrl+3",
             "All issued serials: search, revoke, extend, export",
             "همه سریال‌ها: جست‌وجو، باطل‌کردن، تمدید، خروجی"),
    NavEntry("fingerprint", "Fingerprint Reader", "scan", "Ctrl+4",
             "Validate a customer machine code / export file",
             "بررسی کد اثر انگشت ماشین مشتری / فایل خروجی"),
    NavEntry("build", "Build Protection", "shield-check", "Ctrl+5",
             "Wrap a Python project with the protection SDK + Nuitka",
             "پروژه پایتون را با SDK محافظت + Nuitka بسته‌بندی کنید"),
    NavEntry("settings", "Settings", "settings", "Ctrl+6",
             "Keystore, products, theme, backups",
             "کلید امضا، محصولات، تم، پشتیبان‌ها"),
)

#: Grouped layout (labels above the entries) — the visible navigation.
NAV_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("OVERVIEW", ("dashboard",)),
    ("LICENSING", ("generate", "manager", "fingerprint")),
    ("TOOLS", ("build",)),
    ("GENERAL", ("settings",)),
)

_BY_KEY = {entry.key: entry for entry in NAV_ENTRIES}


def logo_mark(size: int = 36, icon_size: int = 20) -> QLabel:
    """The accent square with the white shield — the product's mark."""
    mark = QLabel()
    mark.setObjectName("logoMark")
    mark.setFixedSize(size, size)
    mark.setAlignment(Qt.AlignCenter)
    mark.setPixmap(pixmap("shield-check", "#FFFFFF", icon_size))
    return mark


class Sidebar(QWidget):
    """The vertical grouped navigation rail."""

    #: Emits the page key of the entry the user selected.
    navigated = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("navRail")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setFixedWidth(236)
        self.buttons: dict[str, QPushButton] = {}
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(14, 18, 14, 14)
        self._layout.setSpacing(2)

        # --- brand -------------------------------------------------------
        brand = QHBoxLayout()
        brand.setContentsMargins(6, 0, 0, 10)
        brand.setSpacing(11)
        brand.addWidget(logo_mark())
        names = QVBoxLayout()
        names.setSpacing(0)
        title = QLabel("SecureCode")
        title.setLayoutDirection(Qt.LeftToRight)
        title.setObjectName("navBrand")
        sub = QLabel(tr("Protector · licensing console"))
        sub.setObjectName("navBrandSub")
        names.addWidget(title)
        names.addWidget(sub)
        brand.addLayout(names, 1)
        self._layout.addLayout(brand)

        for group_title, keys in NAV_GROUPS:
            group = QLabel(tr(group_title))
            group.setProperty("class", "navGroup")
            self._layout.addWidget(group)
            for key in keys:
                self._add_entry(_BY_KEY[key])

        self._layout.addStretch(1)

        # --- footer card -------------------------------------------------
        footer = QFrame()
        footer.setObjectName("navFooter")
        foot = QVBoxLayout(footer)
        foot.setContentsMargins(12, 10, 12, 10)
        foot.setSpacing(3)
        status = QHBoxLayout()
        status.setSpacing(7)
        status.addWidget(bind_pixmap(QLabel(), "offline", "success", 14))
        state = QLabel(tr("Fully offline"))
        state.setProperty("class", "h3")
        status.addWidget(state, 1)
        foot.addLayout(status)
        version = QLabel(tr("No network access · v1.0.0"))
        version.setProperty("class", "subtle")
        foot.addWidget(version)
        footer.setToolTip(tr("This application never performs network access."))
        self._layout.addWidget(footer)

    def _add_entry(self, entry: NavEntry) -> None:
        button = QPushButton(f"  {tr(entry.label)}")
        button.setProperty("navButton", True)
        button.setCheckable(True)
        button.setMinimumHeight(38)
        button.setToolTip(f"{tr(entry.tooltip)}  ({entry.shortcut})")
        button.setCursor(Qt.PointingHandCursor)
        bind_icon(button, entry.icon, "text_muted", 18, checked_role="accent_text")
        button.clicked.connect(lambda: self.navigated.emit(entry.key))
        self._group.addButton(button)
        self.buttons[entry.key] = button
        self._layout.addWidget(button)

    def select(self, key: str) -> None:
        """Programmatically activate an entry (reflects the current page)."""
        if key in self.buttons:
            self.buttons[key].setChecked(True)


__all__ = ["NAV_ENTRIES", "NAV_GROUPS", "NavEntry", "Sidebar", "logo_mark"]
