"""
protector.ui.pages.base — shared page scaffolding + the small component kit
every page is built from (header, cards, card headers, icon badges, status
badges, form fields, buttons, key/value rows).

Rule of the v3 design: pages never set colors in local stylesheets. They
tag widgets (class / badge / iconBadge properties, object names) and the
global theme QSS paints them, so dark/light + accent switching is live.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..i18n import tr
from ..theme import bind_icon, bind_pixmap

if TYPE_CHECKING:  # avoid a Qt import cycle at type time only
    from ..services import Services

#: Page outer margins (left, top, right, bottom).
PAGE_MARGINS = (32, 26, 32, 26)

#: Icon color role for each tone of icon badge.
_TONE_ROLE = {"accent": "accent_text", "success": "success", "warning": "warning",
              "danger": "danger", "info": "info", "neutral": "text_muted"}


class Page(QWidget):
    """Base class for all shell pages.

    Subclasses build their UI in ``_build()`` (called from this constructor)
    and override ``refresh()`` to reload data when shown.
    """

    def __init__(self, services: "Services", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.services = services
        self.setObjectName("pageRoot")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._build()

    # -------------------------------------------------- contract
    def _build(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def refresh(self) -> None:  # pragma: no cover - optional
        """Reload page data (called on show + global refresh)."""


# ---------------------------------------------------------------------------
# layout helpers
# ---------------------------------------------------------------------------
def page_layout(page: QWidget, spacing: int = 18) -> QVBoxLayout:
    """Standard non-scrolling page layout with the shared margins."""
    layout = QVBoxLayout(page)
    layout.setContentsMargins(*PAGE_MARGINS)
    layout.setSpacing(spacing)
    return layout


def scroll_layout(page: QWidget, spacing: int = 18) -> QVBoxLayout:
    """Scrolling page layout: returns the content layout inside the scroller."""
    outer = QVBoxLayout(page)
    outer.setContentsMargins(0, 0, 0, 0)
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QScrollArea.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    content = QWidget()
    content.setObjectName("scrollContent")
    layout = QVBoxLayout(content)
    layout.setContentsMargins(*PAGE_MARGINS)
    layout.setSpacing(spacing)
    scroll.setWidget(content)
    outer.addWidget(scroll)
    return layout


def page_header(title: str, subtitle: str, fa_subtitle: str | None = None,  # noqa: ARG001
                actions: list[QWidget] | None = None) -> QWidget:
    """Page heading: H1 + muted subtitle + trailing actions.

    ``fa_subtitle`` is accepted for compatibility and ignored: Persian text now
    comes from the EN/FA language switch (ui/i18n.py) instead of a second line.
    """
    block = QWidget()
    outer = QHBoxLayout(block)
    outer.setContentsMargins(0, 0, 0, 0)
    outer.setSpacing(16)
    texts = QVBoxLayout()
    texts.setSpacing(3)
    h1 = QLabel(tr(title))
    h1.setProperty("class", "h1")
    texts.addWidget(h1)
    sub = QLabel(tr(subtitle))
    sub.setProperty("class", "muted")
    sub.setWordWrap(True)
    texts.addWidget(sub)
    outer.addLayout(texts, 1)
    for widget in actions or []:
        outer.addWidget(widget, 0, Qt.AlignBottom)
    return block


def make_card(margin: int = 0, spacing: int = 14,
              padding: tuple[int, int, int, int] = (20, 18, 20, 18)
              ) -> tuple[QFrame, QVBoxLayout]:
    """A themed card frame with a ready content layout."""
    card = QFrame()
    card.setProperty("class", "card")
    layout = QVBoxLayout(card)
    layout.setContentsMargins(*padding)
    layout.setSpacing(spacing)
    if margin:
        card.setContentsMargins(margin, margin, margin, margin)
    return card, layout


def icon_badge(name: str, tone: str = "accent", size: int = 36,
               icon_size: int = 18) -> QLabel:
    """Rounded tinted square holding a vector icon."""
    holder = QLabel()
    holder.setProperty("iconBadge", tone)
    holder.setFixedSize(size, size)
    holder.setAlignment(Qt.AlignCenter)
    from ..theme import on_theme
    from ..theme.icons import pixmap

    role = _TONE_ROLE.get(tone, "accent_text")
    on_theme(holder, lambda w, p: w.setPixmap(pixmap(name, p.color(role), icon_size)))
    return holder


def card_header(icon: str | None, title: str, subtitle: str | None = None,
                trailing: QWidget | list[QWidget] | None = None,
                tone: str = "accent") -> QWidget:
    """Card title row: icon badge + title/subtitle + trailing widgets."""
    block = QWidget()
    row = QHBoxLayout(block)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(12)
    if icon:
        row.addWidget(icon_badge(icon, tone, 34, 17), 0, Qt.AlignTop)
    texts = QVBoxLayout()
    texts.setSpacing(1)
    head = QLabel(tr(title))
    head.setProperty("class", "h2")
    texts.addWidget(head)
    if subtitle:
        sub = QLabel(tr(subtitle))
        sub.setProperty("class", "subtle")
        sub.setWordWrap(True)
        sub.setAlignment(Qt.AlignLeading | Qt.AlignVCenter)
        texts.addWidget(sub)
    row.addLayout(texts, 1)
    if trailing is not None:
        for widget in trailing if isinstance(trailing, list) else [trailing]:
            row.addWidget(widget, 0, Qt.AlignVCenter)
    return block


def badge(text: str, kind: str = "neutral") -> QLabel:
    """Pill-shaped status badge (success/warning/danger/info/accent/neutral)."""
    label = QLabel(tr(text))
    label.setProperty("badge", kind)
    label.setAlignment(Qt.AlignCenter)
    return label


def set_badge(label: QLabel, text: str, kind: str) -> None:
    """Change a badge's text + tone (re-polishes so the QSS tone applies)."""
    label.setText(tr(text))
    label.setProperty("badge", kind)
    repolish(label)


def repolish(widget: QWidget) -> None:
    """Re-evaluate the QSS after a dynamic property changed."""
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


def field_label(text: str) -> QLabel:
    label = QLabel(tr(text))
    label.setProperty("class", "fieldLabel")
    return label


def field(label: str, widget: QWidget | QHBoxLayout, hint: QLabel | str | None = None,
          spacing: int = 6) -> QWidget:
    """Label above a control (+ optional hint below)."""
    block = QWidget()
    layout = QVBoxLayout(block)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(spacing)
    layout.addWidget(field_label(label))
    if isinstance(widget, QWidget):
        layout.addWidget(widget)
    else:
        layout.addLayout(widget)
    if hint is not None:
        if isinstance(hint, str):
            hint = QLabel(tr(hint))
            hint.setProperty("class", "subtle")
            hint.setWordWrap(True)
        layout.addWidget(hint)
    return block


def button(text: str, variant: str | None = None, icon: str | None = None,
           tooltip: str | None = None, slot: Callable | None = None,
           icon_role: str | None = None) -> QPushButton:
    """Push button in a theme variant (None = primary, 'secondary', 'ghost',
    'danger', 'iconOnly') with an optional live-tinted vector icon."""
    # Qt has no icon-to-text gap property: a thin space gives it air.
    btn = QPushButton((" " + tr(text)) if icon and text else tr(text))
    if variant:
        btn.setProperty("class", variant)
    if icon:
        role = icon_role or {
            None: "on_accent", "secondary": "text_muted", "flat": "text_muted",
            "ghost": "accent_text", "danger": "danger", "iconOnly": "text_muted",
        }.get(variant, "text_muted")
        bind_icon(btn, icon, role, 16)
    if tooltip:
        btn.setToolTip(tr(tooltip))
    if slot is not None:
        btn.clicked.connect(slot)
    btn.setCursor(Qt.PointingHandCursor)
    return btn


def divider() -> QFrame:
    line = QFrame()
    line.setProperty("class", "divider")
    return line


def kv_grid(keys: list[tuple[str, str]], columns: int = 2) -> tuple[QWidget, dict[str, QLabel]]:
    """Key/value grid; returns (widget, {key_id: value_label})."""
    block = QWidget()
    grid = QGridLayout(block)
    grid.setContentsMargins(0, 0, 0, 0)
    grid.setHorizontalSpacing(20)
    grid.setVerticalSpacing(10)
    values: dict[str, QLabel] = {}
    for index, (key_id, caption) in enumerate(keys):
        cell = QVBoxLayout()
        cell.setSpacing(2)
        key_label = QLabel(tr(caption))
        key_label.setProperty("class", "kvKey")
        value = QLabel("—")
        value.setProperty("class", "kvValue")
        value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        value.setWordWrap(True)
        cell.addWidget(key_label)
        cell.addWidget(value)
        grid.addLayout(cell, index // columns, index % columns)
        values[key_id] = value
    for column in range(columns):
        grid.setColumnStretch(column, 1)
    return block, values


def icon_label(name: str, role: str = "text_subtle", size: int = 14) -> QLabel:
    """A bare live-tinted icon (QLabel)."""
    return bind_pixmap(QLabel(), name, role, size)


def row(widgets: list[QWidget], spacing: int = 10) -> QHBoxLayout:
    """Horizontal row helper for forms."""
    layout = QHBoxLayout()
    layout.setSpacing(spacing)
    for w in widgets:
        layout.addWidget(w)
    return layout


__all__ = ["PAGE_MARGINS", "Page", "badge", "button", "card_header", "divider",
           "field", "field_label", "icon_badge", "icon_label", "kv_grid",
           "make_card", "page_header", "page_layout", "repolish", "row",
           "scroll_layout", "set_badge"]
