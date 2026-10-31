"""
protector.ui.theme — Theme engine: palettes + programmatic QSS builder.

The stylesheet is composed in code (not a static .qss resource) so the
accent color and dark/light mode can switch LIVE at runtime — a static
resource file cannot fulfill that requirement. The generated stylesheet is
written to protector/assets/theme_snapshot.qss on every apply() so the
current theme is also inspectable as a resource file.

Design language (v3 — "SecureCode console"):
A calm, neutral console: soft gray canvas, white (light) / deep slate (dark)
surfaces with 12px radii and hairline borders, one accent color used
sparingly (primary actions, the selected navigation item, focus rings),
semantic status colors with tinted "soft" backgrounds for badges, and a
vector line-icon set (theme/icons.py) that re-tints on every switch.
Typography: Segoe UI Variable for Latin, the bundled Vazirmatn (SIL OFL)
for Persian — widgets marked class="fa" (or via fa()) render in Vazirmatn.

Live re-skinning of things QSS cannot reach (icon pixmaps, QPainter
widgets, per-widget color swatches) goes through ``on_theme()``: a callback
registry fired after every apply().
"""

from __future__ import annotations

import logging
import weakref
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Callable

import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QAbstractButton, QApplication, QLabel, QWidget

from . import icons as _icons

log = logging.getLogger("protector.theme")

_ASSETS = Path(__file__).resolve().parents[2] / "assets"
_FONTS = _ASSETS / "fonts"

# --- typography stacks (platform-appropriate; Vazirmatn ships bundled) ---------
# Qt picks the FIRST installed family from the stack, so listing the macOS
# equivalents (Helvetica Neue / Menlo) keeps the console native on both
# supported platforms. Vazirmatn covers Persian everywhere (load_fonts).
_IS_MAC = sys.platform == "darwin"

#: Latin UI stack used when the interface language is LTR (English).
UI_FONT_STACK_LTR: str = ("'Helvetica Neue', 'Vazirmatn'" if _IS_MAC
                          else "'Segoe UI Variable Text', 'Segoe UI', 'Vazirmatn'")
#: Persian-first stack used when the interface language is RTL (Farsi).
UI_FONT_STACK_RTL: str = ("'Vazirmatn', 'Helvetica Neue'" if _IS_MAC
                          else "'Vazirmatn', 'Segoe UI Variable Text', 'Segoe UI'")
#: Mono stack for serials / machine codes / code inputs.
MONO_FONT_STACK: str = ("'Menlo', 'Cascadia Mono', monospace" if _IS_MAC
                        else "'Cascadia Mono', 'Consolas', monospace")


def make_mono_font(point_size: float = 9.0) -> QFont:
    """Platform-appropriate monospace QFont (Menlo on macOS, Cascadia Mono
    on Windows; Consolas as a final fallback everywhere)."""
    font = QFont()
    font.setFamilies(["Menlo", "Cascadia Mono", "Consolas"] if _IS_MAC
                     else ["Cascadia Mono", "Consolas", "Menlo"])
    font.setStyleHint(QFont.Monospace)
    font.setPointSizeF(point_size)
    return font

#: Curated accent presets offered in Settings (default first).
ACCENT_PRESETS: list[tuple[str, str]] = [
    ("Azure", "#2563EB"),
    ("Indigo", "#4F46E5"),
    ("Violet", "#7C3AED"),
    ("Teal", "#0D9488"),
    ("Emerald", "#059669"),
    ("Amber", "#D97706"),
    ("Rose", "#E11D48"),
    ("Classic", "#0069B4"),
]

DEFAULT_ACCENT = ACCENT_PRESETS[0][1]

_fonts_loaded = False


def load_fonts() -> None:
    """Register the bundled Vazirmatn family (SIL OFL) with Qt.

    Idempotent; called by ThemeManager.apply() so Persian text (class="fa")
    renders in Vazirmatn everywhere, including frozen Nuitka builds where
    system fonts cannot be assumed.
    """
    global _fonts_loaded
    if _fonts_loaded:
        return
    if _FONTS.is_dir():
        for ttf in sorted(_FONTS.glob("Vazirmatn-*.ttf")):
            result = QFontDatabase.addApplicationFont(str(ttf))
            if result < 0:
                log.warning("failed to load font %s", ttf.name)
    else:  # pragma: no cover - dev tree anomaly
        log.warning("fonts directory missing: %s", _FONTS)
    _fonts_loaded = True


def fa(widget: QLabel, text: str) -> QLabel:
    """Mark a label as Persian (Vazirmatn) and set its text."""
    widget.setProperty("class", "fa")
    widget.setText(text)
    return widget


# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Palette:
    """Semantic color tokens consumed by the QSS builder and painters."""

    mode: str
    bg: str
    surface: str
    surface_alt: str
    surface_hover: str
    input_bg: str
    border: str
    border_strong: str
    text: str
    text_muted: str
    text_subtle: str
    text_disabled: str
    accent: str
    accent_hover: str
    accent_pressed: str
    accent_soft: str
    accent_text: str
    on_accent: str
    success: str
    success_soft: str
    warning: str
    warning_soft: str
    danger: str
    danger_soft: str
    danger_hover: str
    info: str
    info_soft: str
    neutral_soft: str
    selection_bg: str
    scrollbar: str
    scrollbar_hover: str
    tooltip_bg: str
    tooltip_text: str
    chrome: str
    console_bg: str
    console_text: str
    overlay: str

    def color(self, role: str) -> str:
        """Resolve a token name (or pass a literal #hex through)."""
        if role.startswith("#"):
            return role
        return getattr(self, role)


#: Light mode — the default.
LIGHT_TOKENS: dict[str, str] = dict(
    bg="#F3F5F9", surface="#FFFFFF", surface_alt="#F8FAFC",
    surface_hover="#F1F4F9", input_bg="#FFFFFF",
    border="#E3E8EF", border_strong="#CDD5E0",
    text="#0F172A", text_muted="#55657C", text_subtle="#8593A8",
    text_disabled="#B3BECC",
    success="#15803D", warning="#B45309", danger="#DC2626",
    danger_hover="#B91C1C", info="#2563EB",
    scrollbar="#CBD3DE", scrollbar_hover="#A9B5C5",
    tooltip_bg="#0F172A", tooltip_text="#F8FAFC",
    chrome="#FFFFFF", console_bg="#0F172A", console_text="#CBD5E1",
    overlay="rgba(243, 245, 249, 200)",
)

#: Dark mode — deep slate surfaces, never pure black.
DARK_TOKENS: dict[str, str] = dict(
    bg="#0A0E15", surface="#111722", surface_alt="#151C29",
    surface_hover="#1A2231", input_bg="#0D121B",
    border="#1F2836", border_strong="#2C3749",
    text="#E6EAF2", text_muted="#9AA6BA", text_subtle="#6C788E",
    text_disabled="#465165",
    success="#34D399", warning="#FBBF24", danger="#F87171",
    danger_hover="#FCA5A5", info="#60A5FA",
    scrollbar="#2C3749", scrollbar_hover="#3B485E",
    tooltip_bg="#E6EAF2", tooltip_text="#0F172A",
    chrome="#0D121B", console_bg="#070A10", console_text="#C9D3E3",
    overlay="rgba(10, 14, 21, 190)",
)


def _mix(hex_color: str, factor: float, towards: str = "#FFFFFF") -> str:
    """Blend ``hex_color`` towards ``towards`` by ``factor`` (0..1)."""
    base = QColor(hex_color)
    target = QColor(towards)
    r = int(base.red() + (target.red() - base.red()) * factor)
    g = int(base.green() + (target.green() - base.green()) * factor)
    b = int(base.blue() + (target.blue() - base.blue()) * factor)
    return f"#{r:02X}{g:02X}{b:02X}"


def make_palette(mode: str = "light", accent: str = DEFAULT_ACCENT) -> Palette:
    """Compose a Palette for a mode ('light'/'dark') + accent color."""
    dark = mode == "dark"
    tokens = dict(DARK_TOKENS if dark else LIGHT_TOKENS)
    surface = tokens["surface"]
    # "Soft" tints are opaque blends over the surface: identical look on
    # cards, no alpha-compositing surprises in QSS or QPainter.
    soft = 0.84 if dark else 0.90
    return Palette(
        mode="dark" if dark else "light",
        accent=accent,
        accent_hover=_mix(accent, 0.14, "#FFFFFF" if dark else "#000000"),
        accent_pressed=_mix(accent, 0.24, "#000000"),
        accent_soft=_mix(accent, soft, surface),
        accent_text=_mix(accent, 0.38, "#FFFFFF") if dark else _mix(accent, 0.08, "#000000"),
        on_accent="#FFFFFF",
        success_soft=_mix(tokens["success"], soft, surface),
        warning_soft=_mix(tokens["warning"], soft, surface),
        danger_soft=_mix(tokens["danger"], soft, surface),
        info_soft=_mix(tokens["info"], soft, surface),
        neutral_soft=tokens["surface_hover"] if not dark else "#1C2433",
        selection_bg=_mix(accent, 0.78 if dark else 0.86, surface),
        **tokens,
    )


# ---------------------------------------------------------------------------
# Live re-skin registry
# ---------------------------------------------------------------------------
_current: Palette = make_palette()
_bindings: list[tuple[weakref.ref, Callable[[QWidget, Palette], None]]] = []


def current_palette() -> Palette:
    """The palette of the last apply() (light default before the first)."""
    return _current


def on_theme(widget: QWidget, callback: Callable[[QWidget, Palette], None]) -> None:
    """Run ``callback(widget, palette)`` now and after every theme change.

    The widget is held weakly; bindings of destroyed widgets are dropped.
    The callback must not capture ``widget`` itself (it receives it).
    """
    callback(widget, _current)
    _bindings.append((weakref.ref(widget), callback))


def _fire(palette: Palette) -> None:
    alive = []
    for ref, callback in _bindings:
        widget = ref()
        if widget is None:
            continue
        try:
            callback(widget, palette)
        except RuntimeError:  # C++ object already deleted
            continue
        alive.append((ref, callback))
    _bindings[:] = alive


def bind_icon(button: QAbstractButton, name: str, role: str = "text_muted",
              size: int = 16, checked_role: str | None = None) -> QAbstractButton:
    """Give a button a theme-tinted vector icon (re-tints live)."""
    from PySide6.QtCore import QSize

    button.setIconSize(QSize(size, size))

    def _apply(widget: QAbstractButton, p: Palette) -> None:
        widget.setIcon(_icons.icon(
            name, p.color(role), size,
            checked_color=p.color(checked_role) if checked_role else None,
            disabled_color=p.text_disabled))

    on_theme(button, _apply)
    return button


def bind_pixmap(label: QLabel, name: str, role: str = "text_muted",
                size: int = 16) -> QLabel:
    """Put a theme-tinted vector icon into a QLabel (re-tints live)."""
    label.setFixedSize(size, size)

    def _apply(widget: QLabel, p: Palette) -> None:
        widget.setPixmap(_icons.pixmap(name, p.color(role), size))

    on_theme(label, _apply)
    return label


# ---------------------------------------------------------------------------
# QSS builder
# ---------------------------------------------------------------------------
def build_qss(p: Palette) -> str:
    """Render the full application stylesheet for a palette."""
    check_img = _icons.svg_file("check", p.on_accent, 3.0)
    chevron = _icons.svg_file("chevron-down", p.text_muted, 2.2)
    chevron_up = _icons.svg_file("chevron-up", p.text_muted, 2.2)
    chevron_off = _icons.svg_file("chevron-down", p.text_disabled, 2.2)
    badge_rules = "\n".join(
        f'QLabel[badge="{kind}"] {{ background: {bg}; color: {fg}; }}'
        for kind, bg, fg in (
            ("success", p.success_soft, p.success),
            ("warning", p.warning_soft, p.warning),
            ("danger", p.danger_soft, p.danger),
            ("info", p.info_soft, p.info),
            ("accent", p.accent_soft, p.accent_text),
            ("neutral", p.neutral_soft, p.text_muted),
        ))
    icon_badge_rules = "\n".join(
        f'QLabel[iconBadge="{kind}"] {{ background: {bg}; border-radius: 10px; }}'
        for kind, bg in (
            ("success", p.success_soft), ("warning", p.warning_soft),
            ("danger", p.danger_soft), ("info", p.info_soft),
            ("accent", p.accent_soft), ("neutral", p.neutral_soft),
        ))
    from .. import i18n

    rtl = i18n.is_rtl()
    fonts = UI_FONT_STACK_RTL if rtl else UI_FONT_STACK_LTR
    mono = MONO_FONT_STACK
    start = "right" if rtl else "left"
    end = "left" if rtl else "right"
    # Persian is cursive: letter-spacing would break the joins between
    # letters, and Vazirmatn reads best ~1px larger than Segoe UI.
    tracking = "" if rtl else "letter-spacing: 1.4px;"
    base = 14 if rtl else 13
    return f"""
* {{
    font-family: {fonts}, sans-serif;
    font-size: {base}px;
    outline: none;
}}
QMainWindow, QWidget#shell, QWidget#shellBody {{ background: {p.bg}; }}
QWidget#pageRoot {{ background: {p.bg}; }}
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget#scrollContent {{ background: transparent; }}
QWidget#scrollContent {{ background: transparent; }}

/* ---------- typography ---------- */
QLabel {{ color: {p.text}; background: transparent; }}
QLabel[class="fa"], QWidget[class="fa"] {{
    font-family: 'Vazirmatn', 'Segoe UI', sans-serif;
}}
QLabel[class="faMuted"] {{
    font-family: 'Vazirmatn', 'Segoe UI', sans-serif;
    color: {p.text_muted}; font-size: 12px;
}}
QLabel[class="muted"] {{ color: {p.text_muted}; }}
QLabel[class="subtle"] {{ color: {p.text_subtle}; font-size: 12px; }}
QLabel[class="h1"] {{ font-size: 22px; font-weight: 700; color: {p.text}; }}
QLabel[class="h2"] {{ font-size: 15px; font-weight: 600; color: {p.text}; }}
QLabel[class="h3"] {{ font-size: 13px; font-weight: 600; color: {p.text}; }}
QLabel[class="overline"] {{
    font-size: 10px; font-weight: 700; {tracking}
    color: {p.text_subtle};
}}
QLabel[class="fieldLabel"] {{ font-size: 12px; font-weight: 600; color: {p.text_muted}; }}
QLabel[class="statValue"] {{ font-size: 26px; font-weight: 700; color: {p.text}; }}
QLabel[class="mono"], QLabel[class="monoMuted"] {{
    font-family: {mono}; font-size: 12px;
}}
QLabel[class="monoMuted"] {{ color: {p.text_muted}; }}
QLabel[class="accent"] {{ color: {p.accent_text}; font-weight: 600; }}
QLabel[class="kvKey"] {{ color: {p.text_subtle}; font-size: 12px; }}
QLabel[class="kvValue"] {{ color: {p.text}; font-weight: 600; }}
QLabel[tone="success"] {{ color: {p.success}; }}
QLabel[tone="danger"] {{ color: {p.danger}; }}
QLabel[tone="warning"] {{ color: {p.warning}; }}

/* ---------- badges / icon badges ---------- */
QLabel[badge] {{
    border-radius: 9px; padding: 2px 9px; font-size: 11px; font-weight: 600;
}}
{badge_rules}
{icon_badge_rules}
QLabel#avatar {{
    border-radius: 17px; font-weight: 700; font-size: 12px;
}}

/* ---------- cards ---------- */
QFrame[class="card"] {{
    background: {p.surface}; border: 1px solid {p.border}; border-radius: 12px;
}}
QFrame[class="cardInset"] {{
    background: {p.surface_alt}; border: 1px solid {p.border}; border-radius: 10px;
}}
QFrame[class="note"] {{
    background: {p.info_soft}; border: none; border-radius: 10px;
}}
QFrame[class="divider"] {{ background: {p.border}; border: none;
                            min-height: 1px; max-height: 1px; }}
QFrame[class="listRow"] {{ background: transparent; border: none;
                            border-bottom: 1px solid {p.border}; }}
QFrame[class="listRow"]:hover {{ background: {p.surface_hover}; }}
QFrame#actionBar {{
    background: {p.surface}; border: 1px solid {p.border}; border-radius: 12px;
}}

/* ---------- inputs ---------- */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDateEdit, QComboBox {{
    background: {p.input_bg}; color: {p.text};
    border: 1px solid {p.border_strong}; border-radius: 8px;
    padding: 7px 11px; min-height: {20 if not rtl else 22}px;
    selection-background-color: {p.selection_bg}; selection-color: {p.text};
}}
QTextEdit, QPlainTextEdit {{ padding: 8px 10px; }}
QLineEdit:hover, QTextEdit:hover, QPlainTextEdit:hover, QSpinBox:hover,
QComboBox:hover {{ border-color: {p.text_subtle}; }}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus,
QDateEdit:focus, QComboBox:focus {{ border: 1px solid {p.accent}; }}
QLineEdit[invalid="true"] {{ border: 1px solid {p.danger}; }}
QLineEdit[valid="true"] {{ border: 1px solid {p.success}; }}
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {{
    color: {p.text_disabled}; background: {p.surface_alt};
}}
QLineEdit[readOnly="true"] {{ background: {p.surface_alt}; }}
QLineEdit#fingerprintEdit {{
    font-family: {mono}; font-size: 14px;
    letter-spacing: 2px;
}}
QComboBox {{ padding-{end}: 30px; padding-{start}: 11px; }}
QComboBox::drop-down {{
    subcontrol-origin: padding; subcontrol-position: center right;
    border: none; width: 28px;
}}
QComboBox::down-arrow {{ image: url("{chevron}"); width: 12px; height: 12px; }}
QComboBox::down-arrow:disabled {{ image: url("{chevron_off}"); }}
QComboBox QAbstractItemView {{
    background: {p.surface}; color: {p.text}; border: 1px solid {p.border_strong};
    border-radius: 8px; padding: 4px; outline: none;
    selection-background-color: {p.accent_soft}; selection-color: {p.text};
}}
QComboBox QAbstractItemView::item {{ min-height: 28px; padding: 0 8px; border-radius: 6px; }}
QSpinBox {{ padding-{end}: 24px; padding-{start}: 11px; }}
QSpinBox::up-button, QSpinBox::down-button {{
    subcontrol-origin: border; width: 22px; border: none;
    background: transparent;
}}
QSpinBox::up-button {{ subcontrol-position: top right; margin: 3px 3px 0 0; }}
QSpinBox::down-button {{ subcontrol-position: bottom right; margin: 0 3px 3px 0; }}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
    background: {p.surface_hover}; border-radius: 4px;
}}
QSpinBox::up-arrow {{ image: url("{chevron_up}"); width: 10px; height: 10px; }}
QSpinBox::down-arrow {{ image: url("{chevron}"); width: 10px; height: 10px; }}

/* ---------- buttons ---------- */
QPushButton {{
    background: {p.accent}; color: {p.on_accent}; border: 1px solid {p.accent};
    border-radius: 8px; padding: 7px 16px; font-weight: 600; min-height: 20px;
}}
QPushButton:hover {{ background: {p.accent_hover}; border-color: {p.accent_hover}; }}
QPushButton:pressed {{ background: {p.accent_pressed}; border-color: {p.accent_pressed}; }}
QPushButton:disabled {{
    background: {p.surface_hover}; border-color: {p.border}; color: {p.text_disabled};
}}
QPushButton[class="flat"], QPushButton[class="secondary"] {{
    background: {p.surface}; color: {p.text}; border: 1px solid {p.border_strong};
}}
QPushButton[class="flat"]:hover, QPushButton[class="secondary"]:hover {{
    background: {p.surface_hover}; border-color: {p.text_subtle};
}}
QPushButton[class="flat"]:pressed, QPushButton[class="secondary"]:pressed {{
    background: {p.border};
}}
QPushButton[class="flat"]:disabled, QPushButton[class="secondary"]:disabled {{
    color: {p.text_disabled}; background: {p.surface}; border-color: {p.border};
}}
QPushButton[class="danger"] {{
    background: {p.surface}; color: {p.danger}; border: 1px solid {p.border_strong};
}}
QPushButton[class="danger"]:hover {{
    background: {p.danger}; color: #FFFFFF; border-color: {p.danger};
}}
QPushButton[class="ghost"] {{
    background: transparent; color: {p.accent_text}; border: 1px solid transparent;
    padding: 6px 10px;
}}
QPushButton[class="ghost"]:hover {{ background: {p.accent_soft}; }}
QPushButton[class="ghost"]:disabled {{ color: {p.text_disabled}; background: transparent; }}
QPushButton[class="iconOnly"] {{
    background: {p.surface}; border: 1px solid {p.border_strong};
    border-radius: 8px; padding: 0; min-width: 34px; max-width: 34px;
    min-height: 34px; max-height: 34px;
}}
QPushButton[class="iconOnly"]:hover {{ background: {p.surface_hover}; }}
QPushButton[size="lg"] {{ padding: 10px 22px; font-size: 14px; border-radius: 10px; }}

/* segmented control (button group) */
QPushButton[segment="true"] {{
    background: transparent; color: {p.text_muted}; border: 1px solid transparent;
    border-radius: 7px; padding: 5px 12px; font-weight: 600;
}}
QPushButton[segment="true"]:hover {{ color: {p.text}; }}
QPushButton[segment="true"]:checked {{
    background: {p.surface}; color: {p.text}; border: 1px solid {p.border_strong};
}}
QFrame#segmented {{
    background: {p.surface_hover}; border: 1px solid {p.border}; border-radius: 9px;
}}

/* theme preview tiles (settings) */
QPushButton[themeTile="true"] {{
    background: {p.surface}; color: {p.text}; border: 1px solid {p.border_strong};
    border-radius: 12px; padding: 0; text-align: left;  /* Qt mirrors this in RTL */
    min-height: 104px; max-height: 104px;
}}
QPushButton[themeTile="true"]:hover {{ border-color: {p.text_subtle}; }}
QPushButton[themeTile="true"]:checked {{ border: 2px solid {p.accent}; }}

/* ---------- checkbox / radio ---------- */
QCheckBox, QRadioButton {{ color: {p.text}; spacing: 8px; background: transparent; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 16px; height: 16px; border: 1px solid {p.border_strong};
    border-radius: 5px; background: {p.input_bg};
}}
QRadioButton::indicator {{ border-radius: 9px; }}
QCheckBox::indicator:hover, QRadioButton::indicator:hover {{ border-color: {p.accent}; }}
QCheckBox::indicator:checked {{
    background: {p.accent}; border-color: {p.accent}; image: url("{check_img}");
}}
QRadioButton::indicator:checked {{ background: {p.accent}; border: 4px solid {p.input_bg}; }}

/* ---------- tables ---------- */
QTableWidget, QTableView {{
    background: {p.surface}; color: {p.text}; border: none;
    gridline-color: {p.border}; alternate-background-color: {p.surface_alt};
    selection-background-color: {p.accent_soft}; selection-color: {p.text};
}}
QTableWidget::item, QTableView::item {{
    padding: 0 10px; border: none; border-bottom: 1px solid {p.border};
}}
QTableWidget::item:selected, QTableView::item:selected {{
    background: {p.accent_soft}; color: {p.text};
}}
QTableWidget::item:hover, QTableView::item:hover {{ background: {p.surface_hover}; }}
QHeaderView {{ background: {p.surface_alt}; border: none; }}
QHeaderView::section {{
    background: {p.surface_alt}; color: {p.text_subtle};
    border: none; border-bottom: 1px solid {p.border};
    padding: 9px 10px; font-weight: 600; font-size: 11px;
}}
QTableCornerButton::section {{ background: {p.surface_alt}; border: none; }}
QFrame#tableFrame {{
    background: {p.surface}; border: 1px solid {p.border}; border-radius: 10px;
}}

/* ---------- navigation rail ---------- */
QWidget#navRail {{ background: {p.chrome}; border-{end}: 1px solid {p.border}; }}
QPushButton[navButton="true"] {{
    background: transparent; border: none; border-radius: 8px;
    color: {p.text_muted}; padding: 9px 12px; font-size: 13px;
    font-weight: 600; text-align: left;  /* Qt mirrors this in RTL */
}}
QPushButton[navButton="true"]:hover {{ background: {p.surface_hover}; color: {p.text}; }}
QPushButton[navButton="true"]:checked {{
    background: {p.accent_soft}; color: {p.accent_text};
}}
QLabel[class="navGroup"] {{
    color: {p.text_subtle}; font-size: {10 + (2 if rtl else 0)}px; font-weight: 700;
    {tracking} padding: 14px 12px 4px 12px;
}}
QLabel#navBrand {{ color: {p.text}; font-size: 15px; font-weight: 700; }}
QLabel#navBrandSub {{ color: {p.text_subtle}; font-size: 11px; }}
QLabel#logoMark {{ background: {p.accent}; border-radius: 10px; }}
QFrame#navFooter {{
    background: {p.surface_alt}; border: 1px solid {p.border}; border-radius: 10px;
}}

/* ---------- title bar ---------- */
QWidget#titleBar {{ background: {p.chrome}; border-bottom: 1px solid {p.border}; }}
QLabel#titleApp {{ color: {p.text_muted}; font-weight: 600; }}
QLabel#titlePage {{ color: {p.text}; font-weight: 600; }}
QLabel#keyChip {{
    background: {p.surface_alt}; border: 1px solid {p.border}; border-radius: 13px;
    color: {p.text_muted}; padding: 3px 12px 3px 10px;
    font-family: {mono}; font-size: 11px;
}}
QPushButton#btnMin, QPushButton#btnMax, QPushButton#themeToggle, QPushButton#btnClose {{
    background: transparent; border: none; border-radius: 7px; padding: 0;
    min-width: 36px; max-width: 36px; min-height: 30px; max-height: 30px;
}}
QPushButton#btnMin:hover, QPushButton#btnMax:hover, QPushButton#themeToggle:hover {{
    background: {p.surface_hover};
}}
QPushButton#btnClose:hover {{ background: #E5484D; }}
QPushButton#langToggle {{
    background: {p.surface_alt}; color: {p.text_muted}; border: 1px solid {p.border};
    border-radius: 7px; padding: 0 9px; min-height: 26px; max-height: 26px;
    font-size: 11px; font-weight: 700; font-family: {fonts}, sans-serif;
}}
QPushButton#langToggle:hover {{ color: {p.accent_text}; border-color: {p.accent}; }}
QPushButton#btnClose:pressed {{ background: #C93A3F; }}

/* ---------- status bar ---------- */
QStatusBar {{ background: {p.chrome}; color: {p.text_subtle}; border-top: 1px solid {p.border};
              min-height: 28px; }}
QStatusBar::item {{ border: none; }}
QStatusBar QLabel {{ color: {p.text_subtle}; font-size: 11px; }}
QLabel#onlineDot {{ color: {p.success}; font-size: 11px; font-weight: 600; }}

/* ---------- Jalali date edit / calendar ---------- */
QWidget#jalaliDateEdit {{
    background: {p.input_bg}; border: 1px solid {p.border_strong}; border-radius: 8px;
}}
QWidget#jalaliDateEdit:hover {{ border-color: {p.text_subtle}; }}
QWidget#jalaliPopupFrame {{
    background: {p.surface}; border: 1px solid {p.border_strong}; border-radius: 12px;
}}
QWidget#jalaliPopup {{ background: {p.surface}; }}

/* ---------- serial output / console ---------- */
QPlainTextEdit#serialView {{
    background: {p.surface_alt}; border: 1px dashed {p.border_strong};
    border-radius: 10px; padding: 12px;
    font-family: {mono}; font-size: 13px;
}}
QPlainTextEdit#console {{
    background: {p.console_bg}; color: {p.console_text};
    border: none; border-radius: 10px; padding: 14px;
    font-family: {mono}; font-size: 12px;
    selection-background-color: #334155; selection-color: #F8FAFC;
}}
QPlainTextEdit#codeInput {{
    font-family: {mono}; font-size: 14px;
}}

/* ---------- scrollbars ---------- */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{
    background: {p.scrollbar}; border-radius: 3px; min-height: 32px; margin: 0 2px;
}}
QScrollBar::handle:vertical:hover {{ background: {p.scrollbar_hover}; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{
    background: {p.scrollbar}; border-radius: 3px; min-width: 32px; margin: 2px 0;
}}
QScrollBar::handle:horizontal:hover {{ background: {p.scrollbar_hover}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* ---------- tooltips / menus / dialogs ---------- */
QToolTip {{
    background: {p.tooltip_bg}; color: {p.tooltip_text}; border: none;
    border-radius: 6px; padding: 6px 9px; font-size: 12px;
}}
QMenu {{
    background: {p.surface}; color: {p.text};
    border: 1px solid {p.border_strong}; border-radius: 10px; padding: 6px;
}}
QMenu::item {{ padding: 7px 22px; border-radius: 6px; }}
QMenu::item:selected {{ background: {p.accent_soft}; }}
QMenu::separator {{ height: 1px; background: {p.border}; margin: 4px 8px; }}
QDialog, QMessageBox, QInputDialog {{ background: {p.surface}; color: {p.text}; }}
QDialog QLabel {{ color: {p.text}; }}
QDialogButtonBox QPushButton {{ min-width: 84px; }}

/* ---------- progress ---------- */
QProgressBar {{
    background: {p.surface_hover}; border: none; border-radius: 3px;
    max-height: 6px; min-height: 6px; text-align: center; color: transparent;
}}
QProgressBar::chunk {{ background: {p.accent}; border-radius: 3px; }}

/* ---------- toasts / busy overlay ---------- */
QFrame#toast {{
    background: {p.surface}; border: 1px solid {p.border_strong}; border-radius: 12px;
}}
QLabel#toastTitle {{ font-weight: 700; color: {p.text}; }}
QLabel#toastMessage {{ color: {p.text_muted}; font-size: 12px; }}
QWidget#spinnerOverlay {{ background: {p.overlay}; }}
QFrame#spinnerCard {{
    background: {p.surface}; border: 1px solid {p.border}; border-radius: 14px;
}}
QLabel#spinnerText {{ color: {p.text}; font-weight: 600; }}

/* ---------- unlock gate ---------- */
QDialog#gate {{ background: {p.surface}; }}
QWidget#gateHero {{ background: {p.surface_alt}; border-bottom: 1px solid {p.border}; }}
QLabel#gateTitle {{ font-size: 19px; font-weight: 700; color: {p.text}; }}
QLabel#gateError {{ color: {p.danger}; font-size: 12px; }}
QLineEdit#gateInput {{ padding: 10px 12px; font-size: 14px; }}
"""


# ---------------------------------------------------------------------------
# Theme manager
# ---------------------------------------------------------------------------
class ThemeManager:
    """Applies palettes to the running QApplication (light/dark + accent)."""

    def __init__(self, mode: str = "light", accent: str = DEFAULT_ACCENT) -> None:
        self._mode = mode if mode in ("dark", "light") else "light"
        self._accent = accent
        self.palette = make_palette(self._mode, self._accent)
        self._extra_windows: list[QWidget] = []

    # -------------------------------------------------- properties
    @property
    def mode(self) -> str:
        return self._mode

    @property
    def accent(self) -> str:
        return self._accent

    @staticmethod
    def system_mode(app: QApplication) -> str:
        """'dark' when Windows is set to dark apps, else 'light'."""
        try:
            scheme = app.styleHints().colorScheme()
            return "dark" if scheme == Qt.ColorScheme.Dark else "light"
        except AttributeError:  # pragma: no cover - Qt < 6.5
            return "light"

    # -------------------------------------------------- application
    def apply(self, app: QApplication) -> None:
        """Build + install the stylesheet; refresh native palette + icons."""
        global _current
        load_fonts()  # bundled Vazirmatn must exist before Persian renders
        self.palette = make_palette(self._mode, self._accent)
        _current = self.palette
        qss = build_qss(self.palette)
        from .. import i18n

        app.setLayoutDirection(i18n.direction())
        # Smooth (un-hinted) outlines: Windows' grid-fitting distorts
        # Vazirmatn's thin Persian strokes at UI sizes; DirectWrite renders
        # it crisply without hinting. Applies to Latin text as well.
        # (On macOS the stacks swap to Helvetica Neue — see UI_FONT_STACK_*.)
        font = QFont()
        if _IS_MAC:
            families = (["Vazirmatn", "Helvetica Neue"] if i18n.is_rtl()
                        else ["Helvetica Neue", "Vazirmatn"])
        else:
            families = (["Vazirmatn", "Segoe UI"] if i18n.is_rtl()
                        else ["Segoe UI Variable Text", "Segoe UI", "Vazirmatn"])
        font.setFamilies(families)
        font.setPixelSize(14 if i18n.is_rtl() else 13)
        font.setHintingPreference(QFont.PreferNoHinting)
        font.setStyleStrategy(QFont.PreferAntialias)
        app.setFont(font)
        app.setStyleSheet(qss)
        p = self.palette
        pal = QPalette()
        for role, value in (
            (QPalette.Window, p.bg), (QPalette.WindowText, p.text),
            (QPalette.Base, p.input_bg), (QPalette.AlternateBase, p.surface_alt),
            (QPalette.Text, p.text), (QPalette.Button, p.surface),
            (QPalette.ButtonText, p.text), (QPalette.Highlight, p.accent),
            (QPalette.HighlightedText, p.on_accent),
            (QPalette.PlaceholderText, p.text_subtle),
            (QPalette.ToolTipBase, p.tooltip_bg), (QPalette.ToolTipText, p.tooltip_text),
            (QPalette.Link, p.accent_text),
        ):
            pal.setColor(role, QColor(value))
        app.setPalette(pal)
        _fire(self.palette)
        # Persist a snapshot as the resource-file artifact.
        try:
            _ASSETS.mkdir(parents=True, exist_ok=True)
            (_ASSETS / "theme_snapshot.qss").write_text(qss, encoding="utf-8")
        except OSError:
            pass

    def restyle(self, app: QApplication, *, mode: str | None = None,
                accent: str | None = None) -> None:
        """Switch mode/accent and re-apply live."""
        if mode:
            self._mode = mode
        if accent:
            self._accent = accent
        self.apply(app)
        for window in self._extra_windows:
            window.setStyleSheet(build_qss(self.palette))


#: All token names (handy for tests / tooling).
TOKENS: tuple[str, ...] = tuple(f.name for f in fields(Palette))

__all__ = ["ACCENT_PRESETS", "DEFAULT_ACCENT", "Palette", "TOKENS", "ThemeManager",
           "bind_icon", "bind_pixmap", "build_qss", "current_palette", "fa",
           "load_fonts", "make_palette", "on_theme"]
