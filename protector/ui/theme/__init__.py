"""
protector.ui.theme — theme engine package (see theme.py, icons.py).
"""

from __future__ import annotations

from .theme import (
    ACCENT_PRESETS,
    DEFAULT_ACCENT,
    MONO_FONT_STACK,
    Palette,
    ThemeManager,
    UI_FONT_STACK_LTR,
    UI_FONT_STACK_RTL,
    bind_icon,
    bind_pixmap,
    build_qss,
    current_palette,
    fa,
    load_fonts,
    make_mono_font,
    make_palette,
    on_theme,
)

__all__ = [
    "ACCENT_PRESETS", "DEFAULT_ACCENT", "MONO_FONT_STACK", "Palette",
    "ThemeManager", "UI_FONT_STACK_LTR", "UI_FONT_STACK_RTL", "bind_icon",
    "bind_pixmap", "build_qss", "current_palette", "fa", "load_fonts",
    "make_mono_font", "make_palette", "on_theme",
]
