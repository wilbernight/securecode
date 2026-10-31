"""
protector.ui — PySide6 user interface of the protector (commercial-grade).

Layout of the package:
    theme/      — palettes + programmatic QSS (ThemeManager)
    widgets/    — frameless title bar, toasts, spinner overlay, workers,
                  bar chart, sidebar
    pages/      — one module per sidebar section
    services.py — dependency container passed to pages
    unlock_dialog.py / main_window.py
"""

from __future__ import annotations
