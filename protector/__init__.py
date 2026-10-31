"""
protector — SecureCode Protector: offline serial generation + EXE protection
toolkit (admin-side desktop application).

Package layout:
    main.py        — entry point (logging, DPI, QApplication bootstrap)
    core/          — crypto, serial factory, DB, settings (no Qt imports)
    ui/            — PySide6 widgets, pages, theme
    tools/         — development-time generators (NOT shipped in any EXE)
    assets/        — icons, generated at build time by tools/make_icon.py

This top-level package intentionally imports nothing: importing `protector`
must be cheap and dependency-free so dev tools can reach core modules
without pulling in Qt.
"""

from __future__ import annotations

__version__ = "1.0.0"
