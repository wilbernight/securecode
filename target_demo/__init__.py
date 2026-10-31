"""
target_demo — SecureNotepad: the protected demo application.

Demonstrates the full offline licensing client SDK (see protection/) wrapped
around a small PySide6 notepad. Run from the repository root:

    python -m target_demo.main           (dev mode: set SC_DEV=1 to disable
                                          anti-debug while developing)
    build.bat                            (Nuitka onefile protected EXE)
"""

from __future__ import annotations

__version__ = "1.0.0"
