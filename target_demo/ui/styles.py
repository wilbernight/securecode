"""
target_demo.ui.styles — Small shared QSS for the demo app (kept minimal by
design: the demo is about the licensing wrapper, not the toolkit's visual
framework — that lives in protector/ui/theme).
"""

from __future__ import annotations

DEMO_QSS = """
* { font-family: 'Segoe UI Variable Text', 'Segoe UI', sans-serif; }
QMainWindow, QDialog { background: #14171F; }
QLabel { color: #E6E9EF; }
QTextEdit, QLineEdit {
    background: #1B202B; color: #E6E9EF; border: 1px solid #2A3140;
    border-radius: 6px; padding: 8px; selection-background-color: #3B82F6;
}
QPushButton {
    background: #3B82F6; color: white; border: none; border-radius: 6px;
    padding: 9px 18px; font-weight: 600;
}
QPushButton:hover { background: #4C8DF8; }
QPushButton:pressed { background: #2E6FD9; }
QPushButton:disabled { background: #2A3140; color: #7A8499; }
QPushButton[flatButton=\"true\"] {
    background: transparent; color: #9AA3B5; border: 1px solid #2A3140;
    font-weight: 500;
}
QPushButton[flatButton=\"true\"]:hover { color: #E6E9EF; border-color: #3B82F6; }
QStatusBar { background: #10131A; color: #8B93A7; }
QToolTip { background: #1F2530; color: #E6E9EF; border: 1px solid #3B4356; }
"""
