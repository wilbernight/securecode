"""
protector.ui.widgets.spinner — async busy-indicator overlay.

A translucent canvas-tinted overlay with a centered card (rotating accent
arc + message text), placed over
any widget while a QThread worker runs (crypto + DB operations must never
block the UI thread — spec requirement). Use the ``busy_overlay()`` helper
as a context manager.
"""

from __future__ import annotations

import math
from contextlib import contextmanager
from typing import Iterator

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ..i18n import tr
from ..theme import current_palette


class BusySpinner(QWidget):
    """The rotating-arc spinner itself (pure QPainter, ~60 FPS)."""

    def __init__(self, parent: QWidget | None = None, size: int = 44) -> None:
        super().__init__(parent)
        self._size = size
        self._angle = 0
        self.setFixedSize(size, size)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    def start(self) -> None:
        self._timer.start(16)
        self.show()

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def _tick(self) -> None:
        self._angle = (self._angle + 8) % 360
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        palette = current_palette()
        # background track
        track = QPen(QColor(palette.border), 3.5)
        track.setCapStyle(Qt.RoundCap)
        painter.setPen(track)
        rect = self.rect().adjusted(5, 5, -5, -5)
        painter.drawArc(rect, 0, 360 * 16)
        # moving arc
        arc = QPen(QColor(palette.accent), 3.5)
        arc.setCapStyle(Qt.RoundCap)
        painter.setPen(arc)
        painter.drawArc(rect, -self._angle * 16, 100 * 16)
        painter.end()


class SpinnerOverlay(QWidget):
    """Full-cover overlay with spinner + message over a host widget."""

    def __init__(self, host: QWidget) -> None:
        super().__init__(host)
        # Plain child widget (NO Qt.SubWindow/window flags: those turn the
        # overlay into a NATIVE window, and native-window show/hide from a
        # foreign thread can hard-deadlock on Windows — the "stuck at
        # loading" bug). Pure composition: safe everywhere.
        self.setObjectName("spinnerOverlay")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setVisible(False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        card = QFrame()
        card.setObjectName("spinnerCard")
        inner = QHBoxLayout(card)
        inner.setContentsMargins(18, 14, 22, 14)
        inner.setSpacing(12)
        self.spinner = BusySpinner(size=30)
        self.message_label = QLabel("Working…")
        self.message_label.setObjectName("spinnerText")
        inner.addWidget(self.spinner)
        inner.addWidget(self.message_label)
        layout.addStretch(1)
        layout.addWidget(card, 0, Qt.AlignCenter)
        layout.addStretch(1)

    # -------------------------------------------------- API
    def start(self, message: str = "Working…") -> None:
        """Show the overlay (grabs mouse so clicks cannot race the worker)."""
        self.message_label.setText(tr(message))
        self.setGeometry(self.parentWidget().rect())
        self.raise_()
        self.show()
        self.spinner.start()

    def stop(self) -> None:
        """Hide the overlay."""
        self.spinner.stop()
        self.hide()

    def set_host_geometry(self) -> None:
        """Re-cover the host after resize (called from host resizeEvent)."""
        if self.isVisible():
            self.setGeometry(self.parentWidget().rect())

    # block interactions beneath the overlay
    def mousePressEvent(self, event) -> None:  # noqa: N802
        event.accept()

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        event.accept()


@contextmanager
def busy_overlay(host: QWidget, message: str = "Working…") -> Iterator[SpinnerOverlay]:
    """Context manager: overlay covers ``host`` for the duration of a block
    (pair with Worker threads — see workers.run_task)."""
    overlay = SpinnerOverlay(host)
    overlay.start(message)
    try:
        yield overlay
    finally:
        overlay.stop()
        overlay.deleteLater()


__all__ = ["BusySpinner", "SpinnerOverlay", "busy_overlay"]
