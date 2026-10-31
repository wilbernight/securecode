"""
protector.ui.widgets.chart — monthly bar chart (custom QPainter).

No QtCharts dependency (keeps the frozen EXE small); supports:
    * 12-month histogram with "nice" y-axis ticks and dashed gridlines
    * accent bars with a soft vertical gradient, rounded tops, the latest
      month emphasized, hover highlight + value bubble + tooltip
    * empty-state text when there is no data yet
    * colors from the live theme palette (light/dark + accent)
Used by the Dashboard page ("Serials issued per month").
"""

from __future__ import annotations

import math
from typing import Sequence

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget

from ..theme import current_palette

_LEFT = 36      # y-axis label gutter
_RIGHT = 8
_TOP = 22
_BOTTOM = 28    # x-axis label band
_EMPTY_TEXT = "No serials issued yet — generate your first key to see activity."


def _nice_max(value: int) -> tuple[int, int]:
    """Round the axis maximum up to a friendly number; return (max, step)."""
    if value <= 4:
        return 4, 1
    raw = value / 4
    magnitude = 10 ** int(math.floor(math.log10(raw)))
    for factor in (1, 2, 2.5, 5, 10):
        step = factor * magnitude
        if step >= raw:
            step = int(math.ceil(step))
            return step * 4, step
    return value, max(1, value // 4)  # pragma: no cover


class BarChart(QWidget):
    """A minimal, dependency-free vertical bar chart."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._labels: list[str] = []
        self._values: list[int] = []
        self._hover_index: int = -1
        self._accent: str | None = None
        self.setMouseTracking(True)
        self.setMinimumHeight(200)

    # -------------------------------------------------- data
    def set_data(self, series: Sequence[tuple[str, int]]) -> None:
        """Load [(label, value)] (e.g. monthly histogram)."""
        self._labels = [str(label) for label, _ in series]
        self._values = [int(value) for _, value in series]
        self._hover_index = -1
        self.update()

    def set_accent(self, color_hex: str) -> None:
        self._accent = color_hex
        self.update()

    def set_mode(self, mode: str) -> None:
        """Kept for API compatibility — colors come from the live palette."""
        self.update()

    # -------------------------------------------------- geometry
    def _plot(self) -> QRectF:
        return QRectF(_LEFT, _TOP, self.width() - _LEFT - _RIGHT,
                      self.height() - _TOP - _BOTTOM)

    def _bar_rects(self) -> list[QRectF]:
        if not self._values:
            return []
        plot = self._plot()
        axis_max, _ = _nice_max(max(self._values))
        step = plot.width() / len(self._values)
        bar_w = min(30.0, step * 0.56)
        rects = []
        for i, value in enumerate(self._values):
            height = (value / axis_max) * plot.height() if axis_max else 0
            height = max(height, 3.0)
            x = plot.left() + i * step + (step - bar_w) / 2
            rects.append(QRectF(x, plot.bottom() - height, bar_w, height))
        return rects

    # -------------------------------------------------- events
    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        pos = event.position()
        plot = self._plot()
        index = -1
        if self._values and plot.left() <= pos.x() <= plot.right():
            step = plot.width() / len(self._values)
            index = min(len(self._values) - 1, int((pos.x() - plot.left()) / step))
        if index != self._hover_index:
            self._hover_index = index
            if index >= 0:
                self.setToolTip(f"{self._labels[index]}: {self._values[index]} serial(s)")
            else:
                self.setToolTip("")
            self.update()

    def leaveEvent(self, event) -> None:  # noqa: N802
        self._hover_index = -1
        self.update()

    # -------------------------------------------------- paint
    def paintEvent(self, event) -> None:  # noqa: N802
        p = current_palette()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        family = self.font().family()

        if not self._values or not any(self._values):
            painter.setPen(QColor(p.text_subtle))
            painter.setFont(QFont(family, 10))
            painter.drawText(self.rect(), Qt.AlignCenter, _EMPTY_TEXT)
            painter.end()
            return

        plot = self._plot()
        axis_max, step_value = _nice_max(max(self._values))
        accent = QColor(self._accent or p.accent)

        # gridlines + y labels
        grid_pen = QPen(QColor(p.border), 1, Qt.DashLine)
        grid_pen.setDashPattern([3, 4])
        painter.setFont(QFont(family, 8))
        for tick in range(0, axis_max + 1, step_value):
            y = plot.bottom() - (tick / axis_max) * plot.height()
            painter.setPen(QPen(QColor(p.border_strong), 1) if tick == 0 else grid_pen)
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(QColor(p.text_subtle))
            painter.drawText(QRectF(0, y - 8, _LEFT - 8, 16),
                             Qt.AlignRight | Qt.AlignVCenter, str(tick))

        rects = self._bar_rects()
        step = plot.width() / len(rects)
        last = len(rects) - 1
        for i, rect in enumerate(rects):
            # hover column wash
            if i == self._hover_index:
                wash = QRectF(plot.left() + i * step + 2, plot.top(), step - 4, plot.height())
                painter.setPen(Qt.NoPen)
                painter.setBrush(QColor(p.surface_hover))
                painter.drawRoundedRect(wash, 6, 6)

            top = QColor(accent)
            bottom = QColor(accent)
            if self._values[i] == 0:
                top = bottom = QColor(p.border)
            elif i not in (last, self._hover_index):
                top.setAlpha(150)
                bottom.setAlpha(90)
            else:
                bottom.setAlpha(190)
            gradient = QLinearGradient(rect.topLeft(), rect.bottomLeft())
            gradient.setColorAt(0, top)
            gradient.setColorAt(1, bottom)
            radius = min(6.0, rect.width() / 2, rect.height())
            path = QPainterPath()
            path.moveTo(rect.left(), rect.bottom())
            path.lineTo(rect.left(), rect.top() + radius)
            path.quadTo(rect.left(), rect.top(), rect.left() + radius, rect.top())
            path.lineTo(rect.right() - radius, rect.top())
            path.quadTo(rect.right(), rect.top(), rect.right(), rect.top() + radius)
            path.lineTo(rect.right(), rect.bottom())
            path.closeSubpath()
            painter.setPen(Qt.NoPen)
            painter.setBrush(gradient)
            painter.drawPath(path)

            # month labels (thinned on narrow widths)
            label = self._labels[i]
            if step < 38:
                label = label[-2:]
                if i % 2 and i != last:
                    continue
            painter.setPen(QColor(p.text if i == self._hover_index else p.text_subtle))
            painter.setFont(QFont(family, 8))
            painter.drawText(QRectF(plot.left() + i * step - 6, plot.bottom() + 8,
                                    step + 12, 14), Qt.AlignCenter, label)

        # value bubble above the hovered bar
        if 0 <= self._hover_index < len(rects):
            rect = rects[self._hover_index]
            text = str(self._values[self._hover_index])
            painter.setFont(QFont(family, 8, QFont.Bold))
            width = max(26, painter.fontMetrics().horizontalAdvance(text) + 14)
            bubble = QRectF(rect.center().x() - width / 2, rect.top() - 24, width, 18)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(p.tooltip_bg))
            painter.drawRoundedRect(bubble, 5, 5)
            painter.setPen(QColor(p.tooltip_text))
            painter.drawText(bubble, Qt.AlignCenter, text)
        painter.end()


__all__ = ["BarChart"]
