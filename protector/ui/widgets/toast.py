"""
protector.ui.widgets.toast — animated toast notifications (bottom-right).

Toast flavors: success / info / warning / error, each with a vector icon in
a tinted badge, a colored status strip and an animated fade in/out. Colors
come from the live palette (light/dark). Never modal, never blocks the UI
thread; purely cosmetic feedback for actions and worker results.
"""

from __future__ import annotations

from typing import Literal

from PySide6.QtCore import (
    QEasingCurve,
    QObject,
    QPropertyAnimation,
    QRect,
    Qt,
    QTimer,
)
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ..i18n import is_rtl, tr
from ..theme import current_palette
from ..theme.icons import pixmap

ToastKind = Literal["success", "info", "warning", "error"]

#: kind -> (icon name, palette role of the tint, icon-badge tone)
_KINDS: dict[str, tuple[str, str, str]] = {
    "success": ("check-circle", "success", "success"),
    "info": ("info", "info", "info"),
    "warning": ("alert", "warning", "warning"),
    "error": ("x-circle", "danger", "danger"),
}


class Toast(QFrame):
    """A single toast card. Managed exclusively by ToastManager."""

    def __init__(self, parent: QWidget, kind: ToastKind, title: str,
                 message: str, duration_ms: int) -> None:
        super().__init__(parent)
        self.setObjectName("toast")
        self.setAttribute(Qt.WA_StyledBackground, True)
        palette = current_palette()
        icon_name, role, tone = _KINDS.get(kind, _KINDS["info"])
        tint = palette.color(role)

        layout = QHBoxLayout(self)
        # Layout margins are not mirrored in RTL: pad the side away from the strip.
        layout.setContentsMargins(*((16, 0, 0, 0) if is_rtl() else (0, 0, 16, 0)))
        layout.setSpacing(12)

        strip = QFrame()
        strip.setFixedWidth(4)
        strip.setStyleSheet(
            f"background: {tint}; border: none; border-top-left-radius: 11px;"
            " border-bottom-left-radius: 11px;")
        layout.addWidget(strip)

        glyph = QLabel()
        glyph.setProperty("iconBadge", tone)
        glyph.setFixedSize(32, 32)
        glyph.setAlignment(Qt.AlignCenter)
        glyph.setPixmap(pixmap(icon_name, tint, 17))
        layout.addWidget(glyph, 0, Qt.AlignVCenter)

        texts = QVBoxLayout()
        texts.setContentsMargins(0, 12, 0, 12)
        texts.setSpacing(2)
        title_label = QLabel(title)
        title_label.setObjectName("toastTitle")
        texts.addWidget(title_label)
        if message:
            message_label = QLabel(message)
            message_label.setObjectName("toastMessage")
            message_label.setWordWrap(True)
            message_label.setMaximumWidth(320)
            texts.addWidget(message_label)
        layout.addLayout(texts, 1)

        # Child widgets ignore windowOpacity — fade through an effect.
        self._opacity = QGraphicsOpacityEffect(self)
        self._opacity.setOpacity(0.0)
        self.setGraphicsEffect(self._opacity)
        self.adjustSize()
        self._fade = QPropertyAnimation(self._opacity, b"opacity")
        self._fade.setEasingCurve(QEasingCurve.OutCubic)
        QTimer.singleShot(duration_ms, self._dismiss)

    def _dismiss(self) -> None:
        """Fade out then remove from the manager's stack."""
        self._fade.stop()
        self._fade.setDuration(260)
        self._fade.setStartValue(self._opacity.opacity())
        self._fade.setEndValue(0.0)
        self._fade.finished.connect(self._cleanup)
        self._fade.start()

    def _cleanup(self) -> None:
        manager = getattr(self.parent(), "_toast_manager", None)
        if manager is not None:
            manager._remove(self)
        else:
            self.deleteLater()


class ToastManager(QObject):
    """Positions and stacks toasts inside the main window (bottom corner at
    the end of the reading direction: right for English, left for Persian)."""

    MARGIN = 20
    BOTTOM = 40  # clear the status bar
    GAP = 10
    STACK_LIMIT = 4

    def __init__(self, container: QWidget, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._container = container
        self._toasts: list[Toast] = []
        container._toast_manager = self  # type: ignore[attr-defined]
        container.installEventFilter(self)

    # -------------------------------------------------- public
    def show(self, kind: ToastKind, title: str, message: str = "",
             duration_ms: int = 3800) -> Toast:
        """Create, animate in and auto-schedule a toast."""
        toast = Toast(self._container, kind, tr(title), tr(message) if message else "",
                      duration_ms)
        toast._fade.setDuration(220)
        toast._fade.setStartValue(0.0)
        toast._fade.setEndValue(1.0)
        toast._fade.start()
        self._toasts.append(toast)
        toast.show()
        toast.raise_()
        while len(self._toasts) > self.STACK_LIMIT:
            oldest = self._toasts.pop(0)
            oldest._dismiss()
        self._relayout()
        return toast

    # -------------------------------------------------- internals
    def _remove(self, toast: Toast) -> None:
        if toast in self._toasts:
            self._toasts.remove(toast)
        toast.hide()
        toast.deleteLater()
        self._relayout()

    def _relayout(self) -> None:
        """Re-stack from bottom-right of the container."""
        area = self._container.rect()
        rtl = is_rtl()  # toasts sit at the reading-direction end corner
        y = area.bottom() - self.BOTTOM
        for toast in reversed(self._toasts):
            width = min(max(toast.sizeHint().width(), 300), 420)
            height = toast.heightForWidth(width) if toast.hasHeightForWidth() \
                else toast.sizeHint().height()
            height = max(height, 56)
            x = area.left() + self.MARGIN if rtl else area.right() - self.MARGIN - width
            toast.setGeometry(QRect(x, y - height, width, height))
            y -= height + self.GAP

    # -------------------------------------------------- Qt events
    def eventFilter(self, watched, event) -> bool:  # noqa: N802
        if watched is self._container and event.type() in (
            event.Type.Resize, event.Type.Move
        ):
            self._relayout()
        return False


__all__ = ["Toast", "ToastManager", "ToastKind"]
