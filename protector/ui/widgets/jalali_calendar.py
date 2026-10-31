"""
protector.ui.widgets.jalali_calendar — Solar Hijri calendar widgets for Qt.

Built on the Doran-core port (protector.core.jalali — MIT © Doran
Contributors, see that module's docstring). Provides:

    * JalaliCalendarWidget — a month grid: Persian week (شنبه first),
      RTL layout, Persian digits, Friday column tinted, "today" outlined,
      selected day in solid accent. Bilingual month header.
    * JalaliDateEdit      — a date picker control (replaces QDateEdit):
      shows the Jalali date in Vazirmatn + the Gregorian date in muted
      Latin, opens the calendar popup, exposes a QDate-compatible API
      subset (date/setDate/dateTime) so pages can drop it in place.

Everything is styled by the global theme QSS (#jalaliPopup, #jalaliDateEdit,
the day cells are flat QPushButtons), so dark/light + accent switching
re-skins the calendar automatically.
"""

from __future__ import annotations

import datetime as _dt

from PySide6.QtCore import QDate, QDateTime, QTime, Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..theme import bind_icon, current_palette
from ...core.jalali import (
    MONTHS_EN,
    MONTHS_FA,
    WEEKDAYS_MIN_FA,
    DoranDate,
    jalali_month_length,
    persian_digits,
)


class JalaliCalendarWidget(QWidget):
    """A single-month Jalali calendar grid (popup-friendly)."""

    #: Emitted with the picked DoranDate when the user clicks a day.
    dateSelected = Signal(object)

    def __init__(self, parent: QWidget | None = None,
                 selected: DoranDate | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("jalaliPopup")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._today = DoranDate.now()
        self._view = (selected or self._today)
        self._selected = selected or self._today

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 14)
        layout.setSpacing(8)
        layout.addWidget(self._build_header())

        self._grid_holder = QWidget()
        self._grid_holder.setLayoutDirection(Qt.RightToLeft)  # Persian week
        self._grid_layout = QVBoxLayout(self._grid_holder)
        self._grid_layout.setContentsMargins(0, 0, 0, 0)
        self._grid_layout.setSpacing(4)
        layout.addWidget(self._grid_holder)
        self._rebuild()

    # -------------------------------------------------- header
    def _build_header(self) -> QWidget:
        bar = QWidget()
        row = QHBoxLayout(bar)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)

        self._prev = QPushButton()
        self._prev.setProperty("class", "iconOnly")
        bind_icon(self._prev, "chevron-right", "text_muted", 15)
        self._prev.setToolTip("Previous month\nماه قبل")
        self._prev.clicked.connect(
            lambda: self._shift_month(-1))
        self._next = QPushButton()
        self._next.setProperty("class", "iconOnly")
        bind_icon(self._next, "chevron-left", "text_muted", 15)
        self._next.setToolTip("Next month\nماه بعد")
        self._next.clicked.connect(
            lambda: self._shift_month(1))

        self._title_fa = QLabel("")
        self._title_fa.setProperty("class", "fa")
        self._title_fa.setStyleSheet("font-size: 14px; font-weight: 700;")
        self._title_fa.setAlignment(Qt.AlignCenter)
        self._title_en = QLabel("")
        self._title_en.setProperty("class", "subtle")
        self._title_en.setAlignment(Qt.AlignCenter)

        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addWidget(self._title_fa)
        titles.addWidget(self._title_en)

        self._today_btn = QPushButton("امروز · Today")
        self._today_btn.setProperty("class", "secondary")
        self._today_btn.setToolTip("Jump to today\nبرو به امروز")
        self._today_btn.clicked.connect(self._go_today)

        row.addWidget(self._prev)
        row.addLayout(titles, 1)
        row.addWidget(self._next)
        row.addWidget(self._today_btn)
        return bar

    # -------------------------------------------------- navigation
    def _shift_month(self, delta: int) -> None:
        year, month = self._view.year, self._view.month
        month += delta
        while month < 1:
            month += 12
            year -= 1
        while month > 12:
            month -= 12
            year += 1
        # Keep the day clamped to the target month's length.
        day = min(self._view.day, jalali_month_length(year, month))
        try:
            self._view = DoranDate.from_jalali(year, month, day)
        except ValueError:  # pragma: no cover - clamp already guards
            return
        self._rebuild()

    def _go_today(self) -> None:
        self._view = self._today
        self._select(self._today)

    def _select(self, date: DoranDate) -> None:
        self._selected = date
        self._view = date
        self._rebuild()
        self.dateSelected.emit(date)

    # -------------------------------------------------- grid
    def _rebuild(self) -> None:
        # Bilingual month title.
        self._title_fa.setText(persian_digits(
            f"{MONTHS_FA[self._view.month - 1]} {self._view.year}"))
        self._title_en.setText(
            f"{MONTHS_EN[self._view.month - 1]} {self._view.year}")

        while self._grid_layout.count():
            item = self._grid_layout.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()

        # Weekday header (RTL grid → شنبه renders rightmost).
        head = QWidget()
        head.setLayoutDirection(Qt.RightToLeft)
        head_row = QHBoxLayout(head)
        head_row.setContentsMargins(0, 0, 0, 0)
        head_row.setSpacing(2)
        palette = current_palette()
        for glyph in WEEKDAYS_MIN_FA:
            cell = QLabel(glyph)
            cell.setProperty("class", "fa")
            cell.setAlignment(Qt.AlignCenter)
            cell.setStyleSheet(
                f"font-size: 11px; font-weight: 700; color: {palette.text_subtle};")
            head_row.addWidget(cell)
        self._grid_layout.addWidget(head)

        # Day grid: weeks of 7, Persian week order (index 0 = شنبه).
        weeks: list[list[DoranDate | None]] = [[]]
        first = DoranDate.from_jalali(self._view.year, self._view.month, 1)
        lead = first.weekday()  # 0 = شنبه
        for _ in range(lead):
            weeks[0].append(None)
        length = jalali_month_length(self._view.year, self._view.month)
        for day in range(1, length + 1):
            if len(weeks[-1]) == 7:
                weeks.append([])
            weeks[-1].append(
                DoranDate.from_jalali(self._view.year, self._view.month, day))
        while len(weeks[-1]) < 7:
            weeks[-1].append(None)

        for week in weeks:
            week_row = QWidget()
            week_row.setLayoutDirection(Qt.RightToLeft)
            cells = QHBoxLayout(week_row)
            cells.setContentsMargins(0, 0, 0, 0)
            cells.setSpacing(2)
            for date in week:
                cells.addWidget(self._day_cell(date), 1)
            self._grid_layout.addWidget(week_row)

    def _day_cell(self, date: DoranDate | None) -> QWidget:
        if date is None:
            blank = QWidget()
            blank.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            blank.setFixedHeight(30)
            return blank
        button = QPushButton(persian_digits(str(date.day)))
        button.setProperty("class", "fa")
        button.setFixedHeight(30)
        button.setCursor(Qt.PointingHandCursor)
        gy, gm, gd = date.to_gregorian()
        is_friday = date.weekday() == 6
        is_today = date == self._today
        is_selected = date == self._selected
        # Flat cell, semantic tints; selected day is a solid accent chip.
        p = current_palette()
        style = (
            "QPushButton { background: transparent; border: 1px solid transparent;"
            " border-radius: 7px; font-size: 12px; font-weight: 600; padding: 0;"
            f" color: {p.danger if is_friday else p.text};"
            " font-family: 'Vazirmatn', sans-serif; }"
            f"QPushButton:hover {{ background: {p.surface_hover}; }}"
        )
        if is_selected:
            style = (
                f"QPushButton {{ background: {p.accent}; color: {p.on_accent};"
                f" border: 1px solid {p.accent}; border-radius: 7px; font-size: 12px;"
                " font-weight: 800; padding: 0;"
                " font-family: 'Vazirmatn', sans-serif; }"
                f"QPushButton:hover {{ background: {p.accent_hover}; }}"
            )
        elif is_today:
            style += f"QPushButton {{ border: 1px solid {p.accent}; color: {p.accent_text}; }}"
        button.setStyleSheet(style)
        button.setToolTip(
            f"{date.format('dddd D MMMM YYYY', fa=True)}\n"
            f"{gy:04d}-{gm:02d}-{gd:02d} (Gregorian)")
        button.clicked.connect(
            lambda _=False, d=date: self.dateSelected.emit(d))
        return button


class JalaliDateEdit(QWidget):
    """A Jalali date picker styled to blend with QLineEdit-based forms.

    Shows the selected Solar Hijri date in Persian digits (Vazirmatn) plus
    the Gregorian date muted next to it; the 📅 button opens the calendar
    popup. API subset mirrors QDateEdit so pages can swap it in directly:
    ``date()``, ``setDate()``, ``dateTime()``.
    """

    #: Emitted whenever the picked date changes (QDate payload).
    dateChanged = Signal(QDate)

    def __init__(self, parent: QWidget | None = None,
                 date: QDate | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("jalaliDateEdit")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._doran = DoranDate.from_qdate(
            date if date is not None else QDate.currentDate())

        row = QHBoxLayout(self)
        row.setContentsMargins(12, 3, 4, 3)
        row.setSpacing(8)

        self._fa_label = QLabel("")
        self._fa_label.setProperty("class", "fa")
        self._fa_label.setStyleSheet("font-size: 13px; font-weight: 600;")
        self._en_label = QLabel("")
        self._en_label.setProperty("class", "subtle")
        self._render()
        row.addWidget(self._fa_label)
        row.addWidget(self._en_label)
        row.addStretch(1)

        self._pick = QPushButton()
        self._pick.setProperty("class", "ghost")
        self._pick.setFixedSize(32, 30)
        self._pick.setCursor(Qt.PointingHandCursor)
        bind_icon(self._pick, "calendar", "accent_text", 16)
        self._pick.setToolTip("Open the Solar Hijri calendar\nتقویم هجری شمسی را باز کن")
        self._pick.clicked.connect(self._open_popup)
        row.addWidget(self._pick)

    # -------------------------------------------------- API (QDateEdit subset)
    def date(self) -> QDate:
        gy, gm, gd = self._doran.to_gregorian()
        return QDate(gy, gm, gd)

    def dateTime(self) -> QDateTime:
        return QDateTime(self.date(), QTime(0, 0))

    def setDate(self, qdate: QDate) -> None:
        self._doran = DoranDate.from_qdate(qdate)
        self._render()
        self.dateChanged.emit(qdate)

    def doran(self) -> DoranDate:
        """The selected date as a DoranDate (Jalali parts + formatting)."""
        return self._doran

    # -------------------------------------------------- rendering
    def _render(self) -> None:
        self._fa_label.setText(self._doran.format("YYYY/MM/DD", fa=True))
        gy, gm, gd = self._doran.to_gregorian()
        self._en_label.setText(f"{gy:04d}-{gm:02d}-{gd:02d}")

    # -------------------------------------------------- popup
    def _open_popup(self) -> None:
        popup = QWidget(self, Qt.Popup | Qt.FramelessWindowHint)
        popup.setObjectName("jalaliPopupFrame")
        popup.setAttribute(Qt.WA_StyledBackground, True)
        popup.setLayout(QVBoxLayout(popup))
        popup.layout().setContentsMargins(2, 2, 2, 2)
        calendar = JalaliCalendarWidget(selected=self._doran)
        popup.layout().addWidget(calendar)

        def _picked(doran: DoranDate) -> None:
            gy, gm, gd = doran.to_gregorian()
            self.setDate(QDate(gy, gm, gd))
            popup.close()

        calendar.dateSelected.connect(_picked)
        popup.adjustSize()
        global_pos = self.mapToGlobal(self.rect().bottomLeft())
        global_pos.setY(global_pos.y() + 6)
        popup.move(global_pos)
        popup.show()


__all__ = ["JalaliCalendarWidget", "JalaliDateEdit"]
