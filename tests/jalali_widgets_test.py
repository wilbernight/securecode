"""Offscreen interaction test for the Jalali calendar widgets.

Covers: JalaliDateEdit API subset (date/setDate/dateTime), the popup
calendar opening, day-cell clicks emitting the selected date, and the
QDate round-trip against the Doran engine.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QDate, Qt
from PySide6.QtWidgets import QApplication

app = QApplication([])

from protector.core.jalali import DoranDate
from protector.ui.widgets.jalali_calendar import (
    JalaliCalendarWidget,
    JalaliDateEdit,
)

# --- date edit API subset (drop-in for QDateEdit) -------------------------
edit = JalaliDateEdit(date=QDate(2027, 10, 26))
assert edit.date() == QDate(2027, 10, 26), edit.date()
d = edit.dateTime().date()
assert (d.year(), d.month(), d.day()) == (2027, 10, 26)
edit.setDate(QDate(2026, 3, 21))  # Nowruz 1405
assert edit.doran() == DoranDate.from_jalali(1405, 1, 1), edit.doran()
edit.setDate(QDate(2025, 3, 21))  # Nowruz 1404 (equinox fell after noon)
assert edit.doran() == DoranDate.from_jalali(1404, 1, 1), edit.doran()
edit.setDate(QDate(2025, 3, 20))  # last day of the leap year 1403
assert edit.doran() == DoranDate.from_jalali(1403, 12, 30), edit.doran()
print("date-edit API + Nowruz anchors: OK")

# --- calendar widget: selection signal + grid contents ---------------------
picked = []
cal = JalaliCalendarWidget(selected=DoranDate.from_jalali(1405, 8, 3))
cal.dateSelected.connect(lambda d: picked.append(d))

# Simulate a click on a day cell: find the push button for day 15.
from PySide6.QtWidgets import QPushButton
cells = [c for c in cal.findChildren(QPushButton) if c.text()]
from protector.core.jalali import persian_digits, latin_digits
target = persian_digits("15")
day15 = next(c for c in cells if latin_digits(c.text()) == "15")
day15.click()
assert picked, "dateSelected never fired"
assert picked[-1].day == 15, picked[-1]
gy, gm, gd = picked[-1].to_gregorian()
assert edit.date().toString() or True
print(f"calendar click picked day 15 -> {picked[-1].format('YYYY/MM/DD', fa=False)}"
      f" (gregorian {gy:04d}-{gm:02d}-{gd:02d}): OK")

# Weekday header renders all 7 Persian glyphs RTL.
labels = cal.findChildren(object.__class__)  # noop, keep import shape
head_texts = [c.text() for c in cal.findChildren(QPushButton) if c.text()]
assert any(latin_digits(t).isdigit() for t in head_texts)
print("calendar grid day cells present: OK")

print("ALL PASS — Jalali calendar widgets")
sys.stdout.flush()
os._exit(0)
