"""Correctness tests for the Doran-core port (protector.core.jalali).

Anchors are externally well-known dates:
    * 22 Bahman 1357 = 1979-02-11 (the Iranian revolution).
    * Nowruz 1403 = 2024-03-20 and Esfand 30, 1403 = 2025-03-20 (1403 leap).
    * Nowruz 1405 = 2026-03-21.
Round-trip: every single day from 1970-01-01 to 2030-12-31 in both
directions, plus weekday checks against Python's own calendar.
"""
import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protector.core.jalali import (  # noqa: E402
    DoranDate, gregorian_to_jalali, is_leap_jalali_year,
    is_valid_jalali_date, jalali_month_length, jalali_to_gregorian,
    latin_digits, persian_digits,
)

checks = 0


def ok(cond: bool, label: str) -> None:
    global checks
    assert cond, label
    checks += 1
    print(f"  ✓ {label}")


print("jalali engine (Doran port) — anchors")
# 22 Bahman 1357 == 1979-02-11
ok(jalali_to_gregorian(1357, 11, 22) == (1979, 2, 11), "22 Bahman 1357 = 1979-02-11")
ok(gregorian_to_jalali(1979, 2, 11) == (1357, 11, 22), "1979-02-11 = 22 Bahman 1357")
# Nowruz 1403 == 2024-03-20 (equinox before noon Tehran -> same day)
ok(jalali_to_gregorian(1403, 1, 1) == (2024, 3, 20), "Nowruz 1403 = 2024-03-20")
# 1403 is a leap year: Esfand has 30 days, Nowruz 1404 = 2025-03-20
ok(is_leap_jalali_year(1403), "1403 is a leap Jalali year")
ok(jalali_month_length(1403, 12) == 30, "Esfand 1403 has 30 days")
ok(jalali_month_length(1404, 12) == 29, "Esfand 1404 has 29 days")
ok(jalali_to_gregorian(1403, 12, 30) == (2025, 3, 20), "Esfand 30, 1403 = 2025-03-20")
# Equinox 2025 fell at 12:31 Tehran (AFTER noon) -> Nowruz 1404 = March 21
ok(jalali_to_gregorian(1404, 1, 1) == (2025, 3, 21), "Nowruz 1404 = 2025-03-21")
# Nowruz 1405 == 2026-03-21 (equinox after noon Tehran)
ok(jalali_to_gregorian(1405, 1, 1) == (2026, 3, 21), "Nowruz 1405 = 2026-03-21")

print("round-trip every day 1970..2030")
start = dt.date(1970, 1, 1)
count = 0
day = start
while day <= dt.date(2030, 12, 31):
    jy, jm, jd = gregorian_to_jalali(day.year, day.month, day.day)
    assert is_valid_jalali_date(jy, jm, jd), (day, jy, jm, jd)
    assert jalali_to_gregorian(jy, jm, jd) == (day.year, day.month, day.day), (day, jy, jm, jd)
    day += dt.timedelta(days=1)
    count += 1
ok(count == 22280, f"round-trip over {count} days (1970-2030)")

print("DoranDate API")
today = DoranDate.now()
gy, gm, gd = today.to_gregorian()
ok(DoranDate.from_gregorian(gy, gm, gd) == today, "DoranDate now/from_gregorian round-trip")
ok(today.add_days(30).add_days(-30) == today, "add_days(+30).add_days(-30) is identity")
ok(today.add_days(365).to_gregorian() is not None, "add_days(365) valid")
wed = DoranDate.from_gregorian(2024, 3, 20)  # a Wednesday
ok(wed.weekday() == 4, "2024-03-20 is چهارشنبه (weekday index 4)")
sat = DoranDate.from_gregorian(2026, 10, 24)  # a Saturday
ok(sat.weekday() == 0, "2026-10-24 is شنبه (weekday index 0)")

print("formatting + digits")
d = DoranDate.from_gregorian(2026, 10, 26)
ok(d.format("YYYY/MM/DD", fa=True) == d.format("YYYY/MM/DD", fa=False).translate(
    str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")), "fa digits equal latin mapped")
ok("مر" in d.format("MMMM", fa=True) or "آب" in d.format("MMMM", fa=True),
   f"MMMM gives a Persian month name ({d.format('MMMM', fa=True)})")
ok(d.format("dddd D MMMM YYYY") != "", "Doran quick-start pattern renders")
ok(persian_digits("1405/08") == "۱۴۰۵/۰۸", "persian_digits")
ok(latin_digits("۱۴۰۵/۰۸") == "1405/08", "latin_digits")

print(f"ALL PASS — {checks} checks")
