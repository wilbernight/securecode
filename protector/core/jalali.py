"""
protector.core.jalali — Solar Hijri (Jalali) calendar engine.

Faithful Python port of the Doran project's core conversion module
(https://github.com/amiralibg/Doran, @doranjs/core, MIT license © Doran
Contributors). Doran itself is a TypeScript ecosystem, which cannot run
inside this PySide6 application — so the battle-tested algorithm is ported
here 1:1 and credited. The underlying math is the widely-used algorithm by
Kazimierz M. Borkowski / Behrang Noruzi Niya (the same one that powers
jalaali-js, moment-jalaali and friends); it is exact for Jalali years in
[-61, 3177].

Differences from the original (pragmatic, documented in DECISIONS.md):
    * Python instead of TypeScript; integers instead of JS floats.
    * Only the pieces this application needs are ported: conversions,
      week-day math (Persian week: Saturday first), month lengths,
      leap years, fa/en locale names, Persian/Latin digits, a DoranDate
      value class with the practical subset of format tokens.
    * Natural-language parsing (@doranjs/nlp) and holiday datasets are
      NOT ported — the protector never needs them.

Verification: tests/jalali_test.py round-trips every day of 1970-2030 and
checks well-known historical anchors (22 Bahman 1357, Nowruz 1403/1404).
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Final

__all__ = [
    "DoranDate", "gregorian_to_jalali", "jalali_to_gregorian",
    "is_leap_jalali_year", "jalali_month_length", "is_valid_jalali_date",
    "persian_digits", "latin_digits", "MONTHS_FA", "MONTHS_EN",
    "WEEKDAYS_FA", "WEEKDAYS_EN",
]


# ---------------------------------------------------------------------------
# Truncated integer division (matches the reference algorithm exactly;
# Python's native // is FLOOR division, which differs for negatives).
# ---------------------------------------------------------------------------
def _div(a: int, b: int) -> int:
    return int(a / b)


def _mod(a: int, b: int) -> int:
    return a - int(a / b) * b


#: Jalali years where a leap-year break occurs (Doran conversion.ts BREAKS).
_BREAKS: Final[tuple[int, ...]] = (
    -61, 9, 38, 199, 426, 686, 756, 818, 1111, 1181, 1210, 1635, 2060,
    2097, 2192, 2262, 2326, 2394, 2456, 3178,
)


def _jal_cal(jy: int, without_leap: bool = False) -> tuple[int, int, int]:
    """(leap, gregorian_year, march_day) for a Jalali year — Doran jalCal().

    ``leap`` is 0 when the year is a leap year, otherwise the number of
    years until the next leap year; ``march`` is the Gregorian day of March
    on which Farvardin 1 of ``jy`` falls.
    """
    bl = len(_BREAKS)
    gy = jy + 621
    leap_j = -14
    jp = _BREAKS[0]

    if jy < jp or jy >= _BREAKS[bl - 1]:
        raise ValueError(
            f"Jalali year {jy} is out of the supported range "
            f"[{jp}, {_BREAKS[bl - 1]}).")

    jump = 0
    for i in range(1, bl):
        jm = _BREAKS[i]
        jump = jm - jp
        if jy < jm:
            break
        leap_j = leap_j + _div(jump, 33) * 8 + _div(_mod(jump, 33), 4)
        jp = jm
    n = jy - jp

    leap_j = leap_j + _div(n, 33) * 8 + _div(_mod(n, 33) + 3, 4)
    if _mod(jump, 33) == 4 and jump - n == 4:
        leap_j += 1

    leap_g = _div(gy, 4) - _div((_div(gy, 100) + 1) * 3, 4) - 150
    march = 20 + leap_j - leap_g

    leap = 0
    if not without_leap:
        if jump - n < 6:
            n = n - jump + _div(jump + 4, 33) * 33
        leap = _mod(_mod(n + 1, 33) - 1, 4)
        if leap == -1:
            leap = 4
    return leap, gy, march


def _gregorian_to_jdn(gy: int, gm: int, gd: int) -> int:
    """Gregorian date -> Julian Day Number (Doran gregorianToJdn)."""
    d = (_div((gy + _div(gm - 8, 6) + 100100) * 1461, 4)
         + _div(153 * _mod(gm + 9, 12) + 2, 5) + gd - 34840408)
    d = d - _div(_div(gy + 100100 + _div(gm - 8, 6), 100) * 3, 4) + 752
    return d


def _jdn_to_gregorian(jdn: int) -> tuple[int, int, int]:
    """Julian Day Number -> (gy, gm, gd) — Doran jdnToGregorian."""
    j = 4 * jdn + 139361631
    j = j + _div(_div(4 * jdn + 183187720, 146097) * 3, 4) * 4 - 3908
    i = _div(_mod(j, 1461), 4) * 5 + 308
    gd = _div(_mod(i, 153), 5) + 1
    gm = _mod(_div(i, 153), 12) + 1
    gy = _div(j, 1461) - 100100 + _div(8 - gm, 6)
    return gy, gm, gd


def _jalali_to_jdn(jy: int, jm: int, jd: int) -> int:
    _, gy, march = _jal_cal(jy, True)
    return (_gregorian_to_jdn(gy, 3, march)
            + (jm - 1) * 31 - _div(jm, 7) * (jm - 7) + jd - 1)


def _jdn_to_jalali(jdn: int) -> tuple[int, int, int]:
    gy = _jdn_to_gregorian(jdn)[0]
    jy = gy - 621
    r_leap, _, r_march = _jal_cal(jy, False)
    jdn1f = _gregorian_to_jdn(gy, 3, r_march)
    k = jdn - jdn1f

    if k >= 0:
        if k <= 185:
            return jy, 1 + _div(k, 31), _mod(k, 31) + 1
        k -= 186
    else:
        jy -= 1
        k += 179
        if r_leap == 1:
            k += 1
    return jy, 7 + _div(k, 30), _mod(k, 30) + 1


# ---------------------------------------------------------------------------
# Public conversions
# ---------------------------------------------------------------------------
def gregorian_to_jalali(gy: int, gm: int, gd: int) -> tuple[int, int, int]:
    """(jy, jm, jd) for a Gregorian date."""
    return _jdn_to_jalali(_gregorian_to_jdn(gy, gm, gd))


def jalali_to_gregorian(jy: int, jm: int, jd: int) -> tuple[int, int, int]:
    """(gy, gm, gd) for a Jalali date."""
    return _jdn_to_gregorian(_jalali_to_jdn(jy, jm, jd))


def _gregorian_weekday(gy: int, gm: int, gd: int) -> int:
    """0 = Saturday … 6 = Friday (the Persian week convention) — Doran."""
    m, y = gm, gy
    if m < 3:
        m += 12
        y -= 1
    k = _mod(y, 100)
    j = _div(y, 100)
    h = _mod(gd + _div(13 * (m + 1), 5) + k + _div(k, 4) + _div(j, 4) + 5 * j, 7)
    return _mod(h, 7)


def is_leap_jalali_year(jy: int) -> bool:
    return _jal_cal(jy, False)[0] == 0


def jalali_month_length(jy: int, jm: int) -> int:
    """Days in a Jalali month: 1-6 → 31, 7-11 → 30, Esfand → 29/30 (leap)."""
    if jm < 1 or jm > 12:
        raise ValueError(f"Jalali month must be between 1 and 12, received {jm}.")
    if jm <= 6:
        return 31
    if jm <= 11:
        return 30
    return 30 if is_leap_jalali_year(jy) else 29


def is_valid_jalali_date(jy: int, jm: int, jd: int) -> bool:
    if jm < 1 or jm > 12 or jd < 1:
        return False
    try:
        return jd <= jalali_month_length(jy, jm)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Locale data (Doran locale.ts fa-IR / en-US, trimmed to what we need)
# ---------------------------------------------------------------------------
MONTHS_FA: Final[tuple[str, ...]] = (
    "فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
    "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند",
)
MONTHS_EN: Final[tuple[str, ...]] = (
    "Farvardin", "Ordibehesht", "Khordad", "Tir", "Mordad", "Shahrivar",
    "Mehr", "Aban", "Azar", "Dey", "Bahman", "Esfand",
)
#: Index 0 = Saturday … 6 = Friday.
WEEKDAYS_FA: Final[tuple[str, ...]] = (
    "شنبه", "یکشنبه", "دوشنبه", "سه‌شنبه", "چهارشنبه", "پنجشنبه", "جمعه",
)
WEEKDAYS_EN: Final[tuple[str, ...]] = (
    "Saturday", "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday",
    "Friday",
)
#: Minimal day glyphs for compact calendar headers (ش ی د س چ پ ج).
WEEKDAYS_MIN_FA: Final[tuple[str, ...]] = (
    "ش", "ی", "د", "س", "چ", "پ", "ج",
)

_FA_DIGIT_TABLE = str.maketrans("0123456789.", "۰۱۲۳۴۵۶۷۸۹٫")
_LA_DIGIT_TABLE = str.maketrans("۰۱۲۳۴۵۶۷۸۹٫", "0123456789.")


def persian_digits(text: str) -> str:
    """Latin digits → Persian digits (Doran toPersianDigits)."""
    return text.translate(_FA_DIGIT_TABLE)


def latin_digits(text: str) -> str:
    """Persian digits → Latin digits (Doran toLatinDigits)."""
    return text.translate(_LA_DIGIT_TABLE)


# ---------------------------------------------------------------------------
# DoranDate — the practical value class (immutable, like @doranjs/core)
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class DoranDate:
    """A Solar Hijri date with formatting, arithmetic and both calendars.

    Construct via :meth:`now`, :meth:`from_gregorian` or :meth:`from_jalali`;
    never stores a timezone (dates only, matching Doran's date-only model).
    """

    year: int   # Jalali year (e.g. 1405)
    month: int  # 1..12 (1 = Farvardin)
    day: int    # 1..31

    # -------------------------------------------------- constructors
    @classmethod
    def now(cls) -> "DoranDate":
        return cls.from_datetime(_dt.date.today())

    @classmethod
    def from_gregorian(cls, year: int, month: int, day: int) -> "DoranDate":
        jy, jm, jd = gregorian_to_jalali(year, month, day)
        return cls(jy, jm, jd)

    @classmethod
    def from_jalali(cls, year: int, month: int, day: int) -> "DoranDate":
        if not is_valid_jalali_date(year, month, day):
            raise ValueError(f"invalid Jalali date {year}/{month}/{day}")
        return cls(year, month, day)

    @classmethod
    def from_datetime(cls, date: _dt.date) -> "DoranDate":
        return cls.from_gregorian(date.year, date.month, date.day)

    @classmethod
    def from_qdate(cls, qdate) -> "DoranDate":
        """Build from a QDate (PySide6)."""
        return cls.from_gregorian(qdate.year(), qdate.month(), qdate.day())

    # -------------------------------------------------- conversions
    def to_gregorian(self) -> tuple[int, int, int]:
        return jalali_to_gregorian(self.year, self.month, self.day)

    def to_date(self) -> _dt.date:
        gy, gm, gd = self.to_gregorian()
        return _dt.date(gy, gm, gd)

    def weekday(self) -> int:
        """0 = شنبه/Saturday … 6 = جمعه/Friday (Persian week)."""
        gy, gm, gd = self.to_gregorian()
        return _gregorian_weekday(gy, gm, gd)

    def month_length(self) -> int:
        return jalali_month_length(self.year, self.month)

    def is_leap_year(self) -> bool:
        return is_leap_jalali_year(self.year)

    # -------------------------------------------------- arithmetic
    def add_days(self, days: int) -> "DoranDate":
        gy, gm, gd = self.to_gregorian()
        return DoranDate.from_datetime(
            _dt.date(gy, gm, gd) + _dt.timedelta(days=days))

    # -------------------------------------------------- formatting
    def format(self, pattern: str, *, fa: bool = True) -> str:
        """Format with Doran-style tokens (subset used by this app).

        Tokens: YYYY YY MM M DD D MMMM (month name) MMM (short month)
        dddd (weekday name) ddd. Digits follow ``fa`` (Persian/Latin).
        """
        wd = self.weekday()
        values = {
            "YYYY": f"{self.year:04d}",
            "YY": f"{self.year % 100:02d}",
            "MM": f"{self.month:02d}",
            "M": str(self.month),
            "DD": f"{self.day:02d}",
            "D": str(self.day),
            "MMMM": (MONTHS_FA if fa else MONTHS_EN)[self.month - 1],
            "MMM": (MONTHS_FA if fa else MONTHS_EN)[self.month - 1][:3],
            "dddd": (WEEKDAYS_FA if fa else WEEKDAYS_EN)[wd],
            "ddd": (WEEKDAYS_FA if fa else WEEKDAYS_EN)[wd][:3],
        }
        out = pattern
        for token in sorted(values, key=len, reverse=True):
            out = out.replace(token, values[token])
        return persian_digits(out) if fa else out
