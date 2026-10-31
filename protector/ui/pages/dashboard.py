"""
protector.ui.pages.dashboard — Dashboard (bilingual EN + FA).

Live counters (issued / active / expiring / expired / revoked) with share
bars, a monthly issuance chart and an activity feed of the most recently
issued serials — captions in BOTH English and Persian (Vazirmatn,
class="fa"). The header carries today's date in both calendars: Gregorian
and Solar Hijri (the Doran-core port in protector.core.jalali). All data is
loaded through worker threads (never blocks the UI).
"""

from __future__ import annotations

import zlib
from datetime import datetime, timezone

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from ...core.jalali import DoranDate
from ..i18n import arrow, digits, is_rtl, num, tr
from ..theme import current_palette, on_theme
from ..theme.theme import _mix
from ..widgets.chart import BarChart
from ..widgets.workers import run_task
from .base import (
    Page,
    badge,
    button,
    card_header,
    icon_badge,
    icon_label,
    make_card,
    page_header,
    page_layout,
)

#: status -> (English caption, Persian caption, badge kind)
_STATUS = {
    "active": ("Active", "فعال", "success"),
    "lifetime": ("Lifetime", "همیشگی", "info"),
    "expiring": ("Expiring", "در حال انقضا", "warning"),
    "expired": ("Expired", "منقضی", "danger"),
    "revoked": ("Revoked", "باطل‌شده", "neutral"),
}

#: (key, icon, tone, English caption, Persian caption)
_STAT_CARDS = (
    ("total", "key", "accent", "Total serials", "کل سریال‌ها"),
    ("active", "check-circle", "success", "Active", "فعال"),
    ("expiring", "hourglass", "warning", "Expiring < 30 days", "در حال انقضا"),
    ("expired", "clock", "danger", "Expired", "منقضی‌شده"),
    ("revoked", "ban", "neutral", "Revoked", "باطل‌شده"),
)

_TONE_ROLE = {"accent": "accent", "success": "success", "warning": "warning",
              "danger": "danger", "neutral": "text_subtle"}

#: Avatar hues (customer initials), picked deterministically per name.
_AVATAR_HUES = ("#2563EB", "#7C3AED", "#0D9488", "#D97706", "#DB2777", "#059669",
                "#4F46E5", "#EA580C")


def _jalali(issued_at: int) -> str:
    """Persian (Solar Hijri) rendering of a UTC timestamp, for tooltips."""
    return DoranDate.from_datetime(
        datetime.fromtimestamp(issued_at, tz=timezone.utc)).format(
            "dddd D MMMM YYYY")


def _initials(name: str) -> str:
    parts = [part for part in name.replace("@", " ").split() if part]
    if not parts:
        return "?"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[1][0]).upper()


class _StatCard(QFrame):
    """One bilingual counter: icon badge, value, captions and a share bar."""

    def __init__(self, icon: str, tone: str, en: str, fa: str) -> None:
        super().__init__()
        self.setProperty("class", "card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(10)
        top.addWidget(icon_badge(icon, tone, 34, 17))
        top.addStretch(1)
        self.share = QLabel("")
        self.share.setProperty("class", "subtle")
        top.addWidget(self.share, 0, Qt.AlignTop)
        layout.addLayout(top)

        self.value = QLabel("—")
        self.value.setProperty("class", "statValue")
        layout.addWidget(self.value)

        captions = QHBoxLayout()
        captions.setSpacing(6)
        caption = QLabel(tr(en))
        caption.setProperty("class", "muted")
        caption.setStyleSheet("font-size: 12px; font-weight: 600;")
        captions.addWidget(caption)
        captions.addStretch(1)
        layout.addLayout(captions)

        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        role = _TONE_ROLE[tone]
        on_theme(self.bar, lambda w, p: w.setStyleSheet(
            f"QProgressBar {{ background: {p.surface_hover}; border: none;"
            " border-radius: 2px; min-height: 4px; max-height: 4px; }"
            f"QProgressBar::chunk {{ background: {p.color(role)}; border-radius: 2px; }}"))
        layout.addWidget(self.bar)

    def set_value(self, value: int, total: int, show_share: bool = True) -> None:
        self.value.setText(num(value))
        ratio = (value / total) if total else 0.0
        self.bar.setValue(int(ratio * 1000) if show_share else (1000 if value else 0))
        self.share.setText(tr("{pct}% of total", pct=round(ratio * 100))
                           if show_share and total else "")


class DashboardPage(Page):
    """Overview of the licensing business at a glance (EN + FA)."""

    def _build(self) -> None:
        layout = page_layout(self, spacing=18)

        # --- header: titles + today chip (both calendars) + actions --------
        today = DoranDate.now()
        chip = QFrame()
        chip.setProperty("class", "cardInset")
        chip_row = QHBoxLayout(chip)
        chip_row.setContentsMargins(12, 7, 14, 7)
        chip_row.setSpacing(10)
        chip_row.addWidget(icon_label("calendar", "accent_text", 16))
        dates = QVBoxLayout()
        dates.setSpacing(0)
        jalali_label = QLabel(today.format("dddd D MMMM YYYY", fa=True))
        jalali_label.setLayoutDirection(Qt.RightToLeft)
        jalali_label.setProperty("class", "fa")
        jalali_label.setStyleSheet("font-size: 12px; font-weight: 600;")
        greg_label = QLabel(datetime.now(timezone.utc).strftime("%A, %d %B %Y"))
        greg_label.setProperty("class", "subtle")
        greg_label.setStyleSheet("font-size: 11px;")
        dates.addWidget(jalali_label)
        dates.addWidget(greg_label)
        chip_row.addLayout(dates)
        chip.setToolTip("امروز — هجری شمسی · میلادی" if is_rtl()
                        else "Today — Solar Hijri · Gregorian")
        self.today_chip = chip

        refresh = button("Refresh", "secondary", "refresh",
                         "Reload counters, chart and recent activity (F5)",
                         self.refresh)
        new_serial = button("New serial", None, "plus",
                            "Issue a new serial key (Ctrl+G)",
                            lambda: self.services.navigate("generate"))
        layout.addWidget(page_header(
            "Dashboard",
            "Licensing activity at a glance — counters refresh on every visit.",
            actions=[chip, refresh, new_serial]))

        # --- stat cards -------------------------------------------------------
        cards = QGridLayout()
        cards.setHorizontalSpacing(14)
        cards.setVerticalSpacing(14)
        self.stat_cards: dict[str, _StatCard] = {}
        for column, (key, icon, tone, en, fa) in enumerate(_STAT_CARDS):
            card = _StatCard(icon, tone, en, fa)
            self.stat_cards[key] = card
            cards.addWidget(card, 0, column)
            cards.setColumnStretch(column, 1)
        layout.addLayout(cards)
        # Back-compat handles (tests / scripts read these labels).
        self.lbl_total = self.stat_cards["total"].value
        self.lbl_active = self.stat_cards["active"].value
        self.lbl_expiring = self.stat_cards["expiring"].value
        self.lbl_expired = self.stat_cards["expired"].value
        self.lbl_revoked = self.stat_cards["revoked"].value

        # --- chart + activity ----------------------------------------------
        bottom = QHBoxLayout()
        bottom.setSpacing(14)

        chart_card, chart_layout = make_card(spacing=12)
        self.chart_total = badge("Last 12 months", "accent")
        chart_layout.addWidget(card_header(
            "trending", "Serials issued per month", "Monthly issuance over the last year",
            self.chart_total))
        self.chart = BarChart()
        self.chart.set_accent(self.services.settings.accent)
        chart_layout.addWidget(self.chart, 1)
        bottom.addWidget(chart_card, 3)

        recent_card, recent_layout = make_card(spacing=6)
        view_all = button("View all", "ghost", arrow(),
                          "Open the Serial Manager (Ctrl+3)",
                          lambda: self.services.navigate("manager"))
        # icon after the text: flip the button's own direction
        view_all.setLayoutDirection(Qt.LeftToRight if is_rtl() else Qt.RightToLeft)
        recent_layout.addWidget(card_header(
            "activity", "Recent activity", "Latest issued serials", view_all))
        recent_layout.addSpacing(6)
        self.recent_list = QVBoxLayout()
        self.recent_list.setSpacing(0)
        recent_layout.addLayout(self.recent_list)
        recent_layout.addStretch(1)
        bottom.addWidget(recent_card, 2)

        layout.addLayout(bottom, 1)

    # -------------------------------------------------- data
    def refresh(self) -> None:
        """Load counters, chart and recent serials (worker threads)."""

        def _stats() -> dict:
            return {
                "counts": self.services.db.counts(),
                "histogram": self.services.db.monthly_histogram(12),
                "recent": [(r.customer, r.fingerprint_code, r.issued_at, r.status)
                           for r in self.services.db.list_records()[:6]],
            }

        run_task(self, _stats, self._apply, busy_text="Loading dashboard…")

    def _apply(self, data: dict) -> None:
        counts = data["counts"]
        total = counts["total"]
        self.stat_cards["total"].set_value(total, total, show_share=False)
        self.stat_cards["active"].set_value(
            counts["active"] + counts.get("lifetime", 0), total)
        self.stat_cards["expiring"].set_value(counts.get("expiring", 0), total)
        self.stat_cards["expired"].set_value(counts.get("expired", 0), total)
        self.stat_cards["revoked"].set_value(counts.get("revoked", 0), total)

        self.chart.set_data(data["histogram"])
        self.chart.set_accent(self.services.settings.accent)
        issued_year = sum(value for _, value in data["histogram"])
        self.chart_total.setText(tr("{n} in 12 months", n=issued_year))

        while self.recent_list.count():
            item = self.recent_list.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        if not data["recent"]:
            self.recent_list.addWidget(self._empty_state())
            return
        rows = data["recent"]
        for index, (customer, code, issued_at, status) in enumerate(rows):
            self.recent_list.addWidget(
                self._activity_row(customer, code, issued_at, status,
                                   last=index == len(rows) - 1))

    # -------------------------------------------------- feed rows
    def _activity_row(self, customer: str, code: str, issued_at: int,
                      status: str, last: bool) -> QWidget:
        p = current_palette()
        row_frame = QFrame()
        if not last:
            row_frame.setProperty("class", "listRow")
        row = QHBoxLayout(row_frame)
        row.setContentsMargins(2, 10, 2, 10)
        row.setSpacing(12)

        name = customer or tr("(unnamed)")
        hue = _AVATAR_HUES[zlib.crc32(name.encode("utf-8")) % len(_AVATAR_HUES)]
        avatar = QLabel(_initials(customer) if customer else "?")
        avatar.setObjectName("avatar")
        avatar.setFixedSize(34, 34)
        avatar.setAlignment(Qt.AlignCenter)
        soft = _mix(hue, 0.84 if p.mode == "dark" else 0.88, p.surface)
        fg = _mix(hue, 0.35, "#FFFFFF") if p.mode == "dark" else hue
        avatar.setStyleSheet(f"background: {soft}; color: {fg};")
        row.addWidget(avatar)

        texts = QVBoxLayout()
        texts.setSpacing(1)
        title = QLabel(name)
        title.setProperty("class", "h3")
        if any("؀" <= ch <= "ۿ" for ch in name):
            title.setProperty("class", "fa")
            title.setStyleSheet("font-weight: 600;")
            title.setAlignment(Qt.AlignLeading | Qt.AlignVCenter)
        sub = QLabel(code)
        sub.setLayoutDirection(Qt.LeftToRight)
        sub.setProperty("class", "monoMuted")
        sub.setStyleSheet("font-size: 11px;")
        texts.addWidget(title)
        texts.addWidget(sub)
        row.addLayout(texts, 1)

        en, fa, kind = _STATUS.get(status, (status, status, "neutral"))
        right = QVBoxLayout()
        right.setSpacing(3)
        status_badge = badge(en, kind)
        stamp = datetime.fromtimestamp(issued_at, tz=timezone.utc)
        date_label = QLabel(DoranDate.from_datetime(stamp).format("D MMMM YYYY", fa=True)
                            if is_rtl() else stamp.strftime("%b %d, %Y"))
        date_label.setProperty("class", "subtle")
        date_label.setStyleSheet("font-size: 11px;")
        date_label.setToolTip(stamp.strftime("%Y-%m-%d") if is_rtl() else _jalali(issued_at))
        right.addWidget(status_badge, 0, Qt.AlignTrailing)
        right.addWidget(date_label, 0, Qt.AlignTrailing)
        row.addLayout(right)
        return row_frame

    def _empty_state(self) -> QWidget:
        block = QWidget()
        layout = QVBoxLayout(block)
        layout.setContentsMargins(0, 30, 0, 30)
        layout.setSpacing(8)
        layout.addWidget(icon_badge("inbox", "neutral", 48, 22), 0, Qt.AlignHCenter)
        title = QLabel(tr("No serials yet"))
        title.setProperty("class", "h3")
        title.setAlignment(Qt.AlignCenter)
        hint = QLabel(tr("Issued keys show up here."))
        hint.setProperty("class", "subtle")
        hint.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        layout.addWidget(hint)
        return block


__all__ = ["DashboardPage"]
