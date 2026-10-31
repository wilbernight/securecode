"""
protector.ui.pages.generate — Generate Serial.

The heart of the admin workflow: customer + machine fingerprint + product +
duration -> Ed25519-signed serial key. The form is split into sectioned
cards (customer & product, target machine, validity, advanced options)
with a pinned action bar; the result panel shows the serial, a key/value
summary of the signed payload and copy / save / verify actions. Includes
live fingerprint validation; all crypto runs on worker threads.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from PySide6.QtCore import QDate, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...core.app_paths import SAVE_HINT
from ...core.fingerprint import (
    FingerprintParseError,
    parse_fingerprint,
    platform_display_name,
)
from ...core.jalali import DoranDate
from ...core.serial_factory import SerialRequest, issue_serial, verify_serial
from ..i18n import is_rtl, ltr, tr
from ..theme import bind_pixmap, current_palette
from ..theme.icons import pixmap
from ..widgets.jalali_calendar import JalaliDateEdit
from ..widgets.workers import run_task
from .base import (
    PAGE_MARGINS,
    Page,
    badge,
    button,
    card_header,
    field,
    field_label,
    kv_grid,
    make_card,
    page_header,
    repolish,
    set_badge,
)

#: Duration presets: label, days (0 = lifetime).
_DURATION_ITEMS: list[tuple[str, int]] = [
    ("30 days", 30), ("6 months", 182), ("1 year", 365),
    ("2 years", 730), ("Lifetime", 0), ("Custom date…", -1),
]


class GeneratePage(Page):
    """Serial issuance form + result panel."""

    # -------------------------------------------------- construction
    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(*PAGE_MARGINS)
        outer.setSpacing(18)
        outer.addWidget(page_header(
            "Generate serial",
            "One serial = one machine. The key never leaves this app unsigned."))

        columns = QHBoxLayout()
        columns.setSpacing(18)
        columns.addWidget(self._build_form(), 11)
        columns.addWidget(self._build_output(), 9)
        outer.addLayout(columns, 1)

    def _build_form(self) -> QWidget:
        column = QWidget()
        column_layout = QVBoxLayout(column)
        column_layout.setContentsMargins(0, 0, 0, 0)
        column_layout.setSpacing(12)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        content = QWidget()
        content.setObjectName("scrollContent")
        form = QVBoxLayout(content)
        form.setContentsMargins(0, 0, 6, 0)
        form.setSpacing(14)

        # --- customer & product --------------------------------------------
        card, layout = make_card(spacing=14)
        layout.addWidget(card_header(
            "user", "Customer & product", "Who the key is for and what it unlocks"))
        self.customer = QLineEdit()
        self.customer.setPlaceholderText(tr("e.g. Acme Corp / john@example.com"))
        self.customer.setToolTip("Free-form customer identifier embedded in the signed payload.")
        self.product = QComboBox()
        self.product.setToolTip("Product this serial unlocks (Settings → Products).")
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.addWidget(field("Customer (optional)", self.customer), 0, 0)
        grid.addWidget(field("Product", self.product), 0, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        form.addWidget(card)

        # --- target machine --------------------------------------------------
        card, layout = make_card(spacing=12)
        layout.addWidget(card_header(
            "cpu", "Target machine", "Hardware fingerprint exported by the customer"))
        # Platform the fingerprint was recorded on (set when prefilled from
        # the Fingerprint Reader / loaded from an export file; display-only
        # — the serial payload itself never encodes the platform).
        self._fp_platform = "windows"
        self.fingerprint = QLineEdit()
        self.fingerprint.setObjectName("fingerprintEdit")
        self.fingerprint.setPlaceholderText("XXXX-XXXX-XXXX-XXXX")
        self.fingerprint.setLayoutDirection(Qt.LeftToRight)
        self.fingerprint.setToolTip(
            "Machine code exported by the customer (Fingerprint Reader tab validates it).")
        self.fingerprint.textChanged.connect(self._validate_fingerprint)
        self.fp_load = button("Load file…", "secondary", "folder",
                              "Read a fingerprint.txt exported by the client app.",
                              self._load_fingerprint_file)
        fp_row = QHBoxLayout()
        fp_row.setSpacing(10)
        fp_row.addWidget(self.fingerprint, 1)
        fp_row.addWidget(self.fp_load)
        layout.addWidget(field("Machine code", fp_row))
        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        self.fp_icon = QLabel()
        self.fp_icon.setFixedSize(16, 16)
        self.fp_status = QLabel(tr("Paste or load a fingerprint code."))
        self.fp_status.setProperty("class", "subtle")
        self.fp_status.setWordWrap(True)
        status_row.addWidget(self.fp_icon, 0, Qt.AlignTop)
        status_row.addWidget(self.fp_status, 1)
        layout.addLayout(status_row)
        form.addWidget(card)

        # --- validity ---------------------------------------------------------
        card, layout = make_card(spacing=12)
        layout.addWidget(card_header(
            "calendar", "Validity", "The client blocks after this date"))
        self.duration = QComboBox()
        for label, days in _DURATION_ITEMS:
            self.duration.addItem(tr(label), days)
        self.duration.currentIndexChanged.connect(self._on_duration_changed)
        # Custom expiry is picked on the Solar Hijri (Jalali) calendar — the
        # Doran-core port — with the Gregorian date shown alongside.
        self.expiry_date = JalaliDateEdit()
        self.expiry_date.setDate(QDate.currentDate().addDays(
            int(self.services.settings.get("default_duration_days", 365) or 365)))
        self.expiry_date.setToolTip(
            "Pick the expiry on the Solar Hijri calendar\n"
            "انتخاب تاریخ انقضا در تقویم هجری شمسی")
        self.expiry_date.setVisible(False)
        self.expiry_date.dateChanged.connect(lambda _: self._update_expiry_preview())
        validity = QHBoxLayout()
        validity.setSpacing(10)
        validity.addWidget(self.duration, 1)
        validity.addWidget(self.expiry_date, 1)
        layout.addWidget(field("Duration", validity))
        preview = QHBoxLayout()
        preview.setSpacing(8)
        preview.addWidget(bind_pixmap(QLabel(), "clock", "text_subtle", 14))
        self.expiry_preview = QLabel("")
        self.expiry_preview.setProperty("class", "subtle")
        preview.addWidget(self.expiry_preview, 1)
        layout.addLayout(preview)
        form.addWidget(card)

        # --- advanced -------------------------------------------------------
        card, layout = make_card(spacing=14)
        layout.addWidget(card_header(
            "sliders", "Advanced options", "Tolerance, clock rollbacks, feature flags",
            tone="neutral"))
        self.tolerance = QSpinBox()
        self.tolerance.setRange(0, 3)
        self.tolerance.setValue(int(self.services.settings.get("default_tolerance", 1)))
        self.tolerance.setToolTip(
            "How many hardware components may change/disappear (vs. what was "
            "recorded at activation) before the machine code stops matching.\n"
            "0 = strictest; 1 recommended (survives one component swap).")
        self.rollback = QSpinBox()
        self.rollback.setRange(0, 10)
        self.rollback.setValue(int(self.services.settings.get("default_rollback", 3)))
        self.rollback.setToolTip(
            "Number of tolerated system-clock rollbacks (24h grace each) before "
            "the client blocks with a clock-tampering error.")
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.addWidget(field("Fingerprint tolerance", self.tolerance,
                             "Components allowed to change (1 recommended)"), 0, 0)
        grid.addWidget(field("Rollback allowance", self.rollback,
                             "Clock rollbacks tolerated (24h grace each)"), 0, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)

        # --- feature flags editor --------------------------------------------
        flags_head = QHBoxLayout()
        flags_head.setSpacing(6)
        flags_texts = QVBoxLayout()
        flags_texts.setSpacing(1)
        flags_texts.addWidget(field_label("Feature flags"))
        flags_hint = QLabel(tr("Embedded in the payload; the client enables modules from them."))
        flags_hint.setProperty("class", "subtle")
        flags_texts.addWidget(flags_hint)
        flags_head.addLayout(flags_texts, 1)
        flags_head.addWidget(button("Add", "ghost", "plus", "Add a feature flag",
                                    lambda: self._add_flag()))
        flags_head.addWidget(button("Remove", "ghost", "trash",
                                    "Remove the selected flag rows", self._remove_flag,
                                    icon_role="text_muted"))
        layout.addLayout(flags_head)
        self.flags_table = QTableWidget(0, 2)
        self.flags_table.setHorizontalHeaderLabels([tr("MODULE"), tr("ENABLED")])
        header = self.flags_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.resizeSection(1, 90)
        header.setDefaultAlignment(Qt.AlignLeading | Qt.AlignVCenter)
        self.flags_table.verticalHeader().setVisible(False)
        self.flags_table.verticalHeader().setDefaultSectionSize(36)
        self.flags_table.setShowGrid(False)
        self.flags_table.setMinimumHeight(118)
        self.flags_table.setMaximumHeight(150)
        self.flags_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table_frame = QFrame()
        table_frame.setObjectName("tableFrame")
        frame_layout = QVBoxLayout(table_frame)
        frame_layout.setContentsMargins(1, 1, 1, 1)
        frame_layout.addWidget(self.flags_table)
        layout.addWidget(table_frame)

        self.notes = QTextEdit()
        self.notes.setPlaceholderText(tr("Internal notes stored encrypted in the database "
                                          "(never leaves this app)."))
        self.notes.setFixedHeight(72)
        layout.addWidget(field("Notes", self.notes))
        form.addWidget(card)
        form.addStretch(1)

        scroll.setWidget(content)
        column_layout.addWidget(scroll, 1)

        # --- pinned action bar ----------------------------------------------
        bar = QFrame()
        bar.setObjectName("actionBar")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(16, 12, 12, 12)
        bar_layout.setSpacing(10)
        bar_layout.addWidget(bind_pixmap(QLabel(), "lock", "text_subtle", 15))
        self.sign_hint = QLabel("")
        self.sign_hint.setProperty("class", "subtle")
        bar_layout.addWidget(self.sign_hint, 1)
        self.issue_btn = button("Issue serial key", None, "key",
                                "Sign the payload with the keystore's Ed25519 key (Ctrl+G).",
                                self._issue)
        self.issue_btn.setProperty("size", "lg")
        bar_layout.addWidget(self.issue_btn)
        column_layout.addWidget(bar)
        return column

    def _build_output(self) -> QWidget:
        card, layout = make_card(spacing=14)
        self.result_badge = badge("Waiting", "neutral")
        layout.addWidget(card_header(
            "key", "Result", "Deliver the serial through any channel",
            self.result_badge))

        self.serial_view = QPlainTextEdit()
        self.serial_view.setObjectName("serialView")
        self.serial_view.setReadOnly(True)
        self.serial_view.setLayoutDirection(Qt.LeftToRight)
        self.serial_view.setPlaceholderText(tr(
            "The generated serial key appears here — copy or save it, then "
            "deliver it to the customer."))
        layout.addWidget(self.serial_view, 1)

        details, self.details = kv_grid([
            ("record", "Record"), ("customer", "Customer"),
            ("expires", "Expires"), ("expires_fa", "Expires (Solar Hijri)"),
            ("machine", "Machine code"), ("nonce", "Nonce"),
        ])
        layout.addWidget(details)

        self.payload_view = QLabel("")
        self.payload_view.setProperty("class", "subtle")
        self.payload_view.setWordWrap(True)
        self.payload_view.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.payload_view.setVisible(False)
        layout.addWidget(self.payload_view)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.copy_btn = button("Copy", "secondary", "copy",
                               "Copy the serial to the clipboard.", self._copy)
        self.save_btn = button("Save .lic", "secondary", "download",
                               "Save the serial as a .lic text file for delivery.", self._save)
        self.verify_btn = button("Verify", "secondary", "shield-check",
                                 "Re-parse and re-verify the signature — exactly what "
                                 "the client does.", self._verify)
        for btn in (self.copy_btn, self.save_btn, self.verify_btn):
            btn.setEnabled(False)
            actions.addWidget(btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        note = QFrame()
        note.setProperty("class", "note")
        note_layout = QHBoxLayout(note)
        note_layout.setContentsMargins(12, 10, 12, 10)
        note_layout.setSpacing(10)
        note_layout.addWidget(bind_pixmap(QLabel(), "info", "info", 16), 0, Qt.AlignTop)
        hint = QLabel(tr(
            "The serial is hardware-locked to the machine code and valid for "
            "the selected period. It works fully offline — no activation "
            "server is ever contacted."))
        hint.setWordWrap(True)
        hint.setProperty("class", "muted")
        hint.setStyleSheet("font-size: 12px;")
        note_layout.addWidget(hint, 1)
        layout.addWidget(note)
        return card

    # -------------------------------------------------- lifecycle
    def refresh(self) -> None:
        """Reload the product combo + defaults from settings."""
        self.product.blockSignals(True)
        self.product.clear()
        for product in self.services.settings.products():
            self.product.addItem(
                f"{product['name']}  ·  v{product.get('version', '')}", product["id"])
        self.product.blockSignals(False)
        default_id = self.services.settings.get("default_product_id", "")
        index = self.product.findData(default_id)
        if index >= 0:
            self.product.setCurrentIndex(index)
        if self.flags_table.rowCount() == 0:
            for name, enabled in (self.services.settings.get(
                    "default_feature_flags", {}) or {}).items():
                self._add_flag(name, enabled)
        self.sign_hint.setText(tr("Signed with Ed25519 key {key}",
                                  key=ltr(self.services.keystore.key_id or "—")))
        self._validate_fingerprint()
        self._update_expiry_preview()

    def prefill(self, fingerprint: str, customer: str | None = None,
                platform: str = "windows") -> None:
        """Called by the shell when jumping here from the Fingerprint Reader."""
        self._fp_platform = platform
        self.fingerprint.setText(fingerprint.replace("-", "").upper())
        if customer:
            self.customer.setText(customer)
        self._validate_fingerprint()

    # -------------------------------------------------- handlers
    def _on_duration_changed(self) -> None:
        custom = self.duration.currentData() == -1
        self.expiry_date.setVisible(custom)
        self._update_expiry_preview()

    def _update_expiry_preview(self) -> None:
        days = self.duration.currentData()
        if days == 0:
            self.expiry_preview.setText(tr("Never expires"))
            return
        if days == -1:
            qdate = self.expiry_date.date()
            target = datetime(qdate.year(), qdate.month(), qdate.day(), tzinfo=timezone.utc)
        else:
            target = datetime.now(timezone.utc) + timedelta(days=int(days or 0))
        jalali = DoranDate.from_datetime(target).format("D MMMM YYYY", fa=True)
        stamp = (f"{jalali}  ·  {ltr(target.strftime('%Y-%m-%d'))}" if is_rtl()
                 else f"{target.strftime('%d %B %Y')}  ·  {jalali}")
        self.expiry_preview.setText(tr("Expires on {date}", date=stamp))

    def _set_fp_state(self, state: str, text: str) -> None:
        p = current_palette()
        icon, role = {"ok": ("check-circle", "success"), "bad": ("x-circle", "danger"),
                      "idle": ("info", "text_subtle")}[state]
        self.fp_icon.setPixmap(pixmap(icon, p.color(role), 16))
        self.fp_status.setText(text)
        self.fp_status.setProperty("tone", {"ok": "success", "bad": "danger"}.get(state, ""))
        self.fingerprint.setProperty("invalid", state == "bad")
        self.fingerprint.setProperty("valid", state == "ok")
        repolish(self.fp_status)
        repolish(self.fingerprint)

    def _validate_fingerprint(self) -> None:
        text = self.fingerprint.text().strip()
        if not text:
            self._set_fp_state("idle", tr("Paste or load a fingerprint code."))
            return
        try:
            info = parse_fingerprint(text, self._fp_platform)
        except FingerprintParseError as exc:
            self._set_fp_state("bad", tr("Invalid code — {msg}", msg=exc.user_message))
            return
        components = ", ".join(info.present_names) or "no components"
        missing = f" — missing: {', '.join(info.missing_names)}" if info.missing_names else ""
        self._set_fp_state("ok", tr("Valid machine code ({info})",
                                    info=f"{platform_display_name(self._fp_platform)}"
                                        f" · {components}{missing}"))

    @staticmethod
    def _repolish(widget: QWidget) -> None:
        repolish(widget)

    def _load_fingerprint_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open fingerprint export", str(SAVE_HINT),
            "Fingerprint exports (*.txt);;All files (*)")
        if not path:
            return
        try:
            from ...core.fingerprint import read_fingerprint_file
            info = read_fingerprint_file(path)
        except FingerprintParseError as exc:
            QMessageBox.warning(self, "Invalid file", exc.user_message)
            return
        self._fp_platform = info.platform
        self.fingerprint.setText(info.code)

    def _add_flag(self, name: str = "", enabled: bool = True) -> None:
        if not name:
            name, ok = QInputDialog.getText(
                self, tr("Add feature flag"),
                tr("Module/feature name (e.g. 'pro_module', 'export_pdf'):"))
            if not ok or not name.strip():
                return
            name = name.strip()
        for r in range(self.flags_table.rowCount()):
            if self.flags_table.item(r, 0).text() == name:
                return
        row_index = self.flags_table.rowCount()
        self.flags_table.insertRow(row_index)
        self.flags_table.setItem(row_index, 0, QTableWidgetItem(name))
        checkbox = QCheckBox()
        checkbox.setChecked(bool(enabled))
        checkbox.setStyleSheet("QCheckBox { padding-left: 12px; }")
        self.flags_table.setCellWidget(row_index, 1, checkbox)

    def _remove_flag(self) -> None:
        selected = self.flags_table.selectionModel().selectedRows()
        for index in sorted(selected, reverse=True):
            self.flags_table.removeRow(index.row())

    def _collect_flags(self) -> dict[str, bool]:
        flags = {}
        for r in range(self.flags_table.rowCount()):
            name_item = self.flags_table.item(r, 0)
            widget = self.flags_table.cellWidget(r, 1)
            if name_item is None or widget is None:
                continue
            flags[name_item.text()] = widget.isChecked()
        return flags

    # -------------------------------------------------- issuance
    def _issue(self) -> None:
        try:
            code_info = parse_fingerprint(self.fingerprint.text(),
                                         self._fp_platform)
        except FingerprintParseError:
            self.services.toast.show(
                "warning", "Invalid fingerprint",
                "Paste a valid 16-character machine code first.")
            return
        if self.product.currentData() is None:
            self.services.toast.show(
                "warning", "No product", "Add a product in Settings first.")
            return

        days = self.duration.currentData()
        expires_at = None
        if days == -1:
            expires_at = int(
                self.expiry_date.dateTime().toSecsSinceEpoch())
            if expires_at <= int(time.time()):
                self.services.toast.show(
                    "warning", "Invalid date", "Custom expiry must be in the future.")
                return

        request = SerialRequest(
            customer=self.customer.text().strip(),
            fingerprint=code_info.code,
            product_id=self.product.currentData(),
            duration_days=days if days != -1 else 365,
            expires_at=expires_at,
            feature_flags=self._collect_flags(),
            tolerance=self.tolerance.value(),
            rollback_allowance=self.rollback.value(),
        )
        keystore, db = self.services.keystore, self.services.db
        notes = self.notes.toPlainText().strip()

        def _work() -> dict:
            issued = issue_serial(request, keystore.sign)
            record_id = db.add_serial(issued.serial, issued.payload, notes)
            return {"record_id": record_id, "issued": issued}

        run_task(self, _work, self._issued, busy_text="Signing serial…")

    def _issued(self, result: dict) -> None:
        issued = result["issued"]
        payload = issued.payload
        self.serial_view.setPlainText(issued.serial)
        if payload.is_lifetime:
            exp, exp_fa = tr("Lifetime"), "همیشگی"
        else:
            exp_dt = datetime.fromtimestamp(payload.expires_at, tz=timezone.utc)
            exp = exp_dt.strftime("%d %b %Y")
            exp_fa = DoranDate.from_datetime(exp_dt).format("D MMMM YYYY", fa=True)
        for key, value in (
            ("record", f"#{result['record_id']}"),
            ("customer", payload.customer or tr("(unnamed)")),
            ("expires", exp), ("expires_fa", exp_fa),
            ("machine", payload.fingerprint), ("nonce", payload.nonce[:16] + "…"),
        ):
            self.details[key].setText(value)
        self.details["expires_fa"].setProperty("class", "fa")
        repolish(self.details["expires_fa"])
        self.payload_view.setVisible(False)
        set_badge(self.result_badge, "Signed", "success")
        for btn in (self.copy_btn, self.save_btn, self.verify_btn):
            btn.setEnabled(True)
        self.services.toast.show(
            "success", "Serial issued",
            tr("Record #{id} stored in the encrypted database.", id=result["record_id"]))
        self.services.refresh_all()

    # -------------------------------------------------- output actions
    def _copy(self) -> None:
        serial = self.serial_view.toPlainText().strip()
        if not serial:
            return
        QGuiApplication.clipboard().setText(serial)
        self.services.toast.show("success", "Copied", "Serial copied to clipboard.")

    def _save(self) -> None:
        serial = self.serial_view.toPlainText().strip()
        if not serial:
            return
        safe_customer = self.customer.text().strip().replace(" ", "_") or "serial"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save serial key", f"{safe_customer}.lic",
            "License key (*.lic);;All files (*)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(serial + "\n")
        self.services.toast.show("success", "Saved", f"Serial written to {path}")

    def _verify(self) -> None:
        serial = self.serial_view.toPlainText().strip()
        if not serial:
            return

        def _work() -> str:
            payload = verify_serial(serial, self.services.keystore.public_key)
            return "   ·   ".join(f"{k}: {v}" for k, v in [
                ("Signature", "valid (Ed25519)"),
                ("Issued", datetime.fromtimestamp(
                    payload.issued_at, tz=timezone.utc).strftime("%Y-%m-%d")),
                ("Expires", "lifetime" if payload.is_lifetime else
                    datetime.fromtimestamp(payload.expires_at, tz=timezone.utc)
                    .strftime("%Y-%m-%d")),
                ("Flags", ", ".join(k for k, v in (payload.feature_flags or {}).items() if v)
                 or "—"),
            ])

        def _verified(text: str) -> None:
            self.payload_view.setText(text)
            self.payload_view.setVisible(True)
            set_badge(self.result_badge, "Verified", "info")
            self.services.toast.show(
                "success", "Signature valid",
                "The serial verifies against the active public key.")

        def _rejected(message: str) -> None:
            set_badge(self.result_badge, "Invalid", "danger")
            self.services.toast.show("error", "Verification failed", message)

        run_task(self, _work, _verified, _rejected, busy_text="Verifying…")


__all__ = ["GeneratePage"]
