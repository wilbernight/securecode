"""
protector.ui.pages.manager — Serial Manager.

Table of every issued serial (from the encrypted SQLite store) with:
    * search (customer / machine code / serial text) with a live result count
    * status filter (active / expiring / expired / revoked) + product filter
    * color-coded status column (tinted dot + label) and an empty state
    * row actions: revoke/restore, extend (re-sign with new validity),
      export/copy serial, delete, issue machine-transfer permit
    * signed blacklist export (distribute as blacklist.sec to customers)
Data loads and crypto actions run on worker threads.
"""

from __future__ import annotations

from datetime import datetime, timezone

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.app_paths import SAVE_HINT
from ...core.jalali import DoranDate
from ...core.serial_factory import (
    SerialRequest,
    build_blacklist,
    build_transfer_permit,
    issue_serial,
)
from ..i18n import digits, is_rtl, tr
from ..theme import current_palette, make_mono_font
from ..theme.icons import icon as make_icon
from ..theme.icons import pixmap
from ..widgets.workers import run_task
from .base import (
    Page,
    badge,
    button,
    card_header,
    divider,
    icon_badge,
    icon_label,
    kv_grid,
    make_card,
    page_header,
    page_layout,
)

#: status -> (English label, palette role, badge kind)
_STATUS = {
    "active": ("Active", "success", "success"),
    "expiring": ("Expiring", "warning", "warning"),
    "expired": ("Expired", "danger", "danger"),
    "revoked": ("Revoked", "text_subtle", "neutral"),
    "lifetime": ("Lifetime", "info", "info"),
}

_COLUMNS = ["STATUS", "CUSTOMER", "PRODUCT", "MACHINE CODE", "ISSUED",
            "EXPIRES", "DAYS", "NONCE"]


def _date(timestamp: int) -> str:
    stamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    if is_rtl():
        return DoranDate.from_datetime(stamp).format("YYYY/MM/DD", fa=True)
    return stamp.strftime("%Y-%m-%d")


class SerialDetailDialog(QDialog):
    """Read-only record detail with copyable serial."""

    def __init__(self, record, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        name = record.customer or tr("(unnamed)")
        self.setWindowTitle(f"#{record.id} — {name}")
        self.setMinimumWidth(600)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(16)

        label, _, kind = _STATUS.get(record.status, (record.status, "", "neutral"))
        layout.addWidget(card_header("key", name, f"#{record.id} · {record.product_id}",
                                     badge(label, kind)))
        layout.addWidget(divider())

        exp = tr("lifetime") if record.expires_at == 0 else _date(record.expires_at)
        grid, values = kv_grid([
            ("machine", "Machine code"), ("issued", "Issued"),
            ("expires", "Expires"), ("nonce", "Nonce"),
            ("tol", "Tolerance / rollbacks"), ("flags", "Feature flags"),
        ])
        values["machine"].setText(record.fingerprint_code)
        values["issued"].setText(_date(record.issued_at))
        values["expires"].setText(exp)
        values["nonce"].setText(record.nonce)
        values["tol"].setText(digits(f"{record.tolerance} / {record.rollback_allowance}"))
        values["flags"].setText(", ".join(k for k, v in (record.flags or {}).items() if v)
                                or "—")
        layout.addWidget(grid)
        if record.notes:
            notes = QLabel(record.notes)
            notes.setProperty("class", "muted")
            notes.setWordWrap(True)
            layout.addWidget(notes)

        serial_box = QPlainTextEdit(record.serial)
        serial_box.setObjectName("serialView")
        serial_box.setLayoutDirection(Qt.LeftToRight)
        serial_box.setReadOnly(True)
        serial_box.setFixedHeight(96)
        layout.addWidget(serial_box)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(button(
            "Copy serial", "secondary", "copy", None,
            lambda: QGuiApplication.clipboard().setText(record.serial)))
        buttons.addWidget(button("Close", None, None, None, self.accept))
        layout.addLayout(buttons)


class EditCustomerDialog(QDialog):
    """Rename a serial record — optionally re-signing the serial.

    The customer name lives in two places: the (encrypted) DB row and the
    Ed25519-signed payload inside the serial the customer holds. Renaming
    the record fixes the admin's bookkeeping; re-issuing additionally
    bakes the new name into a fresh serial the customer must re-activate
    with (expiry, machine binding and flags are preserved).
    """

    def __init__(self, record, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Edit customer name"))
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)

        layout.addWidget(card_header(
            "user", record.customer or tr("(unnamed)"),
            f"#{record.id} · {record.fingerprint_code}"))

        caption = QLabel(tr("Customer name"))
        caption.setProperty("class", "muted")
        layout.addWidget(caption)
        self.name_edit = QLineEdit(record.customer)
        self.name_edit.setObjectName("nameEdit")
        self.name_edit.selectAll()
        layout.addWidget(self.name_edit)

        self.reissue = QCheckBox(tr(
            "Re-issue the serial with the new name"))
        layout.addWidget(self.reissue)

        hint = QLabel(tr(
            "Without re-issuing, only your records change — the name shown "
            "inside the customer's app keeps the old value. Re-issuing keeps "
            "the same expiry and machine binding, and puts the new serial in "
            "your clipboard."))
        hint.setProperty("class", "muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(button("Close", "secondary", None, None, self.reject))
        buttons.addWidget(button("Save", None, "check", None, self.accept))
        layout.addLayout(buttons)


class ManagerPage(Page):
    """Serial table + toolbar + row actions."""

    def _build(self) -> None:
        layout = page_layout(self, spacing=16)
        self._last_records: list = []

        layout.addWidget(page_header(
            "Serial Manager",
            "Every key ever issued — stored AES-256-GCM encrypted on this machine.",
            actions=[button(
                "Export signed blacklist", None, "file",
                "Writes blacklist.sec containing every revoked nonce. Distribute it "
                "to customers (any offline channel) — clients verify its signature.",
                self._export_blacklist)]))

        card, card_layout = make_card(spacing=14)

        # --- toolbar ---------------------------------------------------------
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)
        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("Search customer, machine code or serial…"))
        self.search.setClearButtonEnabled(True)
        self._search_action = self.search.addAction(
            make_icon("search", current_palette().text_subtle, 16),
            QLineEdit.LeadingPosition)
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(220)
        self._debounce.timeout.connect(self._schedule_reload)
        self.search.textChanged.connect(lambda _: self._debounce.start())
        self.status_filter = QComboBox()
        self.status_filter.addItem(tr("All statuses"), "all")
        for status, key in (("Active", "active"), ("Expiring", "expiring"),
                            ("Expired", "expired"), ("Revoked", "revoked")):
            self.status_filter.addItem(tr(status), key)
        self.status_filter.setMinimumWidth(150)
        self.status_filter.currentIndexChanged.connect(self._schedule_reload)
        self.product_filter = QComboBox()
        self.product_filter.setMinimumWidth(180)
        self.product_filter.currentIndexChanged.connect(self._schedule_reload)
        refresh = button("", "iconOnly", "refresh", "Refresh", self.refresh)
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.status_filter)
        toolbar.addWidget(self.product_filter)
        toolbar.addWidget(refresh)
        card_layout.addLayout(toolbar)

        # --- table / empty state -------------------------------------------------
        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels([tr(c) for c in _COLUMNS])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setSortingEnabled(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(42)
        self.table.doubleClicked.connect(self._open_detail)
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeading | Qt.AlignVCenter)
        header.setHighlightSections(False)
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)

        table_frame = QFrame()
        table_frame.setObjectName("tableFrame")
        frame_layout = QVBoxLayout(table_frame)
        frame_layout.setContentsMargins(1, 1, 1, 1)
        frame_layout.addWidget(self.table)

        self.views = QStackedWidget()
        self.views.addWidget(table_frame)
        self.views.addWidget(self._empty_state())
        card_layout.addWidget(self.views, 1)

        # --- actions row -------------------------------------------------------
        actions = QHBoxLayout()
        actions.setSpacing(8)
        for text, variant, icon, slot, tip in (
            ("Revoke / Restore", "secondary", "ban", self._toggle_revoke,
             "Toggle the revocation flag; revoked nonces go into the blacklist."),
            ("Extend…", "secondary", "clock", self._extend,
             "Re-sign the serial with a new validity period (same machine binding)."),
            ("Transfer permit…", "secondary", "transfer", self._transfer_permit,
             "Issue the signed permit that removes the license from the OLD machine."),
            ("Edit name…", "secondary", "user", self._edit_customer,
             "Correct the customer name — optionally re-issue the serial so the "
             "new name shows inside the customer's app."),
            ("Copy serial", "secondary", "copy", self._copy_serial,
             "Copy the selected record's serial key."),
            ("Export .lic", "secondary", "download", self._export_serial,
             "Save the selected serial as .lic."),
        ):
            actions.addWidget(button(text, variant, icon, tip, slot))
        actions.addStretch(1)
        self.count_label = QLabel("")
        self.count_label.setProperty("class", "subtle")
        actions.addWidget(self.count_label)
        actions.addSpacing(8)
        actions.addWidget(button("Delete", "danger", "trash",
                                 "Permanently delete the record (cannot be undone).",
                                 self._delete))
        card_layout.addLayout(actions)
        layout.addWidget(card, 1)

    def _empty_state(self) -> QWidget:
        block = QWidget()
        layout = QVBoxLayout(block)
        layout.setSpacing(8)
        layout.addStretch(1)
        layout.addWidget(icon_badge("inbox", "neutral", 56, 26), 0, Qt.AlignHCenter)
        title = QLabel(tr("No serials match"))
        title.setProperty("class", "h2")
        title.setAlignment(Qt.AlignCenter)
        hint = QLabel(tr("Try another search or filter, or issue a new serial."))
        hint.setProperty("class", "subtle")
        hint.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        layout.addWidget(hint)
        layout.addSpacing(6)
        layout.addWidget(button("New serial", None, "plus", None,
                                lambda: self.services.navigate("generate")),
                         0, Qt.AlignHCenter)
        layout.addStretch(1)
        return block

    # -------------------------------------------------- data
    def refresh(self) -> None:
        """Reload product filter + records (worker thread)."""
        current = self.product_filter.currentData()
        self.product_filter.blockSignals(True)
        self.product_filter.clear()
        self.product_filter.addItem(tr("All products"), "")
        for product in self.services.settings.products():
            self.product_filter.addItem(product["name"], product["id"])
        index = self.product_filter.findData(current)
        self.product_filter.setCurrentIndex(max(0, index))
        self.product_filter.blockSignals(False)
        self._search_action.setIcon(make_icon("search", current_palette().text_subtle, 16))
        self._schedule_reload()

    def _schedule_reload(self) -> None:
        run_task(self, self._load_records, self._fill_table,
                 busy_text="Loading serials…")

    def _load_records(self) -> list:
        return self.services.db.list_records(
            search=self.search.text(),
            status=self.status_filter.currentData() or "all",
            product_id=self.product_filter.currentData() or "",
        )

    def _fill_table(self, records: list) -> None:
        p = current_palette()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self._last_records = list(records)
        mono = make_mono_font(9)
        bold = QFont(self.font())
        bold.setWeight(QFont.DemiBold)
        for record in records:
            row = self.table.rowCount()
            self.table.insertRow(row)
            label, role, _ = _STATUS.get(record.status, (record.status, "text_subtle", ""))
            expires = tr("lifetime") if record.expires_at == 0 else _date(record.expires_at)
            days = "∞" if record.days_left is None else digits(str(record.days_left))
            values = [
                tr(label),
                record.customer or tr("(unnamed)"),
                self._product_name(record.product_id),
                record.fingerprint_code,
                _date(record.issued_at),
                expires,
                days,
                record.nonce[:8] + "…",
            ]
            for column, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                if column == 0:
                    item.setIcon(make_icon("dot", p.color(role), 12))
                    item.setForeground(QColor(p.color(role)))
                    item.setFont(bold)
                    item.setToolTip(record.status)
                elif column == 1:
                    item.setFont(bold)
                elif column in (3, 7):
                    item.setFont(mono)
                    item.setForeground(QColor(p.text_muted))
                elif column == 6 and record.days_left is not None and record.days_left < 30:
                    item.setForeground(QColor(p.warning if record.days_left >= 0 else p.danger))
                self.table.setItem(row, column, item)
        self.table.setSortingEnabled(True)
        self.table.resizeColumnsToContents()
        for column in range(self.table.columnCount() - 1):
            self.table.setColumnWidth(column, self.table.columnWidth(column) + 22)
        self.views.setCurrentIndex(0 if records else 1)
        self.count_label.setText(tr("{n} serials", n=len(records)))

    def _product_name(self, product_id: str) -> str:
        for product in self.services.settings.products():
            if product["id"] == product_id:
                return product["name"]
        return product_id[:13] + "…"

    # -------------------------------------------------- selection helpers
    def _record_for_row(self, row: int):
        """Map a table row back to a record via its unique nonce prefix
        (rows move under sorting, nonce prefixes do not)."""
        nonce_item = self.table.item(row, 7)
        if nonce_item is None:
            return None
        prefix = nonce_item.text()
        for record in getattr(self, "_last_records", []):
            if record.nonce.startswith(prefix.rstrip("…")):
                return record
        return None

    def _selected_record(self):
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            self.services.toast.show("info", "No selection",
                                     "Select a serial row first.")
            return None
        return self._record_for_row(indexes[0].row())

    # -------------------------------------------------- actions
    def _open_detail(self, index) -> None:
        record = self._record_for_row(index.row())
        if record is not None:
            SerialDetailDialog(record, self).exec()

    def _toggle_revoke(self) -> None:
        record = self._selected_record()
        if record is None:
            return
        new_state = not record.revoked

        def _work() -> None:
            self.services.db.set_revoked(record.id, new_state)

        name = record.customer or tr("(unnamed)")
        if is_rtl():
            title = "ابطال سریال" if new_state else "بازگردانی سریال"
            question = (f"سریال «{name}» ابطال شود؟" if new_state
                        else f"سریال «{name}» بازگردانی شود؟")
        else:
            verb = "revoke" if new_state else "restore"
            title = f"{verb.capitalize()} serial"
            question = f"Really {verb} the serial of “{name}”?"
        confirm = QMessageBox.question(self, title, question)
        if confirm != QMessageBox.Yes:
            return
        run_task(self, _work,
                 lambda _: (
                     self.services.toast.show(
                         "success", "Serial " + ("revoked" if new_state else "restored"),
                         "Remember to export and distribute the updated blacklist."),
                     self._schedule_reload(),
                     self.services.refresh_all()),
                 busy_text="Updating…")

    def _extend(self) -> None:
        record = self._selected_record()
        if record is None:
            return
        days, ok = QInputDialog.getInt(
            self, "Extend serial",
            "New validity from today (days; 0 = lifetime):",
            365, 0, 36500, 1)
        if not ok:
            return

        def _work() -> str:
            request = SerialRequest(
                customer=record.customer,
                fingerprint=record.fingerprint_code,
                product_id=record.product_id,
                duration_days=days,
                feature_flags=record.flags,
                tolerance=record.tolerance,
                rollback_allowance=record.rollback_allowance,
            )
            issued = issue_serial(request, self.services.keystore.sign)
            self.services.db.replace_serial(record.id, issued.serial, issued.payload)
            return issued.serial

        run_task(self, _work,
                 lambda serial: (
                     QGuiApplication.clipboard().setText(serial),
                     self.services.toast.show(
                         "success", "Serial extended",
                         "The re-signed serial is in your clipboard — deliver it to the customer."),
                     self._schedule_reload()),
                 busy_text="Re-signing…")

    def _edit_customer(self) -> None:
        """Correct the customer name of the selected record.

        DB-only fix by default; with the re-issue checkbox the serial is
        re-signed with the new name (same expiry, machine binding, flags
        and tolerance) and copied to the clipboard for delivery.
        """
        record = self._selected_record()
        if record is None:
            return
        dialog = EditCustomerDialog(record, self)
        if dialog.exec() != QDialog.Accepted:
            return
        new_name = dialog.name_edit.text().strip()
        reissue = dialog.reissue.isChecked()

        def _work() -> str | None:
            self.services.db.update_customer(record.id, new_name)
            if not reissue:
                return None
            request = SerialRequest(
                customer=new_name,
                fingerprint=record.fingerprint_code,
                product_id=record.product_id,
                expires_at=record.expires_at,  # 0 keeps lifetime; ts keeps date
                feature_flags=record.flags,
                tolerance=record.tolerance,
                rollback_allowance=record.rollback_allowance,
            )
            issued = issue_serial(request, self.services.keystore.sign)
            self.services.db.replace_serial(record.id, issued.serial, issued.payload)
            return issued.serial

        def _done(serial: str | None) -> None:
            if serial:
                QGuiApplication.clipboard().setText(serial)
                self.services.toast.show(
                    "success", tr("Name updated"),
                    tr("The re-signed serial is in your clipboard — deliver it to the customer."))
            else:
                self.services.toast.show("success", tr("Name updated"), "")
            self._schedule_reload()

        run_task(self, _work, _done, busy_text="Saving…")

    def _transfer_permit(self) -> None:
        record = self._selected_record()
        if record is None:
            return
        new_code, ok = QInputDialog.getText(
            self, "Machine transfer",
            "Machine code of the NEW computer (from its fingerprint export):")
        if not ok or not new_code.strip():
            return

        def _work() -> str:
            return build_transfer_permit(
                record.nonce, new_code.strip().upper(),
                self.services.keystore.sign,
                note=f"Transfer of {record.customer or '(unnamed)'}")

        def _done(permit: str) -> None:
            path, _ = QFileDialog.getSaveFileName(
                self, "Save transfer permit", "transfer_permit.sec",
                "Permit file (*.sec);;All files (*)")
            if not path:
                return
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(permit)
            self.services.toast.show(
                "success", "Permit saved",
                "The customer runs 'Deactivate with vendor permit' on the OLD machine.")

        run_task(self, _work, _done, busy_text="Signing permit…")

    def _copy_serial(self) -> None:
        record = self._selected_record()
        if record is None:
            return
        QGuiApplication.clipboard().setText(record.serial)
        self.services.toast.show("success", "Copied", "Serial key copied.")

    def _export_serial(self) -> None:
        record = self._selected_record()
        if record is None:
            return
        safe = (record.customer or "serial").replace(" ", "_")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export serial", f"{safe}.lic", "License key (*.lic);;All files (*)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(record.serial + "\n")
        self.services.toast.show("success", "Exported", f"Serial saved to {path}")

    def _delete(self) -> None:
        record = self._selected_record()
        if record is None:
            return
        confirm = QMessageBox.warning(
            self, tr("Delete"),
            (f"سریال «{record.customer or tr('(unnamed)')}» برای همیشه حذف شود؟\n"
             "کلید تا زمان انقضا روی سیستم مشتری کار می‌کند — برای از کار انداختن، "
             "آن را ابطال و لیست سیاه را توزیع کنید.") if is_rtl() else
            (f"Permanently delete the serial of “{record.customer or '(unnamed)'}”?\n"
             "The key keeps working on the customer machine until expiry — to "
             "kill it, revoke instead and distribute the blacklist."),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return

        def _work() -> None:
            self.services.db.delete_record(record.id)

        run_task(self, _work,
                 lambda _: (self.services.toast.show("success", "Deleted", ""),
                            self._schedule_reload(), self.services.refresh_all()),
                 busy_text="Deleting…")

    def _export_blacklist(self) -> None:
        nonces = self.services.db.revocation_nonces()
        if not nonces:
            self.services.toast.show(
                "info", "Nothing to export", "No serial is currently revoked.")
            return

        def _work() -> str:
            return build_blacklist(nonces, self.services.keystore.sign)

        def _done(content: str) -> None:
            path, _ = QFileDialog.getSaveFileName(
                self, "Export blacklist", "blacklist.sec",
                "Blacklist file (*.sec);;All files (*)")
            if not path:
                return
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
            self.services.toast.show(
                "success", "Blacklist exported",
                f"{len(nonces)} revoked nonce(s). Ship it next to the customer EXE "
                "or into %PROGRAMDATA%\\SecureCode\\<Product>.")

        run_task(self, _work, _done, busy_text="Signing blacklist…")


__all__ = ["ManagerPage", "SerialDetailDialog", "EditCustomerDialog"]
