"""
protector.ui.pages.settings_page — Settings.

Sections:
    * Keystore — key fingerprint, passphrase change, encrypted private-key
      export/import (AES-256-GCM wrapped), keypair regeneration (guarded)
    * Products — the product catalog the Generate page offers
    * Appearance — light/dark preview tiles, accent swatches, EN/FA language
    * Data — encrypted full backup / restore of the license database
"""

from __future__ import annotations

import uuid

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QGuiApplication, QPainter, QPen
from PySide6.QtWidgets import (
    QButtonGroup,
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
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.app_paths import DEMO_KEYPAIR_FILE, SAVE_HINT
from ...core.crypto_engine import KeystoreError, WrongPassphraseError
from ...core.db import DBError
from ...core.settings import DEMO_PRODUCT
from ..i18n import LANGUAGES, is_rtl, language, tr
from ..theme import (
    ACCENT_PRESETS,
    DEFAULT_ACCENT,
    current_palette,
    make_mono_font,
    make_palette,
    on_theme,
)
from ..theme.icons import pixmap
from ..widgets.workers import run_task
from .base import (
    Page,
    badge,
    button,
    card_header,
    field_label,
    icon_label,
    make_card,
    page_header,
    scroll_layout,
)


class _ThemeTile(QPushButton):
    """A checkable preview card of the light or dark theme."""

    def __init__(self, mode: str) -> None:
        super().__init__()
        self._mode = mode
        self.setProperty("themeTile", True)
        self.setCheckable(True)
        self.setFixedHeight(104)
        self.setCursor(Qt.PointingHandCursor)

    def paintEvent(self, event) -> None:  # noqa: N802
        super().paintEvent(event)
        p = current_palette()
        preview = make_palette(self._mode, p.accent)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        frame = QRectF(12, 12, self.width() - 24, 58)
        painter.setPen(QPen(QColor(preview.border_strong), 1))
        painter.setBrush(QColor(preview.bg))
        painter.drawRoundedRect(frame, 7, 7)
        side = QRectF(frame.left() + 1, frame.top() + 1, 34, frame.height() - 2)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(preview.chrome))
        painter.drawRoundedRect(side, 6, 6)
        painter.setBrush(QColor(preview.accent))
        painter.drawRoundedRect(QRectF(side.left() + 7, side.top() + 8, 20, 6), 3, 3)
        painter.setBrush(QColor(preview.border_strong))
        for i in range(3):
            painter.drawRoundedRect(QRectF(side.left() + 7, side.top() + 20 + i * 10, 20, 4), 2, 2)
        card = QRectF(side.right() + 8, frame.top() + 8, frame.width() - 52, 20)
        painter.setBrush(QColor(preview.surface))
        painter.setPen(QPen(QColor(preview.border), 1))
        painter.drawRoundedRect(card, 4, 4)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(preview.text_subtle))
        painter.drawRoundedRect(QRectF(card.left() + 6, card.top() + 7, card.width() * 0.45, 5), 2, 2)
        painter.setBrush(QColor(preview.accent))
        painter.drawRoundedRect(QRectF(card.left(), card.bottom() + 8, 34, 10), 3, 3)
        painter.setPen(QColor(p.text))
        font = QFont(self.font())
        font.setWeight(QFont.DemiBold)
        painter.setFont(font)
        painter.drawText(QRectF(14, 76, self.width() - 28, 18),
                         Qt.AlignLeading | Qt.AlignVCenter,
                         tr("Light") if self._mode == "light" else tr("Dark"))
        if self.isChecked():
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(p.accent))
            badge = QRectF(self.width() - 34, 76, 18, 18)
            if is_rtl():
                badge.moveLeft(16)
            painter.drawEllipse(badge)
            painter.drawPixmap(int(badge.left() + 3), int(badge.top() + 3),
                               pixmap("check", "#FFFFFF", 12))
        painter.end()


class SettingsPage(Page):
    """Settings hub for keystore, products, theme and backups."""

    def _build(self) -> None:
        layout = scroll_layout(self, spacing=16)
        layout.addWidget(page_header(
            "Settings", "Keystore, product catalog, appearance and data backups."))

        top = QHBoxLayout()
        top.setSpacing(16)
        top.addWidget(self._build_appearance_card(), 1)
        top.addWidget(self._build_keystore_card(), 1)
        layout.addLayout(top)
        layout.addWidget(self._build_products_card())
        bottom = QHBoxLayout()
        bottom.setSpacing(16)
        bottom.addWidget(self._build_backup_card(), 1)
        bottom.addWidget(self._build_about_card(), 1)
        layout.addLayout(bottom)
        layout.addStretch(1)

    # ================================================================ keystore
    def _build_keystore_card(self) -> QWidget:
        card, layout = make_card(spacing=14)
        layout.addWidget(card_header(
            "key", "Signing keystore", "The Ed25519 key that signs every serial"))

        key_box = QFrame()
        key_box.setProperty("class", "cardInset")
        key_row = QHBoxLayout(key_box)
        key_row.setContentsMargins(14, 10, 14, 10)
        key_row.setSpacing(10)
        key_row.addWidget(icon_label("lock", "success", 16))
        texts = QVBoxLayout()
        texts.setSpacing(1)
        caption = QLabel(tr("Active signing key"))
        caption.setProperty("class", "kvKey")
        self.key_id_label = QLabel("")
        self.key_id_label.setProperty("class", "mono")
        self.key_id_label.setLayoutDirection(Qt.LeftToRight)
        self.key_id_label.setStyleSheet("font-size: 14px; font-weight: 600;")
        self.key_id_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        texts.addWidget(caption)
        texts.addWidget(self.key_id_label)
        key_row.addLayout(texts, 1)
        layout.addWidget(key_box)

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)
        for index, (text, variant, icon, slot, tip) in enumerate((
            ("Change passphrase…", "secondary", "lock", self._change_passphrase,
             "Re-wrap the keystore under a new passphrase."),
            ("Export private key…", "secondary", "upload", self._export_private_key,
             "Passphrase-wrapped offline backup (AES-256-GCM). Store it in a safe."),
            ("Import key export…", "secondary", "download", self._import_key,
             "Restore a signing key from an encrypted export."),
            ("Regenerate keypair", "danger", "refresh", self._regenerate_keypair,
             "Creates a NEW key. All previously issued serials stop verifying!"),
        )):
            btn = button(text, variant, icon, tip, lambda _=False, s=slot: s())
            grid.addWidget(btn, index // 2, index % 2)
        layout.addLayout(grid)

        import_demo = button(
            "Import shipped demo keypair…", "ghost", "package",
            f"Import {DEMO_KEYPAIR_FILE.name} (passphrase: demo-demo-demo) so the "
            "protector issues serials that the target_demo EXE accepts out of the box.",
            self._import_demo_key)
        layout.addWidget(import_demo, 0, Qt.AlignLeading)
        layout.addStretch(1)
        return card

    # ================================================================ products
    def _build_products_card(self) -> QWidget:
        card, layout = make_card(spacing=14)
        layout.addWidget(card_header(
            "package", "Product catalog", "Products the Generate page can issue serials for"))

        self.products_table = QTableWidget(0, 3)
        self.products_table.setHorizontalHeaderLabels(
            [tr("NAME"), tr("PRODUCT ID (UUID)"), tr("VERSION")])
        header = self.products_table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeading | Qt.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.products_table.verticalHeader().setVisible(False)
        self.products_table.verticalHeader().setDefaultSectionSize(40)
        self.products_table.setShowGrid(False)
        self.products_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.products_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.products_table.setMinimumHeight(130)
        self.products_table.setMaximumHeight(190)
        # Click a UUID cell -> copied to the clipboard (the cell tooltip says so).
        self.products_table.cellClicked.connect(self._copy_product_uuid)
        frame = QFrame()
        frame.setObjectName("tableFrame")
        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(1, 1, 1, 1)
        frame_layout.addWidget(self.products_table)
        layout.addWidget(frame)

        form = QHBoxLayout()
        form.setSpacing(8)
        self.new_product_name = QLineEdit()
        self.new_product_name.setPlaceholderText(tr("Product name (e.g. MyTool Pro)"))
        self.new_product_version = QLineEdit()
        self.new_product_version.setPlaceholderText(tr("Version (e.g. 1.0)"))
        form.addWidget(self.new_product_name, 3)
        form.addWidget(self.new_product_version, 1)
        form.addWidget(button("Add product", None, "plus", None, self._add_product))
        form.addWidget(button("Remove", "danger", "trash", None, self._remove_product))
        layout.addLayout(form)

        note = QLabel(tr("The product UUID must match the product_id compiled into "
                         "that product's EXE (its protection config)."))
        note.setProperty("class", "subtle")
        note.setWordWrap(True)
        layout.addWidget(note)
        return card

    # ================================================================ appearance
    def _build_appearance_card(self) -> QWidget:
        card, layout = make_card(spacing=14)
        layout.addWidget(card_header(
            "palette", "Appearance", "Theme, accent color and language"))

        # theme tiles -----------------------------------------------------
        layout.addWidget(field_label("Theme"))
        tiles = QHBoxLayout()
        tiles.setSpacing(10)
        self._theme_group = QButtonGroup(self)
        self._theme_tiles: dict[str, QPushButton] = {}
        for mode in ("light", "dark"):
            tile = _ThemeTile(mode)
            tile.clicked.connect(lambda _=False, m=mode: self._set_mode(m))
            self._theme_group.addButton(tile)
            self._theme_tiles[mode] = tile
            tiles.addWidget(tile, 1)
        layout.addLayout(tiles)

        # accent swatches ---------------------------------------------------
        layout.addWidget(field_label("Accent color"))
        swatches = QHBoxLayout()
        swatches.setSpacing(8)
        self._swatch_group = QButtonGroup(self)
        self._swatches: dict[str, QPushButton] = {}
        for label, hex_color in ACCENT_PRESETS:
            swatch = QPushButton()
            swatch.setCheckable(True)
            swatch.setFixedSize(30, 30)  # 24px content + 3px ring (QSS below)
            swatch.setToolTip(label)
            swatch.setCursor(Qt.PointingHandCursor)
            on_theme(swatch, lambda w, p, c=hex_color: w.setStyleSheet(
                f"QPushButton {{ background: {c}; border: 3px solid {p.surface};"
                " border-radius: 15px; padding: 0; min-width: 24px; max-width: 24px;"
                " min-height: 24px; max-height: 24px; }"
                f"QPushButton:hover {{ border: 3px solid {p.border_strong}; }}"
                f"QPushButton:checked {{ border: 3px solid {p.text}; }}"))
            swatch.clicked.connect(lambda _=False, c=hex_color: self._set_accent(c))
            self._swatch_group.addButton(swatch)
            self._swatches[hex_color] = swatch
            swatches.addWidget(swatch)
        swatches.addStretch(1)
        layout.addLayout(swatches)

        # language -----------------------------------------------------------
        layout.addWidget(field_label("Language"))
        segmented = QFrame()
        segmented.setObjectName("segmented")
        seg_row = QHBoxLayout(segmented)
        seg_row.setContentsMargins(3, 3, 3, 3)
        seg_row.setSpacing(2)
        self._lang_group = QButtonGroup(self)
        for code, label in LANGUAGES:
            seg = QPushButton(label)
            seg.setProperty("segment", True)
            seg.setCheckable(True)
            seg.setChecked(code == language())
            seg.setCursor(Qt.PointingHandCursor)
            seg.setMinimumWidth(96)
            seg.clicked.connect(lambda _=False, c=code: self.services.set_language(c))
            self._lang_group.addButton(seg)
            seg_row.addWidget(seg)
        lang_row = QHBoxLayout()
        lang_row.addWidget(segmented)
        lang_row.addStretch(1)
        layout.addLayout(lang_row)
        layout.addStretch(1)

        # Back-compat combos (scripts/tests drive these); hidden.
        self.theme_mode = QComboBox()
        self.theme_mode.addItem("Dark", "dark")
        self.theme_mode.addItem("Light", "light")
        self.theme_mode.currentIndexChanged.connect(
            lambda: self._set_mode(self.theme_mode.currentData()))
        self.theme_mode.setVisible(False)
        self.accent_combo = QComboBox()
        for label, hex_color in ACCENT_PRESETS:
            self.accent_combo.addItem(label, hex_color)
        self.accent_combo.currentIndexChanged.connect(
            lambda: self._set_accent(self.accent_combo.currentData()))
        self.accent_combo.setVisible(False)
        return card

    def _set_mode(self, mode: str) -> None:
        if mode and mode != self.services.settings.theme:
            self.services.settings.theme = mode
            self._apply_theme()

    def _set_accent(self, accent: str) -> None:
        if accent and accent != self.services.settings.accent:
            self.services.settings.accent = accent
            self._apply_theme()

    def _apply_theme(self) -> None:
        self.services.theme.restyle(
            self.services.app, mode=self.services.settings.theme,
            accent=self.services.settings.accent)
        self._sync_appearance()
        self.services.refresh_all()

    def _theme_changed(self) -> None:  # kept for API compatibility
        self._set_mode(self.theme_mode.currentData() or "light")
        self._set_accent(self.accent_combo.currentData() or DEFAULT_ACCENT)

    def _sync_appearance(self) -> None:
        mode = self.services.settings.theme
        if mode in self._theme_tiles:
            self._theme_tiles[mode].setChecked(True)
        accent = self.services.settings.accent
        if accent in self._swatches:
            self._swatches[accent].setChecked(True)

    # ================================================================ backup
    def _build_backup_card(self) -> QWidget:
        card, layout = make_card(spacing=14)
        layout.addWidget(card_header(
            "archive", "Database backup", "Encrypted, passphrase-protected backup and restore"))
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(button("Create encrypted backup…", None, "download", None, self._backup))
        row.addWidget(button("Restore from backup…", "secondary", "upload", None, self._restore))
        row.addStretch(1)
        layout.addLayout(row)
        note = QLabel(tr("Backups are passphrase-wrapped containers (AES-256-GCM, "
                         "PBKDF2 600k) — safe to store on any medium."))
        note.setProperty("class", "subtle")
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch(1)
        return card

    # ================================================================ about
    def _build_about_card(self) -> QWidget:
        card, layout = make_card(spacing=12)
        layout.addWidget(card_header("info", "About", "SecureCode Protector · v1.0.0",
                                     badge("100% offline", "success"), tone="info"))
        text = QLabel(tr(
            "SecureCode Protector 1.0.0 — offline serial generation and EXE "
            "protection toolkit. 100% offline: no network access is performed "
            "by this application, ever."))
        text.setProperty("class", "muted")
        text.setWordWrap(True)
        layout.addWidget(text)
        layout.addStretch(1)
        return card

    # ================================================================ refresh
    def refresh(self) -> None:
        self.key_id_label.setText(self.services.keystore.key_id or "—")
        self.products_table.setRowCount(0)
        mono = make_mono_font(9)
        # UUID cells are click-to-copy: render them underlined so the
        # affordance is visible without hovering.
        uuid_font = QFont(mono)
        uuid_font.setUnderline(True)
        for product in self.services.settings.products():
            row = self.products_table.rowCount()
            self.products_table.insertRow(row)
            for column, value in enumerate(
                    (product["name"], product["id"], product.get("version", ""))):
                item = QTableWidgetItem(value)
                if column == 1:
                    item.setToolTip(tr("Click to copy the product UUID."))
                    item.setFont(uuid_font)
                self.products_table.setItem(row, column, item)
        self._sync_appearance()

    # ================================================================ handlers
    def _copy_product_uuid(self, row: int, column: int) -> None:
        """cellClicked handler: copy the clicked UUID cell to the clipboard."""
        if column != 1:
            return  # only the UUID column is click-to-copy
        item = self.products_table.item(row, column)
        if item is None or not item.text():
            return
        QGuiApplication.clipboard().setText(item.text())
        self.services.toast.show("success", tr("Copied"),
                                 tr("Product UUID copied to clipboard."))

    def _keystore_passphrase(self, prompt: str, min_len: int = 4) -> str | None:
        text, ok = QInputDialog.getText(
            self, "Keystore passphrase", prompt, QLineEdit.Password)
        if not ok:
            return None
        if len(text) < min_len:
            QMessageBox.warning(
                self, "Too short", f"Passphrase must be at least {min_len} characters.")
            return None
        return text

    def _change_passphrase(self) -> None:
        old = self._keystore_passphrase("Current passphrase:")
        if old is None:
            return
        new = self._keystore_passphrase("New passphrase (min 8 chars):", 8)
        if new is None:
            return

        def _work() -> None:
            self.services.keystore.change_passphrase(old, new)

        run_task(self, _work,
                 lambda _: self.services.toast.show(
                     "success", "Passphrase changed", "The keystore was re-wrapped."),
                 busy_text="Re-wrapping keystore…")

    def _export_private_key(self) -> None:
        passphrase = self._keystore_passphrase(
            "Export passphrase (min 8 chars) — protects the file on disk:", 8)
        if passphrase is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export private key", "signing_key.sec",
            "Encrypted key export (*.sec);;All files (*)")
        if not path:
            return

        def _work() -> None:
            blob = self.services.keystore.export_private_key(passphrase)
            with open(path, "wb") as handle:
                handle.write(blob)

        run_task(self, _work,
                 lambda _: self.services.toast.show(
                     "success", "Exported",
                     "Keep this file OFFLINE and safe — it can issue serials."),
                 busy_text="Exporting…")

    def _import_key(self, blob_path: str | None = None, preset_pass: str | None = None) -> None:
        if blob_path is None:
            blob_path, _ = QFileDialog.getOpenFileName(
                self, "Import key export", str(SAVE_HINT),
                "Encrypted key export (*.sec);;All files (*)")
        if not blob_path:
            return
        export_pass = preset_pass or self._keystore_passphrase(
            "Passphrase of the export file:")
        if export_pass is None:
            return
        store_pass = self._keystore_passphrase(
            "Re-lock this keystore with a new passphrase (min 8 chars):", 8)
        if store_pass is None:
            return
        try:
            blob = open(blob_path, "rb").read()
        except OSError as exc:
            QMessageBox.critical(self, "Error", f"Could not read file: {exc}")
            return

        confirm = QMessageBox.warning(
            self, "Replace signing key?",
            "Importing a key REPLACES the current signing keypair.\n"
            "All serials issued with the OLD key stop verifying once you "
            "rebuild your product EXEs with the new one (existing local "
            "licenses keep working until then).\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return

        def _work() -> None:
            self.services.keystore.import_private_key(
                blob, export_pass, store_pass=store_pass)

        def _done(_) -> None:
            self.refresh()
            self.services.toast.show(
                "success", "Key imported",
                f"Active key id: {self.services.keystore.key_id}")

        def _fail(message: str) -> None:
            self.services.toast.show("error", "Import failed", message)

        run_task(self, _work, _done, _fail, busy_text="Importing key…")

    def _import_demo_key(self) -> None:
        if not DEMO_KEYPAIR_FILE.is_file():
            QMessageBox.information(
                self, "Demo keypair missing",
                f"Run target_demo/tools/gen_demo_keypair.py first:\n{DEMO_KEYPAIR_FILE}")
            return
        self._import_key(str(DEMO_KEYPAIR_FILE), "demo-demo-demo")

    def _regenerate_keypair(self) -> None:
        text, ok = QInputDialog.getText(
            self, "Regenerate keypair — type REGENERATE to confirm",
            "This INVALIDATES every serial issued so far. Type REGENERATE:")
        if not ok or text.strip().upper() != "REGENERATE":
            return
        store_pass = self._keystore_passphrase(
            "New keystore passphrase (min 8 chars):", 8)
        if store_pass is None:
            return

        def _work() -> None:
            self.services.keystore.create(store_pass, overwrite=True)

        run_task(self, _work,
                 lambda _: (self.refresh(),
                            self.services.toast.show(
                                "warning", "Keypair regenerated",
                                "All existing serials are now invalid.")),
                 busy_text="Generating keypair…")

    def _add_product(self) -> None:
        name = self.new_product_name.text().strip()
        version = self.new_product_version.text().strip() or "1.0"
        if not name:
            QMessageBox.information(self, "Name required", "Enter a product name.")
            return
        product_id = str(uuid.uuid4())
        self.services.settings.add_product(name, product_id, version)
        self.refresh()
        self.services.toast.show("success", "Product added",
                                 f"{name} → {product_id}")

    def _remove_product(self) -> None:
        selected = self.products_table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        product_id = self.products_table.item(row, 1).text()
        self.services.settings.remove_product(product_id)
        self.refresh()

    def _backup(self) -> None:
        passphrase, ok = QInputDialog.getText(
            self, "Backup passphrase", "Passphrase protecting the backup:",
            QLineEdit.Password)
        if not ok or len(passphrase) < 8:
            QMessageBox.warning(self, "Too short", "Use at least 8 characters.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Create backup", "licenses_backup.sec",
            "Encrypted backup (*.sec);;All files (*)")
        if not path:
            return

        def _work() -> str:
            return str(self.services.db.backup(path, passphrase))

        run_task(self, _work,
                 lambda p: self.services.toast.show("success", "Backup created", p),
                 busy_text="Exporting database…")

    def _restore(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Restore backup", str(SAVE_HINT),
            "Encrypted backup (*.sec);;All files (*)")
        if not path:
            return
        passphrase, ok = QInputDialog.getText(
            self, "Backup passphrase", "Passphrase of the backup file:",
            QLineEdit.Password)
        if not ok:
            return

        def _work() -> int:
            try:
                return self.services.db.restore(path, passphrase)
            except WrongPassphraseError:
                # The most common restore failure: the backup has its OWN
                # passphrase (chosen at creation time), not the keystore one.
                raise ValueError(tr(
                    "Wrong backup passphrase — this is the passphrase you "
                    "chose when CREATING the backup, not the keystore "
                    "passphrase.")) from None
            except KeystoreError:
                raise ValueError(tr(
                    "This file is not a valid SecureCode backup.")) from None

        run_task(self, _work,
                 lambda count: (
                     self.services.toast.show(
                         "success", "Restored",
                      tr(f"{count} record(s) imported.") if count else tr(
                          "No new records — this backup's records are "
                          "already in the database.")),
                     self.services.refresh_all()),
                 lambda msg: self.services.toast.show("error", "Restore failed", msg),
                 busy_text="Importing database…")




__all__ = ["SettingsPage"]
