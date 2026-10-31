"""
protector.ui.pages.fingerprint_reader — Fingerprint Reader.

Paste a customer machine code (or load their fingerprint.txt export),
validate the format, show which hardware components were recorded, then
jump straight to the Generate page pre-filled. This page is the intake
side of the customer workflow (see docs/WORKFLOW.md).
"""

from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...core.app_paths import SAVE_HINT
from ...core.fingerprint import (
    FP_EXPORT_FORMAT,
    FingerprintParseError,
    MachineInfo,
    component_labels,
    parse_fingerprint,
    platform_display_name,
    platform_slots,
    read_fingerprint_file,
)
from ..i18n import digits, tr
from ..theme import MONO_FONT_STACK, current_palette
from ..theme.icons import pixmap
from .base import (
    Page,
    badge,
    button,
    card_header,
    divider,
    icon_badge,
    make_card,
    page_header,
    page_layout,
    repolish,
    set_badge,
)

#: component key -> icon. Labels are platform-dependent (what "board" means on
#: Android is not what it means on Windows), so they come from
#: protector.core.fingerprint.component_labels() at build time.
_ICONS = {
    "cpu": "cpu",
    "board": "board",
    "disk": "disk",
    "guid": "hash",
}


class _ComponentRow(QFrame):
    """One hardware component line: icon, label, recorded/missing badge."""

    def __init__(self, key: str, label: str, last: bool) -> None:
        super().__init__()
        if not last:
            self.setProperty("class", "listRow")
        icon = _ICONS[key]
        row = QHBoxLayout(self)
        row.setContentsMargins(2, 11, 2, 11)
        row.setSpacing(12)
        row.addWidget(icon_badge(icon, "neutral", 32, 16))
        text = QLabel(tr(label))
        text.setProperty("class", "h3")
        row.addWidget(text, 1)
        self.state = badge("—", "neutral")
        row.addWidget(self.state)

    def set_state(self, present: bool | None) -> None:
        if present is None:
            set_badge(self.state, "—", "neutral")
        elif present:
            set_badge(self.state, "Recorded", "success")
        else:
            set_badge(self.state, "Not recorded", "warning")


class FingerprintReaderPage(Page):
    """Fingerprint intake + validation."""

    def _build(self) -> None:
        layout = page_layout(self, spacing=18)
        layout.addWidget(page_header(
            "Fingerprint Reader",
            "Customers send you a machine code — validate it here, then issue "
            "a serial locked to exactly that machine."))

        columns = QHBoxLayout()
        columns.setSpacing(18)

        # --- left: input + how it works ---------------------------------------
        left = QVBoxLayout()
        left.setSpacing(18)
        card, card_layout = make_card(spacing=14)
        card_layout.addWidget(card_header(
            "scan", "Machine code input", "Paste the code or the whole fingerprint.txt export"))
        self.input = QPlainTextEdit()
        self.input.setObjectName("codeInput")
        self.input.setLayoutDirection(Qt.LeftToRight)
        self.input.setPlaceholderText(tr(
            "Paste the 16-character machine code (XXXX-XXXX-XXXX-XXXX)\n"
            "…or the complete contents of their fingerprint.txt export."))
        self.input.setFixedHeight(120)
        card_layout.addWidget(self.input)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addWidget(button("Open fingerprint file…", "secondary", "folder",
                                 "Read a fingerprint.txt exported by the client app.",
                                 self._load_file))
        buttons.addWidget(button("Clear", "ghost", None, None, self._clear))
        buttons.addStretch(1)
        buttons.addWidget(button("Validate", None, "check-circle",
                                 "Check the code's structure and decode its component mask.",
                                 self._parse))
        card_layout.addLayout(buttons)
        left.addWidget(card)

        steps_card, steps_layout = make_card(spacing=12)
        steps_layout.addWidget(card_header("info", "How it works", None, tone="info"))
        for index, text in enumerate((
            "Customer runs the app and exports the machine code.",
            "You validate the code here.",
            "Issue a serial locked to that machine and send it back.",
        ), start=1):
            step = QHBoxLayout()
            step.setSpacing(12)
            number = QLabel(digits(str(index)))
            number.setProperty("badge", "accent")
            number.setFixedSize(24, 24)
            number.setAlignment(Qt.AlignCenter)
            step.addWidget(number, 0, Qt.AlignTop)
            label = QLabel(tr(text))
            label.setProperty("class", "muted")
            label.setWordWrap(True)
            step.addWidget(label, 1)
            steps_layout.addLayout(step)
        left.addWidget(steps_card)
        left.addStretch(1)
        columns.addLayout(left, 1)

        # --- right: analysis ---------------------------------------------------
        result_card, result_layout = make_card(spacing=14)
        self.state_badge = badge("Waiting", "neutral")
        result_layout.addWidget(card_header(
            "cpu", "Analysis", "Recorded hardware components", self.state_badge))

        code_box = QFrame()
        code_box.setProperty("class", "cardInset")
        code_layout = QHBoxLayout(code_box)
        code_layout.setContentsMargins(14, 12, 14, 12)
        code_layout.setSpacing(12)
        self.code_icon = QLabel()
        self.code_icon.setFixedSize(20, 20)
        code_layout.addWidget(self.code_icon)
        self.code_label = QLabel("XXXX-XXXX-XXXX-XXXX")
        self.code_label.setLayoutDirection(Qt.LeftToRight)
        self.code_label.setStyleSheet(
            f"font-family: {MONO_FONT_STACK}; font-size: 17px;"
            " font-weight: 600; letter-spacing: 2px;")
        self.code_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        code_layout.addWidget(self.code_label, 1)
        # Platform badge: which OS the fingerprint was recorded on (export
        # metadata; bare pasted codes are treated as Windows).
        self.platform_badge = badge("—", "neutral")
        code_layout.addWidget(self.platform_badge, 0, Qt.AlignVCenter)
        result_layout.addWidget(code_box)

        self.result = QLabel(tr("Nothing validated yet."))
        self.result.setProperty("class", "subtle")
        self.result.setWordWrap(True)
        result_layout.addWidget(self.result)

        # Component rows are rebuilt per platform (iOS has no disk/guid
        # slots, macOS has no disk slot, ...). See _set_platform().
        self.components_layout = QVBoxLayout()
        self.components_layout.setSpacing(0)
        self.rows: dict[str, _ComponentRow] = {}
        self._platform: str | None = None
        self._set_platform("windows")
        result_layout.addLayout(self.components_layout)
        result_layout.addStretch(1)
        result_layout.addWidget(divider())

        self.goto_generate = button(
            "Generate serial for this machine", None, "key",
            "Jump to the Generate tab with this machine code pre-filled.",
            self._goto_generate)
        self.goto_generate.setProperty("size", "lg")
        self.goto_generate.setEnabled(False)
        result_layout.addWidget(self.goto_generate)
        columns.addWidget(result_card, 1)

        layout.addLayout(columns, 1)
        self._info: MachineInfo | None = None
        self._set_code_icon("idle")

    # -------------------------------------------------- helpers
    def _set_platform(self, platform: str) -> None:
        """(Re)build the component rows for the fingerprint's platform.

        Bare pasted codes default to the Windows rows; loading an export
        from the Android/iOS/macOS SDKs swaps in that platform's slots
        (e.g. iOS shows Keychain UUID / IDFV instead of disk / registry).
        """
        if platform == self._platform:
            return
        self._platform = platform
        while (item := self.components_layout.takeAt(0)) is not None:
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        labels = component_labels(platform)
        slots = platform_slots(platform)
        self.rows = {}
        for index, key in enumerate(slots):
            self.rows[key] = _ComponentRow(key, labels[key],
                                           last=index == len(slots) - 1)
            self.components_layout.addWidget(self.rows[key])

    def _set_code_icon(self, state: str) -> None:
        p = current_palette()
        name, role = {"ok": ("check-circle", "success"), "bad": ("x-circle", "danger"),
                      "idle": ("hash", "text_subtle")}[state]
        self.code_icon.setPixmap(pixmap(name, p.color(role), 20))

    def _reset(self, message: str, state: str = "idle") -> None:
        self._info = None
        self.goto_generate.setEnabled(False)
        self.code_label.setText("XXXX-XXXX-XXXX-XXXX")
        self.result.setText(message)
        self.result.setProperty("tone", "danger" if state == "bad" else "")
        repolish(self.result)
        for row in self.rows.values():
            row.set_state(None)
        set_badge(self.state_badge, "Invalid" if state == "bad" else "Waiting",
                  "danger" if state == "bad" else "neutral")
        set_badge(self.platform_badge, "—", "neutral")
        self._set_code_icon(state)

    def _clear(self) -> None:
        self.input.setPlainText("")
        self._reset(tr("Nothing validated yet."))

    def refresh(self) -> None:
        if self._info is None:
            self._set_code_icon("idle")

    # -------------------------------------------------- handlers
    def _load_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Open fingerprint file…"), str(SAVE_HINT),
            "Fingerprint exports (*.txt);;All files (*)")
        if not path:
            return
        try:
            info = read_fingerprint_file(path)
        except FingerprintParseError as exc:
            QMessageBox.warning(self, tr("Invalid file"), exc.user_message)
            return
        # Keep a compact export (with the platform key) in the input box so
        # re-validating shows the same platform again.
        self.input.setPlainText(json.dumps({
            "format": FP_EXPORT_FORMAT,
            "version": 1,
            "platform": info.platform,
            "code": info.code,
        }, indent=2))
        self._show_info(info)

    def _parse(self) -> None:
        text = self.input.toPlainText().strip()
        if not text:
            self._reset(tr("Paste a machine code or load a fingerprint file first."))
            return
        # Accept either the bare code or a full export JSON pasted as text.
        # Bare codes carry no metadata -> treated as Windows exports.
        platform = "windows"
        if text.startswith("{"):
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    text = str(data.get("code", ""))
                    platform = str(data.get("platform", "windows"))
            except json.JSONDecodeError:
                pass
        try:
            info = parse_fingerprint(text, platform)
        except FingerprintParseError as exc:
            self._reset(exc.user_message, "bad")
            return
        self._show_info(info)

    def _show_info(self, info: MachineInfo) -> None:
        self._info = info
        self._set_platform(info.platform)
        self.code_label.setText(info.code)
        set_badge(self.platform_badge, platform_display_name(info.platform),
                  "accent")
        missing = [k for k in self.rows if not info.present[k]]
        for key, row in self.rows.items():
            row.set_state(bool(info.present[key]))
        if missing:
            self.result.setText(tr(
                "Missing components lower the fingerprint's stability — consider tolerance ≥ 1."))
            self.result.setProperty("tone", "warning")
        else:
            self.result.setText(tr("Valid machine code"))
            self.result.setProperty("tone", "success")
        repolish(self.result)
        set_badge(self.state_badge, "Valid machine code", "success")
        self._set_code_icon("ok")
        self.goto_generate.setEnabled(True)

    def _goto_generate(self) -> None:
        if self._info is None:
            return
        self.services.navigate("generate")
        self.services.prefill_generate(self._info.code, None,
                                       self._info.platform)


__all__ = ["FingerprintReaderPage"]
