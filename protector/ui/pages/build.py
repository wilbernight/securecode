"""
protector.ui.pages.build — Build Protection (guided flow).

Wraps an arbitrary Python project with the protection stack:

    1. Analyze        — scans the project, writes protection_report.txt
                        (checklist: entry point, dependencies, SDK presence,
                        recommended hardening steps, threat-model notes)
    2. Inject SDK     — copies shared/ + protection/ (the client SDK) into
                        the project and shows the 5-line bootstrap snippet
    3. Generate build — writes build.bat with the exact Nuitka command
                        (onefile, standalone, pyside6 plugin, Windows
                        version metadata, icon) for THAT project

Everything is offline; the report and build script are plain text files.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from textwrap import dedent

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
)

from ...core.app_paths import REPO_ROOT, SAVE_HINT
from ..widgets.workers import run_task
from ..i18n import arrow, tr
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

_SDK_SOURCES = [REPO_ROOT / "shared", REPO_ROOT / "target_demo" / "protection"]

_BOOTSTRAP_SNIPPET = dedent("""
    # --- SecureCode protection bootstrap (paste at the top of your main) ----
    from protection import LicenseClient, LicenseState, ProtectionConfig, ProtectionRuntime

    config = ProtectionConfig(product_id="<YOUR-PRODUCT-UUID>",
                              product_name="YourApp", company_name="YourCompany")
    runtime = ProtectionRuntime.bootstrap(config)      # anti-RE layers 3+4
    client = LicenseClient(config, clock_guard=runtime.clock_guard)

    status = client.verify_installed(degraded=runtime.degraded)
    if status.state is not LicenseState.VALID:
        ...  # show your activation dialog / license error screen
    else:
        ...  # start your real main window (status.payload has customer/expiry/flags)
""").strip()


class BuildPage(Page):
    """Guided project-protection flow."""

    def _build(self) -> None:
        layout = page_layout(self, spacing=18)
        self._project_dir: Path | None = None

        layout.addWidget(page_header(
            "Build Protection",
            "Wrap your Python project with the offline licensing SDK and "
            "produce the Nuitka build script — no placeholders, fully automated."))

        # --- project selection ---------------------------------------------
        select_card, select_layout = make_card(spacing=12)
        choose = button("Choose folder…", None, "folder",
                        "The folder containing your Python entry point (e.g. main.py).",
                        self._choose_project)
        select_layout.addWidget(card_header(
            "folder", "Project", "The folder containing your Python entry point", choose))
        path_box = QFrame()
        path_box.setProperty("class", "cardInset")
        path_row = QHBoxLayout(path_box)
        path_row.setContentsMargins(12, 9, 12, 9)
        path_row.setSpacing(10)
        path_row.addWidget(icon_label("folder", "text_subtle", 15))
        self.project_path = QLabel(tr("No project selected"))
        self.project_path.setProperty("class", "monoMuted")
        self.project_path.setLayoutDirection(Qt.LeftToRight)
        self.project_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        path_row.addWidget(self.project_path, 1)
        select_layout.addWidget(path_box)
        self.project_hint = QLabel(tr(
            "Pick the project you want to protect. Copy your source there first — "
            "nothing in your project folder is modified until you press "
            "'Inject protection SDK'."))
        self.project_hint.setProperty("class", "subtle")
        self.project_hint.setWordWrap(True)
        select_layout.addWidget(self.project_hint)
        layout.addWidget(select_card)

        # --- the three steps ---------------------------------------------------
        steps = QHBoxLayout()
        steps.setSpacing(14)
        for number, icon, title, desc, slot in (
            (1, "search", "Analyze project",
             "Scan the project and write protection_report.txt", self._analyze),
            (2, "package", "Inject SDK",
             "Copy shared/ + protection/ and show the bootstrap", self._inject_sdk),
            (3, "shield-check", "Generate build.bat",
             "Write the exact Nuitka onefile command", self._generate_build),
        ):
            card, card_layout = make_card(spacing=10)
            top = QHBoxLayout()
            top.addWidget(icon_badge(icon, "accent", 36, 18))
            top.addStretch(1)
            top.addWidget(badge(tr("Step {n}", n=number), "neutral"), 0, Qt.AlignTop)
            card_layout.addLayout(top)
            head = QLabel(tr(title))
            head.setProperty("class", "h2")
            card_layout.addWidget(head)
            sub = QLabel(tr(desc))
            sub.setProperty("class", "subtle")
            sub.setWordWrap(True)
            card_layout.addWidget(sub)
            card_layout.addStretch(1)
            card_layout.addWidget(button("Run", "secondary", arrow(), None, slot),
                                  0, Qt.AlignLeading)
            steps.addWidget(card, 1)
        layout.addLayout(steps)

        # --- output console -------------------------------------------------------
        output_card, output_layout = make_card(spacing=12)
        copy = button("Copy", "secondary", "copy", None, self._copy_output)
        output_layout.addWidget(card_header(
            "terminal", "Output", "Report, bootstrap snippet and build command", copy,
            tone="neutral"))
        self.output = QPlainTextEdit()
        self.output.setObjectName("console")
        self.output.setLayoutDirection(Qt.LeftToRight)
        self.output.setReadOnly(True)
        self.output.setPlaceholderText(tr(
            "The generated protection_report.txt / bootstrap snippet / build "
            "command appear here."))
        output_layout.addWidget(self.output, 1)
        layout.addWidget(output_card, 1)

    # -------------------------------------------------- helpers
    def _copy_output(self) -> None:
        text = self.output.toPlainText()
        if text:
            QGuiApplication.clipboard().setText(text)
            self.services.toast.show("success", "Copied")

    def _project(self) -> Path | None:
        path = self._project_dir
        if path is None:
            self.services.toast.show("info", "No project", "Choose a project folder first.")
            return None
        if not path.is_dir():
            self.services.toast.show("error", "Invalid folder", f"Not a directory: {path}")
            return None
        return path

    def _choose_project(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self, tr("Choose folder…"), str(SAVE_HINT))
        if path:
            self._project_dir = Path(path)
            self.project_path.setText(path)
            self.project_hint.setText(
                f"Selected: {path}. Analyze writes protection_report.txt there; "
                "inject copies shared/ + protection/ beside your entry point.")

    # -------------------------------------------------- step 1: analyze
    def _analyze(self) -> None:
        project = self._project()
        if project is None:
            return

        def _work() -> str:
            return write_protection_report(project)

        run_task(self, _work, self._report_done,
                 busy_text="Analyzing project…")

    def _report_done(self, result: tuple) -> None:
        report_path, content = result
        self.output.setPlainText(content)
        self.services.toast.show(
            "success", "Report written", str(report_path))

    # -------------------------------------------------- step 2: inject SDK
    def _inject_sdk(self) -> None:
        project = self._project()
        if project is None:
            return
        confirm = QMessageBox.question(
            self, "Inject SDK",
            f"Copy shared/ + protection/ into\n{project}\n"
            "(overwrites existing copies of those two folders)?")
        if confirm != QMessageBox.Yes:
            return

        def _work() -> str:
            copied = []
            for source in _SDK_SOURCES:
                target = project / source.name
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(source, target)
                copied.append(source.name)
            return "\n".join(copied)

        def _done(copied: str) -> None:
            self.output.setPlainText(
                f"Copied into the project:\n{copied}\n\n"
                f"Then paste this bootstrap at the top of your main entry:\n\n"
                + _BOOTSTRAP_SNIPPET)
            self.services.toast.show(
                "success", "SDK injected",
                "Add the bootstrap snippet to your entry point (shown here).")

        run_task(self, _work, _done, busy_text="Copying SDK…")

    # -------------------------------------------------- step 3: build.bat
    def _generate_build(self) -> None:
        project = self._project()
        if project is None:
            return

        def _work() -> str:
            entry = find_entry_point(project)
            return write_build_bat(project, entry)

        def _done(build_path: str) -> None:
            self.output.setPlainText(
                f"Build script written: {build_path}\n\n"
                "Run it in a terminal (not double-click) to see the Nuitka "
                "output. Result: <name>.dist\\<name>.exe — a single self-"
                "extracting native binary with ZERO Python bytecode inside.")
            self.services.toast.show("success", "build.bat generated", build_path)

        run_task(self, _work, _done, busy_text="Generating build.bat…")


# ---------------------------------------------------------------------------
# Analysis / report generation (kept module-level: also usable from CLI)
# ---------------------------------------------------------------------------
def find_entry_point(project: Path) -> Path:
    """Locate the most plausible entry point (main.py/app.py/run.py/…)."""
    candidates = ["main.py", "app.py", "run.py", "start.py", "__main__.py"]
    for name in candidates:
        found = list(project.glob(name)) + list(project.glob(f"*/{name}"))
        if found:
            return found[0]
    py_files = sorted(project.rglob("*.py"))
    if not py_files:
        raise FileNotFoundError("no .py files found in the project")
    return py_files[0]


def write_protection_report(project: Path) -> tuple[Path, str]:
    """Write protection_report.txt into the project; return (path, content)."""
    entry = find_entry_point(project)
    py_files = sorted(project.rglob("*.py"))
    py_count = len(py_files)
    uses_qt = any(
        "PySide6" in path.read_text(encoding="utf-8", errors="ignore")[:8192]
        for path in py_files[:50])

    sdk_missing = not (project / "protection").is_dir() or \
        not (project / "shared").is_dir()

    report = f"""\
PROTECTION REPORT — generated by SecureCode Protector
====================================================
Project:      {project}
Entry point:  {entry}
Python files: {py_count}
Qt/PySide6:   {'yes' if uses_qt else 'not detected in entry'}

STATUS CHECKLIST
----------------
[x] Entry point identified: {entry.name}
[{'x' if sdk_missing else ' '}] {'PROTECTION SDK MISSING — run "Inject protection SDK" first' if sdk_missing else 'Protection SDK present (protection/ + shared/)'}
[ ] Bootstrap snippet added to {entry.name} (see below)
[ ] strings/integrity manifest regenerated IF you changed product ids
    (protector/tools/build_strings_table.py + make_integrity_manifest.py)
[ ] build.bat generated (step 3) and run once
[ ] Serial generated in the protector for the FIRST test machine
[ ] Full activation + expiry + transfer workflow smoke-tested offline

WHY NUITKA (not PyInstaller)
----------------------------
Nuitka translates your Python to C and compiles it to native machine code.
The onefile EXE contains NO .pyc and NO marshal bytecode:
    * pyinstxtractor  -> finds nothing to extract
    * uncompyle6 / decompyle3 / pycdc -> nothing to decompile
    * pyinstxtractor-ng, pyextract → the entire attack chain is dead
Embedded constants (keys, identifiers) are additionally AES-encrypted by
the string layer and re-derived at runtime (see protection/strings.py).

RESIDUAL RISKS (honest threat model — full details in docs/SECURITY.md)
-----------------------------------------------------------------------
* A determined expert can still read disassembly (IDA/Ghidra) of the native
  code — the goal is to make this maximally expensive, not impossible.
* The Ed25519 private key never leaves the protector, so forging serials
  requires breaking Ed25519 itself.
* Clock rollback beyond the allowance + revoked serials are handled by
  clock_guard.py / blacklist.sec.

BOOTSTRAP SNIPPET (paste at the top of your entry file)
-------------------------------------------------------
{_BOOTSTRAP_SNIPPET}
"""
    path = project / "protection_report.txt"
    path.write_text(report, encoding="utf-8")
    return path, report


def write_build_bat(project: Path, entry: Path, product_name: str = "SecureApp",
                    company: str = "YourCompany",
                    version: str = "1.0.0") -> str:
    """Write the exact Nuitka build command as build.bat for the project."""
    entry_rel = entry.relative_to(project)
    name = entry.stem
    bat = f"""\
@echo off
REM ============================================================
REM  SecureCode protected build — generated by the protector
REM  Project : {project}
REM  Entry   : {entry_rel}
REM  Requirements: pip install nuitka zstandard (build-time only)
REM ============================================================
setlocal enabledelayedexpansion

REM --- 1) rebuild the app icon if missing -------------------
if not exist assets\\app.ico (
    python tools\\make_icon.py 2>nul || echo [warn] no icon tool, continuing without icon
)

REM --- 2) the Nuitka command ---------------------------------
python -m nuitka ^
  --onefile ^
  --standalone ^
  --enable-plugin=pyside6 ^
  --windows-console-mode=disable ^
  --company-name="{company}" ^
  --product-name="{product_name}" ^
  --file-version={version} ^
  --product-version={version} ^
  --file-description="{product_name} — protected application" ^
  --copyright="Copyright (c) {company}" ^
  --windows-icon-from-ico=assets\\app.ico ^
  --include-package=shared ^
  --include-package=protection ^
  --output-dir=dist ^
  --remove-output ^
  "{entry_rel}"

if errorlevel 1 (
    echo [error] build failed — see messages above.
    exit /b 1
)
echo [ok] built dist\\{name}.dist\\{name}.exe
endlocal
"""
    path = project / "build.bat"
    path.write_text(bat, encoding="utf-8")
    return str(path)


__all__ = ["BuildPage", "find_entry_point", "write_build_bat",
           "write_protection_report"]
