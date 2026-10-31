"""
target_demo.main — SecureNotepad entry point: THE LICENSING WRAPPER FLOW.

This file shows EXACTLY how your own application code gets wrapped by the
protection + licensing stack. The flow is the same for any product:

    1. Logging bootstrap (rotating file, no secrets ever logged)
    2. ProtectionRuntime.bootstrap(cfg)   — Layer 3 + 4 (anti-debug, self-
       integrity; silent exit on tamper)
    3. LicenseClient.verify_installed()   — silent launch verification
    4a. VALID        -> run your main window
    4b. MISSING      -> show the activation dialog -> run on success
    4c. other state  -> license error screen (with retry / exit)

*** WHERE YOUR OWN CODE GOES: `launch_main_window()` below — the rest of the
*** flow never needs to change. Your business logic lives in ui/ and any
*** number of your own modules; nothing about licensing leaks into them
*** beyond the payload (customer, expiry, feature flags) you may read.

Run from the repository root:
    python -m target_demo.main            (set SC_DEV=1 under a real debugger)
Nuitka build (see build.bat at the repo root).
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 1) Logging bootstrap — rotating file handler, NEVER logs secrets.
# ---------------------------------------------------------------------------
def _setup_logging() -> None:
    log_dir = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / \
        "SecureCode" / "SecureNotepad" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        log_dir / "securenotepad.log", maxBytes=512 * 1024,
        backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    # Console output only in dev mode (frozen builds must stay silent).
    if os.environ.get("SC_DEV") == "1":
        root.addHandler(logging.StreamHandler())


def _setup_dpi() -> None:
    """Crisp DPI scaling on Windows (Qt6 defaults are good; we make the
    rounding policy explicit and prefer the modern Segoe UI Variable font)."""
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")


# ---------------------------------------------------------------------------
# The application.
# ---------------------------------------------------------------------------
def launch_main_window(app, client, payload) -> int:
    """Instantiate YOUR product here. Replace SecureNotepadWindow with your
    own main window class — everything else in the flow stays identical."""
    from target_demo.ui.main_window import SecureNotepadWindow

    window = SecureNotepadWindow(client, payload)
    window.show()
    return app.exec()


def main() -> int:
    """Entry point: protection -> verification -> activation -> product."""
    _setup_logging()
    _setup_dpi()
    log = logging.getLogger("demo.main")

    # Qt import AFTER logging so Qt warnings land in the rotating file too.
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    app.setApplicationName("SecureNotepad")
    app.setOrganizationName("SecureCode")

    # ------------------------------------------------------------------ 2) protection
    from target_demo.protection import (
        DEMO_PRODUCT_ID,
        LicenseClient,
        LicenseState,
        ProtectionConfig,
        ProtectionRuntime,
    )

    config = ProtectionConfig(
        # >>> Point product_id at YOUR product's UUID (protector -> Settings ->
        # >>> Product manager) and adjust names for your app's directories.
        product_id=DEMO_PRODUCT_ID,
        product_name="SecureNotepad",
        company_name="SecureCode",
        # >>> Layer-3 policy: EXIT silently (default). DEGRADE keeps the app
        # >>> alive but licensing starts failing with a generic error.
        vm_detection_enabled=False,
    )
    runtime = ProtectionRuntime.bootstrap(config)
    log.info("protection bootstrapped (dev=%s)", config.dev_mode_active())

    # ------------------------------------------------------------------ 3) verification
    client = LicenseClient(config, clock_guard=runtime.clock_guard)

    while True:  # single retry loop: error screen offers a "Retry"
        status = client.verify_installed(
            degraded=runtime.degraded or False)

        # 4a) VALID -> straight into the product.
        if status.state is LicenseState.VALID:
            log.info("license verified; launching product")
            try:
                return launch_main_window(app, client, status.payload)
            finally:
                runtime.shutdown()

        # 4b) MISSING -> activation dialog.
        if status.state is LicenseState.MISSING:
            from target_demo.ui.activation_dialog import ActivationDialog

            dialog = ActivationDialog(client)
            dialog.exec()
            if dialog.activated:
                continue  # re-verify the freshly activated license
            return 0  # user declined activation -> quiet exit

        # 4c) everything else -> professional license error screen.
        from target_demo.ui.license_error import LicenseErrorDialog

        log.warning("license blocked: %s", status.state.value)
        error = LicenseErrorDialog(status, client.machine_code())
        error.exec()
        if error.retry_requested:
            continue
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
