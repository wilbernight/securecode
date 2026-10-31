"""Dev helper: demo-app UI smoke test (activation + notepad windows)."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("SC_DEV", "1")

from PySide6.QtWidgets import QApplication

app = QApplication([])

from target_demo.protection import (
    DEMO_PRODUCT_ID,
    LicenseClient,
    LicenseState,
    ProtectionConfig,
)

config = ProtectionConfig(product_id=DEMO_PRODUCT_ID)
client = LicenseClient(config)

from target_demo.ui.activation_dialog import ActivationDialog

dialog = ActivationDialog(client)
print("activation dialog: OK —", dialog.windowTitle())

from shared.payload_schema import LicensePayload
from target_demo.ui.main_window import SecureNotepadWindow

payload = LicensePayload(
    fingerprint="AABBCCDD-EEFF-1122-3344",
    product_id=DEMO_PRODUCT_ID,
    issued_at=1700000000,
    expires_at=1900000000,
    customer="Smoke Test",
    feature_flags={"core": True},
)
window = SecureNotepadWindow(client, payload)
window.editor.setPlainText("protected text")
window.statusBar().showMessage("ready")
app.processEvents()
print("main window: OK —", window.windowTitle())

from target_demo.ui.license_error import LicenseErrorDialog
from target_demo.protection.license_client import LicenseStatus

error = LicenseErrorDialog(
    LicenseStatus(LicenseState.EXPIRED, "expired"), "AABB-CCDD-EEFF-1122")
print("license error dialog: OK —", error.windowTitle())

print("Demo UI smoke: OK")
sys.stdout.flush()
os._exit(0)
