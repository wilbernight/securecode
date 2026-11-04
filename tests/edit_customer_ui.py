"""Dev helper: end-to-end UI test of ManagerPage._edit_customer (headless).

Run:  QT_QPA_PLATFORM=offscreen python3 -m tests.edit_customer_ui
"""
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

app = QApplication([])

from protector.core.crypto_engine import KeyStore
from protector.core.db import LicenseDB
from protector.core.settings import AppSettings
from protector.ui.services import Services
from protector.ui.theme import ThemeManager

root = tempfile.mkdtemp(prefix="protector-editname-")
ks = KeyStore(os.path.join(root, "keystore.dat"))
ks.create("test-passphrase-123")
db = LicenseDB(os.path.join(root, "licenses.db"), ks.db_master)
st = AppSettings(os.path.join(root, "settings.dat"), ks.db_master)
theme = ThemeManager(st.theme, st.accent)
theme.apply(app)

from shared.payload_schema import LicensePayload
from protector.ui.main_window import ShellWindow

# --- seed one lifetime serial (like the real 'بازرسی' record) --------------
lp = LicensePayload(
    fingerprint="AAAA-BBBB-CCCC-DDDD", product_id=str(st.products()[0]["id"])
    if st.products() else "00000000-0000-0000-0000-000000000000",
    issued_at=int(time.time()), expires_at=0,
    customer="بازرسي", nonce="nonce-edit-1",
)
rid = db.add_serial("SERIAL-EDIT-TEST-0001", lp)

svc = Services(app=app, keystore=ks, db=db, settings=st, theme=theme)
win = ShellWindow(svc)
win.show()
win._goto("manager")
app.processEvents()

# --- wait for the navigation-triggered load, then select the seeded row ------
page = win._pages["manager"]
deadline = time.time() + 10
while time.time() < deadline:
    app.processEvents()
    if page.table.rowCount() == 1:
        break
    time.sleep(0.05)
assert page.table.rowCount() == 1, "manager table did not load the record"
page.table.selectRow(0)
app.processEvents()
sel = page._selected_record()
assert sel is not None, "row selection did not map to a record"
print("✅ manager table loaded; row selected:", sel.customer)

# --- 1) the new button must exist in the actions row -------------------------
texts = [b.text().strip() for b in page.findChildren(QPushButton)]
assert any("ویرایش نام" in t or "Edit name" in t for t in texts), \
    f"Edit-name button MISSING — actions row: {texts}"
print("✅ actions row contains the Edit-name button:",
      next(t for t in texts if "ویرایش نام" in t or "Edit name" in t))

# --- 2) real dialog constructs with the record -------------------------------
from protector.ui.pages.manager import EditCustomerDialog
rec = db.get_record(rid)
dlg = EditCustomerDialog(rec, win)
dlg.name_edit.setText("بازرسی")
assert dlg.name_edit.text() == "بازرسی"
print("✅ EditCustomerDialog constructs; prefilled:", dlg.name_edit.text())

# --- 3) full _edit_customer flow with a stubbed dialog (reissue ON) ----------
import protector.ui.pages.manager as manager_mod

class StubDialog:
    def __init__(self, record, parent=None):
        self.name_edit = type("E", (), {"text": lambda self: "بازرسی"})()
        self.reissue = type("C", (), {"isChecked": lambda self: True})()
    def exec(self):
        return manager_mod.QDialog.Accepted

orig = manager_mod.EditCustomerDialog
manager_mod.EditCustomerDialog = StubDialog
try:
    page._edit_customer()
    deadline = time.time() + 10
    while time.time() < deadline:
        app.processEvents()
        rec = db.get_record(rid)
        # The rename and the re-issued serial land in separate writes; wait
        # for both, otherwise the test races the worker thread (flaky).
        if rec.customer == "بازرسی" and rec.serial != "SERIAL-EDIT-TEST-0001":
            break
        time.sleep(0.05)
finally:
    manager_mod.EditCustomerDialog = orig

updated = db.get_record(rid)
assert updated.customer == "بازرسی", f"rename failed: {updated.customer!r}"
assert updated.expires_at == 0, "lifetime expiry was not preserved"
assert updated.serial != "SERIAL-EDIT-TEST-0001", "serial was not re-issued"
print(f"✅ _edit_customer: DB renamed → {updated.customer!r}, "
      f"expiry kept (lifetime), serial re-issued ({updated.serial[:12]}…)")

# --- 4) search by the corrected name finds it ----------------------------------
assert db.list_records(search="بازرسی")[0].id == rid
print("✅ search finds the corrected name")

print("\nALL EDIT-NAME UI TESTS PASSED")
sys.stdout.flush()
os._exit(0)
