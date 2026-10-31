"""Functional test: clicking a product UUID cell copies it to the clipboard.

Covers the Settings -> Products table click-to-copy affordance:
  1. cellClicked on the UUID column copies the cell text to the clipboard.
  2. cellClicked on other columns leaves the clipboard untouched.
Run from the repository root:  python tests/uuid_copy_test.py
"""

import os
import sys
import tempfile
import uuid as uuidlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QGuiApplication  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

app = QApplication([])

from protector.core.crypto_engine import KeyStore  # noqa: E402
from protector.core.db import LicenseDB  # noqa: E402
from protector.core.settings import AppSettings  # noqa: E402
from protector.ui.services import Services  # noqa: E402
from protector.ui.theme import ThemeManager  # noqa: E402

root = tempfile.mkdtemp(prefix="protector-uuidcopy-")
ks = KeyStore(os.path.join(root, "keystore.dat"))
ks.create("test-passphrase-123")
db = LicenseDB(os.path.join(root, "licenses.db"), ks.db_master)
st = AppSettings(os.path.join(root, "settings.dat"), ks.db_master)
theme = ThemeManager(st.theme, st.accent)
theme.apply(app)

test_uuid = str(uuidlib.uuid4())
st.add_product("ClickCopy Test", test_uuid, "9.9")

from protector.ui.main_window import ShellWindow  # noqa: E402

svc = Services(app=app, keystore=ks, db=db, settings=st, theme=theme)
win = ShellWindow(svc)
win._goto("settings")
app.processEvents()

page = win._pages["settings"]
page.refresh()
app.processEvents()

# find the row carrying our test UUID
target_row = None
for row in range(page.products_table.rowCount()):
    if page.products_table.item(row, 1).text() == test_uuid:
        target_row = row
        break
assert target_row is not None, "test product row not found in the table"

# 1) click the UUID cell -> clipboard must contain the UUID
page.products_table.cellClicked.emit(target_row, 1)
app.processEvents()
assert QGuiApplication.clipboard().text() == test_uuid, "UUID not copied on click"

# 2) click the name cell -> clipboard must stay untouched
QGuiApplication.clipboard().setText("sentinel-value")
page.products_table.cellClicked.emit(target_row, 0)
app.processEvents()
assert QGuiApplication.clipboard().text() == "sentinel-value", \
    "non-UUID column must not touch the clipboard"

# 3) the tooltip advertises the affordance (bilingual via tr())
tip = page.products_table.item(target_row, 1).toolTip()
assert tip and "copy" in tip.lower(), f"unexpected tooltip: {tip!r}"

print("uuid click-to-copy: PASS "
      "(click copies, other columns untouched, tooltip present)")
ks.close()
sys.stdout.flush()
os._exit(0)
