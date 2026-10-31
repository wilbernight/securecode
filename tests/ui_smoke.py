"""Dev helper: UI smoke test run as a file (clean traceback capture)."""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtWidgets import QApplication

app = QApplication([])

from protector.core.crypto_engine import KeyStore
from protector.core.db import LicenseDB
from protector.core.settings import AppSettings
from protector.ui.services import Services
from protector.ui.theme import ThemeManager

root = tempfile.mkdtemp(prefix="protector-ui-")
ks = KeyStore(os.path.join(root, "keystore.dat"))
ks.create("test-passphrase-123")
db = LicenseDB(os.path.join(root, "licenses.db"), ks.db_master)
st = AppSettings(os.path.join(root, "settings.dat"), ks.db_master)
theme = ThemeManager(st.theme, st.accent)
theme.apply(app)

from protector.ui.main_window import ShellWindow

svc = Services(app=app, keystore=ks, db=db, settings=st, theme=theme)
win = ShellWindow(svc)
win.show()
for key in ("dashboard", "generate", "manager", "fingerprint", "build", "settings"):
    win._goto(key)
app.processEvents()
svc.toast.show("success", "Smoke test", "toast rendering works")
gp = win._pages["generate"]
gp.fingerprint.setText("AABBCCDD-EEFF-1122-3344")
gp._add_flag("core", True)
app.processEvents()
print("UI smoke: OK — shell + 6 pages, navigation, toasts, validation OK")
ks.close()
# Qt objects are torn down in arbitrary order after exec-less runs, which
# can trigger a fail-fast abort at interpreter shutdown — exit explicitly.
sys.stdout.flush()
os._exit(0)
