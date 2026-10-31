"""Dev helper: render the restyled protector offscreen and capture
screenshots of the O&O-style professional GUI (light + dark) — bilingual
dashboard, Vazirmatn font, Jalali today chip, grouped sidebar.

Saves demo-run/04_dashboard_light.png, 05_dashboard_dark.png,
06_generate_jalali.png.
"""
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

OUT = Path(__file__).resolve().parents[1] / "demo-run"
OUT.mkdir(exist_ok=True)

from PySide6.QtWidgets import QApplication

app = QApplication([])

from protector.core.crypto_engine import KeyStore
from protector.core.db import LicenseDB
from protector.core.settings import AppSettings
from protector.ui.services import Services
from protector.ui.theme import ThemeManager

root = tempfile.mkdtemp(prefix="protector-restyle-")
ks = KeyStore(os.path.join(root, "keystore.dat"))
ks.create("test-passphrase-123")
db = LicenseDB(os.path.join(root, "licenses.db"), ks.db_master)
st = AppSettings(os.path.join(root, "settings.dat"), ks.db_master)
theme = ThemeManager(st.theme, st.accent)   # light default (O&O style)
theme.apply(app)

from protector.ui.main_window import ShellWindow

svc = Services(app=app, keystore=ks, db=db, settings=st, theme=theme)
win = ShellWindow(svc)
win.resize(1280, 800)
win.show()

# Dashboard through the real async path — also proves the hang fix.
win._goto("dashboard")
app.processEvents()
deadline = time.time() + 6
while time.time() < deadline:
    app.processEvents()
    spinners = [c for c in win._pages["dashboard"].children()
                if c.__class__.__name__ == "SpinnerOverlay"]
    if not spinners or not spinners[0].isVisible():
        break
    time.sleep(0.05)
app.processEvents()
win.grab().save(str(OUT / "04_dashboard_light.png"), "PNG")

# Dark mode of the same dashboard.
svc.theme.restyle(app, mode="dark", accent=st.accent)
app.processEvents()
win._goto("dashboard")
app.processEvents()
win.grab().save(str(OUT / "05_dashboard_dark.png"), "PNG")

# Generate page (light again) with the Jalali date picker visible.
svc.theme.restyle(app, mode="light", accent=st.accent)
win._goto("generate")
gp = win._pages["generate"]
gp.duration.setCurrentIndex(5)  # "Custom date…" -> shows JalaliDateEdit
app.processEvents()
win.grab().save(str(OUT / "06_generate_jalali.png"), "PNG")

print("restyle visual: 04_dashboard_light.png, 05_dashboard_dark.png, "
      "06_generate_jalali.png saved")
ks.close()
sys.stdout.flush()
os._exit(0)
