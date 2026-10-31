"""Dev helper: render the restyled UnlockDialog (offscreen) for review."""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

OUT = Path(__file__).resolve().parents[1] / "demo-run"

from PySide6.QtWidgets import QApplication

app = QApplication([])
from protector.ui.theme import load_fonts

load_fonts()  # bilingual unlock needs Vazirmatn before the theme engine

from protector.core.crypto_engine import KeyStore
from protector.ui.unlock_dialog import UnlockDialog

root = tempfile.mkdtemp(prefix="unlock-visual-")
ks = KeyStore(os.path.join(root, "keystore.dat"))
ks.create("test-passphrase-123")
ks.close()

# UNLOCK mode (what the returning user sees)
from protector.ui.theme import ThemeManager
ThemeManager("light").apply(app)
dialog = UnlockDialog(ks)
dialog.show()
app.processEvents()
dialog.grab().save(str(OUT / "07_unlock_restyle.png"), "PNG")
print("saved 07_unlock_restyle.png")
sys.stdout.flush()
os._exit(0)
