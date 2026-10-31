"""Dev helper: isolate the relay signal-chain behavior."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal
from PySide6.QtWidgets import QApplication, QWidget

app = QApplication([])
page = QWidget()

from protector.ui.widgets.workers import Worker


class _Relay(QObject):
    finished = Signal(object)


worker = Worker(lambda: ("job-thread", str(QThread.currentThread())))
thread = QThread(page)
relay = _Relay(page)
worker.moveToThread(thread)

worker.finished.connect(
    lambda r: print("DIRECT from worker thread:", str(QThread.currentThread()),
                   flush=True),
    Qt.DirectConnection)
worker.finished.connect(relay.finished)
relay.finished.connect(
    lambda r: print("RELAY delivered on thread:", str(QThread.currentThread()),
                    "result:", r, flush=True))
thread.started.connect(worker.run)
thread.start()

QTimer.singleShot(600, app.quit)
app.exec()
print("event loop finished", flush=True)
sys.stdout.flush()
os._exit(0)
