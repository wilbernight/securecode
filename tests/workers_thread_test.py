"""Dev helper: verifies run_task delivers results on the GUI thread.

Also regression-checks the two historical "stuck at loading" bugs:
  1) results must be delivered on the GUI (main) thread  — the _Relay fix;
  2) the caller may DISCARD run_task's return value (as pages do) and the
     job must still run to completion — the _active_tasks pinning fix.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThread, QTimer
from PySide6.QtWidgets import QApplication, QWidget

app = QApplication([])
page = QWidget()
page.resize(400, 300)
page.show()

worker_thread_id = {}
delivery = {}

from protector.ui.widgets.workers import run_task


def job():
    worker_thread_id["value"] = QThread.currentThread()
    return "result-ok"


def done(result):
    delivery["thread"] = QThread.currentThread()
    delivery["is_main"] = QThread.currentThread() is app.thread()
    delivery["result"] = result


run_task(page, job, done, busy_text="testing…")  # return value deliberately discarded
QTimer.singleShot(800, app.quit)
app.exec()

assert delivery, "on_done never ran"
assert delivery["result"] == "result-ok", delivery["result"]
assert worker_thread_id["value"] is not app.thread(), "job should run off the GUI thread"
assert delivery["is_main"], "result must be delivered on the GUI thread"
print("job thread:      worker (non-GUI) OK")
print("delivery thread: Qt mainThread OK")
print("VERDICT: PASS — delivery on GUI thread, worker pinned despite discarded ref")
sys.stdout.flush()
os._exit(0)
