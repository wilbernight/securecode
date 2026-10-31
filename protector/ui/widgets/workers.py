"""
protector.ui.widgets.workers — QThread plumbing for non-blocking operations.

Rule: NOTHING crypto/database-y runs on the GUI thread (spec requirement).

``run_task`` is the launcher used across pages: shows a spinner overlay over
the parent widget, runs the job in a worker thread, then delivers the result
(or a friendly error) ON THE GUI THREAD.

Why the ``_Relay`` object exists (a real bug this file had): connecting a
plain Python closure directly to a worker's signal makes the closure run in
the EMITTER's (worker) thread on PySide6. Touching widgets from that thread
(hide()/setText/…) can hard-deadlock native windows on Windows — exactly
the "stuck at loading" symptom. The relay is a QObject living on the GUI
thread: worker→relay is a queued signal-to-signal connection, so the relay
re-emits (and the closures run) on the GUI thread, guaranteed.

The ``_active_tasks`` registry exists because of a second real bug: the
Worker is an unparented QObject, so a caller that ignores run_task's return
value lets Python's GC destroy it mid-flight — the job then never runs and
the spinner spins forever. Tasks are pinned until _cleanup() executes.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import QWidget

from .spinner import SpinnerOverlay

log = logging.getLogger("protector.workers")

#: Strong references for in-flight tasks. The Worker is an UNPARENTED QObject
#: (moveToThread requires no parent), so if the caller discards run_task's
#: return value — which every page does — Python's GC can destroy the worker
#: mid-flight, silently severing the whole signal chain (job never runs,
#: spinner spins forever: the OTHER half of the "stuck at loading" bug).
#: Entries are removed by _cleanup(), which always runs on the GUI thread.
_active_tasks: set[tuple[Worker, QThread, "_Relay"]] = set()


class Worker(QObject):
    """Runs ``fn`` in a QThread and reports back via signals."""

    finished = Signal(object)   # result value
    failed = Signal(str)        # user-presentable error message

    def __init__(self, fn: Callable[[], Any]) -> None:
        super().__init__()
        self._fn = fn

    # Invoked via the thread's started signal -> runs on the worker thread.
    def run(self) -> None:
        try:
            result = self._fn()
            self.finished.emit(result)
        except Exception as exc:  # noqa: BLE001 — worker boundary
            log.error("worker task failed: %s", exc, exc_info=True)
            user_message = (
                getattr(exc, "user_message", None) or str(exc) or "Operation failed."
            )
            self.failed.emit(user_message)


class _Relay(QObject):
    """GUI-thread hop for worker results (see module docstring)."""

    finished = Signal(object)
    failed = Signal(str)


def run_task(parent: QWidget, fn: Callable[[], Any],
             on_done: Callable[[Any], None],
             on_error: Callable[[str], None] | None = None,
             busy_text: str = "Working…",
             overlay: bool = True) -> Worker:
    """Launch ``fn`` on a worker thread with an optional spinner overlay.

    Args:
        parent: widget to overlay (and to parent the worker objects under).
        fn: the blocking callable (runs on the worker thread).
        on_done: called on the GUI thread with fn's result.
        on_error: called on the GUI thread with a user-presentable message
            on failure (defaults to a log entry when omitted).
        busy_text: label shown on the spinner overlay.
        overlay: disable for fire-and-forget jobs.
    """
    spinner = SpinnerOverlay(parent) if overlay else None
    if spinner is not None:
        spinner.start(busy_text)

    worker = Worker(fn)
    thread = QThread(parent)
    relay = _Relay(parent)  # affinity: GUI thread (parent lives there)
    worker.moveToThread(thread)

    # Pin every object until the task completes (see _active_tasks comment).
    handle = (worker, thread, relay)
    _active_tasks.add(handle)

    def _cleanup() -> None:
        # Runs on the GUI thread: safe to touch widgets.
        _active_tasks.discard(handle)
        thread.quit()
        thread.finished.connect(thread.deleteLater)
        if spinner is not None:
            spinner.stop()
            spinner.deleteLater()
        relay.deleteLater()

    def _finish(result: Any) -> None:
        _cleanup()
        on_done(result)

    def _fail(message: str) -> None:
        _cleanup()
        if on_error is not None:
            on_error(message)
        else:
            log.error("worker failure (no handler): %s", message)

    # Queued (auto) connections: worker thread -> GUI thread.
    worker.finished.connect(relay.finished)
    worker.failed.connect(relay.failed)
    # Direct connections on the GUI thread -> closures run there.
    relay.finished.connect(_finish)
    relay.failed.connect(_fail)

    thread.started.connect(worker.run)
    thread.start()
    return worker


__all__ = ["Worker", "run_task"]
