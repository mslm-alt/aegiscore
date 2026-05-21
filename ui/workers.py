from __future__ import annotations

import traceback

from ui.models import WorkerError

try:
    from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Signal, Slot
    from shiboken6 import isValid
except ImportError:  # pragma: no cover - graceful import path for non-Qt test envs
    QObject = object  # type: ignore[assignment]
    QRunnable = object  # type: ignore[assignment]
    QThreadPool = object  # type: ignore[assignment]
    QTimer = object  # type: ignore[assignment]
    Signal = None  # type: ignore[assignment]
    isValid = lambda obj: obj is not None  # type: ignore[assignment]
    Slot = lambda *args, **kwargs: (lambda fn: fn)  # type: ignore[assignment]


QT_AVAILABLE = Signal is not None


def run_guarded(func, *args, **kwargs):
    try:
        return True, func(*args, **kwargs), None
    except Exception as exc:  # pragma: no cover - exercised through tests
        return False, None, WorkerError(
            type=type(exc).__name__,
            message=str(exc),
            traceback=traceback.format_exc(),
        ).to_dict()


if QT_AVAILABLE:
    class WorkerSignals(QObject):
        result = Signal(object)
        error = Signal(object)
        finished = Signal()


    class FunctionWorker(QRunnable):
        def __init__(self, func, *args, **kwargs):
            super().__init__()
            self._func = func
            self._args = args
            self._kwargs = kwargs
            self.signals = WorkerSignals()
            self.setAutoDelete(False)

        @Slot()
        def run(self):
            try:
                ok, result, error = run_guarded(self._func, *self._args, **self._kwargs)
                if ok:
                    try:
                        if isValid(self.signals):
                            self.signals.result.emit(result)
                    except RuntimeError:
                        pass
                else:
                    try:
                        if isValid(self.signals):
                            self.signals.error.emit(error)
                    except RuntimeError:
                        pass
            finally:
                try:
                    if isValid(self.signals):
                        self.signals.finished.emit()
                except RuntimeError:
                    pass


    class RefreshController(QObject):
        def __init__(self, owner, interval_ms: int | None = None):
            super().__init__(owner)
            self._pool = QThreadPool.globalInstance()
            self._busy = False
            self._paused = False
            self._default_task = None
            self._default_on_result = None
            self._default_on_error = None
            self._default_on_finished = None
            self._timer = None
            self._disposed = False
            self._active_workers = set()
            if interval_ms:
                self._timer = QTimer(self)
                self._timer.setInterval(int(interval_ms))
                self._timer.timeout.connect(self.trigger)

        def configure(self, task=None, on_result=None, on_error=None, on_finished=None):
            self._default_task = task
            self._default_on_result = on_result
            self._default_on_error = on_error
            self._default_on_finished = on_finished

        def start(self):
            if self._timer is not None and not self._paused and not self._disposed:
                self._timer.start()

        def stop(self):
            if self._timer is not None:
                self._timer.stop()
            self._paused = True

        def safe_stop(self):
            self.stop()
            return None

        def dispose(self):
            if self._disposed:
                return None
            self._disposed = True
            self.stop()
            self._default_task = None
            self._default_on_result = None
            self._default_on_error = None
            self._default_on_finished = None
            self._active_workers.clear()
            return None

        def resume(self):
            if self._disposed:
                return None
            self._paused = False
            if self._timer is not None:
                self._timer.start()

        def set_interval(self, interval_ms: int):
            if self._timer is not None:
                self._timer.setInterval(max(1000, int(interval_ms or 1000)))

        def is_paused(self) -> bool:
            return self._paused

        def trigger(self, task=None, on_result=None, on_error=None, on_finished=None):
            task = task or self._default_task
            on_result = on_result or self._default_on_result
            on_error = on_error or self._default_on_error
            on_finished = on_finished or self._default_on_finished
            if task is None or on_result is None or self._busy or self._paused or self._disposed:
                return False
            self._busy = True
            worker = FunctionWorker(task)
            self._active_workers.add(worker)

            def _safe_result(result):
                if self._disposed:
                    return None
                try:
                    on_result(result)
                except RuntimeError:
                    return None
                return None

            def _safe_error(error):
                if self._disposed or on_error is None:
                    return None
                try:
                    on_error(error)
                except RuntimeError:
                    return None
                return None

            worker.signals.result.connect(_safe_result)
            if on_error is not None:
                worker.signals.error.connect(_safe_error)

            def _finished():
                self._active_workers.discard(worker)
                self._busy = False
                if self._disposed or on_finished is None:
                    return None
                try:
                    on_finished()
                except RuntimeError:
                    return None
                return None

            worker.signals.finished.connect(_finished)
            self._pool.start(worker)
            return True
else:
    class WorkerSignals:  # pragma: no cover - import fallback only
        def __init__(self):
            self.result = None
            self.error = None
            self.finished = None


    class FunctionWorker:  # pragma: no cover - import fallback only
        def __init__(self, func, *args, **kwargs):
            self._func = func
            self._args = args
            self._kwargs = kwargs
            self.signals = WorkerSignals()


    class RefreshController:  # pragma: no cover - import fallback only
        def __init__(self, owner=None, interval_ms: int | None = None):
            self._busy = False
            self._paused = False
            self._disposed = False
            self._default_task = None
            self._default_on_result = None
            self._default_on_error = None
            self._default_on_finished = None

        def configure(self, task=None, on_result=None, on_error=None, on_finished=None):
            self._default_task = task
            self._default_on_result = on_result
            self._default_on_error = on_error
            self._default_on_finished = on_finished

        def start(self):
            return None

        def stop(self):
            self._paused = True
            return None

        def safe_stop(self):
            return self.stop()

        def dispose(self):
            self._disposed = True
            self._default_task = None
            self._default_on_result = None
            self._default_on_error = None
            self._default_on_finished = None
            return self.stop()

        def resume(self):
            self._paused = False
            return None

        def set_interval(self, interval_ms: int):
            return None

        def is_paused(self) -> bool:
            return self._paused

        def trigger(self, task=None, on_result=None, on_error=None, on_finished=None):
            task = task or self._default_task
            on_result = on_result or self._default_on_result
            on_error = on_error or self._default_on_error
            on_finished = on_finished or self._default_on_finished
            if self._paused or self._disposed:
                return False
            ok, result, error = run_guarded(task) if task is not None else (False, None, None)
            if ok and on_result is not None:
                on_result(result)
            elif not ok and on_error is not None:
                on_error(error)
            if on_finished is not None:
                on_finished()
            return ok
