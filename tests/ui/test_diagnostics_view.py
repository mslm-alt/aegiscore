import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _qt_app():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_diagnostics_view_refreshes_summary_and_bundle_preview(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.diagnostics as diagnostics_module

    class _ImmediateController:
        def __init__(self, owner=None, interval_ms=None):
            self._task = None
            self._on_result = None
            self._on_finished = None

        def configure(self, task=None, on_result=None, on_error=None, on_finished=None):
            self._task = task
            self._on_result = on_result
            self._on_finished = on_finished

        def trigger(self, task=None, on_result=None, on_error=None, on_finished=None):
            task = task or self._task
            on_result = on_result or self._on_result
            on_finished = on_finished or self._on_finished
            if task is not None and on_result is not None:
                on_result(task())
            if on_finished is not None:
                on_finished()
            return True

    monkeypatch.setattr(diagnostics_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(diagnostics_module.backend_facade, "collect_diagnostics_summary", lambda config_path=None: {
        "status": "ok",
        "db_health": {"status": "ok"},
        "schema_version": 4,
        "rule_count": 179,
        "open_incidents": 2,
        "degraded_flags": [],
        "parse_fail_summary": {},
        "duplicate_summary": {},
        "runtime": {"pressure": {}},
    })
    monkeypatch.setattr(diagnostics_module.backend_facade, "collect_diagnostic_bundle_preview", lambda config_path=None: {
        "message": "Preview only.",
        "would_include": ["db health"],
        "would_redact": ["API keys"],
        "would_exclude": ["database dumps"],
    })

    view = diagnostics_module.DiagnosticsView()

    assert view._summary.text() == "OK"
    assert "Schema version: 4" in view._text.toPlainText()
    assert "db health" in view._bundle_text.toPlainText().lower()


def test_diagnostics_view_not_exposed_in_main_window_navigation():
    source = Path("ui/main_window.py").read_text(encoding="utf-8")

    assert "DiagnosticsView" not in source
