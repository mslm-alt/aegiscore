import importlib
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


class _ImmediateController:
    def __init__(self, owner=None, interval_ms=None):
        return None

    def trigger(self, task=None, on_result=None, on_error=None, on_finished=None):
        if task is not None and on_result is not None:
            on_result(task())
        if on_finished is not None:
            on_finished()
        return True


def test_reports_view_import_graceful():
    pytest.importorskip("PySide6")
    module = importlib.import_module("ui.views.reports")
    assert module.ReportsView is not None


def test_reports_view_only_shows_artifacts_and_preview(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.reports as reports_module

    monkeypatch.setattr(reports_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(reports_module.backend_facade, "collect_reports_summary", lambda **kwargs: {"status": "ok", "empty": False})
    monkeypatch.setattr(reports_module.backend_facade, "collect_report_artifacts", lambda **kwargs: {
        "artifacts": [{
            "name": "report.html",
            "path": "/tmp/report.html",
            "kind": "html",
            "size": 1234,
            "modified_text": "2026-05-19 12:00:00",
            "readable": True,
        }],
    })
    monkeypatch.setattr(reports_module.backend_facade, "collect_report_preview", lambda path: {
        "status": "ok",
        "kind": "html",
        "path": path,
        "preview": "<html>preview</html>",
    })

    view = reports_module.ReportsView()

    assert view._tabs.count() == 2
    assert view._tabs.tabText(0) == "Report Artifacts"
    assert view._tabs.tabText(1) == "Preview"
    assert not hasattr(view, "_generate")
    assert not hasattr(view, "_open_external")
    assert "preview" in view._preview_text.toPlainText().lower()
    assert "Browse available report artifacts" in view._status_note.text()


def test_reports_view_selection_updates_preview(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.reports as reports_module

    monkeypatch.setattr(reports_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(reports_module.backend_facade, "collect_reports_summary", lambda **kwargs: {"status": "ok", "empty": False})
    monkeypatch.setattr(reports_module.backend_facade, "collect_report_artifacts", lambda **kwargs: {
        "artifacts": [
            {
                "name": "report-1.txt",
                "path": "/tmp/report-1.txt",
                "kind": "txt",
                "size": 10,
                "modified_text": "2026-05-19 12:00:00",
                "readable": True,
            },
            {
                "name": "report-2.txt",
                "path": "/tmp/report-2.txt",
                "kind": "txt",
                "size": 12,
                "modified_text": "2026-05-19 12:01:00",
                "readable": True,
            },
        ],
    })
    monkeypatch.setattr(reports_module.backend_facade, "collect_report_preview", lambda path: {
        "status": "ok",
        "kind": "txt",
        "path": path,
        "preview": f"preview:{path}",
    })

    view = reports_module.ReportsView()
    view._artifacts_table.selectRow(1)
    view._load_selected_preview()

    assert view._tabs.currentIndex() == 1
    assert "report-2.txt" in view._preview_status.text()
    assert "preview:/tmp/report-2.txt" == view._preview_text.toPlainText()
