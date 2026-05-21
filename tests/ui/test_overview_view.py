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


def test_overview_view_ml_paused_states(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.overview as overview_module

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

        def start(self):
            return None

    payloads = [
        {
            "overall": "PASS",
            "database": {"status": "ok"},
            "alert_count": 1,
            "open_incidents": 2,
            "phase": "PHASE_1",
            "ml_paused": True,
            "ml_pause_known": True,
            "ml_pause_reason": "incident_guard",
            "source_problem_count": 0,
            "security_locks": {
                "read_only_mode": True,
                "auto_ip_block_disabled": True,
                "manual_actions_locked": True,
            },
        },
        {
            "overall": "PASS",
            "database": {"status": "ok"},
            "alert_count": 1,
            "open_incidents": 2,
            "phase": "PHASE_1",
            "ml_paused": False,
            "ml_pause_known": True,
            "ml_pause_reason": "",
            "source_problem_count": 0,
            "security_locks": {
                "read_only_mode": True,
                "auto_ip_block_disabled": True,
                "manual_actions_locked": True,
            },
        },
        {
            "overall": "WARNING",
            "database": {"status": "degraded"},
            "alert_count": 0,
            "open_incidents": 0,
            "phase": "PHASE_0",
            "ml_paused": None,
            "ml_pause_known": False,
            "ml_pause_reason": "",
            "source_problem_count": 1,
            "security_locks": {
                "read_only_mode": True,
                "auto_ip_block_disabled": True,
                "manual_actions_locked": True,
            },
        },
    ]

    monkeypatch.setattr(overview_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(overview_module.backend_facade, "collect_overview_status", lambda config_path=None: payloads.pop(0))

    view = overview_module.OverviewView()
    assert view._metric_labels["ml_paused"].text() == "Yes"
    assert "incident_guard" in view._metric_labels["ml_paused"].toolTip()

    view.refresh()
    assert view._metric_labels["ml_paused"].text() == "No"

    view.refresh()
    assert view._metric_labels["ml_paused"].text() == "Unknown"


def test_overview_view_refresh_updates_summary_metrics(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.overview as overview_module

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

        def start(self):
            return None

    payloads = [
        {
            "overall": "PASS",
            "database": {"status": "ok"},
            "alert_count": 12,
            "open_incidents": 3,
            "phase": "PHASE_2",
            "ml_paused": False,
            "ml_pause_known": True,
            "ml_pause_reason": "",
            "source_problem_count": 1,
            "security_locks": {
                "read_only_mode": True,
                "auto_ip_block_disabled": True,
                "manual_actions_locked": True,
            },
        },
        {
            "overall": "WARNING",
            "database": {"status": "degraded"},
            "alert_count": 0,
            "open_incidents": 0,
            "phase": "PHASE_0",
            "ml_paused": True,
            "ml_pause_known": True,
            "ml_pause_reason": "incident_guard",
            "source_problem_count": 4,
            "security_locks": {
                "read_only_mode": False,
                "auto_ip_block_disabled": True,
                "manual_actions_locked": True,
            },
        },
    ]

    monkeypatch.setattr(overview_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(overview_module.backend_facade, "collect_overview_status", lambda config_path=None: payloads.pop(0))

    view = overview_module.OverviewView()
    assert view._metric_labels["db_health"].text() == "ok"
    assert view._metric_labels["alert_count"].text() == "12"
    assert view._metric_labels["open_incidents"].text() == "3"
    assert view._metric_labels["phase"].text() == "PHASE_2"
    assert view._metric_labels["source_problems"].text() == "1"
    assert view._metric_labels["security_locks"].text() == "active"

    view.refresh()
    assert view._metric_labels["db_health"].text() == "degraded"
    assert view._metric_labels["alert_count"].text() == "0"
    assert view._metric_labels["open_incidents"].text() == "0"
    assert view._metric_labels["phase"].text() == "PHASE_0"
    assert view._metric_labels["source_problems"].text() == "4"
    assert view._metric_labels["security_locks"].text() == "check"
    assert view._metric_labels["ml_paused"].text() == "Yes"
    assert "incident_guard" in view._metric_labels["ml_paused"].toolTip()
