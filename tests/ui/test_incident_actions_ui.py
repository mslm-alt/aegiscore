from pathlib import Path
import importlib
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _qt_app():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_incidents_view_import_graceful():
    pytest.importorskip("PySide6")
    module = importlib.import_module("ui.views.incidents")
    assert module.IncidentsView is not None


def test_incidents_view_preview_and_execute_smoke(monkeypatch):
    pytest.importorskip("PySide6")
    _qt_app()

    import ui.views.incidents as incidents_module

    class _ImmediateController:
        def __init__(self, owner=None, interval_ms=None):
            self._task = None
            self._on_result = None
            self._on_error = None

        def configure(self, task=None, on_result=None, on_error=None, on_finished=None):
            self._task = task
            self._on_result = on_result
            self._on_error = on_error

        def trigger(self, task=None, on_result=None, on_error=None, on_finished=None):
            task = task or self._task
            on_result = on_result or self._on_result
            if task is not None and on_result is not None:
                on_result(task())
            if on_finished is not None:
                on_finished()
            return True

        def start(self):
            return None

    monkeypatch.setattr(incidents_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(incidents_module.backend_facade, "collect_incidents", lambda **kwargs: {
        "status": "ok",
        "incidents": [{
            "id": 7,
            "created_at": 1710000000,
            "timestamp_text": "2024-03-09 16:00:00",
            "severity": "high",
            "status": "open",
            "title": "Suspicious auth burst",
            "entity_key": "alice",
            "alert_count": 3,
            "risk_score": 92.5,
            "summary": "summary",
            "evidence": [],
            "raw": {},
        }],
        "error": None,
    })
    monkeypatch.setattr(incidents_module.backend_facade, "collect_incident_detail", lambda incident_id, config_path=None: {
        "status": "ok",
        "incident": {"id": incident_id, "status": "open", "severity": "high", "entity_key": "alice", "alert_count": 3},
        "related_alerts": [],
        "detail": {"summary_text": "summary", "evidence_text": "[]"},
        "error": None,
    })
    monkeypatch.setattr(incidents_module.backend_facade, "preview_incident_action", lambda **kwargs: {
        "status": "ready",
        "action": "resolve",
        "incident_id": 7,
        "incident": {"id": 7, "status": "open", "severity": "high", "title": "Suspicious auth burst", "entity_key": "alice", "alert_count": 3},
        "guard": {
            "status": "ready",
            "execution_enabled": True,
            "metadata": {"request": {"required_confirmation_phrase": "CONFIRM INCIDENT_RESOLVE 7"}},
        },
        "would_update": {"status": "resolved", "reason": "ticket", "ml_resume": False, "delete_alerts": False, "delete_events": False},
        "message": "ready",
        "warning": "",
    })
    monkeypatch.setattr(incidents_module.backend_facade, "execute_incident_action", lambda **kwargs: {
        "status": "executed",
        "incident_id": 7,
        "message": "Incident status updated to resolved.",
    })

    view = incidents_module.IncidentsView()
    view.select_incident(7)
    view._role.setCurrentText("admin")
    view._reason.setText("ticket")
    view._confirmation.setText("CONFIRM INCIDENT_RESOLVE 7")
    view._run_preview()

    assert view._execute_button.isEnabled() is True

    view._execute_action()
    assert "updated" in view._preview_status.text().lower()


def test_alert_open_incident_callback_smoke(monkeypatch):
    pytest.importorskip("PySide6")
    _qt_app()

    import ui.views.alerts as alerts_module

    class _ImmediateController:
        def __init__(self, owner=None, interval_ms=None):
            self._task = None
            self._on_result = None
            self._on_error = None
            self._on_finished = None

        def configure(self, task=None, on_result=None, on_error=None, on_finished=None):
            self._task = task
            self._on_result = on_result
            self._on_error = on_error
            self._on_finished = on_finished

        def start(self):
            return None

        def trigger(self, task=None, on_result=None, on_error=None, on_finished=None):
            task = task or self._task
            on_result = on_result or self._on_result
            on_finished = on_finished or self._on_finished
            if task is not None and on_result is not None:
                on_result(task())
            if on_finished is not None:
                on_finished()
            return True

    monkeypatch.setattr(alerts_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alerts", lambda **kwargs: {
        "status": "ok",
        "alerts": [{
            "id": 11,
            "created_at": 1710000000,
            "timestamp_text": "2024-03-09 16:00:00",
            "severity": "high",
            "rule_id": "RULE-11",
            "risk_score": 90.0,
            "entity": "alice",
            "source_ip": "8.8.8.8",
            "target_ip": "",
            "source": "auth_log",
            "message": "ssh brute force",
            "raw": {"incident_id": 7},
        }],
        "error": None,
    })
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": {"id": alert_id},
        "detail": {"explanation_text": "ok"},
        "error": None,
    })
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alert_correlations", lambda alert_id, config_path=None: {"groups": {}})
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alert_raw_parsed", lambda alert_id, config_path=None: {"raw_text": "", "parsed_text": ""})
    monkeypatch.setattr(alerts_module.backend_facade, "collect_entity_timeline", lambda entity, config_path=None: {"entity": entity, "summary": {}, "events": []})

    seen = []
    view = alerts_module.AlertsView(open_incident=seen.append)
    view._table.selectRow(0)
    view._open_selected_incident()

    assert seen == [7]
