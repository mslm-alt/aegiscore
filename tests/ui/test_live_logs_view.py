import importlib
import os
from pathlib import Path
import sys

import pytest
from ui.i18n import set_language

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _qt_app():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_live_logs_view_import_graceful():
    pytest.importorskip("PySide6")
    module = importlib.import_module("ui.views.live_logs")
    assert module.LiveLogsView is not None


def test_live_logs_view_uses_dialog_not_inline_detail(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.live_logs as live_logs_module

    detail_calls = {"count": 0}

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

        def stop(self):
            return None

        def set_interval(self, interval_ms):
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

    monkeypatch.setattr(live_logs_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_live_log_sources", lambda config_path=None: {
        "status": "ok",
        "sources": ["all", "auth_log"],
    })
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_log_health_summary", lambda config_path=None: {
        "status": "ok",
        "sources": ["auth_log"],
        "parse_fail_summary": {"count": 2},
        "duplicate_summary": {"count": 4, "telemetry_count": 1},
    })
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_recent_events", lambda **kwargs: {
        "status": "ok",
        "events": [{
            "id": 31,
            "timestamp_text": "2024-03-09 16:00:00",
            "source": "auth_log",
            "category": "auth",
            "action": "ssh_login",
            "outcome": "success",
            "src_ip": "8.8.8.8",
            "dst_ip": "",
            "username": "alice",
            "process": "sshd",
            "host": "host-a",
            "message": "user logged in",
            "raw": {"alert_id": 5},
            "raw_fields": {},
        }],
    })

    def _detail(event_id, config_path=None):
        detail_calls["count"] += 1
        return {
            "status": "ok",
            "event": {
                "id": event_id,
                "timestamp_text": "2024-03-09 16:00:00",
                "source": "auth_log",
                "category": "auth",
                "action": "ssh_login",
                "outcome": "success",
                "src_ip": "8.8.8.8",
                "username": "alice",
                "process": "sshd",
                "host": "host-a",
                "message": "user logged in",
            },
            "detail": {"raw_json": "{\"alert_id\": 5}"},
            "error": None,
        }

    monkeypatch.setattr(live_logs_module.backend_facade, "collect_event_detail", _detail)

    view = live_logs_module.LiveLogsView()
    assert not hasattr(view, "_detail_text")
    assert detail_calls["count"] == 0

    view._table.selectRow(0)
    assert view._view_details.isEnabled() is True
    assert detail_calls["count"] == 0

    view._show_selected_detail()

    assert detail_calls["count"] == 1
    assert view._detail_dialog is not None
    assert "Event #31" in view._detail_dialog._title.text()
    assert "user logged in" in view._detail_dialog._message.toPlainText()


def test_live_logs_view_refresh_and_filters_stay_available(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.live_logs as live_logs_module

    recent_calls = []

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

        def stop(self):
            return None

        def set_interval(self, interval_ms):
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

    monkeypatch.setattr(live_logs_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_live_log_sources", lambda config_path=None: {
        "status": "ok",
        "sources": ["all", "auth_log"],
    })
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_log_health_summary", lambda config_path=None: {
        "status": "ok",
        "sources": ["auth_log"],
        "parse_fail_summary": {"count": 0},
        "duplicate_summary": {"count": 0, "telemetry_count": 0},
    })

    def _recent(**kwargs):
        recent_calls.append(kwargs)
        return {"status": "ok", "events": []}

    monkeypatch.setattr(live_logs_module.backend_facade, "collect_recent_events", _recent)
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_event_detail", lambda event_id, config_path=None: {
        "status": "ok", "event": {"id": event_id}, "detail": {}, "error": None
    })

    view = live_logs_module.LiveLogsView()
    view._source.setCurrentText("auth_log")
    view._query.setText("alice")
    view._limit.setCurrentText("250")
    view.refresh()

    assert recent_calls
    assert recent_calls[-1]["source"] == "auth_log"
    assert recent_calls[-1]["query"] == "alice"
    assert recent_calls[-1]["limit"] == 250


def test_live_logs_view_summary_metrics_follow_health_and_event_payloads(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.live_logs as live_logs_module

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

        def stop(self):
            return None

        def set_interval(self, interval_ms):
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

    monkeypatch.setattr(live_logs_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_live_log_sources", lambda config_path=None: {
        "status": "ok",
        "sources": ["all", "auth_log", "sudo_log"],
    })
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_log_health_summary", lambda config_path=None: {
        "status": "ok",
        "sources": ["auth_log", "sudo_log"],
        "parse_fail_summary": {"count": 3},
        "duplicate_summary": {"count": 4, "telemetry_count": 2},
    })
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_recent_events", lambda **kwargs: {
        "status": "ok",
        "events": [
            {
                "id": 31,
                "timestamp_text": "2024-03-09 16:00:00",
                "source": "auth_log",
                "category": "auth",
                "action": "ssh_login",
                "outcome": "success",
                "src_ip": "8.8.8.8",
                "dst_ip": "",
                "username": "alice",
                "process": "sshd",
                "host": "host-a",
                "message": "user logged in",
                "raw": {},
                "raw_fields": {},
            },
            {
                "id": 32,
                "timestamp_text": "2024-03-09 16:01:00",
                "source": "sudo_log",
                "category": "privilege",
                "action": "sudo",
                "outcome": "success",
                "src_ip": "",
                "dst_ip": "",
                "username": "root",
                "process": "sudo",
                "host": "host-a",
                "message": "sudo executed",
                "raw": {},
                "raw_fields": {},
            },
        ],
    })
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_event_detail", lambda event_id, config_path=None: {
        "status": "ok",
        "event": {"id": event_id},
        "detail": {},
        "error": None,
    })

    view = live_logs_module.LiveLogsView()

    assert view._summary_labels["source_count"].text() == "2"
    assert view._summary_labels["parse_fail"].text() == "3"
    assert view._summary_labels["duplicate"].text() == "6"
    assert view._summary_labels["total_shown"].text() == "2"
    assert view._summary_labels["status"].text() == "OK"
    assert view._view_details.isEnabled() is True


def test_live_logs_view_translates_main_labels_to_turkish(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.live_logs as live_logs_module

    class _ImmediateController:
        def __init__(self, owner=None, interval_ms=None):
            self._task = None
            self._on_result = None
            self._on_finished = None

        def configure(self, task=None, on_result=None, on_error=None, on_finished=None):
            self._task = task
            self._on_result = on_result
            self._on_finished = on_finished

        def start(self):
            return None

        def stop(self):
            return None

        def set_interval(self, interval_ms):
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

    monkeypatch.setattr(live_logs_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_live_log_sources", lambda config_path=None: {"status": "ok", "sources": ["all"]})
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_log_health_summary", lambda config_path=None: {"status": "ok", "sources": [], "parse_fail_summary": {"count": 0}, "duplicate_summary": {"count": 0, "telemetry_count": 0}})
    monkeypatch.setattr(live_logs_module.backend_facade, "collect_recent_events", lambda **kwargs: {"status": "ok", "events": []})
    set_language("tr")
    view = live_logs_module.LiveLogsView()

    assert view._title.text() == "Canlı Loglar"
    assert view._source_label.text() == "Kaynak"
    assert view._query_label.text() == "Ara"
    assert view._view_details.text() == "Detayları Gör"
