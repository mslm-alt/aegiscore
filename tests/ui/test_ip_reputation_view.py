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

    def trigger(self, task=None, on_result=None, on_error=None, on_finished=None):
        task = task or self._task
        on_result = on_result or self._on_result
        on_error = on_error or self._on_error
        on_finished = on_finished or self._on_finished
        try:
            if task is not None and on_result is not None:
                on_result(task())
        except Exception as exc:
            if on_error is not None:
                on_error({"message": str(exc)})
        if on_finished is not None:
            on_finished()
        return True


def _patch_alerts(monkeypatch, alerts_module):
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
            "raw": {},
        }],
        "error": None,
    })
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": {"id": alert_id},
        "detail": {"explanation_text": "ok"},
        "error": None,
    })
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alert_correlations", lambda alert_id, config_path=None: {
        "groups": {}
    })
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alert_raw_parsed", lambda alert_id, config_path=None: {
        "raw_text": "",
        "parsed_text": "",
    })
    monkeypatch.setattr(alerts_module.backend_facade, "collect_entity_timeline", lambda entity, config_path=None: {
        "entity": entity,
        "summary": {},
        "events": [],
    })
    monkeypatch.setattr(alerts_module.backend_facade, "is_ml_alert", lambda alert: False)


def _patch_ip_view(monkeypatch, ip_module, *, backend="firewalld", real_apply_supported=True, candidates=None):
    monkeypatch.setattr(ip_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(ip_module.backend_facade, "collect_ip_reputation_status", lambda config_path=None: {
        "status": "ok",
        "abuseipdb": {"enabled": False, "key_masked": "", "enrichment_only": True, "manual_approval_required": True},
        "ip_blocking": {
            "enabled": True,
            "mode": "manual_only",
            "backend": backend,
            "real_apply_supported": real_apply_supported,
            "requires_elevation": False,
            "firewall_actions_locked": False,
        },
        "security_locks": {"auto_ip_block_disabled": True},
        "error": None,
    })
    monkeypatch.setattr(ip_module.backend_facade, "collect_ip_block_candidates", lambda **kwargs: {
        "status": "ok",
        "candidates": list(candidates or [{
            "ip": "8.8.8.8",
            "reason": "Repeated SSH brute force",
            "rule_id": "RULE-11",
            "alert_id": 11,
            "severity": "high",
            "risk_score": 90.0,
            "timestamp_text": "2024-03-09 16:00:00",
            "status": "not_blocked",
            "status_text": "Not blocked",
            "backend": backend,
            "backend_capability": "ready",
            "backend_supported": real_apply_supported,
            "guarded": False,
            "guard_reason": "",
            "blocked": False,
            "can_block": real_apply_supported,
            "can_unblock": False,
        }]),
        "empty": not bool(candidates),
        "error": None,
    })


def test_ip_reputation_view_import_graceful():
    pytest.importorskip("PySide6")
    module = importlib.import_module("ui.views.ip_reputation")
    assert module.IPReputationView is not None


def test_alerts_ip_context_callback_smoke(monkeypatch):
    pytest.importorskip("PySide6")
    _qt_app()

    import ui.views.alerts as alerts_module

    _patch_alerts(monkeypatch, alerts_module)

    seen = []
    prepared = []
    view = alerts_module.AlertsView(open_ip_context=seen.append, open_manual_ip_action=lambda ip, action="block": prepared.append((ip, action)))
    view._table.selectRow(0)
    view._open_selected_ip_context()
    view._prepare_manual_block()

    assert seen == ["8.8.8.8"]
    assert prepared == [("8.8.8.8", "block")]


def test_ip_blocking_view_shows_simplified_surface(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.ip_reputation as ip_module

    set_language("en")
    _patch_ip_view(monkeypatch, ip_module)
    view = ip_module.IPReputationView()

    assert view._title.text() == "IP Blocking"
    assert view._table.columnCount() == 7
    assert view._table.rowCount() == 1
    assert view._table.item(0, 3).text() == "RULE-11"
    assert view._table.item(0, 4).text() == "HIGH/90.0"
    assert view._block_button.text() == "Block"
    assert view._unblock_button.text() == "Unblock"
    assert "Automatic blocking is disabled" in view._safety_note.text()
    assert not hasattr(view, "_preview_role")
    assert not hasattr(view, "_execute_button")
    assert not hasattr(view, "_context_summary")


def test_ip_blocking_view_localizes_and_removes_old_tabs(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.ip_reputation as ip_module

    set_language("tr")
    _patch_ip_view(monkeypatch, ip_module)
    view = ip_module.IPReputationView()

    visible_text = " ".join(
        widget.text()
        for widget in [view._title, view._refresh_all, view._block_button, view._unblock_button, view._safety_note]
    )
    assert view._title.text() == "IP Engelleme"
    assert "IP İtibarı" not in visible_text
    assert "Manual Action Preview" not in visible_text
    assert "Action History" not in visible_text
    assert "IP Context" not in visible_text


def test_ip_blocking_view_manual_action_prepare_smoke(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()

    import ui.views.ip_reputation as ip_module

    _patch_ip_view(monkeypatch, ip_module)
    preview_calls = {"count": 0}
    executed = []
    prompts = iter([("ticket-1", True), ("CONFIRM IP_BLOCK 8.8.8.8", True)])
    infos = []

    def _preview(**kwargs):
        preview_calls["count"] += 1
        return {
            "status": "ready",
            "action": "block",
            "ip": "8.8.8.8",
            "ip_validation": {"allowed": True},
            "backend": "firewalld",
            "capability": {"real_apply_supported": True, "dry_run_supported": True, "reason": "ready"},
            "guard": {"status": "ready", "execution_enabled": True, "metadata": {"request": {"required_confirmation_phrase": "CONFIRM IP_BLOCK 8.8.8.8"}}},
            "would_run": [],
            "message": "ready",
        }

    monkeypatch.setattr(ip_module.backend_facade, "preview_ip_action", _preview)
    monkeypatch.setattr(ip_module.backend_facade, "execute_ip_action", lambda **kwargs: executed.append(kwargs) or {"status": "executed", "message": "ok"})
    monkeypatch.setattr(ip_module.QInputDialog, "getText", staticmethod(lambda *args, **kwargs: next(prompts)))
    monkeypatch.setattr(ip_module.QMessageBox, "information", staticmethod(lambda *args: infos.append(args[2])))
    monkeypatch.setattr(ip_module.QMessageBox, "warning", staticmethod(lambda *args: pytest.fail(f"unexpected warning: {args[2]}")))

    view = ip_module.IPReputationView()
    view.prepare_manual_action("8.8.8.8", action="block")

    assert preview_calls["count"] == 2
    assert len(executed) == 1
    assert executed[0]["action"] == "block"
    assert executed[0]["ip"] == "8.8.8.8"
    assert infos == ["ok"]


def test_ip_blocking_view_unsupported_backend_stays_safe(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()

    import ui.views.ip_reputation as ip_module

    _patch_ip_view(monkeypatch, ip_module, backend="ufw", real_apply_supported=False, candidates=[{
        "ip": "8.8.8.8",
        "reason": "Repeated SSH brute force",
        "rule_id": "RULE-11",
        "alert_id": 11,
        "severity": "high",
        "risk_score": 90.0,
        "timestamp_text": "2024-03-09 16:00:00",
        "status": "unsupported_backend",
        "status_text": "Unsupported backend",
        "backend": "ufw",
        "backend_capability": "backend_unsupported",
        "backend_supported": False,
        "guarded": False,
        "guard_reason": "",
        "blocked": False,
        "can_block": False,
        "can_unblock": False,
    }])
    warnings = []
    monkeypatch.setattr(ip_module.backend_facade, "preview_ip_action", lambda **kwargs: {
        "status": "denied",
        "capability": {"real_apply_supported": False},
        "guard": {"execution_enabled": False, "metadata": {"request": {"required_confirmation_phrase": "CONFIRM"}}},
    })
    monkeypatch.setattr(ip_module.QInputDialog, "getText", staticmethod(lambda *args, **kwargs: ("ticket-1", True)))
    monkeypatch.setattr(ip_module.QMessageBox, "warning", staticmethod(lambda *args: warnings.append(args[2])))
    monkeypatch.setattr(ip_module.QMessageBox, "information", staticmethod(lambda *args: pytest.fail("unexpected success dialog")))

    view = ip_module.IPReputationView()
    assert view._block_button.isEnabled() is False
    view._run_action("block", target_ip="8.8.8.8")

    assert warnings == ["Real blocking is not supported by the current firewall backend."]


def test_ip_blocking_view_elevated_privileges_message_is_actionable(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()

    import ui.views.ip_reputation as ip_module

    _patch_ip_view(monkeypatch, ip_module, backend="ufw", real_apply_supported=False, candidates=[{
        "ip": "8.8.8.8",
        "reason": "Repeated SSH brute force",
        "rule_id": "RULE-11",
        "alert_id": 11,
        "severity": "high",
        "risk_score": 90.0,
        "timestamp_text": "2024-03-09 16:00:00",
        "status": "elevated_privileges_required",
        "status_text": "Elevated privileges required",
        "backend": "ufw",
        "backend_capability": "AegisCore must be run with elevated privileges to apply firewall rules.",
        "backend_supported": True,
        "requires_elevation": True,
        "guarded": False,
        "guard_reason": "",
        "blocked": False,
        "can_block": True,
        "can_unblock": False,
    }])
    warnings = []
    monkeypatch.setattr(ip_module.backend_facade, "preview_ip_action", lambda **kwargs: {
        "status": "denied",
        "capability": {
            "real_apply_supported": False,
            "requires_elevation": True,
        },
        "guard": {"execution_enabled": False, "metadata": {"request": {"required_confirmation_phrase": "CONFIRM"}}},
    })
    monkeypatch.setattr(ip_module.QInputDialog, "getText", staticmethod(lambda *args, **kwargs: ("ticket-1", True)))
    monkeypatch.setattr(ip_module.QMessageBox, "warning", staticmethod(lambda *args: warnings.append(args[2])))
    monkeypatch.setattr(ip_module.QMessageBox, "information", staticmethod(lambda *args: pytest.fail("unexpected success dialog")))

    view = ip_module.IPReputationView()
    assert view._block_button.isEnabled() is True
    view._run_action("block", target_ip="8.8.8.8")

    assert warnings == ["AegisCore must be run with elevated privileges to apply firewall rules."]
