from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import ui.backend_facade as backend_facade
from ui.actions import incident_actions
from ui.actions.guard import required_confirmation_for


class _FakeDb:
    def __init__(self, incident=None, fail_update: bool = False, fail_audit: bool = False):
        self.incident = dict(incident) if incident is not None else None
        self.fail_update = fail_update
        self.fail_audit = fail_audit
        self.updated = []
        self.audit_rows = []

    def _execute(self, sql, params=(), fetch=None):
        lowered = str(sql).strip().lower()
        if lowered.startswith("select * from incidents"):
            if self.incident and int(self.incident.get("id", 0) or 0) == int(params[0]):
                return dict(self.incident)
            return None
        if lowered.startswith("update incidents set status"):
            if self.fail_update:
                raise RuntimeError("update_failed")
            if self.incident and int(self.incident.get("id", 0) or 0) == int(params[1]):
                self.incident["status"] = params[0]
                self.updated.append((sql, params))
                return None
            raise RuntimeError("incident_missing")
        if lowered.startswith("insert into user_actions"):
            if self.fail_audit:
                raise RuntimeError("audit_failed")
            self.audit_rows.append((sql, params))
            return None
        return None

    def close(self):
        return None


def _open_incident(status: str = "open", severity: str = "medium"):
    return {
        "id": 7,
        "status": status,
        "severity": severity,
        "title": "Suspicious auth burst",
        "entity_key": "alice",
        "alert_count": 3,
        "risk_score": 92.5,
        "summary": "summary",
        "evidence": [{"kind": "alert", "id": 11}],
    }


def _confirm(action_type: str, incident_id: int = 7) -> str:
    return required_confirmation_for(action_type, str(incident_id))


def test_invalid_incident_id_denied(monkeypatch):
    monkeypatch.setattr(incident_actions, "audit_user_action_available", lambda config: (True, ""))
    result = incident_actions.preview_guarded_incident_action(
        config={},
        action="resolve",
        incident_id=0,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=_confirm("incident_resolve", 0),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert "valid incident id" in result["guard"]["missing_guards"]


def test_missing_incident_denied(monkeypatch):
    db = _FakeDb(incident=None)
    monkeypatch.setattr(incident_actions, "create_database", lambda config: db)
    monkeypatch.setattr(incident_actions, "audit_user_action_available", lambda config: (True, ""))
    result = incident_actions.preview_guarded_incident_action(
        config={},
        action="resolve",
        incident_id=7,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=_confirm("incident_resolve"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert "incident exists" in result["guard"]["missing_guards"]


def test_already_closed_incident_denied(monkeypatch):
    db = _FakeDb(incident=_open_incident(status="closed"))
    monkeypatch.setattr(incident_actions, "create_database", lambda config: db)
    monkeypatch.setattr(incident_actions, "audit_user_action_available", lambda config: (True, ""))
    result = incident_actions.preview_guarded_incident_action(
        config={},
        action="close",
        incident_id=7,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=_confirm("incident_close"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert "closable incident status" in result["guard"]["missing_guards"]


def test_viewer_denied(monkeypatch):
    db = _FakeDb(incident=_open_incident())
    monkeypatch.setattr(incident_actions, "create_database", lambda config: db)
    monkeypatch.setattr(incident_actions, "audit_user_action_available", lambda config: (True, ""))
    result = incident_actions.preview_guarded_incident_action(
        config={},
        action="resolve",
        incident_id=7,
        actor="viewer-1",
        role="viewer",
        reason="ticket",
        confirmation=_confirm("incident_resolve"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert "role:admin" in result["guard"]["missing_guards"]


def test_operator_denied(monkeypatch):
    db = _FakeDb(incident=_open_incident())
    monkeypatch.setattr(incident_actions, "create_database", lambda config: db)
    monkeypatch.setattr(incident_actions, "audit_user_action_available", lambda config: (True, ""))
    result = incident_actions.preview_guarded_incident_action(
        config={},
        action="close",
        incident_id=7,
        actor="operator-1",
        role="operator",
        reason="ticket",
        confirmation=_confirm("incident_close"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert "role:admin" in result["guard"]["missing_guards"]


def test_admin_without_reason_denied(monkeypatch):
    db = _FakeDb(incident=_open_incident())
    monkeypatch.setattr(incident_actions, "create_database", lambda config: db)
    monkeypatch.setattr(incident_actions, "audit_user_action_available", lambda config: (True, ""))
    result = incident_actions.preview_guarded_incident_action(
        config={},
        action="resolve",
        incident_id=7,
        actor="admin-1",
        role="admin",
        reason="",
        confirmation=_confirm("incident_resolve"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert "reason" in result["guard"]["missing_guards"]


def test_admin_without_dry_run_denied(monkeypatch):
    db = _FakeDb(incident=_open_incident())
    monkeypatch.setattr(incident_actions, "create_database", lambda config: db)
    monkeypatch.setattr(incident_actions, "audit_user_action_available", lambda config: (True, ""))
    result = incident_actions.preview_guarded_incident_action(
        config={},
        action="resolve",
        incident_id=7,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=_confirm("incident_resolve"),
        dry_run_completed=False,
    )

    assert result["status"] == "denied"
    assert "dry-run" in result["guard"]["missing_guards"]


def test_admin_without_confirmation_denied(monkeypatch):
    db = _FakeDb(incident=_open_incident())
    monkeypatch.setattr(incident_actions, "create_database", lambda config: db)
    monkeypatch.setattr(incident_actions, "audit_user_action_available", lambda config: (True, ""))
    result = incident_actions.preview_guarded_incident_action(
        config={},
        action="close",
        incident_id=7,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation="WRONG",
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert "typed confirmation" in result["guard"]["missing_guards"]


def test_audit_unavailable_denies_execution(monkeypatch):
    db = _FakeDb(incident=_open_incident())
    monkeypatch.setattr(incident_actions, "create_database", lambda config: db)
    monkeypatch.setattr(incident_actions, "audit_user_action_available", lambda config: (False, "db_down"))
    result = incident_actions.execute_guarded_incident_action(
        config={},
        action="resolve",
        incident_id=7,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=_confirm("incident_resolve"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "audit_unavailable"


def test_open_incident_resolve_success_updates_status_and_audit(monkeypatch):
    db = _FakeDb(incident=_open_incident())
    monkeypatch.setattr(incident_actions, "create_database", lambda config: db)
    monkeypatch.setattr(incident_actions, "audit_user_action_available", lambda config: (True, ""))
    result = incident_actions.execute_guarded_incident_action(
        config={},
        action="resolve",
        incident_id=7,
        actor="admin-1",
        role="admin",
        reason="analyst triage complete",
        confirmation=_confirm("incident_resolve"),
        dry_run_completed=True,
    )

    assert result["status"] == "executed"
    assert db.incident["status"] == "resolved"
    assert len(db.updated) == 1
    assert len(db.audit_rows) == 1
    assert result["would_update"]["ml_resume"] is False
    assert result["would_update"]["delete_alerts"] is False
    assert result["would_update"]["delete_events"] is False


def test_open_incident_close_success_updates_status_and_audit(monkeypatch):
    db = _FakeDb(incident=_open_incident(severity="critical"))
    monkeypatch.setattr(incident_actions, "create_database", lambda config: db)
    monkeypatch.setattr(incident_actions, "audit_user_action_available", lambda config: (True, ""))
    result = incident_actions.execute_guarded_incident_action(
        config={},
        action="close",
        incident_id=7,
        actor="admin-1",
        role="admin",
        reason="ticket complete",
        confirmation=_confirm("incident_close"),
        dry_run_completed=True,
    )

    assert result["status"] == "executed"
    assert db.incident["status"] == "closed"
    assert len(db.updated) == 1
    assert len(db.audit_rows) == 1


def test_no_delete_or_ml_resume_tokens_in_incident_action_path():
    source = Path("ui/actions/incident_actions.py").read_text(encoding="utf-8").lower()
    forbidden = [
        "delete from alerts",
        "delete from events",
        "delete from risk_history",
        "ml_resume(",
        "resume_ml",
    ]

    for token in forbidden:
        assert token not in source


def test_only_expected_guarded_actions_enabled_in_phase_2h():
    result = backend_facade.collect_guarded_action_policies()
    enabled = set(result["executable_action_types"])

    assert result["phase"] == "Phase 2H guarded actions"
    assert {
        "api_key_update",
        "telegram_test_send",
        "email_test_send",
        "ip_block",
        "ip_unblock",
        "incident_resolve",
        "incident_close",
        "db_reset",
        "report_export",
        "diagnostic_bundle_create",
    } <= enabled
    assert {
        "ml_resume",
        "ml_reset",
        "ml_config_update",
    }.isdisjoint(enabled)
