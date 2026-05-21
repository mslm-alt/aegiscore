from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.actions import export_actions


def _fixed_stamp(monkeypatch, stamp="20260101_010203"):
    monkeypatch.setattr(export_actions.time, "strftime", lambda *args, **kwargs: stamp)


class _FakeDb:
    def __init__(self):
        self.audit_rows = []

    def _execute(self, sql, params=(), fetch=None):
        text = str(sql).strip().lower()
        if text.startswith("insert into user_actions"):
            self.audit_rows.append((sql, params))
            return None
        return None

    def close(self):
        return None


def _monkeypatch_report_collectors(monkeypatch):
    class _Facade:
        @staticmethod
        def collect_safe_export_preview(export_type, target_id=None):
            include = {
                "selected_alert": ["selected alert summary", "deterministic explanation", "sanitized metadata"],
                "incident_report": ["incident summary", "related alerts", "sanitized counts"],
                "ml_readiness": ["ML readiness summary", "family readiness states", "sanitized thresholds"],
                "source_health": ["source health summary", "path/readability states", "non-secret diagnostics"],
            }
            return {
                "would_include": include.get(export_type, []),
                "would_redact": ["API keys", "tokens", "passwords"],
                "would_exclude": ["raw secrets", "database dumps"],
                "message": "preview",
            }

        @staticmethod
        def collect_alert_detail(alert_id, config_path=None):
            return {
                "alert": {"id": alert_id, "message": "Authorization: Bearer secret-token-9999", "api_key": "abc123"},
                "detail": {"explanation_text": "smtp_pass=hunter2"},
            }

        @staticmethod
        def collect_alert_raw_parsed(alert_id, config_path=None):
            return {"raw_text": "OPENAI_API_KEY=test-secret", "parsed_text": "ok=value"}

        @staticmethod
        def collect_alert_investigation_summary(alert_id, config_path=None):
            return {
                "summary": {
                    "related_alert_count": 4,
                    "same_source_ip_count": 2,
                    "same_rule_count": 2,
                    "high_critical_related_count": 1,
                    "first_seen": "2024-03-09 00:00:00",
                    "last_seen": "2024-03-09 00:05:00",
                    "top_related_rules": [{"rule_id": "token=report-secret", "count": 2}],
                },
                "timeline_summary": {"status_note": "Authorization: Bearer bundle-secret"},
                "warnings": ["password=warn-secret"],
            }

        @staticmethod
        def collect_incident_detail(incident_id, config_path=None):
            return {
                "incident": {"id": incident_id, "summary": "token=incident-secret"},
                "detail": {"summary_text": "ok"},
                "related_alerts": [{"id": 1, "message": "password=demo"}],
            }

        @staticmethod
        def collect_ml_summary(config_path=None):
            return {"status": "ok", "overall": {"api_key": "ml-secret"}}

        @staticmethod
        def collect_report_readiness(config_path=None):
            return {"status": "ok", "llm": "token=ready"}

        @staticmethod
        def collect_sources_health(config_path=None):
            return {"status": "ok", "sources": [{"source": "auth", "reason": "password=hidden"}]}

        @staticmethod
        def collect_diagnostics_summary(config_path=None):
            return {"status": "ok", "errors": ["Authorization: Bearer diag-secret"]}

        @staticmethod
        def redact_sensitive_payload(payload):
            import ui.backend_facade as backend_facade
            return backend_facade.redact_sensitive_payload(payload)

    monkeypatch.setattr(export_actions, "_facade", lambda: _Facade)


def test_report_export_invalid_type_denied(monkeypatch):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    result = export_actions.preview_report_export(
        config={},
        export_type="bad_type",
        target_id=None,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"


def test_selected_alert_missing_target_denied(monkeypatch):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    result = export_actions.preview_report_export(
        config={},
        export_type="selected_alert",
        target_id=None,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert "target id" in result["guard"]["missing_guards"]


def test_path_traversal_denied(monkeypatch):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    result = export_actions.preview_report_export(
        config={},
        export_type="ml_readiness",
        target_id=None,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
        filename_hint="../escape.json",
    )

    assert result["status"] == "denied"
    assert result["error"] == "path_traversal_blocked"


def test_output_path_workspace_outside_denied(monkeypatch, tmp_path):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    outside = Path("/tmp/outside_export.json")
    result = export_actions.preview_report_export(
        config={},
        export_type="ml_readiness",
        target_id=None,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
        filename_hint=str(outside),
    )

    assert result["status"] == "denied"
    assert result["error"] == "output_path_outside_workspace"


def test_viewer_operator_denied(monkeypatch):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    viewer = export_actions.preview_report_export(
        config={},
        export_type="ml_readiness",
        target_id=None,
        actor="viewer-1",
        role="viewer",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )
    operator = export_actions.preview_report_export(
        config={},
        export_type="ml_readiness",
        target_id=None,
        actor="op-1",
        role="operator",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    assert viewer["status"] == "denied"
    assert operator["status"] == "denied"


def test_admin_without_reason_or_dry_run_or_confirmation_denied(monkeypatch):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    no_reason = export_actions.preview_report_export(config={}, export_type="ml_readiness", target_id=None, actor="a", role="admin", reason="", confirmation=export_actions.confirmation_phrase_for("report_export"), dry_run_completed=True)
    no_dry_run = export_actions.preview_report_export(config={}, export_type="ml_readiness", target_id=None, actor="a", role="admin", reason="ticket", confirmation=export_actions.confirmation_phrase_for("report_export"), dry_run_completed=False)
    no_confirm = export_actions.preview_report_export(config={}, export_type="ml_readiness", target_id=None, actor="a", role="admin", reason="ticket", confirmation="WRONG", dry_run_completed=True)

    assert no_reason["status"] == "denied"
    assert no_dry_run["status"] == "denied"
    assert no_confirm["status"] == "denied"


def test_audit_unavailable_denies_execution(monkeypatch):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (False, "db_down"))
    result = export_actions.execute_report_export(
        config={},
        export_type="ml_readiness",
        target_id=None,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "audit_unavailable"


def test_execute_mocked_selected_alert_writes_sanitized_file(monkeypatch, tmp_path):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    monkeypatch.setattr(export_actions, "create_database", lambda config: _FakeDb())
    result = export_actions.execute_report_export(
        config={},
        export_type="selected_alert",
        target_id="7",
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    text = Path(result["output_path"]).read_text(encoding="utf-8")
    assert result["status"] == "executed"
    assert str(tmp_path / "data" / "exports") in result["output_path"]
    assert "secret-token-9999" not in text
    assert "hunter2" not in text
    assert "test-secret" not in text
    assert "report-secret" not in text
    assert "bundle-secret" not in text
    assert "warn-secret" not in text
    assert "investigation_context" in text


def test_selected_alert_export_includes_investigation_context(monkeypatch, tmp_path):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    monkeypatch.setattr(export_actions, "create_database", lambda config: _FakeDb())

    result = export_actions.execute_report_export(
        config={},
        export_type="selected_alert",
        target_id="7",
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    payload = json.loads(Path(result["output_path"]).read_text(encoding="utf-8"))

    assert result["status"] == "executed"
    assert "investigation_context" in payload
    assert payload["investigation_context"]["summary"]["same_source_ip_count"] == 2
    assert {"summary", "timeline_summary", "warnings"} <= set(payload["investigation_context"])


def test_selected_alert_preview_would_include_investigation_context(monkeypatch):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))

    result = export_actions.preview_report_export(
        config={},
        export_type="selected_alert",
        target_id="7",
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    assert result["status"] in {"ready", "denied", "preview_only"}
    assert "investigation_context" in result["would_include"]


def test_audit_metadata_contains_no_exported_raw_content_and_no_secrets(monkeypatch, tmp_path):
    _monkeypatch_report_collectors(monkeypatch)
    fake_db = _FakeDb()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    monkeypatch.setattr(export_actions, "create_database", lambda config: fake_db)
    result = export_actions.execute_report_export(
        config={},
        export_type="source_health",
        target_id=None,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    assert result["status"] == "executed"
    params = fake_db.audit_rows[0][1]
    details = json.loads(params[-1])
    details_text = json.dumps(details).lower()
    assert "diag-secret" not in details_text
    assert "hunter2" not in details_text
    assert "snapshot" not in details_text


def test_export_module_no_forbidden_actions():
    source = Path("ui/actions/export_actions.py").read_text(encoding="utf-8").lower()
    forbidden = [
        "ipblocker(",
        "firewall-cmd",
        "ml_reset",
        "drop database",
        "drop schema",
        "execute_guarded_db_reset",
    ]

    for token in forbidden:
        assert token not in source


def test_safe_export_path_allowed(monkeypatch, tmp_path):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.chdir(tmp_path)
    _fixed_stamp(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))

    result = export_actions.preview_report_export(
        config={},
        export_type="ml_readiness",
        target_id=None,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    assert result["status"] == "ready"
    assert result["error"] is None
    assert result["output_path"].endswith("ml_readiness_summary_20260101_010203.json")


def test_export_root_symlink_to_outside_blocked(monkeypatch, tmp_path):
    _monkeypatch_report_collectors(monkeypatch)
    outside = tmp_path.parent / "outside-exports"
    outside.mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "exports").symlink_to(outside, target_is_directory=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))

    result = export_actions.preview_report_export(
        config={},
        export_type="ml_readiness",
        target_id=None,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "output_root_symlink_blocked"


def test_export_parent_symlink_escape_blocked(monkeypatch, tmp_path):
    _monkeypatch_report_collectors(monkeypatch)
    outside = tmp_path.parent / "outside-parent"
    outside.mkdir()
    (tmp_path / "data").symlink_to(outside, target_is_directory=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))

    result = export_actions.preview_report_export(
        config={},
        export_type="ml_readiness",
        target_id=None,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "parent_symlink_blocked"


def test_final_output_file_symlink_blocked(monkeypatch, tmp_path):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.chdir(tmp_path)
    _fixed_stamp(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    monkeypatch.setattr(export_actions, "create_database", lambda config: _FakeDb())
    export_dir = tmp_path / "data" / "exports"
    export_dir.mkdir(parents=True)
    target = tmp_path / "outside-target.json"
    target.write_text("blocked", encoding="utf-8")
    final_path = export_dir / "ml_readiness_summary_20260101_010203.json"
    final_path.symlink_to(target)

    result = export_actions.execute_report_export(
        config={},
        export_type="ml_readiness",
        target_id=None,
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "output_file_symlink_blocked"


def test_redaction_behavior_unchanged_in_report_preview(monkeypatch):
    _monkeypatch_report_collectors(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))

    result = export_actions.preview_report_export(
        config={},
        export_type="selected_alert",
        target_id="7",
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("report_export"),
        dry_run_completed=True,
    )

    payload_text = json.dumps(result["preview_payload"], ensure_ascii=False)
    assert result["redaction_enabled"] is True
    assert "secret-token-9999" not in payload_text
    assert "hunter2" not in payload_text
