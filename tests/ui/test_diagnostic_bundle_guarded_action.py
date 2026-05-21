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
        if str(sql).strip().lower().startswith("insert into user_actions"):
            self.audit_rows.append((sql, params))
        return None

    def close(self):
        return None


def test_diagnostic_bundle_writes_sanitized_file(monkeypatch, tmp_path):
    class _Facade:
        @staticmethod
        def collect_diagnostic_bundle_preview(config_path=None):
            return {
                "status": "ok",
                "would_include": ["distro info", "DB health/schema version"],
                "would_redact": ["API keys", "tokens"],
                "would_exclude": ["database dumps"],
                "snapshot": {"token": "secret-token", "safe": "ok"},
                "message": "ready",
            }

    monkeypatch.setattr(export_actions, "_facade", lambda: _Facade)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    monkeypatch.setattr(export_actions, "create_database", lambda config: _FakeDb())
    result = export_actions.execute_diagnostic_bundle_create(
        config={},
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("diagnostic_bundle_create"),
        dry_run_completed=True,
    )

    text = Path(result["output_path"]).read_text(encoding="utf-8")
    assert result["status"] == "executed"
    assert str(tmp_path / "data" / "diagnostic_bundles") in result["output_path"]
    assert "secret-token" not in text


def test_report_export_and_bundle_execution_enabled_and_ml_actions_still_locked():
    import ui.backend_facade as backend_facade

    result = backend_facade.collect_guarded_action_policies()
    enabled = set(result["executable_action_types"])

    assert "report_export" in enabled
    assert "diagnostic_bundle_create" in enabled
    assert "ml_resume" not in enabled
    assert "ml_reset" not in enabled
    assert "ml_config_update" not in enabled


def test_safe_diagnostic_bundle_path_allowed(monkeypatch, tmp_path):
    class _Facade:
        @staticmethod
        def collect_diagnostic_bundle_preview(config_path=None):
            return {
                "status": "ok",
                "would_include": ["distro info"],
                "would_redact": ["API keys"],
                "would_exclude": ["database dumps"],
                "snapshot": {"safe": "ok"},
                "message": "ready",
            }

    monkeypatch.setattr(export_actions, "_facade", lambda: _Facade)
    monkeypatch.chdir(tmp_path)
    _fixed_stamp(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))

    result = export_actions.preview_diagnostic_bundle_create(
        config={},
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("diagnostic_bundle_create"),
        dry_run_completed=True,
    )

    assert result["status"] == "ready"
    assert result["error"] is None
    assert result["output_path"].endswith("diagnostic_bundle_20260101_010203.json")


def test_diagnostic_bundle_root_symlink_to_outside_blocked(monkeypatch, tmp_path):
    class _Facade:
        @staticmethod
        def collect_diagnostic_bundle_preview(config_path=None):
            return {
                "status": "ok",
                "would_include": ["distro info"],
                "would_redact": ["API keys"],
                "would_exclude": ["database dumps"],
                "snapshot": {"safe": "ok"},
                "message": "ready",
            }

    outside = tmp_path.parent / "outside-bundles"
    outside.mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "diagnostic_bundles").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(export_actions, "_facade", lambda: _Facade)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))

    result = export_actions.preview_diagnostic_bundle_create(
        config={},
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("diagnostic_bundle_create"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "output_root_symlink_blocked"


def test_diagnostic_bundle_parent_symlink_escape_blocked(monkeypatch, tmp_path):
    class _Facade:
        @staticmethod
        def collect_diagnostic_bundle_preview(config_path=None):
            return {
                "status": "ok",
                "would_include": ["distro info"],
                "would_redact": ["API keys"],
                "would_exclude": ["database dumps"],
                "snapshot": {"safe": "ok"},
                "message": "ready",
            }

    outside = tmp_path.parent / "outside-data"
    outside.mkdir()
    (tmp_path / "data").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(export_actions, "_facade", lambda: _Facade)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))

    result = export_actions.preview_diagnostic_bundle_create(
        config={},
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("diagnostic_bundle_create"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "parent_symlink_blocked"


def test_diagnostic_bundle_final_output_symlink_blocked(monkeypatch, tmp_path):
    class _Facade:
        @staticmethod
        def collect_diagnostic_bundle_preview(config_path=None):
            return {
                "status": "ok",
                "would_include": ["distro info"],
                "would_redact": ["API keys", "tokens"],
                "would_exclude": ["database dumps"],
                "snapshot": {"token": "secret-token", "safe": "ok"},
                "message": "ready",
            }

    monkeypatch.setattr(export_actions, "_facade", lambda: _Facade)
    monkeypatch.chdir(tmp_path)
    _fixed_stamp(monkeypatch)
    monkeypatch.setattr(export_actions, "audit_user_action_available", lambda config: (True, ""))
    monkeypatch.setattr(export_actions, "create_database", lambda config: _FakeDb())
    bundle_dir = tmp_path / "data" / "diagnostic_bundles"
    bundle_dir.mkdir(parents=True)
    target = tmp_path / "outside-bundle.json"
    target.write_text("blocked", encoding="utf-8")
    final_path = bundle_dir / "diagnostic_bundle_20260101_010203.json"
    final_path.symlink_to(target)

    result = export_actions.execute_diagnostic_bundle_create(
        config={},
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=export_actions.confirmation_phrase_for("diagnostic_bundle_create"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "output_file_symlink_blocked"
