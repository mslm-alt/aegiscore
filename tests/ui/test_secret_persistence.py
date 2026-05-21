from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.actions import secret_store
import ui.backend_facade as backend_facade


def test_allowed_key_validation():
    normalized, invalid = secret_store.validate_allowed_secret_keys({"ABUSEIPDB_API_KEY": "abc", "EMAIL_TO": "ops@example.com"})

    assert normalized["ABUSEIPDB_API_KEY"] == "abc"
    assert invalid == []


def test_disallowed_key_rejected():
    normalized, invalid = secret_store.validate_allowed_secret_keys({"UNSAFE_KEY": "x"})

    assert normalized == {}
    assert invalid == ["UNSAFE_KEY"]


def test_preview_secret_update_no_raw_secret_leak(tmp_path, monkeypatch):
    monkeypatch.setattr(backend_facade, "_integrations_env_path", lambda config_path=None: tmp_path / "integrations.env")

    result = backend_facade.preview_secret_update(
        updates={"ABUSEIPDB_API_KEY": "super-secret-value"},
        actor="alice",
        role="admin",
        reason="ticket-1",
        confirmation="WRONG",
        dry_run_completed=True,
    )

    text = backend_facade._stringify_payload(result)
    assert "super-secret-value" not in text
    assert "ABUSEIPDB_API_KEY" in text


def test_update_env_values_writes_temp_file_and_backup(tmp_path):
    env_path = tmp_path / "integrations.env"
    env_path.write_text("ABUSEIPDB_API_KEY=old\n", encoding="utf-8")

    result = secret_store.update_env_values(env_path, {"ABUSEIPDB_API_KEY": "new-secret"}, backup=True)

    assert result["status"] == "ok"
    assert Path(result["backup_path"]).exists()
    assert "new-secret" in env_path.read_text(encoding="utf-8")


def test_file_permission_best_effort(tmp_path):
    env_path = tmp_path / "integrations.env"

    result = secret_store.update_env_values(env_path, {"EMAIL_TO": "ops@example.com"}, backup=False)

    assert result["status"] == "ok"
    assert env_path.exists()


def test_audit_unavailable_denies_execution(monkeypatch, tmp_path):
    monkeypatch.setattr(backend_facade, "_integrations_env_path", lambda config_path=None: tmp_path / "integrations.env")
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}, "integrations": SimpleNamespace(_raw={}), "config_exists": True})
    monkeypatch.setattr(secret_store, "audit_user_action_available", lambda config: (False, "db_down"))

    result = backend_facade.execute_secret_update(
        updates={"ABUSEIPDB_API_KEY": "new-secret"},
        actor="alice",
        role="admin",
        reason="ticket-2",
        confirmation="CONFIRM API_KEY_UPDATE ABUSEIPDB_API_KEY",
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "audit_unavailable"


def test_audit_payload_no_raw_secret(monkeypatch, tmp_path):
    env_path = tmp_path / "integrations.env"
    captured = {}
    monkeypatch.setattr(backend_facade, "_integrations_env_path", lambda config_path=None: env_path)
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"db": "ok"}, "integrations": SimpleNamespace(_raw={}), "config_exists": True})
    monkeypatch.setattr(secret_store, "audit_user_action_available", lambda config: (True, ""))

    def _record(config, action, actor, target, summary, details, status="ok"):
        captured["details"] = details
        return {"status": "ok", "id": 1, "error": None}

    monkeypatch.setattr(secret_store, "record_user_action", _record)

    result = backend_facade.execute_secret_update(
        updates={"ABUSEIPDB_API_KEY": "new-secret"},
        actor="alice",
        role="admin",
        reason="ticket-3",
        confirmation="CONFIRM API_KEY_UPDATE ABUSEIPDB_API_KEY",
        dry_run_completed=True,
    )

    assert result["status"] == "executed"
    assert captured["details"]["masked_updates"]["ABUSEIPDB_API_KEY"] != "new-secret"
    assert "new-secret" not in backend_facade._stringify_payload(captured["details"])
