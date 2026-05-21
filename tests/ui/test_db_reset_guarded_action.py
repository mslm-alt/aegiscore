from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.actions import db_reset


class _FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=()):
        self.conn.executed.append((str(sql), tuple(params)))
        text = str(sql).strip().lower()
        if text.startswith("insert into user_actions"):
            self.conn.audit_rows.append((str(sql), tuple(params)))
            return None
        if text.startswith("delete from "):
            table_name = text.split()[2]
            self.conn.deleted_tables.append(table_name)
            self.conn.table_counts[table_name] = 0
            return None
        return None


class _FakeConn:
    def __init__(self, table_counts):
        self.table_counts = dict(table_counts)
        self.executed = []
        self.deleted_tables = []
        self.audit_rows = []
        self.commit_count = 0
        self.rollback_count = 0
        self.status = 1

    def cursor(self, *args, **kwargs):
        return _FakeCursor(self)

    def commit(self):
        self.commit_count += 1

    def rollback(self):
        self.rollback_count += 1


class _FakeDb:
    def __init__(self, table_counts):
        self.table_counts = dict(table_counts)
        self.conn = _FakeConn(self.table_counts)
        self.released = False

    def _execute(self, sql, params=(), fetch=None):
        text = str(sql).strip().lower()
        if "select to_regclass" in text:
            table_name = str(params[0]).split(".", 1)[-1]
            return {"name": f"public.{table_name}" if table_name in self.table_counts else None}
        if text.startswith("select count(*) as count from "):
            table_name = text.split()[-1]
            return {"count": int(self.table_counts.get(table_name, 0))}
        return None

    def _conn(self):
        return self.conn

    def _release(self, conn):
        self.released = True

    def close(self):
        return None


def _preview(monkeypatch, table_counts, **kwargs):
    fake_db = _FakeDb(table_counts)
    monkeypatch.setattr(db_reset, "create_database", lambda config: fake_db)
    monkeypatch.setattr(db_reset, "audit_user_action_available", lambda config: (True, ""))
    result = db_reset.preview_guarded_db_reset(
        config={},
        actor=kwargs.get("actor", "admin-1"),
        role=kwargs.get("role", "admin"),
        reason=kwargs.get("reason", "ticket"),
        confirmation=kwargs.get("confirmation", db_reset.confirmation_phrase_for_scope(kwargs.get("include_labels", False), kwargs.get("include_audit_log", False))),
        dry_run_completed=kwargs.get("dry_run_completed", True),
        include_labels=kwargs.get("include_labels", False),
        include_audit_log=kwargs.get("include_audit_log", False),
    )
    return result, fake_db


def test_preview_returns_table_counts_with_fake_db(monkeypatch):
    result, _fake_db = _preview(monkeypatch, {"alerts": 3, "incidents": 2, "user_actions": 9, "labels": 5})

    assert result["status"] == "ready"
    assert any(item["name"] == "alerts" and item["count"] == 3 for item in result["tables"])
    assert result["total_rows_to_delete"] >= 5


def test_default_scope_excludes_labels_and_user_actions(monkeypatch):
    result, _fake_db = _preview(monkeypatch, {"alerts": 3, "user_actions": 9, "labels": 5})

    assert result["scope"]["runtime_only"] is True
    assert result["scope"]["include_labels"] is False
    assert result["scope"]["include_audit_log"] is False
    assert "labels" not in result["will_reset"]
    assert "user_actions" not in result["will_reset"]


def test_include_labels_includes_labels(monkeypatch):
    result, _fake_db = _preview(monkeypatch, {"labels": 5}, include_labels=True)

    assert result["scope"]["include_labels"] is True
    assert "labels" in result["will_reset"]
    assert result["required_confirmation_phrase"] == "RESET AEGISCORE RUNTIME DATA AND LABELS"


def test_include_audit_log_includes_user_actions_with_warning(monkeypatch):
    result, _fake_db = _preview(monkeypatch, {"user_actions": 9}, include_audit_log=True)

    assert result["scope"]["include_audit_log"] is True
    assert "user_actions" in result["will_reset"]
    assert any("audit log" in item.lower() for item in result["warnings"])


def test_viewer_operator_denied(monkeypatch):
    result_viewer, _ = _preview(monkeypatch, {"alerts": 1}, role="viewer")
    result_operator, _ = _preview(monkeypatch, {"alerts": 1}, role="operator")

    assert result_viewer["status"] == "denied"
    assert result_operator["status"] == "denied"


def test_admin_without_reason_denied(monkeypatch):
    result, _ = _preview(monkeypatch, {"alerts": 1}, reason="")

    assert result["status"] == "denied"
    assert "reason" in result["guard"]["missing_guards"]


def test_admin_without_dry_run_denied(monkeypatch):
    result, _ = _preview(monkeypatch, {"alerts": 1}, dry_run_completed=False)

    assert result["status"] == "denied"
    assert "dry-run" in result["guard"]["missing_guards"]


def test_admin_without_confirmation_denied(monkeypatch):
    result, _ = _preview(monkeypatch, {"alerts": 1}, confirmation="WRONG")

    assert result["status"] == "denied"
    assert "typed confirmation" in result["guard"]["missing_guards"]


def test_audit_unavailable_denies_execution(monkeypatch):
    fake_db = _FakeDb({"alerts": 3})
    monkeypatch.setattr(db_reset, "create_database", lambda config: fake_db)
    monkeypatch.setattr(db_reset, "audit_user_action_available", lambda config: (False, "db_down"))
    result = db_reset.execute_guarded_db_reset(
        config={},
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=db_reset.confirmation_phrase_for_scope(),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "audit_unavailable"


def test_execute_uses_allowlist_only_and_resets_expected_tables(monkeypatch, tmp_path):
    fake_db = _FakeDb({"alerts": 3, "incidents": 2, "labels": 5, "user_actions": 9, "schema_version": 4})
    monkeypatch.setattr(db_reset, "create_database", lambda config: fake_db)
    monkeypatch.setattr(db_reset, "audit_user_action_available", lambda config: (True, ""))
    monkeypatch.setattr(db_reset, "_snapshot_path", lambda: tmp_path / "db_reset_snapshot.json")

    result = db_reset.execute_guarded_db_reset(
        config={},
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=db_reset.confirmation_phrase_for_scope(),
        dry_run_completed=True,
        include_labels=False,
        include_audit_log=False,
    )

    assert result["status"] == "executed"
    assert set(fake_db.conn.deleted_tables) <= set(db_reset._RUNTIME_TABLES)
    assert "labels" not in fake_db.conn.deleted_tables
    assert "user_actions" not in fake_db.conn.deleted_tables
    assert Path(result["snapshot_path"]).exists()
    assert result["audit_written"] is True


def test_schema_and_migration_tables_never_reset(monkeypatch, tmp_path):
    fake_db = _FakeDb({"alerts": 3, "schema_version": 4, "model_registry": 2, "system_config": 1})
    monkeypatch.setattr(db_reset, "create_database", lambda config: fake_db)
    monkeypatch.setattr(db_reset, "audit_user_action_available", lambda config: (True, ""))
    monkeypatch.setattr(db_reset, "_snapshot_path", lambda: tmp_path / "db_reset_snapshot.json")
    result = db_reset.execute_guarded_db_reset(
        config={},
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=db_reset.confirmation_phrase_for_scope(),
        dry_run_completed=True,
    )

    assert result["status"] == "executed"
    assert "schema_version" not in fake_db.conn.deleted_tables
    assert "model_registry" not in fake_db.conn.deleted_tables
    assert "system_config" not in fake_db.conn.deleted_tables


def test_snapshot_metadata_contains_no_secrets(monkeypatch, tmp_path):
    fake_db = _FakeDb({"alerts": 3})
    monkeypatch.setattr(db_reset, "create_database", lambda config: fake_db)
    monkeypatch.setattr(db_reset, "audit_user_action_available", lambda config: (True, ""))
    snapshot_file = tmp_path / "db_reset_snapshot.json"
    monkeypatch.setattr(db_reset, "_snapshot_path", lambda: snapshot_file)

    result = db_reset.execute_guarded_db_reset(
        config={},
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=db_reset.confirmation_phrase_for_scope(),
        dry_run_completed=True,
    )

    payload = json.loads(snapshot_file.read_text(encoding="utf-8"))
    text = json.dumps(payload).lower()
    assert result["status"] == "executed"
    assert "secret" not in text or "\"secrets_included\": false" in text
    assert payload["secrets_included"] is False


def test_reset_result_sanitized(monkeypatch, tmp_path):
    fake_db = _FakeDb({"alerts": 3, "incidents": 2})
    monkeypatch.setattr(db_reset, "create_database", lambda config: fake_db)
    monkeypatch.setattr(db_reset, "audit_user_action_available", lambda config: (True, ""))
    monkeypatch.setattr(db_reset, "_snapshot_path", lambda: tmp_path / "db_reset_snapshot.json")
    result = db_reset.execute_guarded_db_reset(
        config={},
        actor="admin-1",
        role="admin",
        reason="ticket",
        confirmation=db_reset.confirmation_phrase_for_scope(),
        dry_run_completed=True,
    )

    assert {"status", "scope", "tables_reset", "rows_deleted_estimate", "rows_remaining_after_reset", "snapshot_path", "audit_written", "message", "error"} <= set(result)
    assert "openai" not in json.dumps(result).lower()


def test_no_forbidden_actions_or_drop_tokens_in_db_reset_path():
    source = Path("ui/actions/db_reset.py").read_text(encoding="utf-8").lower()
    forbidden = [
        "ipblocker(",
        "firewall-cmd",
        "ml_reset",
        "incident_close(",
        "report_export",
        "diagnostic_bundle_create",
        "drop database",
        "drop schema",
    ]

    for token in forbidden:
        assert token not in source


def test_row_count_rejects_malicious_table_names(monkeypatch):
    fake_db = _FakeDb({"alerts": 3})

    for token in ("alerts; DROP TABLE alerts;--", "../alerts", "alerts where 1=1"):
        try:
            db_reset._row_count(fake_db, token)
        except ValueError as exc:
            assert "invalid_reset_table" in str(exc)
        else:
            raise AssertionError("ValueError bekleniyordu")


def test_table_exists_rejects_malicious_table_names(monkeypatch):
    fake_db = _FakeDb({"alerts": 3})

    for token in ("alerts; DROP TABLE alerts;--", "../alerts", "alerts where 1=1"):
        try:
            db_reset._table_exists(fake_db, token)
        except ValueError as exc:
            assert "invalid_reset_table" in str(exc)
        else:
            raise AssertionError("ValueError bekleniyordu")
