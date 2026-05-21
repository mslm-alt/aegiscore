from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import ui.backend_facade as backend_facade


class _FakeDb:
    def close(self):
        return None


def test_collect_action_history_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _FakeDb())
    monkeypatch.setattr(backend_facade, "_load_table_rows", lambda db, table_name, order_columns, limit, filters=None: ([
        {
            "id": 7,
            "ts": 1710000000,
            "action": "report_view",
            "status": "ok",
            "actor": "alice",
            "target": "report.html",
            "summary": "opened report",
            "details": {"screen": "reports"},
        }
    ], ["id", "ts", "action", "status", "actor", "target", "summary", "details"], None))

    result = backend_facade.collect_action_history(limit=10)

    assert result["status"] == "ok"
    assert result["total_returned"] == 1
    assert {"id", "timestamp_text", "action_type", "target", "actor", "result", "reason", "metadata", "raw"} <= set(result["actions"][0])


def test_collect_action_history_missing_table_graceful(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _FakeDb())
    monkeypatch.setattr(backend_facade, "_load_table_rows", lambda db, table_name, order_columns, limit, filters=None: ([], [], "missing_table:user_actions"))

    result = backend_facade.collect_action_history(limit=10)

    assert result["status"] == "degraded"
    assert result["actions"] == []


def test_collect_audit_summary_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "collect_action_history", lambda **kwargs: {
        "status": "ok",
        "actions": [
            {"action_type": "ip_block_preview", "result": "ok", "timestamp_text": "2024-03-09 16:00:00"},
            {"action_type": "report_view", "result": "ok", "timestamp_text": "2024-03-09 15:00:00"},
        ],
    })

    result = backend_facade.collect_audit_summary()

    assert result["status"] == "ok"
    assert {"total_actions", "by_action_type", "by_result", "dangerous_action_count", "ip_action_count", "config_api_key_action_count", "db_reset_count", "last_action_time", "error"} <= set(result)


def test_collect_audit_detail_missing_id_graceful(monkeypatch):
    monkeypatch.setattr(backend_facade, "collect_action_history", lambda **kwargs: {"status": "ok", "actions": []})

    result = backend_facade.collect_audit_detail(999)

    assert result["status"] == "degraded"
    assert result["action"] is None
    assert "action_not_found" in result["error"]


def test_collect_audit_sources_status_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _FakeDb())
    monkeypatch.setattr(backend_facade, "_load_table_rows", lambda db, table_name, order_columns, limit, filters=None: ([{"id": 1}], ["id"], None))
    monkeypatch.setattr(backend_facade, "_execute_db_read", lambda db, sql, params=(), fetch="all": ({"count": 2} if fetch == "one" else [], ""))
    monkeypatch.setattr(backend_facade, "_collect_report_files", lambda data_dir="data": [{"name": "report.html"}])

    result = backend_facade.collect_audit_sources_status()

    assert result["status"] == "ok"
    assert {"user_actions", "ip_block_actions", "report_artifacts"} <= set(result["sources"])


def test_collect_dangerous_action_preview_required_guards():
    result = backend_facade.collect_dangerous_action_preview()

    assert result["status"] == "ok"
    assert result["actions"]
    assert "typed confirmation" in result["actions"][0]["required_guards"]


def test_collect_dangerous_action_preview_derived_from_common_policy(monkeypatch):
    monkeypatch.setattr(backend_facade, "collect_guarded_action_policies", lambda: {
        "status": "ok",
        "policies": [{
            "action_type": "ip_block",
            "role_required": "admin",
            "dry_run_required": True,
            "typed_confirmation_required": True,
            "reason_required": True,
            "audit_required": True,
            "enabled": True,
            "phase": "Phase 2A guarded framework",
            "allowed_in_phase_2": True,
            "destructive": True,
        }],
    })
    monkeypatch.setattr(backend_facade, "preview_guarded_action", lambda **kwargs: {
        "required_guards": ["actor", "reason", "typed confirmation"],
        "execution_enabled": False,
    })

    result = backend_facade.collect_dangerous_action_preview()

    assert result["actions"] == [{
        "action": "ip_block",
        "required_guards": ["actor", "reason", "typed confirmation"],
        "execution_enabled": False,
    }]


def test_audit_backend_no_write_guard_sources():
    for path in ("ui/backend_facade.py",):
        source = Path(path).read_text(encoding="utf-8").lower()
        for token in (
            ".commit(",
            "insert_user_action(",
            "add_ip_block_action(",
            "review_ip_block_suggestion(",
            "block_ip(",
            "unblock_ip(",
            "firewall-cmd",
            "reset_database(",
            "close_incident(",
            "write_text(",
            "smtplib",
            ".sendmail(",
        ):
            assert token not in source
