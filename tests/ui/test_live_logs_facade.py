from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import ui.backend_facade as backend_facade
from ui.models import bounded_buffer


class _EventDb:
    def __init__(self, rows=None):
        self._rows = rows or []

    def _execute(self, sql, params=(), fetch="all"):
        sql_text = str(sql)
        if "information_schema.columns" in sql_text:
            return [{"column_name": name} for name in (
                "id", "ts", "source", "category", "action", "outcome",
                "src_ip", "dst_ip", "username", "process", "raw_log", "alert_id", "rule_id",
            )]
        if "FROM events_recent" in sql_text and fetch == "all":
            return list(self._rows)
        return []

    def close(self):
        return None


def test_collect_recent_events_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _EventDb(rows=[{
        "id": 1,
        "ts": 1710000000,
        "source": "auth_log",
        "category": "auth",
        "action": "ssh_login",
        "outcome": "success",
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "username": "alice",
        "process": "sshd",
        "raw_log": "Accepted password",
        "alert_id": 7,
        "rule_id": "AUTH-001",
    }]))

    result = backend_facade.collect_recent_events(limit=100)

    assert result["status"] == "ok"
    assert result["events"]
    assert {"id", "timestamp_text", "source", "category", "action", "outcome", "src_ip", "dst_ip", "username", "process", "message", "raw"} <= set(result["events"][0])


def test_collect_recent_events_db_unavailable_graceful_degraded(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: None)

    result = backend_facade.collect_recent_events(limit=100)

    assert result["status"] == "degraded"


def test_collect_live_log_sources_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "collect_recent_events", lambda **kwargs: {
        "status": "ok",
        "events": [{"source": "auth_log"}, {"source": "dns"}],
        "error": None,
    })

    result = backend_facade.collect_live_log_sources()

    assert result["status"] == "ok"
    assert "auth_log" in result["sources"]
    assert "process" in result["sources"]


def test_collect_log_health_summary_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "collect_sources_health", lambda config_path=None: {
        "status": "ok",
        "sources": [{"source": "auth_log"}],
        "problems": [],
    })
    monkeypatch.setattr(backend_facade, "collect_diagnostics_summary", lambda config_path=None: {
        "status": "ok",
        "parse_fail_summary": {"count": 1, "by_reason": {"normalize_none": 1}},
        "duplicate_summary": {"count": 2, "telemetry_count": 3},
    })

    result = backend_facade.collect_log_health_summary()

    assert result["status"] == "ok"
    assert {"parse_fail_summary", "duplicate_summary", "sources", "source_problem_count", "normalize_none_count"} <= set(result)


def test_collect_event_detail_missing_id_graceful(monkeypatch):
    monkeypatch.setattr(backend_facade, "collect_recent_events", lambda **kwargs: {
        "status": "ok",
        "events": [],
        "total_returned": 0,
        "error": None,
    })

    result = backend_facade.collect_event_detail(999)

    assert result["status"] == "degraded"
    assert "event_not_found" in result["error"]


def test_bounded_buffer_helper_drops_oldest():
    items = [{"id": 1}, {"id": 2}, {"id": 3}]

    result = bounded_buffer(items, 2)

    assert result == [{"id": 2}, {"id": 3}]


def test_live_logs_no_write_guard_backend_facade_source():
    source = Path("ui/backend_facade.py").read_text(encoding="utf-8")
    forbidden_tokens = [
        "insert into ",
        "update incidents",
        "delete from ",
        ".commit(",
        "write_text(",
        "truncate",
        "rotate",
        "add_ip_block_action",
        "review_ip_block_suggestion",
        "log_ml_control(",
        "reset_database",
        "update_incident(",
    ]

    lowered = source.lower()
    for token in forbidden_tokens:
        assert token.strip().lower() not in lowered
