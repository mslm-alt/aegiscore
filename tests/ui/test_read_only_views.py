from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import ui.backend_facade as backend_facade


class _FakeDb:
    def __init__(self, alerts=None, alert=None):
        self._alerts = alerts or []
        self._alert = alert

    def get_recent_alerts(self, limit=100, hours=24):
        return list(self._alerts)[:limit]

    def get_alert_by_id(self, alert_id):
        if self._alert and int(self._alert.get("id", -1)) == int(alert_id):
            return dict(self._alert)
        return None

    def get_ip_reputation_for_alert(self, alert_id):
        return [{"alert_id": alert_id, "source": "abuseipdb"}]

    def get_open_incidents(self):
        return [{"id": 1}, {"id": 2}]

    def get_stat(self, key):
        if key == "last_read:auth_log":
            return "1710000000"
        return None

    def close(self):
        return None


def test_collect_alerts_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(
        backend_facade,
        "create_database",
        lambda config: _FakeDb(alerts=[{
            "id": 7,
            "ts": 1710000000,
            "severity": "high",
            "rule_id": "RULE-1",
            "risk_score": 88,
            "entity": "alice",
            "source": "auth_log",
            "message": "test alert",
            "context_json": {"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"},
        }]),
    )

    result = backend_facade.collect_alerts(limit=10)

    assert result["status"] == "ok"
    assert len(result["alerts"]) == 1
    assert {
        "id", "created_at", "timestamp_text", "severity", "rule_id",
        "risk_score", "entity", "source_ip", "target_ip", "source",
        "message", "raw",
    } <= set(result["alerts"][0])


def test_collect_alert_detail_missing_id_graceful(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _FakeDb())

    result = backend_facade.collect_alert_detail(999)

    assert result["status"] == "degraded"
    assert result["alert"] is None
    assert "alert_not_found" in result["error"]


def test_collect_sources_health_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"sources": {}}})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian", "pretty": "Debian"})
    monkeypatch.setattr(backend_facade, "is_supported", lambda distro: (True, "Debian/Ubuntu"))
    monkeypatch.setattr(backend_facade, "audit_sources", lambda config: {"auth_log": {"status": "ok", "path": "/tmp/auth.log", "reason": ""}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _FakeDb())
    monkeypatch.setattr(backend_facade, "_phase_stats_summary", lambda state_dir="data": {
        "parse_fail_breakdown_by_source": {"auth_log": 1},
        "duplicate_breakdown_by_source": {"auth_log": 2},
    })
    monkeypatch.setattr(backend_facade, "os", SimpleNamespace(access=lambda path, mode: True, R_OK=4))
    monkeypatch.setattr(backend_facade, "Path", Path)

    result = backend_facade.collect_sources_health()

    assert result["status"] in {"ok", "degraded"}
    assert result["sources"]
    assert {"source", "status", "resolved_path", "path_exists", "readable", "service_active", "last_read", "last_read_text"} <= set(result["sources"][0])


def test_collect_reports_summary_no_report_graceful_empty(monkeypatch):
    monkeypatch.setattr(backend_facade, "_collect_report_files", lambda data_dir="data": [])

    result = backend_facade.collect_reports_summary()

    assert result["status"] == "ok"
    assert result["empty"] is True
    assert result["files"] == []


def test_collect_diagnostics_summary_no_exception(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "_read_database_health", lambda config: {"available": False, "status": "degraded", "details": {}})
    monkeypatch.setattr(backend_facade, "_read_rule_count", lambda config: 42)
    monkeypatch.setattr(backend_facade, "RuntimeStateStore", lambda state_dir="data": type("Store", (), {"status": lambda self: {"runtime_restore_health": {"degraded": False}, "pressure": {}}})())
    monkeypatch.setattr(backend_facade, "_phase_stats_summary", lambda state_dir="data": {"parse_fail_count": 0, "parse_fail_breakdown_by_source": {}, "parse_fail_breakdown_by_reason": {}, "parse_fail_rate": 0.0, "duplicate_count": 0, "telemetry_duplicate_count": 0, "duplicate_breakdown_by_source": {}, "duplicate_breakdown_by_kind": {}, "duplicate_rate": 0.0})
    monkeypatch.setattr(backend_facade.main_module, "collect_parse_fail_diagnostics", lambda config, db, pm_status: {"total_parse_fail_count": 0, "no_action_contract": True})
    monkeypatch.setattr(backend_facade.main_module, "collect_event_growth_diagnostics", lambda config, db, pm_status: {"phase_lifetime_event_count": 0, "no_action_contract": True})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _FakeDb())

    result = backend_facade.collect_diagnostics_summary()

    assert result["status"] in {"ok", "degraded"}
    assert result["rule_count"] == 42
    assert result["parse_fail_diagnostics"]["no_action_contract"] is True
    assert result["event_growth_diagnostics"]["no_action_contract"] is True
def test_no_write_guard_backend_facade_source():
    source = Path("ui/backend_facade.py").read_text(encoding="utf-8")
    forbidden_tokens = [
        "review_ip_block_suggestion",
        "add_ip_block_action",
        "block_ip",
        "unblock_ip",
        "reset_database",
        "log_ml_control",
        "insert_incident(",
        "update_incident(",
        "set_stat(",
    ]

    for token in forbidden_tokens:
        assert token not in source
