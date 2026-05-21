import importlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import ui.backend_facade as backend_facade
from ui.models import builtin_presets


class _InvestigationDb:
    def __init__(self, alerts=None, alert=None):
        self._alerts = alerts or []
        self._alert = alert

    def get_recent_alerts(self, limit=100, hours=24):
        return list(self._alerts)[:limit]

    def get_alert_by_id(self, alert_id):
        if self._alert and int(self._alert.get("id", -1)) == int(alert_id):
            return dict(self._alert)
        return None

    def close(self):
        return None


def _sample_alerts():
    return [
        {
            "id": 1,
            "ts": 1710000000,
            "severity": "high",
            "rule_id": "SSH-BRUTE",
            "risk_score": 90,
            "entity": "alice",
            "source": "auth_log",
            "message": "ssh brute force",
            "context_json": {"src_ip": "8.8.8.8", "raw_event": {"line": "raw1"}, "parsed_metadata": {"user": "alice"}},
        },
        {
            "id": 2,
            "ts": 1710000300,
            "severity": "medium",
            "rule_id": "SSH-BRUTE",
            "risk_score": 70,
            "entity": "alice",
            "source": "auth_log",
            "message": "ssh retry",
            "context_json": {"src_ip": "8.8.8.8"},
        },
        {
            "id": 3,
            "ts": 1710000600,
            "severity": "critical",
            "rule_id": "WEB-ATTACK",
            "risk_score": 99,
            "entity": "web01",
            "source": "nginx",
            "message": "web attack",
            "context_json": {"src_ip": "9.9.9.9"},
        },
    ]


def test_collect_entity_timeline_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _InvestigationDb(alerts=_sample_alerts()))

    result = backend_facade.collect_entity_timeline("alice", limit=10)

    assert result["status"] == "ok"
    assert result["entity"] == "alice"
    assert result["events"]
    assert {"timestamp_text", "kind", "id", "severity", "rule_id", "message", "source_ip", "entity"} <= set(result["events"][0])
    assert {"top_entities", "top_source_ips", "severity_counts", "status_note"} <= set(result["summary"])


def test_collect_entity_timeline_empty_summary(monkeypatch):
    result = backend_facade.collect_entity_timeline("", limit=10)

    assert result["status"] == "ok"
    assert result["events"] == []
    assert result["summary"]["total_events"] == 0
    assert "No related events" in result["summary"]["status_note"]


def test_collect_entity_timeline_degraded_without_db(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: None)

    result = backend_facade.collect_entity_timeline("alice", limit=10)

    assert result["status"] == "degraded"


def test_collect_alert_correlations_missing_alert_graceful(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _InvestigationDb(alerts=_sample_alerts()))

    result = backend_facade.collect_alert_correlations(999, limit=10)

    assert result["status"] == "degraded"
    assert "alert_not_found" in result["error"]


def test_collect_alert_correlations_grouping_counts(monkeypatch):
    alerts = _sample_alerts()
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _InvestigationDb(alerts=alerts, alert=alerts[0]))

    result = backend_facade.collect_alert_correlations(1, limit=10)

    assert result["status"] == "ok"
    assert result["group_summaries"]["same_source_ip"]["count"] == 1
    assert result["group_summaries"]["same_entity"]["count"] == 1
    assert result["group_summaries"]["same_rule"]["count"] == 1
    assert result["group_summaries"]["nearby_time"]["count"] == 2


def test_collect_alert_investigation_summary_schema(monkeypatch):
    alerts = _sample_alerts()
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _InvestigationDb(alerts=alerts, alert=alerts[0]))

    result = backend_facade.collect_alert_investigation_summary(1)

    assert result["status"] in {"ok", "degraded"}
    assert {"same_source_ip_count", "same_entity_count", "same_rule_count", "high_critical_related_count", "first_seen", "last_seen", "top_related_rules"} <= set(result["summary"])
    assert result["summary"]["same_source_ip_count"] == 1
    assert result["summary"]["same_entity_count"] == 1
    assert result["summary"]["same_rule_count"] == 1


def test_collect_alert_raw_parsed_missing_alert_graceful(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _InvestigationDb(alerts=_sample_alerts()))

    result = backend_facade.collect_alert_raw_parsed(999)

    assert result["status"] == "degraded"
    assert result["raw_text"] == ""
    assert result["parsed_text"] == ""


def test_collect_alert_raw_parsed_summary_redaction(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alerts()[0])
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {
            "raw_event": {"process": "Authorization: Bearer SECRET-BEARER", "src_ip": "8.8.8.8"},
            "parsed_metadata": {"process": "password=SECRET-PASS", "src_ip": "8.8.8.8"},
            "context_json": {"username": "token=SECRET-TOKEN"},
        },
        "error": None,
    })

    result = backend_facade.collect_alert_raw_parsed(1)
    text = backend_facade._stringify_payload(result)

    assert result["status"] == "ok"
    assert "SECRET-BEARER" not in text
    assert "SECRET-PASS" not in text
    assert "SECRET-TOKEN" not in text
    assert "redacted" in text.lower()


def test_builtin_preset_list():
    labels = [item.label for item in builtin_presets()]

    assert labels == [
        "All alerts",
        "Critical only",
        "High + Critical",
        "SSH/Auth",
        "Firewall/Network",
        "Web attacks",
        "DB auth failures",
        "Last 1 hour",
        "Last 24 hours",
        "External IP only",
    ]


def test_investigation_view_import_graceful():
    pytest.importorskip("PySide6")
    module = importlib.import_module("ui.views.investigation")
    assert module.InvestigationView is not None


def test_phase_1c_no_write_guard_backend_facade_source():
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
        "write_text(",
        "set_stat(",
    ]

    for token in forbidden_tokens:
        assert token not in source
