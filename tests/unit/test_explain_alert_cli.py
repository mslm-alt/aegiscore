from types import SimpleNamespace

import pytest

import main as main_module
from app.alert_explanations import build_deterministic_alert_explanation


class _FakeDB:
    def __init__(self, alert=None):
        self.alert = alert
        self.closed = False
        self.alerts_count = 10
        self.labels_count = 20
        self.incidents_count = 5
        self.write_calls = 0

    def get_alert_by_id(self, alert_id):
        return dict(self.alert) if self.alert else None

    def get_ip_reputation_for_alert(self, alert_id):
        return []

    def close(self):
        self.closed = True

    def insert_alert(self, *args, **kwargs):
        self.write_calls += 1

    def update_incident(self, *args, **kwargs):
        self.write_calls += 1

    def insert_incident(self, *args, **kwargs):
        self.write_calls += 1


def _base_rule_alert():
    return {
        "id": 101,
        "rule_id": "AUTH-004",
        "severity": "high",
        "risk_score": 75.0,
        "entity": "root",
        "message": "sudo escalation behaviour matched",
        "category": "auth",
        "context_json": {
            "user": "root",
            "process": "/usr/bin/sudo",
            "source": "auditd",
            "action": "sudo",
            "host": "host-1",
        },
    }


def _base_ml_alert():
    return {
        "id": 202,
        "rule_id": "ML-PROC-001",
        "severity": "medium",
        "risk_score": 68.0,
        "entity": "host:host-1",
        "message": "Bu process bu hostta beklenen davranış profilinden sapıyor.",
        "category": "ml_process",
        "context_json": {
            "source": "ml_active_decision_layer",
            "ml_family": "ML-PROC",
            "ml_label": "suspicious_process",
            "ml_family_status": "active",
            "readiness_reason": "ready",
            "model_score": 68.0,
            "normalized_score": 0.68,
            "confidence": 0.84,
            "top_features": ["field_completeness=1.00", "time_anomaly_placeholder=0.40"],
            "time_context": {"hour_of_day": 3, "is_night": True},
            "baseline_deviation": {"available": True, "score_component": 5.0},
            "supporting_event_fields": {"process": "/usr/bin/curl", "host": "host-1", "source": "auditd"},
            "no_action_contract": True,
            "action_taken": False,
            "can_emit_alert": True,
        },
    }


def _disabled_llm():
    return SimpleNamespace(is_active=False, disable_reason="LLM devre dışı")


def _disabled_llm_en():
    return SimpleNamespace(is_active=False, disable_reason="LLM is disabled (enabled: false).", language="en")


def test_deterministic_rule_explanation_is_not_empty():
    result = build_deterministic_alert_explanation(_base_rule_alert())
    assert result["kind"] == "rule"
    assert "Alert ID: 101" in result["text"]
    assert "Neden tetiklendi?" in result["text"]
    assert "Kullanıcı neyi kontrol etmeli?" in result["text"]
    assert result["db_write_attempted"] is False


def test_deterministic_ml_explanation_shows_ml_fields():
    result = build_deterministic_alert_explanation(_base_ml_alert())
    assert result["kind"] == "ml"
    assert "ML Family: ML-PROC" in result["text"]
    assert "ML Label: suspicious_process" in result["text"]
    assert "Top features" in result["text"]
    assert "Time context" in result["text"]
    assert "Baseline deviation" in result["text"]
    assert "no_action_contract: True" in result["text"]
    assert "action_taken: False" in result["text"]


def test_deterministic_fallback_works_when_metadata_missing():
    alert = _base_rule_alert()
    alert["context_json"] = {}
    result = build_deterministic_alert_explanation(alert)
    assert "detay metadata yok" in result["text"].lower()
    assert result["metadata_missing"] is True


def test_explain_alert_cli_uses_deterministic_fallback_when_llm_disabled(monkeypatch, capsys):
    fake_db = _FakeDB(alert=_base_rule_alert())
    before = (fake_db.alerts_count, fake_db.labels_count, fake_db.incidents_count)

    monkeypatch.setattr(main_module, "ensure_database", lambda config: fake_db)
    monkeypatch.setattr(main_module, "_load_llm_client_for_cli", lambda config, path: _disabled_llm())

    args = SimpleNamespace(explain_alert=101, config="config/config.yml")
    code = main_module.run_explain_alert_cli({}, args)

    out = capsys.readouterr().out
    after = (fake_db.alerts_count, fake_db.labels_count, fake_db.incidents_count)
    assert code == 0
    assert "Deterministik Alert Açıklaması" in out
    assert "AUTH-004" in out
    assert "LLM Notu: LLM devre dışı" in out
    assert fake_db.write_calls == 0
    assert before == after
    assert fake_db.closed is True


def test_explain_alert_cli_ml_metadata_path_visible_when_llm_disabled(monkeypatch, capsys):
    fake_db = _FakeDB(alert=_base_ml_alert())
    monkeypatch.setattr(main_module, "ensure_database", lambda config: fake_db)
    monkeypatch.setattr(main_module, "_load_llm_client_for_cli", lambda config, path: _disabled_llm())

    args = SimpleNamespace(explain_alert=202, config="config/config.yml")
    code = main_module.run_explain_alert_cli({}, args)

    out = capsys.readouterr().out
    assert code == 0
    assert "ML Family: ML-PROC" in out
    assert "ML Label: suspicious_process" in out
    assert "Neden anormal görüldü?" in out
    assert fake_db.write_calls == 0


def test_explain_alert_cli_english_uses_english_deterministic_fallback(monkeypatch, capsys):
    fake_db = _FakeDB(alert=_base_rule_alert())
    monkeypatch.setattr(main_module, "ensure_database", lambda config: fake_db)
    monkeypatch.setattr(main_module, "_load_llm_client_for_cli", lambda config, path: _disabled_llm_en())

    args = SimpleNamespace(explain_alert=101, config="config/config.yml")
    code = main_module.run_explain_alert_cli({"language": "en"}, args)

    out = capsys.readouterr().out
    assert code == 0
    assert "Deterministic Alert Explanation" in out
    assert "Why was it triggered?" in out
    assert "LLM Note: LLM is disabled" in out


def test_explain_alert_cli_alert_not_found_is_clean_error(monkeypatch, capsys):
    fake_db = _FakeDB(alert=None)
    monkeypatch.setattr(main_module, "ensure_database", lambda config: fake_db)

    args = SimpleNamespace(explain_alert=999, config="config/config.yml")
    code = main_module.run_explain_alert_cli({}, args)

    err = capsys.readouterr().err
    assert code == 2
    assert "Alert bulunamadı: id=999" in err
    assert fake_db.write_calls == 0
