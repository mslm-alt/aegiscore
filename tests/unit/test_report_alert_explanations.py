import main as main_module

from core.report import ReportEngine


class _ReportDB:
    def __init__(self, alerts=None, recent_window_alerts=None):
        self.alerts = [dict(item) for item in (alerts or [])]
        self.recent_window_alerts = (
            [dict(item) for item in recent_window_alerts]
            if recent_window_alerts is not None
            else [dict(item) for item in self.alerts]
        )
        self.write_calls = 0

    def get_report_stats(self, since):
        return {
            "total_alerts": len(self.recent_window_alerts),
            "by_severity": {"high": 1} if self.recent_window_alerts else {},
            "top_rules": [(self.recent_window_alerts[0].get("rule_id", "AUTH-001"), 1)] if self.recent_window_alerts else [],
            "top_entities": [(self.recent_window_alerts[0].get("entity", "entity-1"), 1)] if self.recent_window_alerts else [],
            "top_users": [("alice", 1)] if self.recent_window_alerts else [],
            "top_hosts": [("host-1", 1)] if self.recent_window_alerts else [],
            "incident_total": 0,
            "by_status": {},
            "by_hour": {10: len(self.recent_window_alerts)} if self.recent_window_alerts else {},
            "recent_incidents": [],
        }

    def get_recent_alerts(self, limit=100, hours=24):
        source = self.recent_window_alerts if hours <= 48 else self.alerts
        return [dict(item) for item in source[:limit]]

    def insert_alert(self, *args, **kwargs):
        self.write_calls += 1

    def update_incident(self, *args, **kwargs):
        self.write_calls += 1

    def insert_incident(self, *args, **kwargs):
        self.write_calls += 1


def _rule_alert():
    return {
        "id": 101,
        "rule_id": "AUTH-004",
        "severity": "high",
        "risk_score": 75.0,
        "entity": "root",
        "message": "sudo escalation behaviour matched",
        "context_json": {
            "user": "root",
            "process": "/usr/bin/sudo",
            "source": "auditd",
            "action": "sudo",
            "host": "host-1",
        },
    }


def _ml_alert():
    return {
        "id": 202,
        "rule_id": "ML-PROC-001",
        "severity": "medium",
        "risk_score": 68.0,
        "entity": "host:host-1",
        "message": "Bu process bu hostta beklenen davranış profilinden sapıyor.",
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


def test_report_includes_rule_alert_explanation_section():
    engine = ReportEngine(_ReportDB([_rule_alert()]), alert_explainer=main_module.build_deterministic_alert_report_payload)
    report = engine.daily_report(days_back=1)
    html = engine.to_html(report)

    assert "Alert Açıklamaları" in html
    assert "Neden tetiklendi?" in html
    assert "AUTH-004" in html
    assert "Risk score" in html
    assert "Kontrol önerileri" in html


def test_report_falls_back_to_last_existing_alerts_when_window_empty():
    db = _ReportDB(alerts=[_rule_alert()], recent_window_alerts=[])
    engine = ReportEngine(db, alert_explainer=main_module.build_deterministic_alert_report_payload)

    report = engine.daily_report(days_back=1)
    html = engine.to_html(report)

    assert report["recent_alert_explanations_source"] == "all_alerts"
    assert "Rapor zaman aralığında alert yoksa, aşağıda son mevcut alert açıklamaları gösterilir." in html
    assert "Neden tetiklendi?" in html
    assert "Kontrol önerileri" in html
    assert "AUTH-004" in html


def test_report_includes_ml_alert_explanation_metadata():
    engine = ReportEngine(_ReportDB([_ml_alert()]), alert_explainer=main_module.build_deterministic_alert_report_payload)
    report = engine.daily_report(days_back=1)
    html = engine.to_html(report)

    assert "ML family" in html
    assert "ML-PROC" in html
    assert "ML label" in html
    assert "suspicious_process" in html
    assert "no_action_contract" in html
    assert "action_taken" in html
    assert "top_features" in html
    assert "time_context" in html
    assert "baseline_deviation" in html


def test_report_fallback_works_when_metadata_missing():
    alert = _rule_alert()
    alert["context_json"] = {}
    engine = ReportEngine(_ReportDB([alert]), alert_explainer=main_module.build_deterministic_alert_report_payload)
    report = engine.daily_report(days_back=1)
    html = engine.to_html(report)

    assert "Metadata eksikti; kısa fallback açıklama gösteriliyor." in html
    assert "Önemli event/log alanı bulunamadı." in html


def test_deterministic_report_payload_carries_canonical_language():
    payload = main_module.build_deterministic_alert_report_payload(_rule_alert(), language="English")

    assert payload["language"] == "en"
    assert payload["rule_metadata"]["language"] == "en"


def test_report_html_output_escapes_alert_fields():
    alert = _rule_alert()
    alert["entity"] = "<script>alert(1)</script>"
    alert["context_json"]["process"] = "<b>bad</b>"
    engine = ReportEngine(_ReportDB([alert]), alert_explainer=main_module.build_deterministic_alert_report_payload)
    report = engine.daily_report(days_back=1)
    html = engine.to_html(report)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<b>bad</b>" not in html
    assert "&lt;b&gt;bad&lt;/b&gt;" in html


def test_report_generation_does_not_write_to_db():
    db = _ReportDB([_rule_alert(), _ml_alert()])
    engine = ReportEngine(db, alert_explainer=main_module.build_deterministic_alert_report_payload)

    report = engine.daily_report(days_back=1)
    html = engine.to_html(report)

    assert report["recent_alert_explanations"]
    assert "Alert Açıklamaları" in html
    assert db.write_calls == 0


def test_report_shows_clean_fallback_when_no_alerts_exist():
    db = _ReportDB(alerts=[], recent_window_alerts=[])
    engine = ReportEngine(db, alert_explainer=main_module.build_deterministic_alert_report_payload)

    report = engine.daily_report(days_back=1)
    html = engine.to_html(report)

    assert report["recent_alert_explanations_source"] == "empty"
    assert "Açıklanacak alert bulunamadı." in html
