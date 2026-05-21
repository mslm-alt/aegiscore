from app.alert_explanations import build_deterministic_alert_report_payload
from core.report import ReportEngine


class _ReportDB:
    def __init__(self, alerts=None):
        self.alerts = [dict(item) for item in (alerts or [])]

    def get_report_stats(self, since):
        return {
            "total_alerts": len(self.alerts),
            "by_severity": {"high": 1} if self.alerts else {},
            "top_rules": [(self.alerts[0].get("rule_id", "AUTH-001"), 1)] if self.alerts else [],
            "top_entities": [(self.alerts[0].get("entity", "entity-1"), 1)] if self.alerts else [],
            "top_users": [("alice", 1)] if self.alerts else [],
            "top_hosts": [("host-1", 1)] if self.alerts else [],
            "incident_total": 0,
            "by_status": {},
            "by_hour": {10: len(self.alerts)} if self.alerts else {},
            "recent_incidents": [],
        }

    def get_recent_alerts(self, limit=100, hours=24):
        return [dict(item) for item in self.alerts[:limit]]


def _rule_alert():
    return {
        "id": 101,
        "rule_id": "AUTH-004",
        "severity": "high",
        "risk_score": 75.0,
        "entity": "root",
        "message": "sudo escalation behaviour matched",
        "context_json": {"user": "root", "process": "/usr/bin/sudo", "source": "auditd", "action": "sudo", "host": "host-1"},
    }


def test_report_html_localizes_to_english_and_preserves_raw_message():
    engine = ReportEngine(_ReportDB([_rule_alert()]), alert_explainer=build_deterministic_alert_report_payload, language="en")
    report = engine.daily_report(days_back=1)
    html = engine.to_html(report)

    assert '<html lang="en">' in html
    assert "Alert Explanations" in html
    assert "Severity Distribution" in html
    assert "Why was it triggered?" in html
    assert "sudo escalation behaviour matched" not in html
    assert "Açıklanacak alert bulunamadı." not in html


def test_report_html_localizes_to_turkish():
    engine = ReportEngine(_ReportDB([_rule_alert()]), alert_explainer=build_deterministic_alert_report_payload, language="tr")
    report = engine.daily_report(days_back=1)
    html = engine.to_html(report)

    assert '<html lang="tr">' in html
    assert "Alert Açıklamaları" in html
    assert "Severity Dağılımı" in html

