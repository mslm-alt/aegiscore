import importlib
import os
from pathlib import Path
import sys

import pytest
from ui.i18n import set_language

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _qt_app():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class _ImmediateController:
    def __init__(self, owner=None, interval_ms=None):
        self._task = None
        self._on_result = None
        self._on_error = None
        self._on_finished = None

    def configure(self, task=None, on_result=None, on_error=None, on_finished=None):
        self._task = task
        self._on_result = on_result
        self._on_error = on_error
        self._on_finished = on_finished

    def start(self):
        return None

    def trigger(self, task=None, on_result=None, on_error=None, on_finished=None):
        task = task or self._task
        on_result = on_result or self._on_result
        on_error = on_error or self._on_error
        on_finished = on_finished or self._on_finished
        try:
            if task is not None and on_result is not None:
                on_result(task())
        except Exception as exc:
            if on_error is not None:
                on_error({"message": str(exc)})
        if on_finished is not None:
            on_finished()
        return True


def _patch_base(monkeypatch, alerts_module):
    monkeypatch.setattr(alerts_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alerts", lambda **kwargs: {
        "status": "ok",
        "alerts": [
            {
                "id": 11,
                "created_at": 1710000000,
                "timestamp_text": "2024-03-09 16:00:00",
                "severity": "high",
                "rule_id": "RULE-11",
                "risk_score": 90.0,
                "entity": "alice",
                "source_ip": "8.8.8.8",
                "target_ip": "",
                "source": "auth_log",
                "message": "ssh brute force",
                "raw": {"incident_id": 7},
            },
            {
                "id": 12,
                "created_at": 1710000100,
                "timestamp_text": "2024-03-09 16:01:40",
                "severity": "medium",
                "rule_id": "ML-AUTH-001",
                "risk_score": 40.0,
                "entity": "alice",
                "source_ip": "10.0.0.5",
                "target_ip": "",
                "source": "ml",
                "message": "behavioral deviation",
                "raw": {"rule_family": "ml"},
            },
        ],
        "error": None,
    })
    monkeypatch.setattr(alerts_module.backend_facade, "is_ml_alert", lambda alert: str(alert.get("rule_id", "")).startswith("ML-") or str(alert.get("source", "")).lower() == "ml")


def test_alerts_view_import_graceful():
    pytest.importorskip("PySide6")
    module = importlib.import_module("ui.views.alerts")
    assert module.AlertsView is not None


def test_alerts_view_hides_ml_alerts_by_default_and_can_include_them(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.alerts as alerts_module

    _patch_base(monkeypatch, alerts_module)
    view = alerts_module.AlertsView()

    assert view._include_ml_alerts.isChecked() is False
    assert len(view._visible_alerts) == 1
    assert view._visible_alerts[0]["rule_id"] == "RULE-11"

    view._include_ml_alerts.setChecked(True)

    assert len(view._visible_alerts) == 2
    assert {item["rule_id"] for item in view._visible_alerts} == {"RULE-11", "ML-AUTH-001"}


def test_alerts_view_query_filters_by_rule_message_entity_and_ip(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.alerts as alerts_module

    _patch_base(monkeypatch, alerts_module)
    view = alerts_module.AlertsView()

    view._query.setText("rule-11")
    assert [item["id"] for item in view._visible_alerts] == [11]

    view._query.setText("brute force")
    assert [item["id"] for item in view._visible_alerts] == [11]

    view._include_ml_alerts.setChecked(True)
    view._query.setText("alice")
    assert {item["id"] for item in view._visible_alerts} == {11, 12}

    view._query.setText("10.0.0.5")
    assert [item["id"] for item in view._visible_alerts] == [12]


def test_alerts_view_empty_query_preserves_existing_list(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.alerts as alerts_module

    _patch_base(monkeypatch, alerts_module)
    view = alerts_module.AlertsView()

    initial_ids = [item["id"] for item in view._visible_alerts]
    view._query.setText("ssh")
    assert [item["id"] for item in view._visible_alerts] == [11]

    view._query.clear()
    assert [item["id"] for item in view._visible_alerts] == initial_ids


def test_alerts_view_query_works_with_ml_and_preset_filters(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.alerts as alerts_module

    _patch_base(monkeypatch, alerts_module)
    view = alerts_module.AlertsView()

    view._query.setText("behavioral")
    assert view._visible_alerts == []

    view._include_ml_alerts.setChecked(True)
    assert [item["id"] for item in view._visible_alerts] == [12]

    view._query.setText("ssh")
    assert [item["id"] for item in view._visible_alerts] == [11]


def test_alerts_detail_dialog_renders_and_stays_read_only(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.alerts as alerts_module

    _patch_base(monkeypatch, alerts_module)
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": {
            "id": alert_id,
            "timestamp_text": "2024-03-09 16:00:00",
            "severity": "high",
            "rule_id": "RULE-11",
            "risk_score": 90.0,
            "entity": "alice",
            "source_ip": "8.8.8.8",
            "source": "auth_log",
            "status": "open",
            "message": "ssh brute force",
        },
        "detail": {
            "explanation": {
                "review_steps": ["Review recent SSH failures", "Check the source host"],
                "evidence_fields": {"source": "auth_log", "user": "alice", "src_ip": "8.8.8.8"},
            },
            "explanation_text": "Repeated auth pattern exceeded threshold.",
            "explanation_kind": "rule",
            "context_json": {"category": "auth", "outcome": "failure"},
            "parsed_metadata": {"process": "sshd"},
            "raw_event": {"message": "raw line"},
            "ip_reputation": [],
        },
        "error": None,
    })

    view = alerts_module.AlertsView()
    view._table.selectRow(0)
    view._show_selected_detail()

    dialog = view._detail_dialog
    assert dialog is not None
    assert dialog._fields["rule_id"].text() == "RULE-11"
    assert dialog._fields["status"].text() == "open / failure"
    assert "Repeated auth pattern exceeded threshold." in dialog._explanation.toPlainText()
    assert dialog._message.isReadOnly() is True
    assert dialog._explanation.isReadOnly() is True
    assert dialog._evidence.isReadOnly() is True
    assert dialog._advanced.isReadOnly() is True


def test_alerts_explanation_button_opens_popup_and_uses_background_contract(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.alerts as alerts_module

    _patch_base(monkeypatch, alerts_module)
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alert_detail", lambda *args, **kwargs: {"status": "ok", "alert": {"id": 11}, "detail": {"explanation_text": "ok"}})
    calls = {"count": 0}

    def _explain(alert_id, prefer_llm=True, config_path=None):
        calls["count"] += 1
        return {
            "status": "ok",
            "alert_id": alert_id,
            "rule_id": "RULE-11",
            "severity": "high",
            "risk_score": 90.0,
            "used_llm": False,
            "fallback_used": True,
            "provider": "fallback",
            "summary": "SSH brute-force denemesi algılandı.",
            "why": "Kısa sürede tekrar eden başarısız girişler var.",
            "why_triggered": "Kısa sürede tekrar eden başarısız girişler var.",
            "risk": "Kimlik bilgisi tahmini veya parola denemesi olabilir.",
            "risk_assessment": "Kimlik bilgisi tahmini veya parola denemesi olabilir.",
            "full_explanation": "Bu alarm tekrarlayan kimlik doğrulama hataları ve yüksek risk skoru nedeniyle önemlidir.",
            "evidence": "Kural: RULE-11\nKaynak: auth_log\nKaynak IP: 8.8.8.8",
            "evidence_summary": "Kural: RULE-11\nKaynak: auth_log\nKaynak IP: 8.8.8.8",
            "recommended_review_steps": ["Kaynak IP geçmişini incele", "Aynı kullanıcı için diğer hataları kontrol et"],
            "false_positive_notes": "Yanlış parola kullanan meşru kullanıcı olabilir.",
            "raw_text": "Uzun açıklama",
            "metadata": {"alert": {"id": 11}},
            "error": None,
        }

    monkeypatch.setattr(alerts_module.backend_facade, "explain_alert_for_ui", _explain)
    view = alerts_module.AlertsView()
    view._table.selectRow(0)

    assert view._explain_button.text() == "Explain Alert"
    view._show_selected_explanation()

    assert calls["count"] == 1
    assert view._explanation_dialog is not None
    assert view._explanation_dialog._fields["rule_id"].text() == "RULE-11"
    assert view._explanation_dialog._fields["severity"].text() == "HIGH"
    assert view._explanation_dialog._fields["risk_score"].text() == "90.0"
    assert "SSH brute-force denemesi algılandı." in view._explanation_dialog._summary.toPlainText()
    assert "tekrarlayan kimlik doğrulama hataları" in view._explanation_dialog._full_explanation.toPlainText()
    assert "Kaynak IP: 8.8.8.8" in view._explanation_dialog._evidence.toPlainText()
    assert "Yanlış parola kullanan meşru kullanıcı olabilir." in view._explanation_dialog._false_positive.toPlainText()


def test_alerts_explanation_button_safe_when_no_alert_selected(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.alerts as alerts_module

    _patch_base(monkeypatch, alerts_module)
    calls = {"count": 0}
    monkeypatch.setattr(alerts_module.backend_facade, "explain_alert_for_ui", lambda *args, **kwargs: calls.__setitem__("count", calls["count"] + 1))
    view = alerts_module.AlertsView()
    view._table.clearSelection()
    view._update_action_state()

    assert view._explain_button.isEnabled() is False
    view._show_selected_explanation()

    assert calls["count"] == 0
    assert view._explanation_dialog is None


def test_alerts_selection_preserves_ip_incident_and_manual_block_callbacks(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.alerts as alerts_module

    _patch_base(monkeypatch, alerts_module)
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alert_detail", lambda *args, **kwargs: {"status": "ok", "alert": {"id": 11}, "detail": {"explanation_text": "ok"}})
    monkeypatch.setattr(alerts_module.backend_facade, "explain_alert_for_ui", lambda *args, **kwargs: {"status": "ok", "alert_id": 11, "rule_id": "RULE-11", "severity": "high", "risk_score": 90.0, "summary": "ok", "why": "ok", "why_triggered": "ok", "risk": "ok", "risk_assessment": "ok", "full_explanation": "ok", "evidence": "ok", "evidence_summary": "ok", "recommended_review_steps": [], "false_positive_notes": "", "raw_text": "ok", "metadata": {}})
    ips = []
    prepared = []
    incidents = []

    view = alerts_module.AlertsView(
        open_ip_context=ips.append,
        open_manual_ip_action=lambda ip, action="block": prepared.append((ip, action)),
        open_incident=incidents.append,
    )
    view._table.selectRow(0)
    view._open_selected_ip_context()
    view._prepare_manual_block()
    view._open_selected_incident()

    assert ips == ["8.8.8.8"]
    assert prepared == [("8.8.8.8", "block")]
    assert incidents == [7]


def test_alerts_view_translates_direct_explanation_button(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.alerts as alerts_module

    _patch_base(monkeypatch, alerts_module)
    set_language("tr")
    view = alerts_module.AlertsView()

    assert view._title.text() == "Alarmlar"
    assert view._view_details.text() == "Detayları Gör"
    assert view._explain_button.text() == "Alarmı Açıkla"
    assert view._include_ml_alerts.text() == "ML alarmlarını dahil et"


def test_alerts_view_english_explanation_button_label(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.alerts as alerts_module

    _patch_base(monkeypatch, alerts_module)
    set_language("en")
    view = alerts_module.AlertsView()

    assert view._title.text() == "Alerts"
    assert view._explain_button.text() == "Explain Alert"
    assert view._include_ml_alerts.text() == "Include ML alerts"
