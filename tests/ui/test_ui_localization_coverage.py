import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.i18n import set_language, tr


def _qt_app():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


_LEAK_TOKENS = [
    "ç", "ğ", "ı", "İ", "ö", "ş", "ü",
    "Açıklama", "Öneri", "Kanıt", "Kaynak", "Kural", "Uyarı",
    "Başarılı", "Başarısız", "Hazır", "Yenile", "Ayarlar",
    "Raporlar", "Tanılama", "Canlı", "girişimi", "tespit edildi",
]


class _ImmediateController:
    def __init__(self, owner=None, interval_ms=None):
        self._task = None
        self._on_result = None
        self._on_finished = None

    def configure(self, task=None, on_result=None, on_error=None, on_finished=None):
        self._task = task
        self._on_result = on_result
        self._on_finished = on_finished

    def trigger(self, task=None, on_result=None, on_error=None, on_finished=None):
        task = task or self._task
        on_result = on_result or self._on_result
        on_finished = on_finished or self._on_finished
        if task is not None and on_result is not None:
            on_result(task())
        if on_finished is not None:
            on_finished()
        return True

    def start(self):
        return None

    def stop(self):
        return None

    def resume(self):
        return None

    def dispose(self):
        return None


def _assert_no_turkish_leak(text: str):
    for token in _LEAK_TOKENS:
        assert token not in text


def test_tr_missing_key_passthrough():
    set_language("en")
    assert tr("missing ui localization key") == "missing ui localization key"
    set_language("tr")
    assert tr("missing ui localization key") == "missing ui localization key"


def test_preflight_and_ip_reputation_localize(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.preflight as preflight_module
    import ui.views.ip_reputation as ip_module

    monkeypatch.setattr(preflight_module, "FunctionWorker", lambda fn, *args: type("W", (), {"signals": type("S", (), {"result": type("Sig", (), {"connect": lambda *a: None})(), "error": type("Sig", (), {"connect": lambda *a: None})()})()})())
    monkeypatch.setattr(ip_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(ip_module.backend_facade, "collect_ip_reputation_status", lambda **kwargs: {"status": "ok", "abuseipdb": {}, "ip_blocking": {}})
    monkeypatch.setattr(ip_module.backend_facade, "collect_ip_block_candidates", lambda **kwargs: {"status": "ok", "candidates": []})

    set_language("en")
    preflight = preflight_module.PreflightWindow(auto_load=False)
    ip_view = ip_module.IPReputationView()
    text = " ".join([
        preflight.windowTitle(),
        preflight._continue_button.text(),
        ip_view._title.text(),
        ip_view._refresh_all.text(),
        ip_view._safety_note.text(),
    ])
    _assert_no_turkish_leak(text)

    set_language("tr")
    preflight = preflight_module.PreflightWindow(auto_load=False)
    ip_view = ip_module.IPReputationView()
    ip_view.retranslate_ui()
    assert preflight.windowTitle() == "AegisCore - Başlangıç Ön Kontrolü"
    assert ip_view._title.text() == "IP Engelleme"


def test_reports_and_diagnostics_localize(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.reports as reports_module
    import ui.views.diagnostics as diagnostics_module

    monkeypatch.setattr(reports_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(reports_module.backend_facade, "collect_reports_summary", lambda **kwargs: {"status": "ok", "empty": True})
    monkeypatch.setattr(reports_module.backend_facade, "collect_report_artifacts", lambda **kwargs: {"artifacts": []})
    monkeypatch.setattr(reports_module.backend_facade, "collect_report_preview", lambda path: {"status": "ok", "kind": "txt", "path": path, "preview": ""})
    monkeypatch.setattr(diagnostics_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(diagnostics_module.backend_facade, "collect_diagnostics_summary", lambda **kwargs: {"status": "ok", "db_health": {"status": "ok"}, "schema_version": 4, "rule_count": 1, "open_incidents": 0, "degraded_flags": [], "parse_fail_summary": {}, "duplicate_summary": {}, "runtime": {}})
    monkeypatch.setattr(diagnostics_module.backend_facade, "collect_diagnostic_bundle_preview", lambda **kwargs: {"message": "preview", "would_include": [], "would_redact": [], "would_exclude": []})

    set_language("en")
    reports = reports_module.ReportsView()
    diagnostics = diagnostics_module.DiagnosticsView()
    text = " ".join([
        reports._title.text(),
        reports._refresh.text(),
        reports._status_note.text(),
        reports._preview_note.text(),
        diagnostics._title.text(),
        diagnostics._refresh.text(),
        diagnostics._bundle_group.title(),
        diagnostics._text.toPlainText(),
    ])
    _assert_no_turkish_leak(text)

    set_language("tr")
    reports = reports_module.ReportsView()
    reports.retranslate_ui()
    diagnostics = diagnostics_module.DiagnosticsView()
    diagnostics.retranslate_ui()
    assert reports._title.text() == "Raporlar"
    assert diagnostics._title.text() == "Tanılama"


def test_settings_localize(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.settings_compact as settings_module

    monkeypatch.setattr(settings_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(settings_module.backend_facade, "collect_settings_status", lambda **kwargs: {
        "status": "ok",
        "theme": {"current": "dark"},
        "llm": {"backend": "openai", "model": "gpt-5.5", "enabled": True, "api_key_configured": True},
        "integrations": {"telegram_configured": True, "email_configured": False},
        "security_locks": {
            "config_write_locked": True,
            "firewall_actions_locked": True,
            "manual_actions_locked": True,
            "auto_ip_block_disabled": True,
        },
    })

    set_language("en")
    settings = settings_module.SettingsView()
    text = " ".join([
        settings._title.text(),
        settings._refresh.text(),
        settings._appearance_title.text(),
        settings._integrations_title.text(),
        settings._safety_title.text(),
        settings._integrations_note.text(),
        " ".join(item.text() for item in settings._safety_items),
    ])
    _assert_no_turkish_leak(text)

    set_language("tr")
    settings = settings_module.SettingsView()
    settings.retranslate_ui()
    assert settings._title.text() == "Ayarlar"
    assert settings._appearance_title.text() == "Görünüm"
    assert settings._integrations_title.text() == "Entegrasyonlar"
    assert settings._safety_title.text() == "Güvenlik"


def test_backend_payloads_have_no_turkish_leak_in_english_mode(monkeypatch):
    import ui.backend_facade as backend_facade

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {
        "config": {"language": "en"},
        "config_path": "config/config.yml",
        "config_exists": True,
        "integrations": type("Integrations", (), {"summary": lambda self: {}})(),
    })
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian"})
    monkeypatch.setattr(backend_facade, "is_supported", lambda distro_info: (True, ""))
    monkeypatch.setattr(backend_facade, "_read_source_health", lambda config, language="tr": {
        "status": "ok",
        "message": backend_facade.system_text("preflight_sources_healthy", language),
        "details": {"sources": {}},
    })
    monkeypatch.setattr(backend_facade, "_read_database_health", lambda config, language="tr": {
        "available": False,
        "status": "degraded",
        "message": backend_facade.system_text("preflight_database_missing", language),
        "details": {"reason": "database_url_missing"},
    })
    monkeypatch.setattr(backend_facade, "_read_ml_safety", lambda config, language="tr": {
        "status": "ok",
        "message": backend_facade.system_text("preflight_ml_safety_ok", language),
        "details": {},
    })
    monkeypatch.setattr(backend_facade, "_read_ip_blocking_safety", lambda config, language="tr": {
        "status": "ok",
        "message": backend_facade.system_text("preflight_ip_blocking_manual_only", language),
        "details": {"manual_only": True},
    })
    monkeypatch.setattr(backend_facade, "collect_security_locks", lambda config_path=None: {
        "read_only_mode": True,
        "auto_ip_block_disabled": True,
        "ml_no_action_contract": True,
        "manual_actions_locked": True,
    })

    preflight_payload = backend_facade.collect_preflight_status(language="en")
    historical_payload = backend_facade.get_historical_preview_status_no_scan(language="en")
    combined_text = " ".join(
        [historical_payload["message"]]
        + [str(item.get("message", "")) for item in preflight_payload["checks"]]
    )

    _assert_no_turkish_leak(combined_text)


def test_ml_center_and_alerts_localize_without_english_leak(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.alerts as alerts_module
    import ui.views.ml_center_compact as ml_module

    monkeypatch.setattr(alerts_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(alerts_module.backend_facade, "collect_alerts", lambda **kwargs: {
        "status": "ok",
        "alerts": [{"id": 1, "timestamp_text": "2026-05-19 11:00:00", "severity": "medium", "rule_id": "RULE-1", "source_ip": "1.1.1.1", "source": "auth_log", "message": "ok", "raw": {}}],
        "error": None,
    })
    monkeypatch.setattr(alerts_module.backend_facade, "is_ml_alert", lambda alert: False)
    monkeypatch.setattr(ml_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(ml_module.backend_facade, "collect_ml_center_summary", lambda **kwargs: {
        "status": "ok",
        "ml_mode_text": "Audit-only",
        "ml_safety_text": "No autonomous action",
        "first_training": {"family_id": "ML-AUTH", "current_samples": 1, "needed_samples": 10, "missing_samples": 9, "ready": False},
        "family_rows": [],
    })
    monkeypatch.setattr(ml_module.backend_facade, "collect_training_status", lambda **kwargs: {
        "status": "ok",
        "timestamp_text": "Never",
        "training_status": "No model has been trained yet.",
        "family_info": "",
        "model_info": "",
    })
    monkeypatch.setattr(ml_module.backend_facade, "collect_historical_scan_status", lambda **kwargs: {
        "status": "ok",
        "timestamp_text": "Never",
        "scan_status": "Historical scan has not been run yet. Run it from the CLI when needed.",
        "note": "CLI/manual only",
    })
    monkeypatch.setattr(ml_module.backend_facade, "collect_ml_alerts", lambda **kwargs: {"status": "ok", "alerts": []})

    set_language("en")
    alerts = alerts_module.AlertsView()
    ml_center = ml_module.MLCenterView()
    text = " ".join([
        alerts._include_ml_alerts.text(),
        ml_center._title.text(),
        ml_center._quota_detail.text(),
        ml_center._training_detail.text(),
        ml_center._historical_detail.text(),
    ])
    _assert_no_turkish_leak(text)

    set_language("tr")
    alerts = alerts_module.AlertsView()
    ml_center = ml_module.MLCenterView()
    ml_center.retranslate_ui()
    assert alerts._include_ml_alerts.text() == "ML alarmlarını dahil et"
    assert ml_center._title.text() == "ML Merkezi"
