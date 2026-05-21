from pathlib import Path
import json
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import ui.backend_facade as backend_facade


_TURKISH_LEAK_RE = re.compile(
    r"[çğıİöşüÇĞÖŞÜ]|Başarılı|Başarısız|Yüklenen|Tüm kurallar|Geçerli|Uyarı|Kaynak|Kural|Açıklama|Öneri|Kanıt|Hazır|Yenile|Ayarlar|Raporlar|Tanılama|bilinmiyor|belirtilmemiş|tespit edildi|girişimi"
)


def test_collect_preflight_status_returns_expected_schema():
    result = backend_facade.collect_preflight_status("config/config.yml")

    assert isinstance(result, dict)
    assert result["overall"] in {"PASS", "WARNING", "BLOCKED"}
    assert isinstance(result["checks"], list)
    assert isinstance(result["security_locks"], dict)
    assert result["checks"]
    first = result["checks"][0]
    assert {"name", "status", "message", "details", "suggestion"} <= set(first)


def test_collect_security_locks_always_returns_required_flags():
    locks = backend_facade.collect_security_locks("config/config.yml")

    assert {"read_only_mode", "auto_ip_block_disabled", "ml_no_action_contract", "manual_actions_locked"} <= set(locks)


def test_facade_returns_degraded_result_without_raising_on_db_unavailable(monkeypatch):
    monkeypatch.setattr(backend_facade, "create_database", lambda config: None)

    result = backend_facade.collect_overview_status("config/config.yml")

    assert result["overall"] in {"PASS", "WARNING", "BLOCKED"}
    assert result["database"]["available"] is False


def test_facade_returns_blocked_result_without_raising_on_config_error(monkeypatch):
    def _boom(_path):
        raise RuntimeError("config_broken")

    monkeypatch.setattr(backend_facade, "_load_config", _boom)

    result = backend_facade.collect_preflight_status("config/config.yml")

    assert result["overall"] == "BLOCKED"
    assert result["checks"][0]["status"] == "BLOCKED"


def test_mask_sensitive_value_redacts_secret():
    masked = backend_facade.mask_sensitive_value("super-secret-token-1234")

    assert "super-secret" not in masked
    assert "1234" in masked
    assert "redacted" in masked.lower()


def test_redact_sensitive_payload_recursive_secret_leak(monkeypatch):
    payload = {
        "api_key": "abcdef123456",
        "nested": [
            {"password": "hunter2"},
            "Authorization: Bearer very-secret-token",
            {"safe": "value"},
        ],
    }

    redacted = backend_facade.redact_sensitive_payload(payload)
    serialized = backend_facade._stringify_payload(redacted)

    assert "abcdef123456" not in serialized
    assert "hunter2" not in serialized
    assert "very-secret-token" not in serialized
    assert "value" in serialized


class _OverviewDb:
    def __init__(self, *, paused=None, pause_reason="", stats=None):
        self._paused = paused
        self._pause_reason = pause_reason
        self._stats = stats or {"alerts_24h": 5}

    def health_check(self):
        return {"ok": True, "status": "ok"}

    def get_stats(self):
        return dict(self._stats)

    def get_open_incidents(self):
        return [{"id": 1}]

    def get_stat(self, key):
        if key != "ml_control_state":
            return None
        if self._paused is None:
            return None
        return json.dumps({"paused": self._paused, "pause_reason": self._pause_reason})

    def close(self):
        return None


def test_collect_overview_status_reads_ml_pause_state(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian"})
    monkeypatch.setattr(backend_facade, "_read_source_health", lambda config: {"details": {"sources": {}}, "status": "ok"})
    monkeypatch.setattr(backend_facade, "_read_database_health", lambda config: {"available": True, "status": "ok"})
    monkeypatch.setattr(backend_facade, "RuntimeStateStore", lambda state_dir="data": type("Store", (), {"status": lambda self: {"total_alerts": 0}})())
    monkeypatch.setattr(backend_facade, "_phase_stats_summary", lambda state_dir="data": {"current_phase": 1})
    monkeypatch.setattr(backend_facade, "get_state_metrics", lambda: type("Metrics", (), {"status": lambda self: {}})())
    monkeypatch.setattr(backend_facade, "collect_security_locks", lambda config_path=None: {})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _OverviewDb(paused=True, pause_reason="incident_guard"))

    result = backend_facade.collect_overview_status("config/config.yml")

    assert result["ml_pause_known"] is True
    assert result["ml_paused"] is True
    assert result["ml_pause_reason"] == "incident_guard"


def test_collect_overview_status_marks_ml_pause_unknown_when_db_unavailable(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian"})
    monkeypatch.setattr(backend_facade, "_read_source_health", lambda config: {"details": {"sources": {}}, "status": "ok"})
    monkeypatch.setattr(backend_facade, "_read_database_health", lambda config: {"available": False, "status": "degraded"})
    monkeypatch.setattr(backend_facade, "RuntimeStateStore", lambda state_dir="data": type("Store", (), {"status": lambda self: {"total_alerts": 0}})())
    monkeypatch.setattr(backend_facade, "_phase_stats_summary", lambda state_dir="data": {"current_phase": 1})
    monkeypatch.setattr(backend_facade, "get_state_metrics", lambda: type("Metrics", (), {"status": lambda self: {}})())
    monkeypatch.setattr(backend_facade, "collect_security_locks", lambda config_path=None: {})

    result = backend_facade.collect_overview_status("config/config.yml")

    assert result["ml_pause_known"] is False
    assert result["ml_paused"] is None


def test_collect_preflight_status_localizes_messages_to_english(monkeypatch):
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

    result = backend_facade.collect_preflight_status("config/config.yml", language="en")
    messages = " ".join(str(item.get("message", "")) for item in result["checks"])

    assert "Config file was loaded." in messages
    assert "DATABASE_URL or database.url is not defined." in messages
    assert "A supported distro family was detected." in messages
    assert "Read-only security locks are active." in messages
    assert not _TURKISH_LEAK_RE.search(messages)


def test_collect_preflight_status_preserves_turkish_messages(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {
        "config": {"language": "tr"},
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

    result = backend_facade.collect_preflight_status("config/config.yml", language="tr")
    messages = " ".join(str(item.get("message", "")) for item in result["checks"])

    assert "Config dosyası okundu." in messages
    assert "DATABASE_URL veya database.url tanımlı değil." in messages
    assert "Desteklenen dağıtım ailesi algılandı." in messages
    assert "Read-only güvenlik kilitleri aktif." in messages


def test_get_historical_preview_status_no_scan_localizes_message():
    result_en = backend_facade.get_historical_preview_status_no_scan(language="en")
    result_tr = backend_facade.get_historical_preview_status_no_scan(language="tr")

    assert result_en["message"] == "Historical log scanning only runs when the user starts a scan from the scan button."
    assert not _TURKISH_LEAK_RE.search(result_en["message"])
    assert result_tr["message"] == "Geçmiş log taraması yalnız kullanıcı scan butonuna bastığında çalışır."
