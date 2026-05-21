from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import ui.backend_facade as backend_facade


def test_collect_settings_status_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {
        "config": {
            "llm": {"enabled": False, "backend": "mock"},
            "abuseipdb": {"enrich_alert_ips": True},
            "ip_blocking": {"enabled": True},
            "ml": {"active_decision_layer": {"enabled": False, "no_action_contract": True}},
            "risk": {"cooldown": {"default_seconds": 300}},
        },
        "config_exists": True,
        "integrations": type("I", (), {
            "_raw": {},
            "summary": lambda self: {},
            "telegram_enabled": False,
            "email_enabled": False,
            "abuseipdb_key": "",
            "openai_key": "",
            "gemini_key": "",
            "anthropic_key": "",
            "telegram_bot_token": "",
            "telegram_chat_id": "",
        })(),
    })
    result = backend_facade.collect_settings_status()

    assert result["status"] in {"ok", "degraded"}
    assert {"status", "config_path", "config_readable", "env_status", "integrations", "llm", "notifications", "security_locks", "error"} <= set(result)
    assert {"backend", "model", "enabled", "api_key_configured"} <= set(result["llm"])


def test_collect_secret_status_secret_masking_no_raw_leak(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {
        "config": {"llm": {"backend": "openai"}, "abuseipdb": {}},
        "config_exists": True,
        "integrations": type("I", (), {
            "_raw": {
                "TELEGRAM_BOT_TOKEN": "telegram-secret",
                "EMAIL_SMTP_PASS": "smtp-secret",
                "OPENAI_API_KEY": "openai-secret",
            },
            "summary": lambda self: {},
            "abuseipdb_key": "",
            "openai_key": "openai-secret",
            "gemini_key": "",
            "anthropic_key": "",
            "telegram_bot_token": "telegram-secret",
            "telegram_chat_id": "",
        })(),
    })

    result = backend_facade.collect_secret_status()
    text = backend_facade._stringify_payload(result)

    assert result["status"] == "ok"
    assert result["secrets"]
    assert "telegram-secret" not in text
    assert "smtp-secret" not in text
    assert "openai-secret" not in text


def test_collect_notification_settings_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {
        "config": {"risk": {"cooldown": {"default_seconds": 123}}, "llm": {"enabled": False, "backend": "mock"}},
        "config_exists": True,
        "integrations": type("I", (), {
            "_raw": {"EMAIL_SMTP_HOST": "smtp.example.com", "EMAIL_SMTP_PORT": "587", "EMAIL_TO": "ops@example.com"},
            "summary": lambda self: {},
            "telegram_enabled": False,
            "email_enabled": True,
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "email_smtp_host": "smtp.example.com",
            "email_to": "ops@example.com",
        })(),
    })

    result = backend_facade.collect_notification_settings()

    assert result["status"] in {"ok", "degraded"}
    assert {"desktop_notifications", "tray_background_mode", "telegram", "email", "severity_thresholds", "cooldown_duplicate_suppression", "missing_required_fields", "error"} <= set(result)
    assert result["desktop_notifications"]["source"] == "session_default_preview"
    assert result["tray_background_mode"]["source"] == "session_default_preview"
    assert result["severity_thresholds"]["source"] == "session_default_preview"


def test_collect_theme_options_returns_expected_modes(monkeypatch):
    monkeypatch.setattr(backend_facade, "_read_qt_theme_mode", lambda: "")
    result = backend_facade.collect_theme_options()

    assert result["status"] == "ok"
    assert [item["id"] for item in result["options"]] == ["dark", "light", "system"]
    assert result["current"] == "dark"
    assert result["source"] == "default_preview"


def test_collect_theme_options_reads_runtime_session(monkeypatch):
    monkeypatch.setattr(backend_facade, "_read_qt_theme_mode", lambda: "light")

    result = backend_facade.collect_theme_options()

    assert result["current"] == "light"
    assert result["source"] == "runtime_session"


def test_validate_settings_safe_preview_preview_only():
    result = backend_facade.validate_settings_safe_preview("telegram")

    assert result["status"] == "preview_only"
    assert "Live validation is disabled" in result["message"]


def test_collect_guarded_action_policies_available_in_settings_context():
    result = backend_facade.collect_guarded_action_policies()

    assert result["status"] == "ok"
    assert result["execution_enabled"] is True
    assert "api_key_update" in result["executable_action_types"]
    assert "telegram_test_send" in result["executable_action_types"]
    assert "email_test_send" in result["executable_action_types"]
    assert any(item["action_type"] == "api_key_update" for item in result["policies"])


def test_settings_no_write_guard_backend_facade_source():
    source = Path("ui/backend_facade.py").read_text(encoding="utf-8").lower()
    forbidden_tokens = [
        "write_text(",
        "requests.get(",
        "requests.post(",
        "abuseipdbclient(",
        "notifier(",
        ".send(",
        ".commit(",
        "insert into settings",
        "update settings",
        "delete from settings",
        "block_ip(",
        "unblock_ip(",
        "reset_database(",
        "close_incident(",
    ]

    for token in forbidden_tokens:
        assert token not in source
