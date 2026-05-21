from pathlib import Path

from core import integrations
from core.integrations import IntegrationSettings
from core.notifier import Notifier


def test_integration_settings_loads_notifier_keys_from_env(monkeypatch, tmp_path):
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    (cfg_dir / "integrations.env").write_text("", encoding="utf-8")

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tg-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "12345")
    monkeypatch.setenv("EMAIL_SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setenv("EMAIL_TO", "admin@example.com")

    settings = IntegrationSettings.load(config_dir=str(cfg_dir))

    assert settings.telegram_enabled is True
    assert settings.telegram_bot_token == "tg-token"
    assert settings.telegram_chat_id == "12345"
    assert settings.email_enabled is True
    assert settings.email_smtp_host == "smtp.gmail.com"
    assert settings.email_to == "admin@example.com"


def test_notifier_becomes_active_with_telegram_settings():
    notifier = Notifier(
        settings={
            "TELEGRAM_BOT_TOKEN": "tg-token",
            "TELEGRAM_CHAT_ID": "12345",
        }
    )

    assert notifier.is_active is True
    status = notifier.status()
    assert status["telegram_active"] is True
    assert status["email_active"] is False


def test_notifier_becomes_active_with_email_settings():
    notifier = Notifier(
        settings={
            "EMAIL_SMTP_HOST": "smtp.gmail.com",
            "EMAIL_SMTP_PORT": "587",
            "EMAIL_SMTP_USER": "bot@example.com",
            "EMAIL_SMTP_PASS": "secret",
            "EMAIL_FROM": "bot@example.com",
            "EMAIL_TO": "admin@example.com",
        }
    )

    assert notifier.is_active is True
    status = notifier.status()
    assert status["telegram_active"] is False
    assert status["email_active"] is True

def test_load_env_file_malformed_line_does_not_log_secret_prefix(tmp_path, caplog):
    env_path = tmp_path / "integrations.env"
    env_path.write_text(
        "# comment\n"
        "OPENAI_API_KEY fake-openai-secret-value\n"
        "GEMINI_API_KEY=valid-gemini-key\n",
        encoding="utf-8",
    )

    caplog.set_level("DEBUG", logger=integrations.logger.name)

    result = integrations._load_env_file(env_path)

    assert result == {"GEMINI_API_KEY": "valid-gemini-key"}
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "fake-openai-secret-value" not in messages
    assert "OPENAI_API_KEY fake-openai-secret-value" not in messages
    assert "Satır 2 atlandı (= yok)" in messages

