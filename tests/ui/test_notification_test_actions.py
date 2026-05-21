from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.actions import notification_test, secret_store
from ui.actions.guard import required_confirmation_for
import ui.backend_facade as backend_facade


def _integrations(raw: dict):
    return SimpleNamespace(
        _raw=dict(raw),
        telegram_bot_token=str(raw.get("TELEGRAM_BOT_TOKEN", "") or ""),
        telegram_chat_id=str(raw.get("TELEGRAM_CHAT_ID", "") or ""),
        email_to=str(raw.get("EMAIL_TO", "") or ""),
        telegram_enabled=bool(raw.get("TELEGRAM_BOT_TOKEN") and raw.get("TELEGRAM_CHAT_ID")),
        email_enabled=bool(raw.get("EMAIL_SMTP_HOST") and raw.get("EMAIL_TO")),
    )


def _context(raw: dict):
    return {
        "config": {"db": "ok"},
        "integrations": _integrations(raw),
        "config_exists": True,
    }


def test_telegram_preview_missing_config_denied(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: _context({}))

    result = backend_facade.preview_notification_test(
        channel="telegram",
        actor="alice",
        role="admin",
        reason="ticket-1",
        confirmation="",
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert "TELEGRAM_BOT_TOKEN" in result["missing_fields"]
    assert result["raw_secret_included"] is False


def test_email_preview_missing_config_denied(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: _context({"EMAIL_TO": "ops@example.com"}))

    result = backend_facade.preview_notification_test(
        channel="email",
        actor="alice",
        role="admin",
        reason="ticket-2",
        confirmation="",
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert "EMAIL_SMTP_HOST" in result["missing_fields"]


def test_telegram_execute_without_admin_denied(monkeypatch):
    raw = {"TELEGRAM_BOT_TOKEN": "token-secret", "TELEGRAM_CHAT_ID": "123456"}
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: _context(raw))

    preview = backend_facade.preview_notification_test(
        channel="telegram",
        actor="alice",
        role="viewer",
        reason="ticket-3",
        confirmation="",
        dry_run_completed=True,
    )
    phrase = preview["guard"]["metadata"]["request"]["required_confirmation_phrase"]
    result = backend_facade.execute_notification_test(
        channel="telegram",
        actor="alice",
        role="viewer",
        reason="ticket-3",
        confirmation=phrase,
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "guard_denied"


def test_email_execute_without_reason_denied(monkeypatch):
    raw = {
        "EMAIL_SMTP_HOST": "smtp.example.com",
        "EMAIL_SMTP_PORT": "587",
        "EMAIL_SMTP_USER": "ops",
        "EMAIL_SMTP_PASS": "pass-secret",
        "EMAIL_FROM": "ops@example.com",
        "EMAIL_TO": "alerts@example.com",
    }
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: _context(raw))
    target = notification_test.masked_destination_for("email", _integrations(raw))
    phrase = required_confirmation_for("email_test_send", target)

    result = backend_facade.execute_notification_test(
        channel="email",
        actor="alice",
        role="admin",
        reason="",
        confirmation=phrase,
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "guard_denied"


def test_execute_without_dry_run_denied(monkeypatch):
    raw = {"TELEGRAM_BOT_TOKEN": "token-secret", "TELEGRAM_CHAT_ID": "123456"}
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: _context(raw))
    target = notification_test.masked_destination_for("telegram", _integrations(raw))
    phrase = required_confirmation_for("telegram_test_send", target)

    result = backend_facade.execute_notification_test(
        channel="telegram",
        actor="alice",
        role="admin",
        reason="ticket-4",
        confirmation=phrase,
        dry_run_completed=False,
    )

    assert result["status"] == "denied"
    assert result["error"] == "guard_denied"


def test_execute_without_confirmation_denied(monkeypatch):
    raw = {
        "EMAIL_SMTP_HOST": "smtp.example.com",
        "EMAIL_SMTP_PORT": "587",
        "EMAIL_SMTP_USER": "ops",
        "EMAIL_SMTP_PASS": "pass-secret",
        "EMAIL_FROM": "ops@example.com",
        "EMAIL_TO": "alerts@example.com",
    }
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: _context(raw))

    result = backend_facade.execute_notification_test(
        channel="email",
        actor="alice",
        role="admin",
        reason="ticket-5",
        confirmation="WRONG",
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "guard_denied"


def test_audit_unavailable_denies_execution(monkeypatch):
    raw = {"TELEGRAM_BOT_TOKEN": "token-secret", "TELEGRAM_CHAT_ID": "123456"}
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: _context(raw))
    monkeypatch.setattr(secret_store, "audit_user_action_available", lambda config: (False, "db_down"))
    target = notification_test.masked_destination_for("telegram", _integrations(raw))
    phrase = required_confirmation_for("telegram_test_send", target)

    result = backend_facade.execute_notification_test(
        channel="telegram",
        actor="alice",
        role="admin",
        reason="ticket-6",
        confirmation=phrase,
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "audit_unavailable"


def test_telegram_send_success_mocked_and_audited(monkeypatch):
    raw = {"TELEGRAM_BOT_TOKEN": "token-secret", "TELEGRAM_CHAT_ID": "123456"}
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: _context(raw))
    monkeypatch.setattr(secret_store, "audit_user_action_available", lambda config: (True, ""))
    captured = {}

    def _record(**kwargs):
        captured["details"] = kwargs["details"]
        return {"status": "ok", "id": 1, "error": None}

    monkeypatch.setattr(secret_store, "record_user_action", _record)
    monkeypatch.setattr(notification_test, "send_telegram_test", lambda integrations: {
        "status": "ok",
        "channel": "telegram",
        "destination_masked": "****3456",
        "message": "Telegram test notification sent.",
        "error": None,
    })
    target = notification_test.masked_destination_for("telegram", _integrations(raw))
    phrase = required_confirmation_for("telegram_test_send", target)

    result = backend_facade.execute_notification_test(
        channel="telegram",
        actor="alice",
        role="admin",
        reason="ticket-7",
        confirmation=phrase,
        dry_run_completed=True,
    )

    assert result["status"] == "executed"
    assert captured["details"]["channel"] == "telegram"
    assert "token-secret" not in backend_facade._stringify_payload(captured["details"])


def test_email_send_success_mocked_and_audited(monkeypatch):
    raw = {
        "EMAIL_SMTP_HOST": "smtp.example.com",
        "EMAIL_SMTP_PORT": "587",
        "EMAIL_SMTP_USER": "ops",
        "EMAIL_SMTP_PASS": "pass-secret",
        "EMAIL_FROM": "ops@example.com",
        "EMAIL_TO": "alerts@example.com",
    }
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: _context(raw))
    monkeypatch.setattr(secret_store, "audit_user_action_available", lambda config: (True, ""))
    captured = {}

    def _record(**kwargs):
        captured["details"] = kwargs["details"]
        return {"status": "ok", "id": 1, "error": None}

    monkeypatch.setattr(secret_store, "record_user_action", _record)
    monkeypatch.setattr(notification_test, "send_email_test", lambda integrations: {
        "status": "ok",
        "channel": "email",
        "destination_masked": "a***@***example.com",
        "message": "Email test notification sent.",
        "error": None,
    })
    target = notification_test.masked_destination_for("email", _integrations(raw))
    phrase = required_confirmation_for("email_test_send", target)

    result = backend_facade.execute_notification_test(
        channel="email",
        actor="alice",
        role="admin",
        reason="ticket-8",
        confirmation=phrase,
        dry_run_completed=True,
    )

    assert result["status"] == "executed"
    assert captured["details"]["channel"] == "email"
    assert "pass-secret" not in backend_facade._stringify_payload(captured["details"])


def test_failure_response_sanitized_no_raw_secret_leak(monkeypatch):
    raw = {"TELEGRAM_BOT_TOKEN": "bot-very-secret", "TELEGRAM_CHAT_ID": "999999"}
    integrations = _integrations(raw)

    class _Boom(RuntimeError):
        pass

    def _raise(*args, **kwargs):
        raise _Boom("https://api.telegram.org/botbot-very-secret/sendMessage exploded")

    monkeypatch.setattr(notification_test.urllib.request, "urlopen", _raise)
    result = notification_test.send_telegram_test(integrations)
    text = backend_facade._stringify_payload(result)

    assert result["status"] == "failed"
    assert "bot-very-secret" not in text
    assert "999999" not in text


def test_notification_action_no_write_guard_sources():
    targets = {
        "ui/backend_facade.py": [
            "write_text(",
            "smtplib",
            "urllib.request",
            "firewall-cmd",
            "block_ip(",
            "reset_database(",
            "close_incident(",
        ],
        "ui/views/settings_compact.py": [
            "write_text(",
            "requests.post(",
            "requests.get(",
            "smtplib",
            "urllib.request",
            "firewall-cmd",
            "block_ip(",
        ],
        "ui/actions/notification_test.py": [
            "update_env_values(",
            "write_text(",
            "firewall-cmd",
            "block_ip(",
            "reset_database(",
            "close_incident(",
        ],
    }

    for path_text, forbidden_tokens in targets.items():
        source = Path(path_text).read_text(encoding="utf-8").lower()
        for token in forbidden_tokens:
            assert token.lower() not in source
