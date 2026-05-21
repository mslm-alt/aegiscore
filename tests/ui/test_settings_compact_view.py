import os
from pathlib import Path
import sys

import pytest
from ui.models import NotificationRule

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _qt_app():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class _ImmediateController:
    def __init__(self, owner=None, interval_ms=None):
        return None

    def trigger(self, task=None, on_result=None, on_error=None, on_finished=None):
        try:
            if task is not None and on_result is not None:
                on_result(task())
        except Exception as exc:
            if on_error is not None:
                on_error({"message": str(exc)})
        if on_finished is not None:
            on_finished()
        return True


def test_compact_settings_hides_integrations_and_keeps_user_preferences(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.settings_compact as settings_module

    monkeypatch.setattr(settings_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(settings_module.backend_facade, "collect_settings_status", lambda config_path=None: {
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

    changed = []
    view = settings_module.SettingsView(notification_rule=NotificationRule(), notification_rule_changed=changed.append)

    assert not hasattr(view, "_tabs")
    assert view._appearance_title.text() == "Appearance"
    assert view._theme_combo.count() >= 3
    assert view._language_selector.count() == 2
    assert view._integration_values["LLM Provider"].text() == "openai"
    assert view._integration_values["LLM Model"].text() == "gpt-5.5"
    assert view._integration_values["LLM API Key"].text() == "Configured"
    assert view._integration_values["Telegram"].text() == "Configured"
    assert view._integration_values["Email"].text() == "Not configured"
    assert not hasattr(view, "_desktop_notifications")
    assert not hasattr(view, "_background_notifications")
    assert not hasattr(view, "_tray_notifications")
    assert not hasattr(view, "_duplicate_suppression")
    assert "manual-only" in view._safety_items[1].text().lower()
    assert "disabled" in view._safety_items[3].text().lower()
