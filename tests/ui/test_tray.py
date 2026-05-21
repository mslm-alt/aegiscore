import importlib
from pathlib import Path
import sys

import pytest
from ui.i18n import set_language, tr

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def test_tray_import_graceful():
    pytest.importorskip("PySide6")
    module = importlib.import_module("ui.tray")
    assert module.TrayManager is not None


def test_tray_no_write_guard_sources():
    source = Path("ui/tray.py").read_text(encoding="utf-8").lower()
    for token in (
        "write_text(",
        "requests.post(",
        "requests.get(",
        ".commit(",
        "insert into alerts",
        "update alerts",
        "delete from alerts",
        "block_ip(",
        "unblock_ip(",
        "reset_database(",
        "close_incident(",
        "smtplib",
        ".sendmail(",
        "firewall-cmd",
    ):
        assert token not in source


def test_tray_status_and_tooltip_update_without_qt():
    import ui.tray as tray_module

    manager = tray_module.TrayManager.__new__(tray_module.TrayManager)
    manager._tray = None
    manager._enabled = False
    manager._notifications_paused = False

    assert manager.status() == {
        "enabled": False,
        "paused": False,
        "supported": bool(tray_module.QSystemTrayIcon is not None),
    }
    manager.update_tooltip(
        app_name="AegisCoreSIEM",
        backend_status="Degraded",
        mode="Read-only",
        ml_status="No-action",
    )


def test_tray_cleanup_hides_and_releases_tray(monkeypatch):
    import ui.tray as tray_module

    class _StubTray:
        def __init__(self):
            self.hidden = False
            self.context_menu = object()

        def hide(self):
            self.hidden = True

        def setContextMenu(self, menu):
            self.context_menu = menu

    manager = tray_module.TrayManager.__new__(tray_module.TrayManager)
    manager._tray = _StubTray()

    manager.cleanup()

    assert manager._tray is None


def test_tray_minimize_to_tray_hides_window_and_shows_notice_once():
    import ui.tray as tray_module

    class _StubWindow:
        def __init__(self):
            self.hide_calls = 0

        def hide(self):
            self.hide_calls += 1

    class _StubTray:
        def __init__(self):
            self.messages = []

        def showMessage(self, title, message, icon, timeout):
            self.messages.append((title, message, icon, timeout))

    class _StubMessageIcon:
        Information = "info"

    class _StubQSystemTrayIcon:
        MessageIcon = _StubMessageIcon

    manager = tray_module.TrayManager.__new__(tray_module.TrayManager)
    manager._window = _StubWindow()
    manager._tray = _StubTray()
    manager._enabled = True
    manager._first_minimize_notice_shown = False

    original_qsystemtrayicon = tray_module.QSystemTrayIcon
    tray_module.QSystemTrayIcon = _StubQSystemTrayIcon
    try:
        assert manager.minimize_to_tray() is True
        assert manager.minimize_to_tray() is True
    finally:
        tray_module.QSystemTrayIcon = original_qsystemtrayicon

    assert manager._window.hide_calls == 2
    assert len(manager._tray.messages) == 1
    assert manager._tray.messages[0][0] == "AegisCore"
    assert "still running" in manager._tray.messages[0][1]


def test_tray_minimize_to_tray_returns_false_when_disabled():
    import ui.tray as tray_module

    manager = tray_module.TrayManager.__new__(tray_module.TrayManager)
    manager._enabled = False

    assert manager.minimize_to_tray() is False


def test_tray_menu_has_only_minimal_actions():
    import ui.tray as tray_module

    manager = tray_module.TrayManager.__new__(tray_module.TrayManager)

    class _Action:
        def __init__(self, text):
            self._text = text

        def text(self):
            return self._text

    manager._show_action = _Action("Show AegisCore")
    manager._alerts_action = _Action("Open Alerts")
    manager._pause_action = _Action("Pause Notifications")
    manager._quit_action = _Action("Quit")

    assert manager.menu_action_texts() == [
        "Show AegisCore",
        "Open Alerts",
        "Pause Notifications",
        "Quit",
    ]


def test_tray_toggle_notifications_updates_pause_resume_label():
    import ui.tray as tray_module

    toggled = []

    class _Action:
        def __init__(self):
            self._text = "Pause Notifications"

        def setText(self, text):
            self._text = text

        def text(self):
            return self._text

    manager = tray_module.TrayManager.__new__(tray_module.TrayManager)
    manager._enabled = True
    manager._notifications_paused = False
    manager._pause_action = _Action()
    manager._toggle_notifications = toggled.append

    manager.toggle_notifications()
    assert toggled == [False]
    assert manager._pause_action.text() == "Resume Notifications"

    manager.toggle_notifications()
    assert toggled == [False, True]
    assert manager._pause_action.text() == "Pause Notifications"


def test_tray_labels_localize():
    set_language("en")
    assert tr("Show AegisCore") == "Show AegisCore"
    assert tr("Open Alerts") == "Open Alerts"
    assert tr("Pause Notifications") == "Pause Notifications"

    set_language("tr")
    assert tr("Show AegisCore") == "AegisCore'u Göster"
    assert tr("Open Alerts") == "Alarmları Aç"
    assert tr("Pause Notifications") == "Bildirimleri Duraklat"
