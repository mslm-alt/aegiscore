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


class _StubRefreshController:
    def __init__(self, owner=None, interval_ms=None):
        self.started = False
        self.stopped = False
        self.resumed = False
        self.config = {}

    def configure(self, *args, **kwargs):
        self.config = kwargs
        return None

    def start(self):
        self.started = True
        return None

    def stop(self):
        self.stopped = True
        return None

    def resume(self):
        self.resumed = True
        return None

    def dispose(self):
        return None


class _StubTrayManager:
    def __init__(self, **kwargs):
        self.enabled = False
        self.tray_icon = None
        self.cleaned = False
        self.minimize_result = False

    def cleanup(self):
        self.cleaned = True
        return None

    def minimize_to_tray(self):
        return self.minimize_result


def test_main_window_sidebar_uses_simplified_sections(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.main_window as main_window_module
    from PySide6.QtWidgets import QWidget

    monkeypatch.setattr(main_window_module, "RefreshController", _StubRefreshController)
    monkeypatch.setattr(main_window_module, "TrayManager", _StubTrayManager)
    monkeypatch.setattr(main_window_module.MainWindow, "_build_sections", lambda self: [
        ("Overview", QWidget()),
        ("Alerts", QWidget()),
        ("Live Logs", QWidget()),
        ("ML Center", QWidget()),
    ])
    monkeypatch.setattr(main_window_module.MainWindow, "_build_hidden_sections", lambda self: [
        ("Incidents", QWidget()),
        ("IP Blocking", QWidget()),
        ("Settings", QWidget()),
    ])

    window = main_window_module.MainWindow()
    names = [window._nav.item(index).text() for index in range(window._nav.count())]

    assert names == ["Overview", "Alerts", "Live Logs", "ML Center"]
    assert "LLM" not in names
    assert "Management" not in names
    assert "Audit" not in names


def test_main_window_retranslate_updates_simplified_sidebar(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.main_window as main_window_module
    from PySide6.QtWidgets import QWidget

    monkeypatch.setattr(main_window_module, "RefreshController", _StubRefreshController)
    monkeypatch.setattr(main_window_module, "TrayManager", _StubTrayManager)
    monkeypatch.setattr(main_window_module.MainWindow, "_build_sections", lambda self: [
        ("Overview", QWidget()),
        ("Alerts", QWidget()),
        ("Live Logs", QWidget()),
        ("ML Center", QWidget()),
    ])
    monkeypatch.setattr(main_window_module.MainWindow, "_build_hidden_sections", lambda self: [("Settings", QWidget())])

    set_language("tr")
    window = main_window_module.MainWindow()
    names = [window._nav.item(index).text() for index in range(window._nav.count())]

    assert names == ["Genel Bakış", "Alarmlar", "Canlı Loglar", "ML Merkezi"]
    assert window._settings_button.text() == "Ayarlar"


def test_main_window_starts_background_polling_with_default_rule(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.main_window as main_window_module
    from PySide6.QtWidgets import QWidget

    monkeypatch.setattr(main_window_module, "RefreshController", _StubRefreshController)
    monkeypatch.setattr(main_window_module, "TrayManager", _StubTrayManager)
    monkeypatch.setattr(main_window_module.MainWindow, "_build_sections", lambda self: [
        ("Overview", QWidget()),
        ("Alerts", QWidget()),
        ("Live Logs", QWidget()),
        ("ML Center", QWidget()),
    ])
    monkeypatch.setattr(main_window_module.MainWindow, "_build_hidden_sections", lambda self: [("Settings", QWidget())])

    window = main_window_module.MainWindow()

    assert window._notification_controller.started is True


def test_main_window_close_event_minimizes_to_tray_when_available(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.main_window as main_window_module
    from PySide6.QtWidgets import QWidget

    monkeypatch.setattr(main_window_module, "RefreshController", _StubRefreshController)
    monkeypatch.setattr(main_window_module, "TrayManager", _StubTrayManager)
    monkeypatch.setattr(main_window_module.MainWindow, "_build_sections", lambda self: [("Overview", QWidget())])
    monkeypatch.setattr(main_window_module.MainWindow, "_build_hidden_sections", lambda self: [("Settings", QWidget())])

    class _Event:
        def __init__(self):
            self.ignored = False
            self.accepted = False

        def ignore(self):
            self.ignored = True

        def accept(self):
            self.accepted = True

    window = main_window_module.MainWindow()
    window._tray_manager.minimize_result = True
    event = _Event()

    window.closeEvent(event)

    assert event.ignored is True
    assert event.accepted is False


def test_main_window_quit_bypasses_minimize_to_tray(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.main_window as main_window_module
    from PySide6.QtWidgets import QWidget

    monkeypatch.setattr(main_window_module, "RefreshController", _StubRefreshController)
    monkeypatch.setattr(main_window_module, "TrayManager", _StubTrayManager)
    monkeypatch.setattr(main_window_module.MainWindow, "_build_sections", lambda self: [("Overview", QWidget())])
    monkeypatch.setattr(main_window_module.MainWindow, "_build_hidden_sections", lambda self: [("Settings", QWidget())])

    class _Event:
        def __init__(self):
            self.ignored = False
            self.accepted = False

        def ignore(self):
            self.ignored = True

        def accept(self):
            self.accepted = True

    window = main_window_module.MainWindow()
    window._tray_manager.minimize_result = True
    window._quit_from_tray()
    event = _Event()

    window.closeEvent(event)

    assert event.accepted is True
    assert event.ignored is False
    assert window._tray_manager.cleaned is True


def test_main_window_high_alert_shows_notification_and_click_opens_alerts(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.main_window as main_window_module
    from PySide6.QtWidgets import QWidget

    monkeypatch.setattr(main_window_module, "RefreshController", _StubRefreshController)
    monkeypatch.setattr(main_window_module, "TrayManager", _StubTrayManager)

    class _AlertsWidget(QWidget):
        def __init__(self):
            super().__init__()
            self.selected_alert = None

        def select_alert(self, alert_id):
            self.selected_alert = alert_id

    alerts_widget = _AlertsWidget()
    monkeypatch.setattr(main_window_module.MainWindow, "_build_sections", lambda self: [
        ("Overview", QWidget()),
        ("Alerts", alerts_widget),
        ("Live Logs", QWidget()),
        ("ML Center", QWidget()),
    ])
    monkeypatch.setattr(main_window_module.MainWindow, "_build_hidden_sections", lambda self: [("Settings", QWidget())])

    shown = {}

    def _show(tray_icon, payload, on_click=None):
        shown["payload"] = payload
        shown["on_click"] = on_click
        return {"status": "ok", "shown": True, "reason": ""}

    monkeypatch.setattr(main_window_module, "show_desktop_notification", _show)

    window = main_window_module.MainWindow()
    window._tray_manager.tray_icon = object()
    window._handle_notification_poll({"alerts": [{
        "id": 7,
        "severity": "critical",
        "rule_id": "RULE-7",
        "entity": "alice",
        "source_ip": "1.2.3.4",
        "message": "critical alert",
        "timestamp_text": "2026-05-19 12:00:00",
    }]})

    assert shown["payload"]["severity"] == "critical"
    shown["on_click"](7)
    assert alerts_widget.selected_alert == 7
    assert window._nav.currentItem().text() == "Alerts"


def test_main_window_low_alert_notification_suppressed(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.main_window as main_window_module
    from PySide6.QtWidgets import QWidget

    monkeypatch.setattr(main_window_module, "RefreshController", _StubRefreshController)
    monkeypatch.setattr(main_window_module, "TrayManager", _StubTrayManager)
    monkeypatch.setattr(main_window_module.MainWindow, "_build_sections", lambda self: [
        ("Overview", QWidget()),
        ("Alerts", QWidget()),
        ("Live Logs", QWidget()),
        ("ML Center", QWidget()),
    ])
    monkeypatch.setattr(main_window_module.MainWindow, "_build_hidden_sections", lambda self: [("Settings", QWidget())])

    shown = []
    monkeypatch.setattr(main_window_module, "show_desktop_notification", lambda *args, **kwargs: shown.append((args, kwargs)))

    window = main_window_module.MainWindow()
    window._tray_manager.tray_icon = object()
    window._handle_notification_poll({"alerts": [{
        "id": 8,
        "severity": "low",
        "rule_id": "RULE-8",
        "entity": "bob",
        "source_ip": "5.6.7.8",
        "message": "low alert",
        "timestamp_text": "2026-05-19 12:01:00",
    }]})

    assert shown == []


def test_main_window_pause_resume_notifications_controls_poller(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.main_window as main_window_module
    from PySide6.QtWidgets import QWidget

    monkeypatch.setattr(main_window_module, "RefreshController", _StubRefreshController)
    monkeypatch.setattr(main_window_module, "TrayManager", _StubTrayManager)
    monkeypatch.setattr(main_window_module.MainWindow, "_build_sections", lambda self: [("Overview", QWidget())])
    monkeypatch.setattr(main_window_module.MainWindow, "_build_hidden_sections", lambda self: [("Settings", QWidget())])

    window = main_window_module.MainWindow()

    window._set_notifications_enabled(False)
    assert window._notification_controller.stopped is True

    window._notification_controller.stopped = False
    window._set_notifications_enabled(True)
    assert window._notification_controller.resumed is True
