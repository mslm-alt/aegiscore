import importlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def test_ui_package_imports_without_pyside():
    import ui
    import ui.app
    import ui.backend_facade
    import ui.theme
    import ui.components

    assert ui is not None


def test_ui_app_handles_missing_pyside_gracefully(monkeypatch, capsys):
    ui_app = importlib.import_module("ui.app")

    monkeypatch.setattr(ui_app, "_import_qt", lambda: (None, ImportError("missing")))
    code = ui_app.main([])

    captured = capsys.readouterr()
    assert code == 2
    assert "PySide6 bulunamadı" in captured.err


def test_qt_modules_import_when_pyside_available():
    pytest.importorskip("PySide6")
    import ui.main_window
    import ui.notifications
    import ui.preflight
    import ui.tray
    import ui.theme
    import ui.components
    import ui.views.alerts
    import ui.views.diagnostics
    import ui.views.investigation
    import ui.views.ip_reputation
    import ui.views.live_logs
    import ui.views.ml_center_compact
    import ui.views.overview
    import ui.views.reports
    import ui.views.settings_compact
    import ui.views.sources
    import ui.workers

    assert ui.main_window is not None


def test_search_view_removed():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("ui.views.search")


def test_diagnostics_view_not_exported_on_public_views_package():
    import ui.views as views

    assert hasattr(views, "DiagnosticsView") is False


def test_standalone_llm_center_ui_not_present():
    assert Path("ui/views/llm_center.py").exists() is False
    assert "LLM Center" not in Path("ui/main_window.py").read_text(encoding="utf-8")


def test_qt_message_filter_suppresses_only_known_benign_warning(capsys):
    ui_app = importlib.import_module("ui.app")

    class _QtMsgType:
        QtWarningMsg = 1
        QtCriticalMsg = 2

    installed = {}

    def _install(handler):
        installed["handler"] = handler

    ui_app._install_qt_message_filter(_QtMsgType, _install)
    installed["handler"](_QtMsgType.QtWarningMsg, None, "This plugin does not support propagateSizeHints()")

    captured = capsys.readouterr()
    assert captured.err == ""


def test_qt_message_filter_keeps_non_benign_messages_visible(capsys):
    ui_app = importlib.import_module("ui.app")

    class _QtMsgType:
        QtWarningMsg = 1
        QtCriticalMsg = 2

    installed = {}

    def _install(handler):
        installed["handler"] = handler

    ui_app._install_qt_message_filter(_QtMsgType, _install)
    installed["handler"](_QtMsgType.QtWarningMsg, None, "QSystemTrayIcon::setVisible: No Icon set")
    installed["handler"](_QtMsgType.QtCriticalMsg, None, "real critical startup issue")

    captured = capsys.readouterr()
    assert "QSystemTrayIcon::setVisible: No Icon set" in captured.err
    assert "real critical startup issue" in captured.err
