import importlib
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def test_preflight_window_apply_degraded_payload_smoke():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from ui.preflight import PreflightWindow

    app = QApplication.instance() or QApplication([])
    window = PreflightWindow(auto_load=False)
    window._apply_preflight({
        "overall": "BLOCKED",
        "checks": [{
            "name": "db",
            "status": "BLOCKED",
            "message": "degraded",
            "details": {"reason": "missing"},
            "suggestion": "inspect",
        }],
        "security_locks": {
            "read_only_mode": True,
            "auto_ip_block_disabled": True,
            "ml_no_action_contract": True,
            "manual_actions_locked": True,
        },
    })
    app.processEvents()

    assert window._overall_badge.text() == "BLOCKED"
    window.close()


def test_refresh_controller_safe_stop_idempotent():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication, QWidget
    from ui.workers import RefreshController

    app = QApplication.instance() or QApplication([])
    owner = QWidget()
    controller = RefreshController(owner, interval_ms=1000)
    controller.configure(task=lambda: {"ok": True}, on_result=lambda payload: None)
    controller.start()
    controller.safe_stop()
    controller.safe_stop()
    controller.dispose()
    controller.dispose()
    app.processEvents()

    assert controller.is_paused() is True
    owner.close()


def test_main_window_create_close_smoke():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    from ui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    app.processEvents()
    assert window.windowTitle() == "AegisCore"
    assert window.minimumSize().width() == 760
    assert window.minimumSize().height() == 560
    assert window.minimumSizeHint().width() == 760
    assert window.minimumSizeHint().height() == 560
    assert window.maximumSize().width() >= 16000
    assert window.maximumSize().height() >= 16000
    assert bool(window.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint) is True
    assert bool(window.windowFlags() & Qt.WindowType.WindowFullscreenButtonHint) is True
    assert window._overview_badge.text().startswith("● ")
    assert window._global_refresh.maximumHeight() <= 30
    assert len(window._header_badges) == 4

    initial_width = window.size().width()
    initial_height = window.size().height()
    window.resize(760, 560)
    app.processEvents()
    assert window.size().width() < initial_width
    assert window.size().height() < initial_height
    assert window.size().width() >= 760
    assert window.size().height() >= 560
    window.resize(1100, 780)
    app.processEvents()
    assert window.size().width() >= 1100
    assert window.size().height() >= 780
    window.resize(1400, 900)
    app.processEvents()
    assert window.size().width() >= 1400
    assert window.size().height() >= 900
    window.showMaximized()
    app.processEvents()
    assert window.isMaximized() is True
    window.showNormal()
    app.processEvents()
    assert window.isMaximized() is False
    assert window.size().width() >= 1400
    assert window.size().height() >= 900
    window.showFullScreen()
    app.processEvents()
    assert window.isFullScreen() is True
    window.showNormal()
    app.processEvents()
    assert window.isFullScreen() is False
    window.close()
    app.processEvents()


def test_main_window_section_hints_remain_responsive():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from ui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    app.processEvents()

    for name, widget in window._section_widgets.items():
        hint = widget.minimumSizeHint()
        assert hint.width() <= 800, name
        assert hint.height() <= 700, name
        assert widget.maximumSize().width() >= 16000, name
        assert widget.maximumSize().height() >= 16000, name

    window.close()
    app.processEvents()


def test_main_window_resizes_cleanly_across_requested_desktop_sizes():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from ui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    app.processEvents()

    for width, height in ((1280, 720), (1366, 768), (1600, 900)):
        window.resize(width, height)
        app.processEvents()
        assert window.size().width() >= width
        assert window.size().height() >= height
        assert window._global_refresh.isVisible() is True
        assert window._nav.isVisible() is True
        assert window._stack.isVisible() is True

    window.showMaximized()
    app.processEvents()
    assert window.isMaximized() is True
    window.close()
    app.processEvents()


def test_ml_center_view_remains_visible_after_requested_resizes():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from ui.views.ml_center_compact import MLCenterView

    app = QApplication.instance() or QApplication([])
    ml_view = MLCenterView()

    ml_view.show()
    app.processEvents()
    for width, height in ((1280, 720), (1366, 768), (1600, 900)):
        ml_view.resize(width, height)
        app.processEvents()
        assert ml_view.isVisible() is True

    assert not hasattr(ml_view, "_train_now_button")
    assert not hasattr(ml_view, "_historical_scan_button")
    assert ml_view._family_table.isVisible() is True
    assert ml_view._alerts_table.isVisible() is True

    ml_view.close()
    app.processEvents()
