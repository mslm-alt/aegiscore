from __future__ import annotations

from typing import Callable

from ui.i18n import tr

try:
    from PySide6.QtGui import QAction, QIcon, QPixmap, QPainter, QColor
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QMenu, QSystemTrayIcon, QWidget
except ImportError:  # pragma: no cover - graceful import path
    QAction = None  # type: ignore[assignment]
    QIcon = None  # type: ignore[assignment]
    QPixmap = None  # type: ignore[assignment]
    QPainter = None  # type: ignore[assignment]
    QColor = None  # type: ignore[assignment]
    Qt = None  # type: ignore[assignment]
    QMenu = None  # type: ignore[assignment]
    QSystemTrayIcon = None  # type: ignore[assignment]
    QWidget = object  # type: ignore[assignment]


def _build_icon():
    if QPixmap is None or QPainter is None or QColor is None or QIcon is None or Qt is None:
        return None
    pixmap = QPixmap(32, 32)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setBrush(QColor("#1f6feb"))
    painter.setPen(QColor("#1f6feb"))
    painter.drawEllipse(2, 2, 28, 28)
    painter.setBrush(QColor("#f5f7fa"))
    painter.drawRect(13, 8, 6, 14)
    painter.drawEllipse(13, 23, 6, 6)
    painter.end()
    return QIcon(pixmap)


class TrayManager:
    def __init__(
        self,
        window: QWidget,
        show_window: Callable[[], None],
        open_alerts: Callable[[], None],
        toggle_notifications: Callable[[bool], None],
        quit_app: Callable[[], None],
    ):
        self._window = window
        self._show_window = show_window
        self._open_alerts = open_alerts
        self._toggle_notifications = toggle_notifications
        self._quit_app = quit_app
        self._tray = None
        self._menu = None
        self._show_action = None
        self._alerts_action = None
        self._pause_action = None
        self._quit_action = None
        self._notifications_paused = False
        self._first_minimize_notice_shown = False
        self._enabled = bool(QSystemTrayIcon is not None and QSystemTrayIcon.isSystemTrayAvailable())
        if self._enabled:
            self._init_tray()

    def _init_tray(self):
        self._tray = QSystemTrayIcon(_build_icon(), self._window)
        menu = QMenu(self._window)
        self._menu = menu
        self._show_action = QAction(tr("Show AegisCore"), menu)
        self._alerts_action = QAction(tr("Open Alerts"), menu)
        self._pause_action = QAction(tr("Pause Notifications"), menu)
        self._quit_action = QAction(tr("Quit"), menu)
        self._show_action.triggered.connect(self._show_window)
        self._alerts_action.triggered.connect(self._open_alerts)
        self._pause_action.triggered.connect(lambda *_args: self.toggle_notifications())
        self._quit_action.triggered.connect(self._quit_app)
        menu.addAction(self._show_action)
        menu.addAction(self._alerts_action)
        menu.addAction(self._pause_action)
        menu.addSeparator()
        menu.addAction(self._quit_action)
        self._tray.setContextMenu(menu)
        self.update_tooltip()
        self._tray.activated.connect(self._handle_activated)
        self._tray.show()

    def _handle_activated(self, reason):
        if QSystemTrayIcon is None:
            return
        if reason in {QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick}:
            self._show_window()

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def tray_icon(self):
        return self._tray

    def menu_action_texts(self) -> list[str]:
        actions = [self._show_action, self._alerts_action, self._pause_action, self._quit_action]
        return [str(action.text()) for action in actions if action is not None]

    def status(self) -> dict:
        return {
            "enabled": self._enabled,
            "paused": self._notifications_paused,
            "supported": bool(QSystemTrayIcon is not None),
        }

    def update_tooltip(
        self,
        app_name: str = "AegisCoreSIEM",
        backend_status: str = "Unknown",
        mode: str = "Read-only",
        ml_status: str = "No-action",
    ):
        if self._tray is None:
            return
        backend = str(backend_status or "Unknown").strip() or "Unknown"
        tooltip = "\n".join([
            str(app_name or "AegisCoreSIEM"),
            f"Backend: {backend}",
            f"Mode: {str(mode or 'Read-only')}",
            f"ML: {str(ml_status or 'No-action')}",
        ])
        self._tray.setToolTip(tooltip)

    def toggle_notifications(self):
        self._notifications_paused = not self._notifications_paused
        self._toggle_notifications(not self._notifications_paused)
        if self._enabled and getattr(self, "_pause_action", None) is not None:
            self._pause_action.setText(
                tr("Resume Notifications") if self._notifications_paused else tr("Pause Notifications")
            )

    def minimize_to_tray(self) -> bool:
        if not self._enabled:
            return False
        self._window.hide()
        if self._tray is not None and not self._first_minimize_notice_shown:
            self._tray.showMessage(
                "AegisCore",
                tr("AegisCore is still running in the background."),
                QSystemTrayIcon.MessageIcon.Information,
                5000,
            )
            self._first_minimize_notice_shown = True
        return True

    def show_message(self, title: str, message: str):
        if self._tray is not None:
            self._tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, 5000)

    def cleanup(self):
        if self._tray is not None:
            self._tray.hide()
            self._tray.setContextMenu(None)
            self._tray = None
        self._menu = None
        self._show_action = None
        self._alerts_action = None
        self._pause_action = None
        self._quit_action = None
