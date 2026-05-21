from __future__ import annotations

from PySide6.QtGui import QCloseEvent
from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ui import backend_facade
from ui.i18n import tr
from ui.models import NotificationRule
from ui.notifications import NotificationDeduper, build_alert_notification_payload, show_desktop_notification
from ui.theme import status_color
from ui.tray import TrayManager
from ui.views import AlertsView, IPReputationView, IncidentsView, LiveLogsView, MLCenterView, OverviewView, SettingsView
from ui.workers import RefreshController


class MainWindow(QMainWindow):
    def __init__(
        self,
        overview_status: dict | None = None,
        security_locks: dict | None = None,
        config_path: str | None = None,
    ):
        super().__init__()
        self._overview_status = dict(overview_status or {})
        self._security_locks = dict(security_locks or {})
        self._config_path = config_path
        self._section_names: list[str] = []
        self._section_widgets: dict[str, QWidget] = {}
        self._stack_widget_names: dict[int, str] = {}
        self._nav_items: dict[str, QListWidgetItem] = {}
        self._header_badges: list[tuple[QLabel, str, str]] = []
        self._notification_rule = NotificationRule()
        self._notification_deduper = NotificationDeduper(rule=self._notification_rule)
        self._notification_controller = RefreshController(self, interval_ms=15000)
        self._quit_requested = False
        self._cleanup_completed = False

        self.setWindowTitle("AegisCore")
        self.setMinimumSize(760, 560)
        self.resize(1280, 820)

        root = QWidget()
        root.setObjectName("appRoot")
        root.setMinimumSize(0, 0)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(10)

        header_card = QFrame()
        header_card.setObjectName("headerCard")
        header_layout = QHBoxLayout(header_card)
        header_layout.setContentsMargins(12, 6, 12, 6)
        header_layout.setSpacing(10)

        brand_layout = QVBoxLayout()
        brand_layout.setSpacing(0)
        brand = QLabel("AegisCore")
        brand.setObjectName("brand")
        brand_layout.addWidget(brand)
        header_layout.addLayout(brand_layout)
        header_layout.addStretch(1)
        self._overview_badge = self._make_header_indicator(self._header_status_text(), self._header_status_kind())
        self._overview_badge.setToolTip(tr("Status"))
        self._global_refresh = QPushButton(tr("Refresh"))
        self._global_refresh.setMaximumHeight(30)
        self._global_refresh.clicked.connect(self._refresh_active_view)
        header_layout.addWidget(self._overview_badge)
        for text, style in self._badge_specs():
            badge = self._make_header_indicator(text, style)
            self._header_badges.append((badge, text, style))
            header_layout.addWidget(badge)
        header_layout.addWidget(self._global_refresh)

        split = QSplitter()
        split.setChildrenCollapsible(False)
        split.setMinimumSize(0, 0)
        split.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        sidebar = QFrame()
        sidebar.setObjectName("sidebarFrame")
        sidebar.setMinimumWidth(0)
        sidebar.setMaximumWidth(320)
        sidebar.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(10, 10, 10, 10)
        sidebar_layout.setSpacing(8)
        self._sidebar_title = QLabel(tr("Navigation"))
        self._sidebar_title.setObjectName("sectionTitle")
        self._sidebar_subtitle = QLabel(tr("Read-only security views"))
        self._sidebar_subtitle.setObjectName("mutedText")
        self._nav = QListWidget()
        self._nav.setObjectName("sidebar")
        self._nav.setMinimumWidth(0)
        self._settings_button = QPushButton(tr("Settings"))
        self._settings_button.setObjectName("sidebarSettingsButton")
        self._settings_button.clicked.connect(self._open_settings_view)
        sidebar_layout.addWidget(self._sidebar_title)
        sidebar_layout.addWidget(self._sidebar_subtitle)
        sidebar_layout.addWidget(self._nav, 1)
        sidebar_layout.addWidget(self._settings_button, 0, Qt.AlignmentFlag.AlignBottom)
        self._stack = QStackedWidget()
        self._stack.setMinimumSize(0, 0)
        self._stack.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        sections = self._build_sections()
        for section, widget in sections:
            widget.setMinimumSize(0, 0)
            widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            self._section_names.append(section)
            self._section_widgets[section] = widget
            self._stack_widget_names[id(widget)] = section
            item = QListWidgetItem(tr(section))
            self._nav_items[section] = item
            self._nav.addItem(item)
            self._stack.addWidget(widget)
        for section, widget in self._build_hidden_sections():
            widget.setMinimumSize(0, 0)
            widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            self._section_widgets[section] = widget
            self._stack_widget_names[id(widget)] = section
            self._stack.addWidget(widget)
        self._nav.currentRowChanged.connect(self._stack.setCurrentIndex)
        self._nav.currentRowChanged.connect(self._handle_nav_row_changed)
        self._nav.setCurrentRow(0)
        self._sync_global_refresh_state()

        split.addWidget(sidebar)
        split.addWidget(self._stack)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setSizes([250, 970])

        root_layout.addWidget(header_card, 0)
        root_layout.addWidget(split, 1)

        self.setCentralWidget(root)
        self.retranslate_ui()
        self._tray_manager = TrayManager(
            window=self,
            show_window=self._show_from_tray,
            open_alerts=self._open_alerts_view,
            toggle_notifications=self._set_notifications_enabled,
            quit_app=self._quit_from_tray,
        )
        self._update_tray_status()
        self._notification_controller.configure(
            task=lambda: backend_facade.collect_alerts(limit=25, config_path=self._config_path),
            on_result=self._handle_notification_poll,
            on_error=lambda error: None,
        )
        if self._notification_rule.background_notifications:
            self._notification_controller.start()

    def minimumSizeHint(self) -> QSize:
        return QSize(self.minimumSize().width(), self.minimumSize().height())

    def _dispose_runtime_controllers(self):
        if hasattr(self._notification_controller, "dispose"):
            self._notification_controller.dispose()
        else:
            self._notification_controller.stop()
        for widget in self._section_widgets.values():
            for value in vars(widget).values():
                if isinstance(value, RefreshController):
                    if hasattr(value, "dispose"):
                        value.dispose()
                    else:
                        value.stop()

    def _finalize_shutdown(self):
        if self._cleanup_completed:
            return
        self._cleanup_completed = True
        self._dispose_runtime_controllers()
        self._tray_manager.cleanup()

    def _build_sections(self):
        return [
            ("Overview", OverviewView(config_path=self._config_path)),
            ("Alerts", AlertsView(
                config_path=self._config_path,
                open_ip_context=self._open_ip_blocking_context,
                open_manual_ip_action=self._prepare_manual_ip_action,
                open_incident=self._open_incident_context,
            )),
            ("Live Logs", LiveLogsView(config_path=self._config_path)),
            ("ML Center", MLCenterView(config_path=self._config_path)),
        ]

    def _build_hidden_sections(self):
        return [
            ("Incidents", IncidentsView(config_path=self._config_path)),
            ("IP Blocking", IPReputationView(config_path=self._config_path)),
            ("Settings", SettingsView(
                config_path=self._config_path,
                notification_rule=self._notification_rule,
                notification_rule_changed=self._update_notification_rule,
                language_changed=self.retranslate_ui,
            )),
        ]

    def _active_section_name(self) -> str:
        widget = self._stack.currentWidget()
        if widget is None:
            return ""
        return self._stack_widget_names.get(id(widget), "")

    def _active_section_widget(self):
        return self._section_widgets.get(self._active_section_name())

    @staticmethod
    def _refresh_entrypoint(widget):
        for attr in ("refresh_all", "refresh"):
            callback = getattr(widget, attr, None)
            if callable(callback):
                return callback, attr
        return None, ""

    def _sync_global_refresh_state(self, *_args):
        callback, _attr = self._refresh_entrypoint(self._active_section_widget())
        enabled = callback is not None
        self._global_refresh.setEnabled(enabled)
        section = tr(self._active_section_name() or "active view")
        self._global_refresh.setToolTip(f"{tr('Refresh')} {section}" if enabled else tr("Active view does not support refresh"))

    def _handle_nav_row_changed(self, row: int):
        self._settings_button.setProperty("active", False)
        self._settings_button.style().unpolish(self._settings_button)
        self._settings_button.style().polish(self._settings_button)
        self._sync_global_refresh_state(row)

    def _refresh_active_view(self):
        callback, _attr = self._refresh_entrypoint(self._active_section_widget())
        if callback is None:
            return
        callback()

    def _update_notification_rule(self, rule: NotificationRule):
        self._notification_rule = rule
        self._notification_deduper.rule = rule
        if rule.enabled and rule.background_notifications:
            self._notification_controller.resume()
        elif not rule.background_notifications:
            self._notification_controller.stop()

    def _set_notifications_enabled(self, enabled: bool):
        self._notification_rule.enabled = bool(enabled)
        if enabled and self._notification_rule.background_notifications:
            self._notification_controller.resume()
        else:
            self._notification_controller.stop()

    def _update_tray_status(self):
        overall = str(self._overview_status.get("overall", "") or "").strip().upper()
        backend_status = "Unknown"
        if overall == "PASS":
            backend_status = "OK"
        elif overall in {"WARNING", "BLOCKED", "DEGRADED", "FAIL"}:
            backend_status = "Degraded"
        update_tooltip = getattr(self._tray_manager, "update_tooltip", None)
        if not callable(update_tooltip):
            return
        update_tooltip(
            app_name="AegisCoreSIEM",
            backend_status=backend_status,
            mode="Read-only",
            ml_status="No-action",
        )

    def _handle_notification_poll(self, payload: dict):
        alerts = list(payload.get("alerts", []) or [])
        for alert in alerts:
            if not self._notification_deduper.should_notify(alert):
                continue
            notification_payload = build_alert_notification_payload(alert)
            if self._notification_rule.tray_enabled:
                show_desktop_notification(
                    self._tray_manager.tray_icon,
                    notification_payload,
                    on_click=self._open_alert_from_notification,
                )
            self._notification_deduper.mark_notified(alert)
            break

    def _show_from_tray(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _open_alerts_view(self):
        try:
            index = self._section_names.index("Alerts")
        except ValueError:
            return
        self._nav.setCurrentRow(index)
        self._show_from_tray()

    def _open_alert_from_notification(self, alert_id: int | None):
        self._open_alerts_view()
        if alert_id in (None, ""):
            return
        widget = self._section_widgets.get("Alerts")
        if widget is not None and hasattr(widget, "select_alert"):
            widget.select_alert(int(alert_id))

    def _quit_from_tray(self):
        self._quit_requested = True
        self.close()

    def _open_settings_view(self):
        widget = self._section_widgets.get("Settings")
        if widget is None:
            return
        self._stack.setCurrentWidget(widget)
        self._nav.blockSignals(True)
        self._nav.clearSelection()
        self._nav.setCurrentRow(-1)
        self._nav.blockSignals(False)
        self._settings_button.setProperty("active", True)
        self._settings_button.style().unpolish(self._settings_button)
        self._settings_button.style().polish(self._settings_button)
        self._sync_global_refresh_state()

    def _open_ip_blocking_context(self, ip: str):
        widget = self._section_widgets.get("IP Blocking")
        if widget is not None:
            self._stack.setCurrentWidget(widget)
        if widget is not None and hasattr(widget, "load_ip_context"):
            widget.load_ip_context(ip)

    def _prepare_manual_ip_action(self, ip: str, action: str = "block"):
        widget = self._section_widgets.get("IP Blocking")
        if widget is not None:
            self._stack.setCurrentWidget(widget)
        if widget is not None and hasattr(widget, "prepare_manual_action"):
            widget.prepare_manual_action(ip, action=action)

    def _open_incident_context(self, incident_id: int, action: str = "resolve"):
        widget = self._section_widgets.get("Incidents")
        if widget is not None:
            self._stack.setCurrentWidget(widget)
        if widget is not None and hasattr(widget, "select_incident"):
            widget.select_incident(incident_id)

    def _build_placeholder_page(self, name: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title = QLabel(name)
        title.setObjectName("pageTitle")

        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 18, 18, 18)
        card_layout.setSpacing(8)
        card_layout.addWidget(QLabel(f"{name} {tr('coming soon')}"))
        card_layout.addWidget(QLabel(tr("Preview is read-only. Secrets are redacted before display.")))

        layout.addWidget(title)
        layout.addWidget(card)
        layout.addStretch(1)
        return page

    def _badge_specs(self):
        return [
            ("Read-only", "read_only"),
            ("Auto block off", "warning"),
            ("ML no-action", "ok"),
            ("Manual lock", "locked"),
        ]

    def retranslate_ui(self):
        self._set_indicator_text(self._overview_badge, self._header_status_text(), self._header_status_kind())
        self._global_refresh.setText(tr("Refresh"))
        self._sidebar_title.setText(tr("Navigation"))
        self._sidebar_subtitle.setText(tr("Read-only security views"))
        self._settings_button.setText(tr("Settings"))
        for section, item in self._nav_items.items():
            item.setText(tr(section))
        for label, source_text, _kind in self._header_badges:
            self._set_indicator_text(label, tr(source_text), _kind)
        for widget in self._section_widgets.values():
            callback = getattr(widget, "retranslate_ui", None)
            if callable(callback):
                callback()
        self._sync_global_refresh_state()

    def _header_status_text(self) -> str:
        overall = str(self._overview_status.get("overall", "") or "").upper()
        if overall == "PASS":
            return tr("System OK")
        if overall in {"BLOCKED", "DEGRADED", "FAIL"}:
            return tr("Degraded")
        if overall == "WARNING":
            return tr("Warning")
        return tr("Unknown")

    def _header_status_kind(self) -> str:
        overall = str(self._overview_status.get("overall", "") or "").upper()
        if overall == "PASS":
            return "ok"
        if overall in {"BLOCKED", "DEGRADED", "FAIL"}:
            return "degraded"
        if overall == "WARNING":
            return "warning"
        return "locked"

    def _make_header_indicator(self, text: str, kind: str) -> QLabel:
        label = QLabel()
        label.setObjectName("mutedText")
        self._set_indicator_text(label, text, kind)
        return label

    def _set_indicator_text(self, label: QLabel, text: str, kind: str) -> None:
        label.setText(f"● {text}")
        label.setStyleSheet(
            f"color: {status_color(kind)}; font-weight: 700; padding: 1px 0px;"
        )

    def closeEvent(self, event: QCloseEvent):
        if not self._quit_requested and self._tray_manager.minimize_to_tray():
            event.ignore()
            return
        self._finalize_shutdown()
        event.accept()
