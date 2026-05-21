from __future__ import annotations

from PySide6.QtCore import QSize
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ui import backend_facade
from ui.i18n import current_language, language_display_name, set_language, tr
from ui.models import NotificationRule, theme_option_specs
from ui.theme import apply_app_theme, badge_style
from ui.workers import RefreshController


class SettingsView(QWidget):
    def __init__(
        self,
        config_path: str | None = None,
        notification_rule: NotificationRule | None = None,
        notification_rule_changed=None,
        language_changed=None,
        *,
        embedded: bool = False,
        allowed_tabs=None,
        title_override: str | None = None,
    ):
        super().__init__()
        self._config_path = config_path
        self._notification_rule = notification_rule or NotificationRule()
        self._notification_rule_changed = notification_rule_changed
        self._language_changed = language_changed
        self._title_override = str(title_override or "Settings")
        self._embedded = bool(embedded)
        self._settings_controller = RefreshController(self)
        self._current_theme = "dark"
        self._settings_payload: dict = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title_row = QHBoxLayout()
        self._title = QLabel(tr(self._title_override))
        self._title.setObjectName("pageTitle")
        self._status_label = QLabel(tr("Ready"))
        self._status_label.setObjectName("badge")
        self._status_label.setStyleSheet(badge_style("read_only"))
        self._refresh = QPushButton(tr("Refresh"))
        self._refresh.clicked.connect(self.refresh_all)
        title_row.addWidget(self._title)
        title_row.addStretch(1)
        title_row.addWidget(self._status_label)
        title_row.addWidget(self._refresh)
        if not self._embedded:
            layout.addLayout(title_row)

        self._appearance_card = self._build_appearance_card()
        self._integrations_card = self._build_integrations_card()
        self._safety_card = self._build_safety_card()
        layout.addWidget(self._appearance_card)
        layout.addWidget(self._integrations_card)
        layout.addWidget(self._safety_card)
        layout.addStretch(1)

        self.refresh_all()

    def minimumSizeHint(self):
        return QSize(720, 520)

    def _build_appearance_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("card")
        layout = QGridLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setHorizontalSpacing(12)
        layout.setVerticalSpacing(8)

        self._appearance_title = QLabel(tr("Appearance"))
        self._appearance_title.setObjectName("sectionTitle")
        self._theme_combo = QComboBox()
        for spec in theme_option_specs():
            self._theme_combo.addItem(spec["label"], spec["id"])
        self._theme_combo.currentIndexChanged.connect(self._apply_theme_preview)
        self._theme_status = QLabel("")
        self._theme_status.setWordWrap(True)
        self._theme_status.setObjectName("mutedText")

        self._language_selector = QComboBox()
        self._language_selector.addItem("English", "en")
        self._language_selector.addItem("Türkçe", "tr")
        self._language_selector.currentIndexChanged.connect(self._apply_language_selection)
        self._language_note = QLabel("")
        self._language_note.setObjectName("mutedText")
        self._language_note.setWordWrap(True)
        self._theme_label = QLabel(tr("Theme"))
        self._language_label = QLabel(tr("Language"))

        layout.addWidget(self._appearance_title, 0, 0, 1, 3)
        layout.addWidget(self._theme_label, 1, 0)
        layout.addWidget(self._theme_combo, 1, 1, 1, 2)
        layout.addWidget(self._theme_status, 2, 0, 1, 3)
        layout.addWidget(self._language_label, 3, 0)
        layout.addWidget(self._language_selector, 3, 1)
        layout.addWidget(self._language_note, 3, 2)
        return card

    def _build_integrations_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self._integrations_title = QLabel(tr("Integrations"))
        self._integrations_title.setObjectName("sectionTitle")
        self._integrations_note = QLabel(tr("Integration secrets stay file-based. This screen only shows safe status summaries."))
        self._integrations_note.setObjectName("mutedText")
        self._integrations_note.setWordWrap(True)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)
        self._integration_values: dict[str, QLabel] = {}
        self._integration_labels: dict[str, QLabel] = {}
        labels = (
            "LLM Provider",
            "LLM Model",
            "LLM API Key",
            "Telegram",
            "Email",
        )
        for row, label in enumerate(labels):
            title = QLabel(tr(label))
            grid.addWidget(title, row, 0)
            value = QLabel("-")
            value.setWordWrap(True)
            grid.addWidget(value, row, 1)
            self._integration_labels[label] = title
            self._integration_values[label] = value

        layout.addWidget(self._integrations_title)
        layout.addWidget(self._integrations_note)
        layout.addLayout(grid)
        return card

    def _build_safety_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self._safety_title = QLabel(tr("Safety"))
        self._safety_title.setObjectName("sectionTitle")
        self._safety_note = QLabel(tr("Sensitive operations remain read-only or manual-only in the desktop UI."))
        self._safety_note.setObjectName("mutedText")
        self._safety_note.setWordWrap(True)

        self._safety_items: list[QLabel] = []
        for _ in range(4):
            item = QLabel("-")
            item.setWordWrap(True)
            self._safety_items.append(item)

        layout.addWidget(self._safety_title)
        layout.addWidget(self._safety_note)
        for item in self._safety_items:
            layout.addWidget(item)
        return card

    def refresh_all(self):
        self._refresh.setEnabled(False)
        self._status_label.setText(tr("Loading..."))
        self._settings_controller.trigger(
            task=lambda: backend_facade.collect_settings_status(config_path=self._config_path),
            on_result=self._apply_settings_payload,
            on_error=lambda error: self._status_label.setText(error.get("message", "settings error")),
            on_finished=lambda: self._refresh.setEnabled(True),
        )

    def _apply_settings_payload(self, payload: dict):
        self._settings_payload = dict(payload or {})
        status = str(payload.get("status", "unknown") or "unknown").lower()
        self._status_label.setText(status.upper())
        self._status_label.setStyleSheet(badge_style("ok" if status == "ok" else "degraded"))

        theme_payload = dict(payload.get("theme", {}) or {})
        current_theme = str(theme_payload.get("current", "dark") or "dark")
        self._current_theme = current_theme
        for index in range(self._theme_combo.count()):
            if self._theme_combo.itemData(index) == current_theme:
                self._theme_combo.blockSignals(True)
                self._theme_combo.setCurrentIndex(index)
                self._theme_combo.blockSignals(False)
                break

        llm_payload = dict(payload.get("llm", {}) or {})
        integrations_payload = dict(payload.get("integrations", {}) or {})
        security_payload = dict(payload.get("security_locks", {}) or {})

        self._theme_status.setText(f"{tr('Current Theme')}: {current_theme}")
        self._language_note.setText(language_display_name(current_language()))
        self._sync_language_selector()

        self._integration_values["LLM Provider"].setText(str(llm_payload.get("backend", "") or "mock"))
        self._integration_values["LLM Model"].setText(str(llm_payload.get("model", "") or tr("Not configured")))
        self._integration_values["LLM API Key"].setText(
            tr("Configured") if llm_payload.get("api_key_configured") else tr("Missing")
        )
        self._integration_values["Telegram"].setText(
            tr("Configured") if integrations_payload.get("telegram_configured") else tr("Not configured")
        )
        self._integration_values["Email"].setText(
            tr("Configured") if integrations_payload.get("email_configured") else tr("Not configured")
        )

        safety_lines = [
            tr("Configuration changes stay file-based and locked in the desktop UI.")
            if security_payload.get("config_write_locked", True)
            else tr("Configuration editing is available outside the desktop UI."),
            tr("Firewall actions stay manual-only and require explicit confirmation.")
            if security_payload.get("firewall_actions_locked", True)
            else tr("Firewall actions are available with explicit confirmation."),
            tr("IP blocking remains manual-only from the UI.")
            if security_payload.get("manual_actions_locked", True)
            else tr("Some manual security actions are available from the UI."),
            tr("Automatic blocking is disabled.")
            if security_payload.get("auto_ip_block_disabled", True)
            else tr("Automatic blocking is enabled."),
        ]
        for label, text in zip(self._safety_items, safety_lines):
            label.setText(text)

    def _apply_theme_preview(self):
        theme_id = str(self._theme_combo.currentData() or "dark")
        self._current_theme = theme_id
        apply_app_theme(theme_id)
        self._theme_status.setText(f"{tr('Current Theme')}: {theme_id}")

    def _apply_language_selection(self):
        language = str(self._language_selector.currentData() or current_language())
        set_language(language)
        self._language_note.setText(language_display_name(language))
        if callable(self._language_changed):
            self._language_changed()

    def _sync_language_selector(self):
        current = current_language()
        for index in range(self._language_selector.count()):
            if self._language_selector.itemData(index) == current:
                self._language_selector.blockSignals(True)
                self._language_selector.setCurrentIndex(index)
                self._language_selector.blockSignals(False)
                return

    def retranslate_ui(self):
        self._title.setText(tr(self._title_override))
        self._refresh.setText(tr("Refresh"))
        self._appearance_title.setText(tr("Appearance"))
        self._theme_label.setText(tr("Theme"))
        self._language_label.setText(tr("Language"))
        self._integrations_title.setText(tr("Integrations"))
        self._integrations_note.setText(tr("Integration secrets stay file-based. This screen only shows safe status summaries."))
        for key, label in self._integration_labels.items():
            label.setText(tr(key))
        self._safety_title.setText(tr("Safety"))
        self._safety_note.setText(tr("Sensitive operations remain read-only or manual-only in the desktop UI."))
        self._theme_status.setText(f"{tr('Current Theme')}: {self._current_theme}")
        if self._settings_payload:
            self._apply_settings_payload(self._settings_payload)
