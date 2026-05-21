from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QPlainTextEdit,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ui import backend_facade
from ui.components import configure_table, set_table_empty_message
from ui.i18n import tr
from ui.theme import badge_style
from ui.workers import RefreshController


class IncidentsView(QWidget):
    _COLUMNS = ["id", "created/time", "severity", "status", "title", "entity", "alert_count", "risk_score"]

    def __init__(self, config_path: str | None = None):
        super().__init__()
        self._config_path = config_path
        self._list_controller = RefreshController(self, interval_ms=15000)
        self._detail_controller = RefreshController(self)
        self._preview_controller = RefreshController(self)
        self._execute_controller = RefreshController(self)
        self._incidents: list[dict] = []
        self._preview_ready = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        controls = QHBoxLayout()
        self._title = QLabel(tr("Incidents"))
        self._title.setObjectName("pageTitle")
        self._status_filter = QComboBox()
        self._status_filter.addItems(["open", "all", "resolved", "closed", "active", "investigating"])
        self._status_filter.currentIndexChanged.connect(self.refresh)
        self._severity_filter = QComboBox()
        self._severity_filter.addItems(["all", "critical", "high", "medium", "low", "info"])
        self._severity_filter.currentIndexChanged.connect(self.refresh)
        self._limit = QComboBox()
        self._limit.addItems(["25", "50", "100", "200"])
        self._limit.setCurrentText("100")
        self._limit.currentIndexChanged.connect(self.refresh)
        self._status = QLabel(tr("Ready"))
        self._status.setObjectName("badge")
        self._status.setStyleSheet(badge_style("read_only"))
        self._refresh = QPushButton(tr("Refresh"))
        self._refresh.clicked.connect(self.refresh)
        controls.addWidget(self._title)
        controls.addStretch(1)
        self._status_filter_label = QLabel(tr("Status"))
        controls.addWidget(self._status_filter_label)
        controls.addWidget(self._status_filter)
        self._severity_filter_label = QLabel(tr("Severity"))
        controls.addWidget(self._severity_filter_label)
        controls.addWidget(self._severity_filter)
        self._limit_label = QLabel(tr("Limit"))
        controls.addWidget(self._limit_label)
        controls.addWidget(self._limit)
        controls.addWidget(self._status)
        controls.addWidget(self._refresh)

        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)

        self._table = QTableWidget(0, len(self._COLUMNS))
        self._table.setHorizontalHeaderLabels(self._COLUMNS)
        configure_table(self._table)
        set_table_empty_message(self._table, tr("No incidents match the current filters."))
        self._table.itemSelectionChanged.connect(self._load_selected_detail)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(12)

        detail_card = QFrame()
        detail_card.setObjectName("card")
        detail_layout = QVBoxLayout(detail_card)
        detail_layout.setContentsMargins(16, 16, 16, 16)
        detail_layout.setSpacing(10)
        self._detail_title = QLabel(tr("Incident detail"))
        self._detail_title.setObjectName("sectionTitle")
        self._detail_summary = QLabel(tr("Select an incident."))
        self._detail_summary.setWordWrap(True)
        self._detail_text = self._build_text_box(tr("Incident summary appears here."))
        self._evidence_text = self._build_text_box(tr("Evidence appears here."))
        self._related_alerts_text = self._build_text_box(tr("Related alerts appear here."))
        detail_layout.addWidget(self._detail_title)
        detail_layout.addWidget(self._detail_summary)
        self._summary_label = QLabel(tr("Summary"))
        detail_layout.addWidget(self._summary_label)
        detail_layout.addWidget(self._detail_text, 1)
        self._evidence_label = QLabel(tr("Evidence"))
        detail_layout.addWidget(self._evidence_label)
        detail_layout.addWidget(self._evidence_text, 1)
        self._related_alerts_label = QLabel(tr("Related Alerts"))
        detail_layout.addWidget(self._related_alerts_label)
        detail_layout.addWidget(self._related_alerts_text, 1)

        action_card = QFrame()
        action_card.setObjectName("card")
        action_layout = QGridLayout(action_card)
        action_layout.setContentsMargins(16, 16, 16, 16)
        action_layout.setHorizontalSpacing(10)
        action_layout.setVerticalSpacing(8)

        self._action = QComboBox()
        self._action.addItems(["resolve", "close"])
        self._action.currentIndexChanged.connect(self._invalidate_preview)
        self._incident_id = QLineEdit()
        self._incident_id.setPlaceholderText(tr("Incident ID"))
        self._incident_id.textChanged.connect(self._invalidate_preview)
        self._actor = QLineEdit("local-user")
        self._actor.textChanged.connect(self._invalidate_preview)
        self._role = QComboBox()
        self._role.addItems(["viewer", "operator", "admin"])
        self._role.setCurrentText("admin")
        self._role.currentIndexChanged.connect(self._invalidate_preview)
        self._reason = QLineEdit()
        self._reason.setPlaceholderText(tr("Reason"))
        self._reason.textChanged.connect(self._invalidate_preview)
        self._confirmation_phrase = QLineEdit()
        self._confirmation_phrase.setReadOnly(True)
        self._confirmation = QLineEdit()
        self._confirmation.setPlaceholderText(tr("Type required confirmation"))
        self._preview_status = QLabel(tr("Preview required before execution."))
        self._preview_status.setWordWrap(True)
        self._preview_button = QPushButton(tr("Dry-run Preview"))
        self._preview_button.clicked.connect(self._run_preview)
        self._execute_button = QPushButton(tr("Execute"))
        self._execute_button.setEnabled(False)
        self._execute_button.clicked.connect(self._execute_action)
        self._result_text = self._build_text_box(tr("Guard preview and execution results appear here."))

        self._action_label = QLabel(tr("Action"))
        action_layout.addWidget(self._action_label, 0, 0)
        action_layout.addWidget(self._action, 0, 1)
        self._incident_id_label = QLabel(tr("Incident ID"))
        action_layout.addWidget(self._incident_id_label, 0, 2)
        action_layout.addWidget(self._incident_id, 0, 3)
        self._actor_label = QLabel(tr("Actor"))
        action_layout.addWidget(self._actor_label, 1, 0)
        action_layout.addWidget(self._actor, 1, 1)
        self._role_label = QLabel(tr("Role"))
        action_layout.addWidget(self._role_label, 1, 2)
        action_layout.addWidget(self._role, 1, 3)
        self._reason_label = QLabel(tr("Reason"))
        action_layout.addWidget(self._reason_label, 2, 0)
        action_layout.addWidget(self._reason, 2, 1, 1, 3)
        self._required_confirmation_label = QLabel(tr("Required Confirmation"))
        action_layout.addWidget(self._required_confirmation_label, 3, 0)
        action_layout.addWidget(self._confirmation_phrase, 3, 1, 1, 3)
        self._typed_confirmation_label = QLabel(tr("Typed Confirmation"))
        action_layout.addWidget(self._typed_confirmation_label, 4, 0)
        action_layout.addWidget(self._confirmation, 4, 1, 1, 3)
        action_layout.addWidget(self._preview_button, 5, 0, 1, 2)
        action_layout.addWidget(self._execute_button, 5, 2, 1, 2)
        action_layout.addWidget(self._preview_status, 6, 0, 1, 4)
        action_layout.addWidget(self._result_text, 7, 0, 1, 4)

        right_layout.addWidget(detail_card, 2)
        right_layout.addWidget(action_card, 1)
        right_scroll = QScrollArea()
        right_scroll.setWidgetResizable(True)
        right_scroll.setWidget(right)
        split.addWidget(self._table)
        split.addWidget(right_scroll)
        split.setSizes([720, 560])

        layout.addLayout(controls)
        layout.addWidget(split, 1)

        self._list_controller.configure(
            task=lambda: backend_facade.collect_incidents(
                status=None if self._status_filter.currentText() == "all" else self._status_filter.currentText(),
                severity=None if self._severity_filter.currentText() == "all" else self._severity_filter.currentText(),
                limit=int(self._limit.currentText()),
                config_path=self._config_path,
            ),
            on_result=self._apply_incidents_payload,
            on_error=lambda error: self._status.setText(error.get("message", "incident error")),
        )
        self.refresh()
        self._list_controller.start()

    def _build_text_box(self, placeholder: str) -> QPlainTextEdit:
        widget = QPlainTextEdit()
        widget.setReadOnly(True)
        widget.setPlaceholderText(placeholder)
        widget.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        return widget

    def refresh(self):
        self._status.setText(tr("Loading..."))
        self._list_controller.trigger()

    def _selected_incident(self) -> dict | None:
        indexes = self._table.selectionModel().selectedRows() if self._table.selectionModel() else []
        if not indexes:
            return None
        row = indexes[0].row()
        if row < 0 or row >= len(self._incidents):
            return None
        return self._incidents[row]

    def _apply_incidents_payload(self, payload: dict):
        self._incidents = list(payload.get("incidents", []) or [])
        status = str(payload.get("status", "unknown") or "unknown").lower()
        self._status.setText(status.upper())
        self._status.setStyleSheet(badge_style("ok" if status == "ok" else "degraded"))
        self._table.setRowCount(len(self._incidents))
        for row, incident in enumerate(self._incidents):
            values = [
                incident.get("id", ""),
                incident.get("timestamp_text", ""),
                incident.get("severity", ""),
                incident.get("status", ""),
                incident.get("title", ""),
                incident.get("entity_key", ""),
                incident.get("alert_count", 0),
                f"{float(incident.get('risk_score', 0.0) or 0.0):.1f}",
            ]
            for column, value in enumerate(values):
                self._table.setItem(row, column, QTableWidgetItem(str(value)))
        if self._incidents:
            self._table.selectRow(0)
        else:
            self._detail_title.setText(tr("Incident detail"))
            self._detail_summary.setText(tr("No incidents matched the current filters."))
            self._detail_text.setPlainText("")
            self._evidence_text.setPlainText("")
            self._related_alerts_text.setPlainText("")
            self._incident_id.setText("")
            self._invalidate_preview()

    def _load_selected_detail(self):
        incident = self._selected_incident()
        if not incident:
            return
        incident_id = incident.get("id")
        self._incident_id.setText(str(incident_id))
        self._detail_summary.setText(tr("Loading detail..."))
        self._detail_controller.trigger(
            task=lambda: backend_facade.collect_incident_detail(int(incident_id), config_path=self._config_path),
            on_result=self._apply_detail_payload,
            on_error=lambda error: self._detail_summary.setText(error.get("message", "detail error")),
        )

    def _apply_detail_payload(self, payload: dict):
        incident = dict(payload.get("incident", {}) or {})
        detail = dict(payload.get("detail", {}) or {})
        related_alerts = list(payload.get("related_alerts", []) or [])
        self._detail_title.setText(f"Incident #{incident.get('id', '-')}")
        self._detail_summary.setText(
            f"{incident.get('status', '')} | {incident.get('severity', '')} | "
            f"{incident.get('entity_key', '')} | alerts={incident.get('alert_count', 0)}"
        )
        self._detail_text.setPlainText(detail.get("summary_text", "") or "")
        self._evidence_text.setPlainText(detail.get("evidence_text", "") or "")
        lines = []
        for alert in related_alerts:
            lines.append(
                f"#{alert.get('id', '-')}"
                f" [{alert.get('severity', '')}]"
                f" {alert.get('timestamp_text', '')}"
                f" {alert.get('rule_id', '')}"
                f" {alert.get('message', '')}"
            )
        self._related_alerts_text.setPlainText("\n".join(lines).strip())

    def _invalidate_preview(self, *_args):
        self._preview_ready = False
        self._execute_button.setEnabled(False)
        action_type = "INCIDENT_CLOSE" if self._action.currentText() == "close" else "INCIDENT_RESOLVE"
        target = self._incident_id.text().strip() or "TARGET"
        self._confirmation_phrase.setText(f"CONFIRM {action_type} {target}")
        self._preview_status.setText(tr("Preview required before execution."))

    def _run_preview(self):
        try:
            incident_id = int(self._incident_id.text().strip())
        except (TypeError, ValueError):
            incident_id = 0
        self._preview_controller.trigger(
            task=lambda: backend_facade.preview_incident_action(
                action=self._action.currentText(),
                incident_id=incident_id,
                actor=self._actor.text(),
                role=self._role.currentText(),
                reason=self._reason.text(),
                confirmation=self._confirmation.text(),
                dry_run_completed=True,
                config_path=self._config_path,
            ),
            on_result=self._apply_preview_payload,
            on_error=lambda error: self._result_text.setPlainText(error.get("message", "preview error")),
        )

    def _apply_preview_payload(self, payload: dict):
        self._result_text.setPlainText(backend_facade._stringify_payload(payload))
        guard = dict(payload.get("guard", {}) or {})
        request = dict(guard.get("metadata", {}) or {}).get("request", {})
        self._confirmation_phrase.setText(str(request.get("required_confirmation_phrase", self._confirmation_phrase.text())))
        self._preview_ready = str(payload.get("status", "")) == "ready" and bool(guard.get("execution_enabled", False))
        self._execute_button.setEnabled(self._preview_ready)
        warning = str(payload.get("warning", "") or "").strip()
        base_message = str(payload.get("message", guard.get("message", "preview")) or "preview")
        self._preview_status.setText(f"{base_message}\n{warning}".strip())

    def _execute_action(self):
        try:
            incident_id = int(self._incident_id.text().strip())
        except (TypeError, ValueError):
            incident_id = 0
        self._execute_controller.trigger(
            task=lambda: backend_facade.execute_incident_action(
                action=self._action.currentText(),
                incident_id=incident_id,
                actor=self._actor.text(),
                role=self._role.currentText(),
                reason=self._reason.text(),
                confirmation=self._confirmation.text(),
                dry_run_completed=self._preview_ready,
                config_path=self._config_path,
            ),
            on_result=self._apply_execute_payload,
            on_error=lambda error: self._result_text.setPlainText(error.get("message", "execute error")),
        )

    def _apply_execute_payload(self, payload: dict):
        self._result_text.setPlainText(backend_facade._stringify_payload(payload))
        self._preview_status.setText(str(payload.get("message", payload.get("status", "executed"))))
        self._preview_ready = False
        self._execute_button.setEnabled(False)
        self.refresh()
        incident_id = payload.get("incident_id")
        try:
            if incident_id not in (None, ""):
                self.select_incident(int(incident_id))
        except Exception:
            pass

    def select_incident(self, incident_id: int):
        target_id = int(incident_id)
        for row, incident in enumerate(self._incidents):
            try:
                if int(incident.get("id", -1) or -1) == target_id:
                    self._table.selectRow(row)
                    return
            except Exception:
                continue
        self.refresh()

    def prepare_incident_action(self, incident_id: int, action: str = "resolve"):
        self.select_incident(int(incident_id))
        index = self._action.findText("close" if str(action).strip().lower() == "close" else "resolve")
        self._action.setCurrentIndex(index if index >= 0 else 0)
        self._incident_id.setText(str(int(incident_id)))
        self._invalidate_preview()

    def retranslate_ui(self):
        self._title.setText(tr("Incidents"))
        self._status_filter_label.setText(tr("Status"))
        self._severity_filter_label.setText(tr("Severity"))
        self._limit_label.setText(tr("Limit"))
        self._refresh.setText(tr("Refresh"))
        self._detail_title.setText(tr("Incident detail") if not self._selected_incident() else self._detail_title.text())
        self._summary_label.setText(tr("Summary"))
        self._evidence_label.setText(tr("Evidence"))
        self._related_alerts_label.setText(tr("Related Alerts"))
        self._incident_id.setPlaceholderText(tr("Incident ID"))
        self._reason.setPlaceholderText(tr("Reason"))
        self._confirmation.setPlaceholderText(tr("Type required confirmation"))
        self._action_label.setText(tr("Action"))
        self._incident_id_label.setText(tr("Incident ID"))
        self._actor_label.setText(tr("Actor"))
        self._role_label.setText(tr("Role"))
        self._reason_label.setText(tr("Reason"))
        self._required_confirmation_label.setText(tr("Required Confirmation"))
        self._typed_confirmation_label.setText(tr("Typed Confirmation"))
        self._preview_button.setText(tr("Dry-run Preview"))
        self._execute_button.setText(tr("Execute"))
        set_table_empty_message(self._table, tr("No incidents match the current filters."))
