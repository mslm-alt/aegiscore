from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor, QBrush, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ui import backend_facade
from ui.components import configure_table, set_table_empty_message
from ui.i18n import tr
from ui.models import builtin_presets, pick_primary_ip, preset_matches_alert
from ui.theme import badge_style, severity_color
from ui.workers import RefreshController


class AlertDetailDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("Alert Details"))
        self.setSizeGripEnabled(True)
        self.setMinimumSize(720, 520)
        self._apply_default_size()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        layout.addWidget(self._scroll, 1)

        self._body = QWidget()
        self._scroll.setWidget(self._body)
        body_layout = QVBoxLayout(self._body)
        body_layout.setContentsMargins(4, 4, 4, 4)
        body_layout.setSpacing(12)

        self._title = QLabel(tr("Alert detail"))
        self._title.setObjectName("sectionTitle")
        self._summary = QLabel("")
        self._summary.setWordWrap(True)
        self._summary.setObjectName("mutedText")

        self._summary_section = QLabel(tr("Summary"))
        self._summary_section.setObjectName("sectionTitle")
        self._summary_card = QFrame()
        self._summary_card.setFrameShape(QFrame.Shape.StyledPanel)
        self._summary_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        grid = QGridLayout(self._summary_card)
        grid.setContentsMargins(12, 12, 12, 12)
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(10)
        self._fields: dict[str, QLabel] = {}
        rows = [
            ("Rule ID", "rule_id"),
            ("Severity", "severity"),
            ("Risk Score", "risk_score"),
            ("Entity", "entity"),
            ("Source", "source"),
            ("Source IP", "source_ip"),
            ("Created time", "created_at"),
            ("Status", "status"),
            ("Family / Category", "family_category"),
        ]
        for row, (label_text, key) in enumerate(rows):
            label = QLabel(tr(label_text))
            label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            grid.addWidget(label, row // 2, (row % 2) * 2)
            value = QLabel("-")
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            grid.addWidget(value, row // 2, (row % 2) * 2 + 1)
            self._fields[key] = value

        self._why_label = QLabel(tr("Why Triggered"))
        self._why_label.setObjectName("sectionTitle")
        self._message = QPlainTextEdit()
        self._message.setReadOnly(True)
        self._message.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self._message.setMaximumHeight(96)
        self._message.setPlaceholderText(tr("No message available."))
        self._explanation = QPlainTextEdit()
        self._explanation.setReadOnly(True)
        self._explanation.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self._explanation.setMinimumHeight(180)
        self._explanation.setPlaceholderText(tr("No explanation available."))
        self._evidence_label = QLabel(tr("Evidence"))
        self._evidence_label.setObjectName("sectionTitle")
        self._evidence = QPlainTextEdit()
        self._evidence.setReadOnly(True)
        self._evidence.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self._evidence.setMinimumHeight(160)
        self._recommendation_label = QLabel(tr("Recommended review steps"))
        self._recommendation_label.setObjectName("sectionTitle")
        self._recommendations = QPlainTextEdit()
        self._recommendations.setReadOnly(True)
        self._recommendations.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self._recommendations.setMaximumHeight(140)

        self._advanced_toggle = QToolButton()
        self._advanced_toggle.setCheckable(True)
        self._advanced_toggle.toggled.connect(self._toggle_advanced)
        self._advanced = QPlainTextEdit()
        self._advanced.setReadOnly(True)
        self._advanced.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._advanced.setVisible(False)
        self._advanced.setMinimumHeight(180)
        close_button = QPushButton(tr("Close"))
        close_button.clicked.connect(self.close)
        self._message_label = QLabel(tr("Message"))
        self._advanced_label = QLabel(tr("Advanced"))

        body_layout.addWidget(self._title)
        body_layout.addWidget(self._summary)
        body_layout.addWidget(self._summary_section)
        body_layout.addWidget(self._summary_card)
        body_layout.addWidget(self._message_label)
        body_layout.addWidget(self._message)
        body_layout.addWidget(self._why_label)
        body_layout.addWidget(self._explanation)
        body_layout.addWidget(self._evidence_label)
        body_layout.addWidget(self._evidence)
        body_layout.addWidget(self._recommendation_label)
        body_layout.addWidget(self._recommendations)
        body_layout.addWidget(self._advanced_toggle, 0, Qt.AlignmentFlag.AlignLeft)
        body_layout.addWidget(self._advanced_label)
        body_layout.addWidget(self._advanced)
        layout.addWidget(close_button, 0, Qt.AlignmentFlag.AlignRight)
        self._advanced_label.setVisible(False)

    def _apply_default_size(self):
        screen = QGuiApplication.primaryScreen()
        if screen is None:
            self.resize(900, 650)
            return
        available = screen.availableGeometry()
        width = min(900, max(720, int(available.width() * 0.7)))
        height = min(650, max(520, int(available.height() * 0.7)))
        self.resize(width, height)

    def _toggle_advanced(self, checked: bool):
        self._advanced.setVisible(checked)
        self._advanced_label.setVisible(checked)
        self._advanced_toggle.setText(tr("Advanced / Hide raw") if checked else tr("Advanced / Show raw"))

    def retranslate_ui(self):
        self.setWindowTitle(tr("Alert Details"))
        self._summary_section.setText(tr("Summary"))
        self._why_label.setText(tr("Why Triggered"))
        self._evidence_label.setText(tr("Evidence"))
        self._recommendation_label.setText(tr("Recommended review steps"))
        self._message_label.setText(tr("Message"))
        self._advanced_label.setText(tr("Advanced"))
        self._advanced_toggle.setText(
            tr("Advanced / Hide raw") if self._advanced_toggle.isChecked() else tr("Advanced / Show raw")
        )
        self._message.setPlaceholderText(tr("No message available."))
        self._explanation.setPlaceholderText(tr("No explanation available."))

    @staticmethod
    def _first_present(payloads: list[dict], keys: list[str]) -> str:
        for source in payloads:
            for key in keys:
                value = source.get(key)
                if value not in (None, "", [], {}, ()):
                    return str(value)
        return ""

    def _format_evidence(self, alert: dict, detail: dict, explanation: dict) -> str:
        context = dict(detail.get("context_json", {}) or {})
        parsed = dict(detail.get("parsed_metadata", {}) or {})
        raw_event = dict(detail.get("raw_event", {}) or {})
        evidence_map = dict(explanation.get("evidence_fields", {}) or {})
        matched_fields = dict(explanation.get("rule_metadata", {}).get("matched_event_fields", {}) or {})
        payloads = [evidence_map, matched_fields, parsed, context, raw_event, alert]
        lines = []
        key_map = [
            ("source", ["source"]),
            ("process", ["process", "process_name", "proc", "exe"]),
            ("user", ["user", "username"]),
            ("src_ip", ["src_ip", "source_ip"]),
            ("dst_ip", ["dst_ip", "target_ip"]),
            ("command", ["command", "cmdline", "cmd"]),
            ("path", ["path", "file_path", "filepath"]),
            ("message", ["message"]),
        ]
        for label, keys in key_map:
            value = self._first_present(payloads, keys)
            if value:
                lines.append(f"{label}: {value}")
        if matched_fields:
            lines.append("")
            lines.append("matched_rule_fields:")
            for key, value in matched_fields.items():
                if value not in (None, "", [], {}, ()):
                    lines.append(f"  {key}: {value}")
        key_evidence = [str(item).strip() for item in list(explanation.get("key_evidence", []) or []) if str(item).strip()]
        if key_evidence:
            lines.append("")
            lines.append("evidence_notes:")
            for item in key_evidence:
                lines.append(f"  - {item}")
        if not lines:
            return tr("No evidence available.")
        return "\n".join(lines)

    def render(self, payload: dict):
        alert = dict(payload.get("alert", {}) or {})
        detail = dict(payload.get("detail", {}) or {})
        explanation = dict(detail.get("explanation", {}) or {})
        self._title.setText(f"Alert #{alert.get('id', '-')}")
        self._summary.setText(
            f"{alert.get('severity', '').upper()} | {alert.get('rule_id', '')} | "
            f"{alert.get('entity', '') or alert.get('source_ip', '')}"
        )
        family_category = " / ".join(
            [
                value for value in [
                    str(alert.get("rule_family", "") or detail.get("explanation_kind", "") or "").strip(),
                    str(alert.get("category", "") or dict(detail.get("context_json", {}) or {}).get("category", "") or "").strip(),
                ] if value
            ]
        ) or "-"
        status_bits = [
            str(alert.get("status", "") or "").strip(),
            str(dict(detail.get("context_json", {}) or {}).get("outcome", "") or alert.get("outcome", "") or "").strip(),
        ]
        mapping = {
            "rule_id": str(alert.get("rule_id", "") or "-"),
            "severity": str(alert.get("severity", "") or "-").upper(),
            "risk_score": f"{float(alert.get('risk_score', 0.0) or 0.0):.1f}",
            "entity": str(alert.get("entity", "") or alert.get("source_ip", "") or "-"),
            "created_at": str(alert.get("timestamp_text", "") or "-"),
            "source": str(alert.get("source", "") or "-"),
            "source_ip": str(alert.get("source_ip", "") or dict(detail.get("context_json", {}) or {}).get("src_ip", "") or "-"),
            "status": " / ".join([bit for bit in status_bits if bit]) or "-",
            "family_category": family_category,
        }
        for key, value in mapping.items():
            self._fields[key].setText(value)
        self._message.setPlainText(str(alert.get("message", "") or ""))
        self._explanation.setPlainText(str(detail.get("explanation_text", "") or tr("No explanation available.")))
        self._evidence.setPlainText(self._format_evidence(alert, detail, explanation))
        review_steps = [str(item).strip() for item in list(explanation.get("review_steps", []) or []) if str(item).strip()]
        self._recommendations.setPlainText(
            "\n".join(f"- {item}" for item in review_steps) if review_steps else tr("No recommendation available.")
        )
        self._advanced.setPlainText(backend_facade._stringify_payload({
            "alert": alert,
            "context_json": detail.get("context_json", {}),
            "parsed_metadata": detail.get("parsed_metadata", {}),
            "raw_event": detail.get("raw_event", {}),
            "ip_reputation": detail.get("ip_reputation", []),
        }))
        self._advanced_toggle.setChecked(False)
        self._toggle_advanced(False)


class AlertExplanationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("Alert Explanation"))
        self.setSizeGripEnabled(True)
        self.setMinimumSize(720, 520)
        self._apply_default_size()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self._title = QLabel(tr("Alert Explanation"))
        self._title.setObjectName("sectionTitle")
        self._status = QLabel(tr("Loading..."))
        self._status.setObjectName("mutedText")

        self._summary_card = QFrame()
        self._summary_card.setFrameShape(QFrame.Shape.StyledPanel)
        self._summary_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        summary_grid = QGridLayout(self._summary_card)
        summary_grid.setContentsMargins(12, 12, 12, 12)
        summary_grid.setHorizontalSpacing(16)
        summary_grid.setVerticalSpacing(10)
        self._fields: dict[str, QLabel] = {}
        rows = [
            ("Rule ID", "rule_id"),
            ("Severity", "severity"),
            ("Risk Score", "risk_score"),
            ("Source", "source"),
            ("Source IP", "source_ip"),
            ("Entity", "entity"),
        ]
        for row, (label_text, key) in enumerate(rows):
            label = QLabel(tr(label_text))
            label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            summary_grid.addWidget(label, row // 2, (row % 2) * 2)
            value = QLabel("-")
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            summary_grid.addWidget(value, row // 2, (row % 2) * 2 + 1)
            self._fields[key] = value

        self._summary = QPlainTextEdit()
        self._summary.setReadOnly(True)
        self._summary.setMaximumHeight(90)

        self._why = QPlainTextEdit()
        self._why.setReadOnly(True)
        self._why.setMaximumHeight(120)

        self._risk = QPlainTextEdit()
        self._risk.setReadOnly(True)
        self._risk.setMaximumHeight(120)

        self._full_explanation = QPlainTextEdit()
        self._full_explanation.setReadOnly(True)
        self._full_explanation.setMinimumHeight(180)

        self._evidence = QPlainTextEdit()
        self._evidence.setReadOnly(True)
        self._evidence.setMaximumHeight(140)

        self._mitigation = QPlainTextEdit()
        self._mitigation.setReadOnly(True)
        self._mitigation.setMaximumHeight(140)

        self._false_positive = QPlainTextEdit()
        self._false_positive.setReadOnly(True)
        self._false_positive.setMaximumHeight(120)

        self._raw_toggle = QToolButton()
        self._raw_toggle.setCheckable(True)
        self._raw_toggle.toggled.connect(self._toggle_raw)
        self._raw = QPlainTextEdit()
        self._raw.setReadOnly(True)
        self._raw.setVisible(False)
        self._raw.setMinimumHeight(180)

        close_button = QPushButton(tr("Close"))
        close_button.clicked.connect(self.close)

        for title, widget in (
            ("Summary", self._summary),
            ("Why Triggered", self._why),
            ("Risk", self._risk),
            ("Full Explanation", self._full_explanation),
            ("Evidence", self._evidence),
            ("Recommended review steps", self._mitigation),
            ("False positive notes", self._false_positive),
        ):
            label = QLabel(tr(title))
            label.setObjectName("sectionTitle")
            layout.addWidget(label)
            layout.addWidget(widget)
        layout.insertWidget(0, self._title)
        layout.insertWidget(1, self._status)
        layout.insertWidget(2, self._summary_card)
        layout.addWidget(self._raw_toggle, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self._raw)
        layout.addWidget(close_button, 0, Qt.AlignmentFlag.AlignRight)
        self.retranslate_ui()

    def _apply_default_size(self):
        screen = QGuiApplication.primaryScreen()
        if screen is None:
            self.resize(860, 640)
            return
        available = screen.availableGeometry()
        width = min(920, max(720, int(available.width() * 0.72)))
        height = min(700, max(520, int(available.height() * 0.74)))
        self.resize(width, height)

    def _toggle_raw(self, checked: bool):
        self._raw.setVisible(checked)
        self._raw_toggle.setText(tr("Advanced / Hide raw") if checked else tr("Advanced / Show raw"))

    def render(self, alert: dict, payload: dict):
        self._title.setText(f"{tr('Alert Explanation')} #{alert.get('id', '-')}")
        self._status.setText(tr("Ready"))
        mapping = {
            "rule_id": str(payload.get("rule_id", "") or alert.get("rule_id", "") or "-"),
            "severity": str(payload.get("severity", "") or alert.get("severity", "") or "-").upper(),
            "risk_score": f"{float(payload.get('risk_score', alert.get('risk_score', 0.0)) or 0.0):.1f}",
            "source": str(payload.get("source", "") or alert.get("source", "") or "-"),
            "source_ip": str(payload.get("source_ip", "") or alert.get("source_ip", "") or "-"),
            "entity": str(payload.get("entity", "") or alert.get("entity", "") or payload.get("source_ip", "") or alert.get("source_ip", "") or "-"),
        }
        for key, value in mapping.items():
            self._fields[key].setText(value if value not in {"", "NONE"} else "-")
        self._summary.setPlainText(str(payload.get("summary", "") or payload.get("raw_text", "") or ""))
        self._why.setPlainText(str(payload.get("why_triggered", "") or tr("No explanation available.")))
        self._risk.setPlainText(str(payload.get("risk_assessment", "") or "-"))
        self._full_explanation.setPlainText(str(payload.get("full_explanation", "") or payload.get("raw_text", "") or "-"))
        self._evidence.setPlainText(str(payload.get("evidence_summary", "") or tr("No evidence available.")))
        steps = [str(item).strip() for item in list(payload.get("recommended_review_steps", []) or []) if str(item).strip()]
        self._mitigation.setPlainText("\n".join(f"- {item}" for item in steps) if steps else tr("No recommendation available."))
        self._false_positive.setPlainText(str(payload.get("false_positive_notes", "") or "-"))
        self._raw.setPlainText(backend_facade._stringify_payload({
            "alert_id": payload.get("alert_id"),
            "used_llm": payload.get("used_llm", False),
            "fallback_used": payload.get("fallback_used", True),
            "provider": payload.get("provider", ""),
            "raw_text": payload.get("raw_text", ""),
            "metadata": payload.get("metadata", {}),
        }))
        self._raw_toggle.setChecked(False)
        self._toggle_raw(False)

    def set_loading(self, alert: dict):
        self._title.setText(f"{tr('Alert Explanation')} #{alert.get('id', '-')}")
        self._status.setText(tr("Loading..."))
        loading_mapping = {
            "rule_id": str(alert.get("rule_id", "") or "-"),
            "severity": str(alert.get("severity", "") or "-").upper(),
            "risk_score": f"{float(alert.get('risk_score', 0.0) or 0.0):.1f}",
            "source": str(alert.get("source", "") or "-"),
            "source_ip": str(alert.get("source_ip", "") or "-"),
            "entity": str(alert.get("entity", "") or alert.get("source_ip", "") or "-"),
        }
        for key, value in loading_mapping.items():
            self._fields[key].setText(value)
        for widget in (
            self._summary,
            self._why,
            self._risk,
            self._full_explanation,
            self._evidence,
            self._mitigation,
            self._false_positive,
            self._raw,
        ):
            widget.setPlainText("")
        self._raw_toggle.setChecked(False)
        self._toggle_raw(False)

    def set_error(self, message: str):
        self._status.setText(tr("Error"))
        for value in self._fields.values():
            value.setText("-")
        self._summary.setPlainText(str(message or tr("Backend unavailable")))

    def retranslate_ui(self):
        self.setWindowTitle(tr("Alert Explanation"))
        self._raw_toggle.setText(tr("Advanced / Hide raw") if self._raw_toggle.isChecked() else tr("Advanced / Show raw"))


class AlertsView(QWidget):
    _COLUMNS = ["time", "severity", "rule_id", "risk_score", "source_ip/entity", "source", "message"]

    def __init__(self, config_path: str | None = None, open_ip_context=None, open_manual_ip_action=None, open_incident=None):
        super().__init__()
        self._config_path = config_path
        self._open_ip_context = open_ip_context
        self._open_manual_ip_action = open_manual_ip_action
        self._open_incident = open_incident
        self._controller = RefreshController(self, interval_ms=12000)
        self._detail_controller = RefreshController(self)
        self._explain_controller = RefreshController(self)
        self._alerts: list[dict] = []
        self._visible_alerts: list[dict] = []
        self._detail_dialog: AlertDetailDialog | None = None
        self._explanation_dialog: AlertExplanationDialog | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        controls = QHBoxLayout()
        self._title = QLabel(tr("Alerts"))
        self._title.setObjectName("pageTitle")
        self._preset = QComboBox()
        for preset in builtin_presets():
            self._preset.addItem(preset.label, preset.key)
        self._preset.currentIndexChanged.connect(self._apply_visible_alerts)
        self._severity = QComboBox()
        self._severity.addItems(["all", "critical", "high", "medium", "low", "info"])
        self._severity.currentIndexChanged.connect(self.refresh)
        self._limit = QComboBox()
        self._limit.addItems(["25", "50", "100", "200"])
        self._limit.setCurrentText("100")
        self._limit.currentIndexChanged.connect(self.refresh)
        self._include_ml_alerts = QCheckBox(tr("Include ML alerts"))
        self._include_ml_alerts.setChecked(False)
        self._include_ml_alerts.toggled.connect(self._apply_visible_alerts)
        self._query = QLineEdit()
        self._query.setPlaceholderText(tr("Search alert id, rule id, entity, IP, message..."))
        self._query.textChanged.connect(self._apply_visible_alerts)
        self._status = QLabel(tr("Ready"))
        self._status.setObjectName("badge")
        self._status.setStyleSheet(badge_style("read_only"))
        self._refresh = QPushButton(tr("Refresh"))
        self._refresh.clicked.connect(self.refresh)
        self._preset_label = QLabel("Preset")
        self._severity_label = QLabel(tr("Severity"))
        self._limit_label = QLabel(tr("Limit"))
        self._query_label = QLabel(tr("Query"))
        controls.addWidget(self._title)
        controls.addStretch(1)
        controls.addWidget(self._preset_label)
        controls.addWidget(self._preset)
        controls.addWidget(self._severity_label)
        controls.addWidget(self._severity)
        controls.addWidget(self._query_label)
        controls.addWidget(self._query, 1)
        controls.addWidget(self._limit_label)
        controls.addWidget(self._limit)
        controls.addWidget(self._include_ml_alerts)
        controls.addWidget(self._status)
        controls.addWidget(self._refresh)

        action_row = QHBoxLayout()
        action_row.setSpacing(8)
        self._view_details = QPushButton(tr("View Details"))
        self._view_details.setEnabled(False)
        self._view_details.clicked.connect(self._show_selected_detail)
        self._explain_button = QPushButton(tr("Explain Alert"))
        self._explain_button.setEnabled(False)
        self._explain_button.clicked.connect(self._show_selected_explanation)
        self._open_ip_context_button = QPushButton(tr("Open IP Blocking"))
        self._open_ip_context_button.setEnabled(False)
        self._open_ip_context_button.clicked.connect(self._open_selected_ip_context)
        self._open_incident_button = QPushButton(tr("Open Incident"))
        self._open_incident_button.setEnabled(False)
        self._open_incident_button.setToolTip(tr("Open the incident detail in the hidden incident view. No action is executed automatically."))
        self._open_incident_button.clicked.connect(self._open_selected_incident)
        self._prepare_manual_block_button = QPushButton(tr("Prepare Manual Block"))
        self._prepare_manual_block_button.setEnabled(False)
        self._prepare_manual_block_button.clicked.connect(self._prepare_manual_block)
        action_row.addWidget(self._view_details)
        action_row.addWidget(self._explain_button)
        action_row.addWidget(self._open_ip_context_button)
        action_row.addWidget(self._open_incident_button)
        action_row.addWidget(self._prepare_manual_block_button)
        action_row.addStretch(1)

        self._table = QTableWidget(0, len(self._COLUMNS))
        self._table.setHorizontalHeaderLabels(self._COLUMNS)
        configure_table(self._table)
        set_table_empty_message(self._table, tr("No alerts match the current filters."))
        self._table.itemSelectionChanged.connect(self._update_action_state)
        self._table.itemDoubleClicked.connect(lambda *_args: self._show_selected_detail())

        layout.addLayout(controls)
        layout.addLayout(action_row)
        layout.addWidget(self._table, 1)

        self._controller.configure(
            task=lambda: backend_facade.collect_alerts(
                limit=int(self._limit.currentText()),
                severity=None if self._severity.currentText() == "all" else self._severity.currentText(),
                config_path=self._config_path,
            ),
            on_result=self._apply_alerts_payload,
            on_error=self._apply_error,
            on_finished=self._finish_refresh,
        )
        self.refresh()
        self._controller.start()

    def minimumSizeHint(self):
        return QSize(780, 560)

    def refresh(self):
        self._refresh.setEnabled(False)
        self._status.setText(tr("Loading..."))
        self._controller.trigger()

    def _finish_refresh(self):
        self._refresh.setEnabled(True)
        if self._status.text() == tr("Loading..."):
            self._status.setText(tr("Ready"))

    def _apply_error(self, error: dict):
        self._status.setText(error.get("message", "error"))
        self._status.setStyleSheet(badge_style("degraded"))

    def _apply_alerts_payload(self, payload: dict):
        self._alerts = list(payload.get("alerts", []) or [])
        status = str(payload.get("status", "unknown") or "unknown").lower()
        self._status.setText(status.upper())
        self._status.setStyleSheet(badge_style("ok" if status == "ok" else "degraded"))
        self._apply_visible_alerts()

    def _apply_visible_alerts(self):
        preset_key = self._preset.currentData() or "all"
        include_ml = self._include_ml_alerts.isChecked()
        query = str(self._query.text() or "").strip().lower()
        self._visible_alerts = [
            alert
            for alert in self._alerts
            if (include_ml or not backend_facade.is_ml_alert(alert))
            and preset_matches_alert(str(preset_key), alert)
            and (not query or query in backend_facade._search_blob(alert))
        ]
        self._table.setRowCount(len(self._visible_alerts))
        for row, alert in enumerate(self._visible_alerts):
            values = [
                alert.get("timestamp_text", ""),
                alert.get("severity", ""),
                alert.get("rule_id", ""),
                f"{float(alert.get('risk_score', 0.0) or 0.0):.1f}",
                alert.get("source_ip", "") or alert.get("entity", ""),
                alert.get("source", ""),
                alert.get("message", ""),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 1:
                    color = QColor(severity_color(str(alert.get("severity", "unknown"))))
                    item.setForeground(QBrush(color))
                self._table.setItem(row, column, item)
        if self._visible_alerts:
            self._table.selectRow(0)
        else:
            self._update_action_state()

    def _selected_alert(self) -> dict | None:
        indexes = self._table.selectionModel().selectedRows() if self._table.selectionModel() else []
        if not indexes:
            return None
        row = indexes[0].row()
        if row < 0 or row >= len(self._visible_alerts):
            return None
        return self._visible_alerts[row]

    def _update_action_state(self):
        alert = self._selected_alert()
        if not alert:
            self._view_details.setEnabled(False)
            self._explain_button.setEnabled(False)
            self._open_ip_context_button.setEnabled(False)
            self._open_incident_button.setEnabled(False)
            self._prepare_manual_block_button.setEnabled(False)
            return
        self._view_details.setEnabled(alert.get("id") not in (None, ""))
        self._explain_button.setEnabled(alert.get("id") not in (None, ""))
        selected_ip = pick_primary_ip(alert)
        self._open_ip_context_button.setEnabled(bool(selected_ip) and self._open_ip_context is not None)
        incident_id = dict(alert.get("raw", {}) or {}).get("incident_id", alert.get("incident_id", ""))
        self._open_incident_button.setEnabled(bool(str(incident_id or "").strip()) and self._open_incident is not None)
        self._prepare_manual_block_button.setEnabled(bool(selected_ip) and self._open_manual_ip_action is not None)

    def _show_selected_detail(self):
        alert = self._selected_alert()
        if not alert or alert.get("id") in (None, ""):
            return
        if self._detail_dialog is None:
            self._detail_dialog = AlertDetailDialog(self)
            self._detail_dialog.retranslate_ui()
        self._detail_dialog._title.setText(tr("Loading alert detail..."))
        self._detail_dialog.show()
        self._detail_dialog.raise_()
        self._detail_dialog.activateWindow()
        self._detail_controller.trigger(
            task=lambda: backend_facade.collect_alert_detail(int(alert["id"]), config_path=self._config_path),
            on_result=self._detail_dialog.render,
            on_error=lambda error: self._detail_dialog._advanced.setPlainText(error.get("message", "detail error")),
        )

    def retranslate_ui(self):
        self._title.setText(tr("Alerts"))
        self._preset_label.setText("Preset")
        self._severity_label.setText(tr("Severity"))
        self._query_label.setText(tr("Query"))
        self._query.setPlaceholderText(tr("Search alert id, rule id, entity, IP, message..."))
        self._limit_label.setText(tr("Limit"))
        self._include_ml_alerts.setText(tr("Include ML alerts"))
        self._refresh.setText(tr("Refresh"))
        self._view_details.setText(tr("View Details"))
        self._explain_button.setText(tr("Explain Alert"))
        self._open_ip_context_button.setText(tr("Open IP Blocking"))
        self._open_incident_button.setText(tr("Open Incident"))
        self._open_incident_button.setToolTip(tr("Open the incident detail in the hidden incident view. No action is executed automatically."))
        self._prepare_manual_block_button.setText(tr("Prepare Manual Block"))
        set_table_empty_message(self._table, tr("No alerts match the current filters."))
        if self._detail_dialog is not None:
            self._detail_dialog.retranslate_ui()
        if self._explanation_dialog is not None:
            self._explanation_dialog.retranslate_ui()

    def _show_selected_explanation(self):
        alert = self._selected_alert()
        if not alert or alert.get("id") in (None, ""):
            return
        if self._explanation_dialog is None:
            self._explanation_dialog = AlertExplanationDialog(self)
        self._explanation_dialog.set_loading(alert)
        self._explanation_dialog.show()
        self._explanation_dialog.raise_()
        self._explanation_dialog.activateWindow()
        self._explain_button.setEnabled(False)
        self._explain_controller.trigger(
            task=lambda: backend_facade.explain_alert_for_ui(int(alert["id"]), prefer_llm=True, config_path=self._config_path),
            on_result=lambda payload: self._apply_alert_explanation(alert, payload),
            on_error=lambda error: self._handle_alert_explanation_error(error),
            on_finished=self._update_action_state,
        )

    def _apply_alert_explanation(self, alert: dict, payload: dict):
        if self._explanation_dialog is None:
            self._explanation_dialog = AlertExplanationDialog(self)
        self._explanation_dialog.render(alert, payload)

    def _handle_alert_explanation_error(self, error: dict):
        if self._explanation_dialog is None:
            self._explanation_dialog = AlertExplanationDialog(self)
        self._explanation_dialog.set_error(error.get("message", "explanation error"))

    def _open_selected_ip_context(self):
        alert = self._selected_alert()
        if not alert or self._open_ip_context is None:
            return
        ip = pick_primary_ip(alert)
        if not ip:
            return
        self._open_ip_context(ip)

    def _prepare_manual_block(self):
        alert = self._selected_alert()
        if not alert or self._open_manual_ip_action is None:
            return
        ip = pick_primary_ip(alert)
        if not ip:
            return
        self._open_manual_ip_action(ip, "block")

    def _open_selected_incident(self):
        alert = self._selected_alert()
        if not alert or self._open_incident is None:
            return
        incident_id = dict(alert.get("raw", {}) or {}).get("incident_id", alert.get("incident_id", ""))
        try:
            normalized_id = int(incident_id)
        except (TypeError, ValueError):
            return
        self._open_incident(normalized_id)

    def select_alert(self, alert_id: int):
        target_id = int(alert_id)
        for row, alert in enumerate(self._visible_alerts):
            try:
                if int(alert.get("id", -1) or -1) == target_id:
                    self._table.selectRow(row)
                    return
            except Exception:
                continue
        self.refresh()
