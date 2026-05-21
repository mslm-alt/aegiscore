from __future__ import annotations

from PySide6.QtCore import QSize
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ui import backend_facade
from ui.components import configure_table, make_metric_card, set_table_empty_message
from ui.i18n import tr
from ui.theme import badge_style, severity_color
from ui.workers import RefreshController


class MLCenterView(QWidget):
    _FAMILY_COLUMNS = ["family", "status", "current", "needed", "missing"]
    _ALERT_COLUMNS = ["time", "severity", "rule_id", "source_ip/entity", "message"]

    def __init__(self, config_path: str | None = None):
        super().__init__()
        self._config_path = config_path
        self._summary_controller = RefreshController(self)
        self._training_controller = RefreshController(self)
        self._historical_controller = RefreshController(self)
        self._alerts_controller = RefreshController(self)
        self._summary_payload: dict = {}
        self._training_payload: dict = {}
        self._historical_payload: dict = {}
        self._ml_alerts: list[dict] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        header = QHBoxLayout()
        self._title = QLabel(tr("ML Center"))
        self._title.setObjectName("pageTitle")
        self._status = QLabel(tr("Ready"))
        self._status.setObjectName("badge")
        self._status.setStyleSheet(badge_style("read_only"))
        self._refresh = QPushButton(tr("Refresh"))
        self._refresh.clicked.connect(self.refresh_all)
        header.addWidget(self._title)
        header.addStretch(1)
        header.addWidget(self._status)
        header.addWidget(self._refresh)
        layout.addLayout(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(12)
        body_layout.addWidget(self._build_summary_card(), 0)
        body_layout.addWidget(self._build_family_card(), 0)
        body_layout.addWidget(self._build_alerts_card(), 1)
        body_layout.addStretch(1)
        scroll.setWidget(body)
        layout.addWidget(scroll, 1)

        self.refresh_all()

    def minimumSizeHint(self):
        return QSize(760, 560)

    def _build_summary_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel(tr("ML Status"))
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        self._summary_cards: dict[str, QLabel] = {}
        for index, (key, label) in enumerate((
            ("mode", "ML Mode"),
            ("safety", "ML Safety"),
            ("quota", "Initial Training Readiness"),
            ("training", "Last Training"),
            ("historical", "Last Historical Scan"),
        )):
            widget = make_metric_card(tr(label), "-")
            self._summary_cards[key] = widget.findChild(QLabel, "value")
            grid.addWidget(widget, index // 2, index % 2)
        layout.addLayout(grid)

        self._quota_detail = QLabel("")
        self._quota_detail.setObjectName("mutedText")
        self._quota_detail.setWordWrap(True)
        self._training_detail = QLabel("")
        self._training_detail.setObjectName("mutedText")
        self._training_detail.setWordWrap(True)
        self._historical_detail = QLabel("")
        self._historical_detail.setObjectName("mutedText")
        self._historical_detail.setWordWrap(True)

        layout.addWidget(self._quota_detail)
        layout.addWidget(self._training_detail)
        layout.addWidget(self._historical_detail)
        return card

    def _build_family_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel(tr("Family Readiness"))
        title.setObjectName("sectionTitle")
        self._family_table = QTableWidget(0, len(self._FAMILY_COLUMNS))
        self._family_table.setHorizontalHeaderLabels(self._FAMILY_COLUMNS)
        configure_table(self._family_table)
        set_table_empty_message(self._family_table, tr("No family readiness rows are available."))

        layout.addWidget(title)
        layout.addWidget(self._family_table)
        return card

    def _build_alerts_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel(tr("ML Alerts"))
        title.setObjectName("sectionTitle")
        note = QLabel(tr("Behavioral/anomaly alerts are listed here so they do not dominate the default Alerts screen."))
        note.setObjectName("mutedText")
        note.setWordWrap(True)
        self._alerts_table = QTableWidget(0, len(self._ALERT_COLUMNS))
        self._alerts_table.setHorizontalHeaderLabels(self._ALERT_COLUMNS)
        configure_table(self._alerts_table)
        set_table_empty_message(self._alerts_table, tr("No ML alerts are available."))

        layout.addWidget(title)
        layout.addWidget(note)
        layout.addWidget(self._alerts_table, 1)
        return card

    def refresh_all(self):
        self._refresh.setEnabled(False)
        self._status.setText(tr("Loading..."))
        self._summary_controller.trigger(
            task=lambda: backend_facade.collect_ml_center_summary(config_path=self._config_path),
            on_result=self._apply_summary,
            on_error=self._apply_error,
        )
        self._training_controller.trigger(
            task=lambda: backend_facade.collect_training_status(config_path=self._config_path),
            on_result=self._apply_training,
            on_error=self._apply_error,
        )
        self._historical_controller.trigger(
            task=lambda: backend_facade.collect_historical_scan_status(config_path=self._config_path),
            on_result=self._apply_historical,
            on_error=self._apply_error,
        )
        self._alerts_controller.trigger(
            task=lambda: backend_facade.collect_ml_alerts(config_path=self._config_path),
            on_result=self._apply_ml_alerts,
            on_error=self._apply_error,
            on_finished=lambda: self._refresh.setEnabled(True),
        )

    def _apply_error(self, error: dict):
        self._status.setText(str(error.get("message", "error") or "error"))
        self._status.setStyleSheet(badge_style("degraded"))
        self._refresh.setEnabled(True)

    def _apply_summary(self, payload: dict):
        self._summary_payload = dict(payload or {})
        status = str(payload.get("status", "unknown") or "unknown").lower()
        self._status.setText(status.upper())
        self._status.setStyleSheet(badge_style("ok" if status == "ok" else "degraded"))
        family_rows = list(payload.get("family_rows", []) or [])
        self._family_table.setRowCount(len(family_rows))
        for row_index, row in enumerate(family_rows):
            values = [
                row.get("family_id", ""),
                tr("Ready") if bool(row.get("ready", False)) else row.get("status", ""),
                str(row.get("current_samples", 0)),
                str(row.get("needed_samples", 0)),
                str(row.get("missing_samples", 0)),
            ]
            for column, value in enumerate(values):
                self._family_table.setItem(row_index, column, QTableWidgetItem(str(value)))
        self._update_summary_card()

    def _apply_training(self, payload: dict):
        self._training_payload = dict(payload or {})
        self._update_summary_card()

    def _apply_historical(self, payload: dict):
        self._historical_payload = dict(payload or {})
        self._update_summary_card()

    def _apply_ml_alerts(self, payload: dict):
        self._ml_alerts = list(payload.get("alerts", []) or [])
        self._alerts_table.setRowCount(len(self._ml_alerts))
        for row, alert in enumerate(self._ml_alerts):
            values = [
                alert.get("timestamp_text", ""),
                alert.get("severity", ""),
                alert.get("rule_id", ""),
                alert.get("source_ip", "") or alert.get("entity", ""),
                alert.get("message", ""),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 1:
                    item.setForeground(QBrush(QColor(severity_color(str(alert.get("severity", "unknown"))))))
                self._alerts_table.setItem(row, column, item)

    def _update_summary_card(self):
        summary = dict(self._summary_payload or {})
        training = dict(self._training_payload or {})
        historical = dict(self._historical_payload or {})
        first_training = dict(summary.get("first_training", {}) or {})

        quota_family = str(first_training.get("family_id", "") or tr("Unknown"))
        quota_current = int(first_training.get("current_samples", 0) or 0)
        quota_needed = int(first_training.get("needed_samples", 0) or 0)
        quota_missing = int(first_training.get("missing_samples", 0) or 0)
        quota_ready = bool(first_training.get("ready", False))

        self._summary_cards["mode"].setText(str(summary.get("ml_mode_text", "-") or "-"))
        self._summary_cards["safety"].setText(str(summary.get("ml_safety_text", "-") or "-"))
        self._summary_cards["quota"].setText(tr("Ready") if quota_ready else tr("Blocked"))
        self._summary_cards["training"].setText(str(training.get("timestamp_text", "-") or "-"))
        self._summary_cards["historical"].setText(str(historical.get("timestamp_text", "-") or "-"))

        self._quota_detail.setText(
            f"{quota_family} | {tr('Current Samples')}: {quota_current} | "
            f"{tr('Needed Samples')}: {quota_needed} | {tr('Missing Samples')}: {quota_missing}"
        )
        training_bits = [
            str(training.get("training_status", "") or ""),
            str(training.get("family_info", "") or ""),
            str(training.get("model_info", "") or ""),
        ]
        self._training_detail.setText(" | ".join(bit for bit in training_bits if bit) or "-")
        historical_bits = [
            str(historical.get("scan_status", "") or ""),
            str(historical.get("note", "") or ""),
        ]
        self._historical_detail.setText(" | ".join(bit for bit in historical_bits if bit) or "-")

    def retranslate_ui(self):
        self._title.setText(tr("ML Center"))
        self._refresh.setText(tr("Refresh"))
        self._family_table.setHorizontalHeaderLabels(self._FAMILY_COLUMNS)
        self._alerts_table.setHorizontalHeaderLabels(self._ALERT_COLUMNS)
        set_table_empty_message(self._family_table, tr("No family readiness rows are available."))
        set_table_empty_message(self._alerts_table, tr("No ML alerts are available."))
        self._update_summary_card()
