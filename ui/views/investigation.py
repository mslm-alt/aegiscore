from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ui import backend_facade
from ui.components import configure_table, set_table_empty_message
from ui.i18n import tr
from ui.models import ViewMetric
from ui.theme import severity_color
from ui.workers import RefreshController
from PySide6.QtGui import QColor, QBrush


class InvestigationView(QWidget):
    def __init__(self, config_path: str | None = None):
        super().__init__()
        self._config_path = config_path
        self._controller = RefreshController(self)
        self._metric_labels: dict[str, QLabel] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header = QHBoxLayout()
        self._title = QLabel(tr("Investigation"))
        self._title.setObjectName("pageTitle")
        self._entity = QLineEdit()
        self._entity.setPlaceholderText(tr("Entity, source IP, target IP..."))
        self._limit = QComboBox()
        self._limit.addItems(["25", "50", "100", "200"])
        self._limit.setCurrentText("100")
        self._status = QLabel(tr("Ready"))
        self._search = QPushButton(tr("Load timeline"))
        self._search.clicked.connect(self.load_timeline)
        header.addWidget(self._title)
        header.addStretch(1)
        header.addWidget(self._entity, 1)
        header.addWidget(self._limit)
        header.addWidget(self._status)
        header.addWidget(self._search)

        grid = QGridLayout()
        for index, key in enumerate(("total_events", "high_critical_count", "first_seen", "last_seen", "top_rules", "top_entities", "top_source_ips", "status_note")):
            card = self._build_card(key.replace("_", " "))
            self._metric_labels[key] = card.findChild(QLabel, "value")
            grid.addWidget(card, index // 4, index % 4)

        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(["#", "timestamp", "severity", "rule_id", "entity/source_ip", "message"])
        configure_table(self._table)
        set_table_empty_message(self._table, tr("Load a timeline to inspect related alert activity."))

        layout.addLayout(header)
        layout.addLayout(grid)
        layout.addWidget(self._table, 1)

    def _build_card(self, label_text: str) -> QWidget:
        card = QWidget()
        layout = QVBoxLayout(card)
        name = QLabel(label_text.title())
        name.setObjectName("sectionTitle")
        value = QLabel("...")
        value.setObjectName("value")
        value.setWordWrap(True)
        layout.addWidget(name)
        layout.addWidget(value)
        return card

    def load_timeline(self):
        self._search.setEnabled(False)
        self._status.setText(tr("Loading..."))
        self._controller.trigger(
            task=lambda: backend_facade.collect_entity_timeline(
                self._entity.text(),
                limit=int(self._limit.currentText()),
                config_path=self._config_path,
            ),
            on_result=self._apply_payload,
            on_error=lambda error: self._status.setText(error.get("message", "error")),
            on_finished=lambda: self._search.setEnabled(True),
        )

    def _apply_payload(self, payload: dict):
        self._status.setText(payload.get("status", "unknown"))
        summary = dict(payload.get("summary", {}) or {})
        metrics = {
            "total_events": str(summary.get("total_events", 0)),
            "high_critical_count": str(summary.get("high_critical_count", 0)),
            "first_seen": summary.get("first_seen", ""),
            "last_seen": summary.get("last_seen", ""),
            "top_rules": ", ".join(
                f"{item.get('rule_id', '')}({item.get('count', 0)})"
                for item in summary.get("top_rules", [])
            ),
            "top_entities": ", ".join(
                f"{item.get('entity', '')}({item.get('count', 0)})"
                for item in summary.get("top_entities", [])
            ),
            "top_source_ips": ", ".join(
                f"{item.get('source_ip', '')}({item.get('count', 0)})"
                for item in summary.get("top_source_ips", [])
            ),
            "status_note": summary.get("status_note", ""),
        }
        for key, value in metrics.items():
            self._metric_labels[key].setText(ViewMetric(label=key, value=value).value)
        events = list(payload.get("events", []) or [])
        self._table.setRowCount(len(events))
        for row_index, event in enumerate(events):
            values = [
                row_index + 1,
                event.get("timestamp_text", ""),
                event.get("severity", ""),
                event.get("rule_id", ""),
                event.get("entity", "") or event.get("source_ip", ""),
                event.get("message", ""),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 2:
                    item.setForeground(QBrush(QColor(severity_color(str(event.get("severity", "unknown"))))))
                self._table.setItem(row_index, column, item)

    def retranslate_ui(self):
        self._title.setText(tr("Investigation"))
        self._entity.setPlaceholderText(tr("Entity, source IP, target IP..."))
        self._search.setText(tr("Load timeline"))
        set_table_empty_message(self._table, tr("Load a timeline to inspect related alert activity."))
