from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from ui import backend_facade
from ui.components import configure_table, make_badge, make_metric_chip, set_table_empty_message
from ui.i18n import tr
from ui.models import bounded_buffer
from ui.theme import badge_style
from ui.workers import RefreshController


class EventDetailDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("Event Details"))
        self.resize(760, 620)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self._title = QLabel(tr("Event detail"))
        self._title.setObjectName("sectionTitle")
        self._summary = QLabel("")
        self._summary.setWordWrap(True)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)
        self._fields: dict[str, QLabel] = {}
        rows = [
            ("Time", "time"),
            ("Source", "source"),
            ("Category", "category"),
            ("Action", "action"),
            ("Outcome", "outcome"),
            ("Host", "host"),
            ("Process", "process"),
            ("User", "username"),
            ("Source IP", "src_ip"),
        ]
        for row, (label_text, key) in enumerate(rows):
            grid.addWidget(QLabel(tr(label_text)), row, 0)
            value = QLabel("-")
            value.setWordWrap(True)
            grid.addWidget(value, row, 1)
            self._fields[key] = value

        self._message = QPlainTextEdit()
        self._message.setReadOnly(True)
        self._message.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self._advanced = QPlainTextEdit()
        self._advanced.setReadOnly(True)
        self._advanced.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        close_button = QPushButton(tr("Close"))
        close_button.clicked.connect(self.close)
        self._message_label = QLabel(tr("Message"))
        self._advanced_label = QLabel(tr("Advanced"))

        layout.addWidget(self._title)
        layout.addWidget(self._summary)
        layout.addLayout(grid)
        layout.addWidget(self._message_label)
        layout.addWidget(self._message, 1)
        layout.addWidget(self._advanced_label)
        layout.addWidget(self._advanced, 2)
        layout.addWidget(close_button, 0, Qt.AlignmentFlag.AlignRight)

    def retranslate_ui(self):
        self.setWindowTitle(tr("Event Details"))
        self._message_label.setText(tr("Message"))
        self._advanced_label.setText(tr("Advanced"))

    def render(self, payload: dict):
        event = dict(payload.get("event", {}) or {})
        detail = dict(payload.get("detail", {}) or {})
        self._title.setText(f"Event #{event.get('id', '-')}")
        self._summary.setText(
            f"{event.get('source', '')} | {event.get('category', '')} | {event.get('action', '')} | "
            f"{event.get('outcome', '')}"
        )
        mapping = {
            "time": str(event.get("timestamp_text", "") or "-"),
            "source": str(event.get("source", "") or "-"),
            "category": str(event.get("category", "") or "-"),
            "action": str(event.get("action", "") or "-"),
            "outcome": str(event.get("outcome", "") or "-"),
            "host": str(event.get("host", "") or "-"),
            "process": str(event.get("process", "") or "-"),
            "username": str(event.get("username", "") or "-"),
            "src_ip": str(event.get("src_ip", "") or "-"),
        }
        for key, value in mapping.items():
            self._fields[key].setText(value)
        self._message.setPlainText(str(event.get("message", "") or ""))
        self._advanced.setPlainText(backend_facade._stringify_payload({
            "event": event,
            "detail": detail,
        }))


class LiveLogsView(QWidget):
    _COLUMNS = ["time", "source", "category", "action", "outcome", "src_ip", "dst_ip", "username", "process", "message"]
    _MAX_BUFFER = 1000

    def __init__(self, config_path: str | None = None):
        super().__init__()
        self._config_path = config_path
        self._events: list[dict] = []
        self._visible_events: list[dict] = []
        self._refresh_controller = RefreshController(self, interval_ms=5000)
        self._sources_controller = RefreshController(self)
        self._health_controller = RefreshController(self)
        self._detail_controller = RefreshController(self)
        self._last_refresh_text = ""
        self._detail_dialog: EventDetailDialog | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self._title = QLabel(tr("Live Logs"))
        self._title.setObjectName("pageTitle")
        self._stream_state = make_badge("LIVE", "ok")
        self._buffer_state = make_badge("BUFFER 0", "read_only")
        self._source = QComboBox()
        self._source.addItem("all")
        self._query = QLineEdit()
        self._query.setPlaceholderText(tr("Search"))
        self._limit = QComboBox()
        self._limit.addItems(["100", "250", "500", "1000"])
        self._limit.setCurrentText("500")
        self._interval = QComboBox()
        self._interval.addItems(["3000", "5000", "10000"])
        self._interval.setCurrentText("5000")
        self._interval.currentIndexChanged.connect(self._update_interval)
        self._auto_refresh = QCheckBox(tr("Auto refresh"))
        self._auto_refresh.setChecked(True)
        self._auto_refresh.toggled.connect(self._toggle_auto_refresh)
        self._pause = QCheckBox(tr("Pause stream"))
        self._pause.toggled.connect(self._toggle_auto_refresh)
        self._refresh = QPushButton(tr("Refresh"))
        self._refresh.clicked.connect(self.refresh)
        self._clear = QPushButton(tr("Clear view"))
        self._clear.clicked.connect(self._clear_view)
        self._view_details = QPushButton(tr("View Details"))
        self._view_details.setEnabled(False)
        self._view_details.clicked.connect(self._show_selected_detail)
        title_row = QHBoxLayout()
        title_row.addWidget(self._title)
        title_row.addWidget(self._stream_state)
        title_row.addWidget(self._buffer_state)
        title_row.addStretch(1)
        title_row.addWidget(self._auto_refresh)
        title_row.addWidget(self._pause)
        title_row.addWidget(self._view_details)
        title_row.addWidget(self._refresh)
        title_row.addWidget(self._clear)

        filter_row = QHBoxLayout()
        self._source_label = QLabel(tr("Source"))
        self._query_label = QLabel(tr("Query"))
        self._limit_label = QLabel(tr("Limit"))
        self._interval_label = QLabel(tr("Interval"))
        filter_row.addWidget(self._source_label)
        filter_row.addWidget(self._source)
        filter_row.addWidget(self._query_label)
        filter_row.addWidget(self._query, 1)
        filter_row.addWidget(self._limit_label)
        filter_row.addWidget(self._limit)
        filter_row.addWidget(self._interval_label)
        filter_row.addWidget(self._interval)

        summary_grid = QGridLayout()
        summary_grid.setHorizontalSpacing(8)
        summary_grid.setVerticalSpacing(8)
        self._summary_labels: dict[str, QLabel] = {}
        for index, (key, label) in enumerate((
            ("total_shown", "Shown"),
            ("source_count", "Sources"),
            ("parse_fail", "Parse fail"),
            ("duplicate", "Duplicate"),
            ("last_refresh", "Last refresh"),
            ("status", "Status"),
        )):
            chip = make_metric_chip(tr(label), "...")
            self._summary_labels[key] = chip.findChild(QLabel, "chipValue")
            summary_grid.addWidget(chip, index // 3, index % 3)

        self._table = QTableWidget(0, len(self._COLUMNS))
        self._table.setHorizontalHeaderLabels(self._COLUMNS)
        configure_table(self._table)
        set_table_empty_message(self._table, tr("No events are visible for the current source and query."))
        self._table.itemSelectionChanged.connect(self._update_action_state)
        self._table.itemDoubleClicked.connect(lambda *_args: self._show_selected_detail())

        layout.addLayout(title_row)
        layout.addLayout(filter_row)
        layout.addLayout(summary_grid)
        layout.addWidget(self._table, 1)

        self._refresh_controller.configure(
            task=lambda: backend_facade.collect_recent_events(
                limit=int(self._limit.currentText()),
                source=None if self._source.currentText() == "all" else self._source.currentText(),
                query=self._query.text() or None,
                config_path=self._config_path,
            ),
            on_result=self._apply_events,
            on_error=lambda error: self._summary_labels["status"].setText(error.get("message", "error")),
        )
        self._toggle_auto_refresh()
        self._load_sources()
        self._load_health()
        self.refresh()

    def _update_interval(self):
        self._refresh_controller.set_interval(int(self._interval.currentText()))
        self._toggle_auto_refresh()

    def _toggle_auto_refresh(self):
        if self._auto_refresh.isChecked() and not self._pause.isChecked():
            self._refresh_controller.start()
            self._stream_state.setText("LIVE")
            self._stream_state.setStyleSheet(badge_style("ok"))
        else:
            self._refresh_controller.stop()
            self._stream_state.setText("PAUSED")
            self._stream_state.setStyleSheet(badge_style("locked"))

    def _clear_view(self):
        self._events = []
        self._visible_events = []
        self._table.setRowCount(0)
        self._view_details.setEnabled(False)
        self._summary_labels["total_shown"].setText("0")
        self._buffer_state.setText("BUFFER 0")

    def _load_sources(self):
        self._sources_controller.trigger(
            task=lambda: backend_facade.collect_live_log_sources(config_path=self._config_path),
            on_result=self._apply_sources,
            on_error=lambda error: None,
        )

    def _apply_sources(self, payload: dict):
        current = self._source.currentText()
        self._source.blockSignals(True)
        self._source.clear()
        for item in payload.get("sources", []):
            self._source.addItem(item)
        index = self._source.findText(current)
        self._source.setCurrentIndex(index if index >= 0 else 0)
        self._source.blockSignals(False)

    def _load_health(self):
        self._health_controller.trigger(
            task=lambda: backend_facade.collect_log_health_summary(config_path=self._config_path),
            on_result=self._apply_health,
            on_error=lambda error: self._summary_labels["status"].setText(error.get("message", "error")),
        )

    def _apply_health(self, payload: dict):
        self._summary_labels["parse_fail"].setText(
            str(dict(payload.get("parse_fail_summary", {}) or {}).get("count", 0))
        )
        duplicate = dict(payload.get("duplicate_summary", {}) or {})
        self._summary_labels["duplicate"].setText(
            str(int(duplicate.get("count", 0) or 0) + int(duplicate.get("telemetry_count", 0) or 0))
        )
        self._summary_labels["source_count"].setText(str(len(payload.get("sources", []) or [])))
        self._summary_labels["status"].setText(str(payload.get("status", "unknown") or "unknown").upper())

    def refresh(self):
        self._load_health()
        self._refresh_controller.trigger()

    def _apply_events(self, payload: dict):
        incoming = list(payload.get("events", []) or [])
        self._events = bounded_buffer(incoming, self._MAX_BUFFER)
        self._visible_events = list(self._events)
        self._table.setRowCount(len(self._visible_events))
        for row_index, item in enumerate(self._visible_events):
            values = [
                item.get("timestamp_text", ""),
                item.get("source", ""),
                item.get("category", ""),
                item.get("action", ""),
                item.get("outcome", ""),
                item.get("src_ip", ""),
                item.get("dst_ip", ""),
                item.get("username", ""),
                item.get("process", ""),
                item.get("message", ""),
            ]
            for column, value in enumerate(values):
                self._table.setItem(row_index, column, QTableWidgetItem(str(value)))
        self._last_refresh_text = backend_facade._coerce_timestamp_text(time.time()).split(" ")[-1]
        self._summary_labels["total_shown"].setText(str(len(self._visible_events)))
        self._summary_labels["last_refresh"].setText(self._last_refresh_text)
        self._summary_labels["status"].setText(str(payload.get("status", "unknown") or "unknown").upper())
        self._buffer_state.setText(f"BUFFER {len(self._events)}")
        if self._visible_events:
            self._table.selectRow(0)
        else:
            self._update_action_state()

    def _update_action_state(self):
        indexes = self._table.selectionModel().selectedRows() if self._table.selectionModel() else []
        if not indexes:
            self._view_details.setEnabled(False)
            return
        row = indexes[0].row()
        if row < 0 or row >= len(self._visible_events):
            self._view_details.setEnabled(False)
            return
        self._view_details.setEnabled(True)

    def _show_selected_detail(self):
        indexes = self._table.selectionModel().selectedRows() if self._table.selectionModel() else []
        if not indexes:
            return
        row = indexes[0].row()
        if row < 0 or row >= len(self._visible_events):
            return
        event = self._visible_events[row]
        if self._detail_dialog is None:
            self._detail_dialog = EventDetailDialog(self)
            self._detail_dialog.retranslate_ui()
        self._detail_dialog._title.setText("Loading event detail...")
        self._detail_dialog.show()
        self._detail_dialog.raise_()
        self._detail_dialog.activateWindow()
        event_id = event.get("id")
        if event_id in (None, ""):
            self._detail_dialog.render({"event": event, "detail": {}})
            return
        self._detail_controller.trigger(
            task=lambda: backend_facade.collect_event_detail(int(event_id), config_path=self._config_path),
            on_result=self._detail_dialog.render,
            on_error=lambda error: self._detail_dialog._advanced.setPlainText(error.get("message", "detail error")),
        )

    def retranslate_ui(self):
        self._title.setText(tr("Live Logs"))
        self._query.setPlaceholderText(tr("Search"))
        self._auto_refresh.setText(tr("Auto refresh"))
        self._pause.setText(tr("Pause stream"))
        self._refresh.setText(tr("Refresh"))
        self._clear.setText(tr("Clear view"))
        self._view_details.setText(tr("View Details"))
        self._source_label.setText(tr("Source"))
        self._query_label.setText(tr("Query"))
        self._limit_label.setText(tr("Limit"))
        self._interval_label.setText(tr("Interval"))
        set_table_empty_message(self._table, tr("No events are visible for the current source and query."))
        if self._detail_dialog is not None:
            self._detail_dialog.retranslate_ui()
