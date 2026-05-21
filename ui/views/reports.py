from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ui import backend_facade
from ui.components import configure_table, make_badge, set_table_empty_message
from ui.i18n import tr
from ui.theme import badge_style
from ui.workers import RefreshController


class ReportsView(QWidget):
    def __init__(self, config_path: str | None = None):
        super().__init__()
        self._config_path = config_path
        self._controller = RefreshController(self)
        self._current_preview_path = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header = QHBoxLayout()
        self._title = QLabel(tr("Reports"))
        self._title.setObjectName("pageTitle")
        self._summary = QLabel("")
        self._summary.setObjectName("badge")
        self._summary.setStyleSheet(badge_style("read_only"))
        self._refresh = QPushButton(tr("Refresh"))
        self._refresh.clicked.connect(self.refresh)
        header.addWidget(self._title)
        header.addStretch(1)
        header.addWidget(self._summary)
        header.addWidget(self._refresh)

        self._tabs = QTabWidget()

        self._artifacts_table = QTableWidget(0, 6)
        self._artifacts_table.setHorizontalHeaderLabels(["name", "path", "kind", "size", "modified", "readable"])
        configure_table(self._artifacts_table)
        set_table_empty_message(self._artifacts_table, tr("No report artifacts were found in the workspace."))
        self._artifacts_table.itemSelectionChanged.connect(self._load_selected_preview)
        artifacts_tab = QWidget()
        artifacts_layout = QVBoxLayout(artifacts_tab)
        self._status_note = QLabel(tr("Browse available report artifacts and inspect a redacted preview."))
        self._status_note.setWordWrap(True)
        self._artifacts_summary = QLabel(tr("No report artifacts loaded."))
        artifacts_layout.addWidget(self._status_note)
        artifacts_layout.addWidget(self._artifacts_summary)
        artifacts_layout.addWidget(self._artifacts_table, 1)

        preview_tab = QWidget()
        preview_layout = QVBoxLayout(preview_tab)
        preview_meta = QHBoxLayout()
        self._preview_status = QLabel(tr("No report selected."))
        preview_meta.addWidget(self._preview_status)
        preview_meta.addStretch(1)
        self._preview_note = QLabel(tr("Preview is read-only. Secrets are redacted before display."))
        self._preview_note.setWordWrap(True)
        self._preview_only_badge = make_badge(tr("PREVIEW ONLY"), "read_only")
        self._preview_text = QPlainTextEdit()
        self._preview_text.setReadOnly(True)
        self._preview_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        preview_layout.addLayout(preview_meta)
        preview_layout.addWidget(self._preview_only_badge)
        preview_layout.addWidget(self._preview_note)
        preview_layout.addWidget(self._preview_text, 1)

        layout.addLayout(header)
        self._tabs.addTab(artifacts_tab, tr("Report Artifacts"))
        self._tabs.addTab(preview_tab, tr("Preview"))
        layout.addWidget(self._tabs, 1)

        self.refresh()

    def refresh(self):
        self._refresh.setEnabled(False)
        self._summary.setText(tr("Loading..."))
        self._controller.trigger(
            task=lambda: backend_facade.collect_reports_summary(config_path=self._config_path),
            on_result=self._apply_payload,
            on_error=lambda error: self._summary.setText(error.get("message", "error")),
            on_finished=lambda: self._refresh.setEnabled(True),
        )

    def _apply_payload(self, payload: dict):
        self._summary.setText(tr("empty") if payload.get("empty") else payload.get("status", "unknown"))
        self._summary.setStyleSheet(badge_style("read_only" if payload.get("empty") else "ok"))
        artifacts = backend_facade.collect_report_artifacts()
        self._apply_artifacts(artifacts)
        items = list(artifacts.get("artifacts", []) or [])
        paths = {str(item.get("path", "") or "") for item in items}
        if self._current_preview_path not in paths:
            self._current_preview_path = str(items[0].get("path", "") or "") if items else ""
        if self._current_preview_path:
            self._apply_report_preview(backend_facade.collect_report_preview(self._current_preview_path))
        else:
            self._preview_status.setText(tr("No report selected."))
            self._preview_text.setPlainText("")

    def _apply_artifacts(self, payload: dict):
        artifacts = list(payload.get("artifacts", []) or [])
        self._artifacts_summary.setText(f"{len(artifacts)} {tr('artifact(s) found.')}")
        self._artifacts_table.setRowCount(len(artifacts))
        for row_index, item in enumerate(artifacts):
            values = [
                item.get("name", ""),
                item.get("path", ""),
                item.get("kind", ""),
                item.get("size", 0),
                item.get("modified_text", ""),
                tr("yes") if item.get("readable") else tr("no"),
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if column == 1:
                    cell.setToolTip(str(item.get("path", "")))
                self._artifacts_table.setItem(row_index, column, cell)
        if artifacts:
            self._artifacts_table.selectRow(0)

    def _load_selected_preview(self):
        row = self._artifacts_table.currentRow()
        if row < 0:
            return
        item = self._artifacts_table.item(row, 1)
        if item is None:
            return
        self._current_preview_path = item.text().strip()
        self._tabs.setCurrentIndex(1)
        self._apply_report_preview(backend_facade.collect_report_preview(self._current_preview_path))

    def _apply_report_preview(self, payload: dict):
        status = payload.get("status", "unknown")
        kind = payload.get("kind", "unknown")
        truncated = bool(payload.get("truncated", payload.get("trun" "cated", False)))
        path = payload.get("path", "")
        suffix = f" | {tr('truncated')}" if truncated else ""
        self._preview_status.setText(f"{status} | {kind} | {path}{suffix}")
        self._preview_text.setPlainText(str(payload.get("preview", "") or payload.get("error", "")))

    def retranslate_ui(self):
        self._title.setText(tr("Reports"))
        self._refresh.setText(tr("Refresh"))
        self._status_note.setText(tr("Browse available report artifacts and inspect a redacted preview."))
        self._preview_note.setText(tr("Preview is read-only. Secrets are redacted before display."))
        self._tabs.setTabText(0, tr("Report Artifacts"))
        self._tabs.setTabText(1, tr("Preview"))
        set_table_empty_message(self._artifacts_table, tr("No report artifacts were found in the workspace."))
