from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from ui import backend_facade
from ui.i18n import tr
from ui.workers import RefreshController


class SourcesView(QWidget):
    def __init__(self, config_path: str | None = None):
        super().__init__()
        self._config_path = config_path
        self._controller = RefreshController(self)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header = QHBoxLayout()
        self._title = QLabel(tr("Sources / Distro Health"))
        self._title.setObjectName("pageTitle")
        self._summary = QLabel("")
        self._refresh = QPushButton(tr("Refresh"))
        self._refresh.clicked.connect(self.refresh)
        header.addWidget(self._title)
        header.addStretch(1)
        header.addWidget(self._summary)
        header.addWidget(self._refresh)

        self._distro = QLabel("")
        self._problems = QLabel("")
        self._problems.setWordWrap(True)
        self._table = QTableWidget(0, 8)
        self._table.setHorizontalHeaderLabels(
            ["source", "status", "path", "exists", "readable", "service", "last_read", "quality"]
        )

        layout.addLayout(header)
        layout.addWidget(self._distro)
        layout.addWidget(self._table, 1)
        layout.addWidget(self._problems)

        self.refresh()

    def refresh(self):
        self._refresh.setEnabled(False)
        self._summary.setText(tr("Loading..."))
        self._controller.trigger(
            task=lambda: backend_facade.collect_sources_health(config_path=self._config_path),
            on_result=self._apply_payload,
            on_error=lambda error: self._summary.setText(error.get("message", "error")),
            on_finished=lambda: self._refresh.setEnabled(True),
        )

    def _apply_payload(self, payload: dict):
        distro = dict(payload.get("distro", {}) or {})
        rows = list(payload.get("sources", []) or [])
        self._summary.setText(payload.get("status", "unknown"))
        self._distro.setText(
            f"{distro.get('pretty', 'Unknown')} | family={distro.get('family', 'unknown')} | supported={distro.get('supported', False)}"
        )
        self._table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            quality = f"parse_fail={row.get('parse_fail_summary', {}).get('count', 0)} duplicate={row.get('duplicate_summary', {}).get('count', 0)}"
            values = [
                row.get("source", ""),
                row.get("status", ""),
                row.get("resolved_path", ""),
                str(row.get("path_exists", False)),
                str(row.get("readable", False)),
                str(row.get("service_active", "")),
                row.get("last_read_text", ""),
                quality,
            ]
            for column, value in enumerate(values):
                self._table.setItem(row_index, column, QTableWidgetItem(str(value)))
        self._problems.setText(f"{tr('Problems')}: " + "; ".join(payload.get("problems", []) or ["none"]))

    def retranslate_ui(self):
        self._title.setText(tr("Sources / Distro Health"))
        self._refresh.setText(tr("Refresh"))
