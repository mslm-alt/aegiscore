from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from ui import backend_facade
from ui.components import make_metric_card
from ui.i18n import tr
from ui.theme import badge_style
from ui.workers import RefreshController


class OverviewView(QWidget):
    def __init__(self, config_path: str | None = None):
        super().__init__()
        self._config_path = config_path
        self._controller = RefreshController(self, interval_ms=12000)
        self._metric_labels: dict[str, QLabel] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header = QHBoxLayout()
        self._title = QLabel(tr("Overview"))
        self._title.setObjectName("pageTitle")
        self._status = QLabel(tr("Ready"))
        self._status.setObjectName("badge")
        self._status.setStyleSheet(badge_style("read_only"))
        self._refresh = QPushButton(tr("Refresh"))
        self._refresh.clicked.connect(self.refresh)
        header.addWidget(self._title)
        header.addStretch(1)
        header.addWidget(self._status)
        header.addWidget(self._refresh)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        specs = [
            ("db_health", "DB health"),
            ("alert_count", "Alert count"),
            ("open_incidents", "Open incidents"),
            ("phase", "Phase"),
            ("ml_paused", "ML paused"),
            ("source_problems", "Source problems"),
            ("security_locks", "Read-only locks"),
        ]
        for index, (key, label) in enumerate(specs):
            card = make_metric_card(tr(label), "...", tr("Read-only snapshot"))
            self._metric_labels[key] = card.findChild(QLabel, "value")
            grid.addWidget(card, index // 3, index % 3)

        layout.addLayout(header)
        layout.addLayout(grid)
        layout.addStretch(1)

        self._controller.configure(
            task=lambda: backend_facade.collect_overview_status(self._config_path),
            on_result=self._apply_payload,
            on_error=self._apply_error,
            on_finished=lambda: self._set_loading(False),
        )
        self.refresh()
        self._controller.start()

    def refresh(self):
        self._set_loading(True)
        self._controller.trigger()

    def _set_loading(self, loading: bool):
        self._refresh.setEnabled(not loading)
        self._status.setText(tr("Loading...") if loading else tr("Ready"))

    def _apply_payload(self, payload: dict):
        db = dict(payload.get("database", {}) or {})
        locks = dict(payload.get("security_locks", {}) or {})
        ml_paused = payload.get("ml_paused")
        ml_pause_known = bool(payload.get("ml_pause_known", False))
        ml_pause_reason = str(payload.get("ml_pause_reason", "") or "")
        if ml_pause_known:
            ml_paused_text = "Yes" if bool(ml_paused) else "No"
        else:
            ml_paused_text = "Unknown"
        mapping = {
            "db_health": db.get("status", "unknown"),
            "alert_count": str(payload.get("alert_count", 0)),
            "open_incidents": str(payload.get("open_incidents", 0)),
            "phase": str(payload.get("phase", "PHASE_0")),
            "ml_paused": ml_paused_text,
            "source_problems": str(payload.get("source_problem_count", 0)),
            "security_locks": "active" if all(bool(locks.get(key, False)) for key in ("read_only_mode", "auto_ip_block_disabled", "manual_actions_locked")) else "check",
        }
        for key, value in mapping.items():
            self._metric_labels[key].setText(value)
        self._metric_labels["ml_paused"].setToolTip(ml_pause_reason or ("ML pause state unavailable." if not ml_pause_known else "ML is not paused."))
        overall = str(payload.get("overall", "WARNING") or "WARNING").lower()
        self._status.setText(overall.upper())
        self._status.setStyleSheet(badge_style(overall))

    def _apply_error(self, error: dict):
        self._status.setText(error.get("message", "error"))

    def retranslate_ui(self):
        self._title.setText(tr("Overview"))
        self._refresh.setText(tr("Refresh"))
