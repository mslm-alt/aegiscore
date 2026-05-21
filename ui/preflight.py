from __future__ import annotations

from PySide6.QtCore import Qt, QThreadPool, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ui.backend_facade import collect_preflight_status
from ui.components import make_badge, make_metric_card
from ui.i18n import tr
from ui.theme import badge_style
from ui.workers import FunctionWorker


class PreflightWindow(QWidget):
    continue_requested = Signal(dict)

    def __init__(self, config_path: str | None = None, auto_load: bool = True):
        super().__init__()
        self._config_path = config_path
        self._preflight_data: dict = {}
        self._thread_pool = QThreadPool.globalInstance()

        self.setWindowTitle(tr("AegisCore - Startup Preflight"))
        self.resize(920, 640)

        outer = QVBoxLayout(self)
        self.setObjectName("preflightRoot")
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(16)

        self._title = QLabel(tr("AegisCore Startup Preflight"))
        self._title.setObjectName("title")
        self._subtitle = QLabel(tr("Read-only desktop UI checks system, distro, DB, and security locks before startup."))
        self._subtitle.setWordWrap(True)

        self._overall_badge = QLabel(tr("LOADING"))
        self._overall_badge.setObjectName("overallBadge")
        self._overall_message = QLabel(tr("Loading..."))
        self._overall_message.setWordWrap(True)

        summary_row = QHBoxLayout()
        summary_row.addWidget(self._overall_badge, 0, Qt.AlignmentFlag.AlignLeft)
        summary_row.addWidget(self._overall_message, 1)

        cards_row = QHBoxLayout()
        self._summary_cards = {
            "overall": make_metric_card(tr("Overall"), tr("LOADING"), tr("Startup safety gates")),
            "checks": make_metric_card(tr("Checks"), "0", tr("Loaded checks")),
            "locks": make_metric_card(tr("Security Locks"), "0", tr("Read-only security locks")),
        }
        for widget in self._summary_cards.values():
            cards_row.addWidget(widget, 1)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(3)
        self._tree.setHeaderLabels([tr("Check"), tr("Status"), tr("Message")])
        self._tree.setRootIsDecorated(False)
        self._tree.setAlternatingRowColors(True)
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self._tree.setUniformRowHeights(False)

        locks_frame = QFrame()
        locks_layout = QVBoxLayout(locks_frame)
        locks_layout.setContentsMargins(14, 14, 14, 14)
        locks_layout.setSpacing(8)
        self._locks_title = QLabel(tr("Security Locks"))
        self._locks_title.setObjectName("sectionTitle")
        self._locks_label = QLabel(tr("Not loaded yet."))
        self._locks_label.setWordWrap(True)
        self._locks_badges = QHBoxLayout()
        self._locks_badges.setSpacing(8)
        locks_layout.addWidget(self._locks_title)
        locks_layout.addWidget(self._locks_label)
        locks_layout.addLayout(self._locks_badges)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        self._continue_anyway = QPushButton(tr("Continue anyway (read-only)"))
        self._continue_anyway.setVisible(False)
        self._continue_anyway.setEnabled(False)
        self._continue_anyway.clicked.connect(self._emit_continue)

        self._continue_button = QPushButton(tr("Continue to AegisCore"))
        self._continue_button.setEnabled(False)
        self._continue_button.clicked.connect(self._emit_continue)

        button_row.addWidget(self._continue_anyway)
        button_row.addWidget(self._continue_button)

        outer.addWidget(self._title)
        outer.addWidget(self._subtitle)
        outer.addLayout(summary_row)
        outer.addLayout(cards_row)
        outer.addWidget(self._tree, 1)
        outer.addWidget(locks_frame)
        outer.addLayout(button_row)

        if auto_load:
            self._load_preflight()

    @staticmethod
    def _metric_value_label(card: QWidget | None) -> QLabel | None:
        if card is None:
            return None
        for object_name in ("value", "metricValue"):
            widget = card.findChild(QLabel, object_name)
            if widget is not None:
                return widget
        return None

    def _load_preflight(self) -> None:
        worker = FunctionWorker(collect_preflight_status, self._config_path)
        worker.signals.result.connect(self._apply_preflight)
        worker.signals.error.connect(self._apply_worker_error)
        self._thread_pool.start(worker)

    def _apply_worker_error(self, error: dict) -> None:
        self._apply_preflight({
            "overall": "BLOCKED",
            "checks": [{
                "name": tr("Startup Preflight"),
                "status": "BLOCKED",
                "message": tr("Unexpected worker error occurred."),
                "details": error,
                "suggestion": tr("Verify the Python environment and backend imports."),
            }],
            "security_locks": {
                "read_only_mode": True,
                "auto_ip_block_disabled": True,
                "ml_no_action_contract": False,
                "manual_actions_locked": True,
            },
        })

    def _apply_preflight(self, payload: dict) -> None:
        self._preflight_data = dict(payload or {})
        overall = str(self._preflight_data.get("overall", "WARNING") or "WARNING").upper()
        if self._overall_badge is not None:
            self._overall_badge.setText(overall)
            self._overall_badge.setStyleSheet(badge_style(overall.lower()))
        if self._overall_message is not None:
            self._overall_message.setText(self._overall_text(overall))
        overall_value = self._metric_value_label(self._summary_cards.get("overall"))
        if overall_value is not None:
            overall_value.setText(overall)
        checks_value = self._metric_value_label(self._summary_cards.get("checks"))
        if checks_value is not None:
            checks_value.setText(str(len(self._preflight_data.get("checks", []) or [])))
        self._tree.clear()

        for item in list(self._preflight_data.get("checks", []) or []):
            tree_item = QTreeWidgetItem([
                str(item.get("name", "") or ""),
                str(item.get("status", "") or ""),
                str(item.get("message", "") or ""),
            ])
            color = self._status_color(str(item.get("status", "WARNING") or "WARNING"))
            tree_item.setForeground(1, color)
            details = item.get("details", {})
            suggestion = str(item.get("suggestion", "") or "")
            if details or suggestion:
                child_lines = []
                if details:
                    child_lines.append(str(details))
                if suggestion:
                    child_lines.append(f"{tr('Suggestion')}: {suggestion}")
                child = QTreeWidgetItem([tr("Details"), "", "\n".join(child_lines)])
                tree_item.addChild(child)
            self._tree.addTopLevelItem(tree_item)

        self._tree.expandAll()
        locks = dict(self._preflight_data.get("security_locks", {}) or {})
        lock_count = sum(1 for key in ("read_only_mode", "auto_ip_block_disabled", "ml_no_action_contract", "manual_actions_locked") if locks.get(key))
        locks_value = self._metric_value_label(self._summary_cards.get("locks"))
        if locks_value is not None:
            locks_value.setText(str(lock_count))
        if self._locks_label is not None:
            self._locks_label.setText(
                " | ".join([
                    f"{tr('Read-only mode')}={self._bool_text(locks.get('read_only_mode', False))}",
                    f"{tr('Auto IP block disabled')}={self._bool_text(locks.get('auto_ip_block_disabled', False))}",
                    f"{tr('ML no-action contract')}={self._bool_text(locks.get('ml_no_action_contract', False))}",
                    f"{tr('Manual actions locked')}={self._bool_text(locks.get('manual_actions_locked', False))}",
                ])
            )
        while self._locks_badges.count():
            item = self._locks_badges.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for text, enabled in (
            (tr("READ ONLY"), locks.get("read_only_mode", False)),
            (tr("Auto block off"), locks.get("auto_ip_block_disabled", False)),
            (tr("ML no-action"), locks.get("ml_no_action_contract", False)),
            (tr("Manual lock"), locks.get("manual_actions_locked", False)),
        ):
            badge = make_badge(text, "pass" if enabled else "warning")
            if badge is not None:
                self._locks_badges.addWidget(badge)
        self._locks_badges.addStretch(1)

        self._continue_button.setEnabled(True)
        if overall == "BLOCKED":
            self._continue_button.setText(tr("Blocked"))
            self._continue_button.setEnabled(False)
            self._continue_anyway.setVisible(True)
            self._continue_anyway.setEnabled(True)
        else:
            self._continue_button.setText(tr("Continue to AegisCore"))
            self._continue_anyway.setVisible(False)
            self._continue_anyway.setEnabled(False)

    def _emit_continue(self) -> None:
        self.continue_requested.emit(self._preflight_data)

    @staticmethod
    def _status_color(status: str) -> QColor:
        token = str(status or "").strip().upper()
        if token == "PASS":
            return QColor("#3ddc97")
        if token == "BLOCKED":
            return QColor("#ff6b6b")
        return QColor("#f6c453")

    @staticmethod
    def _bool_text(value: bool) -> str:
        return tr("Enabled") if value else tr("Disabled")

    @staticmethod
    def _overall_text(status: str) -> str:
        token = str(status or "").strip().upper()
        if token == "PASS":
            return tr("Preflight checks passed. The UI can open safely in read-only mode.")
        if token == "BLOCKED":
            return tr("A critical preflight issue was detected. You can still continue in read-only mode if needed.")
        return tr("Some checks returned warnings. The UI can open in read-only mode, but review the details first.")
