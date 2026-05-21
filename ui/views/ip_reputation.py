from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
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


class IPReputationView(QWidget):
    def __init__(self, config_path: str | None = None):
        super().__init__()
        self._config_path = config_path
        self._status_controller = RefreshController(self)
        self._candidates_controller = RefreshController(self)
        self._candidates: list[dict] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title_row = QHBoxLayout()
        self._title = QLabel(tr("IP Blocking"))
        self._title.setObjectName("pageTitle")
        self._status_label = QLabel(tr("Ready"))
        self._status_label.setObjectName("badge")
        self._status_label.setStyleSheet(badge_style("read_only"))
        self._refresh_all = QPushButton(tr("Refresh All"))
        self._refresh_all.clicked.connect(self.refresh_all)
        title_row.addWidget(self._title)
        title_row.addStretch(1)
        title_row.addWidget(self._status_label)
        title_row.addWidget(self._refresh_all)

        self._summary_card = QFrame()
        self._summary_card.setObjectName("card")
        summary_layout = QGridLayout(self._summary_card)
        summary_layout.setContentsMargins(16, 16, 16, 16)
        summary_layout.setHorizontalSpacing(16)
        summary_layout.setVerticalSpacing(8)
        self._backend_label = QLabel(tr("Backend"))
        self._mode_label = QLabel(tr("Blocking mode"))
        self._capability_label = QLabel(tr("Backend Capability"))
        self._backend_value = QLabel("-")
        self._mode_value = QLabel("-")
        self._capability_value = QLabel("-")
        summary_layout.addWidget(self._backend_label, 0, 0)
        summary_layout.addWidget(self._backend_value, 0, 1)
        summary_layout.addWidget(self._mode_label, 1, 0)
        summary_layout.addWidget(self._mode_value, 1, 1)
        summary_layout.addWidget(self._capability_label, 2, 0)
        summary_layout.addWidget(self._capability_value, 2, 1)

        self._safety_note = QLabel(tr("Automatic blocking is disabled. Only manual block/unblock is allowed."))
        self._safety_note.setWordWrap(True)
        self._detail_note = QLabel("")
        self._detail_note.setObjectName("mutedText")
        self._detail_note.setWordWrap(True)

        actions = QHBoxLayout()
        self._block_button = QPushButton(tr("Block"))
        self._block_button.setEnabled(False)
        self._block_button.clicked.connect(lambda: self._run_action("block"))
        self._unblock_button = QPushButton(tr("Unblock"))
        self._unblock_button.setEnabled(False)
        self._unblock_button.clicked.connect(lambda: self._run_action("unblock"))
        actions.addWidget(self._block_button)
        actions.addWidget(self._unblock_button)
        actions.addStretch(1)

        self._table = QTableWidget(0, len(self._column_labels()))
        self._table.setHorizontalHeaderLabels(self._column_labels())
        configure_table(self._table)
        set_table_empty_message(self._table, tr("No IP blocking candidates are available."))
        self._table.itemSelectionChanged.connect(self._update_action_state)

        layout.addLayout(title_row)
        layout.addWidget(self._summary_card)
        layout.addWidget(self._safety_note)
        layout.addLayout(actions)
        layout.addWidget(self._table, 1)
        layout.addWidget(self._detail_note)

        self.refresh_all()

    @staticmethod
    def _column_labels() -> list[str]:
        return [
            tr("Time"),
            tr("IP address"),
            tr("Reason"),
            tr("Linked Alert"),
            tr("Severity / Risk"),
            tr("Status"),
            tr("Backend"),
        ]

    @staticmethod
    def _status_text(item: dict) -> str:
        mapping = {
            "blocked": tr("Blocked"),
            "guarded": tr("Guarded"),
            "unsupported_backend": tr("Unsupported backend"),
            "not_blocked": tr("Not blocked"),
        }
        return mapping.get(str(item.get("status", "") or ""), str(item.get("status_text", "") or ""))

    def refresh_all(self):
        self._status_label.setText(tr("Loading..."))
        self._status_controller.trigger(
            task=lambda: backend_facade.collect_ip_reputation_status(config_path=self._config_path),
            on_result=self._apply_status_payload,
            on_error=lambda error: self._status_label.setText(error.get("message", "status error")),
        )
        self._candidates_controller.trigger(
            task=lambda: backend_facade.collect_ip_block_candidates(config_path=self._config_path),
            on_result=self._apply_candidates_payload,
            on_error=lambda error: self._detail_note.setText(error.get("message", "candidates error")),
        )

    def load_ip_context(self, ip: str):
        self._focus_candidate(str(ip or "").strip())

    def prepare_manual_action(self, ip: str, action: str = "block"):
        value = str(ip or "").strip()
        if self._focus_candidate(value):
            self._run_action(action)
            return
        self._run_action(action, target_ip=value)

    def _apply_status_payload(self, payload: dict):
        blocking = dict(payload.get("ip_blocking", {}) or {})
        status = str(payload.get("status", "unknown") or "unknown").lower()
        self._status_label.setText(status.upper())
        self._status_label.setStyleSheet(badge_style("ok" if status == "ok" else "degraded"))
        self._backend_value.setText(str(blocking.get("backend", "") or "auto"))
        self._mode_value.setText(str(blocking.get("mode", "") or "manual_only"))
        if bool(blocking.get("real_apply_supported", False)):
            self._capability_value.setText(tr("Real apply supported"))
        elif bool(blocking.get("requires_elevation", False)):
            self._capability_value.setText(tr("AegisCore must be run with elevated privileges to apply firewall rules."))
        else:
            self._capability_value.setText(tr("Real blocking is not supported by the current firewall backend."))

    def _apply_candidates_payload(self, payload: dict):
        self._candidates = list(payload.get("candidates", []) or [])
        self._table.setRowCount(len(self._candidates))
        for row, item in enumerate(self._candidates):
            rule_id = str(item.get("rule_id", "") or "")
            alert_id = item.get("alert_id")
            linked_alert = rule_id or (f"alert:{alert_id}" if alert_id not in (None, "") else "-")
            risk_score = item.get("risk_score", "")
            severity_risk = str(item.get("severity", "") or "").upper()
            if risk_score not in ("", None):
                severity_risk = f"{severity_risk}/{float(risk_score or 0.0):.1f}" if severity_risk else f"{float(risk_score or 0.0):.1f}"
            values = [
                item.get("timestamp_text", ""),
                item.get("ip", ""),
                item.get("reason", ""),
                linked_alert,
                severity_risk or "-",
                self._status_text(item),
                item.get("backend", ""),
            ]
            for column, value in enumerate(values):
                self._table.setItem(row, column, QTableWidgetItem(str(value)))
        if self._candidates:
            self._table.selectRow(0)
        else:
            self._detail_note.setText(tr("No IP blocking candidates are available."))
            self._update_action_state()

    def _selected_candidate(self) -> dict | None:
        indexes = self._table.selectionModel().selectedRows() if self._table.selectionModel() else []
        if not indexes:
            return None
        row = indexes[0].row()
        if row < 0 or row >= len(self._candidates):
            return None
        return self._candidates[row]

    def _focus_candidate(self, ip: str) -> bool:
        target = str(ip or "").strip()
        for row, item in enumerate(self._candidates):
            if str(item.get("ip", "") or "").strip() == target:
                self._table.selectRow(row)
                return True
        self._detail_note.setText(tr("The selected IP is not in the current candidate list."))
        return False

    def _update_action_state(self):
        item = self._selected_candidate()
        if not item:
            self._block_button.setEnabled(False)
            self._unblock_button.setEnabled(False)
            return
        self._block_button.setEnabled(bool(item.get("can_block", False)))
        self._unblock_button.setEnabled(bool(item.get("can_unblock", False)))
        summary = [
            str(item.get("ip", "") or ""),
            str(item.get("reason", "") or ""),
            self._status_text(item),
            str(item.get("backend_capability", "") or ""),
        ]
        self._detail_note.setText(" | ".join(bit for bit in summary if bit))

    def _run_action(self, action: str, target_ip: str | None = None):
        item = self._selected_candidate()
        ip = str(target_ip or (item or {}).get("ip", "") or "").strip()
        if not ip:
            return
        reason, accepted = QInputDialog.getText(self, tr("Reason"), tr("Reason"))
        if not accepted or not str(reason or "").strip():
            return

        preview_seed = backend_facade.preview_ip_action(
            action=action,
            ip=ip,
            actor="local-user",
            role="admin",
            reason=str(reason).strip(),
            confirmation="",
            dry_run_completed=True,
            config_path=self._config_path,
        )
        capability = dict(preview_seed.get("capability", {}) or {})
        if not bool(capability.get("real_apply_supported", False)):
            message = (
                tr("AegisCore must be run with elevated privileges to apply firewall rules.")
                if bool(capability.get("requires_elevation", False))
                else tr("Real blocking is not supported by the current firewall backend.")
            )
            QMessageBox.warning(self, tr("IP Blocking"), message)
            return
        request_meta = dict(dict(preview_seed.get("guard", {}) or {}).get("metadata", {}) or {}).get("request", {}) or {}
        required_confirmation = str(request_meta.get("required_confirmation_phrase", f"CONFIRM IP_{action.upper()} {ip}") or f"CONFIRM IP_{action.upper()} {ip}")
        confirmation, accepted = QInputDialog.getText(self, tr("Typed confirmation"), required_confirmation)
        if not accepted:
            return

        preview = backend_facade.preview_ip_action(
            action=action,
            ip=ip,
            actor="local-user",
            role="admin",
            reason=str(reason).strip(),
            confirmation=str(confirmation).strip(),
            dry_run_completed=True,
            config_path=self._config_path,
        )
        guard = dict(preview.get("guard", {}) or {})
        if str(preview.get("status", "")) != "ready" or not bool(guard.get("execution_enabled", False)):
            QMessageBox.warning(self, tr("IP Blocking"), str(preview.get("message", guard.get("message", "Guard validation failed."))))
            return

        result = backend_facade.execute_ip_action(
            action=action,
            ip=ip,
            actor="local-user",
            role="admin",
            reason=str(reason).strip(),
            confirmation=str(confirmation).strip(),
            dry_run_completed=True,
            config_path=self._config_path,
        )
        status = str(result.get("status", "") or "")
        message = str(result.get("message", "") or status)
        if status == "executed":
            QMessageBox.information(self, tr("IP Blocking"), message)
        else:
            QMessageBox.warning(self, tr("IP Blocking"), message)
        self.refresh_all()
        self._focus_candidate(ip)

    def retranslate_ui(self):
        self._title.setText(tr("IP Blocking"))
        self._refresh_all.setText(tr("Refresh All"))
        self._safety_note.setText(tr("Automatic blocking is disabled. Only manual block/unblock is allowed."))
        self._backend_label.setText(tr("Backend"))
        self._mode_label.setText(tr("Blocking mode"))
        self._capability_label.setText(tr("Backend Capability"))
        self._block_button.setText(tr("Block"))
        self._unblock_button.setText(tr("Unblock"))
        self._table.setHorizontalHeaderLabels(self._column_labels())
        set_table_empty_message(self._table, tr("No IP blocking candidates are available."))
