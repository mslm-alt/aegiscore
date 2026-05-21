from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

from ui.actions.models import GuardedActionRequest, GuardedActionResult
from ui.theme import badge_style


class GuardedActionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Guarded Action Preview")
        self.resize(720, 520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        self._status = QLabel("PREVIEW ONLY")
        self._status.setObjectName("badge")
        self._status.setStyleSheet(badge_style("read_only"))

        self._action = QLabel("-")
        self._target = QLabel("-")
        self._danger = QLabel("Phase 2 execution not enabled yet.")
        self._danger.setWordWrap(True)

        form = QFormLayout()
        form.addRow("Action", self._action)
        form.addRow("Target", self._target)
        form.addRow("Note", self._danger)

        self._reason = QLineEdit()
        self._reason.setPlaceholderText("Reason is required for Phase 2 execution")
        self._confirmation = QLineEdit()
        self._confirmation.setPlaceholderText("Typed confirmation required")
        self._dry_run = QLabel("Dry-run not completed")
        form.addRow("Reason", self._reason)
        form.addRow("Confirmation", self._confirmation)
        form.addRow("Dry-run", self._dry_run)

        self._required = QPlainTextEdit()
        self._required.setReadOnly(True)
        self._preview = QPlainTextEdit()
        self._preview.setReadOnly(True)

        button_row = QHBoxLayout()
        self._execute = QPushButton("Execute")
        self._execute.setEnabled(False)
        self._execute.setToolTip("Phase 2 execution not enabled yet")
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        button_row.addStretch(1)
        button_row.addWidget(self._execute)
        button_row.addWidget(close_button)

        layout.addWidget(self._status)
        layout.addLayout(form)
        layout.addWidget(QLabel("Required guards"))
        layout.addWidget(self._required, 1)
        layout.addWidget(QLabel("Preview result"))
        layout.addWidget(self._preview, 2)
        layout.addLayout(button_row)

    def load_request(self, request: GuardedActionRequest, result: GuardedActionResult):
        self._action.setText(request.action_type)
        self._target.setText(request.target)
        self._reason.setText(request.reason)
        self._confirmation.setText(request.confirmation_phrase)
        self._dry_run.setText("Completed" if request.dry_run_completed else "Not completed")
        self._status.setText(result.status.upper())
        self._status.setStyleSheet(badge_style("locked" if result.status == "locked" else "read_only"))
        self._execute.setEnabled(bool(result.execution_enabled))
        self._execute.setToolTip("Guarded execution ready" if result.execution_enabled else "Phase 2 execution not enabled yet")
        self._required.setPlainText("\n".join(result.required_guards))
        lines = [
            result.message,
            "",
            "would_do:",
            *[f"- {item}" for item in result.would_do],
            "",
            "missing_guards:",
            *[f"- {item}" for item in result.missing_guards],
        ]
        self._preview.setPlainText("\n".join(lines))
