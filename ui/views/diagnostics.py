from __future__ import annotations

from PySide6.QtWidgets import QGroupBox, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from ui import backend_facade
from ui.components import make_badge
from ui.i18n import tr
from ui.theme import badge_style
from ui.workers import RefreshController


class DiagnosticsView(QWidget):
    def __init__(self, config_path: str | None = None):
        super().__init__()
        self._config_path = config_path
        self._controller = RefreshController(self)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header = QHBoxLayout()
        self._title = QLabel(tr("Diagnostics"))
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

        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        self._text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._bundle_group = QGroupBox(tr("Diagnostic Bundle Preview"))
        bundle_layout = QVBoxLayout(self._bundle_group)
        bundle_header = QHBoxLayout()
        self._bundle_summary = QLabel(tr("Preview only. No bundle file will be created."))
        self._bundle_badge = make_badge(tr("PREVIEW ONLY"), "read_only")
        self._bundle_button = QPushButton(tr("Refresh"))
        self._bundle_button.clicked.connect(self._refresh_bundle_preview)
        bundle_header.addWidget(self._bundle_summary)
        bundle_header.addWidget(self._bundle_badge)
        bundle_header.addStretch(1)
        bundle_header.addWidget(self._bundle_button)
        self._bundle_text = QPlainTextEdit()
        self._bundle_text.setReadOnly(True)
        self._bundle_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        bundle_layout.addLayout(bundle_header)
        bundle_layout.addWidget(self._bundle_text)

        layout.addLayout(header)
        layout.addWidget(self._text, 1)
        layout.addWidget(self._bundle_group)

        self.refresh()

    def refresh(self):
        self._refresh.setEnabled(False)
        self._summary.setText(tr("Loading..."))
        self._controller.trigger(
            task=lambda: backend_facade.collect_diagnostics_summary(config_path=self._config_path),
            on_result=self._apply_payload,
            on_error=lambda error: self._summary.setText(error.get("message", "error")),
            on_finished=lambda: self._refresh.setEnabled(True),
        )

    def _apply_payload(self, payload: dict):
        status = str(payload.get("status", "unknown") or "unknown").lower()
        self._summary.setText(status.upper())
        self._summary.setStyleSheet(badge_style("ok" if status == "ok" else "degraded"))
        lines = [
            f"{tr('DB status')}: {payload.get('db_health', {}).get('status', 'unknown')}",
            f"{tr('Schema version')}: {payload.get('schema_version', '?')}",
            f"{tr('Rule count')}: {payload.get('rule_count', 'n/a')}",
            f"{tr('Open incidents')}: {payload.get('open_incidents', 0)}",
            f"{tr('Degraded flags')}: {', '.join(payload.get('degraded_flags', []) or ['none'])}",
            "",
            f"{tr('Parse fail summary')}:",
            backend_facade._stringify_payload(payload.get("parse_fail_summary", {})),
            "",
            f"{tr('Duplicate summary')}:",
            backend_facade._stringify_payload(payload.get("duplicate_summary", {})),
            "",
            f"{tr('Runtime')}:",
            backend_facade._stringify_payload(payload.get("runtime", {})),
        ]
        self._text.setPlainText("\n".join(lines))
        self._refresh_bundle_preview()

    def _refresh_bundle_preview(self):
        payload = backend_facade.collect_diagnostic_bundle_preview(config_path=self._config_path)
        self._bundle_summary.setText(str(payload.get("message", tr("Preview only."))))
        lines = [
            tr("would_include:"),
            *[f"- {item}" for item in payload.get("would_include", []) or []],
            "",
            tr("would_redact:"),
            *[f"- {item}" for item in payload.get("would_redact", []) or []],
            "",
            tr("would_exclude:"),
            *[f"- {item}" for item in payload.get("would_exclude", []) or []],
        ]
        self._bundle_text.setPlainText("\n".join(lines))

    def retranslate_ui(self):
        self._title.setText(tr("Diagnostics"))
        self._refresh.setText(tr("Refresh"))
        self._bundle_group.setTitle(tr("Diagnostic Bundle Preview"))
