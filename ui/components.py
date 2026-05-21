from __future__ import annotations

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QAbstractItemView,
        QFrame,
        QHBoxLayout,
        QLabel,
        QTableWidget,
        QVBoxLayout,
        QWidget,
    )
except ImportError:  # pragma: no cover - graceful import path for non-Qt envs
    Qt = None
    QAbstractItemView = object  # type: ignore[assignment]
    QFrame = object  # type: ignore[assignment]
    QHBoxLayout = object  # type: ignore[assignment]
    QLabel = None  # type: ignore[assignment]
    QTableWidget = object  # type: ignore[assignment]
    QVBoxLayout = object  # type: ignore[assignment]
    QWidget = object  # type: ignore[assignment]

from ui.theme import badge_style, status_color

QT_AVAILABLE = QLabel is not None


def make_badge(text: str, kind: str, compact: bool = False):
    if not QT_AVAILABLE:
        return None
    label = QLabel(str(text or ""))
    label.setObjectName("badge")
    label.setStyleSheet(badge_style(kind, compact=compact))
    return label


def make_metric_chip(title: str, value: str, kind: str | None = None):
    if not QT_AVAILABLE:
        return None
    chip = QFrame()
    chip.setObjectName("metricChip")
    layout = QHBoxLayout(chip)
    layout.setContentsMargins(10, 7, 10, 7)
    layout.setSpacing(8)
    label = QLabel(str(title or ""))
    label.setObjectName("chipLabel")
    metric = QLabel(str(value or ""))
    metric.setObjectName("chipValue")
    layout.addWidget(label)
    layout.addWidget(metric)
    layout.addStretch(1)
    if kind:
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {status_color(kind)}; font-size: 12px;")
        layout.addWidget(dot, 0, Qt.AlignmentFlag.AlignRight)
    return chip


def make_section_title(title: str, subtitle: str | None = None):
    if not QT_AVAILABLE:
        return None
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(2)
    heading = QLabel(str(title or ""))
    heading.setObjectName("pageTitle")
    layout.addWidget(heading)
    if subtitle:
        detail = QLabel(str(subtitle))
        detail.setObjectName("mutedText")
        detail.setWordWrap(True)
        layout.addWidget(detail)
    return widget


def _make_state_box(message: str, detail: str | None, kind: str):
    if not QT_AVAILABLE:
        return None
    card = QFrame()
    card.setObjectName("stateCard")
    layout = QVBoxLayout(card)
    layout.setContentsMargins(16, 16, 16, 16)
    layout.setSpacing(8)
    badge = make_badge(message, kind)
    if badge is not None:
        layout.addWidget(badge, 0, Qt.AlignmentFlag.AlignLeft)
    if detail:
        info = QLabel(str(detail))
        info.setWordWrap(True)
        info.setObjectName("mutedText")
        layout.addWidget(info)
    return card


def make_empty_state(message: str, detail: str | None = None):
    return _make_state_box(message, detail, "read_only")


def make_degraded_state(message: str, detail: str | None = None):
    return _make_state_box(message, detail, "degraded")


def make_metric_card(title: str, value: str, subtitle: str | None = None, kind: str | None = None):
    if not QT_AVAILABLE:
        return None
    card = QFrame()
    card.setObjectName("card")
    layout = QVBoxLayout(card)
    layout.setContentsMargins(16, 16, 16, 16)
    layout.setSpacing(6)
    top = QHBoxLayout()
    heading = QLabel(str(title or ""))
    heading.setObjectName("sectionTitle")
    top.addWidget(heading)
    top.addStretch(1)
    if kind:
        badge = make_badge(kind.replace("_", " ").upper(), kind)
        if badge is not None:
            top.addWidget(badge)
    metric = QLabel(str(value or ""))
    metric.setObjectName("value")
    metric.setWordWrap(True)
    layout.addLayout(top)
    layout.addWidget(metric)
    if subtitle:
        note = QLabel(str(subtitle))
        note.setObjectName("metricSubtitle")
        note.setWordWrap(True)
        layout.addWidget(note)
    return card


def configure_table(table):
    if not QT_AVAILABLE or table is None:
        return table
    if hasattr(table, "setAlternatingRowColors"):
        table.setAlternatingRowColors(True)
    if hasattr(table, "setSelectionBehavior"):
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    if hasattr(table, "setSelectionMode"):
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    if hasattr(table, "setEditTriggers"):
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    horizontal = table.horizontalHeader() if hasattr(table, "horizontalHeader") else None
    if horizontal is not None:
        horizontal.setStretchLastSection(True)
    vertical = table.verticalHeader() if hasattr(table, "verticalHeader") else None
    if vertical is not None:
        vertical.setVisible(False)
    return table


def set_table_empty_message(table, message: str):
    if not QT_AVAILABLE or table is None:
        return
    text = str(message or "")
    if hasattr(table, "setToolTip"):
        table.setToolTip(text)
    if hasattr(table, "setWhatsThis"):
        table.setWhatsThis(text)
    if hasattr(table, "setProperty"):
        table.setProperty("emptyMessage", text)
