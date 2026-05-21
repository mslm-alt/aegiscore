from __future__ import annotations

from typing import Dict

SEVERITY_COLORS: Dict[str, str] = {
    "critical": "#ff5d73",
    "high": "#ff9a4d",
    "medium": "#f3c969",
    "low": "#59c7a5",
    "info": "#6fb1ff",
    "unknown": "#8b9bb4",
}

STATUS_COLORS: Dict[str, str] = {
    "pass": "#29c37d",
    "warning": "#f3c969",
    "blocked": "#ff5d73",
    "degraded": "#ff9a4d",
    "locked": "#7d8da6",
    "ok": "#29c37d",
    "preview_only": "#6fb1ff",
    "read_only": "#6fb1ff",
}

PALETTES: Dict[str, Dict[str, str]] = {
    "dark": {
        "bg": "#0b1220",
        "panel": "#101a2b",
        "panel_alt": "#152238",
        "card": "#111c2f",
        "border": "#22324d",
        "text": "#e8eef7",
        "muted": "#8ea2bd",
        "accent": "#3a8bfd",
        "table_alt": "#0f1829",
        "sidebar": "#0f1728",
    },
    "light": {
        "bg": "#eef3f8",
        "panel": "#ffffff",
        "panel_alt": "#f6f9fc",
        "card": "#ffffff",
        "border": "#d8e1ec",
        "text": "#132033",
        "muted": "#5d6e85",
        "accent": "#2563eb",
        "table_alt": "#f7fafc",
        "sidebar": "#e7eef7",
    },
}


def _normalized_mode(mode: str) -> str:
    token = str(mode or "dark").strip().lower()
    return token if token in PALETTES else "dark"


def severity_color(level: str) -> str:
    token = str(level or "unknown").strip().lower()
    return SEVERITY_COLORS.get(token, SEVERITY_COLORS["unknown"])


def status_color(status: str) -> str:
    token = str(status or "degraded").strip().lower()
    if token in {"pass", "warning", "blocked", "degraded", "locked", "ok", "preview_only", "read_only"}:
        return STATUS_COLORS[token]
    return STATUS_COLORS["degraded"]


def badge_style(kind: str, mode: str = "dark", compact: bool = False) -> str:
    palette = PALETTES[_normalized_mode(mode)]
    token = str(kind or "").strip().lower()
    color = STATUS_COLORS.get(token, SEVERITY_COLORS.get(token, palette["accent"]))
    radius = 9 if compact else 11
    padding = "2px 8px" if compact else "4px 10px"
    return (
        f"background:{color}; color:#f8fbff; border:1px solid {color}; "
        f"border-radius:{radius}px; padding:{padding}; font-weight:700;"
    )


def common_stylesheet(mode: str = "dark") -> str:
    palette = PALETTES[_normalized_mode(mode)]
    return f"""
    QWidget {{
        background: {palette['bg']};
        color: {palette['text']};
        font-family: 'Segoe UI', 'Noto Sans', sans-serif;
        font-size: 13px;
    }}
    QWidget#appRoot, QWidget#preflightRoot {{ background: {palette['bg']}; }}
    QFrame#card, QFrame#metricChip, QGroupBox, QTreeWidget, QTableWidget, QPlainTextEdit, QTabWidget::pane {{
        background: {palette['card']};
        border: 1px solid {palette['border']};
        border-radius: 12px;
    }}
    QFrame#headerCard, QFrame#sidebarFrame, QFrame#stateCard {{
        background: {palette['panel']};
        border: 1px solid {palette['border']};
        border-radius: 14px;
    }}
    QLabel#title {{ font-size: 28px; font-weight: 800; }}
    QLabel#brand {{ font-size: 24px; font-weight: 800; letter-spacing: 0.3px; }}
    QLabel#subtitle, QLabel#mutedText {{ color: {palette['muted']}; }}
    QLabel#sectionTitle, QLabel#pageTitle {{ font-size: 16px; font-weight: 700; }}
    QLabel#metricValue, QLabel#value {{ font-size: 22px; font-weight: 800; }}
    QLabel#metricSubtitle {{ color: {palette['muted']}; }}
    QLabel#badge {{ letter-spacing: 0.3px; }}
    QLabel#chipLabel {{ color: {palette['muted']}; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
    QLabel#chipValue {{ font-size: 14px; font-weight: 700; }}
    QListWidget#sidebar {{
        background: {palette['sidebar']};
        border: 0;
        outline: 0;
        padding: 6px;
    }}
    QListWidget#sidebar::item {{
        padding: 10px 12px;
        margin: 3px 0;
        border-radius: 10px;
        color: {palette['text']};
    }}
    QListWidget#sidebar::item:selected {{
        background: {palette['accent']};
        color: #ffffff;
        font-weight: 700;
    }}
    QListWidget#sidebar::item:hover {{
        background: {palette['panel_alt']};
    }}
    QHeaderView::section {{
        background: {palette['panel_alt']};
        color: {palette['muted']};
        padding: 8px;
        border: 0;
        border-bottom: 1px solid {palette['border']};
        font-weight: 700;
    }}
    QTableWidget {{
        gridline-color: {palette['border']};
        alternate-background-color: {palette['table_alt']};
        selection-background-color: {palette['accent']};
        selection-color: #ffffff;
    }}
    QTreeWidget {{
        alternate-background-color: {palette['table_alt']};
    }}
    QPlainTextEdit {{
        selection-background-color: {palette['accent']};
        font-family: 'Cascadia Code', 'Consolas', monospace;
    }}
    QPushButton {{
        background: {palette['accent']};
        color: #ffffff;
        border: 0;
        border-radius: 10px;
        padding: 8px 14px;
        font-weight: 700;
    }}
    QPushButton:hover {{ background: #4f9bff; }}
    QPushButton:disabled {{
        background: #334155;
        color: #cbd5e1;
    }}
    QLineEdit, QComboBox, QSpinBox {{
        background: {palette['panel']};
        border: 1px solid {palette['border']};
        border-radius: 10px;
        padding: 8px 10px;
    }}
    QProgressBar {{
        background: {palette['panel_alt']};
        border: 1px solid {palette['border']};
        border-radius: 9px;
        text-align: center;
    }}
    QProgressBar::chunk {{
        background: {palette['accent']};
        border-radius: 8px;
    }}
    """


def apply_app_theme(app, mode: str = "dark") -> str:
    normalized = _normalized_mode(mode)
    if app is not None and hasattr(app, "setStyleSheet"):
        app.setStyleSheet(common_stylesheet(normalized))
        if hasattr(app, "setProperty"):
            app.setProperty("themeMode", normalized)
    return normalized
