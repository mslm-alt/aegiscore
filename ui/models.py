from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class PreflightCheck:
    name: str
    status: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    suggestion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityLocks:
    read_only_mode: bool
    auto_ip_block_disabled: bool
    ml_no_action_contract: bool
    manual_actions_locked: bool
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ViewMetric:
    label: str
    value: str
    tone: str = "neutral"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkerError:
    type: str
    message: str
    traceback: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BuiltinPreset:
    key: str
    label: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NotificationRule:
    enabled: bool = True
    severities: List[str] = field(default_factory=lambda: ["critical", "high"])
    cooldown_seconds: int = 300
    suppress_duplicates: bool = True
    background_notifications: bool = True
    tray_enabled: bool = True
    desktop_notifications: bool = True
    preview_filters: Dict[str, bool] = field(default_factory=lambda: {
        "critical": True,
        "high": True,
        "medium": False,
        "low": False,
        "auth_only": False,
        "db_web_only": False,
        "external_ip_only": False,
    })

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def builtin_presets() -> List[BuiltinPreset]:
    return [
        BuiltinPreset("all", "All alerts", "Read-only default list"),
        BuiltinPreset("critical_only", "Critical only", "Only critical severity alerts"),
        BuiltinPreset("high_critical", "High + Critical", "High and critical severity alerts"),
        BuiltinPreset("ssh_auth", "SSH/Auth", "SSH and authentication related alerts"),
        BuiltinPreset("firewall_network", "Firewall/Network", "Firewall and network focused alerts"),
        BuiltinPreset("web_attacks", "Web attacks", "Web and HTTP attack indicators"),
        BuiltinPreset("db_auth_failures", "DB auth failures", "Database login or auth failure alerts"),
        BuiltinPreset("last_1h", "Last 1 hour", "Alerts from the last hour"),
        BuiltinPreset("last_24h", "Last 24 hours", "Alerts from the last 24 hours"),
        BuiltinPreset("external_ip_only", "External IP only", "Alerts with non-private source IPs"),
    ]


def preset_matches_alert(preset_key: str, alert: Dict[str, Any], now: float | None = None) -> bool:
    key = str(preset_key or "all").strip().lower()
    if key in {"", "all"}:
        return True

    payload = dict(alert or {})
    raw = dict(payload.get("raw", {}) or {})
    text_blob = " ".join([
        str(payload.get("rule_id", "") or ""),
        str(payload.get("source", "") or ""),
        str(payload.get("message", "") or ""),
        str(payload.get("entity", "") or ""),
        str(raw.get("process", "") or ""),
        str(raw.get("rule_name", "") or ""),
    ]).lower()
    severity = str(payload.get("severity", "") or "").lower()
    source_ip = str(payload.get("source_ip", "") or "")
    event_ts = payload.get("created_at", raw.get("ts", raw.get("timestamp", 0)))
    event_ts_float = 0.0
    try:
        event_ts_float = float(event_ts or 0.0)
    except (TypeError, ValueError):
        event_ts_float = 0.0
    now_ts = float(now if now is not None else time.time())

    if key == "critical_only":
        return severity == "critical"
    if key == "high_critical":
        return severity in {"high", "critical"}
    if key == "ssh_auth":
        return any(token in text_blob for token in ("ssh", "auth", "login", "sshd", "sudo"))
    if key == "firewall_network":
        return any(token in text_blob for token in ("firewall", "ufw", "iptables", "network", "dns", "port", "socket"))
    if key == "web_attacks":
        return any(token in text_blob for token in ("apache", "nginx", "http", "web", "sql", "xss", "path traversal"))
    if key == "db_auth_failures":
        return any(token in text_blob for token in ("mysql", "postgres", "postgresql", "db", "database", "auth fail", "login fail", "password"))
    if key == "last_1h":
        return bool(event_ts_float and event_ts_float >= now_ts - 3600.0)
    if key == "last_24h":
        return bool(event_ts_float and event_ts_float >= now_ts - 86400.0)
    if key == "external_ip_only":
        if not source_ip:
            return False
        return not (
            source_ip.startswith("10.")
            or source_ip.startswith("192.168.")
            or source_ip.startswith("127.")
            or source_ip.startswith("169.254.")
            or source_ip.startswith("172.16.")
            or source_ip.startswith("172.17.")
            or source_ip.startswith("172.18.")
            or source_ip.startswith("172.19.")
            or source_ip.startswith("172.2")
            or source_ip.startswith("172.30.")
            or source_ip.startswith("172.31.")
        )
    return True


def bounded_buffer(items: List[Dict[str, Any]], max_items: int) -> List[Dict[str, Any]]:
    limit = max(1, int(max_items or 1))
    if len(items) <= limit:
        return list(items)
    return list(items[-limit:])


def bounded_history(items: List[Dict[str, Any]], new_item: Dict[str, Any], max_items: int = 50) -> List[Dict[str, Any]]:
    history = list(items)
    history.append(dict(new_item))
    return bounded_buffer(history, max_items)


def checks_to_dicts(items: List[PreflightCheck]) -> List[Dict[str, Any]]:
    return [item.to_dict() for item in items]


def pick_primary_ip(payload: Dict[str, Any]) -> str:
    alert = dict(payload or {})
    for key in ("source_ip", "target_ip"):
        value = str(alert.get(key, "") or "").strip()
        if value:
            return value
    return ""


def theme_option_specs() -> List[Dict[str, str]]:
    return [
        {"id": "dark", "label": "Dark"},
        {"id": "light", "label": "Light"},
        {"id": "system", "label": "System"},
    ]


def report_export_types() -> List[Dict[str, str]]:
    return [
        {"id": "selected_alert", "label": "Selected alert"},
        {"id": "incident_report", "label": "Incident report"},
        {"id": "ml_readiness", "label": "ML readiness"},
        {"id": "source_health", "label": "Source health"},
        {"id": "diagnostic_bundle", "label": "Diagnostic bundle"},
    ]
