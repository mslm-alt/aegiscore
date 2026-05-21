from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ui.models import NotificationRule

try:
    from PySide6.QtWidgets import QSystemTrayIcon
except ImportError:  # pragma: no cover - graceful import path
    QSystemTrayIcon = None  # type: ignore[assignment]


def build_alert_notification_payload(alert: dict) -> dict:
    payload = dict(alert or {})
    severity = str(payload.get("severity", "unknown") or "unknown").strip().lower()
    severity_title = severity.capitalize() if severity else "Alert"
    entity = str(payload.get("entity", "") or "").strip()
    source_ip = str(payload.get("source_ip", "") or "").strip()
    rule_id = str(payload.get("rule_id", "") or "").strip()
    message = str(payload.get("message", "") or "").strip()
    target = entity or source_ip or "unknown target"
    return {
        "title": f"AegisCore {severity_title} Alert",
        "message": f"{rule_id or 'alert'} | {target} | {message}"[:240],
        "alert_id": payload.get("id"),
        "severity": severity,
        "rule_id": rule_id,
        "source_ip": source_ip,
        "entity": entity,
        "timestamp_text": str(payload.get("timestamp_text", "") or "").strip(),
    }


@dataclass
class NotificationDeduper:
    rule: NotificationRule = field(default_factory=NotificationRule)
    seen_alert_ids: list[int] = field(default_factory=list)
    last_notification_by_key: dict[str, float] = field(default_factory=dict)
    max_seen_ids: int = 1000

    def _alert_key(self, alert: dict) -> str:
        payload = dict(alert or {})
        return "|".join([
            str(payload.get("severity", "") or "").lower(),
            str(payload.get("rule_id", "") or ""),
            str(payload.get("entity", "") or ""),
            str(payload.get("source_ip", "") or ""),
        ])

    def should_notify(self, alert: dict, now: float | None = None) -> bool:
        if not self.rule.enabled or not self.rule.background_notifications or not self.rule.desktop_notifications:
            return False
        payload = dict(alert or {})
        try:
            alert_id = int(payload.get("id", -1) or -1)
        except Exception:
            alert_id = -1
        severity = str(payload.get("severity", "") or "").lower()
        if severity not in set(self.rule.severities):
            return False
        if alert_id >= 0 and alert_id in self.seen_alert_ids:
            return False
        current_time = float(now if now is not None else time.time())
        key = self._alert_key(payload)
        if self.rule.suppress_duplicates:
            last_ts = float(self.last_notification_by_key.get(key, 0.0) or 0.0)
            if last_ts and current_time - last_ts < max(0, int(self.rule.cooldown_seconds or 0)):
                return False
        return True

    def mark_notified(self, alert: dict, now: float | None = None):
        payload = dict(alert or {})
        current_time = float(now if now is not None else time.time())
        try:
            alert_id = int(payload.get("id", -1) or -1)
        except Exception:
            alert_id = -1
        if alert_id >= 0:
            self.seen_alert_ids.append(alert_id)
            if len(self.seen_alert_ids) > max(1, int(self.max_seen_ids or 1)):
                self.seen_alert_ids = self.seen_alert_ids[-int(self.max_seen_ids):]
        self.last_notification_by_key[self._alert_key(payload)] = current_time


def show_desktop_notification(
    tray_icon: Any,
    payload: dict,
    on_click: Callable[[int | None], None] | None = None,
) -> dict:
    if QSystemTrayIcon is None or tray_icon is None:
        return {"status": "disabled", "shown": False, "reason": "tray_unavailable"}
    try:
        alert_id = payload.get("alert_id")
        if on_click is not None:
            try:
                tray_icon.messageClicked.disconnect()
            except Exception:
                pass
            tray_icon.messageClicked.connect(lambda: on_click(alert_id))
        icon = getattr(QSystemTrayIcon.MessageIcon, "Warning", QSystemTrayIcon.MessageIcon.Information)
        tray_icon.showMessage(
            str(payload.get("title", "AegisCore Alert") or "AegisCore Alert"),
            str(payload.get("message", "") or ""),
            icon,
            10000,
        )
        return {"status": "ok", "shown": True, "reason": ""}
    except Exception as exc:
        return {"status": "degraded", "shown": False, "reason": str(exc)}
