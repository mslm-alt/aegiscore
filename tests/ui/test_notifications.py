import importlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.models import NotificationRule
from ui.notifications import NotificationDeduper, build_alert_notification_payload


def _alert(alert_id=1, severity="critical", rule_id="RULE-1", entity="alice", source_ip="1.2.3.4"):
    return {
        "id": alert_id,
        "severity": severity,
        "rule_id": rule_id,
        "entity": entity,
        "source_ip": source_ip,
        "message": "test alert",
        "timestamp_text": "2026-05-11 12:00:00",
    }


def test_notification_deduper_first_alert_notifies():
    deduper = NotificationDeduper(rule=NotificationRule())

    assert deduper.should_notify(_alert()) is True


def test_notification_deduper_duplicate_alert_id_suppressed():
    deduper = NotificationDeduper(rule=NotificationRule())
    alert = _alert()
    deduper.mark_notified(alert, now=100.0)

    assert deduper.should_notify(alert, now=120.0) is False


def test_notification_deduper_cooldown_same_key_suppressed():
    deduper = NotificationDeduper(rule=NotificationRule(cooldown_seconds=300))
    deduper.mark_notified(_alert(alert_id=1), now=100.0)

    assert deduper.should_notify(_alert(alert_id=2), now=200.0) is False


def test_notification_deduper_different_key_notifies():
    deduper = NotificationDeduper(rule=NotificationRule(cooldown_seconds=300))
    deduper.mark_notified(_alert(alert_id=1, severity="critical", rule_id="RULE-1", entity="alice"), now=100.0)

    assert deduper.should_notify(_alert(alert_id=2, severity="high", rule_id="RULE-2", entity="bob"), now=120.0) is True


def test_notification_deduper_low_severity_suppressed_by_default():
    deduper = NotificationDeduper(rule=NotificationRule())

    assert deduper.should_notify(_alert(alert_id=2, severity="low")) is False


def test_notification_deduper_seen_ids_bounded():
    deduper = NotificationDeduper(rule=NotificationRule(), max_seen_ids=3)
    for idx in range(1, 6):
        deduper.mark_notified(_alert(alert_id=idx), now=float(idx))

    assert deduper.seen_alert_ids == [3, 4, 5]


def test_build_alert_notification_payload_schema():
    payload = build_alert_notification_payload(_alert())

    assert {
        "title", "message", "alert_id", "severity", "rule_id",
        "source_ip", "entity", "timestamp_text",
    } <= set(payload)
    assert payload["alert_id"] == 1


def test_show_desktop_notification_graceful_without_tray():
    from ui.notifications import show_desktop_notification

    result = show_desktop_notification(None, build_alert_notification_payload(_alert()))

    assert result["status"] == "disabled"
    assert result["shown"] is False


def test_notifications_wrapper_import_graceful():
    pytest.importorskip("PySide6")
    module = importlib.import_module("ui.notifications")
    assert module is not None


def test_notifications_no_write_guard_sources():
    for path in (
        "ui/notifications.py",
        "ui/main_window.py",
        "ui/views/settings_compact.py",
    ):
        source = Path(path).read_text(encoding="utf-8").lower()
        for token in (
            "write_text(",
            "requests.post(",
            "requests.get(",
            ".commit(",
            "insert into alerts",
            "update alerts",
            "delete from alerts",
            "block_ip(",
            "unblock_ip(",
            "reset_database(",
            "close_incident(",
            "smtplib",
            ".sendmail(",
            "firewall-cmd",
        ):
            assert token not in source
