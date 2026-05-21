from __future__ import annotations

import smtplib
import urllib.error
import urllib.parse
import urllib.request
from email.mime.text import MIMEText
from typing import Any, Dict, Tuple


TELEGRAM_REQUIRED_FIELDS = ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"]
EMAIL_REQUIRED_FIELDS = [
    "EMAIL_SMTP_HOST",
    "EMAIL_SMTP_PORT",
    "EMAIL_SMTP_USER",
    "EMAIL_SMTP_PASS",
    "EMAIL_FROM",
    "EMAIL_TO",
]
TELEGRAM_TEST_MESSAGE = "AegisCore test notification: Telegram integration is configured."
EMAIL_TEST_SUBJECT = "AegisCore Test Notification"
EMAIL_TEST_BODY = "AegisCore test notification: Email integration is configured."


def mask_destination(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "@" in text:
        local, _, domain = text.partition("@")
        local_mask = f"{local[:1]}***" if local else "***"
        domain_mask = domain if len(domain) <= 3 else f"***{domain[-8:]}"
        return f"{local_mask}@{domain_mask}"
    if len(text) <= 4:
        return "*" * len(text)
    return f"{'*' * max(4, len(text) - 4)}{text[-4:]}"


def required_fields_for(channel: str) -> list[str]:
    token = str(channel or "").strip().lower()
    if token == "telegram":
        return list(TELEGRAM_REQUIRED_FIELDS)
    if token == "email":
        return list(EMAIL_REQUIRED_FIELDS)
    return []


def present_fields_for(channel: str, integrations) -> list[str]:
    raw = dict(getattr(integrations, "_raw", {}) or {})
    present: list[str] = []
    for key in required_fields_for(channel):
        value = raw.get(key, "")
        if not str(value or "").strip():
            if key == "TELEGRAM_BOT_TOKEN":
                value = getattr(integrations, "telegram_bot_token", "")
            elif key == "TELEGRAM_CHAT_ID":
                value = getattr(integrations, "telegram_chat_id", "")
        if str(value or "").strip():
            present.append(key)
    return present


def missing_fields_for(channel: str, integrations) -> list[str]:
    present = set(present_fields_for(channel, integrations))
    return [key for key in required_fields_for(channel) if key not in present]


def masked_destination_for(channel: str, integrations) -> str:
    token = str(channel or "").strip().lower()
    raw = dict(getattr(integrations, "_raw", {}) or {})
    if token == "telegram":
        return mask_destination(raw.get("TELEGRAM_CHAT_ID", getattr(integrations, "telegram_chat_id", "")))
    if token == "email":
        return mask_destination(raw.get("EMAIL_TO", getattr(integrations, "email_to", "")))
    return ""


def content_preview_for(channel: str) -> str:
    if str(channel or "").strip().lower() == "telegram":
        return TELEGRAM_TEST_MESSAGE
    if str(channel or "").strip().lower() == "email":
        return EMAIL_TEST_BODY
    return "AegisCore test notification."


def _sanitized_error(prefix: str, exc: Exception) -> str:
    return f"{prefix}_{type(exc).__name__.lower()}"


def send_telegram_test(integrations) -> Dict[str, Any]:
    raw = dict(getattr(integrations, "_raw", {}) or {})
    token = str(raw.get("TELEGRAM_BOT_TOKEN", getattr(integrations, "telegram_bot_token", "")) or "").strip()
    chat_id = str(raw.get("TELEGRAM_CHAT_ID", getattr(integrations, "telegram_chat_id", "")) or "").strip()
    if not token or not chat_id:
        return {
            "status": "failed",
            "channel": "telegram",
            "destination_masked": mask_destination(chat_id),
            "error": "telegram_missing_config",
        }
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = urllib.parse.urlencode(
            {
                "chat_id": chat_id,
                "text": TELEGRAM_TEST_MESSAGE,
                "parse_mode": "HTML",
            }
        ).encode("utf-8")
        request = urllib.request.Request(url, data=payload, method="POST")
        with urllib.request.urlopen(request, timeout=10) as response:
            status_code = int(getattr(response, "status", 200) or 200)
        return {
            "status": "ok",
            "channel": "telegram",
            "destination_masked": mask_destination(chat_id),
            "message": "Telegram test notification sent.",
            "http_status": status_code,
            "error": None,
        }
    except urllib.error.HTTPError as exc:
        return {
            "status": "failed",
            "channel": "telegram",
            "destination_masked": mask_destination(chat_id),
            "message": "Telegram test notification failed.",
            "http_status": int(getattr(exc, "code", 0) or 0),
            "error": _sanitized_error("telegram_send_failed", exc),
        }
    except Exception as exc:
        return {
            "status": "failed",
            "channel": "telegram",
            "destination_masked": mask_destination(chat_id),
            "message": "Telegram test notification failed.",
            "http_status": None,
            "error": _sanitized_error("telegram_send_failed", exc),
        }


def _email_transport(raw: Dict[str, str], timeout: int = 10) -> Tuple[smtplib.SMTP, str, str, str]:
    host = str(raw.get("EMAIL_SMTP_HOST", "") or "").strip()
    port = int(str(raw.get("EMAIL_SMTP_PORT", 587) or 587))
    user = str(raw.get("EMAIL_SMTP_USER", "") or "").strip()
    password = str(raw.get("EMAIL_SMTP_PASS", "") or "").strip()
    from_addr = str(raw.get("EMAIL_FROM", user) or "").strip()
    smtp = smtplib.SMTP(host, port, timeout=timeout)
    return smtp, user, password, from_addr


def send_email_test(integrations) -> Dict[str, Any]:
    raw = dict(getattr(integrations, "_raw", {}) or {})
    to_addr = str(raw.get("EMAIL_TO", getattr(integrations, "email_to", "")) or "").strip()
    if missing_fields_for("email", integrations):
        return {
            "status": "failed",
            "channel": "email",
            "destination_masked": mask_destination(to_addr),
            "error": "email_missing_config",
        }
    try:
        smtp, user, password, from_addr = _email_transport(raw, timeout=10)
        try:
            message = MIMEText(EMAIL_TEST_BODY, "plain", "utf-8")
            message["Subject"] = EMAIL_TEST_SUBJECT
            message["From"] = from_addr
            message["To"] = to_addr
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            if user and password:
                smtp.login(user, password)
            smtp.sendmail(from_addr, [to_addr], message.as_string())
        finally:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass
        return {
            "status": "ok",
            "channel": "email",
            "destination_masked": mask_destination(to_addr),
            "message": "Email test notification sent.",
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "failed",
            "channel": "email",
            "destination_masked": mask_destination(to_addr),
            "message": "Email test notification failed.",
            "error": _sanitized_error("email_send_failed", exc),
        }
