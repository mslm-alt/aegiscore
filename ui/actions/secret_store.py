from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.database import create_database


ALLOWED_SECRET_KEYS = {
    "ABUSEIPDB_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "LLM_API_KEY",
    "LLM_BACKEND",
    "LLM_MODEL",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "EMAIL_SMTP_HOST",
    "EMAIL_SMTP_PORT",
    "EMAIL_SMTP_USER",
    "EMAIL_SMTP_PASS",
    "EMAIL_FROM",
    "EMAIL_TO",
}

_SENSITIVE_KEYS = {
    "ABUSEIPDB_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "LLM_API_KEY",
    "TELEGRAM_BOT_TOKEN",
    "EMAIL_SMTP_PASS",
}


def mask_secret(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 4:
        return "*" * len(text)
    return f"{'*' * max(4, len(text) - 4)}{text[-4:]}"


def validate_allowed_secret_keys(updates: dict) -> tuple[dict[str, str], list[str]]:
    normalized: dict[str, str] = {}
    invalid: list[str] = []
    for key, value in dict(updates or {}).items():
        name = str(key or "").strip()
        if not name:
            continue
        if name not in ALLOWED_SECRET_KEYS:
            invalid.append(name)
            continue
        normalized[name] = str(value or "").strip()
    return normalized, sorted(invalid)


def parse_env_lines(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for raw_line in str(text or "").splitlines():
        stripped = raw_line.strip()
        if not stripped:
            rows.append({"kind": "blank", "raw": raw_line})
            continue
        if stripped.startswith("#"):
            rows.append({"kind": "comment", "raw": raw_line})
            continue
        if "=" not in raw_line:
            rows.append({"kind": "other", "raw": raw_line})
            continue
        key, _, value = raw_line.partition("=")
        rows.append({
            "kind": "entry",
            "key": key.strip(),
            "value": value.strip().strip('"').strip("'"),
            "raw": raw_line,
        })
    return rows


def load_env_file(path: str | Path) -> Dict[str, str]:
    env_path = Path(path)
    if not env_path.exists():
        return {}
    parsed = parse_env_lines(env_path.read_text(encoding="utf-8"))
    return {
        row["key"]: row["value"]
        for row in parsed
        if row.get("kind") == "entry" and row.get("key")
    }


def _format_env_value(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    if any(token in text for token in (" ", "#", '"', "'")):
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return text


def _build_env_text(parsed: List[Dict[str, str]], updates: Dict[str, str]) -> str:
    remaining = dict(updates)
    lines: List[str] = []
    for row in parsed:
        if row.get("kind") != "entry":
            lines.append(row.get("raw", ""))
            continue
        key = row.get("key", "")
        if key in remaining:
            lines.append(f"{key}={_format_env_value(remaining.pop(key))}")
        else:
            lines.append(row.get("raw", ""))
    if lines and lines[-1].strip():
        lines.append("")
    for key in sorted(remaining):
        lines.append(f"{key}={_format_env_value(remaining[key])}")
    return "\n".join(lines).rstrip() + "\n"


def update_env_values(path: str | Path, updates: dict, backup: bool = True) -> Dict[str, Any]:
    env_path = Path(path)
    env_path.parent.mkdir(parents=True, exist_ok=True)
    normalized, invalid = validate_allowed_secret_keys(updates)
    if invalid:
        return {
            "status": "failed",
            "path": str(env_path),
            "updated_keys": sorted(normalized),
            "invalid_keys": invalid,
            "backup_path": None,
            "error": "invalid_keys",
        }

    existing_text = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
    parsed = parse_env_lines(existing_text)
    new_text = _build_env_text(parsed, normalized)

    backup_path = None
    if backup and env_path.exists():
        backup_path = env_path.with_name(f"{env_path.name}.bak.{int(time.time())}")
        shutil.copy2(env_path, backup_path)

    fd, temp_name = tempfile.mkstemp(prefix=f".{env_path.name}.", dir=str(env_path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(new_text)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        os.replace(temp_name, env_path)
        try:
            os.chmod(env_path, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)

    return {
        "status": "ok",
        "path": str(env_path),
        "updated_keys": sorted(normalized),
        "invalid_keys": [],
        "backup_path": str(backup_path) if backup_path is not None else None,
        "error": None,
    }


def restore_env_from_backup(path: str | Path, backup_path: str | Path) -> Dict[str, Any]:
    target = Path(path)
    backup = Path(backup_path)
    if not backup.exists():
        return {"status": "failed", "error": "backup_missing"}
    shutil.copy2(backup, target)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return {"status": "ok", "error": None}


def audit_user_action_available(config: Dict[str, Any]) -> tuple[bool, str]:
    db = None
    try:
        db = create_database(config)
        if db is None:
            return False, "database_unavailable"
        db._execute("SELECT 1 FROM user_actions LIMIT 1", fetch="one")
        return True, ""
    except Exception as exc:
        return False, str(exc)
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass


def record_user_action(
    config: Dict[str, Any],
    action: str,
    actor: str,
    target: str,
    summary: str,
    details: Dict[str, Any],
    status: str = "ok",
) -> Dict[str, Any]:
    db = None
    try:
        db = create_database(config)
        if db is None:
            return {"status": "failed", "error": "database_unavailable"}
        payload = json.dumps(details or {}, ensure_ascii=False)
        now = time.time()
        action_id = int(now * 1000000)
        db._execute(
            "INSERT INTO user_actions (id, ts, action, status, actor, screen, entity_type, entity_id, target, summary, details) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)",
            (
                action_id,
                now,
                action,
                status,
                actor,
                "settings",
                "secret",
                "",
                target,
                summary,
                payload,
            ),
        )
        return {"status": "ok", "id": action_id, "error": None}
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
