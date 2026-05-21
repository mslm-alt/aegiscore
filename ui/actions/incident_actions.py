from __future__ import annotations

import json
import time
from typing import Any, Dict

from core.database import create_database

from .guard import build_guarded_action_preview, get_action_policy, required_confirmation_for
from .models import GuardedActionRequest
from .secret_store import audit_user_action_available

_CLOSABLE_STATUSES = {"open", "active", "in_progress", "investigating"}
_FINAL_STATUSES = {"resolved", "closed", "archived"}


def _sanitize_error(error: Any) -> str:
    text = str(error or "").strip()
    return text[:160] if text else ""


def _normalize_incident_row(row: Dict[str, Any] | None) -> Dict[str, Any] | None:
    if not row:
        return None
    payload = dict(row)
    return {
        "id": payload.get("id"),
        "status": str(payload.get("status", "") or "").strip().lower(),
        "severity": str(payload.get("severity", "") or "").strip().lower(),
        "title": str(payload.get("title", "") or "").strip(),
        "entity_key": str(payload.get("entity_key", "") or "").strip(),
        "alert_count": int(payload.get("alert_count", 0) or 0),
        "risk_score": float(payload.get("risk_score", 0.0) or 0.0),
        "summary": str(payload.get("summary", "") or "").strip(),
        "evidence": payload.get("evidence", []),
        "raw": payload,
    }


def _fetch_incident(db: Any, incident_id: int) -> Dict[str, Any] | None:
    if db is None:
        return None
    row = db._execute("SELECT * FROM incidents WHERE id = %s LIMIT 1", (int(incident_id),), fetch="one")
    return _normalize_incident_row(dict(row)) if row else None


def _build_request(action: str, incident_id: int, actor: str, role: str, reason: str, confirmation: str, dry_run_completed: bool) -> GuardedActionRequest:
    action_token = "close" if str(action or "").strip().lower() == "close" else "resolve"
    action_type = f"incident_{action_token}"
    target = str(int(incident_id))
    policy = get_action_policy(action_type)
    return GuardedActionRequest(
        action_id=f"{action_type}:{target}",
        action_type=action_type,
        target=target,
        target_type="incident",
        actor=str(actor or "").strip(),
        reason=str(reason or "").strip(),
        confirmation_phrase=str(confirmation or "").strip(),
        required_confirmation_phrase=required_confirmation_for(action_type, target),
        dry_run_required=policy.dry_run_required,
        dry_run_completed=bool(dry_run_completed),
        role_required=policy.role_required,
        current_role=str(role or "").strip(),
        metadata={"source": "guarded_incident_action"},
    )


def _record_audit(db: Any, action_type: str, actor: str, incident_id: int, reason: str, details: Dict[str, Any], status: str) -> Dict[str, Any]:
    payload = json.dumps(details or {}, ensure_ascii=False)
    now = time.time()
    action_id = int(now * 1000000)
    db._execute(
        "INSERT INTO user_actions (id, ts, action, status, actor, screen, entity_type, entity_id, target, summary, details) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)",
        (
            action_id,
            now,
            action_type,
            status,
            actor,
            "incidents",
            "incident",
            str(int(incident_id)),
            str(int(incident_id)),
            str(reason or "").strip(),
            payload,
        ),
    )
    return {"status": "ok", "id": action_id, "error": None}


def preview_guarded_incident_action(
    config: Dict[str, Any],
    action: str,
    incident_id: int,
    actor: str,
    role: str,
    reason: str,
    confirmation: str = "",
    dry_run_completed: bool = False,
) -> Dict[str, Any]:
    action_token = "close" if str(action or "").strip().lower() == "close" else "resolve"
    next_status = "closed" if action_token == "close" else "resolved"
    try:
        normalized_id = int(incident_id)
    except (TypeError, ValueError):
        normalized_id = 0
    request = _build_request(action_token, normalized_id or 0, actor, role, reason, confirmation, dry_run_completed)
    guard = build_guarded_action_preview(request).to_dict()
    incident_payload: Dict[str, Any] | None = None
    message = guard.get("message", "Preview only.")

    if normalized_id <= 0:
        guard["status"] = "denied"
        guard["execution_enabled"] = False
        guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["valid incident id"]
        message = "Execution is blocked until a valid incident id is provided."
        return {
            "status": "denied",
            "action": action_token,
            "incident_id": incident_id,
            "incident": None,
            "guard": guard,
            "would_update": {
                "status": next_status,
                "reason": str(reason or "").strip(),
                "ml_resume": False,
                "delete_alerts": False,
                "delete_events": False,
            },
            "audit_required": True,
            "message": message,
            "warning": "",
        }

    db = None
    try:
        db = create_database(config)
        if db is None:
            guard["status"] = "denied"
            guard["execution_enabled"] = False
            guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["incident exists"]
            message = "Execution is blocked because the incident database is unavailable."
            return {
                "status": "denied",
                "action": action_token,
                "incident_id": normalized_id,
                "incident": None,
                "guard": guard,
                "would_update": {
                    "status": next_status,
                    "reason": str(reason or "").strip(),
                    "ml_resume": False,
                    "delete_alerts": False,
                    "delete_events": False,
                },
                "audit_required": True,
                "message": message,
                "warning": "",
            }

        incident_payload = _fetch_incident(db, normalized_id)
        if incident_payload is None:
            guard["status"] = "denied"
            guard["execution_enabled"] = False
            guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["incident exists"]
            message = "Execution is blocked because the incident was not found."
        else:
            current_status = str(incident_payload.get("status", "") or "").lower()
            if current_status in _FINAL_STATUSES:
                guard["status"] = "denied"
                guard["execution_enabled"] = False
                guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["closable incident status"]
                message = f"Execution is blocked because incident status is already {current_status}."
            elif current_status not in _CLOSABLE_STATUSES:
                guard["status"] = "denied"
                guard["execution_enabled"] = False
                guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["closable incident status"]
                message = f"Execution is blocked because incident status {current_status or 'unknown'} cannot transition to {next_status}."

        audit_available, audit_error = audit_user_action_available(config)
        if not audit_available:
            guard["status"] = "denied"
            guard["execution_enabled"] = False
            guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["audit availability"]
            message = "Execution is blocked until audit storage is available."
        else:
            audit_error = ""

        warning = ""
        if incident_payload and action_token == "close" and str(incident_payload.get("severity", "") or "").lower() in {"high", "critical"}:
            warning = "Closing high/critical incidents may unblock ML clean-window logic, but this action does not resume ML automatically."

        return {
            "status": str(guard.get("status", "denied")),
            "action": action_token,
            "incident_id": normalized_id,
            "incident": incident_payload,
            "guard": guard,
            "would_update": {
                "status": next_status,
                "reason": str(reason or "").strip(),
                "ml_resume": False,
                "delete_alerts": False,
                "delete_events": False,
            },
            "audit_required": True,
            "message": message,
            "warning": warning,
            "audit": {
                "available": audit_available,
                "error": audit_error,
            },
        }
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass


def execute_guarded_incident_action(
    config: Dict[str, Any],
    action: str,
    incident_id: int,
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
) -> Dict[str, Any]:
    preview = preview_guarded_incident_action(
        config=config,
        action=action,
        incident_id=incident_id,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
    )
    guard = dict(preview.get("guard", {}) or {})
    audit = dict(preview.get("audit", {}) or {})
    if not bool(audit.get("available", False)):
        return {
            "status": "denied",
            "action": preview.get("action", action),
            "incident_id": preview.get("incident_id", incident_id),
            "incident": preview.get("incident"),
            "message": "Audit is required before incident state changes can run.",
            "audit": {"status": "unavailable", "reason": audit.get("error") or "audit_unavailable"},
            "error": "audit_unavailable",
        }
    if preview.get("status") != "ready" or not bool(guard.get("execution_enabled", False)):
        return {
            "status": "denied",
            "action": preview.get("action", action),
            "incident_id": preview.get("incident_id", incident_id),
            "incident": preview.get("incident"),
            "message": preview.get("message", guard.get("message", "Guard validation failed.")),
            "audit": {"status": "denied", "reason": "guard_denied"},
            "error": "guard_denied",
        }

    db = None
    action_type = f"incident_{preview.get('action', action)}"
    actor_value = str(actor or "").strip() or "local-user"
    reason_value = str(reason or "").strip()
    target_id = int(preview.get("incident_id", incident_id) or 0)
    previous = dict(preview.get("incident", {}) or {})
    new_status = str(dict(preview.get("would_update", {}) or {}).get("status", "") or "")
    raw_previous = dict(previous.get("raw", {}) or {})
    audit_details = {
        "previous_status": str(previous.get("status", "") or ""),
        "new_status": new_status,
        "severity": str(previous.get("severity", "") or ""),
        "entity_key": str(previous.get("entity_key", "") or ""),
        "alert_count": int(previous.get("alert_count", 0) or 0),
        "ml_resume": False,
        "delete_alerts": False,
        "delete_events": False,
    }
    try:
        db = create_database(config)
        if db is None:
            return {
                "status": "failed",
                "action": preview.get("action", action),
                "incident_id": target_id,
                "incident": previous,
                "message": "Incident update failed because the database is unavailable.",
                "audit": {"status": "not_written"},
                "error": "database_unavailable",
            }
        now_ts = time.time()
        sql = "UPDATE incidents SET status = %s WHERE id = %s"
        params = (new_status, target_id)
        if preview.get("action") == "resolve" and "resolved_at" in raw_previous:
            sql = "UPDATE incidents SET status = %s, resolved_at = %s WHERE id = %s"
            params = (new_status, now_ts, target_id)
        elif preview.get("action") == "close" and "closed_at" in raw_previous:
            sql = "UPDATE incidents SET status = %s, closed_at = %s WHERE id = %s"
            params = (new_status, now_ts, target_id)
        db._execute(sql, params)
        try:
            audit_result = _record_audit(db, action_type, actor_value, target_id, reason_value, audit_details, "executed")
        except Exception as exc:
            return {
                "status": "failed",
                "action": preview.get("action", action),
                "incident_id": target_id,
                "incident": {**previous, "status": new_status},
                "message": "Incident state changed but audit write failed.",
                "audit": {"status": "failed", "reason": "audit_write_failed"},
                "error": _sanitize_error(exc),
            }
        return {
            "status": "executed",
            "action": preview.get("action", action),
            "incident_id": target_id,
            "incident": {**previous, "status": new_status},
            "message": f"Incident status updated to {new_status}.",
            "audit": audit_result,
            "error": None,
            "warning": preview.get("warning", ""),
            "would_update": preview.get("would_update", {}),
        }
    except Exception as exc:
        if db is not None:
            try:
                _record_audit(db, action_type, actor_value, target_id, reason_value, {**audit_details, "error": _sanitize_error(exc)}, "failed")
            except Exception:
                pass
        return {
            "status": "failed",
            "action": preview.get("action", action),
            "incident_id": target_id,
            "incident": previous,
            "message": "Incident update failed.",
            "audit": {"status": "attempted"},
            "error": _sanitize_error(exc),
        }
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
