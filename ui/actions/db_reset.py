from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from core.database import create_database

from .guard import build_guarded_action_preview, get_action_policy
from .models import GuardedActionRequest
from .secret_store import audit_user_action_available

_RUNTIME_TABLES = [
    "alerts",
    "alerts_archive",
    "incidents",
    "events_recent",
    "risk_history",
    "entity_state",
    "cooldowns",
    "dedup_cache",
    "process_tree",
    "sequence_state",
    "cross_host_state",
    "system_stats",
    "ip_block_suggestions",
    "ip_block_actions",
]
_LABEL_TABLES = ["labels"]
_AUDIT_TABLES = ["user_actions"]
_PRESERVED_TABLES = ["schema_version", "model_registry", "system_config", "phase_history"]
_RESETTABLE_TABLES = tuple([*_RUNTIME_TABLES, *_LABEL_TABLES, *_AUDIT_TABLES])
_TABLE_COUNT_SQL = {
    "alerts": "SELECT COUNT(*) AS count FROM alerts",
    "alerts_archive": "SELECT COUNT(*) AS count FROM alerts_archive",
    "incidents": "SELECT COUNT(*) AS count FROM incidents",
    "events_recent": "SELECT COUNT(*) AS count FROM events_recent",
    "risk_history": "SELECT COUNT(*) AS count FROM risk_history",
    "entity_state": "SELECT COUNT(*) AS count FROM entity_state",
    "cooldowns": "SELECT COUNT(*) AS count FROM cooldowns",
    "dedup_cache": "SELECT COUNT(*) AS count FROM dedup_cache",
    "process_tree": "SELECT COUNT(*) AS count FROM process_tree",
    "sequence_state": "SELECT COUNT(*) AS count FROM sequence_state",
    "cross_host_state": "SELECT COUNT(*) AS count FROM cross_host_state",
    "system_stats": "SELECT COUNT(*) AS count FROM system_stats",
    "ip_block_suggestions": "SELECT COUNT(*) AS count FROM ip_block_suggestions",
    "ip_block_actions": "SELECT COUNT(*) AS count FROM ip_block_actions",
    "labels": "SELECT COUNT(*) AS count FROM labels",
    "user_actions": "SELECT COUNT(*) AS count FROM user_actions",
}
_TABLE_DELETE_SQL = {
    "alerts": "DELETE FROM alerts",
    "alerts_archive": "DELETE FROM alerts_archive",
    "incidents": "DELETE FROM incidents",
    "events_recent": "DELETE FROM events_recent",
    "risk_history": "DELETE FROM risk_history",
    "entity_state": "DELETE FROM entity_state",
    "cooldowns": "DELETE FROM cooldowns",
    "dedup_cache": "DELETE FROM dedup_cache",
    "process_tree": "DELETE FROM process_tree",
    "sequence_state": "DELETE FROM sequence_state",
    "cross_host_state": "DELETE FROM cross_host_state",
    "system_stats": "DELETE FROM system_stats",
    "ip_block_suggestions": "DELETE FROM ip_block_suggestions",
    "ip_block_actions": "DELETE FROM ip_block_actions",
    "labels": "DELETE FROM labels",
    "user_actions": "DELETE FROM user_actions",
}


def _validate_reset_table_name(table_name: str) -> str:
    token = str(table_name or "").strip()
    if token not in _RESETTABLE_TABLES:
        raise ValueError("invalid_reset_table")
    return token


def _bool_scope(include_labels: bool, include_audit_log: bool) -> Dict[str, bool]:
    return {
        "runtime_only": True,
        "include_labels": bool(include_labels),
        "include_audit_log": bool(include_audit_log),
    }


def confirmation_phrase_for_scope(include_labels: bool = False, include_audit_log: bool = False) -> str:
    if include_labels and include_audit_log:
        return "RESET AEGISCORE RUNTIME DATA LABELS AND AUDIT LOG"
    if include_labels:
        return "RESET AEGISCORE RUNTIME DATA AND LABELS"
    if include_audit_log:
        return "RESET AEGISCORE RUNTIME DATA AND AUDIT LOG"
    return "RESET AEGISCORE RUNTIME DATA"


def _snapshot_path() -> Path:
    stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    return Path("data/reset_backups") / f"db_reset_{stamp}.json"


def _table_exists(db: Any, table_name: str) -> bool:
    table_name = _validate_reset_table_name(table_name)
    row = db._execute("SELECT to_regclass(%s) AS name", (f"public.{table_name}",), fetch="one")
    if isinstance(row, dict):
        return bool(row.get("name"))
    return bool(row)


def _row_count(db: Any, table_name: str) -> int:
    table_name = _validate_reset_table_name(table_name)
    row = db._execute(_TABLE_COUNT_SQL[table_name], fetch="one")
    if isinstance(row, dict):
        return int(row.get("count", 0) or 0)
    return 0


def _table_inventory(db: Any, include_labels: bool, include_audit_log: bool) -> List[Dict[str, Any]]:
    selected = set(_RUNTIME_TABLES)
    if include_labels:
        selected.update(_LABEL_TABLES)
    if include_audit_log:
        selected.update(_AUDIT_TABLES)
    rows: List[Dict[str, Any]] = []
    for table_name in _RESETTABLE_TABLES:
        exists = _table_exists(db, table_name)
        count = _row_count(db, table_name) if exists else 0
        rows.append({
            "name": table_name,
            "exists": exists,
            "count": count,
            "will_reset": table_name in selected and exists,
        })
    return rows


def _warnings(scope: Dict[str, bool], tables: List[Dict[str, Any]]) -> List[str]:
    warnings = [
        "This resets runtime data only. Schema and connection settings remain preserved.",
        "A reset snapshot is created before data reset execution begins.",
    ]
    if scope.get("include_labels"):
        warnings.append("Including labels removes stored labeling state and may affect future review context.")
    if scope.get("include_audit_log"):
        warnings.append("Including audit log clears prior user action history after the reset snapshot is written.")
    if not any(bool(item.get("will_reset")) and int(item.get("count", 0) or 0) > 0 for item in tables):
        warnings.append("No matching runtime rows are currently queued for deletion.")
    return warnings


def _build_request(actor: str, role: str, reason: str, confirmation: str, dry_run_completed: bool, include_labels: bool, include_audit_log: bool) -> GuardedActionRequest:
    policy = get_action_policy("db_reset")
    return GuardedActionRequest(
        action_id="db_reset:runtime",
        action_type="db_reset",
        target="runtime_data_reset",
        target_type="database",
        actor=str(actor or "").strip(),
        reason=str(reason or "").strip(),
        confirmation_phrase=str(confirmation or "").strip(),
        required_confirmation_phrase=confirmation_phrase_for_scope(include_labels=include_labels, include_audit_log=include_audit_log),
        dry_run_required=policy.dry_run_required,
        dry_run_completed=bool(dry_run_completed),
        role_required=policy.role_required,
        current_role=str(role or "").strip(),
        metadata={"source": "guarded_db_reset"},
    )


def _snapshot_payload(actor: str, reason: str, scope: Dict[str, bool], tables: List[Dict[str, Any]], preview: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "kind": "db_reset_snapshot",
        "created_at": time.time(),
        "actor": str(actor or "").strip(),
        "reason": str(reason or "").strip(),
        "scope": scope,
        "tables": tables,
        "total_rows_to_delete": int(preview.get("total_rows_to_delete", 0) or 0),
        "required_confirmation_phrase": str(preview.get("required_confirmation_phrase", "") or ""),
        "warnings": list(preview.get("warnings", []) or []),
        "secrets_included": False,
    }


def _write_snapshot(path: Path, payload: Dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return str(path)


def _record_audit_row(conn: Any, actor: str, reason: str, scope: Dict[str, bool], snapshot_path: str, status: str, total_rows: int, details_extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    now = time.time()
    action_id = int(now * 1000000)
    details = {
        "scope": scope,
        "snapshot_path": snapshot_path,
        "total_rows_to_delete": total_rows,
        "include_labels": bool(scope.get("include_labels")),
        "include_audit_log": bool(scope.get("include_audit_log")),
        "secrets_included": False,
    }
    if details_extra:
        details.update(details_extra)
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO user_actions (id, ts, action, status, actor, screen, entity_type, entity_id, target, summary, details) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)",
            (
                action_id,
                now,
                "db_reset",
                status,
                str(actor or "").strip() or "local-user",
                "db_management",
                "database",
                "",
                "runtime_data_reset",
                str(reason or "").strip(),
                json.dumps(details, ensure_ascii=False),
            ),
        )
    return {"status": "ok", "id": action_id, "error": None}


def preview_guarded_db_reset(
    config: Dict[str, Any],
    actor: str,
    role: str,
    reason: str,
    confirmation: str = "",
    dry_run_completed: bool = False,
    include_labels: bool = False,
    include_audit_log: bool = False,
) -> Dict[str, Any]:
    scope = _bool_scope(include_labels=include_labels, include_audit_log=include_audit_log)
    request = _build_request(actor, role, reason, confirmation, dry_run_completed, include_labels, include_audit_log)
    guard = build_guarded_action_preview(request).to_dict()
    backup_preview = str(_snapshot_path())
    audit_available = False
    audit_error = ""
    db = None
    try:
        db = create_database(config)
        if db is None:
            guard["status"] = "denied"
            guard["execution_enabled"] = False
            guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["database availability", "preview counts", "backup plan"]
            return {
                "status": "denied",
                "scope": scope,
                "tables": [],
                "will_preserve": list(_PRESERVED_TABLES),
                "will_reset": [],
                "total_rows_to_delete": 0,
                "guard": guard,
                "required_confirmation_phrase": request.required_confirmation_phrase,
                "backup": {"will_create_snapshot": True, "path_preview": backup_preview},
                "warnings": ["Database connection is unavailable."],
                "message": "Execution is blocked because the database is unavailable.",
                "audit": {"available": False, "error": "database_unavailable"},
            }
        tables = _table_inventory(db, include_labels=include_labels, include_audit_log=include_audit_log)
        will_reset = [item["name"] for item in tables if item.get("will_reset")]
        total_rows = sum(int(item.get("count", 0) or 0) for item in tables if item.get("will_reset"))
        audit_available, audit_error = audit_user_action_available(config)
        if not audit_available and not include_audit_log:
            guard["status"] = "denied"
            guard["execution_enabled"] = False
            guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["audit availability"]
        if not backup_preview:
            guard["status"] = "denied"
            guard["execution_enabled"] = False
            guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["backup plan"]
        warnings = _warnings(scope, tables)
        message = guard.get("message", "Preview only.")
        if include_audit_log:
            warnings.append("Pre-reset user action history is preserved in the snapshot artifact because audit log reset is enabled.")
        return {
            "status": str(guard.get("status", "denied")),
            "scope": scope,
            "tables": tables,
            "will_preserve": list(_PRESERVED_TABLES),
            "will_reset": will_reset,
            "total_rows_to_delete": total_rows,
            "guard": guard,
            "required_confirmation_phrase": request.required_confirmation_phrase,
            "backup": {"will_create_snapshot": True, "path_preview": backup_preview},
            "warnings": warnings,
            "message": message,
            "audit": {"available": audit_available, "error": audit_error},
        }
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass


def execute_guarded_db_reset(
    config: Dict[str, Any],
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
    include_labels: bool = False,
    include_audit_log: bool = False,
) -> Dict[str, Any]:
    preview = preview_guarded_db_reset(
        config=config,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
        include_labels=include_labels,
        include_audit_log=include_audit_log,
    )
    guard = dict(preview.get("guard", {}) or {})
    audit = dict(preview.get("audit", {}) or {})
    if not bool(audit.get("available", False)) and not include_audit_log:
        return {
            "status": "denied",
            "scope": preview.get("scope", {}),
            "tables_reset": [],
            "rows_deleted_estimate": 0,
            "snapshot_path": None,
            "audit_written": False,
            "message": "Audit is required before runtime data reset can run.",
            "error": "audit_unavailable",
        }
    if preview.get("status") != "ready" or not bool(guard.get("execution_enabled", False)):
        return {
            "status": "denied",
            "scope": preview.get("scope", {}),
            "tables_reset": [],
            "rows_deleted_estimate": int(preview.get("total_rows_to_delete", 0) or 0),
            "snapshot_path": None,
            "audit_written": False,
            "message": preview.get("message", guard.get("message", "Guard validation failed.")),
            "error": "guard_denied",
        }

    snapshot_file = _snapshot_path()
    snapshot_payload = _snapshot_payload(
        actor=str(actor or "").strip(),
        reason=str(reason or "").strip(),
        scope=dict(preview.get("scope", {}) or {}),
        tables=list(preview.get("tables", []) or []),
        preview=preview,
    )
    snapshot_path = _write_snapshot(snapshot_file, snapshot_payload)

    db = None
    conn = None
    pre_audit_written = False
    try:
        db = create_database(config)
        if db is None:
            return {
                "status": "failed",
                "scope": preview.get("scope", {}),
                "tables_reset": [],
                "rows_deleted_estimate": int(preview.get("total_rows_to_delete", 0) or 0),
                "snapshot_path": snapshot_path,
                "audit_written": False,
                "message": "Runtime data reset failed because the database is unavailable.",
                "error": "database_unavailable",
            }
        conn = db._conn() if hasattr(db, "_conn") else None
        if conn is None:
            return {
                "status": "failed",
                "scope": preview.get("scope", {}),
                "tables_reset": [],
                "rows_deleted_estimate": int(preview.get("total_rows_to_delete", 0) or 0),
                "snapshot_path": snapshot_path,
                "audit_written": False,
                "message": "Runtime data reset requires direct transaction support.",
                "error": "transaction_unavailable",
            }

        if not include_audit_log:
            with conn.cursor() as cur:
                _record_audit_row(
                    conn=conn,
                    actor=actor,
                    reason=reason,
                    scope=dict(preview.get("scope", {}) or {}),
                    snapshot_path=snapshot_path,
                    status="started",
                    total_rows=int(preview.get("total_rows_to_delete", 0) or 0),
                    details_extra={"phase": "pre_reset"},
                )
            pre_audit_written = True
            conn.commit()

        table_names = [_validate_reset_table_name(str(name)) for name in list(preview.get("will_reset", []) or []) if str(name) in _RESETTABLE_TABLES]
        deleted_rows = 0
        with conn.cursor() as cur:
            for table_name in table_names:
                count_before = 0
                for item in list(preview.get("tables", []) or []):
                    if item.get("name") == table_name:
                        count_before = int(item.get("count", 0) or 0)
                        break
                cur.execute(_TABLE_DELETE_SQL[table_name])
                deleted_rows += count_before
        conn.commit()

        post_audit_written = pre_audit_written
        if include_audit_log:
            with conn.cursor() as cur:
                _record_audit_row(
                    conn=conn,
                    actor=actor,
                    reason=reason,
                    scope=dict(preview.get("scope", {}) or {}),
                    snapshot_path=snapshot_path,
                    status="executed",
                    total_rows=deleted_rows,
                    details_extra={"phase": "post_reset", "audit_log_was_reset": True},
                )
            conn.commit()
            post_audit_written = True

        verification_tables = _table_inventory(db, include_labels=include_labels, include_audit_log=include_audit_log)
        remaining_rows = sum(int(item.get("count", 0) or 0) for item in verification_tables if item.get("will_reset"))
        return {
            "status": "executed",
            "scope": preview.get("scope", {}),
            "tables_reset": table_names,
            "rows_deleted_estimate": int(preview.get("total_rows_to_delete", 0) or 0),
            "rows_remaining_after_reset": remaining_rows,
            "snapshot_path": snapshot_path,
            "audit_written": post_audit_written,
            "message": "Runtime data reset completed.",
            "error": None,
        }
    except Exception as exc:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        return {
            "status": "failed",
            "scope": preview.get("scope", {}),
            "tables_reset": [],
            "rows_deleted_estimate": int(preview.get("total_rows_to_delete", 0) or 0),
            "snapshot_path": snapshot_path,
            "audit_written": pre_audit_written,
            "message": "Runtime data reset failed.",
            "error": str(exc)[:160],
        }
    finally:
        if db is not None and conn is not None and hasattr(db, "_release"):
            try:
                db._release(conn)
                conn = None
            except Exception:
                pass
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
