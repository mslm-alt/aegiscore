from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict

from core.database import create_database

from .guard import build_guarded_action_preview, get_action_policy
from .models import GuardedActionRequest
from .secret_store import audit_user_action_available

_REPORT_ROOT = Path("data/exports")
_BUNDLE_ROOT = Path("data/diagnostic_bundles")
_VALID_REPORT_TYPES = {"selected_alert", "incident_report", "ml_readiness", "source_health"}
_EXTRA_REDACTION_PATTERNS = [
    re.compile(r"(?im)\b(authorization\s*[:=]\s*bearer\s+)([^\r\n]+)"),
    re.compile(r"(?im)\b((?:token|api_key|password|smtp_pass)\s*[:=]\s*)([^\s<>'\"]+)"),
    re.compile(r"(?im)\b((?:telegram_bot_token|gemini_api_key|openai_api_key)\s*[:=]\s*)([^\s<>'\"]+)"),
]


class UnsafeOutputPathError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = str(code or "unsafe_output_path")


def _facade():
    import ui.backend_facade as backend_facade

    return backend_facade


def confirmation_phrase_for(action_type: str) -> str:
    token = str(action_type or "").strip().lower()
    if token == "diagnostic_bundle_create":
        return "CREATE AEGISCORE DIAGNOSTIC BUNDLE"
    return "EXPORT AEGISCORE REPORT"


def _sanitize_filename(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-._")
    return text or "artifact"


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _path_has_symlink_component(path: Path, project_root: Path) -> str | None:
    try:
        relative = path.relative_to(project_root)
    except ValueError:
        return "output_path_outside_workspace"
    current = project_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return "output_root_symlink_blocked" if current == path else "parent_symlink_blocked"
    return None


def _resolve_output_root(project_root: Path, root: Path) -> tuple[Path, Path]:
    root_path = Path(root)
    if root_path.is_absolute() or ".." in root_path.parts:
        raise UnsafeOutputPathError("output_path_outside_workspace")
    candidate_root = project_root / root_path
    symlink_error = _path_has_symlink_component(candidate_root, project_root)
    if symlink_error:
        raise UnsafeOutputPathError(symlink_error)
    resolved_root = candidate_root.resolve(strict=False)
    if not _is_relative_to(resolved_root, project_root):
        raise UnsafeOutputPathError("output_path_outside_workspace")
    return candidate_root, resolved_root


def _safe_output_path(root: Path, basename: str, suffix: str = ".json", filename_hint: str | None = None) -> tuple[Path | None, str | None]:
    project_root = Path.cwd().resolve()
    try:
        candidate_root, resolved_root = _resolve_output_root(project_root, root)
    except UnsafeOutputPathError as exc:
        return None, exc.code
    if filename_hint:
        candidate = Path(str(filename_hint).strip())
        if ".." in candidate.parts:
            return None, "path_traversal_blocked"
        if candidate.is_absolute():
            try:
                resolved = candidate.resolve()
            except Exception:
                return None, "invalid_output_path"
            if project_root not in resolved.parents and resolved != project_root:
                return None, "output_path_outside_workspace"
        sanitized_hint = _sanitize_filename(candidate.name)
        stem = sanitized_hint.rsplit(".", 1)[0]
    else:
        stem = _sanitize_filename(basename)
    stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    output_path = candidate_root / f"{stem}_{stamp}{suffix}"
    if output_path.is_symlink():
        return None, "output_file_symlink_blocked"
    resolved_parent = output_path.parent.resolve(strict=False)
    if resolved_parent != resolved_root:
        return None, "output_path_outside_workspace"
    if not _is_relative_to(resolved_parent, project_root):
        return None, "output_path_outside_workspace"
    return output_path, None


def _write_json(path: Path, payload: Dict[str, Any], allowed_root: Path) -> Dict[str, Any]:
    project_root = Path.cwd().resolve()
    candidate_root, resolved_root = _resolve_output_root(project_root, allowed_root)
    if path.is_symlink():
        raise UnsafeOutputPathError("output_file_symlink_blocked")
    resolved_path = path.resolve(strict=False)
    if not _is_relative_to(resolved_path, resolved_root):
        raise UnsafeOutputPathError("output_path_outside_workspace")
    if not _is_relative_to(resolved_path, project_root):
        raise UnsafeOutputPathError("output_path_outside_workspace")
    if path.parent.resolve(strict=False) != resolved_root:
        raise UnsafeOutputPathError("output_path_outside_workspace")
    parent_symlink_error = _path_has_symlink_component(path.parent, project_root)
    if parent_symlink_error:
        raise UnsafeOutputPathError(parent_symlink_error)
    candidate_root.mkdir(parents=True, exist_ok=True)
    parent_symlink_error = _path_has_symlink_component(path.parent, project_root)
    if parent_symlink_error:
        raise UnsafeOutputPathError(parent_symlink_error)
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if path.is_symlink():
            raise UnsafeOutputPathError("output_file_symlink_blocked") from exc
        raise
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    return {"path": str(path), "size": path.stat().st_size}


def _apply_extra_redaction(value: Any) -> Any:
    backend_facade = _facade()
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_text = str(key or "").lower()
            if any(token in key_text for token in ("token", "key", "password", "secret", "smtp_pass", "authorization", "bearer")):
                redacted[key] = "<redacted>"
            else:
                redacted[key] = _apply_extra_redaction(item)
        return redacted
    if isinstance(value, list):
        return [_apply_extra_redaction(item) for item in value]
    if isinstance(value, tuple):
        return [_apply_extra_redaction(item) for item in value]
    if isinstance(value, str):
        text = str(value)
        for pattern in _EXTRA_REDACTION_PATTERNS:
            text = pattern.sub(lambda match: f"{match.group(1)}<redacted>", text)
        redact = getattr(backend_facade, "redact_sensitive_payload", lambda payload: payload)
        return redact(text)
    return value


def _record_audit(db: Any, action: str, actor: str, target: str, reason: str, details: Dict[str, Any], status: str) -> Dict[str, Any]:
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
            str(actor or "").strip() or "local-user",
            "reports",
            "artifact",
            "",
            str(target or "").strip(),
            str(reason or "").strip(),
            json.dumps(details or {}, ensure_ascii=False),
        ),
    )
    return {"status": "ok", "id": action_id, "error": None}


def _request(action_type: str, actor: str, role: str, reason: str, confirmation: str, dry_run_completed: bool, target: str) -> GuardedActionRequest:
    policy = get_action_policy(action_type)
    return GuardedActionRequest(
        action_id=f"{action_type}:{target or 'target'}",
        action_type=action_type,
        target=str(target or "").strip() or "target",
        target_type="file_artifact",
        actor=str(actor or "").strip(),
        reason=str(reason or "").strip(),
        confirmation_phrase=str(confirmation or "").strip(),
        required_confirmation_phrase=confirmation_phrase_for(action_type),
        dry_run_required=policy.dry_run_required,
        dry_run_completed=bool(dry_run_completed),
        role_required=policy.role_required,
        current_role=str(role or "").strip(),
        metadata={"source": "guarded_export_action"},
    )


def _report_payload(export_type: str, target_id: str | None, config_path: str | None = None) -> tuple[Dict[str, Any] | None, Dict[str, Any]]:
    backend_facade = _facade()
    token = str(export_type or "").strip()
    include = backend_facade.collect_safe_export_preview(token, target_id=target_id)
    if token not in _VALID_REPORT_TYPES:
        return None, include
    if token == "selected_alert":
        if not str(target_id or "").strip():
            return None, include
        detail = backend_facade.collect_alert_detail(int(target_id), config_path=config_path)
        raw_parsed = backend_facade.collect_alert_raw_parsed(int(target_id), config_path=config_path)
        investigation_context = backend_facade.collect_alert_investigation_summary(int(target_id), config_path=config_path)
        include = {
            **dict(include or {}),
            "would_include": list(dict(include or {}).get("would_include", []) or []) + ["investigation_context"],
        }
        payload = {
            "export_type": token,
            "target_id": str(target_id),
            "alert": detail.get("alert"),
            "detail": detail.get("detail"),
            "raw_parsed": raw_parsed,
            "investigation_context": {
                "summary": investigation_context.get("summary", {}),
                "timeline_summary": investigation_context.get("timeline_summary", {}),
                "warnings": investigation_context.get("warnings", []),
            },
        }
        return _apply_extra_redaction(backend_facade.redact_sensitive_payload(payload)), include
    if token == "incident_report":
        if not str(target_id or "").strip():
            return None, include
        detail = backend_facade.collect_incident_detail(int(target_id), config_path=config_path)
        payload = {
            "export_type": token,
            "target_id": str(target_id),
            "incident": detail.get("incident"),
            "detail": detail.get("detail"),
            "related_alerts": detail.get("related_alerts"),
        }
        return _apply_extra_redaction(backend_facade.redact_sensitive_payload(payload)), include
    if token == "ml_readiness":
        payload = {
            "export_type": token,
            "ml_summary": backend_facade.collect_ml_summary(config_path=config_path),
            "report_readiness": backend_facade.collect_report_readiness(config_path=config_path),
        }
        return _apply_extra_redaction(backend_facade.redact_sensitive_payload(payload)), include
    payload = {
        "export_type": token,
        "source_health": backend_facade.collect_sources_health(config_path=config_path),
        "diagnostics": backend_facade.collect_diagnostics_summary(config_path=config_path),
    }
    return _apply_extra_redaction(backend_facade.redact_sensitive_payload(payload)), include


def preview_report_export(
    config: Dict[str, Any],
    export_type: str,
    target_id: str | None,
    actor: str,
    role: str,
    reason: str,
    confirmation: str = "",
    dry_run_completed: bool = False,
    filename_hint: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    token = str(export_type or "").strip()
    target = str(target_id or "").strip()
    request = _request("report_export", actor, role, reason, confirmation, dry_run_completed, token or "report")
    guard = build_guarded_action_preview(request).to_dict()
    payload, include = _report_payload(token, target, config_path=config_path)
    output_path, path_error = _safe_output_path(_REPORT_ROOT, f"{token}_{target or 'summary'}", filename_hint=filename_hint)
    if token not in _VALID_REPORT_TYPES:
        guard["status"] = "denied"
        guard["execution_enabled"] = False
        guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["valid export type"]
    if token in {"selected_alert", "incident_report"} and not target:
        guard["status"] = "denied"
        guard["execution_enabled"] = False
        guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["target id"]
    if path_error:
        guard["status"] = "denied"
        guard["execution_enabled"] = False
        guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["safe output path"]
    audit_available, audit_error = audit_user_action_available(config)
    if not audit_available:
        guard["status"] = "denied"
        guard["execution_enabled"] = False
        guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["audit availability"]
    return {
        "status": str(guard.get("status", "denied")),
        "export_type": token,
        "target_id": target,
        "would_include": list(include.get("would_include", []) or []),
        "would_redact": list(include.get("would_redact", []) or []),
        "would_exclude": list(include.get("would_exclude", []) or []),
        "output_path": str(output_path) if output_path is not None else "",
        "guard": guard,
        "required_confirmation_phrase": request.required_confirmation_phrase,
        "message": guard.get("message", include.get("message", "preview")),
        "audit": {"available": audit_available, "error": audit_error},
        "redaction_enabled": True,
        "error": path_error,
        "preview_payload": payload if payload is not None else None,
    }


def execute_report_export(
    config: Dict[str, Any],
    export_type: str,
    target_id: str | None,
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
    filename_hint: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    preview = preview_report_export(
        export_type=export_type,
        config=config,
        target_id=target_id,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
        filename_hint=filename_hint,
        config_path=config_path,
    )
    guard = dict(preview.get("guard", {}) or {})
    audit = dict(preview.get("audit", {}) or {})
    if not bool(audit.get("available", False)):
        return {
            "status": "denied",
            "export_type": preview.get("export_type", export_type),
            "output_path": preview.get("output_path", ""),
            "message": "Audit is required before file export can run.",
            "error": "audit_unavailable",
        }
    if preview.get("status") != "ready" or not bool(guard.get("execution_enabled", False)):
        return {
            "status": "denied",
            "export_type": preview.get("export_type", export_type),
            "output_path": preview.get("output_path", ""),
            "message": preview.get("message", guard.get("message", "Guard validation failed.")),
            "error": preview.get("error") or "guard_denied",
        }
    path = Path(str(preview.get("output_path", "") or ""))
    payload = dict(preview.get("preview_payload", {}) or {})
    try:
        write_result = _write_json(path, payload, _REPORT_ROOT)
    except UnsafeOutputPathError as exc:
        return {
            "status": "denied",
            "export_type": preview.get("export_type", export_type),
            "output_path": preview.get("output_path", ""),
            "message": "Output path failed safety validation.",
            "error": exc.code,
        }
    db = None
    try:
        db = create_database(config)
        if db is None:
            return {
                "status": "failed",
                "export_type": preview.get("export_type", export_type),
                "output_path": write_result["path"],
                "message": "Export file was written but audit database is unavailable.",
                "error": "database_unavailable",
            }
        audit_result = _record_audit(
            db=db,
            action="report_export",
            actor=actor,
            target=Path(write_result["path"]).name,
            reason=reason,
            details={
                "output_path": os.path.relpath(write_result["path"], Path.cwd()),
                "export_type": preview.get("export_type", export_type),
                "included_sections": list(preview.get("would_include", []) or []),
                "redaction_enabled": True,
                "file_size": int(write_result["size"]),
                "no_secrets": True,
            },
            status="executed",
        )
        return {
            "status": "executed",
            "export_type": preview.get("export_type", export_type),
            "output_path": write_result["path"],
            "file_size": int(write_result["size"]),
            "audit": audit_result,
            "message": "Report export completed.",
            "error": None,
        }
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass


def preview_diagnostic_bundle_create(
    config: Dict[str, Any],
    actor: str,
    role: str,
    reason: str,
    confirmation: str = "",
    dry_run_completed: bool = False,
    filename_hint: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    backend_facade = _facade()
    request = _request("diagnostic_bundle_create", actor, role, reason, confirmation, dry_run_completed, "diagnostic_bundle")
    guard = build_guarded_action_preview(request).to_dict()
    output_path, path_error = _safe_output_path(_BUNDLE_ROOT, "diagnostic_bundle", filename_hint=filename_hint)
    snapshot = backend_facade.collect_diagnostic_bundle_preview(config_path=config_path)
    redact = getattr(backend_facade, "redact_sensitive_payload", lambda payload: payload)
    sanitized_snapshot = _apply_extra_redaction(redact(dict(snapshot.get("snapshot", {}) or {})))
    if path_error:
        guard["status"] = "denied"
        guard["execution_enabled"] = False
        guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["safe output path"]
    audit_available, audit_error = audit_user_action_available(config)
    if not audit_available:
        guard["status"] = "denied"
        guard["execution_enabled"] = False
        guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["audit availability"]
    return {
        "status": str(guard.get("status", "denied")),
        "would_include": list(snapshot.get("would_include", []) or []),
        "would_redact": list(snapshot.get("would_redact", []) or []),
        "would_exclude": list(snapshot.get("would_exclude", []) or []),
        "output_path": str(output_path) if output_path is not None else "",
        "guard": guard,
        "required_confirmation_phrase": request.required_confirmation_phrase,
        "message": guard.get("message", snapshot.get("message", "preview")),
        "audit": {"available": audit_available, "error": audit_error},
        "snapshot": sanitized_snapshot,
        "redaction_enabled": True,
        "error": path_error,
    }


def execute_diagnostic_bundle_create(
    config: Dict[str, Any],
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
    filename_hint: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    preview = preview_diagnostic_bundle_create(
        actor=actor,
        config=config,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
        filename_hint=filename_hint,
        config_path=config_path,
    )
    guard = dict(preview.get("guard", {}) or {})
    audit = dict(preview.get("audit", {}) or {})
    if not bool(audit.get("available", False)):
        return {
            "status": "denied",
            "output_path": preview.get("output_path", ""),
            "message": "Audit is required before diagnostic bundle creation can run.",
            "error": "audit_unavailable",
        }
    if preview.get("status") != "ready" or not bool(guard.get("execution_enabled", False)):
        return {
            "status": "denied",
            "output_path": preview.get("output_path", ""),
            "message": preview.get("message", guard.get("message", "Guard validation failed.")),
            "error": preview.get("error") or "guard_denied",
        }
    path = Path(str(preview.get("output_path", "") or ""))
    payload = {
        "kind": "diagnostic_bundle",
        "created_at": time.time(),
        "snapshot": dict(preview.get("snapshot", {}) or {}),
        "redaction_enabled": True,
    }
    try:
        write_result = _write_json(path, payload, _BUNDLE_ROOT)
    except UnsafeOutputPathError as exc:
        return {
            "status": "denied",
            "output_path": preview.get("output_path", ""),
            "message": "Output path failed safety validation.",
            "error": exc.code,
        }
    db = None
    try:
        db = create_database(config)
        if db is None:
            return {
                "status": "failed",
                "output_path": write_result["path"],
                "message": "Diagnostic bundle was written but audit database is unavailable.",
                "error": "database_unavailable",
            }
        audit_result = _record_audit(
            db=db,
            action="diagnostic_bundle_create",
            actor=actor,
            target=Path(write_result["path"]).name,
            reason=reason,
            details={
                "output_path": os.path.relpath(write_result["path"], Path.cwd()),
                "export_type": "diagnostic_bundle",
                "included_sections": list(preview.get("would_include", []) or []),
                "redaction_enabled": True,
                "file_size": int(write_result["size"]),
                "no_secrets": True,
            },
            status="executed",
        )
        return {
            "status": "executed",
            "output_path": write_result["path"],
            "file_size": int(write_result["size"]),
            "audit": audit_result,
            "message": "Diagnostic bundle creation completed.",
            "error": None,
        }
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
