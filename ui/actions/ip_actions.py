from __future__ import annotations

import ipaddress
import shutil
import socket
from typing import Any, Dict, List, Tuple

from core.database import create_database
from core.ip_blocking import IPBlocker

from .guard import build_guarded_action_preview, get_action_policy, required_confirmation_for
from .models import GuardedActionRequest
from .secret_store import audit_user_action_available

_REAL_APPLY_BACKENDS = {"firewalld", "ufw"}
_ELEVATED_REQUIRED_REASON = "elevated_privileges_required"


def _sanitize_error(error: str) -> str:
    text = str(error or "").strip()
    if not text:
        return ""
    if text.startswith("command_failed:"):
        return "command_failed"
    if "firewall-cmd" in text:
        return "firewalld_command_failed"
    if "ufw" in text:
        return "ufw_command_failed"
    return text[:160]


def _privilege_message() -> str:
    return "AegisCore must be run with elevated privileges to apply firewall rules."


def _has_permission_error(text: str) -> bool:
    lowered = str(text or "").strip().lower()
    return any(token in lowered for token in ("permission denied", "must be root", "you need to be root"))


def _preferred_backend(config: Dict[str, Any]) -> str:
    token = str(((config or {}).get("ip_blocking", {}) or {}).get("default_backend", "auto") or "").strip().lower()
    aliases = {
        "auto": "auto",
        "firewalld": "firewalld",
        "ufw": "ufw",
        "nft": "nftables",
        "nftables": "nftables",
        "iptables": "iptables",
    }
    return aliases.get(token, "auto")


def _probe_backend_runtime(blocker: IPBlocker, backend: str) -> Dict[str, Any]:
    runtime = {
        "backend": backend or "",
        "available": False,
        "requires_elevation": False,
        "unsupported": False,
    }
    if backend == "firewalld":
        if not shutil.which("firewall-cmd"):
            runtime["unsupported"] = True
            return runtime
        rc, stdout, stderr = blocker._command_runner(["firewall-cmd", "--state"])
        text = " ".join(part for part in (stdout, stderr) if part).strip()
        if rc == 0 and str(stdout or "").strip().lower() == "running":
            runtime["available"] = True
        elif _has_permission_error(text):
            runtime["requires_elevation"] = True
        return runtime
    if backend == "ufw":
        if not shutil.which("ufw"):
            runtime["unsupported"] = True
            return runtime
        rc, stdout, stderr = blocker._command_runner(["ufw", "status"])
        text = " ".join(part for part in (stdout, stderr) if part).strip()
        lowered = text.lower()
        if rc == 0 and "inactive" not in lowered and ("status: active" in lowered or str(stdout or "").strip()):
            runtime["available"] = True
        elif _has_permission_error(text):
            runtime["requires_elevation"] = True
        return runtime
    runtime["unsupported"] = True
    return runtime


def _capability_message(reason: str, requires_elevation: bool) -> str:
    if requires_elevation or reason == _ELEVATED_REQUIRED_REASON:
        return _privilege_message()
    if reason == "real_apply_unsupported_for_backend":
        return "Real blocking is not supported by the current firewall backend."
    if reason == "backend_unavailable":
        return "No supported firewall backend is currently available for manual IP actions."
    return ""


def _self_host_ips() -> set[str]:
    values: set[str] = set()
    try:
        hostname = socket.gethostname()
        for family, _socktype, _proto, _canon, sockaddr in socket.getaddrinfo(hostname, None):
            if family in (socket.AF_INET, socket.AF_INET6) and sockaddr:
                values.add(str(sockaddr[0]))
    except Exception:
        return set()
    return values


def validate_ip_target(ip: str) -> Dict[str, Any]:
    raw = str(ip or "").strip()
    result = {
        "valid": False,
        "normalized_ip": raw,
        "category": "invalid",
        "warning": "",
        "error": "",
        "allowed": False,
    }
    if not raw:
        result["error"] = "empty_ip"
        return result
    try:
        ip_obj = ipaddress.ip_address(raw)
    except ValueError:
        result["error"] = "invalid_ip"
        return result

    result["normalized_ip"] = ip_obj.compressed
    if ip_obj.is_unspecified:
        result["category"] = "unspecified"
        result["error"] = "unspecified_ip"
        return result
    if ip_obj.is_loopback:
        result["category"] = "loopback"
        result["error"] = "loopback_ip"
        return result
    if ip_obj.is_multicast:
        result["category"] = "multicast"
        result["error"] = "multicast_ip"
        return result
    if ip_obj.version == 4 and ip_obj.compressed == "255.255.255.255":
        result["category"] = "broadcast"
        result["error"] = "broadcast_ip"
        return result
    if getattr(ip_obj, "is_link_local", False):
        result["category"] = "link_local"
        result["error"] = "link_local_ip"
        return result
    if ip_obj.is_reserved:
        result["category"] = "reserved"
        result["error"] = "reserved_ip"
        return result
    if ip_obj.compressed in _self_host_ips():
        result["category"] = "self_host"
        result["error"] = "self_host_ip"
        return result
    if ip_obj.is_private:
        result["category"] = "private_lab"
        result["warning"] = "private/lab ip blocked by default in guarded UI"
        result["error"] = "private_ip"
        return result

    result["valid"] = True
    result["allowed"] = True
    result["category"] = "public"
    return result


def _capability_payload(config: Dict[str, Any], blocker: IPBlocker) -> Dict[str, Any]:
    preferred = _preferred_backend(config)
    backend, supported = blocker._detect_backend()
    runtime = _probe_backend_runtime(blocker, backend) if backend else {
        "backend": "",
        "available": False,
        "requires_elevation": False,
        "unsupported": False,
    }
    reason = blocker._real_apply_error(backend, supported)
    requires_elevation = False
    backend_supported = backend in _REAL_APPLY_BACKENDS
    if backend_supported and runtime.get("requires_elevation", False):
        requires_elevation = True
        reason = _ELEVATED_REQUIRED_REASON
    elif not backend_supported:
        reason = "real_apply_unsupported_for_backend" if backend else "backend_unavailable"
    elif not backend:
        reason = "backend_unavailable"
    elif reason and preferred in {"auto", backend} and runtime.get("available", False) is False and not runtime.get("requires_elevation", False):
        reason = reason or "backend_unavailable"
    return {
        "backend": backend or "none",
        "real_apply_supported": not bool(reason),
        "dry_run_supported": bool(backend),
        "plan_supported": bool(backend),
        "requires_elevation": requires_elevation,
        "backend_supported": backend_supported,
        "reason": reason or ("ready" if backend else "backend_unavailable"),
        "message": _capability_message(reason or ("ready" if backend else "backend_unavailable"), requires_elevation),
        "supported": bool(supported),
    }


def _active_block(db, ip: str) -> Dict[str, Any] | None:
    if db is None or not hasattr(db, "get_active_ip_block"):
        return None
    try:
        active = db.get_active_ip_block(ip)
    except Exception:
        return None
    return dict(active or {}) if active else None


def _sanitize_command_plan(commands: List[Any]) -> List[str]:
    lines: List[str] = []
    for cmd in commands or []:
        argv = list(getattr(cmd, "argv", []) or [])
        description = str(getattr(cmd, "description", "") or "").strip()
        joined = " ".join(str(part) for part in argv)
        lines.append(f"{description}: {joined}".strip(": "))
    return lines


def preview_guarded_ip_action(
    config: Dict[str, Any],
    action: str,
    ip: str,
    actor: str,
    role: str,
    reason: str,
    confirmation: str = "",
    dry_run_completed: bool = False,
) -> Dict[str, Any]:
    token = "unblock" if str(action or "").strip().lower() == "unblock" else "block"
    action_type = "ip_unblock" if token == "unblock" else "ip_block"
    ip_validation = validate_ip_target(ip)
    normalized_ip = str(ip_validation.get("normalized_ip", "") or "")
    request = GuardedActionRequest(
        action_id=f"{action_type}:{normalized_ip or 'target'}",
        action_type=action_type,
        target=normalized_ip or str(ip or "").strip(),
        target_type="ip",
        actor=str(actor or "").strip(),
        reason=str(reason or "").strip(),
        confirmation_phrase=str(confirmation or "").strip(),
        required_confirmation_phrase=required_confirmation_for(action_type, normalized_ip or str(ip or "").strip()),
        dry_run_required=True,
        dry_run_completed=bool(dry_run_completed),
        role_required=get_action_policy(action_type).role_required,
        current_role=str(role or "").strip(),
        metadata={"source": "guarded_operator_ip_action"},
    )
    guard = build_guarded_action_preview(request).to_dict()
    db = None
    try:
        db = create_database(config)
        blocker = IPBlocker(config, db)
        capability = _capability_payload(config, blocker)
        active = _active_block(db, normalized_ip) if ip_validation.get("allowed") else None
        backend = str(capability.get("backend", "") or "none")
        commands: List[str] = []
        message = guard.get("message", "Preview only.")
        status = guard.get("status", "denied")
        if not ip_validation.get("allowed"):
            guard["status"] = "denied"
            guard["execution_enabled"] = False
            guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["valid ip"]
            message = f"Execution is blocked: {ip_validation.get('error', 'invalid_ip')}"
            backend = str(capability.get("backend", "") or "none")
            return {
                "status": "denied",
                "action": token,
                "ip": normalized_ip or str(ip or "").strip(),
                "ip_validation": ip_validation,
                "backend": backend,
                "capability": capability,
                "guard": guard,
                "would_run": [],
                "audit_required": True,
                "raw_command_included": False,
                "message": message,
            }

        if token == "block" and active:
            guard["status"] = "denied"
            guard["execution_enabled"] = False
            guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["not already blocked"]
            message = "Execution is blocked: already_blocked"
        elif token == "unblock":
            if not active:
                guard["status"] = "denied"
                guard["execution_enabled"] = False
                guard["missing_guards"] = list(guard.get("missing_guards", [])) + ["existing block"]
                message = "Execution is blocked: not_blocked"
            else:
                commands = _sanitize_command_plan(
                    blocker._build_command_plan("unblock", ipaddress.ip_address(normalized_ip), str(active.get("backend", "") or ""))[1]
                )
                backend = str(active.get("backend", "") or capability.get("backend", "none"))
                capability = {
                    "backend": backend,
                    "real_apply_supported": backend in {"firewalld", "ufw"},
                    "dry_run_supported": bool(backend),
                    "plan_supported": bool(backend),
                    "requires_elevation": False,
                    "backend_supported": backend in _REAL_APPLY_BACKENDS,
                    "reason": "ready" if backend in {"firewalld", "ufw"} else "real_apply_unsupported_for_backend",
                    "message": "" if backend in {"firewalld", "ufw"} else "Real blocking is not supported by the current firewall backend.",
                }
        if token == "block" and not active:
            _rule_ref, plan = blocker._build_command_plan("block", ipaddress.ip_address(normalized_ip), backend if backend != "none" else "")
            commands = _sanitize_command_plan(plan)

        if not capability.get("real_apply_supported", False):
            guard["status"] = "denied"
            guard["execution_enabled"] = False
            missing_guard = "elevated privileges" if capability.get("requires_elevation", False) else "real apply support"
            guard["missing_guards"] = list(guard.get("missing_guards", [])) + [missing_guard]
            status = "denied"
            message = str(capability.get("message", "") or "Execution is blocked until a real-apply capable firewall backend is available.")
        else:
            status = str(guard.get("status", status))
            if status == "ready":
                message = "All guards and backend capability checks passed for manual execution."
            elif guard.get("missing_guards"):
                message = guard.get("message", message)
        return {
            "status": status,
            "action": token,
            "ip": normalized_ip,
            "ip_validation": ip_validation,
            "backend": backend,
            "capability": capability,
            "guard": guard,
            "would_run": commands,
            "audit_required": True,
            "raw_command_included": False,
            "message": message,
        }
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass


def execute_guarded_ip_action(
    config: Dict[str, Any],
    action: str,
    ip: str,
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
) -> Dict[str, Any]:
    preview = preview_guarded_ip_action(
        config=config,
        action=action,
        ip=ip,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
    )
    guard = dict(preview.get("guard", {}) or {})
    if preview.get("status") != "ready" or not bool(guard.get("execution_enabled", False)):
        return {
            "status": "denied",
            "action": preview.get("action", action),
            "ip": preview.get("ip", ip),
            "message": preview.get("message", guard.get("message", "Guard validation failed.")),
            "backend": preview.get("backend", ""),
            "audit": {"status": "denied", "reason": "guard_denied"},
            "error": "guard_denied",
        }
    audit_available, audit_error = audit_user_action_available(config)
    if not audit_available:
        return {
            "status": "denied",
            "action": preview.get("action", action),
            "ip": preview.get("ip", ip),
            "message": "Audit is required before manual IP actions can run.",
            "backend": preview.get("backend", ""),
            "audit": {"status": "unavailable", "reason": audit_error or "audit_unavailable"},
            "error": "audit_unavailable",
        }

    db = None
    try:
        db = create_database(config)
        blocker = IPBlocker(config, db)
        method_name = "unblock_ip" if str(action or "").strip().lower() == "unblock" else "block_ip"
        method = getattr(blocker, method_name)
        result = method(
            ip=str(preview.get("ip", ip) or "").strip(),
            reason=str(reason or "").strip(),
            dry_run=False,
            executed_by=str(actor or "").strip() or "local-user",
        )
        payload = result.to_dict()
        status = "executed" if bool(payload.get("ok")) and str(payload.get("status", "")) == "applied" else "failed"
        if str(payload.get("status", "")) == "refused":
            status = "denied"
        return {
            "status": status,
            "action": preview.get("action", action),
            "ip": payload.get("ip", preview.get("ip", ip)),
            "backend": payload.get("backend", preview.get("backend", "")),
            "capability": preview.get("capability", {}),
            "manual_approval": True,
            "no_auto_block": True,
            "audit": {"status": "attempted", "action_id": payload.get("action_id")},
            "command_preview": _sanitize_command_plan(payload.get("commands", [])),
            "message": (
                "Manual IP action executed."
                if status == "executed"
                else (
                    _privilege_message()
                    if _sanitize_error(payload.get("error", "")) in {"permission_denied", _ELEVATED_REQUIRED_REASON}
                    else "Manual IP action did not complete successfully."
                )
            ),
            "error": _sanitize_error(payload.get("error", "")),
        }
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
