from __future__ import annotations

from typing import Dict, List

from .models import ActionGuardPolicy, GuardedActionRequest, GuardedActionResult


SUPPORTED_ACTION_TYPES = [
    "ip_block",
    "ip_unblock",
    "db_reset",
    "incident_resolve",
    "incident_close",
    "ml_resume",
    "ml_reset",
    "ml_config_update",
    "api_key_update",
    "telegram_test_send",
    "email_test_send",
    "report_export",
    "diagnostic_bundle_create",
]

_ROLE_ORDER = {"viewer": 0, "operator": 1, "admin": 2}
_ACTION_LABELS = {
    "ip_block": "Block IP target in the configured firewall backend",
    "ip_unblock": "Remove a previously applied IP block from the configured firewall backend",
    "db_reset": "Reset runtime database data while preserving schema and connection settings",
    "incident_resolve": "Mark the selected incident as resolved",
    "incident_close": "Close the selected incident",
    "ml_resume": "Resume ML processing for paused families",
    "ml_reset": "Reset ML runtime state and baselines",
    "ml_config_update": "Update ML runtime configuration values",
    "api_key_update": "Write integration secret or API key configuration",
    "telegram_test_send": "Send a live Telegram test notification",
    "email_test_send": "Send a live email test notification",
    "report_export": "Write a report artifact to disk",
    "diagnostic_bundle_create": "Create and write a diagnostic bundle archive",
}


def _build_policies() -> Dict[str, ActionGuardPolicy]:
    destructive_actions = {
        "ip_block",
        "ip_unblock",
        "db_reset",
        "ml_resume",
        "ml_reset",
        "ml_config_update",
        "api_key_update",
    }
    policies: Dict[str, ActionGuardPolicy] = {}
    for action_type in SUPPORTED_ACTION_TYPES:
        destructive = action_type in destructive_actions
        role_required = "admin" if destructive else "operator"
        metadata = {"execution_enabled": False}
        if action_type in {"api_key_update", "telegram_test_send", "email_test_send", "ip_block", "ip_unblock", "incident_resolve", "incident_close", "db_reset"}:
            role_required = "admin"
            metadata["execution_enabled"] = True
        if action_type in {"telegram_test_send", "email_test_send"}:
            metadata["external_send"] = True
        if action_type in {"incident_resolve", "incident_close"}:
            metadata["operational_state_change"] = True
        if action_type == "db_reset":
            metadata["runtime_data_reset"] = True
        if action_type in {"report_export", "diagnostic_bundle_create"}:
            metadata["external_file_write"] = True
            metadata["execution_enabled"] = True
            role_required = "admin"
        policies[action_type] = ActionGuardPolicy(
            action_type=action_type,
            enabled=True,
            phase=(
                "Phase 2G guarded exports"
                if action_type in {"report_export", "diagnostic_bundle_create"}
                else
                "Phase 2F guarded DB reset"
                if action_type == "db_reset"
                else "Phase 2E guarded incident actions"
                if action_type in {"incident_resolve", "incident_close"}
                else "Phase 2C guarded actions"
            ),
            role_required=role_required,
            dry_run_required=True,
            typed_confirmation_required=True,
            reason_required=True,
            audit_required=True,
            allowed_in_phase_2=True,
            destructive=destructive,
            metadata=metadata,
        )
    return policies


_POLICIES = _build_policies()


def normalize_role(role: str) -> str:
    token = str(role or "viewer").strip().lower()
    return token if token in _ROLE_ORDER else "viewer"


def get_action_policy(action_type: str) -> ActionGuardPolicy:
    token = str(action_type or "").strip().lower()
    if token in _POLICIES:
        return _POLICIES[token]
    return ActionGuardPolicy(
        action_type=token or "unknown",
        enabled=False,
        phase="Phase 2A guarded framework",
        role_required="admin",
        dry_run_required=True,
        typed_confirmation_required=True,
        reason_required=True,
        audit_required=True,
        allowed_in_phase_2=False,
        destructive=True,
    )


def required_confirmation_for(action_type: str, target: str) -> str:
    return f"CONFIRM {str(action_type or '').strip().upper()} {str(target or '').strip() or 'TARGET'}"


def _required_guards_for(policy: ActionGuardPolicy) -> List[str]:
    guards = ["actor"]
    if policy.reason_required:
        guards.append("reason")
    if policy.dry_run_required:
        guards.append("dry-run")
    if policy.typed_confirmation_required:
        guards.append("typed confirmation")
    if policy.audit_required:
        guards.append("audit record")
    if policy.destructive:
        guards.append("rollback/undo if applicable")
    return guards


def validate_guarded_action_request(request: GuardedActionRequest) -> List[str]:
    policy = get_action_policy(request.action_type)
    missing: List[str] = []
    current_role = normalize_role(request.current_role)
    required_role = normalize_role(policy.role_required)

    if _ROLE_ORDER.get(current_role, 0) < _ROLE_ORDER.get(required_role, 2):
        missing.append(f"role:{required_role}")
    if not str(request.actor or "").strip():
        missing.append("actor")
    if policy.reason_required and not str(request.reason or "").strip():
        missing.append("reason")
    if policy.dry_run_required and not bool(request.dry_run_completed):
        missing.append("dry-run")
    if policy.typed_confirmation_required:
        if str(request.confirmation_phrase or "").strip() != str(request.required_confirmation_phrase or "").strip():
            missing.append("typed confirmation")
    return missing


def can_execute_action(request: GuardedActionRequest) -> bool:
    policy = get_action_policy(request.action_type)
    if policy.action_type not in {
        "api_key_update",
        "telegram_test_send",
        "email_test_send",
        "ip_block",
        "ip_unblock",
        "incident_resolve",
        "incident_close",
        "db_reset",
        "report_export",
        "diagnostic_bundle_create",
    }:
        return False
    return not validate_guarded_action_request(request)


def build_guarded_action_preview(request: GuardedActionRequest) -> GuardedActionResult:
    policy = get_action_policy(request.action_type)
    required_guards = _required_guards_for(policy)
    missing_guards = validate_guarded_action_request(request)
    execution_enabled = False

    if not policy.enabled:
        status = "locked"
        message = "This action is not enabled in the current guarded framework."
    elif missing_guards:
        status = "denied"
        message = f"Execution is blocked until all required guards are satisfied: {', '.join(missing_guards)}"
    elif can_execute_action(request):
        status = "ready"
        message = "All guards satisfied. This action is eligible for guarded execution."
    else:
        status = "preview_only"
        message = "Phase 2 execution not enabled yet. Preview only."

    return GuardedActionResult(
        status=status,
        action_type=policy.action_type,
        target=str(request.target or "").strip(),
        message=message,
        would_do=[_ACTION_LABELS.get(policy.action_type, "Perform the requested guarded action")],
        required_guards=required_guards,
        missing_guards=missing_guards,
        audit_required=policy.audit_required,
        execution_enabled=can_execute_action(request),
        error=None,
        metadata={
            "policy": policy.to_dict(),
            "request": request.to_dict(),
            "current_role": normalize_role(request.current_role),
            "required_role": normalize_role(policy.role_required),
            "phase": policy.phase,
        },
    )
