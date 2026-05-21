from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.actions.guard import build_guarded_action_preview, can_execute_action, get_action_policy, required_confirmation_for
from ui.actions.models import GuardedActionRequest
import ui.backend_facade as backend_facade


def _request(action_type: str, role: str, reason: str = "", confirmation: str = "", dry_run_completed: bool = False):
    policy = get_action_policy(action_type)
    target = "sample-target"
    return GuardedActionRequest(
        action_id=f"{action_type}:{target}",
        action_type=action_type,
        target=target,
        target_type="generic",
        actor="operator-1",
        reason=reason,
        confirmation_phrase=confirmation,
        required_confirmation_phrase=required_confirmation_for(action_type, target),
        dry_run_required=policy.dry_run_required,
        dry_run_completed=dry_run_completed,
        role_required=policy.role_required,
        current_role=role,
        metadata={},
    )


def test_viewer_cannot_execute_dangerous_actions():
    request = _request("ip_block", role="viewer")
    result = build_guarded_action_preview(request)

    assert can_execute_action(request) is False
    assert result.status == "denied"
    assert "role:admin" in result.missing_guards


def test_operator_cannot_execute_destructive_actions():
    request = _request("db_reset", role="operator")
    result = build_guarded_action_preview(request)

    assert result.status == "denied"
    assert "role:admin" in result.missing_guards


def test_admin_without_reason_denied():
    request = _request(
        "incident_resolve",
        role="admin",
        reason="",
        confirmation=required_confirmation_for("incident_resolve", "sample-target"),
        dry_run_completed=True,
    )
    result = build_guarded_action_preview(request)

    assert result.status == "denied"
    assert "reason" in result.missing_guards


def test_admin_without_typed_confirmation_denied():
    request = _request(
        "incident_close",
        role="admin",
        reason="approved",
        confirmation="WRONG",
        dry_run_completed=True,
    )
    result = build_guarded_action_preview(request)

    assert result.status == "denied"
    assert "typed confirmation" in result.missing_guards


def test_dry_run_required_not_ready_without_dry_run():
    request = _request(
        "ml_reset",
        role="admin",
        reason="approved",
        confirmation=required_confirmation_for("ml_reset", "sample-target"),
        dry_run_completed=False,
    )
    result = build_guarded_action_preview(request)

    assert result.status == "denied"
    assert "dry-run" in result.missing_guards
    assert result.status != "ready"


def test_report_export_actions_can_become_ready():
    request = _request(
        "report_export",
        role="admin",
        reason="approved",
        confirmation=required_confirmation_for("report_export", "sample-target"),
        dry_run_completed=True,
    )
    result = build_guarded_action_preview(request)

    assert result.execution_enabled is True
    assert result.status == "ready"


def test_notification_test_actions_can_become_ready():
    request = _request(
        "telegram_test_send",
        role="admin",
        reason="approved",
        confirmation=required_confirmation_for("telegram_test_send", "sample-target"),
        dry_run_completed=True,
    )
    result = build_guarded_action_preview(request)

    assert result.execution_enabled is True
    assert result.status == "ready"


def test_collect_guarded_action_policies_schema():
    result = backend_facade.collect_guarded_action_policies()

    assert result["status"] == "ok"
    assert len(result["policies"]) >= 1
