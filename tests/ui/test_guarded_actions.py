from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.actions.guard import SUPPORTED_ACTION_TYPES, get_action_policy, required_confirmation_for
from ui.actions.models import GuardedActionRequest
import ui.backend_facade as backend_facade


def _request(action_type: str, role: str = "admin", reason: str = "approved change", confirmation: str | None = None, dry_run_completed: bool = True):
    phrase = required_confirmation_for(action_type, "target-1")
    return GuardedActionRequest(
        action_id=f"{action_type}:target-1",
        action_type=action_type,
        target="target-1",
        target_type="generic",
        actor="alice",
        reason=reason,
        confirmation_phrase=phrase if confirmation is None else confirmation,
        required_confirmation_phrase=phrase,
        dry_run_required=True,
        dry_run_completed=dry_run_completed,
        role_required=get_action_policy(action_type).role_required,
        current_role=role,
        metadata={},
    )


def test_all_supported_action_types_have_policy():
    assert SUPPORTED_ACTION_TYPES
    for action_type in SUPPORTED_ACTION_TYPES:
        policy = get_action_policy(action_type)
        assert policy.action_type == action_type
        assert policy.allowed_in_phase_2 is True


def test_required_confirmation_for_deterministic():
    assert required_confirmation_for("ip_block", "1.2.3.4") == required_confirmation_for("ip_block", "1.2.3.4")


def test_preview_guarded_action_schema():
    result = backend_facade.preview_guarded_action(
        action_type="report_export",
        target="report.html",
        actor="alice",
        role="admin",
        reason="ticket-1",
        confirmation=required_confirmation_for("report_export", "report.html"),
        dry_run_completed=True,
    )

    assert {"status", "action_type", "target", "message", "would_do", "required_guards", "missing_guards", "audit_required", "execution_enabled", "error", "metadata"} <= set(result)


def test_guarded_actions_no_write_guard_sources():
    for path in ("ui/actions/guard.py", "ui/actions/dialogs.py", "ui/actions/models.py", "ui/backend_facade.py"):
        source = Path(path).read_text(encoding="utf-8").lower()
        for token in (
            ".commit(",
            "insert into ",
            "delete from ",
            "update settings",
            "block_ip(",
            "unblock_ip(",
            "firewall-cmd",
            "ipblocker(",
            ".sendmail(",
            "reset_database(",
            "close_incident(",
        ):
            assert token not in source
