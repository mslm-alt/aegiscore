from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.actions import ip_actions
from ui.actions.guard import build_guarded_action_preview, get_action_policy
from ui.actions.guard import required_confirmation_for
from ui.actions.models import GuardedActionRequest
import ui.backend_facade as backend_facade


def _config():
    return {"ip_blocking": {"enabled": True, "default_backend": "firewalld", "real_backend": "firewalld"}}


def _patch_runtime(monkeypatch, config=None):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config or _config()})


def test_invalid_ip_denied(monkeypatch):
    _patch_runtime(monkeypatch)

    result = backend_facade.preview_ip_action(
        action="block",
        ip="not-an-ip",
        actor="alice",
        role="admin",
        reason="ticket-1",
        confirmation="",
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["ip_validation"]["error"] == "invalid_ip"


def test_loopback_multicast_broadcast_denied():
    assert ip_actions.validate_ip_target("127.0.0.1")["error"] == "loopback_ip"
    assert ip_actions.validate_ip_target("224.0.0.1")["error"] == "multicast_ip"
    assert ip_actions.validate_ip_target("255.255.255.255")["error"] == "broadcast_ip"


def test_private_ip_warning_denied():
    result = ip_actions.validate_ip_target("192.168.1.10")

    assert result["allowed"] is False
    assert result["error"] == "private_ip"
    assert "private/lab" in result["warning"]


def test_viewer_denied(monkeypatch):
    _patch_runtime(monkeypatch)
    monkeypatch.setattr(backend_facade.ip_actions, "preview_guarded_ip_action", lambda **kwargs: {
        "status": "denied",
        "action": "block",
        "ip": "8.8.8.8",
        "ip_validation": {"allowed": True},
        "backend": "firewalld",
        "capability": {"real_apply_supported": True, "dry_run_supported": True, "reason": "ready"},
        "guard": {"status": "denied", "execution_enabled": False, "missing_guards": ["role:admin"]},
        "would_run": [],
        "audit_required": True,
        "raw_command_included": False,
        "message": "denied",
    })

    result = backend_facade.preview_ip_action(
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="viewer",
        reason="ticket-2",
        confirmation="",
        dry_run_completed=True,
    )

    assert "role:admin" in result["guard"]["missing_guards"]


def test_operator_denied_for_destructive_action():
    policy = get_action_policy("ip_block")
    request = GuardedActionRequest(
        action_id="ip_block:8.8.8.8",
        action_type="ip_block",
        target="8.8.8.8",
        target_type="ip",
        actor="alice",
        reason="ticket-op",
        confirmation_phrase=required_confirmation_for("ip_block", "8.8.8.8"),
        required_confirmation_phrase=required_confirmation_for("ip_block", "8.8.8.8"),
        dry_run_required=policy.dry_run_required,
        dry_run_completed=True,
        role_required=policy.role_required,
        current_role="operator",
        metadata={},
    )
    result = build_guarded_action_preview(request)

    assert result.status == "denied"
    assert "role:admin" in result.missing_guards


def test_admin_without_reason_denied(monkeypatch):
    _patch_runtime(monkeypatch)
    result = backend_facade.preview_ip_action(
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="",
        confirmation=required_confirmation_for("ip_block", "8.8.8.8"),
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert "reason" in result["guard"]["missing_guards"]


def test_admin_without_dry_run_denied(monkeypatch):
    _patch_runtime(monkeypatch)
    result = backend_facade.preview_ip_action(
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="ticket-3",
        confirmation=required_confirmation_for("ip_block", "8.8.8.8"),
        dry_run_completed=False,
    )

    assert "dry-run" in result["guard"]["missing_guards"]


def test_admin_without_confirmation_denied(monkeypatch):
    _patch_runtime(monkeypatch)
    result = backend_facade.preview_ip_action(
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="ticket-4",
        confirmation="WRONG",
        dry_run_completed=True,
    )

    assert "typed confirmation" in result["guard"]["missing_guards"]


def test_unsupported_backend_execute_denied(monkeypatch):
    _patch_runtime(monkeypatch, {"ip_blocking": {"enabled": True, "default_backend": "ufw", "real_backend": "firewalld"}})
    monkeypatch.setattr(backend_facade.ip_actions, "preview_guarded_ip_action", lambda **kwargs: {
        "status": "denied",
        "action": "block",
        "ip": "8.8.8.8",
        "backend": "ufw",
        "capability": {"real_apply_supported": False, "dry_run_supported": True, "reason": "real_apply_unsupported_for_backend"},
        "guard": {"status": "denied", "execution_enabled": False, "missing_guards": ["real apply support"], "message": "blocked"},
        "message": "blocked",
    })

    result = backend_facade.execute_ip_action(
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="ticket-5",
        confirmation="CONFIRM IP_BLOCK 8.8.8.8",
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "guard_denied"


def test_ufw_capable_backend_mocked_success(monkeypatch):
    _patch_runtime(monkeypatch, {"ip_blocking": {"enabled": True, "default_backend": "ufw", "real_backend": "auto"}})
    monkeypatch.setattr(backend_facade.ip_actions, "execute_guarded_ip_action", lambda **kwargs: {
        "status": "executed",
        "action": "block",
        "ip": "8.8.8.8",
        "backend": "ufw",
        "audit": {"status": "attempted", "action_id": 11},
        "message": "Manual IP action executed.",
        "error": "",
    })

    result = backend_facade.execute_ip_action(
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="ticket-ufw",
        confirmation="CONFIRM IP_BLOCK 8.8.8.8",
        dry_run_completed=True,
    )

    assert result["status"] == "executed"
    assert result["backend"] == "ufw"


def test_firewalld_capable_backend_mocked_success(monkeypatch):
    _patch_runtime(monkeypatch)
    monkeypatch.setattr(backend_facade.ip_actions, "execute_guarded_ip_action", lambda **kwargs: {
        "status": "executed",
        "action": "block",
        "ip": "8.8.8.8",
        "backend": "firewalld",
        "audit": {"status": "attempted", "action_id": 7},
        "message": "Manual IP action executed.",
        "error": "",
    })

    result = backend_facade.execute_ip_action(
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="ticket-6",
        confirmation="CONFIRM IP_BLOCK 8.8.8.8",
        dry_run_completed=True,
    )

    assert result["status"] == "executed"
    assert result["backend"] == "firewalld"


def test_backend_failure_sanitized_and_audit_attempted(monkeypatch):
    _patch_runtime(monkeypatch)
    monkeypatch.setattr(backend_facade.ip_actions, "execute_guarded_ip_action", lambda **kwargs: {
        "status": "failed",
        "action": "block",
        "ip": "8.8.8.8",
        "backend": "firewalld",
        "audit": {"status": "attempted", "action_id": 9},
        "message": "Manual IP action did not complete successfully.",
        "error": "command_failed",
    })

    result = backend_facade.execute_ip_action(
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="ticket-7",
        confirmation="CONFIRM IP_BLOCK 8.8.8.8",
        dry_run_completed=True,
    )

    assert result["status"] == "failed"
    assert result["audit"]["status"] == "attempted"
    assert result["error"] == "command_failed"


def test_permission_denied_returns_actionable_message(monkeypatch):
    preview = {
        "status": "ready",
        "action": "block",
        "ip": "8.8.8.8",
        "backend": "ufw",
        "capability": {"real_apply_supported": True, "dry_run_supported": True, "reason": "ready"},
        "guard": {"status": "ready", "execution_enabled": True},
        "message": "ready",
    }

    class _Result:
        def to_dict(self):
            return {
                "ok": False,
                "status": "failed",
                "ip": "8.8.8.8",
                "backend": "ufw",
                "action_id": 14,
                "commands": [],
                "error": "permission_denied",
            }

    class _Db:
        def close(self):
            return None

    class _Blocker:
        def __init__(self, config, db):
            pass

        def block_ip(self, **kwargs):
            return _Result()

    monkeypatch.setattr(ip_actions, "preview_guarded_ip_action", lambda **kwargs: preview)
    monkeypatch.setattr(ip_actions, "audit_user_action_available", lambda config: (True, ""))
    monkeypatch.setattr(ip_actions, "create_database", lambda config: _Db())
    monkeypatch.setattr(ip_actions, "IPBlocker", _Blocker)

    result = ip_actions.execute_guarded_ip_action(
        config={"ip_blocking": {"enabled": True, "default_backend": "ufw", "real_backend": "auto"}},
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="ticket-perm",
        confirmation="CONFIRM IP_BLOCK 8.8.8.8",
        dry_run_completed=True,
    )

    assert result["status"] == "failed"
    assert result["error"] == "permission_denied"
    assert result["message"] == "AegisCore must be run with elevated privileges to apply firewall rules."


def test_preview_ufw_dry_run_capability_does_not_mark_plan_unsupported(monkeypatch):
    class _Db:
        def get_active_ip_block(self, ip):
            return None

        def close(self):
            return None

    class _FakeBlocker:
        def __init__(self, config, db):
            self.config = config
            self.db = db
            self._command_runner = lambda argv: (0, "Status: active\n", "")

        def _detect_backend(self):
            return "ufw", True

        def _real_apply_error(self, backend, supported):
            return "real_apply_unsupported_for_backend"

        def _build_command_plan(self, action, ip_obj, backend):
            return "deny from 8.8.8.8 to any", [
                type("CommandPlan", (), {
                    "argv": ["ufw", "deny", "from", "8.8.8.8", "to", "any"],
                    "description": "ufw block rule",
                })()
            ]

    monkeypatch.setattr(ip_actions, "create_database", lambda config: _Db())
    monkeypatch.setattr(ip_actions, "IPBlocker", _FakeBlocker)

    result = ip_actions.preview_guarded_ip_action(
        config={"ip_blocking": {"enabled": True, "default_backend": "ufw", "real_backend": "firewalld"}},
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="ticket-ufw-preview",
        confirmation="CONFIRM IP_BLOCK 8.8.8.8",
        dry_run_completed=True,
    )

    assert result["backend"] == "ufw"
    assert result["would_run"]
    assert result["capability"]["dry_run_supported"] is True
    assert result["capability"]["plan_supported"] is True
    assert result["capability"]["real_apply_supported"] is False
    assert result["capability"]["reason"] == "real_apply_unsupported_for_backend"


def test_preview_ufw_permission_required_is_not_marked_unsupported(monkeypatch):
    class _Db:
        def get_active_ip_block(self, ip):
            return None

        def close(self):
            return None

    class _FakeBlocker:
        def __init__(self, config, db):
            self._command_runner = lambda argv: (1, "", "permission denied")

        def _detect_backend(self):
            return "ufw", False

        def _real_apply_error(self, backend, supported):
            return "ufw_unavailable_for_real_apply"

        def _build_command_plan(self, action, ip_obj, backend):
            return "deny from 8.8.8.8 to any", [
                type("CommandPlan", (), {
                    "argv": ["ufw", "deny", "from", "8.8.8.8", "to", "any"],
                    "description": "ufw block rule",
                })()
            ]

    monkeypatch.setattr(ip_actions, "create_database", lambda config: _Db())
    monkeypatch.setattr(ip_actions, "IPBlocker", _FakeBlocker)
    monkeypatch.setattr(ip_actions.shutil, "which", lambda binary: "/usr/sbin/ufw" if binary == "ufw" else None)

    result = ip_actions.preview_guarded_ip_action(
        config={"ip_blocking": {"enabled": True, "default_backend": "ufw", "real_backend": "auto"}},
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="ticket-ufw-perm",
        confirmation="CONFIRM IP_BLOCK 8.8.8.8",
        dry_run_completed=True,
    )

    assert result["would_run"]
    assert result["capability"]["backend_supported"] is True
    assert result["capability"]["requires_elevation"] is True
    assert result["capability"]["reason"] == "elevated_privileges_required"
    assert result["message"] == "AegisCore must be run with elevated privileges to apply firewall rules."


def test_audit_unavailable_denies_execution(monkeypatch):
    preview = {
        "status": "ready",
        "action": "block",
        "ip": "8.8.8.8",
        "backend": "firewalld",
        "capability": {"real_apply_supported": True, "dry_run_supported": True, "reason": "ready"},
        "guard": {"status": "ready", "execution_enabled": True},
        "message": "ready",
    }
    monkeypatch.setattr(ip_actions, "preview_guarded_ip_action", lambda **kwargs: preview)
    monkeypatch.setattr(ip_actions, "audit_user_action_available", lambda config: (False, "db_down"))

    result = ip_actions.execute_guarded_ip_action(
        config=_config(),
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="ticket-8",
        confirmation="CONFIRM IP_BLOCK 8.8.8.8",
        dry_run_completed=True,
    )

    assert result["status"] == "denied"
    assert result["error"] == "audit_unavailable"


def test_preview_raw_command_safe_sanitized(monkeypatch):
    preview = {
        "status": "ready",
        "action": "block",
        "ip": "8.8.8.8",
        "ip_validation": {"allowed": True},
        "backend": "firewalld",
        "capability": {"real_apply_supported": True, "dry_run_supported": True, "reason": "ready"},
        "guard": {"status": "ready", "execution_enabled": True, "required_guards": []},
        "would_run": ["firewalld block rule: firewall-cmd --permanent --add-rich-rule rule family=\"ipv4\" source address=\"8.8.8.8\" drop"],
        "audit_required": True,
        "raw_command_included": False,
        "message": "ready",
    }
    monkeypatch.setattr(backend_facade.ip_actions, "preview_guarded_ip_action", lambda **kwargs: preview)
    _patch_runtime(monkeypatch)

    result = backend_facade.preview_ip_action(
        action="block",
        ip="8.8.8.8",
        actor="alice",
        role="admin",
        reason="ticket-9",
        confirmation="CONFIRM IP_BLOCK 8.8.8.8",
        dry_run_completed=True,
    )

    assert result["raw_command_included"] is False
    assert result["would_run"]


def test_ip_actions_no_forbidden_actions():
    source = Path("ui/actions/ip_actions.py").read_text(encoding="utf-8").lower()
    for token in (
        "reset_database(",
        "close_incident(",
        "ml_reset",
        "report_export",
        "diagnostic_bundle_create",
        "send_email(",
        "telegram_test_send(",
    ):
        assert token not in source


def test_no_auto_block_guard_sources():
    for path_text in ("ui/views/alerts.py",):
        source = Path(path_text).read_text(encoding="utf-8")
        assert "execute_ip_action(" not in source
    backend_source = Path("ui/backend_facade.py").read_text(encoding="utf-8")
    collect_alerts_start = backend_source.index("def collect_alerts(")
    collect_alerts_end = backend_source.index("def collect_alert_detail(", collect_alerts_start)
    collect_alerts_source = backend_source[collect_alerts_start:collect_alerts_end]
    assert "execute_ip_action(" not in collect_alerts_source
