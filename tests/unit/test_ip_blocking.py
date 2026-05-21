from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import core.ip_blocking as ip_blocking
import main as main_module


class _FakeDb:
    def __init__(self, active=None):
        self.active = dict(active or {})
        self.actions = []
        self.logs = []
        self.reviewed = []

    def get_active_ip_block(self, ip):
        return self.active.get(ip)

    def add_ip_block_action(self, **kwargs):
        self.actions.append(kwargs)
        return len(self.actions)

    def log_action(self, **kwargs):
        self.logs.append(kwargs)

    def review_ip_block_suggestion(self, suggestion_id, action):
        self.reviewed.append((suggestion_id, action))

    def close(self):
        return None


def _config(default_backend="ufw", real_backend="auto", allowlist=None):
    return {
        "ip_blocking": {
            "enabled": True,
            "default_backend": default_backend,
            "real_backend": real_backend,
            "allowlist": list(allowlist or []),
        }
    }


def test_ufw_block_real_apply_uses_safe_arg_list(monkeypatch):
    monkeypatch.setattr(ip_blocking.shutil, "which", lambda binary: "/usr/sbin/ufw" if binary == "ufw" else None)
    calls = []

    def _runner(argv):
        calls.append(list(argv))
        if argv == ["ufw", "status"]:
            return 0, "Status: active\n", ""
        if argv == ["ufw", "deny", "from", "8.8.8.8", "to", "any"]:
            return 0, "Rule added", ""
        raise AssertionError(f"unexpected command: {argv}")

    blocker = ip_blocking.IPBlocker(_config(), _FakeDb(), command_runner=_runner)
    result = blocker.block_ip("8.8.8.8", reason="ticket-1", executed_by="tester")

    assert result.ok is True
    assert result.status == "applied"
    assert result.backend == "ufw"
    assert result.backend_rule_ref == "deny from 8.8.8.8 to any"
    assert calls == [
        ["ufw", "status"],
        ["ufw", "status"],
        ["ufw", "deny", "from", "8.8.8.8", "to", "any"],
    ]


def test_ufw_dry_run_returns_plan_without_real_apply_error(monkeypatch):
    monkeypatch.setattr(ip_blocking.shutil, "which", lambda binary: "/usr/sbin/ufw" if binary == "ufw" else None)
    blocker = ip_blocking.IPBlocker(
        _config(real_backend="firewalld"),
        _FakeDb(),
        command_runner=lambda argv: (0, "Status: active\n", ""),
    )

    result = blocker.block_ip("8.8.8.8", reason="ticket-dry", dry_run=True, executed_by="tester")

    assert result.ok is True
    assert result.status == "dry_run"
    assert result.backend == "ufw"
    assert result.supported is True
    assert result.plan_supported is True
    assert result.real_apply_supported is False
    assert result.error == ""
    assert [cmd.argv for cmd in result.commands] == [["ufw", "deny", "from", "8.8.8.8", "to", "any"]]


def test_ufw_unblock_real_apply_uses_safe_arg_list(monkeypatch):
    monkeypatch.setattr(ip_blocking.shutil, "which", lambda binary: "/usr/sbin/ufw" if binary == "ufw" else None)
    calls = []
    db = _FakeDb(active={
        "8.8.8.8": {
            "backend": "ufw",
            "backend_rule_ref": "deny from 8.8.8.8 to any",
            "status": "applied",
        }
    })

    def _runner(argv):
        calls.append(list(argv))
        if argv == ["ufw", "status"]:
            return 0, "Status: active\nAnywhere DENY 8.8.8.8\n", ""
        if argv == ["ufw", "delete", "deny", "from", "8.8.8.8", "to", "any"]:
            return 0, "Rule deleted", ""
        raise AssertionError(f"unexpected command: {argv}")

    blocker = ip_blocking.IPBlocker(_config(), db, command_runner=_runner)
    result = blocker.unblock_ip("8.8.8.8", reason="ticket-2", executed_by="tester")

    assert result.ok is True
    assert result.status == "applied"
    assert result.backend == "ufw"
    assert calls == [
        ["ufw", "status"],
        ["ufw", "delete", "deny", "from", "8.8.8.8", "to", "any"],
    ]


def test_ufw_inactive_or_missing_fails_safe(monkeypatch):
    monkeypatch.setattr(ip_blocking.shutil, "which", lambda binary: "/usr/sbin/ufw" if binary == "ufw" else None)
    blocker = ip_blocking.IPBlocker(_config(), _FakeDb(), command_runner=lambda argv: (0, "Status: inactive\n", ""))

    result = blocker.block_ip("8.8.8.8", reason="ticket-3", executed_by="tester")

    assert result.ok is False
    assert result.status == "failed"
    assert result.backend == "ufw"
    assert result.error == "ufw_unavailable_for_real_apply"


def test_ufw_permission_denied_surfaces_clean_error(monkeypatch):
    monkeypatch.setattr(ip_blocking.shutil, "which", lambda binary: "/usr/sbin/ufw" if binary == "ufw" else None)
    calls = []

    def _runner(argv):
        calls.append(list(argv))
        if argv == ["ufw", "status"]:
            return 0, "Status: active\n", ""
        if argv == ["ufw", "deny", "from", "8.8.8.8", "to", "any"]:
            return 1, "", "permission denied"
        raise AssertionError(f"unexpected command: {argv}")

    blocker = ip_blocking.IPBlocker(_config(), _FakeDb(), command_runner=_runner)
    result = blocker.block_ip("8.8.8.8", reason="ticket-4", executed_by="tester")

    assert result.ok is False
    assert result.status == "failed"
    assert result.error == "permission_denied"


def test_private_ip_guard_blocks_before_backend_command(monkeypatch):
    monkeypatch.setattr(ip_blocking.shutil, "which", lambda binary: "/usr/sbin/ufw")
    blocker = ip_blocking.IPBlocker(_config(), _FakeDb(), command_runner=lambda argv: (_ for _ in ()).throw(AssertionError("command runner must not be called")))

    result = blocker.block_ip("192.168.1.10", reason="ticket-5", executed_by="tester")

    assert result.ok is False
    assert result.status == "refused"
    assert result.guard_reason == "internal_ip:192.168.0.0/16"


def test_firewalld_regression_path_still_supported(monkeypatch):
    monkeypatch.setattr(ip_blocking.shutil, "which", lambda binary: "/usr/bin/firewall-cmd" if binary == "firewall-cmd" else None)
    calls = []

    def _runner(argv):
        calls.append(list(argv))
        if argv == ["firewall-cmd", "--state"]:
            return 0, "running", ""
        if argv[:3] == ["firewall-cmd", "--permanent", "--query-rich-rule"]:
            return 1, "", ""
        if argv[:3] == ["firewall-cmd", "--permanent", "--add-rich-rule"]:
            return 0, "", ""
        if argv == ["firewall-cmd", "--reload"]:
            return 0, "", ""
        raise AssertionError(f"unexpected command: {argv}")

    blocker = ip_blocking.IPBlocker(_config(default_backend="firewalld", real_backend="firewalld"), _FakeDb(), command_runner=_runner)
    result = blocker.block_ip("8.8.8.8", reason="ticket-6", executed_by="tester")

    assert result.ok is True
    assert result.backend == "firewalld"
    assert any(cmd[:3] == ["firewall-cmd", "--permanent", "--add-rich-rule"] for cmd in calls)


def test_nftables_and_iptables_stay_unsupported(monkeypatch):
    monkeypatch.setattr(ip_blocking.shutil, "which", lambda binary: "/usr/sbin/nft" if binary == "nft" else None)
    blocker = ip_blocking.IPBlocker(_config(default_backend="nftables", real_backend="nftables"), _FakeDb(), command_runner=lambda argv: (0, "", ""))

    result = blocker.block_ip("8.8.4.4", reason="ticket-7", executed_by="tester")

    assert result.ok is False
    assert result.status == "failed"
    assert result.error == "real_apply_unsupported_for_backend"


def test_source_has_no_shell_true():
    source = Path("core/ip_blocking.py").read_text(encoding="utf-8").lower()
    assert "shell=true" not in source


def test_cli_dry_run_passes_dry_run_without_real_execute(monkeypatch):
    seen = {}

    class _FakeBlocker:
        def __init__(self, config, db):
            seen["config"] = config
            seen["db"] = db

        def block_ip(self, ip, reason="", dry_run=False, executed_by="terminal", suggestion_id=None):
            seen["call"] = {
                "ip": ip,
                "reason": reason,
                "dry_run": dry_run,
                "executed_by": executed_by,
                "suggestion_id": suggestion_id,
            }
            return ip_blocking.BlockExecutionResult(
                ok=True,
                action="block",
                status="dry_run",
                ip=ip,
                backend="ufw",
                backend_rule_ref="deny from 8.8.8.8 to any",
                dry_run=True,
                supported=True,
            )

    fake_db = _FakeDb()
    monkeypatch.setattr(main_module, "ensure_database", lambda config: fake_db)
    monkeypatch.setattr(main_module, "IPBlocker", _FakeBlocker)
    monkeypatch.setattr(main_module, "_print_ip_block_result", lambda payload: seen.setdefault("printed", payload))
    args = type("Args", (), {
        "list_ip_block_suggestions": False,
        "block_ip": "8.8.8.8",
        "block_suggestion_id": None,
        "unblock_ip": "",
        "dry_run": True,
    })()

    rc = main_module.run_ip_blocking_cli(_config(), args)

    assert rc == 0
    assert seen["call"]["dry_run"] is True
    assert seen["call"]["ip"] == "8.8.8.8"
