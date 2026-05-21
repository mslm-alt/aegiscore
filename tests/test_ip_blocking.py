import sys
import json
from pathlib import Path
from types import MethodType, SimpleNamespace
import urllib.error

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import main as main_module
from core.abuseipdb import AbuseIPDBClient
from core.ip_blocking import IPBlocker
from core.llm import LLMClient
from core.report import ReportEngine


class FakeDB:
    is_connected = True

    def __init__(self):
        self.actions = []
        self.audits = []
        self.suggestions = []
        self.alerts = {}
        self._action_seq = 0
        self._suggestion_seq = 0

    def add_ip_block_action(self, **kwargs):
        self._action_seq += 1
        row = {"id": self._action_seq, **kwargs}
        self.actions.append(row)
        return self._action_seq

    def log_action(self, **kwargs):
        self.audits.append(dict(kwargs))

    def add_ip_block_suggestion(
        self,
        ip,
        reason="",
        source="alert",
        alert_id=None,
        abuse_score=None,
        abuse_reports=None,
        abuse_country="",
        abuse_raw=None,
    ):
        for row in self.suggestions:
            if row["ip"] == ip and not row.get("reviewed", False):
                row.update(
                    {
                        "reason": reason,
                        "source": source,
                        "alert_id": alert_id if alert_id is not None else row.get("alert_id"),
                        "abuse_score": abuse_score if abuse_score is not None else row.get("abuse_score"),
                        "abuse_reports": abuse_reports if abuse_reports is not None else row.get("abuse_reports"),
                        "abuse_country": abuse_country or row.get("abuse_country", ""),
                        "abuse_raw": abuse_raw if abuse_raw is not None else row.get("abuse_raw"),
                    }
                )
                return row["id"]
        self._suggestion_seq += 1
        row = {
            "id": self._suggestion_seq,
            "ip": ip,
            "reason": reason,
            "source": source,
            "alert_id": alert_id,
            "abuse_score": abuse_score,
            "abuse_reports": abuse_reports,
            "abuse_country": abuse_country,
            "abuse_raw": abuse_raw,
            "reviewed": False,
        }
        self.suggestions.append(row)
        return row["id"]

    def get_active_ip_block(self, ip):
        latest = None
        for row in self.actions:
            if row["ip"] == ip and row["status"] == "applied":
                latest = row
        if latest and latest["action"] == "block":
            return dict(latest)
        return None

    def get_ip_block_suggestions(self, reviewed=False, limit=100):
        return [dict(r) for r in self.suggestions if r.get("reviewed", False) == reviewed][:limit]

    def get_ip_reputation_for_alert(self, alert_id):
        return [
            dict(r)
            for r in self.suggestions
            if r.get("alert_id") == alert_id and str(r.get("source", "") or "").lower() == "abuseipdb"
        ]

    def get_alert_by_id(self, alert_id):
        row = self.alerts.get(int(alert_id))
        return dict(row) if row else None

    def review_ip_block_suggestion(self, suggestion_id, action):
        for row in self.suggestions:
            if row["id"] == suggestion_id:
                row["reviewed"] = True
                row["action"] = action
                return True
        return False

    def close(self):
        return None


def _firewalld_runner_factory(executed, existing_rules=None):
    existing = set(existing_rules or [])

    def _runner(argv):
        executed.append(list(argv))
        if argv == ["firewall-cmd", "--state"]:
            return 0, "running", ""
        if argv[:3] == ["firewall-cmd", "--permanent", "--query-rich-rule"]:
            rule = argv[3]
            return (0, "yes", "") if rule in existing else (1, "no", "")
        if argv[:3] == ["firewall-cmd", "--permanent", "--add-rich-rule"]:
            existing.add(argv[3])
            return 0, "", ""
        if argv[:3] == ["firewall-cmd", "--permanent", "--remove-rich-rule"]:
            existing.discard(argv[3])
            return 0, "", ""
        return 0, "", ""
    return _runner


@pytest.mark.parametrize(
    ("ip", "guard_reason"),
    [
        ("127.0.0.1", "loopback_ip"),
        ("10.1.2.3", "internal_ip:10.0.0.0/8"),
        ("172.16.5.4", "internal_ip:172.16.0.0/12"),
        ("192.168.1.9", "internal_ip:192.168.0.0/16"),
        ("224.0.0.5", "multicast_ip"),
        ("255.255.255.255", "broadcast_ip"),
        ("240.0.0.9", "reserved_ip"),
    ],
)
def test_guard_rejects_local_private_and_reserved_ips(ip, guard_reason):
    db = FakeDB()
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (0, "", ""))
    result = blocker.block_ip(ip, dry_run=False)
    assert result.ok is False
    assert result.status == "refused"
    assert result.guard_reason == guard_reason
    assert db.actions[-1]["status"] == "refused"
    assert db.audits[-1]["status"] == "refused"


def test_allowlist_rejects_matching_ip():
    db = FakeDB()
    cfg = {"ip_blocking": {"allowlist": ["8.8.8.0/24"]}}
    blocker = IPBlocker(config=cfg, db=db, command_runner=lambda argv: (0, "", ""))
    result = blocker.block_ip("8.8.8.8")
    assert result.ok is False
    assert result.guard_reason == "allowlist_hit:8.8.8.0/24"


def test_dry_run_produces_firewalld_plan_without_applying(monkeypatch):
    db = FakeDB()
    executed = []
    monkeypatch.setattr("core.ip_blocking.shutil.which", lambda name: "/usr/bin/firewall-cmd" if name == "firewall-cmd" else None)
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=_firewalld_runner_factory(executed))
    result = blocker.block_ip("8.8.8.8", dry_run=True)
    assert result.ok is True
    assert result.status == "dry_run"
    assert result.backend == "firewalld"
    assert len(result.commands) == 2
    assert executed == [["firewall-cmd", "--state"]]
    assert db.actions[-1]["status"] == "dry_run"
    assert db.audits[-1]["action"] == "ip_block"


def test_backend_detection_prefers_firewalld_when_available(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr(
        "core.ip_blocking.shutil.which",
        lambda name: {
            "firewall-cmd": "/usr/bin/firewall-cmd",
            "ufw": "/usr/sbin/ufw",
            "nft": "/usr/sbin/nft",
            "iptables": "/usr/sbin/iptables",
        }.get(name),
    )
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (0, "running", ""))
    backend, supported = blocker._detect_backend()
    assert backend == "firewalld"
    assert supported is True


def test_backend_detection_reports_ufw_as_dry_run_only(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr(
        "core.ip_blocking.shutil.which",
        lambda name: "/usr/sbin/ufw" if name == "ufw" else None,
    )
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (0, "", ""))
    result = blocker.block_ip("8.8.8.8", dry_run=True)
    assert result.ok is True
    assert result.status == "dry_run"
    assert result.backend == "ufw"
    assert result.supported is True
    assert result.plan_supported is True
    assert result.real_apply_supported is False
    assert result.error == ""
    assert len(result.commands) == 1
    assert result.commands[0].argv == ["ufw", "deny", "from", "8.8.8.8", "to", "any"]
    assert result.commands[0].description == "ufw block rule"


@pytest.mark.parametrize("binary,backend", [("nft", "nftables"), ("iptables", "iptables")])
def test_backend_detection_reports_non_firewalld_backends_as_dry_run_only(monkeypatch, binary, backend):
    db = FakeDB()
    monkeypatch.setattr(
        "core.ip_blocking.shutil.which",
        lambda name: f"/usr/sbin/{binary}" if name == binary else None,
    )
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (0, "", ""))
    result = blocker.block_ip("8.8.8.8", dry_run=True)
    assert result.ok is True
    assert result.status == "dry_run"
    assert result.backend == backend
    assert result.supported is True
    assert result.plan_supported is True
    assert result.real_apply_supported is False
    assert len(result.commands) == 1
    assert result.error == ""
    assert result.commands[0].argv[0] == binary


def test_dry_run_guarded_private_ip_returns_no_plan(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr("core.ip_blocking.shutil.which", lambda name: "/usr/sbin/ufw" if name == "ufw" else None)
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (_ for _ in ()).throw(AssertionError("command runner should not be called")))
    result = blocker.block_ip("192.168.1.10", dry_run=True)
    assert result.ok is False
    assert result.status == "refused"
    assert result.guard_reason == "internal_ip:192.168.0.0/16"
    assert result.commands == []


def test_dry_run_without_backend_is_clear_unsupported(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr("core.ip_blocking.shutil.which", lambda name: None)
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (1, "", "inactive"))
    result = blocker.block_ip("8.8.8.8", dry_run=True)
    assert result.ok is False
    assert result.status == "unsupported"
    assert result.backend == ""
    assert result.supported is False
    assert result.plan_supported is False
    assert result.real_apply_supported is False
    assert result.error == ""
    assert result.commands == []


def test_duplicate_block_is_rejected_if_already_applied():
    db = FakeDB()
    db.add_ip_block_action(
        ip="8.8.8.8",
        action="block",
        status="applied",
        dry_run=False,
        backend="firewalld",
        backend_rule_ref='rule family="ipv4" source address="8.8.8.8" drop',
        reason="test",
        guard_reason="",
        error="",
        executed_by="terminal",
        suggestion_id=None,
    )
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (0, "", ""))
    result = blocker.block_ip("8.8.8.8")
    assert result.ok is False
    assert result.guard_reason == "already_blocked"


def test_unblock_inactive_ip_is_refused():
    db = FakeDB()
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (0, "", ""))
    result = blocker.unblock_ip("8.8.8.8")
    assert result.ok is False
    assert result.status == "refused"
    assert result.guard_reason == "not_blocked"


def test_real_block_executes_firewalld_commands_and_audits(monkeypatch):
    db = FakeDB()
    executed = []
    monkeypatch.setattr("core.ip_blocking.shutil.which", lambda name: "/usr/bin/firewall-cmd" if name == "firewall-cmd" else None)
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=_firewalld_runner_factory(executed))
    result = blocker.block_ip("8.8.4.4", reason="manual-test", dry_run=False, suggestion_id=7)
    assert result.ok is True
    assert result.status == "applied"
    assert executed == [
        ["firewall-cmd", "--state"],
        ["firewall-cmd", "--permanent", "--query-rich-rule", 'rule family="ipv4" source address="8.8.4.4" drop'],
        ["firewall-cmd", "--permanent", "--add-rich-rule", 'rule family="ipv4" source address="8.8.4.4" drop'],
        ["firewall-cmd", "--reload"],
    ]
    assert db.actions[-1]["suggestion_id"] == 7
    assert db.audits[-1]["details"]["status"] == "applied"


def test_real_block_fails_safe_without_firewalld(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr("core.ip_blocking.shutil.which", lambda name: None)
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (1, "", "inactive"))
    result = blocker.block_ip("9.9.9.9", dry_run=False)
    assert result.ok is False
    assert result.status == "failed"


def test_real_block_fails_safe_when_only_ufw_exists(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr(
        "core.ip_blocking.shutil.which",
        lambda name: "/usr/sbin/ufw" if name == "ufw" else None,
    )
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (0, "", ""))
    result = blocker.block_ip("9.9.9.9", dry_run=False)
    assert result.ok is False
    assert result.status == "failed"
    assert result.backend == "ufw"
    assert result.error == "real_apply_unsupported_for_backend"
    assert db.actions[-1]["status"] == "failed"


@pytest.mark.parametrize(("binary", "backend"), [("nft", "nftables"), ("iptables", "iptables")])
def test_real_block_fails_safe_for_plan_only_backends(monkeypatch, binary, backend):
    db = FakeDB()
    monkeypatch.setattr(
        "core.ip_blocking.shutil.which",
        lambda name: f"/usr/sbin/{binary}" if name == binary else None,
    )
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (0, "", ""))
    result = blocker.block_ip("9.9.9.9", dry_run=False)
    assert result.ok is False
    assert result.status == "failed"
    assert result.backend == backend
    assert result.supported is False
    assert result.error == "real_apply_unsupported_for_backend"
    assert len(result.commands) == 1
    assert db.actions[-1]["status"] == "failed"


def test_real_block_without_any_backend_fails_safe_with_clear_error(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr("core.ip_blocking.shutil.which", lambda name: None)
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (1, "", "inactive"))
    result = blocker.block_ip("9.9.9.9", dry_run=False)
    assert result.ok is False
    assert result.status == "failed"
    assert result.backend == ""
    assert result.supported is False
    assert result.error == "backend_unavailable_for_real_apply"


def test_firewalld_existing_rule_is_refused_idempotently(monkeypatch):
    db = FakeDB()
    executed = []
    monkeypatch.setattr("core.ip_blocking.shutil.which", lambda name: "/usr/bin/firewall-cmd" if name == "firewall-cmd" else None)
    rule = 'rule family="ipv4" source address="8.8.8.8" drop'
    blocker = IPBlocker(
        config={"ip_blocking": {}},
        db=db,
        command_runner=_firewalld_runner_factory(executed, existing_rules={rule}),
    )
    result = blocker.block_ip("8.8.8.8", dry_run=False)
    assert result.ok is False
    assert result.status == "refused"
    assert result.guard_reason == "already_blocked_backend"
    assert executed == [
        ["firewall-cmd", "--state"],
        ["firewall-cmd", "--permanent", "--query-rich-rule", rule],
    ]


def test_firewalld_unblock_uses_only_recorded_rule_ref(monkeypatch):
    db = FakeDB()
    executed = []
    rule = 'rule family="ipv4" source address="8.8.8.8" drop'
    db.add_ip_block_action(
        ip="8.8.8.8",
        action="block",
        status="applied",
        dry_run=False,
        backend="firewalld",
        backend_rule_ref=rule,
        reason="manual",
        guard_reason="",
        error="",
        executed_by="terminal",
        suggestion_id=None,
    )
    monkeypatch.setattr("core.ip_blocking.shutil.which", lambda name: "/usr/bin/firewall-cmd" if name == "firewall-cmd" else None)
    blocker = IPBlocker(
        config={"ip_blocking": {}},
        db=db,
        command_runner=_firewalld_runner_factory(executed, existing_rules={rule}),
    )
    result = blocker.unblock_ip("8.8.8.8", dry_run=False)
    assert result.ok is True
    assert result.status == "applied"
    assert executed == [
        ["firewall-cmd", "--permanent", "--query-rich-rule", rule],
        ["firewall-cmd", "--permanent", "--remove-rich-rule", rule],
        ["firewall-cmd", "--reload"],
    ]


def test_firewalld_unblock_reports_missing_backend_rule_idempotently(monkeypatch):
    db = FakeDB()
    executed = []
    rule = 'rule family="ipv4" source address="8.8.8.8" drop'
    db.add_ip_block_action(
        ip="8.8.8.8",
        action="block",
        status="applied",
        dry_run=False,
        backend="firewalld",
        backend_rule_ref=rule,
        reason="manual",
        guard_reason="",
        error="",
        executed_by="terminal",
        suggestion_id=None,
    )
    monkeypatch.setattr("core.ip_blocking.shutil.which", lambda name: "/usr/bin/firewall-cmd" if name == "firewall-cmd" else None)
    blocker = IPBlocker(
        config={"ip_blocking": {}},
        db=db,
        command_runner=_firewalld_runner_factory(executed, existing_rules=set()),
    )
    result = blocker.unblock_ip("8.8.8.8", dry_run=False)
    assert result.ok is False
    assert result.status == "failed"
    assert result.error == "backend_rule_missing"
    assert executed == [
        ["firewall-cmd", "--permanent", "--query-rich-rule", rule],
    ]


@pytest.mark.parametrize("family", ["rhel", "suse"])
def test_firewalld_simulated_apply_is_distro_agnostic(monkeypatch, family):
    db = FakeDB()
    executed = []
    monkeypatch.setattr("core.ip_blocking.shutil.which", lambda name: "/usr/bin/firewall-cmd" if name == "firewall-cmd" else None)
    blocker = IPBlocker(config={"ip_blocking": {"distro_family": family}}, db=db, command_runner=_firewalld_runner_factory(executed))
    result = blocker.block_ip("8.8.4.4", dry_run=True)
    assert result.ok is True
    assert result.backend == "firewalld"
    assert result.commands[0].argv[0] == "firewall-cmd"


def test_guard_rejection_happens_before_backend_selection(monkeypatch):
    db = FakeDB()
    blocker = IPBlocker(config={"ip_blocking": {}}, db=db, command_runner=lambda argv: (_ for _ in ()).throw(AssertionError("command runner should not be called")))
    monkeypatch.setattr(blocker, "_detect_backend", lambda: (_ for _ in ()).throw(AssertionError("backend detection should not run")))
    result = blocker.block_ip("127.0.0.1", dry_run=False)
    assert result.ok is False
    assert result.status == "refused"
    assert result.guard_reason == "loopback_ip"


def test_real_backend_config_unsupported_fails_safe_even_with_firewalld(monkeypatch):
    db = FakeDB()
    executed = []
    monkeypatch.setattr("core.ip_blocking.shutil.which", lambda name: "/usr/bin/firewall-cmd" if name == "firewall-cmd" else None)
    blocker = IPBlocker(
        config={"ip_blocking": {"real_backend": "ufw"}},
        db=db,
        command_runner=_firewalld_runner_factory(executed),
    )
    result = blocker.block_ip("8.8.4.4", dry_run=False)
    assert result.ok is False
    assert result.status == "failed"
    assert result.backend == "firewalld"
    assert result.error == "real_apply_unsupported_for_backend"
    assert executed == [["firewall-cmd", "--state"]]


def test_cli_list_ip_block_suggestions_smoke(monkeypatch, capsys):
    db = FakeDB()
    db.suggestions = [
        {
            "id": 11,
            "ip": "8.8.8.8",
            "source": "abuseipdb",
            "reason": "alert:AUTH-001:src_ip",
            "alert_id": 5,
            "abuse_score": 0,
            "abuse_reports": 68,
            "abuse_country": "US",
            "reviewed": False,
            "action": "",
        },
    ]
    monkeypatch.setattr(main_module, "ensure_database", lambda config: db)
    monkeypatch.setattr(main_module, "load_config", lambda path: {"ip_blocking": {}})
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--list-ip-block-suggestions"])
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "Pending IP block suggestions" in out
    assert "8.8.8.8" in out
    assert "score=0" in out
    assert "reports=68" in out
    assert "country=US" in out
    assert "source=abuseipdb" in out
    assert "reviewed=false" in out


def test_cli_list_ip_block_suggestions_handles_empty_abuse_fields(monkeypatch, capsys):
    db = FakeDB()
    db.suggestions = [
        {
            "id": 12,
            "ip": "5.5.5.5",
            "source": "manual",
            "reason": "operator_note",
            "alert_id": None,
            "abuse_score": None,
            "abuse_reports": None,
            "abuse_country": "",
            "reviewed": False,
            "action": "",
        },
    ]
    monkeypatch.setattr(main_module, "ensure_database", lambda config: db)
    monkeypatch.setattr(main_module, "load_config", lambda path: {"ip_blocking": {}})
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--list-ip-block-suggestions"])
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "ip=5.5.5.5" in out
    assert "score=" in out
    assert "reports=" in out
    assert "country=" in out
    assert "source=manual" in out


def test_cli_list_ip_block_suggestions_shows_only_pending_rows(monkeypatch, capsys):
    db = FakeDB()
    db.suggestions = [
        {
            "id": 13,
            "ip": "6.6.6.6",
            "source": "abuseipdb",
            "reason": "alert:NET-001:src_ip",
            "alert_id": 13,
            "abuse_score": 55,
            "abuse_reports": 7,
            "abuse_country": "DE",
            "reviewed": False,
            "action": "",
        },
        {
            "id": 14,
            "ip": "7.7.7.7",
            "source": "alert",
            "reason": "ignored",
            "alert_id": 14,
            "abuse_score": 12,
            "abuse_reports": 1,
            "abuse_country": "FR",
            "reviewed": True,
            "action": "ignored",
        },
    ]
    monkeypatch.setattr(main_module, "ensure_database", lambda config: db)
    monkeypatch.setattr(main_module, "load_config", lambda path: {"ip_blocking": {}})
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--list-ip-block-suggestions"])
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "ip=6.6.6.6" in out
    assert "ip=7.7.7.7" not in out


def test_cli_list_ip_block_suggestions_does_not_instantiate_executor(monkeypatch, capsys):
    db = FakeDB()
    db.suggestions = [
        {"id": 15, "ip": "8.8.4.4", "source": "abuseipdb", "reason": "alert", "alert_id": 15, "reviewed": False},
    ]
    monkeypatch.setattr(main_module, "ensure_database", lambda config: db)
    monkeypatch.setattr(main_module, "load_config", lambda path: {"ip_blocking": {}})
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--list-ip-block-suggestions"])

    class BoomBlocker:
        def __init__(self, config, db):
            raise AssertionError("list command must not instantiate IPBlocker")

    monkeypatch.setattr(main_module, "IPBlocker", BoomBlocker)
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "ip=8.8.4.4" in out


def test_cli_block_suggestion_dry_run_smoke(monkeypatch, capsys):
    db = FakeDB()
    db.suggestions = [
        {"id": 21, "ip": "8.8.4.4", "source": "alert", "reason": "ioc", "alert_id": 7, "reviewed": False},
    ]
    monkeypatch.setattr(main_module, "ensure_database", lambda config: db)
    monkeypatch.setattr(main_module, "load_config", lambda path: {"ip_blocking": {}})
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--block-suggestion-id", "21", "--dry-run"])

    class FakeBlocker:
        def __init__(self, config, db):
            self._db = db

        def block_ip(self, ip, reason="", dry_run=False, executed_by="terminal", suggestion_id=None):
            self._db.log_action(
                action="ip_block",
                status="dry_run",
                actor=executed_by,
                screen="cli",
                entity_type="ip",
                entity_id=ip,
                target=ip,
                summary="dry-run",
                details={"ip": ip, "suggestion_id": suggestion_id, "reason": reason},
            )
            class _Result:
                status = "dry_run"
                ok = True

                @staticmethod
                def to_dict():
                    return {"ok": True, "status": "dry_run", "ip": "8.8.4.4", "suggestion_id": 21}

            return _Result()

    monkeypatch.setattr(main_module, "IPBlocker", FakeBlocker)
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert '"status": "dry_run"' in out
    assert db.audits[-1]["details"]["suggestion_id"] == 21


def test_abuseipdb_suggestion_flow_does_not_invoke_block_executor(monkeypatch):
    calls = []

    class SuggestionOnlyDB:
        def add_ip_block_suggestion(self, **kwargs):
            calls.append(("suggestion", kwargs))
            return 1

        def add_ip_block_action(self, **kwargs):
            raise AssertionError("executor state should not be used by AbuseIPDB suggestion flow")

    client = AbuseIPDBClient(api_key="dummy", db=SuggestionOnlyDB())
    monkeypatch.setattr(
        client,
        "query",
        lambda ip, max_age_days=90: {
            "ip": ip,
            "abuse_score": 90,
            "total_reports": 12,
            "country_code": "US",
            "raw": {"ipAddress": ip},
        },
    )
    result = client.query_and_save("8.8.8.8", alert_id=55)
    assert result["ip"] == "8.8.8.8"
    assert calls and calls[0][0] == "suggestion"


def test_abuseipdb_skip_when_api_key_missing(monkeypatch):
    client = AbuseIPDBClient(api_key="")

    def _boom(*_args, **_kwargs):
        raise AssertionError("network should not be used when API key is missing")

    monkeypatch.setattr("core.abuseipdb.urllib.request.urlopen", _boom)
    assert client.query("8.8.8.8") is None
    assert client.enrich_alert_ips(src_ip="8.8.8.8", alert_id=9) == {"src_ip": None, "dst_ip": None}


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "172.16.1.3", "192.168.1.4", "255.255.255.255"])
def test_abuseipdb_private_and_local_ips_are_skipped(monkeypatch, ip):
    client = AbuseIPDBClient(api_key="dummy")

    def _boom(*_args, **_kwargs):
        raise AssertionError("network should not be used for non-public IPs")

    monkeypatch.setattr("core.abuseipdb.urllib.request.urlopen", _boom)
    assert client.query(ip) is None


def test_abuseipdb_public_ip_writes_suggestion_without_executor(monkeypatch):
    db = FakeDB()
    client = AbuseIPDBClient(api_key="dummy", db=db)

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(
                {
                    "data": {
                        "ipAddress": "8.8.8.8",
                        "abuseConfidenceScore": 87,
                        "totalReports": 11,
                        "countryCode": "US",
                        "isPublic": True,
                    }
                }
            ).encode("utf-8")

    monkeypatch.setattr("core.abuseipdb.urllib.request.urlopen", lambda req, timeout=10: _Resp())
    result = client.query_and_save("8.8.8.8", alert_id=42, reason="alert:AUTH-001:src_ip")
    assert result["abuse_score"] == 87
    assert db.suggestions[-1]["ip"] == "8.8.8.8"
    assert db.suggestions[-1]["alert_id"] == 42
    assert db.suggestions[-1]["abuse_score"] == 87
    assert db.actions == []


def test_abuseipdb_policy_skips_low_score_and_low_reports(monkeypatch):
    db = FakeDB()
    client = AbuseIPDBClient(
        api_key="dummy",
        db=db,
        suggestion_min_abuse_score=25,
        suggestion_min_reports=3,
    )
    monkeypatch.setattr(
        client,
        "query",
        lambda ip, max_age_days=90: {
            "ip": ip,
            "abuse_score": 10,
            "total_reports": 0,
            "country_code": "US",
            "raw": {"ipAddress": ip},
        },
    )
    result = client.query_and_save("8.8.8.8", alert_id=11, reason="alert:AUTH-001:src_ip")
    assert result["suggestion_written"] is False
    assert db.suggestions == []


def test_abuseipdb_policy_writes_when_score_meets_threshold(monkeypatch):
    db = FakeDB()
    client = AbuseIPDBClient(
        api_key="dummy",
        db=db,
        suggestion_min_abuse_score=25,
        suggestion_min_reports=99,
    )
    monkeypatch.setattr(
        client,
        "query",
        lambda ip, max_age_days=90: {
            "ip": ip,
            "abuse_score": 25,
            "total_reports": 0,
            "country_code": "US",
            "raw": {"ipAddress": ip},
        },
    )
    result = client.query_and_save("8.8.8.8", alert_id=12)
    assert result["suggestion_written"] is True
    assert db.suggestions[-1]["ip"] == "8.8.8.8"


def test_abuseipdb_policy_writes_when_report_count_meets_threshold(monkeypatch):
    db = FakeDB()
    client = AbuseIPDBClient(
        api_key="dummy",
        db=db,
        suggestion_min_abuse_score=90,
        suggestion_min_reports=2,
    )
    monkeypatch.setattr(
        client,
        "query",
        lambda ip, max_age_days=90: {
            "ip": ip,
            "abuse_score": 5,
            "total_reports": 2,
            "country_code": "US",
            "raw": {"ipAddress": ip},
        },
    )
    result = client.query_and_save("8.8.4.4", alert_id=13)
    assert result["suggestion_written"] is True
    assert db.suggestions[-1]["ip"] == "8.8.4.4"


def test_abuseipdb_policy_honors_threshold_changes(monkeypatch):
    db = FakeDB()
    client = AbuseIPDBClient(
        api_key="dummy",
        db=db,
        suggestion_min_abuse_score=50,
        suggestion_min_reports=10,
    )
    monkeypatch.setattr(
        client,
        "query",
        lambda ip, max_age_days=90: {
            "ip": ip,
            "abuse_score": 30,
            "total_reports": 5,
            "country_code": "US",
            "raw": {"ipAddress": ip},
        },
    )
    result = client.query_and_save("8.8.8.8", alert_id=14)
    assert result["suggestion_written"] is False
    assert db.suggestions == []


def test_abuseipdb_policy_can_always_suggest_for_high_severity(monkeypatch):
    db = FakeDB()
    client = AbuseIPDBClient(
        api_key="dummy",
        db=db,
        suggestion_min_abuse_score=90,
        suggestion_min_reports=99,
        always_suggest_for_high_severity=True,
    )
    monkeypatch.setattr(
        client,
        "query",
        lambda ip, max_age_days=90: {
            "ip": ip,
            "abuse_score": 1,
            "total_reports": 0,
            "country_code": "US",
            "raw": {"ipAddress": ip},
        },
    )
    result = client.query_and_save("9.9.9.9", alert_id=15, alert_severity="high")
    assert result["suggestion_written"] is True
    assert db.suggestions[-1]["ip"] == "9.9.9.9"


def test_abuseipdb_cache_prevents_repeat_query(monkeypatch):
    db = FakeDB()
    client = AbuseIPDBClient(api_key="dummy", db=db, cache_ttl=3600)
    calls = []

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            calls.append("hit")
            return json.dumps(
                {
                    "data": {
                        "ipAddress": "1.1.1.1",
                        "abuseConfidenceScore": 12,
                        "totalReports": 2,
                        "countryCode": "AU",
                        "isPublic": True,
                    }
                }
            ).encode("utf-8")

    monkeypatch.setattr("core.abuseipdb.urllib.request.urlopen", lambda req, timeout=10: _Resp())
    first = client.query("1.1.1.1")
    second = client.query("1.1.1.1")
    assert first["abuse_score"] == 12
    assert second["abuse_score"] == 12
    assert calls == ["hit"]


def test_abuseipdb_rate_limit_backoff_skips_repeat_query(monkeypatch):
    client = AbuseIPDBClient(api_key="dummy", rate_limit_backoff=300)
    calls = []

    def _rate_limited(req, timeout=10):
        calls.append("hit")
        raise urllib.error.HTTPError(req.full_url, 429, "rate limited", hdrs=None, fp=None)

    monkeypatch.setattr("core.abuseipdb.urllib.request.urlopen", _rate_limited)
    assert client.query("9.9.9.9") is None
    assert client.query("9.9.9.9") is None
    assert calls == ["hit"]


def test_abuseipdb_alert_enrichment_queries_public_src_and_dst_only(monkeypatch):
    db = FakeDB()
    client = AbuseIPDBClient(api_key="dummy", db=db)
    calls = []

    def _query_and_save(ip, db=None, alert_id=None, reason="", max_age_days=90, alert_severity=""):
        calls.append((ip, alert_id, reason, max_age_days, alert_severity))
        return {"ip": ip, "abuse_score": 50}

    monkeypatch.setattr(client, "query_and_save", _query_and_save)
    result = client.enrich_alert_ips(
        src_ip="8.8.8.8",
        dst_ip="10.0.0.8",
        alert_id=77,
        reason_prefix="alert:NET-001",
        max_age_days=30,
        query_dst_ip=True,
        alert_severity="medium",
    )
    assert result["src_ip"]["ip"] == "8.8.8.8"
    assert result["dst_ip"] is None
    assert calls == [("8.8.8.8", 77, "alert:NET-001:src_ip", 30, "medium")]


def test_alert_enrichment_hook_does_not_invoke_block_executor():
    calls = []

    class ExecutorSafeDB:
        is_connected = True

        @staticmethod
        def add_ip_block_action(**kwargs):
            raise AssertionError("alert enrichment must not persist executor actions")

        @staticmethod
        def add_ip_block_suggestion(**kwargs):
            calls.append(("suggestion", kwargs))
            return 1

    client = AbuseIPDBClient(api_key="dummy", db=ExecutorSafeDB())
    client.query = lambda ip, max_age_days=90: {
        "ip": ip,
        "abuse_score": 91,
        "total_reports": 5,
        "country_code": "US",
        "raw": {"ipAddress": ip},
    }

    pipeline = main_module.SIEMPipeline.__new__(main_module.SIEMPipeline)
    pipeline.config = {"abuseipdb": {"enrich_alert_ips": True, "query_dst_ip": True, "max_age_days": 90}}
    pipeline.abuseipdb = client
    pipeline._maybe_enrich_alert_ips = MethodType(main_module.SIEMPipeline._maybe_enrich_alert_ips, pipeline)

    event = SimpleNamespace(src_ip="8.8.8.8", dst_ip="10.0.0.4")
    pipeline._maybe_enrich_alert_ips(event, alert_id=88, rule_id="AUTH-001", severity="high")
    assert calls and calls[0][0] == "suggestion"


def test_emit_alert_enrichment_writes_suggestion_without_executor():
    calls = []

    class AlertFlowDB:
        is_connected = True

        @staticmethod
        def is_in_cooldown(rule_id, entity):
            return False

        @staticmethod
        def insert_alert(alert):
            return 501

        @staticmethod
        def set_cooldown(rule_id, entity, seconds):
            return None

        @staticmethod
        def add_ip_block_action(**kwargs):
            raise AssertionError("alert flow must not persist executor actions")

        @staticmethod
        def add_ip_block_suggestion(**kwargs):
            calls.append(("suggestion", kwargs))
            return 1

    client = AbuseIPDBClient(api_key="dummy", db=AlertFlowDB())
    client.query = lambda ip, max_age_days=90: {
        "ip": ip,
        "abuse_score": 70,
        "total_reports": 3,
        "country_code": "US",
        "raw": {"ipAddress": ip},
    }

    pipeline = main_module.SIEMPipeline.__new__(main_module.SIEMPipeline)
    pipeline.db = AlertFlowDB()
    pipeline.config = {"abuseipdb": {"enrich_alert_ips": True, "query_dst_ip": True, "max_age_days": 90}, "risk": {"cooldown": {"default_seconds": 300}}}
    pipeline.abuseipdb = client
    pipeline.label_engine = None
    pipeline.delayed_buffer = SimpleNamespace(mark_ioc=lambda ent: None, mark_alarm=lambda ent, alarm_type: None)
    pipeline._runtime_state = SimpleNamespace(record_alert_layer=lambda layer: None)
    pipeline._should_emit_user_output = lambda *args, **kwargs: False
    pipeline.write_file = False
    pipeline.notifier = None
    pipeline.correlation = SimpleNamespace(process=lambda data: [])
    pipeline.incident = SimpleNamespace(process_alert=lambda data, risk_score=0: None)
    pipeline.ml_ctrl = SimpleNamespace(on_incident=lambda severity, incident_id: None)
    pipeline.phase = SimpleNamespace(current_phase=0)
    pipeline._record_stage_timing = lambda stage, ms: None
    pipeline._alert_count = 0

    event = SimpleNamespace(
        ts=1000.0,
        host="host01",
        src_ip="8.8.8.8",
        dst_ip="10.0.0.8",
        user="alice",
        process="ssh",
        action="ssh_login",
        outcome="failure",
        source="auth.log",
        category="auth",
        to_dict=lambda: {"src_ip": "8.8.8.8", "dst_ip": "10.0.0.8"},
    )
    main_module.SIEMPipeline._emit_alert(
        pipeline,
        event=event,
        rule_id="AUTH-001",
        severity="high",
        score=75.0,
        message="test alert",
        details={},
    )
    assert calls and calls[0][0] == "suggestion"


def test_emit_alert_enrichment_policy_skips_low_reputation_suggestions():
    calls = []

    class AlertFlowDB:
        is_connected = True

        @staticmethod
        def is_in_cooldown(rule_id, entity):
            return False

        @staticmethod
        def insert_alert(alert):
            return 502

        @staticmethod
        def set_cooldown(rule_id, entity, seconds):
            return None

        @staticmethod
        def add_ip_block_action(**kwargs):
            raise AssertionError("alert flow must not persist executor actions")

        @staticmethod
        def add_ip_block_suggestion(**kwargs):
            calls.append(("suggestion", kwargs))
            return 1

    client = AbuseIPDBClient(
        api_key="dummy",
        db=AlertFlowDB(),
        suggestion_min_abuse_score=25,
        suggestion_min_reports=1,
    )
    client.query = lambda ip, max_age_days=90: {
        "ip": ip,
        "abuse_score": 0,
        "total_reports": 0,
        "country_code": "US",
        "raw": {"ipAddress": ip},
    }

    pipeline = main_module.SIEMPipeline.__new__(main_module.SIEMPipeline)
    pipeline.db = AlertFlowDB()
    pipeline.config = {
        "abuseipdb": {
            "enrich_alert_ips": True,
            "query_dst_ip": True,
            "max_age_days": 90,
        },
        "risk": {"cooldown": {"default_seconds": 300}},
    }
    pipeline.abuseipdb = client
    pipeline.label_engine = None
    pipeline.delayed_buffer = SimpleNamespace(mark_ioc=lambda ent: None, mark_alarm=lambda ent, alarm_type: None)
    pipeline._runtime_state = SimpleNamespace(record_alert_layer=lambda layer: None)
    pipeline._should_emit_user_output = lambda *args, **kwargs: False
    pipeline.write_file = False
    pipeline.notifier = None
    pipeline.correlation = SimpleNamespace(process=lambda data: [])
    pipeline.incident = SimpleNamespace(process_alert=lambda data, risk_score=0: None)
    pipeline.ml_ctrl = SimpleNamespace(on_incident=lambda severity, incident_id: None)
    pipeline.phase = SimpleNamespace(current_phase=0)
    pipeline._record_stage_timing = lambda stage, ms: None
    pipeline._alert_count = 0

    event = SimpleNamespace(
        ts=1001.0,
        host="host02",
        src_ip="8.8.4.4",
        dst_ip="10.0.0.8",
        user="alice",
        process="ssh",
        action="ssh_login",
        outcome="failure",
        source="auth.log",
        category="auth",
        to_dict=lambda: {"src_ip": "8.8.4.4", "dst_ip": "10.0.0.8"},
    )
    main_module.SIEMPipeline._emit_alert(
        pipeline,
        event=event,
        rule_id="AUTH-002",
        severity="medium",
        score=70.0,
        message="test alert policy",
        details={},
    )
    assert calls == []


def test_report_includes_abuseipdb_reputation_section():
    db = FakeDB()
    db.suggestions = [
        {
            "id": 91,
            "ip": "8.8.8.8",
            "source": "abuseipdb",
            "reason": "alert:AUTH-001:src_ip",
            "alert_id": 999002,
            "abuse_score": 12,
            "abuse_reports": 34,
            "abuse_country": "US",
            "reviewed": False,
            "action": "",
            "suggested_at": 2000.0,
        },
        {
            "id": 92,
            "ip": "9.9.9.9",
            "source": "abuseipdb",
            "reason": "alert:NET-002:src_ip",
            "alert_id": 999003,
            "abuse_score": 55,
            "abuse_reports": 4,
            "abuse_country": "DE",
            "reviewed": True,
            "action": "ignored",
            "suggested_at": 1990.0,
        },
    ]

    class ReportDB(FakeDB):
        def get_report_stats(self, since):
            return {
                "total_alerts": 2,
                "by_severity": {"high": 1, "medium": 1},
                "top_rules": [("AUTH-001", 1)],
                "top_entities": [("8.8.8.8", 1)],
                "top_users": [("alice", 1)],
                "top_hosts": [("host01", 1)],
                "incident_total": 0,
                "by_status": {},
                "by_hour": {10: 2},
                "recent_incidents": [],
            }

    report_db = ReportDB()
    report_db.suggestions = db.suggestions
    engine = ReportEngine(report_db)
    report = engine.daily_report(days_back=1)
    html = engine.to_html(report)
    assert "IP Reputation / AbuseIPDB" in html
    assert "8.8.8.8" in html
    assert "999002" in html
    assert "pending" in html
    assert "ignored" in html


def test_report_handles_missing_reputation_enrichment():
    class ReportDB(FakeDB):
        def get_report_stats(self, since):
            return {
                "total_alerts": 0,
                "by_severity": {},
                "top_rules": [],
                "top_entities": [],
                "top_users": [],
                "top_hosts": [],
                "incident_total": 0,
                "by_status": {},
                "by_hour": {},
                "recent_incidents": [],
            }

    engine = ReportEngine(ReportDB())
    report = engine.daily_report(days_back=1)
    html = engine.to_html(report)
    assert "IP Reputation / AbuseIPDB" in html
    assert "No reputation enrichment available." in html


def test_llm_selected_alert_prompt_includes_ip_reputation():
    client = LLMClient({"llm": {"enabled": True, "backend": "mock", "language": "en", "max_tokens": 300}})
    captured = {}

    class CaptureBackend:
        def complete(self, system, user, max_tokens=300):
            captured["system"] = system
            captured["user"] = user
            return "Summary\nAttack Type\nSource/Target\nEvidence\nImpact\nImmediate Action\nLong-term Mitigation\nAdditional Checks\nFalse Positive Likelihood\nConfidence Score"

    client._backend = CaptureBackend()
    alert = {
        "rule_id": "AUTH-001",
        "severity": "high",
        "risk_score": 80,
        "category": "auth",
        "entity": "8.8.8.8",
        "host": "host01",
        "message": "test",
        "ip_reputation": [
            {
                "ip": "8.8.8.8",
                "abuse_score": 12,
                "abuse_reports": 34,
                "abuse_country": "US",
                "source": "abuseipdb",
                "reviewed": False,
                "action": "",
            }
        ],
    }
    client.explain_selected_alert(alert, related_events=[])
    assert "IP reputation:" in captured["user"]
    assert "[IP] — AbuseIPDB score=12, reports=34, country=US, suggestion_status=pending, source=abuseipdb" in captured["user"]


def test_llm_selected_alert_prompt_handles_missing_reputation():
    client = LLMClient({"llm": {"enabled": True, "backend": "mock", "language": "en", "max_tokens": 300}})
    captured = {}

    class CaptureBackend:
        def complete(self, system, user, max_tokens=300):
            captured["user"] = user
            return "Summary\nAttack Type\nSource/Target\nEvidence\nImpact\nImmediate Action\nLong-term Mitigation\nAdditional Checks\nFalse Positive Likelihood\nConfidence Score"

    client._backend = CaptureBackend()
    alert = {
        "rule_id": "AUTH-002",
        "severity": "medium",
        "risk_score": 60,
        "category": "network",
        "entity": "1.1.1.1",
        "host": "host02",
        "message": "test",
    }
    client.explain_selected_alert(alert, related_events=[])
    assert "IP reputation:" in captured["user"]
    assert "No reputation enrichment available." in captured["user"]


def test_cli_explain_alert_calls_selected_alert_llm(monkeypatch, capsys):
    db = FakeDB()
    db.alerts[101] = {
        "id": 101,
        "rule_id": "AUTH-001",
        "severity": "high",
        "risk_score": 88,
        "category": "auth",
        "entity": "8.8.8.8",
        "host": "host01",
        "message": "test alert",
    }
    db.suggestions = [
        {
            "id": 33,
            "ip": "8.8.8.8",
            "source": "abuseipdb",
            "reason": "alert:AUTH-001:src_ip",
            "alert_id": 101,
            "abuse_score": 12,
            "abuse_reports": 34,
            "abuse_country": "US",
            "reviewed": False,
            "action": "",
        }
    ]
    monkeypatch.setattr(main_module, "ensure_database", lambda config: db)
    monkeypatch.setattr(main_module, "load_config", lambda path: {"llm": {"enabled": False}})
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--explain-alert", "101"])

    class FakeLLM:
        is_active = True
        disable_reason = ""

        def __init__(self):
            self.calls = []

        def explain_selected_alert(self, alert_dict, related_events=None):
            self.calls.append((alert_dict, related_events))
            return "LLM explanation body"

    fake_llm = FakeLLM()
    monkeypatch.setattr(main_module, "_load_llm_client_for_cli", lambda config, config_path: fake_llm)
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "LLM explanation body" in out
    assert fake_llm.calls[0][0]["ip_reputation"][0]["abuse_score"] == 12


def test_cli_explain_alert_not_found(monkeypatch, capsys):
    db = FakeDB()
    monkeypatch.setattr(main_module, "ensure_database", lambda config: db)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--explain-alert", "404"])
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "Alert bulunamadı: id=404" in err


def test_cli_explain_alert_handles_llm_disabled(monkeypatch, capsys):
    db = FakeDB()
    db.alerts[102] = {
        "id": 102,
        "rule_id": "AUTH-002",
        "severity": "medium",
        "risk_score": 40,
        "category": "auth",
        "entity": "1.1.1.1",
        "host": "host02",
        "message": "disabled llm",
    }
    monkeypatch.setattr(main_module, "ensure_database", lambda config: db)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--explain-alert", "102"])

    class DisabledLLM:
        is_active = False
        disable_reason = "LLM disabled/not configured"

        def explain_selected_alert(self, alert_dict, related_events=None):
            raise AssertionError("disabled LLM should not be called")

    monkeypatch.setattr(main_module, "_load_llm_client_for_cli", lambda config, config_path: DisabledLLM())
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "LLM disabled/not configured" in out


def test_cli_explain_alert_passes_no_reputation_when_missing(monkeypatch, capsys):
    db = FakeDB()
    db.alerts[103] = {
        "id": 103,
        "rule_id": "NET-001",
        "severity": "low",
        "risk_score": 20,
        "category": "network",
        "entity": "1.1.1.1",
        "host": "host03",
        "message": "no reputation",
    }
    monkeypatch.setattr(main_module, "ensure_database", lambda config: db)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--explain-alert", "103"])

    class FakeLLM:
        is_active = True
        disable_reason = ""

        def __init__(self):
            self.payload = None

        def explain_selected_alert(self, alert_dict, related_events=None):
            self.payload = alert_dict
            return "ok"

    fake_llm = FakeLLM()
    monkeypatch.setattr(main_module, "_load_llm_client_for_cli", lambda config, config_path: fake_llm)
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 0
    assert fake_llm.payload["ip_reputation"] == []


def test_cli_explain_alert_is_read_only_and_does_not_touch_executor(monkeypatch, capsys):
    db = FakeDB()
    db.alerts[104] = {
        "id": 104,
        "rule_id": "AUTH-004",
        "severity": "high",
        "risk_score": 70,
        "category": "auth",
        "entity": "8.8.4.4",
        "host": "host04",
        "message": "read only",
    }
    monkeypatch.setattr(main_module, "ensure_database", lambda config: db)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--explain-alert", "104"])

    class FakeLLM:
        is_active = True
        disable_reason = ""

        def explain_selected_alert(self, alert_dict, related_events=None):
            return "read-only"

    class BoomBlocker:
        def __init__(self, config, db):
            raise AssertionError("explain-alert must not instantiate IPBlocker")

    monkeypatch.setattr(main_module, "_load_llm_client_for_cli", lambda config, config_path: FakeLLM())
    monkeypatch.setattr(main_module, "IPBlocker", BoomBlocker)
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "read-only" in out
    assert db.actions == []
