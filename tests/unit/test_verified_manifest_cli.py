from __future__ import annotations

import json
from pathlib import Path

import pytest

import main as main_module
from core.ml import verified_manifest_cli as cli_module

_LEGACY_ACCEPTED_COUNT_KEY = "accepted" "_candidate_count"


class _FakeDB:
    def __init__(self, *, missing_event_columns=None, missing_alert_columns=None):
        self.ops = []
        self.closed = False
        self.missing_event_columns = set(missing_event_columns or set())
        self.missing_alert_columns = set(missing_alert_columns or set())

    def _execute(self, sql, params=(), fetch="all"):
        self.ops.append((str(sql), tuple(params), fetch))
        text = str(sql)
        if "information_schema.columns" in text:
            table = params[0]
            if table == "events_recent":
                cols = [
                    "id", "ts", "source", "category", "action", "outcome", "username",
                    "process", "host", "src_ip", "message", "raw_log", "risk_bucket",
                    "distro_family", "incident_id",
                ]
                cols = [c for c in cols if c not in self.missing_event_columns]
                return [{"column_name": c} for c in cols]
            if table == "alerts":
                cols = ["id", "ts", "rule_id", "severity", "entity", "message", "incident_id", "context_json", "host", "category"]
                cols = [c for c in cols if c not in self.missing_alert_columns]
                return [{"column_name": c} for c in cols]
        if "FROM events_recent" in text:
            return [
                {
                    "id": 1,
                    "ts": 1000.0,
                    "source": "auth_log",
                    "category": "auth",
                    "action": "ssh_invalid_user",
                    "outcome": "failure",
                    "username": "alice",
                    "process": "/usr/sbin/sshd",
                    "host": "host-a",
                    "src_ip": "198.51.100.10",
                    "message": "token=abc123 invalid user",
                    "raw_log": "OPENAI_API_KEY=sk-test invalid user",
                    "risk_bucket": "suspicious",
                    "distro_family": "debian",
                    "incident_id": "",
                },
                {
                    "id": 2,
                    "ts": 1001.0,
                    "source": "auditd",
                    "category": "process",
                    "action": "exec",
                    "outcome": "unknown",
                    "username": "alice",
                    "process": "nmap",
                    "host": "",
                    "src_ip": "",
                    "message": "discovery execution",
                    "raw_log": "",
                    "risk_bucket": "normal",
                    "distro_family": "debian",
                    "incident_id": "",
                },
            ]
        if "FROM alerts" in text:
            return [
                {
                    "id": 10,
                    "ts": 1000.0,
                    "rule_id": "AUTH-003",
                    "severity": "high",
                    "entity": "alice",
                    "message": "auth rule",
                    "incident_id": "",
                    "context_json": {"event_id": "1", "username": "alice", "src_ip": "198.51.100.10"},
                    "host": "host-a",
                    "category": "auth",
                },
                {
                    "id": 11,
                    "ts": 1001.0,
                    "rule_id": "DISC-002",
                    "severity": "medium",
                    "entity": "alice",
                    "message": "proc discovery",
                    "incident_id": "",
                    "context_json": {"event_id": "2", "process": "nmap"},
                    "host": "",
                    "category": "process",
                },
            ]
        return []

    def close(self):
        self.closed = True


def test_db_loader_missing_columns_is_graceful():
    db = _FakeDB(missing_event_columns={"incident_id", "raw_log"}, missing_alert_columns={"entity"})
    manifest = cli_module.collect_live_verified_manifest(db, limit=25)
    assert manifest["candidate_count"] >= 1
    assert "incident_id" not in manifest["input_snapshots"]["events_recent_columns"]
    assert "entity" not in manifest["input_snapshots"]["alerts_columns"]


def test_event_and_alert_snapshot_conversion_reaches_manifest():
    db = _FakeDB()
    manifest = cli_module.collect_live_verified_manifest(db, limit=25, families=["ML-AUTH"])
    item = manifest["candidates"][0]
    assert item["source_event_id"] == "events_recent:1"
    assert item["correlated_alert_ids"] == ["10"]
    assert item["ml_family"] == "ML-AUTH"


def test_cli_helper_dry_run_returns_manifest_and_no_default_file_write(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    db = _FakeDB()
    monkeypatch.setattr(cli_module, "create_database", lambda config: db)
    lines = []
    rc = cli_module.run_verified_manifest_dry_run({}, printer=lines.append)
    assert rc == 0
    assert db.closed is True
    assert any("direct_learnable_count=" in line for line in lines)
    assert all(f"{_LEGACY_ACCEPTED_COUNT_KEY}=" not in line for line in lines)
    assert any("NO DB WRITE / NO ACTIVE ML / DRY RUN ONLY" in line for line in lines)
    assert not list(tmp_path.rglob("*.json"))


def test_unsupported_family_rejected():
    with pytest.raises(ValueError):
        cli_module.parse_family_filters(["ML-DNS"])


def test_output_path_traversal_denied(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError):
        cli_module.write_manifest_output({"ok": True}, "../outside.json")


def test_explicit_out_writes_sanitized_json(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    db = _FakeDB()
    monkeypatch.setattr(cli_module, "create_database", lambda config: db)
    out = "data/ml_label_scan/latest_verified_manifest.json"
    rc = cli_module.run_verified_manifest_dry_run({}, out_path=out, printer=lambda *_: None)
    assert rc == 0
    payload = json.loads(Path(out).read_text(encoding="utf-8"))
    dumped = json.dumps(payload, ensure_ascii=False)
    assert "abc123" not in dumped
    assert "sk-test" not in dumped
    assert _LEGACY_ACCEPTED_COUNT_KEY not in payload
    assert payload["source"] == "verified_manifest_dry_run"


def test_no_db_write_operations_are_attempted():
    db = _FakeDB()
    cli_module.collect_live_verified_manifest(db)
    assert db.ops
    assert all(str(sql).lstrip().upper().startswith("SELECT") for sql, _params, _fetch in db.ops)


def test_no_active_ml_train_evaluate_or_emit_flags_in_manifest():
    db = _FakeDB()
    manifest = cli_module.collect_live_verified_manifest(db)
    snap = manifest["input_snapshots"]
    assert snap["db_write_attempted"] is False
    assert snap["active_ml_enabled"] is False
    assert snap["train_triggered"] is False
    assert snap["evaluate_triggered"] is False
    assert snap["alert_emit_triggered"] is False
    assert snap["direct_learning_only"] is True


def test_main_cli_smoke_for_verified_manifest_flag(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_verified_manifest_dry_run", lambda config, families=None, limit=5000, out_path="", printer=print: print("Verified Label Manifest Dry Run") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-verified-manifest-dry-run", "--ml-verified-manifest-family", "ML-AUTH"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert "Verified Label Manifest Dry Run" in capsys.readouterr().out
