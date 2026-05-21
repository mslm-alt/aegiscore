from __future__ import annotations

import json
from pathlib import Path

import pytest

import main as main_module
from core.ml import verified_manifest_audit as audit_module
from core.ml.verified_manifest import build_verified_label_manifest


def _event(
    event_id: int,
    *,
    ts: float = 1000.0,
    source: str = "auth_log",
    category: str = "auth",
    action: str = "ssh_invalid_user",
    outcome: str = "failure",
    username: str = "alice",
    process: str = "/usr/sbin/sshd",
    host: str = "host-a",
    src_ip: str = "198.51.100.10",
    message: str = "invalid user",
    raw_log: str = "",
    risk_bucket: str = "suspicious",
):
    return {
        "id": event_id,
        "ts": ts,
        "source": source,
        "category": category,
        "action": action,
        "outcome": outcome,
        "username": username,
        "process": process,
        "host": host,
        "src_ip": src_ip,
        "message": message,
        "raw_log": raw_log,
        "risk_bucket": risk_bucket,
        "distro_family": "debian",
    }


def _alert(alert_id: int, *, ts: float = 1000.0, rule_id: str = "AUTH-003", category: str = "auth", ctx=None):
    return {
        "id": alert_id,
        "ts": ts,
        "rule_id": rule_id,
        "severity": "high",
        "entity": "alice",
        "message": f"rule {rule_id}",
        "incident_id": "",
        "context_json": ctx or {},
        "host": "host-a",
        "category": category,
    }


def _manifest():
    return build_verified_label_manifest(
        [_event(1), _event(2, source="auditd", category="process", action="exec", outcome="unknown", process="nmap", src_ip="", risk_bucket="normal")],
        [_alert(10, ctx={"event_id": "1"}), _alert(11, rule_id="DISC-002", category="process", ts=1001.0, ctx={"event_id": "2", "process": "nmap"})],
    )


def test_audit_valid_manifest_schema():
    audit = audit_module.audit_verified_manifest(_manifest())
    assert audit["schema_valid"] is True
    assert audit["no_action_contract"] is True
    assert audit["active_training_enabled"] is False


def test_audit_blocked_when_no_action_contract_false():
    manifest = _manifest()
    manifest["no_action_contract"] = False
    audit = audit_module.audit_verified_manifest(manifest)
    assert audit["status"] == "blocked"
    assert "no_action_contract_false" in audit["blockers"]


def test_audit_blocked_when_active_training_enabled_true():
    manifest = _manifest()
    manifest["active_training_enabled"] = True
    audit = audit_module.audit_verified_manifest(manifest)
    assert audit["status"] == "blocked"
    assert "active_training_enabled_true" in audit["blockers"]


def test_audit_blocked_on_candidate_count_mismatch():
    manifest = _manifest()
    manifest["candidate_count"] = 999
    audit = audit_module.audit_verified_manifest(manifest)
    assert audit["status"] == "blocked"
    assert "candidate_count_mismatch" in audit["blockers"] or "invalid:candidate_count_reconciliation" in audit["blockers"]


def test_audit_blocked_on_raw_secret_pattern():
    manifest = _manifest()
    manifest["candidates"][0]["evidence_fields"]["raw_excerpt"] = "password=secret"
    audit = audit_module.audit_verified_manifest(manifest)
    assert audit["status"] == "blocked"
    assert any("raw_secret_pattern" in item for item in audit["blockers"])


def test_audit_family_threshold_failure():
    audit = audit_module.audit_verified_manifest(_manifest())
    assert audit["family_results"]["ML-AUTH"]["status"] in {"fail", "warning"}
    assert audit["status"] == "blocked"


def test_audit_direct_learning_ready_with_warnings():
    manifest = _manifest()
    manifest["direct_learnable_count"] = 0
    manifest["ignored_candidate_count"] = len(manifest["candidates"])
    for item in manifest["candidates"]:
        item["disposition"] = "ignored"
        item["rejection_reason"] = ""
    audit = audit_module.audit_verified_manifest(manifest)
    assert audit["status"] == "direct_learning_ready"


def test_audit_recommendations_use_auto_label_language():
    audit = audit_module.audit_verified_manifest(_manifest())
    dumped = json.dumps(audit, ensure_ascii=False)
    assert "human decision" not in dumped.lower()
    assert audit["status"] in {"blocked", "direct_learning_ready", "direct_learning_ready_with_warnings"}
    assert "direct_learnable" in dumped


def test_audit_blocks_suspicious_candidate_with_baseline_scope():
    manifest = _manifest()
    manifest["candidates"][0]["event_class"] = "attack"
    manifest["candidates"][0]["model_usage_scope"] = "baseline_learning"
    audit = audit_module.audit_verified_manifest(manifest)
    assert "candidate[0]:invalid_attack_baseline_scope" in audit["blockers"]


def test_path_traversal_denied_for_exports(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError):
        audit_module.write_json_output({"ok": True}, "../escape.json")


def test_no_db_write_or_runtime_side_effect_static():
    manifest = _manifest()
    manifest["input_snapshots"]["db_write_attempted"] = False
    manifest["input_snapshots"]["active_ml_enabled"] = False
    manifest["input_snapshots"]["train_triggered"] = False
    manifest["input_snapshots"]["evaluate_triggered"] = False
    manifest["input_snapshots"]["alert_emit_triggered"] = False
    manifest["input_snapshots"]["direct_learning_only"] = True
    audit = audit_module.audit_verified_manifest(manifest)
    assert audit["no_action_contract"] is True
    assert audit["active_training_enabled"] is False
    assert audit["db_write_attempted"] is False
    assert audit["active_ml_enabled"] is False
    assert audit["train_triggered"] is False
    assert audit["evaluate_triggered"] is False
    assert audit["alert_emit_triggered"] is False
    assert audit["direct_learning_only"] is True


def test_main_cli_smoke_for_manifest_audit(monkeypatch, tmp_path, capsys):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(_manifest(), ensure_ascii=False), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_verified_manifest_audit_cli", lambda manifest_path, printer=print: print("Verified Manifest Audit") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-verified-manifest-audit", str(manifest_path)])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert "Verified Manifest Audit" in capsys.readouterr().out
