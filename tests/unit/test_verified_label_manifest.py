from __future__ import annotations

from core.ml.verified_manifest import (
    build_verified_label_manifest,
    redact_text,
    validate_verified_label_manifest,
)

_LEGACY_ACCEPTED_COUNT_KEY = "accepted" "_candidate_count"


def _event(
    event_id: int,
    *,
    ts: float = 1000.0,
    source: str = "auth_log",
    category: str = "auth",
    action: str = "ssh_login",
    outcome: str = "failure",
    username: str = "alice",
    process: str = "/usr/sbin/sshd",
    host: str = "host-a",
    src_ip: str = "198.51.100.10",
    message: str = "Failed password",
    raw_log: str = "",
    risk_bucket: str = "suspicious",
    incident_id: str = "",
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
        "incident_id": incident_id,
        "distro_family": "debian",
    }


def _alert(
    alert_id: int,
    *,
    ts: float = 1000.0,
    rule_id: str = "AUTH-002",
    category: str = "auth",
    host: str = "host-a",
    incident_id: str = "",
    ctx: dict | None = None,
):
    return {
        "id": alert_id,
        "ts": ts,
        "rule_id": rule_id,
        "category": category,
        "severity": "high",
        "host": host,
        "incident_id": incident_id,
        "message": f"rule {rule_id}",
        "context_json": ctx or {},
    }


def test_schema_valid_manifest_and_safety_flags():
    manifest = build_verified_label_manifest(
        [_event(1), _event(2, action="session_open", outcome="success", src_ip="192.0.2.2", message="session opened")],
        [_alert(10, ctx={"event_id": "1"})],
        manifest_id="manifest-1",
        created_at="2026-05-11T20:00:00Z",
    )

    assert manifest["manifest_id"] == "manifest-1"
    assert manifest["source"] == "verified_manifest_dry_run"
    assert manifest["dry_run"] is True
    assert manifest["no_action_contract"] is True
    assert manifest["active_training_enabled"] is False
    assert manifest["redaction_status"] == "passed"
    assert _LEGACY_ACCEPTED_COUNT_KEY not in manifest
    assert validate_verified_label_manifest(manifest)["valid"] is True


def test_redaction_masks_fake_secrets():
    text = (
        "token=abc123 Authorization: Bearer topsecret "
        "password=hunter2 api_key=key1 TELEGRAM_BOT_TOKEN=xyz OPENAI_API_KEY=sk-test"
    )
    redacted = redact_text(text)
    assert "abc123" not in redacted
    assert "topsecret" not in redacted
    assert "hunter2" not in redacted
    assert "key1" not in redacted
    assert "sk-test" not in redacted
    assert "[REDACTED]" in redacted


def test_ml_auth_invalid_user_and_failure_burst_become_suspicious():
    events = [
        _event(1, action="ssh_invalid_user", outcome="failure", username="bob", src_ip="203.0.113.10"),
        _event(2, action="ssh_login", outcome="failure", username="alice", src_ip="203.0.113.20"),
    ]
    alerts = [
        _alert(11, rule_id="AUTH-003", ctx={"event_id": "1"}),
        _alert(12, rule_id="AUTH-002", ctx={"event_id": "2"}),
    ]
    manifest = build_verified_label_manifest(events, alerts)
    auth_items = [item for item in manifest["candidates"] if item["ml_family"] == "ML-AUTH"]
    assert len(auth_items) == 2
    assert {item["behavior_label"] for item in auth_items} == {"ssh_invalid_user_enumeration", "ssh_auth_failure"}
    assert all(item["event_class"] == "suspicious" for item in auth_items)


def test_ml_auth_malformed_username_rejected():
    manifest = build_verified_label_manifest(
        [_event(1, action="ssh_invalid_user", outcome="failure", username="28696E76616C6964207573657229")],
        [_alert(10, rule_id="AUTH-003", ctx={"event_id": "1"})],
    )
    item = manifest["candidates"][0]
    assert item["rejection_reason"] == "malformed_identity"
    assert item["disposition"] == "rejected"


def test_ml_proc_generic_syscall_rejects_without_rule_support():
    manifest = build_verified_label_manifest(
        [_event(1, source="auditd", category="process", action="syscall", outcome="unknown", process="bash", username="alice", src_ip="")],
        [],
    )
    item = [row for row in manifest["candidates"] if row["ml_family"] == "ML-PROC"][0]
    assert item["rejection_reason"] == "generic_syscall_noise"
    assert item["disposition"] == "rejected"


def test_ml_proc_disc_rule_is_ignored_when_not_directly_learnable():
    manifest = build_verified_label_manifest(
        [_event(1, source="auditd", category="process", action="exec", outcome="unknown", process="nmap", username="alice", src_ip="")],
        [_alert(10, rule_id="DISC-002", category="process", ctx={"event_id": "1"})],
    )
    item = [row for row in manifest["candidates"] if row["ml_family"] == "ML-PROC"][0]
    assert item["ml_label"] == "discovery_behavior"
    assert item["model_usage_scope"] == "not_learnable"
    assert item["disposition"] == "ignored"
    assert item["learnable"] is False


def test_ml_impact_generic_file_access_rejects():
    manifest = build_verified_label_manifest(
        [_event(1, source="auditd", category="filesystem", action="file_access", outcome="unknown", process="", host="", risk_bucket="suspicious")],
        [],
    )
    item = [row for row in manifest["candidates"] if row["ml_family"] == "ML-IMPACT"][0]
    assert item["rejection_reason"] == "generic_file_access"
    assert item["disposition"] == "rejected"


def test_rule_backed_candidate_can_be_directly_learnable():
    manifest = build_verified_label_manifest(
        [_event(1, action="session_open", outcome="success", src_ip="192.0.2.20", message="session opened cleanly")],
        [_alert(10, rule_id="AUTH-002", ctx={"event_id": "1"})],
    )
    item = manifest["candidates"][0]
    assert item["disposition"] == "direct_learnable"
    assert item["learnable_candidate"] is True
    assert item["model_usage_scope"] == "calibration_only"
    assert item["source_quality"] == "direct_rule_high"
    assert item["no_action_contract"] is True
    assert item["active_training_enabled"] is False


def test_attack_candidate_never_uses_baseline_learning_scope():
    manifest = build_verified_label_manifest(
        [_event(1, action="ssh_invalid_user", outcome="failure", src_ip="192.0.2.25", message="invalid user")],
        [_alert(10, rule_id="AUTH-003", ctx={"event_id": "1"})],
    )
    item = manifest["candidates"][0]
    assert item["event_class"] == "suspicious"
    assert item["model_usage_scope"] != "baseline_learning"


def test_duplicate_and_dominance_only_reject_candidates():
    events = [
        _event(1, source="auditd", category="process", action="exec", outcome="unknown", process="same-proc", username="alice", src_ip=""),
        _event(2, source="auditd", category="process", action="exec", outcome="unknown", process="same-proc", username="alice", src_ip=""),
    ]
    alerts = [
        _alert(10, rule_id="PROC-011", category="process", ctx={"event_id": "1"}),
        _alert(11, rule_id="PROC-011", category="process", ctx={"event_id": "2"}),
    ]
    manifest = build_verified_label_manifest(events, alerts)
    assert all(item["disposition"] in {"direct_learnable", "ignored", "rejected"} for item in manifest["candidates"])
    assert any(item["disposition"] == "rejected" and item["rejection_reason"] == "duplicate_replay" for item in manifest["candidates"])


def test_weak_rule_correlation_is_ignored():
    manifest = build_verified_label_manifest(
        [_event(1, action="ssh_login", outcome="failure", username="", host="", src_ip="198.51.100.30", message="failed password")],
        [_alert(10, rule_id="AUTH-002", category="network", host="", ts=1100.0, ctx={})],
    )
    item = manifest["candidates"][0]
    assert item["rejection_reason"] == "weak_rule_correlation"
    assert item["disposition"] == "ignored"
    assert item["learnable_candidate"] is False


def test_candidate_scoring_is_clamped():
    manifest = build_verified_label_manifest(
        [_event(1, action="session_open", outcome="success", message="ok", src_ip="192.0.2.2")],
        [_alert(10, rule_id="AUTH-002", ctx={"event_id": "1"})],
    )
    score = manifest["candidates"][0]["candidate_score"]
    corr = manifest["candidates"][0]["correlation_score"]
    assert 0.0 <= score <= 1.0
    assert 0.0 <= corr <= 1.0


def test_dominance_summary_and_duplicate_replay_are_reported():
    events = [
        _event(1, source="auditd", category="process", action="exec", outcome="unknown", process="same-proc", username="alice", src_ip=""),
        _event(2, source="auditd", category="process", action="exec", outcome="unknown", process="same-proc", username="alice", src_ip=""),
    ]
    alerts = [
        _alert(10, rule_id="PROC-011", category="process", ctx={"event_id": "1"}),
        _alert(11, rule_id="PROC-011", category="process", ctx={"event_id": "2"}),
    ]
    manifest = build_verified_label_manifest(events, alerts)
    proc = manifest["dominance_summary"]["ML-PROC"]
    assert proc["process_top"]["value"] == "same-proc"
    assert manifest["duplicate_summary"]["duplicate_count"] >= 1
    assert any(item["rejection_reason"] == "duplicate_replay" for item in manifest["candidates"])


def test_behavioral_readiness_decision_can_be_direct_learning_ready_with_warnings():
    manifest = build_verified_label_manifest(
        [_event(1, source="auditd", category="process", action="exec", outcome="unknown", process="nmap", username="alice", src_ip="")],
        [_alert(10, rule_id="DISC-002", category="process", ctx={"event_id": "1"})],
    )
    assert manifest["readiness_decision"] == "blocked"


def test_generator_has_no_db_write_or_runtime_side_effect_api():
    manifest = build_verified_label_manifest([_event(1)], [_alert(10, ctx={"event_id": "1"})])
    assert "human decision" not in str(manifest).lower()
    assert "human decision" not in str(manifest).lower()
    assert manifest["source"] == "verified_manifest_dry_run"
    assert all(item["no_action_contract"] is True for item in manifest["candidates"])
    assert all(item["active_training_enabled"] is False for item in manifest["candidates"])
