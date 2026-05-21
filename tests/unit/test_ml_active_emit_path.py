from types import SimpleNamespace

import pytest

from core.ml.family_registry import classify_label_quota_type, resolve_family_label_quotas
from core.ml.label_engine import LabelEngine, LabelRecord
import main as main_module


def _active_layer(**overrides):
    payload = {
        "enabled": True,
        "mode": "active",
        "no_action_contract": True,
        "min_score": 60.0,
        "min_confidence": 0.60,
    }
    payload.update(overrides)
    return payload


def _base_contract(family_id="ML-PROC", **overrides):
    payload = dict(main_module._ML_FAMILY_READINESS[family_id])
    payload.update({
        "no_action_contract": True,
        "active_emit_min_score": 60.0,
        "active_emit_min_confidence": 0.60,
    })
    payload.update(overrides)
    return payload


def _event_for_family(family_id="ML-PROC"):
    event = main_module._sample_support_event_for_family(family_id)
    event["ts"] = 1715400000.0
    return event


def _readiness(family_id="ML-PROC", **overrides):
    payload = {
        "family_id": family_id,
        "status": "active",
        "reason": "ready",
        "blockers": [],
        "phase_gate_ok": True,
        "event_threshold_ok": True,
        "normal_label_threshold_ok": True,
        "suspicious_label_threshold_ok": True,
        "field_quality_ok": True,
        "time_coverage_ok": True,
        "trust_support_ok": True,
        "metadata_support_ok": True,
        "can_score_support": True,
        "can_emit_alert": True,
        "no_action_contract": True,
    }
    payload.update(overrides)
    return payload


def _support_score(family_id="ML-PROC", **overrides):
    payload = {
        "family_id": family_id,
        "scored": True,
        "score": 82.0,
        "normalized_score": 0.82,
        "confidence": 0.91,
        "reason": "support_score_ready",
        "top_features": ["field_completeness=1.00", "family_match=category:1,action:1,source:1"],
        "time_context": {
            "event_ts": 1715400000.0,
            "hour_of_day": 10,
            "day_of_week": 5,
            "is_weekend": True,
            "is_night": False,
            "timezone_name": "UTC",
            "timezone_offset": "+0000",
        },
        "baseline_deviation": {
            "expected_sources": ["auditd"],
            "expected_actions": ["exec"],
            "expected_categories": ["process"],
            "observed_source": "auditd",
            "observed_action": "exec",
            "observed_category": "process",
            "score_component": 3.0,
            "available": True,
        },
        "can_emit_alert": False,
        "no_action_contract": True,
        "db_write_attempted": False,
        "risk_score_changed": False,
        "runtime_output_changed": False,
    }
    payload.update(overrides)
    return payload


def _event_obj(payload):
    class _Event:
        def __init__(self, data):
            self.ts = data.get("ts", 0.0)
            self.host = data.get("host", "")
            self.source = data.get("source", "")
            self.distro_family = data.get("distro_family", data.get("distro", ""))
            self.distro = data.get("distro", data.get("distro_family", ""))
            self.category = data.get("category", "")
            self.action = data.get("action", "")
            self.outcome = data.get("outcome", "")
            self.user = data.get("user", data.get("username", ""))
            self.src_ip = data.get("src_ip", "")
            self.dst_ip = data.get("dst_ip", "")
            self.process = data.get("process", "")
            self.message = data.get("message", "")
            self.fields = data.get("fields", {})

        def to_dict(self):
            return dict(payload)

    return _Event(payload)


class _QuotaDb:
    def __init__(self):
        self.saved = []

    def save_labels(self, records):
        self.saved.extend(records)
        return len(records)

    def load_labels(self, **kwargs):
        return []


def test_label_quota_defaults_and_type_mapping():
    quotas = resolve_family_label_quotas()

    assert quotas["ML-AUTH"]["normal"] == 3000
    assert quotas["ML-AUTH"]["suspicious"] == 1000
    assert classify_label_quota_type({"model_usage_scope": "baseline_learning", "event_class": "benign", "learnable": True}) == "normal"
    assert classify_label_quota_type({"model_usage_scope": "calibration_only", "event_class": "suspicious", "learnable": True}) == "suspicious"
    assert classify_label_quota_type({"model_usage_scope": "direct_learnable", "event_class": "attack", "learnable": True}) == "suspicious"


def test_live_auto_label_write_respects_family_distro_quota_for_normal(monkeypatch):
    db = _QuotaDb()
    engine = LabelEngine(distro_family="debian", db=db)
    engine._label_quota_contract = {"ML-AUTH": {"normal": 1, "suspicious": 1, "mode": "stop_write"}}
    record = LabelRecord(
        score=0.0,
        label="normal",
        category="auth_normal",
        source="auto_labeled",
        confidence=0.8,
        ts=1715400000.0,
        weight=0.8,
        entity_key="alice",
        ready_after=0.0,
        event_class="benign",
        behavior_label="expected_auth_activity",
        source_trust="observed_benign_high",
        learnable=True,
        model_usage_scope="baseline_learning",
        evidence_fields={"ml_family": "ML-AUTH", "label_family": "ML-AUTH"},
    )
    monkeypatch.setattr(engine._auto_labeler, "process_normal", lambda event, delayed_learning_ok=False: record)

    engine.on_normal_event(SimpleNamespace(), delayed_learning_ok=True)
    engine.on_normal_event(SimpleNamespace(), delayed_learning_ok=True)

    assert len(db.saved) == 1
    assert db.saved[0].distro == "debian"
    assert db.saved[0].evidence_fields["distro_family"] == "debian"


def test_live_auto_label_write_respects_family_distro_quota_for_suspicious(monkeypatch):
    db = _QuotaDb()
    engine = LabelEngine(distro_family="debian", db=db)
    engine._label_quota_contract = {"ML-AUTH": {"normal": 1, "suspicious": 1, "mode": "stop_write"}}
    record = LabelRecord(
        score=80.0,
        label="attack",
        category="brute_force",
        source="auto_labeled",
        confidence=0.95,
        ts=1715400000.0,
        weight=0.95,
        entity_key="alice",
        ready_after=0.0,
        event_class="suspicious",
        behavior_label="auth_attack_or_abuse",
        source_trust="rule_high",
        learnable=True,
        model_usage_scope="calibration_only",
        evidence_fields={"ml_family": "ML-AUTH", "label_family": "ML-AUTH"},
    )
    monkeypatch.setattr(engine._auto_labeler, "process_alert", lambda alert, event=None: record)

    engine.on_alert({"entity": "alice", "ts": 1715400000.0}, event=None)
    engine.on_alert({"entity": "bob", "ts": 1715400001.0}, event=None)

    assert len(db.saved) == 1
    assert engine._quota_blocked_counts[("ML-AUTH", "debian", "suspicious")] == 1


def test_live_auto_label_process_normal_skips_unknown_action():
    engine = LabelEngine(distro_family="debian", db=None)
    event = _event_obj(
        {
            "ts": 1715400000.0,
            "host": "server01",
            "source": "auth",
            "distro_family": "debian",
            "category": "auth",
            "action": "unknown",
            "outcome": "success",
            "user": "alice",
            "process": "sshd",
        }
    )

    assert engine._auto_labeler.process_normal(event, delayed_learning_ok=True) is None


def test_live_auto_label_process_normal_writes_known_benign_with_critical_fields():
    engine = LabelEngine(distro_family="debian", db=None)
    event = _event_obj(
        {
            "ts": 1715400000.0,
            "host": "server01",
            "source": "auth",
            "distro_family": "debian",
            "category": "auth",
            "action": "ssh_login",
            "outcome": "success",
            "user": "alice",
            "process": "sshd",
        }
    )

    record = engine._auto_labeler.process_normal(event, delayed_learning_ok=True)

    assert record is not None
    assert record.evidence_fields["labelability_status"] == "labelable"
    assert record.evidence_fields["labelability_reason"] == "known_benign_normal"
    assert record.ml_family == "ML-AUTH"
    assert record.label_family == "ML-AUTH"
    assert record.no_action_contract is True
    assert record.origin == "organic_live"
    assert record.evidence_fields["ml_family"] == "ML-AUTH"
    assert record.evidence_fields["label_family"] == "ML-AUTH"
    assert record.evidence_fields["no_action_contract"] is True
    assert record.evidence_fields["origin"] == "organic_live"


def test_live_auto_label_process_alert_writes_rule_hit_with_critical_fields():
    engine = LabelEngine(distro_family="debian", db=None)
    event = _event_obj(
        {
            "ts": 1715400000.0,
            "host": "server01",
            "source": "auth",
            "distro_family": "debian",
            "category": "auth",
            "action": "ssh_login",
            "outcome": "failure",
            "user": "alice",
            "process": "sshd",
        }
    )

    record = engine._auto_labeler.process_alert(
        {"rule_id": "AUTH-002", "category": "auth", "score": 80.0, "entity": "alice"},
        event=event,
    )

    assert record is not None
    assert record.evidence_fields["labelability_status"] == "labelable"
    assert record.evidence_fields["labelability_reason"] == "rule_hit"
    assert record.ml_family == "ML-AUTH"
    assert record.label_family == "ML-AUTH"
    assert record.no_action_contract is True
    assert record.origin == "organic_live"
    assert record.evidence_fields["ml_family"] == "ML-AUTH"
    assert record.evidence_fields["label_family"] == "ML-AUTH"
    assert record.evidence_fields["no_action_contract"] is True
    assert record.evidence_fields["origin"] == "organic_live"


def test_live_auto_label_process_alert_accepts_risk_score_only_payload():
    engine = LabelEngine(distro_family="debian", db=None)
    event = _event_obj(
        {
            "ts": 1715400000.0,
            "host": "server01",
            "source": "auth",
            "distro_family": "debian",
            "category": "auth",
            "action": "ssh_login",
            "outcome": "failure",
            "user": "alice",
            "process": "sshd",
        }
    )

    record = engine._auto_labeler.process_alert(
        {"rule_id": "AUTH-002", "category": "auth", "risk_score": 82.0, "entity": "alice"},
        event=event,
    )

    assert record is not None
    assert record.score == 82.0
    assert record.ts == 1715400000.0
    assert record.evidence_fields["timestamp_source"] == "event"
    assert record.evidence_fields["timestamp_confidence"] == "high"
    assert record.event_class == "attack"
    assert record.behavior_label == "ssh_auth_failure"
    assert record.ml_family == "ML-AUTH"
    assert record.label_family == "ML-AUTH"
    assert record.no_action_contract is True
    assert record.origin == "organic_live"
    assert record.evidence_fields["ml_family"] == "ML-AUTH"
    assert record.evidence_fields["label_family"] == "ML-AUTH"
    assert record.evidence_fields["no_action_contract"] is True
    assert record.evidence_fields["origin"] == "organic_live"


def test_label_engine_on_alert_persists_when_payload_has_risk_score_only():
    db = _QuotaDb()
    engine = LabelEngine(distro_family="debian", db=db)
    event = _event_obj(
        {
            "ts": 1715400000.0,
            "host": "server01",
            "source": "auth",
            "distro_family": "debian",
            "category": "auth",
            "action": "ssh_login",
            "outcome": "failure",
            "user": "alice",
            "process": "sshd",
        }
    )

    engine.on_alert(
        {"entity": "alice", "ts": 1715400000.0, "rule_id": "AUTH-002", "category": "auth", "risk_score": 82.0},
        event=event,
    )

    assert len(db.saved) == 1
    saved = db.saved[0]
    assert saved.score == 82.0
    assert saved.ts == 1715400000.0
    assert saved.event_class == "attack"
    assert saved.behavior_label == "ssh_auth_failure"
    assert saved.ml_family == "ML-AUTH"
    assert saved.label_family == "ML-AUTH"
    assert saved.no_action_contract is True
    assert saved.origin == "organic_live"
    assert saved.evidence_fields["ml_family"] == "ML-AUTH"
    assert saved.evidence_fields["label_family"] == "ML-AUTH"
    assert saved.evidence_fields["no_action_contract"] is True
    assert saved.evidence_fields["origin"] == "organic_live"
    assert saved.evidence_fields["timestamp_source"] == "event"
    assert saved.evidence_fields["timestamp_confidence"] == "high"


def test_family_readiness_active_mode_can_emit_when_all_gates_pass():
    result = main_module.evaluate_ml_family_readiness(
        family_id="ML-PROC",
        current_phase=1,
        ml_paused=False,
        family_contract={
            "phase_gate": 1,
            "required_events": 10,
            "required_normal_labels": 5,
            "required_suspicious_labels": 2,
            "field_requirements": {"process_fill_rate": 0.30},
            "required_time_coverage_days": 2,
            "no_action_contract": True,
        },
        runtime_event_count=10,
        normal_label_count=5,
        suspicious_label_count=2,
        field_quality_metrics={
            "process_fill_rate": 1.0,
            "host_fill_rate": 1.0,
            "user_fill_rate": 1.0,
            "src_ip_fill_rate": 1.0,
            "dst_ip_fill_rate": 1.0,
            "dst_port_fill_rate": 1.0,
            "source_count": 2,
        },
        time_coverage_days=2,
        trust_support={"normal": 5, "suspicious": 2},
        metadata_support=7,
        active_decision_layer=_active_layer(),
        linked_process_events=0,
        duplicate_rate=0.0,
        parse_fail_rate=0.0,
        process_tree_count=1,
        errors=[],
    )
    assert result["status"] == "active"
    assert result["can_emit_alert"] is True


def test_active_ml_candidate_disabled_config_blocks():
    candidate = main_module.build_active_ml_alert_candidate(
        event=_event_for_family(),
        family_id="ML-PROC",
        readiness_result=_readiness(),
        support_score_result=_support_score(),
        active_decision_layer=_active_layer(enabled=False, mode="audit_only"),
        family_config=_base_contract(),
        related_rule_context={},
    )
    assert candidate["emit_allowed"] is False
    assert candidate["emit_blocked_reason"] == "active_decision_layer_disabled"


def test_active_ml_candidate_audit_only_mode_blocks():
    candidate = main_module.build_active_ml_alert_candidate(
        event=_event_for_family(),
        family_id="ML-PROC",
        readiness_result=_readiness(can_emit_alert=False, status="active_candidate"),
        support_score_result=_support_score(),
        active_decision_layer=_active_layer(mode="audit_only"),
        family_config=_base_contract(),
        related_rule_context={},
    )
    assert candidate["emit_allowed"] is False
    assert candidate["emit_blocked_reason"] == "audit_only_mode"


def test_active_ml_candidate_paused_blocks():
    candidate = main_module.build_active_ml_alert_candidate(
        event=_event_for_family("ML-AUTH"),
        family_id="ML-AUTH",
        readiness_result=_readiness("ML-AUTH", status="paused", reason="ml_paused", can_emit_alert=False),
        support_score_result=_support_score("ML-AUTH"),
        active_decision_layer=_active_layer(),
        family_config=_base_contract("ML-AUTH"),
        related_rule_context={},
    )
    assert candidate["emit_allowed"] is False
    assert candidate["emit_blocked_reason"] == "ml_paused"


def test_active_ml_candidate_readiness_blocked_blocks():
    candidate = main_module.build_active_ml_alert_candidate(
        event=_event_for_family("ML-SUDO"),
        family_id="ML-SUDO",
        readiness_result=_readiness("ML-SUDO", status="readiness_blocked", reason="insufficient_labels", can_emit_alert=False),
        support_score_result=_support_score("ML-SUDO"),
        active_decision_layer=_active_layer(),
        family_config=_base_contract("ML-SUDO"),
        related_rule_context={},
    )
    assert candidate["emit_allowed"] is False
    assert candidate["emit_blocked_reason"] == "readiness_blocked"


def test_active_ml_candidate_needs_more_data_blocks():
    candidate = main_module.build_active_ml_alert_candidate(
        event=_event_for_family("ML-NET"),
        family_id="ML-NET",
        readiness_result=_readiness("ML-NET", status="needs_more_data", reason="insufficient_time_coverage", can_emit_alert=False),
        support_score_result=_support_score("ML-NET"),
        active_decision_layer=_active_layer(),
        family_config=_base_contract("ML-NET"),
        related_rule_context={},
    )
    assert candidate["emit_allowed"] is False
    assert candidate["emit_blocked_reason"] == "needs_more_data"


def test_active_ml_candidate_valid_contains_explanation_and_no_action_contract():
    candidate = main_module.build_active_ml_alert_candidate(
        event=_event_for_family("ML-PROC"),
        family_id="ML-PROC",
        readiness_result=_readiness("ML-PROC"),
        support_score_result=_support_score("ML-PROC"),
        active_decision_layer=_active_layer(),
        family_config=_base_contract("ML-PROC"),
        related_rule_context={"rule_detections": [{"rule_id": "AUTH-004"}]},
    )
    assert candidate["valid"] is True
    assert candidate["emit_allowed"] is True
    assert candidate["rule_id"] == "ML-PROC-001"
    assert candidate["no_action_contract"] is True
    assert candidate["action_taken"] is False
    assert candidate["can_emit_alert"] is True
    assert candidate["firewall_called"] is False
    assert candidate["ip_block_called"] is False
    assert candidate["quarantine_called"] is False
    assert candidate["delete_called"] is False
    assert candidate["message"]
    assert candidate["explanation_metadata"]["why_triggered_human"]
    assert candidate["explanation_metadata"]["time_context"]
    assert candidate["explanation_metadata"]["top_features"]
    assert candidate["correlation_metadata"]["rule_suppressed"] is False
    assert candidate["correlation_metadata"]["rule_risk_changed"] is False


def test_active_ml_emit_helper_calls_callback_only_in_explicit_emit_path():
    emitted = []
    result = main_module.emit_active_ml_alert_if_allowed(
        event=_event_for_family("ML-PROC"),
        family_id="ML-PROC",
        readiness_result=_readiness("ML-PROC"),
        support_score_result=_support_score("ML-PROC"),
        active_decision_layer=_active_layer(),
        family_config=_base_contract("ML-PROC"),
        related_rule_context={},
        emit_callback=lambda candidate: emitted.append(candidate["rule_id"]),
        dry_run=False,
    )
    assert emitted == ["ML-PROC-001"]
    assert result["emitted"] is True
    assert result["db_write_attempted"] is True


def test_active_ml_emit_helper_default_live_disabled_path_does_not_call_callback():
    emitted = []
    result = main_module.emit_active_ml_alert_if_allowed(
        event=_event_for_family("ML-PROC"),
        family_id="ML-PROC",
        readiness_result=_readiness("ML-PROC", can_emit_alert=False, status="active_candidate"),
        support_score_result=_support_score("ML-PROC"),
        active_decision_layer=_active_layer(enabled=False, mode="audit_only"),
        family_config=_base_contract("ML-PROC"),
        related_rule_context={},
        emit_callback=lambda candidate: emitted.append(candidate["rule_id"]),
        dry_run=False,
    )
    assert emitted == []
    assert result["emitted"] is False
    assert result["db_write_attempted"] is False


def test_active_ml_candidate_all_registry_families_have_deterministic_rule_ids_and_messages():
    for family_spec in main_module.list_ml_families():
        family_id = family_spec.family_id
        candidate = main_module.build_active_ml_alert_candidate(
            event=_event_for_family(family_id),
            family_id=family_id,
            readiness_result=_readiness(family_id),
            support_score_result=_support_score(family_id),
            active_decision_layer=_active_layer(),
            family_config=_base_contract(family_id),
            related_rule_context={},
        )
        assert candidate["rule_id"] == f"{family_id}-001"
        assert candidate["message"]


def test_active_ml_candidate_ml_net_pass_scenario():
    candidate = main_module.build_active_ml_alert_candidate(
        event=_event_for_family("ML-NET"),
        family_id="ML-NET",
        readiness_result=_readiness("ML-NET"),
        support_score_result=_support_score("ML-NET"),
        active_decision_layer=_active_layer(),
        family_config=_base_contract("ML-NET"),
        related_rule_context={},
    )
    assert candidate["emit_allowed"] is True
    assert candidate["rule_id"] == "ML-NET-001"
    assert candidate["category"] == "ml_network"


def test_active_ml_candidate_ml_auth_blocked_scenario():
    candidate = main_module.build_active_ml_alert_candidate(
        event=_event_for_family("ML-AUTH"),
        family_id="ML-AUTH",
        readiness_result=_readiness("ML-AUTH", status="readiness_blocked", can_emit_alert=False),
        support_score_result=_support_score("ML-AUTH"),
        active_decision_layer=_active_layer(),
        family_config=_base_contract("ML-AUTH"),
        related_rule_context={},
    )
    assert candidate["emit_allowed"] is False


def test_active_ml_candidate_ml_sudo_blocked_scenario():
    candidate = main_module.build_active_ml_alert_candidate(
        event=_event_for_family("ML-SUDO"),
        family_id="ML-SUDO",
        readiness_result=_readiness("ML-SUDO"),
        support_score_result=_support_score("ML-SUDO", confidence=0.20),
        active_decision_layer=_active_layer(),
        family_config=_base_contract("ML-SUDO"),
        related_rule_context={},
    )
    assert candidate["emit_allowed"] is False
    assert candidate["emit_blocked_reason"] == "confidence_below_threshold"


def test_active_ml_candidate_invalid_family_safe_fail():
    candidate = main_module.build_active_ml_alert_candidate(
        event=_event_for_family("ML-PROC"),
        family_id="ML-UNKNOWN",
        readiness_result=_readiness("ML-UNKNOWN"),
        support_score_result=_support_score("ML-UNKNOWN"),
        active_decision_layer=_active_layer(),
        family_config={"no_action_contract": True},
        related_rule_context={},
    )
    assert candidate["emit_allowed"] is False
    assert candidate["emit_blocked_reason"] == "invalid_family"


def test_runtime_active_ml_emit_integration_is_noop_when_disabled():
    pipeline = object.__new__(main_module.SIEMPipeline)
    pipeline.config = {"ml": {"active_decision_layer": {"enabled": False, "mode": "audit_only"}}}
    result = pipeline._maybe_emit_active_ml_family_alerts(_event_obj(_event_for_family("ML-PROC")), [])
    assert result == []


def test_runtime_active_ml_emit_integration_emits_with_mock_callback(monkeypatch):
    pipeline = object.__new__(main_module.SIEMPipeline)
    pipeline.config = {"ml": {"active_decision_layer": _active_layer()}}
    pipeline.ml_ctrl = SimpleNamespace(status=lambda: {"paused": False, "reason": ""})
    emitted = []

    monkeypatch.setattr(pipeline, "_runtime_ml_family_candidates", lambda event, detections: ["ML-PROC"])
    monkeypatch.setattr(pipeline, "_build_runtime_ml_rule_context", lambda event, detections: {})
    monkeypatch.setattr(pipeline, "_evaluate_runtime_ml_family_readiness", lambda family_id: _readiness(family_id))
    monkeypatch.setattr(main_module, "compute_ml_family_support_score", lambda **kwargs: _support_score(kwargs["family_id"]))
    monkeypatch.setattr(pipeline, "_emit_active_ml_candidate", lambda event, candidate: emitted.append(candidate["rule_id"]))

    results = pipeline._maybe_emit_active_ml_family_alerts(_event_obj(_event_for_family("ML-PROC")), [])
    assert emitted == ["ML-PROC-001"]
    assert results[0]["emitted"] is True


def test_ml_active_emit_dry_run_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_active_emit_dry_run", lambda config, family_id: print(f"ML Active Emit Dry Run\n{family_id}") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-active-emit-dry-run", "ML-PROC"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "ML Active Emit Dry Run" in out
    assert "ML-PROC" in out
