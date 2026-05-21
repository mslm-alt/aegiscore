import json

import main as main_module
from core.phase_manager import PhaseManager


class _GateDb:
    def __init__(self, labels=None, stats=None, open_incidents=None):
        self._labels = list(labels or [])
        self._stats = dict(stats or {})
        self._open_incidents = list(open_incidents or [])

    def load_labels(self):
        return list(self._labels)

    def get_stat(self, key):
        return self._stats.get(key, "")

    def get_open_incidents(self):
        return list(self._open_incidents)


def _label(*, ts, bucket="normal", origin="bootstrap_historical", dedup_status="unique", duplicate_count=1, day_offset=0):
    evidence = {
        "rule_id": "AUTH-001",
        "log_source": "auth_log" if bucket == "normal" else "journald",
        "timestamp_confidence": "high",
        "timestamp_source": "event",
        "dedup_status": dedup_status,
        "duplicate_count": duplicate_count,
    }
    common = {
        "ts": float(ts + day_offset * 86400),
        "source": "bootstrap" if origin == "bootstrap_historical" else "auto_labeled",
        "distro": "debian",
        "distro_family": "debian",
        "category": "auth",
        "source_trust": "observed_benign_high" if bucket == "normal" else "rule_high",
        "learnable": True,
        "label_reason": "bootstrap_historical_scan" if origin == "bootstrap_historical" else "direct_rule_runtime",
        "bootstrap_job_id": "bootstrap_auth_1" if origin == "bootstrap_historical" else "",
        "label_batch_id": "historical_auth_bootstrap" if origin == "bootstrap_historical" else "",
        "evidence_fields": evidence,
        "timestamp_confidence": "high",
        "timestamp_source": "event",
        "no_action_contract": True,
        "poisoning_guard_passed": True,
    }
    if bucket == "normal":
        return {
            **common,
            "label": "normal",
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "attack_family": "",
            "model_usage_scope": "baseline_learning",
            "ml_family": "ML-AUTH",
            "ml_label": "expected_auth_activity",
            "label_family": "ML-AUTH",
            "source_type": "clean_window_normal",
        }
    return {
        **common,
        "label": "attack",
        "event_class": "attack",
        "behavior_label": "brute_force_or_auth_attack",
        "attack_family": "credential_access",
        "model_usage_scope": "calibration_only",
        "ml_family": "ML-AUTH",
        "ml_label": "brute_force_or_auth_attack",
        "label_family": "ML-AUTH",
        "source_type": "rule_mapped_attack",
    }


def _unmapped_label(ts):
    return {
        "ts": float(ts),
        "source": "bootstrap",
        "distro": "debian",
        "distro_family": "debian",
        "label": "attack",
        "category": "auth",
        "event_class": "unknown_unlabeled",
        "behavior_label": "unknown_unlabeled",
        "attack_family": "",
        "source_trust": "parse_invalid",
        "model_usage_scope": "not_learnable",
        "learnable": False,
        "label_reason": "bootstrap_rule_unmapped",
        "bootstrap_job_id": "bootstrap_auth_1",
        "label_batch_id": "historical_auth_bootstrap",
        "evidence_fields": {
            "rule_id": "REGEX-004",
            "log_source": "auth_log",
            "timestamp_confidence": "low",
            "timestamp_source": "scan_fallback",
            "dedup_status": "unique",
            "duplicate_count": 1,
        },
        "timestamp_confidence": "low",
        "timestamp_source": "scan_fallback",
        "ml_family": "UNMAPPED_NONLEARNABLE",
        "ml_label": "unknown_unlabeled",
        "label_family": "UNMAPPED_NONLEARNABLE",
        "source_type": "rule_mapped_attack",
        "no_action_contract": True,
        "poisoning_guard_passed": False,
    }


def test_phase_0_event_thresholds_do_not_transition_without_label_training_gate(tmp_path):
    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False)
    pm.set_external_phase_gate_resolver(lambda _status: {
        "phase_gate_source": "label_training",
        "label_training_gate_ok": False,
        "phase_gate_blockers": ["no_first_model_training", "insufficient_ready_families"],
        "ready_family_ids": [],
        "ready_family_count": 0,
        "first_model_training_completed": False,
        "first_model_evaluation_passed": False,
        "first_ml_model_ready": False,
        "no_action_contract": True,
    })
    pm.stats.total_events = 600
    pm.stats.start_time -= 3 * 3600
    pm.stats.source_counts = {"auth": 100, "process": 100}

    status = pm.get_status()

    assert pm._check_phase_transition() is None
    assert status["phase_gate"]["label_training_gate_ok"] is False
    assert "no_first_model_training" in status["phase_gate"]["phase_gate_blockers"]
    gate_item = next(item for item in status["next_phase"]["criteria"] if item["name"] == "Label/training gate")
    assert gate_item["done"] is False


def test_phase_0_can_transition_when_event_and_label_training_gate_both_pass(tmp_path):
    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False)
    pm.set_external_phase_gate_resolver(lambda _status: {
        "phase_gate_source": "label_training",
        "label_training_gate_ok": True,
        "phase_gate_blockers": [],
        "ready_family_ids": ["ML-AUTH"],
        "ready_family_count": 1,
        "first_model_training_completed": True,
        "first_model_evaluation_passed": True,
        "first_ml_model_ready": True,
        "no_action_contract": True,
    })
    pm.stats.total_events = 600
    pm.stats.start_time -= 3 * 3600
    pm.stats.source_counts = {"auth": 100, "process": 100}

    transitioned = pm._check_phase_transition()

    assert transitioned == 1


def test_label_training_phase_gate_blocks_without_explicit_first_training_state(monkeypatch):
    labels = []
    for day in range(5):
        labels.extend(_label(ts=1715000000 + day, bucket="normal", day_offset=day) for _ in range(6))
        labels.extend(_label(ts=1715001000 + day, bucket="suspicious", day_offset=day) for _ in range(3))
    labels.append(_unmapped_label(1715600000))
    db = _GateDb(labels=labels, stats={"ml_training_scheduler_state": json.dumps({})})
    monkeypatch.setattr(main_module, "_collect_global_ml_audit", lambda db, pm_status, config=None: {"ml_paused": False, "parse_fail_rate": 0.0})

    report = main_module.collect_label_training_phase_gate_report({}, db, {"current_phase": 0, "phase_name": "Kural"})

    assert report["ready_family_count"] == 1
    assert report["ready_family_ids"] == ["ML-AUTH"]
    assert report["label_training_gate_ok"] is False
    assert "no_first_model_training" in report["phase_gate_blockers"]
    assert "no_first_model_evaluation_pass" in report["phase_gate_blockers"]
    assert "no_first_ml_model_ready" in report["phase_gate_blockers"]
    assert report["training_state"]["active_ml_enabled"] is False


def test_label_training_phase_gate_passes_with_seed_family_and_explicit_training_state(monkeypatch):
    labels = []
    for day in range(5):
        labels.extend(_label(ts=1715000000 + day, bucket="normal", day_offset=day) for _ in range(6))
        labels.extend(_label(ts=1715001000 + day, bucket="suspicious", day_offset=day) for _ in range(3))
    labels.append(_unmapped_label(1715600000))
    scheduler_state = {
        "first_model_training_completed_at": "2026-05-20T02:00:00",
        "first_model_training_status": "promoted",
        "first_model_evaluation_status": "passed",
        "first_ml_model_ready": True,
        "ml_alert_family_ready": True,
        "ml_alert_family_enabled_families": ["ML-AUTH/debian"],
        "last_training_status": "promoted",
        "last_evaluation_status": "passed",
    }
    db = _GateDb(labels=labels, stats={"ml_training_scheduler_state": json.dumps(scheduler_state)})
    monkeypatch.setattr(main_module, "_collect_global_ml_audit", lambda db, pm_status, config=None: {"ml_paused": False, "parse_fail_rate": 0.0})

    report = main_module.collect_label_training_phase_gate_report({}, db, {"current_phase": 0, "phase_name": "Kural"})

    assert report["label_training_gate_ok"] is True
    assert report["ready_family_ids"] == ["ML-AUTH"]
    assert report["phase_gate_blockers"] == []
    assert report["first_model_training_completed"] is True
    assert report["first_model_evaluation_passed"] is True
    assert report["first_ml_model_ready"] is True
    assert report["ml_alert_family_ready"] is True
    assert report["training_state"]["active_ml_enabled"] is False
