import json
import threading
from pathlib import Path
from types import SimpleNamespace

import main as main_module


class _ReadOnlyDb:
    def __init__(self, incidents=None):
        self._incidents = list(incidents or [])

    def get_open_incidents(self):
        return list(self._incidents)

    def insert_event(self, **kwargs):
        raise AssertionError("runtime model scoring events_recent insert yapmamalı")

    def save_labels(self, records):
        raise AssertionError("runtime model scoring label write yapmamalı")


def _label_row(index: int, suspicious: bool) -> dict:
    ts = 1715400000.0 + index
    if suspicious:
        return {
            "ts": ts,
            "source": "auth_log",
            "distro": "debian",
            "distro_family": "debian",
            "label": "attack",
            "category": "auth",
            "action": "ssh_login",
            "outcome": "failure",
            "event_class": "attack",
            "behavior_label": "brute_force_or_auth_attack",
            "source_trust": "rule_high",
            "model_usage_scope": "calibration_only",
            "learnable": True,
            "label_reason": "direct_rule_runtime",
            "ml_family": "ML-AUTH",
            "ml_label": "brute_force_or_auth_attack",
            "label_family": "ML-AUTH",
            "source_type": "rule_mapped_attack",
            "user": "alice",
            "host": "host-1",
            "src_ip": "198.51.100.77",
            "message": "Failed password for alice",
            "fields": {"dst_port": 22},
            "evidence_fields": {"rule_id": "AUTH-004", "dst_port": 22},
            "no_action_contract": True,
        }
    return {
        "ts": ts,
        "source": "auth_log",
        "distro": "debian",
        "distro_family": "debian",
        "label": "normal",
        "category": "auth",
        "action": "ssh_login",
        "outcome": "success",
        "event_class": "benign",
        "behavior_label": "expected_auth_activity",
        "source_trust": "observed_benign_high",
        "model_usage_scope": "baseline_learning",
        "learnable": True,
        "label_reason": "bootstrap_historical_scan",
        "ml_family": "ML-AUTH",
        "ml_label": "expected_auth_activity",
        "label_family": "ML-AUTH",
        "source_type": "clean_window_normal",
        "user": "alice",
        "host": "host-1",
        "src_ip": "10.0.0.5",
        "message": "Accepted password for alice",
        "fields": {"dst_port": 22},
        "evidence_fields": {"rule_id": "AUTH-001", "dst_port": 22},
        "no_action_contract": True,
    }


def _promote_valid_model(tmp_path: Path) -> dict:
    config = {"storage": {"models_dir": str(tmp_path / "models")}}
    rows = [_label_row(index, suspicious=bool(index % 2)) for index in range(40)]
    payload = {"rows": rows, "summary": {"family_id": "ML-AUTH", "distro": "debian", "sample_count": len(rows), "class_counts": {"attack": 20, "benign": 20}, "source_counts": {"auth_log": 40}, "behavior_counts": {"expected_auth_activity": 20, "brute_force_or_auth_attack": 20}, "min_ts": rows[0]["ts"], "max_ts": rows[-1]["ts"]}}
    evaluation = main_module._evaluate_scheduler_training_candidate(payload, {"min_eval_samples_per_class": 3})
    assert evaluation["passed"] is True
    training_result = main_module._train_scheduler_model_artifact(config, "ML-AUTH", "debian", payload, evaluation)
    promotion = main_module._promote_scheduler_model_artifact(config, "ML-AUTH", "debian", training_result)
    assert promotion["promoted"] is True
    return config


def _pipeline(tmp_path: Path):
    pipeline = main_module.SIEMPipeline.__new__(main_module.SIEMPipeline)
    pipeline.config = {"storage": {"models_dir": str(tmp_path / "models")}}
    pipeline.db = _ReadOnlyDb()
    pipeline.ml_ctrl = SimpleNamespace(status=lambda: {"paused": False})
    pipeline._runtime_state = SimpleNamespace(runtime_components={})
    pipeline._ml_promoted_model_lock = threading.Lock()
    pipeline._ml_promoted_model_state = {
        "promoted_model_count": 0,
        "loaded_model_count": 0,
        "model_load_errors": [],
        "scoring_enabled_families": [],
        "last_scoring_status": {},
        "last_refresh_at": "",
        "no_action_contract": True,
    }
    pipeline._ml_promoted_model_runtime = {}
    return pipeline


def _readiness(**overrides):
    payload = {
        "family_id": "ML-AUTH",
        "can_score_support": True,
        "reason": "ready",
    }
    payload.update(overrides)
    return payload


def test_valid_promoted_artifact_loads_and_scores(tmp_path):
    config = _promote_valid_model(tmp_path)
    status = main_module.collect_ml_model_status(config)
    assert status["promoted_model_count"] == 1
    assert status["loaded_model_count"] == 1

    pipeline = _pipeline(tmp_path)
    event = {
        "ts": 1715409000.0,
        "source": "auth_log",
        "category": "auth",
        "action": "ssh_login",
        "outcome": "failure",
        "user": "alice",
        "src_ip": "198.51.100.99",
        "message": "Failed password",
        "distro_family": "debian",
        "fields": {"dst_port": 22},
    }
    result = pipeline._score_event_with_promoted_model("ML-AUTH", event, _readiness())
    assert result["scored"] is True
    assert result["reason"] == "model_score_ready"
    assert result["model_version"] == main_module._ML_PROMOTED_MODEL_VERSION
    assert result["no_action_contract"] is True


def test_invalid_metadata_artifact_is_not_loaded(tmp_path):
    config = _promote_valid_model(tmp_path)
    metadata_path = main_module._scheduler_artifact_paths(config, "ML-AUTH", "debian")["metadata"]
    payload = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
    payload["no_action_contract"] = False
    Path(metadata_path).write_text(json.dumps(payload), encoding="utf-8")

    status = main_module.collect_ml_model_status(config)
    assert status["loaded_model_count"] == 0
    assert status["model_load_errors"][0]["reason"] == "model_metadata_invalid"


def test_corrupt_artifact_does_not_crash_runtime(tmp_path):
    config = _promote_valid_model(tmp_path)
    artifact_path = main_module._scheduler_artifact_paths(config, "ML-AUTH", "debian")["artifact"]
    Path(artifact_path).write_text("not-a-joblib", encoding="utf-8")

    status = main_module.collect_ml_model_status(config)
    assert status["loaded_model_count"] == 0
    assert any(item["reason"] == "model_load_failed" for item in status["model_load_errors"])


def test_feature_schema_mismatch_returns_safe_fallback(tmp_path):
    config = _promote_valid_model(tmp_path)
    metadata_path = main_module._scheduler_artifact_paths(config, "ML-AUTH", "debian")["metadata"]
    payload = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
    payload["feature_schema_version"] = 999
    Path(metadata_path).write_text(json.dumps(payload), encoding="utf-8")

    pipeline = _pipeline(tmp_path)
    event = {"source": "auth_log", "category": "auth", "action": "ssh_login", "outcome": "failure", "distro_family": "debian", "fields": {}}
    result = pipeline._score_event_with_promoted_model("ML-AUTH", event, _readiness())
    assert result["scored"] is False
    assert result["reason"] == "feature_schema_mismatch"


def test_unknown_distro_is_not_scored(tmp_path):
    _promote_valid_model(tmp_path)
    pipeline = _pipeline(tmp_path)
    result = pipeline._score_event_with_promoted_model(
        "ML-AUTH",
        {"source": "auth_log", "category": "auth", "action": "ssh_login", "outcome": "failure", "distro_family": "unknown_distro", "fields": {}},
        _readiness(),
    )
    assert result["scored"] is False
    assert result["reason"] == "unknown_distro"


def test_ml_paused_and_readiness_blocked_prevent_scoring(tmp_path):
    _promote_valid_model(tmp_path)
    pipeline = _pipeline(tmp_path)
    pipeline.ml_ctrl = SimpleNamespace(status=lambda: {"paused": True})
    event = {"source": "auth_log", "category": "auth", "action": "ssh_login", "outcome": "failure", "distro_family": "debian", "fields": {}}
    paused = pipeline._score_event_with_promoted_model("ML-AUTH", event, _readiness())
    blocked = pipeline._score_event_with_promoted_model("ML-AUTH", event, _readiness(can_score_support=False, reason="readiness_blocked"))
    assert paused["reason"] == "ml_paused"
    assert blocked["reason"] == "readiness_blocked"


def test_no_promoted_model_returns_safe_reason(tmp_path):
    pipeline = _pipeline(tmp_path)
    result = pipeline._score_event_with_promoted_model(
        "ML-AUTH",
        {"source": "auth_log", "category": "auth", "action": "ssh_login", "outcome": "failure", "distro_family": "debian", "fields": {}},
        _readiness(),
    )
    assert result["scored"] is False
    assert result["reason"] == "no_promoted_model"


def test_runtime_scoring_path_is_read_only_and_updates_last_status(tmp_path):
    _promote_valid_model(tmp_path)
    pipeline = _pipeline(tmp_path)
    event = SimpleNamespace(
        to_dict=lambda: {
            "ts": 1715409000.0,
            "source": "auth_log",
            "category": "auth",
            "action": "ssh_login",
            "outcome": "failure",
            "user": "alice",
            "src_ip": "198.51.100.99",
            "message": "Failed password",
            "distro_family": "debian",
            "fields": {"dst_port": 22},
        }
    )
    pipeline._evaluate_runtime_ml_family_readiness = lambda family_id: _readiness()
    pipeline._runtime_ml_family_candidates = lambda event, detections: ["ML-AUTH"]

    results = pipeline._score_runtime_promoted_ml_families(event, [])

    assert len(results) == 1
    assert results[0]["no_action_contract"] is True
    assert pipeline._ml_promoted_model_state["last_scoring_status"]["results"][0]["family_id"] == "ML-AUTH"
