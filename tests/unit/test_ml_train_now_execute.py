import json
from pathlib import Path

import main as main_module


class _ExecuteDb:
    def __init__(self, labels=None, stats=None, open_incidents=None):
        self._labels = list(labels or [])
        self._stats = dict(stats or {})
        self._open_incidents = list(open_incidents or [])

    def load_labels(self):
        return list(self._labels)

    def get_stat(self, key):
        return self._stats.get(key, "")

    def set_stat(self, key, value):
        self._stats[key] = value

    def get_open_incidents(self):
        return list(self._open_incidents)

    def close(self):
        return None


def _label_row(*, ts, bucket, distro="debian", origin="bootstrap_historical", learnable=True, usage=None, marker="valid"):
    if bucket == "normal":
        behavior = "expected_auth_activity"
        event_class = "benign"
        usage = usage or "baseline_learning"
        source_trust = "observed_benign_high"
        source_type = "clean_window_normal"
        attack_family = ""
        label = "normal"
    else:
        behavior = "brute_force_or_auth_attack"
        event_class = "attack"
        usage = usage or "calibration_only"
        source_trust = "rule_high"
        source_type = "rule_mapped_attack"
        attack_family = "credential_access"
        label = "attack"
    source = "bootstrap" if origin == "bootstrap_historical" else "auto_labeled"
    return {
        "ts": float(ts + ((int(ts) % 5) * 86400)),
        "source": source,
        "distro": distro,
        "distro_family": distro,
        "label": label,
        "category": "auth",
        "event_class": event_class,
        "behavior_label": behavior,
        "attack_family": attack_family,
        "source_trust": source_trust,
        "model_usage_scope": usage,
        "learnable": learnable,
        "label_reason": "bootstrap_historical_scan" if origin == "bootstrap_historical" else "direct_rule_runtime",
        "bootstrap_job_id": "bootstrap_auth_1" if origin == "bootstrap_historical" else "",
        "label_batch_id": "historical_auth_bootstrap" if origin == "bootstrap_historical" else "",
        "evidence_fields": {
            "rule_id": "AUTH-001",
            "log_source": "auth_log" if bucket == "normal" else "journald",
            "timestamp_confidence": "high",
            "timestamp_source": "event",
            "dedup_status": "unique",
            "duplicate_count": 1,
        },
        "timestamp_confidence": "high",
        "timestamp_source": "event",
        "poisoning_guard_passed": True,
        "ml_family": "ML-AUTH",
        "ml_label": behavior,
        "label_family": "ML-AUTH",
        "source_type": source_type,
        "no_action_contract": True,
        "marker": marker,
    }


def _readiness_report():
    return {
        "global": {
            "current_phase": 2,
            "phase_name": "Baseline",
            "ml_paused": False,
            "counts": {"process_tree": 0},
            "duplicate_rate": 0.0,
            "parse_fail_rate": 0.0,
        },
        "families": {
            "ML-AUTH": {
                "status": "active_candidate",
                "reason": "ready",
                "host_fill_rate": 0.95,
                "user_fill_rate": 0.95,
                "src_ip_fill_rate": 0.95,
                "dst_ip_fill_rate": 0.0,
                "dst_port_fill_rate": 0.0,
                "process_fill_rate": 0.0,
                "source_count": 3,
                "time_coverage_days": 14,
                "linked_process_events": 0,
                "errors": [],
                "distro_cohorts": {
                    "debian": {
                        "distro": "debian",
                        "status": "active_candidate",
                        "reason": "ready",
                        "runtime_events": 6000,
                        "source_count": 3,
                        "quota_normal": {"used": 120, "limit": 3000, "remaining": 2880, "status": "collecting"},
                        "quota_suspicious": {"used": 80, "limit": 1000, "remaining": 920, "status": "collecting"},
                    }
                },
            }
        },
    }


def _successful_training_result(config, family_id, distro, training_payload, evaluation_result):
    paths = main_module._scheduler_artifact_paths(config, family_id, distro)
    metadata = {
        "ml_family": family_id,
        "distro_family": distro,
        "trained_at": "2026-05-14T12:00:00",
        "label_counts": dict(training_payload.get("summary", {}).get("class_counts", {}) or {}),
        "feature_schema_version": main_module._ML_PROMOTED_MODEL_FEATURE_SCHEMA_VERSION,
        "model_version": main_module._ML_PROMOTED_MODEL_VERSION,
        "evaluation_status": "pass",
        "evaluation_reason": "evaluation_passed",
        "artifact_path": str(paths["artifact"]),
        "evaluation_metrics": dict(evaluation_result.get("metrics", {}) or {}),
        "no_action_contract": True,
        "active_ml_enabled": False,
    }
    return {
        "artifact_paths": paths,
        "artifact_payload": {
            "classifier": {"kind": "stub"},
            "scaler": {"kind": "stub"},
            "feature_schema_version": main_module._ML_PROMOTED_MODEL_FEATURE_SCHEMA_VERSION,
            "model_version": main_module._ML_PROMOTED_MODEL_VERSION,
            "no_action_contract": True,
        },
        "metadata_payload": metadata,
    }


def test_manual_train_now_clean_db_does_not_start(monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    report = main_module.execute_manual_training(
        {"storage": {"models_dir": str(tmp_path / "models")}},
        _ExecuteDb(),
        {"current_phase": 2},
        now_ts=1715504400.0,
    )

    assert report["trigger_request"] == "manual_execute"
    assert report["training_started"] is False
    assert report["promoted_models"] == []
    assert report["reason"] in {"readiness_blocked", "insufficient_labels", "insufficient_normal_labels", "insufficient_suspicious_labels", "manual_mode_waiting_for_user"}


def test_manual_train_now_uses_same_eligibility_as_dry_run(monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    labels = [
        *[_label_row(ts=1715000000 + idx, bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, bucket="suspicious") for idx in range(70)],
    ]
    config = {"storage": {"models_dir": str(tmp_path / "models")}}
    db = _ExecuteDb(labels=labels)

    dry_run = main_module.collect_ml_training_scheduler_report(
        config,
        db,
        {"current_phase": 2},
        now_ts=1715504400.0,
        trigger_request="manual_dry_run",
    )
    real_run = main_module.execute_manual_training(config, db, {"current_phase": 2}, now_ts=1715504400.0)

    assert dry_run["eligible_families"] == real_run["eligible_families"]
    assert dry_run["blocked_families"] == real_run["blocked_families"]


def test_manual_train_now_promotes_model_on_evaluation_pass(monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    monkeypatch.setattr(
        main_module,
        "_evaluate_scheduler_training_candidate",
        lambda training_payload, schedule_cfg: {
            "passed": True,
            "reason": "evaluation_passed",
            "metrics": {"train_count": 80, "eval_count": 20, "normal_eval": 10, "suspicious_eval": 10},
        },
    )
    monkeypatch.setattr(main_module, "_train_scheduler_model_artifact", _successful_training_result)
    labels = [
        *[_label_row(ts=1715000000 + idx, bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, bucket="suspicious") for idx in range(70)],
    ]
    refresh_calls = []
    report = main_module.execute_manual_training(
        {"storage": {"models_dir": str(tmp_path / "models")}},
        _ExecuteDb(labels=labels),
        {"current_phase": 2},
        now_ts=1715504400.0,
        refresh_runtime_registry=lambda **kwargs: refresh_calls.append(kwargs) or {"refreshed": True},
    )

    assert report["training_started"] is True
    assert report["evaluation_required"] is True
    assert len(report["promoted_models"]) == 1
    metadata = report["promoted_models"][0]["metadata"]
    assert metadata["evaluation_status"] == "pass"
    assert metadata["no_action_contract"] is True
    assert Path(metadata["artifact_path"]).exists()
    assert report["first_model_training_completed"] is True
    assert report["first_model_evaluation_passed"] is True
    assert report["first_ml_model_ready"] is True
    assert refresh_calls == [{"load_artifacts": False}]


def test_manual_train_now_keeps_existing_model_on_evaluation_fail(monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    monkeypatch.setattr(
        main_module,
        "_evaluate_scheduler_training_candidate",
        lambda training_payload, schedule_cfg: {"passed": False, "reason": "insufficient_eval_support", "metrics": {}},
    )
    labels = [
        *[_label_row(ts=1715000000 + idx, bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, bucket="suspicious") for idx in range(70)],
    ]
    paths = main_module._scheduler_artifact_paths({"storage": {"models_dir": str(tmp_path / "models")}}, "ML-AUTH", "debian")
    paths["root"].mkdir(parents=True, exist_ok=True)
    paths["metadata"].write_text(json.dumps({"existing": True}), encoding="utf-8")

    report = main_module.execute_manual_training(
        {"storage": {"models_dir": str(tmp_path / "models")}},
        _ExecuteDb(labels=labels),
        {"current_phase": 2},
        now_ts=1715504400.0,
    )

    assert report["promoted_models"] == []
    assert report["kept_existing_models"][0]["reason"] == "insufficient_eval_support"
    assert report["first_model_training_completed"] is True
    assert report["first_ml_model_ready"] is False
    assert json.loads(paths["metadata"].read_text(encoding="utf-8")) == {"existing": True}


def test_manual_train_now_filters_unknown_distro_ignored_and_invalid_metadata(monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    monkeypatch.setattr(
        main_module,
        "_evaluate_scheduler_training_candidate",
        lambda training_payload, schedule_cfg: {
            "passed": True,
            "reason": "evaluation_passed",
            "metrics": {"train_count": 8, "eval_count": 4, "normal_eval": 2, "suspicious_eval": 2},
        },
    )
    monkeypatch.setattr(main_module, "_train_scheduler_model_artifact", _successful_training_result)
    original_validate = main_module.validate_ml_label_metadata
    monkeypatch.setattr(
        main_module,
        "validate_ml_label_metadata",
        lambda row: {"valid": False} if row.get("marker") == "invalid_metadata" else original_validate(row),
    )
    labels = [
        *[_label_row(ts=1715000000 + idx, bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, bucket="suspicious") for idx in range(70)],
        _label_row(ts=1715002001, bucket="normal", distro="unknown_distro"),
        _label_row(ts=1715002002, bucket="suspicious", learnable=False),
        _label_row(ts=1715002003, bucket="suspicious", usage="ignored", marker="ignored"),
        _label_row(ts=1715002004, bucket="normal", marker="invalid_metadata"),
    ]

    report = main_module.execute_manual_training(
        {"storage": {"models_dir": str(tmp_path / "models")}},
        _ExecuteDb(labels=labels),
        {"current_phase": 2},
        now_ts=1715504400.0,
    )

    label_counts = report["promoted_models"][0]["metadata"]["label_counts"]
    assert label_counts == {"attack": 70, "benign": 140}


def test_manual_train_now_concurrency_lock_blocks_second_run(monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    future_ts = main_module._iso_local(1715504400.0 + 3600)
    db = _ExecuteDb(
        labels=[_label_row(ts=1715000000, bucket="normal"), _label_row(ts=1715001000, bucket="suspicious")],
        stats={"ml_training_scheduler_state": json.dumps({"run_lock": {"active": True, "owner": "other", "expires_at": future_ts}})},
    )

    report = main_module.execute_manual_training(
        {"storage": {"models_dir": str(tmp_path / "models")}},
        db,
        {"current_phase": 2},
        now_ts=1715504400.0,
    )

    assert report["training_started"] is False
    assert report["reason"] == "persistent_lock_active"
    assert report["kept_existing_models"][0]["reason"] == "persistent_lock_active"
