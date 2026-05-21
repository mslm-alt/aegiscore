import json
import threading
from pathlib import Path
from types import SimpleNamespace

import main as main_module


class _WorkerDb:
    def __init__(self, labels=None, stats=None):
        self._labels = list(labels or [])
        self._stats = dict(stats or {})

    def load_labels(self):
        return list(self._labels)

    def get_stat(self, key):
        return self._stats.get(key, "")

    def set_stat(self, key, value):
        self._stats[key] = value

    def close(self):
        return None

    def insert_event(self, **kwargs):
        raise AssertionError("scheduler worker events_recent insert yapmamalı")

    def save_labels(self, records):
        raise AssertionError("scheduler worker label write yapmamalı")


def _label(*, ts, origin="bootstrap_historical", bucket="normal", distro="debian"):
    if bucket == "normal":
        return {
            "ts": float(ts + ((int(ts) % 5) * 86400)),
            "source": "bootstrap" if origin == "bootstrap_historical" else "auto_labeled",
            "distro": distro,
            "distro_family": distro,
            "label": "normal",
            "category": "auth",
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "attack_family": "",
            "source_trust": "observed_benign_high",
            "model_usage_scope": "baseline_learning",
            "learnable": True,
            "label_reason": "bootstrap_historical_scan" if origin == "bootstrap_historical" else "direct_rule_runtime",
            "bootstrap_job_id": "bootstrap_auth_1" if origin == "bootstrap_historical" else "",
            "label_batch_id": "historical_auth_bootstrap" if origin == "bootstrap_historical" else "",
            "evidence_fields": {"rule_id": "AUTH-001", "log_source": "auth_log", "timestamp_confidence": "high", "timestamp_source": "event", "dedup_status": "unique", "duplicate_count": 1},
            "timestamp_confidence": "high",
            "timestamp_source": "event",
            "poisoning_guard_passed": True,
            "ml_family": "ML-AUTH",
            "ml_label": "expected_auth_activity",
            "label_family": "ML-AUTH",
            "source_type": "clean_window_normal",
            "no_action_contract": True,
        }
    return {
        "ts": float(ts + ((int(ts) % 5) * 86400)),
        "source": "bootstrap" if origin == "bootstrap_historical" else "auto_labeled",
        "distro": distro,
        "distro_family": distro,
        "label": "attack",
        "category": "auth",
        "event_class": "attack",
        "behavior_label": "brute_force_or_auth_attack",
        "attack_family": "credential_access",
        "source_trust": "rule_high",
        "model_usage_scope": "calibration_only",
        "learnable": True,
        "label_reason": "bootstrap_historical_scan" if origin == "bootstrap_historical" else "direct_rule_runtime",
        "bootstrap_job_id": "bootstrap_auth_1" if origin == "bootstrap_historical" else "",
        "label_batch_id": "historical_auth_bootstrap" if origin == "bootstrap_historical" else "",
        "evidence_fields": {"rule_id": "AUTH-001", "log_source": "journald", "timestamp_confidence": "high", "timestamp_source": "event", "dedup_status": "unique", "duplicate_count": 1},
        "timestamp_confidence": "high",
        "timestamp_source": "event",
        "poisoning_guard_passed": True,
        "ml_family": "ML-AUTH",
        "ml_label": "brute_force_or_auth_attack",
        "label_family": "ML-AUTH",
        "source_type": "rule_mapped_attack",
        "no_action_contract": True,
    }


def _pipeline(tmp_path, db):
    pipeline = main_module.SIEMPipeline.__new__(main_module.SIEMPipeline)
    pipeline.config = {
        "storage": {"models_dir": str(tmp_path / "models")},
        "ml": {"training_scheduler": {"initial_delay_seconds": 5, "check_interval_seconds": 300}},
    }
    pipeline.running = True
    pipeline.phase = SimpleNamespace(get_status=lambda: {"current_phase": 2, "phase_name": "Baseline"})
    pipeline._runtime_state = SimpleNamespace(runtime_components={})
    pipeline._ml_training_scheduler_cfg = main_module._resolve_ml_training_scheduler_config(pipeline.config)
    pipeline._ml_training_scheduler_model_root = main_module._scheduler_model_root(pipeline.config)
    pipeline._ml_training_scheduler_model_root.mkdir(parents=True, exist_ok=True)
    pipeline._ml_training_scheduler_thread = None
    pipeline._ml_training_scheduler_stop = threading.Event()
    pipeline._ml_training_scheduler_lock = threading.Lock()
    pipeline._ml_training_scheduler_state = {}
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
    pipeline._ml_training_scheduler_open_db = lambda: db
    return pipeline


def _decision(*, reason="initial_training_eligible", train_now=True):
    return {
        "current_time": "2026-05-18T03:15:00",
        "last_scheduler_check_at": "",
        "schedule_due": True,
        "next_run_at": "2026-05-24T03:00:00",
        "scheduled_day": "sunday",
        "scheduled_time": "03:00",
        "train_now": train_now,
        "reason": reason,
        "eligible_families": [{"family_id": "ML-AUTH", "distro": "debian", "reason": reason, "mode": "initial_training"}] if train_now else [],
        "blocked_families": [] if train_now else [{"family_id": "ML-AUTH", "distro": "debian", "reason": reason}],
        "labels_since_last_train": {"ML-AUTH/debian": {"normal": 10, "suspicious": 8, "last_training_at": ""}},
        "quota_status": {},
        "readiness_status": {},
        "last_training_time": "",
        "last_training_at": "",
        "last_training_status": "",
        "last_training_reason": "",
        "last_training_family_distro": "",
        "last_training_label_counts": {},
        "last_evaluation_status": "",
        "last_model_promoted": False,
        "last_model_kept_reason": "",
        "no_action_contract": True,
        "training_started": False,
        "db_write_attempted": False,
        "active_ml_enabled": False,
    }


def test_worker_noop_updates_last_scheduler_check_at(monkeypatch, tmp_path):
    db = _WorkerDb()
    pipeline = _pipeline(tmp_path, db)
    monkeypatch.setattr(main_module, "collect_ml_training_scheduler_report", lambda config, db, pm_status, now_ts=None: _decision(reason="insufficient_labels", train_now=False))

    result = pipeline._run_ml_training_scheduler_worker_once()

    state = json.loads(db.get_stat("ml_training_scheduler_state"))
    assert result["status"] == "no_op"
    assert state["last_scheduler_check_at"] == "2026-05-18T03:15:00"
    assert state["training_started"] is False
    assert state["active_ml_enabled"] is False


def test_worker_manual_mode_does_not_start_training_even_when_eligible(monkeypatch, tmp_path):
    labels = [*[_label(ts=1715000000 + idx, bucket="normal") for idx in range(40)], *[_label(ts=1715001000 + idx, bucket="suspicious") for idx in range(40)]]
    db = _WorkerDb(labels=labels)
    pipeline = _pipeline(tmp_path, db)
    monkeypatch.setattr(
        main_module,
        "collect_ml_training_scheduler_report",
        lambda config, db, pm_status, now_ts=None: {
            **_decision(reason="manual_training_required", train_now=False),
            "training_mode": "manual",
            "manual_train_now_eligible": True,
            "manual_trigger_required": True,
            "eligible_families": [{"family_id": "ML-AUTH", "distro": "debian", "reason": "initial_training_eligible", "mode": "initial_training"}],
        },
    )

    result = pipeline._run_ml_training_scheduler_worker_once()

    state = json.loads(db.get_stat("ml_training_scheduler_state"))
    assert result["status"] == "no_op"
    assert state["training_mode"] == "manual"
    assert state["last_decision_reason"] == "manual_training_required"
    assert state["training_started"] is False


def test_worker_promotes_artifact_when_evaluation_passes(monkeypatch, tmp_path):
    labels = [*[_label(ts=1715000000 + idx, bucket="normal") for idx in range(40)], *[_label(ts=1715001000 + idx, bucket="suspicious") for idx in range(40)]]
    db = _WorkerDb(labels=labels)
    pipeline = _pipeline(tmp_path, db)
    monkeypatch.setattr(main_module, "collect_ml_training_scheduler_report", lambda config, db, pm_status, now_ts=None: _decision())
    monkeypatch.setattr(main_module, "_evaluate_scheduler_training_candidate", lambda training_payload, schedule_cfg: {"passed": True, "reason": "evaluation_passed", "metrics": {"train_count": 60, "eval_count": 20, "normal_eval": 10, "suspicious_eval": 10}})

    result = pipeline._run_ml_training_scheduler_worker_once()

    assert result["status"] == "completed"
    state = json.loads(db.get_stat("ml_training_scheduler_state"))
    assert state["last_training_status"] == "promoted"
    assert state["last_model_promoted"] is True
    assert state["first_model_training_completed_at"]
    assert state["first_model_evaluation_status"] == "passed"
    assert state["first_ml_model_ready"] is True
    paths = main_module._scheduler_artifact_paths(pipeline.config, "ML-AUTH", "debian")
    assert Path(paths["artifact"]).exists()
    assert Path(paths["metadata"]).exists()


def test_worker_keeps_old_model_when_evaluation_fails(monkeypatch, tmp_path):
    labels = [*[_label(ts=1715000000 + idx, bucket="normal") for idx in range(40)], *[_label(ts=1715001000 + idx, bucket="suspicious") for idx in range(40)]]
    db = _WorkerDb(labels=labels)
    pipeline = _pipeline(tmp_path, db)
    monkeypatch.setattr(main_module, "collect_ml_training_scheduler_report", lambda config, db, pm_status, now_ts=None: _decision())
    monkeypatch.setattr(main_module, "_evaluate_scheduler_training_candidate", lambda training_payload, schedule_cfg: {"passed": False, "reason": "insufficient_eval_support", "metrics": {}})

    pipeline._run_ml_training_scheduler_worker_once()

    state = json.loads(db.get_stat("ml_training_scheduler_state"))
    assert state["last_training_status"] == "evaluation_failed"
    assert state["last_model_promoted"] is False
    assert state["last_model_kept_reason"] == "insufficient_eval_support"
    assert state["first_model_training_completed_at"]
    assert state["first_ml_model_ready"] is False
    paths = main_module._scheduler_artifact_paths(pipeline.config, "ML-AUTH", "debian")
    assert not Path(paths["artifact"]).exists()


def test_worker_same_week_duplicate_due_does_not_retrain(monkeypatch, tmp_path):
    labels = [*[_label(ts=1715000000 + idx, bucket="normal") for idx in range(40)], *[_label(ts=1715001000 + idx, bucket="suspicious") for idx in range(40)]]
    db = _WorkerDb(labels=labels)
    pipeline = _pipeline(tmp_path, db)
    decisions = [
        _decision(reason="weekly_schedule_due", train_now=True),
        _decision(reason="insufficient_new_labels", train_now=False),
    ]
    monkeypatch.setattr(main_module, "collect_ml_training_scheduler_report", lambda config, db, pm_status, now_ts=None: decisions.pop(0))
    monkeypatch.setattr(main_module, "_evaluate_scheduler_training_candidate", lambda training_payload, schedule_cfg: {"passed": True, "reason": "evaluation_passed", "metrics": {"train_count": 60, "eval_count": 20, "normal_eval": 10, "suspicious_eval": 10}})

    first = pipeline._run_ml_training_scheduler_worker_once()
    second = pipeline._run_ml_training_scheduler_worker_once()

    assert first["status"] == "completed"
    assert second["status"] == "no_op"


def test_worker_lock_blocks_concurrent_run(monkeypatch, tmp_path):
    db = _WorkerDb()
    pipeline = _pipeline(tmp_path, db)
    pipeline._ml_training_scheduler_lock.acquire()
    try:
        result = pipeline._run_ml_training_scheduler_worker_once()
    finally:
        pipeline._ml_training_scheduler_lock.release()

    assert result["status"] == "skipped"
    assert result["reason"] == "local_lock_active"


def test_worker_thread_starts_and_stops_cleanly(monkeypatch, tmp_path):
    db = _WorkerDb()
    pipeline = _pipeline(tmp_path, db)
    pipeline._ml_training_scheduler_cfg["initial_delay_seconds"] = 60
    pipeline._ml_training_scheduler_cfg["check_interval_seconds"] = 60
    monkeypatch.setattr(pipeline, "_run_ml_training_scheduler_worker_once", lambda: {"status": "no_op"})

    thread = pipeline._start_ml_training_scheduler_worker()
    assert thread is not None and thread.is_alive()

    pipeline._stop_runtime_workers()

    assert pipeline._ml_training_scheduler_stop.is_set() is True


def test_worker_auto_mode_respects_max_families_per_run(monkeypatch, tmp_path):
    labels = [
        *[_label(ts=1715000000 + idx, bucket="normal") for idx in range(40)],
        *[_label(ts=1715001000 + idx, bucket="suspicious") for idx in range(40)],
        *[_label(ts=1716000000 + idx, bucket="normal") for idx in range(40)],
        *[_label(ts=1716001000 + idx, bucket="suspicious") for idx in range(40)],
    ]
    db = _WorkerDb(labels=labels)
    pipeline = _pipeline(tmp_path, db)
    pipeline.config["ml"]["training_scheduler"].update({"mode": "auto", "max_families_per_run": 1})
    pipeline._ml_training_scheduler_cfg = main_module._resolve_ml_training_scheduler_config(pipeline.config)
    monkeypatch.setattr(
        main_module,
        "collect_ml_training_scheduler_report",
        lambda config, db, pm_status, now_ts=None: {
            **_decision(),
            "training_mode": "auto",
            "execution_candidates": [
                {"family_id": "ML-AUTH", "distro": "debian", "reason": "initial_training_eligible", "mode": "initial_training"},
            ],
            "eligible_families": [
                {"family_id": "ML-AUTH", "distro": "debian", "reason": "initial_training_eligible", "mode": "initial_training"},
                {"family_id": "ML-SUDO", "distro": "debian", "reason": "initial_training_eligible", "mode": "initial_training"},
            ],
            "eligible_seed_families": [
                {"family_id": "ML-AUTH", "distro": "debian", "reason": "initial_training_eligible", "mode": "initial_training"},
                {"family_id": "ML-SUDO", "distro": "debian", "reason": "initial_training_eligible", "mode": "initial_training"},
            ],
        },
    )
    monkeypatch.setattr(main_module, "_evaluate_scheduler_training_candidate", lambda training_payload, schedule_cfg: {"passed": True, "reason": "evaluation_passed", "metrics": {"train_count": 60, "eval_count": 20, "normal_eval": 10, "suspicious_eval": 10}})

    result = pipeline._run_ml_training_scheduler_worker_once()

    assert result["status"] == "completed"
    state = json.loads(db.get_stat("ml_training_scheduler_state"))
    assert state["last_training_family_distro"] == "ML-AUTH/debian"
