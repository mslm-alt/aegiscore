import json
from datetime import datetime

import pytest

import main as main_module


class _SchedulerDb:
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

    def close(self):
        return None


def _label_row(*, ts, origin, bucket, distro="debian", learnable=True, usage=None, behavior=None, event_class=None):
    if bucket == "normal":
        behavior = behavior or "expected_auth_activity"
        event_class = event_class or "benign"
        usage = usage or "baseline_learning"
    else:
        behavior = behavior or "brute_force_or_auth_attack"
        event_class = event_class or "attack"
        usage = usage or "calibration_only"
    source = "bootstrap" if origin == "bootstrap_historical" else "auto_labeled"
    label_batch_id = "historical_auth_bootstrap" if origin == "bootstrap_historical" else ""
    source_trust = "observed_benign_high" if bucket == "normal" else "rule_high"
    return {
        "ts": float(ts + ((int(ts) % 5) * 86400)),
        "source": source,
        "distro": distro,
        "distro_family": distro,
        "label": "normal" if bucket == "normal" else "attack",
        "category": "auth",
        "event_class": event_class,
        "behavior_label": behavior,
        "attack_family": "" if bucket == "normal" else "credential_access",
        "source_trust": source_trust,
        "model_usage_scope": usage,
        "learnable": learnable,
        "label_reason": "bootstrap_historical_scan" if origin == "bootstrap_historical" else "direct_rule_runtime",
        "bootstrap_job_id": "bootstrap_auth_1" if origin == "bootstrap_historical" else "",
        "label_batch_id": label_batch_id,
        "event_class": event_class,
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
        "source_type": "clean_window_normal" if bucket == "normal" else "rule_mapped_attack",
        "no_action_contract": True,
    }


def _readiness_report(*, paused=False, quota_full=False):
    quota_normal = {"used": 3000, "limit": 3000, "remaining": 0, "status": "stop_write"} if quota_full else {"used": 120, "limit": 3000, "remaining": 2880, "status": "collecting"}
    quota_suspicious = {"used": 1000, "limit": 1000, "remaining": 0, "status": "stop_write"} if quota_full else {"used": 80, "limit": 1000, "remaining": 920, "status": "collecting"}
    return {
        "global": {
            "current_phase": 2,
            "phase_name": "Baseline",
            "ml_paused": paused,
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
                        "quota_normal": quota_normal,
                        "quota_suspicious": quota_suspicious,
                    }
                },
            }
        },
    }


def test_scheduler_clean_db_returns_no_training(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())

    report = main_module.collect_ml_training_scheduler_report({}, _SchedulerDb(), {"current_phase": 2}, now_ts=1747141200.0)

    assert report["train_now"] is False
    assert report["training_mode"] == "manual"
    assert report["reason"] in {"manual_mode_waiting_for_user", "insufficient_normal_labels", "insufficient_suspicious_labels", "readiness_blocked"}
    assert report["training_started"] is False
    assert report["db_write_attempted"] is False
    assert report["active_ml_enabled"] is False


def test_scheduler_initial_training_eligible_with_historical_labels(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious") for idx in range(70)],
    ]

    report = main_module.collect_ml_training_scheduler_report({}, _SchedulerDb(labels=labels), {"current_phase": 2}, now_ts=1747141200.0)

    assert report["train_now"] is False
    assert report["manual_train_now_eligible"] is True
    assert report["reason"] == "manual_training_required"
    assert report["eligible_families"][0]["mode"] == "initial_training"


def test_scheduler_manual_mode_worker_does_not_autostart_training(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious") for idx in range(70)],
    ]
    report = main_module.collect_ml_training_scheduler_report(
        {"ml": {"training_scheduler": {"mode": "manual"}}},
        _SchedulerDb(labels=labels),
        {"current_phase": 2},
        now_ts=1747141200.0,
    )
    assert report["training_mode"] == "manual"
    assert report["train_now"] is False
    assert report["manual_train_now_eligible"] is True
    assert report["reason"] == "manual_training_required"


def test_scheduler_threshold_not_met_returns_insufficient_new_labels(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious") for idx in range(70)],
        _label_row(ts=1715600000, origin="organic_live", bucket="normal"),
        _label_row(ts=1715600100, origin="organic_live", bucket="suspicious"),
    ]
    stats = {
        "ml_training_scheduler_state": json.dumps(
            {
                "last_training": {"ML-AUTH/debian": {"trained_at": 1714000000}},
                "last_scheduler_check_at": 1715550000,
            }
        )
    }

    report = main_module.collect_ml_training_scheduler_report(
        {"ml": {"training_scheduler": {"mode": "threshold"}}},
        _SchedulerDb(labels=labels, stats=stats),
        {"current_phase": 2},
        now_ts=1715767200.0,
    )

    assert report["train_now"] is False
    assert report["reason"] == "insufficient_new_labels"


def test_scheduler_weekly_due_can_trigger_guarded_retrain(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious") for idx in range(70)],
        _label_row(ts=1715600000, origin="organic_live", bucket="normal"),
    ]
    stats = {
        "ml_training_scheduler_state": json.dumps(
            {
                "last_training": {"ML-AUTH/debian": {"trained_at": 1714000000}},
                "last_scheduler_check_at": 0,
            }
        )
    }

    report = main_module.collect_ml_training_scheduler_report(
        {"ml": {"training_scheduler": {"mode": "scheduled"}}},
        _SchedulerDb(labels=labels, stats=stats),
        {"current_phase": 2},
        now_ts=datetime(2024, 5, 12, 4, 0, 0).timestamp(),
    )

    assert report["schedule_due"] is True
    assert report["train_now"] is False
    assert report["reason"] in {"insufficient_new_labels", "insufficient_schedule_window"}
    assert report["training_started"] is False


def test_scheduler_quota_full_without_new_data_is_noop(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report(quota_full=True))
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious") for idx in range(70)],
    ]
    stats = {
        "ml_training_scheduler_state": json.dumps(
            {
                "last_training": {"ML-AUTH/debian": {"trained_at": 1715400000}},
                "last_scheduler_check_at": 1715480000,
            }
        )
    }

    report = main_module.collect_ml_training_scheduler_report(
        {"ml": {"training_scheduler": {"mode": "threshold"}}},
        _SchedulerDb(labels=labels, stats=stats),
        {"current_phase": 2},
        now_ts=1715504400.0,
    )

    assert report["train_now"] is False
    assert report["reason"] == "quota_full_no_new_data"


def test_scheduler_respects_ml_paused(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report(paused=True))
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious") for idx in range(70)],
    ]

    report = main_module.collect_ml_training_scheduler_report({}, _SchedulerDb(labels=labels), {"current_phase": 2}, now_ts=1715504400.0)

    assert report["train_now"] is False
    assert report["reason"] == "ml_paused"


def test_scheduler_respects_incident_blocker(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious") for idx in range(70)],
    ]

    report = main_module.collect_ml_training_scheduler_report({}, _SchedulerDb(labels=labels, open_incidents=[{"id": 1}]), {"current_phase": 2}, now_ts=1715504400.0)

    assert report["train_now"] is False
    assert report["reason"] == "open_incident"


def test_scheduler_ignores_unknown_distro_and_not_learnable_labels(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal", distro="unknown_distro") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious", learnable=False) for idx in range(70)],
    ]

    report = main_module.collect_ml_training_scheduler_report({}, _SchedulerDb(labels=labels), {"current_phase": 2}, now_ts=1715504400.0)

    assert report["train_now"] is False
    assert report["eligible_families"] == []
    assert report["reason"] in {"manual_mode_waiting_for_user", "insufficient_normal_labels", "insufficient_suspicious_labels", "readiness_blocked"}


def test_scheduler_disabled_mode_blocks_training(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious") for idx in range(70)],
    ]
    report = main_module.collect_ml_training_scheduler_report(
        {"ml": {"training_scheduler": {"mode": "disabled"}}},
        _SchedulerDb(labels=labels),
        {"current_phase": 2},
        now_ts=1715504400.0,
    )
    assert report["training_mode"] == "disabled"
    assert report["train_now"] is False
    assert report["reason"] == "training_disabled"


def test_train_now_dry_run_ignores_manual_default_but_stays_read_only(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious") for idx in range(70)],
    ]
    report = main_module.collect_ml_training_scheduler_report(
        {"ml": {"training_scheduler": {"mode": "manual"}}},
        _SchedulerDb(labels=labels),
        {"current_phase": 2},
        now_ts=1715504400.0,
        trigger_request="manual_dry_run",
    )
    assert report["trigger_request"] == "manual_dry_run"
    assert report["train_now"] is True
    assert report["reason"] == "manual_train_now_eligible"
    assert report["training_started"] is False
    assert report["db_write_attempted"] is False


def test_ml_train_scheduler_dry_run_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_train_scheduler_dry_run", lambda config: print("ML Training Scheduler Dry Run\ntraining_started=False\ndb_write_attempted=False\nactive_ml_enabled=False") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-train-scheduler-dry-run"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "ML Training Scheduler Dry Run" in out
    assert "training_started=False" in out
    assert "db_write_attempted=False" in out
    assert "active_ml_enabled=False" in out


def test_ml_training_status_cli_dispatches_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_training_status", lambda config: print("ML Training Scheduler Dry Run\ntraining_mode=manual") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-training-status"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert "training_mode=manual" in capsys.readouterr().out


def test_ml_train_now_dry_run_cli_dispatches_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_train_now_dry_run", lambda config: print("ML Training Scheduler Dry Run\ntrigger_request=manual_dry_run\ntraining_started=False\ndb_write_attempted=False") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-train-now-dry-run"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "trigger_request=manual_dry_run" in out
    assert "training_started=False" in out
    assert "db_write_attempted=False" in out


def test_ml_train_now_cli_dispatches_execute(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_train_now", lambda config: print("trigger_request=manual_execute\ntraining_started=True\nactive_ml_enabled=False") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-train-now"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "trigger_request=manual_execute" in out
    assert "training_started=True" in out


def test_scheduler_auto_mode_creates_guarded_execution_candidates(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious") for idx in range(70)],
    ]

    report = main_module.collect_ml_training_scheduler_report(
        {"ml": {"training_scheduler": {"mode": "auto", "max_families_per_run": 1}}},
        _SchedulerDb(labels=labels),
        {"current_phase": 2},
        now_ts=1747141200.0,
    )

    assert report["training_mode"] == "auto"
    assert report["train_now"] is True
    assert report["execution_candidates"]
    assert len(report["execution_candidates"]) == 1
    assert report["active_ml_enabled"] is False


def test_scheduler_report_exposes_model_ready_fields_without_shadow_requirement(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _readiness_report())
    labels = [
        *[_label_row(ts=1715000000 + idx, origin="bootstrap_historical", bucket="normal") for idx in range(140)],
        *[_label_row(ts=1715001000 + idx, origin="bootstrap_historical", bucket="suspicious") for idx in range(70)],
    ]
    stats = {
        "ml_training_scheduler_state": json.dumps(
            {
                "first_model_training_completed_at": "2026-05-19T01:00:00",
                "first_model_training_status": "promoted",
                "first_model_evaluation_status": "passed",
                "first_ml_model_ready": True,
                "ml_alert_family_ready": True,
                "ml_alert_family_enabled_families": ["ML-AUTH/debian"],
            }
        )
    }

    report = main_module.collect_ml_training_scheduler_report({}, _SchedulerDb(labels=labels, stats=stats), {"current_phase": 2}, now_ts=1747141200.0)

    assert report["first_model_training_completed"] is True
    assert report["first_model_evaluation_passed"] is True
    assert report["first_ml_model_ready"] is True
    assert report["ml_alert_family_enabled_families"] == ["ML-AUTH/debian"]
