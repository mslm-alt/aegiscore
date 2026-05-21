import pytest

import main as main_module


def _deprecated_alias(*parts: str) -> str:
    return "".join(parts)


def _minimal_readiness_report(paused=False):
    return {
        "global": {
            "current_phase": 1,
            "phase_name": "Instant ML",
            "ml_paused": paused,
            "counts": {},
            "overall_events": {},
            "label_quality": {
                "label_counts_by_origin": {
                    "organic_live": 3,
                    "bootstrap_historical": 10,
                    "legacy_excluded": 2,
                },
                "label_counts_by_distro": {
                    "debian": 12,
                    "unknown_distro": 3,
                },
                "origin_counts_by_distro": {
                    "debian": {"organic_live": 3, "bootstrap_historical": 8, "legacy_excluded": 1},
                    "unknown_distro": {"bootstrap_historical": 2, "legacy_excluded": 1},
                },
                "family_counts_by_distro": {
                    "debian": {"ML-PROC": {"normal": 1, "suspicious": 2}},
                },
                "active_readiness_label_counts": {
                    "normal": 1,
                    "suspicious": 2,
                },
                "active_readiness_label_counts_by_distro": {
                    "debian": {"normal": 1, "suspicious": 2},
                },
                "organic_live_label_counts": {
                    "total": 3,
                    "family_counts": {"ML-PROC": {"normal": 1, "suspicious": 2}},
                },
                "bootstrap_historical_label_counts": {
                    "total": 10,
                    "family_counts": {"ML-PROC": {"normal": 9, "suspicious": 1}},
                },
                "excluded_legacy_label_counts": {
                    "total": 2,
                    "family_counts": {"ML-PROC": {"normal": 2, "suspicious": 0}},
                },
                "family_origin_counts": {
                    "ML-PROC": {
                        "organic_normal": 1,
                        "organic_suspicious": 2,
                        "bootstrap_normal": 9,
                        "bootstrap_suspicious": 1,
                        "legacy_excluded_normal": 2,
                        "legacy_excluded_suspicious": 0,
                    }
                },
                "quota_summary": {
                    "usage": {
                        "ML-PROC": {
                            "all": {
                                "normal": {"used": 1, "limit": 3000, "remaining": 2999, "status": "collecting"},
                                "suspicious": {"used": 2, "limit": 1000, "remaining": 998, "status": "collecting"},
                            },
                            "debian": {
                                "normal": {"used": 1, "limit": 3000, "remaining": 2999, "status": "collecting"},
                                "suspicious": {"used": 2, "limit": 1000, "remaining": 998, "status": "collecting"},
                            },
                        }
                    },
                    "full_families": [],
                    "quota_blocked_count": 0,
                    "unknown_distro_blocked_count": 0,
                },
            },
            "phase_stats": {},
        },
        "families": {
            "ML-PROC": {
                "status": "needs_more_data" if paused else "active_candidate",
                "reason": "ml_paused" if paused else "ready",
                "runtime_events": 17784,
                "required_events": 10000,
                "normal_labels": 10,
                "required_normal_labels": 300,
                "suspicious_labels": 5,
                "required_suspicious_labels": 150,
                "phase_gate": 1,
                "quota_normal": {"used": 1, "limit": 3000, "remaining": 2999, "status": "collecting"},
                "quota_suspicious": {"used": 2, "limit": 1000, "remaining": 998, "status": "collecting"},
            }
        },
    }


def test_ml_summary_includes_paused_blocker_and_mapping_summary(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _minimal_readiness_report(paused=True))
    monkeypatch.setattr(main_module, "collect_ml_training_scheduler_report", lambda config, db, pm_status: {
        "train_now": False,
        "schedule_due": False,
        "next_run_at": "2026-05-17T03:00:00",
        "reason": "ml_paused",
        "eligible_families": [],
        "blocked_families": [{"family_id": "ML-PROC", "distro": "debian", "reason": "ml_paused"}],
        "labels_since_last_train": {},
        "last_training_time": "",
        "no_action_contract": True,
        "training_started": False,
        "db_write_attempted": False,
        "active_ml_enabled": False,
    })
    monkeypatch.setattr(main_module, "_load_rule_ids_for_ml_mapping_audit", lambda config: (["AUTH-004", "PROC-001"], ""))
    monkeypatch.setattr(main_module, "collect_ml_mapping_audit", lambda rule_ids: {
        "total_rules": 2,
        "mapped_rules": 2,
        "coverage_percent": 100.0,
        "by_ml_family": {"ML-SUDO": 1, "ML-PROC": 1},
    })
    monkeypatch.setattr(main_module, "collect_ml_historical_scan_plan", lambda config, db, pm_status: {
        "families": {"ML-PROC": {"labels": {"process_normal": {"status": "needs_more_data"}}}}
    })
    monkeypatch.setattr(main_module, "collect_ml_normal_label_plan", lambda config, db, pm_status: {
        "global": {"blocking_incident": False},
        "families": {"ML-PROC": {"labels": {"process_normal": {
            "behavioral_baseline_candidate_count": 5,
            "rejected_candidate_count": 9,
            "rejection_reasons": {"suspicious_action": 9},
        }}}},
    })
    monkeypatch.setattr(main_module, "collect_ml_label_trust_audit", lambda config, db, pm_status: {
        "usage_decisions": {"direct_learnable": 4, "baseline_learning": 6, "ignored": 2, "rejected": 1},
        "quality_summary": {"missing_metadata_count": 3},
        "recommended_actions": ["model_usage_scope eksik kayıtlar rejected sayılmalı ve metadata tamamlanmalı"],
        "family_support": {"ML-PROC": {"normal": 0, "suspicious": 0}},
        "global": {},
    })
    monkeypatch.setattr(main_module, "collect_ml_label_metadata_plan", lambda config, db, pm_status: {
        "learnable_candidate_count": 3,
        "blocked_count": 7,
        "missing_metadata_counts": {"missing_source_trust": 10},
        "by_proposed_ml_family": {"ML-PROC": 3},
        "proposals": [{"proposed_ml_family": "ML-PROC"}] * 3,
    })
    monkeypatch.setattr(main_module, "collect_ml_model_status", lambda config: {
        "promoted_model_count": 1,
        "loaded_model_count": 1,
        "model_load_errors": [],
        "scoring_enabled_families": ["ML-PROC/debian"],
        "last_scoring_status": {},
        "no_action_contract": True,
    })

    report = main_module.collect_ml_summary({}, None, {"current_phase": 1, "phase_name": "Instant ML"})
    assert report["overall"]["ready_for_active_ml"] is False
    assert "ml_paused" in report["overall"]["top_blockers"]
    assert report["mapping_summary"]["coverage_percent"] == 100.0
    assert report["readiness_label_counts"]["label_counts_by_origin"]["legacy_excluded"] == 2
    assert report["readiness_label_counts"]["label_counts_by_distro"]["debian"] == 12
    assert report["phase_event_volume"]["counter_scope"] == "normalized_runtime_events_lifetime_phase_counter"
    assert report["label_readiness_summary"]["counter_scope"] == "family_specific_labeled_training_examples"
    assert report["family_summary"]["ML-PROC"]["label_origins"]["bootstrap_normal"] == 9
    assert report["family_summary"]["ML-PROC"]["quota_normal"]["limit"] == 3000
    assert report["label_quota_summary"]["usage"]["ML-PROC"]["all"]["normal"]["used"] == 1
    assert report["label_trust_summary"]["quality_summary"]["missing_metadata_count"] == 3
    assert report["metadata_plan_summary"]["missing_metadata_counts"]["missing_source_trust"] == 10
    assert report["training_scheduler"]["reason"] == "ml_paused"


def test_ml_summary_empty_inputs_do_not_crash(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: {"global": {}, "families": {}})
    monkeypatch.setattr(main_module, "collect_ml_training_scheduler_report", lambda config, db, pm_status: {
        "train_now": False,
        "schedule_due": False,
        "next_run_at": "",
        "reason": "insufficient_labels",
        "eligible_families": [],
        "blocked_families": [],
        "labels_since_last_train": {},
        "last_training_time": "",
        "no_action_contract": True,
        "training_started": False,
        "db_write_attempted": False,
        "active_ml_enabled": False,
    })
    monkeypatch.setattr(main_module, "_load_rule_ids_for_ml_mapping_audit", lambda config: ([], ""))
    monkeypatch.setattr(main_module, "collect_ml_mapping_audit", lambda rule_ids: {
        "total_rules": 0,
        "mapped_rules": 0,
        "coverage_percent": 0.0,
        "by_ml_family": {},
    })
    monkeypatch.setattr(main_module, "collect_ml_historical_scan_plan", lambda config, db, pm_status: {"families": {}})
    monkeypatch.setattr(main_module, "collect_ml_normal_label_plan", lambda config, db, pm_status: {"families": {}, "global": {}})
    monkeypatch.setattr(main_module, "collect_ml_label_trust_audit", lambda config, db, pm_status: {
        "usage_decisions": {},
        "quality_summary": {},
        "recommended_actions": [],
        "family_support": {},
        "global": {},
    })
    monkeypatch.setattr(main_module, "collect_ml_label_metadata_plan", lambda config, db, pm_status: {
        "learnable_candidate_count": 0,
        "blocked_count": 0,
        "missing_metadata_counts": {},
        "by_proposed_ml_family": {},
        "proposals": [],
    })
    monkeypatch.setattr(main_module, "collect_ml_model_status", lambda config: {
        "promoted_model_count": 0,
        "loaded_model_count": 0,
        "model_load_errors": [],
        "scoring_enabled_families": [],
        "last_scoring_status": {},
        "no_action_contract": True,
    })

    report = main_module.collect_ml_summary({}, None, {"current_phase": 0, "phase_name": "Kural"})
    assert report["overall"]["ready_for_active_ml"] is False
    assert report["mapping_summary"]["total_rules"] == 0
    assert report["phase_event_volume"]["phase_lifetime_event_count"] == 0
    assert report["readiness_label_counts"]["label_counts_by_origin"] == {}
    assert report["label_quota_summary"] == {}
    assert report["training_scheduler"]["train_now"] is False


def test_ml_summary_partial_helper_failure_is_reported(monkeypatch):
    monkeypatch.setattr(main_module, "collect_ml_readiness_report", lambda config, db, pm_status: _minimal_readiness_report(paused=False))
    monkeypatch.setattr(main_module, "collect_ml_training_scheduler_report", lambda config, db, pm_status: {
        "train_now": True,
        "schedule_due": True,
        "next_run_at": "2026-05-17T03:00:00",
        "reason": "weekly_schedule_due",
        "eligible_families": [{"family_id": "ML-PROC", "distro": "debian", "reason": "weekly_schedule_due"}],
        "blocked_families": [],
        "labels_since_last_train": {"ML-PROC/debian": {"normal": 9, "suspicious": 2, "last_training_at": ""}},
        "last_training_time": "",
        "no_action_contract": True,
        "training_started": False,
        "db_write_attempted": False,
        "active_ml_enabled": False,
    })
    monkeypatch.setattr(main_module, "_load_rule_ids_for_ml_mapping_audit", lambda config: (["AUTH-004"], ""))
    monkeypatch.setattr(main_module, "collect_ml_mapping_audit", lambda rule_ids: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(main_module, "collect_ml_historical_scan_plan", lambda config, db, pm_status: {"families": {}})
    monkeypatch.setattr(main_module, "collect_ml_normal_label_plan", lambda config, db, pm_status: {"families": {}, "global": {}})
    monkeypatch.setattr(main_module, "collect_ml_label_trust_audit", lambda config, db, pm_status: {
        "usage_decisions": {},
        "quality_summary": {},
        "recommended_actions": [],
        "family_support": {},
        "global": {},
    })
    monkeypatch.setattr(main_module, "collect_ml_label_metadata_plan", lambda config, db, pm_status: {
        "learnable_candidate_count": 0,
        "blocked_count": 0,
        "missing_metadata_counts": {},
        "by_proposed_ml_family": {},
        "proposals": [],
    })
    monkeypatch.setattr(main_module, "collect_ml_model_status", lambda config: {
        "promoted_model_count": 1,
        "loaded_model_count": 0,
        "model_load_errors": [{"reason": "model_load_failed"}],
        "scoring_enabled_families": [],
        "last_scoring_status": {},
        "no_action_contract": True,
    })

    report = main_module.collect_ml_summary({}, None, {"current_phase": 1, "phase_name": "Instant ML"})
    assert any("ml_mapping_audit:boom" in note for note in report["overall"]["query_notes"])
    assert report["mapping_summary"]["total_rules"] == 0


def test_ml_summary_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_summary", lambda config: print("ML Unified Summary") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-summary"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert "ML Unified Summary" in capsys.readouterr().out


def test_print_ml_summary_includes_origin_aware_readiness_counts(capsys):
    report = {
        "overall": {
            "ready_for_active_ml": False,
            "current_phase": 1,
            "phase_name": "Instant ML",
            "ml_paused": True,
            "top_blockers": ["ml_paused"],
            "query_notes": [],
        },
        "family_summary": {
            "ML-PROC": {
                "status": "paused",
                "phase_gate": 1,
                "runtime_events": 100,
                "required_events": 300,
                "normal_labels": {"found": 1, "required": 10},
                "suspicious_labels": {"found": 2, "required": 10},
                "metadata_support": 0,
                "trust_support": {"normal": 1, "suspicious": 2},
                "label_origins": {
                    "organic_normal": 1,
                    "organic_suspicious": 2,
                    "bootstrap_normal": 9,
                    "bootstrap_suspicious": 1,
                    "legacy_excluded_normal": 2,
                    "legacy_excluded_suspicious": 0,
                },
                "top_reasons": ["ml_paused"],
            }
        },
        "mapping_summary": {"total_rules": 0, "mapped_rules": 0, "coverage_percent": 0.0, "by_family": {}},
        "historical_scan_summary": {},
        "historical_scan_distro_breakdown": {"candidate_count_by_distro": {"debian": 7}},
        "normal_label_summary": {"candidate_count_by_distro": {"debian": 4}},
        "training_scheduler": {
            "train_now": False,
            "schedule_due": False,
            "next_run_at": "2026-05-17T03:00:00",
            "reason": "insufficient_new_labels",
            "eligible_families": [],
            "blocked_families": [{"family_id": "ML-PROC", "distro": "debian", "reason": "insufficient_new_labels"}],
            "labels_since_last_train": {"ML-PROC/debian": {"normal": 12, "suspicious": 7, "last_training_at": "2026-05-10T03:00:00"}},
            "last_training_time": "2026-05-10T03:00:00",
            "no_action_contract": True,
            "training_started": False,
            "db_write_attempted": False,
            "active_ml_enabled": False,
        },
        "model_status": {
            "promoted_model_count": 1,
            "loaded_model_count": 1,
            "model_load_errors": [],
            "scoring_enabled_families": ["ML-PROC/debian"],
            "last_scoring_status": {},
            "no_action_contract": True,
        },
        "readiness_label_counts": {
            "label_counts_by_origin": {"organic_live": 3, "bootstrap_historical": 10, "legacy_excluded": 2},
            "label_counts_by_distro": {"debian": 12, "unknown_distro": 3},
            "origin_counts_by_distro": {"debian": {"organic_live": 3, "bootstrap_historical": 8, "legacy_excluded": 1}},
            "family_counts_by_distro": {"debian": {"ML-PROC": {"normal": 1, "suspicious": 2}}},
            "active_readiness_label_counts": {"normal": 1, "suspicious": 2},
            "active_readiness_label_counts_by_distro": {"debian": {"normal": 1, "suspicious": 2}},
            "organic_live_label_counts": {"total": 3},
            "bootstrap_historical_label_counts": {"total": 10},
            "excluded_legacy_label_counts": {"total": 2},
        },
        "label_trust_summary": {},
        "metadata_plan_summary": {},
        "recommended_next_actions": [],
    }

    main_module.print_ml_summary(report)

    out = capsys.readouterr().out
    assert "Readiness label counts:" in out
    assert "Historical scan distro breakdown: {'candidate_count_by_distro': {'debian': 7}}" in out
    assert "'candidate_count_by_distro': {'debian': 4}" in out
    assert "label_counts_by_origin" in out
    assert "Model status:" in out
    assert "'label_counts_by_distro': {'debian': 12, 'unknown_distro': 3}" in out
    assert "Training scheduler:" in out
    assert "label_origins={'organic_normal': 1, 'organic_suspicious': 2, 'bootstrap_normal': 9, 'bootstrap_suspicious': 1, 'legacy_excluded_normal': 2, 'legacy_excluded_suspicious': 0}" in out
    assert _deprecated_alias("manually", "_", "verified") not in out
    assert _deprecated_alias("shadow", "_", "only") not in out
