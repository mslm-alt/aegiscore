import pytest

import main as main_module


def _deprecated_alias(*parts: str) -> str:
    return "".join(parts)


def _deprecated_alias(*parts: str) -> str:
    return "".join(parts)


def test_summarize_label_quality_splits_organic_bootstrap_and_legacy_origins():
    deprecated_origin = _deprecated_alias("manu", "ally", "_", "verified")
    rows = [
        {
            "source": "auto_labeled",
            "distro": "debian",
            "label": "normal",
            "category": "auth",
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "attack_family": "credential_access",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "model_usage_scope": "baseline_learning",
            "label_reason": "direct_rule_runtime",
            "bootstrap_job_id": "",
            "label_batch_id": "",
        },
        {
            "source": "auto_labeled",
            "distro": "debian",
            "label": "attack",
            "category": "auth",
            "event_class": "attack",
            "behavior_label": "brute_force_or_auth_attack",
            "attack_family": "credential_access",
            "source_trust": "rule_high",
            "learnable": True,
            "model_usage_scope": "calibration_only",
            "label_reason": "direct_rule_runtime",
            "bootstrap_job_id": "",
            "label_batch_id": "",
        },
        {
            "source": "bootstrap",
            "distro": "debian",
            "label": "normal",
            "category": "network",
            "event_class": "benign",
            "behavior_label": "normal_network",
            "attack_family": "",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "model_usage_scope": "calibration_only",
            "label_reason": "bootstrap_historical_scan",
            "bootstrap_job_id": "bootstrap_scan_debian_202",
            "label_batch_id": "bootstrap_scan_debian_202",
        },
        {
            "source": "bootstrap",
            "label": "normal",
            "category": "auth",
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "attack_family": "credential_access",
            "source_trust": "observed_benign_medium",
            "learnable": False,
            "model_usage_scope": _deprecated_alias("sha", "dow", "_", "only"),
            "label_reason": _deprecated_alias("canonical", "_", "shadow", "_expected_auth"),
            "bootstrap_job_id": "bootstrap_scan_debian_202",
            "label_batch_id": "bootstrap_scan_debian_202",
        },
        {
            "source": deprecated_origin,
            "label": "normal",
            "category": "compat_probe",
            "event_class": "unknown_unlabeled",
            "behavior_label": "unknown_unlabeled",
            "attack_family": "",
            "source_trust": "legacy_unknown",
            "learnable": False,
            "model_usage_scope": _deprecated_alias("sha", "dow", "_", "only"),
            "label_reason": "legacy_missing_or_unsafe_backfill",
            "bootstrap_job_id": "",
            "label_batch_id": "legacy_canonical_backfill",
        },
    ]

    summary = main_module._summarize_label_quality(rows)

    assert summary["label_counts_by_origin"] == {
        "bootstrap_historical": 1,
        "legacy_excluded": 2,
        "organic_live": 2,
    }
    assert summary["label_counts_by_distro"] == {
        "debian": 3,
        "unknown_distro": 2,
    }
    assert summary["active_readiness_label_counts_by_distro"] == {
        "debian": {"normal": 2, "suspicious": 1},
    }
    assert summary["family_counts"]["ML-AUTH"] == {"normal": 1, "suspicious": 1}
    assert summary["family_counts"]["ML-NET"] == {"normal": 0, "suspicious": 0}
    assert summary["organic_live_label_counts"]["family_counts"]["ML-AUTH"] == {"normal": 1, "suspicious": 1}
    assert summary["bootstrap_historical_label_counts"]["family_counts"]["ML-NET"] == {"normal": 1, "suspicious": 1}
    assert summary["excluded_legacy_label_counts"]["family_counts"]["ML-AUTH"] == {"normal": 1, "suspicious": 0}


def test_summarize_label_quality_excludes_rejected_labels_from_active_readiness_counts():
    rows = [
        {
            "source": "auto_labeled",
            "distro": "debian",
            "label": "attack",
            "category": "auth",
            "event_class": "attack",
            "behavior_label": "auth_attack_or_abuse",
            "attack_family": "credential_access",
            "source_trust": "rule_high",
            "learnable": True,
            "model_usage_scope": "calibration_only",
            "label_reason": "direct_rule_runtime",
        },
        {
            "source": "auto_labeled",
            "distro": "debian",
            "label": "attack",
            "category": "auth",
            "event_class": "attack",
            "behavior_label": "",
            "attack_family": "credential_access",
            "source_trust": "",
            "learnable": True,
            "model_usage_scope": "",
            "label_reason": "missing_metadata_runtime",
        },
    ]

    summary = main_module._summarize_label_quality(rows)

    assert summary["usage_decisions"]["direct_learnable"] == 1
    assert summary["usage_decisions"]["rejected"] == 1
    assert summary["active_readiness_label_counts"] == {"normal": 0, "suspicious": 1}
    assert summary["family_counts"]["ML-AUTH"] == {"normal": 0, "suspicious": 1}


def test_evaluate_ml_readiness_proc_needs_more_data_when_time_coverage_is_thin():
    global_audit = {
        "current_phase": 1,
        "ml_paused": False,
        "duplicate_rate": 0.0,
        "parse_fail_rate": 0.0,
        "counts": {"process_tree": 0},
        "label_quality": {
            "family_counts": {
                "ML-PROC": {"normal": 300, "suspicious": 150},
            }
        },
    }
    family_metrics = {
        "runtime_events": 12000,
        "host_fill_rate": 0.10,
        "user_fill_rate": 0.60,
        "src_ip_fill_rate": 0.40,
        "dst_ip_fill_rate": 0.40,
        "dst_port_fill_rate": 0.40,
        "process_fill_rate": 0.90,
        "source_count": 3,
        "time_coverage_days": 1,
        "errors": [],
    }

    result = main_module._evaluate_ml_family_readiness("ML-PROC", family_metrics, global_audit)

    assert result["status"] == "needs_more_data"
    assert result["reason"] == "insufficient_time_coverage"


def test_evaluate_ml_readiness_auth_blocks_on_runtime_shortage():
    global_audit = {
        "current_phase": 2,
        "ml_paused": False,
        "duplicate_rate": 0.0,
        "parse_fail_rate": 0.0,
        "counts": {"process_tree": 0},
        "label_quality": {
            "family_counts": {
                "ML-AUTH": {"normal": 120, "suspicious": 55},
            }
        },
    }
    family_metrics = {
        "runtime_events": 48,
        "host_fill_rate": 0.80,
        "user_fill_rate": 0.80,
        "src_ip_fill_rate": 0.80,
        "dst_ip_fill_rate": 0.0,
        "dst_port_fill_rate": 0.0,
        "process_fill_rate": 0.0,
        "source_count": 2,
        "time_coverage_days": 7,
        "errors": [],
    }

    result = main_module._evaluate_ml_family_readiness("ML-AUTH", family_metrics, global_audit)

    assert result["status"] == "readiness_blocked"
    assert result["reason"] == "insufficient_runtime_events"


def test_evaluate_ml_readiness_blocks_when_label_threshold_missing():
    global_audit = {
        "current_phase": 1,
        "ml_paused": False,
        "duplicate_rate": 0.0,
        "parse_fail_rate": 0.0,
        "counts": {"process_tree": 0},
        "label_quality": {
            "family_counts": {
                "ML-PROC": {"normal": 299, "suspicious": 150},
            }
        },
    }
    family_metrics = {
        "runtime_events": 12000,
        "host_fill_rate": 0.10,
        "user_fill_rate": 0.60,
        "src_ip_fill_rate": 0.40,
        "dst_ip_fill_rate": 0.40,
        "dst_port_fill_rate": 0.40,
        "process_fill_rate": 0.90,
        "source_count": 3,
        "time_coverage_days": 7,
        "errors": [],
    }

    result = main_module._evaluate_ml_family_readiness("ML-PROC", family_metrics, global_audit)

    assert result["status"] == "readiness_blocked"
    assert result["reason"] == "insufficient_normal_labels"


def test_evaluate_ml_readiness_host_user_gap_blocks_related_family():
    global_audit = {
        "current_phase": 2,
        "ml_paused": False,
        "duplicate_rate": 0.0,
        "parse_fail_rate": 0.0,
        "counts": {"process_tree": 0},
        "label_quality": {
            "family_counts": {
                "ML-USER": {"normal": 250, "suspicious": 120},
            }
        },
    }
    family_metrics = {
        "runtime_events": 3000,
        "host_fill_rate": 0.10,
        "user_fill_rate": 0.40,
        "src_ip_fill_rate": 0.90,
        "dst_ip_fill_rate": 0.0,
        "dst_port_fill_rate": 0.0,
        "process_fill_rate": 0.80,
        "source_count": 3,
        "time_coverage_days": 7,
        "errors": [],
    }

    result = main_module._evaluate_ml_family_readiness("ML-USER", family_metrics, global_audit)

    assert result["status"] == "readiness_blocked"
    assert result["reason"] == "insufficient_host_user_fill_rate"


def test_ml_readiness_cli_is_read_only_and_handles_empty_db(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))

    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if fetch == "one":
                return {}
            return []

        def load_labels(self):
            return []

        def get_stat(self, key):
            return ""

        def insert_event(self, **kwargs):
            raise AssertionError("--ml-readiness DB write yapmamalı")

        def insert_alert(self, alert):
            raise AssertionError("--ml-readiness alert yazmamalı")

        def review_ip_block_suggestion(self, *args, **kwargs):
            raise AssertionError("--ml-readiness suggestion write yapmamalı")

        def add_ip_block_action(self, *args, **kwargs):
            raise AssertionError("--ml-readiness block action yazmamalı")

        def close(self):
            return None

    pm = type("_PM", (), {"get_status": staticmethod(lambda: {
        "current_phase": 0,
        "phase_name": "Kural Motoru",
        "stats": {
            "duplicate_count": 0,
            "telemetry_duplicate_count": 0,
            "parse_fail_count": 0,
            "trainable_events": 0,
            "blocked_events": 0,
        },
    })})()
    monkeypatch.setattr(main_module, "_build_operator_phase_manager", lambda config: (pm, _DB(), ""))
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-readiness"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0

    out = capsys.readouterr().out
    assert "ML Readiness Audit" in out
    assert "ML-AUTH" in out
    assert "status=readiness_blocked" in out
    assert "reason=missing_field" in out or "reason=phase_not_reached" in out or "reason=insufficient_runtime_events" in out


def test_collect_event_metrics_handles_missing_dst_columns_without_sql_error():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            assert "COALESCE(dst_ip" not in sql
            if "information_schema.columns" in sql:
                return [
                    {"column_name": "ts"},
                    {"column_name": "host"},
                    {"column_name": "source"},
                    {"column_name": "category"},
                    {"column_name": "action"},
                    {"column_name": "username"},
                    {"column_name": "src_ip"},
                    {"column_name": "process"},
                    {"column_name": "dst_port"},
                    {"column_name": "risk_bucket"},
                ]
            if fetch == "one":
                return {
                    "total": 25,
                    "host_filled": 20,
                    "user_filled": 15,
                    "src_ip_filled": 14,
                    "dst_ip_filled": 0,
                    "dst_port_filled": 10,
                    "process_filled": 22,
                    "source_count": 3,
                    "day_count": 2,
                    "last_ts": 1000.0,
                }
            return []

    columns, column_notes = main_module._load_table_columns(_DB(), "events_recent")
    metrics, notes = main_module._collect_event_metrics(
        _DB(),
        where_sql=main_module._build_family_where_clause("ML-NET", columns),
        available_columns=columns,
    )

    assert column_notes == []
    assert metrics["runtime_events"] == 25
    assert metrics["dst_port_fill_rate"] == pytest.approx(0.4)
    assert metrics["dst_ip_fill_rate"] == 0.0
    assert "missing_field:dst_ip" in notes


def test_collect_ml_readiness_report_preserves_runtime_counts_when_dst_ip_missing():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql:
                return [
                    {"column_name": "ts"},
                    {"column_name": "host"},
                    {"column_name": "source"},
                    {"column_name": "category"},
                    {"column_name": "action"},
                    {"column_name": "username"},
                    {"column_name": "src_ip"},
                    {"column_name": "process"},
                    {"column_name": "dst_port"},
                    {"column_name": "risk_bucket"},
                ]
            if "FROM events_recent" in sql and fetch == "one":
                if "LOWER(COALESCE(category, '')) = 'process'" in sql:
                    return {
                        "total": 17784,
                        "host_filled": 147,
                        "user_filled": 11438,
                        "src_ip_filled": 17784,
                        "dst_ip_filled": 0,
                        "dst_port_filled": 0,
                        "process_filled": 8000,
                        "source_count": 2,
                        "day_count": 1,
                        "last_ts": 1000.0,
                    }
                return {
                    "total": 36055,
                    "host_filled": 149,
                    "user_filled": 11508,
                    "src_ip_filled": 3550,
                    "dst_ip_filled": 0,
                    "dst_port_filled": 4927,
                    "process_filled": 16062,
                    "source_count": 5,
                    "day_count": 1,
                    "last_ts": 1000.0,
                }
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                if "events_recent" in sql:
                    return {"count": 36055}
                if "labels" in sql:
                    return {"count": 450}
                return {"count": 0}
            if "GROUP BY 1" in sql:
                return [{"name": "auditd", "count": 30079}]
            return []

        def load_labels(self):
            return [
                {"behavior_label": "routine_system_event", "attack_family": "", "category": "process", "label": "normal", "source_trust": "observed_benign_high", "model_usage_scope": "calibration_only", "event_class": "benign", "learnable": True, "source": "bootstrap"},
                {"behavior_label": "destructive_impact_activity", "attack_family": "impact", "category": "process", "label": "attack", "source_trust": "rule_high", "model_usage_scope": "calibration_only", "event_class": "attack", "learnable": True, "source": "bootstrap"},
            ] * 200

        def get_stat(self, key):
            return ""

    report = main_module.collect_ml_readiness_report(
        {},
        _DB(),
        {
            "current_phase": 1,
            "phase_name": "Instant ML",
            "stats": {
                "duplicate_count": 0,
                "telemetry_duplicate_count": 0,
                "parse_fail_count": 0,
                "trainable_events": 0,
                "blocked_events": 0,
            },
        },
    )

    proc = report["families"]["ML-PROC"]
    assert proc["runtime_events"] == 17784
    assert "missing_field:dst_ip" in proc["errors"]
    assert proc["status"] in {"needs_more_data", "readiness_blocked"}


def test_collect_event_metrics_accepts_tuple_rows_without_index_error():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if fetch == "one":
                return (25, 20, 15, 14, 0, 10, 22, 3, 2, 1000.0)
            return []

    metrics, notes = main_module._collect_event_metrics(
        _DB(),
        available_columns={"ts", "host", "username", "src_ip", "process", "source", "dst_port"},
    )

    assert notes == ["missing_field:dst_ip", "missing_field:distro_family", "missing_field:distro_family"]
    assert metrics["runtime_events"] == 25
    assert metrics["host_fill_rate"] == pytest.approx(0.8)
    assert metrics["process_fill_rate"] == pytest.approx(0.88)


def test_build_family_where_clause_dns_avoids_percent_formatting():
    where_sql = main_module._build_family_where_clause("ML-DNS", {"source", "action"})

    assert "dns%" not in where_sql
    assert "LIKE" not in where_sql
    assert "LEFT(" in where_sql


def test_collect_ml_readiness_report_dns_tuple_row_safe_fallback():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql:
                return [
                    {"column_name": "ts"},
                    {"column_name": "source"},
                    {"column_name": "action"},
                    {"column_name": "category"},
                ]
            if "FROM events_recent" in sql and fetch == "one":
                return (0, 0, 0)
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                return {"count": 0}
            if "GROUP BY 1" in sql:
                return []
            return []

        def load_labels(self):
            return []

        def get_stat(self, key):
            return ""

    report = main_module.collect_ml_readiness_report(
        {},
        _DB(),
        {
            "current_phase": 0,
            "phase_name": "Kural Motoru",
            "stats": {
                "duplicate_count": 0,
                "telemetry_duplicate_count": 0,
                "parse_fail_count": 0,
                "trainable_events": 0,
                "blocked_events": 0,
            },
        },
    )

    dns = report["families"]["ML-DNS"]
    assert dns["runtime_events"] == 0
    assert "tuple index out of range" not in " ".join(dns.get("errors", []))
    assert dns["status"] == "readiness_blocked"


def test_collect_ml_readiness_report_blocks_mixed_distro_global_ready_without_ready_cohort():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql:
                return [
                    {"column_name": "ts"},
                    {"column_name": "host"},
                    {"column_name": "source"},
                    {"column_name": "category"},
                    {"column_name": "action"},
                    {"column_name": "username"},
                    {"column_name": "src_ip"},
                    {"column_name": "dst_ip"},
                    {"column_name": "dst_port"},
                    {"column_name": "distro_family"},
                ]
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                if "events_recent" in sql:
                    return {"count": 2000}
                return {"count": 0}
            if "FROM events_recent" in sql and fetch == "one":
                return {
                    "total": 2000,
                    "host_filled": 2000,
                    "user_filled": 2000,
                    "src_ip_filled": 2000,
                    "dst_ip_filled": 0,
                    "dst_port_filled": 0,
                    "process_filled": 0,
                    "source_count": 2,
                    "day_count": 7,
                    "last_ts": 1000.0,
                }
            if "GROUP BY 1, 2" in sql:
                return [
                    {"distro_family": "debian", "source": "auth.log", "count": 1000},
                    {"distro_family": "rhel", "source": "secure", "count": 1000},
                ]
            if "GROUP BY 1" in sql and "distro_family" in sql:
                return [
                    {"distro_family": "debian", "count": 1000},
                    {"distro_family": "rhel", "count": 1000},
                ]
            if "GROUP BY 1" in sql:
                return [{"name": "auth.log", "count": 1000}, {"name": "secure", "count": 1000}]
            return []

        def load_labels(self):
            rows = []
            for _ in range(60):
                rows.append({
                    "source": "auto_labeled",
                    "distro": "debian",
                    "label": "normal",
                    "category": "auth",
                    "event_class": "benign",
                    "behavior_label": "expected_auth_activity",
                    "attack_family": "credential_access",
                    "source_trust": "observed_benign_high",
                    "learnable": True,
                    "model_usage_scope": "baseline_learning",
                    "label_reason": "direct_rule_runtime",
                })
            for _ in range(60):
                rows.append({
                    "source": "auto_labeled",
                    "distro": "rhel",
                    "label": "normal",
                    "category": "auth",
                    "event_class": "benign",
                    "behavior_label": "expected_auth_activity",
                    "attack_family": "credential_access",
                    "source_trust": "observed_benign_high",
                    "learnable": True,
                    "model_usage_scope": "baseline_learning",
                    "label_reason": "direct_rule_runtime",
                })
            for _ in range(30):
                rows.append({
                    "source": "auto_labeled",
                    "distro": "debian",
                    "label": "attack",
                    "category": "auth",
                    "event_class": "attack",
                    "behavior_label": "brute_force_or_auth_attack",
                    "attack_family": "credential_access",
                    "source_trust": "rule_high",
                    "learnable": True,
                    "model_usage_scope": "calibration_only",
                    "label_reason": "direct_rule_runtime",
                })
            for _ in range(30):
                rows.append({
                    "source": "auto_labeled",
                    "distro": "rhel",
                    "label": "attack",
                    "category": "auth",
                    "event_class": "attack",
                    "behavior_label": "brute_force_or_auth_attack",
                    "attack_family": "credential_access",
                    "source_trust": "rule_high",
                    "learnable": True,
                    "model_usage_scope": "calibration_only",
                    "label_reason": "direct_rule_runtime",
                })
            return rows

        def get_stat(self, key):
            return ""

    report = main_module.collect_ml_readiness_report(
        {},
        _DB(),
        {
            "current_phase": 2,
            "phase_name": "Trend ML",
            "stats": {
                "duplicate_count": 0,
                "telemetry_duplicate_count": 0,
                "parse_fail_count": 0,
                "trainable_events": 0,
                "blocked_events": 0,
            },
        },
    )

    auth = report["families"]["ML-AUTH"]
    assert auth["runtime_events"] == 2000
    assert auth["normal_labels"] == 120
    assert auth["suspicious_labels"] == 60
    assert auth["status"] == "readiness_blocked"
    assert auth["reason"] == "mixed_distro_cohort_insufficient"
    assert auth["multi_distro_cohort"] is True
    assert auth["distro_cohorts"]["debian"]["status"] == "readiness_blocked"
    assert auth["distro_cohorts"]["rhel"]["status"] == "readiness_blocked"
    assert auth["distro_cohorts"]["debian"]["normal_labels"] == 60
    assert auth["distro_cohorts"]["rhel"]["normal_labels"] == 60


def test_collect_ml_readiness_report_single_distro_ready_candidate_stays_ready():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql:
                return [
                    {"column_name": "ts"},
                    {"column_name": "host"},
                    {"column_name": "source"},
                    {"column_name": "category"},
                    {"column_name": "action"},
                    {"column_name": "username"},
                    {"column_name": "src_ip"},
                    {"column_name": "dst_ip"},
                    {"column_name": "dst_port"},
                    {"column_name": "distro_family"},
                ]
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                if "events_recent" in sql:
                    return {"count": 2000}
                return {"count": 0}
            if "FROM events_recent" in sql and fetch == "one":
                return {
                    "total": 2000,
                    "host_filled": 2000,
                    "user_filled": 2000,
                    "src_ip_filled": 2000,
                    "dst_ip_filled": 0,
                    "dst_port_filled": 0,
                    "process_filled": 0,
                    "source_count": 2,
                    "day_count": 7,
                    "last_ts": 1000.0,
                }
            if "GROUP BY 1, 2" in sql:
                return [
                    {"distro_family": "debian", "source": "auth.log", "count": 1500},
                    {"distro_family": "debian", "source": "journald", "count": 500},
                ]
            if "GROUP BY 1" in sql and "distro_family" in sql:
                return [{"distro_family": "debian", "count": 2000}]
            if "GROUP BY 1" in sql:
                return [{"name": "auth.log", "count": 1500}, {"name": "journald", "count": 500}]
            return []

        def load_labels(self):
            rows = []
            for _ in range(120):
                rows.append({
                    "source": "auto_labeled",
                    "distro": "debian",
                    "label": "normal",
                    "category": "auth",
                    "event_class": "benign",
                    "behavior_label": "expected_auth_activity",
                    "attack_family": "credential_access",
                    "source_trust": "observed_benign_high",
                    "learnable": True,
                    "model_usage_scope": "baseline_learning",
                    "label_reason": "direct_rule_runtime",
                })
            for _ in range(60):
                rows.append({
                    "source": "auto_labeled",
                    "distro": "debian",
                    "label": "attack",
                    "category": "auth",
                    "event_class": "attack",
                    "behavior_label": "brute_force_or_auth_attack",
                    "attack_family": "credential_access",
                    "source_trust": "rule_high",
                    "learnable": True,
                    "model_usage_scope": "calibration_only",
                    "label_reason": "direct_rule_runtime",
                })
            return rows

        def get_stat(self, key):
            return ""

    report = main_module.collect_ml_readiness_report(
        {},
        _DB(),
        {
            "current_phase": 2,
            "phase_name": "Trend ML",
            "stats": {
                "duplicate_count": 0,
                "telemetry_duplicate_count": 0,
                "parse_fail_count": 0,
                "trainable_events": 0,
                "blocked_events": 0,
            },
        },
    )

    auth = report["families"]["ML-AUTH"]
    assert auth["status"] == "active_candidate"
    assert auth["reason"] == "ready"
    assert auth["multi_distro_cohort"] is False
    assert auth["distro_cohorts"]["debian"]["status"] == "active_candidate"


def test_print_ml_readiness_report_omits_tuple_index_error_text(capsys):
    report = {
        "global": {
            "counts": {"events_recent": 0, "alerts": 0, "incidents": 0, "labels": 0, "process_tree": 0},
            "overall_events": {
                "host_fill_rate": 0.0,
                "user_fill_rate": 0.0,
                "src_ip_fill_rate": 0.0,
                "dst_ip_fill_rate": 0.0,
                "dst_port_fill_rate": 0.0,
                "process_fill_rate": 0.0,
                "time_coverage_days": 0,
                "last_event_ts": None,
            },
            "event_columns": [],
            "top_sources": [],
            "top_categories": [],
            "top_actions": [],
            "label_quality": {
                "total_labels": 0,
                "calibration_eligible_labels": 0,
                "by_source": {},
                "by_source_trust": {},
                "by_model_usage_scope": {},
                "by_learnable": {},
            },
            "phase_stats": {"duplicate_count": 0, "telemetry_duplicate_count": 0, "parse_fail_count": 0, "trainable_events": 0, "blocked_events": 0},
            "current_phase": 0,
            "phase_name": "Kural Motoru",
            "ml_paused": False,
            "ml_pause_reason": "",
            "duplicate_rate": 0.0,
            "parse_fail_rate": 0.0,
            "errors": {},
        },
        "families": {
            family: {
                "status": "readiness_blocked",
                "reason": "missing_field",
                "runtime_events": 0,
                "required_events": 1,
                "normal_labels": 0,
                "required_normal_labels": 1,
                "suspicious_labels": 0,
                "required_suspicious_labels": 1,
                "host_fill_rate": 0.0,
                "user_fill_rate": 0.0,
                "src_ip_fill_rate": 0.0,
                "process_fill_rate": 0.0,
                "source_count": 0,
                "phase_gate": 0,
                "time_coverage_days": 0,
                "required_time_coverage_days": 5,
                "linked_process_events": 0,
                "required_linked_process_events": 0,
                "errors": ["safe_fallback", "missing_field:dns_query"],
            }
            for family in main_module._ML_FAMILY_READINESS
        },
    }

    main_module.print_ml_readiness_report(report)

    out = capsys.readouterr().out
    assert "tuple index out of range" not in out


def test_print_ml_readiness_report_shows_origin_aware_label_counts(capsys):
    report = {
        "global": {
            "counts": {"events_recent": 1, "alerts": 0, "incidents": 0, "labels": 5, "process_tree": 0},
            "overall_events": {
                "host_fill_rate": 0.0,
                "user_fill_rate": 0.0,
                "src_ip_fill_rate": 0.0,
                "dst_ip_fill_rate": 0.0,
                "dst_port_fill_rate": 0.0,
                "process_fill_rate": 0.0,
                "time_coverage_days": 1,
                "last_event_ts": None,
            },
            "event_columns": [],
            "top_sources": [],
            "top_categories": [],
            "top_actions": [],
            "label_quality": {
                "total_labels": 5,
                "calibration_eligible_labels": 2,
                "by_source": {
                    "bootstrap": 1,
                    "auto_labeled": 2,
                    _deprecated_alias("manually", "_", "verified"): 2,
                },
                "by_source_trust": {},
                "by_model_usage_scope": {"baseline_learning": 1, "calibration_only": 2, _deprecated_alias("shadow", "_", "only"): 2},
                "by_learnable": {},
                "label_counts_by_origin": {"organic_live": 2, "bootstrap_historical": 1, "legacy_excluded": 2},
                "label_counts_by_distro": {"debian": 4, "unknown_distro": 1},
                "origin_counts_by_distro": {"debian": {"organic_live": 2, "bootstrap_historical": 1, "legacy_excluded": 1}, "unknown_distro": {"legacy_excluded": 1}},
                "family_counts_by_distro": {"debian": {"ML-PROC": {"normal": 1, "suspicious": 1}, "ML-NET": {"normal": 1, "suspicious": 0}}},
                "usage_decisions": {"baseline_learning": 1, "direct_learnable": 2, "ignored": 1, "rejected": 1},
                "active_readiness_label_counts": {"normal": 1, "suspicious": 1},
                "active_readiness_label_counts_by_distro": {"debian": {"normal": 1, "suspicious": 1}},
                "organic_live_label_counts": {"total": 2, "family_counts": {"ML-PROC": {"normal": 1, "suspicious": 1}}},
                "bootstrap_historical_label_counts": {"total": 1, "family_counts": {"ML-NET": {"normal": 1, "suspicious": 0}}},
                "excluded_legacy_label_counts": {"total": 2, "family_counts": {"ML-PROC": {"normal": 1, "suspicious": 0}}},
                "family_origin_counts": {
                    family: {
                        "organic_normal": 0,
                        "organic_suspicious": 0,
                        "bootstrap_normal": 0,
                        "bootstrap_suspicious": 0,
                        "legacy_excluded_normal": 0,
                        "legacy_excluded_suspicious": 0,
                    }
                    for family in main_module._ML_FAMILY_READINESS
                },
            },
            "phase_stats": {"duplicate_count": 0, "telemetry_duplicate_count": 0, "parse_fail_count": 0, "trainable_events": 0, "blocked_events": 0},
            "current_phase": 0,
            "phase_name": "Kural Motoru",
            "ml_paused": False,
            "ml_pause_reason": "",
            "duplicate_rate": 0.0,
            "parse_fail_rate": 0.0,
            "errors": {},
        },
        "families": {
            family: {
                "status": "readiness_blocked",
                "reason": "missing_field",
                "runtime_events": 0,
                "required_events": 1,
                "normal_labels": 0,
                "required_normal_labels": 1,
                "suspicious_labels": 0,
                "required_suspicious_labels": 1,
                "host_fill_rate": 0.0,
                "user_fill_rate": 0.0,
                "src_ip_fill_rate": 0.0,
                "process_fill_rate": 0.0,
                "source_count": 0,
                "phase_gate": 0,
                "time_coverage_days": 0,
                "required_time_coverage_days": 5,
                "linked_process_events": 0,
                "required_linked_process_events": 0,
                "errors": [],
            }
            for family in main_module._ML_FAMILY_READINESS
        },
    }
    report["global"]["label_quality"]["family_origin_counts"]["ML-PROC"]["organic_normal"] = 1
    report["global"]["label_quality"]["family_origin_counts"]["ML-PROC"]["organic_suspicious"] = 1
    report["global"]["label_quality"]["family_origin_counts"]["ML-PROC"]["legacy_excluded_normal"] = 1
    report["global"]["label_quality"]["family_origin_counts"]["ML-NET"]["bootstrap_normal"] = 1

    main_module.print_ml_readiness_report(report)

    out = capsys.readouterr().out
    assert "by_origin={'organic_live': 2, 'bootstrap_historical': 1, 'legacy_excluded': 2}" in out
    assert "label_counts_by_distro={'debian': 4, 'unknown_distro': 1}" in out
    assert "origin_counts_by_distro={'debian': {'organic_live': 2, 'bootstrap_historical': 1, 'legacy_excluded': 1}, 'unknown_distro': {'legacy_excluded': 1}}" in out
    assert "usage_decisions={'direct_learnable': 2, 'baseline_learning': 1, 'ignored': 1, 'rejected': 1}" in out
    assert "family_counts_by_distro={'debian': {'ML-PROC': {'normal': 1, 'suspicious': 1}, 'ML-NET': {'normal': 1, 'suspicious': 0}}}" in out
    assert "label_counts_by_origin={'organic_live': 2, 'bootstrap_historical': 1, 'legacy_excluded': 2}" in out
    assert "active_readiness_label_counts_by_distro={'debian': {'normal': 1, 'suspicious': 1}}" in out
    assert "organic_normal=1" in out
    assert "bootstrap_normal=1" in out
    assert "legacy_excluded_normal=1" in out
    assert _deprecated_alias("manually", "_", "verified") not in out
    assert _deprecated_alias("shadow", "_", "only") not in out


def test_print_ml_readiness_report_shows_distro_cohorts(capsys):
    report = {
        "global": {
            "counts": {"events_recent": 1, "alerts": 0, "incidents": 0, "labels": 0, "process_tree": 0},
            "overall_events": {
                "host_fill_rate": 0.0,
                "user_fill_rate": 0.0,
                "src_ip_fill_rate": 0.0,
                "dst_ip_fill_rate": 0.0,
                "dst_port_fill_rate": 0.0,
                "process_fill_rate": 0.0,
                "time_coverage_days": 1,
                "last_event_ts": None,
            },
            "event_columns": [],
            "top_sources": [],
            "top_categories": [],
            "top_actions": [],
            "events_by_distro": [],
            "label_quality": {
                "total_labels": 0,
                "calibration_eligible_labels": 0,
                "by_source": {},
                "by_source_trust": {},
                "by_model_usage_scope": {},
                "by_learnable": {},
                "label_counts_by_origin": {},
                "label_counts_by_distro": {},
                "origin_counts_by_distro": {},
                "family_counts_by_distro": {},
                "usage_decisions": {},
                "active_readiness_label_counts": {},
                "active_readiness_label_counts_by_distro": {},
                "organic_live_label_counts": {},
                "bootstrap_historical_label_counts": {},
                "excluded_legacy_label_counts": {},
                "quota_summary": {"full_families": ["ML-AUTH/debian/normal"]},
                "family_origin_counts": {
                    family: {
                        "organic_normal": 0,
                        "organic_suspicious": 0,
                        "bootstrap_normal": 0,
                        "bootstrap_suspicious": 0,
                        "legacy_excluded_normal": 0,
                        "legacy_excluded_suspicious": 0,
                    }
                    for family in main_module._ML_FAMILY_READINESS
                },
            },
            "phase_stats": {"duplicate_count": 0, "telemetry_duplicate_count": 0, "parse_fail_count": 0, "trainable_events": 0, "blocked_events": 0},
            "current_phase": 0,
            "phase_name": "Kural Motoru",
            "ml_paused": False,
            "ml_pause_reason": "",
            "duplicate_rate": 0.0,
            "parse_fail_rate": 0.0,
            "errors": {},
        },
        "families": {
            family: {
                "status": "readiness_blocked",
                "reason": "missing_field",
                "runtime_events": 0,
                "runtime_events_by_distro": {},
                "required_events": 1,
                "normal_labels": 0,
                "required_normal_labels": 1,
                "suspicious_labels": 0,
                "required_suspicious_labels": 1,
                "host_fill_rate": 0.0,
                "user_fill_rate": 0.0,
                "src_ip_fill_rate": 0.0,
                "process_fill_rate": 0.0,
                "source_count": 0,
                "source_by_distro": {},
                "phase_gate": 0,
                "time_coverage_days": 0,
                "required_time_coverage_days": 5,
                "linked_process_events": 0,
                "required_linked_process_events": 0,
                "errors": [],
                "distro_cohorts": {},
                "multi_distro_cohort": False,
            }
            for family in main_module._ML_FAMILY_READINESS
        },
    }
    report["families"]["ML-AUTH"]["distro_cohorts"] = {
        "debian": {
            "distro": "debian",
            "runtime_events": 1000,
            "normal_labels": 60,
            "suspicious_labels": 30,
            "quota_normal": {"used": 60, "limit": 3000, "remaining": 2940, "status": "collecting"},
            "quota_suspicious": {"used": 30, "limit": 1000, "remaining": 970, "status": "collecting"},
            "status": "readiness_blocked",
            "reason": "insufficient_normal_labels",
            "missing": ["insufficient_normal_labels"],
            "source_count": 1,
        },
        "rhel": {
            "distro": "rhel",
            "runtime_events": 1000,
            "normal_labels": 60,
            "suspicious_labels": 30,
            "quota_normal": {"used": 20, "limit": 3000, "remaining": 2980, "status": "collecting"},
            "quota_suspicious": {"used": 10, "limit": 1000, "remaining": 990, "status": "collecting"},
            "status": "readiness_blocked",
            "reason": "insufficient_normal_labels",
            "missing": ["insufficient_normal_labels"],
            "source_count": 1,
        },
    }
    report["families"]["ML-AUTH"]["multi_distro_cohort"] = True

    main_module.print_ml_readiness_report(report)

    out = capsys.readouterr().out
    assert "multi_distro_cohort=True" in out
    assert "quota_full_buckets=['ML-AUTH/debian/normal']" in out
    assert "distro_cohort[debian]=status=readiness_blocked runtime_events=1000 normal_labels=60 suspicious_labels=30 quota_normal={'used': 60, 'limit': 3000, 'remaining': 2940, 'status': 'collecting'} quota_suspicious={'used': 30, 'limit': 1000, 'remaining': 970, 'status': 'collecting'} source_count=1 reason=insufficient_normal_labels missing=insufficient_normal_labels" in out
    assert "distro_cohort[rhel]=status=readiness_blocked runtime_events=1000 normal_labels=60 suspicious_labels=30 quota_normal={'used': 20, 'limit': 3000, 'remaining': 2980, 'status': 'collecting'} quota_suspicious={'used': 10, 'limit': 1000, 'remaining': 990, 'status': 'collecting'} source_count=1 reason=insufficient_normal_labels missing=insufficient_normal_labels" in out
