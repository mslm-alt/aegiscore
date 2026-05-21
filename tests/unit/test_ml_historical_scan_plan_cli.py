import pytest

import main as main_module


def test_historical_scan_plan_target_met_and_needed_zero():
    report = main_module.collect_ml_historical_scan_plan(
        {},
        None,
        {"current_phase": 0, "phase_name": "Kural Motoru", "stats": {}},
    )
    assert report["families"]["ML-AUTH"]["labels"]["ssh_login_normal"]["status"] == "missing_schema"


def test_historical_scan_plan_counts_targets_separately_with_schema_safe_db():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("events_recent",):
                return [{"column_name": c} for c in ("ts", "category", "action", "source", "username", "host", "process", "src_ip")]
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in ("behavior_label", "source", "source_trust", "model_usage_scope", "learnable")]
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                return {"count": 0}
            if "FROM events_recent" in sql and fetch == "one":
                if "LOWER(COALESCE(category, '')) = 'process'" in sql:
                    return {"total": 320, "host_filled": 300, "user_filled": 300, "src_ip_filled": 320, "dst_ip_filled": 0, "dst_port_filled": 0, "process_filled": 320, "source_count": 2, "day_count": 2, "last_ts": 1000.0}
                if "LOWER(COALESCE(category, '')) = 'auth'" in sql:
                    return {"total": 20, "host_filled": 20, "user_filled": 18, "src_ip_filled": 15, "dst_ip_filled": 0, "dst_port_filled": 0, "process_filled": 10, "source_count": 1, "day_count": 1, "last_ts": 1000.0}
                return {"total": 0, "host_filled": 0, "user_filled": 0, "src_ip_filled": 0, "dst_ip_filled": 0, "dst_port_filled": 0, "process_filled": 0, "source_count": 0, "day_count": 0, "last_ts": None}
            if "GROUP BY 1" in sql:
                return []
            return []

        def load_labels(self):
            return (
                [{"behavior_label": "process_normal"}] * 300
                + [{"behavior_label": "suspicious_process"}] * 44
                + [{"behavior_label": "ssh_login_normal"}] * 12
                + [{"behavior_label": "auth_attack_or_abuse"}] * 22
            )

        def get_stat(self, key):
            return ""

        def close(self):
            return None

    report = main_module.collect_ml_historical_scan_plan(
        {},
        _DB(),
        {
            "current_phase": 1,
            "phase_name": "Instant ML",
            "stats": {
                "duplicate_count": 0,
                "telemetry_duplicate_count": 0,
                "parse_fail_count": 0,
            },
        },
    )

    proc_normal = report["families"]["ML-PROC"]["labels"]["process_normal"]
    proc_susp = report["families"]["ML-PROC"]["labels"]["suspicious_process"]
    auth_normal = report["families"]["ML-AUTH"]["labels"]["ssh_login_normal"]
    assert proc_normal["found"] == 300
    assert proc_normal["status"] == "target_met_stop_scan"
    assert proc_normal["needed"] == 0
    assert proc_susp["found"] == 44
    assert proc_susp["status"] == "needs_more_data"
    assert proc_susp["needed"] == 106
    assert auth_normal["found"] == 12
    assert auth_normal["status"] == "needs_more_data"


def test_historical_scan_plan_label_schema_missing_does_not_crash():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("events_recent",):
                return [{"column_name": c} for c in ("ts", "category", "action", "source")]
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": "source"}]
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                return {"count": 0}
            if "FROM events_recent" in sql and fetch == "one":
                return {"total": 0, "host_filled": 0, "user_filled": 0, "src_ip_filled": 0, "dst_ip_filled": 0, "dst_port_filled": 0, "process_filled": 0, "source_count": 0, "day_count": 0, "last_ts": None}
            if "GROUP BY 1" in sql:
                return []
            return []

        def get_stat(self, key):
            return ""

    report = main_module.collect_ml_historical_scan_plan(
        {},
        _DB(),
        {"current_phase": 0, "phase_name": "Kural Motoru", "stats": {}},
    )
    item = report["families"]["ML-AUTH"]["labels"]["ssh_login_normal"]
    assert item["status"] == "missing_schema"
    assert "no_family_label_columns" in report["families"]["ML-AUTH"]["query_notes"]


def test_historical_scan_plan_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_historical_scan_plan", lambda config: print("ML Historical Scan Plan\nML-AUTH") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-historical-scan-plan"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "ML Historical Scan Plan" in out
    assert "ML-AUTH" in out
