import pytest

import main as main_module


def test_normal_plan_rule_or_ioc_like_event_is_rejected():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("events_recent",):
                return [{"column_name": c} for c in ("ts", "action", "outcome", "source", "username", "src_ip", "trainable", "risk_bucket")]
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": "behavior_label"}]
            if "FROM events_recent" in sql and fetch == "one":
                if "AND NOT ((trainable = 1) AND (LOWER(COALESCE(risk_bucket, '')) = 'normal'))" in sql:
                    return {"count": 2}
                if "trainable = 1" in sql and "LOWER(COALESCE(risk_bucket, '')) = 'normal'" in sql:
                    return {"count": 0}
                if "LOWER(COALESCE(action, '')) = 'ssh_login'" in sql:
                    return {"count": 2}
                return {"count": 0}
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                return {"count": 0}
            if "GROUP BY 1" in sql:
                return []
            return []

        def load_labels(self):
            return []

        def get_stat(self, key):
            return ""

        def get_open_incidents(self):
            return []

    report = main_module.collect_ml_normal_label_plan({}, _DB(), {"current_phase": 0, "phase_name": "Kural", "stats": {}})
    item = report["families"]["ML-AUTH"]["labels"]["ssh_login_normal"]
    assert item["behavioral_baseline_candidate_count"] == 0
    assert item["rejection_reasons"]["rule_or_ioc_or_non_trainable"] == 2
    assert item["candidate_count_by_distro"] == {"unknown_distro": 2}
    assert item["rejected_count_by_distro"] == {"unknown_distro": 2}


def test_normal_plan_blocked_by_high_incident():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("events_recent",):
                return [{"column_name": c} for c in ("ts", "action", "outcome", "source", "username", "src_ip", "trainable", "risk_bucket")]
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": "behavior_label"}]
            if "FROM events_recent" in sql and fetch == "one":
                if "LOWER(COALESCE(action, '')) = 'ssh_login'" in sql:
                    return {"count": 4}
                return {"count": 0}
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                return {"count": 0}
            if "GROUP BY 1" in sql:
                return []
            return []

        def load_labels(self):
            return []

        def get_stat(self, key):
            return ""

        def get_open_incidents(self):
            return [{"severity": "high"}]

    report = main_module.collect_ml_normal_label_plan({}, _DB(), {"current_phase": 0, "phase_name": "Kural", "stats": {}})
    item = report["families"]["ML-AUTH"]["labels"]["ssh_login_normal"]
    assert item["status"] == "blocked_by_incident_or_pause"


def test_normal_plan_pause_blocks_candidates():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("events_recent",):
                return [{"column_name": c} for c in ("ts", "action", "outcome", "source", "username", "src_ip", "trainable", "risk_bucket")]
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": "behavior_label"}]
            if "FROM events_recent" in sql and fetch == "one":
                if "LOWER(COALESCE(action, '')) = 'ssh_login'" in sql:
                    return {"count": 4}
                return {"count": 0}
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                return {"count": 0}
            if "GROUP BY 1" in sql:
                return []
            return []

        def load_labels(self):
            return []

        def get_stat(self, key):
            if key == "ml_control_state":
                return '{"paused": true, "pause_reason": "maintenance: patching"}'
            return ""

        def get_open_incidents(self):
            return []

    report = main_module.collect_ml_normal_label_plan({}, _DB(), {"current_phase": 0, "phase_name": "Kural", "stats": {}})
    item = report["families"]["ML-AUTH"]["labels"]["ssh_login_normal"]
    assert item["status"] == "blocked_by_incident_or_pause"


def test_normal_plan_repeated_clean_event_is_accepted_and_target_met_stops_scan():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("events_recent",):
                return [{"column_name": c} for c in ("ts", "category", "action", "source", "process", "trainable", "risk_bucket")]
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": "behavior_label"}]
            if "FROM events_recent" in sql and fetch == "one":
                if "LOWER(COALESCE(category, '')) = 'process'" in sql:
                    return {"count": 4}
                return {"count": 0}
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                return {"count": 0}
            if "GROUP BY 1" in sql:
                return []
            return []

        def load_labels(self):
            return [{"behavior_label": "process_normal"}] * 300

        def get_stat(self, key):
            return ""

        def get_open_incidents(self):
            return []

    report = main_module.collect_ml_normal_label_plan({}, _DB(), {"current_phase": 1, "phase_name": "Instant ML", "stats": {}})
    item = report["families"]["ML-PROC"]["labels"]["process_normal"]
    assert item["needed"] == 0
    assert item["status"] == "target_already_met_stop_scan"


def test_normal_plan_missing_schema_and_empty_db_are_safe():
    report = main_module.collect_ml_normal_label_plan({}, None, {"current_phase": 0, "phase_name": "Kural", "stats": {}})
    item = report["families"]["ML-AUTH"]["labels"]["ssh_login_normal"]
    assert item["status"] == "missing_schema"


def test_normal_plan_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_normal_label_plan", lambda config: print("ML Normal Label Plan\nML-AUTH") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-normal-label-plan"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "ML Normal Label Plan" in out


def test_normal_plan_prints_distro_breakdown(capsys):
    report = {
        "global": {
            "ml_paused": False,
            "ml_pause_reason": "",
            "blocking_incident": False,
            "global_quality_ok": True,
            "candidate_count_by_distro": {"debian": 10, "unknown_distro": 2},
            "family_candidate_count_by_distro": {"debian": {"ML-AUTH": 10}},
            "rejected_count_by_distro": {"debian": 8, "unknown_distro": 2},
            "query_notes": {},
        },
        "families": {
            "ML-AUTH": {
                "candidate_count_by_distro": {"debian": 10},
                "query_notes": [],
                "labels": {
                    "ssh_login_normal": {
                        "existing_found": 0,
                        "required": 100,
                        "needed": 100,
                        "candidate_count": 10,
                        "candidate_count_by_distro": {"debian": 10},
                        "behavioral_baseline_candidate_count": 2,
                        "behavioral_baseline_candidate_count_by_distro": {"debian": 2},
                        "rejected_candidate_count": 8,
                        "rejected_count_by_distro": {"debian": 8},
                        "status": "clean_candidates_available",
                        "rejection_reasons": {"rule_or_ioc_or_non_trainable": 8},
                    }
                },
            }
        },
    }

    main_module.print_ml_normal_label_plan(report)

    out = capsys.readouterr().out
    assert "candidate_count_by_distro={'debian': 10, 'unknown_distro': 2}" in out
    assert "family_candidate_count_by_distro={'debian': {'ML-AUTH': 10}}" in out
    assert "rejected_count_by_distro={'debian': 8, 'unknown_distro': 2}" in out


def test_normal_plan_closed_incident_entity_residue_is_excluded_from_host_candidates(monkeypatch):
    monkeypatch.setattr(main_module, "_collect_global_ml_audit", lambda db, pm_status: {
        "event_columns": ["ts", "host", "source", "message", "trainable", "risk_bucket"],
        "ml_paused": False,
        "ml_pause_reason": "",
        "duplicate_rate": 0.0,
        "parse_fail_rate": 0.0,
        "errors": {},
    })

    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": "behavior_label"}]
            if "GROUP BY 1" in sql:
                return []
            return []

        def load_labels(self):
            return []

        def get_stat(self, key):
            return ""

        def get_open_incidents(self):
            return []

    monkeypatch.setattr(main_module, "_load_closed_incident_entities", lambda db: (["192.168.1.182"], []))

    def _fake_safe_count(_db, where_sql, _cols):
        if "NULLIF(BTRIM(COALESCE(host" in where_sql and "AND NOT (" not in where_sql and "trainable = 1" not in where_sql:
            return 5, []
        if "AND NOT ((trainable = 1)" in where_sql:
            return 0, []
        if "AND NOT (LOWER(COALESCE(source, '')) IN" in where_sql:
            return 0, []
        if "AND NOT (NOT (" in where_sql and "192.168.1.182" in where_sql:
            return 4, []
        if "192.168.1.182" in where_sql and "trainable = 1" in where_sql and "AND NOT (" not in where_sql:
            return 1, []
        return 0, []

    monkeypatch.setattr(main_module, "_safe_count_where", _fake_safe_count)

    report = main_module.collect_ml_normal_label_plan({}, _DB(), {"current_phase": 1, "phase_name": "Instant ML", "stats": {}})
    item = report["families"]["ML-HOST"]["labels"]["host_behavior_normal"]
    assert item["candidate_count"] == 5
    assert item["behavioral_baseline_candidate_count"] == 0
    assert item["rejected_candidate_count"] == 5
    assert item["rejection_reasons"]["closed_incident_entity_residue"] == 4
    assert item["rejection_reasons"]["repeated_behavior_insufficient"] == 1


def test_normal_plan_invalid_network_peer_feature_is_rejected(monkeypatch):
    monkeypatch.setattr(main_module, "_collect_global_ml_audit", lambda db, pm_status: {
        "event_columns": ["ts", "category", "source", "src_ip", "dst_port", "trainable", "risk_bucket"],
        "ml_paused": False,
        "ml_pause_reason": "",
        "duplicate_rate": 0.0,
        "parse_fail_rate": 0.0,
        "errors": {},
    })

    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": "behavior_label"}]
            if "GROUP BY 1" in sql:
                return []
            return []

        def load_labels(self):
            return []

        def get_stat(self, key):
            return ""

        def get_open_incidents(self):
            return []

    monkeypatch.setattr(main_module, "_load_closed_incident_entities", lambda db: ([], []))

    def _fake_safe_count(_db, where_sql, _cols):
        if "LOWER(COALESCE(category, '')) = 'network'" in where_sql and "AND NOT (" not in where_sql and "trainable = 1" not in where_sql:
            return 10, []
        if "AND NOT ((trainable = 1)" in where_sql:
            return 0, []
        if "AND NOT (LOWER(COALESCE(source, '')) IN" in where_sql:
            return 0, []
        if "AND NOT (NULLIF(BTRIM(COALESCE(src_ip::text" in where_sql:
            return 0, []
        if "dst_port <> 0" in where_sql and "AND NOT (" in where_sql:
            return 10, []
        return 0, []

    monkeypatch.setattr(main_module, "_safe_count_where", _fake_safe_count)

    report = main_module.collect_ml_normal_label_plan({}, _DB(), {"current_phase": 1, "phase_name": "Instant ML", "stats": {}})
    item = report["families"]["ML-NET"]["labels"]["normal_network"]
    assert item["candidate_count"] == 10
    assert item["behavioral_baseline_candidate_count"] == 0
    assert item["rejected_candidate_count"] == 10
    assert item["rejection_reasons"]["invalid_network_peer_feature"] == 10


def test_normal_plan_service_noise_is_rejected_and_summary_is_consistent(monkeypatch):
    monkeypatch.setattr(main_module, "_collect_global_ml_audit", lambda db, pm_status: {
        "event_columns": ["ts", "category", "action", "source", "host", "process", "message", "trainable", "risk_bucket"],
        "ml_paused": False,
        "ml_pause_reason": "",
        "duplicate_rate": 0.0,
        "parse_fail_rate": 0.0,
        "errors": {},
    })

    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": "behavior_label"}]
            if "GROUP BY 1" in sql:
                return []
            return []

        def load_labels(self):
            return []

        def get_stat(self, key):
            return ""

        def get_open_incidents(self):
            return []

    monkeypatch.setattr(main_module, "_load_closed_incident_entities", lambda db: ([], []))
    monkeypatch.setattr(
        main_module,
        "_build_family_candidate_quality_filters",
        lambda db, family_id, label_name, available_columns: (
            [("non_service_event", "service_noise_clause")] if family_id == "ML-SERVICE" and label_name == "service_normal" else [],
            [],
        ),
    )

    def _fake_safe_count(_db, where_sql, _cols):
        if "LOWER(COALESCE(category, '')) IN ('system', 'service')" in where_sql and "AND NOT (" not in where_sql and "trainable = 1" not in where_sql:
            return 40, []
        if "AND NOT ((trainable = 1)" in where_sql:
            return 0, []
        if "AND NOT (LOWER(COALESCE(source, '')) IN" in where_sql:
            return 0, []
        if "AND NOT (NULLIF(BTRIM(COALESCE(host::text" in where_sql:
            return 0, []
        if "service_noise_clause" in where_sql and "AND NOT (" in where_sql:
            return 40, []
        return 0, []

    monkeypatch.setattr(main_module, "_safe_count_where", _fake_safe_count)

    report = main_module.collect_ml_normal_label_plan({}, _DB(), {"current_phase": 1, "phase_name": "Instant ML", "stats": {}})
    item = report["families"]["ML-SERVICE"]["labels"]["service_normal"]
    assert item["candidate_count"] == 40
    assert item["behavioral_baseline_candidate_count"] == 0
    assert item["rejected_candidate_count"] == 40
    assert item["rejection_reasons"] == {"non_service_event": 40}


def test_normal_plan_process_noise_is_trimmed(monkeypatch):
    monkeypatch.setattr(main_module, "_collect_global_ml_audit", lambda db, pm_status: {
        "event_columns": ["ts", "category", "source", "process", "message", "trainable", "risk_bucket"],
        "ml_paused": False,
        "ml_pause_reason": "",
        "duplicate_rate": 0.0,
        "parse_fail_rate": 0.0,
        "errors": {},
    })

    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": "behavior_label"}]
            if "GROUP BY 1" in sql:
                return []
            return []

        def load_labels(self):
            return []

        def get_stat(self, key):
            return ""

        def get_open_incidents(self):
            return []

    monkeypatch.setattr(main_module, "_load_closed_incident_entities", lambda db: ([], []))

    def _fake_safe_count(_db, where_sql, _cols):
        if "LOWER(COALESCE(category, '')) = 'process'" in where_sql and "AND NOT (" not in where_sql and "trainable = 1" not in where_sql:
            return 100, []
        if "AND NOT ((trainable = 1)" in where_sql:
            return 0, []
        if "AND NOT (LOWER(COALESCE(source, '')) IN" in where_sql:
            return 0, []
        if "AND NOT (NULLIF(BTRIM(COALESCE(process::text" in where_sql:
            return 0, []
        if "NOT (POSITION('nmap'" in where_sql:
            return 20, []
        if "pg_isready" in where_sql and "AND NOT (" in where_sql:
            return 80, []
        return 0, []

    monkeypatch.setattr(main_module, "_safe_count_where", _fake_safe_count)

    report = main_module.collect_ml_normal_label_plan({}, _DB(), {"current_phase": 1, "phase_name": "Instant ML", "stats": {}})
    item = report["families"]["ML-PROC"]["labels"]["process_normal"]
    assert item["candidate_count"] == 100
    assert item["behavioral_baseline_candidate_count"] == 20
    assert item["rejected_candidate_count"] == 80
    assert item["rejection_reasons"]["low_value_process_noise"] == 80
