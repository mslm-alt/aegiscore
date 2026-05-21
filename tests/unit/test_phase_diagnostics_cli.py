import main as main_module


def test_collect_parse_fail_diagnostics_exposes_breakdowns_and_samples(monkeypatch):
    monkeypatch.setattr(
        main_module,
        "_source_ownership_report",
        lambda config: {
            "distro_family": "debian",
            "sources": {"auth": {"status": "ok", "path": "/var/log/auth.log", "reason": ""}},
            "shared_paths": [],
            "notes": [],
        },
    )

    report = main_module.collect_parse_fail_diagnostics(
        {"sources": {"auth": {"enabled": True, "type": "file", "path": "/var/log/auth.log"}}},
        None,
        {
            "stats": {
                "parse_fail_count": 3,
                "parse_fail_rate": 0.12,
                "parse_fail_breakdown_by_source": {"auth": 3},
                "parse_fail_breakdown_by_reason": {"normalize_none": 3},
                "parse_fail_breakdown_by_parser": {"file": 3},
                "parse_fail_breakdown_by_distro": {"debian": 3},
                "parse_fail_breakdown_by_path": {"/var/log/auth.log": 3},
                "parse_fail_samples": [{"source": "auth", "sample": "token=***"}],
            }
        },
    )

    assert report["total_parse_fail_count"] == 3
    assert report["normalize_none_count"] == 3
    assert report["by_parser"] == {"file": 3}
    assert report["by_distro_family"] == {"debian": 3}
    assert report["by_path"] == {"/var/log/auth.log": 3}
    assert report["samples"] == [{"source": "auth", "sample": "token=***"}]
    assert report["source_ownership"]["distro_family"] == "debian"
    assert report["no_action_contract"] is True


def test_collect_event_growth_diagnostics_separates_phase_and_live_counts(monkeypatch):
    monkeypatch.setattr(
        main_module,
        "_collect_global_ml_audit",
        lambda db, pm_status, config=None: {
            "overall_events": {
                "runtime_events": 500,
                "source_by_distro": {"debian": {"auth": 300, "syslog": 200}},
            },
            "top_sources": {"auth": 300, "syslog": 200},
            "top_categories": {"auth_normal": 280, "process": 220},
            "top_actions": {"ssh_login": 250, "sudo": 120},
            "events_by_distro": {"debian": 500},
            "phase_stats": {
                "total_events": 5200,
                "phase_event_count": 5200,
                "duplicate_count": 120,
                "telemetry_duplicate_count": 33,
                "parse_fail_count": 40,
                "source_counts": {"auth": 3100, "system": 2100},
            },
            "duplicate_rate": 0.03,
            "parse_fail_rate": 0.01,
            "errors": {},
        },
    )
    monkeypatch.setattr(
        main_module,
        "_source_ownership_report",
        lambda config: {
            "distro_family": "debian",
            "sources": {"auth": {"status": "ok", "path": "/var/log/auth.log", "reason": ""}},
            "shared_paths": [{"path": "/var/log/messages", "sources": ["syslog", "dns"], "count": 2}],
            "notes": [],
        },
    )

    report = main_module.collect_event_growth_diagnostics({}, None, {"stats": {"total_events": 5200}})

    assert report["status"] == "phase_lifetime_exceeds_live_window"
    assert report["event_counter_scope"] == "phase_lifetime_normalized_events"
    assert report["live_window_scope"] == "events_recent_runtime_window"
    assert report["phase_lifetime_event_count"] == 5200
    assert report["live_window_event_count"] == 500
    assert report["estimated_non_live_window_events"] == 4700
    assert report["top_sources"][0] == {"name": "auth", "count": 300}
    assert report["source_ownership"]["shared_paths"][0]["count"] == 2
    assert report["historical_scan_is_runtime_counter_source"] is False
    assert report["no_action_contract"] is True
