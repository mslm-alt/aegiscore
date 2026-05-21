from core.formatters import fmt_phase_status


def test_phase_status_localizes_to_english(capsys):
    status = {
        "current_phase": 0,
        "phase_name": "Rule Engine",
        "description": "Read-only detection layer",
        "stats": {
            "uptime_days": 1.0,
            "uptime_hours": 24.0,
            "total_events": 10,
            "unique_users": 2,
            "unique_ips": 3,
            "duplicate_count": 0,
            "duplicate_breakdown_by_source": {},
            "duplicate_breakdown_by_kind": {},
            "parse_fail_count": 0,
            "parse_fail_breakdown_by_source": {},
            "parse_fail_breakdown_by_reason": {},
        },
        "next_phase": {"next_phase": 1, "next_name": "ML", "progress_pct": 10, "criteria": []},
        "active_layers": {"rules": True, "ml": False},
    }

    fmt_phase_status(status, language="en")
    out = capsys.readouterr().out

    assert "System Phase Status" in out
    assert "Current Phase" in out
    assert "Description" in out
    assert "Next" in out
    assert "Mevcut Faz" not in out
