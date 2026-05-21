from __future__ import annotations

import json


def _print_read_only_diagnostic(title: str, report: dict) -> None:
    print(f"\n{'━'*58}")
    print(f"  {title}")
    print(f"{'━'*58}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    print(f"{'━'*58}\n")


def run_diagnose_parse_fail(config: dict, *, build_operator_phase_manager, collect_parse_fail_diagnostics) -> int:
    pm, db, _db_error = build_operator_phase_manager(config)
    try:
        report = collect_parse_fail_diagnostics(config, db, pm.get_status())
        _print_read_only_diagnostic("Parse Fail Diagnostics", report)
    finally:
        if db:
            db.close()
    return 0


def run_diagnose_event_growth(config: dict, *, build_operator_phase_manager, collect_event_growth_diagnostics) -> int:
    pm, db, _db_error = build_operator_phase_manager(config)
    try:
        report = collect_event_growth_diagnostics(config, db, pm.get_status())
        _print_read_only_diagnostic("Event Growth Diagnostics", report)
    finally:
        if db:
            db.close()
    return 0
