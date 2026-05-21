from __future__ import annotations

import json

from core.report import ReportEngine
from core.state_manager import RuntimeStateStore, get_state_metrics


def print_metrics(db, config: dict) -> None:
    rt = RuntimeStateStore(state_dir="data").status()
    summary = {
        "health": db.health_check(),
        "last_hour": db.get_alert_count(hours=1),
        "last_24h": db.get_alert_count(hours=24),
        "open_incidents": len(db.get_open_incidents()),
        "state": get_state_metrics().status(),
        "runtime": {
            "startup_mode": rt.get("startup_mode", "fresh_start"),
            "last_shutdown_clean": rt.get("last_shutdown_clean", True),
            "runtime_restore_health": rt.get("runtime_restore_health", {}),
        },
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))


def run_metrics_cli(config: dict, *, ensure_database) -> int:
    db = ensure_database(config)
    try:
        print_metrics(db, config)
        return 0
    finally:
        db.close()


def run_status_cli(config: dict, *, build_operator_phase_manager, output_language, fmt_phase_status) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        if db:
            summary = {
                "last_hour": db.get_alert_count(hours=1),
                "last_24h": db.get_alert_count(hours=24),
                "open_incidents": len(db.get_open_incidents()),
                "health": db.health_check(),
            }
        else:
            summary = {
                "last_hour": None,
                "last_24h": None,
                "open_incidents": None,
                "health": {
                    "ok": False,
                    "status": "offline_snapshot",
                    "detail": db_error or "DB erişilemedi; snapshot fallback kullanılıyor.",
                },
            }
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        fmt_phase_status(pm.get_status(), language=output_language(config))
        return 0
    finally:
        if db:
            db.close()


def run_phase_cli(config: dict, *, build_operator_phase_manager, output_language, fmt_phase_status) -> int:
    pm, db, _db_error = build_operator_phase_manager(config)
    try:
        fmt_phase_status(pm.get_status(), language=output_language(config))
        return 0
    finally:
        if db:
            db.close()


def run_report_cli(
    config: dict,
    *,
    ensure_database,
    build_deterministic_alert_report_payload,
    output_language,
    system_text,
) -> int:
    db = ensure_database(config)
    try:
        eng = ReportEngine(
            db,
            alert_explainer=build_deterministic_alert_report_payload,
            language=output_language(config),
        )
        report = eng.daily_report()
        eng.save_html(report, "data/report.html")
        print(f"{system_text('reports', output_language(config))}: data/report.html")
        return 0
    finally:
        db.close()
