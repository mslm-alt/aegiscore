from __future__ import annotations

from typing import Any, Callable


def print_ml_family_readiness(result: dict) -> None:
    print(f"\n{'━'*58}")
    print("  ML Family Readiness")
    print(f"{'━'*58}")
    print(f"  family_id={result.get('family_id', '')}")
    print(f"  status={result.get('status', '')}")
    print(f"  reason={result.get('reason', '')}")
    print(f"  blockers={result.get('blockers', [])}")
    print(f"  phase_gate_ok={result.get('phase_gate_ok', False)}")
    print(f"  event_threshold_ok={result.get('event_threshold_ok', False)}")
    print(f"  normal_label_threshold_ok={result.get('normal_label_threshold_ok', False)}")
    print(f"  suspicious_label_threshold_ok={result.get('suspicious_label_threshold_ok', False)}")
    print(f"  field_quality_ok={result.get('field_quality_ok', False)}")
    print(f"  time_coverage_ok={result.get('time_coverage_ok', False)}")
    print(f"  trust_support_ok={result.get('trust_support_ok', False)}")
    print(f"  metadata_support_ok={result.get('metadata_support_ok', False)}")
    print(f"  can_score_support={result.get('can_score_support', False)}")
    print(f"  can_emit_alert={result.get('can_emit_alert', False)}")
    print(f"  no_action_contract={result.get('no_action_contract', False)}")
    print(f"{'━'*58}\n")


def run_ml_family_readiness(
    config: dict,
    family_id: str,
    *,
    ml_family_readiness: dict,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str | None]],
    collect_global_ml_audit: Callable[[Any, dict], dict],
    config_family_readiness_contract: Callable[[dict, str], dict],
    collect_event_metrics: Callable[[Any, str], tuple[dict, list[str]]],
    build_family_where_clause: Callable[[str, set[str]], str],
    evaluate_ml_family_readiness: Callable[..., dict],
    print_ml_family_readiness: Callable[[dict], None],
    sys_module,
) -> int:
    requested_family = (family_id or "").strip().upper()
    if not requested_family:
        print("--ml-family-readiness için FAMILY_ID zorunlu.", file=sys_module.stderr)
        return 2
    if requested_family not in ml_family_readiness:
        print(f"Geçersiz ML family: {requested_family}", file=sys_module.stderr)
        return 2

    pm, db, db_error = build_operator_phase_manager(config)
    try:
        global_audit = collect_global_ml_audit(db, pm.get_status())
        available_columns = set(global_audit.get("event_columns", []))
        cfg = config_family_readiness_contract(config, requested_family)
        metrics, notes = collect_event_metrics(
            db,
            build_family_where_clause(requested_family, available_columns),
            available_columns=available_columns,
        )
        if cfg.get("linked_process_where"):
            linked_metrics, linked_notes = collect_event_metrics(
                db,
                build_family_where_clause("ML-PROC", available_columns),
                available_columns=available_columns,
            )
            metrics["linked_process_events"] = int(linked_metrics.get("runtime_events", 0) or 0)
            notes.extend(linked_notes or [])
        label_counts = ((global_audit.get("label_quality", {}) or {}).get("family_counts", {}) or {}).get(requested_family, {}) or {}
        active_layer = ((config.get("ml", {}) or {}).get("active_decision_layer", {}) or {})
        result = evaluate_ml_family_readiness(
            family_id=requested_family,
            current_phase=int(global_audit.get("current_phase", 0) or 0),
            ml_paused=bool(global_audit.get("ml_paused", False)),
            family_contract=cfg,
            runtime_event_count=int(metrics.get("runtime_events", 0) or 0),
            normal_label_count=int(label_counts.get("normal", 0) or 0),
            suspicious_label_count=int(label_counts.get("suspicious", 0) or 0),
            field_quality_metrics=metrics,
            time_coverage_days=int(metrics.get("time_coverage_days", 0) or 0),
            trust_support={"normal": int(label_counts.get("normal", 0) or 0), "suspicious": int(label_counts.get("suspicious", 0) or 0)},
            metadata_support=max(int(label_counts.get("normal", 0) or 0), int(label_counts.get("suspicious", 0) or 0)),
            active_decision_layer=active_layer,
            linked_process_events=int(metrics.get("linked_process_events", 0) or 0),
            duplicate_rate=float(global_audit.get("duplicate_rate", 0.0) or 0.0),
            parse_fail_rate=float(global_audit.get("parse_fail_rate", 0.0) or 0.0),
            process_tree_count=int(global_audit.get("counts", {}).get("process_tree", 0) or 0),
            errors=list(notes or []),
        )
        if db_error:
            result.setdefault("errors", []).append(f"db_fallback:{db_error}")
        print_ml_family_readiness(result)
    finally:
        if db:
            db.close()
    return 0


__all__ = ["print_ml_family_readiness", "run_ml_family_readiness"]
