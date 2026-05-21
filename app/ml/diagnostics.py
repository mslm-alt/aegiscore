from __future__ import annotations

from typing import Any, Callable
import copy
import time


def _source_ownership_report(
    config: dict | None,
    *,
    audit_sources: Callable[[dict], dict],
    detect_distro: Callable[[], dict],
) -> dict:
    cfg = copy.deepcopy(dict(config or {}))
    try:
        report = audit_sources(cfg)
    except Exception as exc:
        return {
            "distro_family": str(detect_distro().get("family", "unknown") or "unknown"),
            "sources": {},
            "shared_paths": [],
            "notes": [f"audit_sources_error:{exc}"],
        }

    shared_paths: dict[str, list[str]] = {}
    for source_name, source_cfg in ((cfg.get("sources", {}) or {}).items()):
        if not isinstance(source_cfg, dict):
            continue
        if not bool(source_cfg.get("enabled", False)):
            continue
        audited = dict((report.get(source_name, {}) or {}))
        if str(audited.get("status", "") or "") != "ok":
            continue
        path = str(audited.get("path", "") or "")
        if not path or path == "journalctl":
            continue
        shared_paths.setdefault(path, []).append(str(source_name))

    shared_path_rows = [
        {"path": path, "sources": sorted(names), "count": len(names)}
        for path, names in sorted(shared_paths.items())
        if len(names) > 1
    ]
    return {
        "distro_family": str(detect_distro().get("family", "unknown") or "unknown"),
        "sources": {str(name): dict(payload or {}) for name, payload in (report or {}).items()},
        "shared_paths": shared_path_rows,
        "notes": [],
    }


def collect_parse_fail_diagnostics(
    config: dict,
    db,
    pm_status: dict,
    *,
    source_ownership_report: Callable[[dict | None], dict],
) -> dict:
    _ = db
    phase_stats = dict(((pm_status or {}).get("stats", {}) or {}))
    ownership = source_ownership_report(config)
    return {
        "total_parse_fail_count": int(phase_stats.get("parse_fail_count", 0) or 0),
        "parse_fail_rate": float(phase_stats.get("parse_fail_rate", 0.0) or 0.0),
        "by_source": dict(phase_stats.get("parse_fail_breakdown_by_source", {}) or {}),
        "by_reason": dict(phase_stats.get("parse_fail_breakdown_by_reason", {}) or {}),
        "by_parser": dict(phase_stats.get("parse_fail_breakdown_by_parser", {}) or {}),
        "by_distro_family": dict(phase_stats.get("parse_fail_breakdown_by_distro", {}) or {}),
        "by_path": dict(phase_stats.get("parse_fail_breakdown_by_path", {}) or {}),
        "samples": list(phase_stats.get("parse_fail_samples", []) or []),
        "normalize_none_count": int(dict(phase_stats.get("parse_fail_breakdown_by_reason", {}) or {}).get("normalize_none", 0) or 0),
        "source_ownership": ownership,
        "shared_path_risk_count": len(list(ownership.get("shared_paths", []) or [])),
        "query_notes": [],
        "no_action_contract": True,
    }


def collect_event_growth_diagnostics(
    config: dict,
    db,
    pm_status: dict,
    *,
    collect_global_ml_audit: Callable[..., dict],
    source_ownership_report: Callable[[dict | None], dict],
    top_distribution_rows: Callable[[Any], list[dict[str, Any]]],
    distribution_rows_to_dict: Callable[[Any], dict[str, int]],
) -> dict:
    global_audit = collect_global_ml_audit(db, pm_status, config=config)
    phase_stats = dict((global_audit.get("phase_stats", {}) or {}))
    overall_events = dict((global_audit.get("overall_events", {}) or {}))
    live_window_event_count = int(overall_events.get("runtime_events", 0) or 0)
    phase_lifetime_event_count = int(
        phase_stats.get("phase_event_count", phase_stats.get("total_events", 0)) or 0
    )
    phase_vs_live_gap = phase_lifetime_event_count - live_window_event_count
    ownership = source_ownership_report(config)
    status = "aligned"
    if live_window_event_count <= 0 and phase_lifetime_event_count > 0:
        status = "phase_only_or_live_window_empty"
    elif phase_vs_live_gap > 0:
        status = "phase_lifetime_exceeds_live_window"
    elif phase_vs_live_gap < 0:
        status = "live_window_exceeds_phase_counter"
    return {
        "status": status,
        "event_counter_scope": "phase_lifetime_normalized_events",
        "live_window_scope": "events_recent_runtime_window",
        "phase_lifetime_event_count": phase_lifetime_event_count,
        "live_window_event_count": live_window_event_count,
        "phase_vs_live_gap": phase_vs_live_gap,
        "estimated_non_live_window_events": max(0, phase_vs_live_gap),
        "duplicate_count": int(phase_stats.get("duplicate_count", 0) or 0),
        "telemetry_duplicate_count": int(phase_stats.get("telemetry_duplicate_count", 0) or 0),
        "parse_fail_count": int(phase_stats.get("parse_fail_count", 0) or 0),
        "duplicate_rate": float(global_audit.get("duplicate_rate", 0.0) or 0.0),
        "parse_fail_rate": float(global_audit.get("parse_fail_rate", 0.0) or 0.0),
        "top_sources": top_distribution_rows(global_audit.get("top_sources", {})),
        "top_categories": top_distribution_rows(global_audit.get("top_categories", {})),
        "top_actions": top_distribution_rows(global_audit.get("top_actions", {})),
        "events_by_distro": distribution_rows_to_dict(global_audit.get("events_by_distro", {})),
        "source_by_distro": dict(overall_events.get("source_by_distro", {}) or {}),
        "phase_source_counts": dict(phase_stats.get("source_counts", {}) or {}),
        "source_ownership": ownership,
        "shared_path_risk_count": len(list(ownership.get("shared_paths", []) or [])),
        "historical_scan_is_runtime_counter_source": False,
        "query_notes": list((global_audit.get("errors", {}) or {}).keys()),
        "no_action_contract": True,
    }


def _family_label_counts_for_distro(global_audit: dict, family: str, distro: str) -> dict:
    by_distro = (
        (global_audit.get("label_quality", {}) or {}).get("family_counts_by_distro", {}) or {}
    )
    family_counts = ((by_distro.get(distro, {}) or {}).get(family, {}) or {})
    return {
        "normal": int(family_counts.get("normal", 0) or 0),
        "suspicious": int(family_counts.get("suspicious", 0) or 0),
    }


def build_ml_historical_scan_manifest(
    plan_report: dict,
    *,
    job_id: str = "",
    created_at: str = "",
    utc_iso_now: Callable[[], str],
    time_time: Callable[[], float],
    ml_historical_scan_action: Callable[[dict], str],
) -> dict:
    manifest_job_id = (job_id or "").strip() or f"ml-historical-scan-{int(time_time())}"
    manifest_created_at = (created_at or "").strip() or utc_iso_now()
    family_targets = []

    for family_id in sorted((plan_report or {}).get("families", {})):
        family = ((plan_report or {}).get("families", {}) or {}).get(family_id, {}) or {}
        for family_label in sorted((family.get("labels", {}) or {})):
            item = (family.get("labels", {}) or {}).get(family_label, {}) or {}
            found = int(item.get("found", 0) or 0)
            required = int(item.get("required", 0) or 0)
            needed = max(required - found, 0)
            family_targets.append({
                "family_id": family_id,
                "phase_gate": family.get("phase_gate", ""),
                "target_type": item.get("target_type", ""),
                "family_label": family_label,
                "required": required,
                "found": found,
                "gap": max(required - found, 0),
                "needed": needed,
                "candidate_count": int(item.get("candidate_count", family.get("candidate_count", 0)) or 0),
                "status": item.get("status", ""),
                "scan_action": ml_historical_scan_action(item),
                "proposed_label_candidates": [],
                "query_notes": list(family.get("query_notes", []) or []),
            })

    return {
        "job_id": manifest_job_id,
        "created_at": manifest_created_at,
        "plan_type": "ml_historical_label_scan",
        "dry_run": True,
        "no_action_contract": True,
        "family_targets": family_targets,
        "plan_snapshot": {
            "required": True,
            "status": "placeholder_only",
            "kind": "ml_historical_label_scan_plan_snapshot",
            "generated": False,
        },
        "rollback_plan": {
            "required": True,
            "status": "placeholder_only",
            "kind": "ml_historical_label_scan_rollback_plan",
            "generated": False,
        },
    }


def validate_ml_historical_scan_manifest(manifest: dict) -> dict:
    from core.ml.label_engine import validate_ml_label_metadata

    payload = dict(manifest or {})
    problems: list[str] = []
    family_targets = list(payload.get("family_targets", []) or [])

    if not str(payload.get("job_id", "") or "").strip():
        problems.append("missing:job_id")
    if payload.get("plan_type") != "ml_historical_label_scan":
        problems.append("invalid:plan_type")
    if payload.get("dry_run") is not True:
        problems.append("invalid:dry_run")
    if payload.get("no_action_contract") is not True:
        problems.append("invalid:no_action_contract")
    if not isinstance(payload.get("plan_snapshot"), dict):
        problems.append("missing:plan_snapshot")
    if not isinstance(payload.get("rollback_plan"), dict):
        problems.append("missing:rollback_plan")

    for idx, item in enumerate(family_targets, start=1):
        required = int(item.get("required", 0) or 0)
        found = int(item.get("found", 0) or 0)
        needed = int(item.get("needed", 0) or 0)
        scan_action = (item.get("scan_action", "") or "").strip()
        status = (item.get("status", "") or "").strip()
        proposed_candidates = list(item.get("proposed_label_candidates", []) or [])
        expected_needed = max(required - found, 0)
        label_name = (item.get("family_label", "") or "").strip() or f"target_{idx}"

        if found >= required:
            if scan_action != "stop_scan":
                problems.append(f"invalid:scan_action_stop_scan_required:{label_name}")
            if needed != 0:
                problems.append(f"invalid:needed_nonzero_after_target_met:{label_name}")
        else:
            if needed != expected_needed:
                problems.append(f"invalid:needed_gap_mismatch:{label_name}")

        if scan_action == "insufficient_source_data" and proposed_candidates:
            problems.append(f"invalid:insufficient_source_data_has_candidates:{label_name}")
        if scan_action == "blocked_or_paused" and proposed_candidates:
            problems.append(f"invalid:blocked_or_paused_has_candidates:{label_name}")
        if status in {"paused", "missing_schema"} and scan_action != "blocked_or_paused":
            problems.append(f"invalid:blocked_status_action:{label_name}")

        for candidate_idx, candidate in enumerate(proposed_candidates, start=1):
            metadata = candidate.get("proposed_metadata", {}) or {}
            validation = validate_ml_label_metadata(metadata)
            if validation.get("valid") is not True:
                problems.append(
                    f"invalid:proposed_metadata:{label_name}:{candidate_idx}:{','.join(validation.get('problems', []))}"
                )
            source_type = (metadata.get("source_type", "") or "").strip().lower()
            scope = (metadata.get("model_usage_scope", "") or "").strip().lower()
            if source_type in {"synthetic_seed", "bootstrap_seed"} and scope == "active_training":
                problems.append(f"forbidden:seed_active_training:{label_name}:{candidate_idx}")

    return {
        "valid": not problems,
        "problems": problems,
        "manifest": payload,
        "read_only": True,
        "db_write_attempted": False,
    }


def build_ml_normal_label_manifest(
    plan_report: dict,
    *,
    job_id: str = "",
    created_at: str = "",
    utc_iso_now: Callable[[], str],
    time_time: Callable[[], float],
    compat_accepted_count_key: str,
) -> dict:
    manifest_job_id = (job_id or "").strip() or f"ml-normal-label-{int(time_time())}"
    manifest_created_at = (created_at or "").strip() or utc_iso_now()
    global_block = (plan_report or {}).get("global", {}) or {}
    family_normal_targets = []

    for family_id in sorted((plan_report or {}).get("families", {})):
        family = ((plan_report or {}).get("families", {}) or {}).get(family_id, {}) or {}
        for normal_label in sorted((family.get("labels", {}) or {})):
            item = (family.get("labels", {}) or {}).get(normal_label, {}) or {}
            family_normal_targets.append({
                "family": family_id,
                "normal_label": normal_label,
                "required": int(item.get("required", 0) or 0),
                "existing_found": int(item.get("existing_found", 0) or 0),
                "needed": int(item.get("needed", 0) or 0),
                "candidate_count": int(item.get("candidate_count", 0) or 0),
                "behavioral_baseline_candidate_count": int(item.get("behavioral_baseline_candidate_count", item.get(compat_accepted_count_key, 0)) or 0),
                "rejected_candidate_count": int(item.get("rejected_candidate_count", 0) or 0),
                "status": item.get("status", ""),
                "rejection_reasons": dict(item.get("rejection_reasons", {}) or {}),
                "proposed_normal_label_candidates": [],
                "query_notes": list(family.get("query_notes", []) or []),
            })

    return {
        "job_id": manifest_job_id,
        "created_at": manifest_created_at,
        "plan_type": "ml_clean_window_normal_label_plan",
        "dry_run": True,
        "no_action_contract": True,
        "ml_paused": bool(global_block.get("ml_paused", False)),
        "blocking_incident": bool(global_block.get("blocking_incident", False)),
        "global_quality_ok": bool(global_block.get("global_quality_ok", False)),
        "family_normal_targets": family_normal_targets,
        "plan_snapshot": {
            "required": True,
            "status": "placeholder_only",
            "kind": "ml_clean_window_normal_label_plan_snapshot",
            "generated": False,
        },
        "rollback_plan": {
            "required": True,
            "status": "placeholder_only",
            "kind": "ml_clean_window_normal_label_rollback_plan",
            "generated": False,
        },
    }


def validate_ml_normal_label_manifest(
    manifest: dict,
    *,
    compat_accepted_count_key: str,
) -> dict:
    from core.ml.label_engine import validate_ml_label_metadata

    payload = dict(manifest or {})
    problems: list[str] = []
    ml_paused = bool(payload.get("ml_paused", False))
    blocking_incident = bool(payload.get("blocking_incident", False))
    global_quality_ok = bool(payload.get("global_quality_ok", False))
    family_normal_targets = list(payload.get("family_normal_targets", []) or [])

    if not str(payload.get("job_id", "") or "").strip():
        problems.append("missing:job_id")
    if payload.get("plan_type") != "ml_clean_window_normal_label_plan":
        problems.append("invalid:plan_type")
    if payload.get("dry_run") is not True:
        problems.append("invalid:dry_run")
    if payload.get("no_action_contract") is not True:
        problems.append("invalid:no_action_contract")
    if not isinstance(payload.get("plan_snapshot"), dict):
        problems.append("missing:plan_snapshot")
    if not isinstance(payload.get("rollback_plan"), dict):
        problems.append("missing:rollback_plan")

    blocked_reasons = {
        "rule_or_ioc_or_non_trainable",
        "suspicious_action",
        "dual_use_behavior",
    }

    for idx, item in enumerate(family_normal_targets, start=1):
        label_name = (item.get("normal_label", "") or "").strip() or f"target_{idx}"
        needed = int(item.get("needed", 0) or 0)
        required = int(item.get("required", 0) or 0)
        existing_found = int(item.get("existing_found", 0) or 0)
        behavioral_baseline_candidate_count = int(item.get("behavioral_baseline_candidate_count", item.get(compat_accepted_count_key, 0)) or 0)
        candidates = list(item.get("proposed_normal_label_candidates", []) or [])
        rejection_reasons = {str(k): int(v or 0) for k, v in dict(item.get("rejection_reasons", {}) or {}).items()}

        if ml_paused and candidates:
            problems.append(f"invalid:paused_has_candidates:{label_name}")
        if blocking_incident and candidates:
            problems.append(f"invalid:blocking_incident_has_candidates:{label_name}")
        if not global_quality_ok and candidates:
            problems.append(f"invalid:global_quality_false_has_candidates:{label_name}")
        if existing_found >= required:
            if needed != 0:
                problems.append(f"invalid:needed_nonzero_after_target_met:{label_name}")
            if candidates:
                problems.append(f"invalid:target_met_has_candidates:{label_name}")
        if any(rejection_reasons.get(reason, 0) > 0 for reason in blocked_reasons) and candidates:
            problems.append(f"invalid:rejected_candidate_in_candidate_list:{label_name}")
        if behavioral_baseline_candidate_count > 0 and len(candidates) > behavioral_baseline_candidate_count:
            problems.append(f"invalid:candidate_count_exceeds_direct_learnable:{label_name}")

        for candidate_idx, candidate in enumerate(candidates, start=1):
            metadata = candidate.get("proposed_metadata", {}) or {}
            validation = validate_ml_label_metadata(metadata)
            if validation.get("valid") is not True:
                problems.append(
                    f"invalid:proposed_metadata:{label_name}:{candidate_idx}:{','.join(validation.get('problems', []))}"
                )
            if (metadata.get("source_type", "") or "").strip().lower() != "clean_window_normal":
                problems.append(f"invalid:source_type_not_clean_window_normal:{label_name}:{candidate_idx}")
            if (metadata.get("source", "") or "").strip().lower() != "clean_window":
                problems.append(f"invalid:source_not_clean_window:{label_name}:{candidate_idx}")
            if (metadata.get("source_trust", "") or "").strip().lower() != "observed_benign_high":
                problems.append(f"invalid:source_trust:{label_name}:{candidate_idx}")
            scope = (metadata.get("model_usage_scope", "") or "").strip().lower()
            if scope == "active_training" and (metadata.get("source_type", "") or "").strip().lower() != "clean_window_normal":
                problems.append(f"invalid:active_training_scope_source_type:{label_name}:{candidate_idx}")

            candidate_flags = {
                str(flag).strip().lower()
                for flag in (candidate.get("candidate_flags", []) or [])
                if str(flag).strip()
            }
            candidate_rejection = {
                str(flag).strip().lower()
                for flag in (candidate.get("rejection_flags", []) or [])
                if str(flag).strip()
            }
            if candidate_flags & {"maintenance", "pentest"} and scope == "active_training":
                problems.append(f"forbidden:maintenance_pentest_active_training:{label_name}:{candidate_idx}")
            if candidate_rejection & blocked_reasons:
                problems.append(f"invalid:rejection_flagged_candidate:{label_name}:{candidate_idx}")

    return {
        "valid": not problems,
        "problems": problems,
        "manifest": payload,
        "read_only": True,
        "db_write_attempted": False,
    }


__all__ = [
    '_source_ownership_report',
    'collect_parse_fail_diagnostics',
    'collect_event_growth_diagnostics',
    '_family_label_counts_for_distro',
    'build_ml_historical_scan_manifest',
    'validate_ml_historical_scan_manifest',
    'build_ml_normal_label_manifest',
    'validate_ml_normal_label_manifest',
]
