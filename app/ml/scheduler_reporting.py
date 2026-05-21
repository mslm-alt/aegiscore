from __future__ import annotations

import json
import math
import time
from datetime import datetime
from typing import Any, Callable


def quota_bucket_full(quota_payload: dict) -> bool:
    payload = dict(quota_payload or {})
    status = str(payload.get("status", "") or "").strip().lower()
    remaining = _safe_int(payload.get("remaining", 0))
    limit = _safe_int(payload.get("limit", 0))
    return bool(limit > 0 and remaining <= 0) or status in {"full", "stop_write", "blocked"}


def open_incident_count(db) -> int:
    if db is None or not hasattr(db, "get_open_incidents"):
        return 0
    try:
        return len(db.get_open_incidents() or [])
    except Exception:
        return 0


def training_scheduler_label_inventory(
    label_rows: list[dict],
    *,
    classify_label_origin: Callable[[dict], str],
    row_distro_value: Callable[[dict], str],
    label_family_support: Callable[[dict], dict],
    classify_label_usage: Callable[[dict, dict], tuple[str, list[str]]],
    validate_ml_label_metadata: Callable[[dict], dict],
    parse_timestamp: Callable[[Any], float],
) -> dict:
    inventory: dict[str, dict[str, dict[str, Any]]] = {}
    for row in label_rows:
        origin = classify_label_origin(row)
        distro = row_distro_value(row)
        if origin == "legacy_excluded" or distro == "unknown_distro":
            continue
        family_support = label_family_support(row)
        usage, usage_reasons = classify_label_usage(row, family_support)
        validation = validate_ml_label_metadata(row)
        ts_value = parse_timestamp(row.get("ts"))
        for family_id, support in family_support.items():
            bucket = None
            if support.get("normal"):
                bucket = "normal"
            elif support.get("suspicious"):
                bucket = "suspicious"
            if not bucket:
                continue
            distro_bucket = inventory.setdefault(family_id, {}).setdefault(
                distro,
                {
                    "normal": 0,
                    "suspicious": 0,
                    "bootstrap_normal": 0,
                    "bootstrap_suspicious": 0,
                    "organic_normal": 0,
                    "organic_suspicious": 0,
                    "metadata_valid_count": 0,
                    "metadata_missing_count": 0,
                    "timestamps": [],
                },
            )
            if not validation.get("valid", False):
                distro_bucket["metadata_missing_count"] += 1
                continue
            if usage not in {"baseline_learning", "direct_learnable"}:
                continue
            distro_bucket[bucket] += 1
            distro_bucket["metadata_valid_count"] += 1
            if origin == "bootstrap_historical":
                distro_bucket[f"bootstrap_{bucket}"] += 1
            else:
                distro_bucket[f"organic_{bucket}"] += 1
            if ts_value > 0:
                distro_bucket["timestamps"].append(
                    {
                        "ts": ts_value,
                        "origin": origin,
                        "bucket": bucket,
                        "usage": usage,
                        "usage_reasons": list(usage_reasons or []),
                    }
                )
    return inventory


def count_new_training_labels(training_bucket: dict, last_training_ts: float) -> dict:
    normal = 0
    suspicious = 0
    for item in list(training_bucket.get("timestamps", []) or []):
        if float(item.get("ts", 0.0) or 0.0) <= float(last_training_ts or 0.0):
            continue
        if str(item.get("origin", "") or "") not in {"organic_live", "bootstrap_historical"}:
            continue
        bucket = str(item.get("bucket", "") or "")
        if bucket == "normal":
            normal += 1
        elif bucket == "suspicious":
            suspicious += 1
    return {"normal": normal, "suspicious": suspicious}


def label_evidence_fields(row: dict) -> dict:
    evidence = row.get("evidence_fields", {})
    if isinstance(evidence, dict):
        return dict(evidence)
    if isinstance(evidence, str):
        try:
            payload = json.loads(evidence)
            return dict(payload) if isinstance(payload, dict) else {}
        except Exception:
            return {}
    return {}


def label_timestamp_confidence(row: dict, *, label_evidence_fields: Callable[[dict], dict]) -> str:
    evidence = label_evidence_fields(row)
    return str(
        row.get("timestamp_confidence", evidence.get("timestamp_confidence", "")) or ""
    ).strip().lower()


def label_log_source(row: dict, *, label_evidence_fields: Callable[[dict], dict]) -> str:
    evidence = label_evidence_fields(row)
    return str(
        evidence.get("log_source", row.get("log_source", evidence.get("source_log", ""))) or ""
    ).strip().lower()


def label_duplicate_snapshot(row: dict, *, label_evidence_fields: Callable[[dict], dict]) -> tuple[str, int | None]:
    evidence = label_evidence_fields(row)
    dedup_status = str(
        row.get("dedup_status", evidence.get("dedup_status", "")) or ""
    ).strip().lower()
    raw_count = row.get("duplicate_count", evidence.get("duplicate_count"))
    try:
        duplicate_count = int(raw_count) if raw_count not in (None, "") else None
    except (TypeError, ValueError):
        duplicate_count = None
    return dedup_status, duplicate_count


def phase_gate_training_state(db, *, safe_json_stat: Callable[[Any, str], dict]) -> dict:
    raw = safe_json_stat(db, "ml_training_scheduler_state")
    first_training_completed_at = str(
        raw.get("first_model_training_completed_at", raw.get("first_training_completed_at", "")) or ""
    )
    first_training_status = str(
        raw.get("first_model_training_status", raw.get("first_training_status", "")) or ""
    )
    first_evaluation_status = str(
        raw.get("first_model_evaluation_status", raw.get("first_evaluation_status", "")) or ""
    )
    ml_alert_family_enabled = sorted(
        {
            str(item or "").strip()
            for item in list(raw.get("ml_alert_family_enabled_families", []) or [])
            if str(item or "").strip()
        }
    )
    first_ml_model_ready = bool(
        raw.get(
            "first_ml_model_ready",
            raw.get("ml_alert_family_ready", raw.get("first_shadow_model_ready", False)),
        )
    )
    return {
        "first_model_training_completed_at": first_training_completed_at,
        "first_model_training_status": first_training_status,
        "first_model_training_completed": bool(first_training_completed_at),
        "first_model_evaluation_status": first_evaluation_status,
        "first_model_evaluation_passed": first_evaluation_status.strip().lower() in {"pass", "passed", "evaluation_passed"},
        "first_ml_model_ready": first_ml_model_ready,
        "first_ml_model_ready_at": str(raw.get("first_ml_model_ready_at", "") or ""),
        "last_training_status": str(raw.get("last_training_status", "") or ""),
        "last_evaluation_status": str(raw.get("last_evaluation_status", "") or ""),
        "last_model_promoted": bool(raw.get("last_model_promoted", False)),
        "raw": raw,
        "ml_alert_family_ready": bool(raw.get("ml_alert_family_ready", first_ml_model_ready)),
        "ml_alert_family_enabled_families": ml_alert_family_enabled,
        "active_ml_enabled": bool(raw.get("active_ml_enabled", False)),
        "training_started": bool(raw.get("training_started", False)),
    }


def collect_seed_training_readiness(
    config: dict,
    db,
    pm_status: dict,
    *,
    global_audit: dict | None = None,
    collect_global_ml_audit: Callable[..., dict],
    load_labels_read_only: Callable[[Any], tuple[list[dict], str | None]],
    classify_label_origin: Callable[[dict], str],
    row_distro_value: Callable[[dict], str],
    label_family_support: Callable[[dict], dict],
    classify_label_usage: Callable[[dict, dict], tuple[str, list[str]]],
    validate_ml_label_metadata: Callable[[dict], dict],
    label_timestamp_confidence: Callable[[dict], str],
    label_log_source: Callable[[dict], str],
    label_duplicate_snapshot: Callable[[dict], tuple[str, int | None]],
    parse_timestamp: Callable[[Any], float],
    scheduler_state_family_key: Callable[[str, str], str],
    config_family_readiness_contract: Callable[[dict, str], dict],
    safe_ratio: Callable[[float, float], float],
    phase_seed_gate_defaults: dict,
    unmapped_nonlearnable_family: str,
) -> dict:
    audit = dict(global_audit or collect_global_ml_audit(db, pm_status, config=config) or {})
    rows, labels_error = load_labels_read_only(db)
    parse_fail_rate = float(audit.get("parse_fail_rate", 0.0) or 0.0)
    families: dict[str, dict[str, Any]] = {}

    for row in rows:
        origin = classify_label_origin(row)
        distro = row_distro_value(row)
        if origin == "legacy_excluded" or distro == "unknown_distro":
            continue
        family_support = label_family_support(row)
        usage, _usage_reasons = classify_label_usage(row, family_support)
        validation = validate_ml_label_metadata(row)
        timestamp_confidence_value = label_timestamp_confidence(row)
        log_source = label_log_source(row)
        dedup_status, duplicate_count = label_duplicate_snapshot(row)
        ts_value = parse_timestamp(row.get("ts"))
        day_token = datetime.fromtimestamp(ts_value).strftime("%Y-%m-%d") if ts_value > 0 else ""

        for family_id, support in family_support.items():
            family_key = str(family_id or "").strip().upper()
            if family_key == unmapped_nonlearnable_family:
                continue
            bucket = "normal" if support.get("normal") else "suspicious" if support.get("suspicious") else ""
            if not bucket:
                continue
            key = scheduler_state_family_key(family_key, distro)
            item = families.setdefault(
                key,
                {
                    "family_id": family_key,
                    "distro": distro,
                    "candidate_count": 0,
                    "normal": 0,
                    "suspicious": 0,
                    "metadata_valid_count": 0,
                    "metadata_missing_count": 0,
                    "rejected_count": 0,
                    "non_learnable_count": 0,
                    "timestamp_high_or_medium_count": 0,
                    "timestamp_observed_count": 0,
                    "log_sources": set(),
                    "distinct_days": set(),
                    "duplicate_flagged_count": 0,
                    "duplicate_metric_observed_count": 0,
                    "missing_metrics": set(),
                },
            )
            item["candidate_count"] += 1
            if usage == "rejected":
                item["rejected_count"] += 1
            elif usage not in {"baseline_learning", "direct_learnable"}:
                item["non_learnable_count"] += 1

            if validation.get("valid", False):
                item["metadata_valid_count"] += 1
            else:
                item["metadata_missing_count"] += 1

            if timestamp_confidence_value:
                item["timestamp_observed_count"] += 1
                if timestamp_confidence_value in {"high", "medium"}:
                    item["timestamp_high_or_medium_count"] += 1
            else:
                item["missing_metrics"].add("missing_timestamp_confidence")

            if log_source:
                item["log_sources"].add(log_source)
            else:
                item["missing_metrics"].add("missing_source_diversity")

            if day_token:
                item["distinct_days"].add(day_token)

            if dedup_status or duplicate_count is not None:
                item["duplicate_metric_observed_count"] += 1
                if (duplicate_count is not None and duplicate_count > 1) or dedup_status in {"duplicate", "deduped", "suppressed"}:
                    item["duplicate_flagged_count"] += 1
            else:
                item["missing_metrics"].add("missing_duplicate_ratio")

            if validation.get("valid", False) and usage in {"baseline_learning", "direct_learnable"}:
                item[bucket] += 1

    ready_families: list[dict[str, Any]] = []
    family_reports: dict[str, dict[str, Any]] = {}
    min_ready_family_count = int(phase_seed_gate_defaults["min_ready_family_count"])

    for key, item in sorted(families.items()):
        contract = config_family_readiness_contract(config, item["family_id"])
        normal_required = int(contract.get("required_normal_labels", 0) or 0)
        suspicious_required = int(contract.get("required_suspicious_labels", 0) or 0)
        normal_seed_min = max(30, int(math.ceil(normal_required * 0.30)))
        suspicious_seed_min = max(15, int(math.ceil(suspicious_required * 0.30)))
        source_min = 1 if item["family_id"] in {"ML-SUDO", "ML-SERVICE"} else 2
        candidate_count = int(item["candidate_count"] or 0)
        metadata_valid_count = int(item["metadata_valid_count"] or 0)
        metadata_completeness = safe_ratio(metadata_valid_count, candidate_count)
        timestamp_observed_count = int(item["timestamp_observed_count"] or 0)
        timestamp_ratio = safe_ratio(int(item["timestamp_high_or_medium_count"] or 0), timestamp_observed_count)
        rejected_ratio = safe_ratio(int(item["rejected_count"] or 0), candidate_count)
        duplicate_observed_count = int(item["duplicate_metric_observed_count"] or 0)
        duplicate_ratio = safe_ratio(int(item["duplicate_flagged_count"] or 0), duplicate_observed_count)
        source_diversity = len(item["log_sources"])
        distinct_days = len(item["distinct_days"])
        blockers: list[str] = []

        if item["normal"] < normal_seed_min:
            blockers.append("insufficient_normal_labels")
        if item["suspicious"] < suspicious_seed_min:
            blockers.append("insufficient_suspicious_labels")
        if distinct_days < int(phase_seed_gate_defaults["min_distinct_days"]):
            blockers.append("insufficient_distinct_days")
        if timestamp_observed_count <= 0:
            blockers.append("missing_timestamp_confidence")
        elif timestamp_ratio < float(phase_seed_gate_defaults["min_timestamp_confidence_ratio"]):
            blockers.append("timestamp_confidence_low")
        if metadata_valid_count <= 0:
            blockers.append("missing_metadata_completeness")
        elif metadata_completeness < float(phase_seed_gate_defaults["min_metadata_completeness"]):
            blockers.append("metadata_completeness_low")
        if rejected_ratio > float(phase_seed_gate_defaults["max_rejected_ratio"]):
            blockers.append("rejected_ratio_high")
        if duplicate_observed_count <= 0:
            blockers.append("missing_duplicate_ratio")
        elif duplicate_ratio > float(phase_seed_gate_defaults["max_duplicate_ratio"]):
            blockers.append("duplicate_ratio_high")
        if parse_fail_rate > float(phase_seed_gate_defaults["max_parse_fail_rate"]):
            blockers.append("parse_fail_rate_high")
        if source_diversity <= 0:
            blockers.append("missing_source_diversity")
        elif source_diversity < source_min:
            blockers.append("source_diversity_low")
        for missing in sorted(item["missing_metrics"]):
            if missing not in blockers:
                blockers.append(missing)

        report = {
            "family_id": item["family_id"],
            "distro": item["distro"],
            "family_distro": key,
            "normal": int(item["normal"]),
            "suspicious": int(item["suspicious"]),
            "normal_seed_min": normal_seed_min,
            "suspicious_seed_min": suspicious_seed_min,
            "distinct_days": distinct_days,
            "timestamp_high_or_medium_ratio": round(float(timestamp_ratio), 4),
            "metadata_completeness": round(float(metadata_completeness), 4),
            "rejected_ratio": round(float(rejected_ratio), 4),
            "duplicate_ratio": round(float(duplicate_ratio), 4) if duplicate_observed_count > 0 else None,
            "parse_fail_rate": round(float(parse_fail_rate), 4),
            "source_diversity": source_diversity,
            "candidate_count": candidate_count,
            "metadata_valid_count": metadata_valid_count,
            "duplicate_metric_observed_count": duplicate_observed_count,
            "status": "seed_training_ready" if not blockers else "seed_training_blocked",
            "blockers": blockers,
        }
        family_reports[key] = report
        if not blockers:
            ready_families.append(report)

    return {
        "seed_ready_families": ready_families,
        "family_reports": family_reports,
        "ready_family_ids": [item["family_id"] for item in ready_families],
        "ready_family_count": len(ready_families),
        "min_ready_family_count": min_ready_family_count,
        "labels_error": labels_error,
        "parse_fail_rate": round(parse_fail_rate, 4),
    }


def collect_label_training_phase_gate_report(
    config: dict,
    db,
    pm_status: dict,
    *,
    collect_global_ml_audit: Callable[..., dict],
    collect_seed_training_readiness: Callable[..., dict],
    phase_gate_training_state: Callable[[Any], dict],
    open_incident_count: Callable[[Any], int],
) -> dict:
    global_audit = collect_global_ml_audit(db, pm_status, config=config)
    seed = collect_seed_training_readiness(config, db, pm_status, global_audit=global_audit)
    training_state = phase_gate_training_state(db)
    open_incidents = open_incident_count(db)
    blockers: list[str] = []
    family_reports = dict(seed.get("family_reports", {}) or {})

    if bool(global_audit.get("ml_paused", False)):
        blockers.append("ml_paused")
    if open_incidents > 0:
        blockers.append("open_incident")
    if not training_state.get("first_model_training_completed", False):
        blockers.append("no_first_model_training")
    if not training_state.get("first_model_evaluation_passed", False):
        blockers.append("no_first_model_evaluation_pass")
    if not training_state.get("first_ml_model_ready", False):
        blockers.append("no_first_ml_model_ready")
    if seed.get("labels_error"):
        blockers.append(str(seed.get("labels_error")))
    if int(seed.get("ready_family_count", 0) or 0) < int(seed.get("min_ready_family_count", 1) or 1):
        blockers.append("insufficient_ready_families")
        for family_key, report in sorted(family_reports.items()):
            for reason in list(report.get("blockers", []) or [])[:3]:
                blockers.append(f"seed_family_blocked:{family_key}:{reason}")

    return {
        "phase_gate_source": "label_training",
        "label_training_gate_ok": not blockers,
        "event_telemetry_ok": False,
        "ml_paused": bool(global_audit.get("ml_paused", False)),
        "open_incident_blocker": open_incidents > 0,
        "first_model_training_completed": bool(training_state.get("first_model_training_completed", False)),
        "first_model_training_completed_at": str(training_state.get("first_model_training_completed_at", "") or ""),
        "first_model_training_status": str(training_state.get("first_model_training_status", "") or ""),
        "first_model_evaluation_passed": bool(training_state.get("first_model_evaluation_passed", False)),
        "first_model_evaluation_status": str(training_state.get("first_model_evaluation_status", "") or ""),
        "first_ml_model_ready": bool(training_state.get("first_ml_model_ready", False)),
        "first_ml_model_ready_at": str(training_state.get("first_ml_model_ready_at", "") or ""),
        "ml_alert_family_ready": bool(training_state.get("ml_alert_family_ready", False)),
        "ml_alert_family_enabled_families": list(training_state.get("ml_alert_family_enabled_families", []) or []),
        "last_training_status": str(training_state.get("last_training_status", "") or ""),
        "last_evaluation_status": str(training_state.get("last_evaluation_status", "") or ""),
        "ready_family_count": int(seed.get("ready_family_count", 0) or 0),
        "ready_family_ids": list(seed.get("ready_family_ids", []) or []),
        "seed_ready_families": list(seed.get("seed_ready_families", []) or []),
        "eligible_seed_families": list(seed.get("seed_ready_families", []) or []),
        "family_reports": family_reports,
        "phase_gate_blockers": list(dict.fromkeys(blockers)),
        "training_state": {
            "first_model_training_completed_at": str(training_state.get("first_model_training_completed_at", "") or ""),
            "first_model_training_status": str(training_state.get("first_model_training_status", "") or ""),
            "first_model_evaluation_status": str(training_state.get("first_model_evaluation_status", "") or ""),
            "first_ml_model_ready": bool(training_state.get("first_ml_model_ready", False)),
            "ml_alert_family_ready": bool(training_state.get("ml_alert_family_ready", False)),
            "ml_alert_family_enabled_families": list(training_state.get("ml_alert_family_enabled_families", []) or []),
            "last_training_status": str(training_state.get("last_training_status", "") or ""),
            "last_evaluation_status": str(training_state.get("last_evaluation_status", "") or ""),
            "active_ml_enabled": bool(training_state.get("active_ml_enabled", False)),
            "training_started": bool(training_state.get("training_started", False)),
        },
        "no_action_contract": True,
    }


def bind_label_training_phase_gate(pm, config: dict, db, *, collect_label_training_phase_gate_report: Callable[[dict, Any, dict], dict]) -> None:
    if pm is None or not hasattr(pm, "set_external_phase_gate_resolver"):
        return
    pm.set_external_phase_gate_resolver(lambda status: collect_label_training_phase_gate_report(config, db, status))


def training_eligibility_for_cohort(
    family_id: str,
    family_payload: dict,
    cohort_payload: dict,
    global_audit: dict,
    training_bucket: dict,
    *,
    evaluate_ml_family_readiness: Callable[..., dict],
    ml_family_readiness: dict,
) -> dict:
    field_quality_metrics = {
        "host_fill_rate": float(family_payload.get("host_fill_rate", 0.0) or 0.0),
        "user_fill_rate": float(family_payload.get("user_fill_rate", 0.0) or 0.0),
        "src_ip_fill_rate": float(family_payload.get("src_ip_fill_rate", 0.0) or 0.0),
        "dst_ip_fill_rate": float(family_payload.get("dst_ip_fill_rate", 0.0) or 0.0),
        "dst_port_fill_rate": float(family_payload.get("dst_port_fill_rate", 0.0) or 0.0),
        "process_fill_rate": float(family_payload.get("process_fill_rate", 0.0) or 0.0),
        "source_count": int(cohort_payload.get("source_count", family_payload.get("source_count", 0)) or 0),
        "candidate_count_by_distro": {
            str(cohort_payload.get("distro", "")): int(cohort_payload.get("runtime_events", 0) or 0),
        },
    }
    return evaluate_ml_family_readiness(
        family_id=family_id,
        current_phase=int(global_audit.get("current_phase", 0) or 0),
        ml_paused=bool(global_audit.get("ml_paused", False)),
        family_contract=ml_family_readiness.get(family_id, {}),
        runtime_event_count=int(cohort_payload.get("runtime_events", 0) or 0),
        normal_label_count=int(training_bucket.get("normal", 0) or 0),
        suspicious_label_count=int(training_bucket.get("suspicious", 0) or 0),
        field_quality_metrics=field_quality_metrics,
        time_coverage_days=int(family_payload.get("time_coverage_days", 0) or 0),
        trust_support={
            "normal": int(training_bucket.get("normal", 0) or 0),
            "suspicious": int(training_bucket.get("suspicious", 0) or 0),
        },
        metadata_support=int(training_bucket.get("metadata_valid_count", 0) or 0),
        active_decision_layer={"enabled": False, "mode": "audit_only", "no_action_contract": True},
        linked_process_events=int(family_payload.get("linked_process_events", 0) or 0),
        duplicate_rate=float(global_audit.get("duplicate_rate", 0.0) or 0.0),
        parse_fail_rate=float(global_audit.get("parse_fail_rate", 0.0) or 0.0),
        process_tree_count=int(global_audit.get("counts", {}).get("process_tree", 0) or 0),
        errors=list(family_payload.get("errors", []) or []),
    )


def collect_ml_training_scheduler_report(
    config: dict,
    db,
    pm_status: dict,
    *,
    now_ts: float | None = None,
    trigger_request: str = "scheduler",
    resolve_ml_training_scheduler_config: Callable[[dict], dict],
    scheduler_last_training_state: Callable[[Any], dict],
    collect_ml_readiness_report: Callable[[dict, Any, dict], dict],
    collect_seed_training_readiness: Callable[..., dict],
    load_labels_read_only: Callable[[Any], tuple[list[dict], str | None]],
    training_scheduler_label_inventory: Callable[[list[dict]], dict],
    scheduler_window: Callable[[float, dict, float], dict],
    open_incident_count: Callable[[Any], int],
    parse_timestamp: Callable[[Any], float],
    count_new_training_labels: Callable[[dict, float], dict],
    scheduler_min_interval_ready: Callable[[float, int, float], tuple[bool, str]],
    quota_bucket_full: Callable[[dict], bool],
    iso_local: Callable[[float | None], str],
    scheduler_select_execution_candidates: Callable[[list[dict], int], list[dict]],
) -> dict:
    now_ts = float(now_ts if now_ts is not None else time.time())
    schedule_cfg = resolve_ml_training_scheduler_config(config)
    training_mode = str(schedule_cfg.get("mode", "manual") or "manual")
    trigger_mode = str(trigger_request or "scheduler").strip().lower() or "scheduler"
    scheduler_state = scheduler_last_training_state(db)
    raw_scheduler_state = dict(scheduler_state.get("raw", {}) or {})
    global_readiness = collect_ml_readiness_report(config, db, pm_status)
    global_audit = dict(global_readiness.get("global", {}) or {})
    readiness_families = dict(global_readiness.get("families", {}) or {})
    seed = collect_seed_training_readiness(config, db, pm_status, global_audit=global_audit)
    label_rows, labels_error = load_labels_read_only(db)
    training_inventory = training_scheduler_label_inventory(label_rows if not labels_error else [])
    window = scheduler_window(now_ts, schedule_cfg, scheduler_state.get("last_scheduler_check_at", 0.0))
    open_incidents = open_incident_count(db)

    eligible_families: list[dict] = []
    eligible_seed_families: list[dict] = []
    execution_candidates: list[dict] = []
    threshold_candidates: list[dict] = []
    blocked_families: list[dict] = []
    labels_since_last_train: dict[str, dict] = {}
    quota_status: dict[str, dict] = {}
    readiness_status: dict[str, dict] = {}
    all_global_blocked = bool(global_audit.get("ml_paused", False)) or open_incidents > 0
    family_reports = dict(seed.get("family_reports", {}) or {})

    for key, seed_report in sorted(family_reports.items()):
        family_id = str(seed_report.get("family_id", "") or "").strip().upper()
        distro_token = str(seed_report.get("distro", "") or "").strip().lower() or "unknown_distro"
        training_bucket = dict((training_inventory.get(family_id, {}) or {}).get(distro_token, {}) or {})
        candidate_status = str(seed_report.get("status", "seed_training_blocked") or "seed_training_blocked")
        candidate_blockers = list(seed_report.get("blockers", []) or [])
        family_payload = dict(readiness_families.get(family_id, {}) or {})
        cohort_payload = dict((family_payload.get("distro_cohorts", {}) or {}).get(distro_token, {}) or {})
        last_training_entry = dict((scheduler_state.get("last_training", {}) or {}).get(key, {}) or {})
        last_training_ts = parse_timestamp(last_training_entry.get("trained_at"))
        new_counts = count_new_training_labels(training_bucket, last_training_ts)
        min_interval_ready, min_interval_reason = scheduler_min_interval_ready(
            last_training_ts,
            int(schedule_cfg.get("min_seconds_between_training", 0) or 0),
            now_ts,
        )
        quota_normal = dict(cohort_payload.get("quota_normal", seed_report.get("quota_normal", {})) or {})
        quota_suspicious = dict(cohort_payload.get("quota_suspicious", seed_report.get("quota_suspicious", {})) or {})
        quota_full = quota_bucket_full(quota_normal) and quota_bucket_full(quota_suspicious)
        readiness_status[key] = {
            "status": candidate_status,
            "reason": ",".join(candidate_blockers) if candidate_blockers else "ready",
            "runtime_events": int(cohort_payload.get("runtime_events", 0) or 0),
            "normal_labels": int(training_bucket.get("normal", 0) or 0),
            "suspicious_labels": int(training_bucket.get("suspicious", 0) or 0),
            "seed_report": dict(seed_report),
        }
        quota_status[key] = {
            "normal": quota_normal,
            "suspicious": quota_suspicious,
            "quota_full": quota_full,
        }
        labels_since_last_train[key] = {
            "normal": int(new_counts["normal"]),
            "suspicious": int(new_counts["suspicious"]),
            "last_training_at": iso_local(last_training_ts),
        }

        if distro_token == "unknown_distro":
            blocked_families.append({"family_id": family_id, "distro": distro_token, "reason": "unknown_distro"})
            continue
        if bool(global_audit.get("ml_paused", False)):
            blocked_families.append({"family_id": family_id, "distro": distro_token, "reason": "ml_paused"})
            continue
        if open_incidents > 0:
            blocked_families.append({"family_id": family_id, "distro": distro_token, "reason": "open_incident"})
            continue
        if labels_error:
            blocked_families.append({"family_id": family_id, "distro": distro_token, "reason": "labels_unavailable"})
            continue
        if candidate_status != "seed_training_ready":
            blocked_families.append(
                {
                    "family_id": family_id,
                    "distro": distro_token,
                    "reason": candidate_blockers[0] if candidate_blockers else "seed_readiness_blocked",
                }
            )
            continue
        if not min_interval_ready:
            blocked_families.append({"family_id": family_id, "distro": distro_token, "reason": min_interval_reason})
            continue
        if quota_full and int(new_counts["normal"]) <= 0 and int(new_counts["suspicious"]) <= 0 and last_training_ts > 0:
            blocked_families.append({"family_id": family_id, "distro": distro_token, "reason": "quota_full_no_new_data"})
            continue

        initial_training = last_training_ts <= 0.0
        threshold_met = (
            initial_training
            or int(new_counts["normal"]) >= int(schedule_cfg["normal_new_label_threshold"])
            or int(new_counts["suspicious"]) >= int(schedule_cfg["suspicious_new_label_threshold"])
        )
        schedule_due = bool(window.get("schedule_due", False))
        eligible_item = {
            "family_id": family_id,
            "distro": distro_token,
            "mode": "initial_training" if initial_training else "retrain",
            "reason": "initial_training_eligible" if initial_training else ("new_label_threshold_met" if threshold_met else "seed_training_ready"),
            "labels_since_last_train": dict(new_counts),
            "last_training_at": iso_local(last_training_ts),
            "schedule_due": schedule_due,
            "threshold_met": threshold_met,
            "initial_training": initial_training,
        }
        eligible_seed_families.append(dict(eligible_item))
        eligible_families.append(dict(eligible_item))
        if threshold_met:
            threshold_candidates.append(dict(eligible_item))
        if initial_training or threshold_met:
            execution_candidates.append(dict(eligible_item))
        else:
            blocked_families.append({"family_id": family_id, "distro": distro_token, "reason": "insufficient_new_labels"})

    manual_train_now_eligible = bool(eligible_families)
    selected_execution_candidates = scheduler_select_execution_candidates(
        execution_candidates,
        int(schedule_cfg.get("max_families_per_run", 1) or 1),
    )
    scheduled_candidates = [item for item in selected_execution_candidates if bool(item.get("schedule_due", False))]
    threshold_execute_candidates = [item for item in selected_execution_candidates if bool(item.get("threshold_met", False))]
    train_now = False
    overall_reason = ""
    if training_mode == "disabled":
        overall_reason = "training_disabled"
    elif all_global_blocked:
        overall_reason = "ml_paused" if bool(global_audit.get("ml_paused", False)) else "open_incident"
    elif trigger_mode == "manual_dry_run":
        train_now = bool(eligible_families)
        overall_reason = "manual_train_now_eligible" if train_now else "readiness_blocked"
    elif trigger_mode == "manual_execute":
        train_now = bool(selected_execution_candidates)
        if train_now:
            overall_reason = "manual_train_now_eligible"
        else:
            blocked_reasons = [str(item.get("reason", "") or "") for item in blocked_families]
            if blocked_reasons and all(reason == "quota_full_no_new_data" for reason in blocked_reasons):
                overall_reason = "quota_full_no_new_data"
            elif blocked_reasons and "seed_readiness_blocked" in blocked_reasons:
                overall_reason = "readiness_blocked"
            elif blocked_reasons:
                overall_reason = blocked_reasons[0]
            else:
                overall_reason = "insufficient_labels"
    elif training_mode == "manual":
        if eligible_families:
            overall_reason = "manual_training_required"
        else:
            blocked_reasons = [str(item.get("reason", "") or "") for item in blocked_families]
            overall_reason = blocked_reasons[0] if blocked_reasons else "manual_mode_waiting_for_user"
    elif training_mode == "scheduled":
        train_now = bool(scheduled_candidates)
        if scheduled_candidates:
            overall_reason = str((scheduled_candidates[0] if scheduled_candidates else {}).get("reason", "scheduled_training_ready") or "scheduled_training_ready")
        else:
            blocked_reasons = [str(item.get("reason", "") or "") for item in blocked_families]
            overall_reason = blocked_reasons[0] if blocked_reasons else "insufficient_schedule_window"
    elif training_mode == "threshold":
        train_now = bool(threshold_execute_candidates)
        if threshold_execute_candidates:
            overall_reason = str((threshold_execute_candidates[0] if threshold_execute_candidates else {}).get("reason", "new_label_threshold_met") or "new_label_threshold_met")
        else:
            blocked_reasons = [str(item.get("reason", "") or "") for item in blocked_families]
            overall_reason = blocked_reasons[0] if blocked_reasons else "insufficient_new_labels"
    elif training_mode == "auto":
        train_now = bool(selected_execution_candidates)
        if train_now:
            overall_reason = str((selected_execution_candidates[0] if selected_execution_candidates else {}).get("reason", "auto_training_ready") or "auto_training_ready")
        else:
            blocked_reasons = [str(item.get("reason", "") or "") for item in blocked_families]
            overall_reason = blocked_reasons[0] if blocked_reasons else "auto_mode_waiting_for_readiness"
    elif eligible_families:
        overall_reason = str(eligible_families[0].get("reason", "training_eligible") or "training_eligible")
    else:
        blocked_reasons = [str(item.get("reason", "") or "") for item in blocked_families]
        if blocked_reasons and all(reason == "quota_full_no_new_data" for reason in blocked_reasons):
            overall_reason = "quota_full_no_new_data"
        elif blocked_reasons and "seed_readiness_blocked" in blocked_reasons:
            overall_reason = "readiness_blocked"
        elif blocked_reasons:
            overall_reason = blocked_reasons[0]
        else:
            overall_reason = "insufficient_labels"

    last_training_times = [
        parse_timestamp(dict(item or {}).get("trained_at"))
        for item in dict(scheduler_state.get("last_training", {}) or {}).values()
    ]
    last_training_times = [ts for ts in last_training_times if ts > 0]
    first_training_completed_at = str(raw_scheduler_state.get("first_model_training_completed_at", raw_scheduler_state.get("first_training_completed_at", "")) or "")
    first_training_status = str(raw_scheduler_state.get("first_model_training_status", raw_scheduler_state.get("first_training_status", "")) or "")
    first_evaluation_status = str(raw_scheduler_state.get("first_model_evaluation_status", raw_scheduler_state.get("first_evaluation_status", "")) or "")
    first_ml_model_ready = bool(raw_scheduler_state.get("first_ml_model_ready", raw_scheduler_state.get("ml_alert_family_ready", raw_scheduler_state.get("first_shadow_model_ready", False))))
    return {
        "current_time": iso_local(now_ts),
        "training_mode": training_mode,
        "trigger_request": trigger_mode,
        "last_scheduler_check_at": str(raw_scheduler_state.get("last_scheduler_check_at", "") or ""),
        "schedule_due": bool(window.get("schedule_due", False)),
        "scheduler_due": bool(window.get("schedule_due", False)),
        "next_run_at": iso_local(window.get("next_run_at", 0.0)),
        "scheduled_day": str(schedule_cfg.get("weekday", "sunday")),
        "scheduled_time": f"{int(schedule_cfg.get('hour', 3)):02d}:{int(schedule_cfg.get('minute', 0)):02d}",
        "train_now": bool(train_now),
        "manual_train_now_eligible": manual_train_now_eligible,
        "manual_trigger_required": training_mode == "manual",
        "reason": overall_reason,
        "eligible_families": eligible_families,
        "eligible_seed_families": eligible_seed_families,
        "execution_candidates": selected_execution_candidates,
        "scheduled_candidates": scheduled_candidates,
        "threshold_candidates": threshold_candidates,
        "blocked_families": blocked_families,
        "labels_since_last_train": labels_since_last_train,
        "quota_status": quota_status,
        "readiness_status": readiness_status,
        "last_training_time": iso_local(max(last_training_times)) if last_training_times else "",
        "last_training_at": str(raw_scheduler_state.get("last_training_at", "") or ""),
        "last_training_status": str(raw_scheduler_state.get("last_training_status", "") or ""),
        "last_training_reason": str(raw_scheduler_state.get("last_training_reason", "") or ""),
        "last_training_family_distro": str(raw_scheduler_state.get("last_training_family_distro", "") or ""),
        "last_training_label_counts": dict(raw_scheduler_state.get("last_training_label_counts", {}) or {}),
        "last_evaluation_status": str(raw_scheduler_state.get("last_evaluation_status", "") or ""),
        "first_model_training_completed": bool(first_training_completed_at),
        "first_model_training_completed_at": first_training_completed_at,
        "first_model_training_status": first_training_status,
        "first_model_evaluation_passed": first_evaluation_status.strip().lower() in {"pass", "passed", "evaluation_passed"},
        "first_model_evaluation_status": first_evaluation_status,
        "first_ml_model_ready": first_ml_model_ready,
        "ml_alert_family_ready": bool(raw_scheduler_state.get("ml_alert_family_ready", first_ml_model_ready)),
        "ml_alert_family_enabled_families": sorted({str(item or "").strip() for item in list(raw_scheduler_state.get("ml_alert_family_enabled_families", []) or []) if str(item or "").strip()}),
        "last_model_promoted": bool(raw_scheduler_state.get("last_model_promoted", False)),
        "last_model_kept_reason": str(raw_scheduler_state.get("last_model_kept_reason", "") or ""),
        "open_incidents": open_incidents,
        "no_action_contract": True,
        "training_started": False,
        "db_write_attempted": False,
        "active_ml_enabled": False,
        "evaluation_required": bool(eligible_families) and trigger_mode == "manual_execute",
        "trained_families": [],
        "evaluation_results": [],
        "promoted_models": [],
        "kept_existing_models": [],
        "llm_called": False,
        "firewall_action_taken": False,
        "ip_block_action_taken": False,
        "incident_action_taken": False,
        "evaluation_promotion_contract": {
            "evaluation_required": True,
            "promotion_on_pass_only": True,
            "retain_existing_model_on_failure": True,
            "real_model_promotion_started": False,
            "active_ml_enable_unchanged": True,
            "ml_alert_family_separate": True,
        },
        "resource_limits": {
            "cpu_only": bool(schedule_cfg.get("cpu_only", True)),
            "max_families_per_run": int(schedule_cfg.get("max_families_per_run", 1) or 1),
            "max_samples_per_family": int(schedule_cfg.get("max_samples_per_family", 0) or 0),
            "training_timeout_seconds": int(schedule_cfg.get("training_timeout_seconds", 0) or 0),
            "min_seconds_between_training": int(schedule_cfg.get("min_seconds_between_training", 0) or 0),
        },
        "scheduler_contract_defined_in": "main.py::collect_ml_training_scheduler_report",
        "query_notes": [labels_error] if labels_error else [],
    }


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


__all__ = [
    "bind_label_training_phase_gate",
    "collect_label_training_phase_gate_report",
    "collect_ml_training_scheduler_report",
    "collect_seed_training_readiness",
    "count_new_training_labels",
    "label_duplicate_snapshot",
    "label_evidence_fields",
    "label_log_source",
    "label_timestamp_confidence",
    "open_incident_count",
    "phase_gate_training_state",
    "quota_bucket_full",
    "training_eligibility_for_cohort",
    "training_scheduler_label_inventory",
]
