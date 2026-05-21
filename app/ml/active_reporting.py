from __future__ import annotations

import copy
import time
from typing import Any, Callable


def compute_ml_family_support_score(
    *,
    family_id: str,
    event: dict | None,
    readiness_result: dict,
    family_config: dict,
    baseline_summary: dict | None = None,
    get_ml_family_spec: Callable[[str], Any],
    time_module=time,
) -> dict:
    family_key = (family_id or "").strip().upper()
    event_payload = copy.deepcopy(event or {})
    readiness = dict(readiness_result or {})
    contract = dict(family_config or {})
    baseline = dict(baseline_summary or {})
    spec = get_ml_family_spec(family_key)
    event_ts = float(event_payload.get("ts", time_module.time()) or time_module.time())
    local_tm = time_module.localtime(event_ts)
    hour_of_day = int(local_tm.tm_hour)
    day_of_week = int(local_tm.tm_wday)
    is_weekend = day_of_week >= 5
    is_night = hour_of_day < 6 or hour_of_day >= 22
    timezone_name = time_module.strftime("%Z", local_tm)
    timezone_offset = time_module.strftime("%z", local_tm)
    can_score_support = bool(readiness.get("can_score_support", False))
    readiness_reason = (readiness.get("reason", "") or "").strip() or "readiness_not_met"

    result = {
        "family_id": family_key,
        "scored": False,
        "score": 0.0,
        "normalized_score": 0.0,
        "confidence": 0.0,
        "reason": readiness_reason if not can_score_support else "support_score_ready",
        "top_features": [],
        "time_context": {
            "event_ts": event_ts,
            "hour_of_day": hour_of_day,
            "day_of_week": day_of_week,
            "is_weekend": is_weekend,
            "is_night": is_night,
            "timezone_name": timezone_name,
            "timezone_offset": timezone_offset,
        },
        "baseline_deviation": {
            "expected_sources": list(baseline.get("expected_sources", []) or []),
            "expected_actions": list(baseline.get("expected_actions", []) or []),
            "expected_categories": list(baseline.get("expected_categories", []) or []),
            "observed_source": str(event_payload.get("source", "") or ""),
            "observed_action": str(event_payload.get("action", "") or ""),
            "observed_category": str(event_payload.get("category", "") or ""),
            "score_component": 0.0,
            "available": bool(baseline),
        },
        "can_emit_alert": False,
        "no_action_contract": bool(contract.get("no_action_contract", True)),
        "db_write_attempted": False,
        "risk_score_changed": False,
        "runtime_output_changed": False,
    }
    if not can_score_support:
        if readiness.get("status") in {"paused", "disabled"}:
            result["reason"] = readiness.get("reason", readiness.get("status", "readiness_not_met"))
        return result

    primary_features = list(getattr(spec, "primary_features", ()) or ())
    present_features = 0
    missing_features = []
    for key in primary_features:
        value = event_payload.get(key)
        if value not in (None, "", [], {}):
            present_features += 1
        else:
            missing_features.append(key)
    completeness_ratio = (present_features / len(primary_features)) if primary_features else 0.0
    completeness_score = completeness_ratio * 40.0
    result["top_features"].append(f"field_completeness={completeness_ratio:.2f}")

    family_category = str(getattr(spec, "category", "") or "").strip().lower()
    event_category = str(event_payload.get("category", "") or "").strip().lower()
    event_action = str(event_payload.get("action", "") or "").strip().lower()
    event_source = str(event_payload.get("source", "") or "").strip().lower()

    category_match = 1.0 if family_category and family_category in event_category else 0.0
    action_presence = 1.0 if event_action else 0.0
    source_presence = 1.0 if event_source else 0.0
    family_match_score = (category_match * 15.0) + (action_presence * 5.0) + (source_presence * 5.0)
    result["top_features"].append(
        f"family_match=category:{category_match:.0f},action:{action_presence:.0f},source:{source_presence:.0f}"
    )

    time_anomaly_placeholder = 0.7 if is_night else (0.4 if is_weekend else 0.2)
    time_score = time_anomaly_placeholder * 15.0
    result["top_features"].append(f"time_anomaly_placeholder={time_anomaly_placeholder:.2f}")

    baseline_score = 0.0
    if baseline:
        expected_sources = {str(item).strip().lower() for item in baseline.get("expected_sources", []) or [] if str(item).strip()}
        expected_actions = {str(item).strip().lower() for item in baseline.get("expected_actions", []) or [] if str(item).strip()}
        expected_categories = {str(item).strip().lower() for item in baseline.get("expected_categories", []) or [] if str(item).strip()}
        mismatches = 0
        comparisons = 0
        if expected_sources:
            comparisons += 1
            mismatches += 0 if event_source in expected_sources else 1
        if expected_actions:
            comparisons += 1
            mismatches += 0 if event_action in expected_actions else 1
        if expected_categories:
            comparisons += 1
            mismatches += 0 if event_category in expected_categories else 1
        deviation_ratio = (mismatches / comparisons) if comparisons else 0.0
        baseline_score = deviation_ratio * 10.0
        result["baseline_deviation"]["score_component"] = round(baseline_score, 2)
        result["baseline_deviation"]["deviation_ratio"] = round(deviation_ratio, 4)
        result["top_features"].append(f"baseline_deviation={deviation_ratio:.2f}")
    else:
        result["top_features"].append("baseline_deviation=unavailable")

    raw_score = max(0.0, min(100.0, completeness_score + family_match_score + time_score + baseline_score))
    threshold_checks = [
        readiness.get("phase_gate_ok", False),
        readiness.get("event_threshold_ok", False),
        readiness.get("normal_label_threshold_ok", False),
        readiness.get("suspicious_label_threshold_ok", False),
        readiness.get("field_quality_ok", False),
        readiness.get("time_coverage_ok", False),
        readiness.get("trust_support_ok", False),
        readiness.get("metadata_support_ok", False),
    ]
    readiness_confidence = sum(1 for item in threshold_checks if item) / len(threshold_checks) if threshold_checks else 0.0
    confidence = max(0.0, min(1.0, (completeness_ratio * 0.6) + (readiness_confidence * 0.4)))

    result.update({
        "scored": True,
        "score": round(raw_score, 2),
        "normalized_score": round(raw_score / 100.0, 4),
        "confidence": round(confidence, 4),
        "reason": "support_score_ready",
    })
    if missing_features:
        result["top_features"].append(f"missing_features={','.join(missing_features[:5])}")
    return result


def _sample_support_event_for_family(family_id: str, *, time_module=time) -> dict:
    family_key = (family_id or "").strip().upper()
    samples = {
        "ML-PROC": {"source": "auditd", "category": "process", "action": "exec", "process": "/usr/bin/apt", "host": "host-1", "username": "root", "src_ip": "127.0.0.1"},
        "ML-AUTH": {"source": "auth_log", "category": "auth", "action": "ssh_login", "outcome": "success", "host": "host-1", "username": "alice", "src_ip": "10.0.0.5"},
        "ML-NET": {"source": "dns", "category": "network", "action": "dns_query", "host": "host-1", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dst_port": 53},
    }
    sample = dict(samples.get(family_key, {"source": "syslog", "category": "system", "action": "heartbeat", "host": "host-1"}))
    sample["ts"] = time_module.time()
    return sample


def print_ml_family_support_score(result: dict) -> None:
    print(f"\n{'━'*58}")
    print("  ML Family Support Score")
    print(f"{'━'*58}")
    print(f"  family_id={result.get('family_id', '')}")
    print(f"  scored={result.get('scored', False)}")
    print(f"  score={result.get('score', 0.0)}")
    print(f"  normalized_score={result.get('normalized_score', 0.0)}")
    print(f"  confidence={result.get('confidence', 0.0)}")
    print(f"  reason={result.get('reason', '')}")
    print(f"  top_features={result.get('top_features', [])}")
    print(f"  time_context={result.get('time_context', {})}")
    print(f"  baseline_deviation={result.get('baseline_deviation', {})}")
    print(f"  can_emit_alert={result.get('can_emit_alert', False)}")
    print(f"  no_action_contract={result.get('no_action_contract', False)}")
    print(f"  db_write_attempted={result.get('db_write_attempted', False)}")
    print(f"  risk_score_changed={result.get('risk_score_changed', False)}")
    print(f"  runtime_output_changed={result.get('runtime_output_changed', False)}")
    print(f"{'━'*58}\n")


def run_ml_support_score_family(
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
    compute_ml_family_support_score: Callable[..., dict],
    sample_support_event_for_family: Callable[[str], dict],
    print_ml_family_support_score: Callable[[dict], None],
    sys_module,
) -> int:
    requested_family = (family_id or "").strip().upper()
    if not requested_family:
        print("--ml-support-score-family için FAMILY_ID zorunlu.", file=sys_module.stderr)
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
        label_counts = ((global_audit.get("label_quality", {}) or {}).get("family_counts", {}) or {}).get(requested_family, {}) or {}
        readiness = evaluate_ml_family_readiness(
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
            active_decision_layer=((config.get("ml", {}) or {}).get("active_decision_layer", {}) or {}),
            linked_process_events=int(metrics.get("linked_process_events", 0) or 0),
            duplicate_rate=float(global_audit.get("duplicate_rate", 0.0) or 0.0),
            parse_fail_rate=float(global_audit.get("parse_fail_rate", 0.0) or 0.0),
            process_tree_count=int(global_audit.get("counts", {}).get("process_tree", 0) or 0),
            errors=list(notes or []) + ([f"db_fallback:{db_error}"] if db_error else []),
        )
        result = compute_ml_family_support_score(
            family_id=requested_family,
            event=sample_support_event_for_family(requested_family),
            readiness_result=readiness,
            family_config=cfg,
            baseline_summary={},
        )
        print_ml_family_support_score(result)
    finally:
        if db:
            db.close()
    return 0


def build_active_ml_alert_candidate(
    *,
    event: dict | object | None,
    family_id: str,
    readiness_result: dict,
    support_score_result: dict,
    active_decision_layer: dict | None,
    family_config: dict | None,
    related_rule_context: dict | None = None,
    coerce_ml_event_fields: Callable[[dict | object | None], dict],
    get_ml_family_spec: Callable[[str], Any],
    build_ml_family_gate_snapshot: Callable[[dict], dict],
    default_ml_label_for_family: Callable[[str, dict | None], str],
    build_ml_correlation_safe_metadata: Callable[[dict, dict | None, dict | None], dict],
    ml_active_emit_defaults: dict,
    build_ml_alert_explanation_metadata: Callable[..., dict],
    ml_active_message: Callable[[str, dict], str],
    risk_score_for_ml_active_score: Callable[[float, float], float],
    severity_for_ml_active_score: Callable[[float, float], str],
    ml_active_category: Callable[[str], str],
    ml_active_mitre_defaults: dict,
) -> dict:
    family_key = (family_id or "").strip().upper()
    event_payload = coerce_ml_event_fields(event)
    readiness = copy.deepcopy(readiness_result or {})
    support_score = copy.deepcopy(support_score_result or {})
    active_layer = dict(active_decision_layer or {})
    contract = dict(family_config or {})
    spec = get_ml_family_spec(family_key)
    gate_snapshot = build_ml_family_gate_snapshot(readiness)
    min_score = float(contract.get("active_emit_min_score", active_layer.get("min_score", ml_active_emit_defaults["min_score"])) or ml_active_emit_defaults["min_score"])
    min_confidence = float(contract.get("active_emit_min_confidence", active_layer.get("min_confidence", ml_active_emit_defaults["min_confidence"])) or ml_active_emit_defaults["min_confidence"])
    no_action_contract = bool(contract.get("no_action_contract", True)) and bool(active_layer.get("no_action_contract", True))
    active_mode = str(active_layer.get("mode", "audit_only") or "audit_only").strip().lower()
    active_enabled = bool(active_layer.get("enabled", False))
    blocked_reason = ""
    related = copy.deepcopy(related_rule_context or {})

    candidate = {
        "family_id": family_key,
        "valid": False,
        "emit_allowed": False,
        "emit_blocked_reason": "",
        "rule_id": f"{family_key}-001" if family_key else "",
        "category": ml_active_category(family_key),
        "severity": "low",
        "risk_score": 0.0,
        "message": "",
        "source": "ml_active_decision_layer",
        "ml_label": default_ml_label_for_family(family_key, related),
        "family_gate_snapshot": gate_snapshot,
        "model_score": float(support_score.get("score", 0.0) or 0.0),
        "normalized_score": float(support_score.get("normalized_score", 0.0) or 0.0),
        "confidence": float(support_score.get("confidence", 0.0) or 0.0),
        "top_features": list(support_score.get("top_features", []) or []),
        "time_context": dict(support_score.get("time_context", {}) or {}),
        "baseline_deviation": dict(support_score.get("baseline_deviation", {}) or {}),
        "supporting_event_fields": event_payload,
        "related_rule_context": related,
        "correlation_metadata": build_ml_correlation_safe_metadata(event_payload, related, active_layer),
        "no_action_contract": no_action_contract,
        "action_taken": False,
        "can_emit_alert": False,
        "db_write_attempted": False,
        "runtime_output_changed": False,
        "risk_score_changed": False,
        "firewall_called": False,
        "ip_block_called": False,
        "quarantine_called": False,
        "delete_called": False,
        "explanation_metadata": {},
        "context_json": {},
        "mitre_tactic": "",
        "mitre_technique": "",
        "tags": [],
    }
    if spec is None:
        candidate["emit_blocked_reason"] = "invalid_family"
        return candidate
    if not active_enabled:
        blocked_reason = "active_decision_layer_disabled"
    elif active_mode != "active":
        blocked_reason = "audit_only_mode"
    elif not no_action_contract:
        blocked_reason = "no_action_contract_missing"
    elif readiness.get("status") == "paused":
        blocked_reason = "ml_paused"
    elif readiness.get("status") == "disabled":
        blocked_reason = "family_disabled"
    elif readiness.get("status") == "needs_more_data":
        blocked_reason = "needs_more_data"
    elif readiness.get("status") == "readiness_blocked":
        blocked_reason = "readiness_blocked"
    elif not bool(readiness.get("can_emit_alert", False)):
        blocked_reason = str(readiness.get("reason", "") or "emit_not_allowed")
    elif not all(gate_snapshot.get(key, False) for key in (
        "phase_gate_ok",
        "event_threshold_ok",
        "normal_label_threshold_ok",
        "suspicious_label_threshold_ok",
        "field_quality_ok",
        "time_coverage_ok",
        "trust_support_ok",
        "metadata_support_ok",
    )):
        blocked_reason = "family_gate_not_met"
    elif not bool(support_score.get("scored", False)):
        blocked_reason = str(support_score.get("reason", "") or "support_score_unavailable")
    elif float(support_score.get("score", 0.0) or 0.0) < min_score:
        blocked_reason = "score_below_threshold"
    elif float(support_score.get("confidence", 0.0) or 0.0) < min_confidence:
        blocked_reason = "confidence_below_threshold"
    elif bool((related.get("learning_freeze", {}) or {}).get("active", False)):
        blocked_reason = "learning_freeze_active"

    explanation = build_ml_alert_explanation_metadata(
        support_score=support_score,
        readiness_result=readiness,
        supporting_event_fields={**event_payload, "ml_label": candidate["ml_label"]},
        support_or_active="active" if not blocked_reason else "support",
        can_emit_alert=not bool(blocked_reason),
    )
    candidate["message"] = ml_active_message(family_key, explanation)
    candidate["explanation_metadata"] = explanation

    if blocked_reason:
        candidate["emit_blocked_reason"] = blocked_reason
        candidate["context_json"] = {
            "source": candidate["source"],
            "ml_family": family_key,
            "ml_label": candidate["ml_label"],
            "ml_family_status": readiness.get("status", "readiness_blocked"),
            "readiness_reason": readiness.get("reason", "readiness_not_met"),
            "family_gate_snapshot": gate_snapshot,
            "support_score_result": support_score,
            "explanation_metadata": explanation,
            "no_action_contract": no_action_contract,
            "action_taken": False,
            "emit_blocked_reason": blocked_reason,
            "correlation_metadata": candidate["correlation_metadata"],
        }
        return candidate

    risk_score = risk_score_for_ml_active_score(candidate["model_score"], candidate["confidence"])
    severity = severity_for_ml_active_score(candidate["model_score"], candidate["confidence"])
    mitre_tactic, mitre_technique, tags = ml_active_mitre_defaults.get(
        family_key,
        ("TA0043", "T1595", ["ml", family_key.lower().replace("-", "_"), "no_action_contract"]),
    )
    candidate.update({
        "valid": True,
        "emit_allowed": True,
        "severity": severity,
        "risk_score": risk_score,
        "can_emit_alert": True,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "tags": list(tags),
    })
    candidate["context_json"] = {
        "source": candidate["source"],
        "ml_family": family_key,
        "ml_label": candidate["ml_label"],
        "ml_family_status": readiness.get("status", "active"),
        "readiness_reason": readiness.get("reason", "ready"),
        "family_gate_snapshot": gate_snapshot,
        "model_score": candidate["model_score"],
        "normalized_score": candidate["normalized_score"],
        "confidence": candidate["confidence"],
        "top_features": candidate["top_features"],
        "time_context": candidate["time_context"],
        "baseline_deviation": candidate["baseline_deviation"],
        "supporting_event_fields": event_payload,
        "explanation_metadata": explanation,
        "no_action_contract": True,
        "action_taken": False,
        "can_emit_alert": True,
        "correlation_metadata": candidate["correlation_metadata"],
    }
    return candidate


def emit_active_ml_alert_if_allowed(
    *,
    event: dict | object | None,
    family_id: str,
    readiness_result: dict,
    support_score_result: dict,
    active_decision_layer: dict | None,
    family_config: dict | None,
    related_rule_context: dict | None = None,
    emit_callback=None,
    dry_run: bool = False,
    build_active_ml_alert_candidate: Callable[..., dict],
) -> dict:
    candidate = build_active_ml_alert_candidate(
        event=event,
        family_id=family_id,
        readiness_result=readiness_result,
        support_score_result=support_score_result,
        active_decision_layer=active_decision_layer,
        family_config=family_config,
        related_rule_context=related_rule_context,
    )
    result = copy.deepcopy(candidate)
    result["emitted"] = False
    if dry_run or not candidate.get("emit_allowed", False) or emit_callback is None:
        return result
    emit_callback(copy.deepcopy(candidate))
    result["emitted"] = True
    result["db_write_attempted"] = True
    return result


def print_ml_active_emit_dry_run(candidate: dict) -> None:
    print(f"\n{'━'*58}")
    print("  ML Active Emit Dry Run")
    print(f"{'━'*58}")
    print(f"  family_id={candidate.get('family_id', '')}")
    print(f"  valid={candidate.get('valid', False)}")
    print(f"  emit_allowed={candidate.get('emit_allowed', False)}")
    print(f"  emit_blocked_reason={candidate.get('emit_blocked_reason', '')}")
    print(f"  rule_id={candidate.get('rule_id', '')}")
    print(f"  category={candidate.get('category', '')}")
    print(f"  severity={candidate.get('severity', '')}")
    print(f"  risk_score={candidate.get('risk_score', 0.0)}")
    print(f"  message={candidate.get('message', '')}")
    print(f"  no_action_contract={candidate.get('no_action_contract', False)}")
    print(f"  action_taken={candidate.get('action_taken', False)}")
    print(f"  can_emit_alert={candidate.get('can_emit_alert', False)}")
    print(f"  db_write_attempted={candidate.get('db_write_attempted', False)}")
    print(f"  correlation_metadata={candidate.get('correlation_metadata', {})}")
    print(f"{'━'*58}\n")


def run_ml_active_emit_dry_run(
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
    compute_ml_family_support_score: Callable[..., dict],
    sample_support_event_for_family: Callable[[str], dict],
    emit_active_ml_alert_if_allowed: Callable[..., dict],
    print_ml_active_emit_dry_run: Callable[[dict], None],
    sys_module,
) -> int:
    requested_family = (family_id or "").strip().upper()
    if not requested_family:
        print("--ml-active-emit-dry-run için FAMILY_ID zorunlu.", file=sys_module.stderr)
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
        active_layer = dict(((config.get("ml", {}) or {}).get("active_decision_layer", {}) or {}))
        active_layer.update({"enabled": True, "mode": "active", "no_action_contract": True})
        readiness = evaluate_ml_family_readiness(
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
            errors=list(notes or []) + ([f"db_fallback:{db_error}"] if db_error else []),
        )
        support = compute_ml_family_support_score(
            family_id=requested_family,
            event=sample_support_event_for_family(requested_family),
            readiness_result=readiness,
            family_config=cfg,
            baseline_summary={},
        )
        candidate = emit_active_ml_alert_if_allowed(
            event=sample_support_event_for_family(requested_family),
            family_id=requested_family,
            readiness_result=readiness,
            support_score_result=support,
            active_decision_layer=active_layer,
            family_config=cfg,
            related_rule_context={},
            dry_run=True,
        )
        print_ml_active_emit_dry_run(candidate)
    finally:
        if db:
            db.close()
    return 0


def build_runtime_ml_label_candidate_from_rule(
    rule_id: str,
    severity: str = "",
    risk_score: float = 0.0,
    event: dict | None = None,
    alert_context: dict | None = None,
    message: str = "",
    *,
    resolve_rule_id_to_ml_family: Callable[[str], Any],
    build_ml_label_metadata: Callable[..., dict],
    validate_ml_label_metadata: Callable[[dict], dict],
) -> dict:
    normalized_rule_id = (rule_id or "").strip().upper()
    normalized_severity = (severity or "").strip().lower() or "medium"
    normalized_message = (message or "").strip()
    event_payload = copy.deepcopy(event or {})
    context_payload = copy.deepcopy(alert_context or {})
    resolved = resolve_rule_id_to_ml_family(normalized_rule_id)

    candidate = {
        "matched": bool(resolved.matched),
        "rule_id": normalized_rule_id,
        "severity": normalized_severity,
        "risk_score": float(risk_score or 0.0),
        "message": normalized_message,
        "resolver_result": resolved.to_dict(),
        "metadata": None,
        "validation": {"valid": False, "problems": ["unmapped_rule_id"], "metadata": {}},
        "no_action_contract": True,
        "db_write_attempted": False,
        "active_training_enabled": False,
        "runtime_output_changed": False,
        "risk_score_changed": False,
        "event_snapshot": event_payload,
        "alert_context_snapshot": context_payload,
    }
    if not resolved.matched:
        return candidate

    source_type = "rule_mapped_attack" if resolved.label_class == "attack" else "auto_labeled_rule_mapped"
    model_usage_scope = "calibration_only"
    metadata = build_ml_label_metadata(
        source_type,
        resolved.ml_family or "",
        resolved.ml_label or "",
        behavior_label=resolved.ml_label or "",
        event_class="attack" if resolved.label_class == "attack" else "suspicious",
        rule_id=normalized_rule_id,
        evidence_fields={
            "rule_id": normalized_rule_id,
            "severity": normalized_severity,
            "risk_score": float(risk_score or 0.0),
            "message": normalized_message,
            "event": event_payload,
            "alert_context": context_payload,
            "resolver_mapping_reason": resolved.mapping_reason,
        },
        label_reason=f"runtime_rule_candidate_audit:{resolved.mapping_reason}",
        source_trust=resolved.source_trust,
        model_usage_scope=model_usage_scope,
        learnable=False if source_type == "rule_mapped_attack" else True,
    )
    validation = validate_ml_label_metadata(metadata)
    candidate.update({
        "source_type": source_type,
        "metadata": metadata,
        "validation": validation,
        "matched": bool(validation.get("valid") is True),
    })
    return candidate


def print_runtime_ml_label_candidate_audit(candidate: dict) -> None:
    print(f"\n{'━'*58}")
    print("  ML Runtime Label Candidate Audit")
    print(f"{'━'*58}")
    print(f"  rule_id={candidate.get('rule_id', '')}")
    print(f"  matched={candidate.get('matched', False)}")
    print(f"  severity={candidate.get('severity', '')}")
    print(f"  risk_score={candidate.get('risk_score', 0.0)}")
    print(f"  no_action_contract={candidate.get('no_action_contract', False)}")
    print(f"  db_write_attempted={candidate.get('db_write_attempted', False)}")
    print(f"  active_training_enabled={candidate.get('active_training_enabled', False)}")
    print(f"  runtime_output_changed={candidate.get('runtime_output_changed', False)}")
    print(f"  risk_score_changed={candidate.get('risk_score_changed', False)}")
    resolver = candidate.get("resolver_result", {}) or {}
    print(f"  resolver_result={resolver}")
    metadata = candidate.get("metadata")
    if metadata:
        print(
            "  metadata="
            f"source_type={metadata.get('source_type')} "
            f"ml_family={metadata.get('ml_family')} "
            f"ml_label={metadata.get('ml_label')} "
            f"event_class={metadata.get('event_class')} "
            f"source_trust={metadata.get('source_trust')} "
            f"model_usage_scope={metadata.get('model_usage_scope')}"
        )
    print(f"  validation={candidate.get('validation', {})}")
    print(f"{'━'*58}\n")


__all__ = [
    "compute_ml_family_support_score",
    "_sample_support_event_for_family",
    "print_ml_family_support_score",
    "run_ml_support_score_family",
    "build_active_ml_alert_candidate",
    "emit_active_ml_alert_if_allowed",
    "print_ml_active_emit_dry_run",
    "run_ml_active_emit_dry_run",
    "build_runtime_ml_label_candidate_from_rule",
    "print_runtime_ml_label_candidate_audit",
]
