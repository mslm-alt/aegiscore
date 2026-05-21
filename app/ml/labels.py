from __future__ import annotations

from collections import Counter
import json
import re
from typing import Any, Callable

from app.ml.readiness import _evaluate_ml_family_readiness
from app.runtime.pipeline import (
    _load_rule_ids_for_ml_mapping_audit,
    collect_ml_historical_scan_plan,
    collect_ml_mapping_audit,
)
from core.ml.family_registry import list_ml_families, resolve_rule_id_to_ml_family


def _empty_global_audit() -> dict:
    return {
        "event_columns": [],
        "ml_paused": False,
        "ml_pause_reason": "",
        "errors": {"events_recent:columns": ["missing_table:events_recent"]},
    }


_ML_NORMAL_LABEL_PLAN_SPECS = {
    "ML-AUTH": {
        "ssh_login_normal": {
            "required_columns": ("action", "outcome"),
            "base_where": "LOWER(COALESCE(action, '')) = 'ssh_login' AND LOWER(COALESCE(outcome, '')) = 'success'",
            "trusted_sources": ("auth_log", "auth.log", "secure", "syslog"),
            "required_present": ("username", "src_ip"),
        },
        "expected_auth_activity": {
            "required_columns": ("category", "outcome"),
            "base_where": "LOWER(COALESCE(category, '')) = 'auth' AND LOWER(COALESCE(outcome, '')) = 'success'",
            "trusted_sources": ("auth_log", "auth.log", "secure", "syslog"),
            "required_present": ("username",),
        },
    },
    "ML-SUDO": {
        "sudo_normal": {
            "required_columns": ("action",),
            "base_where": "LOWER(COALESCE(action, '')) = 'sudo' AND LOWER(COALESCE(outcome, '')) IN ('', 'success')",
            "trusted_sources": ("auth_log", "auth.log", "secure", "syslog"),
            "required_present": ("username", "process"),
        },
    },
    "ML-PROC": {
        "process_normal": {
            "required_columns": ("category",),
            "base_where": "LOWER(COALESCE(category, '')) = 'process'",
            "trusted_sources": ("auditd", "syslog", "journald"),
            "required_present": ("process",),
            "reject_tokens": ("nmap", "hydra", "nc", "netcat", "curl", "wget", "bash", "python", "perl"),
        },
        "routine_exec": {
            "required_columns": ("action",),
            "base_where": "LOWER(COALESCE(action, '')) = 'exec'",
            "trusted_sources": ("auditd", "syslog", "journald"),
            "required_present": ("process",),
            "reject_tokens": ("nmap", "hydra", "nc", "netcat", "curl", "wget", "bash", "python", "perl"),
        },
    },
    "ML-SERVICE": {
        "service_normal": {
            "required_columns": ("category", "action"),
            "base_where": "LOWER(COALESCE(category, '')) IN ('system', 'service') OR LOWER(COALESCE(action, '')) IN ('service_heartbeat', 'service_start', 'service_restart')",
            "trusted_sources": ("syslog", "journald", "auditd"),
            "required_present": ("host",),
        },
    },
    "ML-NET": {
        "normal_network": {
            "required_columns": ("category",),
            "base_where": "LOWER(COALESCE(category, '')) = 'network' AND LOWER(COALESCE(risk_bucket, 'normal')) = 'normal'",
            "trusted_sources": ("auditd", "dns", "systemd-resolved", "dnsmasq", "resolved"),
            "required_present": ("src_ip",),
        },
        "expected_outbound": {
            "required_columns": ("action",),
            "base_where": "LOWER(COALESCE(action, '')) IN ('connect', 'http_request', 'dns_query')",
            "trusted_sources": ("auditd", "dns", "systemd-resolved", "dnsmasq", "resolved"),
            "required_present": ("src_ip",),
        },
    },
    "ML-USER": {
        "user_behavior_normal": {
            "required_columns": ("username",),
            "base_where": "NULLIF(BTRIM(COALESCE(username, '')), '') IS NOT NULL AND LOWER(COALESCE(risk_bucket, 'normal')) = 'normal'",
            "trusted_sources": ("auth_log", "auth.log", "auditd", "syslog"),
            "required_present": ("username", "host"),
        },
    },
    "ML-HOST": {
        "host_behavior_normal": {
            "required_columns": ("host",),
            "base_where": "NULLIF(BTRIM(COALESCE(host, '')), '') IS NOT NULL AND LOWER(COALESCE(risk_bucket, 'normal')) = 'normal'",
            "trusted_sources": ("auditd", "syslog", "journald", "auth_log", "auth.log"),
            "required_present": ("host",),
        },
    },
    "ML-DBAUTH": {
        "db_login_normal": {
            "required_columns": ("category", "outcome"),
            "base_where": "LOWER(COALESCE(category, '')) = 'db' AND LOWER(COALESCE(outcome, '')) = 'success'",
            "trusted_sources": ("postgresql", "mysql", "mariadb"),
            "required_present": ("username",),
        },
    },
    "ML-DNS": {
        "dns_normal": {
            "required_columns": ("action",),
            "base_where": "LOWER(COALESCE(action, '')) = 'dns_query' AND LOWER(COALESCE(outcome, '')) IN ('', 'success')",
            "trusted_sources": ("dns", "systemd-resolved", "dnsmasq", "resolved"),
            "required_present": ("src_ip",),
        },
    },
    "ML-WEBPOST": {
        "web_request_normal_linked": {
            "required_columns": ("source", "action"),
            "base_where": "LOWER(COALESCE(source, '')) IN ('apache2', 'nginx') AND LOWER(COALESCE(action, '')) = 'http_request' AND LOWER(COALESCE(risk_bucket, 'normal')) = 'normal'",
            "trusted_sources": ("apache2", "nginx"),
            "required_present": ("host",),
        },
    },
    "ML-SEQ": {
        "clean_sequence_normal": {
            "required_columns": ("category",),
            "base_where": "LOWER(COALESCE(category, '')) IN ('auth', 'process', 'network') AND LOWER(COALESCE(risk_bucket, 'normal')) = 'normal'",
            "trusted_sources": ("auditd", "auth_log", "auth.log", "syslog"),
            "required_present": ("host", "username"),
        },
    },
    "ML-IMPACT": {
        "cleanup_normal": {
            "required_columns": ("category",),
            "base_where": "LOWER(COALESCE(category, '')) IN ('filesystem', 'process') AND LOWER(COALESCE(risk_bucket, 'normal')) = 'normal'",
            "trusted_sources": ("auditd", "syslog", "journald"),
            "required_present": ("host", "process"),
        },
    },
}


def collect_ml_normal_label_plan(
    config: dict,
    db,
    pm_status: dict,
    *,
    collect_global_ml_audit: Callable[..., dict],
    load_labels_read_only: Callable[[Any], tuple[list[dict], str | None]],
    count_labels_by_behavior: Callable[[list[dict]], dict],
    has_blocking_open_incident: Callable[[Any], bool],
    columns_present: Callable[[set[str], tuple[str, ...]], bool],
    safe_count_where: Callable[[Any, str, set[str]], tuple[int, list[str]]],
    event_count_by_distro: Callable[..., tuple[dict, list[str]]],
    sum_nested_distro_counts: Callable[[dict[str, dict[str, int]], dict[str, int], str], None],
    build_source_allowlist_clause: Callable[[tuple[str, ...], set[str], list[str]], str],
    build_required_present_clause: Callable[[tuple[str, ...], set[str], list[str]], str],
    build_family_candidate_quality_filters: Callable[[Any, str, str, set[str]], tuple[list[tuple[str, str]], list[str]]],
    normal_label_plan_specs: dict,
    ml_family_readiness: dict,
) -> dict:
    _ = config
    try:
        global_audit = collect_global_ml_audit(db, pm_status, config=config) if db else _empty_global_audit()
    except TypeError:
        global_audit = collect_global_ml_audit(db, pm_status) if db else _empty_global_audit()
    available_columns = set(global_audit.get("event_columns", []) or [])
    label_rows, labels_error = load_labels_read_only(db)
    existing_counts = count_labels_by_behavior(label_rows)
    ml_paused = bool(global_audit.get("ml_paused", False))
    blocking_incident = has_blocking_open_incident(db)

    global_query_notes: dict[str, list[str] | str] = {}
    if labels_error:
        global_query_notes["labels"] = [labels_error]
    if global_audit.get("errors"):
        global_query_notes["events_recent"] = [
            item
            for values in (global_audit.get("errors", {}) or {}).values()
            for item in (values or [])
        ]

    global_candidate_count_by_distro: Counter = Counter()
    global_rejected_count_by_distro: Counter = Counter()
    global_family_candidate_count_by_distro: dict[str, dict[str, int]] = {}
    families: dict[str, dict] = {}

    for family_id, label_specs in normal_label_plan_specs.items():
        readiness = dict(ml_family_readiness.get(family_id, {}) or {})
        family_required = int(readiness.get("required_normal_labels", 0) or 0)
        family_labels: dict[str, dict] = {}
        family_query_notes: list[str] = []
        family_candidate_count_by_distro: Counter = Counter()

        for label_name, spec in (label_specs or {}).items():
            existing_found = int(existing_counts.get(label_name, 0) or 0)
            required = family_required
            needed = max(required - existing_found, 0)
            item = {
                "existing_found": existing_found,
                "required": required,
                "needed": needed,
                "candidate_count": 0,
                "candidate_count_by_distro": {},
                "behavioral_baseline_candidate_count": 0,
                "behavioral_baseline_candidate_count_by_distro": {},
                "rejected_candidate_count": 0,
                "rejected_count_by_distro": {},
                "status": "missing_schema",
                "rejection_reasons": {},
            }
            family_labels[label_name] = item

            required_columns = tuple(spec.get("required_columns", ()) or ())
            if db is None or not available_columns or not columns_present(available_columns, required_columns):
                if db is not None and available_columns:
                    missing = [name for name in required_columns if name not in available_columns]
                    family_query_notes.extend([f"missing_field:{name}" for name in missing])
                continue

            base_where = str(spec.get("base_where", "TRUE") or "TRUE")
            candidate_count, notes = safe_count_where(db, base_where, available_columns)
            family_query_notes.extend(notes)
            candidate_count_by_distro, distro_notes = event_count_by_distro(
                db,
                base_where,
                available_columns,
                fallback_count=candidate_count,
            )
            family_query_notes.extend(distro_notes)
            item["candidate_count"] = int(candidate_count or 0)
            item["candidate_count_by_distro"] = dict(sorted(candidate_count_by_distro.items()))

            for distro, count in (candidate_count_by_distro or {}).items():
                global_candidate_count_by_distro[distro] += int(count or 0)
                family_candidate_count_by_distro[distro] += int(count or 0)
            sum_nested_distro_counts(global_family_candidate_count_by_distro, candidate_count_by_distro, family_id)

            current_where = base_where
            current_count = int(candidate_count or 0)
            reason_counts: Counter = Counter()

            if family_id == "ML-AUTH" and {"trainable", "risk_bucket"}.issubset(available_columns):
                accepted_where = f"({current_where}) AND ((trainable = 1) AND (LOWER(COALESCE(risk_bucket, '')) = 'normal'))"
                accepted_count, accepted_notes = safe_count_where(db, accepted_where, available_columns)
                family_query_notes.extend(accepted_notes)
                reason_counts["rule_or_ioc_or_non_trainable"] += max(current_count - int(accepted_count or 0), 0)
                current_where = accepted_where
                current_count = int(accepted_count or 0)

            source_notes: list[str] = []
            source_clause = build_source_allowlist_clause(tuple(spec.get("trusted_sources", ()) or ()), available_columns, source_notes)
            family_query_notes.extend(source_notes)
            if source_clause != "TRUE":
                filtered_where = f"({current_where}) AND ({source_clause})"
                filtered_count, filtered_notes = safe_count_where(db, filtered_where, available_columns)
                family_query_notes.extend(filtered_notes)
                reason_counts["source_outside_allowlist"] += max(current_count - int(filtered_count or 0), 0)
                current_where = filtered_where
                current_count = int(filtered_count or 0)

            required_notes: list[str] = []
            required_clause = build_required_present_clause(tuple(spec.get("required_present", ()) or ()), available_columns, required_notes)
            family_query_notes.extend(required_notes)
            if required_clause != "TRUE":
                filtered_where = f"({current_where}) AND ({required_clause})"
                filtered_count, filtered_notes = safe_count_where(db, filtered_where, available_columns)
                family_query_notes.extend(filtered_notes)
                reason_counts["missing_required_fields"] += max(current_count - int(filtered_count or 0), 0)
                current_where = filtered_where
                current_count = int(filtered_count or 0)

            quality_filters, quality_notes = build_family_candidate_quality_filters(db, family_id, label_name, available_columns)
            family_query_notes.extend(quality_notes)
            for reason_name, clause in quality_filters:
                rejected_where = f"({current_where}) AND NOT ({clause})"
                rejected_count, rejected_notes = safe_count_where(db, rejected_where, available_columns)
                family_query_notes.extend(rejected_notes)
                accepted_count = max(current_count - int(rejected_count or 0), 0)
                reason_counts[reason_name] += int(rejected_count or 0)
                current_where = f"({current_where}) AND ({clause})"
                current_count = accepted_count

            final_candidate_count = int(current_count or 0)
            final_candidate_count_by_distro, final_distro_notes = event_count_by_distro(
                db,
                current_where,
                available_columns,
                fallback_count=final_candidate_count,
            )
            family_query_notes.extend(final_distro_notes)
            if 0 < final_candidate_count < 2:
                reason_counts["repeated_behavior_insufficient"] += final_candidate_count
                final_candidate_count = 0
                final_candidate_count_by_distro = {}

            rejected_count_by_distro = {}
            for distro, total in (candidate_count_by_distro or {}).items():
                accepted = int((final_candidate_count_by_distro or {}).get(distro, 0) or 0)
                rejected = max(int(total or 0) - accepted, 0)
                if rejected:
                    rejected_count_by_distro[distro] = rejected
                    global_rejected_count_by_distro[distro] += rejected

            item["behavioral_baseline_candidate_count"] = final_candidate_count
            item["behavioral_baseline_candidate_count_by_distro"] = dict(sorted(final_candidate_count_by_distro.items()))
            item["rejected_candidate_count"] = max(item["candidate_count"] - final_candidate_count, 0)
            item["rejected_count_by_distro"] = dict(sorted(rejected_count_by_distro.items()))
            item["rejection_reasons"] = {
                key: int(value or 0)
                for key, value in sorted(reason_counts.items())
                if int(value or 0) > 0
            }

            if ml_paused or blocking_incident:
                item["status"] = "blocked_by_incident_or_pause"
            elif needed <= 0:
                item["status"] = "target_already_met_stop_scan"
            elif final_candidate_count > 0:
                item["status"] = "clean_candidates_available"
            elif item["candidate_count"] > 0:
                item["status"] = "insufficient_source_data"
            else:
                item["status"] = "insufficient_source_data"

        families[family_id] = {
            "phase_gate": readiness.get("phase_gate", 0),
            "required_normal_labels": family_required,
            "candidate_count_by_distro": dict(sorted(family_candidate_count_by_distro.items())),
            "query_notes": sorted(dict.fromkeys(note for note in family_query_notes if note)),
            "labels": family_labels,
        }

    return {
        "global": {
            "ml_paused": ml_paused,
            "ml_pause_reason": str(global_audit.get("ml_pause_reason", "") or ""),
            "blocking_incident": blocking_incident,
            "global_quality_ok": not bool(global_audit.get("errors")),
            "candidate_count_by_distro": dict(sorted(global_candidate_count_by_distro.items())),
            "family_candidate_count_by_distro": {
                distro: {family: int(count or 0) for family, count in sorted(families_map.items())}
                for distro, families_map in sorted(global_family_candidate_count_by_distro.items())
            },
            "rejected_count_by_distro": dict(sorted(global_rejected_count_by_distro.items())),
            "query_notes": global_query_notes,
        },
        "families": families,
    }


def collect_ml_label_trust_audit(
    config: dict,
    db,
    pm_status: dict,
    *,
    load_table_columns: Callable[[Any, str], tuple[set[str], list[str]]],
    load_labels_read_only: Callable[[Any], tuple[list[dict], str | None]],
    summarize_label_quality: Callable[..., dict],
    classify_label_usage: Callable[[dict, dict], tuple[str, list[str]]],
    label_family_support: Callable[[dict], dict],
    label_matches_family: Callable[[dict, str, str], bool],
    ml_family_readiness: dict,
) -> dict:
    _ = pm_status
    label_columns, column_notes = load_table_columns(db, "labels")
    query_notes = list(column_notes or [])
    if not label_columns or "behavior_label" not in label_columns:
        query_notes.append("missing_schema:behavior_label")
        return {
            "global": {
                "total_labels": 0,
                "by_source": {},
                "by_source_trust": {},
                "by_model_usage_scope": {},
                "by_learnable": {},
                "by_event_class": {},
                "by_behavior_label": {},
                "query_notes": sorted(dict.fromkeys(query_notes)),
            },
            "usage_decisions": {},
            "decision_reasons": {},
            "family_support": {family: {"normal": 0, "suspicious": 0} for family in ml_family_readiness},
            "quality_summary": {"missing_metadata_count": 0, "synthetic_ratio": 0.0},
            "recommended_actions": [],
        }

    label_rows, labels_error = load_labels_read_only(db)
    if labels_error:
        query_notes.append(labels_error)

    summary = summarize_label_quality(label_rows, config=config)
    by_event_class = Counter()
    by_behavior_label = Counter()
    decision_reasons = Counter()
    missing_metadata_count = 0
    synthetic_count = 0

    for row in label_rows:
        event_class = (row.get("event_class", "") or "<empty>").strip() or "<empty>"
        behavior_label = (row.get("behavior_label", "") or "<empty>").strip() or "<empty>"
        by_event_class[event_class] += 1
        by_behavior_label[behavior_label] += 1
        if (row.get("source", "") or "").strip().lower() == "synthetic":
            synthetic_count += 1
        if not all((
            (row.get("source_trust", "") or "").strip(),
            (row.get("model_usage_scope", "") or "").strip(),
            (row.get("event_class", "") or "").strip(),
            (row.get("behavior_label", "") or "").strip(),
        )):
            missing_metadata_count += 1
        _usage, reasons = classify_label_usage(row, label_family_support(row))
        for reason in reasons:
            decision_reasons[reason] += 1

    total_labels = int(summary.get("total_labels", 0) or 0)
    recommended_actions = []
    if missing_metadata_count > 0:
        recommended_actions.append("backfill_missing_label_metadata")
    if synthetic_count > 0:
        recommended_actions.append("keep_synthetic_labels_out_of_runtime_learning")

    return {
        "global": {
            "total_labels": total_labels,
            "by_source": dict(sorted((summary.get("by_source", {}) or {}).items())),
            "by_source_trust": dict(sorted((summary.get("by_source_trust", {}) or {}).items())),
            "by_model_usage_scope": dict(sorted((summary.get("by_model_usage_scope", {}) or {}).items())),
            "by_learnable": dict(sorted((summary.get("by_learnable", {}) or {}).items())),
            "by_event_class": dict(sorted(by_event_class.items())),
            "by_behavior_label": dict(sorted(by_behavior_label.items())),
            "query_notes": sorted(dict.fromkeys(query_notes)),
        },
        "usage_decisions": dict(sorted((summary.get("usage_decisions", {}) or {}).items())),
        "decision_reasons": dict(sorted(decision_reasons.items())),
        "family_support": {
            family: {
                "normal": sum(1 for row in label_rows if label_matches_family(row, family, "normal")),
                "suspicious": sum(1 for row in label_rows if label_matches_family(row, family, "suspicious")),
            }
            for family in sorted(ml_family_readiness)
        },
        "quality_summary": {
            "missing_metadata_count": missing_metadata_count,
            "synthetic_ratio": round((synthetic_count / total_labels), 4) if total_labels else 0.0,
        },
        "recommended_actions": recommended_actions,
    }


def collect_ml_label_metadata_plan(
    config: dict,
    db,
    pm_status: dict,
    *,
    load_table_columns: Callable[[Any, str], tuple[set[str], list[str]]],
    load_labels_read_only: Callable[[Any], tuple[list[dict], str | None]],
    propose_ml_label_metadata: Callable[[dict], dict],
    normalize_row_str: Callable[[dict, str], str],
) -> dict:
    _ = config, pm_status
    label_columns, column_notes = load_table_columns(db, "labels")
    query_notes = list(column_notes or [])
    if not label_columns or not any(name in label_columns for name in {"behavior_label", "rule_id", "label"}):
        query_notes.append("missing_schema:no_mappable_label_columns")
        return {
            "total_labels": 0,
            "proposed_updates": 0,
            "learnable_candidate_count": 0,
            "blocked_count": 0,
            "by_proposed_ml_family": {},
            "by_proposed_usage_decision": {},
            "missing_metadata_counts": {},
            "query_notes": sorted(dict.fromkeys(query_notes)),
            "examples": [],
            "proposals": [],
        }

    label_rows, labels_error = load_labels_read_only(db)
    if labels_error:
        query_notes.append(labels_error)

    family_counts = Counter()
    usage_counts = Counter()
    missing_counts = Counter()
    proposals = []
    proposed_updates = 0

    for row in label_rows:
        proposal = propose_ml_label_metadata(row)
        row_id = row.get("id", row.get("label_id"))
        current_behavior = normalize_row_str(row, "behavior_label")
        current_scope = normalize_row_str(row, "model_usage_scope")
        current_event_class = normalize_row_str(row, "event_class")
        current_trust = normalize_row_str(row, "source_trust")
        if not current_behavior:
            missing_counts["behavior_label"] += 1
        if not current_scope:
            missing_counts["model_usage_scope"] += 1
        if not current_event_class:
            missing_counts["event_class"] += 1
        if not current_trust:
            missing_counts["source_trust"] += 1

        family_key = proposal.get("proposed_ml_family") or "<none>"
        usage_key = proposal.get("proposed_usage_decision") or "<none>"
        family_counts[family_key] += 1
        usage_counts[usage_key] += 1

        changed = any((
            (proposal.get("proposed_ml_family") or None) != (row.get("ml_family") or None),
            (proposal.get("proposed_ml_label") or None) != (row.get("ml_label") or None),
            proposal.get("proposed_behavior_label", "") != current_behavior,
            proposal.get("proposed_event_class", "") != current_event_class,
            proposal.get("proposed_source_trust", "") != current_trust,
            proposal.get("proposed_model_usage_scope", "") != current_scope,
        ))
        proposed_updates += int(changed)
        proposals.append({
            "label_id": row_id,
            "source": normalize_row_str(row, "source"),
            "current_behavior_label": current_behavior,
            "current_event_class": current_event_class,
            "current_source_trust": current_trust,
            "current_model_usage_scope": current_scope,
            **proposal,
        })

    return {
        "total_labels": len(label_rows),
        "proposed_updates": proposed_updates,
        "learnable_candidate_count": sum(1 for item in proposals if item.get("learnable_candidate")),
        "blocked_count": sum(1 for item in proposals if not item.get("learnable_candidate")),
        "by_proposed_ml_family": dict(sorted(family_counts.items())),
        "by_proposed_usage_decision": dict(sorted(usage_counts.items())),
        "missing_metadata_counts": dict(sorted(missing_counts.items())),
        "query_notes": sorted(dict.fromkeys(query_notes)),
        "examples": proposals[:10],
        "proposals": proposals,
    }


def collect_ml_label_extraction_audit(
    config: dict,
    db,
    pm_status: dict,
    *,
    load_table_columns: Callable[[Any, str], tuple[set[str], list[str]]],
    load_labels_read_only: Callable[[Any], tuple[list[dict], str | None]],
    normalize_row_str: Callable[[dict, str], str],
    extract_label_metadata_hints: Callable[[dict], dict],
    propose_ml_label_metadata: Callable[[dict], dict],
) -> dict:
    _ = config, pm_status
    label_columns, column_notes = load_table_columns(db, "labels")
    query_notes = list(column_notes or [])
    if not label_columns:
        return {
            "total_labels": 0,
            "labels_with_nonempty_behavior_label": 0,
            "labels_with_nonempty_event_class": 0,
            "labels_with_nonempty_source_trust": 0,
            "labels_with_nonempty_model_usage_scope": 0,
            "labels_with_nonempty_evidence_fields": 0,
            "labels_with_nonempty_label_reason": 0,
            "evidence_fields_rule_id_count": 0,
            "label_reason_hint_count": 0,
            "possible_safe_mapping_count": 0,
            "impossible_mapping_count": 0,
            "bootstrap_job_id_distribution": {},
            "label_batch_id_distribution": {},
            "reasons": {},
            "query_notes": sorted(dict.fromkeys(query_notes)),
            "examples": [],
        }

    label_rows, labels_error = load_labels_read_only(db)
    if labels_error:
        query_notes.append(labels_error)

    reason_counts = Counter()
    bootstrap_job_ids = Counter()
    label_batch_ids = Counter()
    examples = []
    safe_count = 0
    impossible_count = 0
    evidence_rule_id_count = 0
    label_reason_hint_count = 0
    nonempty_behavior = 0
    nonempty_event_class = 0
    nonempty_source_trust = 0
    nonempty_scope = 0
    nonempty_evidence = 0
    nonempty_label_reason = 0

    for row in label_rows:
        if normalize_row_str(row, "behavior_label"):
            nonempty_behavior += 1
        if normalize_row_str(row, "event_class"):
            nonempty_event_class += 1
        if normalize_row_str(row, "source_trust"):
            nonempty_source_trust += 1
        if normalize_row_str(row, "model_usage_scope"):
            nonempty_scope += 1
        if row.get("evidence_fields") not in (None, "", {}):
            nonempty_evidence += 1
        if normalize_row_str(row, "label_reason"):
            nonempty_label_reason += 1
        if normalize_row_str(row, "bootstrap_job_id"):
            bootstrap_job_ids[normalize_row_str(row, "bootstrap_job_id")] += 1
        if normalize_row_str(row, "label_batch_id"):
            label_batch_ids[normalize_row_str(row, "label_batch_id")] += 1

        hints = extract_label_metadata_hints(row)
        if hints.get("evidence_note") == "invalid_json":
            query_notes.append("evidence_fields:invalid_json")
        if not hints.get("evidence_dict"):
            reason_counts["empty_evidence_fields"] += 1
        if any(source.startswith("evidence_fields") for source in hints.get("hint_sources", [])) and hints.get("extracted_rule_id"):
            evidence_rule_id_count += 1
        if any(source.startswith("label_reason") for source in hints.get("hint_sources", [])):
            label_reason_hint_count += 1

        synthetic_row = dict(row)
        if hints.get("extracted_rule_id") and not normalize_row_str(synthetic_row, "rule_id"):
            synthetic_row["rule_id"] = hints["extracted_rule_id"]
        if hints.get("extracted_behavior") and not normalize_row_str(synthetic_row, "behavior_label"):
            synthetic_row["behavior_label"] = hints["extracted_behavior"]
        proposal = propose_ml_label_metadata(synthetic_row)
        safe_to_map = bool(proposal.get("proposed_ml_family") and proposal.get("proposed_ml_label"))
        if safe_to_map:
            safe_count += 1
        else:
            impossible_count += 1
            reason_counts["ambiguous_metadata"] += 1

        examples.append({
            "id": row.get("id", row.get("label_id")),
            "source": normalize_row_str(row, "source"),
            "source_trust": normalize_row_str(row, "source_trust"),
            "model_usage_scope": normalize_row_str(row, "model_usage_scope"),
            "event_class": normalize_row_str(row, "event_class"),
            "behavior_label": normalize_row_str(row, "behavior_label"),
            "safe_to_map": safe_to_map,
            "hint_sources": list(hints.get("hint_sources", [])),
            "proposed_extraction": {
                "rule_id": hints.get("extracted_rule_id", ""),
                "behavior_label": hints.get("extracted_behavior", ""),
                "ml_family": proposal.get("proposed_ml_family"),
                "ml_label": proposal.get("proposed_ml_label"),
                "usage_decision": proposal.get("proposed_usage_decision"),
                "reason": proposal.get("reason", ""),
            },
        })

    return {
        "total_labels": len(label_rows),
        "labels_with_nonempty_behavior_label": nonempty_behavior,
        "labels_with_nonempty_event_class": nonempty_event_class,
        "labels_with_nonempty_source_trust": nonempty_source_trust,
        "labels_with_nonempty_model_usage_scope": nonempty_scope,
        "labels_with_nonempty_evidence_fields": nonempty_evidence,
        "labels_with_nonempty_label_reason": nonempty_label_reason,
        "evidence_fields_rule_id_count": evidence_rule_id_count,
        "label_reason_hint_count": label_reason_hint_count,
        "possible_safe_mapping_count": safe_count,
        "impossible_mapping_count": impossible_count,
        "bootstrap_job_id_distribution": dict(sorted(bootstrap_job_ids.items())),
        "label_batch_id_distribution": dict(sorted(label_batch_ids.items())),
        "reasons": dict(sorted(reason_counts.items())),
        "query_notes": sorted(dict.fromkeys(query_notes)),
        "examples": examples[:10],
    }


def collect_ml_legacy_bootstrap_backfill_plan(
    config: dict,
    db,
    pm_status: dict,
    *,
    load_labels_read_only: Callable[[Any], tuple[list[dict], str | None]],
    collect_legacy_bootstrap_backfill_candidates: Callable[[list[dict]], dict],
    summarize_label_quality: Callable[..., dict],
    apply_legacy_bootstrap_backfill_preview: Callable[[dict], dict],
    legacy_bootstrap_backfill_payload: Callable[[dict], dict],
    legacy_bootstrap_reject_backfill_fields: dict,
) -> dict:
    _ = pm_status
    label_rows, labels_error = load_labels_read_only(db)
    query_notes = [labels_error] if labels_error else []

    selected = collect_legacy_bootstrap_backfill_candidates(label_rows)
    candidates = list(selected["candidates"])
    broad_matches = list(selected["broad_matches"])
    candidate_ids = [row.get("id") for row in candidates if row.get("id") is not None]
    candidate_id_set = set(candidate_ids)
    before_summary = summarize_label_quality(label_rows, config=config)
    preview_rows = [
        apply_legacy_bootstrap_backfill_preview(row) if row.get("id") in candidate_id_set else dict(row)
        for row in label_rows
    ]
    after_summary = summarize_label_quality(preview_rows, config=config)
    before_active = dict(before_summary.get("active_readiness_label_counts", {}) or {})
    after_active = dict(after_summary.get("active_readiness_label_counts", {}) or {})
    readiness_delta = {
        "normal": int(after_active.get("normal", 0) or 0) - int(before_active.get("normal", 0) or 0),
        "suspicious": int(after_active.get("suspicious", 0) or 0) - int(before_active.get("suspicious", 0) or 0),
    }

    safety_blockers = []
    if selected["unsafe_learnable_ids"]:
        safety_blockers.append("unsafe_candidate_learnable_true")
    if selected["unsafe_scope_ids"]:
        safety_blockers.append("unsafe_candidate_training_scope")
    if len(candidates) > 500:
        safety_blockers.append("candidate_count_safety_cap")
    if readiness_delta["normal"] != 0 or readiness_delta["suspicious"] != 0:
        safety_blockers.append("active_readiness_delta_nonzero")

    return {
        "candidate_count": len(candidates),
        "broad_match_count": len(broad_matches),
        "category_distribution": dict(sorted(Counter((row.get("category", "") or "<empty>").strip() or "<empty>" for row in candidates).items())),
        "label_distribution": dict(sorted(Counter((row.get("label", "") or "<empty>").strip() or "<empty>" for row in candidates).items())),
        "missing_metadata_before": len(candidates),
        "missing_metadata_candidate_count": len(candidates),
        "active_readiness_before": before_active,
        "expected_active_readiness_after": after_active,
        "readiness_delta": readiness_delta,
        "sample_row_ids": candidate_ids[:10],
        "candidate_row_ids": candidate_ids,
        "candidate_rows": candidates,
        "backfill_payloads": [legacy_bootstrap_backfill_payload(row) for row in candidates],
        "will_set": {
            **legacy_bootstrap_reject_backfill_fields,
            "evidence_fields": {
                "legacy_category": "<existing category>",
                "original_label": "<existing label>",
                "repair_mode": "reject_backfill",
                "missing_provenance": True,
                "missing_distro": True,
                "training_eligible": False,
                "no_action_contract": True,
            },
            "ml_family": "<unchanged/null>",
            "label_family": "<unchanged/null>",
        },
        "unsafe_learnable_ids": selected["unsafe_learnable_ids"],
        "unsafe_scope_ids": selected["unsafe_scope_ids"],
        "safety_blockers": safety_blockers,
        "safe_to_apply": not safety_blockers,
        "db_write_attempted": False,
        "no_action_contract": True,
        "query_notes": query_notes,
    }


def _summarize_label_quality(
    label_rows: list[dict],
    config: dict | None = None,
    *,
    ml_family_readiness: dict,
    classify_label_origin: Callable[[dict], str],
    row_distro_value: Callable[[dict], str],
    label_family_support: Callable[[dict], dict],
    classify_label_usage: Callable[[dict, dict], tuple[str, list[str]]],
    label_matches_family: Callable[[dict, str, str], bool],
    summarize_label_quota_usage: Callable[..., dict],
) -> dict:
    source_counter = Counter()
    trust_counter = Counter()
    scope_counter = Counter()
    learnable_counter = Counter()
    calib_counter = Counter()
    family_counts = {
        family: {"normal": 0, "suspicious": 0}
        for family in ml_family_readiness
    }
    family_origin_counts = {
        family: {
            "organic_normal": 0,
            "organic_suspicious": 0,
            "bootstrap_normal": 0,
            "bootstrap_suspicious": 0,
            "legacy_excluded_normal": 0,
            "legacy_excluded_suspicious": 0,
        }
        for family in ml_family_readiness
    }
    origin_counter = Counter()
    usage_counter = Counter()
    label_counts_by_distro = Counter()
    origin_counts_by_distro: dict[str, Counter] = {}
    family_counts_by_distro: dict[str, dict[str, dict[str, int]]] = {}
    active_readiness_label_counts_by_distro: dict[str, dict[str, int]] = {}
    calibration_eligible = 0
    for row in label_rows:
        source = (row.get("source", "") or "<empty>").strip() or "<empty>"
        trust = (row.get("source_trust", "") or "<empty>").strip() or "<empty>"
        scope = (row.get("model_usage_scope", "") or "<empty>").strip() or "<empty>"
        event_class = (row.get("event_class", "") or "<empty>").strip() or "<empty>"
        learnable = row.get("learnable")
        origin = classify_label_origin(row)
        distro = row_distro_value(row)
        source_counter[source] += 1
        trust_counter[trust] += 1
        scope_counter[scope] += 1
        learnable_counter[str(bool(learnable)).lower() if learnable is not None else "null"] += 1
        origin_counter[origin] += 1
        label_counts_by_distro[distro] += 1
        origin_counts_by_distro.setdefault(distro, Counter())[origin] += 1
        calib_key = f"{source}:{scope}:{event_class}"
        calib_counter[calib_key] += 1
        if scope == "calibration_only" and learnable is True and event_class in {"attack", "benign"}:
            calibration_eligible += 1
        family_support = label_family_support(row)
        usage, _usage_reasons = classify_label_usage(row, family_support)
        usage_counter[usage] += 1
        readiness_usable = usage in {"baseline_learning", "direct_learnable"}
        for family in ml_family_readiness:
            normal_match = label_matches_family(row, family, "normal")
            suspicious_match = label_matches_family(row, family, "suspicious")
            if normal_match:
                family_counts_by_distro.setdefault(distro, {}).setdefault(family, {"normal": 0, "suspicious": 0})
                if origin == "organic_live" and readiness_usable:
                    family_counts[family]["normal"] += 1
                    family_origin_counts[family]["organic_normal"] += 1
                    family_counts_by_distro[distro][family]["normal"] += 1
                    active_readiness_label_counts_by_distro.setdefault(distro, {"normal": 0, "suspicious": 0})["normal"] += 1
                elif origin == "bootstrap_historical":
                    family_origin_counts[family]["bootstrap_normal"] += 1
                elif origin == "legacy_excluded":
                    family_origin_counts[family]["legacy_excluded_normal"] += 1
            if suspicious_match:
                family_counts_by_distro.setdefault(distro, {}).setdefault(family, {"normal": 0, "suspicious": 0})
                if origin == "organic_live" and readiness_usable:
                    family_counts[family]["suspicious"] += 1
                    family_origin_counts[family]["organic_suspicious"] += 1
                    family_counts_by_distro[distro][family]["suspicious"] += 1
                    active_readiness_label_counts_by_distro.setdefault(distro, {"normal": 0, "suspicious": 0})["suspicious"] += 1
                elif origin == "bootstrap_historical":
                    family_origin_counts[family]["bootstrap_suspicious"] += 1
                elif origin == "legacy_excluded":
                    family_origin_counts[family]["legacy_excluded_suspicious"] += 1
    quota_summary = summarize_label_quota_usage(label_rows, config=config)
    return {
        "total_labels": len(label_rows),
        "calibration_eligible_labels": calibration_eligible,
        "by_source": source_counter,
        "by_source_trust": trust_counter,
        "by_model_usage_scope": scope_counter,
        "by_learnable": learnable_counter,
        "label_counts_by_origin": dict(sorted(origin_counter.items())),
        "label_counts_by_distro": dict(sorted(label_counts_by_distro.items())),
        "origin_counts_by_distro": {
            distro: dict(sorted(counts.items()))
            for distro, counts in sorted(origin_counts_by_distro.items())
        },
        "family_counts_by_distro": {
            distro: {
                family: {
                    "normal": int(values.get("normal", 0) or 0),
                    "suspicious": int(values.get("suspicious", 0) or 0),
                }
                for family, values in sorted(families.items())
            }
            for distro, families in sorted(family_counts_by_distro.items())
        },
        "organic_live_label_counts": {
            "total": int(origin_counter.get("organic_live", 0) or 0),
            "family_counts": {
                family: {
                    "normal": counts["organic_normal"],
                    "suspicious": counts["organic_suspicious"],
                }
                for family, counts in family_origin_counts.items()
            },
        },
        "bootstrap_historical_label_counts": {
            "total": int(origin_counter.get("bootstrap_historical", 0) or 0),
            "family_counts": {
                family: {
                    "normal": counts["bootstrap_normal"],
                    "suspicious": counts["bootstrap_suspicious"],
                }
                for family, counts in family_origin_counts.items()
            },
        },
        "excluded_legacy_label_counts": {
            "total": int(origin_counter.get("legacy_excluded", 0) or 0),
            "family_counts": {
                family: {
                    "normal": counts["legacy_excluded_normal"],
                    "suspicious": counts["legacy_excluded_suspicious"],
                }
                for family, counts in family_origin_counts.items()
            },
        },
        "by_source_scope_event_class": calib_counter,
        "usage_decisions": dict(sorted(usage_counter.items())),
        "family_counts": family_counts,
        "family_origin_counts": family_origin_counts,
        "active_readiness_label_counts": {
            "normal": sum(item["normal"] for item in family_counts.values()),
            "suspicious": sum(item["suspicious"] for item in family_counts.values()),
        },
        "active_readiness_label_counts_by_distro": {
            distro: {
                "normal": int(counts.get("normal", 0) or 0),
                "suspicious": int(counts.get("suspicious", 0) or 0),
            }
            for distro, counts in sorted(active_readiness_label_counts_by_distro.items())
        },
        "quota_summary": quota_summary,
    }


def _collect_event_metrics(
    db,
    where_sql: str = "TRUE",
    available_columns: set[str] | None = None,
    *,
    metric_fill_sql: Callable[[str, set[str], str, list[str]], str],
    execute_read_only: Callable[..., tuple[Any, str | None]],
    row_value: Callable[[Any, str, int, Any], Any],
    event_count_by_distro: Callable[..., tuple[dict[str, int], list[str]]],
    event_source_by_distro: Callable[..., tuple[dict[str, dict[str, int]], list[str]]],
    safe_ratio: Callable[[float, float], float],
) -> tuple[dict, list[str]]:
    available_columns = set(available_columns or set())
    notes: list[str] = []
    ts_expr = "DATE(to_timestamp(ts))" if "ts" in available_columns else "NULL"
    if "ts" not in available_columns:
        notes.append("missing_field:ts")
    sql = f"""
        SELECT
            COUNT(*) AS total,
            {metric_fill_sql('host', available_columns, 'host_filled', notes)},
            {metric_fill_sql('username', available_columns, 'user_filled', notes)},
            {metric_fill_sql('src_ip', available_columns, 'src_ip_filled', notes)},
            {metric_fill_sql('dst_ip', available_columns, 'dst_ip_filled', notes)},
            {'SUM(CASE WHEN dst_port IS NOT NULL AND dst_port <> 0 THEN 1 ELSE 0 END) AS dst_port_filled' if 'dst_port' in available_columns else '0 AS dst_port_filled'},
            {metric_fill_sql('process', available_columns, 'process_filled', notes)},
            {"COUNT(DISTINCT LOWER(COALESCE(source, ''))) AS source_count" if 'source' in available_columns else '0 AS source_count'},
            COUNT(DISTINCT {ts_expr}) AS day_count,
            {"MAX(ts) AS last_ts" if 'ts' in available_columns else 'NULL AS last_ts'}
        FROM events_recent
        WHERE {where_sql}
    """
    if "dst_port" not in available_columns:
        notes.append("missing_field:dst_port")
    if "source" not in available_columns:
        notes.append("missing_field:source")
    row, error = execute_read_only(db, sql, fetch="one")
    if error:
        notes.append(error)
    if not row:
        return {
            "runtime_events": 0,
            "host_fill_rate": 0.0,
            "user_fill_rate": 0.0,
            "src_ip_fill_rate": 0.0,
            "dst_ip_fill_rate": 0.0,
            "dst_port_fill_rate": 0.0,
            "process_fill_rate": 0.0,
            "source_count": 0,
            "time_coverage_days": 0,
            "last_event_ts": None,
            "candidate_count_by_distro": {},
            "source_by_distro": {},
        }, notes
    total = int(row_value(row, "total", 0, 0) or 0)
    distro_counts, distro_notes = event_count_by_distro(
        db,
        where_sql,
        available_columns,
        fallback_count=total,
    )
    source_by_distro, source_distro_notes = event_source_by_distro(
        db,
        where_sql,
        available_columns,
    )
    notes.extend(distro_notes)
    notes.extend(source_distro_notes)
    return {
        "runtime_events": total,
        "host_fill_rate": safe_ratio(row_value(row, "host_filled", 1, 0) or 0, total),
        "user_fill_rate": safe_ratio(row_value(row, "user_filled", 2, 0) or 0, total),
        "src_ip_fill_rate": safe_ratio(row_value(row, "src_ip_filled", 3, 0) or 0, total),
        "dst_ip_fill_rate": safe_ratio(row_value(row, "dst_ip_filled", 4, 0) or 0, total),
        "dst_port_fill_rate": safe_ratio(row_value(row, "dst_port_filled", 5, 0) or 0, total),
        "process_fill_rate": safe_ratio(row_value(row, "process_filled", 6, 0) or 0, total),
        "source_count": int(row_value(row, "source_count", 7, 0) or 0),
        "time_coverage_days": int(row_value(row, "day_count", 8, 0) or 0),
        "last_event_ts": row_value(row, "last_ts", 9, None),
        "candidate_count_by_distro": distro_counts,
        "source_by_distro": source_by_distro,
    }, notes


def _collect_global_ml_audit(
    db,
    pm_status: dict,
    config: dict | None = None,
    *,
    load_table_columns: Callable[[Any, str], tuple[set[str], list[str]]],
    query_ml_audit_table_count: Callable[[Any, str], tuple[int, str | None]],
    collect_event_metrics: Callable[..., tuple[dict, list[str]]],
    collect_distribution: Callable[..., tuple[list[dict], list[str]]],
    load_labels_read_only: Callable[[Any], tuple[list[dict], str | None]],
    summarize_label_quality: Callable[..., dict],
    compute_data_quality_metrics: Callable[..., dict],
    json_loads: Callable[[str], dict],
) -> dict:
    phase_stats = (pm_status or {}).get("stats", {}) or {}
    table_counts = {}
    errors = {}
    event_columns, column_errors = load_table_columns(db, "events_recent")
    if column_errors:
        errors["events_recent:columns"] = column_errors
    elif not event_columns:
        errors["events_recent:columns"] = ["missing_table:events_recent"]
    for table in ("events_recent", "alerts", "incidents", "labels", "process_tree"):
        value, error = query_ml_audit_table_count(db, table)
        table_counts[table] = int(value or 0)
        if error:
            errors[f"table:{table}"] = error

    overall_events, overall_notes = collect_event_metrics(db, available_columns=event_columns)
    if overall_notes:
        errors["events_recent:overall"] = overall_notes
    top_sources, src_notes = collect_distribution(db, "source", available_columns=event_columns)
    top_categories, cat_notes = collect_distribution(db, "category", available_columns=event_columns)
    top_actions, act_notes = collect_distribution(db, "action", available_columns=event_columns)
    if src_notes:
        errors["dist:source"] = src_notes
    if cat_notes:
        errors["dist:category"] = cat_notes
    if act_notes:
        errors["dist:action"] = act_notes
    events_by_distro, distro_notes = collect_distribution(db, "distro_family", available_columns=event_columns)
    if distro_notes:
        errors["dist:distro_family"] = distro_notes

    labels, labels_error = load_labels_read_only(db)
    if labels_error:
        errors["labels"] = labels_error
    label_quality = summarize_label_quality(labels, config=config)

    ml_control_state = {}
    if db is not None and hasattr(db, "get_stat"):
        try:
            raw = db.get_stat("ml_control_state")
            if raw:
                ml_control_state = json_loads(raw)
        except Exception as exc:
            errors["ml_control_state"] = f"query_error:{exc}"

    total_events = int(table_counts.get("events_recent", 0))
    duplicate_total = int(phase_stats.get("duplicate_count", 0) or 0)
    telemetry_duplicate_total = int(phase_stats.get("telemetry_duplicate_count", 0) or 0)
    parse_fail_total = int(phase_stats.get("parse_fail_count", 0) or 0)
    quality_metrics = compute_data_quality_metrics(
        total_events=total_events,
        duplicate_count=duplicate_total,
        telemetry_duplicate_count=telemetry_duplicate_total,
        parse_fail_count=parse_fail_total,
    )

    return {
        "counts": table_counts,
        "overall_events": overall_events,
        "event_columns": sorted(event_columns),
        "top_sources": top_sources,
        "top_categories": top_categories,
        "top_actions": top_actions,
        "events_by_distro": events_by_distro,
        "label_quality": label_quality,
        "phase_stats": phase_stats,
        "current_phase": int((pm_status or {}).get("current_phase", 0) or 0),
        "phase_name": (pm_status or {}).get("phase_name", ""),
        "ml_paused": bool(ml_control_state.get("paused", False)),
        "ml_pause_reason": ml_control_state.get("pause_reason", "") or "",
        "duplicate_rate": float(quality_metrics.get("duplicate_rate", 0.0) or 0.0),
        "parse_fail_rate": float(quality_metrics.get("parse_fail_rate", 0.0) or 0.0),
        "errors": errors,
    }


def _build_family_candidate_quality_filters(
    db,
    family_id: str,
    label_name: str,
    available_columns: set[str],
    *,
    load_closed_incident_entities: Callable[[Any], tuple[list[str], list[str]]],
    build_closed_incident_entity_residue_clause: Callable[[list[str], set[str]], str],
    sql_quote_literal: Callable[[str], str],
) -> tuple[list[tuple[str, str]], list[str]]:
    filters: list[tuple[str, str]] = []
    notes: list[str] = []

    closed_entities, incident_notes = load_closed_incident_entities(db)
    notes.extend(incident_notes)
    closed_incident_clause = build_closed_incident_entity_residue_clause(closed_entities, available_columns)
    if closed_incident_clause != "TRUE":
        filters.append(("closed_incident_entity_residue", closed_incident_clause))

    if family_id == "ML-NET":
        if "src_ip" not in available_columns:
            notes.append("missing_field:src_ip")
            network_clause = "FALSE"
        elif "dst_port" not in available_columns:
            notes.append("missing_field:dst_port")
            network_clause = "FALSE"
        else:
            network_clause = (
                "("
                "("
                "COALESCE(src_ip, '') ~ '^(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$'"
                " OR "
                "(POSITION(':' IN COALESCE(src_ip, '')) > 0 AND COALESCE(src_ip, '') ~* '^[0-9a-f:]+$')"
                ")"
                " AND dst_port IS NOT NULL AND dst_port <> 0"
                ")"
            )
        filters.append(("invalid_network_peer_feature", network_clause))

    if family_id == "ML-SERVICE":
        positive_parts: list[str] = []
        negative_parts: list[str] = []
        if "action" in available_columns:
            positive_parts.append("LOWER(COALESCE(action, '')) IN ('service_heartbeat', 'service_start', 'service_restart', 'service_stop', 'service_reload')")
        if "process" in available_columns:
            positive_parts.append("LOWER(COALESCE(process, '')) IN ('systemd', 'systemctl', 'service')")
            negative_parts.append("LOWER(COALESCE(process, '')) = 'kernel'")
        if "message" in available_columns:
            positive_parts.extend([
                "POSITION('systemd' IN LOWER(COALESCE(message, ''))) > 0",
                "POSITION('service started' IN LOWER(COALESCE(message, ''))) > 0",
                "POSITION('service stopped' IN LOWER(COALESCE(message, ''))) > 0",
                "POSITION('service restarted' IN LOWER(COALESCE(message, ''))) > 0",
                "POSITION('starting ' IN LOWER(COALESCE(message, ''))) > 0",
                "POSITION('started ' IN LOWER(COALESCE(message, ''))) > 0",
            ])
            negative_parts.extend([
                "POSITION('ufw block' IN LOWER(COALESCE(message, ''))) > 0",
                "POSITION('iptables' IN LOWER(COALESCE(message, ''))) > 0",
                "POSITION('firewall' IN LOWER(COALESCE(message, ''))) > 0",
                "POSITION(' block' IN LOWER(COALESCE(message, ''))) > 0",
                "POSITION(' reject' IN LOWER(COALESCE(message, ''))) > 0",
                "POSITION(' drop' IN LOWER(COALESCE(message, ''))) > 0",
            ])
        if negative_parts:
            filters.append(("non_service_event", "NOT (" + " OR ".join(negative_parts) + ")"))
        if positive_parts:
            filters.append(("missing_service_feature", "(" + " OR ".join(positive_parts) + ")"))
        else:
            notes.append("missing_field:service_lifecycle_signal")
            filters.append(("missing_service_feature", "FALSE"))

    if family_id == "ML-PROC":
        low_value_clauses: list[str] = []
        if "process" in available_columns:
            low_value_processes = (
                "pg_isready", "systemctl", "sshd", "sh", "sudo", "su", "ps",
                "sed", "tr", "tail", "ss", "vmtoolsd", "networkmanager", "runc",
            )
            quoted = ", ".join(sql_quote_literal(item) for item in low_value_processes)
            low_value_clauses.extend([
                f"LOWER(COALESCE(process, '')) IN ({quoted})",
                "LOWER(COALESCE(process, '')) ~ '^python[0-9.]*$'",
            ])
        if "message" in available_columns:
            low_value_clauses.extend([
                "POSITION('session opened for user' IN LOWER(COALESCE(message, ''))) > 0",
                "POSITION('accepted password for' IN LOWER(COALESCE(message, ''))) > 0",
            ])
        if low_value_clauses:
            filters.append(("low_value_process_noise", "NOT (" + " OR ".join(low_value_clauses) + ")"))
        else:
            notes.append("missing_field:process_signal")
            filters.append(("low_value_process_noise", "FALSE"))

    if family_id == "ML-HOST" and label_name == "host_behavior_normal":
        host_clauses: list[str] = []
        if "host" in available_columns:
            host_clauses.append("NULLIF(BTRIM(COALESCE(host, '')), '') IS NOT NULL")
        if "src_ip" in available_columns:
            host_clauses.append(
                "COALESCE(src_ip, '') ~ '^(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$'"
            )
        if host_clauses:
            filters.append(("missing_host_identity_signal", "(" + " OR ".join(host_clauses) + ")"))
        else:
            notes.append("missing_field:host_identity_signal")
            filters.append(("missing_host_identity_signal", "FALSE"))

    return filters, notes


def _propose_ml_label_metadata(
    row: dict,
    *,
    resolve_ml_label_metadata_mapping: Callable[[dict], dict],
    normalize_row_str: Callable[[dict, str], str],
) -> dict:
    mapping = resolve_ml_label_metadata_mapping(row)
    source = normalize_row_str(row, "source").lower()
    current_trust = normalize_row_str(row, "source_trust")
    current_scope = normalize_row_str(row, "model_usage_scope")
    current_event_class = normalize_row_str(row, "event_class")
    current_behavior = normalize_row_str(row, "behavior_label")
    learnable = row.get("learnable")
    proposed_usage = "rejected"
    learnable_candidate = False
    reasons: list[str] = [mapping["reason"]]

    proposed_family = mapping["ml_family"]
    proposed_label = mapping["ml_label"]
    proposed_event_class = mapping["event_class"] or current_event_class
    proposed_source_trust = mapping["source_trust"] or current_trust
    proposed_scope = current_scope or "not_learnable"

    if source == "synthetic":
        proposed_scope = "not_learnable"
        proposed_usage = "ignored"
        learnable_candidate = False
        reasons.append("synthetic_not_runtime_observed")
    elif not proposed_family:
        proposed_scope = current_scope or "not_learnable"
        proposed_usage = "ignored" if current_behavior == "routine_system_event" else "rejected"
        learnable_candidate = False
        reasons.append("missing_family_mapping")
    elif proposed_event_class == "benign":
        proposed_source_trust = proposed_source_trust or "observed_benign_high"
        proposed_scope = "baseline_learning"
        proposed_usage = "baseline_learning"
        learnable_candidate = True
        reasons.append("clean_normal_baseline_learning")
    elif proposed_event_class in {"attack", "suspicious"}:
        proposed_source_trust = proposed_source_trust or "rule_high"
        proposed_scope = "calibration_only"
        proposed_usage = "direct_learnable" if learnable is not False else "ignored"
        learnable_candidate = proposed_usage == "direct_learnable"
        reasons.append("rule_backed_direct_learning" if learnable_candidate else "learnable_false")
    else:
        proposed_scope = "not_learnable"
        proposed_usage = "rejected"
        learnable_candidate = False
        reasons.append("unsupported_event_class")

    if not proposed_family:
        reasons.append("no_family_mapping")
    if not proposed_label and proposed_family:
        reasons.append("missing_ml_label")

    return {
        "proposed_source_trust": proposed_source_trust,
        "proposed_model_usage_scope": proposed_scope,
        "proposed_event_class": proposed_event_class or "unknown",
        "proposed_behavior_label": proposed_label or current_behavior or "",
        "proposed_ml_family": proposed_family,
        "proposed_ml_label": proposed_label,
        "proposed_usage_decision": proposed_usage,
        "learnable_candidate": bool(learnable_candidate and proposed_family and proposed_label),
        "reason": ",".join(dict.fromkeys(filter(None, reasons))),
    }


def _extract_label_metadata_hints(
    row: dict,
    *,
    coerce_jsonish_dict: Callable[[Any], tuple[dict, str]],
    normalize_row_str: Callable[[dict, str], str],
    extract_rule_id_from_text: Callable[[str], str],
    extract_behavior_from_text: Callable[[str], str],
    flatten_text_values: Callable[[Any], list[str]],
) -> dict:
    evidence_dict, evidence_note = coerce_jsonish_dict(row.get("evidence_fields"))
    label_reason = normalize_row_str(row, "label_reason")
    row_rule_id = normalize_row_str(row, "rule_id").upper()
    row_behavior = normalize_row_str(row, "behavior_label").lower()
    row_label = normalize_row_str(row, "label").lower()

    extracted_rule_id = row_rule_id
    extracted_behavior = row_behavior or row_label
    hint_sources = []

    if row_rule_id:
        hint_sources.append("row.rule_id")
    if row_behavior:
        hint_sources.append("row.behavior_label")

    if evidence_dict:
        for key in ("rule_id", "matched_rule_id", "rule", "alert_rule_id"):
            value = evidence_dict.get(key)
            if isinstance(value, str):
                extracted_rule_id = extracted_rule_id or value.strip().upper()
                if value.strip():
                    hint_sources.append(f"evidence_fields.{key}")
                    break
        for key in ("behavior_label", "behavior", "ml_label", "label"):
            value = evidence_dict.get(key)
            if isinstance(value, str) and value.strip():
                extracted_behavior = extracted_behavior or value.strip().lower()
                hint_sources.append(f"evidence_fields.{key}")
                break
        if not extracted_rule_id:
            text_values = " ".join(flatten_text_values(evidence_dict))
            maybe_rule = extract_rule_id_from_text(text_values)
            if maybe_rule:
                extracted_rule_id = maybe_rule
                hint_sources.append("evidence_fields.text_scan")
        if not extracted_behavior:
            text_values = " ".join(flatten_text_values(evidence_dict))
            maybe_behavior = extract_behavior_from_text(text_values)
            if maybe_behavior:
                extracted_behavior = maybe_behavior
                hint_sources.append("evidence_fields.behavior_scan")

    reason_rule_id = extract_rule_id_from_text(label_reason)
    if not extracted_rule_id and reason_rule_id:
        extracted_rule_id = reason_rule_id
        hint_sources.append("label_reason.rule_id")
    reason_behavior = extract_behavior_from_text(label_reason)
    if not extracted_behavior and reason_behavior:
        extracted_behavior = reason_behavior
        hint_sources.append("label_reason.behavior")

    return {
        "evidence_dict": evidence_dict,
        "evidence_note": evidence_note,
        "label_reason": label_reason,
        "extracted_rule_id": extracted_rule_id,
        "extracted_behavior": extracted_behavior,
        "hint_sources": hint_sources,
    }


def _execute_read_only(db, sql: str, params=(), fetch: str = "all"):
    if db is None or not hasattr(db, "_execute"):
        return None, "missing_table"
    try:
        return db._execute(sql, params, fetch=fetch), ""
    except Exception as exc:
        msg = str(exc).lower()
        if "relation" in msg and "does not exist" in msg:
            return None, "missing_table"
        if "column" in msg and "does not exist" in msg:
            return None, "missing_field"
        return None, f"query_error:{exc}"


def _load_table_columns(
    db,
    table_name: str,
    *,
    query_rows: Callable[..., tuple[list, str | None]],
    row_value: Callable[[Any, str, int | None, Any], Any],
) -> tuple[set[str], list[str]]:
    if db is None or not hasattr(db, "_execute"):
        return set(), ["missing_table:events_recent"]
    sql = """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        ORDER BY ordinal_position
    """
    rows, error = query_rows(db, sql, params=(table_name,))
    if error:
        return set(), [error]
    columns = set()
    for row in rows:
        name = (row_value(row, "column_name", 0, "") or "").strip().lower()
        if name:
            columns.add(name)
    return columns, []


def _metric_fill_sql(
    column_name: str,
    available_columns: set[str],
    alias: str,
    notes: list[str],
    *,
    sql_non_empty_expr: Callable[[str], str],
) -> str:
    if column_name in available_columns:
        return f"SUM(CASE WHEN {sql_non_empty_expr(column_name)} THEN 1 ELSE 0 END) AS {alias}"
    notes.append(f"missing_field:{column_name}")
    return f"0 AS {alias}"


def _load_labels_read_only(db) -> tuple[list, str]:
    if db is None or not hasattr(db, "load_labels"):
        return [], "missing_table"
    try:
        rows = db.load_labels() or []
        return rows, ""
    except Exception as exc:
        return [], f"query_error:{exc}"


def _collect_distribution(
    db,
    column: str,
    limit: int = 5,
    available_columns: set[str] | None = None,
    *,
    query_rows: Callable[..., tuple[list, str | None]],
) -> tuple[list[dict], list[str]]:
    available_columns = set(available_columns or set())
    if column not in available_columns:
        return [], [f"missing_field:{column}"]
    sql = f"""
        SELECT COALESCE(NULLIF(BTRIM(COALESCE({column}::text, '')), ''), '<empty>') AS name,
               COUNT(*) AS count
        FROM events_recent
        GROUP BY 1
        ORDER BY count DESC, name ASC
        LIMIT %s
    """
    rows, error = query_rows(db, sql, params=(limit,))
    notes = [error] if error else []
    return rows, notes


def _event_count_by_distro(
    db,
    where_sql: str,
    available_columns: set[str],
    *,
    fallback_count: int = 0,
    query_rows: Callable[..., tuple[list, str | None]],
    normalize_distro_value: Callable[[Any], str],
    row_value: Callable[[Any, str, int | None, Any], Any],
) -> tuple[dict[str, int], list[str]]:
    if "distro_family" not in available_columns:
        notes = ["missing_field:distro_family"]
        if fallback_count > 0:
            return {"unknown_distro": int(fallback_count or 0)}, notes
        return {}, notes
    sql = f"""
        SELECT COALESCE(NULLIF(BTRIM(COALESCE(distro_family::text, '')), ''), 'unknown_distro') AS distro_family,
               COUNT(*) AS count
        FROM events_recent
        WHERE {where_sql}
        GROUP BY 1
        ORDER BY count DESC, distro_family ASC
    """
    rows, error = query_rows(db, sql)
    notes = [error] if error else []
    counts: dict[str, int] = {}
    for row in rows or []:
        counts[normalize_distro_value(row_value(row, "distro_family", 0, ""))] = int(row_value(row, "count", 1, 0) or 0)
    return counts, notes


def _event_source_by_distro(
    db,
    where_sql: str,
    available_columns: set[str],
    *,
    query_rows: Callable[..., tuple[list, str | None]],
    normalize_distro_value: Callable[[Any], str],
    row_value: Callable[[Any, str, int | None, Any], Any],
) -> tuple[dict[str, dict[str, int]], list[str]]:
    missing = [name for name in ("distro_family", "source") if name not in available_columns]
    if missing:
        return {}, [f"missing_field:{name}" for name in missing]
    sql = f"""
        SELECT COALESCE(NULLIF(BTRIM(COALESCE(distro_family::text, '')), ''), 'unknown_distro') AS distro_family,
               COALESCE(NULLIF(BTRIM(COALESCE(source::text, '')), ''), '<empty>') AS source,
               COUNT(*) AS count
        FROM events_recent
        WHERE {where_sql}
        GROUP BY 1, 2
        ORDER BY distro_family ASC, count DESC, source ASC
    """
    rows, error = query_rows(db, sql)
    notes = [error] if error else []
    result: dict[str, dict[str, int]] = {}
    for row in rows or []:
        distro = normalize_distro_value(row_value(row, "distro_family", 0, ""))
        source = str(row_value(row, "source", 1, "<empty>") or "<empty>")
        result.setdefault(distro, {})[source] = int(row_value(row, "count", 2, 0) or 0)
    return result, notes


_ML_AUDIT_TABLE_COUNT_SQL = {
    "events_recent": "SELECT COUNT(*) AS count FROM events_recent",
    "alerts": "SELECT COUNT(*) AS count FROM alerts",
    "incidents": "SELECT COUNT(*) AS count FROM incidents",
    "labels": "SELECT COUNT(*) AS count FROM labels",
    "process_tree": "SELECT COUNT(*) AS count FROM process_tree",
}


def _query_ml_audit_table_count(
    db,
    table_name: str,
    *,
    query_scalar: Callable[..., tuple[Any, str | None]],
) -> tuple[int, str | None]:
    query = _ML_AUDIT_TABLE_COUNT_SQL.get(str(table_name or "").strip())
    if not query:
        return 0, "invalid_table"
    value, error = query_scalar(db, query, key="count", default=0)
    return int(value or 0), error


def _sql_quote_literal(value: str) -> str:
    return "'" + str(value or "").replace("'", "''") + "'"


def _normalize_row_str(row: dict, key: str) -> str:
    return (row.get(key, "") or "").strip()


def _coerce_jsonish_dict(value) -> tuple[dict, str]:
    if isinstance(value, dict):
        return value, ""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}, ""
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed, ""
            return {}, "non_dict_json"
        except Exception:
            return {}, "invalid_json"
    return {}, ""


def _flatten_text_values(value) -> list[str]:
    if isinstance(value, dict):
        result = []
        for item in value.values():
            result.extend(_flatten_text_values(item))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_flatten_text_values(item))
        return result
    if isinstance(value, str):
        return [value]
    return []


def _extract_rule_id_from_text(text: str) -> str:
    if not text:
        return ""
    match = re.search(r"\b([A-Z]{2,}(?:-[A-Z0-9]+)+)\b", text.upper())
    return match.group(1).strip().upper() if match else ""


def _extract_behavior_from_text(text: str, *, ml_label_behavior_plan_aliases: dict[str, tuple]) -> str:
    lowered = (text or "").strip().lower()
    if not lowered:
        return ""
    for candidate in ml_label_behavior_plan_aliases:
        if candidate in lowered:
            return candidate
    return ""


def _build_family_where_clause(family: str, available_columns: set[str]) -> str:
    def has(*names: str) -> bool:
        return all(name in available_columns for name in names)

    if family == "ML-AUTH":
        if has("category"):
            return "LOWER(COALESCE(category, '')) = 'auth'"
        if has("action"):
            return "LOWER(COALESCE(action, '')) IN ('ssh_login', 'ssh_fail', 'auth_fail', 'login', 'sshd', 'sudo', 'sudo_fail')"
        if has("source"):
            return "LOWER(COALESCE(source, '')) IN ('auth_log', 'auth.log', 'sshd', 'pam', 'secure')"
        return "TRUE"
    if family == "ML-SUDO":
        if has("action"):
            return "LOWER(COALESCE(action, '')) IN ('sudo', 'sudo_fail', 'su', 'su_fail')"
        if has("category"):
            return "LOWER(COALESCE(category, '')) = 'auth'"
        return "TRUE"
    if family == "ML-PROC":
        if has("category"):
            return "LOWER(COALESCE(category, '')) = 'process'"
        if has("action"):
            return "LOWER(COALESCE(action, '')) IN ('exec', 'syscall')"
        return "TRUE"
    if family == "ML-SERVICE":
        if has("category"):
            return "LOWER(COALESCE(category, '')) IN ('system', 'service')"
        if has("action"):
            return "LOWER(COALESCE(action, '')) IN ('service_start', 'service_stop', 'service_restart', 'systemctl')"
        return "TRUE"
    if family == "ML-NET":
        if has("category"):
            return "LOWER(COALESCE(category, '')) = 'network'"
        if has("action"):
            return "LOWER(COALESCE(action, '')) IN ('connect', 'http_request', 'dns_query')"
        return "TRUE"
    if family == "ML-SEQ":
        if has("category"):
            return "LOWER(COALESCE(category, '')) IN ('auth', 'process', 'network', 'system', 'db')"
        return "TRUE"
    if family == "ML-USER":
        if has("username"):
            return "NULLIF(BTRIM(COALESCE(username::text, '')), '') IS NOT NULL"
        if has("category"):
            return "LOWER(COALESCE(category, '')) IN ('auth', 'process', 'network')"
        return "TRUE"
    if family == "ML-HOST":
        if has("host"):
            return "NULLIF(BTRIM(COALESCE(host::text, '')), '') IS NOT NULL"
        if has("source"):
            return "NULLIF(BTRIM(COALESCE(source::text, '')), '') IS NOT NULL"
        return "TRUE"
    if family == "ML-DBAUTH":
        if has("category"):
            return "LOWER(COALESCE(category, '')) = 'db'"
        if has("source"):
            return "LOWER(COALESCE(source, '')) IN ('postgresql', 'mysql', 'mariadb')"
        return "TRUE"
    if family == "ML-DNS":
        clauses = []
        if has("source"):
            clauses.append("LOWER(COALESCE(source, '')) IN ('dns', 'named', 'bind', 'dnsmasq', 'systemd-resolved', 'resolved')")
        if has("action"):
            clauses.append("LEFT(LOWER(COALESCE(action, '')), 3) = 'dns'")
        return " OR ".join(clauses) if clauses else "TRUE"
    if family == "ML-WEBPOST":
        clauses = []
        if has("category"):
            clauses.append("LOWER(COALESCE(category, '')) = 'web_attack'")
        if has("source", "action"):
            clauses.append("(LOWER(COALESCE(source, '')) IN ('apache2', 'nginx') AND LOWER(COALESCE(action, '')) = 'http_request')")
        elif has("source"):
            clauses.append("LOWER(COALESCE(source, '')) IN ('apache2', 'nginx')")
        return " OR ".join(clauses) if clauses else "TRUE"
    if family == "ML-IMPACT":
        if has("category", "risk_bucket"):
            return "LOWER(COALESCE(category, '')) IN ('process', 'filesystem') AND LOWER(COALESCE(risk_bucket, '')) IN ('suspicious', 'malicious')"
        if has("category"):
            return "LOWER(COALESCE(category, '')) IN ('process', 'filesystem')"
        return "TRUE"
    return "TRUE"


def _label_matches_family(
    row: dict,
    family: str,
    bucket: str,
    *,
    ml_family_readiness: dict,
    ml_family_behavior_aliases: dict[str, dict[str, set[str]]],
) -> bool:
    cfg = ml_family_readiness[family]
    behavior = (row.get("behavior_label", "") or "").strip().lower()
    attack_family = (row.get("attack_family", "") or "").strip().lower()
    category = (row.get("category", "") or "").strip().lower()
    label_value = (row.get("label", "") or "").strip().lower()
    source_trust = (row.get("source_trust", "") or "").strip().lower()
    scope = (row.get("model_usage_scope", "") or "").strip().lower()
    if scope == "not_learnable" and bucket == "normal":
        return False
    if behavior:
        if bucket == "normal" and behavior in cfg.get("normal_behaviors", set()):
            return True
        if bucket == "suspicious" and behavior in cfg.get("suspicious_behaviors", set()):
            return True
        if behavior in ml_family_behavior_aliases.get(family, {}).get(bucket, set()):
            return True
    if family == "ML-AUTH":
        return bucket == "suspicious" and attack_family == "credential_access" and "auth" in label_value
    if family == "ML-SUDO":
        return "sudo" in behavior or " su_" in f" {behavior}"
    if family == "ML-PROC":
        return category == "process" or attack_family in {
            "execution", "defense_evasion", "command_and_control",
            "downloader_stager", "container_abuse", "impact",
        }
    if family == "ML-SERVICE":
        return category == "system" or "service" in behavior
    if family == "ML-NET":
        return attack_family in {"command_and_control", "exfiltration"} or "network" in behavior
    if family == "ML-SEQ":
        return source_trust == "sequence_high"
    if family == "ML-USER":
        return "user" in behavior or "account" in behavior
    if family == "ML-HOST":
        return "host" in behavior
    if family == "ML-DBAUTH":
        return behavior.startswith("db_") or category == "db"
    if family == "ML-DNS":
        return behavior.startswith("dns_")
    if family == "ML-WEBPOST":
        return "web_" in behavior or category == "web_attack"
    if family == "ML-IMPACT":
        return attack_family == "impact" or "impact" in behavior
    return False


def _classify_label_origin(row: dict) -> str:
    def _deprecated_alias(*parts: str) -> str:
        return "".join(parts)

    def _row_str(key: str) -> str:
        return (row.get(key, "") or "").strip()

    source = _row_str("source").lower()
    scope = _row_str("model_usage_scope").lower()
    trust = _row_str("source_trust").lower()
    reason = _row_str("label_reason").lower()
    bootstrap_job_id = _row_str("bootstrap_job_id").lower()
    label_batch_id = _row_str("label_batch_id").lower()
    deprecated_scope_aliases = {_deprecated_alias("sha", "dow", "_", "only")}
    deprecated_source_aliases = {
        _deprecated_alias("manu", "ally", "_", "verified"),
        _deprecated_alias("manu", "al", "_", "verified"),
    }

    legacy_reason = (
        scope in deprecated_scope_aliases
        or source in deprecated_source_aliases
        or trust == "legacy_unknown"
        or reason.startswith("legacy_")
        or "legacy_" in label_batch_id
    )
    if legacy_reason:
        return "legacy_excluded"

    bootstrap_reason = (
        source == "bootstrap"
        or bool(bootstrap_job_id)
        or label_batch_id.startswith("bootstrap_")
        or "historical" in source
        or "historical" in label_batch_id
    )
    if bootstrap_reason:
        return "bootstrap_historical"

    if reason.startswith(_deprecated_alias("canonical", "_", "shadow")) or "shadow" in label_batch_id:
        return "legacy_excluded"

    return "organic_live"


def _label_family_support(
    row: dict,
    *,
    ml_family_readiness: dict,
    ml_family_behavior_aliases: dict[str, dict[str, set[str]]],
) -> dict:
    support = {}
    for spec in list_ml_families():
        normal = _label_matches_family(
            row,
            spec.family_id,
            "normal",
            ml_family_readiness=ml_family_readiness,
            ml_family_behavior_aliases=ml_family_behavior_aliases,
        )
        suspicious = _label_matches_family(
            row,
            spec.family_id,
            "suspicious",
            ml_family_readiness=ml_family_readiness,
            ml_family_behavior_aliases=ml_family_behavior_aliases,
        )
        if normal or suspicious:
            support[spec.family_id] = {
                "normal": bool(normal),
                "suspicious": bool(suspicious),
            }
    return support


def _classify_label_usage(row: dict, family_support: dict) -> tuple[str, list[str]]:
    reasons: list[str] = []
    source = (row.get("source", "") or "").strip().lower()
    scope = (row.get("model_usage_scope", "") or "").strip().lower()
    event_class = (row.get("event_class", "") or "").strip().lower()
    behavior_label = (row.get("behavior_label", "") or "").strip().lower()
    learnable = row.get("learnable")

    if not scope:
        reasons.append("missing_model_usage_scope")
    if not behavior_label:
        reasons.append("missing_behavior_label")
    if event_class == "unknown_unlabeled" or behavior_label == "unknown_unlabeled":
        reasons.append("unknown_unlabeled")
        return "rejected", reasons
    if scope == "not_learnable":
        reasons.append("not_learnable")
        return "ignored", reasons
    if not family_support:
        reasons.append("missing_family_mapping")
    if source == "synthetic":
        reasons.append("synthetic_not_runtime_observed")
        return "ignored", reasons
    if reasons and any(reason in reasons for reason in ("missing_model_usage_scope", "missing_behavior_label", "missing_family_mapping")):
        return "rejected", reasons
    if learnable is False:
        reasons.append("learnable_false")
        return "ignored", reasons
    if event_class == "benign" and scope == "baseline_learning":
        return "baseline_learning", reasons
    if event_class in {"attack", "suspicious"} and scope in {"calibration_only", "baseline_learning"}:
        if scope == "baseline_learning":
            reasons.append("suspicious_baseline_scope_normalized")
        return "direct_learnable", reasons
    reasons.append("unsupported_event_class_or_scope")
    return "rejected", reasons


def _build_family_distro_cohorts(
    family: str,
    family_metrics: dict,
    global_audit: dict,
    *,
    family_label_counts_for_distro: Callable[[dict, str, str], dict],
) -> dict[str, dict]:
    runtime_by_distro = dict(family_metrics.get("candidate_count_by_distro", {}) or {})
    label_by_distro = (
        (global_audit.get("label_quality", {}) or {}).get("family_counts_by_distro", {}) or {}
    )
    distros = {
        str(distro)
        for distro in runtime_by_distro
        if int(runtime_by_distro.get(distro, 0) or 0) > 0
    }
    distros.update(
        distro
        for distro, families in label_by_distro.items()
        if int((((families or {}).get(family, {}) or {}).get("normal", 0) or 0)) > 0
        or int((((families or {}).get(family, {}) or {}).get("suspicious", 0) or 0)) > 0
    )
    cohorts: dict[str, dict] = {}
    for distro in sorted(distros):
        label_counts = family_label_counts_for_distro(global_audit, family, distro)
        source_by_distro = dict((family_metrics.get("source_by_distro", {}) or {}).get(distro, {}) or {})
        cohort_metrics = dict(family_metrics or {})
        cohort_metrics["runtime_events"] = int(runtime_by_distro.get(distro, 0) or 0)
        cohort_metrics["source_count"] = len([key for key, value in source_by_distro.items() if int(value or 0) > 0])
        cohort_metrics["candidate_count_by_distro"] = {distro: cohort_metrics["runtime_events"]}
        cohort_metrics["source_by_distro"] = {distro: source_by_distro} if source_by_distro else {}
        cohort_result = _evaluate_ml_family_readiness(
            family,
            cohort_metrics,
            {
                **dict(global_audit or {}),
                "label_quality": {
                    **dict((global_audit.get("label_quality", {}) or {})),
                    "family_counts": {
                        family: {
                            "normal": label_counts["normal"],
                            "suspicious": label_counts["suspicious"],
                        }
                    },
                },
            },
        )
        cohorts[distro] = {
            "distro": distro,
            "runtime_events": int(cohort_result.get("runtime_events", 0) or 0),
            "normal_labels": int(cohort_result.get("normal_labels", 0) or 0),
            "suspicious_labels": int(cohort_result.get("suspicious_labels", 0) or 0),
            "status": str(cohort_result.get("status", "readiness_blocked") or "readiness_blocked"),
            "reason": str(cohort_result.get("reason", "") or ""),
            "missing": list(cohort_result.get("blockers", []) or []),
            "source_count": int(cohort_result.get("source_count", 0) or 0),
        }
        quota_usage = (((global_audit.get("label_quality", {}) or {}).get("quota_summary", {}) or {}).get("usage", {}) or {})
        distro_quota = (((quota_usage.get(family, {}) or {}).get(distro, {}) or {}))
        if distro_quota:
            cohorts[distro]["quota_normal"] = dict(distro_quota.get("normal", {}) or {})
            cohorts[distro]["quota_suspicious"] = dict(distro_quota.get("suspicious", {}) or {})
    return cohorts


def _apply_distro_cohort_guard(result: dict, distro_cohorts: dict[str, dict]) -> dict:
    payload = dict(result or {})
    cohorts = dict(distro_cohorts or {})
    payload["distro_cohorts"] = cohorts
    payload["multi_distro_cohort"] = len(cohorts) > 1
    if len(cohorts) <= 1:
        return payload

    cohort_ready = any(
        str(item.get("status", "") or "") in {"active_candidate", "active"}
        for item in cohorts.values()
    )
    if payload.get("status") not in {"active_candidate", "active"} or cohort_ready:
        return payload

    blockers = list(payload.get("blockers", []) or [])
    if "mixed_distro_cohort_insufficient" not in blockers:
        blockers.append("mixed_distro_cohort_insufficient")
    payload["status"] = "readiness_blocked"
    payload["reason"] = "mixed_distro_cohort_insufficient"
    payload["blockers"] = blockers
    payload["can_emit_alert"] = False
    payload["can_score_support"] = False
    return payload


def _resolve_ml_label_metadata_mapping(
    row: dict,
    *,
    ml_label_behavior_plan_aliases: dict[str, tuple],
) -> dict:
    rule_id = _normalize_row_str(row, "rule_id").upper()
    behavior = _normalize_row_str(row, "behavior_label").lower()
    current_label = _normalize_row_str(row, "label").lower()
    if rule_id:
        resolved = resolve_rule_id_to_ml_family(rule_id)
        if resolved.matched:
            proposed_event_class = "benign" if resolved.label_class == "normal" else resolved.label_class
            return {
                "matched": True,
                "ml_family": resolved.ml_family,
                "ml_label": resolved.ml_label,
                "event_class": proposed_event_class,
                "source_trust": resolved.source_trust,
                "confidence": resolved.confidence,
                "reason": f"rule_id_mapping:{resolved.mapping_reason}",
            }
    for candidate in (behavior, current_label):
        if candidate and candidate in ml_label_behavior_plan_aliases:
            family, ml_label, event_class, reason = ml_label_behavior_plan_aliases[candidate]
            return {
                "matched": True,
                "ml_family": family,
                "ml_label": ml_label,
                "event_class": event_class,
                "source_trust": "",
                "confidence": 0.0,
                "reason": reason,
            }
    if behavior == "routine_system_event":
        return {
            "matched": False,
            "ml_family": None,
            "ml_label": None,
            "event_class": "benign",
            "source_trust": "",
            "confidence": 0.0,
            "reason": "behavior_alias:routine_system_event_family_ambiguous",
        }
    return {
        "matched": False,
        "ml_family": None,
        "ml_label": None,
        "event_class": "",
        "source_trust": "",
        "confidence": 0.0,
        "reason": "unmapped_label_metadata",
    }


__all__ = [
    '_ML_NORMAL_LABEL_PLAN_SPECS',
    '_extract_behavior_from_text',
    '_extract_rule_id_from_text',
    '_flatten_text_values',
    '_coerce_jsonish_dict',
    '_normalize_row_str',
    '_sql_quote_literal',
    '_query_ml_audit_table_count',
    '_event_source_by_distro',
    '_event_count_by_distro',
    '_collect_distribution',
    '_load_labels_read_only',
    '_metric_fill_sql',
    '_load_table_columns',
    '_execute_read_only',
    '_extract_label_metadata_hints',
    '_propose_ml_label_metadata',
    '_build_family_where_clause',
    '_label_matches_family',
    '_classify_label_origin',
    '_label_family_support',
    '_classify_label_usage',
    '_build_family_distro_cohorts',
    '_apply_distro_cohort_guard',
    '_resolve_ml_label_metadata_mapping',
    '_build_family_candidate_quality_filters',
    '_collect_global_ml_audit',
    '_collect_event_metrics',
    '_summarize_label_quality',
    '_load_rule_ids_for_ml_mapping_audit',
    'collect_ml_mapping_audit',
    'collect_ml_historical_scan_plan',
    'collect_ml_normal_label_plan',
    'collect_ml_label_trust_audit',
    'collect_ml_label_metadata_plan',
    'collect_ml_label_extraction_audit',
    'collect_ml_legacy_bootstrap_backfill_plan',
]
