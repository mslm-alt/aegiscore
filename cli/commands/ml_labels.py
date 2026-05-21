from __future__ import annotations

from typing import Any, Callable


def print_ml_label_trust_audit(report: dict) -> None:
    global_block = report["global"]
    print(f"\n{'━'*58}")
    print("  ML Label Trust Audit")
    print(f"{'━'*58}")
    print(f"  total_labels={global_block['total_labels']}")
    print(f"  by_source={global_block['by_source']}")
    print(f"  by_source_trust={global_block['by_source_trust']}")
    print(f"  by_model_usage_scope={global_block['by_model_usage_scope']}")
    print(f"  by_learnable={global_block['by_learnable']}")
    print(f"  by_event_class={global_block['by_event_class']}")
    print(f"  by_behavior_label={global_block['by_behavior_label']}")
    print(f"  usage_decisions={report['usage_decisions']}")
    print(f"  decision_reasons={report['decision_reasons']}")
    print("  family_support:")
    for family_id in sorted(report["family_support"]):
        counts = report["family_support"][family_id]
        print(f"    {family_id}: normal={counts['normal']} suspicious={counts['suspicious']}")
    print(f"  quality_summary={report['quality_summary']}")
    if global_block.get("query_notes"):
        print(f"  query_notes={global_block['query_notes']}")
    if report.get("recommended_actions"):
        print("  recommended_actions:")
        for action in report["recommended_actions"]:
            print(f"    {action}")
    print(f"{'━'*58}\n")


def run_ml_label_trust_audit(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    collect_ml_label_trust_audit: Callable[[dict, Any, dict], dict],
) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = collect_ml_label_trust_audit(config, db, pm.get_status())
        if db_error:
            report["global"]["query_notes"].append(f"db_fallback:{db_error}")
        print_ml_label_trust_audit(report)
    finally:
        if db:
            db.close()
    return 0


def print_ml_label_extraction_audit(report: dict) -> None:
    print(f"\n{'━'*58}")
    print("  ML Label Extraction Audit")
    print(f"{'━'*58}")
    for key in (
        "total_labels",
        "labels_with_nonempty_behavior_label",
        "labels_with_nonempty_event_class",
        "labels_with_nonempty_source_trust",
        "labels_with_nonempty_model_usage_scope",
        "labels_with_nonempty_evidence_fields",
        "labels_with_nonempty_label_reason",
        "evidence_fields_rule_id_count",
        "label_reason_hint_count",
        "possible_safe_mapping_count",
        "impossible_mapping_count",
    ):
        print(f"  {key}={report.get(key, 0)}")
    print(f"  bootstrap_job_id_distribution={report.get('bootstrap_job_id_distribution', {})}")
    print(f"  label_batch_id_distribution={report.get('label_batch_id_distribution', {})}")
    print(f"  reasons={report.get('reasons', {})}")
    if report.get("query_notes"):
        print(f"  query_notes={report['query_notes']}")
    if report.get("examples"):
        print("  examples:")
        for item in report["examples"]:
            print(
                "    "
                f"id={item['id']} source={item['source']} source_trust={item['source_trust']} "
                f"scope={item['model_usage_scope']} event_class={item['event_class']} "
                f"behavior={item['behavior_label']} safe_to_map={item['safe_to_map']} "
                f"proposed_extraction={item['proposed_extraction']}"
            )
    print(f"{'━'*58}\n")


def run_ml_label_extraction_audit(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    collect_ml_label_extraction_audit: Callable[[dict, Any, dict], dict],
) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = collect_ml_label_extraction_audit(config, db, pm.get_status())
        if db_error:
            report.setdefault("query_notes", []).append(f"db_fallback:{db_error}")
        print_ml_label_extraction_audit(report)
    finally:
        if db:
            db.close()
    return 0


def print_ml_label_metadata_plan(report: dict) -> None:
    print(f"\n{'━'*58}")
    print("  ML Label Metadata Plan")
    print(f"{'━'*58}")
    print(f"  total_labels={report['total_labels']}")
    print(f"  proposed_updates={report['proposed_updates']}")
    print(f"  learnable_candidate_count={report['learnable_candidate_count']}")
    print(f"  blocked_count={report['blocked_count']}")
    print(f"  by_proposed_ml_family={report['by_proposed_ml_family']}")
    print(f"  by_proposed_usage_decision={report['by_proposed_usage_decision']}")
    print(f"  missing_metadata_counts={report['missing_metadata_counts']}")
    if report.get("query_notes"):
        print(f"  query_notes={report['query_notes']}")
    if report.get("examples"):
        print("  examples:")
        for item in report["examples"]:
            print(
                "    "
                f"label_id={item['label_id']} family={item['proposed_ml_family']} "
                f"label={item['proposed_ml_label']} usage={item['proposed_usage_decision']} "
                f"learnable_candidate={item['learnable_candidate']} reason={item['reason']}"
            )
    print(f"{'━'*58}\n")


def run_ml_label_metadata_plan(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    collect_ml_label_metadata_plan: Callable[[dict, Any, dict], dict],
) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = collect_ml_label_metadata_plan(config, db, pm.get_status())
        if db_error:
            report.setdefault("query_notes", []).append(f"db_fallback:{db_error}")
        print_ml_label_metadata_plan(report)
    finally:
        if db:
            db.close()
    return 0


def collect_ml_label_contract_audit() -> dict:
    from core.ml.label_engine import (
        ML_LABEL_CONTRACT_REQUIRED_FIELDS,
        ML_LABEL_SOURCE_TYPES,
        build_ml_label_metadata,
        validate_ml_label_metadata,
    )

    sample_specs = {
        "rule_mapped_attack": {"ml_family": "ML-AUTH", "ml_label": "auth_attack_or_abuse", "rule_id": "AUTH-004"},
        "clean_window_normal": {"ml_family": "ML-PROC", "ml_label": "process_normal"},
        "bootstrap_seed": {"ml_family": "ML-DNS", "ml_label": "dns_anomaly"},
        "synthetic_seed": {"ml_family": "ML-PROC", "ml_label": "suspicious_process"},
        "auto_labeled_rule_mapped": {"ml_family": "ML-WEBPOST", "ml_label": "web_attack_or_post_exploit", "rule_id": "WEB-004"},
    }
    source_type_results = {}
    learnable_source_types = []
    for source_type in sorted(ML_LABEL_SOURCE_TYPES):
        metadata = build_ml_label_metadata(source_type, **sample_specs[source_type])
        validation = validate_ml_label_metadata(metadata)
        source_type_results[source_type] = {
            "metadata": metadata,
            "validation": validation,
        }
        if metadata.get("model_usage_scope") in {"baseline_learning", "calibration_only"} and validation.get("valid"):
            learnable_source_types.append(source_type)
    return {
        "supported_source_types": sorted(ML_LABEL_SOURCE_TYPES),
        "required_fields": list(ML_LABEL_CONTRACT_REQUIRED_FIELDS),
        "no_action_contract": True,
        "learnable_source_types": sorted(learnable_source_types),
        "source_type_results": source_type_results,
    }


def print_ml_label_contract_audit(report: dict) -> None:
    print(f"\n{'━'*58}")
    print("  ML Label Contract Audit")
    print(f"{'━'*58}")
    print(f"  supported_source_types={report['supported_source_types']}")
    print(f"  required_fields={report['required_fields']}")
    print(f"  no_action_contract={report['no_action_contract']}")
    print(f"  learnable_source_types={report['learnable_source_types']}")
    print("  source_type_results:")
    for source_type in sorted(report["source_type_results"]):
        item = report["source_type_results"][source_type]
        print(
            f"    {source_type}: valid={item['validation']['valid']} "
            f"usage={item['metadata'].get('model_usage_scope')} "
            f"ml_family={item['metadata'].get('ml_family')} "
            f"problems={item['validation']['problems']}"
        )
    print(f"{'━'*58}\n")


def run_ml_label_contract_audit(config: dict) -> int:
    _ = config
    print_ml_label_contract_audit(collect_ml_label_contract_audit())
    return 0


def collect_ml_config_audit(
    config: dict,
    db=None,
    *,
    list_ml_families: Callable[[], list[Any]],
    ml_family_readiness: dict,
    ml_config_default_status: dict,
    ml_config_valid_statuses: set[str],
    ml_config_valid_phase_gates: set[str],
    ml_schema_contract: dict,
    load_table_columns: Callable[[Any, str], tuple[set[str], list[str]]],
) -> dict:
    ml_cfg = (config.get("ml", {}) or {})
    active_layer = (ml_cfg.get("active_decision_layer", {}) or {})
    family_cfg = (ml_cfg.get("family", {}) or {})
    registry_specs = {spec.family_id: spec for spec in list_ml_families()}
    expected_families = sorted(registry_specs)
    configured_families = sorted((family_cfg or {}).keys())
    missing_families = sorted(set(expected_families) - set(configured_families))
    extra_families = sorted(set(configured_families) - set(expected_families))
    family_reports = {}
    mismatches = []
    phase_valid = True
    thresholds_positive = True
    no_action_contract_ok = bool(active_layer.get("no_action_contract") is True)

    for family_id in expected_families:
        spec = registry_specs[family_id]
        readiness = ml_family_readiness[family_id]
        actual = (family_cfg.get(family_id, {}) or {})
        expected = {
            "default_status": ml_config_default_status[family_id],
            "phase_gate": spec.phase_gate,
            "runtime_min_events": int(readiness["required_events"]),
            "normal_label_min": int(readiness["required_normal_labels"]),
            "suspicious_label_min": int(readiness["required_suspicious_labels"]),
            "time_features_enabled": bool(spec.time_features_enabled),
            "no_action_contract": bool(spec.no_action_contract),
        }
        family_mismatches = []
        if not actual:
            family_mismatches.append("missing_family_config")
        else:
            if actual.get("default_status") not in ml_config_valid_statuses:
                family_mismatches.append("invalid_default_status")
            if actual.get("phase_gate") not in ml_config_valid_phase_gates:
                family_mismatches.append("invalid_phase_gate")
                phase_valid = False
            for threshold_key in ("runtime_min_events", "normal_label_min", "suspicious_label_min"):
                value = actual.get(threshold_key)
                if not isinstance(value, int) or value <= 0:
                    family_mismatches.append(f"invalid_{threshold_key}")
                    thresholds_positive = False
            if actual.get("no_action_contract") is not True:
                family_mismatches.append("no_action_contract_false")
                no_action_contract_ok = False
            for key, expected_value in expected.items():
                if actual.get(key) != expected_value:
                    family_mismatches.append(f"mismatch:{key}")
        if family_mismatches:
            mismatches.append({family_id: family_mismatches})
        family_reports[family_id] = {
            "config_present": bool(actual),
            "expected": expected,
            "actual": actual,
            "mismatches": family_mismatches,
        }

    label_columns, label_errors = load_table_columns(db, "labels")
    alert_columns, alert_errors = load_table_columns(db, "alerts")
    schema_contract = {
        "query_notes": list(label_errors or []) + list(alert_errors or []),
        "labels_existing_present": sorted(set(label_columns) & set(ml_schema_contract["labels_existing"])),
        "labels_existing_missing": sorted(set(ml_schema_contract["labels_existing"]) - set(label_columns)),
        "labels_future_missing": sorted(set(ml_schema_contract["labels_future"]) - set(label_columns)),
        "alerts_future_missing": sorted(set(ml_schema_contract["alerts_future"]) - set(alert_columns)),
    }
    if not label_columns:
        schema_contract["query_notes"].append("missing_table_or_unavailable:labels")
    if not alert_columns:
        schema_contract["query_notes"].append("missing_table_or_unavailable:alerts")

    recommended_actions = []
    if active_layer.get("enabled") is not False:
        recommended_actions.append("active_decision_layer.enabled false kalmalı; active ML bu patchte açılmamalı")
    if active_layer.get("mode") != "audit_only":
        recommended_actions.append("active_decision_layer.mode audit_only kalmalı")
    if missing_families:
        recommended_actions.append(f"config içinde eksik ML family contract kayıtları var: {', '.join(missing_families)}")
    if schema_contract["labels_future_missing"] or schema_contract["alerts_future_missing"]:
        recommended_actions.append("future ML metadata/schema contract alanları henüz DB'de yok; bu patch migration yapmaz, sadece contract raporlar")
    if schema_contract["labels_existing_missing"]:
        recommended_actions.append("labels metadata contract alanlarının bir kısmı eksik; legacy/backfill planı yürütülmeden önce schema yüzeyi doğrulanmalı")
    if not no_action_contract_ok:
        recommended_actions.append("no_action_contract her family ve active_decision_layer için true kalmalı")

    return {
        "active_decision_layer": {
            "enabled": active_layer.get("enabled"),
            "mode": active_layer.get("mode"),
            "no_action_contract": active_layer.get("no_action_contract"),
        },
        "family_set_match": not missing_families and not extra_families,
        "registry_consistent": not mismatches,
        "phase_gates_valid": phase_valid,
        "thresholds_positive": thresholds_positive,
        "no_action_contract_ok": no_action_contract_ok,
        "missing_families": missing_families,
        "extra_families": extra_families,
        "family_reports": family_reports,
        "schema_contract": schema_contract,
        "recommended_actions": recommended_actions,
    }


def print_ml_config_audit(report: dict) -> None:
    print(f"\n{'━'*58}")
    print("  ML Config Audit")
    print(f"{'━'*58}")
    print(f"  active_decision_layer={report['active_decision_layer']}")
    print(f"  family_set_match={report['family_set_match']}")
    print(f"  registry_consistent={report['registry_consistent']}")
    print(f"  phase_gates_valid={report['phase_gates_valid']}")
    print(f"  thresholds_positive={report['thresholds_positive']}")
    print(f"  no_action_contract_ok={report['no_action_contract_ok']}")
    if report.get("missing_families"):
        print(f"  missing_families={report['missing_families']}")
    if report.get("extra_families"):
        print(f"  extra_families={report['extra_families']}")
    print("  family_reports:")
    for family_id in sorted(report["family_reports"]):
        item = report["family_reports"][family_id]
        print(
            f"    {family_id}: config_present={item['config_present']} "
            f"mismatches={item['mismatches']}"
        )
    print(f"  schema_contract={report['schema_contract']}")
    if report.get("recommended_actions"):
        print("  recommended_actions:")
        for action in report["recommended_actions"]:
            print(f"    {action}")
    print(f"{'━'*58}\n")


def run_ml_config_audit(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    collect_ml_config_audit: Callable[[dict, Any], dict],
) -> int:
    _pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = collect_ml_config_audit(config, db)
        if db_error:
            report["schema_contract"].setdefault("query_notes", []).append(f"db_fallback:{db_error}")
        print_ml_config_audit(report)
    finally:
        if db:
            db.close()
    return 0
