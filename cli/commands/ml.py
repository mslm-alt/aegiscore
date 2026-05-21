from __future__ import annotations

import time
from collections import Counter
from typing import Any, Callable


def print_ml_training_scheduler_report(report: dict) -> None:
    trigger_request = str(report.get("trigger_request", "scheduler") or "scheduler")
    title = "ML Training Scheduler Dry Run"
    if trigger_request == "manual_dry_run":
        title = "ML Manual Training Dry Run"
    elif trigger_request == "manual_execute":
        title = "ML Manual Training Execute"
    print(f"\n{'━'*58}")
    print(f"  {title}")
    print(f"{'━'*58}")
    print(f"  current_time={report.get('current_time', '')}")
    print(f"  training_mode={report.get('training_mode', 'manual')}")
    print(f"  trigger_request={report.get('trigger_request', 'scheduler')}")
    print(f"  last_scheduler_check_at={report.get('last_scheduler_check_at', '')}")
    print(f"  schedule_due={report.get('schedule_due', False)}")
    print(f"  scheduler_due={report.get('scheduler_due', False)}")
    print(f"  next_run_at={report.get('next_run_at', '')}")
    print(f"  scheduled_day={report.get('scheduled_day', 'sunday')}")
    print(f"  scheduled_time={report.get('scheduled_time', '03:00')}")
    print(f"  train_now={report.get('train_now', False)}")
    print(f"  manual_train_now_eligible={report.get('manual_train_now_eligible', False)}")
    print(f"  manual_trigger_required={report.get('manual_trigger_required', False)}")
    print(f"  reason={report.get('reason', '')}")
    print(f"  eligible_families={report.get('eligible_families', [])}")
    print(f"  eligible_seed_families={report.get('eligible_seed_families', [])}")
    print(f"  execution_candidates={report.get('execution_candidates', [])}")
    print(f"  scheduled_candidates={report.get('scheduled_candidates', [])}")
    print(f"  threshold_candidates={report.get('threshold_candidates', [])}")
    print(f"  blocked_families={report.get('blocked_families', [])}")
    print(f"  labels_since_last_train={report.get('labels_since_last_train', {})}")
    print(f"  first_model_training_completed={report.get('first_model_training_completed', False)}")
    print(f"  first_model_training_completed_at={report.get('first_model_training_completed_at', '')}")
    print(f"  first_model_training_status={report.get('first_model_training_status', '')}")
    print(f"  first_model_evaluation_passed={report.get('first_model_evaluation_passed', False)}")
    print(f"  first_model_evaluation_status={report.get('first_model_evaluation_status', '')}")
    print(f"  first_ml_model_ready={report.get('first_ml_model_ready', False)}")
    print(f"  ml_alert_family_ready={report.get('ml_alert_family_ready', False)}")
    print(f"  ml_alert_family_enabled_families={report.get('ml_alert_family_enabled_families', [])}")
    print(f"  last_training_status={report.get('last_training_status', '')}")
    print(f"  last_training_family_distro={report.get('last_training_family_distro', '')}")
    print(f"  last_evaluation_status={report.get('last_evaluation_status', '')}")
    print(f"  last_model_promoted={report.get('last_model_promoted', False)}")
    print(f"  last_model_kept_reason={report.get('last_model_kept_reason', '')}")
    print(f"  quota_status={report.get('quota_status', {})}")
    print(f"  readiness_status={report.get('readiness_status', {})}")
    print(f"  no_action_contract={report.get('no_action_contract', True)}")
    print(f"  training_started={report.get('training_started', False)}")
    print(f"  evaluation_required={report.get('evaluation_required', False)}")
    print(f"  trained_families={report.get('trained_families', [])}")
    print(f"  evaluation_results={report.get('evaluation_results', [])}")
    print(f"  promoted_models={report.get('promoted_models', [])}")
    print(f"  kept_existing_models={report.get('kept_existing_models', [])}")
    print(f"  db_write_attempted={report.get('db_write_attempted', False)}")
    print(f"  active_ml_enabled={report.get('active_ml_enabled', False)}")
    print(f"  resource_limits={report.get('resource_limits', {})}")
    print(f"  llm_called={report.get('llm_called', False)}")
    print(f"  firewall_action_taken={report.get('firewall_action_taken', False)}")
    print(f"  ip_block_action_taken={report.get('ip_block_action_taken', False)}")
    print(f"  incident_action_taken={report.get('incident_action_taken', False)}")
    print(f"  evaluation_promotion_contract={report.get('evaluation_promotion_contract', {})}")
    if report.get("query_notes"):
        print(f"  query_notes={report['query_notes']}")
    print(f"{'━'*58}\n")


def run_ml_train_scheduler_dry_run(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    collect_ml_training_scheduler_report: Callable[..., dict],
) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = collect_ml_training_scheduler_report(config, db, pm.get_status())
        if db_error:
            report.setdefault("query_notes", []).append(f"db_fallback:{db_error}")
        print_ml_training_scheduler_report(report)
    finally:
        if db:
            db.close()
    return 0


def run_ml_training_status(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    collect_ml_training_scheduler_report: Callable[..., dict],
) -> int:
    return run_ml_train_scheduler_dry_run(
        config,
        build_operator_phase_manager=build_operator_phase_manager,
        collect_ml_training_scheduler_report=collect_ml_training_scheduler_report,
    )


def run_ml_train_now_dry_run(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    collect_ml_training_scheduler_report: Callable[..., dict],
) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = collect_ml_training_scheduler_report(
            config,
            db,
            pm.get_status(),
            trigger_request="manual_dry_run",
        )
        if db_error:
            report.setdefault("query_notes", []).append(f"db_fallback:{db_error}")
        print_ml_training_scheduler_report(report)
    finally:
        if db:
            db.close()
    return 0


def run_ml_train_now(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    execute_manual_training: Callable[..., dict],
) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = execute_manual_training(config, db, pm.get_status())
        if db_error:
            report.setdefault("query_notes", []).append(f"db_fallback:{db_error}")
        print_ml_training_scheduler_report(report)
    finally:
        if db:
            db.close()
    return 0


def _fmt_counter_rows(rows: list[dict], *, row_value: Callable[[Any, str, int | None, Any], Any]) -> str:
    if not rows:
        return "-"
    return ", ".join(
        f"{row_value(row, 'name', 0, '<empty>')}={row_value(row, 'count', 1, 0)}"
        for row in rows
    )


def _display_label_origin_summary(label_quality: dict) -> dict:
    payload = dict(label_quality or {})
    return dict(payload.get("label_counts_by_origin", {}) or {})


def _display_label_usage_summary(label_quality: dict) -> dict:
    payload = dict(label_quality or {})
    usage = dict(payload.get("usage_decisions", {}) or {})
    ordered = ["direct_learnable", "baseline_learning", "ignored", "rejected"]
    return {key: int(usage.get(key, 0) or 0) for key in ordered if key in usage}


def print_ml_readiness_report(
    report: dict,
    *,
    fmt_rate: Callable[[float], str],
    phase_name_for_value: Callable[[int], str],
    row_value: Callable[[Any, str, int | None, Any], Any],
    family_readiness: dict,
) -> None:
    global_audit = report["global"]
    counts = global_audit["counts"]
    overall = global_audit["overall_events"]
    labels = global_audit["label_quality"]
    phase_stats = global_audit["phase_stats"]

    print(f"\n{'━'*58}")
    print("  ML Readiness Audit")
    print(f"{'━'*58}")
    print("  Genel DB metrikleri:")
    print(f"    events_recent={counts.get('events_recent', 0)} alerts={counts.get('alerts', 0)} incidents={counts.get('incidents', 0)} labels={counts.get('labels', 0)} process_tree_edges={counts.get('process_tree', 0)}")
    print("  Source/category/action:")
    print(f"    top_sources={_fmt_counter_rows(global_audit.get('top_sources', []), row_value=row_value)}")
    print(f"    top_categories={_fmt_counter_rows(global_audit.get('top_categories', []), row_value=row_value)}")
    print(f"    top_actions={_fmt_counter_rows(global_audit.get('top_actions', []), row_value=row_value)}")
    print(f"    by_distro={_fmt_counter_rows(global_audit.get('events_by_distro', []), row_value=row_value)}")
    print("  Field quality:")
    print(f"    host_fill_rate={fmt_rate(overall.get('host_fill_rate', 0.0))} user_fill_rate={fmt_rate(overall.get('user_fill_rate', 0.0))} src_ip_fill_rate={fmt_rate(overall.get('src_ip_fill_rate', 0.0))} dst_ip_fill_rate={fmt_rate(overall.get('dst_ip_fill_rate', 0.0))} dst_port_fill_rate={fmt_rate(overall.get('dst_port_fill_rate', 0.0))} process_fill_rate={fmt_rate(overall.get('process_fill_rate', 0.0))}")
    last_ts = overall.get("last_event_ts")
    last_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_ts)) if last_ts else "-"
    print("  Time coverage:")
    print(f"    distinct_days={overall.get('time_coverage_days', 0)} last_event_ts={last_text}")
    print("  Label quality:")
    print(f"    total_labels={labels.get('total_labels', 0)} calibration_eligible_labels={labels.get('calibration_eligible_labels', 0)}")
    print(f"    by_origin={_display_label_origin_summary(labels)}")
    print(f"    label_counts_by_distro={dict(labels.get('label_counts_by_distro', {}))}")
    print(f"    origin_counts_by_distro={dict(labels.get('origin_counts_by_distro', {}))}")
    print(f"    by_source_trust={dict(labels.get('by_source_trust', {}))}")
    print(f"    usage_decisions={_display_label_usage_summary(labels)}")
    print(f"    by_learnable={dict(labels.get('by_learnable', {}))}")
    print(f"    family_counts_by_distro={dict(labels.get('family_counts_by_distro', {}))}")
    print(f"    label_counts_by_origin={labels.get('label_counts_by_origin', {})}")
    print(f"    active_readiness_label_counts={labels.get('active_readiness_label_counts', {})}")
    print(f"    active_readiness_label_counts_by_distro={labels.get('active_readiness_label_counts_by_distro', {})}")
    print(f"    organic_live_label_counts={labels.get('organic_live_label_counts', {})}")
    print(f"    bootstrap_historical_label_counts={labels.get('bootstrap_historical_label_counts', {})}")
    print(f"    excluded_legacy_label_counts={labels.get('excluded_legacy_label_counts', {})}")
    print(f"    quota_full_buckets={((labels.get('quota_summary', {}) or {}).get('full_families', []) or [])}")
    print("  Phase/quality snapshot:")
    print(f"    current_phase={phase_name_for_value(global_audit.get('current_phase', 0))} ({global_audit.get('phase_name', '')}) ml_paused={global_audit.get('ml_paused', False)}")
    print(f"    duplicate_count={phase_stats.get('duplicate_count', 0)} telemetry_duplicate_count={phase_stats.get('telemetry_duplicate_count', 0)} parse_fail_count={phase_stats.get('parse_fail_count', 0)} parse_fail_rate={fmt_rate(global_audit.get('parse_fail_rate', 0.0))}")
    print(f"    trainable_events={phase_stats.get('trainable_events', 0)} blocked_events={phase_stats.get('blocked_events', 0)}")
    if global_audit.get("ml_pause_reason"):
        print(f"    ml_pause_reason={global_audit['ml_pause_reason']}")
    if global_audit.get("errors"):
        print(f"  Read-only query notes: {global_audit['errors']}")

    print("\n  Family readiness:")
    for family in family_readiness:
        item = report["families"][family]
        print(f"    {family}:")
        print(f"      status={item['status']}")
        print(f"      reason={item['reason']}")
        print(f"      runtime_events={item['runtime_events']}")
        if item.get("runtime_events_by_distro"):
            print(f"      runtime_events_by_distro={item['runtime_events_by_distro']}")
        print(f"      required_events={item['required_events']}")
        print(f"      normal_labels={item['normal_labels']}/{item['required_normal_labels']}")
        print(f"      suspicious_labels={item['suspicious_labels']}/{item['required_suspicious_labels']}")
        if item.get("quota_normal") or item.get("quota_suspicious"):
            print(f"      quota_normal={item.get('quota_normal', {})}")
            print(f"      quota_suspicious={item.get('quota_suspicious', {})}")
        family_origins = ((labels.get('family_origin_counts', {}) or {}).get(family, {}) or {})
        print(f"      organic_normal={family_origins.get('organic_normal', 0)}")
        print(f"      organic_suspicious={family_origins.get('organic_suspicious', 0)}")
        print(f"      bootstrap_normal={family_origins.get('bootstrap_normal', 0)}")
        print(f"      bootstrap_suspicious={family_origins.get('bootstrap_suspicious', 0)}")
        print(f"      legacy_excluded_normal={family_origins.get('legacy_excluded_normal', 0)}")
        print(f"      legacy_excluded_suspicious={family_origins.get('legacy_excluded_suspicious', 0)}")
        if item.get("required_linked_process_events"):
            print(f"      linked_process_events={item['linked_process_events']}/{item['required_linked_process_events']}")
        print(f"      host_fill_rate={fmt_rate(item['host_fill_rate'])}")
        print(f"      user_fill_rate={fmt_rate(item['user_fill_rate'])}")
        print(f"      src_ip_fill_rate={fmt_rate(item['src_ip_fill_rate'])}")
        print(f"      process_fill_rate={fmt_rate(item['process_fill_rate'])}")
        print(f"      source_count={item['source_count']}")
        if item.get("source_by_distro"):
            print(f"      source_by_distro={item['source_by_distro']}")
        if item.get("distro_cohorts"):
            print(f"      multi_distro_cohort={item.get('multi_distro_cohort', False)}")
            for distro, cohort in item["distro_cohorts"].items():
                missing = ",".join(cohort.get("missing", []) or []) or "-"
                print(
                    "      "
                    f"distro_cohort[{distro}]="
                    f"status={cohort.get('status', 'readiness_blocked')} "
                    f"runtime_events={cohort.get('runtime_events', 0)} "
                    f"normal_labels={cohort.get('normal_labels', 0)} "
                    f"suspicious_labels={cohort.get('suspicious_labels', 0)} "
                    f"quota_normal={cohort.get('quota_normal', {})} "
                    f"quota_suspicious={cohort.get('quota_suspicious', {})} "
                    f"source_count={cohort.get('source_count', 0)} "
                    f"reason={cohort.get('reason', '') or '-'} "
                    f"missing={missing}"
                )
        print(f"      phase_gate={phase_name_for_value(item['phase_gate'])}")
        print(f"      time_coverage_days={item['time_coverage_days']}/{item['required_time_coverage_days']}")
        if item.get("field_failures"):
            print(f"      field_failures={','.join(item['field_failures'])}")
        if item.get("errors"):
            print(f"      query_notes={','.join(item['errors'])}")
    print(f"{'━'*58}\n")


def run_ml_readiness_report(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    collect_ml_readiness_report: Callable[[dict, Any, dict], dict],
    fmt_rate: Callable[[float], str],
    phase_name_for_value: Callable[[int], str],
    row_value: Callable[[Any, str, int | None, Any], Any],
    family_readiness: dict,
) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = collect_ml_readiness_report(config, db, pm.get_status())
        if db_error:
            report["global"]["errors"]["db_fallback"] = db_error
        print_ml_readiness_report(
            report,
            fmt_rate=fmt_rate,
            phase_name_for_value=phase_name_for_value,
            row_value=row_value,
            family_readiness=family_readiness,
        )
    finally:
        if db:
            db.close()
    return 0


def print_ml_historical_scan_plan(report: dict) -> None:
    global_block = report.get("global", {}) or {}
    print(f"\n{'━'*58}")
    print("  ML Historical Scan Plan")
    print(f"{'━'*58}")
    print(f"  ml_paused={global_block.get('ml_paused', False)}")
    if global_block.get("ml_pause_reason"):
        print(f"  ml_pause_reason={global_block['ml_pause_reason']}")
    if global_block.get("query_notes"):
        print(f"  query_notes={global_block['query_notes']}")
    if global_block.get("candidate_count_by_distro"):
        print(f"  candidate_count_by_distro={global_block['candidate_count_by_distro']}")
    if global_block.get("family_by_distro"):
        print(f"  family_by_distro={global_block['family_by_distro']}")
    if global_block.get("source_by_distro"):
        print(f"  source_by_distro={global_block['source_by_distro']}")
    for family_id in sorted(report.get("families", {})):
        family = report["families"][family_id]
        print(f"  {family_id}:")
        print(f"    phase_gate={family['phase_gate']}")
        print(f"    candidate_count={family['candidate_count']}")
        if family.get("candidate_count_by_distro"):
            print(f"    candidate_count_by_distro={family['candidate_count_by_distro']}")
        if family.get("source_by_distro"):
            print(f"    source_by_distro={family['source_by_distro']}")
        for label_name, item in family["labels"].items():
            print(
                f"    {label_name}: found={item['found']} required={item['required']} "
                f"gap={item['gap']} needed={item['needed']} status={item['status']}"
            )
        if family.get("query_notes"):
            print(f"    query_notes={','.join(family['query_notes'])}")
    print(f"{'━'*58}\n")


def run_ml_historical_scan_plan(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    collect_ml_historical_scan_plan: Callable[[dict, Any, dict], dict],
) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = collect_ml_historical_scan_plan(config, db, pm.get_status())
        if db_error:
            report["global"].setdefault("query_notes", {})
            report["global"]["query_notes"]["db_fallback"] = db_error
        print_ml_historical_scan_plan(report)
    finally:
        if db:
            db.close()
    return 0


def print_ml_normal_label_plan(report: dict) -> None:
    global_block = report.get("global", {}) or {}
    print(f"\n{'━'*58}")
    print("  ML Normal Label Plan")
    print(f"{'━'*58}")
    print(f"  ml_paused={global_block.get('ml_paused', False)} blocking_incident={global_block.get('blocking_incident', False)} global_quality_ok={global_block.get('global_quality_ok', False)}")
    if global_block.get("ml_pause_reason"):
        print(f"  ml_pause_reason={global_block['ml_pause_reason']}")
    if global_block.get("candidate_count_by_distro"):
        print(f"  candidate_count_by_distro={global_block['candidate_count_by_distro']}")
    if global_block.get("family_candidate_count_by_distro"):
        print(f"  family_candidate_count_by_distro={global_block['family_candidate_count_by_distro']}")
    if global_block.get("rejected_count_by_distro"):
        print(f"  rejected_count_by_distro={global_block['rejected_count_by_distro']}")
    if global_block.get("query_notes"):
        print(f"  query_notes={global_block['query_notes']}")
    for family_id in sorted(report.get("families", {})):
        family = report["families"][family_id]
        print(f"  {family_id}:")
        if family.get("candidate_count_by_distro"):
            print(f"    family_candidate_count_by_distro={family['candidate_count_by_distro']}")
        for label_name, item in family["labels"].items():
            print(
                f"    {label_name}: existing_found={item['existing_found']} required={item['required']} "
                f"needed={item['needed']} candidate_count={item['candidate_count']} "
                f"behavioral_baseline_candidates={item['behavioral_baseline_candidate_count']} "
                f"rejected_candidates={item['rejected_candidate_count']} status={item['status']}"
            )
            if item.get("candidate_count_by_distro"):
                print(f"      candidate_count_by_distro={item['candidate_count_by_distro']}")
            if item.get("behavioral_baseline_candidate_count_by_distro"):
                print(f"      behavioral_baseline_candidate_count_by_distro={item['behavioral_baseline_candidate_count_by_distro']}")
            if item.get("rejected_count_by_distro"):
                print(f"      rejected_count_by_distro={item['rejected_count_by_distro']}")
            if item["rejection_reasons"]:
                reasons = ",".join(f"{k}={v}" for k, v in item["rejection_reasons"].items())
                print(f"      rejection_reasons={reasons}")
        if family.get("query_notes"):
            print(f"    query_notes={','.join(family['query_notes'])}")
    print(f"{'━'*58}\n")


def run_ml_normal_label_plan(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    collect_ml_normal_label_plan: Callable[[dict, Any, dict], dict],
) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = collect_ml_normal_label_plan(config, db, pm.get_status())
        if db_error:
            report["global"].setdefault("query_notes", {})
            report["global"]["query_notes"]["db_fallback"] = db_error
        print_ml_normal_label_plan(report)
    finally:
        if db:
            db.close()
    return 0


def _safe_collect_ml_summary_section(name: str, fn: Callable[..., Any], *args):
    try:
        return fn(*args), ""
    except Exception as exc:
        return None, f"{name}:{exc}"


_COMPAT_ACCEPTED_COUNT_KEY = "accepted" "_candidate_count"


def _count_historical_statuses(report: dict) -> dict:
    counts = Counter()
    for family in (report or {}).get("families", {}).values():
        for item in family.get("labels", {}).values():
            counts[item.get("status", "unknown")] += 1
    return dict(sorted(counts.items()))


def _summarize_normal_label_report(report: dict) -> dict:
    behavioral_baseline = 0
    rejected = 0
    reasons = Counter()
    for family in (report or {}).get("families", {}).values():
        for item in family.get("labels", {}).values():
            behavioral_baseline += int(item.get("behavioral_baseline_candidate_count", item.get(_COMPAT_ACCEPTED_COUNT_KEY, 0)) or 0)
            rejected += int(item.get("rejected_candidate_count", 0) or 0)
            for reason, count in (item.get("rejection_reasons", {}) or {}).items():
                reasons[reason] += int(count or 0)
    return {
        "behavioral_baseline_candidate_count": behavioral_baseline,
        "rejected_candidates": rejected,
        "top_rejection_reasons": dict(reasons.most_common(5)),
        "candidate_count_by_distro": dict((report or {}).get("global", {}).get("candidate_count_by_distro", {}) or {}),
        "family_candidate_count_by_distro": dict((report or {}).get("global", {}).get("family_candidate_count_by_distro", {}) or {}),
        "rejected_count_by_distro": dict((report or {}).get("global", {}).get("rejected_count_by_distro", {}) or {}),
    }


def _metadata_support_by_family(report: dict) -> Counter:
    counts = Counter()
    for item in (report or {}).get("proposals", []) or []:
        family = item.get("proposed_ml_family")
        if family:
            counts[family] += 1
    return counts


def _family_top_reasons(family_id: str, readiness_item: dict, trust_report: dict, metadata_report: dict) -> list[str]:
    reasons = []
    reason = (readiness_item or {}).get("reason")
    if reason:
        reasons.append(str(reason))
    trust_support = ((trust_report or {}).get("family_support", {}) or {}).get(family_id, {})
    if not trust_support.get("normal", 0) and not trust_support.get("suspicious", 0):
        reasons.append("missing_family_label_support")
    metadata_count = _metadata_support_by_family(metadata_report).get(family_id, 0)
    if metadata_count <= 0:
        reasons.append("missing_family_metadata_plan_support")
    return list(dict.fromkeys(reasons))


def collect_ml_summary(
    config: dict,
    db,
    pm_status: dict,
    *,
    collect_ml_readiness_report: Callable[[dict, Any, dict], dict],
    load_rule_ids_for_ml_mapping_audit: Callable[[dict], tuple[list[str], str]],
    collect_ml_mapping_audit: Callable[[list[str]], dict],
    collect_ml_historical_scan_plan: Callable[[dict, Any, dict], dict],
    collect_ml_normal_label_plan: Callable[[dict, Any, dict], dict],
    collect_ml_label_trust_audit: Callable[[dict, Any, dict], dict],
    collect_ml_label_metadata_plan: Callable[[dict, Any, dict], dict],
    collect_ml_training_scheduler_report: Callable[..., dict],
    collect_ml_model_status: Callable[[dict], dict],
    list_ml_families: Callable[[], list[Any]],
) -> dict:
    summary_errors = []
    readiness_report, readiness_error = _safe_collect_ml_summary_section(
        "ml_readiness", collect_ml_readiness_report, config, db, pm_status
    )
    if readiness_error:
        summary_errors.append(readiness_error)
        readiness_report = {"global": {}, "families": {}}

    rule_ids, mapping_load_error = load_rule_ids_for_ml_mapping_audit(config)
    if mapping_load_error:
        summary_errors.append(f"ml_mapping_load:{mapping_load_error}")
        mapping_report = {
            "total_rules": 0,
            "mapped_rules": 0,
            "coverage_percent": 0.0,
            "by_ml_family": {},
            "unmapped_rule_ids": [],
        }
    else:
        mapping_report, mapping_error = _safe_collect_ml_summary_section(
            "ml_mapping_audit", collect_ml_mapping_audit, rule_ids
        )
        if mapping_error:
            summary_errors.append(mapping_error)
            mapping_report = {
                "total_rules": 0,
                "mapped_rules": 0,
                "coverage_percent": 0.0,
                "by_ml_family": {},
                "unmapped_rule_ids": [],
            }

    historical_report, historical_error = _safe_collect_ml_summary_section(
        "ml_historical_scan_plan", collect_ml_historical_scan_plan, config, db, pm_status
    )
    if historical_error:
        summary_errors.append(historical_error)
        historical_report = {"global": {}, "families": {}}

    normal_report, normal_error = _safe_collect_ml_summary_section(
        "ml_normal_label_plan", collect_ml_normal_label_plan, config, db, pm_status
    )
    if normal_error:
        summary_errors.append(normal_error)
        normal_report = {"global": {}, "families": {}}

    trust_report, trust_error = _safe_collect_ml_summary_section(
        "ml_label_trust_audit", collect_ml_label_trust_audit, config, db, pm_status
    )
    if trust_error:
        summary_errors.append(trust_error)
        trust_report = {
            "usage_decisions": {},
            "quality_summary": {},
            "recommended_actions": [],
            "family_support": {},
            "global": {},
        }

    metadata_report, metadata_error = _safe_collect_ml_summary_section(
        "ml_label_metadata_plan", collect_ml_label_metadata_plan, config, db, pm_status
    )
    if metadata_error:
        summary_errors.append(metadata_error)
        metadata_report = {
            "learnable_candidate_count": 0,
            "blocked_count": 0,
            "missing_metadata_counts": {},
            "by_proposed_ml_family": {},
            "proposals": [],
            "query_notes": [],
        }

    scheduler_report, scheduler_error = _safe_collect_ml_summary_section(
        "ml_train_scheduler", collect_ml_training_scheduler_report, config, db, pm_status
    )
    if scheduler_error:
        summary_errors.append(scheduler_error)
        scheduler_report = {
            "train_now": False,
            "schedule_due": False,
            "next_run_at": "",
            "eligible_families": [],
            "blocked_families": [],
            "reason": "scheduler_unavailable",
            "no_action_contract": True,
            "training_started": False,
            "db_write_attempted": False,
            "active_ml_enabled": False,
        }
    model_status, model_status_error = _safe_collect_ml_summary_section(
        "ml_model_status", collect_ml_model_status, config
    )
    if model_status_error:
        summary_errors.append(model_status_error)
        model_status = {
            "promoted_model_count": 0,
            "loaded_model_count": 0,
            "model_load_errors": [],
            "scoring_enabled_families": [],
            "last_scoring_status": {},
            "no_action_contract": True,
        }

    readiness_global = readiness_report.get("global", {}) or {}
    readiness_families = readiness_report.get("families", {}) or {}
    metadata_support = _metadata_support_by_family(metadata_report)

    family_summary = {}
    blocker_counter = Counter()
    origin_family_counts = (readiness_global.get("label_quality", {}) or {}).get("family_origin_counts", {}) or {}
    for spec in list_ml_families():
        item = readiness_families.get(spec.family_id, {}) or {}
        trust_support = ((trust_report.get("family_support", {}) or {}).get(spec.family_id, {})) if trust_report else {}
        family_origins = origin_family_counts.get(spec.family_id, {}) or {}
        top_reasons = _family_top_reasons(spec.family_id, item, trust_report, metadata_report)
        for reason in top_reasons:
            blocker_counter[reason] += 1
        family_summary[spec.family_id] = {
            "status": item.get("status", "readiness_blocked"),
            "phase_gate": item.get("phase_gate", spec.phase_gate),
            "runtime_events": int(item.get("runtime_events", 0) or 0),
            "required_events": int(item.get("required_events", 0) or 0),
            "normal_labels": {
                "found": int(item.get("normal_labels", 0) or 0),
                "required": int(item.get("required_normal_labels", 0) or 0),
            },
            "suspicious_labels": {
                "found": int(item.get("suspicious_labels", 0) or 0),
                "required": int(item.get("required_suspicious_labels", 0) or 0),
            },
            "metadata_support": int(metadata_support.get(spec.family_id, 0)),
            "trust_support": {
                "normal": int(trust_support.get("normal", 0) or 0),
                "suspicious": int(trust_support.get("suspicious", 0) or 0),
            },
            "label_origins": {
                "organic_normal": int(family_origins.get("organic_normal", 0) or 0),
                "organic_suspicious": int(family_origins.get("organic_suspicious", 0) or 0),
                "bootstrap_normal": int(family_origins.get("bootstrap_normal", 0) or 0),
                "bootstrap_suspicious": int(family_origins.get("bootstrap_suspicious", 0) or 0),
                "legacy_excluded_normal": int(family_origins.get("legacy_excluded_normal", 0) or 0),
                "legacy_excluded_suspicious": int(family_origins.get("legacy_excluded_suspicious", 0) or 0),
            },
            "quota_normal": dict(item.get("quota_normal", {}) or {}),
            "quota_suspicious": dict(item.get("quota_suspicious", {}) or {}),
            "top_reasons": top_reasons,
        }

    if readiness_global.get("ml_paused"):
        blocker_counter["ml_paused"] += 1

    ready_for_active_ml = bool(
        readiness_global
        and not readiness_global.get("ml_paused", False)
        and family_summary
        and all(item["status"] == "active_candidate" for item in family_summary.values())
    )

    recommended_actions = []
    if readiness_global.get("ml_paused"):
        recommended_actions.append("ml_paused açık; incident/pause nedeni temizlenmeden active ML değerlendirilmemeli")
    recommended_actions.extend((trust_report.get("recommended_actions", []) or [])[:5])
    if normal_report.get("global", {}).get("blocking_incident"):
        recommended_actions.append("normal clean-window candidates high/critical incident nedeniyle bloklu")
    for family_id, item in family_summary.items():
        if item["runtime_events"] >= item["required_events"] and (
            item["normal_labels"]["found"] < item["normal_labels"]["required"]
            or item["suspicious_labels"]["found"] < item["suspicious_labels"]["required"]
        ):
            recommended_actions.append(
                f"{family_id} runtime event count güçlü ama family-specific label eşiği eksik"
            )
            break
    recommended_actions = list(dict.fromkeys(recommended_actions))

    return {
        "overall": {
            "ready_for_active_ml": ready_for_active_ml,
            "current_phase": readiness_global.get("current_phase", pm_status.get("current_phase", 0) if isinstance(pm_status, dict) else 0),
            "phase_name": readiness_global.get("phase_name", pm_status.get("phase_name", "") if isinstance(pm_status, dict) else ""),
            "ml_paused": bool(readiness_global.get("ml_paused", False)),
            "top_blockers": [reason for reason, _count in blocker_counter.most_common(5)],
            "query_notes": summary_errors,
        },
        "phase_event_volume": {
            "counter_scope": "normalized_runtime_events_lifetime_phase_counter",
            "phase_lifetime_event_count": int(((pm_status or {}).get("stats", {}) or {}).get("phase_event_count", ((pm_status or {}).get("stats", {}) or {}).get("total_events", 0)) or 0),
            "live_window_event_count": int((readiness_global.get("counts", {}) or {}).get("events_recent", 0) or 0),
            "duplicate_count": int(((pm_status or {}).get("stats", {}) or {}).get("duplicate_count", 0) or 0),
            "telemetry_duplicate_count": int(((pm_status or {}).get("stats", {}) or {}).get("telemetry_duplicate_count", 0) or 0),
            "parse_fail_count": int(((pm_status or {}).get("stats", {}) or {}).get("parse_fail_count", 0) or 0),
        },
        "label_readiness_summary": {
            "counter_scope": "family_specific_labeled_training_examples",
            "active_readiness_label_counts": (readiness_global.get("label_quality", {}) or {}).get("active_readiness_label_counts", {}),
            "active_readiness_label_counts_by_distro": (readiness_global.get("label_quality", {}) or {}).get("active_readiness_label_counts_by_distro", {}),
            "quota_summary": (readiness_global.get("label_quality", {}) or {}).get("quota_summary", {}),
        },
        "family_summary": family_summary,
        "mapping_summary": {
            "total_rules": mapping_report.get("total_rules", 0),
            "mapped_rules": mapping_report.get("mapped_rules", 0),
            "coverage_percent": mapping_report.get("coverage_percent", 0.0),
            "by_family": mapping_report.get("by_ml_family", {}),
        },
        "historical_scan_summary": _count_historical_statuses(historical_report),
        "historical_scan_distro_breakdown": {
            "candidate_count_by_distro": dict((historical_report.get("global", {}) or {}).get("candidate_count_by_distro", {}) or {}),
            "family_by_distro": dict((historical_report.get("global", {}) or {}).get("family_by_distro", {}) or {}),
            "source_by_distro": dict((historical_report.get("global", {}) or {}).get("source_by_distro", {}) or {}),
        },
        "normal_label_summary": _summarize_normal_label_report(normal_report),
        "label_trust_summary": {
            "usage_decisions": trust_report.get("usage_decisions", {}),
            "quality_summary": trust_report.get("quality_summary", {}),
            "direct_learnable_count": int((trust_report.get("usage_decisions", {}) or {}).get("direct_learnable", 0) or 0),
            "baseline_learning_count": int((trust_report.get("usage_decisions", {}) or {}).get("baseline_learning", 0) or 0),
            "ignored_count": int((trust_report.get("usage_decisions", {}) or {}).get("ignored", 0) or 0),
            "rejected_count": int((trust_report.get("usage_decisions", {}) or {}).get("rejected", 0) or 0),
        },
        "label_quota_summary": dict((readiness_global.get("label_quality", {}) or {}).get("quota_summary", {}) or {}),
        "readiness_label_counts": {
            "label_counts_by_origin": (readiness_global.get("label_quality", {}) or {}).get("label_counts_by_origin", {}),
            "label_counts_by_distro": (readiness_global.get("label_quality", {}) or {}).get("label_counts_by_distro", {}),
            "origin_counts_by_distro": (readiness_global.get("label_quality", {}) or {}).get("origin_counts_by_distro", {}),
            "family_counts_by_distro": (readiness_global.get("label_quality", {}) or {}).get("family_counts_by_distro", {}),
            "active_readiness_label_counts": (readiness_global.get("label_quality", {}) or {}).get("active_readiness_label_counts", {}),
            "active_readiness_label_counts_by_distro": (readiness_global.get("label_quality", {}) or {}).get("active_readiness_label_counts_by_distro", {}),
            "organic_live_label_counts": (readiness_global.get("label_quality", {}) or {}).get("organic_live_label_counts", {}),
            "bootstrap_historical_label_counts": (readiness_global.get("label_quality", {}) or {}).get("bootstrap_historical_label_counts", {}),
            "excluded_legacy_label_counts": (readiness_global.get("label_quality", {}) or {}).get("excluded_legacy_label_counts", {}),
            "quota_summary": (readiness_global.get("label_quality", {}) or {}).get("quota_summary", {}),
        },
        "metadata_plan_summary": {
            "learnable_candidate_count": metadata_report.get("learnable_candidate_count", 0),
            "blocked_count": metadata_report.get("blocked_count", 0),
            "missing_metadata_counts": metadata_report.get("missing_metadata_counts", {}),
        },
        "phase_gate_summary": dict((pm_status or {}).get("phase_gate", {}) or {}),
        "training_scheduler": {
            "training_mode": str(scheduler_report.get("training_mode", "manual") or "manual"),
            "trigger_request": str(scheduler_report.get("trigger_request", "scheduler") or "scheduler"),
            "train_now": bool(scheduler_report.get("train_now", False)),
            "manual_train_now_eligible": bool(scheduler_report.get("manual_train_now_eligible", False)),
            "manual_trigger_required": bool(scheduler_report.get("manual_trigger_required", False)),
            "schedule_due": bool(scheduler_report.get("schedule_due", False)),
            "scheduler_due": bool(scheduler_report.get("scheduler_due", False)),
            "next_run_at": str(scheduler_report.get("next_run_at", "") or ""),
            "reason": str(scheduler_report.get("reason", "") or ""),
            "last_scheduler_check_at": str(scheduler_report.get("last_scheduler_check_at", "") or ""),
            "eligible_families": list(scheduler_report.get("eligible_families", []) or []),
            "eligible_seed_families": list(scheduler_report.get("eligible_seed_families", []) or []),
            "execution_candidates": list(scheduler_report.get("execution_candidates", []) or []),
            "scheduled_candidates": list(scheduler_report.get("scheduled_candidates", []) or []),
            "threshold_candidates": list(scheduler_report.get("threshold_candidates", []) or []),
            "blocked_families": list(scheduler_report.get("blocked_families", []) or []),
            "labels_since_last_train": dict(scheduler_report.get("labels_since_last_train", {}) or {}),
            "last_training_time": str(scheduler_report.get("last_training_time", "") or ""),
            "last_training_at": str(scheduler_report.get("last_training_at", "") or ""),
            "last_training_status": str(scheduler_report.get("last_training_status", "") or ""),
            "last_training_reason": str(scheduler_report.get("last_training_reason", "") or ""),
            "last_training_family_distro": str(scheduler_report.get("last_training_family_distro", "") or ""),
            "last_training_label_counts": dict(scheduler_report.get("last_training_label_counts", {}) or {}),
            "last_evaluation_status": str(scheduler_report.get("last_evaluation_status", "") or ""),
            "first_model_training_completed": bool(scheduler_report.get("first_model_training_completed", False)),
            "first_model_training_completed_at": str(scheduler_report.get("first_model_training_completed_at", "") or ""),
            "first_model_training_status": str(scheduler_report.get("first_model_training_status", "") or ""),
            "first_model_evaluation_passed": bool(scheduler_report.get("first_model_evaluation_passed", False)),
            "first_model_evaluation_status": str(scheduler_report.get("first_model_evaluation_status", "") or ""),
            "first_ml_model_ready": bool(scheduler_report.get("first_ml_model_ready", False)),
            "ml_alert_family_ready": bool(scheduler_report.get("ml_alert_family_ready", False)),
            "ml_alert_family_enabled_families": list(scheduler_report.get("ml_alert_family_enabled_families", []) or []),
            "last_model_promoted": bool(scheduler_report.get("last_model_promoted", False)),
            "last_model_kept_reason": str(scheduler_report.get("last_model_kept_reason", "") or ""),
            "no_action_contract": bool(scheduler_report.get("no_action_contract", True)),
            "training_started": bool(scheduler_report.get("training_started", False)),
            "db_write_attempted": bool(scheduler_report.get("db_write_attempted", False)),
            "active_ml_enabled": bool(scheduler_report.get("active_ml_enabled", False)),
            "resource_limits": dict(scheduler_report.get("resource_limits", {}) or {}),
        },
        "model_status": dict(model_status or {}),
        "recommended_next_actions": recommended_actions,
    }


def print_ml_summary(report: dict) -> None:
    overall = report.get("overall", {}) or {}
    print(f"\n{'━'*58}")
    print("  ML Unified Summary")
    print(f"{'━'*58}")
    print(f"  ready_for_active_ml={overall.get('ready_for_active_ml', False)}")
    print(f"  current_phase={overall.get('current_phase', 0)} ({overall.get('phase_name', '')})")
    print(f"  ml_paused={overall.get('ml_paused', False)}")
    print(f"  top_blockers={overall.get('top_blockers', [])}")
    if overall.get("query_notes"):
        print(f"  query_notes={overall['query_notes']}")
    print(f"  Phase event volume: {report.get('phase_event_volume', {})}")
    print(f"  Label readiness summary: {report.get('label_readiness_summary', {})}")
    print("  Family summary:")
    for family_id in sorted(report.get("family_summary", {})):
        item = report["family_summary"][family_id]
        print(
            f"    {family_id}: status={item['status']} phase_gate={item['phase_gate']} "
            f"runtime_events={item['runtime_events']}/{item['required_events']} "
            f"normal_labels={item['normal_labels']['found']}/{item['normal_labels']['required']} "
            f"suspicious_labels={item['suspicious_labels']['found']}/{item['suspicious_labels']['required']} "
            f"quota_normal={item.get('quota_normal', {})} quota_suspicious={item.get('quota_suspicious', {})} "
            f"metadata_support={item['metadata_support']} trust_support={item['trust_support']} "
            f"label_origins={item.get('label_origins', {})} top_reasons={item['top_reasons']}"
        )
    mapping = report.get("mapping_summary", {}) or {}
    print("  Mapping coverage:")
    print(
        f"    total_rules={mapping.get('total_rules', 0)} mapped_rules={mapping.get('mapped_rules', 0)} "
        f"coverage_percent={mapping.get('coverage_percent', 0.0)} by_family={mapping.get('by_family', {})}"
    )
    print(f"  Historical scan summary: {report.get('historical_scan_summary', {})}")
    print(f"  Historical scan distro breakdown: {report.get('historical_scan_distro_breakdown', {})}")
    print(f"  Normal label summary: {report.get('normal_label_summary', {})}")
    print(f"  Label quota summary: {report.get('label_quota_summary', {})}")
    print(f"  Readiness label counts: {report.get('readiness_label_counts', {})}")
    print(f"  Label trust summary: {report.get('label_trust_summary', {})}")
    print(f"  Metadata plan summary: {report.get('metadata_plan_summary', {})}")
    print(f"  Phase gate summary: {report.get('phase_gate_summary', {})}")
    print(f"  Training scheduler: {report.get('training_scheduler', {})}")
    print(f"  Model status: {report.get('model_status', {})}")
    if report.get("recommended_next_actions"):
        print("  Recommended next actions:")
        for action in report["recommended_next_actions"]:
            print(f"    {action}")
    print(f"{'━'*58}\n")


def run_ml_summary(
    config: dict,
    *,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str]],
    collect_ml_summary: Callable[[dict, Any, dict], dict],
) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = collect_ml_summary(config, db, pm.get_status())
        if db_error:
            report["overall"].setdefault("query_notes", [])
            report["overall"]["query_notes"].append(f"db_fallback:{db_error}")
        print_ml_summary(report)
    finally:
        if db:
            db.close()
    return 0


def collect_ml_model_status(
    config: dict,
    *,
    scan_promoted_model_catalog: Callable[..., dict],
    safe_runtime_state_components: Callable[[dict], dict],
) -> dict:
    catalog = scan_promoted_model_catalog(config, load_artifacts=True)
    runtime_components = safe_runtime_state_components(config)
    runtime_status = dict(runtime_components.get("ml_promoted_models", {}) or {})
    return {
        "promoted_model_count": int(catalog.get("promoted_model_count", 0) or 0),
        "loaded_model_count": int(catalog.get("loaded_model_count", 0) or 0),
        "model_load_errors": list(catalog.get("model_load_errors", []) or []),
        "scoring_enabled_families": list(catalog.get("scoring_enabled_families", []) or []),
        "promoted_models": list(catalog.get("promoted_models", []) or []),
        "last_scoring_status": dict(runtime_status.get("last_scoring_status", {}) or {}),
        "last_refresh_at": str(runtime_status.get("last_refresh_at", "") or ""),
        "no_action_contract": True,
    }


def print_ml_model_status(report: dict) -> None:
    print(f"\n{'━'*58}")
    print("  ML Model Status")
    print(f"{'━'*58}")
    print(f"  promoted_model_count={report.get('promoted_model_count', 0)}")
    print(f"  loaded_model_count={report.get('loaded_model_count', 0)}")
    print(f"  model_load_errors={report.get('model_load_errors', [])}")
    print(f"  scoring_enabled_families={report.get('scoring_enabled_families', [])}")
    print(f"  last_scoring_status={report.get('last_scoring_status', {})}")
    print(f"  no_action_contract={report.get('no_action_contract', False)}")
    print(f"{'━'*58}\n")


def run_ml_model_status(
    config: dict,
    *,
    collect_ml_model_status: Callable[[dict], dict],
) -> int:
    print_ml_model_status(collect_ml_model_status(config))
    return 0
