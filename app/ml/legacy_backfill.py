from __future__ import annotations

from typing import Any, Callable


LEGACY_BOOTSTRAP_REJECT_BACKFILL_FIELDS = {
    "event_class": "unknown_unlabeled",
    "behavior_label": "unknown_unlabeled",
    "source_trust": "legacy_incomplete",
    "model_usage_scope": "not_learnable",
    "learnable": False,
    "label_reason": "legacy_bootstrap_missing_metadata",
    "poisoning_guard_passed": False,
}


def legacy_bootstrap_metadata_missing(row: dict) -> bool:
    return any((
        not (row.get("event_class", "") or "").strip(),
        not (row.get("behavior_label", "") or "").strip(),
        not (row.get("source_trust", "") or "").strip(),
        not (row.get("model_usage_scope", "") or "").strip(),
        row.get("learnable") is None,
        not (row.get("label_reason", "") or "").strip(),
    ))


def legacy_bootstrap_backfill_evidence(row: dict) -> dict:
    existing = dict(row.get("evidence_fields", {}) or {}) if isinstance(row.get("evidence_fields"), dict) else {}
    existing.update({
        "legacy_category": str(row.get("category", "") or ""),
        "original_label": str(row.get("label", "") or ""),
        "repair_mode": "reject_backfill",
        "missing_provenance": True,
        "missing_distro": not bool((row.get("distro", "") or "").strip()),
        "training_eligible": False,
        "no_action_contract": True,
    })
    return existing


def legacy_bootstrap_backfill_payload(row: dict, *, legacy_bootstrap_reject_backfill_fields: dict) -> dict:
    payload = {"id": row.get("id")}
    payload.update(legacy_bootstrap_reject_backfill_fields)
    payload["evidence_fields"] = legacy_bootstrap_backfill_evidence(row)
    return payload


def apply_legacy_bootstrap_backfill_preview(row: dict, *, legacy_bootstrap_reject_backfill_fields: dict) -> dict:
    updated = dict(row)
    updated.update(legacy_bootstrap_reject_backfill_fields)
    updated["evidence_fields"] = legacy_bootstrap_backfill_evidence(row)
    return updated


def collect_legacy_bootstrap_backfill_candidates(
    label_rows: list[dict],
    *,
    classify_label_origin: Callable[[dict], str],
    classify_label_usage: Callable[[dict, dict], tuple[str, list[str]]],
    label_family_support: Callable[[dict], dict],
) -> dict:
    broad_matches = []
    candidates = []
    unsafe_learnable_ids = []
    unsafe_scope_ids = []

    for row in label_rows or []:
        source = (row.get("source", "") or "").strip().lower()
        if source != "bootstrap":
            continue
        if classify_label_origin(row) != "bootstrap_historical":
            continue
        if not legacy_bootstrap_metadata_missing(row):
            continue
        broad_matches.append(row)

        row_id = row.get("id")
        scope = (row.get("model_usage_scope", "") or "").strip().lower()
        if row.get("learnable") is True:
            unsafe_learnable_ids.append(row_id)
            continue
        if scope in {"direct_learnable", "baseline_learning"}:
            unsafe_scope_ids.append(row_id)
            continue

        usage, _reasons = classify_label_usage(row, label_family_support(row))
        if usage != "rejected":
            continue
        candidates.append(row)

    return {
        "broad_matches": broad_matches,
        "candidates": candidates,
        "unsafe_learnable_ids": [item for item in unsafe_learnable_ids if item is not None],
        "unsafe_scope_ids": [item for item in unsafe_scope_ids if item is not None],
    }


def print_ml_legacy_bootstrap_backfill_plan(report: dict) -> None:
    print("\n" + "━" * 58)
    print("  ML Legacy Bootstrap Metadata Backfill")
    print("━" * 58)
    print(f"  candidate_count={report.get('candidate_count', 0)}")
    print(f"  broad_match_count={report.get('broad_match_count', 0)}")
    print(f"  category_distribution={report.get('category_distribution', {})}")
    print(f"  label_distribution={report.get('label_distribution', {})}")
    print(f"  active_readiness_before={report.get('active_readiness_before', {})}")
    print(f"  expected_active_readiness_after={report.get('expected_active_readiness_after', {})}")
    print(f"  readiness_delta={report.get('readiness_delta', {})}")
    print(f"  sample_row_ids={report.get('sample_row_ids', [])}")
    print(f"  will_set={report.get('will_set', {})}")
    print(f"  safe_to_apply={report.get('safe_to_apply', False)}")
    if report.get("status"):
        print(f"  status={report['status']}")
    if "updated_count" in report:
        print(f"  updated_count={report.get('updated_count', 0)}")
    if "missing_metadata_before" in report:
        print(f"  missing_metadata_before={report.get('missing_metadata_before', 0)}")
    if "missing_metadata_after" in report:
        print(f"  missing_metadata_after={report.get('missing_metadata_after', 0)}")
    if "active_readiness_after" in report:
        print(f"  active_readiness_after={report.get('active_readiness_after', {})}")
    if "no_learnable_rows_created" in report:
        print(f"  no_learnable_rows_created={report.get('no_learnable_rows_created', False)}")
    if report.get("usage_after"):
        print(f"  usage_after={report['usage_after']}")
    if report.get("unsafe_learnable_ids"):
        print(f"  unsafe_learnable_ids={report['unsafe_learnable_ids']}")
    if report.get("unsafe_scope_ids"):
        print(f"  unsafe_scope_ids={report['unsafe_scope_ids']}")
    if report.get("safety_blockers"):
        print(f"  safety_blockers={report['safety_blockers']}")
    if report.get("abort_reason"):
        print(f"  abort_reason={report['abort_reason']}")
    if report.get("query_notes"):
        print(f"  query_notes={report['query_notes']}")
    print(f"  db_write_attempted={report.get('db_write_attempted', False)}")
    print("━" * 58 + "\n")


def execute_ml_legacy_bootstrap_backfill(
    config: dict,
    db,
    *,
    apply: bool = False,
    collect_ml_legacy_bootstrap_backfill_plan: Callable[[dict, Any, dict], dict],
    load_labels_read_only: Callable[[Any], tuple[list[dict], str]],
    summarize_label_quality: Callable[..., dict],
) -> dict:
    report = collect_ml_legacy_bootstrap_backfill_plan(config, db, {})
    if not apply:
        return report

    report["db_write_attempted"] = True
    candidate_count = int(report.get("candidate_count", 0) or 0)
    if candidate_count <= 0:
        report.update({
            "status": "no_op",
            "updated_count": 0,
            "missing_metadata_before": report.get("missing_metadata_candidate_count", 0),
            "missing_metadata_after": report.get("missing_metadata_candidate_count", 0),
            "active_readiness_after": report.get("active_readiness_before", {}),
            "no_learnable_rows_created": True,
        })
        return report

    if report.get("safety_blockers"):
        report.update({
            "status": "aborted",
            "updated_count": 0,
            "abort_reason": list(report.get("safety_blockers", [])),
        })
        return report

    if not hasattr(db, "backfill_legacy_bootstrap_label_metadata"):
        report.update({
            "status": "aborted",
            "updated_count": 0,
            "abort_reason": ["db_missing_backfill_method"],
        })
        return report

    updated_count = int(db.backfill_legacy_bootstrap_label_metadata(report.get("backfill_payloads", [])) or 0)
    label_rows, labels_error = load_labels_read_only(db)
    if labels_error:
        report.setdefault("query_notes", []).append(labels_error)
    after_plan = collect_ml_legacy_bootstrap_backfill_plan(config, db, {})
    after_summary = summarize_label_quality(label_rows, config=config)
    after_usage = dict(after_summary.get("usage_decisions", {}) or {})
    no_learnable_rows_created = not any(
        row.get("learnable") is True and (row.get("label_reason", "") or "").strip() == "legacy_bootstrap_missing_metadata"
        for row in label_rows
    )

    report.update({
        "status": "applied",
        "updated_count": updated_count,
        "missing_metadata_before": report.get("candidate_count", 0),
        "missing_metadata_after": after_plan.get("candidate_count", 0),
        "active_readiness_after": dict(after_summary.get("active_readiness_label_counts", {}) or {}),
        "readiness_delta": {
            "normal": int((after_summary.get("active_readiness_label_counts", {}) or {}).get("normal", 0) or 0)
            - int((report.get("active_readiness_before", {}) or {}).get("normal", 0) or 0),
            "suspicious": int((after_summary.get("active_readiness_label_counts", {}) or {}).get("suspicious", 0) or 0)
            - int((report.get("active_readiness_before", {}) or {}).get("suspicious", 0) or 0),
        },
        "usage_after": after_usage,
        "no_learnable_rows_created": no_learnable_rows_created,
    })
    if report["readiness_delta"]["normal"] != 0 or report["readiness_delta"]["suspicious"] != 0:
        report["status"] = "aborted"
        report.setdefault("abort_reason", []).append("active_readiness_delta_nonzero_post_verify")
    return report


def run_ml_legacy_bootstrap_backfill(
    config: dict,
    *,
    apply: bool = False,
    build_operator_phase_manager: Callable[[dict], tuple[Any, Any, str | None]],
    execute_ml_legacy_bootstrap_backfill: Callable[..., dict],
    print_ml_legacy_bootstrap_backfill_plan: Callable[[dict], None],
) -> int:
    pm, db, db_error = build_operator_phase_manager(config)
    try:
        report = execute_ml_legacy_bootstrap_backfill(config, db, apply=apply)
        if db_error:
            report.setdefault("query_notes", []).append(f"db_fallback:{db_error}")
        print_ml_legacy_bootstrap_backfill_plan(report)
    finally:
        if db:
            db.close()
    if apply and report.get("status") == "aborted":
        return 2
    return 0


__all__ = [
    LEGACY_BOOTSTRAP_REJECT_BACKFILL_FIELDS,
    legacy_bootstrap_metadata_missing,
    legacy_bootstrap_backfill_evidence,
    legacy_bootstrap_backfill_payload,
    apply_legacy_bootstrap_backfill_preview,
    collect_legacy_bootstrap_backfill_candidates,
    print_ml_legacy_bootstrap_backfill_plan,
    execute_ml_legacy_bootstrap_backfill,
    run_ml_legacy_bootstrap_backfill,
]
