from __future__ import annotations

from typing import Any, Callable


def print_ml_mapping_audit(report: dict) -> None:
    print("\n" + "━" * 58)
    print("  ML Mapping Audit")
    print("━" * 58)
    print(f"  total_rules={report['total_rules']}")
    print(f"  mapped_rules={report['mapped_rules']}")
    print(f"  unmapped_rules={report['unmapped_rules']}")
    print(f"  coverage={report['coverage_percent']:.2f}%")
    print(f"  explicit_override_count={report['explicit_override_count']}")
    print(f"  prefix_fallback_count={report['prefix_fallback_count']}")
    print("  by_family:")
    if report["by_ml_family"]:
        for family, count in report["by_ml_family"].items():
            print(f"    {family}={count}")
    else:
        print("    -")
    print("  by_label:")
    if report["by_ml_label"]:
        for label, count in report["by_ml_label"].items():
            print(f"    {label}={count}")
    else:
        print("    -")
    print("  by_source_trust:")
    if report["by_source_trust"]:
        for trust, count in report["by_source_trust"].items():
            print(f"    {trust}={count}")
    else:
        print("    -")
    print("  Unmapped:")
    if report["unmapped_rule_ids"]:
        for rule_id in report["unmapped_rule_ids"]:
            print(f"    {rule_id}")
    else:
        print("    -")
    print("━" * 58 + "\n")


def run_ml_mapping_audit(
    config: dict,
    *,
    load_rule_ids_for_ml_mapping_audit: Callable[[dict], tuple[list[str], str | None]],
    collect_ml_mapping_audit: Callable[[list[str]], dict],
    print_ml_mapping_audit: Callable[[dict], None],
    sys_module,
) -> int:
    rule_ids, error = load_rule_ids_for_ml_mapping_audit(config)
    if error:
        print(f"ML mapping audit başlatılamadı: {error}", file=sys_module.stderr)
        return 2
    report = collect_ml_mapping_audit(rule_ids)
    print_ml_mapping_audit(report)
    return 0


def run_ml_runtime_label_candidate_audit(
    config: dict,
    rule_id: str,
    *,
    build_runtime_ml_label_candidate_from_rule: Callable[..., dict],
    print_runtime_ml_label_candidate_audit: Callable[[dict], None],
    sys_module,
) -> int:
    _ = config
    normalized_rule_id = (rule_id or "").strip().upper()
    if not normalized_rule_id:
        print("--ml-runtime-label-candidate-audit için RULE_ID zorunlu.", file=sys_module.stderr)
        return 2
    candidate = build_runtime_ml_label_candidate_from_rule(
        normalized_rule_id,
        severity="high",
        risk_score=75.0,
        event={},
        alert_context={},
        message=f"audit_only_runtime_candidate:{normalized_rule_id}",
    )
    print_runtime_ml_label_candidate_audit(candidate)
    return 0


__all__ = [
    print_ml_mapping_audit,
    run_ml_mapping_audit,
    run_ml_runtime_label_candidate_audit,
]
