from __future__ import annotations

import copy
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from core.ml.verified_manifest import ALLOWED_FAMILIES, redact_text, validate_verified_label_manifest
from core.ml.verified_manifest_cli import _resolve_safe_output_path

VALID_SCOPES = {"calibration_only", "baseline_learning", "not_learnable"}
VALID_SOURCE_QUALITY = {"direct_rule_high", "clean_source_high", "heuristic_candidate_medium", "heuristic_candidate_low"}
SECRET_HINTS = ("token=", "authorization: bearer ", "password=", "api_key=", "smtp_pass=", "telegram_bot_token=", "gemini_api_key=", "openai_api_key=")

SHORT_TARGETS = {
    "ML-AUTH": {"benign": 30, "suspicious": 20},
    "ML-PROC": {"benign": 60, "suspicious": 40},
    "ML-IMPACT": {"benign": 0, "suspicious": 20},
}


def audit_verified_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(manifest or {})
    input_snapshots = dict(payload.get("input_snapshots", {}) or {})
    validation = validate_verified_label_manifest(payload)
    blockers: List[str] = []
    warnings: List[str] = []
    recommendations: List[str] = []

    if not validation["valid"]:
        blockers.extend(validation["problems"])

    schema_valid = validation["valid"]
    no_action_contract = payload.get("no_action_contract") is True
    active_training_enabled = payload.get("active_training_enabled") is True
    redaction_status = str(payload.get("redaction_status", "") or "")
    if not no_action_contract:
        blockers.append("no_action_contract_false")
    if active_training_enabled:
        blockers.append("active_training_enabled_true")
    if redaction_status != "passed":
        blockers.append("redaction_failed")

    for key in ("family_summary", "rejection_summary", "dominance_summary", "duplicate_summary", "poisoning_guard_summary"):
        if key not in payload:
            blockers.append(f"missing_summary:{key}")

    counts = _count_candidates(payload)
    if counts["candidate_count"] != counts["direct_learnable_count"] + counts["rejected_candidate_count"] + counts["ignored_candidate_count"]:
        blockers.append("candidate_count_mismatch")

    candidate_results = _audit_candidates(payload.get("candidates", []) or [])
    blockers.extend(candidate_results["blockers"])
    warnings.extend(candidate_results["warnings"])

    family_results = _audit_family_thresholds(payload.get("candidates", []) or [])
    for family, result in family_results.items():
        if result["status"] == "fail":
            if counts["direct_learnable_count"] > 0:
                blockers.append(f"family_threshold_fail:{family}")
        elif result["status"] == "warning":
            warnings.append(f"family_threshold_warning:{family}")

    dominance_results = _audit_dominance(payload.get("dominance_summary", {}) or {}, payload.get("duplicate_summary", {}) or {}, payload.get("poisoning_guard_summary", {}) or {})
    blockers.extend(dominance_results["blockers"])
    warnings.extend(dominance_results["warnings"])

    recommendations.extend(_build_recommendations(payload, family_results, dominance_results))
    status = _decide_audit_status(payload, blockers, warnings, family_results)

    return {
        "status": status,
        "schema_valid": schema_valid,
        "no_action_contract": no_action_contract,
        "active_training_enabled": bool(payload.get("active_training_enabled", False)),
        "redaction_status": redaction_status or "missing",
        "candidate_count": counts["candidate_count"],
        "direct_learnable_count": counts["direct_learnable_count"],
        "rejected_candidate_count": counts["rejected_candidate_count"],
        "ignored_candidate_count": counts["ignored_candidate_count"],
        "family_results": family_results,
        "dominance_results": dominance_results["summary"],
        "poisoning_results": dict(payload.get("poisoning_guard_summary", {}) or {}),
        "duplicate_results": dict(payload.get("duplicate_summary", {}) or {}),
        "blockers": sorted(dict.fromkeys(blockers)),
        "warnings": sorted(dict.fromkeys(warnings)),
        "recommendations": recommendations,
        "db_write_attempted": bool(input_snapshots.get("db_write_attempted", False)),
        "active_ml_enabled": bool(input_snapshots.get("active_ml_enabled", False)),
        "train_triggered": bool(input_snapshots.get("train_triggered", False)),
        "evaluate_triggered": bool(input_snapshots.get("evaluate_triggered", False)),
        "alert_emit_triggered": bool(input_snapshots.get("alert_emit_triggered", False)),
        "direct_learning_only": bool(input_snapshots.get("direct_learning_only", False)),
    }


def summarize_manifest_quality(manifest: Dict[str, Any]) -> Dict[str, Any]:
    audit = audit_verified_manifest(manifest)
    return {
        "status": audit["status"],
        "candidate_count": audit["candidate_count"],
        "direct_learnable_count": audit["direct_learnable_count"],
        "rejected_candidate_count": audit["rejected_candidate_count"],
        "ignored_candidate_count": audit["ignored_candidate_count"],
        "family_results": audit["family_results"],
        "blockers": audit["blockers"],
        "warnings": audit["warnings"],
        "recommendations": audit["recommendations"],
        "no_action_contract": audit["no_action_contract"],
        "active_training_enabled": audit["active_training_enabled"],
        "db_write_attempted": audit["db_write_attempted"],
        "active_ml_enabled": audit["active_ml_enabled"],
        "train_triggered": audit["train_triggered"],
        "evaluate_triggered": audit["evaluate_triggered"],
        "alert_emit_triggered": audit["alert_emit_triggered"],
        "direct_learning_only": audit["direct_learning_only"],
    }

def load_manifest_file(path: str) -> Dict[str, Any]:
    target = Path(path)
    return json.loads(target.read_text(encoding="utf-8"))


def write_json_output(payload: Dict[str, Any], out_path: str) -> Path:
    resolved = _resolve_safe_output_path(out_path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return resolved


def print_manifest_audit_summary(audit: Dict[str, Any], *, printer=print) -> None:
    printer("")
    printer("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    printer("  Verified Manifest Audit")
    printer("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    printer(f"  status={audit.get('status', '')}")
    printer(f"  candidate_count={audit.get('candidate_count', 0)}")
    printer(f"  direct_learnable_count={audit.get('direct_learnable_count', 0)}")
    printer(f"  rejected_candidate_count={audit.get('rejected_candidate_count', 0)}")
    printer(f"  ignored_candidate_count={audit.get('ignored_candidate_count', 0)}")
    printer(f"  family_results={audit.get('family_results', {})}")
    printer(f"  blockers={audit.get('blockers', [])}")
    printer(f"  warnings={audit.get('warnings', [])}")
    printer(f"  recommendations={audit.get('recommendations', [])}")
    printer("  safety:")
    printer(f"    no_action_contract={audit.get('no_action_contract', False)}")
    printer(f"    active_training_enabled={audit.get('active_training_enabled', False)}")
    printer(f"    db_write_attempted={audit.get('db_write_attempted', False)}")
    printer(f"    active_ml_enabled={audit.get('active_ml_enabled', False)}")
    printer(f"    train_triggered={audit.get('train_triggered', False)}")
    printer(f"    evaluate_triggered={audit.get('evaluate_triggered', False)}")
    printer(f"    alert_emit_triggered={audit.get('alert_emit_triggered', False)}")
    printer(f"    direct_learning_only={audit.get('direct_learning_only', False)}")
    printer("  NO DB WRITE / NO ACTIVE ML / AUDIT ONLY")
    printer("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


def run_verified_manifest_audit_cli(
    manifest_path: str,
    printer=print,
) -> int:
    manifest = load_manifest_file(manifest_path)
    audit = audit_verified_manifest(manifest)
    print_manifest_audit_summary(audit, printer=printer)
    return 0


def _count_candidates(manifest: Dict[str, Any]) -> Dict[str, int]:
    return {
        "candidate_count": int(manifest.get("candidate_count", 0) or 0),
        "direct_learnable_count": int(manifest.get("direct_learnable_count", 0) or 0),
        "rejected_candidate_count": int(manifest.get("rejected_candidate_count", 0) or 0),
        "ignored_candidate_count": int(manifest.get("ignored_candidate_count", 0) or 0),
    }


def _audit_candidates(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    blockers: List[str] = []
    warnings: List[str] = []
    for idx, candidate in enumerate(candidates):
        required = (
            "source_event_id", "event_id", "ml_family", "ml_label", "event_class", "behavior_label",
            "source_quality", "model_usage_scope", "learnable", "label_lifecycle_status", "poisoning_guard_passed",
            "evidence_fields", "label_reason", "correlation_level", "correlation_score", "candidate_score",
            "no_action_contract", "active_training_enabled",
        )
        for field in required:
            if field not in candidate or candidate.get(field) in (None, "") and field not in {"rejection_reason"}:
                blockers.append(f"candidate[{idx}]:missing_required_metadata:{field}")
        evidence = candidate.get("evidence_fields")
        if not isinstance(evidence, dict) or not evidence:
            blockers.append(f"candidate[{idx}]:missing_evidence_fields")
        if candidate.get("poisoning_guard_passed") is False:
            warnings.append(f"candidate[{idx}]:poisoning_guard_false")
        if candidate.get("model_usage_scope") not in VALID_SCOPES:
            blockers.append(f"candidate[{idx}]:invalid_model_usage_scope")
        if candidate.get("source_quality") not in VALID_SOURCE_QUALITY:
            blockers.append(f"candidate[{idx}]:invalid_source_quality")
        if candidate.get("event_class") in {"attack", "suspicious"} and candidate.get("model_usage_scope") == "baseline_learning":
            blockers.append(f"candidate[{idx}]:invalid_attack_baseline_scope")
        for score_field in ("correlation_score", "candidate_score"):
            try:
                value = float(candidate.get(score_field, 0.0) or 0.0)
            except Exception:
                blockers.append(f"candidate[{idx}]:invalid_{score_field}")
                continue
            if not (0.0 <= value <= 1.0):
                blockers.append(f"candidate[{idx}]:invalid_{score_field}")
        raw_blob = json.dumps(evidence or {}, ensure_ascii=False).lower()
        if any(token in raw_blob for token in SECRET_HINTS):
            blockers.append(f"candidate[{idx}]:raw_secret_pattern")
    return {"blockers": blockers, "warnings": warnings}


def _audit_family_thresholds(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    for family in ALLOWED_FAMILIES:
        rows = [item for item in candidates if item.get("ml_family") == family]
        direct_learnable = [item for item in rows if item.get("disposition") == "direct_learnable"]
        benign = sum(1 for item in direct_learnable if item.get("event_class") == "benign")
        suspicious = sum(1 for item in direct_learnable if item.get("event_class") in {"suspicious", "attack"})
        target = SHORT_TARGETS[family]
        status = "pass"
        if benign < target["benign"] or suspicious < target["suspicious"]:
            status = "fail" if not direct_learnable else "warning"
        results[family] = {
            "direct_learnable_total": len(direct_learnable),
            "direct_learnable_benign": benign,
            "direct_learnable_suspicious": suspicious,
            "short_target_benign": target["benign"],
            "short_target_suspicious": target["suspicious"],
            "status": status,
        }
    return results


def _audit_dominance(dominance: Dict[str, Any], duplicate_summary: Dict[str, Any], poisoning: Dict[str, Any]) -> Dict[str, Any]:
    blockers: List[str] = []
    warnings: List[str] = []
    summary = copy.deepcopy(dominance)
    for family, item in dominance.items():
        totals = dict(item.get("direct_learnable_vs_ignored_vs_rejected", {}) or {})
        family_total = int(totals.get("direct_learnable", totals.get("accepted", 0)) or 0) + int(totals.get("ignored", 0) or 0) + int(totals.get("rejected", 0) or 0)
        src_share = float(dict(item.get("src_ip_top", {}) or {}).get("share", 0.0) or 0.0)
        proc_share = float(dict(item.get("process_top", {}) or {}).get("share", 0.0) or 0.0)
        if family == "ML-AUTH" and family_total >= 4:
            if src_share > 0.55:
                blockers.append("auth_single_src_ip_cap_exceeded")
            elif src_share > 0.40:
                warnings.append("auth_single_src_ip_warning")
        if family == "ML-PROC" and family_total >= 4:
            if proc_share > 0.50:
                blockers.append("proc_process_dominance_exceeded")
            elif proc_share > 0.35:
                warnings.append("proc_process_dominance_warning")
    dup_ratio = float(duplicate_summary.get("duplicate_fingerprint_ratio", 0.0) or 0.0)
    if dup_ratio > 0.35:
        blockers.append("duplicate_ratio_fail")
    elif dup_ratio > 0.20:
        warnings.append("duplicate_ratio_warning")
    malformed_ratio = float(poisoning.get("malformed_identity_ratio", 0.0) or 0.0)
    if malformed_ratio > 0.05:
        blockers.append("malformed_identity_fail")
    elif malformed_ratio > 0.02:
        warnings.append("malformed_identity_warning")
    bootstrap_count = int(poisoning.get("bootstrap_contamination_count", 0) or 0)
    if bootstrap_count > 0:
        blockers.append("bootstrap_contamination_detected")
    return {"summary": summary, "blockers": blockers, "warnings": warnings}


def _build_recommendations(manifest: Dict[str, Any], family_results: Dict[str, Any], dominance_results: Dict[str, Any]) -> List[str]:
    recommendations: List[str] = []
    if family_results.get("ML-AUTH", {}).get("status") != "pass":
        recommendations.append("ML-AUTH için direct_learnable benign/suspicious rule-backed candidate sayısı artırılmalı.")
    if family_results.get("ML-PROC", {}).get("status") != "pass":
        recommendations.append("ML-PROC için process-backed direct_learnable candidate kapsamı artırılmalı.")
    if family_results.get("ML-IMPACT", {}).get("status") != "pass":
        recommendations.append("ML-IMPACT için DE*/tamper correlated evidence-backed candidate seti güçlendirilmeli.")
    if dominance_results["blockers"] or dominance_results["warnings"]:
        recommendations.append("Dominance/duplicate oranları düşürülmeden direct_learnable label havuzu büyütülmemeli.")
    if int(manifest.get("direct_learnable_count", 0) or 0) == 0:
        recommendations.append("Manifest halen ignored/rejected ağırlıklı; rule mapping veya evidence kalitesi güçlendirilmeli.")
    return recommendations


def _decide_audit_status(manifest: Dict[str, Any], blockers: List[str], warnings: List[str], family_results: Dict[str, Any]) -> str:
    if blockers:
        return "blocked"
    if warnings:
        return "direct_learning_ready_with_warnings"
    if all(item.get("status") == "pass" for item in family_results.values()):
        return "direct_learning_ready"
    return str(manifest.get("readiness_decision", "blocked") or "blocked")
