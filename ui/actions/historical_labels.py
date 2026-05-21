from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.ml.label_engine import validate_ml_label_metadata

_ALLOWED_ROOTS = [
    Path("data/bootstrap_label_scan"),
    Path("data/ml_label_scan"),
    Path("data"),
]


def _facade():
    import ui.backend_facade as backend_facade

    return backend_facade


def _allowed_manifest_path(path_text: str) -> Tuple[Path | None, str | None]:
    requested = str(path_text or "").strip()
    if not requested:
        return None, "manifest_required"
    candidate = Path(requested)
    if ".." in candidate.parts:
        return None, "path_traversal_blocked"
    try:
        resolved = candidate.resolve()
    except Exception:
        return None, "invalid_manifest_path"
    project_root = Path.cwd().resolve()
    allowed_roots = [(project_root / root).resolve() for root in _ALLOWED_ROOTS]
    if not any(root == resolved or root in resolved.parents for root in allowed_roots):
        return None, "manifest_outside_workspace"
    if not resolved.exists() or not resolved.is_file():
        return None, "manifest_not_found"
    return resolved, None


def _manifest_kind(payload: Dict[str, Any]) -> str:
    kind = str(payload.get("kind", "") or "").strip()
    plan_type = str(payload.get("plan_type", "") or "").strip()
    if kind == "bootstrap_label_scan_candidate_manifest":
        return kind
    if plan_type == "ml_historical_label_scan":
        return plan_type
    return ""


def _discover_manifest(manifest_id: str | None) -> Tuple[Path | None, str | None]:
    token = str(manifest_id or "").strip()
    if token:
        return _allowed_manifest_path(token)
    project_root = Path.cwd().resolve()
    candidates: List[Path] = []
    for root in _ALLOWED_ROOTS:
        resolved_root = (project_root / root).resolve()
        if not resolved_root.exists():
            continue
        candidates.extend(resolved_root.rglob("*.json"))
    for path in sorted(candidates, key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if _manifest_kind(payload):
            return path.resolve(), None
    return None, "manifest_not_found"


def _load_manifest(path: Path) -> Tuple[Dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, str(exc)
    if not _manifest_kind(payload):
        return None, "invalid_manifest_schema"
    return dict(payload), None


def _extract_candidates(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    kind = _manifest_kind(manifest)
    if kind == "bootstrap_label_scan_candidate_manifest":
        return [dict(item) for item in list(manifest.get("candidates", []) or [])]
    candidates: List[Dict[str, Any]] = []
    for target in list(manifest.get("family_targets", []) or []):
        target_dict = dict(target or {})
        for item in list(target_dict.get("proposed_label_candidates", []) or []):
            payload = dict(item or {})
            payload.setdefault("family_label", target_dict.get("family_label", ""))
            payload.setdefault("family_id", target_dict.get("family_id", ""))
            candidates.append(payload)
    return candidates


def _candidate_metadata(candidate: Dict[str, Any], manifest_path: str) -> Dict[str, Any]:
    if "proposed_metadata" in candidate:
        metadata = dict(candidate.get("proposed_metadata", {}) or {})
    else:
        metadata = dict(candidate.get("metadata", {}) or candidate)
    source_type = str(metadata.get("source_type", "") or "").strip().lower()
    if source_type in {"", "historical_apply"}:
        metadata["source_type"] = "bootstrap_seed" if candidate.get("bootstrap_job_id") else "auto_labeled_rule_mapped"
    source = str(metadata.get("source", "") or "").strip().lower()
    if not source or source == "historical_apply":
        metadata["source"] = "bootstrap" if metadata.get("source_type") == "bootstrap_seed" else "auto_labeled"
    metadata.setdefault("label_family", metadata.get("ml_family", candidate.get("family_id", "")))
    metadata.setdefault("ml_family", candidate.get("family_id", metadata.get("ml_family", "")))
    metadata.setdefault("ml_label", candidate.get("family_label", metadata.get("ml_label", "")))
    metadata.setdefault("event_class", candidate.get("event_class", metadata.get("event_class", "suspicious")))
    metadata.setdefault("behavior_label", candidate.get("behavior_label", metadata.get("behavior_label", metadata.get("ml_label", ""))))
    metadata.setdefault("source_trust", candidate.get("source_trust", metadata.get("source_trust", "")))
    metadata.setdefault("model_usage_scope", candidate.get("model_usage_scope", metadata.get("model_usage_scope", "")))
    if "learnable" not in metadata and "learnable" in candidate:
        metadata["learnable"] = candidate.get("learnable")
    metadata.setdefault("no_action_contract", True)
    metadata.setdefault("poisoning_guard_passed", True)
    metadata.setdefault("label_reason", candidate.get("label_reason", metadata.get("label_reason", "")))
    metadata.setdefault("evidence_fields", candidate.get("evidence_fields", metadata.get("evidence_fields", {})) or {})
    metadata["manifest_id"] = manifest_path
    metadata["active_training_enabled"] = False
    return metadata


def _classify_preview_usage(metadata: Dict[str, Any]) -> Tuple[str, List[str]]:
    reasons: List[str] = []
    scope = str(metadata.get("model_usage_scope", "") or "").strip().lower()
    event_class = str(metadata.get("event_class", "") or "").strip().lower()
    behavior_label = str(metadata.get("behavior_label", "") or metadata.get("ml_label", "") or "").strip().lower()
    family = str(metadata.get("ml_family", "") or "").strip().upper()
    learnable = metadata.get("learnable")
    source = str(metadata.get("source", "") or "").strip().lower()

    if not family:
        reasons.append("missing_family_mapping")
    if not behavior_label:
        reasons.append("missing_behavior_label")
    if not scope:
        reasons.append("missing_model_usage_scope")
    if event_class == "unknown_unlabeled" or behavior_label == "unknown_unlabeled":
        reasons.append("unknown_unlabeled")
        return "rejected", reasons
    if scope == "not_learnable":
        reasons.append("not_learnable")
        return "ignored", reasons
    if source == "synthetic":
        reasons.append("synthetic_not_runtime_observed")
        return "ignored", reasons
    if reasons:
        return "rejected", reasons
    if learnable is False:
        reasons.append("learnable_false")
        return "ignored", reasons
    if event_class == "benign" and scope == "baseline_learning":
        return "baseline_learning", reasons
    if event_class in {"attack", "suspicious"} and scope in {"baseline_learning", "calibration_only"}:
        if scope == "baseline_learning":
            reasons.append("suspicious_baseline_scope_normalized")
        return "direct_learnable", reasons
    reasons.append("unsupported_event_class_or_scope")
    return "rejected", reasons


def _manifest_summary(manifest: Dict[str, Any], path: Path, metadata_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    families: Dict[str, int] = {}
    usage = Counter()
    for item in metadata_rows:
        family = str(item.get("ml_family", "") or "").upper()
        if family:
            families[family] = families.get(family, 0) + 1
        decision, _reasons = _classify_preview_usage(item)
        usage[decision] += 1
    return {
        "id": str(manifest.get("job_id", "") or manifest.get("bootstrap_job_id", "") or path.name),
        "path": str(path),
        "created_at": str(manifest.get("created_at", "") or ""),
        "candidate_count": len(metadata_rows),
        "families": families,
        "direct_learnable_count": int(usage.get("direct_learnable", 0)),
        "baseline_learning_count": int(usage.get("baseline_learning", 0)),
        "ignored_count": int(usage.get("ignored", 0)),
        "rejected_count": int(usage.get("rejected", 0)),
    }


def preview_historical_label_audit(
    config: Dict[str, Any],
    manifest_id: str | None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    backend_facade = _facade()
    path, path_error = _discover_manifest(manifest_id)
    if path_error or path is None:
        return {
            "status": "degraded",
            "preview_only": True,
            "read_only": True,
            "db_write_attempted": False,
            "no_action_contract": True,
            "manifest": None,
            "usage_summary": {
                "direct_learnable": 0,
                "baseline_learning": 0,
                "ignored": 0,
                "rejected": 0,
            },
            "candidate_rows": [],
            "warnings": ["No historical manifest artifact was found."],
            "message": "Historical labeling is preview/audit only and no manifest artifact was found.",
            "error": path_error,
        }

    manifest, load_error = _load_manifest(path)
    if manifest is None:
        return {
            "status": "degraded",
            "preview_only": True,
            "read_only": True,
            "db_write_attempted": False,
            "no_action_contract": True,
            "manifest": None,
            "usage_summary": {
                "direct_learnable": 0,
                "baseline_learning": 0,
                "ignored": 0,
                "rejected": 0,
            },
            "candidate_rows": [],
            "warnings": ["Manifest schema is invalid."],
            "message": "Historical labeling is preview/audit only and the manifest schema is invalid.",
            "error": load_error,
        }

    candidates = _extract_candidates(manifest)
    metadata_rows = [_candidate_metadata(item, str(path)) for item in candidates]
    ml_summary = backend_facade.collect_ml_summary(config_path=config_path)
    usage_summary = Counter()
    reason_summary = Counter()
    candidate_rows: List[Dict[str, Any]] = []
    invalid_metadata_count = 0

    for metadata in metadata_rows:
        validation = validate_ml_label_metadata(metadata)
        decision, reasons = _classify_preview_usage(metadata)
        if validation.get("valid") is not True:
            invalid_metadata_count += 1
            reasons = list(reasons) + list(validation.get("problems", []) or [])
            decision = "rejected"
        usage_summary[decision] += 1
        for reason in reasons:
            reason_summary[reason] += 1
        candidate_rows.append({
            "ml_family": metadata.get("ml_family", ""),
            "ml_label": metadata.get("ml_label", ""),
            "event_class": metadata.get("event_class", ""),
            "source": metadata.get("source", ""),
            "model_usage_scope": metadata.get("model_usage_scope", ""),
            "learnable": metadata.get("learnable"),
            "usage_decision": decision,
            "reasons": reasons,
            "no_action_contract": bool(metadata.get("no_action_contract", True)),
        })

    warnings = []
    if ml_summary.get("ml_paused"):
        warnings.append("ML paused state detected; historical labeling remains preview/audit only.")
    if ml_summary.get("top_blockers"):
        warnings.append(f"ML blockers present: {', '.join(ml_summary.get('top_blockers', []) or [])}")
    if invalid_metadata_count:
        warnings.append(f"{invalid_metadata_count} candidate(s) rejected due to invalid ML metadata.")
    if not candidate_rows:
        warnings.append("Manifest contains no direct historical label candidates; current flow remains preview-only.")

    return {
        "status": "ok",
        "preview_only": True,
        "read_only": True,
        "db_write_attempted": False,
        "no_action_contract": True,
        "manifest": _manifest_summary(manifest, path, metadata_rows),
        "usage_summary": {
            "direct_learnable": int(usage_summary.get("direct_learnable", 0)),
            "baseline_learning": int(usage_summary.get("baseline_learning", 0)),
            "ignored": int(usage_summary.get("ignored", 0)),
            "rejected": int(usage_summary.get("rejected", 0)),
        },
        "reason_summary": dict(sorted(reason_summary.items())),
        "candidate_rows": candidate_rows,
        "guards": {
            "active_ml_enabled": False,
            "train_will_run": False,
            "alert_emit_will_run": False,
            "risk_score_mutation": False,
            "firewall_mutation": False,
            "incident_mutation": False,
            "preview_only": True,
        },
        "warnings": warnings,
        "message": "Historical labeling is preview/audit only; no labels, user actions, or snapshots are written.",
        "manifest_path": str(path),
        "error": None,
    }
