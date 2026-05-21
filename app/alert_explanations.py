from __future__ import annotations

import json
import time

from core.language import explanation_text, normalize_language


def _alert_context_payload(alert: dict | None) -> dict:
    payload = dict(alert or {})
    context = payload.get("context_json", payload.get("context", {}))
    if isinstance(context, str):
        try:
            context = json.loads(context) if context else {}
        except (json.JSONDecodeError, ValueError):
            context = {}
    return dict(context or {})


def _format_multiline_kv(title: str, values: dict) -> list[str]:
    if not values:
        return [f"{title}: detay metadata yok"]
    return [f"{title}:"] + [f"  - {key}: {value}" for key, value in values.items()]


def _looks_like_ml_alert(alert: dict, context: dict) -> bool:
    rule_id = str((alert or {}).get("rule_id", "") or "").strip().upper()
    if rule_id.startswith("ML-"):
        return True
    if context.get("ml_family") or context.get("ml_label"):
        return True
    return str(context.get("source", "") or "").strip() == "ml_active_decision_layer"


def _build_ml_support_score_from_alert(alert: dict, context: dict) -> dict:
    ml_family = str(context.get("ml_family", "") or "").strip().upper()
    risk_score = float(alert.get("risk_score", 0.0) or 0.0)
    normalized_score = float(context.get("normalized_score", 0.0) or 0.0)
    if normalized_score <= 0.0 and risk_score > 0:
        normalized_score = round(min(1.0, risk_score / 100.0), 4)
    return {
        "family_id": ml_family,
        "score": float(context.get("model_score", risk_score) or 0.0),
        "normalized_score": normalized_score,
        "confidence": float(context.get("confidence", 0.0) or 0.0),
        "top_features": list(context.get("top_features", []) or []),
        "time_context": dict(context.get("time_context", {}) or {}),
        "baseline_deviation": dict(context.get("baseline_deviation", {}) or {}),
        "scored": bool(context.get("model_score") is not None or risk_score > 0),
    }


def _compact_event_fields(event: dict | None, keys: list[str]) -> dict:
    payload = dict(event or {})
    result = {}
    for key in keys:
        value = payload.get(key)
        if value not in (None, "", [], {}):
            result[key] = value
    return result


def _human_rule_trigger_reason(rule_id: str, message: str, matched_event_fields: dict, language: str = "tr") -> str:
    lang = normalize_language(language, default="tr")
    lowered = f"{rule_id} {message}".lower()
    if "sudo" in lowered:
        user = matched_event_fields.get("user") or matched_event_fields.get("username") or ("bu kullanıcı" if lang == "tr" else "this user")
        return explanation_text("rule_trigger_sudo", lang, user=user)
    if "dns" in lowered:
        return explanation_text("rule_trigger_dns", lang)
    if "web" in lowered:
        return explanation_text("rule_trigger_web", lang)
    if "auth" in lowered or "ssh" in lowered:
        return explanation_text("rule_trigger_auth", lang)
    process_name = matched_event_fields.get("process") or matched_event_fields.get("action")
    if process_name:
        return explanation_text("rule_trigger_process", lang, process=process_name)
    return explanation_text("rule_trigger_default", lang)


def _recommended_rule_review_steps(rule_id: str, severity: str, language: str = "tr") -> list[str]:
    lang = normalize_language(language, default="tr")
    steps = [
        explanation_text("review_step_context", lang),
        explanation_text("review_step_pattern", lang),
    ]
    if str(severity or "").strip().lower() in {"high", "critical"}:
        steps.append(explanation_text("review_step_isolation", lang))
    if str(rule_id or "").startswith("WEB-"):
        steps.append(explanation_text("review_step_web", lang))
    return steps


def build_alert_explanation_metadata(*,
                                     rule_id: str,
                                     rule_name: str = "",
                                     severity: str = "",
                                     risk_score: float = 0.0,
                                     event: dict | None = None,
                                     message: str = "",
                                     key_evidence: list[str] | None = None,
                                     language: str = "tr") -> dict:
    lang = normalize_language(language, default="tr")
    event_payload = dict(event or {})
    matched_event_fields = _compact_event_fields(
        event_payload,
        ["source", "category", "action", "outcome", "host", "user", "username", "src_ip", "dst_ip", "process"],
    )
    evidence = list(key_evidence or []) or [
        f"rule_id={str(rule_id or '').strip().upper()}",
        f"severity={str(severity or '').strip().lower() or 'low'}",
    ]
    return {
        "rule_id": (rule_id or "").strip().upper(),
        "rule_name": (rule_name or message or "").strip(),
        "severity": (severity or "").strip().lower() or "low",
        "risk_score": float(risk_score or 0.0),
        "matched_event_fields": matched_event_fields,
        "key_evidence": evidence,
        "why_triggered_human": _human_rule_trigger_reason(rule_id, message or rule_name, matched_event_fields, language=lang),
        "recommended_review_steps": _recommended_rule_review_steps(rule_id, severity, language=lang),
        "action_taken": False,
        "db_write_attempted": False,
        "runtime_output_changed": False,
        "risk_score_changed": False,
        "language": lang,
    }


def _human_ml_trigger_reason(support_score: dict, language: str = "tr") -> str:
    lang = normalize_language(language, default="tr")
    family = str((support_score or {}).get("family_id", "") or "").strip().upper()
    features = " ".join(str(item) for item in ((support_score or {}).get("top_features", []) or []))
    baseline = (support_score or {}).get("baseline_deviation", {}) or {}
    time_ctx = (support_score or {}).get("time_context", {}) or {}
    if family == "ML-SUDO":
        return explanation_text("ml_trigger_sudo", lang)
    if family == "ML-PROC":
        return explanation_text("ml_trigger_proc", lang)
    if family == "ML-NET":
        return explanation_text("ml_trigger_net", lang)
    if baseline.get("available") and float(baseline.get("score_component", 0.0) or 0.0) > 0:
        return explanation_text("ml_trigger_baseline", lang)
    if time_ctx.get("is_night"):
        return explanation_text("ml_trigger_time", lang)
    if features:
        return explanation_text("ml_trigger_features", lang)
    return explanation_text("ml_trigger_default", lang)


def _recommended_ml_review_steps(ml_family: str, language: str = "tr") -> list[str]:
    lang = normalize_language(language, default="tr")
    steps = [
        explanation_text("ml_review_fields", lang),
        explanation_text("ml_review_compare", lang),
    ]
    if (ml_family or "").strip().upper() == "ML-PROC":
        steps.append(explanation_text("ml_review_proc", lang))
    elif (ml_family or "").strip().upper() == "ML-NET":
        steps.append(explanation_text("ml_review_net", lang))
    return steps


def build_ml_alert_explanation_metadata(*,
                                        support_score: dict,
                                        readiness_result: dict,
                                        supporting_event_fields: dict | None = None,
                                        support_or_active: str | None = None,
                                        can_emit_alert: bool | None = None,
                                        language: str = "tr") -> dict:
    lang = normalize_language(language, default="tr")
    score_payload = dict(support_score or {})
    readiness = dict(readiness_result or {})
    supporting = dict(supporting_event_fields or {})
    if support_or_active is None:
        if can_emit_alert is True:
            support_or_active = "active"
        else:
            support_or_active = "support" if score_payload.get("scored") or readiness.get("can_score_support") else "inactive"
    metadata = {
        "ml_family": (score_payload.get("family_id", "") or "").strip().upper(),
        "ml_label": (supporting.get("ml_label", "") or supporting.get("behavior_label", "") or "").strip(),
        "ml_family_status": readiness.get("status", "readiness_blocked"),
        "readiness_reason": readiness.get("reason", "readiness_not_met"),
        "support_or_active": support_or_active,
        "model_score": float(score_payload.get("score", 0.0) or 0.0),
        "normalized_score": float(score_payload.get("normalized_score", 0.0) or 0.0),
        "confidence": float(score_payload.get("confidence", 0.0) or 0.0),
        "top_features": list(score_payload.get("top_features", []) or []),
        "time_context": dict(score_payload.get("time_context", {}) or {}),
        "baseline_deviation": dict(score_payload.get("baseline_deviation", {}) or {}),
        "supporting_event_fields": dict(supporting),
        "why_triggered_human": _human_ml_trigger_reason(score_payload, language=lang),
        "recommended_review_steps": _recommended_ml_review_steps(score_payload.get("family_id", ""), language=lang),
        "no_action_contract": True,
        "can_emit_alert": bool(can_emit_alert) if can_emit_alert is not None else False,
        "action_taken": False,
        "db_write_attempted": False,
        "runtime_output_changed": False,
        "risk_score_changed": False,
        "language": lang,
    }
    if not metadata["ml_label"]:
        metadata["ml_label"] = str(supporting.get("action", "") or supporting.get("category", "") or "shadow_candidate").strip()
    return metadata


def build_deterministic_alert_report_payload(alert: dict, language: str = "tr") -> dict:
    lang = normalize_language(language, default="tr")
    payload = dict(alert or {})
    context = _alert_context_payload(payload)
    alert_id = payload.get("id", payload.get("alert_id", ""))
    entity = str(payload.get("entity", "") or "").strip() or explanation_text("unspecified", lang)
    rule_id = str(payload.get("rule_id", "") or "").strip().upper()
    severity = str(payload.get("severity", "") or "").strip().lower() or "low"
    risk_score = float(payload.get("risk_score", 0.0) or 0.0)
    message = str(payload.get("message", "") or "").strip() or explanation_text("message_missing", lang)
    metadata_missing = False

    if _looks_like_ml_alert(payload, context):
        supporting_fields = dict(context.get("supporting_event_fields", {}) or {})
        if not supporting_fields:
            supporting_fields = _compact_event_fields(
                context,
                ["src_ip", "user", "process", "action", "outcome", "source", "host", "category", "dst_ip", "dst_port"],
            )
        if not supporting_fields:
            metadata_missing = True
        ml_meta = build_ml_alert_explanation_metadata(
            support_score=_build_ml_support_score_from_alert(payload, context),
            readiness_result={
                "status": context.get("ml_family_status", "unknown"),
                "reason": context.get("readiness_reason", "metadata_missing"),
                "can_score_support": True,
            },
            supporting_event_fields={**supporting_fields, "ml_label": context.get("ml_label", "")},
            support_or_active=str(context.get("support_or_active", "active" if context.get("can_emit_alert") else "support")),
            can_emit_alert=bool(context.get("can_emit_alert", False)),
            language=lang,
        )
        if not ml_meta.get("top_features") and not ml_meta.get("time_context") and not ml_meta.get("baseline_deviation", {}).get("available"):
            metadata_missing = True
        return {
            "kind": "ml",
            "alert_id": alert_id,
            "rule_id": rule_id or explanation_text("ml_alert", lang),
            "severity": severity,
            "risk_score": risk_score,
            "entity": entity,
            "message": message,
            "why_triggered": ml_meta.get("why_triggered_human", "") or explanation_text("why_seen_abnormal_fallback", lang),
            "evidence_fields": dict(ml_meta.get("supporting_event_fields", {}) or {}),
            "review_steps": list(ml_meta.get("recommended_review_steps", []) or []),
            "metadata_missing": metadata_missing,
            "ml_metadata": ml_meta,
            "db_write_attempted": False,
            "runtime_output_changed": False,
            "risk_score_changed": False,
            "language": lang,
        }

    event_fields = dict(context.get("supporting_event_fields", {}) or {})
    if not event_fields:
        event_fields = _compact_event_fields(
            context,
            ["src_ip", "user", "process", "action", "outcome", "source", "host", "category", "dst_ip", "dst_port"],
        )
    if not event_fields:
        metadata_missing = True
    rule_meta = build_alert_explanation_metadata(
        rule_id=rule_id,
        rule_name=str(payload.get("rule_name", "") or ""),
        severity=severity,
        risk_score=risk_score,
        event=event_fields,
        message=message,
        language=lang,
    )
    return {
        "kind": "rule",
        "alert_id": alert_id,
        "rule_id": rule_meta.get("rule_id", "") or rule_id,
        "severity": rule_meta.get("severity", "") or severity,
        "risk_score": float(rule_meta.get("risk_score", 0.0) or 0.0),
        "entity": entity,
        "message": message,
        "why_triggered": rule_meta.get("why_triggered_human", "") or explanation_text("why_triggered_fallback", lang),
        "evidence_fields": dict(rule_meta.get("matched_event_fields", {}) or {}),
        "key_evidence": list(rule_meta.get("key_evidence", []) or []),
        "review_steps": list(rule_meta.get("recommended_review_steps", []) or []),
        "metadata_missing": metadata_missing,
        "rule_metadata": rule_meta,
        "db_write_attempted": False,
        "runtime_output_changed": False,
        "risk_score_changed": False,
        "language": lang,
    }


def build_deterministic_alert_explanation(alert: dict, language: str = "tr") -> dict:
    lang = normalize_language(language, default="tr")
    payload = build_deterministic_alert_report_payload(alert, language=lang)
    if payload["kind"] == "ml":
        ml_meta = dict(payload.get("ml_metadata", {}) or {})
        lines = [
            explanation_text("deterministic_explanation_title", lang),
            f"{explanation_text('alert_id', lang)}: {payload.get('alert_id', '')}",
            f"{explanation_text('rule_id', lang)}: {payload.get('rule_id', '') or explanation_text('ml_alert', lang)}",
            f"{explanation_text('severity', lang)}: {payload.get('severity', '')}",
            f"{explanation_text('risk_score', lang)}: {payload.get('risk_score', 0.0):.2f}",
            f"{explanation_text('entity', lang)}: {payload.get('entity', '')}",
            f"{explanation_text('message', lang)}: {payload.get('message', '')}",
            f"{explanation_text('ml_family', lang)}: {ml_meta.get('ml_family', '') or explanation_text('unknown', lang)}",
            f"{explanation_text('ml_label', lang)}: {ml_meta.get('ml_label', '') or explanation_text('unknown', lang)}",
            f"{explanation_text('ml_score_confidence', lang)}: {ml_meta.get('model_score', 0.0):.2f} / {ml_meta.get('confidence', 0.0):.2f}",
            f"{explanation_text('why_seen_abnormal', lang)}: {payload.get('why_triggered', '') or explanation_text('why_seen_abnormal_fallback', lang)}",
        ]
        lines.extend(_format_multiline_kv(explanation_text("top_features", lang), {str(i + 1): item for i, item in enumerate(ml_meta.get("top_features", []) or [])}))
        lines.extend(_format_multiline_kv(explanation_text("time_context", lang), dict(ml_meta.get("time_context", {}) or {})))
        lines.extend(_format_multiline_kv(explanation_text("baseline_deviation", lang), dict(ml_meta.get("baseline_deviation", {}) or {})))
        lines.extend(_format_multiline_kv(explanation_text("important_event_fields", lang), dict(payload.get("evidence_fields", {}) or {})))
        lines.append(explanation_text("review_checks", lang))
        for step in list(payload.get("review_steps", []) or []):
            lines.append(f"  - {step}")
        lines.append(f"no_action_contract: {ml_meta.get('no_action_contract', False)}")
        lines.append(f"action_taken: {ml_meta.get('action_taken', False)}")
        if payload.get("metadata_missing"):
            lines.append(explanation_text("metadata_missing_ml", lang))
        return {
            "kind": "ml",
            "text": "\n".join(lines),
            "why_triggered": payload.get("why_triggered", "") or explanation_text("why_seen_abnormal_fallback", lang),
            "review_steps": list(payload.get("review_steps", []) or []),
            "metadata_missing": bool(payload.get("metadata_missing", False)),
            "db_write_attempted": False,
            "runtime_output_changed": False,
            "risk_score_changed": False,
            "language": lang,
        }

    lines = [
        explanation_text("deterministic_explanation_title", lang),
        f"{explanation_text('alert_id', lang)}: {payload.get('alert_id', '')}",
        f"{explanation_text('rule_id', lang)}: {payload.get('rule_id', '')}",
        f"{explanation_text('severity', lang)}: {payload.get('severity', '')}",
        f"{explanation_text('risk_score', lang)}: {payload.get('risk_score', 0.0):.2f}",
        f"{explanation_text('entity', lang)}: {payload.get('entity', '')}",
        f"{explanation_text('message', lang)}: {payload.get('message', '')}",
        f"{explanation_text('why_triggered', lang)}: {payload.get('why_triggered', '') or explanation_text('why_triggered_fallback', lang)}",
    ]
    lines.extend(_format_multiline_kv(explanation_text("important_event_fields", lang), dict(payload.get("evidence_fields", {}) or {})))
    lines.extend(_format_multiline_kv(explanation_text("key_evidence", lang), {str(i + 1): item for i, item in enumerate(payload.get("key_evidence", []) or [])}))
    lines.append(explanation_text("review_checks", lang))
    for step in list(payload.get("review_steps", []) or []):
        lines.append(f"  - {step}")
    if payload.get("metadata_missing"):
        lines.append(explanation_text("metadata_missing_rule", lang))
    return {
        "kind": "rule",
        "text": "\n".join(lines),
        "why_triggered": payload.get("why_triggered", "") or explanation_text("why_triggered_fallback", lang),
        "review_steps": list(payload.get("review_steps", []) or []),
        "metadata_missing": bool(payload.get("metadata_missing", False)),
        "db_write_attempted": False,
        "runtime_output_changed": False,
        "risk_score_changed": False,
        "language": lang,
    }


def print_alert_explanation_contract_audit(report: dict) -> None:
    rule_meta = (report or {}).get("rule_alert_metadata", {}) or {}
    ml_meta = (report or {}).get("ml_alert_metadata", {}) or {}
    print(f"\n{'━'*58}")
    print("  Alert Explanation Contract Audit")
    print(f"{'━'*58}")
    print(f"  rule_alert_metadata.rule_id={rule_meta.get('rule_id', '')}")
    print(f"  rule_alert_metadata.why_triggered_human={rule_meta.get('why_triggered_human', '')}")
    print(f"  rule_alert_metadata.recommended_review_steps={rule_meta.get('recommended_review_steps', [])}")
    print(f"  ml_alert_metadata.ml_family={ml_meta.get('ml_family', '')}")
    print(f"  ml_alert_metadata.ml_label={ml_meta.get('ml_label', '')}")
    print(f"  ml_alert_metadata.why_triggered_human={ml_meta.get('why_triggered_human', '')}")
    print(f"  ml_alert_metadata.no_action_contract={ml_meta.get('no_action_contract', False)}")
    print(f"  ml_alert_metadata.action_taken={ml_meta.get('action_taken', False)}")
    print(f"  ml_alert_metadata.can_emit_alert={ml_meta.get('can_emit_alert', False)}")
    print(f"  helper_db_write_attempted={report.get('db_write_attempted', False)}")
    print(f"  detection_behavior_changed={report.get('detection_behavior_changed', False)}")
    print(f"  risk_behavior_changed={report.get('risk_behavior_changed', False)}")
    print(f"{'━'*58}\n")


def run_alert_explanation_contract_audit(
    config: dict,
    *,
    compute_ml_family_support_score,
    ml_family_readiness: dict,
) -> int:
    _ = config
    sample_event = {
        "source": "auditd",
        "category": "process",
        "action": "exec",
        "host": "host-1",
        "username": "root",
        "src_ip": "127.0.0.1",
        "process": "/usr/bin/sudo",
    }
    rule_meta = build_alert_explanation_metadata(
        rule_id="AUTH-004",
        rule_name="sudo root escalation or abuse",
        severity="high",
        risk_score=75.0,
        event=sample_event,
        message="sudo escalation behaviour matched",
        key_evidence=["rule_id=AUTH-004", "process=/usr/bin/sudo", "action=exec"],
    )
    readiness = {
        "family_id": "ML-PROC",
        "status": "needs_more_data",
        "reason": "insufficient_time_coverage",
        "can_score_support": True,
    }
    support_score = compute_ml_family_support_score(
        family_id="ML-PROC",
        event={**sample_event, "ts": time.time()},
        readiness_result={
            **readiness,
            "phase_gate_ok": True,
            "event_threshold_ok": True,
            "normal_label_threshold_ok": True,
            "suspicious_label_threshold_ok": True,
            "field_quality_ok": True,
            "time_coverage_ok": False,
            "trust_support_ok": True,
            "metadata_support_ok": True,
        },
        family_config=ml_family_readiness["ML-PROC"],
        baseline_summary={"expected_sources": ["auditd"], "expected_actions": ["exec"], "expected_categories": ["process"]},
    )
    ml_meta = build_ml_alert_explanation_metadata(
        support_score=support_score,
        readiness_result=readiness,
        supporting_event_fields={**sample_event, "ml_label": "suspicious_process"},
    )
    report = {
        "rule_alert_metadata": rule_meta,
        "ml_alert_metadata": ml_meta,
        "db_write_attempted": False,
        "detection_behavior_changed": False,
        "risk_behavior_changed": False,
    }
    print_alert_explanation_contract_audit(report)
    return 0


__all__ = [
    "_alert_context_payload",
    "_format_multiline_kv",
    "_looks_like_ml_alert",
    "_build_ml_support_score_from_alert",
    "_compact_event_fields",
    "_human_rule_trigger_reason",
    "_recommended_rule_review_steps",
    "_human_ml_trigger_reason",
    "_recommended_ml_review_steps",
    "build_alert_explanation_metadata",
    "build_ml_alert_explanation_metadata",
    "build_deterministic_alert_report_payload",
    "build_deterministic_alert_explanation",
    "print_alert_explanation_contract_audit",
    "run_alert_explanation_contract_audit",
]
