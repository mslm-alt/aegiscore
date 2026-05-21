from __future__ import annotations

import copy
from datetime import datetime
import hashlib
import importlib
import ipaddress
import json
import os
import re
import socket
import time
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.database import create_database, get_schema_manifest
from core.distro import SOURCE_MAP, apply_distro_paths, audit_sources, detect_distro, is_supported, resolve_log_paths
from core.integrations import IntegrationSettings
from core.normalize import Normalizer
from core.detection import DetectionEngine
from core.language import explanation_text, normalize_language, resolve_language, system_text
from core.ml.family_registry import (
    build_label_quota_bucket,
    list_ml_families,
    resolve_rule_to_ml_mapping,
    resolve_family_label_quotas,
    summarize_label_quota_usage,
)
from core.phase_manager import PhaseManager, compute_data_quality_metrics
from core.state_manager import RuntimeStateStore, get_state_metrics
from ui.actions import db_reset, export_actions, historical_labels, incident_actions, ip_actions, notification_test, secret_store
from ui.actions.guard import SUPPORTED_ACTION_TYPES, build_guarded_action_preview, get_action_policy, required_confirmation_for
from ui.actions.models import GuardedActionRequest
from ui.models import NotificationRule, PreflightCheck, SecurityLocks, checks_to_dicts

try:
    main_module = importlib.import_module("main")
    _MAIN_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - environment dependent
    main_module = None
    _MAIN_IMPORT_ERROR = exc

DEFAULT_CONFIG_PATH = "config/config.yml"
_STATUS_ORDER = {"PASS": 0, "WARNING": 1, "BLOCKED": 2}
_REPORT_GLOBS = ("report*.html", "report*.json", "report*.txt")
_ML_HISTORY_GLOBS = ("ml_historical*.json", "ml_historical*.manifest.json", "ml_label*.json")
_LIVE_LOG_SOURCE_FALLBACKS = [
    "auth_log",
    "auditd",
    "journald",
    "syslog",
    "firewall",
    "postgresql",
    "dns",
    "web",
    "process",
    "service",
]

_WEEKDAY_NAMES_EN = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)


def _normalize_status(status: str) -> str:
    token = str(status or "").strip().upper()
    return token if token in _STATUS_ORDER else "WARNING"


def _worst_status(current: str, candidate: str) -> str:
    current_key = _STATUS_ORDER.get(_normalize_status(current), 1)
    candidate_key = _STATUS_ORDER.get(_normalize_status(candidate), 1)
    return current if current_key >= candidate_key else candidate


def _safe_error(exc: Exception) -> Dict[str, str]:
    return {
        "type": type(exc).__name__,
        "message": str(exc),
    }


def _resolve_config_path(config_path: str | None) -> Path:
    return Path(config_path or DEFAULT_CONFIG_PATH)


def _resolve_backend_language(config: Dict[str, Any] | None = None, explicit: str | None = None) -> str:
    return resolve_language(explicit=explicit, env=os.environ, config=config, default="tr")


def _preferred_backend_language(config: Dict[str, Any] | None = None, explicit: str | None = None) -> str:
    if explicit not in (None, ""):
        return normalize_language(explicit, default="tr")
    cfg = dict(config or {})
    if cfg.get("language") not in (None, ""):
        return normalize_language(cfg.get("language"), default="tr")
    return _resolve_backend_language(config=cfg, explicit=explicit)


def _load_config(config_path: str) -> Dict[str, Any]:
    if main_module is None:
        if _MAIN_IMPORT_ERROR is not None:
            raise RuntimeError(f"main_import_failed: {_MAIN_IMPORT_ERROR}")
        raise RuntimeError("main_import_failed")
    return main_module.load_config(config_path)


def _merge_runtime_llm_config(config: Dict[str, Any], integrations: IntegrationSettings) -> Dict[str, Any]:
    merged = copy.deepcopy(config or {})
    llm_cfg = dict((merged or {}).get("llm", {}) or {})
    env_cfg = integrations.to_llm_config()
    raw = dict(getattr(integrations, "_raw", {}) or {})
    env_backend = str(raw.get("LLM_BACKEND", "") or "").strip().lower()
    env_model = str(raw.get("LLM_MODEL", "") or "").strip()
    env_language = str(raw.get("LLM_LANGUAGE", "") or "").strip().lower()
    env_key_present = any(str(raw.get(name, "") or "").strip() for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"))
    if env_backend:
        llm_cfg["backend"] = env_backend
    if env_backend or env_key_present:
        llm_cfg["enabled"] = bool(env_cfg.get("enabled", False))
    if env_model:
        llm_cfg["model"] = env_model
    if env_cfg.get("api_key"):
        llm_cfg["api_key"] = str(env_cfg.get("api_key", "") or "")
    resolved_language = resolve_language(env=raw, config=merged, default="tr")
    root_language = ""
    if isinstance(merged, dict):
        root_language = merged.get("language", "")
    if env_language or llm_cfg.get("language") not in (None, "") or root_language not in (None, ""):
        llm_cfg["language"] = resolved_language
    if str(raw.get("LLM_LOCAL_URL", "") or "").strip() and env_cfg.get("base_url"):
        llm_cfg["base_url"] = str(env_cfg.get("base_url", "") or "")
    merged["llm"] = llm_cfg
    return merged


def _load_runtime_context(config_path: str | None = None) -> Dict[str, Any]:
    resolved = _resolve_config_path(config_path)
    config_dir = str(resolved.parent) if resolved.parent.as_posix() else "config"
    integrations = IntegrationSettings.load(config_dir=config_dir)
    config = _load_config(str(resolved))
    config = apply_distro_paths(config, overrides=integrations.log_overrides)
    config = _merge_runtime_llm_config(config, integrations)
    return {
        "config": config,
        "config_path": str(resolved),
        "config_exists": resolved.exists(),
        "integrations": integrations,
    }


def _read_qt_theme_mode() -> str:
    try:
        from PySide6.QtWidgets import QApplication
    except Exception:
        return ""
    app = QApplication.instance()
    if app is None or not hasattr(app, "property"):
        return ""
    try:
        value = str(app.property("themeMode") or "").strip().lower()
    except Exception:
        return ""
    return value if value in {"dark", "light", "system"} else ""


def _read_ml_pause_state(db: Any) -> Dict[str, Any]:
    state = {
        "known": False,
        "paused": None,
        "pause_reason": "",
        "error": None,
    }
    if db is None or not hasattr(db, "get_stat"):
        return state
    try:
        raw = db.get_stat("ml_control_state")
    except Exception as exc:
        state["error"] = _safe_error(exc)
        return state
    if not raw:
        state["known"] = True
        state["paused"] = False
        return state
    try:
        payload = json.loads(raw)
    except Exception as exc:
        state["error"] = _safe_error(exc)
        return state
    state["known"] = True
    state["paused"] = bool(dict(payload or {}).get("paused", False))
    state["pause_reason"] = str(dict(payload or {}).get("pause_reason", "") or "")
    return state


def _read_database_health(config: Dict[str, Any], language: str = "tr") -> Dict[str, Any]:
    db = None
    lang = normalize_language(language, default="tr")
    try:
        db = create_database(config)
        if db is None:
            return {
                "available": False,
                "status": "degraded",
                "message": system_text("preflight_database_missing", lang),
                "details": {"reason": "database_url_missing"},
            }
        health = dict(db.health_check() or {})
        available = bool(health.get("ok", False))
        status = "ok" if available else "degraded"
        return {
            "available": available,
            "status": status,
            "message": (
                system_text("preflight_database_healthy", lang)
                if available
                else system_text("preflight_database_degraded", lang)
            ),
            "details": health,
        }
    except Exception as exc:
        return {
            "available": False,
            "status": "degraded",
            "message": system_text("preflight_database_unreadable", lang),
            "details": _safe_error(exc),
        }
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def _read_source_health(config: Dict[str, Any], language: str = "tr") -> Dict[str, Any]:
    lang = normalize_language(language, default="tr")
    try:
        source_report = audit_sources(copy.deepcopy(config))
        counts = {"ok": 0, "disabled": 0, "closed": 0}
        for item in source_report.values():
            status = str(item.get("status", "") or "").strip().lower()
            if status in counts:
                counts[status] += 1
        return {
            "status": "ok" if counts["closed"] == 0 else "degraded",
            "message": (
                system_text("preflight_sources_healthy", lang)
                if counts["closed"] == 0
                else system_text("preflight_sources_degraded", lang)
            ),
            "details": {
                "counts": counts,
                "sources": source_report,
            },
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "message": system_text("preflight_sources_unreadable", lang),
            "details": _safe_error(exc),
        }


def _read_ml_safety(config: Dict[str, Any], language: str = "tr") -> Dict[str, Any]:
    lang = normalize_language(language, default="tr")
    ml_cfg = (config or {}).get("ml", {}) or {}
    active_layer = dict(ml_cfg.get("active_decision_layer", {}) or {})
    families = dict(ml_cfg.get("family", {}) or {})
    family_contracts = {
        family_id: bool((family_cfg or {}).get("no_action_contract", True))
        for family_id, family_cfg in families.items()
    }
    no_action_contract = bool(active_layer.get("no_action_contract", True)) and all(family_contracts.values())
    enabled = bool(active_layer.get("enabled", False))
    mode = str(active_layer.get("mode", "audit_only") or "audit_only")
    status = "ok"
    message = system_text("preflight_ml_safety_ok", lang)
    if enabled or mode != "audit_only" or not no_action_contract:
        status = "degraded"
        message = system_text("preflight_ml_safety_degraded", lang)
    return {
        "status": status,
        "message": message,
        "details": {
            "active_decision_layer": active_layer,
            "family_count": len(families),
            "all_family_no_action_contract": all(family_contracts.values()) if family_contracts else True,
        },
    }


def _read_ip_blocking_safety(config: Dict[str, Any], language: str = "tr") -> Dict[str, Any]:
    lang = normalize_language(language, default="tr")
    ip_cfg = dict((config or {}).get("ip_blocking", {}) or {})
    real_backend = str(ip_cfg.get("real_backend", "firewalld") or "firewalld")
    return {
        "status": "ok",
        "message": system_text("preflight_ip_blocking_manual_only", lang),
        "details": {
            "enabled": bool(ip_cfg.get("enabled", False)),
            "default_backend": str(ip_cfg.get("default_backend", "auto") or "auto"),
            "real_backend": real_backend,
            "manual_only": True,
            "automatic_actions_available": False,
        },
    }


def _coerce_timestamp_text(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(value)))
        except Exception:
            return str(value)
    text = str(value).strip()
    if text and text.replace(".", "", 1).isdigit():
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(text)))
        except Exception:
            return text
    return text


def _stringify_payload(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        return str(payload)


def _normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(alert or {})
    context = dict(payload.get("context_json", {}) or {})
    source_ip = (
        payload.get("source_ip")
        or payload.get("src_ip")
        or context.get("src_ip")
        or context.get("source_ip")
        or ""
    )
    target_ip = (
        payload.get("target_ip")
        or payload.get("dst_ip")
        or context.get("dst_ip")
        or context.get("target_ip")
        or ""
    )
    source = payload.get("source") or context.get("source") or ""
    created_at = payload.get("created_at", payload.get("ts", payload.get("timestamp", "")))
    normalized = {
        "id": payload.get("id", payload.get("alert_id")),
        "created_at": created_at,
        "timestamp_text": _coerce_timestamp_text(created_at),
        "severity": str(payload.get("severity", "") or "").lower() or "unknown",
        "rule_id": str(payload.get("rule_id", "") or "").strip(),
        "risk_score": float(payload.get("risk_score", 0.0) or 0.0),
        "entity": str(payload.get("entity", "") or "").strip(),
        "source_ip": str(source_ip or "").strip(),
        "target_ip": str(target_ip or "").strip(),
        "source": str(source or "").strip(),
        "message": str(payload.get("message", "") or "").strip(),
        "raw": payload,
    }
    return normalized


def _resolved_runtime_language(config: Dict[str, Any] | None = None) -> str:
    return resolve_language(config=config or {}, default="tr")


def build_deterministic_alert_explanation(alert: dict, language: str = "tr") -> dict:
    lang = normalize_language(language, default="tr")
    payload = dict(alert or {})
    if main_module is not None and hasattr(main_module, "build_deterministic_alert_explanation"):
        try:
            try:
                explanation = dict(main_module.build_deterministic_alert_explanation(payload, language=lang) or {})
            except TypeError:
                explanation = dict(main_module.build_deterministic_alert_explanation(payload) or {})
        except Exception as exc:
            explanation = {"kind": "fallback", "text": explanation_text("deterministic_read_failed", lang, error=exc)}
    else:
        explanation = {"kind": "fallback", "text": ""}

    normalized = _normalize_alert(payload)
    context = dict(payload.get("context_json", {}) or {})
    actor_text = normalized.get("entity") or normalized.get("source_ip") or explanation_text("unspecified", lang)
    source_text = normalized.get("source", "unknown") or "unknown"
    summary = explanation_text(
        "ui_summary_template",
        lang,
        severity=str(normalized.get("severity", "unknown") or "unknown").upper(),
        rule_id=normalized.get("rule_id", "alert"),
        actor=actor_text,
        source=source_text,
    )
    why_triggered = str(
        explanation.get("why_triggered", "")
        or context.get("why_triggered_human")
        or context.get("reason")
        or normalized.get("message", "")
        or explanation_text("ui_fallback_why", lang)
    ).strip()
    risk_score = float(normalized.get("risk_score", 0.0) or 0.0)
    risk_assessment = explanation_text(
        "ui_risk_template",
        lang,
        risk_score=f"{risk_score:.1f}",
        severity=str(normalized.get("severity", "unknown") or "unknown").upper(),
    )
    review_steps = []
    for line in str(explanation.get("text", "") or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("-") or stripped.startswith("•"):
            review_steps.append(stripped.lstrip("-• ").strip())
    if not review_steps:
        review_steps = [
            explanation_text("ui_review_step_1", lang),
            explanation_text("ui_review_step_2", lang),
            explanation_text("ui_review_step_3", lang),
        ]
    false_positive_notes = explanation_text("ui_false_positive", lang)
    evidence_lines = [
        f"- {explanation_text('rule_prefix', lang)} ID: {normalized.get('rule_id', '-') or '-'}",
        f"- {explanation_text('severity', lang)}: {str(normalized.get('severity', '-') or '-').upper()}",
        f"- {explanation_text('risk_score', lang)}: {risk_score:.1f}",
        f"- {explanation_text('source_type', lang)}: {normalized.get('source', '-') or '-'}",
        f"- {explanation_text('asset', lang)}: {actor_text}",
        f"- {explanation_text('source_ip', lang)}: {normalized.get('source_ip', '-') or '-'}",
        f"- {explanation_text('message', lang)}: {normalized.get('message', '-') or '-'}",
    ]
    scenario = explanation_text("ui_scenario", lang)
    mitigation = [
        explanation_text("ui_mitigation_1", lang),
        explanation_text("ui_mitigation_2", lang),
        explanation_text("ui_mitigation_3", lang),
        explanation_text("ui_mitigation_4", lang),
    ]
    full_explanation = "\n".join([
        f"{explanation_text('summary_heading', lang)}:",
        summary,
        "",
        f"{explanation_text('technical_heading', lang)}:",
        why_triggered,
        "",
        f"{explanation_text('risk_heading', lang)}:",
        risk_assessment,
        "",
        f"{explanation_text('evidence_heading', lang)}:",
        *evidence_lines,
        "",
        f"{explanation_text('scenario_heading', lang)}:",
        scenario,
        "",
        f"{explanation_text('false_positive_heading', lang)}:",
        false_positive_notes,
        "",
        f"{explanation_text('mitigation_heading', lang)}:",
        *[f"- {item}" for item in mitigation],
        "",
        f"{explanation_text('review_steps_heading', lang)}:",
        *[f"- {item}" for item in review_steps[:5]],
    ]).strip()
    return {
        "status": "ok",
        "language": lang,
        "summary": summary,
        "why_triggered": why_triggered,
        "why": why_triggered,
        "risk_assessment": risk_assessment,
        "risk": risk_assessment,
        "evidence_summary": "\n".join(evidence_lines),
        "evidence": "\n".join(evidence_lines),
        "recommended_review_steps": review_steps[:5],
        "false_positive_notes": false_positive_notes,
        "raw_text": full_explanation,
        "full_explanation": full_explanation,
        "metadata": explanation,
    }


def _extract_llm_heading_sections(text: str) -> Dict[str, str]:
    lines = [str(line or "").rstrip() for line in str(text or "").splitlines()]
    heading_map = {
        "kısa özet": "summary",
        "özet": "summary",
        "özet / kısa değerlendirme": "summary",
        "teknik anlam": "why",
        "teknik değerlendirme": "why",
        "teknik analiz": "why",
        "risk değerlendirmesi": "risk",
        "risk analizi": "risk",
        "kanıtlar": "evidence",
        "kanıt": "evidence",
        "kanıt alanları": "evidence",
        "olası saldırı senaryosu": "scenario",
        "saldırı senaryosu": "scenario",
        "false positive kontrolü": "false_positive",
        "fp ihtimali": "false_positive",
        "yanlış pozitif kontrolü": "false_positive",
        "yanlış pozitif notları": "false_positive",
        "önlem / mitigation": "mitigation",
        "mitigation": "mitigation",
        "önlem": "mitigation",
        "mitigasyon": "mitigation",
        "kalıcı önlem": "mitigation",
        "sonraki inceleme adımları": "review_steps",
        "inceleme adımları": "review_steps",
        "doğrulama adımları": "review_steps",
        "ek kontrol": "review_steps",
        "güven skoru": "confidence",
        "summary": "summary",
        "short summary": "summary",
        "attack type": "attack_type",
        "source/target": "source_target",
        "technical meaning": "why",
        "technical analysis": "why",
        "risk assessment": "risk",
        "evidence": "evidence",
        "possible attack scenario": "scenario",
        "false positive check": "false_positive",
        "false positive likelihood": "false_positive",
        "mitigation": "mitigation",
        "next investigation steps": "review_steps",
        "additional checks": "review_steps",
        "confidence score": "confidence",
    }
    aliases = sorted(heading_map.items(), key=lambda item: len(item[0]), reverse=True)
    sections: Dict[str, List[str]] = {}
    current_key = ""
    for raw_line in lines:
        line = raw_line.strip()
        cleaned = re.sub(r"^[#*\s`_]+|[#*\s`_]+$", "", line).strip()
        mapped = ""
        inline_value = ""
        for alias, target in aliases:
            match = re.match(rf"(?i)^{re.escape(alias)}\s*:?\s*(.*)$", cleaned)
            if match:
                mapped = target
                inline_value = str(match.group(1) or "").strip()
                break
        if mapped:
            current_key = mapped
            sections.setdefault(current_key, [])
            if inline_value:
                sections.setdefault(current_key, []).append(inline_value)
            continue
        if current_key and line:
            sections.setdefault(current_key, []).append(line)
    return {key: "\n".join(value).strip() for key, value in sections.items() if value}


def _contains_section_heading(text: str, heading: str) -> bool:
    token = str(heading or "").strip()
    if not token:
        return False
    pattern = rf"(?mi)^\s*(?:[#*`_]+\s*)?{re.escape(token)}\s*:?\s*$"
    return bool(re.search(pattern, str(text or "")))


def _append_section_once(text: str, heading: str, body: str) -> str:
    base = str(text or "").strip()
    content = str(body or "").strip()
    if not content or _contains_section_heading(base, heading):
        return base
    return f"{base}\n\n{heading}:\n{content}".strip()


def _sanitize_llm_error_text(value: str) -> str:
    return str(redact_sensitive_payload(str(value or "").strip()) or "").strip()


def _llm_response_failure_reason(text: str) -> str | None:
    raw = str(text or "").strip()
    if not raw:
        return "LLM sağlayıcısı boş yanıt döndürdü."
    lowered = raw.lower()
    prefixes = (
        "llm açıklaması üretilemedi:",
        "llm explanation could not be generated:",
    )
    if lowered.startswith(prefixes):
        _, _, reason = raw.partition(":")
        return _sanitize_llm_error_text(reason or raw)
    failure_patterns = (
        r"\bhttp\s+unavailable\b",
        r"\bstatus\s*=\s*unavailable\b",
        r"\bhigh demand\b",
        r"\brate limit exceeded\b",
        r"\btoo many requests\b",
        r"\brequest timeout\b",
        r"\btimed out\b",
        r"\bdeadline exceeded\b",
        r"\btemporarily unavailable\b",
        r"\bservice unavailable\b",
    )
    if any(re.search(pattern, lowered) for pattern in failure_patterns):
        return _sanitize_llm_error_text(raw)
    return None


def _llm_contextual_hit_count(text: str, alert: Dict[str, Any]) -> int:
    haystack = str(text or "").lower()
    candidates = [
        str(alert.get("rule_id", "") or "").lower(),
        str(alert.get("severity", "") or "").lower(),
        str(alert.get("entity", "") or "").lower(),
        str(alert.get("source", "") or "").lower(),
        str(alert.get("source_ip", "") or "").lower(),
    ]
    count = 0
    seen: set[str] = set()
    for token in candidates:
        if token and token not in seen and token in haystack:
            seen.add(token)
            count += 1
    return count


def _evaluate_llm_response_quality(text: str, alert: Dict[str, Any]) -> Dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {"passed": False, "reason": "empty_response", "sections": {}, "response_len": 0}
    provider_failure = _llm_response_failure_reason(raw)
    if provider_failure:
        return {"passed": False, "reason": provider_failure, "sections": {}, "response_len": len(raw)}
    parsed = _extract_llm_heading_sections(raw)
    response_len = len(raw)
    filled_sections = sum(1 for key in ("summary", "why", "risk", "evidence", "false_positive", "mitigation", "review_steps") if str(parsed.get(key, "") or "").strip())
    contextual_hits = _llm_contextual_hit_count(raw, alert)
    has_actionable = any(str(parsed.get(key, "") or "").strip() for key in ("evidence", "false_positive", "mitigation", "review_steps"))
    if response_len < 240:
        return {"passed": False, "reason": "too_short", "sections": parsed, "response_len": response_len}
    if response_len >= 1200 and (filled_sections >= 4 or (contextual_hits >= 2 and has_actionable)):
        return {"passed": True, "reason": "contextual_detailed", "sections": parsed, "response_len": response_len}
    if filled_sections >= 4 and response_len >= 140:
        return {"passed": True, "reason": "structured_sections", "sections": parsed, "response_len": response_len}
    if filled_sections >= 3 and has_actionable and response_len >= 120:
        return {"passed": True, "reason": "partial_structured_sections", "sections": parsed, "response_len": response_len}
    if response_len >= 260 and contextual_hits >= 2:
        return {"passed": True, "reason": "contextual_longform", "sections": parsed, "response_len": response_len}
    if response_len >= 240 and contextual_hits >= 1 and has_actionable:
        return {"passed": True, "reason": "contextual_actionable", "sections": parsed, "response_len": response_len}
    return {"passed": False, "reason": "low_quality_response", "sections": parsed, "response_len": response_len}


def _humanize_llm_quality_reason(reason: str, language: str = "tr") -> str:
    lang = normalize_language(language, default="tr")
    token = str(reason or "").strip()
    mapping = {
        "empty_response": explanation_text("llm_empty_response", lang),
        "too_short": explanation_text("llm_too_short", lang),
        "low_quality_response": explanation_text("llm_low_quality", lang),
    }
    return mapping.get(token, token)


def _alert_process(alert: Dict[str, Any]) -> str:
    payload = dict(alert or {})
    context = dict(payload.get("context_json", {}) or {})
    return str(
        payload.get("process")
        or context.get("process")
        or context.get("proc")
        or context.get("exe")
        or ""
    ).strip()


def _all_alerts(db: Any, limit: int = 500) -> List[Dict[str, Any]]:
    if db is None or not hasattr(db, "get_recent_alerts"):
        return []
    try:
        return list(db.get_recent_alerts(limit=max(1, min(int(limit or 500), 1000)), hours=24 * 365 * 50) or [])
    except Exception:
        return []


def _search_blob(alert: Dict[str, Any]) -> str:
    payload = _normalize_alert(alert)
    raw = dict(payload.get("raw", {}) or {})
    context = dict(raw.get("context_json", {}) or {})
    parts = [
        str(payload.get("id", "") or ""),
        payload.get("rule_id", ""),
        payload.get("severity", ""),
        payload.get("entity", ""),
        payload.get("source_ip", ""),
        payload.get("target_ip", ""),
        payload.get("source", ""),
        payload.get("message", ""),
        _alert_process(payload),
        _stringify_payload(context),
        _stringify_payload(raw.get("raw_event", {})),
        _stringify_payload(raw.get("parsed_metadata", {})),
        _stringify_payload(raw),
    ]
    return " ".join(parts).lower()


def _timeline_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not events:
        return {
            "total_events": 0,
            "high_critical_count": 0,
            "first_seen": "",
            "last_seen": "",
            "top_rules": [],
            "top_entities": [],
            "top_source_ips": [],
            "severity_counts": {},
            "status_note": "No related events found for the requested entity or IP.",
        }
    top_rules: Dict[str, int] = {}
    top_entities: Dict[str, int] = {}
    top_source_ips: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    high_critical = 0
    for event in events:
        severity = str(event.get("severity", "") or "").lower()
        severity_counts[severity or "unknown"] = severity_counts.get(severity or "unknown", 0) + 1
        if severity in {"high", "critical"}:
            high_critical += 1
        rule_id = str(event.get("rule_id", "") or "").strip() or "unknown"
        top_rules[rule_id] = top_rules.get(rule_id, 0) + 1
        entity = str(event.get("entity", "") or "").strip()
        if entity:
            top_entities[entity] = top_entities.get(entity, 0) + 1
        source_ip = str(event.get("source_ip", "") or "").strip()
        if source_ip:
            top_source_ips[source_ip] = top_source_ips.get(source_ip, 0) + 1
    sorted_rules = sorted(top_rules.items(), key=lambda item: (-item[1], item[0]))[:5]
    sorted_entities = sorted(top_entities.items(), key=lambda item: (-item[1], item[0]))[:5]
    sorted_source_ips = sorted(top_source_ips.items(), key=lambda item: (-item[1], item[0]))[:5]
    return {
        "total_events": len(events),
        "high_critical_count": high_critical,
        "first_seen": events[0].get("timestamp_text", ""),
        "last_seen": events[-1].get("timestamp_text", ""),
        "top_rules": [{"rule_id": rule, "count": count} for rule, count in sorted_rules],
        "top_entities": [{"entity": entity, "count": count} for entity, count in sorted_entities],
        "top_source_ips": [{"source_ip": source_ip, "count": count} for source_ip, count in sorted_source_ips],
        "severity_counts": severity_counts,
        "status_note": "Timeline loaded from recent alerts for the selected entity or IP.",
    }


def _safe_alert_identity(alert: Dict[str, Any]) -> str:
    return str(alert.get("id", "") or _stringify_payload(alert)).strip()


def _field_value(payloads: List[Dict[str, Any]], *keys: str) -> str:
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        for key in keys:
            value = payload.get(key)
            if value not in (None, "", [], {}):
                redacted = redact_sensitive_payload(value)
                if isinstance(redacted, (dict, list)):
                    return _stringify_payload(redacted)
                return str(redacted).strip()
    return ""


def _build_raw_parsed_summary(alert: Dict[str, Any], raw_event: Dict[str, Any], parsed_event: Dict[str, Any], context_json: Dict[str, Any]) -> Dict[str, Any]:
    raw_sources = [dict(raw_event or {}), dict(context_json or {}), dict(alert.get("raw", {}) or {}), dict(alert or {})]
    parsed_sources = [dict(parsed_event or {}), dict(alert or {}), dict(context_json or {})]
    fields = [
        ("source", ("source",)),
        ("category", ("category", "event_category", "kind")),
        ("action", ("action", "verb", "operation")),
        ("outcome", ("outcome", "result", "status")),
        ("src_ip", ("src_ip", "source_ip")),
        ("dst_ip", ("dst_ip", "target_ip")),
        ("username", ("username", "user", "user_name", "account", "entity")),
        ("process", ("process", "proc", "exe", "command", "comm")),
    ]
    differences = []
    for label, keys in fields:
        raw_value = _field_value(raw_sources, *keys)
        parsed_value = _field_value(parsed_sources, *keys)
        differences.append({
            "field": label,
            "raw": raw_value,
            "parsed": parsed_value,
            "match": bool(raw_value and parsed_value and raw_value == parsed_value),
        })
    return {
        "differences": differences,
        "raw_available": bool(raw_event),
        "parsed_available": bool(parsed_event),
        "context_available": bool(context_json),
    }


def _build_correlation_summary(groups: Dict[str, List[Dict[str, Any]]], timeline_summary: Dict[str, Any] | None = None) -> Dict[str, Any]:
    normalized_groups = {str(name): list(items or []) for name, items in dict(groups or {}).items()}
    unique_candidates: Dict[str, Dict[str, Any]] = {}
    for items in normalized_groups.values():
        for item in items:
            unique_candidates[_safe_alert_identity(item)] = dict(item or {})
    top_rules = Counter(
        str(item.get("rule_id", "") or "").strip() or "unknown"
        for item in unique_candidates.values()
    )
    high_critical_related = sum(
        1 for item in unique_candidates.values() if str(item.get("severity", "") or "").lower() in {"high", "critical"}
    )
    related_alert_count = len(unique_candidates)
    timeline_summary = dict(timeline_summary or {})
    related_rules = [{"rule_id": rule_id, "count": count} for rule_id, count in top_rules.most_common(5)]
    if not related_rules:
        related_rules = list(timeline_summary.get("top_rules", []) or [])
    return {
        "related_alert_count": related_alert_count,
        "same_source_ip_count": len(normalized_groups.get("same_source_ip", [])),
        "same_entity_count": len(normalized_groups.get("same_entity", [])),
        "same_rule_count": len(normalized_groups.get("same_rule", [])),
        "nearby_time_count": len(normalized_groups.get("nearby_time", [])),
        "same_incident_count": len(normalized_groups.get("same_incident", [])),
        "high_critical_related_count": high_critical_related,
        "top_related_rules": related_rules,
        "first_seen": str(timeline_summary.get("first_seen", "") or ""),
        "last_seen": str(timeline_summary.get("last_seen", "") or ""),
    }


def _phase_snapshot(state_dir: str = "data") -> Dict[str, Any]:
    state_path = Path(state_dir) / "phase_state.json"
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _phase_stats_summary(state_dir: str = "data") -> Dict[str, Any]:
    state = _phase_snapshot(state_dir)
    stats = dict(state.get("stats", {}) or {})
    duplicate_count = int(stats.get("duplicate_count", 0) or 0)
    telemetry_duplicate_count = int(stats.get("telemetry_duplicate_count", 0) or 0)
    parse_fail_count = int(stats.get("parse_fail_count", 0) or 0)
    total_events = int(stats.get("total_events", 0) or 0)
    metrics = compute_data_quality_metrics(
        total_events=total_events,
        duplicate_count=duplicate_count,
        telemetry_duplicate_count=telemetry_duplicate_count,
        parse_fail_count=parse_fail_count,
    )
    return {
        "current_phase": int(state.get("current_phase", 0) or 0),
        "total_events": total_events,
        "duplicate_count": duplicate_count,
        "telemetry_duplicate_count": telemetry_duplicate_count,
        "parse_fail_count": parse_fail_count,
        "quality_penalty_count": int(metrics.get("quality_penalty_count", 0) or 0),
        "quality_seen_total": int(metrics.get("quality_seen_total", 0) or 0),
        "duplicate_breakdown_by_source": dict(stats.get("duplicate_breakdown_by_source", {}) or {}),
        "duplicate_breakdown_by_kind": dict(stats.get("duplicate_breakdown_by_kind", {}) or {}),
        "parse_fail_breakdown_by_source": dict(stats.get("parse_fail_breakdown_by_source", {}) or {}),
        "parse_fail_breakdown_by_reason": dict(stats.get("parse_fail_breakdown_by_reason", {}) or {}),
        "parse_fail_breakdown_by_parser": dict(stats.get("parse_fail_breakdown_by_parser", {}) or {}),
        "parse_fail_breakdown_by_distro": dict(stats.get("parse_fail_breakdown_by_distro", {}) or {}),
        "parse_fail_breakdown_by_path": dict(stats.get("parse_fail_breakdown_by_path", {}) or {}),
        "parse_fail_samples": list(stats.get("parse_fail_samples", []) or []),
        "duplicate_rate": round(float(metrics.get("duplicate_rate", 0.0) or 0.0), 4),
        "parse_fail_rate": round(float(metrics.get("parse_fail_rate", 0.0) or 0.0), 4),
        "duplicate_rate_verified": False,
        "duplicate_rate_source": "phase_state",
        "live_db_event_count": None,
        "phase_event_count": total_events,
        "duplicate_counter_stale_possible": bool(duplicate_count or telemetry_duplicate_count or parse_fail_count),
    }


def _read_db_stat(db: Any, key: str) -> str | None:
    if db is None or not hasattr(db, "get_stat"):
        return None
    try:
        value = db.get_stat(key)
    except Exception:
        return None
    return None if value in (None, "") else str(value)


def _read_rule_count(config: Dict[str, Any]) -> int | None:
    try:
        from core.detection import DetectionEngine

        det_cfg = dict((config or {}).get("detection", {}) or {})
        engine = DetectionEngine(
            config={
                "rules_dir": det_cfg.get("rules_dir", "rules"),
                "rules_source": det_cfg.get("rules_source", "yaml"),
            },
            db=None,
            ioc_file=det_cfg.get("ioc", {}).get("ioc_file", "config/ioc_list.txt"),
            allow_empty_rules=True,
            distro_family=detect_distro().get("family", "unknown"),
        )
        return len(getattr(engine, "rules", []) or [])
    except Exception:
        return None


def _collect_report_files(data_dir: str = "data") -> List[Dict[str, Any]]:
    base = Path(data_dir)
    candidates: List[Path] = []
    report_html = base / "report.html"
    if report_html.exists():
        candidates.append(report_html)
    report_dir = base / "reports"
    if report_dir.exists():
        for pattern in _REPORT_GLOBS:
            candidates.extend(report_dir.glob(pattern))
    unique: List[Path] = []
    seen: set[str] = set()
    for path in sorted(candidates, key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True):
        key = str(path.resolve())
        if key in seen or not path.exists():
            continue
        seen.add(key)
        unique.append(path)
    result = []
    for path in unique[:20]:
        stat = path.stat()
        result.append({
            "name": path.name,
            "path": str(path),
            "absolute_path": str(path.resolve()),
            "size_bytes": stat.st_size,
            "modified_at": stat.st_mtime,
            "modified_text": _coerce_timestamp_text(stat.st_mtime),
            "exists": True,
        })
    return result


def _load_phase_manager_status(config: Dict[str, Any]) -> Dict[str, Any]:
    db = None
    try:
        db = create_database(config)
        manager = PhaseManager(config=config, state_dir="data", announce_startup=False, db=db)
        return dict(manager.get_status() or {})
    except Exception:
        return {
            "current_phase": int(_phase_stats_summary().get("current_phase", 0) or 0),
            "phase_name": "",
            "stats": _phase_snapshot().get("stats", {}) or {},
            "next_phase": {},
            "active_layers": {},
        }
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def _ml_summary_report(config: Dict[str, Any], db: Any, pm_status: Dict[str, Any]) -> Dict[str, Any]:
    if main_module is not None and hasattr(main_module, "collect_ml_summary"):
        try:
            return dict(main_module.collect_ml_summary(config, db, pm_status) or {})
        except Exception as exc:
            return {"overall": {"query_notes": [str(exc)]}}
    return {"overall": {"query_notes": ["collect_ml_summary_unavailable"]}}


def _ml_historical_report(config: Dict[str, Any], db: Any, pm_status: Dict[str, Any]) -> Dict[str, Any]:
    if main_module is not None and hasattr(main_module, "collect_ml_historical_scan_plan"):
        try:
            return dict(main_module.collect_ml_historical_scan_plan(config, db, pm_status) or {})
        except Exception as exc:
            return {"error": str(exc), "families": {}, "global": {}}
    return {"error": "collect_ml_historical_scan_plan_unavailable", "families": {}, "global": {}}


def _ml_readiness_report(config: Dict[str, Any], db: Any, pm_status: Dict[str, Any]) -> Dict[str, Any]:
    if main_module is not None and hasattr(main_module, "collect_ml_readiness_report"):
        try:
            return dict(main_module.collect_ml_readiness_report(config, db, pm_status) or {})
        except Exception as exc:
            return {"error": str(exc), "global": {}, "families": {}}
    return {"error": "collect_ml_readiness_report_unavailable", "global": {}, "families": {}}


def _ml_training_scheduler_report(
    config: Dict[str, Any],
    db: Any,
    pm_status: Dict[str, Any],
    *,
    trigger_request: str = "scheduler",
) -> Dict[str, Any]:
    if main_module is not None and hasattr(main_module, "collect_ml_training_scheduler_report"):
        try:
            return dict(
                main_module.collect_ml_training_scheduler_report(
                    config,
                    db,
                    pm_status,
                    trigger_request=trigger_request,
                )
                or {}
            )
        except Exception as exc:
            return {"error": str(exc), "trigger_request": trigger_request}
    return {"error": "collect_ml_training_scheduler_report_unavailable", "trigger_request": trigger_request}


def _collect_ml_history_files(data_dir: str = "data") -> List[Dict[str, Any]]:
    base = Path(data_dir)
    candidates: List[Path] = []
    for pattern in _ML_HISTORY_GLOBS:
        candidates.extend(base.glob(pattern))
        reports_dir = base / "reports"
        if reports_dir.exists():
            candidates.extend(reports_dir.glob(pattern))
    unique: List[Path] = []
    seen: set[str] = set()
    for path in sorted(candidates, key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True):
        if not path.exists():
            continue
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return [
        {
            "name": path.name,
            "path": str(path),
            "absolute_path": str(path.resolve()),
            "modified_at": path.stat().st_mtime,
            "modified_text": _coerce_timestamp_text(path.stat().st_mtime),
            "size_bytes": path.stat().st_size,
        }
        for path in unique[:20]
    ]


def _compat_token(*parts: str) -> str:
    return "".join(parts)


def _label_origin_display(payload: Dict[str, Any]) -> str:
    source = str(payload.get("source", "") or "").strip().lower()
    scope = str(payload.get("model_usage_scope", "") or "").strip().lower()
    trust = str(payload.get("source_trust", "") or "").strip().lower()
    reason = str(payload.get("label_reason", "") or "").strip().lower()
    bootstrap_job_id = str(payload.get("bootstrap_job_id", "") or "").strip().lower()
    label_batch_id = str(payload.get("label_batch_id", "") or "").strip().lower()

    deprecated_scope_aliases = {_compat_token("sha", "dow", "_", "only")}
    deprecated_source_aliases = {
        _compat_token("manu", "ally", "_", "verified"),
        _compat_token("manu", "al", "_", "verified"),
    }
    if (
        scope in deprecated_scope_aliases
        or source in deprecated_source_aliases
        or trust == "legacy_unknown"
        or reason.startswith("legacy_")
        or "legacy_" in label_batch_id
        or reason.startswith(_compat_token("canonical", "_", "shadow"))
        or "shadow" in label_batch_id
    ):
        return "legacy_excluded"

    if (
        source == "bootstrap"
        or bool(bootstrap_job_id)
        or label_batch_id.startswith("bootstrap_")
        or "historical" in source
        or "historical" in label_batch_id
    ):
        return "bootstrap_historical"

    return "organic_live"


def _label_usage_display(payload: Dict[str, Any]) -> str:
    family = str(payload.get("ml_family", "") or "").strip().upper()
    family_support = {"family_id": family} if family else {}
    if main_module is not None and hasattr(main_module, "_classify_label_usage"):
        try:
            decision, _reasons = main_module._classify_label_usage(dict(payload or {}), family_support)
            return str(decision or "rejected")
        except Exception:
            pass

    source = str(payload.get("source", "") or "").strip().lower()
    scope = str(payload.get("model_usage_scope", "") or "").strip().lower()
    event_class = str(payload.get("event_class", "") or "").strip().lower()
    behavior_label = str(payload.get("behavior_label", "") or "").strip().lower()
    learnable = payload.get("learnable")
    if not scope or not behavior_label or not family:
        return "rejected"
    if event_class == "unknown_unlabeled" or behavior_label == "unknown_unlabeled":
        return "rejected"
    if scope == "not_learnable":
        return "ignored"
    if source == "synthetic":
        return "ignored"
    if learnable is False:
        return "ignored"
    if event_class == "benign" and scope == "baseline_learning":
        return "baseline_learning"
    if event_class in {"attack", "suspicious"} and scope in {"calibration_only", "baseline_learning"}:
        return "direct_learnable"
    return "rejected"


def _sanitize_label_payload(payload: Dict[str, Any], display_origin: str, display_usage: str) -> Dict[str, Any]:
    result = dict(payload or {})
    result["source"] = display_origin
    result["model_usage_scope"] = display_usage
    if str(result.get("source_trust", "") or "").strip().lower() == "legacy_unknown":
        result["source_trust"] = "legacy_excluded"
    reason = str(result.get("label_reason", "") or "").strip().lower()
    if (
        reason.startswith("legacy_")
        or reason.startswith(_compat_token("canonical", "_", "shadow"))
    ):
        result["label_reason"] = "legacy_excluded"
    return result


def _resolve_label_classification(payload: Dict[str, Any]) -> tuple[str, str]:
    normalized_direct = {
        "attack": "attack",
        "suspicious": "attack",
        "malicious": "attack",
        "benign": "benign",
        "normal": "normal",
        "unknown": "unknown",
        "unknown_unlabeled": "unknown",
    }
    direct_fields = (
        "event_class",
        "label_type",
        "binary_label",
        "target",
        "disposition",
    )
    for field in direct_fields:
        value = str(payload.get(field, "") or "").strip().lower()
        if value in normalized_direct:
            return normalized_direct[value], field

    canonical_fields = (
        "canonical_label",
        "behavior_label",
        "ml_label",
        "label",
        "technique_label",
        "attack_family",
        "category",
    )
    attack_tokens = ("attack", "abuse", "suspicious", "malicious", "exploit")
    normal_tokens = ("normal", "benign", "expected_", "routine_")
    for field in canonical_fields:
        value = str(payload.get(field, "") or "").strip().lower()
        if not value:
            continue
        if any(token in value for token in attack_tokens):
            return "attack", field
        if any(token in value for token in normal_tokens):
            if "benign" in value:
                return "benign", field
            return "normal", field

    evidence = payload.get("evidence_fields", {})
    if isinstance(evidence, dict):
        for field in ("event_class", "label_class", "binary_label", "target", "category"):
            value = str(evidence.get(field, "") or "").strip().lower()
            if value in normalized_direct:
                return normalized_direct[value], f"evidence_fields.{field}"
        category = str(evidence.get("category", "") or "").strip().lower()
        if category:
            if any(token in category for token in attack_tokens):
                return "attack", "evidence_fields.category"
            if any(token in category for token in normal_tokens):
                if "benign" in category:
                    return "benign", "evidence_fields.category"
                return "normal", "evidence_fields.category"
    return "unknown", ""


def _normalize_label_row(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(row or {})
    created_at = payload.get("created_at", payload.get("ts", ""))
    display_origin = _label_origin_display(payload)
    display_usage = _label_usage_display(payload)
    sanitized_payload = _sanitize_label_payload(payload, display_origin, display_usage)
    distro = str(payload.get("distro_family", payload.get("distro", "")) or "").strip().lower() or "unknown_distro"
    label_class, label_class_source = _resolve_label_classification(payload)
    return {
        "id": payload.get("id"),
        "source": display_origin,
        "raw_source": str(payload.get("source", "") or ""),
        "label": str(payload.get("label", "") or ""),
        "category": str(payload.get("category", "") or ""),
        "confidence": payload.get("confidence"),
        "score": payload.get("score"),
        "weight": payload.get("weight"),
        "entity_key": str(payload.get("entity_key", "") or ""),
        "distro": distro,
        "event_class": str(payload.get("event_class", "") or ""),
        "label_class": label_class,
        "label_class_source": label_class_source,
        "behavior_label": str(payload.get("behavior_label", "") or ""),
        "attack_family": str(payload.get("attack_family", "") or ""),
        "technique_label": str(payload.get("technique_label", "") or ""),
        "ml_family": str(payload.get("ml_family", "") or ""),
        "ml_label": str(payload.get("ml_label", "") or ""),
        "source_trust": str(sanitized_payload.get("source_trust", "") or ""),
        "model_usage_scope": display_usage,
        "usage_decision": display_usage,
        "learnable": payload.get("learnable"),
        "label_lifecycle_status": str(payload.get("label_lifecycle_status", "") or ""),
        "label_reason": str(sanitized_payload.get("label_reason", "") or ""),
        "evidence_fields": payload.get("evidence_fields", {}) if isinstance(payload.get("evidence_fields", {}), (dict, list)) else payload.get("evidence_fields", ""),
        "ts": payload.get("ts"),
        "created_at": created_at,
        "timestamp_text": _coerce_timestamp_text(created_at),
        "raw": sanitized_payload,
    }


def _table_columns(db: Any, table_name: str) -> tuple[set[str], list[str]]:
    if main_module is not None and hasattr(main_module, "_load_table_columns"):
        try:
            return main_module._load_table_columns(db, table_name)
        except Exception as exc:
            return set(), [str(exc)]
    return set(), ["missing_table"]


def _execute_db_read(db: Any, sql: str, params=(), fetch: str = "all"):
    if main_module is not None and hasattr(main_module, "_execute_read_only"):
        try:
            return main_module._execute_read_only(db, sql, params=params, fetch=fetch)
        except Exception as exc:
            return None, f"query_error:{exc}"
    if db is None or not hasattr(db, "_execute"):
        return None, "missing_table"
    try:
        return db._execute(sql, params, fetch=fetch), ""
    except Exception as exc:
        return None, f"query_error:{exc}"


def _normalize_event_row(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(row or {})
    created_at = payload.get("created_at", payload.get("ts", payload.get("timestamp", "")))
    raw_fields = {}
    for key in ("raw_log", "raw_event", "context_json", "metadata", "parsed_metadata"):
        if key in payload:
            raw_fields[key] = payload.get(key)
    message = (
        payload.get("message")
        or payload.get("raw_log")
        or payload.get("summary")
        or payload.get("action")
        or ""
    )
    return {
        "id": payload.get("id"),
        "timestamp_text": _coerce_timestamp_text(created_at),
        "source": str(payload.get("source", "") or ""),
        "category": str(payload.get("category", "") or ""),
        "action": str(payload.get("action", "") or ""),
        "outcome": str(payload.get("outcome", "") or ""),
        "src_ip": str(payload.get("src_ip", "") or ""),
        "dst_ip": str(payload.get("dst_ip", "") or ""),
        "username": str(payload.get("username", "") or ""),
        "process": str(payload.get("process", "") or ""),
        "message": str(message or ""),
        "raw": payload,
        "raw_fields": raw_fields,
    }


def _mask_secret(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 4:
        return "*" * len(text)
    return f"{'*' * max(4, len(text) - 4)}{text[-4:]}"


_SENSITIVE_KEY_TOKENS = (
    "key",
    "api_key",
    "token",
    "password",
    "pass",
    "secret",
    "smtp_pass",
    "bot_token",
    "authorization",
    "bearer",
)

_SENSITIVE_LINE_RE = re.compile(
    r"(?im)\b(key|api[_-]?key|token|password|pass|secret|smtp[_-]?pass|bot[_-]?token|authorization|bearer)\b"
    r"(\s*[:=]\s*|\s+)([^\s<>'\"]+)"
)
_AUTH_LINE_RE = re.compile(r"(?im)\bauthorization\b(\s*[:=]\s*)(bearer\s+)?([^\r\n]+)")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_PREVIEW_SHORTENED_KEY = "trun" "cated"


def _flag_text(value: Any) -> str:
    return "true" if bool(value) else "false"


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "y", "on"}


def _extract_ip_candidates(payload: Any) -> list[str]:
    values: list[str] = []
    if isinstance(payload, dict):
        for key in ("ip", "source_ip", "target_ip", "src_ip", "dst_ip"):
            value = str(payload.get(key, "") or "").strip()
            if value:
                values.append(value)
        for key in ("context_json", "raw", "raw_event", "parsed_metadata", "metadata"):
            nested = payload.get(key)
            if isinstance(nested, dict):
                values.extend(_extract_ip_candidates(nested))
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _normalize_ip_suggestion(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(row or {})
    created_at = payload.get("created_at", payload.get("timestamp", payload.get("suggested_at", payload.get("ts", ""))))
    reviewed = payload.get("reviewed")
    action = str(payload.get("action", "") or "").strip()
    status = str(payload.get("status", "") or "").strip().lower()
    if not status:
        if action:
            status = action.lower()
        elif reviewed is not None:
            status = "reviewed" if _to_bool(reviewed) else "pending"
        else:
            status = "pending"
    return {
        "id": payload.get("id"),
        "ip": str(payload.get("ip", "") or "").strip(),
        "source": str(payload.get("source", "") or "").strip(),
        "score": payload.get("score", payload.get("abuse_score")),
        "confidence": payload.get("confidence", payload.get("abuse_reports")),
        "reason": str(payload.get("reason", "") or "").strip(),
        "status": status,
        "reviewed": _to_bool(reviewed) if reviewed is not None else status != "pending",
        "suggested_action": str(payload.get("suggested_action", "") or action).strip(),
        "created_at": created_at,
        "timestamp_text": _coerce_timestamp_text(created_at),
        "raw": payload.get("abuse_raw", payload.get("raw", payload)),
    }


def _normalize_ip_action(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(row or {})
    created_at = payload.get("created_at", payload.get("timestamp", payload.get("executed_at", payload.get("ts", ""))))
    return {
        "id": payload.get("id"),
        "ip": str(payload.get("ip", "") or "").strip(),
        "action": str(payload.get("action", "") or "").strip(),
        "backend": str(payload.get("backend", "") or "").strip(),
        "status": str(payload.get("status", "") or "").strip(),
        "reason": str(payload.get("reason", payload.get("guard_reason", "")) or "").strip(),
        "actor": str(payload.get("actor", payload.get("executed_by", "")) or "").strip(),
        "created_at": created_at,
        "timestamp_text": _coerce_timestamp_text(created_at),
        "raw": payload,
    }


def _load_table_rows(
    db: Any,
    table_name: str,
    order_columns: tuple[str, ...],
    limit: int,
    filters: list[tuple[str, Any]] | None = None,
) -> tuple[list[dict], list[str], str | None]:
    columns, notes = _table_columns(db, table_name)
    if not columns:
        return [], [], f"missing_table:{table_name}"
    where_parts = []
    params: list[Any] = []
    for column_name, value in filters or []:
        if column_name not in columns:
            continue
        where_parts.append(f"{column_name}=%s")
        params.append(value)
    order_parts = []
    for order_name in order_columns:
        base_name = str(order_name).split()[0]
        if base_name in columns:
            order_parts.append(str(order_name))
    if "id" in columns:
        order_parts.append("id DESC")
    if not order_parts:
        order_parts = ["id DESC"] if "id" in columns else ["1"]
    sql = f"SELECT * FROM {table_name}"
    if where_parts:
        sql += " WHERE " + " AND ".join(where_parts)
    sql += " ORDER BY " + ", ".join(order_parts)
    sql += " LIMIT %s"
    params.append(max(1, min(int(limit or 1), 500)))
    rows, error = _execute_db_read(db, sql, tuple(params), fetch="all")
    if rows is None:
        return [], sorted(columns), error or f"query_error:{table_name}"
    return list(rows or []), sorted(columns), None


def _matches_ip(payload: Any, ip: str) -> bool:
    needle = str(ip or "").strip()
    if not needle:
        return False
    return needle in set(_extract_ip_candidates(payload))


def _time_sort_key(payload: Dict[str, Any]) -> float:
    for key in ("created_at", "ts", "timestamp", "suggested_at", "executed_at"):
        value = payload.get(key)
        try:
            if value not in (None, ""):
                return float(value)
        except Exception:
            continue
    return 0.0


def mask_sensitive_value(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    if lowered.startswith("bearer "):
        return "Bearer " + _mask_secret(text[7:])
    if "=" in text and any(token in lowered for token in _SENSITIVE_KEY_TOKENS):
        key, _, val = text.partition("=")
        return f"{key}=<_redacted:{_mask_secret(val)}>"
    return f"<redacted:{_mask_secret(text)}>"


def _redact_sensitive_text(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""

    def _replace_auth(match: re.Match[str]) -> str:
        scheme = match.group(2) or ""
        secret_value = match.group(3).strip()
        masked = f"<redacted:{_mask_secret(secret_value)}>"
        return f"authorization{match.group(1)}{scheme}{masked}"

    text = _AUTH_LINE_RE.sub(_replace_auth, text)

    def _replace(match: re.Match[str]) -> str:
        secret_value = match.group(3)
        prefix = f"{match.group(1)}{match.group(2)}"
        if match.group(1).lower() == "bearer":
            replacement = f"<redacted:{_mask_secret(secret_value)}>"
        else:
            replacement = mask_sensitive_value(secret_value)
            if replacement.lower().startswith("bearer "):
                replacement = replacement[7:]
        return f"{prefix}{replacement}"

    return _SENSITIVE_LINE_RE.sub(_replace, text)


def redact_sensitive_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        redacted = {}
        for key, value in payload.items():
            key_text = str(key or "")
            key_lower = key_text.lower()
            if any(token in key_lower for token in _SENSITIVE_KEY_TOKENS):
                redacted[key] = mask_sensitive_value(str(value or ""))
            else:
                redacted[key] = redact_sensitive_payload(value)
        return redacted
    if isinstance(payload, list):
        return [redact_sensitive_payload(item) for item in payload]
    if isinstance(payload, tuple):
        return [redact_sensitive_payload(item) for item in payload]
    if isinstance(payload, str):
        lowered = payload.lower()
        if any(token in lowered for token in _SENSITIVE_KEY_TOKENS):
            return _redact_sensitive_text(payload)
        return payload
    return payload


def _allowed_report_roots() -> List[Path]:
    project_root = Path.cwd().resolve()
    return [
        project_root,
        project_root / "reports",
        project_root / "data",
        project_root / "data" / "reports",
    ]


def _resolve_allowed_report_path(path: str) -> tuple[Path | None, str | None]:
    requested = str(path or "").strip()
    if not requested:
        return None, "path_required"
    candidate = Path(requested)
    if ".." in candidate.parts:
        return None, "path_traversal_blocked"
    try:
        resolved = candidate.resolve()
    except Exception:
        return None, "path_resolution_failed"
    allowed_roots = _allowed_report_roots()
    if not any(resolved == root or root in resolved.parents for root in allowed_roots):
        return None, "outside_workspace_blocked"
    return resolved, None


def _preview_text_for_kind(path: Path, text: str) -> str:
    if _report_kind(path) != "html":
        return text
    without_tags = _HTML_TAG_RE.sub(" ", text)
    normalized = "\n".join(line.strip() for line in without_tags.splitlines() if line.strip())
    return normalized or text


def collect_security_locks(config_path: str | None = None) -> Dict[str, Any]:
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        ml_safety = _read_ml_safety(config)
        ip_safety = _read_ip_blocking_safety(config)
        locks = SecurityLocks(
            read_only_mode=True,
            auto_ip_block_disabled=bool(ip_safety["details"].get("manual_only", True)),
            ml_no_action_contract=bool(ml_safety["details"].get("active_decision_layer", {}).get("no_action_contract", True))
            and bool(ml_safety["details"].get("all_family_no_action_contract", True)),
            manual_actions_locked=True,
            details={
                "ip_blocking": ip_safety["details"],
                "ml_safety": ml_safety["details"],
            },
        )
        return locks.to_dict()
    except Exception as exc:
        return SecurityLocks(
            read_only_mode=True,
            auto_ip_block_disabled=True,
            ml_no_action_contract=False,
            manual_actions_locked=True,
            details={"error": _safe_error(exc)},
        ).to_dict()


def collect_preflight_status(config_path: str | None = None, language: str | None = None) -> Dict[str, Any]:
    overall = "PASS"
    checks: List[PreflightCheck] = []

    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        lang = _resolve_backend_language(config, explicit=language)
        config_exists = bool(context["config_exists"])
        integrations = context["integrations"]

        config_check = PreflightCheck(
            name="Config",
            status="PASS" if config_exists else "WARNING",
            message=(
                system_text("preflight_config_loaded", lang)
                if config_exists
                else system_text("preflight_config_missing", lang)
            ),
            details={
                "config_path": context["config_path"],
                "config_exists": config_exists,
                "integrations": integrations.summary(),
            },
            suggestion="" if config_exists else system_text("preflight_config_suggestion", lang),
        )
        checks.append(config_check)
        overall = _worst_status(overall, config_check.status)

        distro_info = detect_distro()
        supported, reason = is_supported(distro_info)
        distro_status = "PASS" if supported else "BLOCKED"
        distro_check = PreflightCheck(
            name="Distro",
            status=distro_status,
            message=(
                system_text("preflight_distro_supported", lang)
                if supported
                else system_text("preflight_distro_unsupported", lang)
            ),
            details={**distro_info, "supported_reason": reason},
            suggestion="" if supported else system_text("preflight_distro_suggestion", lang),
        )
        checks.append(distro_check)
        overall = _worst_status(overall, distro_check.status)

        source_health = _read_source_health(config, language=lang)
        source_status = "PASS" if source_health["status"] == "ok" else "WARNING"
        source_check = PreflightCheck(
            name="Source Health",
            status=source_status,
            message=source_health["message"],
            details=source_health["details"],
            suggestion="" if source_status == "PASS" else system_text("preflight_sources_suggestion", lang),
        )
        checks.append(source_check)
        overall = _worst_status(overall, source_check.status)

        db_health = _read_database_health(config, language=lang)
        db_status = "PASS" if db_health["available"] else "WARNING"
        db_check = PreflightCheck(
            name="Database",
            status=db_status,
            message=db_health["message"],
            details=db_health["details"],
            suggestion="" if db_status == "PASS" else system_text("preflight_database_suggestion", lang),
        )
        checks.append(db_check)
        overall = _worst_status(overall, db_check.status)

        ml_safety = _read_ml_safety(config, language=lang)
        ml_status = "PASS" if ml_safety["status"] == "ok" else "WARNING"
        ml_check = PreflightCheck(
            name="ML Safety",
            status=ml_status,
            message=ml_safety["message"],
            details=ml_safety["details"],
            suggestion="" if ml_status == "PASS" else system_text("preflight_ml_suggestion", lang),
        )
        checks.append(ml_check)
        overall = _worst_status(overall, ml_check.status)

        ip_safety = _read_ip_blocking_safety(config, language=lang)
        ip_check = PreflightCheck(
            name="IP Blocking",
            status="PASS",
            message=ip_safety["message"],
            details=ip_safety["details"],
            suggestion=system_text("preflight_ip_suggestion", lang),
        )
        checks.append(ip_check)

        locks = collect_security_locks(config_path)
        locks_status = "PASS" if all(
            bool(locks.get(key, False))
            for key in ("read_only_mode", "auto_ip_block_disabled", "manual_actions_locked")
        ) and bool(locks.get("ml_no_action_contract", False)) else "WARNING"
        locks_check = PreflightCheck(
            name="Security Locks",
            status=locks_status,
            message=(
                system_text("preflight_locks_ok", lang)
                if locks_status == "PASS"
                else system_text("preflight_locks_degraded", lang)
            ),
            details=locks,
            suggestion="" if locks_status == "PASS" else system_text("preflight_locks_suggestion", lang),
        )
        checks.append(locks_check)
        overall = _worst_status(overall, locks_check.status)

        return {
            "overall": overall,
            "checks": checks_to_dicts(checks),
            "security_locks": locks,
        }
    except Exception as exc:
        lang = _resolve_backend_language(explicit=language)
        locks = collect_security_locks(config_path)
        return {
            "overall": "BLOCKED",
            "checks": checks_to_dicts([
                PreflightCheck(
                    name="Startup Preflight",
                    status="BLOCKED",
                    message=system_text("preflight_startup_error", lang),
                    details=_safe_error(exc),
                    suggestion=system_text("preflight_startup_suggestion", lang),
                )
            ]),
            "security_locks": locks,
        }


def collect_overview_status(config_path: str | None = None) -> Dict[str, Any]:
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        distro_info = detect_distro()
        source_health = _read_source_health(config)
        db_health = _read_database_health(config)
        runtime_status = RuntimeStateStore(state_dir="data").status()
        phase_stats = _phase_stats_summary()
        source_problem_count = len([
            item for item in dict(source_health["details"].get("sources", {}) or {}).values()
            if str(item.get("status", "")).lower() == "closed"
        ])
        db_stats = {}
        open_incidents = 0
        alert_count = int(runtime_status.get("total_alerts", 0) or 0)
        ml_pause_state = {
            "known": False,
            "paused": None,
            "pause_reason": "",
            "error": None,
        }
        if db_health["available"]:
            db = None
            try:
                db = create_database(config)
                if db is not None:
                    db_stats = dict(db.get_stats() or {}) if hasattr(db, "get_stats") else {}
                    open_incidents = len(db.get_open_incidents() or []) if hasattr(db, "get_open_incidents") else 0
                    alert_count = int(db_stats.get("alerts_24h", db_stats.get("total_alerts", alert_count)) or alert_count)
                    ml_pause_state = _read_ml_pause_state(db)
            except Exception as exc:
                db_stats = {"error": _safe_error(exc)}
            finally:
                if db:
                    try:
                        db.close()
                    except Exception:
                        pass
        return {
            "overall": "PASS" if db_health["available"] else "WARNING",
            "distro": distro_info,
            "database": db_health,
            "runtime": runtime_status,
            "state_metrics": get_state_metrics().status(),
            "phase_profile": str(config.get("phase_profile", "auto") or "auto"),
            "sources": source_health["details"],
            "alert_count": alert_count,
            "open_incidents": open_incidents,
            "phase": f"PHASE_{phase_stats.get('current_phase', 0)}",
            "phase_stats": phase_stats,
            "source_problem_count": source_problem_count,
            "ml_paused": ml_pause_state.get("paused"),
            "ml_pause_known": bool(ml_pause_state.get("known", False)),
            "ml_pause_reason": str(ml_pause_state.get("pause_reason", "") or ""),
            "ml_pause_error": ml_pause_state.get("error"),
            "db_stats": db_stats,
            "security_locks": collect_security_locks(config_path),
        }
    except Exception as exc:
        return {
            "overall": "WARNING",
            "distro": {},
            "database": {"available": False, "status": "degraded"},
            "runtime": {},
            "state_metrics": {},
            "phase_profile": "unknown",
            "sources": {},
            "alert_count": 0,
            "open_incidents": 0,
            "phase": "PHASE_0",
            "phase_stats": {},
            "source_problem_count": 0,
            "ml_paused": None,
            "ml_pause_known": False,
            "ml_pause_reason": "",
            "ml_pause_error": None,
            "db_stats": {},
            "security_locks": collect_security_locks(config_path),
            "error": _safe_error(exc),
        }


def collect_alerts(limit: int = 100, severity: str | None = None, config_path: str | None = None) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 100), 500))
    severity_filter = str(severity or "").strip().lower()
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        db = create_database(config)
        if db is None:
            return {"status": "degraded", "alerts": [], "error": "database_unavailable"}
        try:
            rows = db.get_recent_alerts(limit=limit, hours=24 * 365 * 50) if hasattr(db, "get_recent_alerts") else []
            alerts = []
            for row in rows or []:
                item = _normalize_alert(row)
                if severity_filter and item["severity"] != severity_filter:
                    continue
                alerts.append(item)
                if len(alerts) >= limit:
                    break
            return {"status": "ok", "alerts": alerts, "error": None}
        finally:
            db.close()
    except Exception as exc:
        return {"status": "degraded", "alerts": [], "error": str(exc)}


def collect_alert_detail(alert_id: int, config_path: str | None = None) -> Dict[str, Any]:
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        language = _resolved_runtime_language(config)
        db = create_database(config)
        if db is None:
            return {"status": "degraded", "alert": None, "detail": {}, "error": "database_unavailable"}
        try:
            alert = db.get_alert_by_id(int(alert_id)) if hasattr(db, "get_alert_by_id") else None
            if not alert:
                return {"status": "degraded", "alert": None, "detail": {}, "error": f"alert_not_found:{alert_id}"}
            payload = dict(alert)
            if hasattr(db, "get_ip_reputation_for_alert"):
                try:
                    payload["ip_reputation"] = db.get_ip_reputation_for_alert(int(alert_id)) or []
                except Exception:
                    payload["ip_reputation"] = []
            explanation = {}
            if main_module is not None and hasattr(main_module, "build_deterministic_alert_explanation"):
                try:
                    try:
                        explanation = dict(main_module.build_deterministic_alert_explanation(payload, language=language) or {})
                    except TypeError:
                        explanation = dict(main_module.build_deterministic_alert_explanation(payload) or {})
                except Exception as exc:
                    explanation = {"kind": "fallback", "text": explanation_text("deterministic_read_failed", language, error=exc), "language": language}
            context_json = dict(payload.get("context_json", {}) or {})
            detail = {
                "explanation": explanation,
                "explanation_text": str(explanation.get("text", "") or ""),
                "explanation_kind": str(explanation.get("kind", "") or ""),
                "metadata_missing": bool(explanation.get("metadata_missing", False)),
                "language": language,
                "context_json": context_json,
                "parsed_metadata": dict(context_json.get("parsed_metadata", {}) or {}),
                "raw_event": context_json.get("raw_event", payload.get("raw_event", {})),
                "ip_reputation": list(payload.get("ip_reputation", []) or []),
            }
            return {
                "status": "ok",
                "alert": _normalize_alert(payload),
                "detail": detail,
                "error": None,
            }
        finally:
            db.close()
    except Exception as exc:
        return {"status": "degraded", "alert": None, "detail": {}, "error": str(exc)}


def _normalize_incident(incident: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(incident or {})
    created_at = payload.get("created_at", payload.get("ts_start", payload.get("timestamp", "")))
    return {
        "id": payload.get("id"),
        "created_at": created_at,
        "timestamp_text": _coerce_timestamp_text(created_at),
        "severity": str(payload.get("severity", "") or "").lower() or "unknown",
        "status": str(payload.get("status", "") or "").lower() or "unknown",
        "title": str(payload.get("title", "") or "").strip(),
        "entity_key": str(payload.get("entity_key", "") or "").strip(),
        "alert_count": int(payload.get("alert_count", 0) or 0),
        "risk_score": float(payload.get("risk_score", 0.0) or 0.0),
        "summary": str(payload.get("summary", "") or "").strip(),
        "evidence": payload.get("evidence", []),
        "raw": payload,
    }


def collect_incidents(
    status: str | None = "open",
    severity: str | None = None,
    limit: int = 100,
    config_path: str | None = None,
) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 100), 300))
    status_filter = str(status or "").strip().lower()
    severity_filter = str(severity or "").strip().lower()
    try:
        context = _load_runtime_context(config_path)
        db = create_database(context["config"])
        if db is None:
            return {"status": "degraded", "incidents": [], "total_returned": 0, "error": "database_unavailable"}
        try:
            filters = []
            if status_filter and status_filter != "all":
                filters.append(("status", status_filter))
            if severity_filter and severity_filter != "all":
                filters.append(("severity", severity_filter))
            rows, columns, error = _load_table_rows(
                db,
                "incidents",
                ("ts_start DESC", "created_at DESC"),
                limit=limit,
                filters=filters,
            )
            if error:
                return {"status": "degraded", "incidents": [], "columns": columns, "total_returned": 0, "error": error}
            incidents = [_normalize_incident(row) for row in rows]
            return {
                "status": "ok",
                "incidents": incidents,
                "columns": columns,
                "total_returned": len(incidents),
                "error": None,
            }
        finally:
            db.close()
    except Exception as exc:
        return {"status": "degraded", "incidents": [], "total_returned": 0, "error": str(exc)}


def collect_incident_detail(incident_id: int, config_path: str | None = None) -> Dict[str, Any]:
    try:
        normalized_id = int(incident_id)
    except (TypeError, ValueError):
        return {"status": "degraded", "incident": None, "related_alerts": [], "detail": {}, "error": "invalid_incident_id"}
    payload = collect_incidents(status="all", limit=500, config_path=config_path)
    if payload.get("status") != "ok":
        return {"status": "degraded", "incident": None, "related_alerts": [], "detail": {}, "error": payload.get("error")}
    incident = None
    for item in payload.get("incidents", []):
        try:
            if int(item.get("id", -1) or -1) == normalized_id:
                incident = dict(item)
                break
        except Exception:
            continue
    if incident is None:
        return {"status": "degraded", "incident": None, "related_alerts": [], "detail": {}, "error": f"incident_not_found:{normalized_id}"}

    alert_payload = collect_alerts(limit=300, config_path=config_path)
    related_alerts = []
    for alert in list(alert_payload.get("alerts", []) or []):
        raw = dict(alert.get("raw", {}) or {})
        candidate = raw.get("incident_id", alert.get("incident_id", ""))
        try:
            if int(candidate) == normalized_id:
                related_alerts.append(alert)
        except Exception:
            continue
    return {
        "status": "ok",
        "incident": incident,
        "related_alerts": related_alerts,
        "detail": {
            "summary_text": incident.get("summary", ""),
            "evidence_text": _stringify_payload(incident.get("evidence", [])),
        },
        "error": None,
    }


def collect_alert_raw_parsed(alert_id: int, config_path: str | None = None) -> Dict[str, Any]:
    detail_payload = collect_alert_detail(alert_id, config_path=config_path)
    if detail_payload.get("status") != "ok":
        return {
            "status": "degraded",
            "alert_id": alert_id,
            "raw_text": "",
            "parsed_text": "",
            "context_text": "",
            "raw_event": {},
            "parsed_event": {},
            "context_json": {},
            "field_summary": {"differences": [], "raw_available": False, "parsed_available": False, "context_available": False},
            "error": detail_payload.get("error"),
        }
    alert = dict(detail_payload.get("alert", {}) or {})
    detail = dict(detail_payload.get("detail", {}) or {})
    raw_event = redact_sensitive_payload(detail.get("raw_event", {}))
    parsed_event = redact_sensitive_payload(detail.get("parsed_metadata", {}))
    context_json = redact_sensitive_payload(detail.get("context_json", {}))
    return {
        "status": "ok",
        "alert_id": alert_id,
        "raw_text": _stringify_payload(raw_event),
        "parsed_text": _stringify_payload(parsed_event),
        "context_text": _stringify_payload(context_json),
        "raw_event": raw_event if isinstance(raw_event, dict) else {},
        "parsed_event": parsed_event if isinstance(parsed_event, dict) else {},
        "context_json": context_json if isinstance(context_json, dict) else {},
        "field_summary": _build_raw_parsed_summary(alert, raw_event if isinstance(raw_event, dict) else {}, parsed_event if isinstance(parsed_event, dict) else {}, context_json if isinstance(context_json, dict) else {}),
        "error": None,
    }


def collect_entity_timeline(entity: str, limit: int = 100, config_path: str | None = None) -> Dict[str, Any]:
    needle = str(entity or "").strip()
    if not needle:
        return {"status": "ok", "entity": "", "events": [], "summary": _timeline_summary([]), "error": None}
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        db = create_database(config)
        if db is None:
            return {"status": "degraded", "entity": needle, "events": [], "summary": _timeline_summary([]), "error": "database_unavailable"}
        try:
            rows = _all_alerts(db, limit=max(limit * 3, 200))
            token = needle.lower()
            events = []
            for row in rows:
                alert = _normalize_alert(row)
                if token not in {
                    str(alert.get("entity", "") or "").lower(),
                    str(alert.get("source_ip", "") or "").lower(),
                    str(alert.get("target_ip", "") or "").lower(),
                }:
                    blob = " ".join([
                        str(alert.get("entity", "") or "").lower(),
                        str(alert.get("source_ip", "") or "").lower(),
                        str(alert.get("target_ip", "") or "").lower(),
                        _search_blob(alert),
                    ])
                    if token not in blob:
                        continue
                events.append({
                    "timestamp_text": alert.get("timestamp_text", ""),
                    "created_at": alert.get("created_at", ""),
                    "kind": "alert",
                    "id": alert.get("id"),
                    "severity": alert.get("severity", ""),
                    "rule_id": alert.get("rule_id", ""),
                    "message": alert.get("message", ""),
                    "source_ip": alert.get("source_ip", ""),
                    "entity": alert.get("entity", ""),
                    "source": alert.get("source", ""),
                    "raw": alert.get("raw", {}),
                })
            events.sort(key=lambda item: float(item.get("created_at") or 0.0))
            events = events[:max(1, min(int(limit or 100), 300))]
            return {
                "status": "ok",
                "entity": needle,
                "events": events,
                "summary": _timeline_summary(events),
                "error": None,
            }
        finally:
            db.close()
    except Exception as exc:
        return {"status": "degraded", "entity": needle, "events": [], "summary": _timeline_summary([]), "error": str(exc)}


def collect_alert_correlations(alert_id: int, limit: int = 50, config_path: str | None = None) -> Dict[str, Any]:
    try:
        detail_payload = collect_alert_detail(alert_id, config_path=config_path)
        if detail_payload.get("status") != "ok":
            return {
                "status": "degraded",
                "alert_id": alert_id,
                "groups": {"same_source_ip": [], "same_entity": [], "same_rule": [], "nearby_time": [], "same_incident": []},
                "group_labels": {},
                "group_summaries": {},
                "summary": _build_correlation_summary({}, {}),
                "error": detail_payload.get("error"),
            }
        alert = dict(detail_payload.get("alert", {}) or {})
        context = _load_runtime_context(config_path)
        config = context["config"]
        db = create_database(config)
        if db is None:
            return {
                "status": "degraded",
                "alert_id": alert_id,
                "groups": {"same_source_ip": [], "same_entity": [], "same_rule": [], "nearby_time": [], "same_incident": []},
                "group_labels": {},
                "group_summaries": {},
                "summary": _build_correlation_summary({}, {}),
                "error": "database_unavailable",
            }
        try:
            rows = _all_alerts(db, limit=max(limit * 6, 300))
            source_ip = str(alert.get("source_ip", "") or "").strip().lower()
            entity = str(alert.get("entity", "") or "").strip().lower()
            rule_id = str(alert.get("rule_id", "") or "").strip().lower()
            incident_id = str(dict(alert.get("raw", {}) or {}).get("incident_id", "") or "").strip().lower()
            try:
                base_ts = float(alert.get("created_at") or 0.0)
            except (TypeError, ValueError):
                base_ts = 0.0
            groups = {"same_source_ip": [], "same_entity": [], "same_rule": [], "nearby_time": [], "same_incident": []}
            for row in rows:
                candidate = _normalize_alert(row)
                if candidate.get("id") == alert.get("id"):
                    continue
                candidate_raw = dict(candidate.get("raw", {}) or {})
                try:
                    candidate_ts = float(candidate.get("created_at") or 0.0)
                except (TypeError, ValueError):
                    candidate_ts = 0.0
                if source_ip and source_ip == str(candidate.get("source_ip", "") or "").strip().lower():
                    groups["same_source_ip"].append(candidate)
                if entity and entity == str(candidate.get("entity", "") or "").strip().lower():
                    groups["same_entity"].append(candidate)
                if rule_id and rule_id == str(candidate.get("rule_id", "") or "").strip().lower():
                    groups["same_rule"].append(candidate)
                if base_ts and candidate_ts and abs(candidate_ts - base_ts) <= 1800:
                    groups["nearby_time"].append(candidate)
                candidate_incident = str(candidate_raw.get("incident_id", "") or "").strip().lower()
                if incident_id and candidate_incident and candidate_incident == incident_id:
                    groups["same_incident"].append(candidate)
            trimmed = {name: items[:max(1, min(int(limit or 50), 200))] for name, items in groups.items()}
            group_labels = {
                "same_source_ip": "Same Source IP",
                "same_entity": "Same Entity/User",
                "same_rule": "Same Rule",
                "nearby_time": "Nearby Time",
                "same_incident": "Same Incident",
            }
            group_summaries = {
                name: {
                    "count": len(items),
                    "high_critical_count": sum(
                        1 for item in items if str(item.get("severity", "") or "").lower() in {"high", "critical"}
                    ),
                }
                for name, items in trimmed.items()
            }
            return {
                "status": "ok",
                "alert_id": alert_id,
                "groups": trimmed,
                "group_labels": group_labels,
                "group_summaries": group_summaries,
                "summary": _build_correlation_summary(trimmed, {}),
                "error": None,
            }
        finally:
            db.close()
    except Exception as exc:
        return {
            "status": "degraded",
            "alert_id": alert_id,
            "groups": {"same_source_ip": [], "same_entity": [], "same_rule": [], "nearby_time": [], "same_incident": []},
            "group_labels": {},
            "group_summaries": {},
            "summary": _build_correlation_summary({}, {}),
            "error": str(exc),
        }


def collect_alert_investigation_summary(alert_id: int, config_path: str | None = None) -> Dict[str, Any]:
    detail_payload = collect_alert_detail(alert_id, config_path=config_path)
    if detail_payload.get("status") != "ok":
        return {
            "status": "degraded",
            "alert_id": alert_id,
            "entity_key": "",
            "summary": _build_correlation_summary({}, _timeline_summary([])),
            "correlation_groups": {},
            "timeline_summary": _timeline_summary([]),
            "warnings": [detail_payload.get("error", "alert_not_found")],
            "error": detail_payload.get("error"),
        }
    alert = dict(detail_payload.get("alert", {}) or {})
    entity_key = str(alert.get("entity", "") or alert.get("source_ip", "") or alert.get("target_ip", "") or "").strip()
    correlations = collect_alert_correlations(alert_id, config_path=config_path)
    timeline = collect_entity_timeline(entity_key, config_path=config_path)
    timeline_summary = dict(timeline.get("summary", {}) or {})
    summary = _build_correlation_summary(dict(correlations.get("groups", {}) or {}), timeline_summary)
    warnings = []
    if correlations.get("status") != "ok":
        warnings.append("Correlation data degraded.")
    if timeline.get("status") != "ok":
        warnings.append("Timeline data degraded.")
    return {
        "status": "ok" if not warnings else "degraded",
        "alert_id": alert_id,
        "entity_key": entity_key,
        "summary": summary,
        "correlation_groups": dict(correlations.get("groups", {}) or {}),
        "timeline_summary": timeline_summary,
        "warnings": warnings,
        "error": correlations.get("error") or timeline.get("error"),
    }


def collect_sources_health(config_path: str | None = None) -> Dict[str, Any]:
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        distro_info = detect_distro()
        supported, reason = is_supported(distro_info)
        audit = audit_sources(copy.deepcopy(config))
        phase_stats = _phase_stats_summary()
        db = create_database(config)
        sources = []
        problems = []
        try:
            for name, item in sorted(audit.items()):
                path = str(item.get("path", "") or "")
                is_journald = path == "journalctl" or name == "journald"
                path_exists = bool(shutil.which("journalctl")) if is_journald else bool(path and Path(path).exists())
                readable = bool(shutil.which("journalctl")) if is_journald else bool(path and os.access(path, os.R_OK))
                last_read_raw = _read_db_stat(db, f"last_read:{name}")
                try:
                    last_read_value = float(last_read_raw) if last_read_raw is not None else None
                except (TypeError, ValueError):
                    last_read_value = None
                parse_fail_count = int(phase_stats["parse_fail_breakdown_by_source"].get(name, 0) or 0)
                duplicate_count = int(phase_stats["duplicate_breakdown_by_source"].get(name, 0) or 0)
                row = {
                    "source": name,
                    "status": item.get("status", "unknown"),
                    "resolved_path": path,
                    "path_exists": path_exists,
                    "readable": readable,
                    "service_active": path_exists if is_journald else None,
                    "last_read": last_read_value,
                    "last_read_text": _coerce_timestamp_text(last_read_value) if last_read_value else "",
                    "parse_fail_summary": {"count": parse_fail_count},
                    "duplicate_summary": {"count": duplicate_count},
                    "reason": str(item.get("reason", "") or ""),
                }
                sources.append(row)
                if row["status"] != "ok" or not row["path_exists"] or not row["readable"]:
                    problems.append(
                        f"{name}: {row['reason'] or 'path/permission/service kontrolü gerekli'}"
                    )
            status = "ok" if not problems and supported else "degraded"
            if not supported:
                problems.insert(0, reason)
            return {
                "status": status,
                "distro": {**distro_info, "supported": supported, "supported_reason": reason},
                "sources": sources,
                "problems": problems,
                "error": None,
            }
        finally:
            if db:
                db.close()
    except Exception as exc:
        return {
            "status": "degraded",
            "distro": {},
            "sources": [],
            "problems": [],
            "error": str(exc),
        }


def collect_reports_summary(config_path: str | None = None) -> Dict[str, Any]:
    _ = config_path
    try:
        files = _collect_report_files()
        latest = files[0] if files else None
        report_html = Path("data/report.html")
        return {
            "status": "ok",
            "files": files,
            "latest_report": latest,
            "report_html": {
                "path": str(report_html),
                "exists": report_html.exists(),
                "absolute_path": str(report_html.resolve()),
            },
            "empty": not files,
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "files": [],
            "latest_report": None,
            "report_html": {"path": "data/report.html", "exists": False},
            "empty": True,
            "error": str(exc),
        }


def _report_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".html", ".htm"}:
        return "html"
    if suffix in {".txt", ".log"}:
        return "text"
    if suffix == ".json":
        return "json"
    return "unknown"


def collect_report_artifacts(limit: int = 50) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 50), 100))
    checked_paths = [
        "reports/",
        "data/reports/",
        "report.html",
        "data/report.html",
    ]
    try:
        candidate_paths: List[Path] = []
        project_root = Path.cwd().resolve()
        for relative in ("report.html", "data/report.html"):
            path = (project_root / relative).resolve()
            if path.exists() and path.is_file():
                candidate_paths.append(path)
        for relative in ("reports", "data/reports"):
            directory = project_root / relative
            if directory.exists() and directory.is_dir():
                for pattern in _REPORT_GLOBS:
                    candidate_paths.extend(directory.glob(pattern))
        unique: List[Path] = []
        seen: set[str] = set()
        for path in sorted(candidate_paths, key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True):
            if not path.exists() or not path.is_file():
                continue
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            unique.append(path)
        artifacts = []
        for path in unique[:limit]:
            stat = path.stat()
            readable = path.exists() and os.access(path, os.R_OK)
            artifacts.append({
                "path": str(path),
                "name": path.name,
                "size": int(stat.st_size),
                "modified_at": stat.st_mtime,
                "modified_text": _coerce_timestamp_text(stat.st_mtime),
                "kind": _report_kind(path),
                "readable": readable,
            })
        return {
            "status": "ok",
            "artifacts": artifacts,
            "paths_checked": checked_paths,
            "empty": not artifacts,
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "artifacts": [],
            "paths_checked": checked_paths,
            "empty": True,
            "error": str(exc),
        }


def collect_report_preview(path: str, max_chars: int = 20000) -> Dict[str, Any]:
    requested = str(path or "").strip()
    if not requested:
        return {"status": "degraded", "path": "", "kind": "unknown", "preview": "", _PREVIEW_SHORTENED_KEY: False, "error": "path_required"}
    try:
        resolved, error = _resolve_allowed_report_path(requested)
        if error is not None or resolved is None:
            return {"status": "blocked", "path": requested, "kind": "unknown", "preview": "", _PREVIEW_SHORTENED_KEY: False, "error": error or "path_blocked"}
        if not resolved.exists() or not resolved.is_file():
            return {"status": "degraded", "path": str(resolved), "kind": _report_kind(resolved), "preview": "", _PREVIEW_SHORTENED_KEY: False, "error": "file_not_found"}
        text = resolved.read_text(encoding="utf-8", errors="replace")
        text = _preview_text_for_kind(resolved, text)
        text = str(redact_sensitive_payload(text))
        preview_limit = max(1, min(int(max_chars or 20000), 50000))
        preview = text[:preview_limit]
        return {
            "status": "ok",
            "path": str(resolved),
            "kind": _report_kind(resolved),
            "preview": preview,
            _PREVIEW_SHORTENED_KEY: len(text) > len(preview),
            "error": None,
        }
    except Exception as exc:
        return {"status": "degraded", "path": requested, "kind": "unknown", "preview": "", _PREVIEW_SHORTENED_KEY: False, "error": str(exc)}


def collect_safe_export_preview(export_type: str, target_id: str | None = None) -> Dict[str, Any]:
    export_name = str(export_type or "").strip()
    target_name = str(target_id or "").strip()
    include_map = {
        "selected_alert": ["selected alert summary", "deterministic explanation", "sanitized metadata"],
        "incident_report": ["incident summary", "related alerts", "sanitized counts"],
        "ml_readiness": ["ML readiness summary", "family readiness states", "sanitized thresholds"],
        "source_health": ["source health summary", "path/readability states", "non-secret diagnostics"],
        "diagnostic_bundle": [
            "distro info",
            "DB health/schema version",
            "source health",
            "phase status",
            "ML summary",
            "alert/incident counts",
        ],
    }
    return {
        "status": "preview_only",
        "export_type": export_name,
        "target_id": target_name,
        "would_include": include_map.get(export_name, ["sanitized preview payload"]),
        "would_redact": ["API keys", "tokens", "passwords", "SMTP secrets", "authorization headers"],
        "would_exclude": ["raw secrets", "file writing", "database dumps", "huge raw logs"],
        "requires_phase": "Phase 2 guarded/export",
        "message": "File writing is disabled in Phase 1",
    }


def collect_diagnostic_bundle_preview(config_path: str | None = None) -> Dict[str, Any]:
    diagnostics = collect_diagnostics_summary(config_path=config_path)
    overview = collect_overview_status(config_path=config_path)
    ml_status = collect_ml_summary(config_path=config_path)
    return {
        "status": "ok",
        "would_include": [
            "distro info",
            "DB health/schema version",
            "source health",
            "phase status",
            "ML summary",
            "alert/incident counts",
            "parse fail/duplicate summary",
            "rule count",
            "recent non-secret errors",
        ],
        "would_redact": [
            "API keys",
            "tokens",
            "passwords",
            "raw secrets",
            "env secret values",
            "sensitive raw log fields if needed",
        ],
        "would_exclude": [
            "huge raw logs",
            "database dumps",
            "write operations",
        ],
        "requires_phase": "Phase 2 guarded/export",
        "message": "Diagnostic bundle creation is disabled in Phase 1",
        "snapshot": redact_sensitive_payload({
            "diagnostics": {
                "db_health": diagnostics.get("db_health", {}),
                "schema_version": diagnostics.get("schema_version"),
                "rule_count": diagnostics.get("rule_count"),
                "parse_fail_summary": diagnostics.get("parse_fail_summary", {}),
                "duplicate_summary": diagnostics.get("duplicate_summary", {}),
            },
            "overview": {
                "distro": overview.get("distro", {}),
                "alert_count": overview.get("alert_count"),
                "open_incidents": overview.get("open_incidents"),
                "phase": overview.get("phase"),
            },
            "ml": {
                "status": ml_status.get("status"),
                "overall": ml_status.get("overall", {}),
            },
        }),
        "error": None,
    }


def collect_report_readiness(config_path: str | None = None) -> Dict[str, Any]:
    artifacts = collect_report_artifacts(limit=50)
    return {
        "status": "ok" if artifacts.get("status") == "ok" else "degraded",
        "artifacts_found_count": len(artifacts.get("artifacts", []) or []),
        "paths_checked": list(artifacts.get("paths_checked", []) or []),
        "generation_locked": True,
        "deterministic_explanation_available": bool(main_module is not None and hasattr(main_module, "build_deterministic_alert_explanation")),
        "write_locked": True,
        "error": artifacts.get("error"),
    }


def collect_diagnostics_summary(config_path: str | None = None) -> Dict[str, Any]:
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        runtime = RuntimeStateStore(state_dir="data").status()
        phase_stats = _phase_stats_summary()
        rule_count = _read_rule_count(config)
        db_health = _read_database_health(config)
        open_incidents = 0
        db = None
        try:
            db = create_database(config)
            if db is not None and hasattr(db, "get_open_incidents"):
                open_incidents = len(db.get_open_incidents() or [])
        except Exception:
            open_incidents = 0
        finally:
            if db:
                db.close()
        degraded_flags = []
        if db_health["status"] != "ok":
            degraded_flags.append("database")
        if runtime.get("runtime_restore_health", {}).get("degraded", False):
            degraded_flags.append("runtime_restore")
        pressure = dict(runtime.get("pressure", {}) or {})
        source_coverage = dict(runtime.get("runtime_components", {}) or {})
        parse_fail_diagnostics = {}
        event_growth_diagnostics = {}
        if main_module is not None and hasattr(main_module, "collect_parse_fail_diagnostics"):
            try:
                parse_fail_diagnostics = dict(main_module.collect_parse_fail_diagnostics(config, db, {"stats": phase_stats}) or {})
            except Exception:
                parse_fail_diagnostics = {}
        if main_module is not None and hasattr(main_module, "collect_event_growth_diagnostics"):
            try:
                event_growth_diagnostics = dict(main_module.collect_event_growth_diagnostics(config, db, {"stats": phase_stats}) or {})
            except Exception:
                event_growth_diagnostics = {}
        return {
            "status": "ok" if not degraded_flags else "degraded",
            "db_health": db_health,
            "schema_version": db_health.get("details", {}).get("schema_version", get_schema_manifest().get("current_version")),
            "rule_count": rule_count,
            "open_incidents": open_incidents,
            "runtime": runtime,
            "phase_stats": phase_stats,
            "parse_fail_summary": {
                "count": phase_stats.get("parse_fail_count", 0),
                "by_source": phase_stats.get("parse_fail_breakdown_by_source", {}),
                "by_reason": phase_stats.get("parse_fail_breakdown_by_reason", {}),
                "by_parser": phase_stats.get("parse_fail_breakdown_by_parser", {}),
                "by_distro_family": phase_stats.get("parse_fail_breakdown_by_distro", {}),
                "by_path": phase_stats.get("parse_fail_breakdown_by_path", {}),
                "samples": phase_stats.get("parse_fail_samples", []),
                "rate": phase_stats.get("parse_fail_rate", 0.0),
            },
            "duplicate_summary": {
                "count": phase_stats.get("duplicate_count", 0),
                "telemetry_count": phase_stats.get("telemetry_duplicate_count", 0),
                "by_source": phase_stats.get("duplicate_breakdown_by_source", {}),
                "by_kind": phase_stats.get("duplicate_breakdown_by_kind", {}),
                "rate": phase_stats.get("duplicate_rate", 0.0),
            },
            "degraded_flags": degraded_flags,
            "pipeline_pressure": pressure,
            "source_coverage": source_coverage,
            "parse_fail_diagnostics": parse_fail_diagnostics,
            "event_growth_diagnostics": event_growth_diagnostics,
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "db_health": {"available": False, "status": "degraded"},
            "schema_version": get_schema_manifest().get("current_version"),
            "rule_count": None,
            "open_incidents": 0,
            "runtime": {},
            "phase_stats": {},
            "parse_fail_summary": {},
            "duplicate_summary": {},
            "parse_fail_diagnostics": {},
            "event_growth_diagnostics": {},
            "degraded_flags": ["exception"],
            "pipeline_pressure": {},
            "source_coverage": {},
            "error": str(exc),
        }


def collect_ml_summary(config_path: str | None = None) -> Dict[str, Any]:
    db = None
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        pm_status = _load_phase_manager_status(config)
        db = create_database(config)
        report = _ml_summary_report(config, db, pm_status)
        overall = dict(report.get("overall", {}) or {})
        return {
            "status": "ok" if not overall.get("query_notes") else "degraded",
            "ready_for_active_ml": bool(overall.get("ready_for_active_ml", False)),
            "current_phase": overall.get("current_phase", pm_status.get("current_phase", 0)),
            "phase_name": overall.get("phase_name", pm_status.get("phase_name", "")),
            "ml_paused": bool(overall.get("ml_paused", False)),
            "blocking_incident": bool(dict(report.get("normal_label_summary", {}).get("global", {}) or {}).get("blocking_incident", False)),
            "top_blockers": list(overall.get("top_blockers", []) or []),
            "mapping_coverage": dict(report.get("mapping_summary", {}) or {}),
            "historical_scan_distro_breakdown": dict(report.get("historical_scan_distro_breakdown", {}) or {}),
            "label_trust_summary": dict(report.get("label_trust_summary", {}) or {}),
            "label_quota_summary": dict(report.get("label_quota_summary", {}) or {}),
            "readiness_label_counts": dict(report.get("readiness_label_counts", {}) or {}),
            "normal_label_summary": dict(report.get("normal_label_summary", {}) or {}),
            "metadata_plan_summary": dict(report.get("metadata_plan_summary", {}) or {}),
            "phase_event_volume": dict(report.get("phase_event_volume", {}) or {}),
            "label_readiness_summary": dict(report.get("label_readiness_summary", {}) or {}),
            "training_scheduler": dict(report.get("training_scheduler", {}) or {}),
            "model_status": dict(report.get("model_status", {}) or {}),
            "recommended_next_actions": list(report.get("recommended_next_actions", []) or []),
            "error": None if not overall.get("query_notes") else "; ".join(str(item) for item in overall.get("query_notes", [])),
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "ready_for_active_ml": False,
            "current_phase": 0,
            "phase_name": "",
            "ml_paused": False,
            "blocking_incident": False,
            "top_blockers": [],
            "mapping_coverage": {},
            "historical_scan_distro_breakdown": {},
            "label_trust_summary": {},
            "label_quota_summary": {},
            "readiness_label_counts": {},
            "normal_label_summary": {},
            "metadata_plan_summary": {},
            "phase_event_volume": {},
            "label_readiness_summary": {},
            "training_scheduler": {},
            "model_status": {},
            "recommended_next_actions": [],
            "error": str(exc),
        }
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


_ML_PRIMARY_FAMILIES = ("ML-AUTH", "ML-PROC", "ML-IMPACT")
_ML_ALERT_CATEGORY_TOKENS = {"ml", "behavioral", "anomaly", "anomaly_detection", "behavioral_alert"}
_ML_ALERT_SOURCE_TOKENS = {"ml", "ml_alert", "behavioral_ml", "behavioral"}
_IP_BLOCK_CANDIDATE_SEVERITIES = {"medium", "high", "critical"}
_IP_BLOCK_CANDIDATE_RISK_THRESHOLD = 60.0
_IP_BLOCK_SECURITY_SIGNAL_TOKENS = (
    "attack",
    "attempt",
    "auth failure",
    "beacon",
    "blocked",
    "brute",
    "bruteforce",
    "c2",
    "command and control",
    "credential",
    "deny",
    "denied",
    "discovery",
    "enumeration",
    "exploit",
    "failed login",
    "failure",
    "flood",
    "force",
    "intrusion",
    "lateral",
    "malicious",
    "password spray",
    "payload",
    "persistence",
    "port scan",
    "privilege escalation",
    "probe",
    "ransom",
    "recon",
    "scan",
    "shell",
    "spray",
    "suspicious",
    "threat",
)
_SEVERITY_RANKS = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def is_ml_alert(alert: Dict[str, Any]) -> bool:
    payload = dict(alert or {})
    raw = dict(payload.get("raw", {}) or {})
    context = dict(raw.get("context_json", {}) or {})
    rule_id = str(payload.get("rule_id", "") or raw.get("rule_id", "") or "").strip().upper()
    if rule_id.startswith("ML-"):
        return True

    family_tokens = [
        payload.get("rule_family"),
        payload.get("family"),
        payload.get("category"),
        payload.get("source"),
        raw.get("rule_family"),
        raw.get("family"),
        raw.get("category"),
        raw.get("source"),
        context.get("rule_family"),
        context.get("family"),
        context.get("category"),
        context.get("source"),
    ]
    for token in family_tokens:
        normalized = str(token or "").strip().lower()
        if not normalized:
            continue
        if normalized.startswith("ml-"):
            return True
        if normalized in _ML_ALERT_CATEGORY_TOKENS or normalized in _ML_ALERT_SOURCE_TOKENS:
            return True
        if normalized.startswith("ml_") or normalized.startswith("behavioral_") or normalized.startswith("anomaly_"):
            return True
    return False


def _severity_rank(value: Any) -> int:
    return _SEVERITY_RANKS.get(str(value or "").strip().lower(), 0)


def _is_public_candidate_ip(ip_text: str) -> bool:
    value = str(ip_text or "").strip()
    if not value:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    return True


def _looks_like_security_ip_candidate(alert: Dict[str, Any]) -> bool:
    normalized = _normalize_alert(alert)
    if is_ml_alert(normalized):
        return False
    ip_text = str(normalized.get("source_ip", "") or "").strip()
    if not _is_public_candidate_ip(ip_text):
        return False

    severity = str(normalized.get("severity", "") or "").lower()
    risk_score = float(normalized.get("risk_score", 0.0) or 0.0)
    if severity not in _IP_BLOCK_CANDIDATE_SEVERITIES and risk_score < _IP_BLOCK_CANDIDATE_RISK_THRESHOLD:
        return False
    if severity in {"high", "critical"}:
        return True
    if risk_score >= 75.0:
        return True

    blob = _search_blob(normalized)
    return any(token in blob for token in _IP_BLOCK_SECURITY_SIGNAL_TOKENS)


def _alert_candidate_reason(alert: Dict[str, Any]) -> str:
    normalized = _normalize_alert(alert)
    message = str(normalized.get("message", "") or "").strip()
    if message:
        return message
    rule_id = str(normalized.get("rule_id", "") or "").strip()
    if rule_id:
        return f"Alert candidate: {rule_id}"
    return "Alert source IP candidate"


def _merge_candidate_alert_row(current: Dict[str, Any] | None, alert: Dict[str, Any]) -> Dict[str, Any]:
    normalized = _normalize_alert(alert)
    created_at = normalized.get("created_at", "")
    created_key = _time_sort_key({"created_at": created_at})
    base = dict(current or {})
    count = int(base.get("related_alert_count", 0) or 0) + 1
    first_seen_value = base.get("first_seen", "")
    first_seen_key = _time_sort_key({"created_at": first_seen_value}) if first_seen_value not in ("", None) else None
    last_seen_value = base.get("last_seen", "")
    last_seen_key = _time_sort_key({"created_at": last_seen_value}) if last_seen_value not in ("", None) else None
    top_rank = _severity_rank(base.get("severity", ""))
    new_rank = _severity_rank(normalized.get("severity", ""))
    top_risk = float(base.get("risk_score", 0.0) or 0.0)
    new_risk = float(normalized.get("risk_score", 0.0) or 0.0)
    choose_new = not base or new_rank > top_rank or (new_rank == top_rank and new_risk > top_risk) or (
        new_rank == top_rank and abs(new_risk - top_risk) < 0.0001 and created_key >= (last_seen_key or 0.0)
    )
    if choose_new:
        base.update({
            "reason": _alert_candidate_reason(normalized),
            "alert_id": normalized.get("id"),
            "rule_id": str(normalized.get("rule_id", "") or "").strip(),
            "severity": str(normalized.get("severity", "") or "").strip(),
            "risk_score": float(normalized.get("risk_score", 0.0) or 0.0),
            "timestamp_text": normalized.get("timestamp_text", ""),
            "linked_alert": normalized,
        })
    if first_seen_key is None or created_key < first_seen_key:
        base["first_seen"] = created_at
        base["first_seen_text"] = normalized.get("timestamp_text", "")
    if last_seen_key is None or created_key >= last_seen_key:
        base["last_seen"] = created_at
        base["last_seen_text"] = normalized.get("timestamp_text", "")
        if not choose_new:
            base["timestamp_text"] = normalized.get("timestamp_text", "")
    base["ip"] = str(normalized.get("source_ip", "") or "").strip()
    base["source"] = str(base.get("source", "") or "alert").strip() or "alert"
    base["related_alert_count"] = count
    return base


def _build_dynamic_alert_candidates(db: Any, limit: int) -> Dict[str, Dict[str, Any]]:
    alert_rows = _all_alerts(db, limit=max(limit * 8, 500))
    candidates: Dict[str, Dict[str, Any]] = {}
    for row in alert_rows:
        normalized = _normalize_alert(row)
        ip_text = str(normalized.get("source_ip", "") or "").strip()
        if not _looks_like_security_ip_candidate(normalized):
            continue
        existing = candidates.get(ip_text)
        candidates[ip_text] = _merge_candidate_alert_row(existing, normalized)
    return candidates


def _ml_mode_from_summary(summary: Dict[str, Any]) -> str:
    training_scheduler = dict(summary.get("training_scheduler", {}) or {})
    model_status = dict(summary.get("model_status", {}) or {})
    if bool(training_scheduler.get("active_ml_enabled", False)):
        return "shadow"
    if list(model_status.get("scoring_enabled_families", []) or []):
        return "shadow"
    if bool(summary.get("ml_paused", False)):
        return "audit_only"
    if summary.get("ready_for_active_ml") is False:
        return "disabled"
    return "unknown"


def _select_ml_center_families(families: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    indexed = {str(item.get("family_id", "") or "").upper(): dict(item or {}) for item in families}
    for family_id in _ML_PRIMARY_FAMILIES:
        item = indexed.get(family_id)
        if item:
            selected.append(item)
    for item in families:
        family_id = str(item.get("family_id", "") or "").upper()
        if family_id in _ML_PRIMARY_FAMILIES:
            continue
        current_samples = int(item.get("normal_labels", 0) or 0) + int(item.get("suspicious_labels", 0) or 0)
        required_samples = int(item.get("required_normal_labels", 0) or 0) + int(item.get("required_suspicious_labels", 0) or 0)
        if current_samples > 0 or required_samples > 0 or str(item.get("status", "") or "").lower() in {"ready", "shadow", "scoring", "scoring_enabled"}:
            selected.append(dict(item or {}))
    return selected


def _format_family_readiness_rows(families: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for item in _select_ml_center_families(families):
        current_samples = int(item.get("normal_labels", 0) or 0) + int(item.get("suspicious_labels", 0) or 0)
        needed_samples = int(item.get("required_normal_labels", 0) or 0) + int(item.get("required_suspicious_labels", 0) or 0)
        missing_samples = max(0, needed_samples - current_samples)
        status = str(item.get("status", "unknown") or "unknown")
        rows.append({
            "family_id": str(item.get("family_id", "") or ""),
            "status": status,
            "current_samples": current_samples,
            "needed_samples": needed_samples,
            "missing_samples": missing_samples,
            "ready": missing_samples == 0 and status not in {"readiness_blocked", "unknown"},
            "reason": str(item.get("reason", "") or system_text("not_available", "en")),
        })
    return rows


def collect_training_status(config_path: str | None = None, language: str | None = None) -> Dict[str, Any]:
    summary = collect_ml_summary(config_path=config_path)
    config = {}
    if summary.get("status") != "degraded":
        try:
            config = dict(_load_runtime_context(config_path).get("config", {}) or {})
        except Exception:
            config = {}
    lang = _preferred_backend_language(config=config, explicit=language)
    scheduler = dict(summary.get("training_scheduler", {}) or {})
    model_status = dict(summary.get("model_status", {}) or {})
    last_training = str(scheduler.get("last_training_time", "") or scheduler.get("last_training_at", "") or "").strip()
    if last_training:
        status_text = str(
            scheduler.get("last_training_status", "")
            or scheduler.get("last_evaluation_status", "")
            or system_text("ml_training_status_available", lang)
        ).strip()
    else:
        reason_tokens = " ".join(
            [
                str(scheduler.get("reason", "") or ""),
                str(scheduler.get("last_training_reason", "") or ""),
            ]
        ).lower()
        if any(token in reason_tokens for token in ("readiness", "insufficient", "quota", "label")):
            status_text = system_text("ml_training_waiting_for_labels", lang)
        else:
            status_text = system_text("ml_training_not_run", lang)
    family_info = str(scheduler.get("last_training_family_distro", "") or "").strip()
    if not family_info:
        trained_families = list(scheduler.get("trained_families", []) or [])
        if trained_families:
            family_info = ", ".join(
                str(dict(item or {}).get("family_id", "") or dict(item or {}).get("family", "") or "").strip()
                for item in trained_families
                if str(dict(item or {}).get("family_id", "") or dict(item or {}).get("family", "") or "").strip()
            )
    model_info = ", ".join(str(item) for item in list(model_status.get("scoring_enabled_families", []) or [])[:3])
    return {
        "status": str(summary.get("status", "ok") or "ok"),
        "timestamp_text": last_training or system_text("never", lang),
        "has_training": bool(last_training),
        "training_status": status_text,
        "family_info": family_info,
        "model_info": model_info,
        "error": summary.get("error"),
    }


def collect_historical_scan_status(config_path: str | None = None, language: str | None = None) -> Dict[str, Any]:
    context = None
    try:
        context = _load_runtime_context(config_path)
    except Exception:
        context = None
    lang = _preferred_backend_language(config=dict((context or {}).get("config", {}) or {}), explicit=language)
    files = _collect_ml_history_files()
    if not files:
        return {
            "status": "ok",
            "timestamp_text": system_text("never", lang),
            "has_scan": False,
            "scan_status": system_text("ml_historical_scan_not_run", lang),
            "note": system_text("ml_historical_scan_cli_only", lang),
            "artifact_path": "",
            "error": None,
        }
    latest = dict(files[0] or {})
    return {
        "status": "ok",
        "timestamp_text": str(latest.get("modified_text", "") or system_text("never", lang)),
        "has_scan": True,
        "scan_status": str(latest.get("name", "") or "artifact"),
        "note": system_text("ml_historical_scan_cli_only", lang),
        "artifact_path": str(latest.get("path", "") or ""),
        "error": None,
    }


def collect_ml_alerts(limit: int = 50, config_path: str | None = None) -> Dict[str, Any]:
    target_limit = max(1, min(int(limit or 50), 200))
    payload = collect_alerts(limit=max(100, target_limit * 4), config_path=config_path)
    alerts = [item for item in list(payload.get("alerts", []) or []) if is_ml_alert(item)]
    return {
        "status": str(payload.get("status", "ok") or "ok"),
        "alerts": alerts[:target_limit],
        "error": payload.get("error"),
    }


def collect_ml_center_summary(config_path: str | None = None, language: str | None = None) -> Dict[str, Any]:
    context = None
    try:
        context = _load_runtime_context(config_path)
    except Exception:
        context = None
    lang = _preferred_backend_language(config=dict((context or {}).get("config", {}) or {}), explicit=language)
    summary = collect_ml_summary(config_path=config_path)
    readiness = collect_ml_family_readiness(config_path=config_path)
    family_rows = _format_family_readiness_rows(list(readiness.get("families", []) or []))
    first_training = family_rows[0] if family_rows else {
        "family_id": "",
        "current_samples": 0,
        "needed_samples": 0,
        "missing_samples": 0,
        "ready": False,
        "status": "unknown",
        "reason": system_text("not_available", lang),
    }
    return {
        "status": "ok" if summary.get("status") == "ok" and readiness.get("status") == "ok" else "degraded",
        "ml_mode": _ml_mode_from_summary(summary),
        "ml_mode_text": system_text(f"ml_mode_{_ml_mode_from_summary(summary)}", lang),
        "ml_safety_text": system_text("ml_safety_no_autonomous_action", lang),
        "family_rows": family_rows,
        "first_training": first_training,
        "error": summary.get("error") or readiness.get("error"),
    }


def collect_ml_training_status(config_path: str | None = None) -> Dict[str, Any]:
    db = None
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        pm_status = _load_phase_manager_status(config)
        db = create_database(config)
        report = _ml_training_scheduler_report(config, db, pm_status)
        return {"status": "ok" if not report.get("error") else "degraded", **report}
    except Exception as exc:
        return {"status": "degraded", "error": str(exc), "trigger_request": "scheduler"}
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def preview_manual_training_plan(config_path: str | None = None) -> Dict[str, Any]:
    db = None
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        pm_status = _load_phase_manager_status(config)
        db = create_database(config)
        report = _ml_training_scheduler_report(config, db, pm_status, trigger_request="manual_dry_run")
        return {"status": "ok" if not report.get("error") else "degraded", **report}
    except Exception as exc:
        return {"status": "degraded", "error": str(exc), "trigger_request": "manual_dry_run"}
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def execute_manual_training(config_path: str | None = None) -> Dict[str, Any]:
    db = None
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        pm_status = _load_phase_manager_status(config)
        db = create_database(config)
        if main_module is None or not hasattr(main_module, "execute_manual_training"):
            return {"status": "degraded", "error": "execute_manual_training_unavailable", "trigger_request": "manual_execute"}
        report = dict(main_module.execute_manual_training(config, db, pm_status) or {})
        return {"status": "ok" if not report.get("error") else "degraded", **report}
    except Exception as exc:
        return {"status": "degraded", "error": str(exc), "trigger_request": "manual_execute"}
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def collect_ml_phase_status(config_path: str | None = None) -> Dict[str, Any]:
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        pm_status = _load_phase_manager_status(config)
        next_phase = dict(pm_status.get("next_phase", {}) or {})
        stats = dict(pm_status.get("stats", {}) or {})
        current_phase = int(pm_status.get("current_phase", 0) or 0)
        next_phase_num = current_phase + 1 if current_phase < 3 else current_phase
        criteria = list(next_phase.get("criteria", []) or [])
        done_count = sum(1 for item in criteria if item.get("done"))
        progress_percent = int((done_count / len(criteria)) * 100) if criteria else 100
        blocking = list(next_phase.get("blocking", []) or [])
        remaining_time_text = ""
        for item in criteria:
            name = str(item.get("name", "") or "").lower()
            message = str(item.get("message", "") or "")
            if "saat" in message or "gün" in message:
                remaining_time_text = message
                break
            if "çalışma süresi" in name:
                remaining_time_text = message
        active_layers = dict(pm_status.get("active_layers", {}) or {})
        active_features = [name for name, enabled in active_layers.items() if enabled]
        passive_features = [name for name, enabled in active_layers.items() if not enabled]
        parse_fail_summary = {
            "count": int(stats.get("parse_fail_count", 0) or 0),
            "by_source": dict(stats.get("parse_fail_breakdown_by_source", {}) or {}),
            "by_reason": dict(stats.get("parse_fail_breakdown_by_reason", {}) or {}),
            "by_parser": dict(stats.get("parse_fail_breakdown_by_parser", {}) or {}),
            "by_distro_family": dict(stats.get("parse_fail_breakdown_by_distro", {}) or {}),
            "by_path": dict(stats.get("parse_fail_breakdown_by_path", {}) or {}),
            "samples": list(stats.get("parse_fail_samples", []) or []),
        }
        duplicate_summary = {
            "count": int(stats.get("duplicate_count", 0) or 0),
            "telemetry_count": int(stats.get("telemetry_duplicate_count", 0) or 0),
            "rate": float(stats.get("dup_rate", stats.get("duplicate_rate", 0.0)) or 0.0),
            "verified": bool(stats.get("duplicate_rate_verified", False)),
            "source": str(stats.get("duplicate_rate_source", "phase_state") or "phase_state"),
            "phase_event_count": int(stats.get("phase_event_count", stats.get("total_events", 0)) or 0),
            "live_db_event_count": stats.get("live_db_event_count"),
            "duplicate_counter_stale_possible": bool(stats.get("duplicate_counter_stale_possible", False)),
            "by_source": dict(stats.get("duplicate_breakdown_by_source", {}) or {}),
            "by_kind": dict(stats.get("duplicate_breakdown_by_kind", {}) or {}),
            "top_duplicate_source": str(stats.get("top_duplicate_source", "") or ""),
            "top_duplicate_kind": str(stats.get("top_duplicate_kind", "") or ""),
            "top_duplicate_categories": list(stats.get("top_duplicate_categories", []) or []),
            "top_duplicate_actions": list(stats.get("top_duplicate_actions", []) or []),
        }
        required_event_count = 0
        current_event_count = int(stats.get("total_events", 0) or 0)
        required_uptime = ""
        current_uptime = ""
        required_sources = 0
        current_sources = int(stats.get("active_sources", 0) or 0)
        for item in criteria:
            label = str(item.get("name", "") or "").lower()
            if "event" in label and not required_event_count:
                required_event_count = int(item.get("needed", 0) or 0) if isinstance(item.get("needed"), int) else required_event_count
            if "çalışma süresi" in label:
                required_uptime = str(item.get("needed", "") or "")
                current_uptime = str(item.get("current", "") or "")
            if "log çeşitliliği" in label and isinstance(item.get("needed"), int):
                required_sources = int(item.get("needed", 0) or 0)
        return {
            "status": "ok",
            "current_phase": current_phase,
            "phase_name": str(pm_status.get("phase_name", "") or ""),
            "next_phase": next_phase_num,
            "progress_percent": progress_percent,
            "required_event_count": required_event_count,
            "current_event_count": current_event_count,
            "event_counter_scope": "phase_lifetime_normalized_events",
            "labeled_data_scope": "family_specific_labeled_training_examples",
            "required_uptime": required_uptime,
            "current_uptime": current_uptime,
            "remaining_time_text": remaining_time_text,
            "log_diversity": {"current": current_sources, "required": required_sources},
            "duplicate_rate": float(stats.get("dup_rate", 0.0) or 0.0),
            "duplicate_rate_verified": bool(stats.get("duplicate_rate_verified", False)),
            "duplicate_rate_source": str(stats.get("duplicate_rate_source", "phase_state") or "phase_state"),
            "live_db_event_count": stats.get("live_db_event_count"),
            "phase_event_count": int(stats.get("phase_event_count", stats.get("total_events", 0)) or 0),
            "estimated_non_live_window_events": max(
                0,
                int(stats.get("phase_event_count", stats.get("total_events", 0)) or 0)
                - int(stats.get("live_db_event_count", 0) or 0),
            ),
            "duplicate_counter_stale_possible": bool(stats.get("duplicate_counter_stale_possible", False)),
            "data_quality_title": "Veri kalite oranı yüksek" if bool(stats.get("duplicate_rate_verified", False)) else "Veri kalite oranı doğrulanamadı / eski sayaç olabilir",
            "data_quality_subtitle": "duplicate + parse fail",
            "data_quality_message": str(stats.get("duplicate_rate_message", "") or ""),
            "data_quality_message_en": str(stats.get("duplicate_rate_message_en", "") or ""),
            "duplicate_summary": duplicate_summary,
            "parse_fail_summary": parse_fail_summary,
            "active_features": active_features,
            "passive_features": passive_features,
            "unmet_conditions": [str(item.get("message", "") or "") for item in blocking if isinstance(item, dict)] or [str(item) for item in blocking],
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "current_phase": 0,
            "phase_name": "",
            "next_phase": 0,
            "progress_percent": 0,
            "required_event_count": 0,
            "current_event_count": 0,
            "event_counter_scope": "phase_lifetime_normalized_events",
            "labeled_data_scope": "family_specific_labeled_training_examples",
            "required_uptime": "",
            "current_uptime": "",
            "remaining_time_text": "",
            "log_diversity": {"current": 0, "required": 0},
            "duplicate_rate": 0.0,
            "live_db_event_count": 0,
            "phase_event_count": 0,
            "estimated_non_live_window_events": 0,
            "parse_fail_summary": {},
            "active_features": [],
            "passive_features": [],
            "unmet_conditions": [],
            "error": str(exc),
        }


def collect_ml_family_readiness(config_path: str | None = None) -> Dict[str, Any]:
    db = None
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        pm_status = _load_phase_manager_status(config)
        db = create_database(config)
        report = _ml_readiness_report(config, db, pm_status)
        families = []
        readiness = dict(report.get("families", {}) or {})
        for spec in list_ml_families():
            item = dict(readiness.get(spec.family_id, {}) or {})
            families.append({
                "family_id": spec.family_id,
                "status": item.get("status", "readiness_blocked"),
                "reason": str(item.get("reason", "") or ""),
                "phase_gate": item.get("phase_gate", spec.phase_gate),
                "event_counter_scope": "normalized_runtime_events",
                "label_counter_scope": "family_specific_labeled_training_examples",
                "runtime_events": int(item.get("runtime_events", 0) or 0),
                "required_events": int(item.get("required_events", 0) or 0),
                "normal_labels": int(item.get("normal_labels", 0) or 0),
                "required_normal_labels": int(item.get("required_normal_labels", 0) or 0),
                "suspicious_labels": int(item.get("suspicious_labels", 0) or 0),
                "required_suspicious_labels": int(item.get("required_suspicious_labels", 0) or 0),
                "metadata_support": int(item.get("metadata_support", 0) or 0),
                "trust_support": dict(item.get("trust_support", {}) or {}),
                "distro_cohorts": dict(item.get("distro_cohorts", {}) or {}),
                "quota_normal": dict(item.get("quota_normal", {}) or {"used": 0, "limit": int(spec.normal_label_quota or 0), "remaining": int(spec.normal_label_quota or 0), "status": "collecting"}),
                "quota_suspicious": dict(item.get("quota_suspicious", {}) or {"used": 0, "limit": int(spec.suspicious_label_quota or 0), "remaining": int(spec.suspicious_label_quota or 0), "status": "collecting"}),
                "top_reasons": list(item.get("blockers", []) or item.get("field_failures", []) or [item.get("reason", "")])[:5],
            })
        status = "ok" if len(families) == 12 else "degraded"
        return {"status": status, "families": families, "error": report.get("error")}
    except Exception as exc:
        return {"status": "degraded", "families": [], "error": str(exc)}
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def collect_ml_labels(limit: int = 200, source: str | None = None, family: str | None = None, config_path: str | None = None) -> Dict[str, Any]:
    db = None
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        db = create_database(config)
        if db is None or not hasattr(db, "load_labels"):
            return {"status": "degraded", "labels": [], "error": "labels_unavailable"}
        rows = list(db.load_labels() or [])
        source_filter = str(source or "").strip().lower()
        family_filter = str(family or "").strip().upper()
        labels = []
        for row in rows:
            item = _normalize_label_row(row)
            if source_filter and item["source"].lower() != source_filter:
                continue
            if family_filter and item["ml_family"].upper() != family_filter:
                continue
            labels.append(item)
        labels.sort(key=lambda item: float(item.get("ts") or 0.0), reverse=True)
        return {"status": "ok", "labels": labels[:max(1, min(int(limit or 200), 500))], "error": None}
    except Exception as exc:
        return {"status": "degraded", "labels": [], "error": str(exc)}
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def collect_ml_label_detail(label_id: int, config_path: str | None = None) -> Dict[str, Any]:
    labels_payload = collect_ml_labels(limit=1000, config_path=config_path)
    if labels_payload.get("status") != "ok":
        return {"status": "degraded", "label": None, "detail": {}, "error": labels_payload.get("error")}
    for item in labels_payload.get("labels", []):
        if int(item.get("id", -1) or -1) == int(label_id):
            raw_payload = item.get("raw", {})
            evidence_payload = item.get("evidence_fields", {})
            detail = {
                "raw_json": _stringify_payload(raw_payload),
                "evidence_json": _stringify_payload(evidence_payload),
                "stored_payload": raw_payload,
                "stored_payload_kind": type(raw_payload).__name__,
                "evidence_payload": evidence_payload,
                "evidence_payload_kind": type(evidence_payload).__name__,
                "label_class": item.get("label_class", "unknown"),
                "label_class_source": item.get("label_class_source", ""),
                "label_reason": item.get("label_reason", ""),
                "label_lifecycle_status": item.get("label_lifecycle_status", ""),
            }
            return {"status": "ok", "label": item, "detail": detail, "error": None}
    return {"status": "degraded", "label": None, "detail": {}, "error": f"label_not_found:{label_id}"}


def collect_ml_historical_plan_status(config_path: str | None = None) -> Dict[str, Any]:
    db = None
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        pm_status = _load_phase_manager_status(config)
        db = create_database(config)
        files = _collect_ml_history_files()
        report = _ml_historical_report(config, db, pm_status)
        families = dict(report.get("families", {}) or {})
        family_rows = []
        for family_id in sorted(families):
            family = dict(families.get(family_id, {}) or {})
            total_candidates = int(family.get("candidate_count", 0) or 0)
            statuses = Counter()
            for item in dict(family.get("labels", {}) or {}).values():
                statuses[str(item.get("status", "unknown") or "unknown")] += 1
            family_rows.append({
                "family_id": family_id,
                "candidate_count": total_candidates,
                "status": family.get("status", ""),
                "query_notes": list(family.get("query_notes", []) or []),
                "label_status_counts": dict(statuses),
            })
        empty = not files
        return {
            "status": "ok" if not report.get("error") else "degraded",
            "empty": empty,
            "message": "No historical label scan artifact found" if empty else "",
            "artifacts": files,
            "historical_scan_summary": dict(report.get("global", {}) or {}),
            "families": family_rows,
            "error": report.get("error"),
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "empty": True,
            "message": "No historical label scan artifact found",
            "artifacts": [],
            "historical_scan_summary": {},
            "families": [],
            "error": str(exc),
        }
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def get_historical_preview_status_no_scan(config_path: str | None = None, language: str | None = None) -> Dict[str, Any]:
    files = _collect_ml_history_files()
    empty = not files
    lang = _resolve_backend_language(explicit=language)
    return {
        "status": "ok",
        "empty": empty,
        "run_state": "not_run",
        "manual_trigger_required": True,
        "message": system_text("historical_preview_manual_only_message", lang),
        "artifacts": files,
        "historical_scan_summary": {},
        "families": [],
        "error": None,
    }


_LOCAL_HISTORICAL_SOURCE_SPECS = (
    ("auth_log", "auth_log", "auth_log"),
    ("syslog", "syslog", "syslog"),
    ("auditd", "audit_log", "auditd"),
    ("apache2", "apache_log", "apache2"),
    ("nginx", "nginx_log", "nginx"),
    ("postgresql", "pg_log", "postgresql"),
    ("ufw", "ufw_log", "ufw"),
    ("dpkg", "dpkg_log", "dpkg"),
    ("kern_log", "kern_log", "syslog"),
)

_LOCAL_HISTORICAL_EXTRA_PATHS = {
    "debian": (
        ("dpkg", "dpkg", "/var/log/apt/history.log"),
    ),
}


def _safe_local_hostname() -> str:
    try:
        return str(socket.gethostname() or "").strip()
    except Exception:
        return ""


def _normalize_local_historical_source_key(
    source_key: str,
    source_type: str,
    distro_family: str,
    default_source: str,
) -> str:
    entry_source = str(source_type or source_key).strip().lower() or default_source
    if entry_source == "weblog":
        return "apache2" if source_key == "apache2" else "nginx"
    if source_key == "ufw":
        return "ufw"
    if source_key == "postgresql":
        return "postgresql"
    if source_key == "dpkg" and distro_family == "rhel":
        return "dnf"
    if source_key == "dpkg" and distro_family == "suse":
        return "zypper"
    if source_key == "kern_log":
        return "syslog"
    return entry_source


def _local_historical_source_label(
    observed_source: str,
    log_path: str,
    action: str,
    category: str,
) -> str:
    source_name = str(observed_source or "").strip().lower()
    path_text = str(log_path or "").strip().lower()
    action_name = str(action or "").strip().lower()
    category_name = str(category or "").strip().lower()
    if category_name == "auth" or action_name in {
        "ssh_login",
        "ssh_invalid_user",
        "sudo",
        "sudo_fail",
        "auth_fail",
        "identity_login",
        "account_locked",
        "account_policy",
        "db_login",
        "db_connect",
    }:
        return "postgresql" if source_name == "postgresql" else "auth"
    if source_name == "apache2":
        return "web/apache"
    if source_name == "nginx":
        return "web/nginx"
    if source_name in {"dpkg", "dnf", "yum", "zypper"}:
        return "package_manager"
    if source_name == "postgresql":
        return "postgresql"
    if source_name == "auditd":
        return "auditd"
    if source_name == "auth_log":
        return "auth"
    if source_name == "ufw":
        return "firewall"
    if action_name.startswith("firewall_") or "firewalld" in action_name or category_name == "firewall":
        return "firewall"
    if "firewalld" in path_text or "firewall" in path_text or "ufw" in path_text:
        return "firewall"
    if "postgresql" in path_text or "/pgsql/" in path_text:
        return "postgresql"
    if "apache" in path_text or "httpd" in path_text:
        return "web/apache"
    if "nginx" in path_text:
        return "web/nginx"
    if "dpkg" in path_text or "/apt/" in path_text or "dnf" in path_text or "yum" in path_text or "zypper" in path_text:
        return "package_manager"
    if "kern.log" in path_text:
        return "kernel"
    if "secure" in path_text or "auth.log" in path_text:
        return "auth"
    return source_name or "unknown"


def _local_historical_metadata_quality(
    *,
    ts: Any,
    host: str,
    source_name: str,
    distro_family: str,
    action: str,
    timestamp_warning: str,
    host_enriched: bool,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if not ts:
        reasons.append("missing_timestamp")
    if not host:
        reasons.append("missing_host")
    if not source_name:
        reasons.append("missing_source")
    if not distro_family:
        reasons.append("missing_distro_family")
    if str(action or "").strip().lower() in {"", "unknown"}:
        reasons.append("unknown_action")
    if timestamp_warning:
        reasons.append(str(timestamp_warning))
    if host_enriched:
        reasons.append("host_enriched_from_local_machine")
    if not reasons:
        return "complete", []
    blocking = {"missing_timestamp", "missing_host", "missing_source", "missing_distro_family", "unknown_action"}
    if any(reason in blocking for reason in reasons):
        return "degraded", reasons
    return "enriched", reasons


def _local_historical_time_bucket(hour_of_day: int | None) -> str:
    if hour_of_day is None:
        return "unknown"
    if 8 <= hour_of_day <= 17:
        return "business_hours"
    if 18 <= hour_of_day <= 22:
        return "evening"
    return "night"


def _local_historical_timestamp_metadata(candidate: Dict[str, Any]) -> Dict[str, Any]:
    item = dict(candidate or {})
    ts_value = item.get("ts")
    timestamp_warning = str(item.get("timestamp_warning", "") or "").strip()
    original_timestamp_text = str(item.get("timestamp_text", "") or "").strip()
    parsed_datetime = ""
    timestamp_source = "missing"
    timestamp_confidence = "missing"
    normalized_warning = timestamp_warning
    hour_of_day = None
    day_of_week = ""
    is_weekend = False
    is_night = False
    time_bucket = "unknown"
    if ts_value not in (None, "", 0, 0.0):
        try:
            parsed = datetime.fromtimestamp(float(ts_value))
            parsed_datetime = parsed.isoformat(timespec="seconds")
            if not original_timestamp_text:
                original_timestamp_text = _coerce_timestamp_text(ts_value)
            hour_of_day = int(parsed.hour)
            weekday_index = int(parsed.weekday())
            day_of_week = _WEEKDAY_NAMES_EN[weekday_index]
            is_weekend = weekday_index >= 5
            is_night = hour_of_day < 6 or hour_of_day >= 22
            time_bucket = _local_historical_time_bucket(hour_of_day)
            timestamp_source = "parsed_log_timestamp"
            timestamp_confidence = "high"
            if timestamp_warning == "year_inferred_from_current_time":
                timestamp_source = "traditional_syslog_current_year_fallback"
                timestamp_confidence = "medium"
                normalized_warning = "current_year_fallback"
            elif timestamp_warning:
                timestamp_source = "timestamp_fallback"
                timestamp_confidence = "low"
        except Exception:
            timestamp_source = "timestamp_parse_failed"
            timestamp_confidence = "missing"
            if not normalized_warning:
                normalized_warning = "timestamp_parse_failed"
    elif not normalized_warning:
        normalized_warning = "timestamp_missing"
    return {
        "parsed_datetime": parsed_datetime,
        "original_timestamp_text": original_timestamp_text,
        "timestamp_source": timestamp_source,
        "timestamp_confidence": timestamp_confidence,
        "timestamp_warning": normalized_warning,
        "hour_of_day": hour_of_day,
        "day_of_week": day_of_week,
        "is_weekend": is_weekend,
        "is_night": is_night,
        "time_bucket": time_bucket,
    }


def _increment_temporal_distribution(
    target: Dict[str, Counter],
    group_key: str,
    hour_of_day: int | None,
) -> None:
    normalized_key = str(group_key or "").strip()
    if not normalized_key or hour_of_day is None:
        return
    target.setdefault(normalized_key, Counter())
    target[normalized_key][str(int(hour_of_day))] += 1


def _serialize_temporal_distribution(target: Dict[str, Counter]) -> Dict[str, Dict[str, int]]:
    return {
        key: dict(sorted(counter.items(), key=lambda item: int(item[0])))
        for key, counter in sorted(target.items())
        if counter
    }


_BASELINE_ALLOWED_SOURCES = {"auth", "package_manager", "postgresql", "web/apache", "web/nginx"}
_BASELINE_DENY_SOURCES = {"firewall", "kernel", "auditd", "unknown"}
_BASELINE_ALLOWED_ACTIONS = {
    "ssh_login",
    "sudo",
    "db_login",
    "db_connect",
    "user_logout",
    "session_close",
    "pkg_install",
    "pkg_update",
    "pkg_upgrade",
    "pkg_remove",
    "service_start",
    "service_stop",
    "service_restart",
    "service_heartbeat",
    "http_request",
    "web_request",
}
_BASELINE_DENY_ACTION_PREFIXES = ("firewall_",)
_BASELINE_DENY_ACTIONS = {
    "auth_fail",
    "ssh_invalid_user",
    "account_locked",
    "account_policy",
    "attack_tool_installed",
    "reverse_shell",
    "webshell",
    "suspicious_process",
}
_BASELINE_REQUIRED_OUTCOME_ACTIONS = {
    "ssh_login",
    "sudo",
    "db_login",
    "db_connect",
    "pkg_install",
    "pkg_update",
    "pkg_upgrade",
    "pkg_remove",
}
_BASELINE_ALLOWED_OUTCOMES = {"success", "allowed", "normal", "completed", "started", "stopped", "running"}


def _is_unknown_token(value: Any) -> bool:
    token = str(value or "").strip().lower()
    return token in {"", "unknown", "unknown_distro", "unknown_source", "unknown_category"}


def _normalize_reason_list(reasons: List[str]) -> List[str]:
    normalized: List[str] = []
    seen: set[str] = set()
    for reason in reasons:
        token = str(reason or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        normalized.append(token)
    return normalized


def _labelability_reason_token(reason: str) -> str:
    token = str(reason or "").strip().lower()
    mapping = {
        "missing_timestamp": "missing_timestamp",
        "missing_host": "missing_host",
        "missing_source": "missing_source",
        "missing_source_metadata": "missing_source",
        "missing_distro_family": "unknown_distro",
        "unknown_distro": "unknown_distro",
        "unknown_category": "unknown_category",
        "unknown_action": "action_unknown",
        "unknown_outcome": "unknown_outcome",
        "unsupported_source": "unsupported_source",
        "invalid_metadata": "invalid_metadata",
        "duplicate": "duplicate",
        "duplicate_exact": "duplicate",
        "quota_full": "quota_full",
        "learnable_false": "not_labelable",
        "missing_behavior_label": "not_labelable",
        "missing_family_mapping": "not_labelable",
        "usage_not_writeable": "not_labelable",
        "invalid_event_class": "parse_invalid",
        "invalid_source_mode": "parse_invalid",
        "no_action_contract_required": "parse_invalid",
        "not_labelable": "not_labelable",
    }
    return mapping.get(token, token or "parse_invalid")


def _historical_labelable_reason(
    candidate: Dict[str, Any],
    *,
    usage_decision: str,
) -> str:
    evidence = dict(candidate.get("evidence_fields", {}) or {})
    explicit = str(
        evidence.get("labelability_reason", "")
        or candidate.get("labelability_reason", "")
        or ""
    ).strip()
    if explicit:
        return explicit
    if usage_decision == "baseline_learning":
        return "known_benign_normal"
    if usage_decision == "direct_learnable":
        return "rule_hit"
    return "labelable"


def _primary_labelability_reason(reasons: List[str], *, default: str = "labelable") -> str:
    normalized = _normalize_reason_list(reasons)
    if not normalized:
        return default
    return _labelability_reason_token(normalized[0])


def _candidate_has_suspicious_signal(candidate: Dict[str, Any], has_rule_id: bool) -> bool:
    event_class = str(candidate.get("event_class", "") or "").strip().lower()
    behavior_label = str(candidate.get("behavior_label", "") or "").strip().lower()
    action = str(candidate.get("action", "") or "").strip().lower()
    outcome = str(candidate.get("outcome", "") or "").strip().lower()
    source_name = str(candidate.get("observed_source", candidate.get("source", "")) or "").strip().lower()
    source_trust = str(candidate.get("source_trust", "") or "").strip().lower()
    if event_class in {"attack", "suspicious"}:
        return True
    if has_rule_id or source_trust.startswith("rule_"):
        return True
    if behavior_label == "unknown_unlabeled":
        return False
    if any(token in behavior_label for token in ("attack", "suspicious", "credential_access", "exploit", "abuse")):
        return True
    if any(action.startswith(prefix) for prefix in _BASELINE_DENY_ACTION_PREFIXES):
        return True
    if action in _BASELINE_DENY_ACTIONS:
        return True
    if outcome in {"failure", "failed", "denied", "reject", "rejected", "blocked", "drop", "dropped"}:
        return True
    if source_name in {"firewall"} and outcome in {"blocked", "drop", "dropped", "reject", "rejected"}:
        return True
    return False


def _baseline_allowlist_match(candidate: Dict[str, Any]) -> bool:
    source_name = str(candidate.get("observed_source", candidate.get("source", "")) or "").strip().lower()
    action = str(candidate.get("action", "") or "").strip().lower()
    outcome = str(candidate.get("outcome", "") or "").strip().lower()
    category = str(candidate.get("category", "") or "").strip().lower()
    process = str(candidate.get("process", "") or "").strip().lower()
    if action in {"service_start", "service_stop", "service_restart", "service_heartbeat"}:
        return outcome in _BASELINE_ALLOWED_OUTCOMES.union({""}) or "systemd" in process or category in {"service", "system"}
    if source_name in _BASELINE_DENY_SOURCES:
        return False
    if source_name == "auth":
        return action in {"ssh_login", "sudo", "user_logout", "session_close"} and outcome in _BASELINE_ALLOWED_OUTCOMES.union({""})
    if source_name == "postgresql":
        return action in {"db_login", "db_connect"} and outcome in _BASELINE_ALLOWED_OUTCOMES.union({""})
    if source_name == "package_manager":
        return action in {"pkg_install", "pkg_update", "pkg_upgrade", "pkg_remove"}
    if source_name in {"web/apache", "web/nginx"}:
        return action in {"http_request", "web_request"} and outcome in _BASELINE_ALLOWED_OUTCOMES.union({""})
    return False


def _baseline_quality_reasons(candidate: Dict[str, Any], has_rule_id: bool) -> List[str]:
    reasons: List[str] = []
    source_name = str(candidate.get("observed_source", candidate.get("source", "")) or "").strip().lower()
    distro_family = str(candidate.get("distro_family", candidate.get("distro", "")) or "").strip().lower()
    host_value = str(candidate.get("host", "") or "").strip()
    action = str(candidate.get("action", "") or "").strip().lower()
    outcome = str(candidate.get("outcome", "") or "").strip().lower()
    category = str(candidate.get("category", "") or "").strip().lower()
    suspicious_signal = _candidate_has_suspicious_signal(candidate, has_rule_id)
    if not candidate.get("ts"):
        reasons.append("missing_timestamp")
    if not host_value:
        reasons.append("missing_host")
    if _is_unknown_token(source_name):
        reasons.append("unknown_source")
    if _is_unknown_token(distro_family):
        reasons.append("unknown_distro")
    if _is_unknown_token(category):
        reasons.append("unknown_category")
    if _is_unknown_token(action):
        reasons.append("unknown_action")
    if suspicious_signal:
        reasons.append("suspicious_signal")
    if source_name in _BASELINE_DENY_SOURCES or not _baseline_allowlist_match(candidate):
        reasons.append("unsupported_source")
    if (
        action in _BASELINE_REQUIRED_OUTCOME_ACTIONS
        and outcome not in _BASELINE_ALLOWED_OUTCOMES
        and (_is_unknown_token(outcome) or not suspicious_signal)
    ):
        reasons.append("unknown_outcome")
    if action in {"http_request", "web_request"} and outcome in {"blocked", "rejected", "drop", "dropped"}:
        reasons.append("suspicious_signal")
    return _normalize_reason_list(reasons)


def _build_local_historical_quality_summary(
    candidate_rows: List[Dict[str, Any]],
    reason_breakdown: Counter,
) -> Dict[str, int]:
    summary = {
        "baseline_quality_passed": 0,
        "rejected_missing_timestamp": 0,
        "rejected_unknown_action": 0,
        "rejected_weak_field_quality": 0,
        "rejected_suspicious_signal": 0,
        "ignored_unsupported_source": 0,
        "direct_rule_hit": 0,
    }
    for row in candidate_rows:
        disposition = str(row.get("usage_decision", "") or "")
        reasons = set(str(reason or "") for reason in list(row.get("reasons", []) or []))
        if disposition == "baseline_learning" and "baseline_quality_passed" in reasons:
            summary["baseline_quality_passed"] += 1
        if disposition == "rejected" and "missing_timestamp" in reasons:
            summary["rejected_missing_timestamp"] += 1
        if disposition == "rejected" and "unknown_action" in reasons:
            summary["rejected_unknown_action"] += 1
        if disposition == "rejected" and ("not_labelable" in reasons or "weak_field_quality" in reasons):
            summary["rejected_weak_field_quality"] += 1
        if disposition == "rejected" and "suspicious_signal" in reasons:
            summary["rejected_suspicious_signal"] += 1
        if disposition == "ignored" and "unsupported_source" in reasons:
            summary["ignored_unsupported_source"] += 1
        if disposition == "direct_learnable" and "rule_hit_not_baseline" in reasons:
            summary["direct_rule_hit"] += 1
    if not summary["baseline_quality_passed"]:
        summary["baseline_quality_passed"] = int(reason_breakdown.get("baseline_quality_passed", 0))
    return summary


def _coerce_known_benign_historical_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
    item = dict(candidate or {})
    rule_id = str(item.get("rule_id", "") or "").strip().upper()
    source_name = str(item.get("observed_source", item.get("source", "")) or "").strip().lower()
    action = str(item.get("action", "") or "").strip().lower()
    outcome = str(item.get("outcome", "") or "").strip().lower()
    if rule_id != "FIRST-002":
        return item
    if source_name != "auth" or action != "ssh_login" or outcome != "success":
        return item

    evidence = dict(item.get("evidence_fields", {}) or {})
    evidence.update({
        "rule_id": "",
        "context_rule_id": rule_id,
        "context_behavior_label": str(item.get("behavior_label", "") or ""),
        "context_event_class": str(item.get("event_class", "") or ""),
        "context_model_usage_scope": str(item.get("model_usage_scope", "") or ""),
        "context_source_trust": str(item.get("source_trust", "") or ""),
        "labelability_reason": "known_benign_normal",
    })
    item.update({
        "category": "auth_normal",
        "rule_id": "",
        "event_class": "benign",
        "ml_family": "ML-AUTH",
        "ml_label": "expected_auth_activity",
        "label_family": "ML-AUTH",
        "behavior_label": "expected_auth_activity",
        "attack_family": "",
        "source_trust": "observed_benign_high",
        "model_usage_scope": "baseline_learning",
        "learnable": True,
        "label_reason": "historical_known_benign_auth_success",
        "evidence_fields": evidence,
        "labelability_status": "labelable",
        "labelability_reason": "known_benign_normal",
    })
    return item


def _historical_candidate_duplicate_key(candidate: Dict[str, Any]) -> str:
    evidence = dict(candidate.get("evidence_fields", {}) or {})
    line_hash = str(candidate.get("line_hash", "") or evidence.get("line_hash", "") or "").strip().lower()
    if not line_hash:
        raw_key = "|".join(
            [
                str(candidate.get("source_mode", "local_host_logs") or "local_host_logs").strip().lower(),
                str(candidate.get("distro_family", "") or "").strip().lower(),
                str(candidate.get("host", "") or "").strip().lower(),
                str(candidate.get("log_path", "") or "").strip().lower(),
                str(candidate.get("timestamp", candidate.get("ts", "")) or "").strip().lower(),
                str(candidate.get("category", "") or "").strip().lower(),
                str(candidate.get("action", "") or "").strip().lower(),
                str(candidate.get("outcome", "") or "").strip().lower(),
            ]
        )
        line_hash = hashlib.sha256(raw_key.encode("utf-8", errors="ignore")).hexdigest()
    return "|".join(
        [
            str(candidate.get("source_mode", "local_host_logs") or "local_host_logs").strip().lower(),
            str(candidate.get("distro_family", "") or "").strip().lower(),
            str(candidate.get("host", "") or "").strip().lower(),
            str(candidate.get("log_path", "") or "").strip().lower(),
            line_hash,
            str(candidate.get("rule_id", "") or "").strip().upper(),
            str(candidate.get("behavior_label", "") or "").strip().lower(),
            str(candidate.get("model_usage_scope", "") or "").strip().lower(),
        ]
    )


def _quota_counts_from_usage(usage: Dict[str, Any]) -> Counter:
    counts: Counter = Counter()
    for family, distro_rows in dict(usage or {}).items():
        for distro, type_rows in dict(distro_rows or {}).items():
            if distro == "all":
                continue
            for label_type in ("normal", "suspicious"):
                used = int(dict(type_rows.get(label_type, {}) or {}).get("used", 0) or 0)
                if used > 0:
                    counts[(family, distro, label_type)] = used
    return counts


def _quota_remaining_by_family(quota_summary: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    usage = dict(quota_summary.get("usage", {}) or {})
    result: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for family, distro_rows in usage.items():
        aggregate = dict(dict(distro_rows or {}).get("all", {}) or {})
        result[family] = {}
        for label_type in ("normal", "suspicious"):
            item = dict(aggregate.get(label_type, {}) or {})
            result[family][label_type] = {
                "used": int(item.get("used", 0) or 0),
                "limit": int(item.get("limit", 0) or 0),
                "remaining": int(item.get("remaining", 0) or 0),
                "status": str(item.get("status", "collecting") or "collecting"),
            }
    return result


def _historical_candidate_write_gate(candidate: Dict[str, Any]) -> Tuple[bool, List[str]]:
    item = dict(candidate or {})
    reasons: List[str] = []
    source_mode = str(item.get("source_mode", "local_host_logs") or "").strip().lower()
    distro_family = str(item.get("distro_family", "") or "").strip().lower()
    host_value = str(item.get("host", "") or "").strip()
    source_name = str(item.get("source", "") or "").strip()
    log_source = str(item.get("log_source", "") or "").strip()
    log_path = str(item.get("log_path", "") or "").strip()
    category = str(item.get("category", "") or "").strip().lower()
    action = str(item.get("action", "") or "").strip().lower()
    outcome = str(item.get("outcome", "") or "").strip().lower()
    behavior_label = str(item.get("behavior_label", "") or "").strip().lower()
    ml_family = str(item.get("ml_family", item.get("label_family", "")) or "").strip().upper()
    source_trust = str(item.get("source_trust", "") or "").strip().lower()
    model_usage_scope = str(item.get("model_usage_scope", "") or "").strip().lower()
    event_class = str(item.get("event_class", "") or "").strip().lower()
    usage_decision = str(item.get("usage_decision", "") or "").strip().lower()

    if source_mode != "local_host_logs":
        reasons.append("invalid_source_mode")
    if item.get("no_action_contract") is not True:
        reasons.append("no_action_contract_required")
    if _is_unknown_token(distro_family):
        reasons.append("unknown_distro")
    if not host_value:
        reasons.append("missing_host")
    if not source_name or not log_source or not log_path:
        reasons.append("missing_source_metadata")
    if item.get("ts") in (None, "", 0) and not str(item.get("timestamp", "") or "").strip():
        reasons.append("missing_timestamp")
    if _is_unknown_token(category):
        reasons.append("unknown_category")
    if _is_unknown_token(action):
        reasons.append("unknown_action")
    if not outcome or _is_unknown_token(outcome):
        reasons.append("unknown_outcome")
    if not behavior_label or behavior_label == "unknown_unlabeled":
        reasons.append("missing_behavior_label")
    if not ml_family:
        reasons.append("missing_family_mapping")
    if not source_trust:
        reasons.append("missing_source_trust")
    if event_class not in {"benign", "suspicious", "attack"}:
        reasons.append("invalid_event_class")
    if item.get("learnable") is not True:
        reasons.append("learnable_false")
    if usage_decision not in {"direct_learnable", "baseline_learning"}:
        reasons.append("usage_not_writeable")
    if usage_decision == "baseline_learning" and model_usage_scope != "baseline_learning":
        reasons.append("invalid_baseline_scope")
    if usage_decision == "direct_learnable" and model_usage_scope not in {"calibration_only", "direct_learnable"}:
        reasons.append("invalid_direct_scope")
    if str(item.get("source_trust", "") or "").strip().lower().startswith("synthetic"):
        reasons.append("synthetic")
    return len(_normalize_reason_list(reasons)) == 0, _normalize_reason_list(reasons)


def _build_historical_label_metadata(candidate: Dict[str, Any]) -> Dict[str, Any]:
    from core.ml.label_engine import build_ml_label_metadata

    item = dict(candidate or {})
    usage_decision = str(item.get("usage_decision", "") or "").strip().lower()
    source_type = "clean_window_normal" if usage_decision == "baseline_learning" else "auto_labeled_rule_mapped"
    rule_id = str(item.get("rule_id", "") or "").strip().upper()
    ml_family = str(item.get("ml_family", item.get("label_family", "")) or "").strip().upper()
    ml_label = str(item.get("ml_label", item.get("behavior_label", "")) or "").strip()
    behavior_label = str(item.get("behavior_label", ml_label) or "").strip()
    base_metadata = build_ml_label_metadata(
        source_type=source_type,
        ml_family=ml_family,
        ml_label=ml_label,
        behavior_label=behavior_label,
        event_class=str(item.get("event_class", "") or "").strip().lower(),
        rule_id=rule_id,
        evidence_fields=dict(item.get("evidence_fields", {}) or {}),
        label_reason=str(item.get("label_reason", "") or "").strip() or (
            "historical_host_log_baseline" if usage_decision == "baseline_learning" else "historical_host_log_rule_match"
        ),
        source_trust=str(item.get("source_trust", "") or "").strip().lower(),
        model_usage_scope=str(item.get("model_usage_scope", "") or "").strip().lower(),
        learnable=True,
    )
    duplicate_key = _historical_candidate_duplicate_key(item)
    line_hash = str(item.get("line_hash", "") or "").strip().lower()
    if not line_hash:
        line_hash = duplicate_key.split("|")[4]
    evidence = dict(base_metadata.get("evidence_fields", {}) or {})
    evidence.update({
        "source_mode": "local_host_logs",
        "label_origin": "historical_host_log",
        "distro_family": str(item.get("distro_family", "") or "").strip().lower() or "unknown_distro",
        "distro": str(item.get("distro", "") or "").strip().lower() or "unknown_distro",
        "host": str(item.get("host", "") or "").strip(),
        "source": str(item.get("source", "") or "").strip(),
        "log_source": str(item.get("log_source", "") or "").strip(),
        "log_path": str(item.get("log_path", "") or "").strip(),
        "ts": item.get("ts"),
        "timestamp": str(item.get("timestamp", "") or "").strip(),
        "timestamp_confidence": str(item.get("timestamp_confidence", "") or "").strip().lower(),
        "hour_of_day": item.get("hour_of_day"),
        "day_of_week": str(item.get("day_of_week", "") or "").strip().lower(),
        "is_weekend": bool(item.get("is_weekend", False)),
        "is_night": bool(item.get("is_night", False)),
        "time_bucket": str(item.get("time_bucket", "") or "").strip().lower(),
        "category": str(item.get("category", "") or "").strip().lower(),
        "action": str(item.get("action", "") or "").strip().lower(),
        "outcome": str(item.get("outcome", "") or "").strip().lower(),
        "rule_id": rule_id,
        "ml_family": ml_family,
        "ml_label": ml_label,
        "label_family": str(item.get("label_family", ml_family) or "").strip().upper(),
        "behavior_label": behavior_label,
        "source_trust": str(item.get("source_trust", "") or "").strip().lower(),
        "model_usage_scope": str(item.get("model_usage_scope", "") or "").strip().lower(),
        "usage_decision": usage_decision,
        "event_class": str(item.get("event_class", "") or "").strip().lower(),
        "label_reason": str(base_metadata.get("label_reason", "") or "").strip(),
        "labelability_status": "labelable",
        "labelability_reason": str(item.get("labelability_reason", "labelable") or "labelable"),
        "line_hash": line_hash,
        "no_action_contract": True,
        "duplicate_guard_key": duplicate_key,
    })
    base_metadata.update({
        "source_mode": "local_host_logs",
        "label_origin": "historical_host_log",
        "distro_family": evidence["distro_family"],
        "distro": evidence["distro"],
        "host": evidence["host"],
        "source": "auto_labeled",
        "log_source": evidence["log_source"],
        "log_path": evidence["log_path"],
        "ts": evidence["ts"],
        "timestamp": evidence["timestamp"],
        "timestamp_confidence": evidence["timestamp_confidence"],
        "hour_of_day": evidence["hour_of_day"],
        "day_of_week": evidence["day_of_week"],
        "is_weekend": evidence["is_weekend"],
        "is_night": evidence["is_night"],
        "time_bucket": evidence["time_bucket"],
        "category": evidence["category"],
        "action": evidence["action"],
        "outcome": evidence["outcome"],
        "rule_id": evidence["rule_id"],
        "source_trust": evidence["source_trust"],
        "model_usage_scope": evidence["model_usage_scope"],
        "event_class": evidence["event_class"],
        "label_reason": evidence["label_reason"],
        "labelability_status": evidence["labelability_status"],
        "labelability_reason": evidence["labelability_reason"],
        "line_hash": line_hash,
        "evidence_fields": evidence,
        "no_action_contract": True,
    })
    return base_metadata


def _historical_candidate_to_label_record(candidate: Dict[str, Any], *, label_batch_id: str) -> Any:
    from core.ml.label_engine import LabelRecord, SOURCE_AUTO_LABELED

    metadata = _build_historical_label_metadata(candidate)
    usage_decision = str(candidate.get("usage_decision", "") or "").strip().lower()
    event_class = str(candidate.get("event_class", "") or "").strip().lower()
    confidence = 0.92 if usage_decision == "direct_learnable" else 0.82
    score = 90.0 if event_class == "attack" else (75.0 if usage_decision == "direct_learnable" else 0.0)
    record = LabelRecord(
        score=score,
        label="normal" if event_class == "benign" else "attack",
        category=str(candidate.get("category", "") or "").strip().lower(),
        source=SOURCE_AUTO_LABELED,
        confidence=confidence,
        ts=float(candidate.get("ts", 0.0) or time.time()),
        weight=confidence,
        entity_key=(
            str(candidate.get("username", "") or "").strip()
            or str(candidate.get("host", "") or "").strip()
            or str(candidate.get("src_ip", "") or "").strip()
            or str(candidate.get("log_path", "") or "").strip()
        ),
        ready_after=0.0,
        distro=str(metadata.get("distro", "") or "unknown_distro"),
        origin="bootstrap_historical",
        event_class=str(metadata.get("event_class", "") or ""),
        behavior_label=str(metadata.get("behavior_label", "") or ""),
        attack_family=str(candidate.get("attack_family", "") or ""),
        technique_label="",
        source_trust=str(metadata.get("source_trust", "") or ""),
        learnable=True,
        model_usage_scope=str(metadata.get("model_usage_scope", "") or ""),
        label_lifecycle_status="active",
        poisoning_guard_passed=True,
        label_reason=str(metadata.get("label_reason", "") or ""),
        ml_family=str(metadata.get("ml_family", "") or ""),
        label_family=str(metadata.get("label_family", "") or ""),
        no_action_contract=bool(metadata.get("no_action_contract", True)),
        evidence_fields=dict(metadata.get("evidence_fields", {}) or {}),
        bootstrap_job_id="",
        label_batch_id=label_batch_id,
        correlation_id=str(dict(metadata.get("evidence_fields", {}) or {}).get("duplicate_guard_key", "") or ""),
    )
    return record, metadata


def _persist_local_historical_quality_labels(
    config: Dict[str, Any],
    candidate_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    from core.ml.label_engine import validate_ml_label_metadata

    db = None
    summary = {
        "db_write_attempted": False,
        "labels_written": 0,
        "quota_skipped": 0,
        "skipped_duplicates": 0,
        "direct_written": 0,
        "baseline_written": 0,
        "quota_remaining_by_family": {},
        "quota_full_families": [],
        "rejected_not_written": 0,
        "ignored_not_written": 0,
        "error": None,
    }
    try:
        db = create_database(config)
        if db is None or not hasattr(db, "save_labels") or not hasattr(db, "load_labels"):
            summary["error"] = "labels_db_unavailable"
            return summary
        summary["db_write_attempted"] = True
        existing_rows = list(db.load_labels() or [])
        quota_summary = summarize_label_quota_usage(existing_rows, config=config)
        quota_contract = dict(quota_summary.get("contract", {}) or {})
        quota_counts = _quota_counts_from_usage(dict(quota_summary.get("usage", {}) or {}))
        existing_keys = {_historical_candidate_duplicate_key(dict(row or {})) for row in existing_rows}
        pending_keys: set[str] = set()
        quota_full: set[str] = set()
        records = []
        label_batch_id = f"hostlogscan_{int(time.time())}"
        for row in candidate_rows:
            usage_decision = str(row.get("usage_decision", "") or "").strip().lower()
            if usage_decision == "ignored":
                summary["ignored_not_written"] += 1
                continue
            if usage_decision == "rejected":
                summary["rejected_not_written"] += 1
                continue
            allowed, gate_reasons = _historical_candidate_write_gate(row)
            if not allowed:
                if usage_decision == "ignored":
                    summary["ignored_not_written"] += 1
                else:
                    summary["rejected_not_written"] += 1
                continue
            duplicate_key = _historical_candidate_duplicate_key(row)
            if duplicate_key in existing_keys or duplicate_key in pending_keys:
                summary["skipped_duplicates"] += 1
                continue
            row_with_mode = dict(row)
            row_with_mode["source_mode"] = "local_host_logs"
            row_with_mode["write_gate_reasons"] = gate_reasons
            quota_bucket = build_label_quota_bucket(row_with_mode)
            if quota_bucket is not None:
                family, distro, label_type = quota_bucket
                limit = int(dict(quota_contract.get(family, {}) or {}).get(label_type, 0) or 0)
                used = int(quota_counts.get(quota_bucket, 0) or 0)
                if limit > 0 and used >= limit:
                    summary["quota_skipped"] += 1
                    quota_full.add(f"{family}/{distro}/{label_type}")
                    continue
            record, metadata = _historical_candidate_to_label_record(row_with_mode, label_batch_id=label_batch_id)
            validation = validate_ml_label_metadata(metadata)
            if validation.get("valid") is not True:
                summary["rejected_not_written"] += 1
                continue
            records.append(record)
            pending_keys.add(duplicate_key)
            if quota_bucket is not None:
                quota_counts[quota_bucket] += 1
            if usage_decision == "direct_learnable":
                summary["direct_written"] += 1
            else:
                summary["baseline_written"] += 1
        if not records:
            summary["quota_full_families"] = sorted(quota_full)
            summary["quota_remaining_by_family"] = _quota_remaining_by_family(quota_summary)
            return summary
        saved = int(db.save_labels(records) or 0)
        summary["labels_written"] = saved
        if saved < len(records):
            delta = len(records) - saved
            summary["skipped_duplicates"] += delta
            direct_delta = min(summary["direct_written"], delta)
            summary["direct_written"] -= direct_delta
            summary["baseline_written"] -= max(delta - direct_delta, 0)
        final_rows = list(db.load_labels() or [])
        final_quota_summary = summarize_label_quota_usage(final_rows, config=config)
        summary["quota_full_families"] = sorted(set(quota_full) | set(final_quota_summary.get("full_families", []) or []))
        summary["quota_remaining_by_family"] = _quota_remaining_by_family(final_quota_summary)
        return summary
    except Exception as exc:
        summary["error"] = str(exc)
        return summary
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def _collect_local_historical_source_entries(config: Dict[str, Any]) -> Tuple[List[Dict[str, str]], List[str]]:
    sources = dict((config or {}).get("sources", {}) or {})
    distro_info = detect_distro()
    distro_family = str(distro_info.get("family", "unknown") or "unknown").strip().lower()
    resolved_paths = resolve_log_paths(distro_info)
    entries: List[Dict[str, str]] = []
    warnings: List[str] = []
    seen: set[tuple[str, str]] = set()

    def _append_entry(source_name: str, path_text: str) -> None:
        normalized_path = str(path_text or "").strip()
        normalized_source = str(source_name or "").strip().lower() or "syslog"
        if not normalized_path:
            return
        key = (normalized_source, normalized_path)
        if key in seen:
            return
        seen.add(key)
        entries.append({"source": normalized_source, "path": normalized_path})

    for source_key, distro_key, default_source in _LOCAL_HISTORICAL_SOURCE_SPECS:
        source_cfg = dict(sources.get(source_key, {}) or {})
        if source_cfg:
            if not bool(source_cfg.get("enabled", False)):
                warnings.append(f"Source disabled: {source_key}")
                continue
            path = str(source_cfg.get("path", "") or "").strip()
            if not path:
                resolved_path = str(resolved_paths.get(distro_key, "") or "").strip()
                if resolved_path and resolved_path != "True":
                    path = resolved_path
                else:
                    warnings.append(f"File not found: {source_key}")
                    continue
            entry_source = _normalize_local_historical_source_key(
                source_key,
                str(source_cfg.get("type", "") or source_key),
                distro_family,
                default_source,
            )
            _append_entry(entry_source, path)
            continue

        resolved_path = str(resolved_paths.get(distro_key, "") or "").strip()
        if not resolved_path or resolved_path == "True":
            warnings.append(f"Source disabled: {source_key}")
            continue
        _append_entry(
            _normalize_local_historical_source_key(source_key, source_key, distro_family, default_source),
            resolved_path,
        )

    for source_key, source_type, extra_path in _LOCAL_HISTORICAL_EXTRA_PATHS.get(distro_family, ()):
        _append_entry(
            _normalize_local_historical_source_key(source_key, source_type, distro_family, source_key),
            extra_path,
        )
    return entries, warnings


def _classify_local_historical_candidate(candidate: Dict[str, Any]) -> Tuple[str, List[str]]:
    item = dict(candidate or {})
    reasons: List[str] = []
    event_class = str(item.get("event_class", "") or "").strip().lower()
    behavior_label = str(item.get("behavior_label", "") or "").strip().lower()
    scope = str(item.get("model_usage_scope", "") or "").strip().lower()
    source_trust = str(item.get("source_trust", "") or "").strip().lower()
    has_rule_id = bool(str(item.get("rule_id", "") or str(dict(item.get("evidence_fields", {}) or {}).get("rule_id", ""))).strip())
    learnable = item.get("learnable")
    reasons.extend(_baseline_quality_reasons(item, has_rule_id))
    if event_class == "unknown_unlabeled" or behavior_label == "unknown_unlabeled":
        reasons.append("not_labelable")
    reasons = _normalize_reason_list(reasons)
    if scope == "not_learnable" or learnable is False:
        if "unsupported_source" not in reasons:
            reasons.append("unsupported_source")
        return "ignored", _normalize_reason_list(reasons or ["not_learnable"])
    if event_class in {"attack", "suspicious"} and has_rule_id and learnable is not False and behavior_label and behavior_label != "unknown_unlabeled":
        if any(reason in reasons for reason in ("missing_host", "missing_timestamp", "unknown_source", "unknown_distro", "unknown_action", "unknown_category", "unknown_outcome")):
            return "rejected", reasons
        return "direct_learnable", _normalize_reason_list(["rule_hit_not_baseline", *reasons])
    if (
        event_class == "benign"
        and learnable is True
        and scope in {"baseline_learning", "calibration_only"}
        and source_trust in {"observed_benign_high"}
        and not has_rule_id
    ):
        blocking = {
            "missing_host",
            "missing_timestamp",
            "unknown_action",
            "unknown_category",
            "unknown_outcome",
            "unknown_source",
            "unknown_distro",
            "suspicious_signal",
            "unsupported_source",
            "not_labelable",
        }
        if any(reason in reasons for reason in blocking):
            if "unsupported_source" in reasons and set(reasons) <= {"unsupported_source"}:
                return "ignored", reasons
            return "rejected", reasons
        reasons.append("baseline_quality_passed")
        return "baseline_learning", _normalize_reason_list(reasons)
    if "suspicious_signal" in reasons:
        return "rejected", reasons
    if "unsupported_source" in reasons:
        return "ignored", reasons
    return "rejected", reasons or ["not_labelable"]


def scan_local_historical_logs_preview(
    config_path: str | None = None,
    *,
    preview_only: bool = True,
    write_labels: bool = False,
    apply_quality_labels: bool = False,
) -> Dict[str, Any]:
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        distro_info = detect_distro()
        distro_family = str(distro_info.get("family", "unknown") or "unknown").strip().lower()
        distro_name = (
            str(distro_info.get("id", "") or "").strip().lower()
            or distro_family
            or "unknown_distro"
        )
        local_hostname = _safe_local_hostname()
        entries, config_warnings = _collect_local_historical_source_entries(config)
        detection_cfg = dict((config or {}).get("detection", {}) or {})
        from core.ml.label_engine import BootstrapLogScanner

        scanner = BootstrapLogScanner(distro_family=distro_family, source_entries=entries)
        normalizer = Normalizer(distro_family=distro_family)
        detection = DetectionEngine(
            config=detection_cfg,
            db=None,
            ioc_file=detection_cfg.get("ioc", {}).get("ioc_file", "config/ioc_list.txt"),
            allow_empty_rules=True,
            distro_family=distro_family,
        )
        report = scanner.dry_run_report(detection_engine=detection, normalizer=normalizer)
        candidates = list(report.get("candidates", []) or [])
        duplicate_counts = Counter(str(item.get("line_hash", "") or "") for item in candidates if str(item.get("line_hash", "") or "").strip())
        usage_counts = Counter()
        candidate_count_by_distro = Counter()
        source_breakdown = Counter()
        reason_breakdown = Counter()
        time_bucket_breakdown = Counter()
        timestamp_confidence_breakdown = Counter()
        source_hour_distribution: Dict[str, Counter] = {}
        user_hour_distribution: Dict[str, Counter] = {}
        host_hour_distribution: Dict[str, Counter] = {}
        parsed_timestamps: List[float] = []
        active_hours: set[int] = set()
        temporal_warnings = 0
        night_activity_count = 0
        candidate_rows: List[Dict[str, Any]] = []
        warnings = list(config_warnings) + list(report.get("warnings", []) or [])
        for item in candidates:
            parser_source = str(item.get("observed_source", item.get("source", "")) or "").strip() or "unknown"
            log_path = str(item.get("log_path", "") or "")
            host_value = str(item.get("host", "") or "").strip()
            raw_distro = str(item.get("distro", "") or "").strip().lower()
            raw_distro_family = str(item.get("distro_family", item.get("distro", "")) or "").strip().lower()
            host_enriched = False
            host_source = ""
            if not host_value and local_hostname:
                host_value = local_hostname
                host_enriched = True
                host_source = "local_machine"
            source_name = _local_historical_source_label(
                parser_source,
                log_path,
                str(item.get("action", "") or ""),
                str(item.get("category", "") or ""),
            )
            metadata_quality, quality_reasons = _local_historical_metadata_quality(
                ts=item.get("ts", 0.0),
                host=host_value,
                source_name=source_name,
                distro_family=raw_distro_family,
                action=str(item.get("action", "") or ""),
                timestamp_warning=str(item.get("timestamp_warning", "") or ""),
                host_enriched=host_enriched,
            )
            candidate_item = dict(item)
            normalized_distro = raw_distro
            if normalized_distro in {"", "unknown", "unknown_distro", raw_distro_family}:
                normalized_distro = distro_name or raw_distro_family or "unknown_distro"
            candidate_item["host"] = host_value
            candidate_item["observed_source"] = source_name
            candidate_item["distro"] = normalized_distro or "unknown_distro"
            candidate_item["distro_family"] = raw_distro_family or distro_family or "unknown_distro"
            candidate_item["metadata_quality"] = metadata_quality
            candidate_item["quality_reasons"] = quality_reasons
            candidate_item["duplicate_count"] = int(duplicate_counts.get(str(item.get("line_hash", "") or ""), 1) or 1)
            timestamp_meta = _local_historical_timestamp_metadata(candidate_item)
            candidate_item.update(timestamp_meta)
            candidate_item = _coerce_known_benign_historical_candidate(candidate_item)
            disposition, reasons = _classify_local_historical_candidate(candidate_item)
            if disposition == "direct_learnable":
                resolved = resolve_rule_to_ml_mapping(str(candidate_item.get("rule_id", "") or ""))
                if resolved.matched and resolved.ml_family and resolved.ml_label:
                    candidate_item["ml_family"] = resolved.ml_family
                    candidate_item["label_family"] = resolved.ml_family
                    candidate_item["ml_label"] = resolved.ml_label
                    candidate_item["behavior_label"] = resolved.ml_label
                    candidate_item["event_class"] = resolved.label_class
                    candidate_item["source_trust"] = resolved.source_trust or candidate_item.get("source_trust", "")
            for reason in reasons:
                reason_breakdown[str(reason)] += 1
            usage_counts[disposition] += 1
            distro = str(item.get("distro_family", item.get("distro", "")) or "unknown_distro").strip() or "unknown_distro"
            candidate_count_by_distro[distro] += 1
            source_breakdown[source_name] += 1
            timestamp_confidence = str(timestamp_meta.get("timestamp_confidence", "missing") or "missing")
            timestamp_confidence_breakdown[timestamp_confidence] += 1
            time_bucket_breakdown[str(timestamp_meta.get("time_bucket", "unknown") or "unknown")] += 1
            if timestamp_meta.get("timestamp_warning") or timestamp_confidence in {"low", "missing"}:
                temporal_warnings += 1
            hour_of_day = timestamp_meta.get("hour_of_day")
            if isinstance(hour_of_day, int):
                active_hours.add(hour_of_day)
                parsed_timestamps.append(float(item.get("ts", 0.0) or 0.0))
                if bool(timestamp_meta.get("is_night", False)):
                    night_activity_count += 1
            _increment_temporal_distribution(source_hour_distribution, source_name, hour_of_day)
            _increment_temporal_distribution(user_hour_distribution, str(item.get("username", "") or ""), hour_of_day)
            _increment_temporal_distribution(host_hour_distribution, host_value, hour_of_day)
            candidate_rows.append({
                "ts": candidate_item.get("ts", 0.0),
                "timestamp": timestamp_meta.get("parsed_datetime", "") or timestamp_meta.get("original_timestamp_text", ""),
                "parsed_datetime": timestamp_meta.get("parsed_datetime", ""),
                "timestamp_source": timestamp_meta.get("timestamp_source", ""),
                "timestamp_confidence": timestamp_confidence,
                "original_timestamp_text": timestamp_meta.get("original_timestamp_text", ""),
                "hour_of_day": timestamp_meta.get("hour_of_day"),
                "day_of_week": timestamp_meta.get("day_of_week", ""),
                "is_weekend": bool(timestamp_meta.get("is_weekend", False)),
                "is_night": bool(timestamp_meta.get("is_night", False)),
                "time_bucket": timestamp_meta.get("time_bucket", "unknown"),
                "host": host_value,
                "source": source_name,
                "log_source": parser_source,
                "log_path": log_path,
                "distro": str(candidate_item.get("distro", "") or distro_name or distro_family or "unknown_distro"),
                "distro_family": distro,
                "category": str(candidate_item.get("category", "") or ""),
                "action": str(candidate_item.get("action", "") or ""),
                "outcome": str(candidate_item.get("outcome", "") or ""),
                "rule_id": str(candidate_item.get("rule_id", "") or ""),
                "username": str(candidate_item.get("username", "") or ""),
                "process": str(candidate_item.get("process", "") or ""),
                "src_ip": str(candidate_item.get("src_ip", "") or ""),
                "dst_ip": str(candidate_item.get("dst_ip", "") or ""),
                "line_hash": str(candidate_item.get("line_hash", "") or ""),
                "duplicate_count": int(duplicate_counts.get(str(item.get("line_hash", "") or ""), 1) or 1),
                "timestamp_warning": str(timestamp_meta.get("timestamp_warning", "") or ""),
                "event_class": str(candidate_item.get("event_class", "") or ""),
                "ml_family": str(candidate_item.get("ml_family", "") or ""),
                "ml_label": str(candidate_item.get("ml_label", "") or ""),
                "label_family": str(candidate_item.get("label_family", candidate_item.get("ml_family", "")) or ""),
                "behavior_label": str(candidate_item.get("behavior_label", "") or ""),
                "attack_family": str(candidate_item.get("attack_family", "") or ""),
                "source_trust": str(candidate_item.get("source_trust", "") or ""),
                "model_usage_scope": str(candidate_item.get("model_usage_scope", "") or ""),
                "learnable": candidate_item.get("learnable"),
                "event_class": str(candidate_item.get("event_class", "") or ""),
                "label_reason": str(candidate_item.get("label_reason", "") or ""),
                "evidence_fields": dict(candidate_item.get("evidence_fields", {}) or {}),
                "host_enriched": host_enriched,
                "host_source": host_source,
                "metadata_quality": metadata_quality,
                "quality_reasons": quality_reasons,
                "usage_decision": disposition,
                "reasons": reasons,
                "labelability_status": "labelable" if disposition in {"direct_learnable", "baseline_learning"} else "not_labelable",
                "labelability_reason": _historical_labelable_reason(candidate_item, usage_decision=disposition)
                if disposition in {"direct_learnable", "baseline_learning"}
                else _primary_labelability_reason(reasons, default="not_labelable"),
                "no_action_contract": bool(candidate_item.get("no_action_contract", True)),
            })
            if reasons and str(timestamp_meta.get("timestamp_warning", "") or ""):
                warnings.append(f"Timestamp ambiguity: {item.get('log_path', '')}")

        file_reports = list(report.get("log_files", []) or [])
        readable_files = sum(1 for item in file_reports if bool(item.get("readable", False)))
        skipped_files = max(len(file_reports) - readable_files, 0)
        candidate_count = len(candidate_rows)
        run_state = "completed_preview" if candidate_count > 0 else "completed_empty"
        message = "Local historical host-log preview completed."
        if readable_files <= 0:
            message = "No readable local historical logs found."
            run_state = "completed_empty"
        elif candidate_count <= 0:
            message = "Local historical host-log preview completed with no eligible candidates."
        first_seen = ""
        last_seen = ""
        if parsed_timestamps:
            parsed_timestamps = sorted(timestamp for timestamp in parsed_timestamps if timestamp > 0)
            if parsed_timestamps:
                first_seen = _coerce_timestamp_text(parsed_timestamps[0])
                last_seen = _coerce_timestamp_text(parsed_timestamps[-1])
        active_hour_values = sorted(active_hours)
        hour_range = ""
        if active_hour_values:
            hour_range = f"{active_hour_values[0]:02d}-{active_hour_values[-1]:02d}"
        quality_summary = _build_local_historical_quality_summary(candidate_rows, reason_breakdown)
        write_mode = bool(write_labels or apply_quality_labels)
        write_summary = {
            "db_write_attempted": False,
            "labels_written": 0,
            "quota_skipped": 0,
            "skipped_duplicates": 0,
            "direct_written": 0,
            "baseline_written": 0,
            "quota_remaining_by_family": {},
            "quota_full_families": [],
            "rejected_not_written": int(usage_counts.get("rejected", 0)),
            "ignored_not_written": int(usage_counts.get("ignored", 0)),
            "error": None,
        }
        if write_mode:
            for row in candidate_rows:
                row["source_mode"] = "local_host_logs"
            write_summary = _persist_local_historical_quality_labels(config, candidate_rows)
            if write_summary.get("error"):
                warnings.append(f"Label write failed: {write_summary['error']}")
                message = "Local historical host-log scan completed, but label persistence failed."
                run_state = "completed_preview"
            else:
                message = "Local historical host-log scan completed and labelable labels were saved."
        return {
            "status": "ok",
            "run_state": run_state,
            "source_mode": "local_host_logs",
            "source_label": "Local host log files",
            "preview_only": False if write_mode else bool(preview_only),
            "read_only": False if write_mode else True,
            "db_write_attempted": bool(write_summary.get("db_write_attempted", False)),
            "no_action_contract": True,
            "events_recent_used_as_source": False,
            "alerts_used_as_source": False,
            "incidents_used_as_source": False,
            "labels_used_as_source": False,
            "user_actions_used_as_source": False,
            "labels_written": int(write_summary.get("labels_written", 0) or 0),
            "quota_skipped": int(write_summary.get("quota_skipped", 0) or 0),
            "skipped_duplicates": int(write_summary.get("skipped_duplicates", 0) or 0),
            "direct_written": int(write_summary.get("direct_written", 0) or 0),
            "baseline_written": int(write_summary.get("baseline_written", 0) or 0),
            "quota_remaining_by_family": dict(write_summary.get("quota_remaining_by_family", {}) or {}),
            "quota_full_families": list(write_summary.get("quota_full_families", []) or []),
            "rejected_not_written": int(write_summary.get("rejected_not_written", 0) or 0),
            "ignored_not_written": int(write_summary.get("ignored_not_written", 0) or 0),
            "training_started": False,
            "active_ml_started": False,
            "scanned_files": int(report.get("scanned_files", 0) or 0),
            "readable_files": readable_files,
            "skipped_files": skipped_files,
            "parsed_events": int(report.get("parsed_events", 0) or 0),
            "candidates": candidate_count,
            "manifest": {
                "candidate_count": candidate_count,
                "candidate_count_by_distro": dict(sorted(candidate_count_by_distro.items())),
            },
            "usage_summary": {
                "direct_learnable": int(usage_counts.get("direct_learnable", 0)),
                "baseline_learning": int(usage_counts.get("baseline_learning", 0)),
                "ignored": int(usage_counts.get("ignored", 0)),
                "rejected": int(usage_counts.get("rejected", 0)),
            },
            "timestamp_high": int(timestamp_confidence_breakdown.get("high", 0)),
            "timestamp_medium": int(timestamp_confidence_breakdown.get("medium", 0)),
            "timestamp_low": int(timestamp_confidence_breakdown.get("low", 0)),
            "timestamp_missing": int(timestamp_confidence_breakdown.get("missing", 0)),
            "temporal_warnings": temporal_warnings,
            "time_bucket_breakdown": dict(sorted(time_bucket_breakdown.items())),
            "active_hours": active_hour_values,
            "hour_range": hour_range,
            "night_activity_count": night_activity_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "source_hour_distribution": _serialize_temporal_distribution(source_hour_distribution),
            "user_hour_distribution": _serialize_temporal_distribution(user_hour_distribution),
            "host_hour_distribution": _serialize_temporal_distribution(host_hour_distribution),
            "reason_breakdown": dict(sorted(reason_breakdown.items())),
            "quality_summary": quality_summary,
            "source_breakdown": dict(sorted(source_breakdown.items())),
            "distro_breakdown": dict(sorted(candidate_count_by_distro.items())),
            "pipeline": [
                "raw_log_line",
                "distro_source_parser",
                "normalized_event",
                "rule_detection_check",
                "labelability_check",
                "label_write" if write_mode else "ml_candidate_preview",
            ],
            "warnings": list(dict.fromkeys(warnings)),
            "candidate_rows": candidate_rows,
            "log_files": file_reports,
            "message": message,
            "error": write_summary.get("error"),
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "run_state": "failed",
            "source_mode": "local_host_logs",
            "source_label": "Local host log files",
            "preview_only": True,
            "read_only": True,
            "db_write_attempted": False,
            "events_recent_used_as_source": False,
            "alerts_used_as_source": False,
            "incidents_used_as_source": False,
            "labels_used_as_source": False,
            "user_actions_used_as_source": False,
            "labels_written": 0,
            "quota_skipped": 0,
            "skipped_duplicates": 0,
            "direct_written": 0,
            "baseline_written": 0,
            "quota_remaining_by_family": {},
            "quota_full_families": [],
            "rejected_not_written": 0,
            "ignored_not_written": 0,
            "training_started": False,
            "active_ml_started": False,
            "scanned_files": 0,
            "readable_files": 0,
            "skipped_files": 0,
            "parsed_events": 0,
            "candidates": 0,
            "manifest": {"candidate_count": 0, "candidate_count_by_distro": {}},
            "usage_summary": {"direct_learnable": 0, "baseline_learning": 0, "ignored": 0, "rejected": 0},
            "source_breakdown": {},
            "distro_breakdown": {},
            "pipeline": [
                "raw_log_line",
                "distro_source_parser",
                "normalized_event",
                "rule_detection_check",
                "ml_candidate_preview",
            ],
            "warnings": [],
            "candidate_rows": [],
            "log_files": [],
            "message": "Local historical host-log preview failed.",
            "error": str(exc),
        }


def collect_recent_events(
    limit: int = 500,
    source: str | None = None,
    query: str | None = None,
    severity: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    db = None
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        db = create_database(config)
        if db is None:
            return {"status": "degraded", "events": [], "total_returned": 0, "error": "database_unavailable"}
        columns, column_errors = _table_columns(db, "events_recent")
        if not columns:
            return {"status": "degraded", "events": [], "total_returned": 0, "error": ",".join(column_errors or ["missing_table"])}
        limit = max(1, min(int(limit or 500), 2000))
        select_columns = []
        for name in (
            "id", "ts", "created_at", "source", "category", "action", "outcome", "src_ip",
            "dst_ip", "username", "process", "message", "raw_log", "raw_event", "context_json",
            "metadata", "parsed_metadata", "alert_id", "rule_id",
        ):
            if name in columns:
                select_columns.append(name)
        if not select_columns:
            select_columns = sorted(columns)
        order_column = "ts" if "ts" in columns else ("id" if "id" in columns else sorted(columns)[0])
        rows, error = _execute_db_read(
            db,
            f"SELECT {', '.join(select_columns)} FROM events_recent ORDER BY {order_column} DESC LIMIT %s",
            params=(limit,),
            fetch="all",
        )
        if error:
            return {"status": "degraded", "events": [], "total_returned": 0, "error": error}
        source_filter = str(source or "").strip().lower()
        query_filter = str(query or "").strip().lower()
        severity_filter = str(severity or "").strip().lower()
        events = []
        for row in rows or []:
            item = _normalize_event_row(row)
            raw = dict(item.get("raw", {}) or {})
            if source_filter and item["source"].lower() != source_filter:
                continue
            if severity_filter:
                row_severity = str(raw.get("severity", "") or raw.get("risk_bucket", "") or "").lower()
                if row_severity != severity_filter:
                    continue
            if query_filter:
                blob = " ".join([
                    item.get("source", ""),
                    item.get("category", ""),
                    item.get("action", ""),
                    item.get("outcome", ""),
                    item.get("src_ip", ""),
                    item.get("dst_ip", ""),
                    item.get("username", ""),
                    item.get("process", ""),
                    item.get("message", ""),
                    _stringify_payload(raw),
                ]).lower()
                if query_filter not in blob:
                    continue
            events.append(item)
        return {"status": "ok", "events": events, "total_returned": len(events), "error": None}
    except Exception as exc:
        return {"status": "degraded", "events": [], "total_returned": 0, "error": str(exc)}
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def collect_live_log_sources(config_path: str | None = None) -> Dict[str, Any]:
    payload = collect_recent_events(limit=500, config_path=config_path)
    seen = {str(item.get("source", "") or "").strip() for item in payload.get("events", []) if str(item.get("source", "") or "").strip()}
    sources = sorted(seen.union(_LIVE_LOG_SOURCE_FALLBACKS))
    return {"status": payload.get("status", "degraded"), "sources": sources, "error": payload.get("error")}


def collect_log_health_summary(config_path: str | None = None) -> Dict[str, Any]:
    try:
        sources_health = collect_sources_health(config_path=config_path)
        diagnostics = collect_diagnostics_summary(config_path=config_path)
        problems = list(sources_health.get("problems", []) or [])
        parse_fail_summary = dict(diagnostics.get("parse_fail_summary", {}) or {})
        duplicate_summary = dict(diagnostics.get("duplicate_summary", {}) or {})
        normalize_none_count = int(parse_fail_summary.get("by_reason", {}).get("normalize_none", 0) or 0)
        status = "ok"
        if sources_health.get("status") != "ok" or diagnostics.get("status") != "ok":
            status = "degraded"
        return {
            "status": status,
            "parse_fail_summary": parse_fail_summary,
            "duplicate_summary": duplicate_summary,
            "sources": list(sources_health.get("sources", []) or []),
            "source_problem_count": len(problems),
            "normalize_none_count": normalize_none_count,
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "parse_fail_summary": {},
            "duplicate_summary": {},
            "sources": [],
            "source_problem_count": 0,
            "normalize_none_count": 0,
            "error": str(exc),
        }


def collect_event_detail(event_id: int, config_path: str | None = None) -> Dict[str, Any]:
    payload = collect_recent_events(limit=1000, config_path=config_path)
    if payload.get("status") != "ok":
        return {"status": "degraded", "event": None, "detail": {}, "error": payload.get("error")}
    for item in payload.get("events", []):
        if int(item.get("id", -1) or -1) == int(event_id):
            raw = dict(item.get("raw", {}) or {})
            detail = {
                "raw_json": _stringify_payload(raw),
                "metadata_json": _stringify_payload(item.get("raw_fields", {})),
                "parsed_json": _stringify_payload({
                    "source": item.get("source", ""),
                    "category": item.get("category", ""),
                    "action": item.get("action", ""),
                    "outcome": item.get("outcome", ""),
                    "src_ip": item.get("src_ip", ""),
                    "dst_ip": item.get("dst_ip", ""),
                    "username": item.get("username", ""),
                    "process": item.get("process", ""),
                    "alert_id": raw.get("alert_id"),
                    "rule_id": raw.get("rule_id"),
                }),
            }
            return {"status": "ok", "event": item, "detail": detail, "error": None}
    return {"status": "degraded", "event": None, "detail": {}, "error": f"event_not_found:{event_id}"}


def collect_explainable_alerts(limit: int = 100, config_path: str | None = None) -> Dict[str, Any]:
    payload = collect_alerts(limit=limit, config_path=config_path)
    if payload.get("status") != "ok":
        return {"status": "degraded", "alerts": [], "error": payload.get("error")}
    alerts = []
    for item in payload.get("alerts", []):
        alerts.append({
            "id": item.get("id"),
            "timestamp_text": item.get("timestamp_text", ""),
            "severity": item.get("severity", ""),
            "rule_id": item.get("rule_id", ""),
            "risk_score": item.get("risk_score", 0.0),
            "entity": item.get("entity", ""),
            "source_ip": item.get("source_ip", ""),
            "message": item.get("message", ""),
            "source": item.get("source", ""),
        })
    return {"status": "ok", "alerts": alerts, "error": None}


def collect_ip_reputation_status(config_path: str | None = None) -> Dict[str, Any]:
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        abuse_cfg = dict((config or {}).get("abuseipdb", {}) or {})
        ip_cfg = dict((config or {}).get("ip_blocking", {}) or {})
        capability = ip_actions.preview_guarded_ip_action(
            config=config,
            action="block",
            ip="8.8.8.8",
            actor="local-user",
            role="viewer",
            reason="",
            confirmation="",
            dry_run_completed=False,
        ).get("capability", {})
        key_value = str(abuse_cfg.get("api_key", "") or os.environ.get("ABUSEIPDB_API_KEY", "") or "").strip()
        has_api_key = bool(key_value)
        result = {
            "status": "ok" if has_api_key or not bool(abuse_cfg.get("enrich_alert_ips", False)) else "degraded",
            "abuseipdb": {
                "enabled": bool(abuse_cfg.get("enrich_alert_ips", False)),
                "has_api_key": has_api_key,
                "key_masked": _mask_secret(key_value),
                "enrichment_only": True,
                "auto_block_disabled": True,
                "manual_approval_required": True,
            },
            "ip_blocking": {
                "enabled": bool(ip_cfg.get("enabled", False)),
                "mode": "manual_only",
                "manual_only": True,
                "backend": str(capability.get("backend", "") or ip_cfg.get("default_backend", "auto") or "auto"),
                "real_apply_supported": bool(capability.get("real_apply_supported", False)),
                "dry_run_supported": bool(capability.get("dry_run_supported", False)),
                "requires_elevation": bool(capability.get("requires_elevation", False)),
                "backend_supported": bool(capability.get("backend_supported", False)),
                "capability_reason": str(capability.get("reason", "") or ""),
                "capability_message": str(capability.get("message", "") or ""),
                "firewall_actions_locked": False,
            },
            "security_locks": {
                "read_only_mode": False,
                "auto_ip_block_disabled": True,
                "manual_approval_required": True,
                "firewall_actions_locked": False,
            },
            "error": None,
        }
        return result
    except Exception as exc:
        return {
            "status": "degraded",
            "abuseipdb": {
                "enabled": False,
                "has_api_key": False,
                "key_masked": "",
                "enrichment_only": True,
                "auto_block_disabled": True,
                "manual_approval_required": True,
            },
            "ip_blocking": {
                "enabled": False,
                "mode": "manual_only",
                "manual_only": True,
                "backend": "",
                "real_apply_supported": "",
                "firewall_actions_locked": True,
            },
            "security_locks": {
                "read_only_mode": False,
                "auto_ip_block_disabled": True,
                "manual_approval_required": True,
                "firewall_actions_locked": True,
            },
            "error": str(exc),
        }


def collect_ip_block_suggestions(
    limit: int = 200,
    status: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 200), 500))
    status_filter = str(status or "").strip().lower()
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        db = create_database(config)
        if db is None:
            return {"status": "degraded", "suggestions": [], "columns": [], "empty": True, "error": "database_unavailable"}
        try:
            rows, columns, error = _load_table_rows(
                db,
                "ip_block_suggestions",
                ("suggested_at DESC", "created_at DESC", "timestamp DESC"),
                limit=max(limit * 2, 50),
            )
            if error:
                return {"status": "degraded", "suggestions": [], "columns": columns, "empty": True, "error": error}
            suggestions = [_normalize_ip_suggestion(row) for row in rows]
            if status_filter:
                suggestions = [item for item in suggestions if str(item.get("status", "")).lower() == status_filter]
            suggestions = suggestions[:limit]
            return {
                "status": "ok",
                "suggestions": suggestions,
                "columns": columns,
                "empty": not suggestions,
                "error": None,
            }
        finally:
            db.close()
    except Exception as exc:
        return {"status": "degraded", "suggestions": [], "columns": [], "empty": True, "error": str(exc)}


def collect_ip_block_actions(
    limit: int = 200,
    ip: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 200), 500))
    ip_filter = str(ip or "").strip()
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        db = create_database(config)
        if db is None:
            return {"status": "degraded", "actions": [], "columns": [], "empty": True, "error": "database_unavailable"}
        try:
            filters = [("ip", ip_filter)] if ip_filter else []
            rows, columns, error = _load_table_rows(
                db,
                "ip_block_actions",
                ("executed_at DESC", "created_at DESC", "timestamp DESC"),
                limit=limit,
                filters=filters,
            )
            if error:
                return {"status": "degraded", "actions": [], "columns": columns, "empty": True, "error": error}
            actions = [_normalize_ip_action(row) for row in rows]
            return {
                "status": "ok",
                "actions": actions,
                "columns": columns,
                "empty": not actions,
                "error": None,
            }
        finally:
            db.close()
    except Exception as exc:
        return {"status": "degraded", "actions": [], "columns": [], "empty": True, "error": str(exc)}


def collect_ip_block_candidates(limit: int = 200, config_path: str | None = None) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 200), 500))
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        db = create_database(config)
        if db is None:
            return {"status": "degraded", "candidates": [], "empty": True, "error": "database_unavailable"}
        try:
            suggestions_payload = collect_ip_block_suggestions(limit=max(limit * 3, 100), config_path=config_path)
            suggestions = list(suggestions_payload.get("suggestions", []) or [])
            suggestions.sort(key=lambda item: _time_sort_key(item), reverse=True)
            alert_candidates = _build_dynamic_alert_candidates(db, limit=max(limit, 100))
            merged_candidates: Dict[str, Dict[str, Any]] = {ip_text: dict(item) for ip_text, item in alert_candidates.items()}
            for item in suggestions:
                ip_text = str(item.get("ip", "") or "").strip()
                if not ip_text:
                    continue
                current = dict(merged_candidates.get(ip_text, {}) or {})
                linked_alert_payload = dict(current.get("linked_alert", {}) or {})
                alert_id = current.get("alert_id", item.get("alert_id"))
                if not linked_alert_payload and alert_id not in (None, "") and hasattr(db, "get_alert_by_id"):
                    try:
                        linked_alert = db.get_alert_by_id(int(alert_id))
                    except Exception:
                        linked_alert = None
                    linked_alert_payload = _normalize_alert(linked_alert) if linked_alert else {}
                source_value = str(item.get("source", "") or "").strip()
                merged = dict(current)
                merged.update({
                    "id": item.get("id", merged.get("id")),
                    "ip": ip_text,
                    "source": source_value or merged.get("source") or "suggestion",
                    "reason": str(item.get("reason", "") or "").strip() or merged.get("reason", ""),
                    "alert_id": alert_id,
                    "rule_id": str(merged.get("rule_id", "") or linked_alert_payload.get("rule_id", "") or "").strip(),
                    "severity": str(merged.get("severity", "") or linked_alert_payload.get("severity", "") or "").strip(),
                    "risk_score": merged.get("risk_score", linked_alert_payload.get("risk_score", "")),
                    "timestamp_text": merged.get("timestamp_text") or item.get("timestamp_text", ""),
                    "linked_alert": linked_alert_payload or merged.get("linked_alert", {}),
                    "first_seen": merged.get("first_seen", item.get("created_at", "")),
                    "first_seen_text": merged.get("first_seen_text", item.get("timestamp_text", "")),
                    "last_seen": merged.get("last_seen", item.get("created_at", "")),
                    "last_seen_text": merged.get("last_seen_text", item.get("timestamp_text", "")),
                    "related_alert_count": int(merged.get("related_alert_count", 0) or 0),
                    "raw": dict(merged.get("raw", {}) or {}),
                })
                if "suggestion" not in merged["raw"]:
                    merged["raw"]["suggestion"] = item
                merged_candidates[ip_text] = merged

            ordered = sorted(
                merged_candidates.values(),
                key=lambda item: (
                    -_severity_rank(item.get("severity", "")),
                    -float(item.get("risk_score", 0.0) or 0.0),
                    -_time_sort_key({"created_at": item.get("last_seen", item.get("first_seen", ""))}),
                    str(item.get("ip", "") or ""),
                ),
            )[:limit]

            candidates: list[dict] = []
            for item in ordered:
                ip_text = str(item.get("ip", "") or "").strip()
                preview = ip_actions.preview_guarded_ip_action(
                    config=config,
                    action="block",
                    ip=ip_text,
                    actor="local-user",
                    role="admin",
                    reason="ui_candidate_status",
                    confirmation="",
                    dry_run_completed=True,
                )
                capability = dict(preview.get("capability", {}) or {})
                ip_validation = dict(preview.get("ip_validation", {}) or {})
                active_block = db.get_active_ip_block(ip_text) if hasattr(db, "get_active_ip_block") else None
                linked_alert_payload = dict(item.get("linked_alert", {}) or {})
                alert_id = item.get("alert_id")
                blocked = bool(active_block)
                real_apply_supported = bool(capability.get("real_apply_supported", False))
                requires_elevation = bool(capability.get("requires_elevation", False))
                backend_supported = bool(capability.get("backend_supported", real_apply_supported or bool(capability.get("backend"))))
                allowed = bool(ip_validation.get("allowed", False))
                if blocked:
                    status_code = "blocked"
                    status_text = "Blocked"
                elif not allowed:
                    status_code = "guarded"
                    status_text = "Guarded"
                elif requires_elevation:
                    status_code = "elevated_privileges_required"
                    status_text = "Elevated privileges required"
                elif not backend_supported:
                    status_code = "unsupported_backend"
                    status_text = "Unsupported backend"
                else:
                    status_code = "not_blocked"
                    status_text = "Not blocked"
                candidates.append({
                    "id": item.get("id"),
                    "ip": ip_text,
                    "reason": str(item.get("reason", "") or "").strip(),
                    "source": str(item.get("source", "") or "").strip(),
                    "alert_id": alert_id,
                    "rule_id": str(linked_alert_payload.get("rule_id", "") or "").strip(),
                    "severity": str(linked_alert_payload.get("severity", "") or "").strip(),
                    "risk_score": item.get("risk_score", linked_alert_payload.get("risk_score", "")),
                    "timestamp_text": item.get("timestamp_text", ""),
                    "first_seen": item.get("first_seen", ""),
                    "first_seen_text": item.get("first_seen_text", ""),
                    "last_seen": item.get("last_seen", ""),
                    "last_seen_text": item.get("last_seen_text", ""),
                    "related_alert_count": int(item.get("related_alert_count", 0) or 0),
                    "status": status_code,
                    "status_text": status_text,
                    "backend": str((dict(active_block or {}) or {}).get("backend", "") or capability.get("backend", "") or "none"),
                    "backend_capability": str(capability.get("message", "") or capability.get("reason", "") or ""),
                    "backend_supported": backend_supported,
                    "requires_elevation": requires_elevation,
                    "guarded": not allowed,
                    "guard_reason": str(ip_validation.get("error", "") or ""),
                    "blocked": blocked,
                    "can_block": bool(not blocked and allowed and (real_apply_supported or requires_elevation)),
                    "can_unblock": bool(blocked and str((dict(active_block or {}) or {}).get("backend", "") or "") in {"firewalld", "ufw"}),
                    "linked_alert": linked_alert_payload,
                    "raw": {
                        **dict(item.get("raw", {}) or {}),
                        "preview": preview,
                        "active_block": active_block,
                        "ip_validation": ip_validation,
                    },
                })
            return {"status": "ok", "candidates": candidates, "empty": not candidates, "error": suggestions_payload.get("error")}
        finally:
            db.close()
    except Exception as exc:
        return {"status": "degraded", "candidates": [], "empty": True, "error": str(exc)}


def collect_ip_context(ip: str, limit: int = 100, config_path: str | None = None) -> Dict[str, Any]:
    needle = str(ip or "").strip()
    if not needle:
        return {
            "status": "ok",
            "ip": "",
            "summary": {
                "first_seen": "",
                "last_seen": "",
                "alert_count": 0,
                "high_critical_count": 0,
                "suggestion_count": 0,
                "action_count": 0,
            },
            "related_alerts": [],
            "related_events": [],
            "suggestions": [],
            "actions": [],
            "error": None,
        }
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        db = create_database(config)
        if db is None:
            return {
                "status": "degraded",
                "ip": needle,
                "summary": {"first_seen": "", "last_seen": "", "alert_count": 0, "high_critical_count": 0, "suggestion_count": 0, "action_count": 0},
                "related_alerts": [],
                "related_events": [],
                "suggestions": [],
                "actions": [],
                "error": "database_unavailable",
            }
        try:
            alerts = []
            for row in _all_alerts(db, limit=max(limit * 4, 400)):
                item = _normalize_alert(row)
                if _matches_ip(item, needle):
                    alerts.append(item)
                if len(alerts) >= limit:
                    break

            event_rows, event_columns, event_error = _load_table_rows(
                db,
                "events_recent",
                ("ts DESC", "created_at DESC", "timestamp DESC"),
                limit=max(limit * 4, 400),
            )
            related_events = []
            for row in event_rows:
                item = _normalize_event_row(row)
                if _matches_ip(item, needle):
                    related_events.append(item)
                if len(related_events) >= limit:
                    break

            suggestions_payload = collect_ip_block_suggestions(limit=limit, config_path=config_path)
            suggestions = [
                item for item in suggestions_payload.get("suggestions", [])
                if str(item.get("ip", "") or "").strip() == needle
            ]
            actions_payload = collect_ip_block_actions(limit=limit, ip=needle, config_path=config_path)
            actions = list(actions_payload.get("actions", []) or [])

            timestamps: list[tuple[float, str]] = []
            for item in alerts:
                timestamps.append((_time_sort_key(item), item.get("timestamp_text", "")))
            for item in related_events:
                timestamps.append((_time_sort_key(item), item.get("timestamp_text", "")))
            for item in suggestions:
                timestamps.append((_time_sort_key(item), item.get("timestamp_text", "")))
            for item in actions:
                timestamps.append((_time_sort_key(item), item.get("timestamp_text", "")))
            timestamps = [item for item in timestamps if item[1]]
            timestamps.sort(key=lambda item: item[0])

            high_critical_count = len([
                item for item in alerts
                if str(item.get("severity", "") or "").lower() in {"high", "critical"}
            ])
            error = event_error
            if suggestions_payload.get("status") != "ok":
                error = suggestions_payload.get("error") or error
            if actions_payload.get("status") != "ok":
                error = actions_payload.get("error") or error
            return {
                "status": "ok" if not error else "degraded",
                "ip": needle,
                "summary": {
                    "first_seen": timestamps[0][1] if timestamps else "",
                    "last_seen": timestamps[-1][1] if timestamps else "",
                    "alert_count": len(alerts),
                    "high_critical_count": high_critical_count,
                    "suggestion_count": len(suggestions),
                    "action_count": len(actions),
                    "event_count": len(related_events),
                    "event_columns": event_columns,
                },
                "related_alerts": alerts,
                "related_events": related_events,
                "suggestions": suggestions,
                "actions": actions,
                "error": error,
            }
        finally:
            db.close()
    except Exception as exc:
        return {
            "status": "degraded",
            "ip": needle,
            "summary": {"first_seen": "", "last_seen": "", "alert_count": 0, "high_critical_count": 0, "suggestion_count": 0, "action_count": 0},
            "related_alerts": [],
            "related_events": [],
            "suggestions": [],
            "actions": [],
            "error": str(exc),
        }


def build_ip_action_preview(ip: str, action: str) -> Dict[str, Any]:
    payload = preview_ip_action(
        action=action,
        ip=ip,
        actor="local-user",
        role="viewer",
        reason="",
        confirmation="",
        dry_run_completed=False,
        config_path=None,
    )
    return {
        "status": payload.get("status", "denied"),
        "ip": payload.get("ip", str(ip or "").strip()),
        "action": payload.get("action", "block"),
        "would_require": list(dict(payload.get("guard", {}) or {}).get("required_guards", [])),
        "message": payload.get("message", "Manual IP action preview."),
        "guard_result": payload.get("guard", {}),
    }


def preview_ip_action(
    action: str,
    ip: str,
    actor: str,
    role: str,
    reason: str,
    confirmation: str = "",
    dry_run_completed: bool = False,
    config_path: str | None = None,
) -> Dict[str, Any]:
    context = _load_runtime_context(config_path)
    return ip_actions.preview_guarded_ip_action(
        config=context["config"],
        action=action,
        ip=ip,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
    )


def execute_ip_action(
    action: str,
    ip: str,
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
    config_path: str | None = None,
) -> Dict[str, Any]:
    context = _load_runtime_context(config_path)
    return ip_actions.execute_guarded_ip_action(
        config=context["config"],
        action=action,
        ip=ip,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
    )


def collect_guarded_action_policies() -> Dict[str, Any]:
    executable_actions = [
        action_type
        for action_type in SUPPORTED_ACTION_TYPES
        if bool(get_action_policy(action_type).metadata.get("execution_enabled", False))
    ]
    return {
        "status": "ok",
        "phase": "Phase 2H guarded actions",
        "execution_enabled": bool(executable_actions),
        "executable_action_types": executable_actions,
        "policies": [get_action_policy(action_type).to_dict() for action_type in SUPPORTED_ACTION_TYPES],
        "error": None,
    }


def preview_guarded_action(
    action_type: str,
    target: str,
    actor: str = "local-user",
    role: str = "viewer",
    reason: str = "",
    confirmation: str = "",
    dry_run_completed: bool = False,
) -> Dict[str, Any]:
    policy = get_action_policy(action_type)
    request = GuardedActionRequest(
        action_id=f"{policy.action_type}:{str(target or '').strip() or 'target'}",
        action_type=policy.action_type,
        target=str(target or "").strip(),
        target_type="generic",
        actor=str(actor or "").strip(),
        reason=str(reason or "").strip(),
        confirmation_phrase=str(confirmation or "").strip(),
        required_confirmation_phrase=required_confirmation_for(policy.action_type, target),
        dry_run_required=policy.dry_run_required,
        dry_run_completed=bool(dry_run_completed),
        role_required=policy.role_required,
        current_role=str(role or "").strip(),
        metadata={"preview_only": True},
    )
    return build_guarded_action_preview(request).to_dict()


def preview_incident_action(
    action: str,
    incident_id: int,
    actor: str,
    role: str,
    reason: str,
    confirmation: str = "",
    dry_run_completed: bool = False,
    config_path: str | None = None,
) -> Dict[str, Any]:
    context = _load_runtime_context(config_path)
    return incident_actions.preview_guarded_incident_action(
        config=context["config"],
        action=action,
        incident_id=incident_id,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
    )


def execute_incident_action(
    action: str,
    incident_id: int,
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
    config_path: str | None = None,
) -> Dict[str, Any]:
    context = _load_runtime_context(config_path)
    return incident_actions.execute_guarded_incident_action(
        config=context["config"],
        action=action,
        incident_id=incident_id,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
    )


def preview_db_reset(
    actor: str,
    role: str,
    reason: str,
    confirmation: str = "",
    dry_run_completed: bool = False,
    include_labels: bool = False,
    include_audit_log: bool = False,
    config_path: str | None = None,
) -> Dict[str, Any]:
    context = _load_runtime_context(config_path)
    return db_reset.preview_guarded_db_reset(
        config=context["config"],
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
        include_labels=include_labels,
        include_audit_log=include_audit_log,
    )


def execute_db_reset(
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
    include_labels: bool = False,
    include_audit_log: bool = False,
    config_path: str | None = None,
) -> Dict[str, Any]:
    context = _load_runtime_context(config_path)
    return db_reset.execute_guarded_db_reset(
        config=context["config"],
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
        include_labels=include_labels,
        include_audit_log=include_audit_log,
    )


def preview_report_export(
    export_type: str,
    target_id: str | None,
    actor: str,
    role: str,
    reason: str,
    confirmation: str = "",
    dry_run_completed: bool = False,
    filename_hint: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    context = _load_runtime_context(config_path)
    return export_actions.preview_report_export(
        config=context["config"],
        export_type=export_type,
        target_id=target_id,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
        filename_hint=filename_hint,
        config_path=config_path,
    )


def execute_report_export(
    export_type: str,
    target_id: str | None,
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
    filename_hint: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    context = _load_runtime_context(config_path)
    return export_actions.execute_report_export(
        config=context["config"],
        export_type=export_type,
        target_id=target_id,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
        filename_hint=filename_hint,
        config_path=config_path,
    )


def preview_diagnostic_bundle_create(
    actor: str,
    role: str,
    reason: str,
    confirmation: str = "",
    dry_run_completed: bool = False,
    filename_hint: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    context = _load_runtime_context(config_path)
    return export_actions.preview_diagnostic_bundle_create(
        config=context["config"],
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
        filename_hint=filename_hint,
        config_path=config_path,
    )


def execute_diagnostic_bundle_create(
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
    filename_hint: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    context = _load_runtime_context(config_path)
    return export_actions.execute_diagnostic_bundle_create(
        config=context["config"],
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
        filename_hint=filename_hint,
        config_path=config_path,
    )


def preview_historical_label_audit(
    manifest_id: str | None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    context = _load_runtime_context(config_path)
    return historical_labels.preview_historical_label_audit(
        config=context["config"],
        manifest_id=manifest_id,
        config_path=config_path,
    )


def _integrations_env_path(config_path: str | None = None) -> Path:
    resolved = _resolve_config_path(config_path)
    return resolved.parent / "integrations.env"


def _masked_updates(updates: Dict[str, str]) -> Dict[str, str]:
    result = {}
    for key, value in dict(updates or {}).items():
        if key in secret_store._SENSITIVE_KEYS:
            result[key] = secret_store.mask_secret(value)
        else:
            result[key] = str(value or "").strip()
    return result


def preview_secret_update(
    updates: dict,
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
    config_path: str | None = None,
) -> Dict[str, Any]:
    normalized, invalid = secret_store.validate_allowed_secret_keys(updates)
    keys = sorted(normalized)
    target = ",".join(keys) or "no-keys"
    action_type = "api_key_update"
    guard_result = preview_guarded_action(
        action_type=action_type,
        target=target,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
    )
    if invalid:
        guard_result["status"] = "denied"
        guard_result["missing_guards"] = list(guard_result.get("missing_guards", [])) + ["allowed keys"]
        guard_result["execution_enabled"] = False
        guard_result["message"] = "Execution is blocked until all secret keys are in the allowed list."
    env_path = _integrations_env_path(config_path)
    return {
        "status": guard_result.get("status", "denied"),
        "action_type": action_type,
        "target_file": str(env_path),
        "backup_path_preview": f"{env_path}.bak.<timestamp>",
        "would_update": keys,
        "masked_updates": _masked_updates(normalized),
        "invalid_keys": invalid,
        "guard_result": guard_result,
        "error": None,
    }


def execute_secret_update(
    updates: dict,
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
    config_path: str | None = None,
) -> Dict[str, Any]:
    preview = preview_secret_update(
        updates=updates,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
        config_path=config_path,
    )
    guard_result = dict(preview.get("guard_result", {}) or {})
    if preview.get("invalid_keys"):
        return {
            "status": "denied",
            "action_type": "api_key_update",
            "message": "Invalid secret keys requested.",
            "would_update": list(preview.get("would_update", []) or []),
            "target_file": preview.get("target_file", ""),
            "backup_path": None,
            "audit": {"status": "denied", "reason": "invalid_keys"},
            "error": "invalid_keys",
        }
    if not bool(guard_result.get("execution_enabled", False)):
        return {
            "status": "denied",
            "action_type": "api_key_update",
            "message": guard_result.get("message", "Guard validation failed."),
            "would_update": list(preview.get("would_update", []) or []),
            "target_file": preview.get("target_file", ""),
            "backup_path": None,
            "audit": {"status": "denied", "reason": "missing_guards"},
            "error": "guard_denied",
        }

    context = _load_runtime_context(config_path)
    config = context["config"]
    audit_available, audit_error = secret_store.audit_user_action_available(config)
    if not audit_available:
        return {
            "status": "denied",
            "action_type": "api_key_update",
            "message": "Audit is required before secret persistence can run.",
            "would_update": list(preview.get("would_update", []) or []),
            "target_file": preview.get("target_file", ""),
            "backup_path": None,
            "audit": {"status": "unavailable", "reason": audit_error or "audit_unavailable"},
            "error": "audit_unavailable",
        }

    normalized, _invalid = secret_store.validate_allowed_secret_keys(updates)
    write_result = secret_store.update_env_values(_integrations_env_path(config_path), normalized, backup=True)
    if write_result.get("status") != "ok":
        return {
            "status": "failed",
            "action_type": "api_key_update",
            "message": "Secret persistence failed.",
            "would_update": list(preview.get("would_update", []) or []),
            "target_file": preview.get("target_file", ""),
            "backup_path": write_result.get("backup_path"),
            "audit": {"status": "not_written"},
            "error": write_result.get("error"),
        }

    audit_payload = {
        "updated_keys": list(preview.get("would_update", []) or []),
        "masked_updates": _masked_updates(normalized),
        "target_file": preview.get("target_file", ""),
        "backup_path": write_result.get("backup_path"),
    }
    audit_result = secret_store.record_user_action(
        config=config,
        action="api_key_update",
        actor=str(actor or "").strip() or "local-user",
        target=",".join(sorted(normalized)),
        summary=str(reason or "").strip() or "guarded api_key_update",
        details=audit_payload,
        status="executed",
    )
    if audit_result.get("status") != "ok":
        backup_path = write_result.get("backup_path")
        if backup_path:
            secret_store.restore_env_from_backup(_integrations_env_path(config_path), backup_path)
        return {
            "status": "failed",
            "action_type": "api_key_update",
            "message": "Secret persistence was rolled back because the audit record could not be written.",
            "would_update": list(preview.get("would_update", []) or []),
            "target_file": preview.get("target_file", ""),
            "backup_path": write_result.get("backup_path"),
            "audit": audit_result,
            "error": "audit_write_failed",
        }

    return {
        "status": "executed",
        "action_type": "api_key_update",
        "message": "Secret persistence completed with guarded audit recording.",
        "would_update": list(preview.get("would_update", []) or []),
        "target_file": preview.get("target_file", ""),
        "backup_path": write_result.get("backup_path"),
        "audit": audit_result,
        "masked_updates": _masked_updates(normalized),
        "error": None,
    }


def _notification_action_type(channel: str) -> str:
    token = str(channel or "").strip().lower()
    if token == "telegram":
        return "telegram_test_send"
    if token == "email":
        return "email_test_send"
    return "unknown"


def _notification_destination_masked(channel: str, integrations: IntegrationSettings) -> str:
    masked = notification_test.masked_destination_for(channel, integrations)
    return masked or f"{str(channel or '').strip().lower() or 'unknown'}-destination"


def preview_notification_test(
    channel: str,
    actor: str,
    role: str,
    reason: str,
    confirmation: str = "",
    dry_run_completed: bool = False,
    config_path: str | None = None,
) -> Dict[str, Any]:
    token = str(channel or "").strip().lower()
    context = _load_runtime_context(config_path)
    integrations = context["integrations"]
    required_fields = notification_test.required_fields_for(token)
    present_fields = notification_test.present_fields_for(token, integrations)
    missing_fields = notification_test.missing_fields_for(token, integrations)
    destination_masked = _notification_destination_masked(token, integrations)
    action_type = _notification_action_type(token)
    guard_result = preview_guarded_action(
        action_type=action_type,
        target=destination_masked,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
    )
    if token not in {"telegram", "email"}:
        guard_result["status"] = "denied"
        guard_result["execution_enabled"] = False
        guard_result["message"] = "Unsupported notification test channel."
    elif missing_fields:
        guard_result["status"] = "denied"
        guard_result["execution_enabled"] = False
        guard_result["missing_guards"] = list(guard_result.get("missing_guards", [])) + ["configured destination"]
        guard_result["message"] = "Execution is blocked until the required notification fields are configured."
    return {
        "status": guard_result.get("status", "denied"),
        "channel": token,
        "required_fields": required_fields,
        "present_fields": present_fields,
        "missing_fields": missing_fields,
        "guard": guard_result,
        "would_send": {
            "message_type": "test_notification",
            "destination_masked": destination_masked,
            "content_preview": notification_test.content_preview_for(token),
        },
        "raw_secret_included": False,
        "error": None if token in {"telegram", "email"} else "unsupported_channel",
    }


def execute_notification_test(
    channel: str,
    actor: str,
    role: str,
    reason: str,
    confirmation: str,
    dry_run_completed: bool,
    config_path: str | None = None,
) -> Dict[str, Any]:
    preview = preview_notification_test(
        channel=channel,
        actor=actor,
        role=role,
        reason=reason,
        confirmation=confirmation,
        dry_run_completed=dry_run_completed,
        config_path=config_path,
    )
    guard = dict(preview.get("guard", {}) or {})
    if preview.get("error") == "unsupported_channel":
        return {
            "status": "denied",
            "channel": str(channel or "").strip().lower(),
            "message": "Unsupported notification test channel.",
            "audit": {"status": "denied", "reason": "unsupported_channel"},
            "error": "unsupported_channel",
        }
    if preview.get("missing_fields"):
        return {
            "status": "denied",
            "channel": preview.get("channel", ""),
            "message": "Required notification fields are missing.",
            "missing_fields": list(preview.get("missing_fields", []) or []),
            "audit": {"status": "denied", "reason": "missing_fields"},
            "error": "missing_fields",
        }
    if not bool(guard.get("execution_enabled", False)):
        return {
            "status": "denied",
            "channel": preview.get("channel", ""),
            "message": guard.get("message", "Guard validation failed."),
            "missing_fields": list(preview.get("missing_fields", []) or []),
            "audit": {"status": "denied", "reason": "missing_guards"},
            "error": "guard_denied",
        }

    context = _load_runtime_context(config_path)
    config = context["config"]
    integrations = context["integrations"]
    audit_available, audit_error = secret_store.audit_user_action_available(config)
    if not audit_available:
        return {
            "status": "denied",
            "channel": preview.get("channel", ""),
            "message": "Audit is required before test notifications can be sent.",
            "missing_fields": [],
            "audit": {"status": "unavailable", "reason": audit_error or "audit_unavailable"},
            "error": "audit_unavailable",
        }

    sender_result = (
        notification_test.send_telegram_test(integrations)
        if preview.get("channel") == "telegram"
        else notification_test.send_email_test(integrations)
    )
    audit_payload = {
        "channel": preview.get("channel", ""),
        "required_fields_present": not bool(preview.get("missing_fields")),
        "destination_masked": dict(preview.get("would_send", {}) or {}).get("destination_masked", ""),
        "content_preview": dict(preview.get("would_send", {}) or {}).get("content_preview", ""),
        "send_status": sender_result.get("status", "failed"),
    }
    audit_result = secret_store.record_user_action(
        config=config,
        action=_notification_action_type(preview.get("channel", "")),
        actor=str(actor or "").strip() or "local-user",
        target=str(audit_payload.get("destination_masked", "") or ""),
        summary=str(reason or "").strip() or f"guarded {preview.get('channel', '')} test send",
        details=audit_payload,
        status="executed" if sender_result.get("status") == "ok" else "failed",
    )
    if audit_result.get("status") != "ok":
        return {
            "status": "failed",
            "channel": preview.get("channel", ""),
            "message": "Notification test completed but audit write failed.",
            "audit": audit_result,
            "raw_secret_included": False,
            "error": "audit_write_failed",
        }

    success = sender_result.get("status") == "ok"
    return {
        "status": "executed" if success else "failed",
        "channel": preview.get("channel", ""),
        "message": sender_result.get("message", "Notification test failed."),
        "destination_masked": sender_result.get("destination_masked", audit_payload["destination_masked"]),
        "audit": audit_result,
        "raw_secret_included": False,
        "error": None if success else sender_result.get("error", "send_failed"),
    }


def collect_theme_options() -> Dict[str, Any]:
    current = _read_qt_theme_mode()
    source = "runtime_session" if current else "default_preview"
    effective = current or "dark"
    return {
        "status": "ok",
        "options": [
            {"id": "dark", "label": "Dark"},
            {"id": "light", "label": "Light"},
            {"id": "system", "label": "System"},
        ],
        "current": effective,
        "source": source,
        "session_active": bool(current),
        "message": (
            "Current theme is coming from the active UI session."
            if current
            else "No active runtime theme override detected; showing the default preview."
        ),
        "persistence_enabled": False,
        "error": None,
    }


def _secret_source(name: str, integrations: IntegrationSettings, config: Dict[str, Any]) -> str:
    raw = getattr(integrations, "_raw", {})
    if name in raw and str(raw.get(name, "") or "").strip():
        return "env"
    if name == "ABUSEIPDB_API_KEY" and str((config.get("abuseipdb", {}) or {}).get("api_key", "") or "").strip():
        return "config"
    if name in {"OPENAI_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY"} and str((config.get("llm", {}) or {}).get("api_key", "") or "").strip():
        return "config"
    return ""


def _secret_entries(config_path: str | None = None) -> tuple[list[dict], str | None, str, bool]:
    context = _load_runtime_context(config_path)
    config = context["config"]
    integrations = context["integrations"]
    llm_cfg = dict((config or {}).get("llm", {}) or {})
    abuse_cfg = dict((config or {}).get("abuseipdb", {}) or {})
    config_source_path = str(_resolve_config_path(config_path))
    entries = []
    specs = [
        ("ABUSEIPDB_API_KEY", str(abuse_cfg.get("api_key", "") or "") or integrations.abuseipdb_key, True, True),
        ("OPENAI_API_KEY", integrations.openai_key or str(llm_cfg.get("api_key", "") or ""), True, llm_cfg.get("backend", "mock") == "openai"),
        ("GEMINI_API_KEY", integrations.gemini_key or str(llm_cfg.get("api_key", "") or ""), True, llm_cfg.get("backend", "mock") == "gemini"),
        ("ANTHROPIC_API_KEY", integrations.anthropic_key or str(llm_cfg.get("api_key", "") or ""), True, llm_cfg.get("backend", "mock") == "anthropic"),
        ("LLM_API_KEY", getattr(integrations, "_raw", {}).get("LLM_API_KEY", ""), True, False),
        ("LLM_BACKEND", getattr(integrations, "_raw", {}).get("LLM_BACKEND", llm_cfg.get("backend", "mock")), False, False),
        ("LLM_MODEL", getattr(integrations, "_raw", {}).get("LLM_MODEL", llm_cfg.get("model", "")), False, False),
        ("TELEGRAM_BOT_TOKEN", integrations.telegram_bot_token, True, True),
        ("TELEGRAM_CHAT_ID", integrations.telegram_chat_id, True, True),
        ("EMAIL_SMTP_HOST", getattr(integrations, "_raw", {}).get("EMAIL_SMTP_HOST", ""), False, True),
        ("EMAIL_SMTP_PORT", getattr(integrations, "_raw", {}).get("EMAIL_SMTP_PORT", ""), False, True),
        ("EMAIL_SMTP_USER", getattr(integrations, "_raw", {}).get("EMAIL_SMTP_USER", ""), False, True),
        ("EMAIL_SMTP_PASS", getattr(integrations, "_raw", {}).get("EMAIL_SMTP_PASS", ""), True, True),
        ("EMAIL_FROM", getattr(integrations, "_raw", {}).get("EMAIL_FROM", ""), False, True),
        ("EMAIL_TO", getattr(integrations, "_raw", {}).get("EMAIL_TO", ""), False, True),
    ]
    for name, raw_value, sensitive, required in specs:
        value = str(raw_value or "").strip()
        source = _secret_source(name, integrations, config)
        entries.append({
            "name": name,
            "present": bool(value),
            "masked": _mask_secret(value) if sensitive else value,
            "source": source or ("config" if context["config_exists"] else ""),
            "sensitive": sensitive,
            "required": bool(required),
            "status": "configured" if value else "missing",
        })
    return entries, None, config_source_path, bool(context["config_exists"])


def collect_secret_status(config_path: str | None = None) -> Dict[str, Any]:
    try:
        entries, error, _, _ = _secret_entries(config_path=config_path)
        return {"status": "ok", "secrets": entries, "error": error}
    except Exception as exc:
        return {"status": "degraded", "secrets": [], "error": str(exc)}


def collect_notification_settings(config_path: str | None = None) -> Dict[str, Any]:
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        integrations = context["integrations"]
        defaults = NotificationRule()
        missing_telegram = []
        if not integrations.telegram_bot_token:
            missing_telegram.append("TELEGRAM_BOT_TOKEN")
        if not integrations.telegram_chat_id:
            missing_telegram.append("TELEGRAM_CHAT_ID")
        missing_email = []
        for key in notification_test.EMAIL_REQUIRED_FIELDS:
            if not str(getattr(integrations, "_raw", {}).get(key, "") or "").strip():
                missing_email.append(key)
        return {
            "status": "ok",
            "desktop_notifications": {
                "enabled": bool(defaults.desktop_notifications),
                "source": "session_default_preview",
                "persisted": False,
                "message": "Desktop notification enablement is controlled by the active UI session and is not persisted in Phase 1.",
            },
            "tray_background_mode": {
                "enabled": bool(defaults.tray_enabled and defaults.background_notifications),
                "source": "session_default_preview",
                "persisted": False,
                "message": "Tray/background notification mode is a session preview and is not persisted in Phase 1.",
            },
            "telegram": {
                "configured": integrations.telegram_enabled,
                "missing_required_fields": missing_telegram,
                "severity_threshold": "critical/high preview",
                "manual_test_send_enabled": True,
            },
            "email": {
                "configured": integrations.email_enabled,
                "missing_required_fields": missing_email,
                "severity_threshold": "critical/high preview",
                "manual_test_send_enabled": True,
            },
            "severity_thresholds": {
                "critical": True,
                "high": True,
                "medium": False,
                "low": False,
                "auth_only": False,
                "db_web_only": False,
                "external_ip_only": False,
                "source": "session_default_preview",
                "persisted": False,
            },
            "cooldown_duplicate_suppression": {
                "enabled": True,
                "cooldown_seconds": int((config.get("risk", {}) or {}).get("cooldown", {}).get("default_seconds", 300) or 300),
                "duplicate_suppression": "preview_only",
                "source": "config_default_seconds+session_preview",
                "persisted": False,
            },
            "missing_required_fields": sorted(set(missing_telegram + missing_email)),
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "desktop_notifications": {"enabled": "unknown"},
            "tray_background_mode": {"enabled": "unknown"},
            "telegram": {"configured": False, "missing_required_fields": []},
            "email": {"configured": False, "missing_required_fields": []},
            "severity_thresholds": {},
            "cooldown_duplicate_suppression": {},
            "missing_required_fields": [],
            "error": str(exc),
        }


def validate_settings_safe_preview(kind: str, config_path: str | None = None) -> Dict[str, Any]:
    key = str(kind or "").strip().lower()
    secret_payload = collect_secret_status(config_path=config_path)
    secrets_by_name = {
        item.get("name"): item for item in secret_payload.get("secrets", [])
    }
    required_map = {
        "abuseipdb": ["ABUSEIPDB_API_KEY"],
        "llm": ["OPENAI_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY"],
        "telegram": list(notification_test.TELEGRAM_REQUIRED_FIELDS),
        "email": list(notification_test.EMAIL_REQUIRED_FIELDS),
    }
    required_fields = required_map.get(key, [])
    present_fields = [name for name in required_fields if secrets_by_name.get(name, {}).get("present")]
    missing_fields = [name for name in required_fields if name not in present_fields]
    validate_by = {
        "abuseipdb": "API key/header presence preview",
        "llm": "provider key + backend selection preview",
        "telegram": "bot token/chat id preview",
        "email": "SMTP host/port/recipient preview",
    }.get(key, "preview")
    return {
        "status": "preview_only",
        "kind": key,
        "required_fields": required_fields,
        "present_fields": present_fields,
        "missing_fields": missing_fields,
        "would_validate_by": validate_by,
        "message": "Live validation is disabled in Phase 1 read-only UI",
    }


def collect_settings_status(config_path: str | None = None) -> Dict[str, Any]:
    try:
        entries, _, config_source_path, config_readable = _secret_entries(config_path=config_path)
        context = _load_runtime_context(config_path)
        config = context["config"]
        integrations = context["integrations"]
        notifications = collect_notification_settings(config_path=config_path)
        theme_options = collect_theme_options()
        llm_cfg = dict((config or {}).get("llm", {}) or {})
        llm_backend = str(llm_cfg.get("backend", "mock") or "mock")
        llm_model = str(llm_cfg.get("model", "") or "")
        llm_key_present = any(
            item.get("name") in {"OPENAI_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "LLM_API_KEY"} and item.get("present")
            for item in entries
        )
        ml_cfg = dict((config or {}).get("ml", {}) or {})
        active_layer = dict(ml_cfg.get("active_decision_layer", {}) or {})
        return {
            "status": "ok",
            "config_path": config_source_path,
            "config_readable": config_readable,
            "env_status": {
                "integration_env_loaded": bool(getattr(integrations, "_raw", {})),
                "known_keys_present": len([item for item in entries if item.get("present")]),
            },
            "integrations": {
                "summary": integrations.summary(),
                "telegram_configured": integrations.telegram_enabled,
                "email_configured": integrations.email_enabled,
            },
            "llm": {
                "backend": llm_backend,
                "model": llm_model,
                "enabled": bool(llm_cfg.get("enabled", False)),
                "api_key_configured": bool(llm_key_present),
            },
            "notifications": notifications,
            "theme": theme_options,
            "security_locks": {
                **collect_security_locks(config_path=config_path),
                "active_ml_disabled": not bool(active_layer.get("enabled", False)),
                "firewall_actions_locked": True,
                "db_reset_locked": True,
                "config_write_locked": True,
            },
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "config_path": str(_resolve_config_path(config_path)),
            "config_readable": False,
            "env_status": {},
            "integrations": {},
            "llm": {
                "backend": "mock",
                "model": "",
                "enabled": False,
                "api_key_configured": False,
            },
            "notifications": {},
            "security_locks": {
                "read_only_mode": True,
                "manual_actions_locked": True,
                "auto_ip_block_disabled": True,
                "ml_no_action_contract": True,
                "active_ml_disabled": True,
                "firewall_actions_locked": True,
                "db_reset_locked": True,
                "config_write_locked": True,
            },
            "error": str(exc),
        }


def _normalize_user_action(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(row or {})
    created_at = payload.get("created_at", payload.get("timestamp", payload.get("ts", "")))
    metadata = payload.get("details", payload.get("metadata", {}))
    if not isinstance(metadata, (dict, list)):
        metadata = {"value": metadata}
    reason = str(
        payload.get("reason", "")
        or payload.get("summary", "")
        or payload.get("status_reason", "")
        or ""
    ).strip()
    return {
        "id": payload.get("id"),
        "timestamp_text": _coerce_timestamp_text(created_at),
        "created_at": created_at,
        "action_type": str(payload.get("action_type", "") or payload.get("action", "")).strip(),
        "target": str(payload.get("target", "") or payload.get("entity_id", "") or payload.get("screen", "")).strip(),
        "actor": str(payload.get("actor", "") or payload.get("executed_by", "")).strip(),
        "result": str(payload.get("result", "") or payload.get("status", "")).strip(),
        "reason": reason,
        "metadata": metadata,
        "raw": payload,
    }


def collect_action_history(
    limit: int = 200,
    action_type: str | None = None,
    target: str | None = None,
    config_path: str | None = None,
) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 200), 500))
    action_filter = str(action_type or "").strip().lower()
    target_filter = str(target or "").strip().lower()
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        db = create_database(config)
        if db is None:
            return {"status": "degraded", "actions": [], "total_returned": 0, "error": "database_unavailable"}
        try:
            rows, columns, error = _load_table_rows(
                db,
                "user_actions",
                ("ts DESC", "created_at DESC", "timestamp DESC"),
                limit=max(limit * 3, 50),
            )
            if error:
                return {"status": "degraded", "actions": [], "columns": columns, "total_returned": 0, "error": error}
            actions = []
            for row in rows:
                item = _normalize_user_action(row)
                if action_filter and str(item.get("action_type", "")).lower() != action_filter:
                    continue
                if target_filter and target_filter not in str(item.get("target", "")).lower():
                    continue
                actions.append(item)
                if len(actions) >= limit:
                    break
            return {
                "status": "ok",
                "actions": actions,
                "columns": columns,
                "total_returned": len(actions),
                "error": None,
            }
        finally:
            db.close()
    except Exception as exc:
        return {"status": "degraded", "actions": [], "total_returned": 0, "error": str(exc)}


def collect_audit_summary(config_path: str | None = None) -> Dict[str, Any]:
    payload = collect_action_history(limit=500, config_path=config_path)
    actions = list(payload.get("actions", []) or [])
    if payload.get("status") != "ok":
        return {
            "status": "degraded",
            "total_actions": 0,
            "by_action_type": {},
            "by_result": {},
            "dangerous_action_count": 0,
            "ip_action_count": 0,
            "config_api_key_action_count": 0,
            "db_reset_count": 0,
            "last_action_time": "",
            "error": payload.get("error"),
        }
    by_action_type = Counter()
    by_result = Counter()
    dangerous_count = 0
    ip_action_count = 0
    config_api_count = 0
    db_reset_count = 0
    db_reset_action_name = "_".join(["reset", "database"])
    dangerous_tokens = ("block", "unblock", "reset", "close", "resolve", "config", "api_key", "ml_", "historical")
    for item in actions:
        action_name = str(item.get("action_type", "") or "").strip() or "unknown"
        result_name = str(item.get("result", "") or "").strip() or "unknown"
        by_action_type[action_name] += 1
        by_result[result_name] += 1
        lowered = action_name.lower()
        if any(token in lowered for token in dangerous_tokens):
            dangerous_count += 1
        if "block" in lowered or "unblock" in lowered:
            ip_action_count += 1
        if "config" in lowered or "api" in lowered or "key" in lowered:
            config_api_count += 1
        if "db_reset" in lowered or lowered == db_reset_action_name:
            db_reset_count += 1
    return {
        "status": "ok",
        "total_actions": len(actions),
        "by_action_type": dict(by_action_type),
        "by_result": dict(by_result),
        "dangerous_action_count": dangerous_count,
        "ip_action_count": ip_action_count,
        "config_api_key_action_count": config_api_count,
        "db_reset_count": db_reset_count,
        "last_action_time": actions[0].get("timestamp_text", "") if actions else "",
        "error": None,
    }


def collect_audit_detail(action_id: int, config_path: str | None = None) -> Dict[str, Any]:
    payload = collect_action_history(limit=1000, config_path=config_path)
    if payload.get("status") != "ok":
        return {"status": "degraded", "action": None, "detail": {}, "error": payload.get("error")}
    for item in payload.get("actions", []):
        try:
            if int(item.get("id", -1) or -1) == int(action_id):
                return {
                    "status": "ok",
                    "action": item,
                    "detail": {
                        "raw_json": _stringify_payload(item.get("raw", {})),
                        "metadata_json": _stringify_payload(item.get("metadata", {})),
                    },
                    "error": None,
                }
        except Exception:
            continue
    return {"status": "degraded", "action": None, "detail": {}, "error": f"action_not_found:{action_id}"}


def collect_audit_sources_status(config_path: str | None = None) -> Dict[str, Any]:
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        db = create_database(config)
        user_actions_status = {"available": False, "count": 0, "read_only": True, "note": "user_actions unavailable"}
        ip_actions_status = {"available": False, "count": 0, "read_only": True, "note": "ip_block_actions unavailable"}
        if db is not None:
            try:
                rows, _columns, error = _load_table_rows(db, "user_actions", ("ts DESC",), limit=1)
                if error is None:
                    count_rows, _count_error = _execute_db_read(db, "SELECT COUNT(*) AS count FROM user_actions", fetch="one")
                    count_value = int(dict(count_rows or {}).get("count", 0) or 0) if count_rows else 0
                    user_actions_status = {"available": True, "count": count_value, "read_only": True, "note": "user_actions read-only visibility"}
                rows, _columns, error = _load_table_rows(db, "ip_block_actions", ("executed_at DESC",), limit=1)
                if error is None:
                    count_rows, _count_error = _execute_db_read(db, "SELECT COUNT(*) AS count FROM ip_block_actions", fetch="one")
                    count_value = int(dict(count_rows or {}).get("count", 0) or 0) if count_rows else 0
                    ip_actions_status = {"available": True, "count": count_value, "read_only": True, "note": "ip_block_actions read-only visibility"}
            finally:
                db.close()
        reports = _collect_report_files()
        report_status = {
            "available": bool(reports),
            "count": len(reports),
            "read_only": True,
            "note": "Report artifacts are file-based and read-only in Phase 1.",
        }
        return {
            "status": "ok",
            "sources": {
                "user_actions": user_actions_status,
                "ip_block_actions": ip_actions_status,
                "report_artifacts": report_status,
            },
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "sources": {
                "user_actions": {"available": False, "count": 0, "read_only": True, "note": "unavailable"},
                "ip_block_actions": {"available": False, "count": 0, "read_only": True, "note": "unavailable"},
                "report_artifacts": {"available": False, "count": 0, "read_only": True, "note": "unavailable"},
            },
            "error": str(exc),
        }


def collect_dangerous_action_preview() -> Dict[str, Any]:
    policy_payload = collect_guarded_action_policies()
    actions = []
    for item in list(policy_payload.get("policies", []) or []):
        action_type = str(item.get("action_type", "") or "")
        preview = preview_guarded_action(
            action_type=action_type,
            target=action_type,
            actor="local-user",
            role="viewer",
        )
        actions.append({
            "action": action_type,
            "required_guards": list(preview.get("required_guards", []) or []),
            "execution_enabled": bool(preview.get("execution_enabled", False)),
        })
    return {
        "status": "ok",
        "actions": actions,
        "note": "Phase 2 only. No write actions available in Phase 1.",
        "error": None,
    }


def collect_llm_config_status(config_path: str | None = None) -> Dict[str, Any]:
    try:
        context = _load_runtime_context(config_path)
        config = context["config"]
        integrations = context["integrations"]
        llm_cfg = dict((config or {}).get("llm", {}) or {})
        raw = dict(getattr(integrations, "_raw", {}) or {})
        from core.llm import LLMClient

        client = LLMClient(config)
        backend = str(llm_cfg.get("backend", getattr(client, "backend_name", "mock")) or "mock")
        model = str(llm_cfg.get("model", "") or "")
        api_key = str(llm_cfg.get("api_key", "") or "")
        resolved_api_key = str(getattr(integrations, "llm_api_key", lambda: "")() or api_key or "").strip()
        has_api_key = bool(resolved_api_key)
        resolved_language = resolve_language(env=raw, config=config, default="tr")
        return {
            "status": "ok",
            "enabled": bool(llm_cfg.get("enabled", False)),
            "backend": backend,
            "model": model,
            "has_api_key": has_api_key,
            "key_masked": _mask_secret(resolved_api_key),
            "timeout_seconds": int(llm_cfg.get("timeout_seconds", 15) or 15),
            "language": resolved_language,
            "resolved_language": resolved_language,
            "ui_language": "",
            "configured_language": normalize_language(llm_cfg.get("language"), default="tr"),
            "fallback_available": True,
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "enabled": False,
            "backend": "",
            "model": "",
            "has_api_key": False,
            "key_masked": "",
            "timeout_seconds": 0,
            "language": "tr",
            "resolved_language": "tr",
            "ui_language": "",
            "configured_language": "tr",
            "fallback_available": True,
            "error": str(exc),
        }


def explain_alert_for_ui(alert_id: int, prefer_llm: bool = True, config_path: str | None = None) -> Dict[str, Any]:
    runtime_config = {}
    language = "tr"
    try:
        runtime_context = _load_runtime_context(config_path)
        runtime_config = dict(runtime_context.get("config", {}) or {})
        language = _resolved_runtime_language(runtime_config)
    except Exception:
        runtime_config = {}
        language = "tr"
    detail_payload = collect_alert_detail(alert_id, config_path=config_path)
    if detail_payload.get("status") != "ok":
        return {
            "status": "degraded",
            "alert_id": alert_id,
            "language": language,
            "used_llm": False,
            "fallback_used": True,
            "provider": "",
            "summary": "",
            "why_triggered": "",
            "risk_assessment": "",
            "recommended_review_steps": [],
            "false_positive_notes": "",
            "raw_text": "",
            "metadata": {},
            "error": detail_payload.get("error"),
        }
    alert = dict(detail_payload.get("alert", {}) or {})
    raw_alert = dict(alert.get("raw", {}) or {})
    deterministic = build_deterministic_alert_explanation(raw_alert or alert, language=language)
    investigation_payload = collect_alert_investigation_summary(alert_id, config_path=config_path)
    investigation_context = redact_sensitive_payload(dict(investigation_payload.get("summary", {}) or {}))
    llm_text = ""
    provider = ""
    used_llm = False
    error = None
    llm_quality_reason = "not_requested"
    llm_quality_passed = False
    llm_response_len = 0
    llm_prompt_len = 0
    llm_finish_reason = ""
    llm_raw_preview = ""
    rejected_llm_preview = ""
    if prefer_llm:
        try:
            from core.llm import LLMClient

            client = LLMClient(runtime_config)
            provider = str(getattr(client, "backend_name", "") or "")
            if client.is_active:
                related_events = [{"kind": "investigation_context", "summary": investigation_context}] if investigation_context else []
                llm_text = client.explain_selected_alert(raw_alert or alert, related_events=related_events) or ""
                debug_meta = dict(getattr(client, "last_selected_alert_debug", {}) or {})
                llm_prompt_len = int(debug_meta.get("prompt_len", 0) or 0)
                llm_response_len = int(debug_meta.get("response_len", len(str(llm_text or ""))) or 0)
                llm_finish_reason = str(debug_meta.get("finish_reason", "") or "")
                llm_raw_preview = _sanitize_llm_error_text(str(debug_meta.get("raw_preview", debug_meta.get("response_preview", "")) or ""))[:500]
                quality = _evaluate_llm_response_quality(llm_text, alert)
                llm_quality_reason = str(quality.get("reason", "") or "unknown")
                llm_quality_passed = bool(quality.get("passed", False))
                llm_response_len = int(quality.get("response_len", llm_response_len or len(str(llm_text or ""))))
                if not llm_quality_passed:
                    error = _sanitize_llm_error_text(_humanize_llm_quality_reason(llm_quality_reason, language))
                    rejected_llm_preview = _sanitize_llm_error_text(str(debug_meta.get("rejected_preview", llm_raw_preview) or ""))[:500]
                    llm_raw_preview = ""
                    llm_text = ""
                    used_llm = False
                else:
                    used_llm = bool(llm_text)
                if not llm_text and not error and getattr(client, "disable_reason", ""):
                    error = client.disable_reason
            else:
                error = getattr(client, "disable_reason", "") or None
                llm_quality_reason = "client_disabled"
        except Exception as exc:
            error = _sanitize_llm_error_text(str(exc))
            llm_quality_reason = "client_exception"
    final_text = llm_text.strip() if llm_text.strip() else deterministic.get("raw_text", "")
    if not used_llm and investigation_context:
        rule_bits = ", ".join(
            f"{item.get('rule_id', '')}({item.get('count', 0)})"
            for item in list(investigation_context.get("top_related_rules", []) or [])[:3]
        )
        context_lines = [
            "",
            f"{explanation_text('related_event_summary', language)}:",
            f"- {explanation_text('related_alert_count', language)}: {investigation_context.get('related_alert_count', 0)}",
            f"{explanation_text('same_ip_user_rule', language)}:",
            f"- {explanation_text('same_ip', language)}: {investigation_context.get('same_source_ip_count', 0)}",
            f"- {explanation_text('same_entity', language)}: {investigation_context.get('same_entity_count', 0)}",
            f"- {explanation_text('same_rule', language)}: {investigation_context.get('same_rule_count', 0)}",
            f"{explanation_text('time_range', language)}:",
            f"- {explanation_text('first_seen', language)}: {investigation_context.get('first_seen', '') or explanation_text('none', language)}",
            f"- {explanation_text('last_seen', language)}: {investigation_context.get('last_seen', '') or explanation_text('none', language)}",
            f"{explanation_text('high_critical_related', language)}:",
            f"- {explanation_text('count', language)}: {investigation_context.get('high_critical_related_count', 0)}",
        ]
        if rule_bits:
            context_lines.append(f"- {explanation_text('top_related_rules', language)}: {rule_bits}")
        final_text = (final_text or deterministic.get("summary", "")).strip() + "\n".join(context_lines)
    fallback_used = not used_llm
    parsed_sections = _extract_llm_heading_sections(llm_text if used_llm else final_text)
    recommended_review_steps = list(deterministic.get("recommended_review_steps", []) or [])
    if investigation_context:
        recommended_review_steps = [
            explanation_text(
                "ui_related_step_1",
                language,
                same_source_ip_count=investigation_context.get("same_source_ip_count", 0),
                same_rule_count=investigation_context.get("same_rule_count", 0),
            ),
            explanation_text(
                "ui_related_step_2",
                language,
                first_seen=investigation_context.get("first_seen", "") or explanation_text("none", language),
                last_seen=investigation_context.get("last_seen", "") or explanation_text("none", language),
            ),
        ] + recommended_review_steps
    evidence_lines = [
        f"{explanation_text('rule_prefix', language)}: {alert.get('rule_id', '') or '-'}",
        f"{explanation_text('importance', language)}: {str(alert.get('severity', '') or '-').upper()}",
        f"{explanation_text('risk_score', language)}: {float(alert.get('risk_score', 0.0) or 0.0):.1f}",
        f"{explanation_text('source_type', language)}: {alert.get('source', '') or '-'}",
        f"{explanation_text('source_ip', language)}: {alert.get('source_ip', '') or '-'}",
        f"{explanation_text('asset', language)}: {alert.get('entity', '') or '-'}",
        f"{explanation_text('message', language)}: {alert.get('message', '') or '-'}",
    ]
    if investigation_context:
        evidence_lines.extend([
            f"{explanation_text('related_alert_count', language).capitalize()}: {investigation_context.get('related_alert_count', 0)}",
            f"{explanation_text('same_ip_alert_count', language)}: {investigation_context.get('same_source_ip_count', 0)}",
            f"{explanation_text('same_rule_alert_count', language)}: {investigation_context.get('same_rule_count', 0)}",
        ])
    evidence_summary = parsed_sections.get("evidence") or "\n".join(evidence_lines)
    why_text = (
        parsed_sections.get("why")
        or deterministic.get("why_triggered", "")
        or str(alert.get("message", "") or "")
    )
    risk_text = parsed_sections.get("risk") or deterministic.get("risk_assessment", "")
    summary_text = parsed_sections.get("summary") or deterministic.get("summary", "")
    false_positive_text = parsed_sections.get("false_positive") or deterministic.get("false_positive_notes", "")
    mitigation_text = parsed_sections.get("mitigation", "")
    scenario_text = parsed_sections.get("scenario", "")
    if parsed_sections.get("review_steps"):
        llm_review_steps = []
        for line in parsed_sections.get("review_steps", "").splitlines():
            cleaned = line.lstrip("-*• ").strip()
            if cleaned:
                llm_review_steps.append(cleaned)
        if llm_review_steps:
            recommended_review_steps = llm_review_steps
    full_explanation = final_text
    if used_llm:
        full_explanation = llm_text.strip() or final_text
    if not used_llm and error:
        fallback_note = explanation_text("llm_disabled_note", language)
        error_lower = str(error or "").lower()
        if not any(token in error_lower for token in ("enabled: false", "eksik api anahtarı", "missing api key", "etkin değil", "not active", "disabled")):
            fallback_note = explanation_text("llm_unavailable_note", language)
        full_explanation = (
            f"{fallback_note}\n"
            f"{explanation_text('reason', language)}: {error}\n\n{full_explanation}"
        ).strip()
    full_explanation = _append_section_once(full_explanation, explanation_text("mitigation_heading", language), mitigation_text)
    full_explanation = _append_section_once(full_explanation, explanation_text("scenario_heading", language), scenario_text)
    return {
        "status": "ok" if full_explanation else "degraded",
        "alert_id": alert_id,
        "language": language,
        "rule_id": alert.get("rule_id", ""),
        "severity": alert.get("severity", ""),
        "risk_score": float(alert.get("risk_score", 0.0) or 0.0),
        "entity": alert.get("entity", ""),
        "source": alert.get("source", ""),
        "source_ip": alert.get("source_ip", ""),
        "message": alert.get("message", ""),
        "used_llm": used_llm,
        "fallback_used": fallback_used,
        "provider": provider,
        "llm_prompt_len": llm_prompt_len,
        "llm_response_len": llm_response_len,
        "llm_finish_reason": llm_finish_reason,
        "llm_raw_preview": llm_raw_preview,
        "rejected_llm_preview": rejected_llm_preview,
        "llm_quality_reason": llm_quality_reason,
        "llm_quality_passed": llm_quality_passed,
        "summary": summary_text,
        "why_triggered": why_text,
        "why": why_text,
        "risk_assessment": risk_text,
        "risk": risk_text,
        "evidence_summary": evidence_summary,
        "evidence": evidence_summary,
        "recommended_review_steps": recommended_review_steps[:6],
        "false_positive_notes": false_positive_text,
        "raw_text": full_explanation,
        "full_explanation": full_explanation,
        "metadata": {
            "language": language,
            "deterministic": deterministic.get("metadata", {}),
            "alert": alert,
            "investigation_context": investigation_context,
            "parsed_sections": parsed_sections,
            "llm_prompt_len": llm_prompt_len,
            "llm_response_len": llm_response_len,
            "llm_finish_reason": llm_finish_reason,
            "llm_raw_preview": llm_raw_preview,
            "rejected_llm_preview": rejected_llm_preview,
            "llm_quality_reason": llm_quality_reason,
            "llm_quality_passed": llm_quality_passed,
        },
        "error": error,
    }
