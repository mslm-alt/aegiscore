from __future__ import annotations

import copy
import hashlib
import re
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.ml.family_registry import resolve_rule_id_to_ml_family

ALLOWED_FAMILIES = ("ML-AUTH", "ML-PROC", "ML-IMPACT")
EXTRACTION_POLICY_VERSION = "phase5f-v1"
MANIFEST_SOURCE = "verified_manifest_dry_run"

CORRELATION_SCORES = {
    "exact_event_link": 0.98,
    "incident_bridge": 0.88,
    "time_entity_rule_category_match": 0.72,
    "time_proximity_only": 0.52,
}

SOURCE_QUALITY_LEVELS = {
    "direct_rule_high": "Q1",
    "clean_source_high": "Q2",
    "heuristic_candidate_medium": "Q3",
    "heuristic_candidate_low": "Q4",
}

READINESS_ORDER = ("direct_learning_ready", "direct_learning_ready_with_warnings", "blocked")

_SECRET_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(token=)([^&\s]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)([^\s]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(password=)([^&\s]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(api_key=)([^&\s]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(smtp_pass=)([^&\s]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(TELEGRAM_BOT_TOKEN=)([^\s]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(GEMINI_API_KEY=)([^\s]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(OPENAI_API_KEY=)([^\s]+)"), r"\1[REDACTED]"),
)


@dataclass(frozen=True)
class EventSnapshot:
    event_id: str
    ts: float
    source: str = ""
    category: str = ""
    action: str = ""
    outcome: str = ""
    username: str = ""
    process: str = ""
    host: str = ""
    src_ip: str = ""
    message: str = ""
    raw_log: str = ""
    risk_bucket: str = ""
    distro_family: str = ""
    incident_id: str = ""

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "EventSnapshot":
        event_id = str(row.get("id", row.get("event_id", "")) or "").strip() or f"event-{int(time.time() * 1000)}"
        return cls(
            event_id=event_id,
            ts=float(row.get("ts", 0.0) or 0.0),
            source=_norm(row.get("source", "")),
            category=_norm(row.get("category", "")),
            action=_norm(row.get("action", "")),
            outcome=_norm(row.get("outcome", "")),
            username=_norm(row.get("username", "")),
            process=_norm(row.get("process", "")),
            host=_norm(row.get("host", "")),
            src_ip=_norm(row.get("src_ip", "")),
            message=str(row.get("message", "") or ""),
            raw_log=str(row.get("raw_log", "") or ""),
            risk_bucket=_norm(row.get("risk_bucket", "")),
            distro_family=_norm(row.get("distro_family", "")),
            incident_id=_norm(row.get("incident_id", "")),
        )


@dataclass(frozen=True)
class AlertSnapshot:
    alert_id: str
    ts: float
    rule_id: str = ""
    category: str = ""
    severity: str = ""
    host: str = ""
    incident_id: str = ""
    message: str = ""
    context_json: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "AlertSnapshot":
        ctx = row.get("context_json", row.get("context", {}))
        if not isinstance(ctx, dict):
            ctx = {}
        return cls(
            alert_id=str(row.get("id", row.get("alert_id", "")) or "").strip() or f"alert-{int(time.time() * 1000)}",
            ts=float(row.get("ts", 0.0) or 0.0),
            rule_id=str(row.get("rule_id", "") or "").strip().upper(),
            category=_norm(row.get("category", "")),
            severity=_norm(row.get("severity", "")),
            host=_norm(row.get("host", "")),
            incident_id=_norm(row.get("incident_id", "")),
            message=str(row.get("message", "") or ""),
            context_json=ctx,
        )


@dataclass
class CandidateLabel:
    source_event_id: str
    event_id: str
    correlated_alert_ids: List[str]
    correlation_level: str
    correlation_score: float
    candidate_score: float
    ml_family: str
    ml_label: str
    event_class: str
    behavior_label: str
    source_quality: str
    model_usage_scope: str
    learnable: bool
    label_lifecycle_status: str
    poisoning_guard_passed: bool
    label_reason: str
    evidence_fields: Dict[str, Any]
    rejection_reason: str
    learnable_candidate: bool
    disposition: str
    no_action_contract: bool = True
    active_training_enabled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ManifestSummary:
    candidate_count: int
    direct_learnable_count: int
    rejected_candidate_count: int
    ignored_candidate_count: int
    readiness_decision: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerifiedLabelManifest:
    manifest_id: str
    created_at: str
    source: str
    dry_run: bool
    no_action_contract: bool
    active_training_enabled: bool
    target_families: List[str]
    input_snapshots: Dict[str, Any]
    extraction_policy_version: str
    candidate_count: int
    direct_learnable_count: int
    rejected_candidate_count: int
    ignored_candidate_count: int
    poisoning_guard_summary: Dict[str, Any]
    dominance_summary: Dict[str, Any]
    duplicate_summary: Dict[str, Any]
    family_summary: Dict[str, Any]
    rejection_summary: Dict[str, Any]
    readiness_decision: str
    redaction_status: str
    candidates: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_verified_label_manifest(
    events: Iterable[Dict[str, Any] | EventSnapshot],
    alerts: Iterable[Dict[str, Any] | AlertSnapshot],
    *,
    manifest_id: str = "",
    created_at: str = "",
    families: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    event_rows = [_coerce_event(item) for item in events]
    alert_rows = [_coerce_alert(item) for item in alerts]
    now_text = created_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest_token = manifest_id or f"ml-verified-manifest-{int(time.time())}"
    target_families = _normalize_target_families(families)

    by_family_events = {family: [] for family in target_families}
    for event in event_rows:
        family = classify_event_family(event)
        if family in by_family_events:
            by_family_events[family].append(event)

    family_alerts = {family: [] for family in target_families}
    for alert in alert_rows:
        mapped = resolve_rule_id_to_ml_family(alert.rule_id)
        if mapped.ml_family in family_alerts:
            family_alerts[mapped.ml_family].append(alert)

    raw_candidates: List[CandidateLabel] = []
    for family in target_families:
        for event in by_family_events[family]:
            raw_candidates.append(_build_candidate_for_event(event, family_alerts[family], manifest_token))

    raw_candidates = _apply_duplicate_and_dominance_guards(raw_candidates)
    candidates = [item.to_dict() for item in raw_candidates]
    family_summary = _build_family_summary(candidates, target_families)
    rejection_summary = dict(sorted(Counter(item["rejection_reason"] or "non_rejected" for item in candidates).items()))
    dominance_summary = _build_dominance_summary(candidates, target_families)
    duplicate_summary = _build_duplicate_summary(candidates)
    poisoning_guard_summary = _build_poisoning_guard_summary(candidates, dominance_summary, duplicate_summary)
    readiness_decision = _readiness_decision(candidates, family_summary, poisoning_guard_summary)

    direct_learnable_count = sum(1 for item in candidates if item["disposition"] == "direct_learnable")
    rejected_count = sum(1 for item in candidates if item["disposition"] == "rejected")
    ignored_count = sum(1 for item in candidates if item["disposition"] == "ignored")

    manifest = VerifiedLabelManifest(
        manifest_id=manifest_token,
        created_at=now_text,
        source=MANIFEST_SOURCE,
        dry_run=True,
        no_action_contract=True,
        active_training_enabled=False,
        target_families=list(target_families),
        input_snapshots={
            "events_count": len(event_rows),
            "alerts_count": len(alert_rows),
            "families_seen": {family: len(by_family_events[family]) for family in target_families},
            "alert_families_seen": {family: len(family_alerts[family]) for family in target_families},
            "generated_at": now_text,
        },
        extraction_policy_version=EXTRACTION_POLICY_VERSION,
        candidate_count=len(candidates),
        direct_learnable_count=direct_learnable_count,
        rejected_candidate_count=rejected_count,
        ignored_candidate_count=ignored_count,
        poisoning_guard_summary=poisoning_guard_summary,
        dominance_summary=dominance_summary,
        duplicate_summary=duplicate_summary,
        family_summary=family_summary,
        rejection_summary=rejection_summary,
        readiness_decision=readiness_decision,
        redaction_status="passed",
        candidates=candidates,
    )
    return manifest.to_dict()


def validate_verified_label_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(manifest or {})
    problems: List[str] = []
    required_top = (
        "manifest_id",
        "created_at",
        "source",
        "dry_run",
        "no_action_contract",
        "active_training_enabled",
        "target_families",
        "input_snapshots",
        "extraction_policy_version",
        "candidate_count",
        "direct_learnable_count",
        "rejected_candidate_count",
        "ignored_candidate_count",
        "poisoning_guard_summary",
        "dominance_summary",
        "duplicate_summary",
        "family_summary",
        "rejection_summary",
        "readiness_decision",
        "redaction_status",
        "candidates",
    )
    for field in required_top:
        if field not in payload:
            problems.append(f"missing:{field}")
    if payload.get("source") != MANIFEST_SOURCE:
        problems.append("invalid:source")
    if payload.get("dry_run") is not True:
        problems.append("invalid:dry_run")
    if payload.get("no_action_contract") is not True:
        problems.append("invalid:no_action_contract")
    if payload.get("active_training_enabled") is not False:
        problems.append("invalid:active_training_enabled")
    if payload.get("redaction_status") != "passed":
        problems.append("invalid:redaction_status")
    families = payload.get("target_families", [])
    try:
        normalized = _normalize_target_families(families)
    except ValueError:
        normalized = ()
    if sorted(families) != sorted(normalized):
        problems.append("invalid:target_families")
    candidate_count = int(payload.get("candidate_count", 0) or 0)
    direct_learnable = int(payload.get("direct_learnable_count", 0) or 0)
    rejected = int(payload.get("rejected_candidate_count", 0) or 0)
    ignored = int(payload.get("ignored_candidate_count", 0) or 0)
    if candidate_count != direct_learnable + rejected + ignored:
        problems.append("invalid:candidate_count_reconciliation")
    for idx, candidate in enumerate(payload.get("candidates", []) or []):
        problems.extend(f"candidate[{idx}]:{p}" for p in _validate_candidate(candidate))
    return {"valid": not problems, "problems": problems}


def classify_event_family(event: EventSnapshot) -> Optional[str]:
    if event.category == "auth" or event.source in {"auth_log", "auditd", "journald"} and event.action in {
        "ssh_login", "ssh_invalid_user", "session_open", "session_close", "sudo", "auth", "login",
    }:
        return "ML-AUTH"
    if event.category == "process" or event.action in {"exec", "syscall", "cron_exec", "lotl_exec"}:
        return "ML-PROC"
    if event.category in {"filesystem", "process"} and event.risk_bucket in {"suspicious", "malicious"}:
        return "ML-IMPACT"
    return None


def _normalize_target_families(families: Optional[Iterable[str]]) -> Tuple[str, ...]:
    if families is None:
        return tuple(ALLOWED_FAMILIES)
    normalized = []
    for item in families:
        family = str(item or "").strip().upper()
        if not family:
            continue
        if family not in ALLOWED_FAMILIES:
            raise ValueError(f"unsupported family: {family}")
        if family not in normalized:
            normalized.append(family)
    return tuple(normalized or ALLOWED_FAMILIES)


def redact_text(text: str, *, limit: int = 160) -> str:
    value = str(text or "")
    for pattern, repl in _SECRET_PATTERNS:
        value = pattern.sub(repl, value)
    value = re.sub(r"(?i)(?:openai_|telegram_bot_|gemini_)?api_key=[^\s]+", "api_key=[REDACTED]", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit]


def _coerce_event(item: Dict[str, Any] | EventSnapshot) -> EventSnapshot:
    return item if isinstance(item, EventSnapshot) else EventSnapshot.from_row(item)


def _coerce_alert(item: Dict[str, Any] | AlertSnapshot) -> AlertSnapshot:
    return item if isinstance(item, AlertSnapshot) else AlertSnapshot.from_row(item)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _event_fingerprint(event: EventSnapshot) -> str:
    raw = "|".join([
        event.source,
        event.category,
        event.action,
        event.outcome,
        event.username,
        event.process,
        event.host,
        event.src_ip,
        redact_text(event.message, limit=80),
    ])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _build_candidate_for_event(event: EventSnapshot, alerts: List[AlertSnapshot], manifest_id: str) -> CandidateLabel:
    correlated, level, rule_corr, reason_hint = _correlate_alerts(event, alerts)
    family = classify_event_family(event) or ""
    correlation_score = CORRELATION_SCORES.get(level, 0.0)
    evidence = _build_evidence_fields(event, correlated, manifest_id)

    ml_label, event_class, behavior_label = _resolve_label(family, event, correlated)
    rejection_reason = _candidate_rejection_reason(event, family, correlated, level)
    field_quality = _field_quality_score(event, family)
    evidence_score = _evidence_completeness_score(event, evidence, family)
    family_confidence = _family_confidence_score(family, event, correlated)
    score = _clamp(0.30 * evidence_score + 0.30 * rule_corr + 0.20 * field_quality + 0.20 * family_confidence)
    source_quality, usage_scope, learnable = _resolve_usage_and_quality(
        family, event_class, score, level, rejection_reason, correlated
    )

    disposition = "rejected"
    learnable_candidate = False
    strong_rule_support = level in {"exact_event_link", "incident_bridge", "time_entity_rule_category_match"} and bool(correlated)
    if not rejection_reason and strong_rule_support and field_quality >= 0.60 and evidence_score >= 0.60 and score >= 0.85 and learnable:
        disposition = "direct_learnable"
        learnable_candidate = usage_scope == "calibration_only"
    elif not rejection_reason and score >= 0.65:
        disposition = "ignored"
    elif rejection_reason == "weak_rule_correlation" and score >= 0.60:
        disposition = "ignored"

    label_lifecycle_status = "verified_candidate" if disposition != "rejected" else "rejected_candidate"
    poisoning_guard_passed = rejection_reason not in {
        "local_test_noise",
        "external_burst_dominance",
        "single_source_dominance",
        "duplicate_replay",
        "bootstrap_source_excluded",
    }
    label_reason = f"verified_manifest_dry_run:{family.lower()}:{reason_hint}"
    if rejection_reason:
        learnable = False
        learnable_candidate = False
        if disposition == "direct_learnable":
            disposition = "rejected"
        if usage_scope == "baseline_learning":
            usage_scope = "not_learnable"
    candidate = CandidateLabel(
        source_event_id=f"events_recent:{event.event_id}",
        event_id=event.event_id,
        correlated_alert_ids=[item.alert_id for item in correlated],
        correlation_level=level,
        correlation_score=_clamp(correlation_score),
        candidate_score=_clamp(score),
        ml_family=family,
        ml_label=ml_label,
        event_class=event_class,
        behavior_label=behavior_label,
        source_quality=source_quality,
        model_usage_scope=usage_scope,
        learnable=learnable,
        label_lifecycle_status=label_lifecycle_status,
        poisoning_guard_passed=poisoning_guard_passed,
        label_reason=label_reason,
        evidence_fields=evidence,
        rejection_reason=rejection_reason,
        learnable_candidate=learnable_candidate,
        disposition=disposition,
    )
    return candidate


def _correlate_alerts(event: EventSnapshot, alerts: List[AlertSnapshot]) -> Tuple[List[AlertSnapshot], str, float, str]:
    best: List[AlertSnapshot] = []
    best_level = "time_proximity_only"
    best_score = 0.0
    best_reason = "time_only"
    for alert in alerts:
        time_diff = abs(alert.ts - event.ts)
        if time_diff > 900:
            continue
        ctx = alert.context_json or {}
        exact = any(
            str(ctx.get(key, "") or "").strip() == str(event.event_id)
            for key in ("event_id", "source_event_id", "correlation_id")
        )
        same_incident = bool(event.incident_id and alert.incident_id and event.incident_id == alert.incident_id)
        same_host = bool(event.host and alert.host and event.host == alert.host)
        same_user = bool(event.username and _norm(ctx.get("username", "")) == event.username)
        same_process = bool(event.process and _norm(ctx.get("process", "")) == event.process)
        same_ip = bool(event.src_ip and _norm(ctx.get("src_ip", "")) == event.src_ip)
        same_category = bool(alert.category and alert.category == event.category)
        level = "time_proximity_only"
        score = 0.52
        reason = "time_only"
        if exact:
            level = "exact_event_link"
            score = 0.98
            reason = "exact_context_event_id"
        elif same_incident and (same_host or same_user or same_process or same_ip):
            level = "incident_bridge"
            score = 0.88
            reason = "incident_bridge"
        elif same_category and (same_host or same_user or same_process or same_ip):
            level = "time_entity_rule_category_match"
            score = 0.72
            reason = "time_entity_match"
        if score > best_score:
            best = [alert]
            best_level = level
            best_score = score
            best_reason = reason
    if best:
        mapped = resolve_rule_id_to_ml_family(best[0].rule_id)
        return best, best_level, _clamp(max(best_score, mapped.confidence if mapped.matched else best_score)), best_reason
    return [], "time_proximity_only", 0.20, "no_rule_support"


def _resolve_label(family: str, event: EventSnapshot, correlated: List[AlertSnapshot]) -> Tuple[str, str, str]:
    rule_id = correlated[0].rule_id if correlated else ""
    mapped = resolve_rule_id_to_ml_family(rule_id)
    if family == "ML-AUTH":
        if event.action == "ssh_invalid_user" and event.outcome == "failure":
            return "auth_attack_or_abuse", "suspicious", "ssh_invalid_user_enumeration"
        if event.action == "ssh_login" and event.outcome == "failure":
            return "auth_attack_or_abuse", "suspicious", "ssh_auth_failure"
        if event.action in {"session_open", "session_close", "ssh_login"} and event.outcome == "success":
            return "ssh_login_normal", "benign", "expected_auth_activity"
        return "auth_attack_or_abuse", "suspicious", "auth_attack_or_abuse"
    if family == "ML-PROC":
        if rule_id.startswith("DISC-"):
            return "discovery_behavior", "suspicious", "process_discovery"
        if rule_id.startswith(("PROC-", "AUDIT-")):
            return "suspicious_process", "suspicious", "suspicious_process"
        if event.action == "lotl_exec":
            return "lolbin_abuse", "suspicious", "lolbin_abuse"
        return "process_normal", "benign", "routine_process_activity"
    if family == "ML-IMPACT":
        if mapped.ml_label in {"impact_or_tamper", "defense_evasion_or_tamper"}:
            return mapped.ml_label, mapped.label_class if mapped.label_class in {"attack", "suspicious"} else "suspicious", "destructive_impact_activity"
        return "cleanup_normal", "benign", "routine_system_event"
    return "unknown", "unknown_unlabeled", "unknown_unlabeled"


def _candidate_rejection_reason(event: EventSnapshot, family: str, correlated: List[AlertSnapshot], level: str) -> str:
    if family not in ALLOWED_FAMILIES:
        return "unsupported_family"
    if event.source == "bootstrap":
        return "bootstrap_source_excluded"
    if event.message and redact_text(event.message) != event.message and _contains_secret(event.message):
        return "unsafe_for_learning"
    if family == "ML-AUTH":
        if _malformed_identity(event.username):
            return "malformed_identity"
        if event.action == "ssh_login" and event.outcome == "failure" and not correlated:
            return "weak_rule_correlation"
        if event.action == "ssh_login" and event.outcome == "failure" and not event.src_ip:
            return "ambiguous_context"
    if family == "ML-PROC":
        if not event.process:
            return "empty_process_for_proc_family"
        if event.action == "syscall" and not correlated:
            return "generic_syscall_noise"
        if "chrome" in event.process and not correlated:
            return "local_test_noise"
    if family == "ML-IMPACT":
        if event.category == "filesystem" and event.action == "file_access" and not correlated:
            return "generic_file_access"
        if not correlated:
            return "weak_rule_correlation"
    if not event.host and not event.process and family in {"ML-PROC", "ML-IMPACT"}:
        return "empty_host_and_process"
    if level == "time_proximity_only":
        return "weak_rule_correlation"
    if event.message and any(token in event.message.lower() for token in ("test", "demo", "sample", "localhost")):
        return "local_test_noise"
    return ""


def _field_quality_score(event: EventSnapshot, family: str) -> float:
    fields = [event.source, event.category, event.action, event.outcome]
    if family == "ML-AUTH":
        fields.extend([event.username, event.process, event.host, event.src_ip])
    elif family == "ML-PROC":
        fields.extend([event.process, event.username, event.host])
    elif family == "ML-IMPACT":
        fields.extend([event.process, event.host])
    filled = sum(1 for item in fields if item)
    return _clamp(filled / max(len(fields), 1))


def _evidence_completeness_score(event: EventSnapshot, evidence: Dict[str, Any], family: str) -> float:
    required = ["source", "category", "action", "outcome", "message_excerpt"]
    if family == "ML-AUTH":
        required.extend(["username", "process"])
    elif family == "ML-PROC":
        required.extend(["process"])
    elif family == "ML-IMPACT":
        required.extend(["process", "rule_id_hint"])
    filled = sum(1 for key in required if evidence.get(key))
    return _clamp(filled / max(len(required), 1))


def _family_confidence_score(family: str, event: EventSnapshot, correlated: List[AlertSnapshot]) -> float:
    if family == "ML-AUTH":
        if event.action == "ssh_invalid_user" and event.outcome == "failure":
            return 0.95
        if event.action == "ssh_login" and event.outcome == "failure":
            return 0.88 if correlated else 0.55
        if event.action in {"session_open", "session_close"} and event.outcome == "success":
            return 0.82
        return 0.60
    if family == "ML-PROC":
        if correlated and correlated[0].rule_id.startswith(("PROC-", "AUDIT-")):
            return 0.88
        if correlated and correlated[0].rule_id.startswith("DISC-"):
            return 0.70
        if event.action == "lotl_exec":
            return 0.82
        return 0.45
    if family == "ML-IMPACT":
        if correlated and correlated[0].rule_id.startswith("DE-"):
            return 0.86
        if correlated:
            return 0.74
        return 0.30
    return 0.0


def _resolve_usage_and_quality(
    family: str,
    event_class: str,
    score: float,
    level: str,
    rejection_reason: str,
    correlated: List[AlertSnapshot],
) -> Tuple[str, str, bool]:
    rule_id = correlated[0].rule_id if correlated else ""
    if rule_id.startswith("DISC-") and not rejection_reason:
        return "heuristic_candidate_medium", "not_learnable", False
    if rejection_reason:
        return "heuristic_candidate_low", "not_learnable", False
    if score >= 0.85:
        if family == "ML-AUTH" and level in {"exact_event_link", "incident_bridge", "time_entity_rule_category_match"}:
            return "direct_rule_high", "calibration_only", True
        if family == "ML-PROC":
            return "direct_rule_high", "calibration_only", True
        if family == "ML-IMPACT":
            return "direct_rule_high", "calibration_only", True
    if event_class == "benign" and score >= 0.75 and family == "ML-AUTH":
        return "clean_source_high", "baseline_learning", True
    if score >= 0.65:
        return "heuristic_candidate_medium", "not_learnable", False
    return "heuristic_candidate_low", "not_learnable", False


def _build_evidence_fields(event: EventSnapshot, correlated: List[AlertSnapshot], manifest_id: str) -> Dict[str, Any]:
    rule_hint = correlated[0].rule_id if correlated else ""
    return {
        "manifest_id": manifest_id,
        "ts": event.ts,
        "source": event.source,
        "category": event.category,
        "action": event.action,
        "outcome": event.outcome,
        "username": event.username,
        "process": event.process,
        "host": event.host,
        "src_ip": event.src_ip,
        "message_excerpt": redact_text(event.message or event.raw_log),
        "raw_excerpt": redact_text(event.raw_log or event.message),
        "raw_presence": bool(event.raw_log or event.message),
        "rule_id_hint": rule_hint,
        "correlated_alert_ids": [item.alert_id for item in correlated],
    }


def _apply_duplicate_and_dominance_guards(candidates: List[CandidateLabel]) -> List[CandidateLabel]:
    by_family = defaultdict(list)
    for item in candidates:
        by_family[item.ml_family].append(item)

    for family, rows in by_family.items():
        fp_counts = Counter(_candidate_fingerprint(row) for row in rows)
        ip_counts = Counter((row.evidence_fields.get("src_ip", "") or "<empty>") for row in rows)
        process_counts = Counter((row.evidence_fields.get("process", "") or "<empty>") for row in rows)
        for row in rows:
            fp = _candidate_fingerprint(row)
            if fp_counts[fp] > 1 and not row.rejection_reason:
                row.rejection_reason = "duplicate_replay"
                row.disposition = "rejected"
                row.learnable_candidate = False
                row.learnable = False
                row.model_usage_scope = "not_learnable"
                row.poisoning_guard_passed = False
            src_ip = row.evidence_fields.get("src_ip", "") or "<empty>"
            if family == "ML-AUTH" and len(rows) >= 4 and src_ip != "<empty>" and ip_counts[src_ip] / max(len(rows), 1) > 0.55 and not row.rejection_reason:
                row.rejection_reason = "external_burst_dominance"
                row.disposition = "rejected"
                row.learnable_candidate = False
                row.learnable = False
                row.model_usage_scope = "not_learnable"
                row.poisoning_guard_passed = False
            proc = row.evidence_fields.get("process", "") or "<empty>"
            if family == "ML-PROC" and len(rows) >= 4 and proc != "<empty>" and process_counts[proc] / max(len(rows), 1) > 0.50 and not row.rejection_reason:
                row.rejection_reason = "single_source_dominance"
                row.disposition = "rejected"
                row.learnable_candidate = False
                row.learnable = False
                row.model_usage_scope = "not_learnable"
                row.poisoning_guard_passed = False
            if row.rejection_reason and row.disposition == "direct_learnable":
                row.disposition = "rejected"
    return candidates


def _candidate_fingerprint(candidate: CandidateLabel) -> str:
    raw = "|".join([
        candidate.ml_family,
        candidate.evidence_fields.get("source", "") or "",
        candidate.evidence_fields.get("action", "") or "",
        candidate.evidence_fields.get("username", "") or "",
        candidate.evidence_fields.get("process", "") or "",
        candidate.evidence_fields.get("src_ip", "") or "",
        candidate.evidence_fields.get("message_excerpt", "") or "",
    ])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _build_family_summary(candidates: List[Dict[str, Any]], families: Iterable[str]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    for family in families:
        rows = [item for item in candidates if item.get("ml_family") == family]
        summary[family] = {
            "candidate_count": len(rows),
            "direct_learnable": sum(1 for item in rows if item.get("disposition") == "direct_learnable"),
            "rejected": sum(1 for item in rows if item.get("disposition") == "rejected"),
            "ignored": sum(1 for item in rows if item.get("disposition") == "ignored"),
            "learnable_candidate_count": sum(1 for item in rows if item.get("learnable_candidate") is True),
        }
    return summary


def _top_share(values: Iterable[str]) -> Tuple[str, float]:
    counter = Counter(value or "<empty>" for value in values)
    if not counter:
        return "<empty>", 0.0
    name, count = counter.most_common(1)[0]
    total = sum(counter.values())
    return name, _clamp(count / max(total, 1))


def _build_dominance_summary(candidates: List[Dict[str, Any]], families: Iterable[str]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for family in families:
        rows = [item for item in candidates if item.get("ml_family") == family]
        src_name, src_share = _top_share(item.get("evidence_fields", {}).get("src_ip", "") for item in rows)
        user_name, user_share = _top_share(item.get("evidence_fields", {}).get("username", "") for item in rows)
        proc_name, proc_share = _top_share(item.get("evidence_fields", {}).get("process", "") for item in rows)
        host_name, host_share = _top_share(item.get("evidence_fields", {}).get("host", "") for item in rows)
        result[family] = {
            "src_ip_top": {"value": src_name, "share": src_share},
            "username_top": {"value": user_name, "share": user_share},
            "process_top": {"value": proc_name, "share": proc_share},
            "host_top": {"value": host_name, "share": host_share},
            "direct_learnable_vs_ignored_vs_rejected": {
                "direct_learnable": sum(1 for item in rows if item.get("disposition") == "direct_learnable"),
                "ignored": sum(1 for item in rows if item.get("disposition") == "ignored"),
                "rejected": sum(1 for item in rows if item.get("disposition") == "rejected"),
            },
            "source_distribution": dict(sorted(Counter(item.get("evidence_fields", {}).get("source", "") or "<empty>" for item in rows).items())),
        }
    return result


def _build_duplicate_summary(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    fps = [_candidate_fingerprint(_dict_to_candidate(item)) for item in candidates]
    total = len(fps)
    unique = len(set(fps))
    duplicate_count = max(total - unique, 0)
    return {
        "total": total,
        "unique": unique,
        "duplicate_count": duplicate_count,
        "duplicate_fingerprint_ratio": _clamp(duplicate_count / max(total, 1)) if total else 0.0,
    }


def _build_poisoning_guard_summary(candidates: List[Dict[str, Any]], dominance: Dict[str, Any], duplicates: Dict[str, Any]) -> Dict[str, Any]:
    malformed = sum(1 for item in candidates if item.get("rejection_reason") == "malformed_identity")
    local_noise = sum(1 for item in candidates if item.get("rejection_reason") == "local_test_noise")
    bootstrap = sum(1 for item in candidates if item.get("rejection_reason") == "bootstrap_source_excluded")
    total = len(candidates)
    return {
        "duplicate_fingerprint_ratio": duplicates.get("duplicate_fingerprint_ratio", 0.0),
        "local_test_noise_ratio": _clamp(local_noise / max(total, 1)) if total else 0.0,
        "malformed_identity_ratio": _clamp(malformed / max(total, 1)) if total else 0.0,
        "bootstrap_contamination_count": bootstrap,
        "dominance_summary_present": bool(dominance),
    }


def _readiness_decision(candidates: List[Dict[str, Any]], family_summary: Dict[str, Any], poisoning: Dict[str, Any]) -> str:
    if not candidates:
        return "blocked"
    direct_learnable = sum(1 for item in candidates if item.get("disposition") == "direct_learnable")
    if poisoning.get("bootstrap_contamination_count", 0) > 0:
        return "blocked"
    if poisoning.get("duplicate_fingerprint_ratio", 0.0) > 0.35:
        return "blocked"
    if direct_learnable >= 50:
        return "direct_learning_ready_with_warnings"
    if direct_learnable > 0:
        return "direct_learning_ready"
    return "blocked"


def _contains_secret(text: str) -> bool:
    return any(pattern.search(text or "") for pattern, _ in _SECRET_PATTERNS)


def _malformed_identity(username: str) -> bool:
    value = str(username or "")
    return bool(value and re.fullmatch(r"[0-9A-Fa-f]{12,}", value))


def _dict_to_candidate(item: Dict[str, Any]) -> CandidateLabel:
    return CandidateLabel(
        source_event_id=item.get("source_event_id", ""),
        event_id=item.get("event_id", ""),
        correlated_alert_ids=list(item.get("correlated_alert_ids", []) or []),
        correlation_level=item.get("correlation_level", ""),
        correlation_score=float(item.get("correlation_score", 0.0) or 0.0),
        candidate_score=float(item.get("candidate_score", 0.0) or 0.0),
        ml_family=item.get("ml_family", ""),
        ml_label=item.get("ml_label", ""),
        event_class=item.get("event_class", ""),
        behavior_label=item.get("behavior_label", ""),
        source_quality=item.get("source_quality", ""),
        model_usage_scope=item.get("model_usage_scope", ""),
        learnable=bool(item.get("learnable", False)),
        label_lifecycle_status=item.get("label_lifecycle_status", ""),
        poisoning_guard_passed=bool(item.get("poisoning_guard_passed", False)),
        label_reason=item.get("label_reason", ""),
        evidence_fields=copy.deepcopy(item.get("evidence_fields", {}) or {}),
        rejection_reason=item.get("rejection_reason", ""),
        learnable_candidate=bool(item.get("learnable_candidate", False)),
        disposition=item.get("disposition", ""),
        no_action_contract=bool(item.get("no_action_contract", True)),
        active_training_enabled=bool(item.get("active_training_enabled", False)),
    )


def _validate_candidate(candidate: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    required = (
        "source_event_id",
        "event_id",
        "correlated_alert_ids",
        "correlation_level",
        "correlation_score",
        "candidate_score",
        "ml_family",
        "ml_label",
        "event_class",
        "behavior_label",
        "source_quality",
        "model_usage_scope",
        "learnable",
        "label_lifecycle_status",
        "poisoning_guard_passed",
        "label_reason",
        "evidence_fields",
        "rejection_reason",
        "disposition",
        "no_action_contract",
        "active_training_enabled",
    )
    for field in required:
        if field not in candidate:
            problems.append(f"missing:{field}")
    if "learnable_candidate" not in candidate:
        problems.append("missing:learnable_candidate")
    if candidate.get("no_action_contract") is not True:
        problems.append("invalid:no_action_contract")
    if candidate.get("active_training_enabled") is not False:
        problems.append("invalid:active_training_enabled")
    if candidate.get("ml_family") not in ALLOWED_FAMILIES:
        problems.append("invalid:ml_family")
    if not isinstance(candidate.get("evidence_fields"), dict):
        problems.append("invalid:evidence_fields")
    return problems


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))
