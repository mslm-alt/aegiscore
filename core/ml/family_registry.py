from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class MLFamilySpec:
    family_id: str
    category: str
    phase_gate: str
    normal_label_targets: Dict[str, int]
    suspicious_label_targets: Dict[str, int]
    primary_features: Tuple[str, ...]
    time_features_enabled: bool
    no_action_contract: bool = True
    normal_label_quota: int = 0
    suspicious_label_quota: int = 0
    quota_mode: str = "stop_write"


@dataclass(frozen=True)
class MLRuleMappingResult:
    matched: bool
    rule_id: str
    ml_family: Optional[str]
    ml_label: Optional[str]
    label_class: str
    source_trust: str
    confidence: float
    mapping_reason: str

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class _MappingRule:
    family_id: str
    ml_label: str
    label_class: str
    source_trust: str
    confidence: float
    mapping_reason: str
    exact_rule_ids: Tuple[str, ...] = ()
    prefixes: Tuple[str, ...] = ()


ML_FAMILY_REGISTRY: Dict[str, MLFamilySpec] = {
    "ML-AUTH": MLFamilySpec(
        family_id="ML-AUTH",
        category="auth",
        phase_gate="PHASE_2",
        normal_label_targets={"ssh_login_normal": 100, "expected_auth_activity": 100},
        suspicious_label_targets={"auth_attack_or_abuse": 50},
        primary_features=("source", "action", "username", "src_ip", "host", "outcome"),
        time_features_enabled=True,
        normal_label_quota=3000,
        suspicious_label_quota=1000,
    ),
    "ML-SUDO": MLFamilySpec(
        family_id="ML-SUDO",
        category="privilege_escalation",
        phase_gate="PHASE_2",
        normal_label_targets={"sudo_normal": 100},
        suspicious_label_targets={"sudo_escalation_or_root_access": 50},
        primary_features=("action", "username", "process", "host", "outcome"),
        time_features_enabled=True,
        normal_label_quota=2000,
        suspicious_label_quota=500,
    ),
    "ML-PROC": MLFamilySpec(
        family_id="ML-PROC",
        category="process",
        phase_gate="PHASE_1",
        normal_label_targets={"process_normal": 300},
        suspicious_label_targets={"suspicious_process": 150, "lolbin_abuse": 75},
        primary_features=("category", "action", "process", "username", "host", "src_ip"),
        time_features_enabled=True,
        normal_label_quota=3000,
        suspicious_label_quota=1000,
    ),
    "ML-SERVICE": MLFamilySpec(
        family_id="ML-SERVICE",
        category="service",
        phase_gate="PHASE_2",
        normal_label_targets={"service_normal": 100},
        suspicious_label_targets={"persistence_service_mod": 50},
        primary_features=("category", "action", "process", "host", "outcome"),
        time_features_enabled=True,
        normal_label_quota=2000,
        suspicious_label_quota=500,
    ),
    "ML-NET": MLFamilySpec(
        family_id="ML-NET",
        category="network",
        phase_gate="PHASE_1",
        normal_label_targets={"normal_network": 200},
        suspicious_label_targets={"network_abuse": 100},
        primary_features=("category", "action", "src_ip", "dst_ip", "dst_port", "process", "host"),
        time_features_enabled=True,
        normal_label_quota=3000,
        suspicious_label_quota=1000,
    ),
    "ML-SEQ": MLFamilySpec(
        family_id="ML-SEQ",
        category="sequence",
        phase_gate="PHASE_3",
        normal_label_targets={"clean_sequence_normal": 150},
        suspicious_label_targets={"suspicious_sequence": 100},
        primary_features=("chain_id", "category", "action", "username", "host", "src_ip"),
        time_features_enabled=True,
        normal_label_quota=2000,
        suspicious_label_quota=1000,
    ),
    "ML-USER": MLFamilySpec(
        family_id="ML-USER",
        category="user_behavior",
        phase_gate="PHASE_2",
        normal_label_targets={"user_behavior_normal": 200},
        suspicious_label_targets={"user_behavior_anomaly": 80},
        primary_features=("username", "source", "action", "process", "host", "src_ip"),
        time_features_enabled=True,
        normal_label_quota=3000,
        suspicious_label_quota=800,
    ),
    "ML-HOST": MLFamilySpec(
        family_id="ML-HOST",
        category="host_behavior",
        phase_gate="PHASE_2",
        normal_label_targets={"host_behavior_normal": 300},
        suspicious_label_targets={"host_behavior_anomaly": 100},
        primary_features=("host", "source", "action", "process", "username", "src_ip"),
        time_features_enabled=True,
        normal_label_quota=3000,
        suspicious_label_quota=800,
    ),
    "ML-DBAUTH": MLFamilySpec(
        family_id="ML-DBAUTH",
        category="db_auth",
        phase_gate="PHASE_2",
        normal_label_targets={"db_login_normal": 80, "expected_db_activity": 80},
        suspicious_label_targets={"db_login_abuse": 40},
        primary_features=("category", "action", "username", "host", "src_ip", "process"),
        time_features_enabled=True,
        normal_label_quota=2000,
        suspicious_label_quota=500,
    ),
    "ML-DNS": MLFamilySpec(
        family_id="ML-DNS",
        category="dns",
        phase_gate="PHASE_2",
        normal_label_targets={"dns_normal": 150},
        suspicious_label_targets={"dns_anomaly": 60},
        primary_features=("source", "action", "src_ip", "dst_ip", "dst_port", "host"),
        time_features_enabled=True,
        normal_label_quota=3000,
        suspicious_label_quota=800,
    ),
    "ML-WEBPOST": MLFamilySpec(
        family_id="ML-WEBPOST",
        category="web_post_exploitation",
        phase_gate="PHASE_3",
        normal_label_targets={"web_request_normal_linked": 150},
        suspicious_label_targets={"web_attack_or_post_exploit": 80},
        primary_features=("source", "action", "category", "process", "host", "src_ip"),
        time_features_enabled=True,
        normal_label_quota=3000,
        suspicious_label_quota=1000,
    ),
    "ML-IMPACT": MLFamilySpec(
        family_id="ML-IMPACT",
        category="impact",
        phase_gate="PHASE_3",
        normal_label_targets={"cleanup_normal": 80},
        suspicious_label_targets={"impact_or_tamper": 60},
        primary_features=("category", "action", "process", "host", "username", "src_ip"),
        time_features_enabled=True,
        normal_label_quota=1000,
        suspicious_label_quota=800,
    ),
}

ML_QUOTA_LABEL_TYPES: Tuple[str, ...] = ("normal", "suspicious")
ML_QUOTA_MODES: Tuple[str, ...] = ("stop_write", "sampling", "drift_only")
_UNKNOWN_DISTRO_TOKENS = {"", "unknown", "unknown_distro", "n/a", "na", "none"}


_EXACT_RULE_MAPPINGS: Tuple[_MappingRule, ...] = (
    _MappingRule(
        family_id="ML-SUDO",
        ml_label="sudo_escalation_or_root_access",
        label_class="attack",
        source_trust="rule_high",
        confidence=0.99,
        mapping_reason="explicit_rule_override",
        exact_rule_ids=("AUTH-004", "AUTH-005", "AUTH-009"),
    ),
    _MappingRule(
        family_id="ML-DNS",
        ml_label="high_entropy_dns_burst",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.96,
        mapping_reason="explicit_rule_override",
        exact_rule_ids=("THR-023",),
    ),
    _MappingRule(
        family_id="ML-WEBPOST",
        ml_label="web_discovery_probe",
        label_class="suspicious",
        source_trust="rule_medium",
        confidence=0.82,
        mapping_reason="explicit_rule_override",
        exact_rule_ids=("WEB-005",),
    ),
    _MappingRule(
        family_id="ML-WEBPOST",
        ml_label="web_attack_or_post_exploit",
        label_class="attack",
        source_trust="rule_high",
        confidence=0.98,
        mapping_reason="explicit_rule_override",
        exact_rule_ids=("NET-WEB-001", "NET-WEB-002", "WEB-004", "WEB-014", "WEB-015", "WEB-018", "WEB-019", "WEB-020"),
    ),
    _MappingRule(
        family_id="ML-PROC",
        ml_label="package_repository_abuse",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.95,
        mapping_reason="explicit_rule_override",
        exact_rule_ids=("PKG-013", "PKG-014"),
    ),
    _MappingRule(
        family_id="ML-NET",
        ml_label="network_abuse",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.95,
        mapping_reason="explicit_rule_override",
        exact_rule_ids=("NET-DB-001",),
    ),
    _MappingRule(
        family_id="ML-DBAUTH",
        ml_label="db_login_abuse",
        label_class="attack",
        source_trust="rule_high",
        confidence=0.97,
        mapping_reason="explicit_rule_override",
        exact_rule_ids=("DB-001",),
    ),
    _MappingRule(
        family_id="ML-IMPACT",
        ml_label="impact_or_tamper",
        label_class="attack",
        source_trust="rule_high",
        confidence=0.98,
        mapping_reason="explicit_rule_override",
        exact_rule_ids=("SEQ-065", "SEQ-066"),
    ),
)


_PREFIX_RULE_MAPPINGS: Tuple[_MappingRule, ...] = (
    _MappingRule(
        family_id="ML-SUDO",
        ml_label="sudo_escalation_or_root_access",
        label_class="attack",
        source_trust="rule_high",
        confidence=0.98,
        mapping_reason="prefix_override_atk_pe",
        prefixes=("ATK-PE-",),
    ),
    _MappingRule(
        family_id="ML-AUTH",
        ml_label="brute_force_or_auth_attack",
        label_class="attack",
        source_trust="rule_high",
        confidence=0.98,
        mapping_reason="prefix_rule_atk_bf",
        prefixes=("ATK-BF-",),
    ),
    _MappingRule(
        family_id="ML-SEQ",
        ml_label="lateral_movement_sequence",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.97,
        mapping_reason="prefix_rule_atk_lm",
        prefixes=("ATK-LM-",),
    ),
    _MappingRule(
        family_id="ML-SERVICE",
        ml_label="persistence_behavior",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.97,
        mapping_reason="prefix_rule_atk_per",
        prefixes=("ATK-PER-",),
    ),
    _MappingRule(
        family_id="ML-IMPACT",
        ml_label="impact_or_tamper",
        label_class="attack",
        source_trust="rule_high",
        confidence=0.97,
        mapping_reason="prefix_override_impact",
        prefixes=("PROC-IMP", "IMPACT-", "TAMPER-", "LOG-TAMPER-"),
    ),
    _MappingRule(
        family_id="ML-SERVICE",
        ml_label="persistence_service_mod",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.96,
        mapping_reason="prefix_rule_audit_persist",
        prefixes=("AUDIT-PERSIST-",),
    ),
    _MappingRule(
        family_id="ML-SUDO",
        ml_label="privilege_escalation_behavior",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.96,
        mapping_reason="prefix_rule_audit_privesc",
        prefixes=("AUDIT-PRIVESC-",),
    ),
    _MappingRule(
        family_id="ML-PROC",
        ml_label="lolbin_abuse",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.96,
        mapping_reason="prefix_override_lolbin",
        prefixes=("LOLBIN-", "LOL-"),
    ),
    _MappingRule(
        family_id="ML-WEBPOST",
        ml_label="web_attack_or_post_exploit",
        label_class="attack",
        source_trust="rule_high",
        confidence=0.96,
        mapping_reason="prefix_override_web",
        prefixes=("NET-WEB-", "WEB-"),
    ),
    _MappingRule(
        family_id="ML-DNS",
        ml_label="dns_anomaly",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.95,
        mapping_reason="prefix_rule_dns",
        prefixes=("DNS-",),
    ),
    _MappingRule(
        family_id="ML-DBAUTH",
        ml_label="db_login_abuse",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.95,
        mapping_reason="prefix_rule_db",
        prefixes=("DB-",),
    ),
    _MappingRule(
        family_id="ML-SERVICE",
        ml_label="persistence_service_mod",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.95,
        mapping_reason="prefix_rule_persistence",
        prefixes=("PERS-",),
    ),
    _MappingRule(
        family_id="ML-IMPACT",
        ml_label="defense_evasion_or_tamper",
        label_class="suspicious",
        source_trust="rule_medium",
        confidence=0.93,
        mapping_reason="prefix_rule_defense_evasion",
        prefixes=("DE-",),
    ),
    _MappingRule(
        family_id="ML-PROC",
        ml_label="discovery_behavior",
        label_class="suspicious",
        source_trust="rule_medium",
        confidence=0.92,
        mapping_reason="prefix_rule_discovery",
        prefixes=("DISC-",),
    ),
    _MappingRule(
        family_id="ML-IMPACT",
        ml_label="file_integrity_tamper",
        label_class="suspicious",
        source_trust="rule_medium",
        confidence=0.91,
        mapping_reason="prefix_rule_fim",
        prefixes=("FIM-",),
    ),
    _MappingRule(
        family_id="ML-HOST",
        ml_label="first_seen_behavior",
        label_class="suspicious",
        source_trust="rule_low",
        confidence=0.88,
        mapping_reason="prefix_rule_first_seen",
        prefixes=("FIRST-",),
    ),
    _MappingRule(
        family_id="ML-HOST",
        ml_label="monitoring_or_host_drift",
        label_class="suspicious",
        source_trust="rule_low",
        confidence=0.86,
        mapping_reason="prefix_rule_monitoring",
        prefixes=("MON-",),
    ),
    _MappingRule(
        family_id="ML-PROC",
        ml_label="package_install_or_package_abuse",
        label_class="suspicious",
        source_trust="rule_medium",
        confidence=0.90,
        mapping_reason="prefix_rule_package",
        prefixes=("PKG-",),
    ),
    _MappingRule(
        family_id="ML-SUDO",
        ml_label="privilege_escalation_behavior",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.95,
        mapping_reason="prefix_rule_privesc",
        prefixes=("PRIVESC-",),
    ),
    _MappingRule(
        family_id="ML-NET",
        ml_label="network_abuse",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.94,
        mapping_reason="prefix_rule_network",
        prefixes=("FW-", "NET-"),
    ),
    _MappingRule(
        family_id="ML-SEQ",
        ml_label="suspicious_sequence",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.94,
        mapping_reason="prefix_rule_sequence",
        prefixes=("SEQ-",),
    ),
    _MappingRule(
        family_id="ML-PROC",
        ml_label="suspicious_process",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.94,
        mapping_reason="prefix_rule_process",
        prefixes=("PROC-", "AUDIT-CRED-", "AUDIT-"),
    ),
    _MappingRule(
        family_id="ML-AUTH",
        ml_label="auth_attack_or_abuse",
        label_class="suspicious",
        source_trust="rule_high",
        confidence=0.93,
        mapping_reason="prefix_rule_auth",
        prefixes=("AUTH-", "SSH-"),
    ),
)


def list_ml_families() -> List[MLFamilySpec]:
    return [ML_FAMILY_REGISTRY[key] for key in sorted(ML_FAMILY_REGISTRY)]


def get_ml_family_spec(family_id: str) -> Optional[MLFamilySpec]:
    return ML_FAMILY_REGISTRY.get((family_id or "").strip().upper())


def ml_family_registry_snapshot() -> Dict[str, Dict[str, object]]:
    return {family_id: asdict(spec) for family_id, spec in ML_FAMILY_REGISTRY.items()}


def resolve_family_label_quotas(config: Optional[Dict[str, object]] = None) -> Dict[str, Dict[str, object]]:
    ml_cfg = dict((config or {}).get("ml", {}) or {}) if isinstance(config, dict) else {}
    family_cfg = dict(ml_cfg.get("family", {}) or {})
    result: Dict[str, Dict[str, object]] = {}
    for family_id, spec in ML_FAMILY_REGISTRY.items():
        overrides = dict(family_cfg.get(family_id, {}) or {})
        mode = str(overrides.get("label_quota_mode", spec.quota_mode) or spec.quota_mode).strip().lower()
        if mode not in ML_QUOTA_MODES:
            mode = spec.quota_mode
        result[family_id] = {
            "normal": int(overrides.get("normal_label_quota", spec.normal_label_quota) or spec.normal_label_quota),
            "suspicious": int(overrides.get("suspicious_label_quota", spec.suspicious_label_quota) or spec.suspicious_label_quota),
            "mode": mode,
        }
    return result


def classify_label_quota_type(payload: Dict[str, object]) -> str:
    item = dict(payload or {})
    evidence = dict(item.get("evidence_fields", {}) or {}) if isinstance(item.get("evidence_fields", {}), dict) else {}
    scope = str(item.get("model_usage_scope", evidence.get("model_usage_scope", "")) or "").strip().lower()
    event_class = str(item.get("event_class", evidence.get("event_class", "")) or "").strip().lower()
    learnable = item.get("learnable", evidence.get("learnable"))
    usage_decision = str(item.get("usage_decision", evidence.get("usage_decision", "")) or "").strip().lower()
    if learnable is False or scope in {"ignored", "rejected", "not_learnable"} or usage_decision in {"ignored", "rejected"}:
        return ""
    if scope == "baseline_learning" or event_class == "benign":
        return "normal"
    if scope in {"calibration_only", "direct_learnable"} or event_class in {"suspicious", "attack"}:
        return "suspicious"
    return ""


def build_label_quota_bucket(payload: Dict[str, object]) -> Optional[Tuple[str, str, str]]:
    item = dict(payload or {})
    evidence = dict(item.get("evidence_fields", {}) or {}) if isinstance(item.get("evidence_fields", {}), dict) else {}
    family = str(
        item.get("ml_family", item.get("label_family", evidence.get("ml_family", evidence.get("label_family", ""))))
        or ""
    ).strip().upper()
    distro = str(item.get("distro_family", item.get("distro", evidence.get("distro_family", evidence.get("distro", "")))) or "").strip().lower()
    label_type = classify_label_quota_type(item)
    if not family or not label_type or distro in _UNKNOWN_DISTRO_TOKENS:
        return None
    return family, distro, label_type


def summarize_label_quota_usage(
    rows: List[Dict[str, object]],
    config: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    contract = resolve_family_label_quotas(config)
    usage: Dict[str, Dict[str, Dict[str, Dict[str, object]]]] = {}
    unknown_distro_blocked = 0
    quota_blocked_count = 0
    full_entries: List[str] = []

    for row in list(rows or []):
        label_type = classify_label_quota_type(dict(row or {}))
        if not label_type:
            continue
        bucket = build_label_quota_bucket(dict(row or {}))
        if bucket is None:
            unknown_distro_blocked += 1
            continue
        family, distro, bucket_type = bucket
        limit = int(dict(contract.get(family, {}) or {}).get(bucket_type, 0) or 0)
        family_bucket = usage.setdefault(family, {})
        distro_bucket = family_bucket.setdefault(distro, {})
        slot = distro_bucket.setdefault(
            bucket_type,
            {"used": 0, "limit": limit, "remaining": max(limit, 0), "status": "collecting"},
        )
        slot["used"] = int(slot.get("used", 0) or 0) + 1

    for family, distro_rows in usage.items():
        for distro, type_rows in distro_rows.items():
            for label_type, values in type_rows.items():
                limit = int(values.get("limit", 0) or 0)
                used = int(values.get("used", 0) or 0)
                remaining = max(limit - used, 0)
                status = "full" if limit > 0 and used >= limit else "collecting"
                values["remaining"] = remaining
                values["status"] = status
                if status == "full":
                    quota_blocked_count += 1
                    full_entries.append(f"{family}/{distro}/{label_type}")

    empty_template = {"used": 0, "limit": 0, "remaining": 0, "status": "collecting"}
    for family, quotas in contract.items():
        usage.setdefault(family, {})
        usage[family].setdefault("all", {})
        for label_type in ML_QUOTA_LABEL_TYPES:
            used_total = 0
            for distro, distro_rows in usage[family].items():
                if distro == "all":
                    continue
                used_total += int(dict(distro_rows.get(label_type, {}) or {}).get("used", 0) or 0)
            limit = int(dict(quotas or {}).get(label_type, 0) or 0)
            remaining = max(limit - used_total, 0)
            status = "full" if limit > 0 and used_total >= limit else "collecting"
            usage[family]["all"].setdefault(
                label_type,
                {
                    **empty_template,
                    "used": used_total,
                    "limit": limit,
                    "remaining": remaining,
                    "status": status,
                },
            )

    return {
        "contract": contract,
        "usage": usage,
        "full_families": sorted(full_entries),
        "quota_blocked_count": quota_blocked_count,
        "unknown_distro_blocked_count": unknown_distro_blocked,
    }


def resolve_rule_to_ml_mapping(rule_id: str) -> MLRuleMappingResult:
    normalized_rule_id = (rule_id or "").strip().upper()
    if not normalized_rule_id:
        return MLRuleMappingResult(
            matched=False,
            rule_id="",
            ml_family=None,
            ml_label=None,
            label_class="unknown_unlabeled",
            source_trust="",
            confidence=0.0,
            mapping_reason="missing_rule_id",
        )

    for rule in _EXACT_RULE_MAPPINGS:
        if normalized_rule_id in rule.exact_rule_ids:
            return MLRuleMappingResult(
                matched=True,
                rule_id=normalized_rule_id,
                ml_family=rule.family_id,
                ml_label=rule.ml_label,
                label_class=rule.label_class,
                source_trust=rule.source_trust,
                confidence=rule.confidence,
                mapping_reason=rule.mapping_reason,
            )

    for rule in _PREFIX_RULE_MAPPINGS:
        if any(normalized_rule_id.startswith(prefix) for prefix in rule.prefixes):
            return MLRuleMappingResult(
                matched=True,
                rule_id=normalized_rule_id,
                ml_family=rule.family_id,
                ml_label=rule.ml_label,
                label_class=rule.label_class,
                source_trust=rule.source_trust,
                confidence=rule.confidence,
                mapping_reason=rule.mapping_reason,
            )

    return MLRuleMappingResult(
        matched=False,
        rule_id=normalized_rule_id,
        ml_family=None,
        ml_label=None,
        label_class="unknown_unlabeled",
        source_trust="",
        confidence=0.0,
        mapping_reason="unmapped_rule_id",
    )


def _normalize_rule_id(rule_id: str) -> str:
    return (rule_id or "").strip().upper()


def _match_exact_rule(rule_id: str, rules: Iterable[_MappingRule]) -> Optional[_MappingRule]:
    for rule in rules:
        if rule_id in rule.exact_rule_ids:
            return rule
    return None


def _match_prefix_rule(rule_id: str, rules: Iterable[_MappingRule]) -> Optional[_MappingRule]:
    for rule in rules:
        if any(rule_id.startswith(prefix) for prefix in rule.prefixes):
            return rule
    return None


def resolve_rule_id_to_ml_family(rule_id: str) -> MLRuleMappingResult:
    normalized = _normalize_rule_id(rule_id)
    if not normalized:
        return MLRuleMappingResult(
            matched=False,
            rule_id=normalized,
            ml_family=None,
            ml_label=None,
            label_class="unknown",
            source_trust="rule_low",
            confidence=0.0,
            mapping_reason="empty_rule_id",
        )

    matched = _match_exact_rule(normalized, _EXACT_RULE_MAPPINGS)
    if matched is None:
        matched = _match_prefix_rule(normalized, _PREFIX_RULE_MAPPINGS)
    if matched is None:
        return MLRuleMappingResult(
            matched=False,
            rule_id=normalized,
            ml_family=None,
            ml_label=None,
            label_class="unknown",
            source_trust="rule_low",
            confidence=0.0,
            mapping_reason="unmapped_rule_id",
        )

    return MLRuleMappingResult(
        matched=True,
        rule_id=normalized,
        ml_family=matched.family_id,
        ml_label=matched.ml_label,
        label_class=matched.label_class,
        source_trust=matched.source_trust,
        confidence=matched.confidence,
        mapping_reason=matched.mapping_reason,
    )
