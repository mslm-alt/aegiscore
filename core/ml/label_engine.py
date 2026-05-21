"""
core/ml/label_engine.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Hybrid labeling layer

Four sources with hierarchical weighting:
  1. synthetic         — bootstrap scaffold with no real data         weight=0.50
  2. bootstrap         — install-time log scan, runs once             weight=0.65
  3. auto_labeled      — live system labels from rule/IOC/chain hits  weight=0.72-0.95

Lifecycle (linear, no abrupt transitions):
  Start      : synthetic(0.50) + bootstrap(0.65) feed calibration
  Growth     : auto_labeled records accumulate and the seed weights shrink linearly
  Maturity   : synthetic weight→0, bootstrap weight→0
  Long term  : auto_labeled only

Transition formulas:
  synthetic_weight = max(0, 0.50 * (1 - ratio / 2.0))
  bootstrap_weight = max(0, 0.65 * (1 - ratio / 3.0))

Loop-protection rules:
  1. ready_after: a label waits MIN_AUTO_LABEL_AGE seconds before entering calibration
  2. Entity throttle: max MAX_AUTO_PER_ENTITY_24H auto labels per entity in 24h
  3. Alarm guard: auto-normal labels are blocked for alarmed entities
  4. Delayed learning: process_normal is accepted only when delayed_learning_ok=True
"""

import json
import hashlib
import os
import re
import time
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import Counter, defaultdict
from core.ml.family_registry import (
    build_label_quota_bucket,
    get_ml_family_spec,
    resolve_family_label_quotas,
    resolve_rule_to_ml_mapping,
)

logger = logging.getLogger(__name__)

# -- Source Constants --------------------------------------------------------

SOURCE_SYNTHETIC          = "synthetic"
SOURCE_BOOTSTRAP          = "bootstrap"
SOURCE_AUTO_LABELED       = "auto_labeled"
SOURCE_OPERATOR_LABEL     = "operator_label"
SOURCE_BASE_WEIGHTS: Dict[str, float] = {
    SOURCE_SYNTHETIC:         0.50,
    SOURCE_BOOTSTRAP:         0.65,
    SOURCE_AUTO_LABELED:      1.0,   # multiplied by confidence
    SOURCE_OPERATOR_LABEL:    2.0,
}
SYNTHETIC_ATTACK_BASE_WEIGHT = 0.45
SYNTHETIC_NORMAL_BASE_WEIGHT = 0.55

SYNTHETIC_RETIRE_AT_RATIO = 2.0
BOOTSTRAP_RETIRE_AT_RATIO = 3.0

DISTRO_THRESHOLDS: Dict[str, int] = {
    "debian": 50, "ubuntu": 50,
    "rhel":   60, "centos": 60, "fedora": 55,
    "suse":   45, "opensuse": 45,
    "unknown": 50,
}

ATTACK_CATEGORIES = [
    "brute_force", "lolbin", "persistence", "lateral_movement",
    "privilege_esc", "first_seen", "slow_low", "webshell", "journald",
    "selinux_evasion", "zypper_tamper",
]
DISTRO_ATTACK_CATEGORIES: Dict[str, List[str]] = {
    "debian": [
        "brute_force", "lolbin", "persistence", "lateral_movement",
        "privilege_esc", "first_seen", "slow_low", "webshell", "journald",
    ],
    "rhel": [
        "brute_force", "lolbin", "persistence", "lateral_movement",
        "privilege_esc", "first_seen", "slow_low", "webshell", "journald",
        "selinux_evasion",
    ],
    "suse": [
        "brute_force", "lolbin", "persistence", "lateral_movement",
        "privilege_esc", "first_seen", "slow_low", "webshell", "journald",
        "zypper_tamper",
    ],
}
NORMAL_CATEGORIES = [
    "package_management", "auth_normal", "system_service",
    "normal_network", "routine_file_access", "normal_logout", "selinux_routine",
]

AUTO_LABEL_MIN_CONFIDENCE = 0.70
MIN_AUTO_LABEL_AGE        = 300     # seconds
MAX_AUTO_PER_ENTITY_24H   = 3
AUTO_LABEL_CATEGORY_CAP   = 200

ML_LABEL_EVENT_CLASSES = {"benign", "attack", "suspicious", "unknown_unlabeled"}
ML_LABEL_USAGE_SCOPES = {"baseline_learning", "calibration_only", "not_learnable"}
ML_LABEL_SOURCE_TYPES = {
    "rule_mapped_attack",
    "clean_window_normal",
    "bootstrap_seed",
    "synthetic_seed",
    "auto_labeled_rule_mapped",
}
UNMAPPED_NONLEARNABLE_FAMILY = "UNMAPPED_NONLEARNABLE"
_AUTO_LABEL_BENIGN_ADMIN_ALLOWLIST = {"PKG-013", "PKG-014"}
ML_LABEL_CONTRACT_REQUIRED_FIELDS = (
    "event_class",
    "behavior_label",
    "source_trust",
    "model_usage_scope",
    "learnable",
    "evidence_fields",
    "label_reason",
    "ml_family",
    "ml_label",
    "label_family",
    "source",
    "no_action_contract",
)
_ML_LABEL_SOURCE_DEFAULTS = {
    "rule_mapped_attack": {
        "event_class": "attack",
        "source": "rule_mapped",
        "source_trust": "rule_high",
        "model_usage_scope": "calibration_only",
        "learnable": True,
    },
    "clean_window_normal": {
        "event_class": "benign",
        "source": "clean_window",
        "source_trust": "observed_benign_high",
        "model_usage_scope": "baseline_learning",
        "learnable": True,
    },
    "bootstrap_seed": {
        "event_class": "attack",
        "source": "bootstrap",
        "source_trust": "bootstrap_canonical",
        "model_usage_scope": "calibration_only",
        "learnable": False,
    },
    "synthetic_seed": {
        "event_class": "attack",
        "source": "synthetic",
        "source_trust": "synthetic_high",
        "model_usage_scope": "not_learnable",
        "learnable": False,
    },
    "auto_labeled_rule_mapped": {
        "event_class": "suspicious",
        "source": "auto_labeled",
        "source_trust": "rule_high",
        "model_usage_scope": "calibration_only",
        "learnable": True,
    },
}


def build_ml_label_metadata(source_type: str,
                            ml_family: str,
                            ml_label: str,
                            *,
                            behavior_label: str = "",
                            event_class: str = "",
                            rule_id: str = "",
                            evidence_fields=None,
                            label_reason: str = "",
                            source_trust: str = "",
                            model_usage_scope: str = "",
                            learnable=None) -> Dict[str, object]:
    normalized_source_type = (source_type or "").strip().lower()
    defaults = _ML_LABEL_SOURCE_DEFAULTS.get(normalized_source_type, {})
    family_id = (ml_family or "").strip().upper()
    label_name = (ml_label or "").strip()
    behavior = (behavior_label or "").strip() or label_name
    evidence = dict(evidence_fields or {})
    if rule_id:
        evidence.setdefault("rule_id", (rule_id or "").strip().upper())
    evidence.setdefault("source_type", normalized_source_type)
    evidence.setdefault("ml_family", family_id)
    metadata = {
        "event_class": (event_class or defaults.get("event_class", "unknown_unlabeled")).strip().lower(),
        "behavior_label": behavior,
        "source_trust": (source_trust or defaults.get("source_trust", "rule_low")).strip().lower(),
        "model_usage_scope": (model_usage_scope or defaults.get("model_usage_scope", "not_learnable")).strip().lower(),
        "learnable": defaults.get("learnable") if learnable is None else bool(learnable),
        "evidence_fields": evidence,
        "label_reason": (label_reason or f"ml_label_contract:{normalized_source_type}").strip(),
        "ml_family": family_id,
        "ml_label": label_name,
        "label_family": family_id,
        "rule_id": (rule_id or "").strip().upper(),
        "source": (defaults.get("source", normalized_source_type) or normalized_source_type).strip().lower(),
        "no_action_contract": True,
        "source_type": normalized_source_type,
        "poisoning_guard_passed": True,
    }
    return metadata


def _with_labelability_metadata(metadata: Dict[str, object], *, status: str, reason: str) -> Dict[str, object]:
    payload = dict(metadata or {})
    evidence = dict(payload.get("evidence_fields", {}) or {})
    labelability_status = str(status or "not_labelable").strip().lower() or "not_labelable"
    labelability_reason = str(reason or "parse_invalid").strip().lower() or "parse_invalid"
    payload["labelability_status"] = labelability_status
    payload["labelability_reason"] = labelability_reason
    evidence["labelability_status"] = labelability_status
    evidence["labelability_reason"] = labelability_reason
    payload["evidence_fields"] = evidence
    return payload


def validate_ml_label_metadata(metadata: Dict[str, object]) -> Dict[str, object]:
    problems: List[str] = []
    payload = dict(metadata or {})
    source_type = (payload.get("source_type", "") or "").strip().lower()
    ml_family = (payload.get("ml_family", "") or "").strip().upper()
    ml_label = (payload.get("ml_label", "") or "").strip()
    event_class = (payload.get("event_class", "") or "").strip().lower()
    model_usage_scope = (payload.get("model_usage_scope", "") or "").strip().lower()
    source = (payload.get("source", "") or "").strip().lower()

    for field in ML_LABEL_CONTRACT_REQUIRED_FIELDS:
        if payload.get(field) in (None, "", {}):
            problems.append(f"missing:{field}")
    if source_type not in ML_LABEL_SOURCE_TYPES:
        problems.append("invalid:source_type")
    if get_ml_family_spec(ml_family) is None:
        problems.append("invalid:ml_family")
    if not ml_label:
        problems.append("invalid:ml_label")
    if event_class not in ML_LABEL_EVENT_CLASSES:
        problems.append("invalid:event_class")
    if model_usage_scope not in ML_LABEL_USAGE_SCOPES:
        problems.append("invalid:model_usage_scope")
    if payload.get("no_action_contract") is not True:
        problems.append("invalid:no_action_contract")
    if payload.get("label_family") != ml_family:
        problems.append("mismatch:label_family")
    if not isinstance(payload.get("evidence_fields"), dict):
        problems.append("invalid:evidence_fields")
    if source_type in {"bootstrap_seed", "synthetic_seed"} and model_usage_scope == "active_training":
        problems.append("forbidden:seed_active_training")
    if source_type == "rule_mapped_attack" and event_class not in {"attack", "suspicious"}:
        problems.append("invalid:rule_mapped_attack_event_class")
    if source_type == "clean_window_normal" and event_class != "benign":
        problems.append("invalid:clean_window_event_class")
    if source not in {"rule_mapped", "clean_window", "bootstrap", "synthetic", "auto_labeled", "operator_label"}:
        problems.append("invalid:source")
    if source == "unknown" and model_usage_scope == "baseline_learning":
        problems.append("forbidden:unknown_source_baseline_learning")
    sentinel_allowed = (
        source_type in {"rule_mapped_attack", "clean_window_normal"}
        and ml_family == UNMAPPED_NONLEARNABLE_FAMILY
        and payload.get("label_family") == UNMAPPED_NONLEARNABLE_FAMILY
        and ml_label == "unknown_unlabeled"
        and (payload.get("behavior_label", "") or "").strip().lower() == "unknown_unlabeled"
        and event_class == "unknown_unlabeled"
        and model_usage_scope == "not_learnable"
        and payload.get("learnable") is False
    )
    if sentinel_allowed:
        problems = [
            problem for problem in problems
            if problem not in {"invalid:ml_family", "mismatch:label_family", "invalid:rule_mapped_attack_event_class", "invalid:clean_window_event_class"}
        ]
    return {
        "valid": not problems,
        "problems": problems,
        "metadata": payload,
    }

HISTORIC_MAX_FILE_MB  = 500
HISTORIC_MAX_TOTAL_MB = 2048
HISTORIC_MAX_AGE_DAYS = 30

TRUSTED_PACKAGE_PROCESSES = {
    "apt", "apt-get", "dpkg", "yum", "dnf", "zypper", "rpm",
    "unattended-upgrade", "update-notifier",
}
SAFE_NETWORK_PROCESSES = {"systemd-resolved", "named", "dnsmasq", "resolved", "networkmanager"}
ROUTINE_FILE_PREFIXES = (
    "/etc/", "/usr/", "/var/log/", "/var/lib/", "/run/", "/tmp/",
)
CONFIG_MGMT_PROCESSES = {
    "ansible", "ansible-playbook", "chef-client", "puppet", "puppet-agent",
    "salt-call", "salt-minion",
}
ADMIN_CONTEXT_TOKENS = (
    "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion",
    "backup", "restore", "rsnapshot", "borg", "restic", "duplicity", "timeshift",
    "snapper", "transactional-update", "subscription-manager", "suseconnect",
    "unattended-upgrades", "needrestart", "packagekit", "supportconfig", "sosreport",
    "apport", "ubuntu-bug", "healthz", "readyz", "livez", "server-status", "server-info",
    "/var/backups/", "/srv/backup/", "/backup/", "/backups/", "/etc/ansible/",
    "/srv/ansible/", "/srv/salt/", "/etc/puppetlabs/", "/var/lib/puppet/",
)


def _event_text(event) -> str:
    if event is None:
        return ""
    fields = getattr(event, "fields", {}) or {}
    parts = [
        getattr(event, "message", "") or "",
        getattr(event, "process", "") or "",
        getattr(event, "action", "") or "",
        getattr(event, "category", "") or "",
        str(fields.get("cmdline", "") or ""),
        str(fields.get("path", "") or ""),
        str(fields.get("path_decoded", "") or ""),
    ]
    return " ".join(part.lower() for part in parts if part)


def _safe_event_ts(event=None, alert: Optional[dict] = None) -> Tuple[float, str]:
    candidates = []
    if event is not None:
        candidates.append(getattr(event, "ts", 0.0))
    if alert is not None:
        candidates.append((alert or {}).get("ts", 0.0))
    for raw in candidates:
        try:
            ts_value = float(raw or 0.0)
        except (TypeError, ValueError):
            ts_value = 0.0
        if ts_value > 0.0:
            return ts_value, "event"
    return time.time(), "ingest_fallback"


def _coerce_alert_score(alert: dict) -> float:
    candidates = [
        alert.get("score", None),
        alert.get("risk_score", None),
        alert.get("raw_score", None),
    ]
    risk_block = alert.get("risk", None)
    if isinstance(risk_block, dict):
        candidates.append(risk_block.get("final_score", None))

    for raw in candidates:
        if raw in (None, ""):
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return 0.0


def _looks_benign_admin_context(event) -> bool:
    if event is None:
        return False
    action = (getattr(event, "action", "") or "").lower()
    process = (getattr(event, "process", "") or "").lower().split("[")[0]
    text = _event_text(event)

    if action in {"pkg_install", "pkg_update", "pkg_upgrade", "service_heartbeat"}:
        return True
    if process in TRUSTED_PACKAGE_PROCESSES or process in CONFIG_MGMT_PROCESSES:
        return True
    return any(token in text for token in ADMIN_CONTEXT_TOKENS)


def _is_routine_file_access(event) -> bool:
    fields = getattr(event, "fields", {}) or {}
    path = str(
        fields.get("path")
        or getattr(event, "path", "")
        or fields.get("file_path")
        or ""
    ).lower()
    return bool(path) and path.startswith(ROUTINE_FILE_PREFIXES)


def _infer_explicit_normal_category(event, process: str = "") -> Optional[str]:
    action = (getattr(event, "action", "") or "").lower()
    outcome = (getattr(event, "outcome", "") or "").lower()
    category = (getattr(event, "category", "") or "").lower()
    message = (getattr(event, "message", "") or "").lower()
    fields = getattr(event, "fields", {}) or {}

    if outcome == "failure":
        return None
    if fields.get("alert_flag") or fields.get("lotl") or fields.get("first_seen"):
        return None
    if fields.get("suspicious") or fields.get("public_outbound") or fields.get("unknown_process"):
        return None
    if any(token in message for token in (
        "suspicious", "unknown process", "public outbound", "reverse shell",
        "webshell", "privilege escalation", "lateral movement",
    )):
        return None

    if action == "ssh_login" and outcome == "success":
        return "auth_normal"
    if action == "db_login" and outcome == "success":
        return "expected_db_activity"
    if action in ("user_logout", "session_close") and outcome in ("success", ""):
        return "normal_logout"
    if action in ("pkg_install", "pkg_update", "pkg_upgrade") and process in TRUSTED_PACKAGE_PROCESSES:
        return "package_management"
    if action == "dns_query" and outcome in ("success", ""):
        return "normal_network"
    if action == "file_read" and outcome == "success" and _is_routine_file_access(event):
        return "routine_file_access"
    if action == "service_heartbeat" or "systemd" in process:
        return "system_service"
    if ("selinux" in action or category == "selinux") and outcome in ("success", "allowed", "normal", ""):
        return "selinux_routine"
    return None


def _labelability_snapshot_for_event(event, *, distro_family: str = "", require_rule_hit: bool = False) -> Tuple[bool, str, Dict[str, str]]:
    reasons: List[str] = []
    source = (getattr(event, "source", "") or "").strip().lower() if event is not None else ""
    host = (getattr(event, "host", "") or "").strip() if event is not None else ""
    category = (getattr(event, "category", "") or "").strip().lower() if event is not None else ""
    action = (getattr(event, "action", "") or "").strip().lower() if event is not None else ""
    outcome = (getattr(event, "outcome", "") or "").strip().lower() if event is not None else ""
    ts_value = float(getattr(event, "ts", 0.0) or 0.0) if event is not None else 0.0
    distro = (distro_family or "").strip().lower()
    if event is None:
        reasons.append("parse_invalid")
    if ts_value <= 0.0:
        reasons.append("missing_timestamp")
    if not host:
        reasons.append("missing_host")
    if source in {"", "unknown", "unknown_source"}:
        reasons.append("missing_source")
    if category in {"", "unknown", "unknown_category"}:
        reasons.append("unknown_category")
    if action in {"", "unknown"}:
        reasons.append("action_unknown")
    if outcome == "unknown":
        reasons.append("unknown_outcome")
    if distro in {"", "unknown", "unknown_distro"}:
        reasons.append("unknown_distro")
    if require_rule_hit and not category:
        reasons.append("parse_invalid")
    normalized = []
    seen = set()
    for reason in reasons:
        if reason and reason not in seen:
            seen.add(reason)
            normalized.append(reason)
    return len(normalized) == 0, (normalized[0] if normalized else "labelable"), {
        "labelability_status": "labelable" if not normalized else "not_labelable",
        "labelability_reason": normalized[0] if normalized else "labelable",
    }


def _map_attack_category(rule_id: str, category: str = "", event=None) -> str:
    rid = (rule_id or "").upper()
    action = (getattr(event, "action", "") or "").lower()

    if rid == "THR-023":
        return "dns_anomaly"
    if rid == "WEB-005":
        return "web_discovery"
    if rid in {"PKG-013", "PKG-014"}:
        return "package_repository_abuse"

    if action in ("selinux_disabled", "selinux_policy_change"):
        return "selinux_evasion"
    if action == "rpm_tampering":
        return "persistence"
    if action == "attack_tool_installed":
        return "tool_install"
    if action in ("firewalld_stopped", "security_tool_removed"):
        return "defense_evasion"

    if rid in ("RHEL-001", "RHEL-002"):
        return "selinux_evasion"
    if rid == "RHEL-003":
        return "defense_evasion"
    if rid == "RHEL-004":
        return "persistence"
    if rid == "RHEL-005":
        return "tool_install"

    if rid.startswith("PROC-CRED") or rid.startswith("AUDIT-CRED") or rid == "SEQ-054":
        return "credential_access"
    if rid.startswith("PROC-EXFIL") or rid == "SEQ-045":
        return "exfiltration"
    if rid.startswith("PROC-CONT") or rid in {"SEQ-053", "SEQ-059"}:
        return "container_abuse"
    if rid.startswith("PROC-C2") or rid in {"SEQ-061", "SEQ-062"}:
        return "command_and_control"
    if rid.startswith("PROC-DL") or rid in {"SEQ-063", "SEQ-064"}:
        return "downloader_stager"
    if rid.startswith("PROC-IMP") or rid in {"SEQ-065", "SEQ-066"}:
        return "impact"
    if rid in {"ATK-LM-003", "ATK-LM-004", "SEQ-060"}:
        return "lateral_movement"
    if rid in {"SEQ-049", "SEQ-050", "SEQ-057"}:
        return "defense_evasion"
    if rid in {"SEQ-051", "SEQ-058"}:
        return "tool_install"
    if rid in {"PERS-018", "SEQ-055", "SEQ-068"}:
        return "account_abuse"
    if rid in {"PERS-019", "SEQ-069"}:
        return "service_hijack"
    if rid in {"WEB-017", "SEQ-052", "SEQ-056"}:
        return "webshell"
    if rid in {"SEQ-046", "SEQ-067"}:
        return "privilege_esc"

    if "LOL"     in rid: return "lolbin"
    if "AUTH"    in rid or "SSH" in rid: return "brute_force"
    if "PERSIST" in rid: return "persistence"
    if "LATERAL" in rid: return "lateral_movement"
    if "PRIVESC" in rid or "SUDO" in rid: return "privilege_esc"
    if "FIRST"   in rid: return "first_seen"
    if "SLOW"    in rid: return "slow_low"
    if "WEB"     in rid or "SHELL" in rid: return "webshell"
    if "JRN"     in rid or "SERVICE" in rid: return "journald"
    if "SELINUX" in rid: return "selinux_evasion"
    if "ZYP"     in rid or "ZYPPER" in rid: return "zypper_tamper"
    if "CHAIN"   in rid: return "lateral_movement"
    return category or "unknown_attack"


def _bootstrap_rule_unmapped_metadata(rule_id: str, category: str = "") -> Dict[str, object]:
    rid = (rule_id or "").upper()
    prefix = rid.split("-", 1)[0] if "-" in rid else rid
    source_trust = "rule_low"
    if prefix == "THR":
        source_trust = "rule_medium"
    elif prefix == "SEQ":
        source_trust = "sequence_high"
    return _with_labelability_metadata({
        "event_class": "unknown_unlabeled",
        "behavior_label": "unknown_unlabeled",
        "ml_family": UNMAPPED_NONLEARNABLE_FAMILY,
        "ml_label": "unknown_unlabeled",
        "label_family": UNMAPPED_NONLEARNABLE_FAMILY,
        "attack_family": "",
        "technique_label": "",
        "source_trust": "parse_invalid",
        "model_usage_scope": "not_learnable",
        "learnable": False,
        "label_lifecycle_status": "candidate",
        "label_reason": "bootstrap_rule_unmapped",
        "poisoning_guard_passed": False,
        "evidence_fields": {"rule_id": rid or "", "rule_category": category or ""},
    }, status="not_labelable", reason="parse_invalid")


_BOOTSTRAP_RULE_DENYLIST = {
    "ATK-PE-001",
    "ATK-LM-001",
    "AUTH-014",
    "DISC-002",
    "FIRST-002",
    "NET-001",
}


def _bootstrap_rule_metadata(rule_id: str, label: str,
                             category: str = "", event=None) -> Dict[str, object]:
    if (label or "").lower() != "attack":
        return {}

    rid = (rule_id or "").upper()
    if not rid:
        return {}
    if rid in _BOOTSTRAP_RULE_DENYLIST:
        return _bootstrap_rule_unmapped_metadata(rid, category)

    mapping = resolve_rule_to_ml_mapping(rid)
    if not mapping.matched:
        return _bootstrap_rule_unmapped_metadata(rid, category)

    source_trust = mapping.source_trust or "rule_high"
    model_usage_scope = "calibration_only"
    learnable = True
    lifecycle = "candidate"

    mapped = _with_labelability_metadata({
        "event_class": mapping.label_class or "attack",
        "behavior_label": mapping.ml_label or "",
        "ml_family": mapping.ml_family or "",
        "ml_label": mapping.ml_label or "",
        "label_family": mapping.ml_family or "",
        "attack_family": "",
        "technique_label": "",
        "source_trust": source_trust,
        "model_usage_scope": model_usage_scope,
        "learnable": learnable,
        "label_lifecycle_status": lifecycle,
        "label_reason": mapping.mapping_reason or "",
        "poisoning_guard_passed": True,
        "evidence_fields": {"rule_id": rid, "rule_category": category or ""},
    }, status="labelable", reason="rule_hit")

    def _done(behavior_label: str, attack_family: str, technique_label: str, label_reason: str) -> Dict[str, object]:
        mapped["event_class"] = "attack"
        mapped["behavior_label"] = behavior_label
        mapped["ml_label"] = behavior_label
        mapped["attack_family"] = attack_family
        mapped["technique_label"] = technique_label
        mapped["label_reason"] = label_reason
        return mapped

    def _done_preserve_event_class(
        behavior_label: str,
        attack_family: str,
        technique_label: str,
        label_reason: str,
    ) -> Dict[str, object]:
        mapped["behavior_label"] = behavior_label
        mapped["ml_label"] = behavior_label
        mapped["attack_family"] = attack_family
        mapped["technique_label"] = technique_label
        mapped["label_reason"] = label_reason
        return mapped

    auth_exact = {
        "AUTH-001": ("root_ssh_login", "initial_access", "valid_accounts_root_ssh"),
        "AUTH-002": ("ssh_auth_failure", "credential_access", "ssh_bruteforce"),
        "AUTH-003": ("ssh_invalid_user_enumeration", "credential_access", "ssh_invalid_user_enum"),
        "AUTH-004": ("sudo_root_access", "privilege_escalation", "sudo_root_access"),
        "AUTH-005": ("su_root_access", "privilege_escalation", "su_root_access"),
        "AUTH-006": ("local_user_creation", "persistence", "create_local_account"),
        "AUTH-009": ("sudo_auth_failure", "privilege_escalation", "sudo_auth_failure"),
        "AUTH-010": ("account_lockout_after_auth_failures", "credential_access", "account_lockout"),
        "AUTH-011": ("openvpn_auth_failure", "credential_access", "vpn_auth_failure"),
        "AUTH-012": ("sssd_auth_failure", "credential_access", "identity_auth_failure"),
        "AUTH-012A": ("winbind_auth_failure", "credential_access", "identity_auth_failure"),
        "AUTH-012B": ("winbind_account_lockout", "credential_access", "account_lockout"),
        "AUTH-012D": ("strongswan_auth_failure", "credential_access", "vpn_auth_failure"),
        "AUTH-012E": ("wireguard_handshake_failure", "credential_access", "vpn_auth_failure"),
        "AUTH-013": ("smtp_auth_failure", "credential_access", "smtp_auth_failure"),
    }
    if rid in auth_exact:
        behavior_label, attack_family, technique_label = auth_exact[rid]
        return _done(behavior_label, attack_family, technique_label, "bootstrap_rule_match_auth")

    if rid == "THR-023":
        return _done_preserve_event_class(
            "high_entropy_dns_burst",
            "command_and_control",
            "dns_burst_anomaly",
            "bootstrap_rule_match_dns_burst",
        )

    web_exact = {
        "NET-WEB-001": ("sql_injection_attempt", "initial_access", "sql_injection"),
        "NET-WEB-002": ("path_traversal_attempt", "discovery", "path_traversal"),
        "WEB-004": ("web_shell_upload", "execution", "web_shell_upload"),
        "WEB-014": ("xss_attempt", "initial_access", "xss_payload"),
        "WEB-015": ("xxe_attempt", "initial_access", "xxe_payload"),
        "WEB-018": ("dvwa_exploitation_attempt", "initial_access", "dvwa_exploit"),
    }
    if rid in web_exact:
        behavior_label, attack_family, technique_label = web_exact[rid]
        return _done(behavior_label, attack_family, technique_label, "bootstrap_rule_match_web")
    if rid == "WEB-005":
        return _done_preserve_event_class(
            "web_discovery_probe",
            "discovery",
            "web_scanner_probe",
            "bootstrap_rule_match_web_discovery",
        )

    if rid == "DB-001":
        return _done("db_auth_failure", "credential_access", "db_auth_failure", "bootstrap_rule_match_db")

    if rid in {"PKG-013", "PKG-014"}:
        return _done_preserve_event_class(
            "package_repository_abuse",
            "defense_evasion",
            "package_repo_tamper",
            "bootstrap_rule_match_package_repo",
        )

    proc_exact = {
        "PROC-001": ("dangerous_sudo_execution", "privilege_escalation", "dangerous_sudo_exec"),
        "PROC-003": ("service_shell_spawn", "execution", "service_shell_spawn"),
        "PROC-004": ("reverse_shell_execution", "command_and_control", "reverse_shell_exec"),
        "PROC-005": ("temp_interpreter_execution", "execution", "temp_script_exec"),
        "PROC-006": ("base64_obfuscated_execution", "defense_evasion", "obfuscated_exec"),
        "PROC-007": ("ptrace_process_injection", "defense_evasion", "ptrace_injection"),
        "PROC-008": ("named_pipe_shell_communication", "command_and_control", "named_pipe_shell"),
        "PROC-009": ("backdoor_port_listener", "command_and_control", "backdoor_listener"),
        "PROC-010": ("unusual_suid_execution", "privilege_escalation", "suid_exec"),
    }
    if rid in proc_exact:
        behavior_label, attack_family, technique_label = proc_exact[rid]
        return _done(behavior_label, attack_family, technique_label, "bootstrap_rule_match_proc")

    proc_prefixes = (
        ("PROC-CRED", "credential_material_access", "credential_access", "credential_material_access"),
        ("PROC-EXFIL", "outbound_exfiltration_activity", "exfiltration", "archive_or_transfer_exfil"),
        ("PROC-CONT", "container_abuse_activity", "container_abuse", "container_exec_abuse"),
        ("PROC-C2", "ssh_tunnel_command_and_control", "command_and_control", "ssh_tunnel_c2"),
        ("PROC-DL", "payload_download_activity", "downloader_stager", "payload_download"),
        ("PROC-IMP", "destructive_impact_activity", "impact", "destructive_impact"),
    )
    for prefix, behavior_label, attack_family, technique_label in proc_prefixes:
        if rid.startswith(prefix):
            return _done(behavior_label, attack_family, technique_label, "bootstrap_rule_match_proc_family")

    mapped["attack_family"] = _map_attack_category(rid, category, event)
    mapped["technique_label"] = mapped["behavior_label"]
    return mapped


def _bootstrap_normal_unknown_metadata(category: str = "", event=None,
                                       reason: str = "bootstrap_normal_unknown") -> Dict[str, object]:
    action = (getattr(event, "action", "") or "").lower() if event is not None else ""
    source = (getattr(event, "source", "") or "").lower() if event is not None else ""
    process = (getattr(event, "process", "") or "").lower() if event is not None else ""
    return _with_labelability_metadata({
        "event_class": "unknown_unlabeled",
        "behavior_label": "unknown_unlabeled",
        "ml_family": UNMAPPED_NONLEARNABLE_FAMILY,
        "ml_label": "unknown_unlabeled",
        "label_family": UNMAPPED_NONLEARNABLE_FAMILY,
        "attack_family": "",
        "technique_label": "",
        "source_trust": "parse_invalid",
        "model_usage_scope": "not_learnable",
        "learnable": False,
        "label_lifecycle_status": "candidate",
        "label_reason": reason,
        "poisoning_guard_passed": False,
        "evidence_fields": {
            "normal_category": category or "",
            "action": action,
            "source": source,
            "process": process,
        },
    }, status="not_labelable", reason="parse_invalid")


def _bootstrap_normal_metadata(event, category: str,
                               process_safe: bool = True) -> Dict[str, object]:
    action = (getattr(event, "action", "") or "").lower()
    source = (getattr(event, "source", "") or "").lower()
    process = (getattr(event, "process", "") or "").lower()

    def _mk(ml_family: str, ml_label: str, behavior_label: str, technique_label: str,
            source_trust: str, model_usage_scope: str,
            learnable: bool, reason: str) -> Dict[str, object]:
        return _with_labelability_metadata({
            "event_class": "benign",
            "behavior_label": behavior_label,
            "ml_family": ml_family,
            "ml_label": ml_label,
            "label_family": ml_family,
            "attack_family": "",
            "technique_label": technique_label,
            "source_trust": source_trust,
            "model_usage_scope": model_usage_scope,
            "learnable": learnable,
            "label_lifecycle_status": "candidate",
            "label_reason": reason,
            "poisoning_guard_passed": True,
            "evidence_fields": {
                "normal_category": category or "",
                "action": action,
                "source": source,
                "process": process,
                "process_safe": bool(process_safe),
            },
        }, status="labelable", reason="known_benign_normal")

    if category == "auth_normal":
        return _mk(
            "ML-AUTH",
            "expected_auth_activity",
            "expected_auth_activity",
            "ssh_login_success",
            "observed_benign_high",
            "baseline_learning",
            True,
            "bootstrap_normal_expected_auth",
        )

    if category == "expected_db_activity":
        return _mk(
            "ML-DBAUTH",
            "expected_db_activity",
            "expected_db_activity",
            "db_login_success",
            "observed_benign_high",
            "baseline_learning",
            True,
            "bootstrap_normal_expected_db",
        )

    if category in {"system_service", "selinux_routine"}:
        return _mk(
            "ML-SERVICE",
            "service_normal",
            "routine_system_event",
            action or category,
            "observed_benign_high",
            "baseline_learning",
            True,
            "bootstrap_normal_routine_system",
        )

    if category == "normal_network":
        return _mk(
            "ML-NET",
            "normal_network",
            "normal_network",
            action or category,
            "observed_benign_high",
            "baseline_learning",
            True,
            "bootstrap_normal_network",
        )

    if category == "normal_logout":
        return _mk(
            "ML-AUTH",
            "expected_auth_activity",
            "expected_auth_activity",
            action or category,
            "observed_benign_high",
            "baseline_learning",
            True,
            "bootstrap_normal_logout",
        )

    if category in {"package_management", "routine_file_access"}:
        return _mk(
            "ML-HOST",
            "host_behavior_normal",
            "routine_system_event",
            action or category,
            "observed_benign_high",
            "baseline_learning",
            True,
            "bootstrap_normal_general_benign",
        )

    return _bootstrap_normal_unknown_metadata(category, event)


# ── Data Structures ───────────────────────────────────────────────────

class LabelRecord:
    __slots__ = ("score", "label", "category", "source", "confidence",
                 "ts", "weight", "entity_key", "ready_after", "distro",
                 "origin",
                 "event_class", "behavior_label", "attack_family",
                 "technique_label", "source_trust", "learnable",
                 "model_usage_scope", "label_lifecycle_status",
                 "poisoning_guard_passed", "label_reason",
                 "ml_family", "label_family", "no_action_contract",
                 "evidence_fields", "bootstrap_job_id",
                 "label_batch_id", "correlation_id")

    def __init__(self, score: float, label: str, category: str,
                 source: str, confidence: float = 1.0, ts: float = 0.0,
                 weight: float = 1.0, entity_key: str = "",
                 ready_after: float = 0.0, distro: str = "", origin: str = "",
                 event_class: str = "", behavior_label: str = "",
                 attack_family: str = "", technique_label: str = "",
                 source_trust: str = "", learnable=None,
                 model_usage_scope: str = "",
                 label_lifecycle_status: str = "",
                 poisoning_guard_passed=None, label_reason: str = "",
                 ml_family: str = "", label_family: str = "",
                 no_action_contract=None,
                 evidence_fields=None,
                 bootstrap_job_id: str = "", label_batch_id: str = "",
                 correlation_id: str = ""):
        self.score       = score
        self.label       = label
        self.category    = category
        self.source      = source
        self.confidence  = confidence
        self.ts          = ts or time.time()
        self.weight      = weight
        self.entity_key  = entity_key
        self.ready_after = ready_after
        self.distro      = distro
        self.origin = origin
        self.event_class = event_class
        self.behavior_label = behavior_label
        self.attack_family = attack_family
        self.technique_label = technique_label
        self.source_trust = source_trust
        self.learnable = learnable
        self.model_usage_scope = model_usage_scope
        self.label_lifecycle_status = label_lifecycle_status
        self.poisoning_guard_passed = poisoning_guard_passed
        self.label_reason = label_reason
        self.ml_family = ml_family
        self.label_family = label_family
        self.no_action_contract = no_action_contract
        self.evidence_fields = evidence_fields
        self.bootstrap_job_id = bootstrap_job_id
        self.label_batch_id = label_batch_id
        self.correlation_id = correlation_id


# ── 1. Synthetic Label Loader ─────────────────────────────────────────

class SyntheticLabelLoader:
    def __init__(self, labels_dir: str = "data/labels", distro_family: str = "debian"):
        self._dir       = Path(labels_dir) / distro_family
        self._distro    = distro_family
        self._threshold = DISTRO_THRESHOLDS.get(distro_family, 50)

    def load(self, user_map: Dict[str, str] = None) -> List[LabelRecord]:
        if not self._dir.exists():
            logger.warning(f"[LabelEngine] Etiket dizini yok: {self._dir}")
            return []
        records  = []
        user_map = user_map or {}
        for jsonl in sorted(self._dir.rglob("*.jsonl")):
            try:
                for line in jsonl.open():
                    line = line.strip()
                    if not line:
                        continue
                    raw  = json.loads(line)
                    user = raw.get("user", "")
                    if user_map:
                        raw["user"] = user_map.get(user, user)
                    label = raw.get("label", "normal")
                    records.append(LabelRecord(
                        score       = float(raw.get("score", 50.0)),
                        label       = label,
                        category    = raw.get("attack_type") or raw.get("normal_type") or "unknown",
                        source      = SOURCE_SYNTHETIC,
                        confidence  = 1.0,
                        ts          = raw.get("ts", time.time()),
                        weight      = self._synthetic_label_weight(label),
                        entity_key  = raw.get("user", ""),
                        ready_after = 0.0,
                    ))
            except Exception as e:
                logger.warning(f"[LabelEngine] {jsonl} yüklenemedi: {e}")
        logger.info(f"[LabelEngine:Synthetic] {len(records)} etiket yüklendi "
                    f"({self._distro}, base attack={SYNTHETIC_ATTACK_BASE_WEIGHT:.2f}, "
                    f"normal={SYNTHETIC_NORMAL_BASE_WEIGHT:.2f})")
        return records

    def _synthetic_label_weight(self, label: str) -> float:
        return SYNTHETIC_ATTACK_BASE_WEIGHT if label == "attack" else SYNTHETIC_NORMAL_BASE_WEIGHT

    @property
    def threshold(self) -> int:
        return self._threshold


# ── 2. Bootstrap Log Scanner ──────────────────────────────────────────

class BootstrapLogScanner:
    """Runs once at installation time. source='bootstrap', weight=0.65"""

    _TRADITIONAL_SYSLOG_TS = re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+")

    def __init__(self, distro_family: str = "debian",
                 max_age_days: int = HISTORIC_MAX_AGE_DAYS,
                 max_file_mb:  int = HISTORIC_MAX_FILE_MB,
                 max_total_mb: int = HISTORIC_MAX_TOTAL_MB,
                 source_entries: Optional[List[Dict[str, str]]] = None):
        self._distro      = distro_family
        self._max_age     = max_age_days * 86400
        self._max_file_mb = max_file_mb
        self._max_total   = max_total_mb * 1024 * 1024
        self._threshold   = DISTRO_THRESHOLDS.get(distro_family, 50)
        self._attack_counts: Dict[str, int] = defaultdict(int)
        self._normal_counts: Dict[str, int] = defaultdict(int)
        self._total_scanned_bytes = 0
        self._done = False
        self._source_entries = [dict(item or {}) for item in list(source_entries or [])]

    def _configured_log_paths(self) -> List[Path]:
        candidates = {
            "debian": ["/var/log/auth.log", "/var/log/syslog",
                       "/var/log/audit/audit.log", "/var/log/dpkg.log",
                       "/var/log/apt/history.log"],
            "rhel":   ["/var/log/secure", "/var/log/messages",
                       "/var/log/audit/audit.log", "/var/log/dnf.log"],
            "suse":   ["/var/log/auth.log", "/var/log/messages",
                       "/var/log/audit/audit.log", "/var/log/zypper.log"],
        }
        paths = candidates.get(self._distro, candidates["debian"])
        return [Path(p) for p in paths]

    def _configured_source_entries(self) -> List[Dict[str, str]]:
        if self._source_entries:
            entries = []
            for item in self._source_entries:
                path_text = str(item.get("path", "") or "").strip()
                source = str(item.get("source", "") or "").strip()
                if not path_text or not source:
                    continue
                entries.append({"source": source, "path": path_text})
            if entries:
                return entries
        return [{"source": self._source_for_log_file(path), "path": str(path)} for path in self._configured_log_paths()]

    def _all_full(self) -> bool:
        active_attack_categories = DISTRO_ATTACK_CATEGORIES.get(self._distro, ATTACK_CATEGORIES)
        for cat in active_attack_categories:
            if self._attack_counts[cat] < self._threshold:
                return False
        for cat in NORMAL_CATEGORIES:
            if self._normal_counts[cat] < self._threshold:
                return False
        return True

    def _iter_expanded_source_files(self) -> List[Tuple[Path, str]]:
        files: List[Tuple[Path, str]] = []
        seen: set[tuple[str, str]] = set()
        for entry in self._configured_source_entries():
            source = str(entry.get("source", "") or "").strip() or "syslog"
            base_path = Path(str(entry.get("path", "") or "").strip())
            expanded = self._expand_log_path(base_path)
            if not expanded:
                expanded = [base_path]
            for item in expanded:
                key = (str(item), source)
                if key in seen:
                    continue
                seen.add(key)
                files.append((item, source))
        return files

    def _log_files(self) -> List[Path]:
        return [path for path, _source in self._iter_expanded_source_files() if path.exists()]

    @staticmethod
    def _expand_log_path(path: Path) -> List[Path]:
        if path.is_file():
            return [path]
        if not path.is_dir():
            return []
        expanded: List[Path] = []
        seen: set[str] = set()
        patterns = ("*.log", "*_log", "messages*", "secure*", "history*", "postgresql*", "*.csv")
        for pattern in patterns:
            for candidate in sorted(path.glob(pattern)):
                if candidate.is_file():
                    text = str(candidate)
                    if text not in seen:
                        seen.add(text)
                        expanded.append(candidate)
        for candidate in sorted(path.iterdir()):
            if candidate.is_file():
                text = str(candidate)
                if text not in seen:
                    seen.add(text)
                    expanded.append(candidate)
        return expanded

    def _source_for_log_file(self, log_file: Path) -> str:
        path = str(log_file)
        name = log_file.name.lower()
        if name == "auth.log":
            return "auth_log"
        if name == "secure":
            return "auth_log"
        if name == "messages":
            return "syslog"
        if name == "audit.log":
            return "auditd"
        if name in ("ufw.log", "firewall", "firewalld"):
            return "ufw"
        if name in ("kern.log",):
            return "syslog"
        if name.startswith("postgresql") or "pgsql" in path.lower():
            return "postgresql"
        if "nginx" in path.lower():
            return "nginx"
        if "apache" in path.lower() or "httpd" in path.lower():
            return "apache2"
        if name == "dpkg.log":
            return "dpkg"
        if name in ("dnf.log", "dnf.rpm.log", "yum.log"):
            return "dnf"
        if "zypper" in name or name == "history":
            return "zypper" if self._distro == "suse" else "dpkg"
        return path

    @staticmethod
    def _line_hash(raw_line: str) -> str:
        return hashlib.sha256((raw_line or "").encode("utf-8", errors="replace")).hexdigest()[:16]

    def _timestamp_quality_note(self, raw_line: str, event) -> str:
        if not raw_line or event is None:
            return ""
        source = (getattr(event, "source", "") or "").lower()
        if source in {"auth_log", "syslog", "ufw", "apache2", "nginx", "postgresql"} and self._TRADITIONAL_SYSLOG_TS.match(raw_line):
            return "year_inferred_from_current_time"
        return ""

    def _manifest_timestamp_metadata(self, event, raw_line: str) -> Dict[str, object]:
        ts_note = self._timestamp_quality_note(raw_line, event)
        ts_value, timestamp_source = _safe_event_ts(event=event)
        if ts_value > 0.0 and timestamp_source == "event":
            confidence = "medium" if ts_note else "high"
            return {
                "ts": ts_value,
                "timestamp_warning": ts_note,
                "timestamp_source": "log_event",
                "timestamp_confidence": confidence,
            }
        return {
            "ts": ts_value,
            "timestamp_warning": ts_note or "timestamp_parse_failed",
            "timestamp_source": "scan_fallback",
            "timestamp_confidence": "low",
        }

    @staticmethod
    def _apply_manifest_timestamp_quality_gate(canonical: Dict[str, object], timestamp_confidence: str) -> Dict[str, object]:
        payload = dict(canonical or {})
        confidence = str(timestamp_confidence or "").strip().lower()
        if confidence in {"low", "missing"}:
            payload["learnable"] = False
            payload["model_usage_scope"] = "not_learnable"
            payload["poisoning_guard_passed"] = False
            evidence = dict(payload.get("evidence_fields", {}) or {})
            evidence["timestamp_quality_gate"] = "blocked_low_confidence"
            payload["evidence_fields"] = evidence
        return payload

    @staticmethod
    def _finalize_manifest_candidate(
        *,
        canonical: Dict[str, object],
        evidence: Dict[str, object],
        source: str,
        log_file: Path,
        raw_line: str,
        timestamp_meta: Dict[str, object],
    ) -> Tuple[Dict[str, object], Dict[str, object], str]:
        payload = BootstrapLogScanner._apply_manifest_timestamp_quality_gate(
            canonical,
            str(timestamp_meta.get("timestamp_confidence", "") or ""),
        )
        line_hash = BootstrapLogScanner._line_hash(raw_line)
        evidence_payload = dict(payload.get("evidence_fields", {}) or evidence or {})
        evidence_payload.update(
            {
                "origin": "bootstrap_historical",
                "log_path": str(log_file),
                "log_source": source,
                "line_hash": line_hash,
                "timestamp_source": str(timestamp_meta.get("timestamp_source", "") or ""),
                "timestamp_confidence": str(timestamp_meta.get("timestamp_confidence", "") or ""),
                "no_action_contract": True,
                "poisoning_guard_passed": bool(payload.get("poisoning_guard_passed", False)),
                "ml_family": payload.get("ml_family", "") or "",
                "label_family": payload.get("label_family", "") or payload.get("ml_family", "") or "",
            }
        )
        if timestamp_meta.get("timestamp_warning"):
            evidence_payload["timestamp_warning"] = str(timestamp_meta["timestamp_warning"])
        return payload, evidence_payload, line_hash

    def _attack_manifest_candidate(self, result, cat: str, event, source: str, log_file: Path, raw_line: str) -> Dict[str, object]:
        canonical = _bootstrap_rule_metadata(
            result.rule_id,
            "attack",
            cat,
            event,
        )
        timestamp_meta = self._manifest_timestamp_metadata(event, raw_line)
        evidence = dict(canonical.get("evidence_fields", None) or {})
        evidence.update(
            {
                "scan_mode": "bootstrap_auto_label_scan",
            }
        )
        canonical, evidence, line_hash = self._finalize_manifest_candidate(
            canonical=canonical,
            evidence=evidence,
            source=source,
            log_file=log_file,
            raw_line=raw_line,
            timestamp_meta=timestamp_meta,
        )
        return {
            "source": SOURCE_BOOTSTRAP,
            "observed_source": source,
            "label": "attack",
            "category": cat,
            "score": float(result.score),
            "confidence": 0.85,
            "weight": SOURCE_BASE_WEIGHTS[SOURCE_BOOTSTRAP],
            "entity_key": "",
            "distro": self._distro,
            "distro_family": self._distro,
            "ts": timestamp_meta["ts"],
            "host": getattr(event, "host", "") or "",
            "action": getattr(event, "action", "") or "",
            "outcome": getattr(event, "outcome", "") or "",
            "process": getattr(event, "process", "") or "",
            "username": getattr(event, "user", "") or "",
            "src_ip": getattr(event, "src_ip", "") or "",
            "dst_ip": getattr(event, "dst_ip", "") or "",
            "origin": "bootstrap_historical",
            "log_path": str(log_file),
            "log_source": source,
            "line_hash": line_hash,
            "rule_id": getattr(result, "rule_id", "") or "",
            "timestamp_warning": timestamp_meta["timestamp_warning"],
            "timestamp_source": timestamp_meta["timestamp_source"],
            "timestamp_confidence": timestamp_meta["timestamp_confidence"],
            "ready_after": 0.0,
            "event_class": canonical.get("event_class", "") or "",
            "ml_family": canonical.get("ml_family", "") or "",
            "ml_label": canonical.get("ml_label", "") or "",
            "label_family": canonical.get("label_family", "") or "",
            "behavior_label": canonical.get("behavior_label", "") or "",
            "attack_family": canonical.get("attack_family", "") or "",
            "technique_label": canonical.get("technique_label", "") or "",
            "source_trust": canonical.get("source_trust", "") or "",
            "learnable": canonical.get("learnable", None),
            "model_usage_scope": canonical.get("model_usage_scope", "") or "",
            "source_type": "rule_mapped_attack",
            "label_lifecycle_status": canonical.get("label_lifecycle_status", "") or "",
            "label_reason": canonical.get("label_reason", "") or "bootstrap_auto_label_scan_attack_rule_match",
            "evidence_fields": evidence,
            "no_action_contract": True,
            "poisoning_guard_passed": bool(canonical.get("poisoning_guard_passed", False)),
            "correlation_id": "",
        }

    def _normal_manifest_candidate(self, cat: str, event, source: str, log_file: Path, raw_line: str) -> Dict[str, object]:
        canonical = _bootstrap_normal_metadata(
            event,
            cat,
            process_safe=True,
        )
        timestamp_meta = self._manifest_timestamp_metadata(event, raw_line)
        evidence = dict(canonical.get("evidence_fields", None) or {})
        evidence.update(
            {
                "scan_mode": "bootstrap_auto_label_scan",
            }
        )
        canonical, evidence, line_hash = self._finalize_manifest_candidate(
            canonical=canonical,
            evidence=evidence,
            source=source,
            log_file=log_file,
            raw_line=raw_line,
            timestamp_meta=timestamp_meta,
        )
        return {
            "source": SOURCE_BOOTSTRAP,
            "observed_source": source,
            "label": "normal",
            "category": cat,
            "score": 0.0,
            "confidence": 0.75,
            "weight": SOURCE_BASE_WEIGHTS[SOURCE_BOOTSTRAP],
            "entity_key": "",
            "distro": self._distro,
            "distro_family": self._distro,
            "ts": timestamp_meta["ts"],
            "host": getattr(event, "host", "") or "",
            "action": getattr(event, "action", "") or "",
            "outcome": getattr(event, "outcome", "") or "",
            "process": getattr(event, "process", "") or "",
            "username": getattr(event, "user", "") or "",
            "src_ip": getattr(event, "src_ip", "") or "",
            "dst_ip": getattr(event, "dst_ip", "") or "",
            "origin": "bootstrap_historical",
            "log_path": str(log_file),
            "log_source": source,
            "line_hash": line_hash,
            "rule_id": "",
            "timestamp_warning": timestamp_meta["timestamp_warning"],
            "timestamp_source": timestamp_meta["timestamp_source"],
            "timestamp_confidence": timestamp_meta["timestamp_confidence"],
            "ready_after": 0.0,
            "event_class": canonical.get("event_class", "") or "",
            "ml_family": canonical.get("ml_family", "") or "",
            "ml_label": canonical.get("ml_label", "") or "",
            "label_family": canonical.get("label_family", "") or "",
            "behavior_label": canonical.get("behavior_label", "") or "",
            "attack_family": canonical.get("attack_family", "") or "",
            "technique_label": canonical.get("technique_label", "") or "",
            "source_trust": canonical.get("source_trust", "") or "",
            "learnable": canonical.get("learnable", None),
            "model_usage_scope": canonical.get("model_usage_scope", "") or "",
            "source_type": "clean_window_normal",
            "label_lifecycle_status": canonical.get("label_lifecycle_status", "") or "",
            "label_reason": canonical.get("label_reason", "") or "bootstrap_auto_label_scan_normal_historical_match",
            "evidence_fields": evidence,
            "no_action_contract": True,
            "poisoning_guard_passed": bool(canonical.get("poisoning_guard_passed", False)),
            "correlation_id": "",
        }

    @staticmethod
    def _candidate_identity(candidate: Dict[str, object]) -> Dict[str, object]:
        keys = (
            "source", "label", "category", "score", "confidence", "weight",
            "entity_key", "distro", "ts", "ready_after",
        )
        return {key: candidate.get(key, None) for key in keys}

    def _build_bootstrap_job_id(self, candidates: List[Dict[str, object]]) -> str:
        digest = hashlib.sha256()
        for candidate in candidates:
            payload = {
                "identity": self._candidate_identity(candidate),
                "event_class": candidate.get("event_class", ""),
                "behavior_label": candidate.get("behavior_label", ""),
                "attack_family": candidate.get("attack_family", ""),
                "technique_label": candidate.get("technique_label", ""),
                "source_trust": candidate.get("source_trust", ""),
                "learnable": candidate.get("learnable", None),
                "model_usage_scope": candidate.get("model_usage_scope", ""),
                "label_lifecycle_status": candidate.get("label_lifecycle_status", ""),
                "label_reason": candidate.get("label_reason", ""),
                "evidence_fields": candidate.get("evidence_fields", None),
            }
            digest.update(json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8"))
            digest.update(b"\n")
        suffix = digest.hexdigest()[:12] if candidates else "empty0000000"
        return f"bootstrap_scan_{self._distro}_{len(candidates)}_{suffix}"

    def scan(self, detection_engine, normalizer) -> List[LabelRecord]:
        if self._done:
            return []
        records = []
        cutoff  = time.time() - self._max_age
        total_b = 0
        for log_file in self._log_files():
            if self._all_full():
                logger.info("[LabelEngine:Bootstrap] Tüm kategoriler doldu, tarama durdu.")
                break
            if total_b > self._max_total:
                break
            file_size = log_file.stat().st_size
            if file_size > self._max_file_mb * 1024 * 1024:
                continue
            total_b += file_size
            source = self._source_for_log_file(log_file)
            try:
                with open(log_file, errors="replace") as f:
                    for line in f:
                        if self._all_full():
                            break
                        try:
                            event = normalizer.normalize(line.strip(), source)
                            if not event or (event.ts and event.ts < cutoff):
                                continue
                            if hasattr(detection_engine, "analyze"):
                                results = detection_engine.analyze(event)
                            else:
                                results = detection_engine.rule_engine.check(event)
                            if results:
                                cat = self._infer_attack_category(results[0].rule_id, event)
                                if self._attack_counts[cat] < self._threshold:
                                    canonical = _bootstrap_rule_metadata(
                                        results[0].rule_id,
                                        "attack",
                                        cat,
                                        event,
                                    )
                                    self._attack_counts[cat] += 1
                                    records.append(LabelRecord(
                                        score=results[0].score, label="attack",
                                        category=cat, source=SOURCE_BOOTSTRAP,
                                        confidence=0.85, ts=event.ts or time.time(),
                                        weight=SOURCE_BASE_WEIGHTS[SOURCE_BOOTSTRAP],
                                        ready_after=0.0,
                                        distro=self._distro,
                                        origin="bootstrap_historical",
                                        event_class=canonical.get("event_class", "") or "",
                                        behavior_label=canonical.get("behavior_label", "") or "",
                                        attack_family=canonical.get("attack_family", "") or "",
                                        technique_label=canonical.get("technique_label", "") or "",
                                        source_trust=canonical.get("source_trust", "") or "",
                                        learnable=canonical.get("learnable", None),
                                        model_usage_scope=canonical.get("model_usage_scope", "") or "",
                                        label_lifecycle_status=canonical.get("label_lifecycle_status", "") or "",
                                        poisoning_guard_passed=canonical.get("poisoning_guard_passed", None),
                                        label_reason=canonical.get("label_reason", "") or "",
                                        evidence_fields=canonical.get("evidence_fields", None),
                                    ))
                            else:
                                cat = self._infer_normal_category(event)
                                if cat and self._normal_counts[cat] < self._threshold:
                                    canonical = _bootstrap_normal_metadata(
                                        event,
                                        cat,
                                        process_safe=True,
                                    )
                                    self._normal_counts[cat] += 1
                                    records.append(LabelRecord(
                                        score=0.0, label="normal",
                                        category=cat, source=SOURCE_BOOTSTRAP,
                                        confidence=0.75, ts=event.ts or time.time(),
                                        weight=SOURCE_BASE_WEIGHTS[SOURCE_BOOTSTRAP],
                                        ready_after=0.0,
                                        distro=self._distro,
                                        origin="bootstrap_historical",
                                        event_class=canonical.get("event_class", "") or "",
                                        behavior_label=canonical.get("behavior_label", "") or "",
                                        attack_family=canonical.get("attack_family", "") or "",
                                        technique_label=canonical.get("technique_label", "") or "",
                                        source_trust=canonical.get("source_trust", "") or "",
                                        learnable=canonical.get("learnable", None),
                                        model_usage_scope=canonical.get("model_usage_scope", "") or "",
                                        label_lifecycle_status=canonical.get("label_lifecycle_status", "") or "",
                                        poisoning_guard_passed=canonical.get("poisoning_guard_passed", None),
                                        label_reason=canonical.get("label_reason", "") or "",
                                        evidence_fields=canonical.get("evidence_fields", None),
                                    ))
                        except Exception:
                            continue
            except Exception as e:
                logger.debug(f"[LabelEngine:Bootstrap] {log_file}: {e}")
        self._total_scanned_bytes = total_b
        self._done = True
        logger.info(f"[LabelEngine:Bootstrap] {sum(self._attack_counts.values())} saldırı, "
                    f"{sum(self._normal_counts.values())} normal (weight=0.65)")
        return records

    def dry_run_report(self, detection_engine, normalizer) -> Dict[str, object]:
        cutoff = time.time() - self._max_age
        threshold = self._threshold
        configured_entries = self._configured_source_entries()
        active_attack_categories = DISTRO_ATTACK_CATEGORIES.get(self._distro, ATTACK_CATEGORIES)
        normal_categories = list(NORMAL_CATEGORIES)
        file_reports = []
        skipped = Counter()
        attack_counts: Dict[str, int] = defaultdict(int)
        normal_counts: Dict[str, int] = defaultdict(int)
        scanned_files = 0
        scanned_bytes = 0
        parsed_events = 0
        candidate_attack = 0
        candidate_normal = 0
        candidates: List[Dict[str, object]] = []
        source_counts = Counter()
        warnings: List[str] = []

        for entry in configured_entries:
            base_path = Path(str(entry.get("path", "") or "").strip())
            entry_source = str(entry.get("source", "") or "").strip() or self._source_for_log_file(base_path)
            expanded_paths = self._expand_log_path(base_path) if base_path.exists() else []
            if not expanded_paths:
                expanded_paths = [base_path]
            for log_file in expanded_paths:
                exists = log_file.exists()
                readable = exists and os.access(log_file, os.R_OK)
                size_bytes = log_file.stat().st_size if exists and log_file.is_file() else None
                source = entry_source if entry_source else (self._source_for_log_file(log_file) if exists else self._source_for_log_file(Path(str(log_file))))
                file_reports.append(
                    {
                        "path": str(log_file),
                        "source": source,
                        "exists": exists,
                        "readable": readable,
                        "size_bytes": size_bytes,
                    }
                )

                if not exists:
                    skipped["file_missing"] += 1
                    warnings.append(f"File not found: {log_file}")
                    continue
                if not readable:
                    skipped["file_unreadable"] += 1
                    warnings.append(f"Permission denied: {log_file}")
                    continue
                if log_file.is_dir():
                    skipped["path_is_directory"] += 1
                    warnings.append(f"Directory not expanded to readable files: {log_file}")
                    continue
                if size_bytes is not None and size_bytes > self._max_file_mb * 1024 * 1024:
                    skipped["file_too_large"] += 1
                    continue
                if scanned_bytes + (size_bytes or 0) > self._max_total:
                    skipped["max_total_mb_exceeded"] += 1
                    continue

                scanned_files += 1
                scanned_bytes += size_bytes or 0

                try:
                    with open(log_file, errors="replace") as fh:
                        for line in fh:
                            if all(attack_counts[cat] >= threshold for cat in active_attack_categories) and all(
                                normal_counts[cat] >= threshold for cat in normal_categories
                            ):
                                skipped["all_category_quotas_full"] += 1
                                break
                            try:
                                stripped = line.strip()
                                event = normalizer.normalize(stripped, source)
                            except Exception:
                                skipped["normalize_exception"] += 1
                                continue
                            if not event:
                                skipped["normalize_none"] += 1
                                continue
                            parsed_events += 1
                            source_counts[source] += 1
                            if event.ts and event.ts < cutoff:
                                skipped["older_than_max_age"] += 1
                                continue
                            try:
                                if hasattr(detection_engine, "analyze"):
                                    results = detection_engine.analyze(event)
                                else:
                                    results = detection_engine.rule_engine.check(event)
                            except Exception:
                                skipped["rule_check_exception"] += 1
                                continue
                            if results:
                                cat = self._infer_attack_category(results[0].rule_id, event)
                                if attack_counts[cat] >= threshold:
                                    skipped["attack_category_quota_full"] += 1
                                    continue
                                attack_counts[cat] += 1
                                candidate_attack += 1
                                candidates.append(
                                    self._attack_manifest_candidate(results[0], cat, event, source, log_file, stripped)
                                )
                                continue

                            cat = self._infer_normal_category(event)
                            if not cat:
                                skipped["normal_not_classified"] += 1
                                continue
                            if normal_counts[cat] >= threshold:
                                skipped["normal_category_quota_full"] += 1
                                continue
                            normal_counts[cat] += 1
                            candidate_normal += 1
                            candidates.append(
                                self._normal_manifest_candidate(cat, event, source, log_file, stripped)
                            )
                except Exception:
                    skipped["file_open_exception"] += 1

        bootstrap_job_id = self._build_bootstrap_job_id(candidates)
        duplicate_counts = Counter(
            str(candidate.get("line_hash", "") or "")
            for candidate in candidates
            if str(candidate.get("line_hash", "") or "").strip()
        )
        for candidate in candidates:
            candidate["bootstrap_job_id"] = bootstrap_job_id
            duplicate_key = str(candidate.get("line_hash", "") or "")
            duplicate_count = int(duplicate_counts.get(duplicate_key, 1) or 1)
            dedup_status = "duplicate_line_hash_observed" if duplicate_count > 1 else "unique"
            candidate["duplicate_count"] = duplicate_count
            candidate["duplicate_key"] = duplicate_key
            candidate["dedup_status"] = dedup_status
            evidence = dict(candidate.get("evidence_fields", {}) or {})
            evidence["duplicate_count"] = duplicate_count
            evidence["duplicate_key"] = duplicate_key
            evidence["dedup_status"] = dedup_status
            candidate["evidence_fields"] = evidence
        return {
            "distro_family": self._distro,
            "bootstrap_job_id": bootstrap_job_id,
            "limits": {
                "max_age_days": int(self._max_age / 86400),
                "max_file_mb": self._max_file_mb,
                "max_total_mb": int(self._max_total / (1024 * 1024)),
                "category_quota": threshold,
                "attack_categories": active_attack_categories,
                "normal_categories": normal_categories,
            },
            "log_files": file_reports,
            "scanned_files": scanned_files,
            "parsed_events": parsed_events,
            "scanned_bytes": scanned_bytes,
            "candidate_attack": candidate_attack,
            "candidate_normal": candidate_normal,
            "duplicate_summary": {
                "candidate_count": len(candidates),
                "unique_line_hash_count": len(duplicate_counts),
                "duplicate_candidate_count": int(
                    sum(1 for candidate in candidates if int(candidate.get("duplicate_count", 1) or 1) > 1)
                ),
            },
            "source_counts": dict(sorted(source_counts.items())),
            "warnings": warnings,
            "skipped_reason": dict(sorted(skipped.items())),
            "attack_category_counts": dict(sorted(attack_counts.items())),
            "normal_category_counts": dict(sorted(normal_counts.items())),
            "candidates": candidates,
        }

    def _infer_attack_category(self, rule_id: str, event=None) -> str:
        return _map_attack_category(rule_id, event=event)

    def _infer_normal_category(self, event) -> Optional[str]:
        action  = (event.action  or "").lower()
        process = (event.process or "").lower()
        category = (event.category or "").lower()

        if action in {
            "first_seen", "lotl_exec", "attack_tool_installed", "security_tool_removed",
            "sudo", "su", "account_locked", "account_policy", "identity_login",
            "vpn_login", "smtp_reject", "firewall_block", "firewall_reject",
        }:
            return None
        if category in {"web", "web_attack", "persistence", "privilege_esc", "lateral_movement"}:
            return None
        return _infer_explicit_normal_category(event, process)

    @property
    def status(self) -> Dict:
        return {
            "done":          self._done,
            "attack_counts": dict(self._attack_counts),
            "normal_counts": dict(self._normal_counts),
            "total_bytes":   self._total_scanned_bytes,
        }


# ── 3. Otomatik Etiketleyici ──────────────────────────────────────────────────

class AutoLabeler:
    """
    Canlı sistem auto_labeled etiketleri. Dört döngü koruması aktif.
    """

    def __init__(self):
        self._records: List[LabelRecord] = []
        self._lock = threading.Lock()
        self._count = 0
        self._alarmed_entities: Dict[str, float] = {}
        self._entity_label_log: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self._safe_processes = {
            "cron", "crond", "rsyslog", "syslogd", "sshd", "ntpd",
            "systemd", "systemd-journald", "systemd-logind", "dbus-daemon",
            "NetworkManager", "networkd", "resolved", "udevd",
            "apt-get", "apt", "dpkg", "yum", "dnf", "zypper", "rpm",
            "unattended-upgrade", "update-notifier",
        }

    def mark_alarm(self, entity_key: str) -> None:
        if entity_key:
            self._alarmed_entities[entity_key] = time.time()

    def process_alert(self, alert: dict, event=None) -> Optional[LabelRecord]:
        rule_id     = (alert.get("rule_id", "") or "").strip().upper()
        category    = alert.get("category", "")
        ioc_match   = alert.get("ioc_match", False)
        chain_match = alert.get("chain_id", None)
        score       = _coerce_alert_score(alert)
        entity_key  = alert.get("entity", "")

        if ioc_match:            confidence = 0.95
        elif chain_match:        confidence = 0.88
        elif score >= 90:        confidence = 0.86
        elif score >= 80:        confidence = 0.82
        elif score >= 70:        confidence = 0.78
        elif score >= 60:        confidence = 0.74
        else:                    return None

        mapped_category = self._rule_to_category(rule_id, category, event)
        if (
            not ioc_match
            and not chain_match
            and mapped_category == "unknown_attack"
            and score < 90
        ):
            return None
        if (
            not ioc_match
            and not chain_match
            and score < 90
            and _looks_benign_admin_context(event)
            and rule_id not in _AUTO_LABEL_BENIGN_ADMIN_ALLOWLIST
        ):
            return None
        if entity_key and not self._entity_quota_ok(entity_key, "attack"):
            return None
        if not self._category_cap_ok("attack", mapped_category):
            return None

        canonical = _bootstrap_rule_metadata(rule_id, "attack", mapped_category, event)
        if (
            canonical.get("learnable") is False
            and canonical.get("event_class") == "unknown_unlabeled"
            and rule_id in _BOOTSTRAP_RULE_DENYLIST
        ):
            return None
        label_ts, timestamp_source = _safe_event_ts(event=event, alert=alert)
        now = time.time()
        evidence = dict(canonical.get("evidence_fields", None) or {})
        evidence.setdefault("origin", "organic_live")
        evidence.setdefault("ml_family", canonical.get("ml_family", "") or "")
        evidence.setdefault("label_family", canonical.get("label_family", "") or canonical.get("ml_family", "") or "")
        evidence.setdefault("no_action_contract", True)
        evidence["timestamp_source"] = timestamp_source
        evidence["timestamp_confidence"] = "high" if timestamp_source == "event" else "low"

        record = LabelRecord(
            score=score, label="attack",
            category=mapped_category,
            source=SOURCE_AUTO_LABELED, confidence=confidence,
            ts=label_ts, weight=confidence,
            entity_key=entity_key,
            ready_after=now + MIN_AUTO_LABEL_AGE,
            origin="organic_live",
            event_class=canonical.get("event_class", "") or "",
            behavior_label=canonical.get("behavior_label", "") or "",
            attack_family=canonical.get("attack_family", "") or "",
            technique_label=canonical.get("technique_label", "") or "",
            source_trust=canonical.get("source_trust", "") or "",
            learnable=canonical.get("learnable", None),
            model_usage_scope=canonical.get("model_usage_scope", "") or "",
            label_lifecycle_status=canonical.get("label_lifecycle_status", "") or "",
            poisoning_guard_passed=canonical.get("poisoning_guard_passed", None),
            label_reason=canonical.get("label_reason", "") or "",
            ml_family=canonical.get("ml_family", "") or "",
            label_family=canonical.get("label_family", "") or canonical.get("ml_family", "") or "",
            no_action_contract=True,
            evidence_fields=evidence,
            distro=str(getattr(event, "distro_family", getattr(event, "distro", "")) or ""),
        )
        with self._lock:
            self._records.append(record)
            self._count += 1
        if entity_key:
            self._entity_label_log[(entity_key, "attack")].append(time.time())
        return record

    def process_normal(self, event, delayed_learning_ok: bool = False) -> Optional[LabelRecord]:
        """
        Döngü koruması — dört şart:
          1. delayed_learning_ok=True
          2. Process güvenli listede
          3. Entity alarm işaretli değil
          4. Entity throttle geçilmemiş
        """
        if not delayed_learning_ok:
            return None

        process    = (event.process or "").lower().split("[")[0]
        entity_key = getattr(event, "user", "") or getattr(event, "src_ip", "")
        category   = self._infer_normal_category(event, process)

        if category is None:
            return None
        if event.outcome not in ("success", None, ""):
            return None
        if self._is_alarmed(entity_key):
            return None
        if entity_key and not self._entity_quota_ok(entity_key, "normal"):
            return None
        if not self._category_cap_ok("normal", category):
            return None

        canonical = _bootstrap_normal_metadata(
            event,
            category,
            process_safe=self._is_safe_normal_process(process),
        )
        label_ts, timestamp_source = _safe_event_ts(event=event)
        now = time.time()
        evidence = dict(canonical.get("evidence_fields", None) or {})
        evidence.setdefault("origin", "organic_live")
        evidence.setdefault("ml_family", canonical.get("ml_family", "") or "")
        evidence.setdefault("label_family", canonical.get("label_family", "") or canonical.get("ml_family", "") or "")
        evidence.setdefault("no_action_contract", True)
        evidence["timestamp_source"] = timestamp_source
        evidence["timestamp_confidence"] = "high" if timestamp_source == "event" else "low"

        record = LabelRecord(
            score=0.0, label="normal", category=category,
            source=SOURCE_AUTO_LABELED, confidence=0.78,
            ts=label_ts, weight=0.78,
            entity_key=entity_key,
            ready_after=now + MIN_AUTO_LABEL_AGE,
            origin="organic_live",
            event_class=canonical.get("event_class", "") or "",
            behavior_label=canonical.get("behavior_label", "") or "",
            attack_family=canonical.get("attack_family", "") or "",
            technique_label=canonical.get("technique_label", "") or "",
            source_trust=canonical.get("source_trust", "") or "",
            learnable=canonical.get("learnable", None),
            model_usage_scope=canonical.get("model_usage_scope", "") or "",
            label_lifecycle_status=canonical.get("label_lifecycle_status", "") or "",
            poisoning_guard_passed=canonical.get("poisoning_guard_passed", None),
            label_reason=canonical.get("label_reason", "") or "",
            ml_family=canonical.get("ml_family", "") or "",
            label_family=canonical.get("label_family", "") or canonical.get("ml_family", "") or "",
            no_action_contract=True,
            evidence_fields=evidence,
            distro=str(getattr(event, "distro_family", getattr(event, "distro", "")) or ""),
        )
        with self._lock:
            self._records.append(record)
            self._count += 1
        if entity_key:
            self._entity_label_log[(entity_key, "normal")].append(time.time())
        return record

    def _infer_normal_category(self, event, process: str) -> Optional[str]:
        return _infer_explicit_normal_category(event, process)

    def _is_safe_normal_process(self, process: str) -> bool:
        proc = (process or "").lower().split("[")[0]
        if not proc:
            return True
        if proc in {p.lower() for p in self._safe_processes}:
            return True
        if proc in TRUSTED_PACKAGE_PROCESSES:
            return True
        if proc in SAFE_NETWORK_PROCESSES:
            return True
        if proc in CONFIG_MGMT_PROCESSES:
            return True
        if proc.startswith("systemd"):
            return True
        if proc in {"postgres", "postgresql", "mysqld", "mysql", "mariadbd"}:
            return True
        return False

    def get_ready_records(self) -> List[LabelRecord]:
        now = time.time()
        with self._lock:
            return [r for r in self._records if r.ready_after <= now]

    def _is_alarmed(self, entity_key: str) -> bool:
        if not entity_key:
            return False
        ts = self._alarmed_entities.get(entity_key)
        return bool(ts and (time.time() - ts) < 86400)

    def _entity_quota_ok(self, entity_key: str, label_side: str) -> bool:
        if not entity_key:
            return True
        cutoff = time.time() - 86400
        log_key = (entity_key, label_side)
        recent = [t for t in self._entity_label_log.get(log_key, []) if t > cutoff]
        self._entity_label_log[log_key] = recent
        return len(recent) < MAX_AUTO_PER_ENTITY_24H

    def _category_cap_ok(self, label: str, category: str) -> bool:
        if not category:
            return True
        active = sum(
            1 for r in self._records
            if getattr(r, "source", None) == SOURCE_AUTO_LABELED
            and getattr(r, "label", None) == label
            and getattr(r, "category", None) == category
        )
        return active < AUTO_LABEL_CATEGORY_CAP

    def _rule_to_category(self, rule_id: str, category: str, event=None) -> str:
        return _map_attack_category(rule_id, category, event)

    @property
    def count(self) -> int:
        return self._count

    def count_by_label(self, label: str) -> int:
        return sum(1 for r in self._records if getattr(r, "label", None) == label)


# ── 4. Label Engine (Main Coordinator) ────────────────────────────────

class LabelEngine:
    """
    Tüm etiket kaynaklarını koordine eder.

    synthetic_weight : 0.50 → 0.0  lineer  (auto/synthetic oranı 0→2)
    bootstrap_weight : 0.65 → 0.0  lineer  (auto/bootstrap oranı 0→3)
    auto weight      : confidence  (0.72-0.95)
    """

    def __init__(self, distro_family: str = "debian",
                 labels_dir: str = "data/labels", db=None,
                 bootstrap_scan_mode: str = "auto"):
        self._distro    = distro_family
        self._db        = db
        self._threshold = DISTRO_THRESHOLDS.get(distro_family, 50)
        self._bootstrap_scan_mode = (bootstrap_scan_mode or "auto").strip().lower() or "auto"
        if self._bootstrap_scan_mode not in {"auto", "disabled"}:
            self._bootstrap_scan_mode = "auto"

        self._synthetic_loader  = SyntheticLabelLoader(labels_dir, distro_family)
        self._bootstrap_scanner = BootstrapLogScanner(distro_family)
        self._auto_labeler      = AutoLabeler()

        self._synthetic_records: List[LabelRecord] = []
        self._bootstrap_records: List[LabelRecord] = []
        self._operator_records: List[LabelRecord] = []
        self._synthetic_weight: float = SOURCE_BASE_WEIGHTS[SOURCE_SYNTHETIC]   # 0.50
        self._bootstrap_weight: float = SOURCE_BASE_WEIGHTS[SOURCE_BOOTSTRAP]   # 0.65
        self._synthetic_attack_weight: float = SOURCE_BASE_WEIGHTS[SOURCE_SYNTHETIC]
        self._synthetic_normal_weight: float = SOURCE_BASE_WEIGHTS[SOURCE_SYNTHETIC]
        self._bootstrap_attack_weight: float = SOURCE_BASE_WEIGHTS[SOURCE_BOOTSTRAP]
        self._bootstrap_normal_weight: float = SOURCE_BASE_WEIGHTS[SOURCE_BOOTSTRAP]

        # Per-event dedup: produce only one auto-label when multiple rules fire from the same event
        # key: "entity:int(ts)", value: ts
        self._per_event_seen: Dict[str, float] = {}

        self._user_map: Dict[str, str] = {}
        self._label_quota_contract = resolve_family_label_quotas()
        self._label_quota_counts: Counter = Counter()
        self._quota_blocked_counts: Counter = Counter()
        logger.info(f"[LabelEngine] Başlatıldı — {distro_family}, eşik={self._threshold}/kategori")

    @staticmethod
    def _is_calibration_eligible(record: LabelRecord) -> bool:
        if record is None:
            return False
        if getattr(record, "model_usage_scope", "") != "calibration_only":
            return False
        if getattr(record, "learnable", None) is not True:
            return False
        if getattr(record, "poisoning_guard_passed", None) is False:
            return False

        event_class = (getattr(record, "event_class", "") or "").strip().lower()
        behavior_label = (getattr(record, "behavior_label", "") or "").strip().lower()
        if event_class not in {"attack", "benign"}:
            return False
        if event_class == "unknown_unlabeled" or behavior_label == "unknown_unlabeled":
            return False

        source_trust = (getattr(record, "source_trust", "") or "").strip().lower()
        trusted = {
            "rule_high",
            "sequence_high",
            "observed_benign_high",
        }
        if source_trust not in trusted:
            return False

        return True

    @staticmethod
    def _record_to_payload(record) -> Dict[str, object]:
        if record is None:
            return {}
        if isinstance(record, dict):
            return dict(record)
        payload = {}
        for field in getattr(record, "__slots__", ()):
            payload[field] = getattr(record, field, None)
        return payload

    def _quota_bucket_for_payload(self, payload) -> Optional[Tuple[str, str, str]]:
        item = self._record_to_payload(payload)
        evidence = dict(item.get("evidence_fields", {}) or {}) if isinstance(item.get("evidence_fields", {}), dict) else {}
        distro_family = str(
            item.get("distro_family")
            or item.get("distro")
            or evidence.get("distro_family")
            or evidence.get("distro")
            or self._distro
            or ""
        ).strip().lower()
        if distro_family:
            item.setdefault("distro_family", distro_family)
            item.setdefault("distro", distro_family)
            evidence.setdefault("distro_family", distro_family)
            evidence.setdefault("distro", distro_family)
        item["evidence_fields"] = evidence
        return build_label_quota_bucket(item)

    def _prime_label_quota_counts(self, rows: List[Dict[str, object]]) -> None:
        self._label_quota_counts.clear()
        for row in list(rows or []):
            bucket = self._quota_bucket_for_payload(row)
            if bucket is not None:
                self._label_quota_counts[bucket] += 1

    def _quota_allows_record(self, record: LabelRecord) -> Tuple[bool, str]:
        bucket = self._quota_bucket_for_payload(record)
        if bucket is None:
            return True, ""
        family, distro, label_type = bucket
        limit = int(dict(self._label_quota_contract.get(family, {}) or {}).get(label_type, 0) or 0)
        used = int(self._label_quota_counts.get(bucket, 0) or 0)
        if limit > 0 and used >= limit:
            evidence = dict(getattr(record, "evidence_fields", {}) or {})
            evidence["quota_status"] = "quota_full"
            evidence["quota_bucket"] = f"{family}/{distro}/{label_type}"
            record.evidence_fields = evidence
            self._quota_blocked_counts[bucket] += 1
            logger.info(
                "[LabelEngine] label quota full; write skipped family=%s distro=%s type=%s used=%s limit=%s",
                family,
                distro,
                label_type,
                used,
                limit,
            )
            return False, "quota_full"
        return True, ""

    def _record_saved_for_quota(self, record: LabelRecord) -> None:
        bucket = self._quota_bucket_for_payload(record)
        if bucket is not None:
            self._label_quota_counts[bucket] += 1

    def _enrich_record_for_quota(self, record: Optional[LabelRecord]) -> Optional[LabelRecord]:
        if record is None:
            return None
        if not getattr(record, "distro", ""):
            record.distro = self._distro
        evidence = dict(getattr(record, "evidence_fields", {}) or {})
        if self._distro:
            evidence.setdefault("distro_family", self._distro)
            evidence.setdefault("distro", self._distro)
        if getattr(record, "behavior_label", ""):
            evidence.setdefault("behavior_label", getattr(record, "behavior_label", ""))
        if getattr(record, "model_usage_scope", ""):
            evidence.setdefault("model_usage_scope", getattr(record, "model_usage_scope", ""))
        if getattr(record, "event_class", ""):
            evidence.setdefault("event_class", getattr(record, "event_class", ""))
        if getattr(record, "origin", ""):
            evidence.setdefault("origin", getattr(record, "origin", ""))
        if getattr(record, "ml_family", ""):
            evidence.setdefault("ml_family", getattr(record, "ml_family", ""))
        if getattr(record, "label_family", ""):
            evidence.setdefault("label_family", getattr(record, "label_family", ""))
        if getattr(record, "no_action_contract", None) is not None:
            evidence.setdefault("no_action_contract", getattr(record, "no_action_contract", None))
        if getattr(record, "learnable", None) is not None:
            evidence.setdefault("learnable", getattr(record, "learnable", None))
        evidence.setdefault("labelability_status", "labelable")
        evidence.setdefault("labelability_reason", "labelable")
        if not getattr(record, "origin", "") and evidence.get("origin"):
            record.origin = evidence.get("origin", "")
        if not getattr(record, "ml_family", "") and evidence.get("ml_family"):
            record.ml_family = evidence.get("ml_family", "")
        if not getattr(record, "label_family", "") and evidence.get("label_family"):
            record.label_family = evidence.get("label_family", "")
        if getattr(record, "no_action_contract", None) is None and "no_action_contract" in evidence:
            record.no_action_contract = evidence.get("no_action_contract")
        record.evidence_fields = evidence
        return record

    def initialize(self, user_map: Dict[str, str] = None,
                   detection_engine=None, normalizer=None) -> None:
        self._user_map = user_map or self._detect_users()
        self._synthetic_records = self._synthetic_loader.load(self._user_map)
        logger.info(f"[LabelEngine] {len(self._synthetic_records)} synthetic etiket hazır")

        # Load bootstrap / auto_labeled records from the DB
        if self._db and hasattr(self._db, "load_labels"):
            try:
                rows = self._db.load_labels(distro=self._distro)
                for row in rows:
                    r = LabelRecord(
                        score      = float(row.get("score", 50.0)),
                        label      = row.get("label", "normal"),
                        category   = row.get("category", "unknown"),
                        source     = row.get("source", SOURCE_AUTO_LABELED),
                        confidence = float(row.get("confidence", 1.0)),
                        ts         = float(row.get("ts", time.time())),
                        weight     = float(row.get("weight", 1.0)),
                        entity_key = row.get("entity_key", ""),
                        ready_after= float(row.get("ready_after", 0.0)),
                        distro     = row.get("distro", ""),
                        origin = row.get("origin", "") or "",
                        event_class = row.get("event_class", "") or "",
                        behavior_label = row.get("behavior_label", "") or "",
                        attack_family = row.get("attack_family", "") or "",
                        technique_label = row.get("technique_label", "") or "",
                        source_trust = row.get("source_trust", "") or "",
                        learnable = row.get("learnable", None),
                        model_usage_scope = row.get("model_usage_scope", "") or "",
                        label_lifecycle_status = row.get("label_lifecycle_status", "") or "",
                        poisoning_guard_passed = row.get("poisoning_guard_passed", None),
                        label_reason = row.get("label_reason", "") or "",
                        ml_family = row.get("ml_family", "") or "",
                        label_family = row.get("label_family", "") or "",
                        no_action_contract = row.get("no_action_contract", None),
                        evidence_fields = row.get("evidence_fields", None),
                        bootstrap_job_id = row.get("bootstrap_job_id", "") or "",
                        label_batch_id = row.get("label_batch_id", "") or "",
                        correlation_id = row.get("correlation_id", "") or "",
                    )
                    if r.source == SOURCE_BOOTSTRAP:
                        self._bootstrap_records.append(r)
                    elif r.source == SOURCE_AUTO_LABELED:
                        self._auto_labeler._records.append(r)
                        self._auto_labeler._count += 1
                self._prime_label_quota_counts(rows)
                logger.info(f"[LabelEngine] DB'den {len(rows)} etiket yüklendi")
            except Exception as e:
                logger.warning(f"[LabelEngine] DB etiket yüklenemedi: {e}")

        # Scan bootstrap data only when the DB is empty
        if (
            self._bootstrap_scan_mode == "auto"
            and not self._bootstrap_records
            and detection_engine
            and normalizer
        ):
            self._bootstrap_records = self._bootstrap_scanner.scan(detection_engine, normalizer)
            logger.info(f"[LabelEngine] {len(self._bootstrap_records)} bootstrap etiketi hazır")
            if self._db and hasattr(self._db, "save_labels"):
                try:
                    self._db.save_labels(self._bootstrap_records)
                except Exception as e:
                    logger.debug(f"[LabelEngine] Bootstrap DB'ye yazılamadı: {e}")

    def _detect_users(self) -> Dict[str, str]:
        user_map = {
            "{{admin_user}}": "root",
            "{{service_user}}": "www-data",
            "{{regular_user}}": "user",
        }
        try:
            admins = []; services = []; regulars = []
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) < 7:
                        continue
                    uname, _, uid, _, _, home, shell = parts[:7]
                    uid = int(uid)
                    if uid == 0:
                        admins.append(uname)
                    elif uid < 1000 and shell in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin"):
                        services.append(uname)
                    elif uid >= 1000 and "/home/" in home:
                        regulars.append(uname)
            if admins:   user_map["{{admin_user}}"]   = admins[0]
            if services: user_map["{{service_user}}"] = services[0]
            if regulars: user_map["{{regular_user}}"] = regulars[0]
        except Exception as e:
            logger.debug(f"[LabelEngine] /etc/passwd okunamadı: {e}")
        return user_map

    # ── Event Flow ────────────────────────────────────────────────────────

    def on_alert(self, alert: dict, event=None) -> None:
        # Emit only one auto-label when multiple rules trigger from the same event.
        # Identify the event by the event.ts + entity combination.
        entity = alert.get("entity", "")
        evt_ts = float(alert.get("ts", 0) or 0)
        # Round ts when it is not an integer; use an approximately 1-second window to suppress the same event burst
        _dedup_key = f"{entity}:{int(evt_ts)}"
        if _dedup_key and _dedup_key in self._per_event_seen:
            # Still record the alarm, just skip label generation
            if entity:
                self._auto_labeler.mark_alarm(entity)
            return
        if _dedup_key:
            self._per_event_seen[_dedup_key] = evt_ts
            # Cache limit: keep at most 500 entries
            if len(self._per_event_seen) > 500:
                # Drop the oldest entries
                oldest = sorted(self._per_event_seen, key=lambda k: self._per_event_seen[k])
                for old in oldest[:100]:
                    del self._per_event_seen[old]

        record = self._enrich_record_for_quota(self._auto_labeler.process_alert(alert, event))
        if entity:
            self._auto_labeler.mark_alarm(entity)
        self._update_weights()
        if record and self._db and hasattr(self._db, "save_labels"):
            allowed, _reason = self._quota_allows_record(record)
            if not allowed:
                return
            try:
                saved = int(self._db.save_labels([record]) or 0)
                if saved > 0:
                    self._record_saved_for_quota(record)
            except Exception as e:
                logger.debug(f"[LabelEngine] auto_labeled DB'ye yazılamadı: {e}")

    def on_normal_event(self, event, delayed_learning_ok: bool = False) -> None:
        record = self._enrich_record_for_quota(
            self._auto_labeler.process_normal(event, delayed_learning_ok=delayed_learning_ok)
        )
        if record and self._db and hasattr(self._db, "save_labels"):
            allowed, _reason = self._quota_allows_record(record)
            if not allowed:
                return
            try:
                saved = int(self._db.save_labels([record]) or 0)
                if saved > 0:
                    self._record_saved_for_quota(record)
            except Exception as e:
                logger.debug(f"[LabelEngine] normal auto_labeled DB'ye yazılamadı: {e}")

    def on_operator_label(self, score: float, label: str,
                          category: str = "operator", entity_key: str = "") -> None:
        record = LabelRecord(
            score=score, label=label, category=category,
            source=SOURCE_OPERATOR_LABEL, confidence=1.0,
            ts=time.time(), weight=SOURCE_BASE_WEIGHTS[SOURCE_OPERATOR_LABEL],
            entity_key=entity_key, ready_after=0.0,
            distro=self._distro,
        )
        self._operator_records.append(record)
        if self._db and hasattr(self._db, "save_labels"):
            try:
                self._db.save_labels([record])
            except Exception as e:
                logger.debug(f"[LabelEngine] Operator etiketi DB'ye yazılamadı: {e}")

    # ── Kalibrasyon Verisi ────────────────────────────────────────────────────

    def get_calibration_data(self) -> List[Tuple[float, int, float]]:
        """
        (score, label_int, effective_weight) listesi.
        Auto etiketler ready_after dolmadan dahil edilmez.
        """
        result = []

        for r in self._synthetic_records:
            if r is None:
                continue
            if r.confidence >= AUTO_LABEL_MIN_CONFIDENCE and self._is_calibration_eligible(r):
                factor = self._effective_source_weight(SOURCE_SYNTHETIC, r.label) / SOURCE_BASE_WEIGHTS[SOURCE_SYNTHETIC]
                if factor > 0:
                    result.append((r.score, 1 if r.label == "attack" else 0,
                                   r.weight * factor))

        for r in self._bootstrap_records:
            if r is None:
                continue
            if r.confidence >= AUTO_LABEL_MIN_CONFIDENCE and self._is_calibration_eligible(r):
                factor = self._effective_source_weight(SOURCE_BOOTSTRAP, r.label) / SOURCE_BASE_WEIGHTS[SOURCE_BOOTSTRAP]
                if factor > 0:
                    result.append((r.score, 1 if r.label == "attack" else 0,
                                   r.weight * factor))

        for r in self._auto_labeler.get_ready_records():
            if r.confidence >= AUTO_LABEL_MIN_CONFIDENCE and self._is_calibration_eligible(r):
                result.append((r.score, 1 if r.label == "attack" else 0, r.weight))

        for r in self._operator_records:
            if self._is_calibration_eligible(r):
                result.append((r.score, 1 if r.label == "attack" else 0, r.weight))

        return result

    # ── Linear Weight Update ──────────────────────────────────────────────

    def _update_weights(self) -> None:
        self._synthetic_attack_weight = self._retired_weight(
            SOURCE_SYNTHETIC, "attack", self._synthetic_records, SYNTHETIC_RETIRE_AT_RATIO
        )
        self._synthetic_normal_weight = self._retired_weight(
            SOURCE_SYNTHETIC, "normal", self._synthetic_records, SYNTHETIC_RETIRE_AT_RATIO
        )
        self._bootstrap_attack_weight = self._retired_weight(
            SOURCE_BOOTSTRAP, "attack", self._bootstrap_records, BOOTSTRAP_RETIRE_AT_RATIO
        )
        self._bootstrap_normal_weight = self._retired_weight(
            SOURCE_BOOTSTRAP, "normal", self._bootstrap_records, BOOTSTRAP_RETIRE_AT_RATIO
        )
        self._synthetic_weight = min(self._synthetic_attack_weight, self._synthetic_normal_weight)
        self._bootstrap_weight = min(self._bootstrap_attack_weight, self._bootstrap_normal_weight)

    def _retired_weight(self, source: str, label: str,
                        records: List[LabelRecord], retire_ratio: float) -> float:
        base_weight = SOURCE_BASE_WEIGHTS[source]
        auto_count = self._auto_label_count(label)
        source_count = self._source_label_count(records, label)
        if source_count <= 0:
            return base_weight
        ratio = auto_count / source_count
        new_w = max(0.0, base_weight * (1.0 - ratio / retire_ratio))
        return new_w

    def _auto_label_count(self, label: str) -> int:
        count_by_label = getattr(self._auto_labeler, "count_by_label", None)
        if callable(count_by_label):
            return count_by_label(label)
        return getattr(self._auto_labeler, "count", 0)

    def _source_label_count(self, records: List[LabelRecord], label: str) -> int:
        labeled = [r for r in records if getattr(r, "label", None) == label]
        if labeled:
            return len(labeled)
        return len(records)

    def _effective_source_weight(self, source: str, label: str) -> float:
        if source == SOURCE_SYNTHETIC:
            if self._synthetic_weight <= 0:
                return 0.0
            return self._synthetic_attack_weight if label == "attack" else self._synthetic_normal_weight
        if source == SOURCE_BOOTSTRAP:
            if self._bootstrap_weight <= 0:
                return 0.0
            return self._bootstrap_attack_weight if label == "attack" else self._bootstrap_normal_weight
        return SOURCE_BASE_WEIGHTS.get(source, 1.0)

    # ── Durum ─────────────────────────────────────────────────────────────────

    def status(self) -> Dict:
        auto_c = self._auto_labeler.count
        syn_c  = len(self._synthetic_records)
        boot_c = len(self._bootstrap_records)
        operator_c = len(self._operator_records)
        return {
            "distro":    self._distro,
            "threshold": self._threshold,
            "sources": {
                SOURCE_SYNTHETIC: {
                    "count":  syn_c,
                    "weight": round(self._synthetic_weight, 3),
                    "active": self._synthetic_weight > 0,
                    "retire_ratio": f"{(auto_c/syn_c if syn_c else 0):.2f}/{SYNTHETIC_RETIRE_AT_RATIO}",
                },
                SOURCE_BOOTSTRAP: {
                    "count":  boot_c,
                    "weight": round(self._bootstrap_weight, 3),
                    "active": self._bootstrap_weight > 0,
                    "retire_ratio": f"{(auto_c/boot_c if boot_c else 0):.2f}/{BOOTSTRAP_RETIRE_AT_RATIO}",
                },
                SOURCE_AUTO_LABELED: {
                    "count":  auto_c,
                    "weight": "0.72-0.95 (confidence)",
                    "active": True,
                },
                SOURCE_OPERATOR_LABEL: {
                    "count":  operator_c,
                    "weight": SOURCE_BASE_WEIGHTS[SOURCE_OPERATOR_LABEL],
                    "active": True,
                },
            },
            "calibration_points": len(self.get_calibration_data()),
            "bootstrap_scan": self._bootstrap_scanner.status,
            "user_map":       dict(self._user_map),
        }
