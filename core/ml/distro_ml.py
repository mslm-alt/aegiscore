"""
core/ml/distro_ml.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Three-layer distro-aware ML adaptation

Layer 1 — Distro feature (feature[24])
Layer 2 — Noise filter (SELinux, SAP, zypper)
Layer 3 — Distro-specific baseline thresholds
"""

import logging
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Layer 1: Distro feature index ────────────────────────────────────────────

DISTRO_FAMILY_IDX = {
    "debian":  0.0,
    "rhel":    0.33,
    "suse":    0.67,
    "unknown": 1.0,
}


def get_distro_feature(distro_family: str) -> float:
    return DISTRO_FAMILY_IDX.get(distro_family, 1.0)


# ── Layer 2: Noise filter ────────────────────────────────────────────────────

# (distro_family, source, action_contains) → weight
NOISE_FILTER: Dict[Tuple, float] = {
    # RHEL — SELinux logs every syscall, so reduce the ML weight
    ("rhel", "auditd", "selinux"):       0.1,
    ("rhel", "auditd", "avc"):           0.1,
    ("rhel", "auditd", "syscall"):       0.3,
    # RHEL — repeated systemd journal noise
    ("rhel", "journald", "started"):     0.2,
    ("rhel", "journald", "stopped"):     0.2,
    # SUSE — repeated SAP process pattern
    ("suse", "syslog",   "sap"):         0.15,
    ("suse", "syslog",   "hana"):        0.15,
    # SUSE — zypper automatic update noise
    ("suse", "syslog",   "zypper"):      0.25,
    # Debian — systemd-resolved DNS noise
    ("debian", "syslog", "resolved"):    0.2,
    ("debian", "syslog", "dnsmasq"):     0.25,
}


def get_noise_weight(distro_family: str, source: str, action: str) -> float:
    """
    Return the ML learning weight for the event.
    1.0 = full weight (normal)
    0.1 = very low weight (noise)
    """
    action_lower  = (action or "").lower()
    source_lower  = (source or "").lower()

    for (fam, src, act_contains), weight in NOISE_FILTER.items():
        if fam == distro_family and src == source_lower and act_contains in action_lower:
            return weight

    # Generic source weights (log trust level — Group 2)
    source_trust = {
        "auditd":    1.0,   # high trust
        "auth_log":  0.95,
        "syslog":    0.8,
        "journald":  0.75,  # medium trust
        "ufw":       0.7,
        "dpkg":      0.7,
        "apache2":   0.5,   # application log — low trust
        "nginx":     0.5,
        "dns":       0.6,
        "mysql":     0.45,
    }
    return source_trust.get(source_lower, 0.6)


# ── Layer 3: Distro-specific baseline thresholds ────────────────────────────

DISTRO_THRESHOLDS = {
    "debian": {
        "auditd_event_rate_multiplier": 1.0,   # normal
        "duplicate_rate_tolerance":     2.0,
        "phase1_min_events":            300,
        "anomaly_sensitivity":          1.0,
    },
    "rhel": {
        "auditd_event_rate_multiplier": 3.0,   # 3x higher normal rate because of SELinux
        "duplicate_rate_tolerance":     4.0,   # more tolerant
        "phase1_min_events":            500,   # more events required (high noise)
        "anomaly_sensitivity":          0.7,   # less sensitive (to reduce false positives)
    },
    "suse": {
        "auditd_event_rate_multiplier": 2.0,
        "duplicate_rate_tolerance":     3.0,
        "phase1_min_events":            400,
        "anomaly_sensitivity":          0.8,
    },
    "unknown": {
        "auditd_event_rate_multiplier": 2.0,   # conservative
        "duplicate_rate_tolerance":     3.0,
        "phase1_min_events":            300,
        "anomaly_sensitivity":          0.9,
    },
}


def get_distro_thresholds(distro_family: str) -> Dict:
    return DISTRO_THRESHOLDS.get(distro_family, DISTRO_THRESHOLDS["unknown"])


class DistroMLAdapter:
    """
    Provide distro adaptation to the ML pipeline.
    Used by instant_ml and baseline.
    """

    def __init__(self, distro_family = "unknown"):
        # Accept either a dict or a str — {"family": "debian"} or "debian"
        if isinstance(distro_family, dict):
            distro_family = distro_family.get("family", "unknown")
        self.distro_family  = distro_family
        self.thresholds     = get_distro_thresholds(distro_family)
        self.feature_value  = get_distro_feature(distro_family)
        logger.info(f"[DistroML] Adaptör hazır: family={distro_family}, "
                    f"sensitivity={self.thresholds['anomaly_sensitivity']}, "
                    f"auditd_mult={self.thresholds['auditd_event_rate_multiplier']}")

    def adjust_anomaly_score(self, score: float, source: str, action: str) -> float:
        """Adjust the anomaly score using the noise weight."""
        weight = get_noise_weight(self.distro_family, source, action)
        return score * weight

    def should_train(self, source: str, action: str) -> bool:
        """Return whether this event should enter ML training."""
        weight = get_noise_weight(self.distro_family, source, action)
        return weight >= 0.3   # do not train on very noisy events (< 0.3)

    def phase1_min_events(self) -> int:
        return self.thresholds["phase1_min_events"]

    def anomaly_sensitivity(self) -> float:
        return self.thresholds["anomaly_sensitivity"]

    def get_source_trust(self, source: str) -> float:
        """
        Return the trust score for a specific log source (0.0–1.0).
        Consistent with get_noise_weight() as an action-independent trust value.
        """
        return get_noise_weight(self.distro_family, source, "")
