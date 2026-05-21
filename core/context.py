from __future__ import annotations
"""
core/context.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AegisCore — Context & Confidence Layer

Cross-cutting components used across phases:

  1. EntityFrequencyBaseline  — measures deviation from normal frequency
  2. ScoreExplainer           — explains why the score was high and which signals contributed
"""

import time
import math
import logging
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
from dataclasses import field

import numpy as np

logger = logging.getLogger(__name__)


# ── 1. Rule Confidence Weighter ───────────────────────────────────────────────

# Severity → base weight multiplier
SEVERITY_WEIGHT = {
    "critical": 1.5,
    "high":     1.2,
    "medium":   1.0,
    "low":      0.7,
}

# High-confidence prefixes: give these rules extra trust
HIGH_CONFIDENCE_PREFIXES = (
    "IOC-", "THR-", "AUTH-0", "AUDIT-PRIVESC", "ATK-PE-",
)

def rule_confidence_weight(rule_id: str, severity: str,
                           score: float) -> float:
    """
    Calculate a confidence weight based on rule ID and severity.

    Instead of a fixed rule weight:
    - Higher severity → larger weight
    - Known high-confidence prefixes → extra multiplier
    - Score 90+ → treat as a critical signal

    Returns: weight in the 0.5–2.0 range
    """
    base = SEVERITY_WEIGHT.get(severity.lower(), 1.0)

    # High-confidence prefix
    if any(rule_id.startswith(p) for p in HIGH_CONFIDENCE_PREFIXES):
        base *= 1.3

    # Very high raw score → increase confidence
    if score >= 90:
        base *= 1.2
    elif score >= 70:
        base *= 1.1

    return min(base, 2.0)


# ── 2. Asset Criticality Map ──────────────────────────────────────────────────

DEFAULT_ASSET_CRITICALITY = {
    # Value: 1.0 = normal, >1.0 = critical, <1.0 = less critical
    "db":          2.0,
    "database":    2.0,
    "prod":        1.8,
    "production":  1.8,
    "payment":     2.0,
    "finance":     2.0,
    "auth":        1.6,
    "ldap":        1.6,
    "dc":          1.8,
    "gateway":     1.5,
    "vpn":         1.5,
    "bastion":     1.5,
    "jump":        1.5,
    "backup":      1.4,
    "monitor":     1.2,
    "dev":         0.7,
    "test":        0.6,
    "staging":     0.8,
    "lab":         0.5,
}

class EntityFrequencyBaseline:
    """
    Learn the normal event frequency per entity (IP/user/process).
    Measures frequency drift in addition to first-seen detection.

    Example:
      alice normally makes 10 SSH attempts per hour → 100 is anomalous
      5.5.5.5 is never seen normally → even one event is a first sighting

    Sliding window: last 1 hour
    Learns the average frequency with EWMA

    Environment independence: very good
    - Each entity learns its own baseline
    """

    def __init__(self, window_secs: float = 3600,
                 alpha: float = 0.15,
                 z_threshold: float = 3.0,
                 short_window_secs: float = 300.0,
                 min_drift_span_secs: float = 900.0,
                 short_burst_ratio: float = 0.7,
                 short_burst_multiplier: float = 2.0):
        self.window_secs  = window_secs
        self.alpha        = alpha
        self.z_threshold  = z_threshold
        self.short_window_secs       = short_window_secs
        self.min_drift_span_secs     = min_drift_span_secs
        self.short_burst_ratio       = short_burst_ratio
        self.short_burst_multiplier  = short_burst_multiplier

        # entity → {"ewma": float, "ewma_var": float, "n": int, "events": deque, "last_seen": float}
        self._profiles: Dict[str, Dict] = defaultdict(lambda: {
            "ewma": None, "ewma_var": 0.0, "n": 0,
            "events": deque(), "last_seen": 0.0,
        })

    def record(self, entity: str, ts: float = None):
        """Record an event."""
        now = ts or time.time()
        p   = self._profiles[entity]
        p["events"].append(now)
        p["last_seen"] = now   # recency takibi

        # Drop events outside the active window
        cutoff = now - self.window_secs
        while p["events"] and p["events"][0] < cutoff:
            p["events"].popleft()

    def frequency_score(self, entity: str, ts: float = None) -> float:
        """
        Return how far the current frequency deviates from normal as a 0-100 score.
        0 = normal, 100 = highly anomalous
        """
        now = ts or time.time()
        p   = self._profiles[entity]

        # Event count inside the window = frequency (N events per hour)
        current_events = self._window_events(p, now)
        current_rate = len(current_events)

        # Update EWMA
        if p["ewma"] is None:
            p["ewma"]     = current_rate
            p["ewma_var"] = 0.0
            p["n"]        = 1
            return 0.0   # first observation → no score

        if self._is_short_burst(p, current_events, now):
            return 0.0

        old_mean = p["ewma"]
        old_var = p["ewma_var"]
        p["n"]        += 1
        p["last_seen"]  = now
        p["ewma"]     = (1 - self.alpha) * p["ewma"]     + self.alpha * current_rate
        p["ewma_var"] = (1 - self.alpha) * (p["ewma_var"] +
                         self.alpha * (current_rate - old_mean) ** 2)

        if p["n"] < 5:
            return 0.0   # warmup

        std = max(old_var ** 0.5, 1e-3)
        z   = abs(current_rate - old_mean) / std

        if z < self.z_threshold:
            return 0.0

        # z > threshold → produce a score
        score = min((z / self.z_threshold - 1.0) * 40, 80.0)
        return score

    def _window_events(self, profile: Dict, now: float):
        cutoff = now - self.window_secs
        return [t for t in profile["events"] if t >= cutoff]

    def _is_short_burst(self, profile: Dict, current_events: List[float], now: float) -> bool:
        if len(current_events) < 5:
            return False

        span = current_events[-1] - current_events[0]
        if span > self.min_drift_span_secs:
            return False

        recent_cutoff = now - self.short_window_secs
        short_window_count = sum(1 for t in current_events if t >= recent_cutoff)
        concentration = short_window_count / max(len(current_events), 1)
        baseline_rate = float(profile.get("ewma") or 0.0)
        elevated = len(current_events) >= max(5.0, baseline_rate * self.short_burst_multiplier)
        return elevated and concentration >= self.short_burst_ratio

    def is_new_entity(self, entity: str) -> bool:
        """Return whether this entity has never been seen before."""
        return self._profiles[entity]["n"] == 0


# ── 4. Feature Quality Gate ───────────────────────────────────────────────────

# Acceptable minimum ratio of valid features
FEATURE_QUALITY_MIN_VALID = 0.6   # at least 60% of features must be valid
FEATURE_QUALITY_MAX_NAN   = 0.2   # at most 20% NaN is acceptable

def feature_quality_score(features: np.ndarray) -> Tuple[bool, float, str]:
    """
    Measure feature vector quality.

    Returns:
        (is_ok, quality_score, reason)
        is_ok = True → ML can produce a score
        is_ok = False → skip ML
    """
    if features is None or len(features) == 0:
        return False, 0.0, "empty_features"

    n = len(features)

    # NaN check
    nan_ratio = float(np.isnan(features).sum()) / n
    if nan_ratio > FEATURE_QUALITY_MAX_NAN:
        return False, 0.0, f"too_many_nan:{nan_ratio:.0%}"

    # Inf check
    inf_count = np.isinf(features).sum()
    if inf_count > 0:
        return False, 0.0, f"has_inf:{inf_count}"

    # All-zero check (often caused by failed feature extraction)
    if np.all(features == 0):
        return False, 0.5, "all_zeros"

    # Ratio of valid features
    valid_ratio = 1.0 - nan_ratio
    if valid_ratio < FEATURE_QUALITY_MIN_VALID:
        return False, valid_ratio, f"low_valid:{valid_ratio:.0%}"

    # Variance check — a fully constant vector is meaningless for the model
    std = features.std()
    if std < 1e-6:
        return False, 0.6, "zero_variance"

    return True, valid_ratio, "ok"


# ── 5. Baseline Confidence Score ──────────────────────────────────────────────

def sample_confidence(n_samples: int,
                      min_samples: int = 100,
                      full_confidence_at: int = 500) -> float:
    """
    Shared sample confidence multiplier.

    Prevent small-sample baseline and sequence models from dominating.
    """
    if full_confidence_at <= min_samples:
        return 1.0 if n_samples >= min_samples else 0.0
    if n_samples < min_samples:
        return 0.0
    if n_samples >= full_confidence_at:
        return 1.0
    return (n_samples - min_samples) / (full_confidence_at - min_samples)


def baseline_confidence(n_samples: int,
                        min_samples: int = 100,
                        full_confidence_at: int = 500) -> float:
    """
    Confidence score based on how many samples trained the baseline (0.0-1.0).

    - n < min_samples        → 0.0 (not reliable yet)
    - min_samples ≤ n < full → linear increase
    - n >= full_confidence   → 1.0

    Usage: baseline_score * baseline_confidence(n)
    This keeps small-sample baselines from becoming too dominant.
    """
    return sample_confidence(
        n_samples,
        min_samples=min_samples,
        full_confidence_at=full_confidence_at,
    )


# ── 6. Score Explainer ────────────────────────────────────────────────────────

class ScoreExplainer:
    """
    Explain why the risk score increased.

    For each signal:
    - Source (rule_engine, ml_if, baseline_user, ...)
    - Score and weight
    - Human-readable explanation

    Output: appended to alert.context_json["explanation"].
    """

    SOURCE_LABELS = {
        "rule_engine":      "Kural motoru",
        "ioc":              "IOC eşleşmesi",
        "threshold":        "Eşik aşımı",
        "first_seen":       "İlk kez görüldü",
        "rarity":           "Nadir event",
        "ml_if":            "ML (Isolation Forest)",
        "ml_ew":            "ML (EWMA spike)",
        "ml_pca":           "ML (PCA anomali)",
        "baseline_user":    "Kullanıcı baseline sapması",
        "baseline_service": "Servis baseline sapması",
        "correlation":      "Korelasyon bonusu",
        "regex":            "Regex eşleşmesi",
        "monitor":          "Sistem izleme",
        "ewma":             "ML (EWMA spike)",
        "ocsvm":            "ML (OC-SVM)",
        "asset_criticality":"Asset kritikliği çarpanı",
        "freq_anomaly":     "Sıklık anomalisi",
    }

    def explain(self, signals: List, final_score: float,
                host: str = "", asset_mult: float = 1.0) -> Dict:
        """
        Build a human-readable explanation from the signal list.

        Returns:
            {
              "summary": "Kural motoru + IOC eşleşmesi yüksek skor üretti",
              "top_contributors": [...],
              "asset_note": "...",
              "score": 85.2
            }
        """
        if not signals:
            return {"summary": "Sinyal yok", "top_contributors": [], "score": 0}

        # Highest contributors
        contributors = sorted(
            signals,
            key=lambda s: s.score * getattr(s, 'weight', 1.0),
            reverse=True
        )[:5]

        top = []
        for sig in contributors:
            label = self.SOURCE_LABELS.get(sig.source, sig.source)
            top.append({
                "source":   sig.source,
                "label":    label,
                "score":    round(sig.score, 1),
                "weight":   round(getattr(sig, 'weight', 1.0), 2),
                "contrib":  round(sig.score * getattr(sig, 'weight', 1.0), 1),
            })

        # Summary sentence
        if contributors:
            top_src  = self.SOURCE_LABELS.get(contributors[0].source, contributors[0].source)
            if len(contributors) > 1:
                top_src2 = self.SOURCE_LABELS.get(contributors[1].source, contributors[1].source)
                summary  = f"{top_src} + {top_src2} yüksek risk sinyali üretti"
            else:
                summary  = f"{top_src} yüksek risk sinyali üretti"
        else:
            summary = "Düşük güvenilirlikli sinyal kombinasyonu"

        # Asset note
        asset_note = ""
        if asset_mult > 1.1:
            asset_note = f"Kritik host ({host}) — skor x{asset_mult:.1f} çarpanı uygulandı"
        elif asset_mult < 0.9:
            asset_note = f"Düşük öncelikli host ({host}) — skor azaltıldı"

        return {
            "summary":          summary,
            "top_contributors": top,
            "final_score":      round(final_score, 2),
            "asset_note":       asset_note,
            "signal_count":     len(signals),
        }


# ── Asset Criticality Map ─────────────────────────────────────────────────────

class AssetCriticalityMap:
    """
    Host / asset criticality multiplier — risk increases on high-value targets.

    Example config.yml:
        risk:
          asset_criticality:
            high:    [dc01, db-prod, vault]
            medium:  [web01, web02, mail]
            low:     []

    Match: exact name or substring (lowercase).
    Returned multiplier: critical → 1.5 | high → 1.3 | medium → 1.1 | low → 1.0
    """

    MULTIPLIERS = {
        "critical": 1.5,
        "high":     1.3,
        "medium":   1.1,
        "low":      1.0,
    }

    def __init__(self, config: Dict = None):
        cfg = (config or {}).get("asset_criticality", {})
        self._critical: List[str] = [h.lower() for h in cfg.get("critical", [])]
        self._high:     List[str] = [h.lower() for h in cfg.get("high",     [])]
        self._medium:   List[str] = [h.lower() for h in cfg.get("medium",   [])]

    def multiplier(self, host: str) -> float:
        """Return the risk multiplier for the host name."""
        if not host:
            return 1.0
        h = host.lower()
        if any(pat in h for pat in self._critical):
            return self.MULTIPLIERS["critical"]
        if any(pat in h for pat in self._high):
            return self.MULTIPLIERS["high"]
        if any(pat in h for pat in self._medium):
            return self.MULTIPLIERS["medium"]
        return self.MULTIPLIERS["low"]

    def status(self) -> Dict:
        return {
            "critical_assets": self._critical,
            "high_assets":     self._high,
            "medium_assets":   self._medium,
        }
