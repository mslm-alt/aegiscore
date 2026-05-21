"""
core/risk.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 8: Risk Scoring Layer

Combines signals from all detection layers.
Produces the final risk score for a single entity or event.

Components:
  1. WeightedRiskScorer   - weighted scoring
  2. ScoreDecay           - score decreases over time
  3. Cooldown/Suppression - repeated alert suppression
  4. RiskScoringEngine    - combines all of the above
"""

import time
import math
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


# ── Risk Signal ───────────────────────────────────────────────────────────────

@dataclass
class RiskSignal:
    """A single detection signal."""
    source:    str   = ""     # rule_engine / ml_if / ml_pca / baseline / correlation
    score:     float = 0.0    # 0-100
    weight:    float = 1.0    # weight
    ts:        float = 0.0
    details:   Dict  = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """Final risk assessment."""
    entity:          str   = ""
    final_score:     float = 0.0
    severity:        str   = "low"
    signals:         List  = field(default_factory=list)
    breakdown:       Dict  = field(default_factory=dict)
    should_alert:    bool  = False
    ts:              float = field(default_factory=time.time)
    explanation:     Dict  = field(default_factory=dict)   # ScoreExplainer output
    asset_multiplier:float = 1.0                            # asset criticality multiplier
    host:            str   = ""


# ── 1. Weighted Risk Scorer ───────────────────────────────────────────────────

# Default weights per source
DEFAULT_WEIGHTS = {
    # Rule layer: strongest signal
    "rule_engine":      1.0,
    "ioc":              1.5,
    "regex":            1.0,
    "monitor":          0.6,
    "threshold":        0.9,
    "first_seen":       0.6,
    # PHASE 1 ML: keep both legacy aliases and real model names
    "ml_if":            0.9,
    "isolation_forest": 0.9,   # real instant_ml name
    "ewma":             0.8,
    "ml_pca":           0.7,
    "incremental_pca":  0.7,   # real instant_ml name
    "ml_ensemble":      1.0,
    # PHASE 2: behavior baselines, both aliases and canonical names
    "baseline_user":    0.8,
    "user_baseline":    0.8,   # canonical baseline.py name
    "baseline_service": 0.7,
    "service_baseline": 0.7,   # canonical baseline.py name
    "peer_group":       0.8,
    "process_tree":     0.75,  # canonical baseline.py name
    "freq_anomaly":     0.6,
    # Global
    "correlation":      1.2,
}

CONFIG_WEIGHT_MAP = {
    "rule":        ["rule_engine", "regex"],
    "ioc":         ["ioc"],
    "correlation": ["correlation"],
    "ml":          ["ml_if", "isolation_forest", "ewma", "ml_pca", "incremental_pca", "ml_ensemble"],
    "baseline":    ["baseline_user", "user_baseline", "baseline_service", "service_baseline",
                    "peer_group", "process_tree"],
    "monitor":     ["monitor"],
    "threshold":   ["threshold", "first_seen"],
}

# CONFIG_WEIGHT_MAP is expanded into the weights dict


class WeightedRiskScorer:
    """
    Calculate the risk score using a weighted average.
    Reads weights from config.yml, otherwise falls back to DEFAULT_WEIGHTS.
    """

    def __init__(self, config: Dict = None):
        self.weights = DEFAULT_WEIGHTS.copy()
        # Apply risk_weights from config.yml
        if config:
            cfg_weights = config.get("risk_weights", {})
            for cfg_key, w in cfg_weights.items():
                if cfg_key in self.weights:
                    self.weights[cfg_key] = float(w)
                for internal_key in CONFIG_WEIGHT_MAP.get(cfg_key, []):
                    self.weights[internal_key] = float(w)
            logger.debug(f"[AegisCore:Risk] loaded weights from config: {cfg_weights}")

    def calculate(self, signals: List[RiskSignal]) -> Tuple[float, Dict]:
        """
        Combine signals with source-aware weighting.
        Returns: (final_score, breakdown)
        """
        if not signals:
            return 0.0, {}

        total_weight  = 0.0
        weighted_sum  = 0.0
        breakdown     = {}

        for sig in signals:
            w = self.weights.get(sig.source, 0.5) * sig.weight
            weighted_sum  += sig.score * w
            total_weight  += w
            breakdown[sig.source] = {
                "score":  round(sig.score, 2),
                "weight": round(w, 2),
                "contribution": round(sig.score * w, 2)
            }

        final = (weighted_sum / total_weight) if total_weight > 0 else 0.0
        return min(final, 100.0), breakdown

    def max_score(self, signals: List[RiskSignal]) -> float:
        """Return the maximum score across all signals."""
        return max((s.score for s in signals), default=0.0)


# ── 2. Score Decay ────────────────────────────────────────────────────────────

class ScoreDecay:
    """
    Decay the risk score over time.
    Older alerts contribute less while recent activity matters more.

    Formula: score * 0.5^(elapsed / half_life)
    """

    def __init__(self, half_life: float = 3600):
        """
        half_life: seconds until scores are reduced by half.
        Default: 1 hour.
        """
        self.half_life = half_life

    def decay(self, score: float, elapsed_seconds: float) -> float:
        """Reduce the score according to elapsed time."""
        if elapsed_seconds <= 0:
            return score
        factor = 0.5 ** (elapsed_seconds / self.half_life)
        return score * factor

    def time_weighted_score(self, score_history: List[Tuple[float, float]]) -> float:
        """
        Compute a time-weighted cumulative score from a (ts, score) list.
        The most recent event contributes the most.
        """
        if not score_history:
            return 0.0
        now    = time.time()
        total  = 0.0
        for ts, score in score_history:
            elapsed = now - ts
            total  += self.decay(score, elapsed)
        return min(total, 100.0)


# ── 3. Severity Classifier ───────────────────────────────────────────────────

def score_to_severity(score: float,
                      thresholds: Dict[str, float] = None) -> str:
    """Convert a risk score into a severity label."""
    t = thresholds or {"low": 30, "medium": 50, "high": 70, "critical": 90}
    if score >= t.get("critical", 90): return "critical"
    if score >= t.get("high",     70): return "high"
    if score >= t.get("medium",   50): return "medium"
    if score >= t.get("low",      30): return "low"
    return "info"


# ── 4. Risk Scoring Engine ────────────────────────────────────────────────────

class RiskScoringEngine:
    """
    Main risk scoring engine.

    For each event/entity:
    1. Collect all detection signals
    2. Calculate the weighted score
    3. Apply decay
    4. Determine severity
    5. Decide whether to alert
    """

    def __init__(self, config: Dict = None, phase_mgr=None):
        cfg      = config or {}
        risk_cfg = cfg.get("risk", {})

        # Pass the full config into WeightedRiskScorer so it can read risk_weights
        self.scorer     = WeightedRiskScorer(config=cfg)
        self.decay      = ScoreDecay(
            half_life=risk_cfg.get("decay", {}).get("half_life", 3600)
        )
        # v8: phase-manager reference for the grace period
        self.phase_mgr  = phase_mgr

        # score_to_severity thresholds from config.yml
        policy = cfg.get("alert_policy", {})
        sev_map = policy.get("score_to_severity", {})
        self.thresholds = {
            "critical": sev_map.get("critical", 90),
            "high":     sev_map.get("high", 70),
            "medium":   sev_map.get("medium", 50),
            # Bug #9: the "low" threshold for score_to_severity must be 30, not 0
            "low":      sev_map.get("low", 30),
        }
        # Bug #1: min_risk_for_alert was read but never used inside assess()
        self.min_risk_for_alert = policy.get("min_risk_for_alert", 40)

        # entity → [(ts, score)] history
        self._entity_history: Dict[str, List[Tuple[float, float]]] = defaultdict(list)
        # entity → son assessment
        self._entity_scores:  Dict[str, float] = {}

        self._assessments_count = 0

        # 5a: per-host calibration store — reduces false positives on noisy hosts
        try:
            from core.ml.calibration import HostCalibrationStore
            models_dir = cfg.get("storage", {}).get("models_dir", "data/models")
            self._host_calib = HostCalibrationStore(
                window_size = cfg.get("risk", {}).get("host_calib_window", 5000),
                min_samples = cfg.get("risk", {}).get("host_calib_min_samples", 50),
                save_dir    = models_dir,
            )
        except Exception as _hce:
            logger.debug(f"[Risk] HostCalibrationStore yüklenemedi: {_hce}")
            self._host_calib = None

        # Context components
        try:
            from core.context import ScoreExplainer, AssetCriticalityMap
            self._explainer    = ScoreExplainer()
            self._asset_map    = AssetCriticalityMap(config=cfg)
        except ImportError:
            self._explainer = None
            self._asset_map = None

        logger.info("[AegisCore:Risk] RiskScoringEngine hazır (explainer + asset map + host_calib).")

    def _tune_detection_signal(self, det, source: str) -> Tuple[float, float, Dict[str, Any]]:
        """
        Dar kapsamlı auth/noise tuning.
        Brute-force ve anlamlı novelty korunur; typo/noise burst etkisi yumuşatılır.
        Returns: (score, weight, extra_details)
        """
        score = float(getattr(det, "score", 0.0) or 0.0)
        weight = 1.0
        details: Dict[str, Any] = {}
        rule_id = getattr(det, "rule_id", "") or ""

        # Single failed-login and invalid-user signals should not accumulate risk too aggressively.
        if rule_id in ("AUTH-002", "AUTH-003"):
            score *= 0.65
            weight *= 0.75
            details["tuned_for_noise"] = "single_login_failure"

        # Failed logins from a new IP should remain only as a mild novelty signal.
        elif rule_id in ("FIRST-001", "FSEEN-001") or rule_id.startswith(("FIRST-", "FSEEN-")):
            score *= 0.6
            weight *= 0.7
            details["tuned_for_noise"] = "first_seen_failed_login"

        # Avoid excessive risk during SSH connection-flood typos or reconnect bursts.
        elif rule_id == "THR-003":
            score *= 0.7
            weight *= 0.75
            details["tuned_for_noise"] = "connection_flood"

        return round(score, 2), round(weight, 3), details

    def assess(self, entity: str, signals: List[RiskSignal],
               host: str = "", asset_multiplier: float = 1.0) -> Optional[RiskAssessment]:
        """
        Entity için risk değerlendirmesi yap.
        Boş sinyal listesi verilirse None döndürür.

        host: asset criticality için host adı
        asset_multiplier: dışarıdan verilen çarpan (AssetCriticalityMap'ten)
        """
        # Bug #6: do not produce an assessment when the signal list is empty
        if not signals:
            return None

        self._assessments_count += 1
        now = time.time()

        # Instant score
        instant_score, breakdown = self.scorer.calculate(signals)

        # 5a: per-host calibration — normalize against the host's own history
        if self._host_calib and host:
            # Update ML signals with host-specific calibration
            for sig in signals:
                if sig.source not in ("rule_engine", "ioc", "correlation"):
                    self._host_calib.update(host, sig.source, sig.score)
            # Host'un median skoru biliniyorsa instant_score'u normalize et
            cal_score = self._host_calib.calibrate(host, "aggregate", instant_score)
            if cal_score != instant_score:
                logger.debug(
                    f"[Risk] Host calibration: {host} "
                    f"raw={instant_score:.1f} → cal={cal_score:.1f}"
                )
                instant_score = cal_score

        # Apply the asset-criticality multiplier, which is already precomputed
        if asset_multiplier > 1.0:
            instant_score = min(instant_score * asset_multiplier, 100.0)

        # Pull historical scores and apply decay
        history = self._entity_history[entity]
        history.append((now, instant_score))
        history[:] = [(ts, s) for ts, s in history if now - ts < 21600]

        # Time-weighted cumulative score
        cumulative = self.decay.time_weighted_score(history)

        # Final skor
        final_score = (instant_score * 0.6 + cumulative * 0.4)
        final_score = min(final_score, 100.0)

        self._entity_scores[entity] = final_score
        severity     = score_to_severity(final_score, self.thresholds)
        # Bug #1: thresholds["low"] yerine min_risk_for_alert kullan
        should_alert = final_score >= self.min_risk_for_alert

        # Score explainability
        explanation = {}
        if self._explainer:
            explanation = self._explainer.explain(
                signals, final_score, host=host,
                asset_mult=asset_multiplier
            )

        return RiskAssessment(
            entity           = entity,
            final_score      = round(final_score, 2),
            severity         = severity,
            signals          = signals,
            breakdown        = breakdown,
            should_alert     = should_alert,
            ts               = now,
            explanation      = explanation,
            asset_multiplier = asset_multiplier,
            host             = host,
        )

    def get_entity_score(self, entity: str) -> float:
        """Entity'nin son risk skoru."""
        return self._entity_scores.get(entity, 0.0)

    def get_top_entities(self, n: int = 10) -> List[Tuple[str, float]]:
        """Return the highest-risk entities."""
        return sorted(
            self._entity_scores.items(),
            key=lambda x: x[1], reverse=True
        )[:n]

    def build_signals_from_detections(self,
                                       rule_detections: List,
                                       ml_results: List,
                                       baseline_scores: Dict,
                                       context_scores: Dict = None) -> List[RiskSignal]:
        """
        Farklı detection katmanlarının çıktılarını RiskSignal listesine çevir.

        context_scores: context.py bileşenlerinden gelen ek sinyaller
                  Örnek: {"freq_anomaly": 45, "peer_group": 30}
        """
        signals = []
        now = time.time()

        # Rule/Regex/IOC/Threshold detections — confidence weight ile
        try:
            from core.context import rule_confidence_weight
        except ImportError:
            rule_confidence_weight = None

        for det in rule_detections:
            source = "ioc"        if det.rule_id.startswith("IOC")   else \
                     "threshold"  if det.rule_id.startswith("THR")   else \
                     "first_seen" if det.rule_id.startswith("FIRST") else \
                     "regex"      if det.rule_id.startswith("REGEX") else \
                     "rule_engine"

            # Severity-based confidence weight
            w = 1.0
            if rule_confidence_weight and source == "rule_engine":
                w = rule_confidence_weight(
                    det.rule_id,
                    getattr(det, 'severity', 'medium'),
                    det.score
                )
            tuned_score, tuned_weight, tuned_details = self._tune_detection_signal(det, source)
            signals.append(RiskSignal(
                source=source, score=tuned_score, weight=w * tuned_weight, ts=now,
                details={"rule_id": det.rule_id,
                         "severity": getattr(det, 'severity', ''),
                         **tuned_details}
            ))

        # v8: grace-period factor — ramp ML weight gradually after a phase transition
        _grace = (self.phase_mgr.ml_confidence_factor()
                  if self.phase_mgr else 1.0)

        # Instant ML — preserve the model name
        for ml in ml_results:
            model_name = getattr(ml, 'model', 'ml')
            source = model_name if model_name in DEFAULT_WEIGHTS else f"ml_{model_name[:2].lower()}"
            signals.append(RiskSignal(
                source=source, score=ml.score, weight=_grace, ts=now,
                details=getattr(ml, 'details', {})
            ))

        # Baseline
        for source, score in baseline_scores.items():
            if score > 0:
                signals.append(RiskSignal(
                    source=source, score=score, weight=_grace, ts=now
                ))

        # Ek context sinyalleri
        if context_scores:
            for source, score in context_scores.items():
                if score > 0:
                    signals.append(RiskSignal(
                        source=source, score=float(score), ts=now
                    ))

        return signals

    def status(self) -> Dict:
        return {
            "assessments_done":  self._assessments_count,
            "entities_tracked":  len(self._entity_scores),
            "top_risk_entities": self.get_top_entities(5),
        }
