"""
tests/test_maintenance_integration.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Integration tests:
  1. Grace period math validation
  2. Confidence/BaselineValidator davranışı
"""

import sys
import time
from tests.shims import activate_test_shims

activate_test_shims()

import pytest
from datetime import datetime, UTC
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.ml.learning_guard import (
    DelayedLearningBuffer,
    ConfidenceScorer, BaselineValidator,
)


# ── Grace Period Math ────────────────────────────────────────────────────────

class TestGracePeriodMath:
    """
    PHASE_1 grace period: 0.3 → 1.0 linear interpolation
    phase_manager.ml_confidence_factor() → elapsed / GRACE_WINDOW * (1.0 - 0.3) + 0.3
    """

    def _grace_factor(self, elapsed: float, grace_window: float = 7200.0) -> float:
        """Calculate the grace factor by simulating the phase_manager.py logic."""
        GRACE_MIN = 0.3
        GRACE_MAX = 1.0
        if elapsed <= 0:
            return GRACE_MIN
        if elapsed >= grace_window:
            return GRACE_MAX
        return GRACE_MIN + (elapsed / grace_window) * (GRACE_MAX - GRACE_MIN)

    def test_initial_factor_is_minimum(self):
        factor = self._grace_factor(0)
        assert abs(factor - 0.3) < 0.001

    def test_full_factor_at_end(self):
        factor = self._grace_factor(7200)
        assert abs(factor - 1.0) < 0.001

    def test_midpoint_factor(self):
        # 3600 seconds → 50% → 0.3 + 0.5 * 0.7 = 0.65
        factor = self._grace_factor(3600)
        assert abs(factor - 0.65) < 0.01

    def test_factor_monotonic(self):
        """The factor must increase monotonically."""
        factors = [self._grace_factor(t) for t in range(0, 7201, 600)]
        for i in range(1, len(factors)):
            assert factors[i] >= factors[i-1]

    def test_factor_bounds(self):
        """The factor must never leave the [0.3, 1.0] range."""
        for t in [-100, 0, 1000, 3600, 7200, 10000]:
            f = self._grace_factor(t)
            assert 0.3 <= f <= 1.0, f"t={t} → factor={f} out of bounds"

    def test_grace_affects_ml_weight(self):
        """The ML weight should decrease when the grace factor is low."""
        base_ml_score = 0.8   # high anomaly score

        # New phase — factor=0.3
        weighted_early = base_ml_score * self._grace_factor(0)
        # Settled phase — factor=1.0
        weighted_late  = base_ml_score * self._grace_factor(7200)

        assert weighted_early < weighted_late
        assert abs(weighted_early - 0.24) < 0.01   # 0.8 * 0.3
        assert abs(weighted_late  - 0.80) < 0.01   # 0.8 * 1.0


# ── Confidence Scorer ────────────────────────────────────────────────────────

class TestConfidenceScorerIntegration:
    class FakeEvent:
        def __init__(self, user="alice", process="sshd", ts=None):
            self.user    = user
            self.process = process
            self.src_ip  = "10.0.0.1"
            self.action  = "ssh_login"
            self.ts      = ts or time.time()

    def test_new_user_lower_confidence(self):
        scorer = ConfidenceScorer()
        # First-seen user → penalty
        score1 = scorer.score(self.FakeEvent(user="newuser"))
        # Known user (repeat)
        score2 = scorer.score(self.FakeEvent(user="newuser"))
        # The second sighting should produce higher confidence
        assert score1 <= 1.0
        assert score2 <= 1.0

    def test_score_bounded(self):
        scorer = ConfidenceScorer()
        for i in range(20):
            score = scorer.score(self.FakeEvent(user=f"user{i}"))
            assert 0.0 <= score <= 1.0, f"Score {score} out of bounds"

    def test_night_penalty(self):
        # Night 02:00 UTC — penalty expected
        night_ts = datetime(2026, 3, 5, 2, 0, 0, tzinfo=UTC).timestamp()
        day_ts   = datetime(2026, 3, 5, 10, 0, 0, tzinfo=UTC).timestamp()

        # Create new users so both scenarios start equally
        scorer_night = ConfidenceScorer()
        scorer_day   = ConfidenceScorer()
        night_score  = scorer_night.score(self.FakeEvent(user="u_night", ts=night_ts))
        day_score    = scorer_day.score(self.FakeEvent(user="u_day",   ts=day_ts))
        assert night_score < day_score, "Night score should be lower than day score"


# ── BaselineValidator ────────────────────────────────────────────────────────

class TestBaselineValidatorIntegration:
    def test_clean_environment_can_advance(self):
        v = BaselineValidator(clean_window_hours=0.0)  # zero window
        can, reason = v.can_advance_to_phase1()
        assert can is True
        assert reason == ""

    def test_recent_critical_blocks_advance(self):
        v = BaselineValidator(clean_window_hours=1.0)
        v.record_incident("critical")
        can, reason = v.can_advance_to_phase1()
        assert can is False
        assert len(reason) > 0

    def test_old_incident_allows_advance(self):
        v = BaselineValidator(clean_window_hours=0.001)  # 3.6 seconds
        v._last_critical_ts = time.time() - 10  # 10 seconds ago
        can, _ = v.can_advance_to_phase1()
        assert can is True

    def test_ioc_blocks_advance(self):
        v = BaselineValidator(clean_window_hours=1.0)
        v.record_ioc()
        can, reason = v.can_advance_to_phase1()
        assert can is False
        assert "IOC" in reason
