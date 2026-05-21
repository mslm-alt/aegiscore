"""
tests/test_maintenance_integration.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Integration tests:
  1. Grace period math validation
  2. Delayed buffer flush davranışı
"""

import sys
import time
import pytest
from datetime import datetime, UTC
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.ml.learning_guard import (
    DelayedLearningBuffer,
    ConfidenceScorer, BaselineValidator,
)
from core.ml_control import MLController
from main import SIEMPipeline


class TestDelayedBufferMaintenanceFlush:
    def test_trainable_ready_event_calls_on_normal_event(self):
        pipeline = SIEMPipeline.__new__(SIEMPipeline)
        event = object()
        pipeline.delayed_buffer = SimpleNamespace(flush_ready=lambda: [(event, True)])
        pipeline.phase = SimpleNamespace(is_active=lambda phase_name: phase_name == "instant_ml")
        pipeline.instant_ml = SimpleNamespace(process=Mock())
        pipeline.label_engine = SimpleNamespace(on_normal_event=Mock())

        flushed = pipeline._flush_delayed_learning_ready_events()

        assert flushed == 1
        pipeline.instant_ml.process.assert_called_once_with(event, should_learn=True)
        pipeline.label_engine.on_normal_event.assert_called_once_with(
            event,
            delayed_learning_ok=True,
        )

    def test_non_trainable_ready_event_skips_on_normal_event(self):
        pipeline = SIEMPipeline.__new__(SIEMPipeline)
        event = object()
        pipeline.delayed_buffer = SimpleNamespace(flush_ready=lambda: [(event, False)])
        pipeline.phase = SimpleNamespace(is_active=lambda phase_name: True)
        pipeline.instant_ml = SimpleNamespace(process=Mock())
        pipeline.label_engine = SimpleNamespace(on_normal_event=Mock())

        flushed = pipeline._flush_delayed_learning_ready_events()

        assert flushed == 1
        pipeline.instant_ml.process.assert_not_called()
        pipeline.label_engine.on_normal_event.assert_not_called()

    def test_maintenance_pressure_snapshot_tracks_queue_growth_and_lag_delta(self):
        pipeline = SIEMPipeline.__new__(SIEMPipeline)
        pipeline._pipeline_pressure = {
            "version": 1,
            "latency": {
                "queue_wait_ewma_ms": 18.0,
                "processing_ewma_ms": 7.0,
                "end_to_end_ewma_ms": 25.0,
                "samples": 5,
            },
            "stages": {
                "normalize_ewma_ms": 0.0,
                "detect_ewma_ms": 0.0,
                "ml_ewma_ms": 0.0,
                "baseline_ewma_ms": 0.0,
                "risk_ewma_ms": 0.0,
                "alerts_ewma_ms": 0.0,
                "total_ewma_ms": 0.0,
            },
            "maintenance": {
                "active": True,
                "last_started_ts": 0.0,
                "last_finished_ts": 0.0,
                "last_duration_ms": 0.0,
                "last_queue_depth_before": 0,
                "last_queue_depth_after": 0,
                "last_queue_growth": 0,
                "last_queue_wait_delta_ms": 0.0,
                "last_processing_delta_ms": 0.0,
                "last_delayed_flush_count": 0,
                "last_mode_active": False,
            },
        }
        pipeline._event_queue = SimpleNamespace(
            health=lambda: {"qsize": 8, "maxsize": 100, "fill_pct": 8.0}
        )

        before_queue = {"qsize": 3}
        before_latency = {"queue_wait_ewma_ms": 10.0, "processing_ewma_ms": 4.5}

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("main.time.time", lambda: 120.2)
            mp.setattr("main.Path.exists", lambda self: self.name == "maintenance_mode.json")
            pipeline._record_maintenance_pressure(
                started_ts=120.0,
                before_queue=before_queue,
                before_latency=before_latency,
                flushed=6,
            )

        maintenance = pipeline._pipeline_pressure["maintenance"]
        assert maintenance["active"] is False
        assert maintenance["last_duration_ms"] == 200.0
        assert maintenance["last_queue_growth"] == 5
        assert maintenance["last_queue_wait_delta_ms"] == 8.0
        assert maintenance["last_processing_delta_ms"] == 2.5
        assert maintenance["last_delayed_flush_count"] == 6
        assert maintenance["last_mode_active"] is True


class TestDelayedLearningConfig:
    def test_config_delay_used_for_default_profiles(self):
        delay = SIEMPipeline._resolve_delayed_learning_delay_seconds(
            {"delayed_learning": {"default_delay_seconds": 7200}}
        )

        assert delay == 7200

    def test_fallback_delay_used_when_config_missing(self):
        delay = SIEMPipeline._resolve_delayed_learning_delay_seconds({})

        assert delay == 7200

    def test_lab_profile_uses_lab_delay_with_minimum_floor(self):
        delay = SIEMPipeline._resolve_delayed_learning_delay_seconds(
            {
                "phase_profile": "lab",
                "delayed_learning": {"default_delay_seconds": 7200, "lab_delay_seconds": 1800},
            }
        )

        assert delay == 5400


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


class TestMLControllerAutoResume:
    def _make_db(self, state=None, open_incidents=None):
        stats = {}
        if state is not None:
            import json as _json
            stats["ml_control_state"] = _json.dumps(state)

        logs = []

        class _DB:
            def get_stat(self, key):
                return stats.get(key)

            def set_stat(self, key, value):
                stats[key] = value

            def log_ml_control(self, action, reason="", actor="auto", source=""):
                logs.append({
                    "action": action,
                    "reason": reason,
                    "actor": actor,
                    "source": source,
                })

            def get_open_incidents(self):
                return list(open_incidents or [])

        return _DB(), stats, logs

    def test_tick_auto_resumes_when_clean_window_elapsed_and_no_open_blocking_incident(self, monkeypatch):
        paused_at = 100.0
        db, stats, logs = self._make_db(state={
            "paused": True,
            "pause_reason": "auto:incident:INC-OLD",
            "paused_at": paused_at,
            "excluded_sources": [],
            "last_incident_ts": paused_at,
        })
        ctrl = MLController(config={"ml_control": {"auto_resume": True, "clean_window_hours": 2.0}}, db=db)
        monkeypatch.setattr("core.ml_control.time.time", lambda: paused_at + 3 * 3600)

        ctrl.tick()

        assert ctrl.status()["paused"] is False
        assert any(item["action"] == "resume" and item["reason"] == "auto:clean_window" for item in logs)

    def test_tick_keeps_paused_when_open_high_or_critical_incident_exists(self, monkeypatch):
        paused_at = 100.0
        db, stats, logs = self._make_db(
            state={
                "paused": True,
                "pause_reason": "auto:incident:INC-OLD",
                "paused_at": paused_at,
                "excluded_sources": [],
                "last_incident_ts": paused_at,
            },
            open_incidents=[
                {"severity": "low"},
                {"severity": "critical"},
            ],
        )
        ctrl = MLController(config={"ml_control": {"auto_resume": True, "clean_window_hours": 2.0}}, db=db)
        monkeypatch.setattr("core.ml_control.time.time", lambda: paused_at + 3 * 3600)

        ctrl.tick()

        assert ctrl.status()["paused"] is True
        assert ctrl.status()["pause_reason"] == "auto:incident:INC-OLD"
        assert not any(item["action"] == "resume" for item in logs)

    def test_manual_pause_is_not_opened_by_tick(self, monkeypatch):
        paused_at = 100.0
        db, stats, logs = self._make_db(state={
            "paused": True,
            "pause_reason": "manual:operator",
            "paused_at": paused_at,
            "excluded_sources": [],
            "last_incident_ts": paused_at,
        })
        ctrl = MLController(config={"ml_control": {"auto_resume": True, "clean_window_hours": 2.0}}, db=db)
        monkeypatch.setattr("core.ml_control.time.time", lambda: paused_at + 3 * 3600)

        ctrl.tick()

        assert ctrl.status()["paused"] is True
        assert ctrl.status()["pause_reason"] == "manual:operator"
        assert not any(item["action"] == "resume" for item in logs)
