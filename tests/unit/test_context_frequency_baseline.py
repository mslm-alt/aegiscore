import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def _event(**kwargs):
    defaults = {
        "action": "ssh_login",
        "outcome": "failure",
        "src_ip": "198.51.100.10",
        "user": "alice",
        "ts": 0.0,
        "fields": {},
        "message": "",
        "category": "auth",
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class TestEntityFrequencyBaselineSeparation:
    def _warm_low_frequency_baseline(self, baseline, entity="alice"):
        for ts in (0, 1800, 3600, 5400, 7200, 9000):
            baseline.record(entity, ts)
            baseline.frequency_score(entity, ts)

    def test_short_burst_is_suppressed_while_threshold_and_ewma_can_trigger(self, tmp_path):
        from core.context import EntityFrequencyBaseline
        from core.detection import ThresholdDetector
        from core.ml.instant_ml import EWMADetector

        baseline = EntityFrequencyBaseline(
            window_secs=1800,
            short_window_secs=60,
            min_drift_span_secs=300,
        )
        self._warm_low_frequency_baseline(baseline, entity="alice")

        burst_scores = []
        for ts in (10800, 10805, 10810, 10815, 10820, 10825):
            baseline.record("alice", ts)
            burst_scores.append(baseline.frequency_score("alice", ts))

        assert max(burst_scores) == 0.0

        threshold = ThresholdDetector({"rules_dir": "rules"})
        results = []
        for _ in range(6):
            results.extend(threshold.check(_event()))
        assert any(r.triggered for r in results)

        ewma = EWMADetector(
            config={"warmup_samples": 1, "ewma_z_threshold": 2.0},
            model_dir=str(tmp_path),
        )
        ewma._trained = True
        ewma._n_total = 20
        ewma._signals["event_rate"] = {"mean": 1.0, "var": 0.01, "n": 20}
        ewma._signals["failure_rate"] = {"mean": 0.1, "var": 0.01, "n": 20}
        ewma._signals["score"] = {"mean": 10.0, "var": 1.0, "n": 20}
        ewma._window_events = 180
        ewma._window_failures = 90
        ewma._window_start = 1000.0

        with mock.patch("time.time", return_value=1061.0):
            result = ewma.update(_event(), ml_score=10.0, should_learn=False)

        assert result.anomaly is True
        assert result.score > 0.0

    def test_slow_burn_frequency_drift_produces_entity_frequency_signal(self):
        from core.context import EntityFrequencyBaseline

        baseline = EntityFrequencyBaseline(
            window_secs=3600,
            short_window_secs=60,
            min_drift_span_secs=300,
        )
        for ts in (0, 4000, 8000, 12000, 16000, 20000):
            baseline.record("alice", ts)
            baseline.frequency_score("alice", ts)

        drift_scores = []
        for ts in (24000, 24600, 25200, 25800, 26400, 27000, 27600):
            baseline.record("alice", ts)
            drift_scores.append(baseline.frequency_score("alice", ts))

        assert max(drift_scores) > 0.0
