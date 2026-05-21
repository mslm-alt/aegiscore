"""
tests/unit/test_risk_correlation.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk and correlation engine tests.

Coverage:
  - WeightedRiskScorer (signal weights, isolation_forest / user_baseline correction)
  - ScoreDecay (time-based score decay)
  - RiskScoringEngine (assess, entity score)
  - CorrelationEngine (temporal window, chain detection)
  - IncidentManager (grouping, dedup)

Run:
    pytest tests/unit/test_risk_correlation.py -v
"""

import sys
import time
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.risk import (
    WeightedRiskScorer, RiskSignal, ScoreDecay,
    RiskScoringEngine, DEFAULT_WEIGHTS,
)
from core.correlation import CorrelationEngine
from core.ml.instant_ml import MLResult


# ── WeightedRiskScorer ────────────────────────────────────────────────────────

class TestWeightedRiskScorer:

    @pytest.fixture
    def scorer(self):
        return WeightedRiskScorer()

    def _sig(self, source: str, score: float) -> RiskSignal:
        return RiskSignal(source=source, score=score, ts=time.time())

    def test_isolation_forest_correct_weight(self, scorer):
        """Fix 5: isolation_forest must now use weight 0.90, not fallback 0.50."""
        sig = self._sig("isolation_forest", 80.0)
        total, breakdown = scorer.calculate([sig])
        assert breakdown["isolation_forest"]["weight"] == pytest.approx(0.9, abs=0.01)

    def test_user_baseline_correct_weight(self, scorer):
        """Fix 5: user_baseline must now use weight 0.80."""
        sig = self._sig("user_baseline", 70.0)
        total, breakdown = scorer.calculate([sig])
        assert breakdown["user_baseline"]["weight"] == pytest.approx(0.8, abs=0.01)

    def test_process_tree_correct_weight(self, scorer):
        """Fix 5: process_tree must now use weight 0.75."""
        sig = self._sig("process_tree", 60.0)
        total, breakdown = scorer.calculate([sig])
        assert breakdown["process_tree"]["weight"] == pytest.approx(0.75, abs=0.01)

    def test_unknown_source_gets_fallback(self, scorer):
        """Unknown sources must use the 0.50 fallback."""
        sig = self._sig("unknown_model_xyz", 80.0)
        total, breakdown = scorer.calculate([sig])
        assert breakdown["unknown_model_xyz"]["weight"] == pytest.approx(0.5, abs=0.01)

    def test_ioc_highest_weight(self, scorer):
        """IOC must have the highest weight."""
        assert DEFAULT_WEIGHTS["ioc"] > DEFAULT_WEIGHTS["rule_engine"]
        assert DEFAULT_WEIGHTS["ioc"] > DEFAULT_WEIGHTS["ml_if"]

    def test_hmm_not_in_default_weights(self):
        """Fix 18: the ghost model hmm must no longer be in DEFAULT_WEIGHTS."""
        assert "hmm" not in DEFAULT_WEIGHTS

    def test_multiple_signals_aggregated(self, scorer):
        signals = [
            self._sig("rule_engine", 70.0),
            self._sig("isolation_forest", 65.0),
        ]
        total, breakdown = scorer.calculate(signals)
        assert 0 < total <= 100
        assert len(breakdown) == 2

    def test_empty_signals_zero(self, scorer):
        total, breakdown = scorer.calculate([])
        assert total == 0.0


# ── ScoreDecay ────────────────────────────────────────────────────────────────

class TestScoreDecay:

    def test_no_elapsed_no_decay(self):
        decay = ScoreDecay(half_life=3600)
        assert decay.decay(80.0, 0) == pytest.approx(80.0)

    def test_half_life_halves_score(self):
        decay = ScoreDecay(half_life=3600)
        result = decay.decay(80.0, 3600)
        assert result == pytest.approx(40.0, abs=0.5)

    def test_full_decay_near_zero(self):
        decay = ScoreDecay(half_life=3600)
        result = decay.decay(80.0, 36000)  # 10 half-lives
        assert result < 0.1

    def test_score_bounded_above(self):
        decay = ScoreDecay(half_life=3600)
        assert decay.decay(100.0, 0) <= 100.0

    def test_score_non_negative(self):
        decay = ScoreDecay(half_life=3600)
        assert decay.decay(80.0, 999999) >= 0.0


# ── RiskScoringEngine ─────────────────────────────────────────────────────────

class TestRiskScoringEngine:

    @pytest.fixture
    def engine(self):
        return RiskScoringEngine(config={})

    def _sig(self, source: str, score: float) -> RiskSignal:
        return RiskSignal(source=source, score=score, ts=time.time())

    def test_assess_returns_assessment(self, engine):
        signals = [self._sig("rule_engine", 75.0)]
        result = engine.assess("10.0.0.1", signals)
        assert result is not None
        assert 0 <= result.final_score <= 100

    def test_empty_signals_returns_none(self, engine):
        result = engine.assess("10.0.0.1", [])
        assert result is None

    def test_high_ioc_score(self, engine):
        signals = [self._sig("ioc", 90.0)]
        result = engine.assess("1.2.3.4", signals)
        assert result is not None
        assert result.final_score > 50

    def test_entity_score_tracked(self, engine):
        signals = [self._sig("rule_engine", 80.0)]
        engine.assess("192.168.1.1", signals)
        score = engine.get_entity_score("192.168.1.1")
        assert score > 0

    def test_build_signals_from_detections(self, engine):
        from core.detection import DetectionResult
        det = DetectionResult(
            triggered=True, rule_id="AUTH-001", severity="high",
            score=80.0, category="auth", message="test",
        )
        signals = engine.build_signals_from_detections(
            rule_detections=[det],
            ml_results=[],
            baseline_scores={},
        )
        assert len(signals) >= 1
        assert any(s.score == 80.0 for s in signals)

    def test_isolation_forest_signal_correct_weight(self, engine):
        """Fix 5: isolation_forest signal weight must be correct."""
        from core.ml.instant_ml import MLResult
        ml = MLResult(model="isolation_forest", score=75.0, anomaly=True)
        signals = engine.build_signals_from_detections([], [ml], {})
        iso_signals = [s for s in signals if s.source == "isolation_forest"]
        assert len(iso_signals) == 1
        # Weight must use the correct value (0.9 * grace), not fallback 0.5
        assert iso_signals[0].weight > 0.5 or iso_signals[0].weight == pytest.approx(0.9, abs=0.1)

    def test_user_baseline_signal(self, engine):
        """Fix 5: user_baseline signal must use the correct source name."""
        signals = engine.build_signals_from_detections([], [], {"user_baseline": 65.0})
        ub_signals = [s for s in signals if s.source == "user_baseline"]
        assert len(ub_signals) == 1
        assert ub_signals[0].score == 65.0

    def test_incremental_pca_signal_maps_to_known_weight(self, engine):
        ml = MLResult(model="incremental_pca", score=72.0, anomaly=True)
        signals = engine.build_signals_from_detections([], [ml], {})
        pca_signals = [s for s in signals if s.source == "incremental_pca"]
        assert len(pca_signals) == 1
        assert pca_signals[0].weight == pytest.approx(1.0, abs=0.1)

    def test_risk_tuning_softens_single_login_failure_and_first_seen_noise(self, engine):
        from core.detection import DetectionResult
        auth_fail = DetectionResult(
            triggered=True, rule_id="AUTH-002", severity="high",
            score=70.0, category="auth", message="SSH giriş başarısız",
        )
        first_seen_fail = DetectionResult(
            triggered=True, rule_id="FIRST-001", severity="low",
            score=30.0, category="auth", message="Yeni kaynak IP ilk kez başarısız SSH denemesi yaptı",
        )
        brute_force = DetectionResult(
            triggered=True, rule_id="THR-001", severity="high",
            score=80.0, category="threshold", message="SSH Brute Force",
        )

        signals = engine.build_signals_from_detections(
            rule_detections=[auth_fail, first_seen_fail, brute_force],
            ml_results=[],
            baseline_scores={},
        )
        by_rule = {s.details["rule_id"]: s for s in signals}

        assert by_rule["AUTH-002"].score < 70.0
        assert by_rule["AUTH-002"].weight < 1.5
        assert by_rule["AUTH-002"].details["tuned_for_noise"] == "single_login_failure"

        assert by_rule["FIRST-001"].score < 30.0
        assert by_rule["FIRST-001"].weight < 1.0
        assert by_rule["FIRST-001"].details["tuned_for_noise"] == "first_seen_failed_login"

        assert by_rule["THR-001"].score == 80.0
        assert by_rule["THR-001"].details.get("tuned_for_noise") is None

    def test_risk_tuning_reduces_connection_flood_noise_without_touching_bruteforce(self, engine):
        from core.detection import DetectionResult
        flood = DetectionResult(
            triggered=True, rule_id="THR-003", severity="medium",
            score=60.0, category="network", message="SSH bağlantı fırtınası",
        )
        brute_force = DetectionResult(
            triggered=True, rule_id="THR-001", severity="high",
            score=80.0, category="auth", message="SSH Brute Force",
        )

        signals = engine.build_signals_from_detections(
            rule_detections=[flood, brute_force],
            ml_results=[],
            baseline_scores={},
        )
        by_rule = {s.details["rule_id"]: s for s in signals}

        assert by_rule["THR-003"].score < 60.0
        assert by_rule["THR-003"].weight < 1.0
        assert by_rule["THR-003"].details["tuned_for_noise"] == "connection_flood"
        assert by_rule["THR-001"].score == 80.0

    def test_risk_tuning_acceptance_noise_soft_but_escalation_intact(self, engine):
        from core.detection import DetectionResult
        noisy_fail = DetectionResult(
            triggered=True, rule_id="AUTH-002", severity="high",
            score=70.0, category="auth", message="SSH giriş başarısız",
        )
        first_seen_fail = DetectionResult(
            triggered=True, rule_id="FIRST-001", severity="low",
            score=30.0, category="auth", message="Yeni kaynak IP ilk kez başarısız SSH denemesi yaptı",
        )
        meaningful_novelty = DetectionResult(
            triggered=True, rule_id="FIRST-002", severity="medium",
            score=40.0, category="auth", message="Kullanıcı bu IP üzerinden ilk kez başarılı giriş yaptı",
        )
        brute_force = DetectionResult(
            triggered=True, rule_id="THR-001", severity="high",
            score=80.0, category="auth", message="SSH Brute Force",
        )

        signals = engine.build_signals_from_detections(
            rule_detections=[noisy_fail, first_seen_fail, meaningful_novelty, brute_force],
            ml_results=[],
            baseline_scores={},
        )
        by_rule = {s.details["rule_id"]: s for s in signals}

        assert by_rule["AUTH-002"].score < 70.0
        assert by_rule["FIRST-001"].score < 30.0
        assert by_rule["FIRST-002"].score < 40.0
        assert by_rule["THR-001"].score == 80.0
        assert by_rule["THR-001"].score > by_rule["AUTH-002"].score
        assert by_rule["FIRST-002"].details.get("tuned_for_noise") == "first_seen_failed_login"


class TestCorrelationEngine:

    def test_alert_to_alert_chain_produces_incident(self):
        engine = CorrelationEngine(config={}, db=None)

        first = engine.process({
            "id": 1,
            "ts": 1000.0,
            "rule_id": "ML-IF",
            "severity": "high",
            "risk_score": 82.0,
            "category": "ml",
            "message": "Isolation forest anomaly",
            "host": "srv1",
            "raw_event": {"src_ip": "203.0.113.10", "user": "alice"},
            "details": {},
        })
        assert first == []

        second = engine.process({
            "id": 2,
            "ts": 1030.0,
            "rule_id": "PROC-001",
            "severity": "critical",
            "risk_score": 95.0,
            "category": "process",
            "message": "Dangerous command execution",
            "host": "srv1",
            "raw_event": {"src_ip": "203.0.113.10", "user": "alice"},
            "details": {},
        })

        assert any(inc.chain_name == "CHAIN-006" for inc in second), second

    def test_dns_beacon_then_suspicious_exec_produces_incident(self):
        engine = CorrelationEngine(config={}, db=None)

        first = engine.process({
            "id": 10,
            "ts": 1000.0,
            "rule_id": "THR-020",
            "severity": "high",
            "risk_score": 76.0,
            "category": "threshold",
            "message": "Beacon-like long DNS queries",
            "host": "srv-dns",
            "raw_event": {"src_ip": "192.0.2.10", "action": "dns_query", "outcome": "unknown"},
            "details": {},
        })
        assert first == []

        second = engine.process({
            "id": 11,
            "ts": 1045.0,
            "rule_id": "NET-012",
            "severity": "critical",
            "risk_score": 95.0,
            "category": "network",
            "message": "Shell process dış bağlantı açtı",
            "host": "srv-dns",
            "raw_event": {"src_ip": "192.0.2.10", "action": "suspicious_outbound", "outcome": "success"},
            "details": {},
        })

        assert any(inc.chain_name == "CHAIN-007" for inc in second), second

    def test_webshell_staging_then_outbound_produces_incident(self):
        engine = CorrelationEngine(config={}, db=None)

        first = engine.process({
            "id": 20,
            "ts": 2000.0,
            "rule_id": "WEB-004",
            "severity": "critical",
            "risk_score": 95.0,
            "category": "web_attack",
            "message": "Web shell yükleme girişimi",
            "host": "web-1",
            "raw_event": {"src_ip": "198.51.100.25", "action": "shell_upload", "outcome": "success"},
            "details": {},
        })
        assert first == []

        second = engine.process({
            "id": 21,
            "ts": 2055.0,
            "rule_id": "PROC-003",
            "severity": "high",
            "risk_score": 75.0,
            "category": "process",
            "message": "Servis sürecinden beklenmedik shell oluşturuldu",
            "host": "web-1",
            "raw_event": {"src_ip": "198.51.100.25", "action": "exec", "outcome": "success"},
            "details": {},
        })

        assert any(inc.chain_name == "CHAIN-008" for inc in second), second

    def test_credential_abuse_then_sudo_then_persistence_produces_incidents(self):
        engine = CorrelationEngine(config={}, db=None)

        first = engine.process({
            "id": 30,
            "ts": 3000.0,
            "rule_id": "SEQ-021",
            "severity": "medium",
            "risk_score": 55.0,
            "category": "sequence",
            "message": "Identity Failure → Success",
            "host": "id-1",
            "raw_event": {"user": "alice", "action": "identity_login", "outcome": "success"},
            "details": {},
        })
        assert first == []

        second = engine.process({
            "id": 31,
            "ts": 3060.0,
            "rule_id": "SEQ-039",
            "severity": "high",
            "risk_score": 76.0,
            "category": "sequence",
            "message": "Identity Success → Sudo/Su",
            "host": "id-1",
            "raw_event": {"user": "alice", "action": "sudo", "outcome": "success"},
            "details": {},
        })
        assert any(inc.chain_name == "CHAIN-009" for inc in second), second

        third = engine.process({
            "id": 32,
            "ts": 3120.0,
            "rule_id": "PERS-006",
            "severity": "critical",
            "risk_score": 90.0,
            "category": "auth",
            "message": "sudo ile SSH authorized_keys dosyasına yazıldı",
            "host": "id-1",
            "raw_event": {"user": "alice", "action": "sudo", "outcome": "success"},
            "details": {},
        })

        assert any(inc.chain_name == "CHAIN-010" for inc in third), third

    def test_package_tamper_then_systemd_drift_produces_incident(self):
        engine = CorrelationEngine(config={}, db=None)

        first = engine.process({
            "id": 40,
            "ts": 4000.0,
            "rule_id": "PKG-010",
            "severity": "critical",
            "risk_score": 95.0,
            "category": "process",
            "message": "Güvenlik aracı kaldırıldı",
            "host": "pkg-1",
            "raw_event": {"action": "security_tool_removed", "outcome": "success"},
            "details": {},
        })
        assert first == []

        second = engine.process({
            "id": 41,
            "ts": 4200.0,
            "rule_id": "FIM-SYSTEMD-001",
            "severity": "critical",
            "risk_score": 95.0,
            "category": "persistence",
            "message": "Yeni systemd unit: /etc/systemd/system/backdoor.service",
            "host": "pkg-1",
            "raw_event": {"action": "service_created", "outcome": "success"},
            "details": {},
        })

        assert any(inc.chain_name == "CHAIN-011" for inc in second), second

    def test_chain_cooldown_suppresses_duplicate_incidents_for_same_entity(self):
        engine = CorrelationEngine(config={}, db=None)

        engine.process({
            "id": 50,
            "ts": 5000.0,
            "rule_id": "WEB-004",
            "severity": "critical",
            "risk_score": 95.0,
            "category": "web_attack",
            "message": "Web shell yükleme girişimi",
            "host": "web-2",
            "raw_event": {"src_ip": "198.51.100.77", "action": "shell_upload", "outcome": "success"},
            "details": {},
        })
        first_hit = engine.process({
            "id": 51,
            "ts": 5050.0,
            "rule_id": "NET-013",
            "severity": "medium",
            "risk_score": 65.0,
            "category": "network",
            "message": "İndirme aracı dış bağlantı",
            "host": "web-2",
            "raw_event": {"src_ip": "198.51.100.77", "action": "suspicious_outbound", "outcome": "success"},
            "details": {},
        })
        assert any(inc.chain_name == "CHAIN-008" for inc in first_hit), first_hit

        duplicate = engine.process({
            "id": 52,
            "ts": 5070.0,
            "rule_id": "NET-013",
            "severity": "medium",
            "risk_score": 65.0,
            "category": "network",
            "message": "İndirme aracı dış bağlantı",
            "host": "web-2",
            "raw_event": {"src_ip": "198.51.100.77", "action": "suspicious_outbound", "outcome": "success"},
            "details": {},
        })

        assert duplicate == []

    def test_rhel_localhost_aliases_do_not_create_cross_host_incident(self):
        engine = CorrelationEngine(config={}, db=None)

        first = engine.process({
            "id": 900,
            "ts": 9000.0,
            "rule_id": "AUTH-003",
            "severity": "medium",
            "risk_score": 60.0,
            "category": "auth",
            "message": "Invalid user",
            "host": "localhost.localdomain",
            "raw_event": {
                "src_ip": "192.168.91.129",
                "user": "invaliduser_1",
                "action": "ssh_login",
                "outcome": "failure",
                "distro_family": "rhel",
            },
            "details": {},
        })
        second = engine.process({
            "id": 901,
            "ts": 9001.0,
            "rule_id": "THR-004",
            "severity": "high",
            "risk_score": 70.0,
            "category": "threshold",
            "message": "Enumeration",
            "host": "localhost",
            "raw_event": {
                "src_ip": "192.168.91.129",
                "user": "invaliduser_2",
                "action": "ssh_login",
                "outcome": "failure",
                "distro_family": "rhel",
            },
            "details": {},
        })

        assert not any(inc.chain_name == "cross_host_lateral" for inc in first + second)

    def test_rhel_genuinely_different_hosts_still_create_cross_host_incident(self):
        engine = CorrelationEngine(config={}, db=None)

        engine.process({
            "id": 910,
            "ts": 9100.0,
            "rule_id": "AUTH-003",
            "severity": "medium",
            "risk_score": 60.0,
            "category": "auth",
            "message": "Invalid user",
            "host": "rocky-web-01",
            "raw_event": {
                "src_ip": "192.168.91.129",
                "user": "invaliduser_1",
                "action": "ssh_login",
                "outcome": "failure",
                "distro_family": "rhel",
            },
            "details": {},
        })
        second = engine.process({
            "id": 911,
            "ts": 9101.0,
            "rule_id": "AUTH-003",
            "severity": "medium",
            "risk_score": 60.0,
            "category": "auth",
            "message": "Invalid user",
            "host": "rocky-db-01",
            "raw_event": {
                "src_ip": "192.168.91.129",
                "user": "invaliduser_2",
                "action": "ssh_login",
                "outcome": "failure",
                "distro_family": "rhel",
            },
            "details": {},
        })

        assert any(inc.chain_name == "cross_host_lateral" for inc in second)

    def test_non_rhel_localhost_alias_behavior_is_unchanged(self):
        engine = CorrelationEngine(config={}, db=None)

        engine.process({
            "id": 920,
            "ts": 9200.0,
            "rule_id": "AUTH-003",
            "severity": "medium",
            "risk_score": 60.0,
            "category": "auth",
            "message": "Invalid user",
            "host": "localhost.localdomain",
            "raw_event": {
                "src_ip": "192.168.91.129",
                "user": "invaliduser_1",
                "action": "ssh_invalid_user",
                "outcome": "failure",
                "distro_family": "debian",
            },
            "details": {},
        })
        second = engine.process({
            "id": 921,
            "ts": 9201.0,
            "rule_id": "AUTH-003",
            "severity": "medium",
            "risk_score": 60.0,
            "category": "auth",
            "message": "Invalid user",
            "host": "localhost",
            "raw_event": {
                "src_ip": "192.168.91.129",
                "user": "invaliduser_2",
                "action": "ssh_invalid_user",
                "outcome": "failure",
                "distro_family": "debian",
            },
            "details": {},
        })

        assert any(inc.chain_name == "cross_host_lateral" for inc in second)
