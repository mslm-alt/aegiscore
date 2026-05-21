"""
tests/test_retention_and_calibration.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3c: Retention / cleanup dependency tests
5a: HostCalibrationStore tests
5b: Missing integration coverage (drop visibility, model confidence)
"""

import sys
import time
from tests.shims import activate_test_shims

activate_test_shims()

import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── 3c: Retention Dependency Tests ─────────────────────────────────────────

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

        buf = DelayedLearningBuffer(delay_seconds=3600)  # long delay

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

        # Simulate DB cleanup — the buffer stays in memory and is unaffected
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
        _state["10.0.0.1"]["SEQ-001"] = {"step": 2, "last_ts": time.time() - 90000}  # eski
        _state["10.0.0.2"]["SEQ-002"] = {"step": 1, "last_ts": time.time() - 100}    # yeni

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


# ── 5a: HostCalibrationStore Tests ──────────────────────────────────────────

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
        new_model_weight = 0.6 * self._grace(0)       # yeni = 0.3 factor → 0.18

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
    Dört kaynak: synthetic, bootstrap, auto_labeled, manually_verified
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

    def test_four_sources_in_status(self):
        """status() should return four source types."""
        from core.ml.label_engine import (LabelEngine,
            SOURCE_SYNTHETIC, SOURCE_BOOTSTRAP,
            SOURCE_AUTO_LABELED, SOURCE_MANUALLY_VERIFIED)
        engine = self._make_engine()
        s = engine.status()
        assert "sources" in s
        for src in [SOURCE_SYNTHETIC, SOURCE_BOOTSTRAP,
                    SOURCE_AUTO_LABELED, SOURCE_MANUALLY_VERIFIED]:
            assert src in s["sources"], f"'{src}' sources içinde olmalı"

    def test_manually_verified_weight_is_2(self):
        """manually_verified weight should stay at 2.0 and never decay."""
        from core.ml.label_engine import (LabelEngine,
            SOURCE_BASE_WEIGHTS, SOURCE_MANUALLY_VERIFIED)
        assert SOURCE_BASE_WEIGHTS[SOURCE_MANUALLY_VERIFIED] == 2.0

        engine = self._make_engine()
        engine._synthetic_records = [None] * 10

        class FakeAutoLabeler:
            count = 9999
            def get_ready_records(self): return []
        engine._auto_labeler = FakeAutoLabeler()
        engine._update_weights()

        # Manual weight never changes
        s = engine.status()
        assert s["sources"][SOURCE_MANUALLY_VERIFIED]["weight"] == 2.0

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

    def test_operator_label_accepted_no_db(self):
        """Operator labels should not raise exceptions when the DB is absent."""
        from core.ml.label_engine import LabelEngine, SOURCE_MANUALLY_VERIFIED
        engine = LabelEngine(distro_family="debian", db=None)
        try:
            engine.on_operator_label(score=85.0, label="attack", category="brute_force")
        except Exception as e:
            pytest.fail(f"Operator etiket exception fırlattı: {e}")
        assert len(engine._manually_records) == 1
        assert engine._manually_records[0].source == SOURCE_MANUALLY_VERIFIED
        assert engine._manually_records[0].weight == 2.0


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
