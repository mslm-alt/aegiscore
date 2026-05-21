import json
from collections import defaultdict, deque
from types import SimpleNamespace

from core.detection import ThresholdDetector
from core.ml.learning_guard import ConfidenceScorer, RareEventFilter, AnomalyGuard, BaselineValidator
from core.state_manager import RuntimeStateStore
from main import SIEMPipeline


def _make_pipeline(tmp_path):
    pipeline = SIEMPipeline.__new__(SIEMPipeline)
    pipeline._runtime_state = RuntimeStateStore(state_dir=str(tmp_path))
    pipeline._event_count = 0
    pipeline._alert_count = 0
    pipeline._incident_count = 0
    pipeline._source_stats = {}
    pipeline._source_coverage = {
        "degraded": False,
        "enabled_count": 0,
        "available_count": 0,
        "unavailable_count": 0,
        "available": [],
        "unavailable": {},
        "optional_disabled": [],
    }
    pipeline._dedup_cache = {}
    pipeline._xsrc_dedup_cache = {}
    pipeline._auth_shadow_peer_cache = {}
    pipeline._shadow_dedup_stats = {
        "shadow_dedup_peer_cached": {"total": 0, "by_source": {}},
        "shadow_dedup_suppressed": {"total": 0, "by_source": {}},
        "shadow_dedup_kept_no_peer": {"total": 0, "by_source": {}},
        "shadow_dedup_kept_high_priority": {"total": 0, "by_source": {}},
    }
    pipeline._auditd_noise_suppressed_stats = {"total": 0, "by_reason": {}}
    pipeline.conf_scorer = ConfidenceScorer()
    pipeline.rare_filter = RareEventFilter()
    pipeline.anomaly_guard = AnomalyGuard()
    pipeline.baseline_validator = BaselineValidator(clean_window_hours=2.0)
    pipeline.detection = SimpleNamespace(threshold=ThresholdDetector({}))
    pipeline.correlation = SimpleNamespace(chain=SimpleNamespace(_fired={}))
    return pipeline


def test_runtime_components_restore_after_checkpoint_restart(tmp_path):
    pipeline = _make_pipeline(tmp_path)
    pipeline._event_count = 42
    pipeline._alert_count = 7
    pipeline._incident_count = 3
    pipeline._source_stats = {"auth.log": {"count": 9, "last_ts": 111.0, "error_count": 1}}
    pipeline._source_coverage = {
        "degraded": True,
        "enabled_count": 2,
        "available_count": 1,
        "unavailable_count": 1,
        "available": ["auth.log"],
        "unavailable": {"auditd": "path_missing"},
        "optional_disabled": ["mail"],
    }
    pipeline._dedup_cache = {"evt1": 10.0}
    pipeline._xsrc_dedup_cache = {"x1": 11.0}
    pipeline._auth_shadow_peer_cache = {"login_failed|root|203.0.113.5": (12.0, "auth_log")}
    pipeline._shadow_dedup_stats["shadow_dedup_suppressed"] = {"total": 2, "by_source": {"accounting": 2}}

    pipeline.conf_scorer._user_first_seen = {"alice": 100.0}
    pipeline.conf_scorer._binary_freq = {"sshd": 4}
    pipeline.conf_scorer._hour_counts = defaultdict(int, {3: 2})
    pipeline.conf_scorer._total = 8

    pipeline.rare_filter._seen["auth.log|auth|ssh_login|alice"].extend([20.0, 21.0])
    pipeline.anomaly_guard._counters["login_fail:203.0.113.5"].extend([30.0, 31.0])

    pipeline.baseline_validator._last_critical_ts = 40.0
    pipeline.baseline_validator._last_ioc_ts = 41.0
    pipeline.baseline_validator._last_bruteforce_ts = 42.0
    pipeline.baseline_validator._block_reason = "restore-me"

    pipeline.detection.threshold._windows["THR-001:ssh_login:failure:src_ip|203.0.113.5"].extend([50.0, 51.0])
    pipeline.detection.threshold._cooldowns = {"_cd:THR-001:ssh_login:failure:src_ip|203.0.113.5": 52.0}
    pipeline.correlation.chain._fired = {("entity-1", "CHAIN-1"): 53.0}

    pipeline._save_runtime_state_on_shutdown()

    restarted = _make_pipeline(tmp_path)
    assert restarted._runtime_state._restored is True
    restarted._restore_runtime_components()

    assert restarted._source_stats == {"auth.log": {"count": 9, "last_ts": 111.0, "error_count": 1}}
    assert restarted._source_coverage["degraded"] is True
    assert restarted._source_coverage["unavailable"] == {"auditd": "path_missing"}
    assert restarted._dedup_cache == {"evt1": 10.0}
    assert restarted._xsrc_dedup_cache == {"x1": 11.0}
    assert restarted._auth_shadow_peer_cache == {"login_failed|root|203.0.113.5": [12.0, "auth_log"]}
    assert restarted._shadow_dedup_stats["shadow_dedup_suppressed"]["total"] == 2

    assert restarted.conf_scorer._user_first_seen == {"alice": 100.0}
    assert restarted.conf_scorer._binary_freq == {"sshd": 4}
    assert restarted.conf_scorer._hour_counts[3] == 2
    assert restarted.conf_scorer._total == 8

    assert list(restarted.rare_filter._seen["auth.log|auth|ssh_login|alice"]) == [20.0, 21.0]
    assert list(restarted.anomaly_guard._counters["login_fail:203.0.113.5"]) == [30.0, 31.0]

    assert restarted.baseline_validator._last_critical_ts == 40.0
    assert restarted.baseline_validator._last_ioc_ts == 41.0
    assert restarted.baseline_validator._last_bruteforce_ts == 42.0
    assert restarted.baseline_validator._block_reason == "restore-me"

    key = "THR-001:ssh_login:failure:src_ip|203.0.113.5"
    assert list(restarted.detection.threshold._windows[key]) == [50.0, 51.0]
    assert restarted.detection.threshold._cooldowns == {"_cd:THR-001:ssh_login:failure:src_ip|203.0.113.5": 52.0}
    assert restarted.correlation.chain._fired == {("entity-1", "CHAIN-1"): 53.0}


def test_runtime_threshold_restore_handles_distinct_windows(tmp_path):
    pipeline = _make_pipeline(tmp_path)
    key = "THR-010:ssh_login:failure:src_ip|192.168.1.182"
    pipeline.detection.threshold._windows[key].append((60.0, "alice"))
    pipeline.detection.threshold._windows[key].append((61.0, "bob"))

    pipeline._save_runtime_state_on_shutdown()

    restarted = _make_pipeline(tmp_path)
    restarted._restore_runtime_components()

    assert list(restarted.detection.threshold._windows[key]) == [
        (60.0, "alice"),
        (61.0, "bob"),
    ]


def test_runtime_component_restore_tolerates_missing_or_older_fields(tmp_path):
    store = RuntimeStateStore(state_dir=str(tmp_path))
    store.total_events = 5
    store.save(
        clean_shutdown=True,
        runtime_components={
            "confidence_scorer": {"total": 2},
            "threshold_detector": {"cooldowns": {"_cd:key": 1.0}},
            "correlation_chain": {"fired": {"broken-key": 2.0}},
        },
    )

    restarted = _make_pipeline(tmp_path)
    restarted._restore_runtime_components()

    assert restarted.conf_scorer._total == 2
    assert restarted.conf_scorer._user_first_seen == {}
    assert restarted.detection.threshold._cooldowns == {"_cd:key": 1.0}
    assert restarted.correlation.chain._fired == {}
    assert restarted._auth_shadow_peer_cache == {}
    assert restarted._source_coverage["degraded"] is False


def test_runtime_component_restore_degrades_safely_on_malformed_component(tmp_path):
    store = RuntimeStateStore(state_dir=str(tmp_path))
    store.save(
        clean_shutdown=True,
        runtime_components={
            "confidence_scorer": {
                "user_first_seen": {"alice": "bad-ts"},
                "total": 3,
            },
            "threshold_detector": {
                "cooldowns": {"_cd:key": 1.0},
            },
            "source_stats": {
                "auth.log": {"count": 2, "last_ts": 10.0, "error_count": 0},
            },
            "source_coverage": {
                "degraded": True,
                "enabled_count": 1,
                "available_count": 0,
                "unavailable_count": 1,
                "available": [],
                "unavailable": {"auditd": "path_missing"},
                "optional_disabled": [],
            },
        },
    )

    restarted = _make_pipeline(tmp_path)
    restarted._restore_runtime_components()

    assert restarted._source_stats == {"auth.log": {"count": 2, "last_ts": 10.0, "error_count": 0}}
    assert restarted._source_coverage["degraded"] is True
    assert restarted.detection.threshold._cooldowns == {"_cd:key": 1.0}
    assert restarted.conf_scorer._user_first_seen == {}
    assert restarted._runtime_state.runtime_restore_health["degraded"] is True
    assert any(x.startswith("confidence_scorer:") for x in restarted._runtime_state.runtime_restore_health["failed_components"])


def test_auditd_noise_stats_persist_in_runtime_checkpoint_and_phase_state(tmp_path):
    pipeline = _make_pipeline(tmp_path)
    pipeline._auditd_noise_suppressed_stats = {
        "total": 4,
        "by_reason": {
            "container_runtime_syscall": 3,
            "container_runtime_file_access": 1,
        },
    }
    phase_state_file = tmp_path / "phase_state.json"

    def _save_phase():
        phase_state_file.write_text(json.dumps({"stats": {"total_events": 0}}))

    pipeline.phase = SimpleNamespace(
        _save=_save_phase,
        _state_file=phase_state_file,
    )

    assert pipeline._save_phase_state() is True
    saved_phase_state = json.loads(phase_state_file.read_text())
    assert saved_phase_state["auditd_noise_suppressed"] == pipeline._auditd_noise_suppressed_stats

    pipeline._save_runtime_state_on_shutdown()

    restarted = _make_pipeline(tmp_path)
    restarted._restore_runtime_components()

    assert restarted._auditd_noise_suppressed_stats == pipeline._auditd_noise_suppressed_stats
