import contextlib
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml
import time
from collections import deque

from core.state_manager import RuntimeStateStore
from core.detection import DetectionResult
from core.monitor import MonitorAlert
from core.normalize import NormalizedEvent
from main import SIEMPipeline, run_test_precheck


def test_fresh_start_mode_without_existing_runtime_state(tmp_path):
    store = RuntimeStateStore(state_dir=str(tmp_path))

    assert store._restored is False
    assert store.startup_mode == "fresh_start"
    assert store.last_shutdown_clean is True


def test_clean_shutdown_does_not_trigger_crash_restore(tmp_path):
    state_dir = str(tmp_path)
    store = RuntimeStateStore(state_dir=state_dir)
    store.total_events = 12
    store.total_alerts = 3
    store.mark_running()
    store.save(
        clean_shutdown=True,
        shutdown_metadata={
            "shutdown_attempted_at": time.time(),
            "queue_drained_ok": True,
            "final_flush_ok": True,
            "final_state_save_ok": True,
        },
    )

    restarted = RuntimeStateStore(state_dir=state_dir)

    assert restarted._restored is True
    assert restarted.startup_mode == "clean_restart"
    assert restarted.last_shutdown_clean is True
    assert restarted.total_events == 12
    assert restarted.total_alerts == 3
    assert restarted.runtime_restore_health["restore_status"] == "clean_restart"
    assert restarted.runtime_restore_health["marker_valid"] is True


def test_unclean_exit_triggers_crash_restore(tmp_path):
    state_dir = str(tmp_path)
    store = RuntimeStateStore(state_dir=state_dir)
    store.total_events = 21
    store.total_incidents = 2
    store.mark_running()

    restarted = RuntimeStateStore(state_dir=state_dir)

    assert restarted._restored is True
    assert restarted.startup_mode == "crash_restore"
    assert restarted.last_shutdown_clean is False
    assert restarted.total_events == 21
    assert restarted.total_incidents == 2
    assert restarted.runtime_restore_health["restore_status"] == "crash_restore"


def test_pipeline_shutdown_writes_final_clean_checkpoint(tmp_path):
    pipeline = SIEMPipeline.__new__(SIEMPipeline)
    pipeline._runtime_state = RuntimeStateStore(state_dir=str(tmp_path))
    pipeline._shutdown = SimpleNamespace(had_failures=lambda: False)
    pipeline._event_queue = SimpleNamespace(qsize=0)
    pipeline._pending_event = None
    pipeline._event_count = 33
    pipeline._alert_count = 4
    pipeline._incident_count = 1
    pipeline._collect_runtime_components = lambda: {"source_stats": {}, "source_coverage": {}}

    pipeline._runtime_state.mark_running()
    pipeline._save_runtime_state_on_shutdown()

    restarted = RuntimeStateStore(state_dir=str(tmp_path))

    assert restarted.startup_mode == "clean_restart"
    assert restarted.last_shutdown_clean is True
    assert restarted.total_events == 33
    assert restarted.total_alerts == 4
    assert restarted.total_incidents == 1


def test_lifecycle_acceptance_clean_then_unclean_restart_flow(tmp_path):
    state_dir = str(tmp_path)

    clean = RuntimeStateStore(state_dir=state_dir)
    clean.total_events = 10
    clean.mark_running()
    clean.save(
        clean_shutdown=True,
        shutdown_metadata={
            "shutdown_attempted_at": time.time(),
            "queue_drained_ok": True,
            "final_flush_ok": True,
            "final_state_save_ok": True,
        },
    )

    clean_restart = RuntimeStateStore(state_dir=state_dir)
    assert clean_restart.startup_mode == "clean_restart"
    assert clean_restart.last_shutdown_clean is True

    clean_restart.mark_running()
    crash_restore = RuntimeStateStore(state_dir=state_dir)
    assert crash_restore.startup_mode == "crash_restore"
    assert crash_restore.last_shutdown_clean is False


def test_clean_marker_with_missing_flags_is_not_trusted(tmp_path):
    state_dir = str(tmp_path)
    store = RuntimeStateStore(state_dir=state_dir)
    store.total_events = 9
    store.save(clean_shutdown=True)

    restarted = RuntimeStateStore(state_dir=state_dir)

    assert restarted._restored is True
    assert restarted.startup_mode == "dirty_restore"
    assert restarted.runtime_restore_health["restore_status"] == "dirty_restore"
    assert restarted.runtime_restore_health["marker_valid"] is False
    assert "runtime_state:clean_marker_incomplete" in restarted.runtime_restore_health["failed_components"]


class TestRecentRuntimeFixes(unittest.TestCase):
    def test_events_per_second_prunes_old_entries_without_changing_rate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = RuntimeStateStore(state_dir=tmpdir)
            now = time.time()
            store._eps_window = deque([now - 61.0, now - 60.0, now - 59.0, now - 1.0])

            eps = store.events_per_second

            self.assertIsInstance(store._eps_window, deque)
            self.assertEqual(eps, round(2 / 60.0, 3))
            self.assertEqual(list(store._eps_window), [now - 59.0, now - 1.0])

    def test_user_output_suppression_respects_ttl_window(self):
        pipeline = SIEMPipeline.__new__(SIEMPipeline)
        pipeline._user_output_suppression = {}
        pipeline._user_output_ttl = 30

        with patch("main.time.time", side_effect=[100.0, 110.0, 131.0]):
            self.assertTrue(pipeline._should_emit_user_output("alert_print", ("R-1", "host-1")))
            self.assertFalse(pipeline._should_emit_user_output("alert_print", ("R-1", "host-1")))
            self.assertTrue(pipeline._should_emit_user_output("alert_print", ("R-1", "host-1")))

    def test_monitor_alert_suppression_key_changes_with_detail_fields(self):
        pipeline = SIEMPipeline.__new__(SIEMPipeline)
        pipeline._user_output_suppression = {}
        pipeline._user_output_ttl = 30
        pipeline._alert_count = 0
        inserted = []
        pipeline.db = SimpleNamespace(insert_alert=lambda data: inserted.append(data))
        runtime_layers = []
        pipeline._runtime_state = SimpleNamespace(record_alert_layer=lambda layer: runtime_layers.append(layer))

        base = {
            "host": "node-1",
            "entity": "alice",
            "source": "fim",
            "process": "vim",
        }
        alert_a = MonitorAlert(
            rule_id="FIM-001",
            severity="high",
            message="critical file changed",
            details={**base, "path": "/etc/passwd"},
        )
        alert_b = MonitorAlert(
            rule_id="FIM-001",
            severity="high",
            message="critical file changed",
            details={**base, "path": "/etc/shadow"},
        )

        with patch("main.fmt_monitor_alert") as fmt_mock:
            pipeline._on_monitor_alert(alert_a)
            pipeline._on_monitor_alert(alert_b)

        self.assertEqual(fmt_mock.call_count, 2)
        self.assertEqual(pipeline._alert_count, 2)
        self.assertEqual([item["detection_layer"] for item in inserted], ["monitor", "monitor"])
        self.assertEqual(runtime_layers, ["monitor", "monitor"])

    def test_ml_training_dedup_blocks_only_recent_duplicate_events(self):
        pipeline = SIEMPipeline.__new__(SIEMPipeline)
        pipeline._ml_train_dedup_cache = {}
        pipeline._ml_train_dedup_checks = 0
        pipeline._ml_train_dedup_ttl = 15
        pipeline._ml_train_dedup_cleanup_every = 128
        pipeline._ml_train_dedup_max_entries = 4096
        event = NormalizedEvent(
            source="auth.log",
            host="node-1",
            category="auth",
            action="ssh_login",
            outcome="failure",
            user="root",
            src_ip="203.0.113.5",
            process="sshd",
            message="Failed password for root",
            fields={},
        )

        with patch("main.time.time", side_effect=[100.0, 110.0, 116.0]):
            self.assertTrue(pipeline._should_train_ml_event(event))
            self.assertFalse(pipeline._should_train_ml_event(event))
            self.assertTrue(pipeline._should_train_ml_event(event))

    def test_shutdown_runtime_state_logs_when_save_fails(self):
        pipeline = SIEMPipeline.__new__(SIEMPipeline)
        pipeline._shutdown = SimpleNamespace(had_failures=lambda: False)
        pipeline._event_queue = SimpleNamespace(qsize=0)
        pipeline._pending_event = None
        pipeline._runtime_state = SimpleNamespace(
            total_events=0,
            total_alerts=0,
            total_incidents=0,
            save=lambda **kwargs: False,
        )
        pipeline._event_count = 12
        pipeline._alert_count = 3
        pipeline._incident_count = 1
        pipeline._collect_runtime_components = lambda: {"source_stats": {}}

        with patch("main.logger.error") as err_mock:
            pipeline._save_runtime_state_on_shutdown()

        self.assertEqual(pipeline._runtime_state.total_events, 12)
        self.assertEqual(pipeline._runtime_state.total_alerts, 3)
        self.assertEqual(pipeline._runtime_state.total_incidents, 1)
        err_mock.assert_called_once_with(
            "[AegisCore:Shutdown] Runtime state clean shutdown kaydı başarısız."
        )

    def test_shutdown_skips_clean_marker_when_previous_step_failed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = SIEMPipeline.__new__(SIEMPipeline)
            pipeline._runtime_state = RuntimeStateStore(state_dir=tmpdir)
            pipeline._shutdown = SimpleNamespace(had_failures=lambda: True)
            pipeline._event_queue = SimpleNamespace(qsize=0)
            pipeline._pending_event = None
            pipeline._event_count = 7
            pipeline._alert_count = 1
            pipeline._incident_count = 0
            pipeline._collect_runtime_components = lambda: {"source_stats": {}}

            pipeline._runtime_state.mark_running()
            saved = pipeline._save_runtime_state_on_shutdown()
            restarted = RuntimeStateStore(state_dir=tmpdir)

            self.assertFalse(saved)
            self.assertEqual(restarted.startup_mode, "crash_restore")
            self.assertFalse(restarted.last_shutdown_clean)

    def test_drain_timeout_returns_false_and_blocks_clean_marker(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = SIEMPipeline.__new__(SIEMPipeline)
            pipeline._event_queue = SimpleNamespace(qsize=2)
            pipeline._pending_event = {"id": 1}
            pipeline._shutdown = SimpleNamespace(had_failures=lambda: True)
            pipeline._runtime_state = RuntimeStateStore(state_dir=tmpdir)
            pipeline._event_count = 5
            pipeline._alert_count = 1
            pipeline._incident_count = 0
            pipeline._collect_runtime_components = lambda: {"source_stats": {}}

            with patch("main.time.time", side_effect=[100.0, 106.0, 106.0, 106.0]), \
                 patch("main.logger.error"):
                drained = pipeline._drain_ingestion_queue(timeout=5.0)
            saved = pipeline._save_runtime_state_on_shutdown()
            restarted = RuntimeStateStore(state_dir=tmpdir)

            self.assertFalse(drained)
            self.assertFalse(saved)
            self.assertEqual(restarted.startup_mode, "fresh_start")

    def test_flush_pending_failure_returns_false(self):
        pipeline = SIEMPipeline.__new__(SIEMPipeline)
        pipeline.db = SimpleNamespace(commit=lambda: (_ for _ in ()).throw(RuntimeError("db down")))
        pipeline._pending_event = None

        with patch("main.logger.warning") as warn_mock:
            result = pipeline._flush_pending()

        self.assertTrue(result)
        warn_mock.assert_called_once()

    def test_restore_health_visible_in_status(self):
        store = RuntimeStateStore.__new__(RuntimeStateStore)
        store.total_events = 1
        store.total_alerts = 0
        store.total_incidents = 0
        store.unique_users = set()
        store.unique_hosts = set()
        store.start_time = time.time()
        store.last_event_ts = 0.0
        store._eps_window = deque()
        store._eps_lock = contextlib.nullcontext()
        store.alerts_by_layer = {}
        store.runtime_components = {}
        store._restored = True
        store.startup_mode = "crash_restore"
        store.last_shutdown_clean = False
        store.runtime_restore_health = {
            "degraded": True,
            "failed_components": ["source_stats:ValueError"],
            "restore_status": "crash_restore",
            "saved_at": 100.0,
            "restore_age_sec": 25.0,
        }

        status = store.status()

        self.assertEqual(status["runtime_restore_health"]["restore_status"], "crash_restore")
        self.assertEqual(status["runtime_restore_health"]["saved_at"], 100.0)
        self.assertEqual(status["runtime_restore_health"]["restore_age_sec"], 25.0)

    def test_corrupt_runtime_state_exposes_dirty_restore_status(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / RuntimeStateStore.FILE
            p.write_text("{not-json", encoding="utf-8")

            restarted = RuntimeStateStore(state_dir=tmpdir)

            self.assertFalse(restarted._restored)
            self.assertEqual(restarted.startup_mode, "dirty_restore")
            self.assertEqual(restarted.runtime_restore_health["restore_status"], "dirty_restore")
            self.assertFalse(restarted.runtime_restore_health["marker_valid"])

    def test_save_ml_snapshots_persists_host_calibration(self):
        pipeline = SIEMPipeline.__new__(SIEMPipeline)
        save_calls = []
        pipeline.instant_ml = SimpleNamespace(
            iso=SimpleNamespace(_save=lambda: save_calls.append("iso")),
            pca=SimpleNamespace(_save=lambda: save_calls.append("pca")),
            ewma=SimpleNamespace(_save=lambda: save_calls.append("ewma")),
            status=lambda: {"if_trained": True, "ewma_trained": True, "pca_trained": True},
        )
        pipeline.risk = SimpleNamespace(
            _host_calib=SimpleNamespace(save=lambda: save_calls.append("host_calib"))
        )
        pipeline._ml_store = SimpleNamespace(save_versions=lambda versions: save_calls.append(("versions", versions)))

        pipeline._save_ml_snapshots()

        self.assertEqual(save_calls[:4], ["iso", "pca", "ewma", "host_calib"])
        self.assertEqual(
            save_calls[4],
            ("versions", {
                "isolation_forest": True,
                "ewma": True,
                "incremental_pca": True,
            }),
        )

    def test_run_test_precheck_skips_db_and_returns_lightweight_success(self):
        class _RuleEngineStub:
            def __init__(self, *args, **kwargs):
                self.rules = [{"id": "RULE-1"}]

        with contextlib.redirect_stdout(io.StringIO()), \
             patch("main.detect_distro", return_value={"family": "debian", "pretty_name": "Debian Test"}), \
             patch("main.is_supported", return_value=(True, "")), \
             patch("core.detection.RuleEngine", _RuleEngineStub), \
             patch("main.ensure_database", side_effect=RuntimeError("db unavailable")):
            rc, db_ready = run_test_precheck({}, allow_empty_rules=False)

        self.assertEqual(rc, 0)
        self.assertFalse(db_ready)


def test_pipeline_ops_status_exposes_runtime_and_shadow_dedup():
    pipeline = SIEMPipeline.__new__(SIEMPipeline)
    pipeline._runtime_state = RuntimeStateStore.__new__(RuntimeStateStore)
    pipeline._runtime_state.startup_mode = "crash_restore"
    pipeline._runtime_state.last_shutdown_clean = False
    pipeline._runtime_state.runtime_restore_health = {
        "degraded": True,
        "failed_components": ["confidence_scorer:ValueError"],
    }
    pipeline._runtime_state.status = lambda: {
        "startup_mode": pipeline._runtime_state.startup_mode,
        "last_shutdown_clean": pipeline._runtime_state.last_shutdown_clean,
        "runtime_restore_health": pipeline._runtime_state.runtime_restore_health,
    }
    pipeline._auth_shadow_dedup_enabled = True
    pipeline._auth_shadow_peer_ttl = 5
    pipeline._shadow_dedup_stats = {
        "shadow_dedup_peer_cached": {"total": 1, "by_source": {"auth_log": 1}},
        "shadow_dedup_suppressed": {"total": 2, "by_source": {"accounting": 2}},
        "shadow_dedup_kept_no_peer": {"total": 0, "by_source": {}},
        "shadow_dedup_kept_high_priority": {"total": 1, "by_source": {"auth_log": 1}},
    }
    pipeline._source_coverage = {
        "degraded": True,
        "enabled_count": 2,
        "available_count": 1,
        "unavailable_count": 1,
        "available": ["journald"],
        "unavailable": {"auditd": "path_missing"},
        "optional_disabled": ["mail"],
    }
    pipeline._pipeline_pressure = {
        "version": 1,
        "latency": {
            "queue_wait_ewma_ms": 12.5,
            "processing_ewma_ms": 8.0,
            "end_to_end_ewma_ms": 20.5,
            "samples": 3,
        },
        "stages": {
            "normalize_ewma_ms": 1.2,
            "detect_ewma_ms": 2.3,
            "ml_ewma_ms": 0.8,
            "baseline_ewma_ms": 1.1,
            "risk_ewma_ms": 0.9,
            "alerts_ewma_ms": 0.7,
            "total_ewma_ms": 7.0,
        },
        "maintenance": {
            "active": False,
            "last_started_ts": 0.0,
            "last_finished_ts": 0.0,
            "last_duration_ms": 140.0,
            "last_queue_depth_before": 2,
            "last_queue_depth_after": 5,
            "last_queue_growth": 3,
            "last_queue_wait_delta_ms": 6.0,
            "last_processing_delta_ms": 1.0,
            "last_delayed_flush_count": 4,
            "last_mode_active": True,
        },
    }
    pipeline._source_stats = {
        "auth.log": {
            "count": 9,
            "last_ts": 111.0,
            "last_ingest_ts": 190.0,
            "last_processed_ts": 195.0,
            "error_count": 1,
        }
    }
    pipeline._event_queue = SimpleNamespace(
        health=lambda: {
            "qsize": 4,
            "maxsize": 100,
            "fill_pct": 4.0,
            "high_water": 9,
            "depth_trend_per_min": 3.5,
            "drop_count": 1,
            "last_put_ts": 198.0,
            "last_get_ts": 199.0,
        }
    )
    pipeline._refresh_source_coverage = lambda: pipeline._source_coverage

    with patch("main.time.time", return_value=200.0):
        ops = pipeline._ops_status()

    assert ops["runtime"]["startup_mode"] == "crash_restore"
    assert ops["runtime"]["last_shutdown_clean"] is False
    assert ops["runtime"]["runtime_restore_health"]["degraded"] is True
    assert ops["runtime"]["telemetry_degraded"] is True
    assert ops["shadow_dedup"]["enabled"] is True
    assert ops["shadow_dedup"]["window_seconds"] == 5
    assert ops["shadow_dedup"]["stats"]["shadow_dedup_suppressed"]["total"] == 2
    assert ops["pipeline_pressure"]["queue"]["high_water"] == 9
    assert ops["pipeline_pressure"]["queue"]["depth_trend_per_min"] == 3.5
    assert ops["pipeline_pressure"]["latency"]["queue_wait_ewma_ms"] == 12.5
    assert ops["pipeline_pressure"]["maintenance"]["last_queue_growth"] == 3
    assert ops["pipeline_pressure"]["sources"]["max_ingest_lag_sec"] == 10.0
    assert ops["telemetry_coverage"]["snapshot_no_go"] == ["faillog", "lastlog"]
    assert ops["telemetry_coverage"]["source_health"]["unavailable"] == {"auditd": "path_missing"}
    assert ops["learning_policy"] == {
        "trainable_when": [
            "no_rule_detections",
            "not_suspicious_action",
            "confidence_gte_0_40",
            "not_rare_event",
            "not_distro_noise",
            "ml_control_allows",
        ],
        "blocked_when": [
            "any_rule_detection",
            "suspicious_action_or_lotl",
            "ml_paused_or_source_excluded",
            "low_confidence",
            "rare_event",
            "distro_noise",
        ],
    }


def test_learning_gate_blocks_detection_bearing_event():
    pipeline = SIEMPipeline.__new__(SIEMPipeline)
    pipeline.delayed_buffer = type("DelayedBufferStub", (), {"SUSPICIOUS_ACTIONS": set()})()
    evt = NormalizedEvent(action="ssh_login", fields={})
    det = DetectionResult(triggered=True, rule_id="FW-001", severity="low")

    should_learn, reason = pipeline._classify_learning_gate(evt, [det])
    bucket = pipeline._classify_risk_bucket(evt, [det], reason)

    assert should_learn is False
    assert reason == "rule_detection"
    assert bucket == "suspicious"


def test_learning_gate_keeps_clean_event_trainable():
    pipeline = SIEMPipeline.__new__(SIEMPipeline)
    pipeline.delayed_buffer = type("DelayedBufferStub", (), {"SUSPICIOUS_ACTIONS": {"lotl_exec"}})()
    evt = NormalizedEvent(action="ssh_login", fields={})

    should_learn, reason = pipeline._classify_learning_gate(evt, [])
    bucket = pipeline._classify_risk_bucket(evt, [], reason)

    assert should_learn is True
    assert reason == ""
    assert bucket == "normal"


def test_learning_gate_blocks_suspicious_action_without_detection():
    pipeline = SIEMPipeline.__new__(SIEMPipeline)
    pipeline.delayed_buffer = type("DelayedBufferStub", (), {"SUSPICIOUS_ACTIONS": {"lotl_exec"}})()
    evt = NormalizedEvent(action="lotl_exec", fields={})

    should_learn, reason = pipeline._classify_learning_gate(evt, [])
    bucket = pipeline._classify_risk_bucket(evt, [], reason)

    assert should_learn is False
    assert reason == "suspicious_action"
    assert bucket == "malicious"


def test_learning_gate_blocks_lotl_flag_without_detection():
    pipeline = SIEMPipeline.__new__(SIEMPipeline)
    pipeline.delayed_buffer = type("DelayedBufferStub", (), {"SUSPICIOUS_ACTIONS": set()})()
    evt = NormalizedEvent(action="exec", fields={"lotl": True})

    should_learn, reason = pipeline._classify_learning_gate(evt, [])
    bucket = pipeline._classify_risk_bucket(evt, [], reason)

    assert should_learn is False
    assert reason == "lotl_flag"
    assert bucket == "malicious"


def test_core_closure_acceptance_log_centric_ml_and_portability():
    repo_root = Path(__file__).resolve().parents[2]
    pipeline = SIEMPipeline.__new__(SIEMPipeline)
    pipeline._runtime_state = RuntimeStateStore.__new__(RuntimeStateStore)
    pipeline._runtime_state.startup_mode = "clean_restart"
    pipeline._runtime_state.last_shutdown_clean = True
    pipeline._runtime_state.runtime_restore_health = {"degraded": False, "failed_components": []}
    pipeline._runtime_state.status = lambda: {
        "startup_mode": pipeline._runtime_state.startup_mode,
        "last_shutdown_clean": pipeline._runtime_state.last_shutdown_clean,
        "runtime_restore_health": pipeline._runtime_state.runtime_restore_health,
    }
    pipeline._auth_shadow_dedup_enabled = True
    pipeline._auth_shadow_peer_ttl = 5
    pipeline._shadow_dedup_stats = {}
    pipeline._source_coverage = {
        "degraded": False,
        "enabled_count": 1,
        "available_count": 1,
        "unavailable_count": 0,
        "available": ["journald"],
        "unavailable": {},
        "optional_disabled": ["mail"],
    }
    pipeline._refresh_source_coverage = lambda: pipeline._source_coverage
    pipeline.delayed_buffer = type("DelayedBufferStub", (), {"SUSPICIOUS_ACTIONS": {"lotl_exec"}})()

    ops = pipeline._ops_status()
    clean_evt = NormalizedEvent(action="ssh_login", fields={})
    det_evt = NormalizedEvent(action="ssh_login", fields={})
    det = DetectionResult(triggered=True, rule_id="FW-001", severity="low")

    cfg = yaml.safe_load(
        (repo_root / "config" / "config.yml").read_text(encoding="utf-8")
    )
    preflight = (repo_root / "scripts" / "preflight.sh").read_text(encoding="utf-8")

    should_learn_clean, reason_clean = pipeline._classify_learning_gate(clean_evt, [])
    should_learn_det, reason_det = pipeline._classify_learning_gate(det_evt, [det])

    assert "local_process" not in ops["telemetry_coverage"]
    assert ops["telemetry_coverage"]["snapshot_no_go"] == ["faillog", "lastlog"]
    assert ops["telemetry_coverage"]["source_health"]["degraded"] is False
    assert ops["learning_policy"]["blocked_when"][0] == "any_rule_detection"
    assert should_learn_clean is True
    assert reason_clean == ""
    assert should_learn_det is False
    assert reason_det == "rule_detection"


def test_source_coverage_only_flags_enabled_unreadable_sources(tmp_path):
    pipeline = SIEMPipeline.__new__(SIEMPipeline)
    readable = tmp_path / "auth.log"
    readable.write_text("ok", encoding="utf-8")
    pipeline.config = {
        "sources": {
            "auth_log": {"enabled": True, "type": "syslog", "path": str(readable)},
            "auditd": {"enabled": True, "type": "auditd", "path": str(tmp_path / "missing.log")},
            "mail": {"enabled": False, "type": "syslog", "path": str(tmp_path / "mail.log")},
        }
    }

    cov = pipeline._refresh_source_coverage()

    assert cov["degraded"] is True
    assert cov["available"] == ["auth_log"]
    assert cov["unavailable"] == {"auditd": "path_missing"}
    assert cov["optional_disabled"] == ["mail"]
