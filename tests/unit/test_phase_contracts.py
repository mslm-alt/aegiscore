import json
import threading
from types import MethodType, SimpleNamespace
from unittest.mock import Mock

from core.detection import DetectionResult
from core.ml.instant_ml import MLResult
from core.normalize import NormalizedEvent
from core.phase_manager import PHASE_ACTIVE_LAYERS, Phase, PhaseManager
from core.risk import DEFAULT_WEIGHTS, WeightedRiskScorer, RiskSignal
from main import SIEMPipeline


def _evt():
    return NormalizedEvent(
        ts=1710000000.0,
        source="auth.log",
        category="auth",
        action="ssh_login",
        outcome="success",
        user="alice",
        src_ip="203.0.113.10",
        process="sshd",
        host="srv1",
        message="accepted password",
        fields={},
        distro_family="debian",
    )


class _PhaseStub:
    def __init__(self, current_phase, active_layers):
        self.current_phase = current_phase
        self._active_layers = set(active_layers)

    def is_active(self, layer):
        return layer in self._active_layers

    def update(self, event):
        return None

    def record_duplicate(self, kind="exact"):
        return None

    def record_parse_fail(self):
        return None


def _make_pipeline(phase_value, active_layers):
    pipeline = SIEMPipeline.__new__(SIEMPipeline)
    pipeline.phase = _PhaseStub(phase_value, active_layers)
    pipeline._source_stats = {}
    pipeline._dedup_cache = {}
    pipeline._xsrc_dedup_cache = {}
    pipeline._auth_shadow_peer_cache = {}
    pipeline._shadow_dedup_stats = {}
    pipeline._auditd_noise_suppressed_stats = {"total": 0, "by_reason": {}}
    pipeline._dedup_ttl = 60
    pipeline._xsrc_dedup_ttl = 5
    pipeline._auth_shadow_peer_ttl = 5
    pipeline._auth_shadow_dedup_enabled = False
    pipeline._event_count = 0
    pipeline._alert_count = 0
    pipeline._incident_count = 0
    pipeline._last_event_ts = 0.0
    pipeline._pending_event = None
    pipeline._user_output_suppression = {}
    pipeline._user_output_ttl = 30
    pipeline._noisy_log_counters = {}
    pipeline._ml_train_dedup_cache = {}
    pipeline._ml_train_dedup_checks = 0
    pipeline._ml_train_dedup_ttl = 15
    pipeline._ml_train_dedup_cleanup_every = 128
    pipeline._ml_train_dedup_max_entries = 4096
    pipeline._ml_shadow_enabled = False
    pipeline._ml_shadow_write_file = False
    pipeline._ml_shadow_path = "data/ml_shadow.jsonl"
    pipeline._ml_shadow_sample_rate = 1.0
    pipeline._ml_shadow_sources = []
    pipeline._ml_shadow_include_raw_context = False
    pipeline._ml_shadow_lock = threading.Lock()
    pipeline._process_lock = SimpleNamespace()
    pipeline._autosave = lambda: None
    pipeline._should_train_ml_event = lambda event: True
    pipeline._should_suppress_wtmp_shadow_copy = lambda event, now: False
    pipeline._process_risk_modifier = lambda event: 0.0
    pipeline._min_risk_for_alert = lambda rule_id: 0.0
    pipeline._should_emit_user_output = lambda kind, key_parts: False
    pipeline.write_file = False
    pipeline.config = {"risk": {"cooldown": {"default_seconds": 300}}}

    event = _evt()
    pipeline.normalizer = SimpleNamespace(normalize=lambda raw, source: event)
    pipeline.detection = SimpleNamespace(analyze=Mock(return_value=[]))
    pipeline.anomaly_guard = SimpleNamespace(record=Mock(return_value=None))
    pipeline.baseline_validator = SimpleNamespace(
        can_advance_to_phase1=lambda: (True, ""),
        record_incident=lambda severity: None,
        record_ioc=lambda: None,
        record_bruteforce=lambda: None,
    )
    pipeline.delayed_buffer = SimpleNamespace(
        SUSPICIOUS_ACTIONS=set(),
        add=Mock(),
        mark_ioc=Mock(),
        mark_alarm=Mock(),
    )
    pipeline.ml_ctrl = SimpleNamespace(
        should_learn=True,
        is_source_excluded=lambda source: False,
        on_incident=lambda severity, incident_id: None,
    )
    pipeline.conf_scorer = SimpleNamespace(score=Mock(return_value=1.0))
    pipeline.rare_filter = SimpleNamespace(is_rare=Mock(return_value=False))
    pipeline.distro_adapter = SimpleNamespace(
        should_train=lambda source, action: True,
        adjust_anomaly_score=lambda score, source, action: score,
    )
    pipeline.calibration = SimpleNamespace(
        update=Mock(),
        calibrate=lambda model, score: {
            "raw_score": score,
            "calibrated_score": score,
            "label_adjusted": False,
            "threshold": 70.0,
            "should_alert": True,
            "warmup_progress": 100.0,
            "is_warmed_up": True,
            "sample_count": 42,
        },
        status=lambda: {"warmup": {"warmed_up": True, "progress_pct": 100.0, "sample_count": 42}},
    )
    pipeline.instant_ml = SimpleNamespace(process=Mock(return_value=[]))
    pipeline.baseline = SimpleNamespace(update=Mock(return_value=({}, [])))
    pipeline.risk = SimpleNamespace(
        build_signals_from_detections=Mock(return_value=[]),
        assess=Mock(return_value=None),
        _asset_map=SimpleNamespace(multiplier=lambda host: 1.0),
    )
    pipeline.host_baseline = SimpleNamespace(
        update=Mock(),
        anomaly_score=Mock(return_value=0.0),
    )
    pipeline._runtime_state = SimpleNamespace(
        record_event=Mock(),
        record_alert_layer=Mock(),
        status=lambda: {},
    )
    pipeline.db = SimpleNamespace(
        insert_event=lambda **kwargs: None,
        insert_alert=lambda alert: 1,
        is_in_cooldown=lambda rule_id, entity_key: False,
        set_cooldown=lambda rule_id, entity_key, seconds: None,
    )
    pipeline.correlation = SimpleNamespace(process=lambda alert: [])
    pipeline.incident = SimpleNamespace(process_alert=lambda alert, risk_score=None: None)
    pipeline.label_engine = None
    pipeline.llm = None

    emitted = []

    def _capture_emit(self, event_obj, rule_id, severity, score, message, category="", tag="",
                      detection_layer="rule", cal_score=0, rule_file="", mitre_tactic="",
                      mitre_technique="", tags=None, details=None):
        emitted.append({
            "rule_id": rule_id,
            "severity": severity,
            "score": score,
            "category": category,
            "detection_layer": detection_layer,
            "rule_file": rule_file,
        })

    pipeline._emit_alert = MethodType(_capture_emit, pipeline)
    return pipeline, emitted


def test_phase_active_layers_contract_matrix():
    assert PHASE_ACTIVE_LAYERS[Phase.PHASE_0]["instant_ml"] is False
    assert PHASE_ACTIVE_LAYERS[Phase.PHASE_0]["baseline"] is False
    assert PHASE_ACTIVE_LAYERS[Phase.PHASE_0]["correlation"] is True

    assert PHASE_ACTIVE_LAYERS[Phase.PHASE_1]["instant_ml"] is True
    assert PHASE_ACTIVE_LAYERS[Phase.PHASE_1]["baseline"] is False
    assert PHASE_ACTIVE_LAYERS[Phase.PHASE_2]["instant_ml"] is True
    assert PHASE_ACTIVE_LAYERS[Phase.PHASE_2]["baseline"] is True

    assert PHASE_ACTIVE_LAYERS[Phase.PHASE_3]["instant_ml"] is True
    assert PHASE_ACTIVE_LAYERS[Phase.PHASE_3]["baseline"] is True


def test_phase_0_instant_ml_learns_but_does_not_emit_alerts():
    pipeline, emitted = _make_pipeline(Phase.PHASE_0, active_layers=[])
    pipeline.instant_ml.process.return_value = [
        MLResult(model="isolation_forest", score=91.0, anomaly=True),
    ]

    pipeline._process_event_locked("raw", "auth.log")

    pipeline.instant_ml.process.assert_called_once()
    assert [x for x in emitted if x["rule_id"].startswith("ML-")] == []


def test_phase_1_instant_ml_support_is_active():
    pipeline, emitted = _make_pipeline(Phase.PHASE_1, active_layers=["instant_ml"])
    pipeline.instant_ml.process.return_value = [
        MLResult(model="isolation_forest", score=91.0, anomaly=True),
    ]

    pipeline._process_event_locked("raw", "auth.log")

    pipeline.instant_ml.process.assert_called_once()
    assert [x["rule_id"] for x in emitted if x["rule_id"].startswith("ML-")] == ["ML-ISO"]


def test_ml_shadow_mode_disabled_does_not_create_jsonl(tmp_path):
    pipeline, _ = _make_pipeline(Phase.PHASE_1, active_layers=["instant_ml"])
    pipeline._ml_shadow_path = str(tmp_path / "ml_shadow.jsonl")
    pipeline.instant_ml.process.return_value = [
        MLResult(model="isolation_forest", score=91.0, anomaly=True),
    ]

    pipeline._process_event_locked("raw", "auth.log")

    assert not (tmp_path / "ml_shadow.jsonl").exists()


def test_ml_shadow_mode_enabled_writes_jsonl_without_changing_alerts(tmp_path):
    off_pipeline, off_emitted = _make_pipeline(Phase.PHASE_1, active_layers=["instant_ml"])
    on_pipeline, on_emitted = _make_pipeline(Phase.PHASE_1, active_layers=["instant_ml"])
    shadow_path = tmp_path / "ml_shadow.jsonl"

    ml_result = MLResult(model="isolation_forest", score=91.0, anomaly=True)
    off_pipeline.instant_ml.process.return_value = [ml_result]
    on_pipeline.instant_ml.process.return_value = [ml_result]

    on_pipeline._ml_shadow_enabled = True
    on_pipeline._ml_shadow_write_file = True
    on_pipeline._ml_shadow_path = str(shadow_path)

    off_pipeline._process_event_locked("raw", "auth.log")
    on_pipeline._process_event_locked("raw", "auth.log")

    assert off_emitted == on_emitted
    assert shadow_path.exists()

    lines = shadow_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["phase"] == Phase.PHASE_1
    assert payload["trainable"] is True
    assert payload["shadow_verdict"]["would_alert"] is True
    assert payload["shadow_verdict"]["reason"] == "ml_threshold_passed"
    assert payload["risk"]["final_score"] == 0.0
    assert payload["risk"]["should_alert"] is False
    assert payload["host_baseline_score"] == 0.0
    assert payload["baseline_scores"] == {}
    assert payload["warmup_status"]["warmed_up"] is True
    assert payload["model_ready"]["isolation_forest"] is True
    assert payload["ml_scores"]["isolation_forest"]["score"] == 91.0
    assert payload["calibration_scores"]["isolation_forest"]["evaluated"] is True
    assert payload["calibration_scores"]["isolation_forest"]["would_alert"] is True
    assert "context" not in payload


def test_phase_1_baseline_is_not_primary_decider():
    pipeline, emitted = _make_pipeline(Phase.PHASE_1, active_layers=["instant_ml"])
    pipeline.baseline.update.return_value = ({"user_baseline": 72.0}, [])

    pipeline._process_event_locked("raw", "auth.log")

    pipeline.baseline.update.assert_called_once()
    args = pipeline.risk.build_signals_from_detections.call_args.args
    assert args[2] == {}
    assert [x for x in emitted if x["rule_id"].startswith("PTREE-")] == []


def test_phase_2_baseline_support_is_active():
    pipeline, emitted = _make_pipeline(Phase.PHASE_2, active_layers=["instant_ml", "baseline"])
    pipeline.baseline.update.return_value = ({"user_baseline": 61.0}, [])

    pipeline._process_event_locked("raw", "auth.log")

    args = pipeline.risk.build_signals_from_detections.call_args.args
    assert args[2] == {"user_baseline": 61.0}
    assert [x for x in emitted if x["rule_id"].startswith("PTREE-")] == []


def test_phase_2_process_tree_baseline_can_still_alert():
    pipeline, emitted = _make_pipeline(Phase.PHASE_2, active_layers=["instant_ml", "baseline"])
    ptree = DetectionResult(
        triggered=True,
        rule_id="PTREE-001",
        severity="critical",
        score=90.0,
        category="process",
        message="Anormal process hiyerarşisi",
        rule_file="process_tree_baseline",
        mitre_tactic="TA0002",
        mitre_technique="T1059",
        tags=["process-tree"],
    )
    pipeline.baseline.update.return_value = ({}, [ptree])

    pipeline._process_event_locked("raw", "auth.log")

    assert "PTREE-001" in [x["rule_id"] for x in emitted]


def test_phase_3_keeps_baseline_outputs_active():
    pipeline, emitted = _make_pipeline(
        Phase.PHASE_3,
        active_layers=["instant_ml", "baseline"],
    )
    pipeline.baseline.update.return_value = ({"user_baseline": 71.0}, [])

    pipeline._process_event_locked("raw", "auth.log")

    args = pipeline.risk.build_signals_from_detections.call_args.args
    assert args[2] == {"user_baseline": 71.0}


def test_monitor_alerts_keep_monitor_layer_mapping():
    pipeline, _ = _make_pipeline(Phase.PHASE_3, active_layers=["instant_ml", "baseline"])
    captured = []

    def _insert_alert(alert):
        captured.append(alert)
        return 1

    pipeline.db.insert_alert = _insert_alert
    pipeline._should_emit_user_output = lambda kind, key_parts: False

    event = _evt()
    SIEMPipeline._emit_alert(
        pipeline,
        event,
        rule_id="FIM-001",
        severity="high",
        score=80.0,
        message="critical file changed",
        category="filesystem",
    )

    assert captured[0]["detection_layer"] == "monitor"
    pipeline._runtime_state.record_alert_layer.assert_called_with("monitor")


def test_ioc_rule_and_regex_confidence_do_not_decay_with_phase(tmp_path):
    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False)
    pm._current_phase = Phase.PHASE_3
    pm._phase_entered_at[int(Phase.PHASE_3)] = 0.0

    assert pm.get_model_confidence("rule_engine") == 1.0
    assert pm.get_model_confidence("ioc") == 1.0
    assert pm.get_model_confidence("regex") == 1.0
    assert pm.get_model_confidence("correlation") == 1.0


def test_phase_entered_at_persists_across_reload(tmp_path):
    phase_ts = 1234.5

    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False)
    pm._current_phase = Phase.PHASE_2
    pm._phase_entered_at = {
        int(Phase.PHASE_0): 100.0,
        int(Phase.PHASE_2): phase_ts,
    }
    pm._save()

    reloaded = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False)

    assert reloaded.current_phase == Phase.PHASE_2
    assert reloaded._phase_entered_at[int(Phase.PHASE_2)] == phase_ts


def test_phase_entered_at_missing_current_phase_defaults_on_reload(tmp_path):
    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False)
    pm._current_phase = Phase.PHASE_1
    pm._phase_entered_at = {int(Phase.PHASE_0): 42.0}
    pm._save()

    reloaded = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False)

    assert reloaded.current_phase == Phase.PHASE_1
    assert int(Phase.PHASE_1) in reloaded._phase_entered_at
    assert isinstance(reloaded._phase_entered_at[int(Phase.PHASE_1)], float)


def test_phase_status_marks_offline_snapshot_when_db_is_absent(tmp_path):
    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False)

    status = pm.get_status()

    assert status["accounting_mode"] == "offline_snapshot"
    assert "Offline snapshot" in status["accounting_note"]


def test_phase_status_marks_db_reconciled_when_db_is_wired(tmp_path):
    db = SimpleNamespace(
        _execute=lambda *_args, **_kwargs: {"value": "42"},
    )

    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False, db=db)
    status = pm.get_status()

    assert status["accounting_mode"] == "db_reconciled"
    assert status["stats"]["total_events"] == 42
    assert "DB-reconciled" in status["accounting_note"]


def test_phase_status_recomputes_dup_rate_after_db_event_reconcile(tmp_path):
    phase_state = tmp_path / "phase_state.json"
    phase_state.write_text(json.dumps({
        "current_phase": 0,
        "stats": {
            "total_events": 10,
            "duplicate_count": 2,
            "telemetry_duplicate_count": 0,
            "parse_fail_count": 1,
        },
    }), encoding="utf-8")
    db = SimpleNamespace(
        _execute=lambda *_args, **_kwargs: {"value": "25"},
    )

    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False, db=db)
    status = pm.get_status()

    assert status["stats"]["total_events"] == 25
    assert status["stats"]["dup_rate"] == round(3 / 28, 3)


def test_phase_state_preserves_duplicate_and_parse_fail_breakdowns(tmp_path):
    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False)
    pm.stats.record_duplicate(kind="exact_same_source", source="auditd")
    pm.stats.record_parse_fail(
        source="mail",
        reason="normalize_none",
        parser="file",
        distro_family="debian",
        path="/var/log/mail.log",
        sample="token=*** authentication failure",
    )
    pm._save()

    reloaded = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False)
    status = reloaded.get_status()

    assert status["stats"]["duplicate_breakdown_by_source"] == {"auditd": 1}
    assert status["stats"]["duplicate_breakdown_by_kind"] == {"exact_same_source": 1}
    assert status["stats"]["parse_fail_breakdown_by_source"] == {"mail": 1}
    assert status["stats"]["parse_fail_breakdown_by_reason"] == {"normalize_none": 1}
    assert status["stats"]["parse_fail_breakdown_by_parser"] == {"file": 1}
    assert status["stats"]["parse_fail_breakdown_by_distro"] == {"debian": 1}
    assert status["stats"]["parse_fail_breakdown_by_path"] == {"/var/log/mail.log": 1}
    assert status["stats"]["parse_fail_samples"] == [{
        "source": "mail",
        "reason": "normalize_none",
        "parser": "file",
        "distro_family": "debian",
        "path": "/var/log/mail.log",
        "sample": "token=*** authentication failure",
    }]


def test_phase_status_marks_stale_duplicate_counter_when_live_db_is_empty(tmp_path):
    phase_state = tmp_path / "phase_state.json"
    phase_state.write_text(json.dumps({
        "current_phase": 0,
        "stats": {
            "total_events": 40,
            "duplicate_count": 24,
            "telemetry_duplicate_count": 3,
            "parse_fail_count": 1,
        },
    }), encoding="utf-8")

    class _EmptyLiveDb:
        def _execute(self, sql, params=None, fetch=None):
            text = " ".join(str(sql).split())
            if "system_config" in text:
                return {"value": "40"}
            if "FROM events_recent" in text:
                return {"count": 0}
            if "FROM dedup_cache" in text:
                return {"count": 0}
            raise AssertionError(text)

    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False, db=_EmptyLiveDb())
    status = pm.get_status()
    quality_gate = next(item for item in status["next_phase"]["criteria"] if item["name"] == "Veri kalitesi")

    assert status["stats"]["duplicate_rate_verified"] is False
    assert status["stats"]["duplicate_rate_source"] == "phase_state"
    assert status["stats"]["live_db_event_count"] == 0
    assert status["stats"]["phase_event_count"] == 40
    assert status["stats"]["duplicate_counter_stale_possible"] is True
    assert "canlı DB ile doğrulanamadı" in quality_gate["message"]
    assert "Veri kalite oranı yüksek" not in quality_gate["message"]


def test_phase_status_keeps_warning_when_live_duplicate_evidence_is_verified(tmp_path):
    phase_state = tmp_path / "phase_state.json"
    phase_state.write_text(json.dumps({
        "current_phase": 0,
        "stats": {
            "total_events": 100,
            "duplicate_count": 35,
            "duplicate_breakdown_by_source": {"auditd": 30},
            "duplicate_breakdown_by_kind": {"exact_same_source": 35},
            "telemetry_duplicate_count": 10,
            "parse_fail_count": 5,
        },
    }), encoding="utf-8")

    class _VerifiedLiveDb:
        def _execute(self, sql, params=None, fetch=None):
            text = " ".join(str(sql).split())
            if "system_config" in text:
                return {"value": "100"}
            if "SELECT COUNT(*) AS count FROM events_recent" in text:
                return {"count": 100}
            if "SELECT COUNT(*) AS count FROM dedup_cache" in text:
                return {"count": 9}
            if "GROUP BY COALESCE(category, '')" in text:
                return [{"name": "auth", "count": 22}]
            if "GROUP BY COALESCE(action, '')" in text:
                return [{"name": "execve", "count": 19}]
            raise AssertionError(text)

    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False, db=_VerifiedLiveDb())
    status = pm.get_status()
    quality_gate = next(item for item in status["next_phase"]["criteria"] if item["name"] == "Veri kalitesi")

    assert status["stats"]["duplicate_rate_verified"] is True
    assert status["stats"]["duplicate_rate_source"] == "live_runtime"
    assert status["stats"]["top_duplicate_source"] == "auditd"
    assert status["stats"]["top_duplicate_kind"] == "exact_same_source"
    assert status["stats"]["top_duplicate_categories"] == [{"name": "auth", "count": 22}]
    assert status["stats"]["top_duplicate_actions"] == [{"name": "execve", "count": 19}]
    assert "Veri kalite oranı yüksek" in quality_gate["message"]
    assert "source=auditd" in quality_gate["message"]
    assert "kind=exact_same_source" in quality_gate["message"]


def test_ml_and_baseline_weights_do_not_override_high_confidence_deterministic_signal():
    scorer = WeightedRiskScorer()
    signals = [
        RiskSignal(source="rule_engine", score=95.0, ts=1.0),
        RiskSignal(source="isolation_forest", score=70.0, ts=1.0),
        RiskSignal(source="user_baseline", score=65.0, ts=1.0),
    ]

    total, breakdown = scorer.calculate(signals)

    assert DEFAULT_WEIGHTS["rule_engine"] >= DEFAULT_WEIGHTS["isolation_forest"]
    assert DEFAULT_WEIGHTS["rule_engine"] > DEFAULT_WEIGHTS["user_baseline"]
    assert breakdown["rule_engine"]["contribution"] > breakdown["user_baseline"]["contribution"]
    assert total >= 75.0


def test_phase_query_count_accepts_only_allowlisted_table_names(tmp_path):
    calls = []

    class _Db:
        def _execute(self, sql, params=None, fetch=None):
            calls.append((sql, params, fetch))
            return {"count": 12}

    pm = PhaseManager(config={}, state_dir=str(tmp_path), announce_startup=False, db=_Db())
    calls.clear()

    assert pm._query_count("events_recent") == 12
    assert pm._query_count("alerts; DROP TABLE alerts;--") is None
    assert calls == [("SELECT COUNT(*) AS count FROM events_recent", None, "one")]
