import pytest

import main as main_module
from app.alert_explanations import (
    build_alert_explanation_metadata,
    build_deterministic_alert_explanation,
    build_ml_alert_explanation_metadata,
)
from app.ml.active_reporting import compute_ml_family_support_score
from app.ml.specs import ML_FAMILY_READINESS

TURKISH_FALLBACK_TOKENS = (
    "ç", "ğ", "ı", "İ", "ö", "ş", "ü",
    "Açıklama", "Öneri", "Kanıt", "Risk özeti", "Kural", "Uyarı",
    "tespit edildi", "girişimi", "kullanıcı", "kaynak",
)


def _sample_event():
    return {
        "source": "auditd",
        "category": "process",
        "action": "exec",
        "host": "host-1",
        "username": "root",
        "src_ip": "127.0.0.1",
        "process": "/usr/bin/sudo",
    }


def _sample_readiness():
    return {
        "family_id": "ML-PROC",
        "status": "needs_more_data",
        "reason": "insufficient_time_coverage",
        "can_score_support": True,
        "phase_gate_ok": True,
        "event_threshold_ok": True,
        "normal_label_threshold_ok": True,
        "suspicious_label_threshold_ok": True,
        "field_quality_ok": True,
        "time_coverage_ok": False,
        "trust_support_ok": True,
        "metadata_support_ok": True,
    }


def test_rule_alert_explanation_metadata_has_required_fields():
    metadata = build_alert_explanation_metadata(
        rule_id="AUTH-004",
        rule_name="sudo root escalation or abuse",
        severity="high",
        risk_score=75.0,
        event=_sample_event(),
        message="sudo escalation behaviour matched",
        key_evidence=["rule_id=AUTH-004", "process=/usr/bin/sudo"],
    )
    for field in (
        "rule_id",
        "rule_name",
        "severity",
        "risk_score",
        "matched_event_fields",
        "key_evidence",
        "why_triggered_human",
        "recommended_review_steps",
    ):
        assert field in metadata
    assert metadata["why_triggered_human"]
    assert metadata["db_write_attempted"] is False


def test_ml_alert_explanation_metadata_has_required_fields():
    support = compute_ml_family_support_score(
        family_id="ML-PROC",
        event={**_sample_event(), "ts": 1715400000.0},
        readiness_result=_sample_readiness(),
        family_config=ML_FAMILY_READINESS["ML-PROC"],
        baseline_summary={"expected_sources": ["auditd"], "expected_actions": ["exec"], "expected_categories": ["process"]},
    )
    metadata = build_ml_alert_explanation_metadata(
        support_score=support,
        readiness_result=_sample_readiness(),
        supporting_event_fields={**_sample_event(), "ml_label": "suspicious_process"},
    )
    for field in (
        "ml_family",
        "ml_label",
        "ml_family_status",
        "readiness_reason",
        "support_or_active",
        "model_score",
        "normalized_score",
        "confidence",
        "top_features",
        "time_context",
        "baseline_deviation",
        "supporting_event_fields",
        "why_triggered_human",
        "recommended_review_steps",
    ):
        assert field in metadata
    assert metadata["why_triggered_human"]
    assert metadata["time_context"]
    assert metadata["top_features"]


def test_ml_alert_explanation_metadata_carries_no_action_contract():
    support = compute_ml_family_support_score(
        family_id="ML-PROC",
        event={**_sample_event(), "ts": 1715400000.0},
        readiness_result=_sample_readiness(),
        family_config=ML_FAMILY_READINESS["ML-PROC"],
        baseline_summary={},
    )
    metadata = build_ml_alert_explanation_metadata(
        support_score=support,
        readiness_result=_sample_readiness(),
        supporting_event_fields={**_sample_event(), "ml_label": "suspicious_process"},
    )
    assert metadata["no_action_contract"] is True
    assert metadata["action_taken"] is False
    assert metadata["can_emit_alert"] is False


def test_explanation_helpers_do_not_change_runtime_behavior_flags():
    rule_meta = build_alert_explanation_metadata(
        rule_id="AUTH-004",
        rule_name="sudo root escalation or abuse",
        severity="high",
        risk_score=75.0,
        event=_sample_event(),
        message="sudo escalation behaviour matched",
    )
    support = compute_ml_family_support_score(
        family_id="ML-PROC",
        event={**_sample_event(), "ts": 1715400000.0},
        readiness_result=_sample_readiness(),
        family_config=ML_FAMILY_READINESS["ML-PROC"],
        baseline_summary={},
    )
    ml_meta = build_ml_alert_explanation_metadata(
        support_score=support,
        readiness_result=_sample_readiness(),
        supporting_event_fields={**_sample_event(), "ml_label": "suspicious_process"},
    )
    assert rule_meta["runtime_output_changed"] is False
    assert rule_meta["risk_score_changed"] is False
    assert ml_meta["runtime_output_changed"] is False
    assert ml_meta["risk_score_changed"] is False


def test_rule_alert_explanation_metadata_localizes_english_fields():
    metadata = build_alert_explanation_metadata(
        rule_id="AUTH-004",
        rule_name="sudo root escalation or abuse",
        severity="high",
        risk_score=75.0,
        event=_sample_event(),
        message="sudo escalation behaviour matched",
        language="en",
    )

    assert metadata["language"] == "en"
    assert "sudo/root privilege behavior" in metadata["why_triggered_human"].lower()
    assert all("doğrula" not in step.lower() for step in metadata["recommended_review_steps"])


def test_ml_alert_explanation_metadata_localizes_english_fields():
    support = compute_ml_family_support_score(
        family_id="ML-PROC",
        event={**_sample_event(), "ts": 1715400000.0},
        readiness_result=_sample_readiness(),
        family_config=ML_FAMILY_READINESS["ML-PROC"],
        baseline_summary={},
    )
    metadata = build_ml_alert_explanation_metadata(
        support_score=support,
        readiness_result=_sample_readiness(),
        supporting_event_fields={**_sample_event(), "ml_label": "suspicious_process"},
        language="en",
    )

    assert metadata["language"] == "en"
    assert "expected behavior profile" in metadata["why_triggered_human"].lower()
    assert any("validate the relevant event fields" in step.lower() for step in metadata["recommended_review_steps"])


def test_deterministic_alert_explanation_english_has_no_turkish_leakage():
    rule_result = build_deterministic_alert_explanation(
        {
            "id": 101,
            "rule_id": "AUTH-004",
            "severity": "high",
            "risk_score": 75.0,
            "entity": "root",
            "message": "sudo escalation behaviour matched",
            "context_json": _sample_event(),
        },
        language="en",
    )
    ml_result = build_deterministic_alert_explanation(
        {
            "id": 202,
            "rule_id": "ML-PROC-001",
            "severity": "medium",
            "risk_score": 68.0,
            "entity": "host:host-1",
            "message": "process execution anomaly",
            "context_json": {
                "source": "ml_active_decision_layer",
                "ml_family": "ML-PROC",
                "ml_label": "suspicious_process",
                "ml_family_status": "active",
                "readiness_reason": "ready",
                "model_score": 68.0,
                "normalized_score": 0.68,
                "confidence": 0.84,
                "top_features": ["field_completeness=1.00"],
                "time_context": {"hour_of_day": 3, "is_night": True},
                "baseline_deviation": {"available": True, "score_component": 5.0},
                "supporting_event_fields": {"process": "/usr/bin/curl", "host": "host-1", "source": "auditd"},
                "no_action_contract": True,
                "action_taken": False,
                "can_emit_alert": True,
            },
        },
        language="en",
    )

    for result in (rule_result, ml_result):
        assert result["language"] == "en"
        text = result["text"]
        for token in TURKISH_FALLBACK_TOKENS:
            assert token not in text


def test_deterministic_alert_explanation_turkish_behavior_is_preserved():
    result = build_deterministic_alert_explanation(
        {
            "id": 101,
            "rule_id": "AUTH-004",
            "severity": "high",
            "risk_score": 75.0,
            "entity": "root",
            "message": "sudo escalation behaviour matched",
            "context_json": _sample_event(),
        },
        language="tr",
    )

    assert result["language"] == "tr"
    assert "Deterministik Alert Açıklaması" in result["text"]
    assert "Neden tetiklendi?" in result["text"]


def test_alert_explanation_contract_audit_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_alert_explanation_contract_audit", lambda config: print("Alert Explanation Contract Audit") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--alert-explanation-contract-audit"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert "Alert Explanation Contract Audit" in capsys.readouterr().out
