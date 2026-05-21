import pytest

import main as main_module


def _readiness(**overrides):
    payload = {
        "family_id": "ML-PROC",
        "status": "active_candidate",
        "reason": "ready",
        "can_score_support": True,
        "can_emit_alert": False,
        "phase_gate_ok": True,
        "event_threshold_ok": True,
        "normal_label_threshold_ok": True,
        "suspicious_label_threshold_ok": True,
        "field_quality_ok": True,
        "time_coverage_ok": True,
        "trust_support_ok": True,
        "metadata_support_ok": True,
        "no_action_contract": True,
    }
    payload.update(overrides)
    return payload


def _family_contract(**overrides):
    payload = {
        "default_status": "readiness_blocked",
        "phase_gate": 1,
        "required_events": 100,
        "required_normal_labels": 10,
        "required_suspicious_labels": 5,
    }
    payload.update(overrides)
    return payload


def _event():
    return {
        "ts": 1715400000.0,
        "source": "auditd",
        "category": "process",
        "action": "exec",
        "process": "/usr/bin/apt",
        "host": "host-1",
        "username": "root",
        "src_ip": "127.0.0.1",
    }


def test_support_score_paused_readiness_returns_not_scored():
    result = main_module.compute_ml_family_support_score(
        family_id="ML-PROC",
        event=_event(),
        readiness_result=_readiness(status="paused", reason="ml_paused", can_score_support=False),
        family_config=_family_contract(),
        baseline_summary={},
    )
    assert result["scored"] is False
    assert result["reason"] == "ml_paused"


def test_support_score_readiness_true_returns_scored():
    result = main_module.compute_ml_family_support_score(
        family_id="ML-PROC",
        event=_event(),
        readiness_result=_readiness(),
        family_config=_family_contract(),
        baseline_summary={},
    )
    assert result["scored"] is True
    assert result["score"] > 0
    assert result["normalized_score"] > 0


def test_support_score_active_decision_layer_disabled_never_emits():
    result = main_module.compute_ml_family_support_score(
        family_id="ML-PROC",
        event=_event(),
        readiness_result=_readiness(),
        family_config=_family_contract(),
        baseline_summary={},
    )
    assert result["can_emit_alert"] is False


def test_support_score_carries_runtime_safe_contract_flags():
    result = main_module.compute_ml_family_support_score(
        family_id="ML-PROC",
        event=_event(),
        readiness_result=_readiness(),
        family_config=_family_contract(),
        baseline_summary={},
    )
    assert result["no_action_contract"] is True
    assert result["db_write_attempted"] is False
    assert result["risk_score_changed"] is False
    assert result["runtime_output_changed"] is False


def test_support_score_time_features_are_present():
    result = main_module.compute_ml_family_support_score(
        family_id="ML-PROC",
        event=_event(),
        readiness_result=_readiness(),
        family_config=_family_contract(),
        baseline_summary={},
    )
    time_context = result["time_context"]
    assert "hour_of_day" in time_context
    assert "day_of_week" in time_context
    assert "is_weekend" in time_context
    assert "is_night" in time_context
    assert "timezone_name" in time_context
    assert "timezone_offset" in time_context


def test_support_score_is_deterministic_and_explainable():
    first = main_module.compute_ml_family_support_score(
        family_id="ML-PROC",
        event=_event(),
        readiness_result=_readiness(),
        family_config=_family_contract(),
        baseline_summary={"expected_sources": ["auditd"], "expected_actions": ["exec"], "expected_categories": ["process"]},
    )
    second = main_module.compute_ml_family_support_score(
        family_id="ML-PROC",
        event=_event(),
        readiness_result=_readiness(),
        family_config=_family_contract(),
        baseline_summary={"expected_sources": ["auditd"], "expected_actions": ["exec"], "expected_categories": ["process"]},
    )
    assert first["score"] == second["score"]
    assert first["normalized_score"] == second["normalized_score"]
    assert first["top_features"]


def test_support_score_helper_is_pure_and_does_not_mutate_event():
    event = _event()
    before = dict(event)
    result = main_module.compute_ml_family_support_score(
        family_id="ML-PROC",
        event=event,
        readiness_result=_readiness(),
        family_config=_family_contract(),
        baseline_summary={},
    )
    assert event == before
    assert result["db_write_attempted"] is False


def test_ml_support_score_family_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_support_score_family", lambda config, family_id: print(f"ML Family Support Score\n{family_id}") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-support-score-family", "ML-PROC"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "ML Family Support Score" in out
    assert "ML-PROC" in out
