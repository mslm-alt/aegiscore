import pytest

import main as main_module


def test_auth_004_runtime_candidate_maps_to_ml_sudo():
    event = {"source": "auth_log", "action": "sudo"}
    context = {"entity": "root", "layer": "rule"}
    candidate = main_module.build_runtime_ml_label_candidate_from_rule(
        "AUTH-004",
        severity="critical",
        risk_score=90.0,
        event=event,
        alert_context=context,
        message="sudo escalation",
    )

    assert candidate["matched"] is True
    assert candidate["metadata"]["ml_family"] == "ML-SUDO"
    assert candidate["metadata"]["ml_label"] == "sudo_escalation_or_root_access"
    assert candidate["metadata"]["no_action_contract"] is True
    assert candidate["metadata"]["model_usage_scope"] == "calibration_only"
    assert candidate["active_training_enabled"] is False
    assert candidate["db_write_attempted"] is False
    assert event == {"source": "auth_log", "action": "sudo"}
    assert context == {"entity": "root", "layer": "rule"}


def test_web_rule_runtime_candidate_maps_to_ml_webpost():
    candidate = main_module.build_runtime_ml_label_candidate_from_rule(
        "WEB-014",
        severity="high",
        risk_score=70.0,
        event={"source": "apache2"},
        alert_context={"host": "web-1"},
        message="web attack",
    )
    assert candidate["matched"] is True
    assert candidate["metadata"]["ml_family"] == "ML-WEBPOST"
    assert candidate["metadata"]["ml_label"] == "web_attack_or_post_exploit"
    assert candidate["validation"]["valid"] is True


def test_unknown_rule_runtime_candidate_stays_unmatched():
    candidate = main_module.build_runtime_ml_label_candidate_from_rule(
        "MISC-999",
        severity="low",
        risk_score=10.0,
        event={"source": "syslog"},
        alert_context={},
        message="unknown rule",
    )
    assert candidate["matched"] is False
    assert candidate["metadata"] is None
    assert candidate["db_write_attempted"] is False
    assert candidate["active_training_enabled"] is False


def test_runtime_candidate_never_uses_active_training():
    auth = main_module.build_runtime_ml_label_candidate_from_rule("AUTH-004", severity="high", risk_score=50.0, event={}, alert_context={}, message="")
    web = main_module.build_runtime_ml_label_candidate_from_rule("WEB-014", severity="high", risk_score=50.0, event={}, alert_context={}, message="")
    assert auth["metadata"]["model_usage_scope"] in {"calibration_only", "not_learnable"}
    assert web["metadata"]["model_usage_scope"] in {"calibration_only", "not_learnable"}
    assert auth["metadata"]["model_usage_scope"] != "baseline_learning"
    assert web["metadata"]["model_usage_scope"] != "baseline_learning"


def test_runtime_candidate_helper_is_pure_and_does_not_change_runtime_outputs():
    event = {"source": "auth_log", "action": "sudo", "raw": {"nested": True}}
    context = {"message": "alert", "risk_score": 88.0}
    event_before = {"source": "auth_log", "action": "sudo", "raw": {"nested": True}}
    context_before = {"message": "alert", "risk_score": 88.0}

    candidate = main_module.build_runtime_ml_label_candidate_from_rule(
        "AUTH-004",
        severity="critical",
        risk_score=88.0,
        event=event,
        alert_context=context,
        message="candidate audit",
    )

    assert event == event_before
    assert context == context_before
    assert candidate["runtime_output_changed"] is False
    assert candidate["risk_score_changed"] is False
    assert candidate["risk_score"] == 88.0


def test_runtime_candidate_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_runtime_label_candidate_audit", lambda config, rule_id: print(f"ML Runtime Label Candidate Audit\n{rule_id}") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-runtime-label-candidate-audit", "AUTH-004"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "ML Runtime Label Candidate Audit" in out
    assert "AUTH-004" in out
