import pytest

import main as main_module


def _base_contract(**overrides):
    contract = {
        "default_status": "readiness_blocked",
        "phase_gate": 1,
        "required_events": 100,
        "required_normal_labels": 10,
        "required_suspicious_labels": 5,
        "field_requirements": {"process_fill_rate": 0.30},
        "hard_field_rates": set(),
        "require_process_tree": False,
        "required_time_coverage_days": 5,
        "linked_process_required_events": 0,
    }
    contract.update(overrides)
    return contract


def _base_quality(**overrides):
    quality = {
        "host_fill_rate": 0.80,
        "user_fill_rate": 0.80,
        "src_ip_fill_rate": 0.80,
        "dst_ip_fill_rate": 0.80,
        "dst_port_fill_rate": 0.80,
        "process_fill_rate": 0.80,
        "source_count": 3,
    }
    quality.update(overrides)
    return quality


def _evaluate(**overrides):
    params = {
        "family_id": "ML-PROC",
        "current_phase": 1,
        "ml_paused": False,
        "family_contract": _base_contract(),
        "runtime_event_count": 100,
        "normal_label_count": 10,
        "suspicious_label_count": 5,
        "field_quality_metrics": _base_quality(),
        "time_coverage_days": 5,
        "trust_support": {"normal": 10, "suspicious": 5},
        "metadata_support": 10,
        "active_decision_layer": {"enabled": False, "mode": "audit_only"},
        "linked_process_events": 0,
        "duplicate_rate": 0.0,
        "parse_fail_rate": 0.0,
        "process_tree_count": 1,
        "errors": [],
    }
    params.update(overrides)
    return main_module.evaluate_ml_family_readiness(**params)


def test_family_readiness_paused_blocks_emit():
    result = _evaluate(ml_paused=True)
    assert result["status"] == "paused"
    assert result["can_emit_alert"] is False
    assert result["can_score_support"] is False


def test_family_readiness_active_decision_layer_disabled_never_emits():
    result = _evaluate()
    assert result["status"] == "active_candidate"
    assert result["can_score_support"] is True
    assert result["can_emit_alert"] is False


def test_family_readiness_phase_not_reached_blocks():
    result = _evaluate(current_phase=0, family_contract=_base_contract(phase_gate=2))
    assert result["status"] == "readiness_blocked"
    assert result["reason"] == "phase_not_reached"


def test_family_readiness_event_threshold_missing_blocks():
    result = _evaluate(runtime_event_count=99)
    assert result["status"] == "readiness_blocked"
    assert result["reason"] == "insufficient_runtime_events"


def test_family_readiness_label_threshold_missing_blocks():
    result = _evaluate(normal_label_count=9)
    assert result["status"] == "readiness_blocked"
    assert result["reason"] == "insufficient_normal_labels"


def test_family_readiness_field_quality_low_blocks():
    result = _evaluate(
        family_contract=_base_contract(field_requirements={"process_fill_rate": 0.90}),
        field_quality_metrics=_base_quality(process_fill_rate=0.20),
    )
    assert result["status"] == "needs_more_data"
    assert result["reason"] == "insufficient_field_quality"


def test_family_readiness_all_thresholds_pass_but_audit_only_mode_has_no_emit():
    result = _evaluate(active_decision_layer={"enabled": True, "mode": "audit_only"})
    assert result["status"] == "active_candidate"
    assert result["can_score_support"] is True
    assert result["can_emit_alert"] is False


def test_family_readiness_needs_more_data_can_score_support_without_emit():
    result = _evaluate(
        time_coverage_days=1,
    )
    assert result["status"] == "needs_more_data"
    assert result["can_score_support"] is True
    assert result["can_emit_alert"] is False


def test_family_readiness_disabled_family_returns_disabled():
    result = _evaluate(family_contract=_base_contract(default_status="disabled", enabled=False))
    assert result["status"] == "disabled"
    assert result["can_emit_alert"] is False


def test_family_readiness_carries_no_action_contract():
    result = _evaluate()
    assert result["no_action_contract"] is True


def test_ml_family_readiness_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_family_readiness", lambda config, family_id: print(f"ML Family Readiness\n{family_id}") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-family-readiness", "ML-PROC"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "ML Family Readiness" in out
    assert "ML-PROC" in out
