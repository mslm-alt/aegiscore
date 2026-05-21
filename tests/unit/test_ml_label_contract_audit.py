import pytest

import main as main_module
from core.ml.label_engine import build_ml_label_metadata, validate_ml_label_metadata


def test_rule_mapped_attack_metadata_is_complete():
    metadata = build_ml_label_metadata(
        "rule_mapped_attack",
        "ML-AUTH",
        "auth_attack_or_abuse",
        rule_id="AUTH-004",
    )
    result = validate_ml_label_metadata(metadata)
    assert result["valid"] is True
    assert metadata["event_class"] == "attack"
    assert metadata["model_usage_scope"] == "calibration_only"
    assert metadata["no_action_contract"] is True


def test_clean_window_normal_metadata_is_benign_and_learnable():
    metadata = build_ml_label_metadata(
        "clean_window_normal",
        "ML-PROC",
        "process_normal",
    )
    result = validate_ml_label_metadata(metadata)
    assert result["valid"] is True
    assert metadata["event_class"] == "benign"
    assert metadata["learnable"] is True
    assert metadata["model_usage_scope"] == "baseline_learning"


def test_bootstrap_and_synthetic_seed_never_use_baseline_learning():
    bootstrap = build_ml_label_metadata("bootstrap_seed", "ML-DNS", "dns_anomaly")
    synthetic = build_ml_label_metadata("synthetic_seed", "ML-PROC", "suspicious_process")
    assert bootstrap["model_usage_scope"] != "baseline_learning"
    assert synthetic["model_usage_scope"] != "baseline_learning"
    assert validate_ml_label_metadata(bootstrap)["valid"] is True
    assert validate_ml_label_metadata(synthetic)["valid"] is True


def test_unknown_source_validation_rules():
    metadata = build_ml_label_metadata("rule_mapped_attack", "ML-SUDO", "sudo_escalation_or_root_access")
    assert validate_ml_label_metadata(metadata)["valid"] is True

    invalid = dict(metadata)
    invalid["ml_family"] = ""
    invalid["ml_label"] = ""
    invalid["source"] = "unknown"
    invalid["model_usage_scope"] = "baseline_learning"
    result = validate_ml_label_metadata(invalid)
    assert result["valid"] is False
    assert "invalid:ml_family" in result["problems"]
    assert "invalid:ml_label" in result["problems"]
    assert "invalid:source" in result["problems"]


def test_ml_label_contract_audit_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_label_contract_audit", lambda config: print("ML Label Contract Audit") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-label-contract-audit"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert "ML Label Contract Audit" in capsys.readouterr().out
