import copy

import pytest

import main as main_module


def test_ml_config_contract_matches_registry_and_defaults():
    config = main_module.load_config("config/config.yml")
    report = main_module.collect_ml_config_audit(config, None)

    assert report["active_decision_layer"]["enabled"] is False
    assert report["active_decision_layer"]["mode"] == "audit_only"
    assert report["active_decision_layer"]["no_action_contract"] is True
    assert report["family_set_match"] is True
    assert report["registry_consistent"] is True
    assert report["phase_gates_valid"] is True
    assert report["thresholds_positive"] is True
    assert report["no_action_contract_ok"] is True


def test_ml_config_audit_warns_on_missing_family_and_invalid_values():
    config = copy.deepcopy(main_module.load_config("config/config.yml"))
    del config["ml"]["family"]["ML-DNS"]
    config["ml"]["active_decision_layer"]["enabled"] = True
    config["ml"]["family"]["ML-PROC"]["phase_gate"] = "PHASE_X"
    config["ml"]["family"]["ML-PROC"]["runtime_min_events"] = 0

    report = main_module.collect_ml_config_audit(config, None)

    assert report["family_set_match"] is False
    assert "ML-DNS" in report["missing_families"]
    assert report["phase_gates_valid"] is False
    assert report["thresholds_positive"] is False
    assert report["registry_consistent"] is False
    assert any("active_decision_layer.enabled false kalmalı" in item for item in report["recommended_actions"])


def test_ml_config_audit_schema_contract_is_read_only_and_safe():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in (
                    "source_trust", "model_usage_scope", "event_class", "behavior_label",
                    "learnable", "label_reason", "evidence_fields",
                )]
            if "information_schema.columns" in sql and params == ("alerts",):
                return [{"column_name": c} for c in ("id", "rule_id", "ts", "severity")]
            return []

    config = main_module.load_config("config/config.yml")
    report = main_module.collect_ml_config_audit(config, _DB())

    assert "bootstrap_job_id" in report["schema_contract"]["labels_existing_missing"]
    assert "ml_family" in report["schema_contract"]["labels_future_missing"]
    assert "ml_family" in report["schema_contract"]["alerts_future_missing"]


def test_ml_config_audit_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_config_audit", lambda config: print("ML Config Audit") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-config-audit"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert "ML Config Audit" in capsys.readouterr().out
