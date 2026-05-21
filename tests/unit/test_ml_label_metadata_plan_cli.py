import pytest

import main as main_module


def test_bootstrap_labels_follow_direct_or_baseline_usage():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in (
                    "id", "source", "source_trust", "model_usage_scope",
                    "event_class", "behavior_label", "rule_id", "label",
                )]
            return []

        def load_labels(self):
            return [
                {"id": 1, "source": "bootstrap", "behavior_label": "dns_anomaly"},
                {"id": 2, "source": "bootstrap", "behavior_label": "routine_system_event"},
            ]

    report = main_module.collect_ml_label_metadata_plan({}, _DB(), {})
    assert report["total_labels"] == 2
    first = report["proposals"][0]
    second = report["proposals"][1]
    assert first["proposed_ml_family"] == "ML-DNS"
    assert first["proposed_usage_decision"] == "direct_learnable"
    assert first["proposed_model_usage_scope"] == "calibration_only"
    assert first["learnable_candidate"] is True
    assert second["proposed_ml_family"] is None
    assert second["proposed_usage_decision"] == "ignored"
    assert second["learnable_candidate"] is False


def test_rule_id_and_behavior_alias_mapping_are_used():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in (
                    "label_id", "source", "source_trust", "model_usage_scope",
                    "event_class", "behavior_label", "rule_id", "label", "confidence",
                )]
            return []

        def load_labels(self):
            return [
                {
                    "label_id": "L-1",
                    "source": "auto_labeled",
                    "source_trust": "",
                    "model_usage_scope": "",
                    "event_class": "",
                    "behavior_label": "",
                    "rule_id": "AUTH-004",
                    "confidence": 0.95,
                },
                {
                    "label_id": "L-2",
                    "source": "bootstrap",
                    "behavior_label": "sudo_root_access",
                },
            ]

    report = main_module.collect_ml_label_metadata_plan({}, _DB(), {})
    auth = report["proposals"][0]
    sudo = report["proposals"][1]
    assert auth["proposed_ml_family"] == "ML-SUDO"
    assert auth["proposed_ml_label"] == "sudo_escalation_or_root_access"
    assert auth["proposed_usage_decision"] == "direct_learnable"
    assert sudo["proposed_ml_family"] == "ML-SUDO"
    assert sudo["proposed_ml_label"] == "sudo_escalation_or_root_access"


def test_unknown_and_missing_schema_are_safe():
    class _SchemaDB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": "source"}]
            return []

    report = main_module.collect_ml_label_metadata_plan({}, _SchemaDB(), {})
    assert report["total_labels"] == 0
    assert "missing_schema:no_mappable_label_columns" in report["query_notes"]

    class _UnknownDB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in ("source", "behavior_label", "label")]
            return []

        def load_labels(self):
            return [{"source": "bootstrap", "behavior_label": "totally_unknown_label"}]

    report = main_module.collect_ml_label_metadata_plan({}, _UnknownDB(), {})
    item = report["proposals"][0]
    assert item["proposed_ml_family"] is None
    assert item["learnable_candidate"] is False


def test_auto_labeled_and_cli_are_read_only(monkeypatch, tmp_path, capsys):
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in (
                    "id", "source", "source_trust", "model_usage_scope",
                    "event_class", "behavior_label", "rule_id", "label",
                )]
            return []

        def load_labels(self):
            return [{"id": 7, "source": "auto_labeled", "source_trust": "rule_high", "model_usage_scope": "calibration_only", "confidence": 0.95, "behavior_label": "suspicious_process"}]

    report = main_module.collect_ml_label_metadata_plan({}, _DB(), {})
    item = report["proposals"][0]
    assert item["proposed_usage_decision"] == "direct_learnable"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_label_metadata_plan", lambda config: print("ML Label Metadata Plan") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-label-metadata-plan"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert "ML Label Metadata Plan" in capsys.readouterr().out
