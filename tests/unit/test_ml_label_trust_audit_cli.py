import pytest

import main as main_module


def test_label_usage_audit_classifies_direct_baseline_ignored_and_rejected():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("events_recent",):
                return []
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in ("behavior_label", "source", "source_trust", "model_usage_scope", "learnable", "event_class", "confidence", "label_reason", "evidence_fields")]
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                return {"count": 0}
            return []

        def load_labels(self):
            return [
                {"source": "auto_labeled", "source_trust": "rule_high", "model_usage_scope": "calibration_only", "learnable": True, "event_class": "attack", "behavior_label": "suspicious_process", "confidence": 0.95},
                {"source": "bootstrap", "source_trust": "rule_high", "model_usage_scope": "baseline_learning", "learnable": True, "event_class": "benign", "behavior_label": "ssh_login_normal", "confidence": 1.0},
                {"source": "synthetic", "source_trust": "synthetic_high", "model_usage_scope": "calibration_only", "learnable": True, "event_class": "attack", "behavior_label": "brute_force_or_auth_attack", "confidence": 1.0},
                {"source": "bootstrap", "source_trust": "rule_high", "model_usage_scope": "not_learnable", "learnable": False, "event_class": "unknown_unlabeled", "behavior_label": "unknown_unlabeled", "confidence": 1.0},
                {"source": "auto_labeled", "source_trust": "", "model_usage_scope": "", "learnable": True, "event_class": "attack", "behavior_label": "", "confidence": 0.80},
            ]

        def get_stat(self, key):
            return ""

        def get_open_incidents(self):
            return []

    report = main_module.collect_ml_label_trust_audit({}, _DB(), {"current_phase": 0, "phase_name": "Kural", "stats": {}})
    assert report["usage_decisions"]["direct_learnable"] == 1
    assert report["usage_decisions"]["baseline_learning"] == 1
    assert report["usage_decisions"]["ignored"] == 1
    assert report["usage_decisions"]["rejected"] == 2
    assert report["decision_reasons"]["unknown_unlabeled"] == 1
    assert report["decision_reasons"]["missing_model_usage_scope"] == 1
    assert report["decision_reasons"]["missing_behavior_label"] == 1


def test_suspicious_event_with_wrong_baseline_scope_is_normalized_to_direct():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("events_recent",):
                return []
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in ("behavior_label", "source", "source_trust", "model_usage_scope", "learnable", "event_class")]
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                return {"count": 0}
            return []

        def load_labels(self):
            return [
                {
                    "source": "auto_labeled",
                    "source_trust": "rule_high",
                    "model_usage_scope": "baseline_learning",
                    "learnable": True,
                    "event_class": "attack",
                    "behavior_label": "auth_attack_or_abuse",
                }
            ]

        def get_stat(self, key):
            return ""

        def get_open_incidents(self):
            return []

    report = main_module.collect_ml_label_trust_audit({}, _DB(), {"current_phase": 0, "phase_name": "Kural", "stats": {}})
    assert report["usage_decisions"]["direct_learnable"] == 1
    assert report["usage_decisions"].get("baseline_learning", 0) == 0
    assert report["decision_reasons"]["suspicious_baseline_scope_normalized"] == 1


def test_usage_audit_reports_quality_gaps_and_family_support_counts():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("events_recent",):
                return []
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in ("behavior_label", "source", "source_trust", "model_usage_scope", "learnable", "event_class")]
            if "SELECT COUNT(*) AS count FROM " in sql and fetch == "one":
                return {"count": 0}
            return []

        def load_labels(self):
            return (
                [{"source": "bootstrap", "source_trust": "rule_high", "model_usage_scope": "baseline_learning", "learnable": True, "event_class": "benign", "behavior_label": "ssh_login_normal"}] * 6
                + [{"source": "bootstrap", "source_trust": "rule_high", "model_usage_scope": "calibration_only", "learnable": True, "event_class": "attack", "behavior_label": "auth_attack_or_abuse"}] * 2
                + [{"source": "auto_labeled", "source_trust": "rule_high", "model_usage_scope": "calibration_only", "learnable": True, "event_class": "attack", "behavior_label": "suspicious_process", "confidence": 0.95}]
            )

        def get_stat(self, key):
            return ""

        def get_open_incidents(self):
            return []

    report = main_module.collect_ml_label_trust_audit({}, _DB(), {"current_phase": 0, "phase_name": "Kural", "stats": {}})
    assert report["quality_summary"]["missing_metadata_count"] == 0
    assert report["quality_summary"]["synthetic_ratio"] == 0.0
    assert report["family_support"]["ML-AUTH"]["normal"] >= 1
    assert report["family_support"]["ML-AUTH"]["suspicious"] >= 1


def test_missing_schema_and_empty_db_are_safe_for_label_usage_audit():
    report = main_module.collect_ml_label_trust_audit({}, None, {"current_phase": 0, "phase_name": "Kural", "stats": {}})
    assert report["global"]["total_labels"] == 0
    assert "missing_schema:behavior_label" in report["global"]["query_notes"]


def test_label_trust_audit_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_label_trust_audit", lambda config: print("ML Label Trust Audit") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-label-trust-audit"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert "ML Label Trust Audit" in capsys.readouterr().out
