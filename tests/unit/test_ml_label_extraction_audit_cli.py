import pytest

import main as main_module


def test_evidence_fields_and_label_reason_rule_id_are_extracted():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in (
                    "id", "source", "evidence_fields", "label_reason", "behavior_label",
                    "event_class", "source_trust", "model_usage_scope", "bootstrap_job_id", "label_batch_id",
                )]
            return []

        def load_labels(self):
            return [
                {
                    "id": 1,
                    "source": "bootstrap",
                    "evidence_fields": {"rule_id": "DB-001"},
                    "label_reason": "",
                    "behavior_label": "",
                    "bootstrap_job_id": "job-1",
                },
                {
                    "id": 2,
                    "source": "auto_labeled",
                    "evidence_fields": {},
                    "label_reason": "Matched AUTH-004 and sudo escalation flow",
                    "behavior_label": "",
                    "label_batch_id": "batch-2",
                },
            ]

    report = main_module.collect_ml_label_extraction_audit({}, _DB(), {})
    assert report["evidence_fields_rule_id_count"] == 1
    assert report["label_reason_hint_count"] == 1
    assert report["possible_safe_mapping_count"] == 2
    assert report["bootstrap_job_id_distribution"]["job-1"] == 1
    assert report["label_batch_id_distribution"]["batch-2"] == 1


def test_empty_and_invalid_evidence_fields_do_not_crash_and_ambiguous_stays_false():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in (
                    "id", "source", "evidence_fields", "label_reason", "behavior_label",
                    "event_class", "source_trust", "model_usage_scope",
                )]
            return []

        def load_labels(self):
            return [
                {"id": 1, "source": "bootstrap", "evidence_fields": "", "label_reason": "", "behavior_label": ""},
                {"id": 2, "source": "bootstrap", "evidence_fields": "{bad json", "label_reason": "", "behavior_label": "totally_unknown"},
            ]

    report = main_module.collect_ml_label_extraction_audit({}, _DB(), {})
    assert report["total_labels"] == 2
    assert report["possible_safe_mapping_count"] == 0
    assert report["impossible_mapping_count"] == 2
    assert report["reasons"]["empty_evidence_fields"] == 2
    assert report["reasons"]["ambiguous_metadata"] == 2
    assert any("evidence_fields:invalid_json" == note for note in report["query_notes"])


def test_bootstrap_mapping_is_extracted_as_direct_learning_candidate():
    class _DB:
        def _execute(self, sql, params=(), fetch="all"):
            if "information_schema.columns" in sql and params == ("labels",):
                return [{"column_name": c} for c in (
                    "id", "source", "behavior_label", "event_class",
                    "source_trust", "model_usage_scope",
                )]
            return []

        def load_labels(self):
            return [{"id": 7, "source": "bootstrap", "behavior_label": "dns_anomaly"}]

    report = main_module.collect_ml_label_extraction_audit({}, _DB(), {})
    item = report["examples"][0]
    assert item["safe_to_map"] is True
    assert item["proposed_extraction"]["usage_decision"] == "direct_learnable"


def test_extraction_audit_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "run_ml_label_extraction_audit", lambda config: print("ML Label Extraction Audit") or 0)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-label-extraction-audit"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert "ML Label Extraction Audit" in capsys.readouterr().out
