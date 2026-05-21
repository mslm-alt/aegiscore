import pytest

import main as main_module


def test_collect_ml_mapping_audit_counts_coverage_and_unmapped():
    report = main_module.collect_ml_mapping_audit([
        "AUTH-004",
        "AUTH-002",
        "DNS-001",
        "DB-001",
        "MISC-999",
    ])

    assert report["total_rules"] == 5
    assert report["mapped_rules"] == 4
    assert report["unmapped_rules"] == 1
    assert report["coverage_percent"] == 80.0
    assert report["by_ml_family"]["ML-SUDO"] == 1
    assert report["by_ml_family"]["ML-AUTH"] == 1
    assert report["by_ml_family"]["ML-DNS"] == 1
    assert report["by_ml_family"]["ML-DBAUTH"] == 1
    assert report["explicit_override_count"] == 2
    assert report["prefix_fallback_count"] == 2
    assert report["unmapped_rule_ids"] == ["MISC-999"]


def test_collect_ml_mapping_audit_source_trust_and_override_breakdown():
    report = main_module.collect_ml_mapping_audit(["AUTH-004", "AUTH-002", "AUTH-003"])

    assert report["by_source_trust"]["rule_high"] == 3
    assert report["explicit_override_count"] == 1
    assert report["prefix_fallback_count"] == 2


def test_collect_ml_mapping_audit_empty_ruleset_is_safe():
    report = main_module.collect_ml_mapping_audit([])
    assert report["total_rules"] == 0
    assert report["mapped_rules"] == 0
    assert report["coverage_percent"] == 0.0
    assert report["unmapped_rule_ids"] == []


def test_ml_mapping_audit_cli_is_read_only(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "_load_rule_ids_for_ml_mapping_audit", lambda config: (["AUTH-004", "AUTH-002", "MISC-999"], ""))
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-mapping-audit"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "ML Mapping Audit" in out
    assert "total_rules=3" in out
    assert "MISC-999" in out


def test_ml_mapping_audit_cli_loader_failure_is_clean(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(main_module, "_load_rule_ids_for_ml_mapping_audit", lambda config: ([], "rule_loader_unavailable"))
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--ml-mapping-audit"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "rule_loader_unavailable" in err
    assert "Traceback" not in err
