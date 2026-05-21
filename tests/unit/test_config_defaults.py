from pathlib import Path

import yaml

from core.risk import WeightedRiskScorer


def _load_repo_config():
    repo_root = Path(__file__).resolve().parents[2]
    with open(repo_root / "config" / "config.yml", "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_lean_default_config_flags():
    config = _load_repo_config()

    assert config["monitor"]["systemd_creation_only"] is True
    assert config["ml"]["bootstrap_scan_mode"] == "auto"
    assert "shadow_mode" not in config["ml"]
    assert config["ml"]["active_decision_layer"]["enabled"] is False
    assert config["ml"]["active_decision_layer"]["mode"] == "audit_only"
    assert config["ml"]["active_decision_layer"]["no_action_contract"] is True
    assert config["ml"]["family"]["ML-PROC"]["default_status"] == "readiness_blocked"
    assert config["ml"]["family"]["ML-PROC"]["no_action_contract"] is True
    assert config["ml"]["family"]["ML-DNS"]["no_action_contract"] is True


def test_lean_default_risk_weights_apply_direct_context_overrides():
    config = _load_repo_config()
    scorer = WeightedRiskScorer(config=config)

    assert scorer.weights["monitor"] == 0.6
    assert scorer.weights["freq_anomaly"] == 0.25
