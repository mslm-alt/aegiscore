from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.actions import historical_labels


def _valid_candidate():
    return {
        "proposed_metadata": {
            "source_type": "auto_labeled_rule_mapped",
            "source": "auto_labeled",
            "ml_family": "ML-AUTH",
            "label_family": "ML-AUTH",
            "ml_label": "auth_attack_or_abuse",
            "event_class": "suspicious",
            "behavior_label": "auth_attack_or_abuse",
            "source_trust": "rule_high",
            "model_usage_scope": "calibration_only",
            "learnable": True,
            "no_action_contract": True,
            "label_reason": "rule_hit",
            "evidence_fields": {"note": "safe"},
        },
        "family_id": "ML-AUTH",
        "family_label": "auth_attack_or_abuse",
    }


def _write_manifest(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "data" / "ml_label_scan" / "manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _facade_stub(monkeypatch, paused: bool = False):
    class _Facade:
        @staticmethod
        def collect_ml_summary(config_path=None):
            return {
                "status": "ok",
                "ready_for_active_ml": False,
                "ml_paused": paused,
                "top_blockers": ["ml_paused"] if paused else [],
            }

    monkeypatch.setattr(historical_labels, "_facade", lambda: _Facade)


def test_no_manifest_returns_preview_only_degraded(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _facade_stub(monkeypatch)

    result = historical_labels.preview_historical_label_audit(config={}, manifest_id=None)

    assert result["status"] == "degraded"
    assert result["preview_only"] is True
    assert result["db_write_attempted"] is False


def test_path_traversal_manifest_denied(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _facade_stub(monkeypatch)

    result = historical_labels.preview_historical_label_audit(config={}, manifest_id="../bad.json")

    assert result["status"] == "degraded"
    assert result["error"] == "path_traversal_blocked"


def test_invalid_manifest_schema_denied(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _facade_stub(monkeypatch)
    path = _write_manifest(tmp_path, {"kind": "wrong"})

    result = historical_labels.preview_historical_label_audit(config={}, manifest_id=str(path))

    assert result["status"] == "degraded"
    assert result["error"] == "invalid_manifest_schema"


def test_missing_required_ml_metadata_is_rejected_in_preview(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _facade_stub(monkeypatch)
    path = _write_manifest(tmp_path, {
        "job_id": "job-1",
        "plan_type": "ml_historical_label_scan",
        "dry_run": True,
        "no_action_contract": True,
        "family_targets": [{"family_id": "ML-AUTH", "family_label": "auth", "proposed_label_candidates": [{"proposed_metadata": {"ml_family": "ML-AUTH"}}]}],
    })

    result = historical_labels.preview_historical_label_audit(config={}, manifest_id=str(path))

    assert result["status"] == "ok"
    assert result["usage_summary"]["rejected"] == 1
    assert result["db_write_attempted"] is False


def test_preview_valid_manifest_classifies_direct_and_keeps_no_action(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _facade_stub(monkeypatch, paused=True)
    path = _write_manifest(tmp_path, {
        "job_id": "job-1",
        "plan_type": "ml_historical_label_scan",
        "dry_run": True,
        "no_action_contract": True,
        "family_targets": [{"family_id": "ML-AUTH", "family_label": "auth_attack_or_abuse", "proposed_label_candidates": [_valid_candidate()]}],
    })

    result = historical_labels.preview_historical_label_audit(config={}, manifest_id=str(path))

    assert result["status"] == "ok"
    assert result["usage_summary"]["direct_learnable"] == 1
    assert result["guards"]["active_ml_enabled"] is False
    assert result["guards"]["train_will_run"] is False
    assert result["guards"]["alert_emit_will_run"] is False
    assert result["preview_only"] is True


def test_synthetic_candidate_is_ignored_in_preview(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _facade_stub(monkeypatch)
    candidate = _valid_candidate()
    candidate["proposed_metadata"]["source_type"] = "synthetic_seed"
    candidate["proposed_metadata"]["source"] = "synthetic"
    candidate["proposed_metadata"]["source_trust"] = "synthetic_high"
    path = _write_manifest(tmp_path, {
        "job_id": "job-1",
        "plan_type": "ml_historical_label_scan",
        "dry_run": True,
        "no_action_contract": True,
        "family_targets": [{"family_id": "ML-AUTH", "family_label": "auth_attack_or_abuse", "proposed_label_candidates": [candidate]}],
    })

    result = historical_labels.preview_historical_label_audit(config={}, manifest_id=str(path))

    assert result["usage_summary"]["ignored"] == 1
    assert result["usage_summary"]["direct_learnable"] == 0
    assert "synthetic_not_runtime_observed" in result["reason_summary"]


def test_benign_baseline_scope_stays_baseline_in_preview(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _facade_stub(monkeypatch)
    candidate = _valid_candidate()
    candidate["proposed_metadata"]["event_class"] = "benign"
    candidate["proposed_metadata"]["behavior_label"] = "ssh_login_normal"
    candidate["proposed_metadata"]["ml_label"] = "ssh_login_normal"
    candidate["proposed_metadata"]["model_usage_scope"] = "baseline_learning"
    path = _write_manifest(tmp_path, {
        "job_id": "job-1",
        "plan_type": "ml_historical_label_scan",
        "dry_run": True,
        "no_action_contract": True,
        "family_targets": [{"family_id": "ML-AUTH", "family_label": "ssh_login_normal", "proposed_label_candidates": [candidate]}],
    })

    result = historical_labels.preview_historical_label_audit(config={}, manifest_id=str(path))

    assert result["usage_summary"]["baseline_learning"] == 1
    assert result["usage_summary"]["direct_learnable"] == 0
    assert result["preview_only"] is True
    assert result["read_only"] is True
    assert result["db_write_attempted"] is False


def test_benign_calibration_only_is_not_baseline_in_preview(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _facade_stub(monkeypatch)
    candidate = _valid_candidate()
    candidate["proposed_metadata"]["event_class"] = "benign"
    candidate["proposed_metadata"]["behavior_label"] = "ssh_login_normal"
    candidate["proposed_metadata"]["ml_label"] = "ssh_login_normal"
    candidate["proposed_metadata"]["model_usage_scope"] = "calibration_only"
    path = _write_manifest(tmp_path, {
        "job_id": "job-1",
        "plan_type": "ml_historical_label_scan",
        "dry_run": True,
        "no_action_contract": True,
        "family_targets": [{"family_id": "ML-AUTH", "family_label": "ssh_login_normal", "proposed_label_candidates": [candidate]}],
    })

    result = historical_labels.preview_historical_label_audit(config={}, manifest_id=str(path))

    assert result["usage_summary"]["baseline_learning"] == 0
    assert result["usage_summary"]["direct_learnable"] == 0
    assert result["usage_summary"]["rejected"] == 1
    row = result["candidate_rows"][0]
    assert row["usage_decision"] == "rejected"


def test_attack_with_baseline_scope_normalizes_to_direct_in_preview(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _facade_stub(monkeypatch)
    candidate = _valid_candidate()
    candidate["proposed_metadata"]["event_class"] = "attack"
    candidate["proposed_metadata"]["model_usage_scope"] = "baseline_learning"
    path = _write_manifest(tmp_path, {
        "job_id": "job-1",
        "plan_type": "ml_historical_label_scan",
        "dry_run": True,
        "no_action_contract": True,
        "family_targets": [{"family_id": "ML-AUTH", "family_label": "auth_attack_or_abuse", "proposed_label_candidates": [candidate]}],
    })

    result = historical_labels.preview_historical_label_audit(config={}, manifest_id=str(path))

    assert result["usage_summary"]["direct_learnable"] == 1
    assert result["usage_summary"]["baseline_learning"] == 0
    row = result["candidate_rows"][0]
    assert row["usage_decision"] == "direct_learnable"
    assert "suspicious_baseline_scope_normalized" in row["reasons"]


def test_preview_contains_no_mutating_behavior_strings():
    import ui.backend_facade as backend_facade

    source = Path("ui/actions/historical_labels.py").read_text(encoding="utf-8").lower()
    for token in ("save_labels(", "insert into user_actions", "label_apply_backups"):
        assert token not in source

    result = backend_facade.collect_guarded_action_policies()
    enabled = set(result["executable_action_types"])
    assert "ml_resume" not in enabled
    assert "ml_reset" not in enabled
    assert "ml_config_update" not in enabled
