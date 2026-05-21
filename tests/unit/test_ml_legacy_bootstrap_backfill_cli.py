import pytest

import main as main_module


class _FakeDB:
    def __init__(self, rows):
        self.rows = [dict(row) for row in rows]
        self.backfill_calls = []

    def load_labels(self):
        return [dict(row) for row in self.rows]

    def backfill_legacy_bootstrap_label_metadata(self, updates):
        self.backfill_calls.append([dict(item) for item in updates])
        by_id = {row.get("id"): row for row in self.rows}
        updated = 0
        for item in updates:
            row = by_id.get(item.get("id"))
            if not row:
                continue
            row.update({
                "event_class": item["event_class"],
                "behavior_label": item["behavior_label"],
                "source_trust": item["source_trust"],
                "model_usage_scope": item["model_usage_scope"],
                "learnable": item["learnable"],
                "label_reason": item["label_reason"],
                "poisoning_guard_passed": item["poisoning_guard_passed"],
                "evidence_fields": dict(item["evidence_fields"]),
            })
            updated += 1
        return updated


def test_collect_legacy_bootstrap_backfill_plan_targets_only_rejected_missing_rows():
    db = _FakeDB([
        {
            "id": 1,
            "source": "bootstrap",
            "label": "normal",
            "category": "normal_logout",
            "ts": 100.0,
            "event_class": "",
            "behavior_label": "",
            "source_trust": "",
            "model_usage_scope": "",
            "learnable": None,
            "label_reason": "",
            "distro": "",
        },
        {
            "id": 2,
            "source": "bootstrap",
            "label": "attack",
            "category": "auth",
            "ts": 101.0,
            "event_class": "attack",
            "behavior_label": "sudo_root_access",
            "source_trust": "rule_high",
            "model_usage_scope": "calibration_only",
            "learnable": True,
            "label_reason": "bootstrap_rule_match_auth",
            "distro": "debian",
        },
        {
            "id": 3,
            "source": "auto_labeled",
            "label": "normal",
            "category": "auth",
            "ts": 102.0,
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "source_trust": "observed_benign_high",
            "model_usage_scope": "baseline_learning",
            "learnable": True,
            "label_reason": "runtime_normal",
            "distro": "debian",
        },
    ])

    report = main_module.collect_ml_legacy_bootstrap_backfill_plan({}, db, {})

    assert report["candidate_count"] == 1
    assert report["sample_row_ids"] == [1]
    assert report["category_distribution"] == {"normal_logout": 1}
    assert report["label_distribution"] == {"normal": 1}
    assert report["db_write_attempted"] is False
    assert report["readiness_delta"] == {"normal": 0, "suspicious": 0}
    payload = report["backfill_payloads"][0]
    assert payload["event_class"] == "unknown_unlabeled"
    assert payload["behavior_label"] == "unknown_unlabeled"
    assert payload["source_trust"] == "legacy_incomplete"
    assert payload["model_usage_scope"] == "not_learnable"
    assert payload["learnable"] is False
    assert payload["label_reason"] == "legacy_bootstrap_missing_metadata"
    assert payload["poisoning_guard_passed"] is False
    assert payload["evidence_fields"]["legacy_category"] == "normal_logout"
    assert payload["evidence_fields"]["original_label"] == "normal"
    assert payload["evidence_fields"]["repair_mode"] == "reject_backfill"
    assert payload["evidence_fields"]["training_eligible"] is False
    assert "ml_family" not in payload
    assert "label_family" not in payload


def test_collect_legacy_bootstrap_backfill_plan_skips_training_eligible_bootstrap_rows():
    db = _FakeDB([
        {
            "id": 9,
            "source": "bootstrap",
            "label": "normal",
            "category": "system_service",
            "ts": 100.0,
            "event_class": "",
            "behavior_label": "",
            "source_trust": "",
            "model_usage_scope": "baseline_learning",
            "learnable": True,
            "label_reason": "",
        }
    ])

    report = main_module.collect_ml_legacy_bootstrap_backfill_plan({}, db, {})

    assert report["candidate_count"] == 0
    assert report["unsafe_learnable_ids"] == [9]
    assert report["safety_blockers"] == ["unsafe_candidate_learnable_true"]


def test_execute_legacy_bootstrap_backfill_apply_updates_only_candidates_and_keeps_readiness_flat():
    db = _FakeDB([
        {
            "id": 1,
            "source": "bootstrap",
            "label": "normal",
            "category": "normal_logout",
            "ts": 100.0,
            "event_class": "",
            "behavior_label": "",
            "source_trust": "",
            "model_usage_scope": "",
            "learnable": None,
            "label_reason": "",
            "distro": "",
        },
        {
            "id": 2,
            "source": "bootstrap",
            "label": "attack",
            "category": "auth",
            "ts": 101.0,
            "event_class": "attack",
            "behavior_label": "sudo_root_access",
            "source_trust": "rule_high",
            "model_usage_scope": "calibration_only",
            "learnable": True,
            "label_reason": "bootstrap_rule_match_auth",
            "distro": "debian",
        },
        {
            "id": 3,
            "source": "auto_labeled",
            "label": "normal",
            "category": "auth",
            "ts": 102.0,
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "source_trust": "observed_benign_high",
            "model_usage_scope": "baseline_learning",
            "learnable": True,
            "label_reason": "runtime_normal",
            "distro": "debian",
        },
    ])

    report = main_module.execute_ml_legacy_bootstrap_backfill({}, db, apply=True)

    assert report["status"] == "applied"
    assert report["updated_count"] == 1
    assert report["missing_metadata_before"] == 1
    assert report["missing_metadata_after"] == 0
    assert report["readiness_delta"] == {"normal": 0, "suspicious": 0}
    assert report["no_learnable_rows_created"] is True
    assert len(db.backfill_calls) == 1
    updated = db.rows[0]
    untouched = db.rows[1]
    assert updated["event_class"] == "unknown_unlabeled"
    assert updated["behavior_label"] == "unknown_unlabeled"
    assert updated["source_trust"] == "legacy_incomplete"
    assert updated["model_usage_scope"] == "not_learnable"
    assert updated["learnable"] is False
    assert updated["label_reason"] == "legacy_bootstrap_missing_metadata"
    assert updated["evidence_fields"]["legacy_category"] == "normal_logout"
    assert "ml_family" not in updated
    assert "label_family" not in updated
    assert untouched["behavior_label"] == "sudo_root_access"


def test_execute_legacy_bootstrap_backfill_aborts_when_candidate_count_exceeds_safety_cap():
    rows = []
    for idx in range(1, 502):
        rows.append({
            "id": idx,
            "source": "bootstrap",
            "label": "normal",
            "category": "system_service",
            "ts": float(idx),
            "event_class": "",
            "behavior_label": "",
            "source_trust": "",
            "model_usage_scope": "",
            "learnable": None,
            "label_reason": "",
        })
    db = _FakeDB(rows)

    report = main_module.execute_ml_legacy_bootstrap_backfill({}, db, apply=True)

    assert report["status"] == "aborted"
    assert report["updated_count"] == 0
    assert "candidate_count_safety_cap" in report["abort_reason"]
    assert db.backfill_calls == []


def test_legacy_bootstrap_backfill_cli_dispatches_dry_run(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(main_module.IntegrationSettings, "load", staticmethod(lambda config_dir="config": type("_I", (), {"log_overrides": {}})()))
    monkeypatch.setattr(
        main_module,
        "run_ml_legacy_bootstrap_backfill",
        lambda config, apply=False: print(f"ML Legacy Bootstrap Metadata Backfill\napply={apply}\ndb_write_attempted={apply}") or 0,
    )
    monkeypatch.setattr(
        main_module.sys,
        "argv",
        ["main.py", "--ml-backfill-legacy-bootstrap-metadata", "--dry-run"],
    )

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    out = capsys.readouterr().out
    assert exc.value.code == 0
    assert "ML Legacy Bootstrap Metadata Backfill" in out
    assert "apply=False" in out

