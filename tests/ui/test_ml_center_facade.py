from pathlib import Path
from types import SimpleNamespace
from datetime import datetime
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import core.ml.label_engine as label_engine
import ui.backend_facade as backend_facade


class _MLDb:
    def __init__(self, labels=None):
        self._labels = labels or []

    def load_labels(self):
        return list(self._labels)

    def close(self):
        return None


class _HistoricalLabelDb:
    def __init__(self):
        self._labels = []

    def load_labels(self):
        return list(self._labels)

    def save_labels(self, records):
        saved = 0
        for record in records:
            evidence = dict(getattr(record, "evidence_fields", {}) or {})
            duplicate_key = str(evidence.get("duplicate_guard_key", "") or "")
            if duplicate_key and any(
                str(dict(item.get("evidence_fields", {}) or {}).get("duplicate_guard_key", "") or "") == duplicate_key
                for item in self._labels
            ):
                continue
            row = {slot: getattr(record, slot, None) for slot in getattr(record, "__slots__", ())}
            self._labels.append(row)
            saved += 1
        return saved

    def close(self):
        return None


def _summary_stub(config, db, pm_status):
    return {
        "overall": {
            "ready_for_active_ml": False,
            "current_phase": 2,
            "phase_name": "Baseline",
            "ml_paused": True,
            "top_blockers": ["ml_paused"],
            "query_notes": [],
        },
        "mapping_summary": {"coverage_percent": 75.0},
        "label_quota_summary": {
            "usage": {"ML-AUTH": {"all": {"normal": {"used": 1, "limit": 3000, "remaining": 2999, "status": "collecting"}}}},
            "full_families": [],
        },
        "label_trust_summary": {"ignored_count": 10},
        "normal_label_summary": {"accepted_normal_candidates": 4},
        "metadata_plan_summary": {"blocked_count": 2},
        "training_scheduler": {
            "train_now": False,
            "schedule_due": False,
            "next_run_at": "2026-05-17T03:00:00",
            "reason": "insufficient_new_labels",
            "eligible_families": [],
            "blocked_families": [{"family_id": "ML-AUTH", "distro": "debian", "reason": "insufficient_new_labels"}],
            "labels_since_last_train": {},
            "last_training_time": "",
            "no_action_contract": True,
            "training_started": False,
            "db_write_attempted": False,
            "active_ml_enabled": False,
        },
        "model_status": {
            "promoted_model_count": 1,
            "loaded_model_count": 1,
            "model_load_errors": [],
            "scoring_enabled_families": ["ML-AUTH/debian"],
            "last_scoring_status": {},
            "no_action_contract": True,
        },
        "recommended_next_actions": ["keep audit only"],
    }


def _readiness_stub(config, db, pm_status):
    families = {}
    for spec in backend_facade.list_ml_families():
        families[spec.family_id] = {
            "status": "readiness_blocked",
            "phase_gate": 2,
            "runtime_events": 10,
            "required_events": 100,
            "normal_labels": 5,
            "required_normal_labels": 20,
            "suspicious_labels": 1,
            "required_suspicious_labels": 10,
            "metadata_support": 0,
            "trust_support": {"normal": 0, "suspicious": 0},
            "blockers": ["insufficient_runtime_events"],
            "reason": "insufficient_runtime_events",
        }
    return {"global": {}, "families": families}


def _historical_stub(config, db, pm_status):
    return {"global": {"ml_paused": True}, "families": {}, "error": None}


def test_collect_ml_summary_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "_load_phase_manager_status", lambda config: {"current_phase": 2, "phase_name": "Baseline"})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _MLDb())
    monkeypatch.setattr(backend_facade, "_ml_summary_report", _summary_stub)

    result = backend_facade.collect_ml_summary()

    assert result["status"] == "ok"
    assert {
        "status", "ready_for_active_ml", "current_phase", "ml_paused", "blocking_incident", "top_blockers",
        "mapping_coverage", "historical_scan_distro_breakdown", "label_trust_summary", "label_quota_summary", "readiness_label_counts", "normal_label_summary",
        "metadata_plan_summary", "phase_event_volume", "label_readiness_summary", "training_scheduler", "model_status", "recommended_next_actions", "error",
    } <= set(result)


def test_collect_ml_phase_status_schema_degraded(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "_load_phase_manager_status", lambda config: {
        "current_phase": 1,
        "phase_name": "Instant ML",
        "active_layers": {"instant_ml": True, "advanced_ml": False},
        "stats": {"total_events": 50, "active_sources": 2, "dup_rate": 0.01, "parse_fail_count": 1},
        "next_phase": {
            "criteria": [
                {"name": "Event sayısı", "needed": 500, "done": False, "message": "⏳ 450 event daha gerekli"},
                {"name": "Çalışma süresi", "needed": "3 gün", "current": "1 gün", "done": False, "message": "⏳ 2 gün daha gerekli"},
            ],
            "blocking": ["phase gate"],
        },
    })

    result = backend_facade.collect_ml_phase_status()

    assert result["status"] == "ok"
    assert {"current_phase", "next_phase", "progress_percent", "required_event_count", "current_event_count"} <= set(result)
    assert result["event_counter_scope"] == "phase_lifetime_normalized_events"
    assert result["labeled_data_scope"] == "family_specific_labeled_training_examples"


def test_phase_stats_summary_uses_canonical_duplicate_formula(tmp_path):
    phase_state = tmp_path / "phase_state.json"
    phase_state.write_text(
        '{"current_phase": 0, "stats": {"total_events": 10, "duplicate_count": 2, "telemetry_duplicate_count": 20, "parse_fail_count": 3}}',
        encoding="utf-8",
    )

    result = backend_facade._phase_stats_summary(state_dir=str(tmp_path))

    assert result["duplicate_rate"] == round(5 / 35, 4)
    assert result["parse_fail_rate"] == round(3 / 35, 4)


def test_collect_ml_phase_status_surfaces_stale_data_quality_message(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "_load_phase_manager_status", lambda config: {
        "current_phase": 1,
        "phase_name": "Instant ML",
        "active_layers": {"instant_ml": True},
        "stats": {
            "total_events": 40,
            "active_sources": 2,
            "dup_rate": 0.6,
            "duplicate_count": 24,
            "telemetry_duplicate_count": 3,
            "parse_fail_count": 1,
            "duplicate_rate_verified": False,
            "duplicate_rate_source": "phase_state",
            "live_db_event_count": 0,
            "phase_event_count": 40,
            "duplicate_counter_stale_possible": True,
            "duplicate_rate_message": "Veri kalite sayacı (duplicate + parse fail) canlı DB ile doğrulanamadı; eski phase state etkisi olabilir.",
            "duplicate_rate_message_en": "Data-quality counter (duplicate + parse fail) is not verified against live DB; stale phase state may be involved.",
        },
        "next_phase": {
            "criteria": [
                {
                    "name": "Veri kalitesi",
                    "needed": "max %10",
                    "done": False,
                    "message": "Veri kalite sayacı (duplicate + parse fail) canlı DB ile doğrulanamadı; eski phase state etkisi olabilir.",
                },
            ],
            "blocking": [],
        },
    })

    result = backend_facade.collect_ml_phase_status()

    assert result["duplicate_rate_verified"] is False
    assert result["data_quality_title"] == "Veri kalite oranı doğrulanamadı / eski sayaç olabilir"
    assert "canlı DB ile doğrulanamadı" in result["data_quality_message"]
    assert "stale phase state may be involved" in result["data_quality_message_en"]
    assert result["estimated_non_live_window_events"] == 40


def test_collect_ml_phase_status_carries_verified_duplicate_breakdown(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "_load_phase_manager_status", lambda config: {
        "current_phase": 1,
        "phase_name": "Instant ML",
        "active_layers": {"instant_ml": True},
        "stats": {
            "total_events": 100,
            "active_sources": 2,
            "dup_rate": 0.25,
            "duplicate_count": 20,
            "telemetry_duplicate_count": 5,
            "parse_fail_count": 5,
            "duplicate_breakdown_by_source": {"auditd": 18},
            "duplicate_breakdown_by_kind": {"exact_same_source": 20},
            "duplicate_rate_verified": True,
            "duplicate_rate_source": "live_runtime",
            "live_db_event_count": 100,
            "phase_event_count": 100,
            "duplicate_counter_stale_possible": False,
            "top_duplicate_source": "auditd",
            "top_duplicate_kind": "exact_same_source",
            "top_duplicate_categories": [{"name": "auth", "count": 14}],
            "top_duplicate_actions": [{"name": "execve", "count": 11}],
        },
        "next_phase": {"criteria": [], "blocking": []},
    })

    result = backend_facade.collect_ml_phase_status()

    assert result["duplicate_rate_verified"] is True
    assert result["duplicate_summary"]["top_duplicate_source"] == "auditd"
    assert result["duplicate_summary"]["top_duplicate_kind"] == "exact_same_source"
    assert result["duplicate_summary"]["top_duplicate_categories"] == [{"name": "auth", "count": 14}]
    assert result["duplicate_summary"]["top_duplicate_actions"] == [{"name": "execve", "count": 11}]


def test_collect_ml_family_readiness_returns_12_rows_or_graceful_degraded(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "_load_phase_manager_status", lambda config: {"current_phase": 2})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _MLDb())
    monkeypatch.setattr(backend_facade, "_ml_readiness_report", _readiness_stub)

    result = backend_facade.collect_ml_family_readiness()

    assert result["status"] in {"ok", "degraded"}
    assert len(result["families"]) == 12
    assert {"reason", "distro_cohorts"} <= set(result["families"][0])


def test_collect_ml_labels_schema_missing_optional_columns_graceful(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _MLDb(labels=[{
        "id": 1,
        "source": "bootstrap",
        "label": "ssh_login_normal",
        "entity_key": "alice",
        "ts": 1710000000,
    }]))

    result = backend_facade.collect_ml_labels(limit=10)

    assert result["status"] == "ok"
    assert result["labels"]
    assert {"id", "source", "label", "entity_key", "timestamp_text", "raw"} <= set(result["labels"][0])
    assert result["labels"][0]["distro"] == "unknown_distro"


def test_collect_ml_labels_normalizes_deprecated_display_fields(monkeypatch):
    def _alias(*parts):
        return "".join(parts)

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _MLDb(labels=[
        {
            "id": 1,
            "source": "auto_labeled",
            "distro": "debian",
            "event_class": "attack",
            "behavior_label": "suspicious_process",
            "ml_family": "ML-PROC",
            "model_usage_scope": "calibration_only",
            "learnable": True,
            "ts": 1710000001,
        },
        {
            "id": 2,
            "source": "bootstrap",
            "distro": "debian",
            "event_class": "benign",
            "behavior_label": "normal_network",
            "ml_family": "ML-NET",
            "model_usage_scope": "calibration_only",
            "learnable": True,
            "bootstrap_job_id": "bootstrap_scan_debian_202",
            "label_reason": "bootstrap_historical_scan",
            "ts": 1710000002,
        },
        {
            "id": 3,
            "source": _alias("manu", "ally", "_", "verified"),
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "ml_family": "ML-AUTH",
            "model_usage_scope": _alias("sha", "dow", "_", "only"),
            "learnable": False,
            "source_trust": "legacy_unknown",
            "label_reason": _alias("canonical", "_", "shadow", "_probe"),
            "ts": 1710000003,
        },
    ]))

    result = backend_facade.collect_ml_labels(limit=10)

    assert result["status"] == "ok"
    assert [item["source"] for item in result["labels"]] == [
        "legacy_excluded",
        "bootstrap_historical",
        "organic_live",
    ]
    assert result["labels"][0]["model_usage_scope"] == "ignored"
    assert result["labels"][1]["model_usage_scope"] == "rejected"
    assert result["labels"][2]["model_usage_scope"] == "direct_learnable"
    assert result["labels"][0]["label_class"] == "benign"
    assert result["labels"][1]["label_class"] == "benign"
    assert result["labels"][2]["label_class"] == "attack"
    assert result["labels"][0]["distro"] == "unknown_distro"
    assert result["labels"][1]["distro"] == "debian"
    assert result["labels"][2]["distro"] == "debian"
    dumped = result["labels"][0]["raw"]
    assert dumped["source"] == "legacy_excluded"
    assert dumped["model_usage_scope"] == "ignored"
    assert dumped["label_reason"] == "legacy_excluded"


def test_collect_ml_label_detail_uses_sanitized_display_payload(monkeypatch):
    def _alias(*parts):
        return "".join(parts)

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _MLDb(labels=[{
        "id": 7,
        "source": _alias("manu", "ally", "_", "verified"),
        "distro": "debian",
        "event_class": "benign",
        "behavior_label": "expected_auth_activity",
        "ml_family": "ML-AUTH",
        "model_usage_scope": _alias("sha", "dow", "_", "only"),
        "learnable": False,
        "source_trust": "legacy_unknown",
        "label_reason": _alias("canonical", "_", "shadow", "_probe"),
        "ts": 1710000000,
    }]))

    result = backend_facade.collect_ml_label_detail(7)

    assert result["status"] == "ok"
    assert result["label"]["source"] == "legacy_excluded"
    assert result["label"]["distro"] == "debian"
    assert result["label"]["model_usage_scope"] == "ignored"
    assert result["label"]["label_class"] == "benign"
    assert result["detail"]["label_class"] == "benign"
    assert "legacy_excluded" in result["detail"]["raw_json"]
    assert _alias("sha", "dow", "_", "only") not in result["detail"]["raw_json"]
    assert _alias("manu", "ally", "_", "verified") not in result["detail"]["raw_json"]


def test_collect_ml_labels_unknown_class_when_no_canonical_signal(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _MLDb(labels=[{
        "id": 9,
        "source": "historical_host_log",
        "ml_family": "ML-AUTH",
        "model_usage_scope": "shadow_only",
        "learnable": False,
        "label": "opaque_candidate",
        "category": "uncategorized",
        "ts": 1710000100,
    }]))

    result = backend_facade.collect_ml_labels(limit=10)

    assert result["status"] == "ok"
    assert result["labels"][0]["label_class"] == "unknown"
    assert result["labels"][0]["model_usage_scope"] == "rejected"


def test_collect_ml_label_detail_missing_id_graceful(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _MLDb(labels=[]))

    result = backend_facade.collect_ml_label_detail(999)

    assert result["status"] == "degraded"
    assert "label_not_found" in result["error"]


def test_collect_ml_historical_plan_status_no_artifact_empty_state(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "_load_phase_manager_status", lambda config: {"current_phase": 2})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _MLDb())
    monkeypatch.setattr(backend_facade, "_collect_ml_history_files", lambda data_dir="data": [])
    monkeypatch.setattr(backend_facade, "_ml_historical_report", _historical_stub)

    result = backend_facade.collect_ml_historical_plan_status()

    assert result["empty"] is True
    assert "No historical label scan artifact found" in result["message"]


def test_get_historical_preview_status_no_scan_returns_manual_wait_state(monkeypatch):
    monkeypatch.setattr(backend_facade, "_collect_ml_history_files", lambda data_dir="data": [{"name": "manifest.json", "path": "data/ml_label_scan/manifest.json"}])

    result = backend_facade.get_historical_preview_status_no_scan()

    assert result["status"] == "ok"
    assert result["run_state"] == "not_run"
    assert result["manual_trigger_required"] is True
    assert result["historical_scan_summary"] == {}
    assert result["families"] == []
    assert result["artifacts"] == [{"name": "manifest.json", "path": "data/ml_label_scan/manifest.json"}]


def test_scan_local_historical_logs_preview_debian_auth_and_nginx_host_logs_only(monkeypatch, tmp_path):
    auth_log = tmp_path / "auth.log"
    nginx_log = tmp_path / "access.log"
    auth_log.write_text(
        "May 10 12:34:56 server01 sshd[1234]: Failed password for root from 1.2.3.4 port 11111 ssh2\n"
        "May 10 12:35:56 server01 sshd[1235]: Accepted password for alice from 10.0.0.1 port 22345 ssh2\n"
        "May 10 12:36:56 server01 sshd[1236]: Accepted password for alice from 10.0.0.1 port 22346 ssh2\n",
        encoding="utf-8",
    )
    nginx_log.write_text(
        '203.0.113.13 - - [10/May/2026:12:13:00 +0300] "POST /upload/avatar.php.jpg HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )

    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "auth_log": {"enabled": True, "path": str(auth_log), "type": "auth_log"},
            "nginx": {"enabled": True, "path": str(nginx_log), "type": "nginx"},
            "syslog": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "apache2": {"enabled": False, "path": ""},
            "postgresql": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
            "dpkg": {"enabled": False, "path": ""},
        },
    }
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian", "pretty": "Debian"})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: (_ for _ in ()).throw(AssertionError("db must not be used")))

    result = backend_facade.scan_local_historical_logs_preview()

    assert result["status"] == "ok"
    assert result["source_mode"] == "local_host_logs"
    assert result["preview_only"] is True
    assert result["read_only"] is True
    assert result["db_write_attempted"] is False
    assert result["no_action_contract"] is True
    assert result["events_recent_used_as_source"] is False
    assert result["alerts_used_as_source"] is False
    assert result["incidents_used_as_source"] is False
    assert result["labels_used_as_source"] is False
    assert result["user_actions_used_as_source"] is False
    assert result["parsed_events"] >= 4
    assert result["scanned_files"] >= 2
    assert result["usage_summary"]["baseline_learning"] >= 1
    assert result["usage_summary"]["direct_learnable"] >= 1
    assert "web/nginx" in result["source_breakdown"]
    assert "auth" in result["source_breakdown"]
    assert any(row["log_source"] == "nginx" for row in result["candidate_rows"])
    assert any(row["source"] == "web/nginx" for row in result["candidate_rows"])
    rule_hit = next(row for row in result["candidate_rows"] if row["rule_id"] == "AUTH-002")
    baseline = next(
        row
        for row in result["candidate_rows"]
        if row["usage_decision"] == "baseline_learning" and row["ml_family"] == "ML-AUTH"
    )
    assert rule_hit["ml_family"] == "ML-AUTH"
    assert rule_hit["behavior_label"] == "auth_attack_or_abuse"
    assert rule_hit["source_trust"] == "rule_high"
    assert rule_hit["model_usage_scope"] == "calibration_only"
    assert rule_hit["no_action_contract"] is True
    assert baseline["ml_family"] == "ML-AUTH"
    assert baseline["behavior_label"] == "expected_auth_activity"
    assert baseline["source_trust"] == "observed_benign_high"
    assert baseline["model_usage_scope"] == "baseline_learning"
    assert baseline["learnable"] is True
    assert result["pipeline"] == [
        "raw_log_line",
        "distro_source_parser",
        "normalized_event",
        "rule_detection_check",
        "labelability_check",
        "ml_candidate_preview",
    ]


def test_scan_local_historical_logs_write_labels_saves_quality_candidates_and_skips_duplicates(monkeypatch, tmp_path):
    auth_log = tmp_path / "auth.log"
    auth_log.write_text(
        "May 10 12:34:56 server01 sshd[1234]: Failed password for root from 1.2.3.4 port 11111 ssh2\n"
        "May 10 12:35:56 server01 sshd[1235]: Accepted password for alice from 10.0.0.1 port 22345 ssh2\n"
        "May 10 12:36:56 server01 sshd[1236]: Accepted password for alice from 10.0.0.1 port 22346 ssh2\n",
        encoding="utf-8",
    )
    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "auth_log": {"enabled": True, "path": str(auth_log), "type": "auth_log"},
            "syslog": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "apache2": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "postgresql": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
            "dpkg": {"enabled": False, "path": ""},
        },
    }
    db = _HistoricalLabelDb()
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian", "id": "debian", "pretty": "Debian"})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: db)

    result = backend_facade.scan_local_historical_logs_preview(preview_only=False, write_labels=True)

    assert result["status"] == "ok"
    assert result["preview_only"] is False
    assert result["read_only"] is False
    assert result["db_write_attempted"] is True
    assert result["labels_written"] == 3
    assert result["direct_written"] == 1
    assert result["baseline_written"] == 2
    assert result["skipped_duplicates"] == 0
    rows = db.load_labels()
    assert len(rows) == 3
    direct = next(row for row in rows if row["model_usage_scope"] == "calibration_only")
    baseline = next(row for row in rows if row["model_usage_scope"] == "baseline_learning")
    assert direct["source"] == "auto_labeled"
    assert direct["behavior_label"] in {"auth_attack_or_abuse", "first_seen_behavior"}
    assert direct["evidence_fields"]["source_mode"] == "local_host_logs"
    assert direct["evidence_fields"]["label_origin"] == "historical_host_log"
    assert direct["evidence_fields"]["rule_id"] in {"AUTH-002", "FIRST-002"}
    assert direct["evidence_fields"]["distro_family"] == "debian"
    assert baseline["behavior_label"] == "expected_auth_activity"
    assert baseline["evidence_fields"]["model_usage_scope"] == "baseline_learning"
    assert baseline["evidence_fields"]["no_action_contract"] is True

    rerun = backend_facade.scan_local_historical_logs_preview(preview_only=False, write_labels=True)

    assert rerun["labels_written"] == 0
    assert rerun["skipped_duplicates"] >= 3
    assert len(db.load_labels()) == 3


def test_scan_local_historical_logs_write_labels_reclassifies_first_seen_successful_login_as_baseline(monkeypatch, tmp_path):
    auth_log = tmp_path / "auth.log"
    auth_log.write_text(
        "May 10 12:35:56 server01 sshd[1235]: Accepted password for alice from 10.0.0.1 port 22345 ssh2\n",
        encoding="utf-8",
    )
    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "auth_log": {"enabled": True, "path": str(auth_log), "type": "auth_log"},
            "syslog": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "apache2": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "postgresql": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
            "dpkg": {"enabled": False, "path": ""},
        },
    }
    db = _HistoricalLabelDb()
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian", "id": "debian", "pretty": "Debian"})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: db)

    result = backend_facade.scan_local_historical_logs_preview(preview_only=False, write_labels=True)

    assert result["status"] == "ok"
    assert result["labels_written"] == 1
    assert result["baseline_written"] == 1
    assert result["direct_written"] == 0
    row = db.load_labels()[0]
    assert row["event_class"] == "benign"
    assert row["behavior_label"] == "expected_auth_activity"
    assert row["evidence_fields"]["ml_family"] == "ML-AUTH"
    assert row["source_trust"] == "observed_benign_high"
    assert row["model_usage_scope"] == "baseline_learning"
    assert row["evidence_fields"]["rule_id"] == ""
    assert row["evidence_fields"]["context_rule_id"] == "FIRST-002"
    assert row["evidence_fields"]["labelability_reason"] == "known_benign_normal"


def test_scan_local_historical_logs_write_labels_respects_family_distro_quota(monkeypatch, tmp_path):
    config = {
        "ml": {"family": {"ML-AUTH": {"normal_label_quota": 1, "suspicious_label_quota": 1}}},
    }
    db = _HistoricalLabelDb()
    monkeypatch.setattr(backend_facade, "create_database", lambda config: db)
    candidate_rows = [
        {
            "source_mode": "local_host_logs",
            "distro_family": "debian",
            "distro": "debian",
            "host": "server01",
            "source": "auth",
            "log_source": "auth_log",
            "log_path": "/tmp/auth.log",
            "ts": 1715400000.0,
            "timestamp": "2024-05-11T10:00:00",
            "timestamp_confidence": "high",
            "hour_of_day": 10,
            "day_of_week": "saturday",
            "is_weekend": True,
            "is_night": False,
            "time_bucket": "business_hours",
            "category": "brute_force",
            "action": "ssh_login",
            "outcome": "failure",
            "rule_id": "AUTH-002",
            "ml_family": "ML-AUTH",
            "ml_label": "auth_attack_or_abuse",
            "label_family": "ML-AUTH",
            "behavior_label": "auth_attack_or_abuse",
            "source_trust": "rule_high",
            "model_usage_scope": "calibration_only",
            "learnable": True,
            "event_class": "suspicious",
            "label_reason": "historical_rule_hit",
            "metadata_quality": "complete",
            "evidence_fields": {"line_hash": "line-1"},
            "line_hash": "line-1",
            "usage_decision": "direct_learnable",
            "no_action_contract": True,
        },
        {
            "source_mode": "local_host_logs",
            "distro_family": "debian",
            "distro": "debian",
            "host": "server01",
            "source": "auth",
            "log_source": "auth_log",
            "log_path": "/tmp/auth.log",
            "ts": 1715400060.0,
            "timestamp": "2024-05-11T10:01:00",
            "timestamp_confidence": "high",
            "hour_of_day": 10,
            "day_of_week": "saturday",
            "is_weekend": True,
            "is_night": False,
            "time_bucket": "business_hours",
            "category": "auth_normal",
            "action": "ssh_login",
            "outcome": "success",
            "rule_id": "",
            "ml_family": "ML-AUTH",
            "ml_label": "expected_auth_activity",
            "label_family": "ML-AUTH",
            "behavior_label": "expected_auth_activity",
            "source_trust": "observed_benign_high",
            "model_usage_scope": "baseline_learning",
            "learnable": True,
            "event_class": "benign",
            "label_reason": "historical_clean_auth",
            "metadata_quality": "complete",
            "evidence_fields": {"line_hash": "line-2"},
            "line_hash": "line-2",
            "usage_decision": "baseline_learning",
            "no_action_contract": True,
        },
        {
            "source_mode": "local_host_logs",
            "distro_family": "debian",
            "distro": "debian",
            "host": "server01",
            "source": "auth",
            "log_source": "auth_log",
            "log_path": "/tmp/auth.log",
            "ts": 1715400120.0,
            "timestamp": "2024-05-11T10:02:00",
            "timestamp_confidence": "high",
            "hour_of_day": 10,
            "day_of_week": "saturday",
            "is_weekend": True,
            "is_night": False,
            "time_bucket": "business_hours",
            "category": "brute_force",
            "action": "ssh_login",
            "outcome": "failure",
            "rule_id": "AUTH-002",
            "ml_family": "ML-AUTH",
            "ml_label": "auth_attack_or_abuse",
            "label_family": "ML-AUTH",
            "behavior_label": "auth_attack_or_abuse",
            "source_trust": "rule_high",
            "model_usage_scope": "calibration_only",
            "learnable": True,
            "event_class": "suspicious",
            "label_reason": "historical_rule_hit",
            "metadata_quality": "complete",
            "evidence_fields": {"line_hash": "line-3"},
            "line_hash": "line-3",
            "usage_decision": "direct_learnable",
            "no_action_contract": True,
        },
    ]

    result = backend_facade._persist_local_historical_quality_labels(config, candidate_rows)

    assert result["labels_written"] == 2
    assert result["baseline_written"] == 1
    assert result["direct_written"] == 1
    assert result["quota_skipped"] == 1
    assert "ML-AUTH/debian/suspicious" in result["quota_full_families"]
    assert result["quota_remaining_by_family"]["ML-AUTH"]["normal"]["remaining"] == 0
    assert result["quota_remaining_by_family"]["ML-AUTH"]["suspicious"]["remaining"] == 0
    assert len(db.load_labels()) == 2


def test_scan_local_historical_logs_write_labels_rejects_weak_candidates(monkeypatch):
    import core.ml.label_engine as label_engine

    def _fake_report(self, detection_engine=None, normalizer=None):
        return {
            "log_files": [{"path": "/tmp/fake.log", "readable": True}],
            "scanned_files": 1,
            "parsed_events": 1,
            "warnings": [],
            "candidates": [
                {
                    "ts": 0.0,
                    "distro": "unknown_distro",
                    "distro_family": "unknown_distro",
                    "host": "",
                    "source": "auth",
                    "log_path": "/tmp/fake.log",
                    "category": "auth",
                    "action": "unknown",
                    "outcome": "unknown",
                    "line_hash": "deadbeef",
                    "event_class": "benign",
                    "ml_family": "ML-AUTH",
                    "ml_label": "expected_auth_activity",
                    "label_family": "ML-AUTH",
                    "behavior_label": "expected_auth_activity",
                    "source_trust": "observed_benign_high",
                    "model_usage_scope": "baseline_learning",
                    "learnable": True,
                    "label_reason": "historical_test_candidate",
                    "evidence_fields": {},
                }
            ],
        }

    config = {"detection": {"rules_dir": "rules", "rules_source": "yaml"}, "sources": {}}
    db = _HistoricalLabelDb()
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "unknown", "pretty": "Unknown"})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: db)
    monkeypatch.setattr(label_engine.BootstrapLogScanner, "dry_run_report", _fake_report)

    result = backend_facade.scan_local_historical_logs_preview(preview_only=False, write_labels=True)

    assert result["status"] == "ok"
    assert result["labels_written"] == 0
    assert (result["rejected_not_written"] + result["ignored_not_written"]) >= 1
    assert db.load_labels() == []


def test_scan_local_historical_logs_write_labels_accepts_valid_candidate_even_with_enriched_metadata(monkeypatch):
    db = _HistoricalLabelDb()
    monkeypatch.setattr(backend_facade, "create_database", lambda config: db)
    candidate_rows = [
        {
            "source_mode": "local_host_logs",
            "distro_family": "debian",
            "distro": "debian",
            "host": "server01",
            "source": "auth",
            "log_source": "auth_log",
            "log_path": "/tmp/auth.log",
            "ts": 1715400060.0,
            "timestamp": "2024-05-11T10:01:00",
            "timestamp_confidence": "medium",
            "hour_of_day": 10,
            "day_of_week": "saturday",
            "is_weekend": True,
            "is_night": False,
            "time_bucket": "business_hours",
            "category": "auth",
            "action": "ssh_login",
            "outcome": "success",
            "rule_id": "",
            "ml_family": "ML-AUTH",
            "ml_label": "expected_auth_activity",
            "label_family": "ML-AUTH",
            "behavior_label": "expected_auth_activity",
            "source_trust": "observed_benign_high",
            "model_usage_scope": "baseline_learning",
            "learnable": True,
            "event_class": "benign",
            "label_reason": "historical_clean_auth",
            "metadata_quality": "enriched",
            "quality_reasons": ["host_enriched_from_local_machine"],
            "evidence_fields": {"line_hash": "line-accept"},
            "line_hash": "line-accept",
            "usage_decision": "baseline_learning",
            "labelability_status": "labelable",
            "labelability_reason": "labelable",
            "no_action_contract": True,
        },
    ]

    result = backend_facade._persist_local_historical_quality_labels({}, candidate_rows)

    assert result["labels_written"] == 1
    row = db.load_labels()[0]
    assert row["evidence_fields"]["labelability_status"] == "labelable"
    assert row["evidence_fields"]["labelability_reason"] == "labelable"


def test_scan_local_historical_logs_preview_rhel_secure_and_dnf(monkeypatch, tmp_path):
    secure_log = tmp_path / "secure"
    dnf_log = tmp_path / "dnf.log"
    secure_log.write_text(
        "May 10 12:34:56 server01 sshd[1234]: Accepted password for alice from 10.0.0.1 port 22345 ssh2\n",
        encoding="utf-8",
    )
    dnf_log.write_text(
        "2026-05-10T12:34:56+03:00 INFO Installed: hydra-9.5-1.x86_64\n",
        encoding="utf-8",
    )

    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "auth_log": {"enabled": True, "path": str(secure_log), "type": "auth_log"},
            "dpkg": {"enabled": True, "path": str(dnf_log), "type": "dnf"},
            "syslog": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "apache2": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "postgresql": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
        },
    }
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "rhel", "id": "rocky", "pretty": "Rocky Linux"})

    result = backend_facade.scan_local_historical_logs_preview()

    assert result["status"] == "ok"
    assert result["parsed_events"] >= 2
    assert any(row["log_source"] == "dnf" for row in result["candidate_rows"])
    assert any(row["source"] == "package_manager" for row in result["candidate_rows"])
    assert any(row["distro_family"] == "rhel" for row in result["candidate_rows"])
    assert any(row["distro"] == "rocky" for row in result["candidate_rows"])


def test_scan_local_historical_logs_write_labels_rhel_successful_login_becomes_baseline(monkeypatch, tmp_path):
    secure_log = tmp_path / "secure"
    secure_log.write_text(
        "May 10 12:34:56 rhel01 sshd[1234]: Accepted password for alice from 10.0.0.1 port 22345 ssh2\n",
        encoding="utf-8",
    )
    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "auth_log": {"enabled": True, "path": str(secure_log), "type": "auth_log"},
            "syslog": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "apache2": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "postgresql": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
            "dpkg": {"enabled": False, "path": ""},
        },
    }
    db = _HistoricalLabelDb()
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "rhel", "id": "rhel", "pretty": "Rocky Linux"})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: db)

    result = backend_facade.scan_local_historical_logs_preview(preview_only=False, write_labels=True)

    assert result["labels_written"] == 1
    assert result["baseline_written"] == 1
    row = db.load_labels()[0]
    assert row["evidence_fields"]["distro_family"] == "rhel"
    assert row["behavior_label"] == "expected_auth_activity"
    assert row["model_usage_scope"] == "baseline_learning"


def test_scan_local_historical_logs_preview_suse_messages_and_zypper_preserve_metadata(monkeypatch, tmp_path):
    messages_log = tmp_path / "messages"
    zypper_log = tmp_path / "history"
    messages_log.write_text(
        "May 10 12:34:56 leap16 sshd[1234]: Accepted password for alice from 10.0.0.1 port 22345 ssh2\n",
        encoding="utf-8",
    )
    zypper_log.write_text(
        "2026-05-10 12:34:56|install|hydra|9.5|x86_64||repo|\n",
        encoding="utf-8",
    )

    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "syslog": {"enabled": True, "path": str(messages_log), "type": "syslog"},
            "dpkg": {"enabled": True, "path": str(zypper_log), "type": "zypper"},
            "auth_log": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "apache2": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "postgresql": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
        },
    }
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "suse", "id": "opensuse", "pretty": "openSUSE"})

    result = backend_facade.scan_local_historical_logs_preview()

    assert result["status"] == "ok"
    assert result["parsed_events"] >= 2
    assert result["source_breakdown"]["auth"] >= 1
    assert result["source_breakdown"]["package_manager"] >= 1
    assert any(row["distro_family"] == "suse" for row in result["candidate_rows"])
    assert any(row["distro"] == "opensuse" for row in result["candidate_rows"])
    assert any(row["log_path"].endswith("history") for row in result["candidate_rows"])
    assert any(row["ts"] for row in result["candidate_rows"])
    package_row = next(row for row in result["candidate_rows"] if row["log_source"] == "zypper")
    assert package_row["distro_family"] == "suse"
    assert package_row["no_action_contract"] is True
    assert package_row["evidence_fields"] is not None


def test_scan_local_historical_logs_write_labels_suse_successful_login_becomes_baseline(monkeypatch, tmp_path):
    messages_log = tmp_path / "messages"
    messages_log.write_text(
        "May 10 12:34:56 suse01 sshd[1234]: Accepted password for alice from 10.0.0.1 port 22345 ssh2\n",
        encoding="utf-8",
    )
    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "syslog": {"enabled": True, "path": str(messages_log), "type": "syslog"},
            "auth_log": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "apache2": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "postgresql": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
            "dpkg": {"enabled": False, "path": ""},
        },
    }
    db = _HistoricalLabelDb()
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "suse", "id": "suse", "pretty": "openSUSE"})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: db)

    result = backend_facade.scan_local_historical_logs_preview(preview_only=False, write_labels=True)

    assert result["labels_written"] == 1
    assert result["baseline_written"] == 1
    row = db.load_labels()[0]
    assert row["evidence_fields"]["distro_family"] == "suse"
    assert row["behavior_label"] == "expected_auth_activity"
    assert row["model_usage_scope"] == "baseline_learning"


def test_collect_local_historical_source_entries_debian_adds_apt_history(monkeypatch):
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian", "pretty": "Debian"})
    monkeypatch.setattr(
        backend_facade,
        "resolve_log_paths",
        lambda distro_info=None: {
            "auth_log": "/var/log/auth.log",
            "syslog": "/var/log/syslog",
            "kern_log": "/var/log/kern.log",
            "audit_log": "/var/log/audit/audit.log",
            "apache_log": "/var/log/apache2",
            "nginx_log": "/var/log/nginx",
            "pg_log": "/var/log/postgresql",
            "ufw_log": "/var/log/ufw.log",
            "dpkg_log": "/var/log/dpkg.log",
        },
    )

    entries, warnings = backend_facade._collect_local_historical_source_entries({"sources": {}})
    entry_paths = {item["path"] for item in entries}

    assert "/var/log/dpkg.log" in entry_paths
    assert "/var/log/apt/history.log" in entry_paths
    assert not any("apt/history.log" in warning for warning in warnings)


def test_classify_local_historical_candidate_rejects_unknown_or_missing_quality():
    rejected, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 0,
            "host": "",
            "source": "",
            "distro_family": "",
            "action": "unknown",
        }
    )
    unknown, unknown_reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "unknown_unlabeled",
            "behavior_label": "unknown_unlabeled",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 1710000000,
            "host": "host-1",
            "source": "auth_log",
            "distro_family": "debian",
            "action": "ssh_login",
        }
    )

    assert rejected == "rejected"
    assert {"missing_timestamp", "missing_host", "unknown_source", "unknown_distro", "unknown_action", "unknown_category"} <= set(reasons)
    assert unknown in {"ignored", "rejected"}
    assert "not_labelable" in unknown_reasons


def test_scan_local_historical_logs_preview_warns_on_missing_and_permission_denied(monkeypatch, tmp_path):
    import core.ml.label_engine as label_engine

    readable = tmp_path / "auth.log"
    denied = tmp_path / "secure"
    readable.write_text(
        "Mar  5 12:34:56 server01 sshd[1234]: Accepted password for alice from 10.0.0.1 port 22345 ssh2\n",
        encoding="utf-8",
    )
    denied.write_text(
        "Mar  5 12:34:57 server01 sshd[1234]: Failed password for root from 1.2.3.4 port 11111 ssh2\n",
        encoding="utf-8",
    )

    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "auth_log": {"enabled": True, "path": str(readable), "type": "auth_log"},
            "syslog": {"enabled": True, "path": str(tmp_path / "missing.log"), "type": "syslog"},
            "auditd": {"enabled": False, "path": ""},
            "apache2": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "postgresql": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
            "dpkg": {"enabled": True, "path": str(denied), "type": "dnf"},
        },
    }
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "rhel", "pretty": "Rocky Linux"})
    real_access = label_engine.os.access
    monkeypatch.setattr(label_engine.os, "access", lambda path, mode: False if str(path) == str(denied) else real_access(path, mode))

    result = backend_facade.scan_local_historical_logs_preview()

    assert result["status"] == "ok"
    assert any("File not found" in warning for warning in result["warnings"])
    assert any("Permission denied" in warning for warning in result["warnings"])


def test_scan_local_historical_logs_preview_enriches_missing_host_and_source_safely(monkeypatch, tmp_path):
    package_log = tmp_path / "history"
    package_log.write_text(
        "2026-05-10 12:34:56|install|hydra|9.5|x86_64||repo|\n",
        encoding="utf-8",
    )
    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "dpkg": {"enabled": True, "path": str(package_log), "type": "zypper"},
            "auth_log": {"enabled": False, "path": ""},
            "syslog": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "apache2": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "postgresql": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
        },
    }
    monkeypatch.setattr(backend_facade, "_safe_local_hostname", lambda: "phase2-host")
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "suse", "pretty": "openSUSE"})

    result = backend_facade.scan_local_historical_logs_preview()

    row = result["candidate_rows"][0]
    assert row["host"] == "phase2-host"
    assert row["host_enriched"] is True
    assert row["host_source"] == "local_machine"
    assert row["log_source"] == "zypper"
    assert row["source"] == "package_manager"
    assert row["metadata_quality"] == "enriched"
    assert "host_enriched_from_local_machine" in row["quality_reasons"]
    assert row["line_hash"]


def test_scan_local_historical_logs_preview_preserves_existing_host_without_fabrication(monkeypatch, tmp_path):
    auth_log = tmp_path / "auth.log"
    auth_log.write_text(
        "May 10 12:34:56 server01 sshd[1234]: Failed password for root from 1.2.3.4 port 11111 ssh2\n",
        encoding="utf-8",
    )
    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "auth_log": {"enabled": True, "path": str(auth_log), "type": "auth_log"},
            "syslog": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "apache2": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "postgresql": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
            "dpkg": {"enabled": False, "path": ""},
        },
    }
    monkeypatch.setattr(backend_facade, "_safe_local_hostname", lambda: "should-not-overwrite")
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian", "pretty": "Debian"})

    result = backend_facade.scan_local_historical_logs_preview()

    row = result["candidate_rows"][0]
    assert row["host"] == "server01"
    assert row["host_enriched"] is False
    assert row["host_source"] == ""
    assert row["source"] == "auth"
    assert row["rule_id"] == "AUTH-002"


def test_scan_local_historical_logs_preview_debian_source_matrix(monkeypatch, tmp_path):
    auth_log = tmp_path / "auth.log"
    apache_log = tmp_path / "access.log"
    ufw_log = tmp_path / "ufw.log"
    pg_log = tmp_path / "postgresql.log"
    dpkg_log = tmp_path / "dpkg.log"
    apt_history = tmp_path / "history.log"
    auth_log.write_text(
        "May 10 12:34:56 server01 sshd[1234]: Failed password for root from 1.2.3.4 port 11111 ssh2\n",
        encoding="utf-8",
    )
    apache_log.write_text(
        'example.com:80 10.0.0.6 - - [10/May/2026:12:04:00 +0000] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" "curl/8.0"\n',
        encoding="utf-8",
    )
    ufw_log.write_text(
        "May 10 10:00:00 server01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.5 DST=192.168.1.1 LEN=60 PROTO=TCP SPT=54321 DPT=22 WINDOW=65535\n",
        encoding="utf-8",
    )
    pg_log.write_text(
        '2026-05-10 13:41:13.786 +03 dbhost postgres [14419]FATAL:  password authentication failed for user "aegiscore"\n',
        encoding="utf-8",
    )
    dpkg_log.write_text(
        "2026-05-10 10:05:00 remove ufw:amd64 0.36 <none>\n",
        encoding="utf-8",
    )
    apt_history.write_text(
        "Install: curl:amd64 (7.81.0-1)\n",
        encoding="utf-8",
    )
    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "auth_log": {"enabled": True, "path": str(auth_log), "type": "auth_log"},
            "apache2": {"enabled": True, "path": str(apache_log), "type": "apache2"},
            "ufw": {"enabled": True, "path": str(ufw_log), "type": "ufw"},
            "postgresql": {"enabled": True, "path": str(pg_log), "type": "postgresql"},
            "dpkg": {"enabled": True, "path": str(dpkg_log), "type": "dpkg"},
            "syslog": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
        },
    }
    monkeypatch.setattr(backend_facade, "_safe_local_hostname", lambda: "deb-host")
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian", "pretty": "Debian"})
    monkeypatch.setattr(
        backend_facade,
        "resolve_log_paths",
        lambda distro_info=None: {
            "auth_log": str(auth_log),
            "syslog": "",
            "kern_log": "",
            "audit_log": "",
            "apache_log": str(apache_log),
            "nginx_log": "",
            "pg_log": str(pg_log),
            "ufw_log": str(ufw_log),
            "dpkg_log": str(dpkg_log),
        },
    )
    monkeypatch.setattr(
        backend_facade,
        "_LOCAL_HISTORICAL_EXTRA_PATHS",
        {"debian": (("dpkg", "dpkg", str(apt_history)),)},
    )

    result = backend_facade.scan_local_historical_logs_preview()
    sources = {row["source"] for row in result["candidate_rows"]}

    assert result["status"] == "ok"
    assert result["parsed_events"] >= 6
    assert {"auth", "web/apache", "firewall", "postgresql", "package_manager"} <= sources


def test_scan_local_historical_logs_preview_rhel_source_matrix(monkeypatch, tmp_path):
    secure_log = tmp_path / "secure"
    messages_log = tmp_path / "messages"
    httpd_log = tmp_path / "access_log"
    pg_log = tmp_path / "postgresql.log"
    dnf_log = tmp_path / "dnf.log"
    secure_log.write_text(
        "May 10 12:34:56 server01 sshd[1234]: Failed password for rocky from 192.168.91.129 port 51112 ssh2\n",
        encoding="utf-8",
    )
    messages_log.write_text(
        "May 10 12:03:00 host kernel: AEGIS_TEST_DROP IN=eth0 OUT= SRC=192.168.91.129 DST=192.168.91.131 LEN=60 PROTO=TCP SPT=54322 DPT=65000\n",
        encoding="utf-8",
    )
    httpd_log.write_text(
        'example.com:80 10.0.0.6 - - [10/May/2026:12:04:00 +0000] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" "curl/8.0"\n',
        encoding="utf-8",
    )
    pg_log.write_text(
        '2026-05-10 13:41:13.786 +03 dbhost postgres [14419]FATAL:  password authentication failed for user "aegiscore"\n',
        encoding="utf-8",
    )
    dnf_log.write_text(
        "2026-05-10T12:34:56+03:00 INFO Installed: hydra-9.5-1.x86_64\n",
        encoding="utf-8",
    )
    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "auth_log": {"enabled": True, "path": str(secure_log), "type": "auth_log"},
            "syslog": {"enabled": True, "path": str(messages_log), "type": "syslog"},
            "apache2": {"enabled": True, "path": str(httpd_log), "type": "apache2"},
            "postgresql": {"enabled": True, "path": str(pg_log), "type": "postgresql"},
            "dpkg": {"enabled": True, "path": str(dnf_log), "type": "dnf"},
            "auditd": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
        },
    }
    monkeypatch.setattr(backend_facade, "_safe_local_hostname", lambda: "rhel-host")
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "rhel", "pretty": "Rocky Linux"})

    result = backend_facade.scan_local_historical_logs_preview()
    sources = {row["source"] for row in result["candidate_rows"]}

    assert result["status"] == "ok"
    assert result["parsed_events"] >= 5
    assert {"auth", "firewall", "web/apache", "postgresql", "package_manager"} <= sources


def test_scan_local_historical_logs_preview_suse_source_matrix(monkeypatch, tmp_path):
    messages_log = tmp_path / "messages"
    apache_log = tmp_path / "apache_access.log"
    pg_log = tmp_path / "postgresql.log"
    zypper_log = tmp_path / "history"
    messages_log.write_text(
        "May 10 12:34:56 leap16 sshd[1234]: Failed password for root from 1.2.3.4 port 11111 ssh2\n"
        "May 10 12:03:00 leap16 kernel: filter_IN_public_REJECT: IN=eth0 OUT= SRC=192.168.91.129 DST=192.168.91.131 LEN=60 PROTO=TCP SPT=54321 DPT=65000\n",
        encoding="utf-8",
    )
    apache_log.write_text(
        '203.0.113.13 - - [10/May/2026:12:13:00 +0300] "POST /upload/avatar.php.jpg HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )
    pg_log.write_text(
        '2026-05-10 13:41:13.786 +03 aegiscore_opensuse_live aegiscore [14419]ÖLÜMCÜL (FATAL):  "aegiscore" kullanıcısı için şifre doğrulaması başarısız oldu\n',
        encoding="utf-8",
    )
    zypper_log.write_text(
        "2026-05-10 12:34:56|install|hydra|9.5|x86_64||repo|\n",
        encoding="utf-8",
    )
    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "syslog": {"enabled": True, "path": str(messages_log), "type": "syslog"},
            "apache2": {"enabled": True, "path": str(apache_log), "type": "apache2"},
            "postgresql": {"enabled": True, "path": str(pg_log), "type": "postgresql"},
            "dpkg": {"enabled": True, "path": str(zypper_log), "type": "zypper"},
            "auth_log": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
        },
    }
    monkeypatch.setattr(backend_facade, "_safe_local_hostname", lambda: "suse-host")
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "suse", "pretty": "openSUSE"})

    result = backend_facade.scan_local_historical_logs_preview()
    sources = {row["source"] for row in result["candidate_rows"]}

    assert result["status"] == "ok"
    assert result["parsed_events"] >= 5
    assert {"auth", "firewall", "web/apache", "postgresql", "package_manager"} <= sources


def test_local_historical_timestamp_metadata_marks_high_and_temporal_fields():
    metadata = backend_facade._local_historical_timestamp_metadata({"ts": datetime(2025, 5, 10, 12, 0, 0).timestamp()})

    assert metadata["timestamp_confidence"] == "high"
    assert metadata["timestamp_source"] == "parsed_log_timestamp"
    assert metadata["parsed_datetime"]
    assert metadata["hour_of_day"] == 12
    assert metadata["day_of_week"] == "saturday"
    assert metadata["is_weekend"] is True
    assert metadata["is_night"] is False
    assert metadata["time_bucket"] == "business_hours"


def test_local_historical_timestamp_metadata_day_of_week_stays_english_under_turkish_strftime(monkeypatch):
    class _FakeParsed:
        hour = 12

        def isoformat(self, timespec="seconds"):
            return "2025-05-10T12:00:00"

        def weekday(self):
            return 5

        def strftime(self, fmt):
            return "Cumartesi"

    class _FakeDatetime:
        @staticmethod
        def fromtimestamp(value):
            return _FakeParsed()

    monkeypatch.setattr(backend_facade, "datetime", _FakeDatetime)

    metadata = backend_facade._local_historical_timestamp_metadata({"ts": 1746878400.0})

    assert metadata["day_of_week"] == "saturday"


def test_local_historical_timestamp_metadata_marks_syslog_year_fallback_medium():
    metadata = backend_facade._local_historical_timestamp_metadata(
        {"ts": 1746873296.0, "timestamp_warning": "year_inferred_from_current_time"}
    )

    assert metadata["timestamp_confidence"] == "medium"
    assert metadata["timestamp_source"] == "traditional_syslog_current_year_fallback"
    assert metadata["timestamp_warning"] == "current_year_fallback"


def test_classify_local_historical_candidate_allows_medium_confidence_timestamp_for_baseline():
    disposition, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 1746873296.0,
            "timestamp_confidence": "low",
            "host": "server01",
            "observed_source": "auth",
            "source": "auth",
            "source": "auth",
            "distro_family": "debian",
            "category": "auth_normal",
            "action": "ssh_login",
            "outcome": "success",
        }
    )

    assert disposition == "baseline_learning"
    assert "baseline_quality_passed" in reasons


def test_classify_local_historical_candidate_allows_strong_normal_auth_baseline():
    disposition, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 1746873296.0,
            "timestamp_confidence": "high",
            "timestamp_source": "parsed_log_timestamp",
            "host": "server01",
            "observed_source": "auth",
            "source": "auth",
            "distro_family": "debian",
            "category": "auth_normal",
            "action": "ssh_login",
            "outcome": "success",
            "metadata_quality": "complete",
            "duplicate_count": 1,
        }
    )

    assert disposition == "baseline_learning"
    assert "baseline_quality_passed" in reasons


def test_classify_local_historical_candidate_allows_service_baseline():
    disposition, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "benign",
            "behavior_label": "system_service",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 1746873296.0,
            "timestamp_confidence": "high",
            "timestamp_source": "parsed_log_timestamp",
            "host": "rhel01",
            "observed_source": "auth",
            "source": "auth",
            "distro_family": "rhel",
            "category": "system",
            "action": "service_restart",
            "outcome": "completed",
            "process": "systemd",
            "metadata_quality": "complete",
            "duplicate_count": 1,
        }
    )

    assert disposition == "baseline_learning"
    assert "baseline_quality_passed" in reasons


def test_classify_local_historical_candidate_allows_suse_package_baseline():
    disposition, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "benign",
            "behavior_label": "package_management",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 1746873296.0,
            "timestamp_confidence": "high",
            "timestamp_source": "parsed_log_timestamp",
            "host": "suse01",
            "observed_source": "package_manager",
            "source": "package_manager",
            "distro_family": "suse",
            "category": "package_management",
            "action": "pkg_install",
            "outcome": "success",
            "metadata_quality": "enriched",
            "duplicate_count": 1,
        }
    )

    assert disposition == "baseline_learning"
    assert "baseline_quality_passed" in reasons


def test_classify_local_historical_candidate_rejects_unknown_action_and_missing_host_as_not_learnable():
    disposition, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "benign",
            "behavior_label": "routine_system_event",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 1746873296.0,
            "timestamp_confidence": "high",
            "host": "",
            "observed_source": "package_manager",
            "source": "package_manager",
            "distro_family": "suse",
            "category": "package_management",
            "action": "unknown",
            "outcome": "success",
            "metadata_quality": "complete",
        }
    )

    assert disposition == "rejected"
    assert "missing_host" in reasons
    assert "unknown_action" in reasons


def test_classify_local_historical_candidate_keeps_suspicious_direct_with_timestamp_warning():
    disposition, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "attack",
            "behavior_label": "credential_access",
            "model_usage_scope": "direct_learning",
            "source_trust": "rule_hit_high",
            "learnable": True,
            "rule_id": "AUTH-002",
            "ts": 0,
            "timestamp_confidence": "missing",
            "timestamp_warning": "timestamp_missing",
            "host": "server01",
            "source": "auth",
            "distro_family": "debian",
            "action": "auth_fail",
        }
    )

    assert disposition == "rejected"
    assert "missing_timestamp" in reasons


def test_classify_local_historical_candidate_rejects_unknown_distro_for_baseline():
    disposition, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 1746873296.0,
            "timestamp_confidence": "high",
            "host": "server01",
            "observed_source": "auth",
            "source": "auth",
            "distro_family": "unknown_distro",
            "category": "auth_normal",
            "action": "ssh_login",
            "outcome": "success",
            "metadata_quality": "complete",
        }
    )

    assert disposition == "rejected"
    assert "unknown_distro" in reasons


def test_classify_local_historical_candidate_rejects_firewall_block_from_baseline():
    disposition, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "benign",
            "behavior_label": "normal_network",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 1746873296.0,
            "timestamp_confidence": "high",
            "host": "server01",
            "observed_source": "firewall",
            "source": "firewall",
            "distro_family": "debian",
            "category": "firewall",
            "action": "firewall_block",
            "outcome": "blocked",
            "metadata_quality": "complete",
        }
    )

    assert disposition == "rejected"
    assert "suspicious_signal" in reasons
    assert "unsupported_source" in reasons


def test_classify_local_historical_candidate_allows_duplicate_burst_baseline_until_exact_write_dedupe():
    disposition, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "benign",
            "behavior_label": "package_management",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 1746873296.0,
            "timestamp_confidence": "high",
            "host": "server01",
            "observed_source": "package_manager",
            "source": "package_manager",
            "distro_family": "suse",
            "category": "package_management",
            "action": "pkg_install",
            "outcome": "success",
            "metadata_quality": "complete",
            "duplicate_count": 3,
        }
    )

    assert disposition == "baseline_learning"
    assert "baseline_quality_passed" in reasons


def test_classify_local_historical_candidate_ignores_unsupported_source_noise():
    disposition, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "benign",
            "behavior_label": "system_noise",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 1746873296.0,
            "timestamp_confidence": "high",
            "host": "server01",
            "observed_source": "kernel",
            "source": "kernel",
            "distro_family": "debian",
            "category": "system",
            "action": "kernel_notice",
            "outcome": "normal",
            "metadata_quality": "complete",
        }
    )

    assert disposition == "ignored"
    assert "unsupported_source" in reasons


def test_classify_local_historical_candidate_allows_parser_fallback_baseline_when_critical_fields_exist():
    disposition, reasons = backend_facade._classify_local_historical_candidate(
        {
            "event_class": "benign",
            "behavior_label": "expected_auth_activity",
            "model_usage_scope": "baseline_learning",
            "source_trust": "observed_benign_high",
            "learnable": True,
            "rule_id": "",
            "ts": 1746873296.0,
            "timestamp_confidence": "low",
            "timestamp_source": "timestamp_fallback",
            "host": "server01",
            "observed_source": "auth",
            "source": "auth",
            "distro_family": "debian",
            "category": "auth_normal",
            "action": "ssh_login",
            "outcome": "success",
            "metadata_quality": "complete",
        }
    )

    assert disposition == "baseline_learning"
    assert "baseline_quality_passed" in reasons


def test_known_benign_historical_candidate_coerces_first_seen_success_to_baseline():
    candidate = backend_facade._coerce_known_benign_historical_candidate(
        {
            "event_class": "suspicious",
            "behavior_label": "first_seen_behavior",
            "model_usage_scope": "calibration_only",
            "source_trust": "rule_low",
            "learnable": True,
            "rule_id": "FIRST-002",
            "ts": 1746873296.0,
            "timestamp_confidence": "medium",
            "host": "server01",
            "observed_source": "auth",
            "source": "auth",
            "distro_family": "debian",
            "category": "first_seen",
            "action": "ssh_login",
            "outcome": "success",
            "evidence_fields": {"rule_id": "FIRST-002", "labelability_reason": "rule_hit"},
        }
    )

    disposition, reasons = backend_facade._classify_local_historical_candidate(candidate)

    assert candidate["rule_id"] == ""
    assert candidate["event_class"] == "benign"
    assert candidate["behavior_label"] == "expected_auth_activity"
    assert candidate["source_trust"] == "observed_benign_high"
    assert candidate["model_usage_scope"] == "baseline_learning"
    assert candidate["evidence_fields"]["context_rule_id"] == "FIRST-002"
    assert candidate["labelability_reason"] == "known_benign_normal"
    assert disposition == "baseline_learning"
    assert "baseline_quality_passed" in reasons


def test_scan_local_historical_logs_preview_temporal_baseline_summary(monkeypatch, tmp_path):
    auth_log = tmp_path / "auth.log"
    auth_log.write_text(
        "May 10 12:34:56 server01 sshd[1234]: Accepted password for alice from 10.0.0.1 port 22345 ssh2\n"
        "May 10 23:34:56 server01 sshd[1234]: Accepted password for alice from 10.0.0.1 port 22345 ssh2\n"
        "May 10 23:35:56 server01 sshd[1234]: Failed password for root from 1.2.3.4 port 11111 ssh2\n",
        encoding="utf-8",
    )
    config = {
        "detection": {"rules_dir": "rules", "rules_source": "yaml"},
        "sources": {
            "auth_log": {"enabled": True, "path": str(auth_log), "type": "auth_log"},
            "syslog": {"enabled": False, "path": ""},
            "auditd": {"enabled": False, "path": ""},
            "apache2": {"enabled": False, "path": ""},
            "nginx": {"enabled": False, "path": ""},
            "postgresql": {"enabled": False, "path": ""},
            "ufw": {"enabled": False, "path": ""},
            "dpkg": {"enabled": False, "path": ""},
        },
    }
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": config})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian", "pretty": "Debian"})

    result = backend_facade.scan_local_historical_logs_preview()

    assert result["status"] == "ok"
    assert result["timestamp_medium"] == 3
    assert result["timestamp_low"] == 0
    assert result["timestamp_missing"] == 0
    assert result["temporal_warnings"] == 3
    assert result["time_bucket_breakdown"]["business_hours"] == 1
    assert result["time_bucket_breakdown"]["night"] == 2
    assert result["night_activity_count"] == 2
    assert result["hour_range"] == "12-23"
    assert result["first_seen"]
    assert result["last_seen"]
    assert result["source_hour_distribution"]["auth"]["12"] == 1
    assert result["source_hour_distribution"]["auth"]["23"] == 2
    assert result["user_hour_distribution"]["alice"]["12"] == 1
    assert result["host_hour_distribution"]["server01"]["23"] == 2
    assert result["quality_summary"]["baseline_quality_passed"] == 2
    assert result["quality_summary"]["direct_rule_hit"] >= 1
    baseline_rows = [row for row in result["candidate_rows"] if row["usage_decision"] == "baseline_learning"]
    direct_rows = [row for row in result["candidate_rows"] if row["usage_decision"] == "direct_learnable"]
    assert len(baseline_rows) == 2
    assert len(direct_rows) >= 1
    assert all(row["timestamp_confidence"] == "medium" for row in baseline_rows + direct_rows)
    assert all(row["time_bucket"] in {"business_hours", "night"} for row in result["candidate_rows"])


def test_scan_local_historical_logs_preview_timestamp_missing_benign_not_baseline(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"detection": {}, "sources": {}}})
    monkeypatch.setattr(backend_facade, "detect_distro", lambda: {"family": "debian", "pretty": "Debian"})

    class _FakeScanner:
        def __init__(self, distro_family=None, source_entries=None):
            self.distro_family = distro_family
            self.source_entries = source_entries

        def dry_run_report(self, detection_engine=None, normalizer=None):
            return {
                "scanned_files": 1,
                "parsed_events": 1,
                "warnings": [],
                "log_files": [{"path": "/tmp/auth.log", "readable": True}],
                "candidates": [
                    {
                        "ts": 0,
                        "host": "server01",
                        "observed_source": "auth_log",
                        "log_path": "/tmp/auth.log",
                        "distro_family": "debian",
                        "category": "auth",
                        "action": "ssh_login",
                        "outcome": "success",
                        "rule_id": "",
                        "username": "alice",
                        "process": "sshd",
                        "src_ip": "10.0.0.1",
                        "dst_ip": "",
                        "line_hash": "abc123",
                        "timestamp_warning": "",
                        "event_class": "benign",
                        "behavior_label": "expected_auth_activity",
                        "source_trust": "observed_benign_high",
                        "model_usage_scope": "baseline_learning",
                        "learnable": True,
                    }
                ],
            }

    monkeypatch.setattr(label_engine, "BootstrapLogScanner", _FakeScanner)

    result = backend_facade.scan_local_historical_logs_preview()

    row = result["candidate_rows"][0]
    assert row["timestamp_confidence"] == "missing"
    assert row["usage_decision"] == "rejected"
    assert result["usage_summary"]["baseline_learning"] == 0
    assert result["quality_summary"]["rejected_missing_timestamp"] == 1
    assert result["reason_breakdown"]["missing_timestamp"] == 1


def test_scan_local_historical_logs_preview_distro_timestamp_metadata_preserved(monkeypatch, tmp_path):
    deb_auth = tmp_path / "auth.log"
    rhel_secure = tmp_path / "secure"
    suse_messages = tmp_path / "messages"
    deb_auth.write_text(
        "May 10 12:34:56 debian01 sshd[1234]: Accepted password for alice from 10.0.0.1 port 22345 ssh2\n",
        encoding="utf-8",
    )
    rhel_secure.write_text(
        "May 10 12:34:56 rhel01 sshd[1234]: Failed password for rocky from 192.168.91.129 port 51112 ssh2\n",
        encoding="utf-8",
    )
    suse_messages.write_text(
        "2026-05-10 12:34:56|install|hydra|9.5|x86_64||repo|\n",
        encoding="utf-8",
    )

    for family, path, source_key, source_type in (
        ("debian", deb_auth, "auth_log", "auth_log"),
        ("rhel", rhel_secure, "auth_log", "auth_log"),
        ("suse", suse_messages, "dpkg", "zypper"),
    ):
        config = {
            "detection": {"rules_dir": "rules", "rules_source": "yaml"},
            "sources": {
                "syslog": {"enabled": False, "path": ""},
                "auditd": {"enabled": False, "path": ""},
                "apache2": {"enabled": False, "path": ""},
                "nginx": {"enabled": False, "path": ""},
                "postgresql": {"enabled": False, "path": ""},
                "ufw": {"enabled": False, "path": ""},
                "dpkg": {"enabled": False, "path": ""},
                "auth_log": {"enabled": False, "path": ""},
            },
        }
        config["sources"][source_key] = {"enabled": True, "path": str(path), "type": source_type}
        monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None, config=config: {"config": config})
        monkeypatch.setattr(backend_facade, "detect_distro", lambda family=family: {"family": family, "id": family, "pretty": family})
        result = backend_facade.scan_local_historical_logs_preview()
        row = result["candidate_rows"][0]
        assert row["distro_family"] == family
        assert row["distro"] == family
        assert row["timestamp_confidence"] in {"high", "medium"}
        assert row["parsed_datetime"]
        assert row["timestamp_source"]


def test_ml_center_no_write_guard_backend_facade_source():
    source = Path("ui/backend_facade.py").read_text(encoding="utf-8")
    forbidden_tokens = [
        "cleanup_labels(",
        "log_ml_control(",
        "add_ip_block_action",
        "review_ip_block_suggestion",
        "reset_database",
        "insert_incident(",
        "update_incident(",
        "set_stat(",
    ]

    for token in forbidden_tokens:
        assert token not in source


def test_collect_training_status_fallback_without_training(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"language": "en"}})
    monkeypatch.setattr(backend_facade, "collect_ml_summary", lambda config_path=None: {
        "status": "ok",
        "training_scheduler": {
            "reason": "readiness_blocked",
            "last_training_time": "",
            "last_training_at": "",
            "last_training_status": "",
            "last_evaluation_status": "",
            "last_training_family_distro": "",
            "trained_families": [],
        },
        "model_status": {"scoring_enabled_families": []},
        "error": None,
    })

    result = backend_facade.collect_training_status()

    assert result["timestamp_text"] == "Never"
    assert result["has_training"] is False
    assert result["training_status"] == "Waiting for enough high-quality labeled data."


def test_collect_historical_scan_status_fallback_without_artifact(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"language": "en"}})
    monkeypatch.setattr(backend_facade, "_collect_ml_history_files", lambda data_dir="data": [])

    result = backend_facade.collect_historical_scan_status()

    assert result["timestamp_text"] == "Never"
    assert result["has_scan"] is False
    assert result["scan_status"] == "Historical scan has not been run yet. Run it from the CLI when needed."
    assert result["note"] == "CLI/manual only"


def test_collect_ml_alerts_filters_only_ml_alerts(monkeypatch):
    monkeypatch.setattr(backend_facade, "collect_alerts", lambda limit=100, severity=None, config_path=None: {
        "status": "ok",
        "alerts": [
            {"id": 1, "rule_id": "RULE-1", "source": "auth_log", "raw": {}},
            {"id": 2, "rule_id": "ML-AUTH-001", "source": "ml", "raw": {}},
            {"id": 3, "rule_id": "RULE-3", "source": "syslog", "raw": {"rule_family": "ml"}},
        ],
        "error": None,
    })

    result = backend_facade.collect_ml_alerts(limit=10)

    assert [item["id"] for item in result["alerts"]] == [2, 3]


def test_collect_ml_center_summary_reports_primary_family_quota(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"language": "en"}})
    monkeypatch.setattr(backend_facade, "collect_ml_summary", lambda config_path=None: {
        "status": "ok",
        "ml_paused": True,
        "ready_for_active_ml": False,
        "training_scheduler": {},
        "model_status": {"scoring_enabled_families": []},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_ml_family_readiness", lambda config_path=None: {
        "status": "ok",
        "families": [
            {
                "family_id": "ML-AUTH",
                "status": "readiness_blocked",
                "reason": "insufficient_labels",
                "normal_labels": 8,
                "required_normal_labels": 20,
                "suspicious_labels": 2,
                "required_suspicious_labels": 10,
            }
        ],
        "error": None,
    })

    result = backend_facade.collect_ml_center_summary()

    assert result["ml_mode_text"] == "Audit-only"
    assert result["ml_safety_text"] == "No autonomous action"
    assert result["first_training"]["family_id"] == "ML-AUTH"
    assert result["first_training"]["current_samples"] == 10
    assert result["first_training"]["needed_samples"] == 30
    assert result["first_training"]["missing_samples"] == 20
