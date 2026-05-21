from __future__ import annotations
"""
main.py — AegisCore v16.0.0
Phase-based end-to-end pipeline.

PHASE_0 -> Rule/IOC/Regex/Threshold (immediate)
PHASE_1 -> + Instant ML      (200 events / 1 hour)
PHASE_2 -> + Baseline        (5000 events / 3 days)
PHASE_3 -> + Mature Baseline (20000 events / 7 days)

Log Sources:
  auth.log, syslog, journald, ufw, apache2, nginx, mysql, postgresql, mail, auditd, dpkg, wtmp, btmp

Active Monitor:
  File integrity (FIM), process monitoring, network connections
  Browser allowlist, process risk scoring, cooldown mechanism

Noise Reduction:
  Risk-threshold filter, process modifier, YAML rule-based cooldown
  Dedup cache, entity-based rate limiting

DB:
  PostgreSQL (required)
  Connection-safe persistence, migration integrity, archive and maintenance

Supported Distributions:
  Debian/Ubuntu, RHEL/CentOS/Rocky/AlmaLinux, SUSE/openSUSE

Usage:
  DATABASE_URL=postgresql://user:pass@host/db sudo .venv/bin/python main.py
  DATABASE_URL=postgresql://user:pass@host/db .venv/bin/python main.py --test
  python main.py --phase                  # phase status
  python main.py --status                 # alert summary
  python main.py --metrics                # detailed metrics
  python main.py --validate-rules         # validate rules
  python main.py --preflight              # system preflight check
  python main.py --ml-pause               # pause ML training
  python main.py --ml-resume              # resume ML training
  python main.py --ml-reset               # reset ML baseline
  python main.py --ml-status              # ML control status
  python main.py --ml-exclude auditd      # exclude source from ML
  python main.py --ml-include auditd      # add source back to ML
"""

import os, sys, time, json, signal, logging, subprocess, threading, shutil, re, random, copy, tempfile, math
from collections import Counter
from core.state_manager import ContextStateStore, MLStateStore, RuntimeStateStore, GracefulShutdown, get_state_metrics
from core.state_manager import atomic_json_save
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import yaml
import joblib

from app.bootstrap import configure_logging as _configure_logging_impl, prepare_startup_config
from app.io_utils import ensure_jsonl_writable as _ensure_jsonl_writable_impl
from app.startup import print_startup_banner as _print_startup_banner_impl
from app.database_bootstrap import ensure_database as _ensure_database_impl
from app.alert_explanations import (
    _alert_context_payload as _alert_context_payload_impl,
    _build_ml_support_score_from_alert as _build_ml_support_score_from_alert_impl,
    _compact_event_fields as _compact_event_fields_impl,
    _format_multiline_kv as _format_multiline_kv_impl,
    _human_ml_trigger_reason as _human_ml_trigger_reason_impl,
    _human_rule_trigger_reason as _human_rule_trigger_reason_impl,
    _looks_like_ml_alert as _looks_like_ml_alert_impl,
    _recommended_ml_review_steps as _recommended_ml_review_steps_impl,
    _recommended_rule_review_steps as _recommended_rule_review_steps_impl,
    build_alert_explanation_metadata as _build_alert_explanation_metadata_impl,
    build_deterministic_alert_explanation as _build_deterministic_alert_explanation_impl,
    build_deterministic_alert_report_payload as _build_deterministic_alert_report_payload_impl,
    build_ml_alert_explanation_metadata as _build_ml_alert_explanation_metadata_impl,
    print_alert_explanation_contract_audit as _print_alert_explanation_contract_audit_impl,
    run_alert_explanation_contract_audit as _run_alert_explanation_contract_audit_impl,
)
from app.configuration import load_config as _load_config_impl, read_version as _read_version_impl, resolve_output_language as _resolve_output_language_impl
from app.ml.diagnostics import (
    _family_label_counts_for_distro as _family_label_counts_for_distro_impl,
    _source_ownership_report as _source_ownership_report_impl,
    build_ml_historical_scan_manifest as _build_ml_historical_scan_manifest_impl,
    build_ml_normal_label_manifest as _build_ml_normal_label_manifest_impl,
    collect_event_growth_diagnostics as _collect_event_growth_diagnostics_impl,
    collect_parse_fail_diagnostics as _collect_parse_fail_diagnostics_impl,
    validate_ml_historical_scan_manifest as _validate_ml_historical_scan_manifest_impl,
    validate_ml_normal_label_manifest as _validate_ml_normal_label_manifest_impl,
)
from app.ml.labels import (
    _ML_NORMAL_LABEL_PLAN_SPECS,
    _apply_distro_cohort_guard as _apply_distro_cohort_guard_impl,
    _build_family_candidate_quality_filters as _build_family_candidate_quality_filters_impl,
    _build_family_distro_cohorts as _build_family_distro_cohorts_impl,
    _build_family_where_clause as _build_family_where_clause_impl,
    _classify_label_origin as _classify_label_origin_impl,
    _classify_label_usage as _classify_label_usage_impl,
    _coerce_jsonish_dict as _coerce_jsonish_dict_impl,
    _collect_distribution as _collect_distribution_impl,
    _collect_event_metrics as _collect_event_metrics_impl,
    _collect_global_ml_audit as _collect_global_ml_audit_impl,
    _event_count_by_distro as _event_count_by_distro_impl,
    _event_source_by_distro as _event_source_by_distro_impl,
    _execute_read_only as _execute_read_only_impl,
    _extract_behavior_from_text as _extract_behavior_from_text_impl,
    _extract_label_metadata_hints as _extract_label_metadata_hints_impl,
    _extract_rule_id_from_text as _extract_rule_id_from_text_impl,
    _flatten_text_values as _flatten_text_values_impl,
    _label_family_support as _label_family_support_impl,
    _label_matches_family as _label_matches_family_impl,
    _load_labels_read_only as _load_labels_read_only_impl,
    _load_rule_ids_for_ml_mapping_audit as _load_rule_ids_for_ml_mapping_audit_impl,
    _load_table_columns as _load_table_columns_impl,
    _metric_fill_sql as _metric_fill_sql_impl,
    _normalize_row_str as _normalize_row_str_impl,
    _propose_ml_label_metadata as _propose_ml_label_metadata_impl,
    _query_ml_audit_table_count as _query_ml_audit_table_count_impl,
    _resolve_ml_label_metadata_mapping as _resolve_ml_label_metadata_mapping_impl,
    _sql_quote_literal as _sql_quote_literal_impl,
    _summarize_label_quality as _summarize_label_quality_impl,
    collect_ml_historical_scan_plan as _collect_ml_historical_scan_plan_impl,
    collect_ml_label_extraction_audit as _collect_ml_label_extraction_audit_impl,
    collect_ml_label_metadata_plan as _collect_ml_label_metadata_plan_impl,
    collect_ml_label_trust_audit as _collect_ml_label_trust_audit_impl,
    collect_ml_legacy_bootstrap_backfill_plan as _collect_ml_legacy_bootstrap_backfill_plan_impl,
    collect_ml_mapping_audit as _collect_ml_mapping_audit_runtime_impl,
    collect_ml_normal_label_plan as _collect_ml_normal_label_plan_impl,
)
from app.ml.active_reporting import (
    _sample_support_event_for_family as _sample_support_event_for_family_impl,
    build_active_ml_alert_candidate as _build_active_ml_alert_candidate_impl,
    build_runtime_ml_label_candidate_from_rule as _build_runtime_ml_label_candidate_from_rule_impl,
    compute_ml_family_support_score as _compute_ml_family_support_score_impl,
    emit_active_ml_alert_if_allowed as _emit_active_ml_alert_if_allowed_impl,
    print_ml_active_emit_dry_run as _print_ml_active_emit_dry_run_impl,
    print_ml_family_support_score as _print_ml_family_support_score_impl,
    print_runtime_ml_label_candidate_audit as _print_runtime_ml_label_candidate_audit_impl,
    run_ml_active_emit_dry_run as _run_ml_active_emit_dry_run_impl,
    run_ml_support_score_family as _run_ml_support_score_family_impl,
)
from app.ml.bootstrap_scan import (
    run_bootstrap_label_scan_dry_run as _run_bootstrap_label_scan_dry_run_impl,
)
from app.ml.legacy_backfill import (
    LEGACY_BOOTSTRAP_REJECT_BACKFILL_FIELDS as _LEGACY_BOOTSTRAP_REJECT_BACKFILL_FIELDS_IMPL,
    apply_legacy_bootstrap_backfill_preview as _apply_legacy_bootstrap_backfill_preview_impl,
    collect_legacy_bootstrap_backfill_candidates as _collect_legacy_bootstrap_backfill_candidates_impl,
    execute_ml_legacy_bootstrap_backfill as _execute_ml_legacy_bootstrap_backfill_impl,
    legacy_bootstrap_backfill_payload as _legacy_bootstrap_backfill_payload_impl,
    legacy_bootstrap_metadata_missing as _legacy_bootstrap_metadata_missing_impl,
    print_ml_legacy_bootstrap_backfill_plan as _print_ml_legacy_bootstrap_backfill_plan_impl,
    run_ml_legacy_bootstrap_backfill as _run_ml_legacy_bootstrap_backfill_impl,
)
from app.ml.runtime_label_audit import (
    print_ml_mapping_audit as _print_ml_mapping_audit_impl,
    run_ml_mapping_audit as _run_ml_mapping_audit_impl,
    run_ml_runtime_label_candidate_audit as _run_ml_runtime_label_candidate_audit_impl,
)
from app.ml.specs import (
    ML_CONFIG_DEFAULT_STATUS as _ML_CONFIG_DEFAULT_STATUS_IMPL,
    ML_FAMILY_BEHAVIOR_ALIASES as _ML_FAMILY_BEHAVIOR_ALIASES_IMPL,
    ML_FAMILY_READINESS as _ML_FAMILY_READINESS_IMPL,
    ML_LABEL_BEHAVIOR_PLAN_ALIASES as _ML_LABEL_BEHAVIOR_PLAN_ALIASES_IMPL,
    ML_SCHEMA_CONTRACT as _ML_SCHEMA_CONTRACT_IMPL,
)
from app.ml.readiness import (
    _evaluate_ml_family_readiness as _evaluate_ml_family_readiness_impl,
    collect_ml_readiness_report as _collect_ml_readiness_report_impl,
    evaluate_ml_family_readiness as _evaluate_ml_family_readiness_public_impl,
)
from app.ml.readiness_reporting import (
    print_ml_family_readiness as _print_ml_family_readiness_impl,
    run_ml_family_readiness as _run_ml_family_readiness_impl,
)
from app.ml.scheduler_reporting import (
    bind_label_training_phase_gate as _bind_label_training_phase_gate_impl,
    collect_label_training_phase_gate_report as _collect_label_training_phase_gate_report_impl,
    collect_ml_training_scheduler_report as _collect_ml_training_scheduler_report_impl,
    collect_seed_training_readiness as _collect_seed_training_readiness_impl,
    count_new_training_labels as _count_new_training_labels_impl,
    label_duplicate_snapshot as _label_duplicate_snapshot_impl,
    label_evidence_fields as _label_evidence_fields_impl,
    label_log_source as _label_log_source_impl,
    label_timestamp_confidence as _label_timestamp_confidence_impl,
    open_incident_count as _open_incident_count_impl,
    phase_gate_training_state as _phase_gate_training_state_impl,
    quota_bucket_full as _quota_bucket_full_impl,
    training_eligibility_for_cohort as _training_eligibility_for_cohort_impl,
    training_scheduler_label_inventory as _training_scheduler_label_inventory_impl,
)
from app.ml.training import (
    _build_scheduler_training_payload as _build_scheduler_training_payload_impl,
    _evaluate_scheduler_training_candidate as _evaluate_scheduler_training_candidate_impl,
    _promote_scheduler_model_artifact as _promote_scheduler_model_artifact_impl,
    _resolve_ml_training_scheduler_config as _resolve_ml_training_scheduler_config_impl,
    _safe_runtime_state_components as _safe_runtime_state_components_impl,
    _scan_promoted_model_catalog as _scan_promoted_model_catalog_impl,
    _scheduler_artifact_paths as _scheduler_artifact_paths_impl,
    _scheduler_filtered_training_rows as _scheduler_filtered_training_rows_impl,
    _scheduler_last_training_state as _scheduler_last_training_state_impl,
    _scheduler_lock_owner_token as _scheduler_lock_owner_token_impl,
    _scheduler_min_interval_ready as _scheduler_min_interval_ready_impl,
    _scheduler_model_root as _scheduler_model_root_impl,
    _scheduler_record_first_training_state as _scheduler_record_first_training_state_impl,
    _scheduler_select_execution_candidates as _scheduler_select_execution_candidates_impl,
    _scheduler_state_family_key as _scheduler_state_family_key_impl,
    _scheduler_state_history_entry as _scheduler_state_history_entry_impl,
    _scheduler_update_state as _scheduler_update_state_impl,
    _scheduler_window as _scheduler_window_impl,
    _train_scheduler_model_artifact as _train_scheduler_model_artifact_impl,
)
from app.ml.training_actions import (
    ML_PROMOTED_MODEL_FEATURE_SCHEMA_VERSION as _ML_PROMOTED_MODEL_FEATURE_SCHEMA_VERSION_IMPL,
    ML_PROMOTED_MODEL_METADATA_FIELDS as _ML_PROMOTED_MODEL_METADATA_FIELDS_IMPL,
    ML_PROMOTED_MODEL_VERSION as _ML_PROMOTED_MODEL_VERSION_IMPL,
    ML_TRAIN_SCHEDULER_DEFAULTS as _ML_TRAIN_SCHEDULER_DEFAULTS_IMPL,
    ML_TRAINING_MODES as _ML_TRAINING_MODES_IMPL,
    WEEKDAY_NAME_TO_INDEX as _WEEKDAY_NAME_TO_INDEX_IMPL,
    acquire_scheduler_persistent_lock as _acquire_scheduler_persistent_lock_impl,
    atomic_joblib_dump as _atomic_joblib_dump_impl,
    execute_manual_training_with_owner as _execute_manual_training_impl,
    label_row_target as _label_row_target_impl,
    limit_scheduler_training_rows as _limit_scheduler_training_rows_impl,
    normalize_model_distro as _normalize_model_distro_impl,
    payload_from_training_row as _payload_from_training_row_impl,
    port_bucket_from_payload as _port_bucket_from_payload_impl,
    promoted_model_feature_vector as _promoted_model_feature_vector_impl,
    read_scheduler_state as _read_scheduler_state_impl,
    release_scheduler_persistent_lock as _release_scheduler_persistent_lock_impl,
    stable_token_bucket as _stable_token_bucket_impl,
    validate_promoted_model_metadata as _validate_promoted_model_metadata_impl,
    write_scheduler_state as _write_scheduler_state_impl,
)

sys.path.insert(0, str(Path(__file__).parent))

from core.database       import Database, create_database
from core.database       import get_schema_manifest, get_pending_schema_versions
from core.event_queue        import EventIngestionQueue
from core.source_rate_limiter import SourceRateLimiter
from core.normalize      import Normalizer, NormalizedEvent
from core.detection      import DetectionEngine, DetectionResult
from core.ml.instant_ml  import InstantMLEngine, extract_features
from core.ml.calibration import ScoreCalibrationEngine
from core.ml.baseline    import BaselineLearningEngine
from core.correlation    import CorrelationEngine, Incident
from core.risk           import RiskScoringEngine, RiskSignal
from core.incident       import IncidentManager
from core.phase_manager  import PhaseManager, Phase, compute_data_quality_metrics
from core.monitor        import ActiveMonitor, MonitorAlert
from core.report         import ReportEngine
from core.context        import feature_quality_score

from core.llm          import LLMClient
from core.threat_intel import ThreatIntelUpdater
from core.distro       import apply_distro_paths, detect_distro, audit_sources, is_supported, check_supported_or_exit
from core.integrations import IntegrationSettings
from core.abuseipdb    import AbuseIPDBClient
from core.ip_blocking  import IPBlocker
from core.notifier     import Notifier
from core.ml_control   import MLController
from core.ml.distro_ml import DistroMLAdapter
from core.ml.learning_guard import (ConfidenceScorer, DelayedLearningBuffer,
                                    RareEventFilter, AnomalyGuard, BaselineValidator)
from core.ml.host_baseline    import HostBaselineEngine
from core.ml.family_registry  import resolve_rule_id_to_ml_family
from core.ml.family_registry  import (
    get_ml_family_spec,
    list_ml_families,
    summarize_label_quota_usage,
)
from core.ml.label_engine import UNMAPPED_NONLEARNABLE_FAMILY, validate_ml_label_metadata
from core.ml.verified_manifest import redact_text
from core.ml.verified_manifest_cli import run_verified_manifest_dry_run
from core.ml.verified_manifest_audit import run_verified_manifest_audit_cli
from core.language import system_text
import app.runtime.alerts as _runtime_alerts
import app.runtime.event_processing as _runtime_event_processing
import app.runtime.ml_runtime as _runtime_ml_runtime
import app.runtime.ops as _runtime_ops
import app.runtime.pipeline as _runtime_pipeline
import app.runtime.maintenance as _runtime_maintenance
import app.runtime.ml_scheduler as _runtime_ml_scheduler
from app.runtime.pipeline import SIEMPipeline as _SIEMPipelineImpl
from cli import build_parser, dispatch_command, is_info_only_command
from cli.commands import (
    _find_pending_block_suggestion as _find_pending_block_suggestion_impl,
    _load_llm_client_for_cli,
    _open_optional_database as _open_optional_database_impl,
    _print_ip_block_result as _print_ip_block_result_impl,
    _print_ip_block_suggestions as _print_ip_block_suggestions_impl,
    _print_read_only_diagnostic,
    _with_database as _with_database_impl,
    build_operator_phase_manager as _build_operator_phase_manager_impl,
    collect_ml_config_audit as _collect_ml_config_audit_impl,
    collect_ml_label_contract_audit as _collect_ml_label_contract_audit_impl,
    collect_ml_model_status as _collect_ml_model_status_impl,
    collect_ml_summary as _collect_ml_summary_impl,
    print_metrics,
    print_ml_config_audit as _print_ml_config_audit_impl,
    print_ml_historical_scan_plan as _print_ml_historical_scan_plan_impl,
    print_ml_label_contract_audit as _print_ml_label_contract_audit_impl,
    print_ml_label_extraction_audit as _print_ml_label_extraction_audit_impl,
    print_ml_label_metadata_plan as _print_ml_label_metadata_plan_impl,
    print_ml_label_trust_audit as _print_ml_label_trust_audit_impl,
    print_ml_model_status as _print_ml_model_status_impl,
    print_ml_normal_label_plan as _print_ml_normal_label_plan_impl,
    print_ml_readiness_report as _print_ml_readiness_report_impl,
    print_ml_summary as _print_ml_summary_impl,
    print_ml_training_scheduler_report as _print_ml_training_scheduler_report_impl,
    run_db_doctor as _run_db_doctor_impl,
    run_db_pending as _run_db_pending_impl,
    run_db_version as _run_db_version_impl,
    run_diagnose_event_growth as _run_diagnose_event_growth_impl,
    run_diagnose_parse_fail as _run_diagnose_parse_fail_impl,
    run_explain_alert_cli as _run_explain_alert_cli_impl,
    run_ip_blocking_cli as _run_ip_blocking_cli_impl,
    run_metrics_cli as _run_metrics_cli,
    run_ml_config_audit as _run_ml_config_audit_impl,
    run_ml_historical_scan_plan as _run_ml_historical_scan_plan_impl,
    run_ml_label_contract_audit as _run_ml_label_contract_audit_impl,
    run_ml_label_extraction_audit as _run_ml_label_extraction_audit_impl,
    run_ml_label_metadata_plan as _run_ml_label_metadata_plan_impl,
    run_ml_label_trust_audit as _run_ml_label_trust_audit_impl,
    run_ml_model_status as _run_ml_model_status_impl,
    run_ml_normal_label_plan as _run_ml_normal_label_plan_impl,
    run_ml_readiness_report as _run_ml_readiness_report_impl,
    run_ml_summary as _run_ml_summary_impl,
    run_ml_train_now as _run_ml_train_now_impl,
    run_ml_train_now_dry_run as _run_ml_train_now_dry_run_impl,
    run_ml_train_scheduler_dry_run as _run_ml_train_scheduler_dry_run_impl,
    run_ml_training_status as _run_ml_training_status_impl,
    run_phase_cli as _run_phase_cli,
    run_report_cli as _run_report_cli,
    run_smoke_test as _run_smoke_test_impl,
    run_status_cli as _run_status_cli,
    run_test_precheck as _run_test_precheck_impl,
)

# Extracted modules
from core.formatters import (
    fmt_alert, fmt_monitor_alert, fmt_incident,
    fmt_rule_stats, fmt_phase_status,
    COLORS, ICONS, RESET, BOLD, GREEN, YELLOW, RED, CYAN,
)
from core.ingest import tail_file, tail_journald, tail_utmp

# -- JSONL safe-write helper -------------------------------------------------

def _bootstrap_scan_artifact_dir(bootstrap_job_id: str) -> Path:
    return Path("data") / "bootstrap_label_scan" / bootstrap_job_id


def _bootstrap_scan_artifact_paths(bootstrap_job_id: str) -> dict:
    base = _bootstrap_scan_artifact_dir(bootstrap_job_id)
    return {
        "artifact_dir": base,
        "candidate_manifest": base / "candidate_manifest.json",
        "dry_run_report": base / "dry_run_report.json",
        "pre_plan_snapshot": base / "pre_plan_snapshot.json",
        "candidate_plan": base / "candidate_plan.json",
        "rollback_report": base / "rollback_report.json",
    }


def _write_json_file(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _utc_iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sanitize_diagnostic_sample(raw: Any, *, limit: int = 160) -> str:
    text = " ".join(str(raw or "").split())
    if not text:
        return ""
    return redact_text(text, limit=limit)


def _safe_source_config(config: dict | None, source_name: str) -> dict:
    sources = ((config or {}).get("sources", {}) or {})
    source_cfg = sources.get(source_name, {})
    return dict(source_cfg or {}) if isinstance(source_cfg, dict) else {}


def _source_parser_hint(config: dict | None, source_name: str) -> str:
    source_cfg = _safe_source_config(config, source_name)
    return str(
        source_cfg.get("parser")
        or source_cfg.get("type")
        or source_cfg.get("source_type")
        or source_name
        or "unknown"
    )


def _source_path_hint(config: dict | None, source_name: str) -> str:
    source_cfg = _safe_source_config(config, source_name)
    source_type = str(source_cfg.get("type", "") or "").strip().lower()
    if source_type == "journald":
        return "journalctl"
    path = source_cfg.get("path", "")
    return str(path or source_name or "unknown")


def _source_ownership_report(config: dict | None) -> dict:
    return _source_ownership_report_impl(
        config,
        audit_sources=audit_sources,
        detect_distro=detect_distro,
    )


def run_bootstrap_label_scan_dry_run(config: dict) -> int:
    from core.ml.label_engine import BootstrapLogScanner

    return _run_bootstrap_label_scan_dry_run_impl(
        config,
        detect_distro=detect_distro,
        normalizer_cls=Normalizer,
        detection_engine_cls=DetectionEngine,
        bootstrap_log_scanner_cls=BootstrapLogScanner,
        bootstrap_scan_artifact_paths=_bootstrap_scan_artifact_paths,
        write_json_file=_write_json_file,
    )


def _ensure_jsonl_writable(path: str) -> bool:
    return _ensure_jsonl_writable_impl(path)


# ── Logging ───────────────────────────────────────────────────────────────────

_LOG_FILE_WARNING_EMITTED = False

def _read_version(path: str = "VERSION", default: str = "0.0.0") -> str:
    return _read_version_impl(path, default=default)


def setup_logging(level: str = "WARNING"):
    global _LOG_FILE_WARNING_EMITTED
    _LOG_FILE_WARNING_EMITTED = _configure_logging_impl(
        level,
        warning_emitted=_LOG_FILE_WARNING_EMITTED,
        stdout=sys.stdout,
        logging_module=logging,
        file_handler_factory=logging.FileHandler,
        logger_name="siem.main",
        log_path="data/siem.log",
    )

logger = logging.getLogger("siem.main")


def _output_language(config: dict | None = None, explicit: str | None = None) -> str:
    return _resolve_output_language_impl(config=config, explicit=explicit, environ=os.environ)


def load_config(path: str = "config/config.yml") -> dict:
    return _load_config_impl(path)


def ensure_database(config: dict):
    return _ensure_database_impl(config)


def _find_pending_block_suggestion(db, suggestion_id: int) -> dict | None:
    return _find_pending_block_suggestion_impl(db, suggestion_id)


def _print_ip_block_suggestions(rows: list[dict]) -> None:
    _print_ip_block_suggestions_impl(rows)


def _print_ip_block_result(result: dict) -> None:
    _print_ip_block_result_impl(result)


_alert_context_payload = _alert_context_payload_impl
_format_multiline_kv = _format_multiline_kv_impl
_looks_like_ml_alert = _looks_like_ml_alert_impl
_build_ml_support_score_from_alert = _build_ml_support_score_from_alert_impl
build_deterministic_alert_explanation = _build_deterministic_alert_explanation_impl
build_deterministic_alert_report_payload = _build_deterministic_alert_report_payload_impl


def run_explain_alert_cli(config: dict, args) -> int:
    return _run_explain_alert_cli_impl(
        config,
        args,
        ensure_database=ensure_database,
        load_llm_client_for_cli=_load_llm_client_for_cli,
        build_deterministic_alert_explanation=build_deterministic_alert_explanation,
        sys_module=sys,
    )


_compact_event_fields = _compact_event_fields_impl
_human_rule_trigger_reason = _human_rule_trigger_reason_impl
_recommended_rule_review_steps = _recommended_rule_review_steps_impl
build_alert_explanation_metadata = _build_alert_explanation_metadata_impl
_human_ml_trigger_reason = _human_ml_trigger_reason_impl
_recommended_ml_review_steps = _recommended_ml_review_steps_impl
build_ml_alert_explanation_metadata = _build_ml_alert_explanation_metadata_impl


_ML_ACTIVE_EMIT_DEFAULTS = {
    "min_score": 60.0,
    "min_confidence": 0.60,
}


_ML_ACTIVE_MITRE_DEFAULTS = {
    "ML-AUTH": ("TA0006", "T1110", ["ml", "auth", "identity", "no_action_contract"]),
    "ML-SUDO": ("TA0004", "T1548", ["ml", "sudo", "privilege_escalation", "no_action_contract"]),
    "ML-PROC": ("TA0002", "T1059", ["ml", "process", "execution", "no_action_contract"]),
    "ML-SERVICE": ("TA0003", "T1543", ["ml", "service", "persistence", "no_action_contract"]),
    "ML-NET": ("TA0011", "T1071", ["ml", "network", "egress", "no_action_contract"]),
    "ML-SEQ": ("TA0008", "T1021", ["ml", "sequence", "multi_stage", "no_action_contract"]),
    "ML-USER": ("TA0006", "T1078", ["ml", "user_behavior", "identity", "no_action_contract"]),
    "ML-HOST": ("TA0007", "T1082", ["ml", "host_behavior", "discovery", "no_action_contract"]),
    "ML-DBAUTH": ("TA0006", "T1078.004", ["ml", "db_auth", "identity", "no_action_contract"]),
    "ML-DNS": ("TA0011", "T1071.004", ["ml", "dns", "egress", "no_action_contract"]),
    "ML-WEBPOST": ("TA0011", "T1105", ["ml", "web", "post_exploit", "no_action_contract"]),
    "ML-IMPACT": ("TA0040", "T1485", ["ml", "impact", "tamper", "no_action_contract"]),
}


def _coerce_ml_event_fields(event: dict | object | None) -> dict:
    if event is None:
        return {}
    if isinstance(event, dict):
        payload = copy.deepcopy(event)
    elif hasattr(event, "to_dict"):
        payload = copy.deepcopy(event.to_dict())
    else:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    for key in (
        "ts", "host", "source", "category", "action", "outcome",
        "user", "username", "src_ip", "dst_ip", "process", "message",
        "distro_family", "fields",
    ):
        if key in payload:
            continue
        if hasattr(event, key):
            payload[key] = copy.deepcopy(getattr(event, key))
    if payload.get("user") and not payload.get("username"):
        payload["username"] = payload.get("user")
    elif payload.get("username") and not payload.get("user"):
        payload["user"] = payload.get("username")
    if not payload.get("distro_family"):
        payload["distro_family"] = "unknown_distro"
    if not isinstance(payload.get("fields"), dict):
        payload["fields"] = {}
    return payload


def _default_ml_label_for_family(family_id: str, related_rule_context: dict | None = None) -> str:
    related = dict(related_rule_context or {})
    for item in list(related.get("related_rule_candidates", []) or []):
        if (item.get("ml_family", "") or "").strip().upper() != (family_id or "").strip().upper():
            continue
        label = (item.get("ml_label", "") or "").strip()
        if label:
            return label
    spec = get_ml_family_spec(family_id)
    if spec is None:
        return ""
    suspicious_targets = getattr(spec, "suspicious_label_targets", {}) or {}
    if suspicious_targets:
        return next(iter(suspicious_targets.keys()))
    normal_targets = getattr(spec, "normal_label_targets", {}) or {}
    if normal_targets:
        return next(iter(normal_targets.keys()))
    return ""


def _severity_for_ml_active_score(score: float, confidence: float) -> str:
    combined = float(score or 0.0) * 0.7 + float(confidence or 0.0) * 30.0
    if combined >= 90.0:
        return "critical"
    if combined >= 75.0:
        return "high"
    if combined >= 55.0:
        return "medium"
    return "low"


def _risk_score_for_ml_active_score(score: float, confidence: float) -> float:
    combined = float(score or 0.0) * 0.7 + float(confidence or 0.0) * 30.0
    return round(max(0.0, min(100.0, combined)), 2)


def _ml_active_category(family_id: str) -> str:
    family_key = (family_id or "").strip().upper()
    spec = get_ml_family_spec(family_key)
    category = str(getattr(spec, "category", "") or family_key.lower()).strip().lower()
    return f"ml_{category.replace('-', '_').replace(' ', '_') or 'family'}"


def _ml_active_message(family_id: str, explanation: dict) -> str:
    reason = str((explanation or {}).get("why_triggered_human", "") or "").strip()
    if reason:
        return reason
    family_key = (family_id or "").strip().upper()
    if family_key == "ML-PROC":
        return "Bu process bu hostta normal profile göre nadir görüldü."
    if family_key == "ML-NET":
        return "Bu bağlantı host'un normal ağ saat/hedef profilinden saptı."
    if family_key in {"ML-AUTH", "ML-SUDO"}:
        return "Bu kullanıcı için bu saat aralığında yetkili erişim davranışı beklenen profile uymuyor."
    return f"{family_key} family anomalisi için aktif ML eşikleri aşıldı."


def _build_ml_family_gate_snapshot(readiness_result: dict) -> dict:
    readiness = dict(readiness_result or {})
    return {
        "status": readiness.get("status", "readiness_blocked"),
        "reason": readiness.get("reason", "readiness_not_met"),
        "blockers": list(readiness.get("blockers", []) or []),
        "phase_gate_ok": bool(readiness.get("phase_gate_ok", False)),
        "event_threshold_ok": bool(readiness.get("event_threshold_ok", False)),
        "normal_label_threshold_ok": bool(readiness.get("normal_label_threshold_ok", False)),
        "suspicious_label_threshold_ok": bool(readiness.get("suspicious_label_threshold_ok", False)),
        "field_quality_ok": bool(readiness.get("field_quality_ok", False)),
        "time_coverage_ok": bool(readiness.get("time_coverage_ok", False)),
        "trust_support_ok": bool(readiness.get("trust_support_ok", False)),
        "metadata_support_ok": bool(readiness.get("metadata_support_ok", False)),
    }


def _build_ml_correlation_safe_metadata(event_payload: dict,
                                        related_rule_context: dict | None,
                                        active_decision_layer: dict | None) -> dict:
    related = copy.deepcopy(related_rule_context or {})
    active_layer = dict(active_decision_layer or {})
    related_rule_ids = []
    for item in list(related.get("rule_detections", []) or []):
        rule_id = (item.get("rule_id", "") or "").strip().upper()
        if rule_id:
            related_rule_ids.append(rule_id)
    related_rule_ids = list(dict.fromkeys(related_rule_ids))
    return {
        "same_entity": bool(event_payload.get("src_ip") or event_payload.get("user") or event_payload.get("host")),
        "related_rule_ids": related_rule_ids,
        "related_rule_count": len(related_rule_ids),
        "confidence_boost_enabled": bool(((active_layer.get("correlation_confidence_boost", {}) or {}).get("enabled", False))),
        "future_safe_only": True,
        "rule_suppressed": False,
        "rule_risk_changed": False,
    }


def build_active_ml_alert_candidate(*,
                                    event: dict | object | None,
                                    family_id: str,
                                    readiness_result: dict,
                                    support_score_result: dict,
                                    active_decision_layer: dict | None,
                                    family_config: dict | None,
                                    related_rule_context: dict | None = None) -> dict:
    return _build_active_ml_alert_candidate_impl(
        event=event,
        family_id=family_id,
        readiness_result=readiness_result,
        support_score_result=support_score_result,
        active_decision_layer=active_decision_layer,
        family_config=family_config,
        related_rule_context=related_rule_context,
        coerce_ml_event_fields=_coerce_ml_event_fields,
        get_ml_family_spec=get_ml_family_spec,
        build_ml_family_gate_snapshot=_build_ml_family_gate_snapshot,
        default_ml_label_for_family=_default_ml_label_for_family,
        build_ml_correlation_safe_metadata=_build_ml_correlation_safe_metadata,
        ml_active_emit_defaults=_ML_ACTIVE_EMIT_DEFAULTS,
        build_ml_alert_explanation_metadata=build_ml_alert_explanation_metadata,
        ml_active_message=_ml_active_message,
        risk_score_for_ml_active_score=_risk_score_for_ml_active_score,
        severity_for_ml_active_score=_severity_for_ml_active_score,
        ml_active_category=_ml_active_category,
        ml_active_mitre_defaults=_ML_ACTIVE_MITRE_DEFAULTS,
    )


def emit_active_ml_alert_if_allowed(*,
                                    event: dict | object | None,
                                    family_id: str,
                                    readiness_result: dict,
                                    support_score_result: dict,
                                    active_decision_layer: dict | None,
                                    family_config: dict | None,
                                    related_rule_context: dict | None = None,
                                    emit_callback=None,
                                    dry_run: bool = False) -> dict:
    return _emit_active_ml_alert_if_allowed_impl(
        event=event,
        family_id=family_id,
        readiness_result=readiness_result,
        support_score_result=support_score_result,
        active_decision_layer=active_decision_layer,
        family_config=family_config,
        related_rule_context=related_rule_context,
        emit_callback=emit_callback,
        dry_run=dry_run,
        build_active_ml_alert_candidate=build_active_ml_alert_candidate,
    )


print_alert_explanation_contract_audit = _print_alert_explanation_contract_audit_impl


def run_alert_explanation_contract_audit(config: dict) -> int:
    return _run_alert_explanation_contract_audit_impl(
        config,
        compute_ml_family_support_score=compute_ml_family_support_score,
        ml_family_readiness=_ML_FAMILY_READINESS,
    )


def run_ip_blocking_cli(config: dict, args) -> int:
    return _run_ip_blocking_cli_impl(
        config,
        args,
        ensure_database=ensure_database,
        ip_blocker_cls=IPBlocker,
        sys_module=sys,
    )


def _with_database(config: dict, error_prefix: str, action: Callable[[Database], int]) -> int:
    return _with_database_impl(config, error_prefix, action, ensure_database=ensure_database)


def _open_optional_database(config: dict):
    return _open_optional_database_impl(config, create_database_func=create_database)


def _build_operator_phase_manager(config: dict):
    return _build_operator_phase_manager_impl(
        config,
        bind_label_training_phase_gate=_bind_label_training_phase_gate,
        create_database_func=create_database,
    )


_ML_PHASE_SEED_GATE_DEFAULTS = {
    "min_distinct_days": 5,
    "min_timestamp_confidence_ratio": 0.90,
    "min_metadata_completeness": 0.99,
    "max_rejected_ratio": 0.20,
    "max_duplicate_ratio": 0.10,
    "max_parse_fail_rate": 0.05,
    "min_ready_family_count": 1,
}

_ML_READINESS_DEFAULTS = {
    "min_time_coverage_days": 5,
    "min_source_diversity": 2,
    "min_host_fill_rate": 0.50,
    "min_user_fill_rate": 0.50,
    "min_process_fill_rate": 0.30,
    "min_src_ip_fill_rate": 0.30,
    "min_dst_ip_fill_rate": 0.30,
    "min_dst_port_fill_rate": 0.30,
    "max_parse_fail_rate": 0.10,
    "max_duplicate_rate": 0.20,
}

_ML_FAMILY_READINESS = _ML_FAMILY_READINESS_IMPL


def _safe_ratio(num: float, den: float) -> float:
    return float(num) / float(den) if den else 0.0


def _fmt_rate(value: float) -> str:
    return f"{value * 100:.1f}%"


def _phase_name_for_value(phase_value: int) -> str:
    try:
        return f"PHASE_{int(phase_value)}"
    except Exception:
        return "PHASE_?"


def _execute_read_only(db, sql: str, params=(), fetch: str = "all"):
    return _execute_read_only_impl(db, sql, params=params, fetch=fetch)

def _row_value(row, key: str, index: int | None = None, default=None):
    if row is None:
        return default
    if isinstance(row, dict):
        return row.get(key, default)
    if isinstance(row, (list, tuple)):
        if index is not None and 0 <= index < len(row):
            return row[index]
        return default
    return getattr(row, key, default)


def _load_table_columns(db, table_name: str) -> tuple[set[str], list[str]]:
    return _load_table_columns_impl(
        db,
        table_name,
        query_rows=_query_rows,
        row_value=_row_value,
    )

def _sql_non_empty_expr(column_name: str) -> str:
    return f"NULLIF(BTRIM(COALESCE({column_name}::text, '')), '') IS NOT NULL"


def _metric_fill_sql(column_name: str, available_columns: set[str], alias: str, notes: list[str]) -> str:
    return _metric_fill_sql_impl(
        column_name,
        available_columns,
        alias,
        notes,
        sql_non_empty_expr=_sql_non_empty_expr,
    )

def _build_family_where_clause(family: str, available_columns: set[str]) -> str:
    return _build_family_where_clause_impl(family, available_columns)


def _query_scalar(db, sql: str, params=(), key: str = "count", default=0):
    row, error = _execute_read_only(db, sql, params=params, fetch="one")
    if not row:
        return default, error
    return _row_value(row, key, 0, default), error


def _query_rows(db, sql: str, params=()):
    rows, error = _execute_read_only(db, sql, params=params, fetch="all")
    if not rows or not isinstance(rows, list):
        return [], error
    return rows, error


def _load_labels_read_only(db) -> tuple[list, str]:
    return _load_labels_read_only_impl(db)


_ML_FAMILY_BEHAVIOR_ALIASES = _ML_FAMILY_BEHAVIOR_ALIASES_IMPL


def _label_matches_family(row: dict, family: str, bucket: str) -> bool:
    return _label_matches_family_impl(
        row,
        family,
        bucket,
        ml_family_readiness=_ML_FAMILY_READINESS,
        ml_family_behavior_aliases=_ML_FAMILY_BEHAVIOR_ALIASES,
    )


def _classify_label_origin(row: dict) -> str:
    return _classify_label_origin_impl(row)


def _summarize_label_quality(label_rows: list[dict], config: dict | None = None) -> dict:
    return _summarize_label_quality_impl(
        label_rows,
        config=config,
        ml_family_readiness=_ML_FAMILY_READINESS,
        classify_label_origin=_classify_label_origin,
        row_distro_value=_row_distro_value,
        label_family_support=_label_family_support,
        classify_label_usage=_classify_label_usage,
        label_matches_family=_label_matches_family,
        summarize_label_quota_usage=summarize_label_quota_usage,
    )

def _collect_event_metrics(db, where_sql: str = "TRUE", available_columns: set[str] | None = None) -> tuple[dict, list[str]]:
    return _collect_event_metrics_impl(
        db,
        where_sql=where_sql,
        available_columns=available_columns,
        metric_fill_sql=_metric_fill_sql,
        execute_read_only=_execute_read_only,
        row_value=_row_value,
        event_count_by_distro=_event_count_by_distro,
        event_source_by_distro=_event_source_by_distro,
        safe_ratio=_safe_ratio,
    )

def _collect_distribution(db, column: str, limit: int = 5, available_columns: set[str] | None = None) -> tuple[list[dict], list[str]]:
    return _collect_distribution_impl(
        db,
        column,
        limit=limit,
        available_columns=available_columns,
        query_rows=_query_rows,
    )

def _normalize_distro_value(value: Any) -> str:
    token = str(value or "").strip().lower()
    return token or "unknown_distro"


def _row_distro_value(row: dict) -> str:
    return _normalize_distro_value(
        row.get("distro_family", row.get("distro", ""))
    )


def _event_count_by_distro(
    db,
    where_sql: str,
    available_columns: set[str],
    *,
    fallback_count: int = 0,
) -> tuple[dict[str, int], list[str]]:
    return _event_count_by_distro_impl(
        db,
        where_sql,
        available_columns,
        fallback_count=fallback_count,
        query_rows=_query_rows,
        normalize_distro_value=_normalize_distro_value,
        row_value=_row_value,
    )

def _event_source_by_distro(
    db,
    where_sql: str,
    available_columns: set[str],
) -> tuple[dict[str, dict[str, int]], list[str]]:
    return _event_source_by_distro_impl(
        db,
        where_sql,
        available_columns,
        query_rows=_query_rows,
        normalize_distro_value=_normalize_distro_value,
        row_value=_row_value,
    )

def _sum_nested_distro_counts(
    target: dict[str, dict[str, int]],
    distro_counts: dict[str, int],
    key: str,
) -> None:
    for distro, count in (distro_counts or {}).items():
        bucket = target.setdefault(distro, {})
        bucket[key] = int(bucket.get(key, 0) or 0) + int(count or 0)


_ML_AUDIT_TABLE_COUNT_SQL = {
    "events_recent": "SELECT COUNT(*) AS count FROM events_recent",
    "alerts": "SELECT COUNT(*) AS count FROM alerts",
    "incidents": "SELECT COUNT(*) AS count FROM incidents",
    "labels": "SELECT COUNT(*) AS count FROM labels",
    "process_tree": "SELECT COUNT(*) AS count FROM process_tree",
}


def _query_ml_audit_table_count(db, table_name: str) -> tuple[int, str | None]:
    return _query_ml_audit_table_count_impl(
        db,
        table_name,
        query_scalar=_query_scalar,
    )

def _collect_global_ml_audit(db, pm_status: dict, config: dict | None = None) -> dict:
    return _collect_global_ml_audit_impl(
        db,
        pm_status,
        config=config,
        load_table_columns=_load_table_columns,
        query_ml_audit_table_count=_query_ml_audit_table_count,
        collect_event_metrics=_collect_event_metrics,
        collect_distribution=_collect_distribution,
        load_labels_read_only=_load_labels_read_only,
        summarize_label_quality=_summarize_label_quality,
        compute_data_quality_metrics=compute_data_quality_metrics,
        json_loads=json.loads,
    )

def _top_distribution_rows(payload: Any, *, limit: int = 6) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        rows = [
            {"name": str(name or ""), "count": int(count or 0)}
            for name, count in payload.items()
            if int(count or 0) > 0
        ]
    else:
        for item in list(payload or []):
            row = dict(item or {})
            count = int(row.get("count", 0) or 0)
            if count <= 0:
                continue
            rows.append({"name": str(row.get("name", "") or ""), "count": count})
    rows.sort(key=lambda item: (-int(item["count"]), str(item["name"])))
    return rows[:limit]


def _distribution_rows_to_dict(payload: Any) -> dict[str, int]:
    if isinstance(payload, dict):
        return {str(name or ""): int(count or 0) for name, count in payload.items()}
    result: dict[str, int] = {}
    for item in list(payload or []):
        row = dict(item or {})
        result[str(row.get("name", "") or "")] = int(row.get("count", 0) or 0)
    return result


def collect_parse_fail_diagnostics(config: dict, db, pm_status: dict) -> dict:
    return _collect_parse_fail_diagnostics_impl(
        config,
        db,
        pm_status,
        source_ownership_report=_source_ownership_report,
    )

def collect_event_growth_diagnostics(config: dict, db, pm_status: dict) -> dict:
    return _collect_event_growth_diagnostics_impl(
        config,
        db,
        pm_status,
        collect_global_ml_audit=_collect_global_ml_audit,
        source_ownership_report=_source_ownership_report,
        top_distribution_rows=_top_distribution_rows,
        distribution_rows_to_dict=_distribution_rows_to_dict,
    )

def _family_label_counts_for_distro(global_audit: dict, family: str, distro: str) -> dict:
    return _family_label_counts_for_distro_impl(global_audit, family, distro)

def _build_family_distro_cohorts(family: str, family_metrics: dict, global_audit: dict) -> dict[str, dict]:
    return _build_family_distro_cohorts_impl(
        family,
        family_metrics,
        global_audit,
        family_label_counts_for_distro=_family_label_counts_for_distro,
    )


def _apply_distro_cohort_guard(result: dict, distro_cohorts: dict[str, dict]) -> dict:
    return _apply_distro_cohort_guard_impl(result, distro_cohorts)


_ML_TRAIN_SCHEDULER_DEFAULTS = _ML_TRAIN_SCHEDULER_DEFAULTS_IMPL
_ML_TRAINING_MODES = _ML_TRAINING_MODES_IMPL
_ML_PROMOTED_MODEL_FEATURE_SCHEMA_VERSION = _ML_PROMOTED_MODEL_FEATURE_SCHEMA_VERSION_IMPL
_ML_PROMOTED_MODEL_VERSION = _ML_PROMOTED_MODEL_VERSION_IMPL
_ML_PROMOTED_MODEL_METADATA_FIELDS = _ML_PROMOTED_MODEL_METADATA_FIELDS_IMPL
_WEEKDAY_NAME_TO_INDEX = _WEEKDAY_NAME_TO_INDEX_IMPL


def _safe_json_stat(db, key: str) -> dict:
    if db is None or not hasattr(db, "get_stat"):
        return {}
    try:
        raw = db.get_stat(key)
        if not raw:
            return {}
        payload = json.loads(raw)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _iso_local(ts: float | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%dT%H:%M:%S")


def _parse_timestamp(value: Any) -> float:
    if value in (None, ""):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return 0.0
    try:
        return float(text)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.timestamp()
        except ValueError:
            continue
    return 0.0


def _quota_bucket_full(quota_payload: dict) -> bool:
    return _quota_bucket_full_impl(quota_payload)


def _open_incident_count(db) -> int:
    return _open_incident_count_impl(db)


def _training_scheduler_label_inventory(label_rows: list[dict]) -> dict:
    return _training_scheduler_label_inventory_impl(
        label_rows,
        classify_label_origin=_classify_label_origin,
        row_distro_value=_row_distro_value,
        label_family_support=_label_family_support,
        classify_label_usage=_classify_label_usage,
        validate_ml_label_metadata=validate_ml_label_metadata,
        parse_timestamp=_parse_timestamp,
    )


def _count_new_training_labels(training_bucket: dict, last_training_ts: float) -> dict:
    return _count_new_training_labels_impl(training_bucket, last_training_ts)


def _label_evidence_fields(row: dict) -> dict:
    return _label_evidence_fields_impl(row)


def _label_timestamp_confidence(row: dict) -> str:
    return _label_timestamp_confidence_impl(row, label_evidence_fields=_label_evidence_fields)


def _label_log_source(row: dict) -> str:
    return _label_log_source_impl(row, label_evidence_fields=_label_evidence_fields)


def _label_duplicate_snapshot(row: dict) -> tuple[str, int | None]:
    return _label_duplicate_snapshot_impl(row, label_evidence_fields=_label_evidence_fields)


def _phase_gate_training_state(db) -> dict:
    return _phase_gate_training_state_impl(db, safe_json_stat=_safe_json_stat)


def _collect_seed_training_readiness(config: dict, db, pm_status: dict, global_audit: dict | None = None) -> dict:
    return _collect_seed_training_readiness_impl(
        config,
        db,
        pm_status,
        global_audit=global_audit,
        collect_global_ml_audit=_collect_global_ml_audit,
        load_labels_read_only=_load_labels_read_only,
        classify_label_origin=_classify_label_origin,
        row_distro_value=_row_distro_value,
        label_family_support=_label_family_support,
        classify_label_usage=_classify_label_usage,
        validate_ml_label_metadata=validate_ml_label_metadata,
        label_timestamp_confidence=_label_timestamp_confidence,
        label_log_source=_label_log_source,
        label_duplicate_snapshot=_label_duplicate_snapshot,
        parse_timestamp=_parse_timestamp,
        scheduler_state_family_key=_scheduler_state_family_key,
        config_family_readiness_contract=_config_family_readiness_contract,
        safe_ratio=_safe_ratio,
        phase_seed_gate_defaults=_ML_PHASE_SEED_GATE_DEFAULTS,
        unmapped_nonlearnable_family=UNMAPPED_NONLEARNABLE_FAMILY,
    )


def collect_label_training_phase_gate_report(config: dict, db, pm_status: dict) -> dict:
    return _collect_label_training_phase_gate_report_impl(
        config,
        db,
        pm_status,
        collect_global_ml_audit=_collect_global_ml_audit,
        collect_seed_training_readiness=_collect_seed_training_readiness,
        phase_gate_training_state=_phase_gate_training_state,
        open_incident_count=_open_incident_count,
    )


def _bind_label_training_phase_gate(pm, config: dict, db) -> None:
    _bind_label_training_phase_gate_impl(
        pm,
        config,
        db,
        collect_label_training_phase_gate_report=collect_label_training_phase_gate_report,
    )


def _acquire_scheduler_persistent_lock(db, *, now_ts: float, ttl_seconds: float, owner: str | None = None) -> tuple[bool, dict, str]:
    return _acquire_scheduler_persistent_lock_impl(
        db,
        now_ts=now_ts,
        ttl_seconds=ttl_seconds,
        owner=owner,
        scheduler_lock_owner_token=_scheduler_lock_owner_token,
        read_scheduler_state=_read_scheduler_state,
        parse_timestamp=_parse_timestamp,
        iso_local=_iso_local,
        write_scheduler_state=_write_scheduler_state,
    )


def _release_scheduler_persistent_lock(db, state: dict | None = None, *, owner: str | None = None) -> dict:
    return _release_scheduler_persistent_lock_impl(
        db,
        state,
        owner=owner,
        scheduler_lock_owner_token=_scheduler_lock_owner_token,
        read_scheduler_state=_read_scheduler_state,
        iso_local=_iso_local,
        write_scheduler_state=_write_scheduler_state,
    )


def _normalize_model_distro(value: Any) -> str:
    return _normalize_model_distro_impl(value)


def _stable_token_bucket(value: Any, modulo: int = 997) -> float:
    return _stable_token_bucket_impl(value, modulo)


def _port_bucket_from_payload(payload: dict) -> float:
    return _port_bucket_from_payload_impl(payload)


def _payload_from_training_row(row: dict) -> dict:
    return _payload_from_training_row_impl(row, coerce_ml_event_fields=_coerce_ml_event_fields)


def _promoted_model_feature_vector(event_payload: dict, family_id: str, distro: str) -> list[float]:
    return _promoted_model_feature_vector_impl(
        event_payload,
        family_id,
        distro,
        coerce_ml_event_fields=_coerce_ml_event_fields,
        get_ml_family_spec=get_ml_family_spec,
        stable_token_bucket=_stable_token_bucket,
        port_bucket_from_payload=_port_bucket_from_payload,
    )


def _label_row_target(row: dict) -> int:
    return _label_row_target_impl(row)


def _validate_promoted_model_metadata(metadata: dict) -> tuple[bool, list[str]]:
    return _validate_promoted_model_metadata_impl(
        metadata,
        metadata_fields=_ML_PROMOTED_MODEL_METADATA_FIELDS,
        normalize_model_distro=_normalize_model_distro,
        list_ml_families=list_ml_families,
        feature_schema_version=_ML_PROMOTED_MODEL_FEATURE_SCHEMA_VERSION,
    )


def _atomic_joblib_dump(path: Path, payload: Any) -> bool:
    return _atomic_joblib_dump_impl(path, payload, logger_override=logger)


def _write_scheduler_state(db, state: dict) -> bool:
    return _write_scheduler_state_impl(db, state, logger_override=logger)


def _read_scheduler_state(db) -> dict:
    return _read_scheduler_state_impl(db, safe_json_stat=_safe_json_stat)


def _limit_scheduler_training_rows(rows: list[dict], max_samples: int) -> list[dict]:
    return _limit_scheduler_training_rows_impl(rows, max_samples, parse_timestamp=_parse_timestamp)


def _training_eligibility_for_cohort(
    family_id: str,
    family_payload: dict,
    cohort_payload: dict,
    global_audit: dict,
    training_bucket: dict,
) -> dict:
    return _training_eligibility_for_cohort_impl(
        family_id,
        family_payload,
        cohort_payload,
        global_audit,
        training_bucket,
        evaluate_ml_family_readiness=evaluate_ml_family_readiness,
        ml_family_readiness=_ML_FAMILY_READINESS,
    )


def collect_ml_training_scheduler_report(config: dict, db, pm_status: dict, *, now_ts: float | None = None, trigger_request: str = "scheduler") -> dict:
    return _collect_ml_training_scheduler_report_impl(
        config,
        db,
        pm_status,
        now_ts=now_ts,
        trigger_request=trigger_request,
        resolve_ml_training_scheduler_config=_resolve_ml_training_scheduler_config,
        scheduler_last_training_state=_scheduler_last_training_state,
        collect_ml_readiness_report=collect_ml_readiness_report,
        collect_seed_training_readiness=_collect_seed_training_readiness,
        load_labels_read_only=_load_labels_read_only,
        training_scheduler_label_inventory=_training_scheduler_label_inventory,
        scheduler_window=_scheduler_window,
        open_incident_count=_open_incident_count,
        parse_timestamp=_parse_timestamp,
        count_new_training_labels=_count_new_training_labels,
        scheduler_min_interval_ready=_scheduler_min_interval_ready,
        quota_bucket_full=_quota_bucket_full,
        iso_local=_iso_local,
        scheduler_select_execution_candidates=_scheduler_select_execution_candidates,
    )


def print_ml_training_scheduler_report(report: dict) -> None:
    _print_ml_training_scheduler_report_impl(report)


def run_ml_train_scheduler_dry_run(config: dict) -> int:
    return _run_ml_train_scheduler_dry_run_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_ml_training_scheduler_report=collect_ml_training_scheduler_report,
    )


def run_ml_training_status(config: dict) -> int:
    return _run_ml_training_status_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_ml_training_scheduler_report=collect_ml_training_scheduler_report,
    )


def run_ml_train_now_dry_run(config: dict) -> int:
    return _run_ml_train_now_dry_run_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_ml_training_scheduler_report=collect_ml_training_scheduler_report,
    )


def _refresh_promoted_model_registry_noop(*, load_artifacts: bool = False) -> dict:
    return {"refreshed": False, "load_artifacts": bool(load_artifacts), "no_action_contract": True}


def evaluate_ml_family_readiness(*args, **kwargs):
    return _evaluate_ml_family_readiness_public_impl(*args, **kwargs)


def _evaluate_ml_family_readiness(family: str, family_metrics: dict, global_audit: dict) -> dict:
    return _evaluate_ml_family_readiness_impl(family, family_metrics, global_audit)


def collect_ml_readiness_report(config: dict, db, pm_status: dict) -> dict:
    return _collect_ml_readiness_report_impl(config, db, pm_status)


def _resolve_ml_training_scheduler_config(config: dict) -> dict:
    return _resolve_ml_training_scheduler_config_impl(config)


def _scheduler_window(now_ts: float, schedule_cfg: dict, last_check_ts: float) -> dict:
    return _scheduler_window_impl(now_ts, schedule_cfg, last_check_ts)


def _scheduler_last_training_state(db) -> dict:
    return _scheduler_last_training_state_impl(db)


def _scheduler_state_family_key(family_id: str, distro: str) -> str:
    return _scheduler_state_family_key_impl(family_id, distro)


def _scheduler_lock_owner_token() -> str:
    return _scheduler_lock_owner_token_impl()


def _scheduler_model_root(config: dict) -> Path:
    return _scheduler_model_root_impl(config)


def _scheduler_artifact_paths(config: dict, family_id: str, distro: str) -> dict[str, Path]:
    return _scheduler_artifact_paths_impl(config, family_id, distro)


def _safe_runtime_state_components(config: dict) -> dict:
    return _safe_runtime_state_components_impl(config)


def _scan_promoted_model_catalog(config: dict, *, load_artifacts: bool = False) -> dict:
    return _scan_promoted_model_catalog_impl(config, load_artifacts=load_artifacts)


def _scheduler_state_history_entry(state: dict) -> dict:
    return _scheduler_state_history_entry_impl(state)


def _scheduler_update_state(db, mutate: Callable[[dict], dict]) -> dict:
    return _scheduler_update_state_impl(db, mutate)


def _scheduler_filtered_training_rows(label_rows: list[dict], family_id: str, distro: str) -> list[dict]:
    return _scheduler_filtered_training_rows_impl(label_rows, family_id, distro)


def _build_scheduler_training_payload(
    label_rows: list[dict],
    family_id: str,
    distro: str,
    *,
    max_samples_per_family: int | None = None,
) -> dict:
    return _build_scheduler_training_payload_impl(
        label_rows,
        family_id,
        distro,
        max_samples_per_family=max_samples_per_family,
    )


def _evaluate_scheduler_training_candidate(training_payload: dict, schedule_cfg: dict) -> dict:
    return _evaluate_scheduler_training_candidate_impl(training_payload, schedule_cfg)


def _train_scheduler_model_artifact(config: dict, family_id: str, distro: str, training_payload: dict, evaluation_result: dict) -> dict:
    return _train_scheduler_model_artifact_impl(config, family_id, distro, training_payload, evaluation_result)


def _promote_scheduler_model_artifact(config: dict, family_id: str, distro: str, training_result: dict) -> dict:
    return _promote_scheduler_model_artifact_impl(config, family_id, distro, training_result)


def _scheduler_min_interval_ready(last_training_ts: float, min_seconds_between_training: int, now_ts: float) -> tuple[bool, str]:
    return _scheduler_min_interval_ready_impl(last_training_ts, min_seconds_between_training, now_ts)


def _scheduler_select_execution_candidates(candidates: list[dict], max_families_per_run: int) -> list[dict]:
    return _scheduler_select_execution_candidates_impl(candidates, max_families_per_run)


def _scheduler_record_first_training_state(
    state: dict,
    *,
    now_ts: float,
    training_status: str,
    evaluation_status: str,
    model_ready: bool,
    family_key: str,
) -> None:
    _scheduler_record_first_training_state_impl(
        state,
        now_ts=now_ts,
        training_status=training_status,
        evaluation_status=evaluation_status,
        model_ready=model_ready,
        family_key=family_key,
    )


def _load_rule_ids_for_ml_mapping_audit(config: dict) -> tuple[list[str], str]:
    return _load_rule_ids_for_ml_mapping_audit_impl(config)


def collect_ml_mapping_audit(rule_ids: list[str]) -> dict:
    return _collect_ml_mapping_audit_runtime_impl(rule_ids)


def collect_ml_historical_scan_plan(config: dict, db, pm_status: dict) -> dict:
    return _collect_ml_historical_scan_plan_impl(config, db, pm_status)


def collect_ml_normal_label_plan(config: dict, db, pm_status: dict) -> dict:
    return _collect_ml_normal_label_plan_impl(
        config,
        db,
        pm_status,
        collect_global_ml_audit=_collect_global_ml_audit,
        load_labels_read_only=_load_labels_read_only,
        count_labels_by_behavior=_count_labels_by_behavior,
        has_blocking_open_incident=_has_blocking_open_incident,
        columns_present=_columns_present,
        safe_count_where=_safe_count_where,
        event_count_by_distro=_event_count_by_distro,
        sum_nested_distro_counts=_sum_nested_distro_counts,
        build_source_allowlist_clause=_build_source_allowlist_clause,
        build_required_present_clause=_build_required_present_clause,
        build_family_candidate_quality_filters=_build_family_candidate_quality_filters,
        normal_label_plan_specs=_ML_NORMAL_LABEL_PLAN_SPECS,
        ml_family_readiness=_ML_FAMILY_READINESS,
    )

def collect_ml_label_trust_audit(config: dict, db, pm_status: dict) -> dict:
    return _collect_ml_label_trust_audit_impl(
        config,
        db,
        pm_status,
        load_table_columns=_load_table_columns,
        load_labels_read_only=_load_labels_read_only,
        summarize_label_quality=_summarize_label_quality,
        classify_label_usage=_classify_label_usage,
        label_family_support=_label_family_support,
        label_matches_family=_label_matches_family,
        ml_family_readiness=_ML_FAMILY_READINESS,
    )

def collect_ml_label_metadata_plan(config: dict, db, pm_status: dict) -> dict:
    return _collect_ml_label_metadata_plan_impl(
        config,
        db,
        pm_status,
        load_table_columns=_load_table_columns,
        load_labels_read_only=_load_labels_read_only,
        propose_ml_label_metadata=_propose_ml_label_metadata,
        normalize_row_str=_normalize_row_str,
    )

def collect_ml_label_extraction_audit(config: dict, db, pm_status: dict) -> dict:
    return _collect_ml_label_extraction_audit_impl(
        config,
        db,
        pm_status,
        load_table_columns=_load_table_columns,
        load_labels_read_only=_load_labels_read_only,
        normalize_row_str=_normalize_row_str,
        extract_label_metadata_hints=_extract_label_metadata_hints,
        propose_ml_label_metadata=_propose_ml_label_metadata,
    )

def execute_manual_training(
    config: dict,
    db,
    pm_status: dict,
    *,
    now_ts: float | None = None,
    refresh_runtime_registry: Callable[..., dict] | None = None,
) -> dict:
    _sync_runtime_pipeline_dependencies()
    _runtime_pipeline.validate_ml_label_metadata = validate_ml_label_metadata
    return _execute_manual_training_impl(
        config,
        db,
        pm_status,
        now_ts=now_ts,
        refresh_runtime_registry=refresh_runtime_registry,
        owner_token=_scheduler_lock_owner_token,
        resolve_ml_training_scheduler_config=_resolve_ml_training_scheduler_config,
        collect_ml_training_scheduler_report=collect_ml_training_scheduler_report,
        refresh_promoted_model_registry_noop=_refresh_promoted_model_registry_noop,
        acquire_scheduler_persistent_lock=_acquire_scheduler_persistent_lock,
        load_labels_read_only=_load_labels_read_only,
        iso_local=_iso_local,
        write_scheduler_state=_write_scheduler_state,
        scheduler_state_family_key=_scheduler_state_family_key,
        build_scheduler_training_payload=_build_scheduler_training_payload,
        evaluate_scheduler_training_candidate=_evaluate_scheduler_training_candidate,
        scheduler_record_first_training_state=_scheduler_record_first_training_state,
        scheduler_state_history_entry=_scheduler_state_history_entry,
        train_scheduler_model_artifact=_train_scheduler_model_artifact,
        promote_scheduler_model_artifact=_promote_scheduler_model_artifact,
        release_scheduler_persistent_lock=_release_scheduler_persistent_lock,
    )


def run_ml_train_now(config: dict) -> int:
    return _run_ml_train_now_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        execute_manual_training=execute_manual_training,
    )


def print_ml_readiness_report(report: dict) -> None:
    _print_ml_readiness_report_impl(
        report,
        fmt_rate=_fmt_rate,
        phase_name_for_value=_phase_name_for_value,
        row_value=_row_value,
        family_readiness=_ML_FAMILY_READINESS,
    )


def run_ml_readiness_report(config: dict) -> int:
    return _run_ml_readiness_report_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_ml_readiness_report=collect_ml_readiness_report,
        fmt_rate=_fmt_rate,
        phase_name_for_value=_phase_name_for_value,
        row_value=_row_value,
        family_readiness=_ML_FAMILY_READINESS,
    )


def _config_family_readiness_contract(config: dict, family_id: str) -> dict:
    family_key = (family_id or "").strip().upper()
    base = dict(_ML_FAMILY_READINESS.get(family_key, {}) or {})
    ml_cfg = (config.get("ml", {}) or {})
    family_cfg = ((ml_cfg.get("family", {}) or {}).get(family_key, {}) or {})
    phase_gate_value = base.get("phase_gate", 0)
    phase_gate_raw = family_cfg.get("phase_gate")
    if isinstance(phase_gate_raw, str):
        phase_gate_map = {"PHASE_1": int(Phase.PHASE_1), "PHASE_2": int(Phase.PHASE_2), "PHASE_3": int(Phase.PHASE_3)}
        phase_gate_value = phase_gate_map.get(phase_gate_raw.strip().upper(), phase_gate_value)
    base.update({
        "default_status": family_cfg.get("default_status", _ML_CONFIG_DEFAULT_STATUS.get(family_key, "readiness_blocked")),
        "enabled": family_cfg.get("default_status") != "disabled",
        "phase_gate": phase_gate_value,
        "required_events": int(family_cfg.get("runtime_min_events", base.get("required_events", 0)) or 0),
        "required_normal_labels": int(family_cfg.get("normal_label_min", base.get("required_normal_labels", 0)) or 0),
        "required_suspicious_labels": int(family_cfg.get("suspicious_label_min", base.get("required_suspicious_labels", 0)) or 0),
        "no_action_contract": bool(family_cfg.get("no_action_contract", True)),
    })
    return base


def print_ml_family_readiness(result: dict) -> None:
    _print_ml_family_readiness_impl(result)


def run_ml_family_readiness(config: dict, family_id: str) -> int:
    return _run_ml_family_readiness_impl(
        config,
        family_id,
        ml_family_readiness=_ML_FAMILY_READINESS,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_global_ml_audit=_collect_global_ml_audit,
        config_family_readiness_contract=_config_family_readiness_contract,
        collect_event_metrics=_collect_event_metrics,
        build_family_where_clause=_build_family_where_clause,
        evaluate_ml_family_readiness=evaluate_ml_family_readiness,
        print_ml_family_readiness=print_ml_family_readiness,
        sys_module=sys,
    )


def compute_ml_family_support_score(*,
                                    family_id: str,
                                    event: dict | None,
                                    readiness_result: dict,
                                    family_config: dict,
                                    baseline_summary: dict | None = None) -> dict:
    return _compute_ml_family_support_score_impl(
        family_id=family_id,
        event=event,
        readiness_result=readiness_result,
        family_config=family_config,
        baseline_summary=baseline_summary,
        get_ml_family_spec=get_ml_family_spec,
        time_module=time,
    )


def _sample_support_event_for_family(family_id: str) -> dict:
    return _sample_support_event_for_family_impl(family_id, time_module=time)


def print_ml_family_support_score(result: dict) -> None:
    _print_ml_family_support_score_impl(result)


def run_ml_support_score_family(config: dict, family_id: str) -> int:
    return _run_ml_support_score_family_impl(
        config,
        family_id,
        ml_family_readiness=_ML_FAMILY_READINESS,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_global_ml_audit=_collect_global_ml_audit,
        config_family_readiness_contract=_config_family_readiness_contract,
        collect_event_metrics=_collect_event_metrics,
        build_family_where_clause=_build_family_where_clause,
        evaluate_ml_family_readiness=evaluate_ml_family_readiness,
        compute_ml_family_support_score=compute_ml_family_support_score,
        sample_support_event_for_family=_sample_support_event_for_family,
        print_ml_family_support_score=print_ml_family_support_score,
        sys_module=sys,
    )


def print_ml_active_emit_dry_run(candidate: dict) -> None:
    _print_ml_active_emit_dry_run_impl(candidate)


def run_ml_active_emit_dry_run(config: dict, family_id: str) -> int:
    return _run_ml_active_emit_dry_run_impl(
        config,
        family_id,
        ml_family_readiness=_ML_FAMILY_READINESS,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_global_ml_audit=_collect_global_ml_audit,
        config_family_readiness_contract=_config_family_readiness_contract,
        collect_event_metrics=_collect_event_metrics,
        build_family_where_clause=_build_family_where_clause,
        evaluate_ml_family_readiness=evaluate_ml_family_readiness,
        compute_ml_family_support_score=compute_ml_family_support_score,
        sample_support_event_for_family=_sample_support_event_for_family,
        emit_active_ml_alert_if_allowed=emit_active_ml_alert_if_allowed,
        print_ml_active_emit_dry_run=print_ml_active_emit_dry_run,
        sys_module=sys,
    )


def print_ml_mapping_audit(report: dict) -> None:
    _print_ml_mapping_audit_impl(report)


def run_ml_mapping_audit(config: dict) -> int:
    return _run_ml_mapping_audit_impl(
        config,
        load_rule_ids_for_ml_mapping_audit=_load_rule_ids_for_ml_mapping_audit,
        collect_ml_mapping_audit=collect_ml_mapping_audit,
        print_ml_mapping_audit=print_ml_mapping_audit,
        sys_module=sys,
    )


def build_runtime_ml_label_candidate_from_rule(rule_id: str,
                                               severity: str = "",
                                               risk_score: float = 0.0,
                                               event: dict | None = None,
                                               alert_context: dict | None = None,
                                               message: str = "") -> dict:
    from core.ml.label_engine import build_ml_label_metadata, validate_ml_label_metadata

    return _build_runtime_ml_label_candidate_from_rule_impl(
        rule_id,
        severity,
        risk_score,
        event,
        alert_context,
        message,
        resolve_rule_id_to_ml_family=resolve_rule_id_to_ml_family,
        build_ml_label_metadata=build_ml_label_metadata,
        validate_ml_label_metadata=validate_ml_label_metadata,
    )


def print_runtime_ml_label_candidate_audit(candidate: dict) -> None:
    _print_runtime_ml_label_candidate_audit_impl(candidate)


def run_ml_runtime_label_candidate_audit(config: dict, rule_id: str) -> int:
    return _run_ml_runtime_label_candidate_audit_impl(
        config,
        rule_id,
        build_runtime_ml_label_candidate_from_rule=build_runtime_ml_label_candidate_from_rule,
        print_runtime_ml_label_candidate_audit=print_runtime_ml_label_candidate_audit,
        sys_module=sys,
    )


def _count_labels_by_behavior(label_rows: list[dict]) -> Counter:
    counts = Counter()
    for row in label_rows or []:
        behavior = (row.get("behavior_label", "") or "").strip()
        if behavior:
            counts[behavior] += 1
    return counts


def _historical_scan_label_plan_status(found: int, required: int, candidate_count: int, schema_ok: bool, paused: bool) -> str:
    if paused:
        return "paused"
    if not schema_ok:
        return "missing_schema"
    if found >= required:
        return "target_met_stop_scan"
    if candidate_count <= 0:
        return "insufficient_source_data"
    return "needs_more_data"


def print_ml_historical_scan_plan(report: dict) -> None:
    _print_ml_historical_scan_plan_impl(report)


def run_ml_historical_scan_plan(config: dict) -> int:
    return _run_ml_historical_scan_plan_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_ml_historical_scan_plan=collect_ml_historical_scan_plan,
    )


def _ml_historical_scan_action(item: dict) -> str:
    status = (item.get("status", "") or "").strip().lower()
    found = int(item.get("found", 0) or 0)
    required = int(item.get("required", 0) or 0)
    candidate_count = int(item.get("candidate_count", 0) or 0)

    if status in {"paused", "missing_schema"}:
        return "blocked_or_paused"
    if found >= required:
        return "stop_scan"
    if status == "insufficient_source_data" or candidate_count <= 0:
        return "insufficient_source_data"
    return "collect_up_to_needed"


def build_ml_historical_scan_manifest(plan_report: dict, *, job_id: str = "", created_at: str = "") -> dict:
    return _build_ml_historical_scan_manifest_impl(
        plan_report,
        job_id=job_id,
        created_at=created_at,
        utc_iso_now=_utc_iso_now,
        time_time=time.time,
        ml_historical_scan_action=_ml_historical_scan_action,
    )

def validate_ml_historical_scan_manifest(manifest: dict) -> dict:
    return _validate_ml_historical_scan_manifest_impl(manifest)

def _has_blocking_open_incident(db) -> bool:
    if db is None or not hasattr(db, "get_open_incidents"):
        return False
    try:
        for inc in db.get_open_incidents() or []:
            severity = (inc.get("severity", "") or "").strip().lower()
            if severity in {"high", "critical"}:
                return True
    except Exception:
        return False
    return False


def _columns_present(columns: set[str], names: tuple[str, ...]) -> bool:
    return all(name in columns for name in names)


def _safe_count_where(db, where_sql: str, available_columns: set[str]) -> tuple[int, list[str]]:
    notes: list[str] = []
    if not available_columns:
        return 0, ["missing_schema:events_recent"]
    sql = f"SELECT COUNT(*) AS count FROM events_recent WHERE {where_sql}"
    value, error = _query_scalar(db, sql, key="count", default=0)
    if error:
        notes.append(error)
    return int(value or 0), notes


def _build_source_allowlist_clause(sources: tuple[str, ...], available_columns: set[str], notes: list[str]) -> str:
    if "source" not in available_columns:
        notes.append("missing_field:source")
        return "FALSE"
    quoted = ", ".join(f"'{src}'" for src in sources)
    return f"LOWER(COALESCE(source, '')) IN ({quoted})"


def _build_required_present_clause(required_present: tuple[str, ...], available_columns: set[str], notes: list[str]) -> str:
    clauses = []
    for column in required_present:
        if column not in available_columns:
            notes.append(f"missing_field:{column}")
            return "FALSE"
        clauses.append(_sql_non_empty_expr(column))
    return " AND ".join(clauses) if clauses else "TRUE"


def _build_reject_token_clause(tokens: tuple[str, ...], available_columns: set[str]) -> str:
    clauses = []
    if "process" in available_columns:
        clauses.extend([f"POSITION('{token}' IN LOWER(COALESCE(process, ''))) > 0" for token in tokens])
    if "message" in available_columns:
        clauses.extend([f"POSITION('{token}' IN LOWER(COALESCE(message, ''))) > 0" for token in tokens])
    return " OR ".join(clauses) if clauses else "FALSE"


def _sql_quote_literal(value: str) -> str:
    return _sql_quote_literal_impl(value)

def _load_closed_incident_entities(db) -> tuple[list[str], list[str]]:
    sql = """
        SELECT DISTINCT LOWER(BTRIM(COALESCE(entity_key, ''))) AS entity_key
        FROM incidents
        WHERE LOWER(COALESCE(status, '')) IN ('closed', 'resolved')
          AND LOWER(COALESCE(severity, '')) IN ('high', 'critical')
          AND NULLIF(BTRIM(COALESCE(entity_key, '')), '') IS NOT NULL
    """
    rows, error = _query_rows(db, sql)
    notes = [error] if error else []
    entities: list[str] = []
    for row in rows or []:
        entity = (_row_value(row, "entity_key", 0, "") or "").strip().lower()
        if entity:
            entities.append(entity)
    return sorted(set(entities)), notes


def _build_closed_incident_entity_residue_clause(entities: list[str], available_columns: set[str]) -> str:
    if not entities:
        return "TRUE"
    clauses: list[str] = []
    if "src_ip" in available_columns:
        quoted = ", ".join(_sql_quote_literal(entity) for entity in entities)
        clauses.append(f"LOWER(COALESCE(src_ip, '')) IN ({quoted})")
    for column in ("message", "raw_log"):
        if column in available_columns:
            clauses.extend(
                [f"POSITION({_sql_quote_literal(entity)} IN LOWER(COALESCE({column}, ''))) > 0" for entity in entities]
            )
    if not clauses:
        return "TRUE"
    return "NOT (" + " OR ".join(clauses) + ")"


def _build_family_candidate_quality_filters(db, family_id: str, label_name: str, available_columns: set[str]) -> tuple[list[tuple[str, str]], list[str]]:
    return _build_family_candidate_quality_filters_impl(
        db,
        family_id,
        label_name,
        available_columns,
        load_closed_incident_entities=_load_closed_incident_entities,
        build_closed_incident_entity_residue_clause=_build_closed_incident_entity_residue_clause,
        sql_quote_literal=_sql_quote_literal,
    )

def print_ml_normal_label_plan(report: dict) -> None:
    _print_ml_normal_label_plan_impl(report)


def run_ml_normal_label_plan(config: dict) -> int:
    return _run_ml_normal_label_plan_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_ml_normal_label_plan=collect_ml_normal_label_plan,
    )


def build_ml_normal_label_manifest(plan_report: dict, *, job_id: str = "", created_at: str = "") -> dict:
    return _build_ml_normal_label_manifest_impl(
        plan_report,
        job_id=job_id,
        created_at=created_at,
        utc_iso_now=_utc_iso_now,
        time_time=time.time,
        compat_accepted_count_key="accepted_candidate_count",
    )

def validate_ml_normal_label_manifest(manifest: dict) -> dict:
    return _validate_ml_normal_label_manifest_impl(
        manifest,
        compat_accepted_count_key="accepted_candidate_count",
    )

def _label_family_support(row: dict) -> dict:
    return _label_family_support_impl(
        row,
        ml_family_readiness=_ML_FAMILY_READINESS,
        ml_family_behavior_aliases=_ML_FAMILY_BEHAVIOR_ALIASES,
    )


def _classify_label_usage(row: dict, family_support: dict) -> tuple[str, list[str]]:
    return _classify_label_usage_impl(row, family_support)


_LEGACY_BOOTSTRAP_REJECT_BACKFILL_FIELDS = _LEGACY_BOOTSTRAP_REJECT_BACKFILL_FIELDS_IMPL


def _legacy_bootstrap_metadata_missing(row: dict) -> bool:
    return _legacy_bootstrap_metadata_missing_impl(row)



def _legacy_bootstrap_backfill_payload(row: dict) -> dict:
    return _legacy_bootstrap_backfill_payload_impl(
        row,
        legacy_bootstrap_reject_backfill_fields=_LEGACY_BOOTSTRAP_REJECT_BACKFILL_FIELDS,
    )


def _apply_legacy_bootstrap_backfill_preview(row: dict) -> dict:
    return _apply_legacy_bootstrap_backfill_preview_impl(
        row,
        legacy_bootstrap_reject_backfill_fields=_LEGACY_BOOTSTRAP_REJECT_BACKFILL_FIELDS,
    )


def _collect_legacy_bootstrap_backfill_candidates(label_rows: list[dict]) -> dict:
    return _collect_legacy_bootstrap_backfill_candidates_impl(
        label_rows,
        classify_label_origin=_classify_label_origin,
        classify_label_usage=_classify_label_usage,
        label_family_support=_label_family_support,
    )


def collect_ml_legacy_bootstrap_backfill_plan(config: dict, db, pm_status: dict) -> dict:
    return _collect_ml_legacy_bootstrap_backfill_plan_impl(
        config,
        db,
        pm_status,
        load_labels_read_only=_load_labels_read_only,
        collect_legacy_bootstrap_backfill_candidates=_collect_legacy_bootstrap_backfill_candidates,
        summarize_label_quality=_summarize_label_quality,
        apply_legacy_bootstrap_backfill_preview=_apply_legacy_bootstrap_backfill_preview,
        legacy_bootstrap_backfill_payload=_legacy_bootstrap_backfill_payload,
        legacy_bootstrap_reject_backfill_fields=_LEGACY_BOOTSTRAP_REJECT_BACKFILL_FIELDS,
    )


def print_ml_legacy_bootstrap_backfill_plan(report: dict) -> None:
    _print_ml_legacy_bootstrap_backfill_plan_impl(report)


def execute_ml_legacy_bootstrap_backfill(config: dict, db, *, apply: bool = False) -> dict:
    return _execute_ml_legacy_bootstrap_backfill_impl(
        config,
        db,
        apply=apply,
        collect_ml_legacy_bootstrap_backfill_plan=collect_ml_legacy_bootstrap_backfill_plan,
        load_labels_read_only=_load_labels_read_only,
        summarize_label_quality=_summarize_label_quality,
    )


def print_ml_label_trust_audit(report: dict) -> None:
    _print_ml_label_trust_audit_impl(report)


def run_ml_label_trust_audit(config: dict) -> int:
    return _run_ml_label_trust_audit_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_ml_label_trust_audit=collect_ml_label_trust_audit,
    )


_ML_LABEL_BEHAVIOR_PLAN_ALIASES = _ML_LABEL_BEHAVIOR_PLAN_ALIASES_IMPL


def _normalize_row_str(row: dict, key: str) -> str:
    return _normalize_row_str_impl(row, key)

def _resolve_ml_label_metadata_mapping(row: dict) -> dict:
    return _resolve_ml_label_metadata_mapping_impl(
        row,
        ml_label_behavior_plan_aliases=_ML_LABEL_BEHAVIOR_PLAN_ALIASES,
    )


def _propose_ml_label_metadata(row: dict) -> dict:
    return _propose_ml_label_metadata_impl(
        row,
        resolve_ml_label_metadata_mapping=_resolve_ml_label_metadata_mapping,
        normalize_row_str=_normalize_row_str,
    )

def _coerce_jsonish_dict(value) -> tuple[dict, str]:
    return _coerce_jsonish_dict_impl(value)

def _flatten_text_values(value) -> list[str]:
    return _flatten_text_values_impl(value)

def _extract_rule_id_from_text(text: str) -> str:
    return _extract_rule_id_from_text_impl(text)

def _extract_behavior_from_text(text: str) -> str:
    return _extract_behavior_from_text_impl(text, ml_label_behavior_plan_aliases=_ML_LABEL_BEHAVIOR_PLAN_ALIASES)

def _extract_label_metadata_hints(row: dict) -> dict:
    return _extract_label_metadata_hints_impl(
        row,
        coerce_jsonish_dict=_coerce_jsonish_dict,
        normalize_row_str=_normalize_row_str,
        extract_rule_id_from_text=_extract_rule_id_from_text,
        extract_behavior_from_text=_extract_behavior_from_text,
        flatten_text_values=_flatten_text_values,
    )

def print_ml_label_extraction_audit(report: dict) -> None:
    _print_ml_label_extraction_audit_impl(report)


def run_ml_label_extraction_audit(config: dict) -> int:
    return _run_ml_label_extraction_audit_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_ml_label_extraction_audit=collect_ml_label_extraction_audit,
    )


def print_ml_label_metadata_plan(report: dict) -> None:
    _print_ml_label_metadata_plan_impl(report)


def run_ml_label_metadata_plan(config: dict) -> int:
    return _run_ml_label_metadata_plan_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_ml_label_metadata_plan=collect_ml_label_metadata_plan,
    )


def run_ml_legacy_bootstrap_backfill(config: dict, *, apply: bool = False) -> int:
    return _run_ml_legacy_bootstrap_backfill_impl(
        config,
        apply=apply,
        build_operator_phase_manager=_build_operator_phase_manager,
        execute_ml_legacy_bootstrap_backfill=execute_ml_legacy_bootstrap_backfill,
        print_ml_legacy_bootstrap_backfill_plan=print_ml_legacy_bootstrap_backfill_plan,
    )


def collect_ml_summary(config: dict, db, pm_status: dict) -> dict:
    return _collect_ml_summary_impl(
        config,
        db,
        pm_status,
        collect_ml_readiness_report=collect_ml_readiness_report,
        load_rule_ids_for_ml_mapping_audit=_load_rule_ids_for_ml_mapping_audit,
        collect_ml_mapping_audit=collect_ml_mapping_audit,
        collect_ml_historical_scan_plan=collect_ml_historical_scan_plan,
        collect_ml_normal_label_plan=collect_ml_normal_label_plan,
        collect_ml_label_trust_audit=collect_ml_label_trust_audit,
        collect_ml_label_metadata_plan=collect_ml_label_metadata_plan,
        collect_ml_training_scheduler_report=collect_ml_training_scheduler_report,
        collect_ml_model_status=collect_ml_model_status,
        list_ml_families=list_ml_families,
    )


def print_ml_summary(report: dict) -> None:
    _print_ml_summary_impl(report)


def run_ml_summary(config: dict) -> int:
    return _run_ml_summary_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_ml_summary=collect_ml_summary,
    )


def run_diagnose_parse_fail(config: dict) -> int:
    return _run_diagnose_parse_fail_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_parse_fail_diagnostics=collect_parse_fail_diagnostics,
    )


def run_diagnose_event_growth(config: dict) -> int:
    return _run_diagnose_event_growth_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_event_growth_diagnostics=collect_event_growth_diagnostics,
    )


def collect_ml_model_status(config: dict) -> dict:
    return _collect_ml_model_status_impl(
        config,
        scan_promoted_model_catalog=_scan_promoted_model_catalog,
        safe_runtime_state_components=_safe_runtime_state_components,
    )


def print_ml_model_status(report: dict) -> None:
    _print_ml_model_status_impl(report)


def run_ml_model_status(config: dict) -> int:
    return _run_ml_model_status_impl(
        config,
        collect_ml_model_status=collect_ml_model_status,
    )


_ML_CONFIG_DEFAULT_STATUS = _ML_CONFIG_DEFAULT_STATUS_IMPL

_ML_SCHEMA_CONTRACT = _ML_SCHEMA_CONTRACT_IMPL

_ML_CONFIG_VALID_PHASE_GATES = {"PHASE_1", "PHASE_2", "PHASE_3"}
_ML_CONFIG_VALID_STATUSES = {"active", "active_candidate", "needs_more_data", "readiness_blocked", "disabled", "paused"}


def _phase_contract_name(value: int) -> str:
    mapping = {
        int(Phase.PHASE_1): "PHASE_1",
        int(Phase.PHASE_2): "PHASE_2",
        int(Phase.PHASE_3): "PHASE_3",
    }
    return mapping.get(int(value or 0), f"PHASE_{value}")


def collect_ml_config_audit(config: dict, db=None) -> dict:
    return _collect_ml_config_audit_impl(
        config,
        db,
        list_ml_families=list_ml_families,
        ml_family_readiness=_ML_FAMILY_READINESS,
        ml_config_default_status=_ML_CONFIG_DEFAULT_STATUS,
        ml_config_valid_statuses=_ML_CONFIG_VALID_STATUSES,
        ml_config_valid_phase_gates=_ML_CONFIG_VALID_PHASE_GATES,
        ml_schema_contract=_ML_SCHEMA_CONTRACT,
        load_table_columns=_load_table_columns,
    )


def print_ml_config_audit(report: dict) -> None:
    _print_ml_config_audit_impl(report)


def run_ml_config_audit(config: dict) -> int:
    return _run_ml_config_audit_impl(
        config,
        build_operator_phase_manager=_build_operator_phase_manager,
        collect_ml_config_audit=collect_ml_config_audit,
    )


def collect_ml_label_contract_audit() -> dict:
    return _collect_ml_label_contract_audit_impl()


def print_ml_label_contract_audit(report: dict) -> None:
    _print_ml_label_contract_audit_impl(report)


def run_ml_label_contract_audit(config: dict) -> int:
    return _run_ml_label_contract_audit_impl(config)


def run_smoke_test(config: dict, language: str | None = None) -> int:
    return _run_smoke_test_impl(
        config,
        language=language,
        detect_distro=detect_distro,
        is_supported=is_supported,
        ensure_database=ensure_database,
        normalizer_cls=Normalizer,
        detection_engine_cls=DetectionEngine,
    )


def run_test_precheck(config: dict, allow_empty_rules: bool = False) -> tuple[int, bool]:
    return _run_test_precheck_impl(
        config,
        allow_empty_rules=allow_empty_rules,
        detect_distro=detect_distro,
        is_supported=is_supported,
        ensure_database=ensure_database,
        normalizer_cls=Normalizer,
    )


def run_db_doctor(config: dict) -> int:
    return _run_db_doctor_impl(config, ensure_database=ensure_database)


def run_db_version(config: dict) -> int:
    return _run_db_version_impl(config, ensure_database=ensure_database)


def run_db_pending(config: dict) -> int:
    return _run_db_pending_impl(config, ensure_database=ensure_database)

# ── Startup Banner ────────────────────────────────────────────────────────────

def print_startup_banner(
    config: dict,
    llm_client=None,
    threat_intel=None,
    *,
    selected_source=None,
    language: str | None = None,
):
    _print_startup_banner_impl(
        config,
        llm_client,
        threat_intel,
        selected_source=selected_source,
        language=language,
        read_version=_read_version,
        output_language=_output_language,
        system_text=system_text,
        logger=logger,
        bold=BOLD,
        cyan=CYAN,
        green=GREEN,
        yellow=YELLOW,
        red=RED,
        reset=RESET,
        phase_manager_cls=PhaseManager,
    )


# ── SIEM Pipeline ─────────────────────────────────────────────────────────────

_RUNTIME_PIPELINE_SYNC_NAMES = (
    "ActiveMonitor",
    "AnomalyGuard",
    "BOLD",
    "BaselineLearningEngine",
    "BaselineValidator",
    "ConfidenceScorer",
    "ContextStateStore",
    "CorrelationEngine",
    "DelayedLearningBuffer",
    "DetectionEngine",
    "DistroMLAdapter",
    "EventIngestionQueue",
    "GracefulShutdown",
    "HostBaselineEngine",
    "IncidentManager",
    "InstantMLEngine",
    "LLMClient",
    "MLController",
    "MLStateStore",
    "MonitorAlert",
    "NormalizedEvent",
    "Normalizer",
    "Notifier",
    "Path",
    "Phase",
    "PhaseManager",
    "RESET",
    "RareEventFilter",
    "ReportEngine",
    "RiskScoringEngine",
    "RuntimeStateStore",
    "ScoreCalibrationEngine",
    "SourceRateLimiter",
    "_acquire_scheduler_persistent_lock",
    "_bind_label_training_phase_gate",
    "_build_family_where_clause",
    "_build_scheduler_training_payload",
    "_coerce_ml_event_fields",
    "_collect_event_metrics",
    "_collect_global_ml_audit",
    "_classify_label_usage",
    "_config_family_readiness_contract",
    "_ensure_jsonl_writable",
    "_evaluate_scheduler_training_candidate",
    "_has_blocking_open_incident",
    "_label_family_support",
    "_iso_local",
    "_load_labels_read_only",
    "_normalize_model_distro",
    "_promote_scheduler_model_artifact",
    "_promoted_model_feature_vector",
    "_read_scheduler_state",
    "_release_scheduler_persistent_lock",
    "_resolve_ml_training_scheduler_config",
    "_sanitize_diagnostic_sample",
    "_scan_promoted_model_catalog",
    "_scheduler_lock_owner_token",
    "_scheduler_model_root",
    "_scheduler_record_first_training_state",
    "_scheduler_state_family_key",
    "_scheduler_state_history_entry",
    "_source_parser_hint",
    "_source_path_hint",
    "_train_scheduler_model_artifact",
    "_validate_promoted_model_metadata",
    "_write_scheduler_state",
    "build_runtime_ml_label_candidate_from_rule",
    "collect_ml_training_scheduler_report",
    "compute_ml_family_support_score",
    "create_database",
    "datetime",
    "detect_distro",
    "emit_active_ml_alert_if_allowed",
    "ensure_database",
    "evaluate_ml_family_readiness",
    "extract_features",
    "atomic_json_save",
    "feature_quality_score",
    "fmt_alert",
    "fmt_incident",
    "fmt_monitor_alert",
    "fmt_phase_status",
    "get_state_metrics",
    "json",
    "list_ml_families",
    "logger",
    "os",
    "random",
    "re",
    "resolve_rule_id_to_ml_family",
    "shutil",
    "tail_file",
    "tail_journald",
    "tail_utmp",
    "threading",
    "tempfile",
    "timedelta",
    "time",
    "yaml",
    "joblib",
)


def _sync_runtime_pipeline_dependencies() -> None:
    namespace = globals()
    for name in _RUNTIME_PIPELINE_SYNC_NAMES:
        if name in namespace:
            setattr(_runtime_alerts, name, namespace[name])
            setattr(_runtime_event_processing, name, namespace[name])
            setattr(_runtime_ml_runtime, name, namespace[name])
            setattr(_runtime_ops, name, namespace[name])
            setattr(_runtime_pipeline, name, namespace[name])
            setattr(_runtime_maintenance, name, namespace[name])
            setattr(_runtime_ml_scheduler, name, namespace[name])


_sync_runtime_pipeline_dependencies()


class SIEMPipeline(_SIEMPipelineImpl):
    def __init__(self, *args, **kwargs):
        _sync_runtime_pipeline_dependencies()
        super().__init__(*args, **kwargs)

    def __getattribute__(self, name):
        if name not in {"__class__", "__dict__", "__weakref__"}:
            _sync_runtime_pipeline_dependencies()
        return super().__getattribute__(name)


def main() -> None:
    try:
        version = _read_version(default="0.0.0")
    except Exception:
        version = "0.0.0"

    parser = build_parser(version)
    args = parser.parse_args()

    config, integration_settings, log_level = prepare_startup_config(
        args.config,
        load_config_fn=load_config,
    )
    setup_logging(log_level)

    handlers = {
        "MLController": MLController,
        "_output_language": _output_language,
        "datetime": __import__("datetime"),
        "ensure_database": ensure_database,
        "json": json,
        "main_file": __file__,
        "run_alert_explanation_contract_audit": run_alert_explanation_contract_audit,
        "run_bootstrap_label_scan_dry_run": run_bootstrap_label_scan_dry_run,
        "run_db_doctor": run_db_doctor,
        "run_db_pending": run_db_pending,
        "run_db_version": run_db_version,
        "run_diagnose_event_growth": run_diagnose_event_growth,
        "run_diagnose_parse_fail": run_diagnose_parse_fail,
        "run_explain_alert_cli": lambda cfg, parsed_args: run_explain_alert_cli(cfg, parsed_args),
        "run_ip_blocking_cli": lambda cfg, parsed_args: run_ip_blocking_cli(cfg, parsed_args),
        "run_metrics_cli": lambda cfg: _run_metrics_cli(cfg, ensure_database=ensure_database),
        "run_ml_active_emit_dry_run": run_ml_active_emit_dry_run,
        "run_ml_config_audit": run_ml_config_audit,
        "run_ml_family_readiness": run_ml_family_readiness,
        "run_ml_historical_scan_plan": run_ml_historical_scan_plan,
        "run_ml_label_contract_audit": run_ml_label_contract_audit,
        "run_ml_label_extraction_audit": run_ml_label_extraction_audit,
        "run_ml_label_metadata_plan": run_ml_label_metadata_plan,
        "run_ml_label_trust_audit": run_ml_label_trust_audit,
        "run_ml_legacy_bootstrap_backfill": run_ml_legacy_bootstrap_backfill,
        "run_ml_mapping_audit": run_ml_mapping_audit,
        "run_ml_model_status": run_ml_model_status,
        "run_ml_normal_label_plan": run_ml_normal_label_plan,
        "run_ml_readiness_report": run_ml_readiness_report,
        "run_ml_runtime_label_candidate_audit": run_ml_runtime_label_candidate_audit,
        "run_ml_summary": run_ml_summary,
        "run_ml_support_score_family": run_ml_support_score_family,
        "run_ml_train_now": run_ml_train_now,
        "run_ml_train_now_dry_run": run_ml_train_now_dry_run,
        "run_ml_train_scheduler_dry_run": run_ml_train_scheduler_dry_run,
        "run_ml_training_status": run_ml_training_status,
        "run_phase_cli": lambda cfg: _run_phase_cli(
            cfg,
            build_operator_phase_manager=_build_operator_phase_manager,
            output_language=_output_language,
            fmt_phase_status=fmt_phase_status,
        ),
        "run_report_cli": lambda cfg: _run_report_cli(
            cfg,
            ensure_database=ensure_database,
            build_deterministic_alert_report_payload=build_deterministic_alert_report_payload,
            output_language=_output_language,
            system_text=system_text,
        ),
        "run_smoke_test": run_smoke_test,
        "run_status_cli": lambda cfg: _run_status_cli(
            cfg,
            build_operator_phase_manager=_build_operator_phase_manager,
            output_language=_output_language,
            fmt_phase_status=fmt_phase_status,
        ),
        "run_test_precheck": run_test_precheck,
        "run_verified_manifest_audit_cli": run_verified_manifest_audit_cli,
        "run_verified_manifest_dry_run": run_verified_manifest_dry_run,
        "shutil": shutil,
        "subprocess_run": subprocess.run,
        "sys": sys,
        "system_text": system_text,
        "time": time,
    }

    dispatch_result = dispatch_command(args, config, handlers)
    if dispatch_result.action == "raise":
        raise SystemExit(dispatch_result.code or 0)
    if dispatch_result.action == "return":
        if dispatch_result.code not in (None, 0):
            raise SystemExit(dispatch_result.code)
        return

    check_supported_or_exit()
    print_startup_banner(config)

    pipeline = SIEMPipeline(config, allow_empty_rules=args.allow_empty_rules)
    pid_file = None

    def handler(sig, frame):
        if pid_file:
            try:
                os.unlink(pid_file)
            except OSError as _e:
                logger.debug(f"[AegisCore] PID dosyası silinemedi: {_e}")
        pipeline.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    def hup_handler(sig, frame):
        """SIGHUP → graceful restart: stop the current process and let systemd restart it.
        Triggered via ExecReload=kill -TERM $MAINPID.
        If the application ignores SIGHUP, signal behavior becomes undefined."""
        logger.info("[AegisCore] SIGHUP alindi — graceful shutdown baslatiliyor (systemd yeniden baslatacak)")
        if pid_file:
            try:
                os.unlink(pid_file)
            except OSError as _e:
                logger.debug(f"[AegisCore] PID dosyası silinemedi: {_e}")
        pipeline.stop()
        sys.exit(0)

    signal.signal(signal.SIGHUP, hup_handler)

    def usr1_handler(sig, frame):
        """SIGUSR1 → print an instant status screen without killing the process."""
        try:
            pipeline._print_status()
        except Exception as _e:
            logger.debug(f"[AegisCore] SIGUSR1 status hatası: {_e}")

    signal.signal(signal.SIGUSR1, usr1_handler)

    if dispatch_result.test_prechecked or args.test:
        pipeline._run_test_mode()
        raise SystemExit(0)

    if args.source:
        sources = config.get("sources", {})
        if args.source not in sources:
            print(f"Kaynak yok: {args.source}")
            raise SystemExit(1)
        pipeline.running = True
        pipeline.monitor.start()
        pipeline._start_queue_consumer()
        pipeline.run_source(args.source, sources[args.source])
        raise SystemExit(0)

    pipeline.start()
    raise SystemExit(0)


if __name__ == "__main__":
    main()
