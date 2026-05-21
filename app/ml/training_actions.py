from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

import joblib
import logging

logger = logging.getLogger("siem.main")

ML_TRAIN_SCHEDULER_DEFAULTS = {
    "mode": "manual",
    "weekday": "sunday",
    "hour": 3,
    "minute": 0,
    "check_interval_seconds": 1800,
    "initial_delay_seconds": 60,
    "lock_ttl_seconds": 14400,
    "normal_new_label_threshold": 500,
    "suspicious_new_label_threshold": 100,
    "enabled": True,
    "no_action_contract": True,
    "evaluation_required": True,
    "promotion_on_pass_only": True,
    "retain_existing_model_on_failure": True,
    "active_ml_enable_unchanged": True,
    "min_eval_samples_per_class": 3,
    "min_seconds_between_training": 86400,
    "max_families_per_run": 1,
    "max_samples_per_family": 5000,
    "training_timeout_seconds": 900,
    "cpu_only": True,
}
ML_TRAINING_MODES = {"manual", "scheduled", "threshold", "auto", "disabled"}
ML_PROMOTED_MODEL_FEATURE_SCHEMA_VERSION = 1
ML_PROMOTED_MODEL_VERSION = "scheduler_family_distro_v1"
ML_PROMOTED_MODEL_METADATA_FIELDS = (
    "ml_family",
    "distro_family",
    "trained_at",
    "label_counts",
    "feature_schema_version",
    "model_version",
    "evaluation_status",
    "no_action_contract",
    "artifact_path",
)
WEEKDAY_NAME_TO_INDEX = {
    "monday": 0,
    "tuesday": 1,
    "wednesday": 2,
    "thursday": 3,
    "friday": 4,
    "saturday": 5,
    "sunday": 6,
}


def acquire_scheduler_persistent_lock(
    db,
    *,
    now_ts: float,
    ttl_seconds: float,
    owner: str | None = None,
    scheduler_lock_owner_token: Callable[[], str],
    read_scheduler_state: Callable[[Any], dict],
    parse_timestamp: Callable[[Any], float],
    iso_local: Callable[[float | None], str],
    write_scheduler_state: Callable[[Any, dict], bool],
) -> tuple[bool, dict, str]:
    lock_owner = str(owner or scheduler_lock_owner_token() or "").strip() or scheduler_lock_owner_token()
    state = read_scheduler_state(db)
    run_lock = dict(state.get("run_lock", {}) or {})
    active = bool(run_lock.get("active", False))
    expires_at = parse_timestamp(run_lock.get("expires_at"))
    if active and expires_at > now_ts and str(run_lock.get("owner", "") or "") != lock_owner:
        return False, state, "persistent_lock_active"
    if active and expires_at and expires_at <= now_ts:
        state["last_model_kept_reason"] = "stale_training_lock_recovered"
    state["run_lock"] = {
        "active": True,
        "owner": lock_owner,
        "started_at": iso_local(now_ts),
        "expires_at": iso_local(now_ts + max(float(ttl_seconds or 0.0), 1.0)),
    }
    write_scheduler_state(db, state)
    return True, state, ""


def release_scheduler_persistent_lock(
    db,
    state: dict | None = None,
    *,
    owner: str | None = None,
    scheduler_lock_owner_token: Callable[[], str],
    read_scheduler_state: Callable[[Any], dict],
    iso_local: Callable[[float | None], str],
    write_scheduler_state: Callable[[Any, dict], bool],
) -> dict:
    payload = dict(state or read_scheduler_state(db) or {})
    payload["run_lock"] = {
        "active": False,
        "owner": str(owner or scheduler_lock_owner_token() or "").strip() or scheduler_lock_owner_token(),
        "released_at": iso_local(time.time()),
    }
    write_scheduler_state(db, payload)
    return payload


def normalize_model_distro(value: Any) -> str:
    token = str(value or "").strip().lower()
    return token or "unknown_distro"


def stable_token_bucket(value: Any, modulo: int = 997) -> float:
    token = str(value or "").strip().lower()
    if not token:
        return 0.0
    total = 0
    for index, char in enumerate(token):
        total += (index + 1) * ord(char)
    return round((total % modulo) / float(modulo), 6)


def port_bucket_from_payload(payload: dict) -> float:
    fields = dict(payload.get("fields", {}) or {})
    raw = fields.get("dst_port", payload.get("dst_port", fields.get("port", 0)))
    try:
        port = int(raw)
    except (TypeError, ValueError):
        port = 0
    if port <= 0:
        return 0.0
    if port < 1024:
        return 0.33
    if port < 49152:
        return 0.66
    return 1.0


def payload_from_training_row(row: dict, *, coerce_ml_event_fields: Callable[[dict], dict]) -> dict:
    payload = {
        "ts": row.get("ts", 0.0),
        "source": row.get("source", ""),
        "category": row.get("category", ""),
        "action": row.get("action", ""),
        "outcome": row.get("outcome", ""),
        "process": row.get("process", ""),
        "message": row.get("message", ""),
        "host": row.get("host", ""),
        "user": row.get("user", row.get("username", "")),
        "username": row.get("username", row.get("user", "")),
        "src_ip": row.get("src_ip", ""),
        "dst_ip": row.get("dst_ip", ""),
        "distro_family": row.get("distro_family", row.get("distro", "unknown_distro")),
        "fields": dict(row.get("fields", {}) or {}),
    }
    evidence = dict(row.get("evidence_fields", {}) or {})
    for key in ("action", "category", "outcome", "process", "src_ip", "dst_ip", "host"):
        if not payload.get(key):
            payload[key] = str(evidence.get(key, "") or "")
    if not payload.get("user"):
        payload["user"] = str(evidence.get("user", evidence.get("username", "")) or "")
        payload["username"] = payload["user"]
    if "dst_port" not in payload["fields"] and evidence.get("dst_port") not in (None, ""):
        payload["fields"]["dst_port"] = evidence.get("dst_port")
    return coerce_ml_event_fields(payload)


def promoted_model_feature_vector(
    event_payload: dict,
    family_id: str,
    distro: str,
    *,
    coerce_ml_event_fields: Callable[[dict], dict],
    get_ml_family_spec: Callable[[str], Any],
    stable_token_bucket: Callable[[Any, int], float],
    port_bucket_from_payload: Callable[[dict], float],
) -> list[float]:
    payload = coerce_ml_event_fields(event_payload)
    ts = float(payload.get("ts", time.time()) or time.time())
    local_tm = time.localtime(ts)
    category = str(payload.get("category", "") or "").strip().lower()
    action = str(payload.get("action", "") or "").strip().lower()
    outcome = str(payload.get("outcome", "") or "").strip().lower()
    source = str(payload.get("source", "") or "").strip().lower()
    process = str(payload.get("process", "") or "").strip().lower()
    message = str(payload.get("message", "") or "")
    user = str(payload.get("user", payload.get("username", "")) or "").strip().lower()
    family_spec = get_ml_family_spec(family_id)
    expected_category = str(getattr(family_spec, "category", "") or "").strip().lower()
    return [
        round(int(local_tm.tm_hour) / 23.0, 6),
        round(int(local_tm.tm_wday) / 6.0, 6),
        1.0 if int(local_tm.tm_wday) >= 5 else 0.0,
        stable_token_bucket(category),
        stable_token_bucket(action),
        stable_token_bucket(source),
        stable_token_bucket(outcome),
        1.0 if user else 0.0,
        1.0 if process else 0.0,
        1.0 if str(payload.get("src_ip", "") or "").strip() else 0.0,
        1.0 if str(payload.get("dst_ip", "") or "").strip() else 0.0,
        port_bucket_from_payload(payload),
        round(min(len(message) / 512.0, 1.0), 6),
        1.0 if expected_category and expected_category in category else 0.0,
        stable_token_bucket(distro),
    ]


def label_row_target(row: dict) -> int:
    event_class = str(row.get("event_class", "") or "").strip().lower()
    return 0 if event_class == "benign" else 1


def validate_promoted_model_metadata(
    metadata: dict,
    *,
    metadata_fields: tuple[str, ...],
    normalize_model_distro: Callable[[Any], str],
    list_ml_families: Callable[[], list[Any]],
    feature_schema_version: int,
) -> tuple[bool, list[str]]:
    payload = dict(metadata or {})
    problems: list[str] = []
    for field in metadata_fields:
        if payload.get(field) in (None, "", {}):
            problems.append(f"missing:{field}")
    if payload.get("no_action_contract") is not True:
        problems.append("invalid:no_action_contract")
    family = str(payload.get("ml_family", "") or "").strip().upper()
    valid_families = {spec.family_id for spec in list_ml_families()}
    if family not in valid_families:
        problems.append("invalid:ml_family")
    if normalize_model_distro(payload.get("distro_family")) == "unknown_distro":
        problems.append("invalid:unknown_distro")
    if int(payload.get("feature_schema_version", -1) or -1) != feature_schema_version:
        problems.append("invalid:feature_schema_version")
    if str(payload.get("evaluation_status", "") or "").strip().lower() not in {"pass", "passed"}:
        problems.append("invalid:evaluation_status")
    return len(problems) == 0, problems


def atomic_joblib_dump(path: Path, payload: Any, *, logger_override=None) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: str | None = None
    active_logger = logger_override or logger
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False, suffix=".tmp") as tf:
            tmp_path = tf.name
            joblib.dump(payload, tf.name)
            tf.flush()
            os.fsync(tf.fileno())
        os.replace(tmp_path, path)
        return True
    except Exception as exc:
        active_logger.error("[AegisCore:MLScheduler] Artifact write failed (%s): %s", path, exc)
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass
        return False


def write_scheduler_state(db, state: dict, *, logger_override=None) -> bool:
    if db is None or not hasattr(db, "set_stat"):
        return False
    payload = dict(state or {})
    history = list(payload.get("history", []) or [])
    if history:
        payload["history"] = history[-20:]
    active_logger = logger_override or logger
    try:
        db.set_stat("ml_training_scheduler_state", json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return True
    except Exception as exc:
        active_logger.warning("[AegisCore:MLScheduler] State write failed: %s", exc)
        return False


def read_scheduler_state(db, *, safe_json_stat: Callable[[Any, str], dict]) -> dict:
    state = safe_json_stat(db, "ml_training_scheduler_state")
    return state if isinstance(state, dict) else {}


def limit_scheduler_training_rows(rows: list[dict], max_samples: int, *, parse_timestamp: Callable[[Any], float]) -> list[dict]:
    limit = max(1, int(max_samples or 1))
    if len(rows) <= limit:
        return list(rows)
    normal_rows = [row for row in rows if str(row.get("event_class", "") or "").strip().lower() == "benign"]
    suspicious_rows = [
        row for row in rows
        if str(row.get("event_class", "") or "").strip().lower() in {"attack", "suspicious"}
    ]
    preferred_suspicious = min(len(suspicious_rows), max(1, limit // 2))
    preferred_normal = min(len(normal_rows), limit - preferred_suspicious)
    if preferred_normal <= 0 and normal_rows:
        preferred_normal = 1
    if preferred_suspicious + preferred_normal > limit:
        preferred_normal = max(0, limit - preferred_suspicious)
    selected = normal_rows[-preferred_normal:] + suspicious_rows[-preferred_suspicious:]
    if len(selected) < limit:
        seen = {id(item) for item in selected}
        for row in reversed(rows):
            if id(row) in seen:
                continue
            selected.insert(0, row)
            seen.add(id(row))
            if len(selected) >= limit:
                break
    selected.sort(key=lambda item: parse_timestamp(item.get("ts")))
    return selected[-limit:]


def execute_manual_training_with_owner(
    config: dict,
    db,
    pm_status: dict,
    *,
    now_ts: float | None = None,
    refresh_runtime_registry: Callable[..., dict] | None = None,
    owner_token: Callable[[], str],
    resolve_ml_training_scheduler_config: Callable[[dict], dict],
    collect_ml_training_scheduler_report: Callable[..., dict],
    refresh_promoted_model_registry_noop: Callable[..., dict],
    acquire_scheduler_persistent_lock: Callable[..., tuple[bool, dict, str]],
    load_labels_read_only: Callable[[Any], tuple[list[dict], str | None]],
    iso_local: Callable[[float | None], str],
    write_scheduler_state: Callable[[Any, dict], bool],
    scheduler_state_family_key: Callable[[str, str], str],
    build_scheduler_training_payload: Callable[..., dict],
    evaluate_scheduler_training_candidate: Callable[[dict, dict], dict],
    scheduler_record_first_training_state: Callable[..., None],
    scheduler_state_history_entry: Callable[[dict], dict],
    train_scheduler_model_artifact: Callable[[dict, str, str, dict, dict], dict],
    promote_scheduler_model_artifact: Callable[[dict, str, str, dict], dict],
    release_scheduler_persistent_lock: Callable[..., dict],
) -> dict:
    now_ts = float(now_ts if now_ts is not None else time.time())
    schedule_cfg = resolve_ml_training_scheduler_config(config)
    owner = f"manual:{owner_token()}"
    decision = collect_ml_training_scheduler_report(
        config,
        db,
        pm_status,
        now_ts=now_ts,
        trigger_request="manual_execute",
    )
    report = dict(decision or {})
    report.update(
        {
            "trigger_request": "manual_execute",
            "training_started": False,
            "db_write_attempted": False,
            "active_ml_enabled": False,
            "evaluation_required": bool(decision.get("train_now", False)),
            "trained_families": [],
            "evaluation_results": [],
            "promoted_models": [],
            "kept_existing_models": [],
            "llm_called": False,
            "firewall_action_taken": False,
            "ip_block_action_taken": False,
            "incident_action_taken": False,
            "no_action_contract": True,
        }
    )
    if db is None:
        report["reason"] = "db_unavailable"
        report.setdefault("query_notes", []).append("db_unavailable")
        return report

    acquired = False
    state: dict = {}
    label_rows: list[dict] = []
    labels_error = ""
    refresh_fn = refresh_runtime_registry or refresh_promoted_model_registry_noop
    try:
        acquired, state, lock_reason = acquire_scheduler_persistent_lock(
            db,
            now_ts=now_ts,
            ttl_seconds=float(schedule_cfg.get("lock_ttl_seconds", 14400) or 14400.0),
            owner=owner,
        )
        if not acquired:
            report["reason"] = lock_reason
            report["kept_existing_models"].append({"family_distro": "", "reason": lock_reason})
            return report

        label_rows, labels_error = load_labels_read_only(db)
        if labels_error:
            report.setdefault("query_notes", []).append(labels_error)

        report_training_mode = str(report.get("training_mode", schedule_cfg.get("mode", "manual")) or schedule_cfg.get("mode", "manual"))
        state.update(
            {
                "enabled": True,
                "training_mode": report_training_mode,
                "last_scheduler_check_at": report.get("current_time", iso_local(now_ts)),
                "next_run_at": report.get("next_run_at", ""),
                "last_decision_reason": report.get("reason", ""),
                "last_trigger_request": "manual_execute",
                "eligible_families_snapshot": list(report.get("eligible_families", []) or []),
                "blocked_families_snapshot": list(report.get("blocked_families", []) or []),
                "schedule_due": bool(report.get("schedule_due", False)),
                "no_action_contract": True,
                "training_started": False,
                "db_write_attempted": True,
                "active_ml_enabled": False,
                "query_notes": list(report.get("query_notes", []) or []),
            }
        )
        write_scheduler_state(db, state)
        report["db_write_attempted"] = True

        if not report.get("train_now", False):
            return report

        report["training_started"] = True
        state["training_started"] = True
        write_scheduler_state(db, state)

        for item in list(report.get("execution_candidates", []) or report.get("eligible_families", []) or []):
            family_id = str(item.get("family_id", "") or "").strip().upper()
            distro = str(item.get("distro", "") or "").strip().lower() or "unknown_distro"
            family_key = scheduler_state_family_key(family_id, distro)
            report["trained_families"].append(
                {
                    "family_id": family_id,
                    "distro": distro,
                    "family_distro": family_key,
                    "reason": str(item.get("reason", "") or report.get("reason", "")),
                    "mode": str(item.get("mode", "") or ""),
                }
            )
            try:
                training_payload = build_scheduler_training_payload(
                    label_rows if not labels_error else [],
                    family_id,
                    distro,
                    max_samples_per_family=int(schedule_cfg.get("max_samples_per_family", 0) or 0),
                )
                evaluation = evaluate_scheduler_training_candidate(training_payload, schedule_cfg)
                evaluation_status = "passed" if evaluation.get("passed", False) else "failed"
                evaluation_item = {
                    "family_id": family_id,
                    "distro": distro,
                    "family_distro": family_key,
                    "status": evaluation_status,
                    "reason": str(evaluation.get("reason", "evaluation_failed") or "evaluation_failed"),
                    "metrics": dict(evaluation.get("metrics", {}) or {}),
                    "label_counts": dict(training_payload.get("summary", {}).get("class_counts", {}) or {}),
                }
                report["evaluation_results"].append(evaluation_item)
                state.update(
                    {
                        "last_training_at": iso_local(now_ts),
                        "last_training_family_distro": family_key,
                        "last_training_reason": str(item.get("reason", "") or report.get("reason", "")),
                        "last_training_label_counts": dict(training_payload.get("summary", {}).get("class_counts", {}) or {}),
                        "last_evaluation_status": evaluation_status,
                    }
                )

                if not evaluation.get("passed", False):
                    scheduler_record_first_training_state(
                        state,
                        now_ts=now_ts,
                        training_status="evaluation_failed",
                        evaluation_status=evaluation_status,
                        model_ready=False,
                        family_key=family_key,
                    )
                    state["last_training_status"] = "evaluation_failed"
                    state["last_model_promoted"] = False
                    state["last_model_kept_reason"] = evaluation_item["reason"]
                    report["kept_existing_models"].append(
                        {
                            "family_id": family_id,
                            "distro": distro,
                            "family_distro": family_key,
                            "reason": evaluation_item["reason"],
                        }
                    )
                    history = list(state.get("history", []) or [])
                    history.append(scheduler_state_history_entry(state))
                    state["history"] = history[-20:]
                    write_scheduler_state(db, state)
                    continue

                training_result = train_scheduler_model_artifact(config, family_id, distro, training_payload, evaluation)
                state["last_evaluation_status"] = str(
                    dict(training_result.get("metadata_payload", {}) or {}).get("evaluation_status", state.get("last_evaluation_status", ""))
                    or state.get("last_evaluation_status", "")
                )
                promotion = promote_scheduler_model_artifact(config, family_id, distro, training_result)
                if promotion.get("promoted", False):
                    metadata_payload = dict(training_result.get("metadata_payload", {}) or {})
                    scheduler_record_first_training_state(
                        state,
                        now_ts=now_ts,
                        training_status="promoted",
                        evaluation_status=str(metadata_payload.get("evaluation_status", evaluation_status) or evaluation_status),
                        model_ready=True,
                        family_key=family_key,
                    )
                    report["promoted_models"].append(
                        {
                            "family_id": family_id,
                            "distro": distro,
                            "family_distro": family_key,
                            "artifact_path": str(promotion.get("artifact_path", "") or ""),
                            "metadata_path": str(promotion.get("metadata_path", "") or ""),
                            "metadata": metadata_payload,
                        }
                    )
                    state["last_training_status"] = "promoted"
                    state["last_model_promoted"] = True
                    state["last_model_kept_reason"] = ""
                    last_training = dict(state.get("last_training", {}) or {})
                    last_training[family_key] = {
                        "trained_at": iso_local(now_ts),
                        "status": "promoted",
                        "label_counts": dict(training_payload.get("summary", {}).get("class_counts", {}) or {}),
                        "artifact_path": str(promotion.get("artifact_path", "") or ""),
                        "metadata_path": str(promotion.get("metadata_path", "") or ""),
                    }
                    state["last_training"] = last_training
                    refresh_fn(load_artifacts=False)
                else:
                    reason = str(promotion.get("reason", "artifact_write_failed") or "artifact_write_failed")
                    scheduler_record_first_training_state(
                        state,
                        now_ts=now_ts,
                        training_status="artifact_write_failed",
                        evaluation_status=str(state.get("last_evaluation_status", evaluation_status) or evaluation_status),
                        model_ready=False,
                        family_key=family_key,
                    )
                    state["last_training_status"] = "evaluation_failed" if "evaluation" in reason else "artifact_write_failed"
                    state["last_model_promoted"] = False
                    state["last_model_kept_reason"] = reason
                    report["kept_existing_models"].append(
                        {
                            "family_id": family_id,
                            "distro": distro,
                            "family_distro": family_key,
                            "reason": reason,
                        }
                    )
                history = list(state.get("history", []) or [])
                history.append(scheduler_state_history_entry(state))
                state["history"] = history[-20:]
                write_scheduler_state(db, state)
            except Exception as exc:
                scheduler_record_first_training_state(
                    state,
                    now_ts=now_ts,
                    training_status="artifact_write_failed",
                    evaluation_status="failed",
                    model_ready=False,
                    family_key=family_key,
                )
                state["last_training_status"] = "artifact_write_failed"
                state["last_model_promoted"] = False
                state["last_model_kept_reason"] = str(exc) or "manual_training_failed"
                report["kept_existing_models"].append(
                    {
                        "family_id": family_id,
                        "distro": distro,
                        "family_distro": family_key,
                        "reason": str(exc) or "manual_training_failed",
                    }
                )
                history = list(state.get("history", []) or [])
                history.append(scheduler_state_history_entry(state))
                state["history"] = history[-20:]
                write_scheduler_state(db, state)
        report["last_training_status"] = str(state.get("last_training_status", report.get("last_training_status", "")) or report.get("last_training_status", ""))
        report["last_model_promoted"] = bool(state.get("last_model_promoted", report.get("last_model_promoted", False)))
        report["last_model_kept_reason"] = str(state.get("last_model_kept_reason", report.get("last_model_kept_reason", "")) or report.get("last_model_kept_reason", ""))
        report["last_evaluation_status"] = str(state.get("last_evaluation_status", report.get("last_evaluation_status", "")) or report.get("last_evaluation_status", ""))
        report["last_training_at"] = str(state.get("last_training_at", report.get("last_training_at", "")) or report.get("last_training_at", ""))
        report["last_training_family_distro"] = str(state.get("last_training_family_distro", report.get("last_training_family_distro", "")) or report.get("last_training_family_distro", ""))
        report["last_training_label_counts"] = dict(state.get("last_training_label_counts", report.get("last_training_label_counts", {}) or {}) or {})
        report["first_model_training_completed"] = bool(state.get("first_model_training_completed_at", ""))
        report["first_model_training_completed_at"] = str(state.get("first_model_training_completed_at", "") or "")
        report["first_model_training_status"] = str(state.get("first_model_training_status", "") or "")
        report["first_model_evaluation_passed"] = str(state.get("first_model_evaluation_status", "") or "").strip().lower() in {"pass", "passed", "evaluation_passed"}
        report["first_model_evaluation_status"] = str(state.get("first_model_evaluation_status", "") or "")
        report["first_ml_model_ready"] = bool(state.get("first_ml_model_ready", False))
        report["ml_alert_family_ready"] = bool(state.get("ml_alert_family_ready", False))
        report["ml_alert_family_enabled_families"] = list(state.get("ml_alert_family_enabled_families", []) or [])
        report["training_started"] = bool(report.get("trained_families"))
        return report
    finally:
        if acquired:
            state["training_started"] = False
            release_scheduler_persistent_lock(db, state, owner=owner)


__all__ = [
    "ML_TRAIN_SCHEDULER_DEFAULTS",
    "ML_TRAINING_MODES",
    "ML_PROMOTED_MODEL_FEATURE_SCHEMA_VERSION",
    "ML_PROMOTED_MODEL_VERSION",
    "ML_PROMOTED_MODEL_METADATA_FIELDS",
    "WEEKDAY_NAME_TO_INDEX",
    "acquire_scheduler_persistent_lock",
    "release_scheduler_persistent_lock",
    "normalize_model_distro",
    "stable_token_bucket",
    "port_bucket_from_payload",
    "payload_from_training_row",
    "promoted_model_feature_vector",
    "label_row_target",
    "validate_promoted_model_metadata",
    "atomic_joblib_dump",
    "write_scheduler_state",
    "read_scheduler_state",
    "limit_scheduler_training_rows",
    "execute_manual_training_with_owner",
]
