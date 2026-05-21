#!/usr/bin/env python3
"""
Dry-run audit for legacy ML labels before canonical metadata backfill.

Bu script:
  - labels tablosunu ve synthetic label havuzunu okur
  - DB'ye write/update/delete yapmaz
  - legacy kayıtlar için güvenli canonical backfill önerisi üretir
  - calibration_only vs shadow_only / unknown_unlabeled coverage tahmini verir
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.database_postgres import PostgresDatabase, psycopg2  # noqa: E402
from core.integrations import IntegrationSettings  # noqa: E402
from core.ml.label_engine import LabelEngine, LabelRecord  # noqa: E402


STRONG_ATTACK_CATEGORIES = {
    "credential_access",
    "exfiltration",
    "command_and_control",
    "impact",
    "downloader_stager",
    "container_abuse",
    "privilege_esc",
    "privilege_escalation",
    "initial_access",
    "webshell",
}

EXPECTED_NORMAL_CATEGORIES = {
    "auth_normal": ("expected_auth_activity", "observed_benign_high"),
    "expected_db_activity": ("expected_db_activity", "observed_benign_high"),
    "system_service": ("routine_system_event", "observed_benign_high"),
    "selinux_routine": ("routine_system_event", "observed_benign_high"),
}

GENERAL_BENIGN_CATEGORIES = {
    "package_management",
    "normal_network",
    "routine_file_access",
    "normal_logout",
}

SYNTHETIC_NORMAL_WHITELIST = {
    "auth_normal",
    "selinux_routine",
    "system_service",
}

SYNTHETIC_ATTACK_WHITELIST = {
    "brute_force_success",
    "persistence",
    "privilege_esc",
    "lateral_movement",
    "webshell",
}

CANONICAL_TEXT_FIELDS = (
    "event_class",
    "behavior_label",
    "attack_family",
    "technique_label",
    "source_trust",
    "model_usage_scope",
    "label_lifecycle_status",
)
CANONICAL_OPTIONAL_FIELDS = ("learnable", "evidence_fields")
CANONICAL_UPDATE_FIELDS = CANONICAL_TEXT_FIELDS + CANONICAL_OPTIONAL_FIELDS
DB_BACKED_SOURCES = {"bootstrap", "auto_labeled", "manually_verified"}


def _resolve_database_url(cli_value: str = "") -> str:
    if cli_value:
        return cli_value.strip()
    env_url = (os.environ.get("DATABASE_URL", "") or os.environ.get("AEGISCORE_DB_URL", "")).strip()
    if env_url:
        return env_url
    env_cfg = IntegrationSettings.load().database_url
    if env_cfg:
        return env_cfg
    cfg_path = ROOT / "config" / "config.yml"
    if cfg_path.exists():
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            url = ((data.get("database", {}) or {}).get("url", "") or "").strip()
            if url:
                return url
        except Exception:
            pass
    return ""


def _existing_metadata(record: LabelRecord) -> Dict[str, Any]:
    return {
        "event_class": getattr(record, "event_class", "") or "",
        "behavior_label": getattr(record, "behavior_label", "") or "",
        "attack_family": getattr(record, "attack_family", "") or "",
        "technique_label": getattr(record, "technique_label", "") or "",
        "source_trust": getattr(record, "source_trust", "") or "",
        "learnable": getattr(record, "learnable", None),
        "model_usage_scope": getattr(record, "model_usage_scope", "") or "",
        "label_lifecycle_status": getattr(record, "label_lifecycle_status", "") or "",
        "label_reason": getattr(record, "label_reason", "") or "",
        "evidence_fields": getattr(record, "evidence_fields", None),
    }


def _is_missing_canonical(meta: Dict[str, Any]) -> bool:
    return not any(
        [
            meta.get("event_class"),
            meta.get("behavior_label"),
            meta.get("source_trust"),
            meta.get("model_usage_scope"),
        ]
    )


def _proposed_backfill(record: LabelRecord, source_name: str) -> Dict[str, Any]:
    meta = _existing_metadata(record)
    if not _is_missing_canonical(meta):
        return meta

    label = (getattr(record, "label", "") or "").lower()
    category = (getattr(record, "category", "") or "").lower()

    # Synthetic provenance is deliberately conservative in phase 1/2 migration.
    if source_name == "synthetic":
        if label == "attack" and category in SYNTHETIC_ATTACK_WHITELIST:
            return {
                "event_class": "attack",
                "behavior_label": category,
                "attack_family": category,
                "technique_label": category,
                "source_trust": "synthetic_high",
                "learnable": True,
                "model_usage_scope": "calibration_only",
                "label_lifecycle_status": "backfill_candidate",
                "label_reason": "legacy_synthetic_attack_whitelist_backfill",
                "evidence_fields": {
                    "legacy_category": category,
                    "legacy_label": label,
                    "rule_hint": getattr(record, "rule_hint", "") if hasattr(record, "rule_hint") else "",
                },
            }
        if label == "normal" and category in SYNTHETIC_NORMAL_WHITELIST:
            return {
                "event_class": "benign",
                "behavior_label": category,
                "attack_family": "",
                "technique_label": category,
                "source_trust": "synthetic_high",
                "learnable": True,
                "model_usage_scope": "calibration_only",
                "label_lifecycle_status": "backfill_candidate",
                "label_reason": "legacy_synthetic_normal_whitelist_backfill",
                "evidence_fields": {
                    "legacy_category": category,
                    "legacy_label": label,
                    "rule_hint": getattr(record, "rule_hint", "") if hasattr(record, "rule_hint") else "",
                },
            }
        return {
            "event_class": "unknown_unlabeled",
            "behavior_label": "unknown_unlabeled",
            "attack_family": "",
            "technique_label": "",
            "source_trust": "synthetic_low",
            "learnable": False,
            "model_usage_scope": "shadow_only",
            "label_lifecycle_status": "backfill_candidate",
            "label_reason": "legacy_synthetic_conservative_backfill",
            "evidence_fields": {"legacy_category": category, "legacy_label": label},
        }

    if label == "attack":
        if category in STRONG_ATTACK_CATEGORIES:
            return {
                "event_class": "attack",
                "behavior_label": category,
                "attack_family": category,
                "technique_label": category,
                "source_trust": "rule_high",
                "learnable": True,
                "model_usage_scope": "calibration_only",
                "label_lifecycle_status": "backfill_candidate",
                "label_reason": "legacy_attack_strong_category_backfill",
                "evidence_fields": {"legacy_category": category, "legacy_label": label},
            }
        return {
            "event_class": "unknown_unlabeled",
            "behavior_label": "unknown_unlabeled",
            "attack_family": "",
            "technique_label": "",
            "source_trust": "rule_medium",
            "learnable": False,
            "model_usage_scope": "shadow_only",
            "label_lifecycle_status": "backfill_candidate",
            "label_reason": "legacy_attack_unsafe_or_generic",
            "evidence_fields": {"legacy_category": category, "legacy_label": label},
        }

    if label == "normal":
        if category in EXPECTED_NORMAL_CATEGORIES:
            behavior_label, source_trust = EXPECTED_NORMAL_CATEGORIES[category]
            return {
                "event_class": "benign",
                "behavior_label": behavior_label,
                "attack_family": "",
                "technique_label": category,
                "source_trust": source_trust,
                "learnable": True,
                "model_usage_scope": "calibration_only",
                "label_lifecycle_status": "backfill_candidate",
                "label_reason": "legacy_normal_expected_backfill",
                "evidence_fields": {"legacy_category": category, "legacy_label": label},
            }
        if category in GENERAL_BENIGN_CATEGORIES:
            return {
                "event_class": "benign",
                "behavior_label": "benign_activity",
                "attack_family": "",
                "technique_label": category,
                "source_trust": "observed_benign_medium",
                "learnable": False,
                "model_usage_scope": "shadow_only",
                "label_lifecycle_status": "backfill_candidate",
                "label_reason": "legacy_normal_general_benign_backfill",
                "evidence_fields": {"legacy_category": category, "legacy_label": label},
            }

    return {
        "event_class": "unknown_unlabeled",
        "behavior_label": "unknown_unlabeled",
        "attack_family": "",
        "technique_label": "",
        "source_trust": "legacy_unknown",
        "learnable": False,
        "model_usage_scope": "shadow_only",
        "label_lifecycle_status": "backfill_candidate",
        "label_reason": "legacy_missing_or_unsafe_backfill",
        "evidence_fields": {"legacy_category": category, "legacy_label": label},
    }


def _coverage_bucket(meta: Dict[str, Any]) -> str:
    event_class = (meta.get("event_class", "") or "").lower()
    behavior_label = (meta.get("behavior_label", "") or "").lower()
    model_usage_scope = (meta.get("model_usage_scope", "") or "").lower()
    source_trust = (meta.get("source_trust", "") or "").lower()
    learnable = meta.get("learnable", None)

    if not any([event_class, behavior_label, model_usage_scope, source_trust]):
        return "missing_unsafe"
    if event_class == "unknown_unlabeled" or behavior_label == "unknown_unlabeled":
        return "unknown_unlabeled"
    if model_usage_scope == "shadow_only":
        return "shadow_only"
    if model_usage_scope == "calibration_only" and learnable is True:
        if event_class == "attack":
            return "eligible_attack"
        if event_class == "benign":
            return "eligible_normal"
    return "missing_unsafe"


def _iter_all_records(engine: LabelEngine) -> Iterable[Tuple[str, LabelRecord]]:
    yield from (("synthetic", r) for r in engine._synthetic_records)
    yield from (("bootstrap", r) for r in engine._bootstrap_records)
    yield from (("auto_labeled", r) for r in engine._auto_labeler._records)
    yield from (("manually_verified", r) for r in engine._manually_records)


def _load_db_rows(db: PostgresDatabase, distro: str) -> List[Dict[str, Any]]:
    if distro:
        rows = db._execute(
            "SELECT * FROM labels WHERE distro = %s OR distro = '' ORDER BY ts ASC",
            (distro,),
            fetch="all",
        )
    else:
        rows = db._execute("SELECT * FROM labels ORDER BY ts ASC", fetch="all")
    return list(rows or [])


def _record_from_row(row: Dict[str, Any]) -> LabelRecord:
    return LabelRecord(
        score=row.get("score", 0.0) or 0.0,
        label=row.get("label", "") or "",
        category=row.get("category", "") or "",
        source=row.get("source", "") or "",
        confidence=row.get("confidence", 1.0) or 1.0,
        ts=row.get("ts", 0.0) or 0.0,
        weight=row.get("weight", 1.0) or 1.0,
        entity_key=row.get("entity_key", "") or "",
        ready_after=row.get("ready_after", 0.0) or 0.0,
        distro=row.get("distro", "") or "",
        event_class=row.get("event_class", "") or "",
        behavior_label=row.get("behavior_label", "") or "",
        attack_family=row.get("attack_family", "") or "",
        technique_label=row.get("technique_label", "") or "",
        source_trust=row.get("source_trust", "") or "",
        learnable=row.get("learnable", None),
        model_usage_scope=row.get("model_usage_scope", "") or "",
        label_lifecycle_status=row.get("label_lifecycle_status", "") or "",
        poisoning_guard_passed=row.get("poisoning_guard_passed", None),
        label_reason=row.get("label_reason", "") or "",
        evidence_fields=row.get("evidence_fields", None),
        review_flags=row.get("review_flags", None),
        bootstrap_job_id=row.get("bootstrap_job_id", "") or "",
        label_batch_id=row.get("label_batch_id", "") or "",
        correlation_id=row.get("correlation_id", "") or "",
    )


def _canonical_update_values(proposed: Dict[str, Any]) -> Dict[str, Any]:
    return {field: proposed.get(field, None) for field in CANONICAL_UPDATE_FIELDS}


def _row_is_apply_candidate(row: Dict[str, Any], proposed: Dict[str, Any]) -> bool:
    current_meta = _existing_metadata(_record_from_row(row))
    if not _is_missing_canonical(current_meta):
        return False
    for field, value in _canonical_update_values(proposed).items():
        if row.get(field, None) is None and value is not None:
            return True
    return False


def _build_apply_candidates(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    for row in rows:
        source_name = (row.get("source", "") or "").strip()
        if source_name not in DB_BACKED_SOURCES:
            continue
        record = _record_from_row(row)
        proposed = _proposed_backfill(record, source_name)
        if not _row_is_apply_candidate(row, proposed):
            continue
        candidates.append(
            {
                "id": row["id"],
                "source": source_name,
                "label": row.get("label", "") or "",
                "category": row.get("category", "") or "",
                "entity_key": row.get("entity_key", "") or "",
                "distro": row.get("distro", "") or "",
                "ts": row.get("ts", 0.0) or 0.0,
                "current": {field: row.get(field, None) for field in CANONICAL_UPDATE_FIELDS + ("label_reason", "label_batch_id")},
                "proposed": _canonical_update_values(proposed),
                "proposed_label_reason": proposed.get("label_reason", "") or "",
            }
        )
    return candidates


def _build_batch_id(distro: str, candidates: List[Dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for candidate in candidates:
        digest.update(str(candidate["id"]).encode("utf-8"))
        digest.update(b":")
        digest.update((candidate["proposed_label_reason"] or "").encode("utf-8"))
        digest.update(b":")
        digest.update(json.dumps(candidate["proposed"], sort_keys=True, ensure_ascii=True).encode("utf-8"))
        digest.update(b"\n")
    suffix = digest.hexdigest()[:12] if candidates else "empty0000000"
    return f"legacy_canonical_backfill_{distro}_{len(candidates)}_{suffix}"


def _artifact_dir(batch_id: str) -> Path:
    return ROOT / "data" / "legacy_canonical_backfill" / batch_id


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_snapshot_and_rollback(report: Dict[str, Any], candidates: List[Dict[str, Any]]) -> Dict[str, str]:
    batch_id = report["proposed_label_batch_id"]
    artifact_dir = _artifact_dir(batch_id)
    snapshot_path = artifact_dir / "pre_apply_snapshot.json"
    rollback_path = artifact_dir / "rollback_report.json"
    report_path = artifact_dir / "audit_report.json"
    _write_json(
        snapshot_path,
        {
            "kind": "legacy_canonical_backfill_pre_apply_snapshot",
            "label_batch_id": batch_id,
            "generated_at": time.time(),
            "distro_family": report["distro_family"],
            "rows": candidates,
        },
    )
    _write_json(
        rollback_path,
        {
            "kind": "legacy_canonical_backfill_rollback_report",
            "label_batch_id": batch_id,
            "generated_at": time.time(),
            "rollback_scope": {
                "table": "labels",
                "where": {"label_batch_id": batch_id},
                "row_count": len(candidates),
            },
            "restore_fields": list(CANONICAL_UPDATE_FIELDS) + ["label_reason", "label_batch_id"],
            "pre_apply_rows": candidates,
        },
    )
    _write_json(report_path, report)
    return {
        "artifact_dir": str(artifact_dir),
        "snapshot_path": str(snapshot_path),
        "rollback_report_path": str(rollback_path),
        "audit_report_path": str(report_path),
    }


def _apply_backfill(db: PostgresDatabase, batch_id: str, candidates: List[Dict[str, Any]]) -> int:
    if not candidates:
        return 0
    conn = db._conn()
    try:
        with conn.cursor() as cur:
            updated = 0
            for candidate in candidates:
                proposed = candidate["proposed"]
                evidence_value = proposed.get("evidence_fields", None)
                evidence_json = psycopg2.extras.Json(evidence_value) if evidence_value is not None else None
                cur.execute(
                    """
                    UPDATE labels
                    SET event_class = CASE WHEN event_class IS NULL THEN %s ELSE event_class END,
                        behavior_label = CASE WHEN behavior_label IS NULL THEN %s ELSE behavior_label END,
                        attack_family = CASE WHEN attack_family IS NULL THEN %s ELSE attack_family END,
                        technique_label = CASE WHEN technique_label IS NULL THEN %s ELSE technique_label END,
                        source_trust = CASE WHEN source_trust IS NULL THEN %s ELSE source_trust END,
                        learnable = CASE WHEN learnable IS NULL THEN %s ELSE learnable END,
                        model_usage_scope = CASE WHEN model_usage_scope IS NULL THEN %s ELSE model_usage_scope END,
                        label_lifecycle_status = CASE WHEN label_lifecycle_status IS NULL THEN %s ELSE label_lifecycle_status END,
                        evidence_fields = CASE WHEN evidence_fields IS NULL THEN %s ELSE evidence_fields END,
                        label_reason = %s,
                        label_batch_id = %s
                    WHERE id = %s
                      AND (
                          event_class IS NULL
                          OR behavior_label IS NULL
                          OR attack_family IS NULL
                          OR technique_label IS NULL
                          OR source_trust IS NULL
                          OR learnable IS NULL
                          OR model_usage_scope IS NULL
                          OR label_lifecycle_status IS NULL
                          OR evidence_fields IS NULL
                      )
                    """,
                    (
                        proposed.get("event_class", None),
                        proposed.get("behavior_label", None),
                        proposed.get("attack_family", None),
                        proposed.get("technique_label", None),
                        proposed.get("source_trust", None),
                        proposed.get("learnable", None),
                        proposed.get("model_usage_scope", None),
                        proposed.get("label_lifecycle_status", None),
                        evidence_json,
                        candidate["proposed_label_reason"],
                        batch_id,
                        candidate["id"],
                    ),
                )
                updated += cur.rowcount
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        db._release(conn)


def _batch_already_applied(db: PostgresDatabase, batch_id: str) -> bool:
    rows = db.query(
        "SELECT COUNT(*) AS count FROM labels WHERE label_batch_id = %s",
        (batch_id,),
    )
    count = int((rows[0] or {}).get("count", 0) or 0) if rows else 0
    return count > 0


def run_audit(database_url: str, distro: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    db = PostgresDatabase(url=database_url)
    engine = LabelEngine(distro_family=distro, db=db)
    engine.initialize()

    totals = Counter()
    by_source = defaultdict(Counter)

    for source_name, record in _iter_all_records(engine):
        totals["total"] += 1
        by_source[source_name]["total"] += 1

        proposed = _proposed_backfill(record, source_name)
        bucket = _coverage_bucket(proposed)
        totals[bucket] += 1
        by_source[source_name][bucket] += 1

    db_rows = _load_db_rows(db, distro)
    apply_candidates = _build_apply_candidates(db_rows)
    proposed_batch_id = _build_batch_id(distro, apply_candidates)
    return {
        "distro_family": distro,
        "proposed_label_batch_id": proposed_batch_id,
        "totals": {
            "total_labels": totals["total"],
            "eligible_attack": totals["eligible_attack"],
            "eligible_normal": totals["eligible_normal"],
            "shadow_only": totals["shadow_only"],
            "unknown_unlabeled": totals["unknown_unlabeled"],
            "missing_unsafe": totals["missing_unsafe"],
        },
        "by_source": {
            source: {
                "total": counts["total"],
                "eligible_attack": counts["eligible_attack"],
                "eligible_normal": counts["eligible_normal"],
                "shadow_only": counts["shadow_only"],
                "unknown_unlabeled": counts["unknown_unlabeled"],
                "missing_unsafe": counts["missing_unsafe"],
            }
            for source, counts in sorted(by_source.items())
        },
        "apply_plan": {
            "db_rows_scanned": len(db_rows),
            "db_rows_updateable": len(apply_candidates),
            "apply_requires_flags": ["--apply", f"--confirm-label-batch-id {proposed_batch_id}"],
            "artifact_dir": str(_artifact_dir(proposed_batch_id)),
        },
    }, apply_candidates


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manual maintenance audit for legacy ML label canonical backfill planning."
    )
    parser.add_argument("--database-url", default="", help="Override PostgreSQL URL.")
    parser.add_argument("--distro", default="debian", help="Distro family for synthetic/bootstrap context.")
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the reviewed maintenance backfill plan to DB; never runs automatically in product runtime.",
    )
    parser.add_argument(
        "--confirm-label-batch-id",
        default="",
        help="Required with --apply. Must exactly match the proposed dry-run label_batch_id.",
    )
    args = parser.parse_args()

    database_url = _resolve_database_url(args.database_url)
    if not database_url:
        print("DATABASE_URL bulunamadı. --database-url veya env/config gerekli.", file=sys.stderr)
        return 2

    report, apply_candidates = run_audit(database_url=database_url, distro=args.distro.lower())

    if args.apply and not args.confirm_label_batch_id.strip():
        print("--apply için ayrıca --confirm-label-batch-id zorunlu.", file=sys.stderr)
        return 2
    if args.apply and args.confirm_label_batch_id.strip() != report["proposed_label_batch_id"]:
        print(
            "Confirm label_batch_id mevcut dry-run planıyla eşleşmiyor. "
            f"Beklenen: {report['proposed_label_batch_id']}",
            file=sys.stderr,
        )
        return 2

    if args.apply:
        db = PostgresDatabase(url=database_url)
        if _batch_already_applied(db, report["proposed_label_batch_id"]):
            print(
                f"label_batch_id zaten uygulanmış: {report['proposed_label_batch_id']}",
                file=sys.stderr,
            )
            return 2
        artifact_paths = _write_snapshot_and_rollback(report, apply_candidates)
        updated_rows = _apply_backfill(db, report["proposed_label_batch_id"], apply_candidates)
        report["apply_result"] = {
            "mode": "apply",
            "updated_rows": updated_rows,
            **artifact_paths,
        }

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    print(f"Legacy canonical backfill dry-run audit ({report['distro_family']})")
    print(f"Proposed label_batch_id: {report['proposed_label_batch_id']}")
    totals = report["totals"]
    print(
        "Coverage: "
        f"total={totals['total_labels']} "
        f"eligible_attack={totals['eligible_attack']} "
        f"eligible_normal={totals['eligible_normal']} "
        f"shadow_only={totals['shadow_only']} "
        f"unknown_unlabeled={totals['unknown_unlabeled']} "
        f"missing_unsafe={totals['missing_unsafe']}"
    )
    print(
        "Apply plan: "
        f"db_rows_scanned={report['apply_plan']['db_rows_scanned']} "
        f"db_rows_updateable={report['apply_plan']['db_rows_updateable']} "
        f"confirm=\"{report['proposed_label_batch_id']}\""
    )
    print("By source:")
    for source, counts in report["by_source"].items():
        print(
            f"  {source}: total={counts['total']} "
            f"eligible_attack={counts['eligible_attack']} "
            f"eligible_normal={counts['eligible_normal']} "
            f"shadow_only={counts['shadow_only']} "
            f"unknown_unlabeled={counts['unknown_unlabeled']} "
            f"missing_unsafe={counts['missing_unsafe']}"
        )
    if args.apply:
        print(f"Apply result: updated_rows={report['apply_result']['updated_rows']}")
        print(f"Snapshot: {report['apply_result']['snapshot_path']}")
        print(f"Rollback report: {report['apply_result']['rollback_report_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
