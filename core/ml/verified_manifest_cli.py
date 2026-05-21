from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from core.database import create_database
from core.ml.verified_manifest import ALLOWED_FAMILIES, build_verified_label_manifest


def parse_family_filters(values: Sequence[str] | str | None) -> Tuple[str, ...]:
    if values is None:
        return tuple(ALLOWED_FAMILIES)
    tokens: List[str] = []
    if isinstance(values, str):
        values = [values]
    for item in values:
        for part in str(item or "").split(","):
            name = part.strip().upper()
            if not name:
                continue
            if name not in ALLOWED_FAMILIES:
                raise ValueError(f"unsupported family: {name}")
            if name not in tokens:
                tokens.append(name)
    return tuple(tokens or ALLOWED_FAMILIES)


def collect_live_verified_manifest(
    db: Any,
    *,
    families: Sequence[str] | str | None = None,
    limit: int = 5000,
    manifest_id: str = "",
    created_at: str = "",
) -> Dict[str, Any]:
    target_families = parse_family_filters(families)
    event_columns = _load_table_columns(db, "events_recent")
    alert_columns = _load_table_columns(db, "alerts")
    events = _load_event_rows(db, event_columns, limit)
    alerts = _load_alert_rows(db, alert_columns, limit)
    manifest = build_verified_label_manifest(
        events,
        alerts,
        manifest_id=manifest_id,
        created_at=created_at,
        families=target_families,
    )
    manifest["input_snapshots"]["events_recent_columns"] = sorted(event_columns)
    manifest["input_snapshots"]["alerts_columns"] = sorted(alert_columns)
    manifest["input_snapshots"]["requested_limit"] = int(limit)
    manifest["input_snapshots"]["db_write_attempted"] = False
    manifest["input_snapshots"]["active_ml_enabled"] = False
    manifest["input_snapshots"]["train_triggered"] = False
    manifest["input_snapshots"]["evaluate_triggered"] = False
    manifest["input_snapshots"]["alert_emit_triggered"] = False
    manifest["input_snapshots"]["direct_learning_only"] = True
    return manifest


def run_verified_manifest_dry_run(
    config: Dict[str, Any],
    *,
    families: Sequence[str] | str | None = None,
    limit: int = 5000,
    out_path: str = "",
    printer=print,
) -> int:
    db = create_database(config)
    if db is None:
        raise RuntimeError("PostgreSQL URL gerekli (DATABASE_URL veya config)")
    try:
        manifest = collect_live_verified_manifest(db, families=families, limit=limit)
    finally:
        if hasattr(db, "close"):
            db.close()
    if out_path:
        write_manifest_output(manifest, out_path)
    print_verified_manifest_summary(manifest, printer=printer)
    return 0


def write_manifest_output(manifest: Dict[str, Any], out_path: str) -> Path:
    resolved = _resolve_safe_output_path(out_path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return resolved


def print_verified_manifest_summary(manifest: Dict[str, Any], *, printer=print) -> None:
    printer("")
    printer("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    printer("  Verified Label Manifest Dry Run")
    printer("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    printer(f"  manifest_id={manifest.get('manifest_id', '')}")
    printer(f"  target_families={manifest.get('target_families', [])}")
    printer(f"  candidate_count={manifest.get('candidate_count', 0)}")
    printer(f"  direct_learnable_count={manifest.get('direct_learnable_count', 0)}")
    printer(f"  rejected_candidate_count={manifest.get('rejected_candidate_count', 0)}")
    printer(f"  ignored_candidate_count={manifest.get('ignored_candidate_count', 0)}")
    printer(f"  readiness_decision={manifest.get('readiness_decision', '')}")
    printer(f"  family_summary={manifest.get('family_summary', {})}")
    printer(f"  rejection_summary={manifest.get('rejection_summary', {})}")
    printer(f"  dominance_summary={manifest.get('dominance_summary', {})}")
    printer("  safety:")
    printer("    no_action_contract=true")
    printer("    active_training_enabled=false")
    printer("    db_write_attempted=false")
    printer("    active_ml_enabled=false")
    printer("    train_triggered=false")
    printer("    evaluate_triggered=false")
    printer("    alert_emit_triggered=false")
    printer("    direct_learning_only=true")
    printer("  NO DB WRITE / NO ACTIVE ML / DRY RUN ONLY")
    printer("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


def _resolve_safe_output_path(out_path: str) -> Path:
    token = str(out_path or "").strip()
    if not token:
        raise ValueError("empty output path")
    cwd = Path.cwd().resolve()
    candidate = Path(token)
    resolved = (cwd / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    if cwd not in resolved.parents and resolved != cwd:
        raise ValueError("output path must stay within workspace")
    return resolved


def _load_table_columns(db: Any, table_name: str) -> set[str]:
    sql = """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        ORDER BY ordinal_position
    """
    rows = db._execute(sql, (table_name,), fetch="all") or []
    return {str(row.get("column_name", "") or "").strip().lower() for row in rows if str(row.get("column_name", "") or "").strip()}


def _load_event_rows(db: Any, columns: set[str], limit: int) -> List[Dict[str, Any]]:
    wanted = [
        ("id", "id"),
        ("ts", "ts"),
        ("source", "source"),
        ("category", "category"),
        ("action", "action"),
        ("outcome", "outcome"),
        ("username", "username"),
        ("process", "process"),
        ("host", "host"),
        ("src_ip", "src_ip"),
        ("message", "message"),
        ("raw_log", "raw_log"),
        ("risk_bucket", "risk_bucket"),
        ("distro_family", "distro_family"),
        ("incident_id", "incident_id"),
    ]
    sql = f"""
        SELECT {", ".join(_select_expr(name, alias, columns) for name, alias in wanted)}
        FROM events_recent
        ORDER BY ts DESC
        LIMIT %s
    """
    return db._execute(sql, (int(limit),), fetch="all") or []


def _load_alert_rows(db: Any, columns: set[str], limit: int) -> List[Dict[str, Any]]:
    wanted = [
        ("id", "id"),
        ("ts", "ts"),
        ("rule_id", "rule_id"),
        ("severity", "severity"),
        ("entity", "entity"),
        ("message", "message"),
        ("incident_id", "incident_id"),
        ("context_json", "context_json"),
        ("host", "host"),
        ("category", "category"),
    ]
    sql = f"""
        SELECT {", ".join(_select_expr(name, alias, columns) for name, alias in wanted)}
        FROM alerts
        ORDER BY ts DESC
        LIMIT %s
    """
    return db._execute(sql, (int(limit),), fetch="all") or []


def _select_expr(name: str, alias: str, columns: set[str]) -> str:
    if name in columns:
        return f"{name} AS {alias}"
    if alias == "context_json":
        return f"'{{}}'::jsonb AS {alias}"
    if alias in {"id", "ts"}:
        return f"NULL AS {alias}"
    return f"''::text AS {alias}"
