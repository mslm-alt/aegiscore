from __future__ import annotations

import json
from typing import Callable

from core.database import Database, create_database, get_pending_schema_versions, get_schema_manifest
from core.phase_manager import PhaseManager


def _with_database(config: dict, error_prefix: str, action: Callable[[Database], int], *, ensure_database) -> int:
    try:
        db = ensure_database(config)
    except RuntimeError as exc:
        print(f"{error_prefix}: {exc}")
        return 1
    try:
        return action(db)
    finally:
        db.close()


def _open_optional_database(config: dict, *, create_database_func=create_database):
    try:
        db = create_database_func(config)
        if db is None:
            return None, "database_url_missing"
        health = db.health_check()
        if not health.get("ok", True):
            db.close()
            status = health.get("status", "unhealthy")
            detail = health.get("detail") or health.get("error") or ""
            return None, f"{status}: {detail}".strip(": ")
        return db, ""
    except Exception as exc:
        return None, str(exc)


def build_operator_phase_manager(config: dict, *, bind_label_training_phase_gate, create_database_func=create_database):
    db, db_error = _open_optional_database(config, create_database_func=create_database_func)
    pm = PhaseManager(
        config=config,
        state_dir="data",
        announce_startup=False,
        db=db,
    )
    bind_label_training_phase_gate(pm, config, db)
    return pm, db, db_error


def run_db_doctor(config: dict, *, ensure_database) -> int:
    def _run(db: Database) -> int:
        health = db.health_check()
        print(json.dumps(health, indent=2, ensure_ascii=False))
        return 0 if health.get("ok") else 1

    return _with_database(config, "DB doctor başarısız", _run, ensure_database=ensure_database)


def run_db_version(config: dict, *, ensure_database) -> int:
    def _run(db: Database) -> int:
        health = db.health_check()
        data = {
            "database_version": health.get("schema_version", 0),
            "expected_version": health.get("expected_version", 0),
            "manifest": get_schema_manifest(),
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    return _with_database(config, "DB version alınamadı", _run, ensure_database=ensure_database)


def run_db_pending(config: dict, *, ensure_database) -> int:
    def _run(db: Database) -> int:
        health = db.health_check()
        pending = get_pending_schema_versions(int(health.get("schema_version", 0)))
        print(json.dumps({
            "schema_version": health.get("schema_version", 0),
            "pending_versions": pending,
        }, indent=2, ensure_ascii=False))
        return 0 if not pending else 2

    return _with_database(config, "DB pending alınamadı", _run, ensure_database=ensure_database)
