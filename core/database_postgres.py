from __future__ import annotations
"""
core/database_postgres.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PostgreSQL Backend

Usage:
  DATABASE_URL=postgresql://user:pass@localhost:5432/linuxsiem

Requirement:
  pip install psycopg2-binary

Features:
  - Connection pooling (ThreadedConnectionPool)
  - Transaction management
  - JSONB support
  - Concurrent-write safe
"""

import os
import time
import json
import logging
import threading
from core.database import _normalize_alert_row
from typing import Dict, List, Optional, Any

from .database import (
    Database,
    CURRENT_VERSION,
    MIGRATIONS,
    get_schema_manifest,
    get_pending_schema_versions,
)

logger = logging.getLogger(__name__)

PG_POOL_MIN_DEFAULT = 2
PG_POOL_MAX_DEFAULT = 10

_INCIDENT_UPDATE_ASSIGNMENTS = {
    "ts_start": "ts_start=%s",
    "ts_end": "ts_end=%s",
    "host": "host=%s",
    "title": "title=%s",
    "severity": "severity=%s",
    "risk_score": "risk_score=%s",
    "status": "status=%s",
    "alert_count": "alert_count=%s",
    "entity_key": "entity_key=%s",
    "category": "category=%s",
    "reopen_count": "reopen_count=%s",
    "evidence": "evidence=%s",
    "tags": "tags=%s",
    "summary": "summary=%s",
}
_ANALYZE_TABLES = ("alerts", "alerts_archive", "events_recent", "risk_history", "sequence_state", "cross_host_state")
_FACTORY_RESET_TABLES = (
    "ip_block_actions",
    "ip_block_suggestions",
    "labels",
    "events_recent",
    "alerts_archive",
    "alerts",
    "incidents",
    "entity_state",
    "cooldowns",
    "dedup_cache",
    "sequence_state",
    "process_tree",
    "risk_history",
    "cross_host_state",
    "ml_control_log",
    "phase_history",
    "system_stats",
    "system_config",
    "model_registry",
)

CRITICAL_SCHEMA_TABLES = (
    "schema_version",
    "alerts",
    "alerts_archive",
    "incidents",
    "entity_state",
    "cooldowns",
    "dedup_cache",
    "model_registry",
    "risk_history",
    "system_stats",
    "sequence_state",
    "process_tree",
    "events_recent",
    "phase_history",
    "cross_host_state",
    "ml_control_log",
    "system_config",
    "labels",
    "ip_block_suggestions",
    "ip_block_actions",
)

try:
    import psycopg2
    import psycopg2.pool
    import psycopg2.extras
    import psycopg2.sql as psycopg2_sql
    HAS_PSYCOPG2 = True
except ImportError:
    psycopg2 = None
    psycopg2_sql = None
    HAS_PSYCOPG2 = False


# PostgreSQL schema
PG_INIT_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at DOUBLE PRECISION NOT NULL
);

-- Active alerts
CREATE TABLE IF NOT EXISTS alerts (
    id               SERIAL PRIMARY KEY,
    ts               DOUBLE PRECISION NOT NULL,
    host             TEXT NOT NULL DEFAULT '',
    rule_id          TEXT NOT NULL,
    rule_file        TEXT DEFAULT '',
    severity         TEXT NOT NULL,
    risk_score       DOUBLE PRECISION NOT NULL DEFAULT 0,
    category         TEXT DEFAULT '',
    message          TEXT NOT NULL,
    entity           TEXT DEFAULT '',
    detection_layer  TEXT DEFAULT 'rule',
    raw_score        DOUBLE PRECISION DEFAULT 0,
    cal_score        DOUBLE PRECISION DEFAULT 0,
    phase            INTEGER DEFAULT 0,
    incident_id      INTEGER DEFAULT NULL,
    mitre_tactic     TEXT DEFAULT '',
    mitre_technique  TEXT DEFAULT '',
    tags             TEXT DEFAULT '',
    context_json     JSONB DEFAULT '{}',
    created_at       DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
);

-- Archived alerts (moved here after retention, not deleted)
CREATE TABLE IF NOT EXISTS alerts_archive (
    LIKE alerts INCLUDING ALL
);
CREATE INDEX IF NOT EXISTS idx_alerts_archive_ts     ON alerts_archive(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_archive_rule   ON alerts_archive(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_archive_entity ON alerts_archive(entity);

CREATE TABLE IF NOT EXISTS incidents (
    id           SERIAL PRIMARY KEY,
    ts_start     DOUBLE PRECISION NOT NULL,
    ts_end       DOUBLE PRECISION DEFAULT NULL,
    host         TEXT NOT NULL DEFAULT '',
    title        TEXT NOT NULL,
    severity     TEXT NOT NULL,
    risk_score   DOUBLE PRECISION NOT NULL DEFAULT 0,
    status       TEXT DEFAULT 'open',
    alert_count  INTEGER DEFAULT 0,
    entity_key   TEXT DEFAULT '',
    category     TEXT DEFAULT '',
    reopen_count INTEGER DEFAULT 0,
    evidence     JSONB DEFAULT '[]',
    tags         JSONB DEFAULT '[]',
    summary      TEXT DEFAULT '',
    created_at   DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
);

CREATE TABLE IF NOT EXISTS entity_state (
    id          SERIAL PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_key  TEXT NOT NULL,
    first_seen  DOUBLE PRECISION NOT NULL,
    last_seen   DOUBLE PRECISION NOT NULL,
    count       INTEGER DEFAULT 1,
    metadata    JSONB DEFAULT '{}',
    UNIQUE(entity_type, entity_key)
);

CREATE TABLE IF NOT EXISTS cooldowns (
    id          SERIAL PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    entity_key  TEXT NOT NULL DEFAULT '',
    expires_at  DOUBLE PRECISION NOT NULL,
    UNIQUE(rule_id, entity_key)
);

CREATE TABLE IF NOT EXISTS dedup_cache (
    hash        TEXT PRIMARY KEY,
    first_seen  DOUBLE PRECISION NOT NULL,
    count       INTEGER DEFAULT 1,
    last_seen   DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS model_registry (
    id          SERIAL PRIMARY KEY,
    model_name  TEXT NOT NULL,
    host        TEXT NOT NULL DEFAULT 'global',
    version     INTEGER DEFAULT 1,
    trained_at  DOUBLE PRECISION NOT NULL,
    samples     INTEGER DEFAULT 0,
    path        TEXT NOT NULL,
    metrics     JSONB DEFAULT '{}',
    active      INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS risk_history (
    id          SERIAL PRIMARY KEY,
    ts          DOUBLE PRECISION NOT NULL,
    entity_key  TEXT NOT NULL,
    score       DOUBLE PRECISION NOT NULL,
    components  JSONB DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS system_stats (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
);

CREATE TABLE IF NOT EXISTS sequence_state (
    entity  TEXT NOT NULL,
    seq_id  TEXT NOT NULL,
    step    INTEGER NOT NULL DEFAULT 0,
    last_ts DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (entity, seq_id)
);

CREATE TABLE IF NOT EXISTS process_tree (
    parent     TEXT NOT NULL,
    child      TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 1,
    first_seen DOUBLE PRECISION NOT NULL,
    last_seen  DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (parent, child)
);

CREATE TABLE IF NOT EXISTS events_recent (
    id            SERIAL PRIMARY KEY,
    ts            DOUBLE PRECISION NOT NULL,
    host          TEXT DEFAULT '',
    source        TEXT DEFAULT '',
    category      TEXT DEFAULT '',
    action        TEXT DEFAULT '',
    outcome       TEXT DEFAULT '',
    username      TEXT DEFAULT '',
    src_ip        TEXT DEFAULT '',
    process       TEXT DEFAULT '',
    message       TEXT DEFAULT '',
    phase         INTEGER DEFAULT 0,
    trainable     INTEGER DEFAULT 1,
    dst_port      INTEGER DEFAULT 0,
    risk_bucket   TEXT DEFAULT 'normal',
    distro_family TEXT DEFAULT 'unknown',
    raw_log       TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS phase_history (
    id     SERIAL PRIMARY KEY,
    ts     DOUBLE PRECISION NOT NULL,
    phase  INTEGER NOT NULL,
    reason TEXT DEFAULT '',
    stats  JSONB DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS cross_host_state (
    src_ip   TEXT    NOT NULL,
    host     TEXT    NOT NULL,
    last_ts  DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (src_ip, host)
);
CREATE INDEX IF NOT EXISTS idx_cross_host_ip ON cross_host_state(src_ip);
CREATE INDEX IF NOT EXISTS idx_cross_host_ts ON cross_host_state(last_ts);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_alerts_ts        ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_host      ON alerts(host);
CREATE INDEX IF NOT EXISTS idx_alerts_rule      ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_entity    ON alerts(entity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_entity ON incidents(entity_key);
CREATE INDEX IF NOT EXISTS idx_entity_key       ON entity_state(entity_type, entity_key);
CREATE INDEX IF NOT EXISTS idx_cooldowns_expire ON cooldowns(expires_at);
CREATE INDEX IF NOT EXISTS idx_risk_entity      ON risk_history(entity_key);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events_recent(ts);
-- Composite indexes for get_rule_stats and retention queries
CREATE INDEX IF NOT EXISTS idx_alerts_rule_ts   ON alerts(rule_id, ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ts_sev    ON alerts(ts, severity);
CREATE INDEX IF NOT EXISTS idx_incidents_ts     ON incidents(status, ts_start);
CREATE INDEX IF NOT EXISTS idx_events_ts_src    ON events_recent(ts, source);
CREATE INDEX IF NOT EXISTS idx_risk_entity_ts   ON risk_history(entity_key, ts);

CREATE TABLE IF NOT EXISTS ml_control_log (
    id      SERIAL PRIMARY KEY,
    ts      DOUBLE PRECISION NOT NULL,
    action  TEXT NOT NULL,
    reason  TEXT DEFAULT '',
    actor   TEXT DEFAULT 'auto',
    source  TEXT DEFAULT '',
    notes   TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ml_control_ts ON ml_control_log(ts);

CREATE TABLE IF NOT EXISTS system_config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_ts DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM NOW())
);

-- Label table (bootstrap / auto_labeled / manually_verified)
-- synthetic labels are loaded from file and never written to the DB
CREATE TABLE IF NOT EXISTS labels (
    id          BIGSERIAL PRIMARY KEY,
    source      TEXT NOT NULL,          -- bootstrap | auto_labeled | manually_verified
    label       TEXT NOT NULL,          -- attack | normal
    category    TEXT NOT NULL,
    score       DOUBLE PRECISION NOT NULL,
    confidence  DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    weight      DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    entity_key  TEXT DEFAULT '',
    distro      TEXT DEFAULT '',
    ts          DOUBLE PRECISION NOT NULL,
    ready_after DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    event_class TEXT DEFAULT NULL,
    behavior_label TEXT DEFAULT NULL,
    attack_family TEXT DEFAULT NULL,
    technique_label TEXT DEFAULT NULL,
    source_trust TEXT DEFAULT NULL,
    learnable BOOLEAN DEFAULT NULL,
    model_usage_scope TEXT DEFAULT NULL,
    label_lifecycle_status TEXT DEFAULT NULL,
    poisoning_guard_passed BOOLEAN DEFAULT NULL,
    label_reason TEXT DEFAULT NULL,
    evidence_fields JSONB DEFAULT NULL,
    review_flags JSONB DEFAULT NULL,
    bootstrap_job_id TEXT DEFAULT NULL,
    label_batch_id TEXT DEFAULT NULL,
    correlation_id TEXT DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_labels_source ON labels(source);
CREATE INDEX IF NOT EXISTS idx_labels_ts     ON labels(ts);
CREATE INDEX IF NOT EXISTS idx_labels_label  ON labels(label);
CREATE UNIQUE INDEX IF NOT EXISTS idx_labels_exact_unique
ON labels(source, label, category, score, confidence, weight, entity_key, distro, ts, ready_after);

CREATE TABLE IF NOT EXISTS ip_block_suggestions (
    id              SERIAL PRIMARY KEY,
    ip              TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',   -- example: "brute_force", "abuseipdb_hit"
    source          TEXT NOT NULL DEFAULT '',   -- "alert" | "abuseipdb" | "manual"
    alert_id        INTEGER,                    -- ilgili alert (varsa)
    abuse_score     INTEGER DEFAULT NULL,       -- AbuseIPDB confidence score (0-100)
    abuse_reports   INTEGER DEFAULT NULL,       -- AbuseIPDB total report count
    abuse_country   TEXT DEFAULT '',
    abuse_raw       JSONB,                      -- raw AbuseIPDB response
    suggested_at    DOUBLE PRECISION NOT NULL,
    reviewed        BOOLEAN NOT NULL DEFAULT FALSE,
    reviewed_at     DOUBLE PRECISION DEFAULT NULL,
    action          TEXT DEFAULT NULL           -- "blocked" | "ignored" | NULL (bekliyor)
);
CREATE INDEX IF NOT EXISTS idx_ipblock_ip          ON ip_block_suggestions(ip);
CREATE INDEX IF NOT EXISTS idx_ipblock_reviewed    ON ip_block_suggestions(reviewed);
CREATE INDEX IF NOT EXISTS idx_ipblock_suggested   ON ip_block_suggestions(suggested_at DESC);

CREATE TABLE IF NOT EXISTS ip_block_actions (
    id                SERIAL PRIMARY KEY,
    ip                TEXT NOT NULL,
    action            TEXT NOT NULL,              -- "block" | "unblock"
    status            TEXT NOT NULL,              -- "dry_run" | "applied" | "failed" | "refused"
    backend           TEXT DEFAULT '',
    backend_rule_ref  TEXT DEFAULT '',
    reason            TEXT DEFAULT '',
    guard_reason      TEXT DEFAULT '',
    error             TEXT DEFAULT '',
    dry_run           BOOLEAN NOT NULL DEFAULT FALSE,
    executed_at       DOUBLE PRECISION NOT NULL,
    executed_by       TEXT DEFAULT 'terminal',
    suggestion_id     INTEGER DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_ipblock_actions_ip      ON ip_block_actions(ip);
CREATE INDEX IF NOT EXISTS idx_ipblock_actions_ts      ON ip_block_actions(executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ipblock_actions_status  ON ip_block_actions(status);
CREATE INDEX IF NOT EXISTS idx_ipblock_actions_action  ON ip_block_actions(action);

CREATE TABLE IF NOT EXISTS user_actions (
    id          BIGINT PRIMARY KEY,
    ts          DOUBLE PRECISION NOT NULL,
    action      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'ok',
    actor       TEXT DEFAULT 'terminal',
    screen      TEXT DEFAULT '',
    entity_type TEXT DEFAULT '',
    entity_id   TEXT DEFAULT '',
    target      TEXT DEFAULT '',
    summary     TEXT DEFAULT '',
    details     JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_user_actions_ts     ON user_actions(ts DESC);
CREATE INDEX IF NOT EXISTS idx_user_actions_action ON user_actions(action);
CREATE INDEX IF NOT EXISTS idx_user_actions_target ON user_actions(target);
"""


class PostgresDatabase(Database):
    """
    PostgreSQL backend.
    Connection pool ile thread-safe, concurrent write destekli.
    """

    def __init__(self, url: str = None):
        self._require_psycopg2()

        self.url = url or os.environ.get("DATABASE_URL", "")
        if not self.url:
            raise ValueError("PostgreSQL URL gerekli (DATABASE_URL veya config)")

        pool_min, pool_max = self._resolve_pool_limits()

        # Connection pool: preserve the current 2/10 default, overridable via env
        self._pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=pool_min, maxconn=pool_max, dsn=self.url
        )
        self._run_migrations()

        # Batch insert buffer for insert_event (high-frequency path)
        self._event_batch: List[tuple] = []
        self._event_batch_lock  = threading.Lock()
        self._event_batch_size  = 50    # flush after every 50 buffered events
        self._event_batch_last  = time.time()
        self._event_batch_max_age = 2.0  # wait at most 2 seconds

        logger.info(f"[DB] PostgreSQL hazır: {self.url.split('@')[-1]}")

    def flush(self) -> None:
        """Flush the pending event batch through the public API."""
        self._flush_event_batch()

    def commit(self) -> None:
        """Map database-like commit calls to an event-batch flush."""
        self.flush()

    @staticmethod
    def _resolve_pool_limits() -> tuple[int, int]:
        """Read pool limits from env config and fall back safely on invalid values."""

        def _read_int(name: str, default: int) -> int:
            raw = os.environ.get(name, "").strip()
            if not raw:
                return default
            try:
                value = int(raw)
            except ValueError:
                logger.warning(f"[DB/PG] Geçersiz {name}={raw!r}; fallback={default}")
                return default
            if value < 1:
                logger.warning(f"[DB/PG] Geçersiz {name}={raw!r}; fallback={default}")
                return default
            return value

        pool_min = _read_int("AEGISCORE_PG_POOL_MIN", PG_POOL_MIN_DEFAULT)
        pool_max = _read_int("AEGISCORE_PG_POOL_MAX", PG_POOL_MAX_DEFAULT)
        if pool_min > pool_max:
            logger.warning(
                f"[DB/PG] Pool limitleri ters sırada: min={pool_min} max={pool_max}; "
                f"fallback={PG_POOL_MIN_DEFAULT}/{PG_POOL_MAX_DEFAULT}"
            )
            return PG_POOL_MIN_DEFAULT, PG_POOL_MAX_DEFAULT
        return pool_min, pool_max

    def _conn(self):
        return self._pool.getconn()

    @staticmethod
    def _require_psycopg2():
        if not HAS_PSYCOPG2 or psycopg2 is None:
            raise ImportError("psycopg2-binary gerekli: pip install psycopg2-binary")

    def _release(self, conn):
        self._require_psycopg2()
        # Clear broken transaction state before returning the connection to the pool
        try:
            if conn.status != psycopg2.extensions.STATUS_READY:
                conn.rollback()
        except psycopg2.Error as _e:
            logger.debug(f"[DB/PG] _release rollback atlandı: {_e}")
        self._pool.putconn(conn)

    def _execute(self, sql: str, params: tuple = (), fetch: str = None):
        self._require_psycopg2()
        conn = self._conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, params)
                conn.commit()
                if fetch == "one":
                    return cur.fetchone()
                elif fetch == "all":
                    return cur.fetchall()
                return cur.rowcount
        except Exception as e:
            conn.rollback()
            logger.error(f"[DB/PG] Sorgu hatası: {e}")
            raise
        finally:
            self._release(conn)

    def _identifier_statement(self, template: str, identifier: str, *, allowed: tuple[str, ...] | list[str] | set[str]):
        self._require_psycopg2()
        token = str(identifier or "").strip()
        if token not in set(allowed):
            raise ValueError(f"unsafe_sql_identifier:{token}")
        if psycopg2_sql is None:
            raise ImportError("psycopg2-binary gerekli: pip install psycopg2-binary")
        return psycopg2_sql.SQL(template).format(psycopg2_sql.Identifier(token))

    @staticmethod
    def _iter_init_statements() -> List[str]:
        statements: List[str] = []
        for statement in PG_INIT_SQL.split(";"):
            stmt = statement.strip()
            if stmt:
                statements.append(stmt)
        return statements

    def _get_missing_schema_tables(self, cur) -> List[str]:
        missing = []
        for table in CRITICAL_SCHEMA_TABLES:
            cur.execute("SELECT to_regclass(%s)", (f"public.{table}",))
            row = cur.fetchone()
            table_name = row[0] if row else None
            if not table_name:
                missing.append(table)
        return missing

    def _ensure_user_actions_schema(self) -> None:
        """Ensure the user_actions audit table without SERIAL side effects.

        If the table already exists in a live DB, create sequence/default/index pieces
        conditionally and safely to avoid sequence/catalog conflicts seen on the
        CREATE TABLE IF NOT EXISTS + BIGSERIAL path.
        """
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS user_actions (
                        id          BIGINT PRIMARY KEY,
                        ts          DOUBLE PRECISION NOT NULL,
                        action      TEXT NOT NULL,
                        status      TEXT NOT NULL DEFAULT 'ok',
                        actor       TEXT DEFAULT 'terminal',
                        screen      TEXT DEFAULT '',
                        entity_type TEXT DEFAULT '',
                        entity_id   TEXT DEFAULT '',
                        target      TEXT DEFAULT '',
                        summary     TEXT DEFAULT '',
                        details     JSONB DEFAULT '{}'
                    )
                """)
                cur.execute("SELECT to_regclass('public.user_actions_id_seq')")
                seq_row = cur.fetchone()
                has_sequence = bool(seq_row and seq_row[0])
                if not has_sequence:
                    cur.execute("CREATE SEQUENCE IF NOT EXISTS user_actions_id_seq")

                cur.execute("""
                    ALTER TABLE user_actions
                    ALTER COLUMN actor SET DEFAULT 'terminal'
                """)

                cur.execute("""
                    SELECT column_default
                    FROM information_schema.columns
                    WHERE table_schema='public' AND table_name='user_actions' AND column_name='id'
                """)
                default_row = cur.fetchone()
                default_expr = default_row[0] if default_row else ""
                if "nextval('user_actions_id_seq" not in (default_expr or ""):
                    cur.execute("""
                        ALTER TABLE user_actions
                        ALTER COLUMN id SET DEFAULT nextval('user_actions_id_seq'::regclass)
                    """)
                cur.execute("ALTER SEQUENCE user_actions_id_seq OWNED BY user_actions.id")
                cur.execute("""
                    SELECT COALESCE(MAX(id), 0) FROM user_actions
                """)
                max_id_row = cur.fetchone()
                max_id = max_id_row[0] if max_id_row and max_id_row[0] is not None else 0
                cur.execute(
                    "SELECT setval('user_actions_id_seq', %s, %s)",
                    (max_id if max_id > 0 else 1, max_id > 0),
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_user_actions_ts ON user_actions(ts DESC)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_user_actions_action ON user_actions(action)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_user_actions_target ON user_actions(target)"
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)

    def _ensure_ip_block_actions_schema(self) -> None:
        """Complete the ip_block_actions table idempotently on a live DB."""
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS ip_block_actions (
                        id                SERIAL PRIMARY KEY,
                        ip                TEXT NOT NULL,
                        action            TEXT NOT NULL,
                        status            TEXT NOT NULL,
                        backend           TEXT DEFAULT '',
                        backend_rule_ref  TEXT DEFAULT '',
                        reason            TEXT DEFAULT '',
                        guard_reason      TEXT DEFAULT '',
                        error             TEXT DEFAULT '',
                        dry_run           BOOLEAN NOT NULL DEFAULT FALSE,
                        suggestion_id     INTEGER DEFAULT NULL,
                        executed_at       DOUBLE PRECISION NOT NULL,
                        executed_by       TEXT DEFAULT 'terminal'
                    )
                """)
                for column_sql in (
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS ip TEXT NOT NULL DEFAULT ''",
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'block'",
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'failed'",
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS backend TEXT DEFAULT ''",
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS backend_rule_ref TEXT DEFAULT ''",
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS reason TEXT DEFAULT ''",
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS guard_reason TEXT DEFAULT ''",
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS error TEXT DEFAULT ''",
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS dry_run BOOLEAN NOT NULL DEFAULT FALSE",
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS suggestion_id INTEGER DEFAULT NULL",
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS executed_at DOUBLE PRECISION NOT NULL DEFAULT 0",
                    "ALTER TABLE ip_block_actions ADD COLUMN IF NOT EXISTS executed_by TEXT DEFAULT 'terminal'",
                ):
                    cur.execute(column_sql)
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ipblock_actions_ip ON ip_block_actions(ip)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ipblock_actions_ts ON ip_block_actions(executed_at DESC)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ipblock_actions_status ON ip_block_actions(status)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ipblock_actions_action ON ip_block_actions(action)"
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)

    def _ensure_labels_schema(self) -> None:
        """Add backward-compatible shadow metadata columns to the labels table."""
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS labels (
                        id          BIGSERIAL PRIMARY KEY,
                        source      TEXT NOT NULL,
                        label       TEXT NOT NULL,
                        category    TEXT NOT NULL,
                        score       DOUBLE PRECISION NOT NULL,
                        confidence  DOUBLE PRECISION NOT NULL DEFAULT 1.0,
                        weight      DOUBLE PRECISION NOT NULL DEFAULT 1.0,
                        entity_key  TEXT DEFAULT '',
                        distro      TEXT DEFAULT '',
                        ts          DOUBLE PRECISION NOT NULL,
                        ready_after DOUBLE PRECISION NOT NULL DEFAULT 0.0
                    )
                """)
                for column_sql in (
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS event_class TEXT DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS behavior_label TEXT DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS attack_family TEXT DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS technique_label TEXT DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS source_trust TEXT DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS learnable BOOLEAN DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS model_usage_scope TEXT DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS label_lifecycle_status TEXT DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS poisoning_guard_passed BOOLEAN DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS label_reason TEXT DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS evidence_fields JSONB DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS review_flags JSONB DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS bootstrap_job_id TEXT DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS label_batch_id TEXT DEFAULT NULL",
                    "ALTER TABLE labels ADD COLUMN IF NOT EXISTS correlation_id TEXT DEFAULT NULL",
                ):
                    cur.execute(column_sql)
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_labels_source ON labels(source)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_labels_ts ON labels(ts)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_labels_label ON labels(label)"
                )
                cur.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_labels_exact_unique
                    ON labels(source, label, category, score, confidence, weight, entity_key, distro, ts, ready_after)
                """)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)

    def _run_migrations(self):
        """Create the PostgreSQL schema and mark schema_version.

        PG_INIT_SQL is used as the source. Each CREATE statement runs on a
        separate connection so errors such as "already exists" do not affect
        other statements.
        """
        ddl_failures: List[str] = []

        # Stage 1: run each CREATE/CREATE INDEX statement on its own connection
        for stmt in self._iter_init_statements():
            if "CREATE TABLE IF NOT EXISTS user_actions" in stmt:
                continue
            if "CREATE INDEX IF NOT EXISTS idx_user_actions_" in stmt:
                continue
            conn = self._conn()
            try:
                with conn.cursor() as cur:
                    cur.execute(stmt)
                conn.commit()
                logger.debug(f"[DB/PG] Init OK: {stmt[:60]}")
            except Exception as _se:
                conn.rollback()
                ddl_failures.append(f"{type(_se).__name__}: {_se} | {stmt[:80]}")
                logger.error(f"[DB/PG] Init başarısız: {_se} | {stmt[:80]}")
            finally:
                self._release(conn)

        try:
            self._ensure_user_actions_schema()
            logger.debug("[DB/PG] user_actions audit şeması doğrulandı")
        except Exception as _se:
            ddl_failures.append(f"{type(_se).__name__}: {_se} | ensure_user_actions_schema")
            logger.error(f"[DB/PG] user_actions init başarısız: {_se}")

        try:
            self._ensure_ip_block_actions_schema()
            logger.debug("[DB/PG] ip_block_actions şeması doğrulandı")
        except Exception as _se:
            ddl_failures.append(f"{type(_se).__name__}: {_se} | ensure_ip_block_actions_schema")
            logger.error(f"[DB/PG] ip_block_actions init başarısız: {_se}")

        try:
            self._ensure_labels_schema()
            logger.debug("[DB/PG] labels shadow metadata şeması doğrulandı")
        except Exception as _se:
            ddl_failures.append(f"{type(_se).__name__}: {_se} | ensure_labels_schema")
            logger.error(f"[DB/PG] labels init başarısız: {_se}")

        if ddl_failures:
            raise RuntimeError(
                "[DB/PG] Şema kurulumu tamamlanamadı; schema_version güncellenmedi. "
                + " || ".join(ddl_failures[:3])
            )

        # Stage 2: mark schema_version records
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                missing_tables = self._get_missing_schema_tables(cur)
                if missing_tables:
                    raise RuntimeError(
                        "[DB/PG] Kritik şema tabloları eksik: "
                        + ", ".join(missing_tables)
                    )
                cur.execute("SELECT COALESCE(MAX(version),0) FROM schema_version")
                _row = cur.fetchone()
                current = _row[0] if _row and _row[0] is not None else 0
                if current < CURRENT_VERSION:
                    now = time.time()
                    for ver in range(current + 1, CURRENT_VERSION + 1):
                        cur.execute(
                            "INSERT INTO schema_version (version, applied_at) "                            "VALUES (%s, %s) ON CONFLICT DO NOTHING",
                            (ver, now),
                        )
                    logger.info(f"[DB/PG] Schema {current} → {CURRENT_VERSION} işaretlendi.")
                else:
                    logger.debug(f"[DB/PG] Schema güncel: v{current}")
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"[DB/PG] schema_version hatası: {e}")
            raise
        finally:
            self._release(conn)

    # ── Alert ─────────────────────────────────────────────────────────────────

    def insert_alert(self, alert: Dict) -> Optional[int]:
        tags = alert.get("tags", "")
        if isinstance(tags, list):
            import json as _json
            tags = _json.dumps(tags)
        elif isinstance(tags, str) and not tags.startswith("["):
            import json as _json
            tags = _json.dumps([tags] if tags else [])

        context = alert.get("context_json", alert.get("context", {}))
        if isinstance(context, dict):
            import json as _json
            context = _json.dumps(context)

        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO alerts
                        (ts,host,rule_id,rule_file,severity,risk_score,category,
                         message,entity,detection_layer,raw_score,cal_score,phase,
                         incident_id,mitre_tactic,mitre_technique,tags,context_json)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id
                """, (
                    alert.get("ts", time.time()),
                    alert.get("host", ""),
                    alert.get("rule_id", ""),
                    alert.get("rule_file", ""),
                    alert.get("severity", "low"),
                    alert.get("risk_score", 0),
                    alert.get("category", ""),
                    alert.get("message", ""),
                    alert.get("entity", ""),
                    alert.get("detection_layer", "rule"),
                    alert.get("raw_score", 0),
                    alert.get("cal_score", 0),
                    alert.get("phase", 0),
                    alert.get("incident_id"),
                    alert.get("mitre_tactic", ""),
                    alert.get("mitre_technique", ""),
                    tags,
                    context,
                ))
                row = cur.fetchone()
                conn.commit()
                return row[0] if row else None
        except Exception as e:
            conn.rollback()
            logger.error(f"[DB/PG] insert_alert hatası: {e}")
            return None
        finally:
            self._release(conn)

    def get_recent_alerts(self, limit: int = 100, hours: float = 24) -> List[Dict]:
        cutoff = time.time() - hours * 3600
        rows = self._execute(
            "SELECT * FROM alerts WHERE ts > %s ORDER BY ts DESC LIMIT %s",
            (cutoff, limit), fetch="all"
        )
        return [_normalize_alert_row(dict(r)) for r in (rows or [])]

    def get_alert_by_id(self, alert_id: int) -> Optional[Dict]:
        row = self._execute(
            "SELECT * FROM alerts WHERE id = %s LIMIT 1",
            (int(alert_id),), fetch="one"
        )
        return _normalize_alert_row(dict(row)) if row else None

    def get_alert_count(self, hours: float = 1) -> int:
        cutoff = time.time() - hours * 3600
        row = self._execute(
            "SELECT COUNT(*) FROM alerts WHERE ts > %s", (cutoff,), fetch="one"
        )
        return row["count"] if row else 0

    # ── Incident ──────────────────────────────────────────────────────────────

    def insert_incident(self, incident: Dict) -> Optional[int]:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO incidents
                        (ts_start,ts_end,host,title,severity,risk_score,
                         status,alert_count,entity_key,category,tags,summary)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id
                """, (
                    incident.get("ts_start", time.time()),
                    incident.get("ts_end"),
                    incident.get("host", ""),
                    incident.get("title", ""),
                    incident.get("severity", "medium"),
                    incident.get("risk_score", 0),
                    incident.get("status", "open"),
                    incident.get("alert_count", 0),
                    incident.get("entity_key", ""),
                    incident.get("category", ""),
                    json.dumps(incident.get("tags", [])),
                    incident.get("summary", ""),
                ))
                row = cur.fetchone()
                conn.commit()
                return row[0] if row else None
        except Exception as e:
            conn.rollback()
            logger.error(f"[DB/PG] insert_incident: {e}")
            return None
        finally:
            self._release(conn)

    def update_incident(self, incident_id: int, updates: Dict) -> bool:
        if not updates:
            return False
        allowed = {
            "ts_start", "ts_end", "host", "title", "severity", "risk_score",
            "status", "alert_count", "entity_key", "category", "reopen_count",
            "evidence", "tags", "summary",
        }
        unknown = [k for k in updates if k not in allowed]
        if unknown:
            raise ValueError(f"Bilinmeyen incident alan(lar)i: {', '.join(sorted(unknown))}")
        sets = ", ".join(_INCIDENT_UPDATE_ASSIGNMENTS[key] for key in updates)
        vals = []
        for key, value in updates.items():
            if key in ("evidence", "tags"):
                vals.append(json.dumps(value))
            else:
                vals.append(value)
        vals.append(incident_id)
        try:
            self._execute("UPDATE incidents SET " + sets + " WHERE id=%s", tuple(vals))
            return True
        except psycopg2.Error as e:
            logger.debug(f"[DB/PG] update_incident hatası: {e}")
            return False

    def get_open_incidents(self) -> List[Dict]:
        rows = self._execute(
            "SELECT * FROM incidents WHERE status='open' ORDER BY ts_start DESC LIMIT 100",
            fetch="all"
        )
        return [dict(r) for r in (rows or [])]

    def get_closed_incidents(self, since_hours: int = 24) -> List[Dict]:
        """Return incidents closed within the last N hours (for reopen checks)."""
        cutoff = time.time() - since_hours * 3600
        rows = self._execute(
            "SELECT * FROM incidents WHERE status='closed' AND ts_end > %s "
            "ORDER BY ts_end DESC LIMIT 200",
            (cutoff,), fetch="all"
        )
        return [dict(r) for r in (rows or [])]

    # ── Entity State ──────────────────────────────────────────────────────────

    def is_first_seen(self, entity_type: str, entity_key: str) -> bool:
        if not entity_key:
            return False
        now = time.time()
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                # Atomic flow: try INSERT, fall back to UPDATE on conflict, and inspect
                # whether INSERT returned a row. The old SELECT+INSERT split could
                # race; this now uses a single SQL statement.
                cur.execute(
                    """
                    INSERT INTO entity_state (entity_type, entity_key, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (entity_type, entity_key)
                        DO UPDATE SET last_seen = EXCLUDED.last_seen,
                                      count     = entity_state.count + 1
                    RETURNING (xmax = 0) AS inserted
                    """,
                    (entity_type, entity_key, now, now)
                )
                row = cur.fetchone()
                conn.commit()
                # xmax=0 → new row (INSERT), xmax≠0 → update (UPDATE)
                return bool(row and row[0])
        except Exception as e:
            conn.rollback()
            logger.error(f"[DB/PG] is_first_seen: {e}")
            return False
        finally:
            self._release(conn)

    def mark_seen(self, entity_type: str, entity_key: str) -> None:
        self.is_first_seen(entity_type, entity_key)

    def get_entity_state(self, entity_type: str, entity_key: str) -> Optional[Dict]:
        row = self._execute(
            "SELECT * FROM entity_state WHERE entity_type=%s AND entity_key=%s",
            (entity_type, entity_key), fetch="one"
        )
        return dict(row) if row else None

    def set_entity_state(self, entity_type: str, entity_key: str, metadata: Dict) -> None:
        now = time.time()
        self._execute("""
            INSERT INTO entity_state (entity_type,entity_key,first_seen,last_seen,metadata)
            VALUES (%s,%s,%s,%s,%s)
            ON CONFLICT (entity_type,entity_key)
            DO UPDATE SET last_seen=EXCLUDED.last_seen, metadata=EXCLUDED.metadata
        """, (entity_type, entity_key, now, now, json.dumps(metadata)))

    # ── Cooldown ──────────────────────────────────────────────────────────────

    def is_in_cooldown(self, rule_id: str, entity_key: str = "") -> bool:
        now = time.time()
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM cooldowns WHERE expires_at < %s", (now,))
                cur.execute(
                    "SELECT id FROM cooldowns WHERE rule_id=%s AND entity_key=%s",
                    (rule_id, entity_key)
                )
                row = cur.fetchone()
            conn.commit()
            return row is not None
        except Exception as e:
            conn.rollback()
            logger.error(f"[DB/PG] is_in_cooldown: {e}")
            return False
        finally:
            self._release(conn)

    def set_cooldown(self, rule_id: str, entity_key: str = "", seconds: int = 300) -> None:
        expires = time.time() + seconds
        self._execute("""
            INSERT INTO cooldowns (rule_id, entity_key, expires_at)
            VALUES (%s,%s,%s)
            ON CONFLICT (rule_id, entity_key)
            DO UPDATE SET expires_at=EXCLUDED.expires_at
        """, (rule_id, entity_key, expires))

    # ── Dedup ─────────────────────────────────────────────────────────────────

    def is_duplicate(self, hash_str: str) -> bool:
        row = self._execute(
            "SELECT hash FROM dedup_cache WHERE hash=%s", (hash_str,), fetch="one"
        )
        if row:
            self._execute(
                "UPDATE dedup_cache SET count=count+1, last_seen=%s WHERE hash=%s",
                (time.time(), hash_str)
            )
            return True
        return False

    def mark_hash(self, hash_str: str) -> None:
        now = time.time()
        self._execute("""
            INSERT INTO dedup_cache (hash, first_seen, last_seen)
            VALUES (%s,%s,%s)
            ON CONFLICT DO NOTHING
        """, (hash_str, now, now))

    # ── Events ────────────────────────────────────────────────────────────────

    def insert_event(self, event_summary: Dict = None, **kwargs) -> None:
        if event_summary is None:
            event_summary = kwargs
        trainable     = 1 if event_summary.get("trainable", True) else 0
        risk_bucket   = event_summary.get("risk_bucket", "normal")
        dst_port      = event_summary.get("dst_port", 0) or 0
        distro_family = event_summary.get("distro_family", "unknown") or "unknown"
        raw_log       = event_summary.get("raw_log", "") or ""
        row = (
            event_summary.get("ts", time.time()),
            event_summary.get("host", ""),
            event_summary.get("source", ""),
            event_summary.get("category", ""),
            event_summary.get("action", ""),
            event_summary.get("outcome", ""),
            event_summary.get("user", ""),
            event_summary.get("src_ip", ""),
            event_summary.get("process", ""),
            event_summary.get("message", "")[:300],
            event_summary.get("phase", 0),
            trainable,
            dst_port,
            risk_bucket,
            distro_family,
            raw_log[:2000],  # raw log line, max 2000 characters
        )
        flush_now = False
        with self._event_batch_lock:
            self._event_batch.append(row)
            age = time.time() - self._event_batch_last
            if len(self._event_batch) >= self._event_batch_size or age >= self._event_batch_max_age:
                flush_now = True

        if flush_now:
            self._flush_event_batch()

    def _flush_event_batch(self) -> None:
        """Write buffered event rows in a single transaction."""
        with self._event_batch_lock:
            if not self._event_batch:
                return
            batch = self._event_batch[:]
            self._event_batch.clear()
            self._event_batch_last = time.time()

        conn = self._conn()
        try:
            with conn.cursor() as cur:
                psycopg2.extras.execute_values(cur, """
                    INSERT INTO events_recent
                        (ts,host,source,category,action,outcome,username,src_ip,process,
                         message,phase,trainable,dst_port,risk_bucket,distro_family,raw_log)
                    VALUES %s
                    ON CONFLICT DO NOTHING
                """, batch)
            conn.commit()
            logger.debug(f"[DB/PG] Batch insert: {len(batch)} event yazıldı.")
        except Exception as e:
            conn.rollback()
            logger.error(f"[DB/PG] _flush_event_batch hatası: {e}", exc_info=True)
        finally:
            self._release(conn)

    # ── Sequence ──────────────────────────────────────────────────────────────

    def get_sequence_state(self, entity: str, seq_id: str) -> Optional[Dict]:
        row = self._execute(
            "SELECT * FROM sequence_state WHERE entity=%s AND seq_id=%s",
            (entity, seq_id), fetch="one"
        )
        return dict(row) if row else None

    def set_sequence_state(self, entity: str, seq_id: str, step: int, ts: float) -> None:
        self._execute("""
            INSERT INTO sequence_state (entity,seq_id,step,last_ts)
            VALUES (%s,%s,%s,%s)
            ON CONFLICT (entity,seq_id)
            DO UPDATE SET step=EXCLUDED.step, last_ts=EXCLUDED.last_ts
        """, (entity, seq_id, step, ts))

    def delete_sequence_state(self, entity: str, seq_id: str) -> None:
        self._execute(
            "DELETE FROM sequence_state WHERE entity=%s AND seq_id=%s",
            (entity, seq_id)
        )

    def cleanup_sequence_states(self, timeout: float) -> None:
        self._execute(
            "DELETE FROM sequence_state WHERE last_ts < %s",
            (time.time() - timeout,)
        )

    # ── Process Tree ──────────────────────────────────────────────────────────

    def update_process_tree(self, parent: str, child: str) -> None:
        now = time.time()
        self._execute("""
            INSERT INTO process_tree (parent,child,count,first_seen,last_seen)
            VALUES (%s,%s,1,%s,%s)
            ON CONFLICT (parent,child)
            DO UPDATE SET count=process_tree.count+1, last_seen=EXCLUDED.last_seen
        """, (parent, child, now, now))

    def get_process_children(self, parent: str) -> List[Dict]:
        rows = self._execute(
            "SELECT * FROM process_tree WHERE parent=%s ORDER BY count DESC",
            (parent,), fetch="all"
        )
        return [dict(r) for r in (rows or [])]

    # ── System Stats ──────────────────────────────────────────────────────────

    def get_stat(self, key: str) -> Optional[str]:
        row = self._execute(
            "SELECT value FROM system_stats WHERE key=%s", (key,), fetch="one"
        )
        return next(iter(row.values())) if row else None

    def set_stat(self, key: str, value: str) -> None:
        self._execute("""
            INSERT INTO system_stats (key,value,updated_at)
            VALUES (%s,%s,%s)
            ON CONFLICT (key)
            DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at
        """, (key, value, time.time()))

    def log_action(
        self,
        action: str,
        status: str = "ok",
        actor: str = "terminal",
        screen: str = "",
        entity_type: str = "",
        entity_id: str = "",
        target: str = "",
        summary: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._execute("""
            INSERT INTO user_actions
            (ts, action, status, actor, screen, entity_type, entity_id, target, summary, details)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            time.time(),
            action,
            status,
            actor,
            screen,
            entity_type,
            entity_id,
            target,
            summary,
            json.dumps(details or {}, ensure_ascii=False),
        ))

    def get_recent_user_actions(self, limit: int = 100) -> List[Dict]:
        rows = self._execute(
            "SELECT ts, action, status, actor, screen, entity_type, entity_id, "
            "target, summary, details FROM user_actions ORDER BY ts DESC LIMIT %s",
            (limit,),
            fetch="all",
        )
        return [dict(r) for r in (rows or [])]

    # ── ML Control Log ────────────────────────────────────────────────────────

    def log_ml_control(self, action: str, reason: str = "",
                       actor: str = "auto", source: str = "") -> None:
        self._execute("""
            INSERT INTO ml_control_log (ts, action, reason, actor, source)
            VALUES (%s,%s,%s,%s,%s)
        """, (time.time(), action, reason, actor, source))

    def get_ml_control_log(self, limit: int = 50) -> List[Dict]:
        rows = self._execute(
            "SELECT ts, action, reason, actor, source FROM ml_control_log "
            "ORDER BY ts DESC LIMIT %s", (limit,), fetch="all"
        )
        return [dict(r) for r in (rows or [])]

    # ── Health ────────────────────────────────────────────────────────────────

    def health_check(self) -> Dict:
        try:
            conn = self._conn()
            try:
                with conn.cursor() as cur:
                    missing_tables = self._get_missing_schema_tables(cur)
                    cur.execute("SELECT COUNT(*) FROM alerts")
                    row = cur.fetchone()
                    alert_count = row[0] if row else -1
                    cur.execute("SELECT COALESCE(MAX(version),0) FROM schema_version")
                    schema_row = cur.fetchone()
                    db_version = schema_row[0] if schema_row and schema_row[0] is not None else 0
                conn.commit()
            finally:
                self._release(conn)

            # v8: migration integrity — compare against the expected version
            migration_ok = (db_version >= CURRENT_VERSION) and not missing_tables
            if not migration_ok:
                if missing_tables:
                    logger.warning(
                        "[DB/PG] Kritik şema tabloları eksik: %s",
                        ", ".join(missing_tables),
                    )
                if db_version < CURRENT_VERSION:
                    logger.warning(
                        f"[DB/PG] Schema versiyonu geride: db={db_version} "
                        f"beklenen={CURRENT_VERSION}"
                    )

            if missing_tables:
                status = "schema_incomplete"
            elif db_version < CURRENT_VERSION:
                status = "migration_needed"
            else:
                status = "ok"

            return {
                "ok":             migration_ok,
                "status":         status,
                "backend":        "postgresql",
                "connection_ok":  True,
                "schema_ok":      migration_ok,
                "alerts_readable": True,
                "alert_count":    alert_count,
                "schema_version": db_version,
                "expected_version": CURRENT_VERSION,
                "schema_manifest": get_schema_manifest(),
                "pending_versions": get_pending_schema_versions(db_version),
                "migration_ok":   migration_ok,
                "missing_tables": missing_tables,
                "pool_min":       self._pool.minconn,
                "pool_max":       self._pool.maxconn,
            }
        except Exception as e:
            import traceback as _tb
            return {"ok": False, "status": "error", "error": str(e),
                    "connection_ok": False,
                    "schema_ok": False,
                    "alerts_readable": False,
                    "error_type": type(e).__name__,
                    "detail": _tb.format_exc()[-500:]}

    # ── Process Tree ─────────────────────────────────────────────────────────

    def is_new_process_pair(self, parent: str, child: str, min_seen: int = 5) -> bool:
        """Return True if this parent→child pair has been seen fewer than min_seen times."""
        row = self._execute(
            "SELECT count FROM process_tree WHERE parent=%s AND child=%s",
            (parent, child), fetch="one"
        )
        if row is None:
            return True
        return row["count"] < min_seen

    # ── Dedup cleanup ─────────────────────────────────────────────────────────

    def cleanup_dedup_cache(self, hours: int = 48) -> int:
        """Delete dedup records older than hours and return the number removed."""
        cutoff = time.time() - hours * 3600
        row = self._execute(
            "SELECT COUNT(*) FROM dedup_cache WHERE last_seen < %s",
            (cutoff,), fetch="one"
        )
        count = next(iter(row.values())) if row else 0
        if count > 0:
            self._execute("DELETE FROM dedup_cache WHERE last_seen < %s", (cutoff,))
            logger.debug(f"[DB/PG] dedup_cache temizlendi: {count} kayıt (>{hours}s)")
        return count

    def cleanup_events_recent(self, days: int = 14) -> int:
        """Delete events_recent rows older than days."""
        cutoff = time.time() - days * 86400
        row = self._execute(
            "SELECT COUNT(*) FROM events_recent WHERE ts < %s",
            (cutoff,), fetch="one"
        )
        count = next(iter(row.values())) if row else 0
        if count > 0:
            self._execute("DELETE FROM events_recent WHERE ts < %s", (cutoff,))
            logger.debug(f"[DB/PG] events_recent temizlendi: {count} kayıt (>{days}g)")
        return count

    def cleanup_risk_history(self, days: int = 30) -> int:
        """Delete risk_history rows older than days."""
        cutoff = time.time() - days * 86400
        row = self._execute(
            "SELECT COUNT(*) FROM risk_history WHERE ts < %s",
            (cutoff,), fetch="one"
        )
        count = next(iter(row.values())) if row else 0
        if count > 0:
            self._execute("DELETE FROM risk_history WHERE ts < %s", (cutoff,))
            logger.debug(f"[DB/PG] risk_history temizlendi: {count} kayıt (>{days}g)")
        return count

    # ── Report queries ────────────────────────────────────────────────────────

    def get_report_stats(self, since: float) -> Dict:
        """
        Return all metrics required for reporting.
        Uses PostgreSQL extract().
        """
        try:
            row = self._execute(
                "SELECT COUNT(*) FROM alerts WHERE ts >= %s", (since,), fetch="one"
            )
            total = next(iter(row.values())) if row else 0

            sev_rows = self._execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE ts >= %s GROUP BY severity",
                (since,), fetch="all"
            ) or []
            by_severity = {r["severity"]: r["count"] for r in sev_rows}

            rule_rows = self._execute("""
                SELECT rule_id, COUNT(*) AS cnt FROM alerts
                WHERE ts >= %s GROUP BY rule_id ORDER BY cnt DESC LIMIT 10
            """, (since,), fetch="all") or []
            top_rules = [(r["rule_id"], r["cnt"]) for r in rule_rows]

            entity_rows = self._execute("""
                SELECT entity, COUNT(*) AS cnt FROM alerts
                WHERE ts >= %s AND entity != ''
                GROUP BY entity ORDER BY cnt DESC LIMIT 10
            """, (since,), fetch="all") or []
            top_entities = [(r["entity"], r["cnt"]) for r in entity_rows]

            host_rows = self._execute("""
                SELECT host, COUNT(*) AS cnt FROM alerts
                WHERE ts >= %s GROUP BY host ORDER BY cnt DESC LIMIT 5
            """, (since,), fetch="all") or []
            top_hosts = [(r["host"], r["cnt"]) for r in host_rows]

            inc_row = self._execute(
                "SELECT COUNT(*) FROM incidents WHERE ts_start >= %s", (since,), fetch="one"
            )
            incident_total = next(iter(inc_row.values())) if inc_row else 0

            inc_rows = self._execute(
                "SELECT status, COUNT(*) FROM incidents WHERE ts_start >= %s GROUP BY status",
                (since,), fetch="all"
            ) or []
            by_status = {r["status"]: r["count"] for r in inc_rows}

            # PG: extract(hour from to_timestamp(ts))
            hour_rows = self._execute("""
                SELECT EXTRACT(HOUR FROM to_timestamp(ts))::int AS h, COUNT(*) AS cnt
                FROM alerts WHERE ts >= %s GROUP BY h ORDER BY h
            """, (since,), fetch="all") or []
            by_hour = {r["h"]: r["cnt"] for r in hour_rows}

            top_user_rows = self._execute("""
                SELECT username, COUNT(*) AS cnt FROM events_recent
                WHERE ts >= %s AND username != ''
                GROUP BY username ORDER BY cnt DESC LIMIT 10
            """, (since,), fetch="all") or []
            top_users = [(r["username"], r["cnt"]) for r in top_user_rows]

            return {
                "total_alerts":   total,
                "by_severity":    by_severity,
                "top_rules":      top_rules,
                "top_entities":   top_entities,
                "top_users":      top_users,
                "top_hosts":      top_hosts,
                "incident_total": incident_total,
                "by_status":      by_status,
                "by_hour":        by_hour,
            }
        except Exception as e:
            logger.error(f"[DB/PG] get_report_stats hatası: {e}")
            return {}

    # ── Rule stats queries ────────────────────────────────────────────────────

    def get_rule_stats(self, limit: int = 50, hours: float = 168) -> List[Dict]:
        """Rule-level statistics for terminal reports and the --rule-stats command."""
        cutoff = time.time() - hours * 3600
        rows = self._execute("""
            SELECT
                rule_id,
                COUNT(*)            AS hit_count,
                AVG(risk_score)     AS avg_score,
                MAX(ts)             AS last_hit,
                MIN(ts)             AS first_hit,
                severity,
                mitre_tactic,
                mitre_technique
            FROM alerts
            WHERE ts > %s
            GROUP BY rule_id, severity, mitre_tactic, mitre_technique
            ORDER BY hit_count DESC
            LIMIT %s
        """, (cutoff, limit), fetch="all") or []
        return [dict(r) for r in rows]

    def get_never_fired_rules(self, all_rule_ids: List[str],
                               hours: float = 168) -> List[str]:
        """Find rules that have never fired."""
        cutoff = time.time() - hours * 3600
        rows = self._execute(
            "SELECT DISTINCT rule_id FROM alerts WHERE ts > %s",
            (cutoff,), fetch="all"
        ) or []
        fired = {r["rule_id"] for r in rows}
        return [rid for rid in all_rule_ids if rid not in fired]

    def get_top_entities(self, hours: float = 24, limit: int = 10) -> List[Dict]:
        """Return the entities that generated the most alerts."""
        cutoff = time.time() - hours * 3600
        rows = self._execute("""
            SELECT entity, COUNT(*) AS alert_count, MAX(risk_score) AS max_score
            FROM alerts
            WHERE ts > %s AND entity != ''
            GROUP BY entity
            ORDER BY alert_count DESC
            LIMIT %s
        """, (cutoff, limit), fetch="all") or []
        return [dict(r) for r in rows]

    # ── Archive ───────────────────────────────────────────────────────────────

    def archive_old_alerts(self, days: int = 30) -> int:
        """
        Move old alerts to alerts_archive and remove them from the active table.
        Data is preserved to meet forensic/history expectations.
        Returns: number of moved alerts.
        """
        cutoff = time.time() - days * 86400
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                # 1. Copy into the archive — rows already archived are skipped (ON CONFLICT)
                cur.execute("""
                    INSERT INTO alerts_archive
                    SELECT * FROM alerts
                    WHERE ts < %s
                    ON CONFLICT (id) DO NOTHING
                """, (cutoff,))
                newly_archived = cur.rowcount

                # 2. Delete from the source table — always run regardless of rowcount.
                # Edge case: if the row is already archived, ON CONFLICT yields rowcount=0,
                # but the alert may still remain in alerts → use unconditional DELETE.
                cur.execute(
                    "SELECT COUNT(*) FROM alerts WHERE ts < %s", (cutoff,)
                )
                row = cur.fetchone()
                to_delete = row[0] if row else 0

                if to_delete > 0:
                    cur.execute("DELETE FROM alerts WHERE ts < %s", (cutoff,))
                    logger.info(
                        f"[DB/PG] {to_delete} alert aktif alerts tablosundan silinip arsive alindi "
                        f"({newly_archived} yeni arsivlendi, >{days} gun)"
                    )
            conn.commit()
            return to_delete
        except Exception as e:
            conn.rollback()
            logger.error(f"[DB/PG] archive_old_alerts hatasi: {e}")
            return 0
        finally:
            self._release(conn)

    def delete_old_alerts(self, days: int = 30) -> int:
        """
        Eski alertleri kalici olarak siler (arsivlemez).
        Disk alani kritikse kullanilir — veri kurtarilamaz.
        Normal retention icin archive_old_alerts tercih edilmeli.
        """
        cutoff = time.time() - days * 86400
        row = self._execute(
            "SELECT COUNT(*) FROM alerts WHERE ts < %s", (cutoff,), fetch="one"
        )
        count = next(iter(row.values())) if row else 0
        if count > 0:
            self._execute("DELETE FROM alerts WHERE ts < %s", (cutoff,))
            logger.warning(
                f"[DB/PG] {count} alert kalici silindi (>{days} gun) -- "
                f"arsivlenmedi, kurtarilamaz"
            )
        return count

    def vacuum(self) -> None:
        conn = self._conn()
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("VACUUM ANALYZE")
            conn.autocommit = False
            logger.info("[DB/PG] VACUUM ANALYZE tamamlandı.")
        except Exception as e:
            logger.error(f"[DB/PG] VACUUM hatası: {e}")
        finally:
            self._release(conn)

    def analyze(self) -> None:
        """
        ANALYZE updates query planner statistics.
        It is independent from VACUUM and can run more frequently inside a transaction.
        This prevents the planner from choosing slow plans based on stale statistics
        after heavy INSERT/DELETE activity on large tables.
        """
        conn = self._conn()
        try:
            # ANALYZE can run inside a transaction — autocommit is not required
            cur = conn.cursor()
            # Prioritize critical tables for analysis
            for table in _ANALYZE_TABLES:
                try:
                    cur.execute(self._identifier_statement("ANALYZE {}", table, allowed=_ANALYZE_TABLES))
                except psycopg2.errors.UndefinedTable:
                    logger.debug(f"[DB/PG] ANALYZE: tablo yok, atlandı: {table}")
                except psycopg2.Error as _ae:
                    logger.debug(f"[DB/PG] ANALYZE {table} hatası: {_ae}")
            conn.commit()
            logger.info("[DB/PG] ANALYZE tamamlandı — query planner istatistikleri güncellendi.")
        except Exception as e:
            logger.error(f"[DB/PG] ANALYZE hatası: {e}", exc_info=True)
            try:
                conn.rollback()
            except psycopg2.Error as _re:
                logger.debug(f"[DB/PG] ANALYZE rollback hatası: {_re}")
        finally:
            self._release(conn)

    def close(self):
        self._flush_event_batch()  # flush the buffer before shutdown
        self._pool.closeall()


    # ── Cross-host State Persistence (v8) ────────────────────────────────────

    def save_cross_host_state(self, ip_to_hosts: dict) -> None:
        """
        Persist the cross-host IP→host map to the DB.
        Correlation state is preserved across restarts.
        """
        try:
            for src_ip, hosts in ip_to_hosts.items():
                for host, last_ts in hosts.items():
                    self._execute(
                        """INSERT INTO cross_host_state (src_ip, host, last_ts)
                           VALUES (%s, %s, %s)
                           ON CONFLICT (src_ip, host) DO UPDATE SET last_ts = EXCLUDED.last_ts""",
                        (src_ip, host, last_ts)
                    )
        except Exception as e:
            logger.error(f"[DB/PG] save_cross_host_state hatası: {e}")

    def load_cross_host_state(self, ttl: float = 3600.0) -> dict:
        """
        DB'den cross-host state'i yükle. TTL süresi dolmuş kayıtlar atlanır.
        Returns: {src_ip: {host: last_ts}}
        """
        result: dict = {}
        cutoff = time.time() - ttl
        try:
            rows = self._execute(
                "SELECT src_ip, host, last_ts FROM cross_host_state WHERE last_ts > %s",
                (cutoff,), fetch="all"
            ) or []
            for row in rows:
                ip   = row["src_ip"]
                host = row["host"]
                ts   = row["last_ts"]
                if ip not in result:
                    result[ip] = {}
                result[ip][host] = ts
        except Exception as e:
            logger.error(f"[DB/PG] load_cross_host_state hatası: {e}")
        return result

    def cleanup_cross_host_state(self, ttl: float = 3600.0) -> int:
        """Clean up expired cross-host records."""
        cutoff = time.time() - ttl
        try:
            row = self._execute(
                "SELECT COUNT(*) FROM cross_host_state WHERE last_ts < %s",
                (cutoff,), fetch="one"
            )
            count = next(iter(row.values())) if row else 0
            if count > 0:
                self._execute(
                    "DELETE FROM cross_host_state WHERE last_ts < %s", (cutoff,)
                )
                logger.debug(f"[DB/PG] cross_host_state temizlendi: {count} kayıt")
            return count
        except Exception as e:
            logger.error(f"[DB/PG] cleanup_cross_host_state hatası: {e}")
            return 0

    # ── Ek metodlar ──────────────────────────────────────────────────────────────

    def load_sequence_states(self) -> dict:
        """Return all sequence states as a dict."""
        try:
            rows = self._execute(
                "SELECT entity, seq_id, step, last_ts FROM sequence_state",
                fetch="all"
            ) or []
            result = {}
            for r in rows:
                key = f"{r['entity']}:{r['seq_id']}"
                result[key] = {"step": r["step"], "last_ts": r["last_ts"]}
            return result
        except Exception as e:
            logger.error(f"[DB/PG] load_sequence_states hatası: {e}")
            return {}

    def save_sequence_state(self, entity: str, seq_id: str, step: int, ts: float) -> None:
        """Legacy API compatibility — forward to set_sequence_state."""
        self.set_sequence_state(entity, seq_id, step, ts)

    def delete_sequence(self, entity: str, seq_id: str) -> None:
        """Legacy API compatibility — forward to delete_sequence_state."""
        self.delete_sequence_state(entity, seq_id)

    def insert_alert_compat(self, alert: dict) -> None:
        """Legacy API compatibility — forward to insert_alert."""
        return self.insert_alert(alert)

    def get_stats(self) -> dict:
        """System statistics summary."""
        try:
            return {
                "total_alerts":   self.get_alert_count(hours=876000),
                "alerts_1h":      self.get_alert_count(hours=1),
                "alerts_24h":     self.get_alert_count(hours=24),
                "open_incidents": len(self.get_open_incidents()),
            }
        except Exception as e:
            logger.error(f"[DB/PG] get_stats hatası: {e}")
            return {}

    # ── Entity Risk Persist (Correlation state) ───────────────────────────────

    def save_entity_risk_state(self, entity_state: dict) -> None:
        """
        EntityCorrelator state'ini DB'ye kaydet.
        entity_state: {entity_key: {score, alerts, last_ts, first_ts}}
        Use the system_config table as a JSON store.
        """
        try:
            import json as _json
            serializable = {}
            for k, v in entity_state.items():
                serializable[k] = {
                    "score":    v.get("score", 0.0),
                    "last_ts":  v.get("last_ts", 0.0),
                    "first_ts": v.get("first_ts", 0.0),
                    "alerts":   v.get("alerts", [])[-100:],  # son 100 alert ID yeter
                }
            self._execute(
                """INSERT INTO system_config (key, value, updated_ts)
                   VALUES ('entity_risk_state', %s, %s)
                   ON CONFLICT (key) DO UPDATE
                   SET value = EXCLUDED.value, updated_ts = EXCLUDED.updated_ts""",
                (_json.dumps(serializable), time.time())
            )
        except Exception as e:
            logger.error(f"[DB/PG] save_entity_risk_state hatası: {e}")

    def load_entity_risk_state(self, max_age_seconds: float = 604800.0) -> dict:
        """
        Load EntityCorrelator state from the DB.
        max_age_seconds: default 7 days, aligned with the slow-and-low window
        """
        try:
            import json as _json
            row = self._execute(
                "SELECT value, updated_ts FROM system_config WHERE key = 'entity_risk_state'",
                fetch="one"
            )
            if not row:
                return {}
            age = time.time() - (row.get("updated_ts") or 0)
            if age > max_age_seconds:
                logger.info("[DB/PG] entity_risk_state çok eski, atlandı.")
                return {}
            return _json.loads(row["value"])
        except Exception as e:
            logger.error(f"[DB/PG] load_entity_risk_state hatası: {e}")
            return {}

    # ── Labels ────────────────────────────────────────────────────────────────

    def save_labels(self, records: list) -> int:
        """
        bootstrap / auto_labeled / manually_verified etiketleri DB'ye yaz.
        synthetic etiketler dosyadan okunur, buraya gelmez.
        Exact duplicate etiketler ikinci kez biriktirilmez.
        """
        from core.ml.label_engine import LabelRecord

        def _jsonb_or_none(value):
            if value is None:
                return None
            return psycopg2.extras.Json(value)

        saved = 0
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                for r in records:
                    if not isinstance(r, LabelRecord):
                        raise TypeError(
                            f"save_labels LabelRecord bekler, gelen tip: {type(r).__name__}"
                        )
                    if getattr(r, "source", "") == "synthetic":
                        continue
                    try:
                        evidence_fields = dict(getattr(r, "evidence_fields", None) or {})
                        origin = str(getattr(r, "origin", "") or "").strip().lower()
                        if origin:
                            evidence_fields.setdefault("origin", origin)
                        elif getattr(r, "source", "") == "auto_labeled":
                            evidence_fields.setdefault("origin", "organic_live")
                        elif getattr(r, "source", "") == "bootstrap":
                            evidence_fields.setdefault("origin", "bootstrap_historical")
                        cur.execute(
                            """INSERT INTO labels
                               (source, label, category, score, confidence, weight,
                                entity_key, distro, ts, ready_after,
                                event_class, behavior_label, attack_family,
                                technique_label, source_trust, learnable,
                                model_usage_scope, label_lifecycle_status,
                                poisoning_guard_passed, label_reason,
                                evidence_fields, review_flags,
                                bootstrap_job_id, label_batch_id, correlation_id)
                               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                                       %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                                       %s,%s,%s,%s,%s)
                               ON CONFLICT
                               (source, label, category, score, confidence, weight,
                                entity_key, distro, ts, ready_after)
                               DO NOTHING""",
                            (r.source, r.label, r.category, r.score, r.confidence,
                             r.weight, r.entity_key or "", r.distro,
                             r.ts, r.ready_after,
                             getattr(r, "event_class", None) or None,
                             getattr(r, "behavior_label", None) or None,
                             getattr(r, "attack_family", None) or None,
                             getattr(r, "technique_label", None) or None,
                             getattr(r, "source_trust", None) or None,
                             getattr(r, "learnable", None),
                             getattr(r, "model_usage_scope", None) or None,
                             getattr(r, "label_lifecycle_status", None) or None,
                             getattr(r, "poisoning_guard_passed", None),
                             getattr(r, "label_reason", None) or None,
                             _jsonb_or_none(evidence_fields),
                             _jsonb_or_none(getattr(r, "review_flags", None)),
                             getattr(r, "bootstrap_job_id", None) or None,
                             getattr(r, "label_batch_id", None) or None,
                             getattr(r, "correlation_id", None) or None)
                        )
                        saved += cur.rowcount
                    except Exception as e:
                        logger.debug(f"[DB/PG] save_labels kayıt hatası: {e}")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)
        if saved:
            logger.debug(f"[DB/PG] {saved} etiket kaydedildi")
        return saved

    def load_labels(self, distro: str = "") -> list:
        """
        Load labels from the DB. The distro filter is optional.
        Returns a list of dicts instead of LabelRecord objects — LabelEngine converts them.
        """
        def _hydrate_label_row(row: Dict) -> Dict:
            payload = dict(row or {})
            evidence = payload.get("evidence_fields")
            if isinstance(evidence, dict):
                for key, value in evidence.items():
                    if payload.get(key) in (None, "", {}):
                        payload[key] = value
            return payload

        try:
            if distro:
                rows = self._execute(
                    "SELECT * FROM labels WHERE distro = %s OR distro = '' ORDER BY ts ASC",
                    (distro,), fetch="all"
                ) or []
            else:
                rows = self._execute(
                    "SELECT * FROM labels ORDER BY ts ASC",
                    fetch="all"
                ) or []
            logger.info(f"[DB/PG] {len(rows)} etiket yüklendi (distro={distro or 'all'})")
            return [_hydrate_label_row(dict(r)) for r in rows]
        except Exception as e:
            logger.error(f"[DB/PG] load_labels hatası: {e}")
            return []

    def cleanup_labels(self, days: int = 180, manual: bool = False) -> int:
        """
        Eski auto_labeled etiketleri temizle.
        manually_verified ve bootstrap etiketler silinmez.
        """
        if not manual:
            logger.info("[DB/PG] cleanup_labels atlandı — manual-only")
            return 0
        import time as _time
        cutoff = _time.time() - days * 86400
        try:
            row = self._execute(
                "SELECT COUNT(*) FROM labels WHERE source = 'auto_labeled' AND ts < %s",
                (cutoff,), fetch="one"
            )
            count = next(iter(row.values())) if row else 0
            if count > 0:
                self._execute(
                    "DELETE FROM labels WHERE source = 'auto_labeled' AND ts < %s",
                    (cutoff,)
                )
                logger.info(f"[DB/PG] labels temizlendi: {count} auto_labeled kayıt (>{days}g)")
            return count
        except Exception as e:
            logger.error(f"[DB/PG] cleanup_labels hatası: {e}")
            return 0

    def backfill_legacy_bootstrap_label_metadata(self, updates: list[dict]) -> int:
        """Apply explicit rejected-metadata backfill to legacy bootstrap label records."""
        if not updates:
            return 0

        def _jsonb_or_none(value):
            if value is None:
                return None
            return psycopg2.extras.Json(value)

        updated = 0
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                for item in updates:
                    row_id = item.get("id")
                    if row_id is None:
                        continue
                    cur.execute(
                        """
                        UPDATE labels
                           SET event_class = %s,
                               behavior_label = %s,
                               source_trust = %s,
                               model_usage_scope = %s,
                               learnable = %s,
                               label_reason = %s,
                               poisoning_guard_passed = %s,
                               evidence_fields = COALESCE(evidence_fields, '{}'::jsonb) || %s::jsonb
                         WHERE id = %s
                           AND source = 'bootstrap'
                           AND (
                               COALESCE(BTRIM(event_class), '') = ''
                               OR COALESCE(BTRIM(behavior_label), '') = ''
                               OR COALESCE(BTRIM(source_trust), '') = ''
                               OR COALESCE(BTRIM(model_usage_scope), '') = ''
                               OR learnable IS NULL
                               OR COALESCE(BTRIM(label_reason), '') = ''
                           )
                           AND COALESCE(learnable, FALSE) IS DISTINCT FROM TRUE
                           AND COALESCE(BTRIM(model_usage_scope), '') NOT IN ('direct_learnable', 'baseline_learning')
                        """,
                        (
                            item.get("event_class"),
                            item.get("behavior_label"),
                            item.get("source_trust"),
                            item.get("model_usage_scope"),
                            item.get("learnable"),
                            item.get("label_reason"),
                            item.get("poisoning_guard_passed"),
                            _jsonb_or_none(item.get("evidence_fields")),
                            row_id,
                        ),
                    )
                    updated += int(cur.rowcount or 0)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)
        return updated

    # ── Missing Retention Methods ─────────────────────────────────────────────

    def cleanup_incidents(self, days: int = 180) -> int:
        """Clean up old incident records."""
        import time as _time
        cutoff = _time.time() - days * 86400
        try:
            row = self._execute(
                "SELECT COUNT(*) FROM incidents WHERE ts_start < %s", (cutoff,), fetch="one"
            )
            count = next(iter(row.values())) if row else 0
            if count > 0:
                self._execute("DELETE FROM incidents WHERE ts_start < %s", (cutoff,))
                logger.info(f"[DB/PG] incidents temizlendi: {count} kayıt (>{days}g)")
            return count
        except Exception as e:
            logger.error(f"[DB/PG] cleanup_incidents hatası: {e}")
            return 0

    def cleanup_entity_state(self, days: int = 30) -> int:
        """Clean up entity-state records that have not been updated for a long time."""
        import time as _time
        cutoff = _time.time() - days * 86400
        try:
            row = self._execute(
                "SELECT COUNT(*) FROM entity_state WHERE last_ts < %s", (cutoff,), fetch="one"
            )
            count = next(iter(row.values())) if row else 0
            if count > 0:
                self._execute("DELETE FROM entity_state WHERE last_ts < %s", (cutoff,))
                logger.info(f"[DB/PG] entity_state temizlendi: {count} kayıt (>{days}g)")
            return count
        except Exception as e:
            logger.error(f"[DB/PG] cleanup_entity_state hatası: {e}")
            return 0

    def cleanup_process_tree(self, days: int = 7, manual: bool = False) -> int:
        """Clean up old process-tree records."""
        if not manual:
            logger.info("[DB/PG] cleanup_process_tree atlandı — manual-only")
            return 0
        import time as _time
        cutoff = _time.time() - days * 86400
        try:
            row = self._execute(
                "SELECT COUNT(*) FROM process_tree WHERE last_seen < %s", (cutoff,), fetch="one"
            )
            count = next(iter(row.values())) if row else 0
            if count > 0:
                self._execute("DELETE FROM process_tree WHERE last_seen < %s", (cutoff,))
                logger.info(f"[DB/PG] process_tree temizlendi: {count} kayıt (>{days}g)")
            return count
        except Exception as e:
            logger.error(f"[DB/PG] cleanup_process_tree hatası: {e}")
            return 0

    def cleanup_ml_control_log(self, days: int = 90, manual: bool = False) -> int:
        """Clean up old ML control-log records."""
        if not manual:
            logger.info("[DB/PG] cleanup_ml_control_log atlandı — manual-only")
            return 0
        import time as _time
        cutoff = _time.time() - days * 86400
        try:
            row = self._execute(
                "SELECT COUNT(*) FROM ml_control_log WHERE ts < %s", (cutoff,), fetch="one"
            )
            count = next(iter(row.values())) if row else 0
            if count > 0:
                self._execute("DELETE FROM ml_control_log WHERE ts < %s", (cutoff,))
                logger.info(f"[DB/PG] ml_control_log temizlendi: {count} kayıt (>{days}g)")
            return count
        except Exception as e:
            logger.error(f"[DB/PG] cleanup_ml_control_log hatası: {e}")
            return 0

    def cleanup_model_registry(self, keep_latest: int = 3, manual: bool = False) -> int:
        """
        Keep the latest keep_latest version for each model and remove older ones.
        """
        if not manual:
            logger.info("[DB/PG] cleanup_model_registry atlandı — manual-only")
            return 0
        try:
            rows = self._execute(
                "SELECT DISTINCT model_name FROM model_registry", fetch="all"
            ) or []
            total = 0
            for row in rows:
                name = row["model_name"]
                old = self._execute(
                    """SELECT id FROM model_registry WHERE model_name = %s
                       ORDER BY trained_at DESC OFFSET %s""",
                    (name, keep_latest), fetch="all"
                ) or []
                if old:
                    ids = [r["id"] for r in old]
                    self._execute(
                        "DELETE FROM model_registry WHERE id = ANY(%s)", (ids,)
                    )
                    total += len(ids)
            if total:
                logger.info(f"[DB/PG] model_registry temizlendi: {total} eski versiyon")
            return total
        except Exception as e:
            logger.error(f"[DB/PG] cleanup_model_registry hatası: {e}")
            return 0

    def cleanup_phase_history(self, days: int = 90) -> int:
        """Clean up old phase-transition records."""
        import time as _time
        cutoff = _time.time() - days * 86400
        try:
            row = self._execute(
                "SELECT COUNT(*) FROM phase_history WHERE ts < %s", (cutoff,), fetch="one"
            )
            count = next(iter(row.values())) if row else 0
            if count > 0:
                self._execute("DELETE FROM phase_history WHERE ts < %s", (cutoff,))
                logger.info(f"[DB/PG] phase_history temizlendi: {count} kayıt (>{days}g)")
            return count
        except Exception as e:
            logger.error(f"[DB/PG] cleanup_phase_history hatası: {e}")
            return 0

    def run_full_cleanup(self) -> dict:
        """
        Run all cleanup methods. Called by the maintenance scheduler.
        """
        return {
            "alerts_archived":      self.archive_old_alerts(days=90),
            "events_deleted":       self.cleanup_events_recent(days=14),
            "risk_history_deleted": self.cleanup_risk_history(days=30),
            "dedup_deleted":        self.cleanup_dedup_cache(hours=48),
            "incidents_deleted":    self.cleanup_incidents(days=180),
            "entity_state_deleted": self.cleanup_entity_state(days=30),
            "process_tree_deleted": self.cleanup_process_tree(days=7, manual=False),
            "ml_log_deleted":       self.cleanup_ml_control_log(days=90, manual=False),
            "model_registry_pruned":self.cleanup_model_registry(keep_latest=3, manual=False),
            "phase_history_deleted":self.cleanup_phase_history(days=90),
            "labels_deleted":       self.cleanup_labels(days=180, manual=False),
            "cross_host_deleted":   self.cleanup_cross_host_state(ttl=3600),
        }

    def factory_reset(self) -> bool:
        """
        Clear all operational and user data.
        The minimum preserved state is the DB schema and schema_version records.
        """
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                for table in _FACTORY_RESET_TABLES:
                    cur.execute(self._identifier_statement("DELETE FROM {}", table, allowed=_FACTORY_RESET_TABLES))
            conn.commit()
            logger.warning("[DB/PG] Factory reset tamamlandı; tüm operasyonel veriler silindi.")
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"[DB/PG] factory_reset hatası: {e}")
            return False
        finally:
            self._release(conn)

    # ── IP Block Suggestions ──────────────────────────────────────────────────

    def add_ip_block_suggestion(self, ip: str, reason: str = "",
                                 source: str = "alert", alert_id: int = None,
                                 abuse_score: int = None, abuse_reports: int = None,
                                 abuse_country: str = "", abuse_raw: dict = None) -> Optional[int]:
        """
        Add an IP-block suggestion.
        Do not insert a duplicate suggestion if the same IP already has an unreviewed record.
        """
        if not ip:
            return None
        now = time.time()
        # Update the existing pending record if the same IP already has reviewed=False
        existing = self._execute(
            "SELECT id FROM ip_block_suggestions WHERE ip=%s AND reviewed=FALSE LIMIT 1",
            (ip,), fetch="one"
        )
        if existing:
            self._execute(
                """UPDATE ip_block_suggestions
                   SET reason=%s, source=%s, alert_id=COALESCE(%s, alert_id),
                       abuse_score=COALESCE(%s, abuse_score),
                       abuse_reports=COALESCE(%s, abuse_reports),
                       abuse_country=COALESCE(NULLIF(%s,''), abuse_country),
                       abuse_raw=COALESCE(%s::jsonb, abuse_raw),
                       suggested_at=%s
                   WHERE id=%s""",
                (reason, source, alert_id,
                 abuse_score, abuse_reports, abuse_country,
                 json.dumps(abuse_raw) if abuse_raw else None,
                 now, existing["id"])
            )
            return existing["id"]

        row = self._execute(
            """INSERT INTO ip_block_suggestions
               (ip, reason, source, alert_id, abuse_score, abuse_reports,
                abuse_country, abuse_raw, suggested_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
               RETURNING id""",
            (ip, reason, source, alert_id,
             abuse_score, abuse_reports, abuse_country,
             json.dumps(abuse_raw) if abuse_raw else None,
             now),
            fetch="one"
        )
        return row["id"] if row else None

    def get_ip_block_suggestions(self, reviewed: bool = False,
                                  limit: int = 100) -> List[Dict]:
        """
        List IP-block suggestions.
        reviewed=False → only pending items (CLI/operator review queue)
        reviewed=True  → reviewed items (history view)
        """
        rows = self._execute(
            """SELECT * FROM ip_block_suggestions
               WHERE reviewed=%s
               ORDER BY suggested_at DESC LIMIT %s""",
            (reviewed, limit), fetch="all"
        )
        return [dict(r) for r in (rows or [])]

    def get_ip_reputation_for_alert(self, alert_id: int) -> List[Dict]:
        rows = self._execute(
            """SELECT *
               FROM ip_block_suggestions
               WHERE alert_id=%s AND source='abuseipdb'
               ORDER BY suggested_at DESC, id DESC""",
            (int(alert_id),), fetch="all"
        )
        return [dict(r) for r in (rows or [])]

    def get_blocked_ip_suggestions(self, limit: int = 100) -> List[Dict]:
        """Return IP records currently marked as blocked."""
        rows = self._execute(
            """SELECT *
               FROM ip_block_suggestions
               WHERE reviewed=TRUE AND action='blocked'
               ORDER BY suggested_at DESC LIMIT %s""",
            (limit,), fetch="all"
        )
        return [dict(r) for r in (rows or [])]

    def review_ip_block_suggestion(self, suggestion_id: int, action: str) -> bool:
        """
        Review a suggestion: action = "blocked" | "ignored"
        Called from the manual operator CLI flow.
        """
        if action not in ("blocked", "ignored"):
            return False
        affected = self._execute(
            """UPDATE ip_block_suggestions
               SET reviewed=TRUE, reviewed_at=%s, action=%s
               WHERE id=%s""",
            (time.time(), action, suggestion_id)
        )
        return bool(affected and int(affected) > 0)

    def get_blocked_ips(self) -> List[str]:
        """List IPs marked with action='blocked'."""
        rows = self.get_blocked_ip_suggestions(limit=10000)
        return list(dict.fromkeys(r.get("ip", "") for r in rows if r.get("ip")))

    def add_ip_block_action(
        self,
        ip: str,
        action: str,
        status: str,
        dry_run: bool = False,
        backend: str = "",
        backend_rule_ref: str = "",
        reason: str = "",
        guard_reason: str = "",
        error: str = "",
        executed_by: str = "terminal",
        suggestion_id: int = None,
    ) -> Optional[int]:
        if not ip:
            return None
        if action not in ("block", "unblock"):
            raise ValueError(f"Geçersiz ip block action: {action}")
        if status not in ("dry_run", "applied", "failed", "refused"):
            raise ValueError(f"Geçersiz ip block status: {status}")
        row = self._execute(
            """INSERT INTO ip_block_actions
               (ip, action, status, backend, backend_rule_ref, reason,
                guard_reason, error, dry_run, executed_at, executed_by, suggestion_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               RETURNING id""",
            (
                ip,
                action,
                status,
                backend,
                backend_rule_ref,
                reason,
                guard_reason,
                error,
                bool(dry_run),
                time.time(),
                executed_by,
                suggestion_id,
            ),
            fetch="one",
        )
        return row["id"] if row else None

    def get_ip_block_actions(self, ip: str = "", limit: int = 100) -> List[Dict]:
        if ip:
            rows = self._execute(
                """SELECT * FROM ip_block_actions
                   WHERE ip=%s
                   ORDER BY executed_at DESC, id DESC LIMIT %s""",
                (ip, limit),
                fetch="all",
            )
        else:
            rows = self._execute(
                """SELECT * FROM ip_block_actions
                   ORDER BY executed_at DESC, id DESC LIMIT %s""",
                (limit,),
                fetch="all",
            )
        return [dict(r) for r in (rows or [])]

    def get_active_ip_block(self, ip: str) -> Optional[Dict]:
        if not ip:
            return None
        row = self._execute(
            """SELECT *
               FROM ip_block_actions
               WHERE ip=%s AND status='applied'
               ORDER BY executed_at DESC, id DESC
               LIMIT 1""",
            (ip,),
            fetch="one",
        )
        if not row:
            return None
        result = dict(row)
        return result if result.get("action") == "block" else None
