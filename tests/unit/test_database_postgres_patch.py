import time
from inspect import signature
from types import SimpleNamespace

from core.database import Database
from core import database_postgres as dbpg
from core.ml.label_engine import LabelRecord


class _FakeCursor:
    def __init__(self, fetchone_results=None, rowcounts=None):
        self.fetchone_results = list(fetchone_results or [])
        self.rowcounts = list(rowcounts or [])
        self.executed = []
        self.rowcount = -1

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        if self.rowcounts:
            self.rowcount = self.rowcounts.pop(0)

    def fetchone(self):
        if self.fetchone_results:
            return self.fetchone_results.pop(0)
        return None

    def fetchall(self):
        return []


class _FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor
        self.autocommit = False
        self.committed = False
        self.rolled_back = False

    def cursor(self, *args, **kwargs):
        return self._cursor

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


def _make_db():
    return dbpg.PostgresDatabase.__new__(dbpg.PostgresDatabase)


class _ScriptedCursor:
    def __init__(self, fetchone_results=None, fail_on=None):
        self.fetchone_results = list(fetchone_results or [])
        self.fail_on = dict(fail_on or {})
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        for needle, exc in self.fail_on.items():
            if needle in sql:
                raise exc

    def fetchone(self):
        if self.fetchone_results:
            return self.fetchone_results.pop(0)
        return None


class _PoolStub:
    def __init__(self, minconn=2, maxconn=10):
        self.minconn = minconn
        self.maxconn = maxconn


def test_pg_init_sql_adds_raw_log_for_events_recent():
    events_recent_sql = dbpg.PG_INIT_SQL.split("CREATE TABLE IF NOT EXISTS events_recent", 1)[1]
    assert "raw_log       TEXT DEFAULT ''" in events_recent_sql


def test_pg_init_sql_adds_optional_user_actions_audit_table():
    user_actions_sql = dbpg.PG_INIT_SQL.split("CREATE TABLE IF NOT EXISTS user_actions", 1)[1]
    assert "id          BIGINT PRIMARY KEY" in user_actions_sql
    assert "details     JSONB DEFAULT '{}'" in user_actions_sql
    assert "CREATE INDEX IF NOT EXISTS idx_user_actions_ts" in user_actions_sql
    assert "CREATE INDEX IF NOT EXISTS idx_user_actions_action" in user_actions_sql
    assert "CREATE INDEX IF NOT EXISTS idx_user_actions_target" in user_actions_sql


def test_execute_raises_clear_import_error_when_psycopg2_missing(monkeypatch):
    db = _make_db()
    monkeypatch.setattr(dbpg, "HAS_PSYCOPG2", False)
    monkeypatch.setattr(dbpg, "psycopg2", None)

    try:
        db._execute("SELECT 1")
    except ImportError as exc:
        assert "psycopg2-binary gerekli" in str(exc)
    else:
        raise AssertionError("ImportError bekleniyordu")


def test_release_raises_clear_import_error_when_psycopg2_missing(monkeypatch):
    db = _make_db()
    monkeypatch.setattr(dbpg, "HAS_PSYCOPG2", False)
    monkeypatch.setattr(dbpg, "psycopg2", None)

    try:
        db._release(object())
    except ImportError as exc:
        assert "psycopg2-binary gerekli" in str(exc)
    else:
        raise AssertionError("ImportError bekleniyordu")


def test_run_migrations_does_not_mark_schema_current_when_ddl_fails(monkeypatch):
    db = _make_db()
    statements = [
        "CREATE TABLE ok_table (id INTEGER)",
        "CREATE TABLE broken_table (id INTEGER)",
    ]
    conns = [
        _FakeConn(_ScriptedCursor()),
        _FakeConn(_ScriptedCursor(fail_on={"broken_table": RuntimeError("ddl boom")})),
    ]
    released = []
    db._pool = _PoolStub()
    db._iter_init_statements = lambda: list(statements)
    db._conn = lambda: conns.pop(0)
    db._release = lambda c: released.append(c)

    try:
        db._run_migrations()
    except RuntimeError as exc:
        assert "schema_version güncellenmedi" in str(exc)
        assert "ddl boom" in str(exc)
    else:
        raise AssertionError("RuntimeError bekleniyordu")

    assert len(released) == 2
    assert released[0].committed is True
    assert released[1].rolled_back is True
    executed_sql = [sql for conn in released for sql, _ in conn._cursor.executed]
    assert not any("INSERT INTO schema_version" in sql for sql in executed_sql)


def test_health_check_reports_missing_critical_table_as_incomplete():
    db = _make_db()
    cursor = _ScriptedCursor(fetchone_results=[("alerts",), (None,), (5,), (dbpg.CURRENT_VERSION,)])
    conn = _FakeConn(cursor)
    released = []
    db._pool = _PoolStub()
    db._conn = lambda: conn
    db._release = lambda c: released.append(c)

    original_tables = dbpg.CRITICAL_SCHEMA_TABLES
    dbpg.CRITICAL_SCHEMA_TABLES = ("alerts", "incidents")
    try:
        health = db.health_check()
    finally:
        dbpg.CRITICAL_SCHEMA_TABLES = original_tables

    assert health["ok"] is False
    assert health["status"] == "schema_incomplete"
    assert health["missing_tables"] == ["incidents"]
    assert health["schema_version"] == dbpg.CURRENT_VERSION
    assert conn.committed is True
    assert released == [conn]


def test_run_migrations_marks_schema_current_after_success():
    db = _make_db()
    statements = [
        "CREATE TABLE ok_table (id INTEGER)",
        "CREATE INDEX ok_idx ON ok_table(id)",
    ]
    ddl_conn_1 = _FakeConn(_ScriptedCursor())
    ddl_conn_2 = _FakeConn(_ScriptedCursor())
    schema_cursor = _ScriptedCursor(
        fetchone_results=[("schema_version",), ("alerts",), (0,)]
    )
    schema_conn = _FakeConn(schema_cursor)
    released = []
    conns = [ddl_conn_1, ddl_conn_2, schema_conn]
    db._pool = _PoolStub()
    db._iter_init_statements = lambda: list(statements)
    db._conn = lambda: conns.pop(0)
    db._release = lambda c: released.append(c)
    db._ensure_user_actions_schema = lambda: None
    db._ensure_ip_block_actions_schema = lambda: None
    db._ensure_labels_schema = lambda: None

    original_tables = dbpg.CRITICAL_SCHEMA_TABLES
    dbpg.CRITICAL_SCHEMA_TABLES = ("schema_version", "alerts")
    try:
        db._run_migrations()
    finally:
        dbpg.CRITICAL_SCHEMA_TABLES = original_tables

    executed_sql = [sql for sql, _ in schema_cursor.executed]
    inserts = [sql for sql in executed_sql if "INSERT INTO schema_version" in sql]
    assert len(inserts) == dbpg.CURRENT_VERSION
    assert schema_conn.committed is True
    assert released == [ddl_conn_1, ddl_conn_2, schema_conn]


def test_run_migrations_skips_inline_user_actions_ddl_and_uses_safe_helper():
    db = _make_db()
    statements = [
        "CREATE TABLE IF NOT EXISTS alerts (id INTEGER)",
        "CREATE TABLE IF NOT EXISTS user_actions (id BIGINT PRIMARY KEY)",
        "CREATE INDEX IF NOT EXISTS idx_user_actions_target ON user_actions(target)",
    ]
    ddl_conn = _FakeConn(_ScriptedCursor())
    schema_cursor = _ScriptedCursor(fetchone_results=[("schema_version",), (0,)])
    schema_conn = _FakeConn(schema_cursor)
    released = []
    conns = [ddl_conn, schema_conn]
    db._pool = _PoolStub()
    db._iter_init_statements = lambda: list(statements)
    db._conn = lambda: conns.pop(0)
    db._release = lambda c: released.append(c)
    ensure_calls = []
    db._ensure_user_actions_schema = lambda: ensure_calls.append("called")
    db._ensure_ip_block_actions_schema = lambda: None
    db._ensure_labels_schema = lambda: None

    original_tables = dbpg.CRITICAL_SCHEMA_TABLES
    dbpg.CRITICAL_SCHEMA_TABLES = ("schema_version",)
    try:
        db._run_migrations()
    finally:
        dbpg.CRITICAL_SCHEMA_TABLES = original_tables

    ddl_sql = [sql for sql, _ in ddl_conn._cursor.executed]
    assert ddl_sql == ["CREATE TABLE IF NOT EXISTS alerts (id INTEGER)"]
    assert ensure_calls == ["called"]
    assert schema_conn.committed is True
    assert released == [ddl_conn, schema_conn]


def test_review_ip_block_suggestion_returns_true_only_when_row_updated():
    db = _make_db()
    calls = []

    def fake_execute(sql, params=(), fetch=None):
        calls.append((sql, params, fetch))
        return 1

    db._execute = fake_execute

    assert db.review_ip_block_suggestion(42, "blocked") is True
    assert "UPDATE ip_block_suggestions" in calls[0][0]


def test_review_ip_block_suggestion_returns_false_when_no_row_updated():
    db = _make_db()
    db._execute = lambda sql, params=(), fetch=None: 0

    assert db.review_ip_block_suggestion(999, "ignored") is False


def test_factory_reset_clears_system_config_and_preserves_schema_metadata():
    db = _make_db()
    cursor = _FakeCursor()
    conn = _FakeConn(cursor)
    released = []
    db._conn = lambda: conn
    db._release = lambda c: released.append(c)
    db._identifier_statement = lambda _template, identifier, *, allowed: f"DELETE FROM {identifier}"

    assert db.factory_reset() is True

    sqls = [sql for sql, _ in cursor.executed]
    assert "DELETE FROM system_config" in sqls
    assert "DELETE FROM system_stats" in sqls
    assert "DELETE FROM model_registry" in sqls
    assert all("schema_version" not in sql for sql in sqls)
    assert conn.committed is True
    assert conn.rolled_back is False
    assert released == [conn]


def test_factory_reset_rolls_back_when_delete_fails():
    db = _make_db()
    cursor = _ScriptedCursor(fail_on={"DELETE FROM incidents": RuntimeError("boom")})
    conn = _FakeConn(cursor)
    released = []
    db._conn = lambda: conn
    db._release = lambda c: released.append(c)
    db._identifier_statement = lambda _template, identifier, *, allowed: f"DELETE FROM {identifier}"

    assert db.factory_reset() is False

    sqls = [sql for sql, _ in cursor.executed]
    assert "DELETE FROM alerts" in sqls
    assert "DELETE FROM incidents" in sqls
    assert conn.committed is False
    assert conn.rolled_back is True
    assert released == [conn]


def test_cleanup_process_tree_uses_last_seen(monkeypatch):
    db = _make_db()
    calls = []

    def fake_execute(sql, params=(), fetch=None):
        calls.append((sql, params, fetch))
        if fetch == "one":
            return {"count": 2}
        return None

    db._execute = fake_execute

    deleted = db.cleanup_process_tree(days=7, manual=True)

    assert deleted == 2
    assert calls[0][0] == "SELECT COUNT(*) FROM process_tree WHERE last_seen < %s"
    assert calls[1][0] == "DELETE FROM process_tree WHERE last_seen < %s"


def test_cleanup_model_registry_orders_by_trained_at_when_manual_cleanup_enabled():
    db = _make_db()
    calls = []

    def fake_execute(sql, params=(), fetch=None):
        calls.append((sql, params, fetch))
        if sql == "SELECT DISTINCT model_name FROM model_registry":
            return [{"model_name": "detector"}]
        if "SELECT id FROM model_registry" in sql:
            return [{"id": 10}, {"id": 11}]
        if "DELETE FROM model_registry WHERE id = ANY(%s)" in sql:
            return None
        raise AssertionError(sql)

    db._execute = fake_execute

    deleted = db.cleanup_model_registry(keep_latest=3, manual=True)

    assert deleted == 2
    assert "ORDER BY trained_at DESC OFFSET %s" in calls[1][0]


def test_cleanup_model_registry_manual_false_is_noop():
    db = _make_db()
    calls = []
    db._execute = lambda sql, params=(), fetch=None: calls.append((sql, params, fetch))

    deleted = db.cleanup_model_registry(keep_latest=3, manual=False)

    assert deleted == 0
    assert calls == []


def test_vacuum_uses_context_managed_cursor():
    db = _make_db()
    cursor = _FakeCursor()
    conn = _FakeConn(cursor)
    released = []
    db._conn = lambda: conn
    db._release = lambda c: released.append(c)

    db.vacuum()

    assert cursor.executed == [("VACUUM ANALYZE", None)]
    assert conn.autocommit is False
    assert released == [conn]


def test_archive_old_alerts_logs_active_table_to_archive(monkeypatch):
    db = _make_db()
    cursor = _FakeCursor(fetchone_results=[(3,)], rowcounts=[2, -1, 3])
    conn = _FakeConn(cursor)
    log_messages = []
    db._conn = lambda: conn
    db._release = lambda c: None
    monkeypatch.setattr(dbpg.logger, "info", log_messages.append)

    moved = db.archive_old_alerts(days=30)

    assert moved == 3
    assert conn.committed is True
    assert cursor.executed[0][0].strip().startswith("INSERT INTO alerts_archive")
    assert cursor.executed[1][0] == "SELECT COUNT(*) FROM alerts WHERE ts < %s"
    assert cursor.executed[2][0] == "DELETE FROM alerts WHERE ts < %s"
    assert "aktif alerts tablosundan silinip arsive alindi" in log_messages[0]


def test_labels_exact_duplicate_is_ignored_and_counted_correctly():
    labels_sql = dbpg.PG_INIT_SQL.split("CREATE TABLE IF NOT EXISTS labels", 1)[1]
    assert "CREATE UNIQUE INDEX IF NOT EXISTS idx_labels_exact_unique" in labels_sql

    db = _make_db()
    cursor = _FakeCursor(rowcounts=[1, 0])
    conn = _FakeConn(cursor)
    db._conn = lambda: conn
    db._release = lambda c: None

    record = LabelRecord(
        source="auto_labeled",
        label="attack",
        category="brute_force",
        score=90.0,
        confidence=0.8,
        weight=1.0,
        entity_key="user:alice",
        distro="debian",
        ts=1710000000.0,
        ready_after=1710000300.0,
    )

    saved = db.save_labels([record, record])

    assert saved == 1
    assert "ON CONFLICT" in cursor.executed[0][0]
    assert "(source, label, category, score, confidence, weight," in cursor.executed[0][0]
    assert conn.committed is True


def test_save_labels_rejects_non_labelrecord_entries():
    db = _make_db()
    cursor = _FakeCursor()
    conn = _FakeConn(cursor)
    db._conn = lambda: conn
    db._release = lambda c: None

    try:
        db.save_labels([SimpleNamespace(source="auto_labeled")])
    except TypeError as exc:
        assert "LabelRecord bekler" in str(exc)
        assert "SimpleNamespace" in str(exc)
    else:
        raise AssertionError("TypeError bekleniyordu")

    assert conn.rolled_back is True
    assert cursor.executed == []


def test_save_labels_persists_origin_in_evidence_for_schema_compatible_hydration():
    db = _make_db()
    cursor = _FakeCursor(rowcounts=[1])
    conn = _FakeConn(cursor)
    db._conn = lambda: conn
    db._release = lambda c: None

    record = LabelRecord(
        source="auto_labeled",
        label="attack",
        category="webshell",
        score=88.0,
        confidence=0.82,
        weight=0.82,
        entity_key="198.51.100.99",
        distro="debian",
        ts=1710000001.0,
        ready_after=1710000301.0,
        origin="organic_live",
        evidence_fields={"ml_family": "ML-WEBPOST"},
    )

    saved = db.save_labels([record])

    assert saved == 1
    params = cursor.executed[0][1]
    evidence_json = params[20]
    evidence_payload = getattr(evidence_json, "adapted", None) or getattr(evidence_json, "obj", None)
    assert evidence_payload["origin"] == "organic_live"
    assert evidence_payload["ml_family"] == "ML-WEBPOST"


def test_load_labels_hydrates_origin_from_evidence_fields_when_schema_has_no_origin_column():
    db = _make_db()
    db._execute = lambda sql, params=(), fetch=None: [
        {
            "id": 1,
            "source": "auto_labeled",
            "label": "attack",
            "category": "webshell",
            "evidence_fields": {"origin": "organic_live", "ml_family": "ML-WEBPOST"},
        }
    ]

    rows = db.load_labels()

    assert rows[0]["origin"] == "organic_live"
    assert rows[0]["ml_family"] == "ML-WEBPOST"


def test_is_in_cooldown_uses_single_connection_and_cursor():
    db = _make_db()
    cursor = _FakeCursor(fetchone_results=[(42,)])
    conn = _FakeConn(cursor)
    releases = []
    db._conn = lambda: conn
    db._release = lambda c: releases.append(c)

    in_cooldown = db.is_in_cooldown("RULE-1", "entity-1")

    assert in_cooldown is True
    assert len(cursor.executed) == 2
    assert cursor.executed[0][0] == "DELETE FROM cooldowns WHERE expires_at < %s"
    assert cursor.executed[1][0] == "SELECT id FROM cooldowns WHERE rule_id=%s AND entity_key=%s"
    assert conn.committed is True
    assert releases == [conn]


def test_update_incident_rejects_unknown_keys_and_whitelists_allowed_fields():
    db = _make_db()
    calls = []
    db._execute = lambda sql, params=(), fetch=None: calls.append((sql, params, fetch))

    ok = db.update_incident(7, {"status": "closed", "summary": "done", "tags": ["x"]})

    assert ok is True
    assert calls[0][0] == "UPDATE incidents SET status=%s, summary=%s, tags=%s WHERE id=%s"
    assert calls[0][1] == ("closed", "done", '["x"]', 7)

    try:
        db.update_incident(7, {"bogus_field": 1})
    except ValueError as exc:
        assert "bogus_field" in str(exc)
    else:
        raise AssertionError("ValueError bekleniyordu")


def test_identifier_statement_rejects_malicious_table_names(monkeypatch):
    db = _make_db()
    db._require_psycopg2 = lambda: None
    monkeypatch.setattr(dbpg, "psycopg2_sql", object())

    for token in ("alerts; DROP TABLE alerts;--", "../alerts", "alerts where 1=1"):
        try:
            db._identifier_statement("DELETE FROM {}", token, allowed=("alerts", "incidents"))
        except ValueError as exc:
            assert "unsafe_sql_identifier" in str(exc)
        else:
            raise AssertionError("ValueError bekleniyordu")


def test_execute_without_fetch_returns_rowcount_not_lastrowid():
    db = _make_db()
    db._require_psycopg2 = lambda: None
    original_psycopg2 = dbpg.psycopg2
    dbpg.psycopg2 = type(
        "_FakePsycopg2",
        (),
        {"extras": type("_FakeExtras", (), {"RealDictCursor": object})},
    )()
    cursor = _FakeCursor(rowcounts=[7])
    cursor.lastrowid = 999
    conn = _FakeConn(cursor)
    released = []
    db._conn = lambda: conn
    db._release = lambda c: released.append(c)

    try:
        result = db._execute("UPDATE alerts SET severity=%s", ("high",))
    finally:
        dbpg.psycopg2 = original_psycopg2

    assert result == 7
    assert conn.committed is True
    assert released == [conn]


def test_get_report_stats_queries_real_top_users_summary():
    db = _make_db()
    calls = []

    def fake_execute(sql, params=(), fetch=None):
        normalized = " ".join(sql.split())
        calls.append((normalized, params, fetch))
        if normalized == "SELECT COUNT(*) FROM alerts WHERE ts >= %s":
            return {"count": 5}
        if normalized == "SELECT severity, COUNT(*) FROM alerts WHERE ts >= %s GROUP BY severity":
            return [{"severity": "high", "count": 3}]
        if "SELECT rule_id, COUNT(*) AS cnt FROM alerts" in normalized:
            return [{"rule_id": "R-1", "cnt": 2}]
        if "SELECT entity, COUNT(*) AS cnt FROM alerts" in normalized:
            return [{"entity": "user:alice", "cnt": 2}]
        if "SELECT host, COUNT(*) AS cnt FROM alerts" in normalized:
            return [{"host": "srv-1", "cnt": 4}]
        if normalized == "SELECT COUNT(*) FROM incidents WHERE ts_start >= %s":
            return {"count": 1}
        if "SELECT status, COUNT(*) FROM incidents" in normalized:
            return [{"status": "open", "count": 1}]
        if "SELECT EXTRACT(HOUR FROM to_timestamp(ts))::int AS h, COUNT(*) AS cnt" in normalized:
            return [{"h": 3, "cnt": 2}]
        if "SELECT username, COUNT(*) AS cnt FROM events_recent" in normalized:
            return [{"username": "alice", "cnt": 6}, {"username": "root", "cnt": 2}]
        raise AssertionError(normalized)

    db._execute = fake_execute

    stats = db.get_report_stats(1700000000.0)

    assert stats["top_users"] == [("alice", 6), ("root", 2)]
    assert any("FROM events_recent" in sql for sql, _, _ in calls)


def test_database_postgres_uses_direct_time_calls_for_runtime_helpers():
    source = open(dbpg.__file__, "r", encoding="utf-8").read()

    assert "__import__('time').time()" not in source


def test_database_abstract_interface_matches_postgres_public_contract():
    expected = {
        "save_cross_host_state": ("ip_to_hosts",),
        "load_cross_host_state": ("ttl",),
        "cleanup_cross_host_state": ("ttl",),
        "save_entity_risk_state": ("entity_state",),
        "load_entity_risk_state": ("max_age_seconds",),
        "save_labels": ("records",),
        "load_labels": ("distro",),
        "cleanup_labels": ("days", "manual"),
        "run_full_cleanup": (),
        "delete_old_alerts": ("days",),
        "analyze": (),
        "get_stats": (),
        "log_action": ("action", "status", "actor", "screen", "entity_type", "entity_id", "target", "summary", "details"),
        "get_recent_user_actions": ("limit",),
    }

    for method_name, expected_params in expected.items():
        assert hasattr(Database, method_name)
        assert hasattr(dbpg.PostgresDatabase, method_name)

        base_sig = signature(getattr(Database, method_name))
        pg_sig = signature(getattr(dbpg.PostgresDatabase, method_name))

        assert tuple(base_sig.parameters.keys())[1:] == expected_params
        assert tuple(pg_sig.parameters.keys())[1:] == expected_params


def test_log_action_writes_user_actions_row():
    db = _make_db()
    calls = []
    db._execute = lambda sql, params=(), fetch=None: calls.append((sql, params, fetch))

    db.log_action(
        action="archive_alert",
        status="ok",
        actor="terminal",
        screen="alerts",
        entity_type="alert",
        entity_id="42",
        target="AUTH-001",
        summary="Archived alert",
        details={"rule_id": "AUTH-001"},
    )

    assert "INSERT INTO user_actions" in calls[0][0]
    assert calls[0][1][1:9] == (
        "archive_alert",
        "ok",
        "terminal",
        "alerts",
        "alert",
        "42",
        "AUTH-001",
        "Archived alert",
    )


def test_get_recent_user_actions_returns_rows_as_dicts():
    db = _make_db()
    db._execute = lambda sql, params=(), fetch=None: [
        {"action": "archive_alert", "status": "ok", "actor": "terminal"},
        {"action": "delete_alert", "status": "ok", "actor": "terminal"},
    ]

    rows = db.get_recent_user_actions(limit=2)

    assert rows == [
        {"action": "archive_alert", "status": "ok", "actor": "terminal"},
        {"action": "delete_alert", "status": "ok", "actor": "terminal"},
    ]
