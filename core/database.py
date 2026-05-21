"""
core/database.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DB Abstraction Katmani — v2.2

Mimari:
  Database (abstract interface)
  └── PostgresDatabase (core/database_postgres.py) — tek desteklenen backend

NOT: Bu proje PostgreSQL-only'dir. SQLite, WAL mode, busy_timeout
gibi kavramlar gecerli degildir — bu dosya sadece abstract interface
tanimlar, runtime implementasyonu database_postgres.py'dedir.

Config:
  database:
    url: postgresql://user:pass@host/db
  veya env: DATABASE_URL=postgresql://user:pass@host/db

Migration:
  MIGRATIONS dict — her key bir versiyon, value SQL string.
  PostgreSQL ALTER TABLE IF NOT EXISTS ile guvenli uygulanir.
  CURRENT_VERSION = max(MIGRATIONS.keys()) ile otomatik hesaplanir.
"""

import os
import time
import json
import queue
import logging
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)


def _normalize_alert_row(row: Dict) -> Dict:
    """
    Alert satırını normalize et — her iki backend'de aynı Python tipi dönsün.

    PostgreSQL: JSONB olarak gelir → zaten dict/list

    Uygulama katmanı her zaman dict/list bekler.
    """
    if not row:
        return row
    result = dict(row)

    # context_json — convert to dict when stored as a str
    ctx = result.get("context_json")
    if isinstance(ctx, str):
        try:
            result["context_json"] = json.loads(ctx) if ctx else {}
        except (json.JSONDecodeError, ValueError):
            result["context_json"] = {}

    # tags — convert to list when stored as a str
    tags = result.get("tags")
    if isinstance(tags, str):
        try:
            result["tags"] = json.loads(tags) if tags else []
        except (json.JSONDecodeError, ValueError):
            result["tags"] = []

    return result


# ── Schema Version ─────────────────────────────────────────────────────
#
# Bug #2 fix:
#   The old code defined MIGRATIONS = {1: "... AUTOINCREMENT ..."} using SQLite-specific
#   SQL in a dict and derived CURRENT_VERSION = max(MIGRATIONS.keys())
#   from that dict.
#
#   Ancak proje PostgreSQL-only'dir (bkz. database_postgres.py / PG_INIT_SQL).
#   The MIGRATIONS dict was never executed; it only served as the source
#   for CURRENT_VERSION. That was misleading and also carried invalid SQL syntax
#   such as AUTOINCREMENT and strftime, which are SQLite-specific.
#
#   The real schema is defined in PG_INIT_SQL inside database_postgres.py.
#   The ALTER TABLE statements in MIGRATIONS[7-11] (Postgres-compatible) were also
#   moved into PG_INIT_SQL, and _run_migrations() already uses PG_INIT_SQL.
#
#
#   New design: CURRENT_VERSION is a fixed int and no longer depends on a stale dict
#   for versioning. When a new schema change is made, update both this value and PG_INIT_SQL
#   together.
#
CURRENT_VERSION: int = 15

# Temel migration/versioning iskeleti:
# Yeni bir DB degisikligi geldiginde bu tabloya aciklama eklenir ve
# CURRENT_VERSION ile birlikte guncellenir.
#
# v1-v10 gecmisi: Eski MIGRATIONS dict'inden ve database_postgres.py
# Re-documented from the table definitions in PG_INIT_SQL.
# (Eski dict SQLite-spesifik SQL iceriyordu ve hic execute edilmiyordu;
#  gercek degisiklikler PG_INIT_SQL'e entegre edildi.)
SCHEMA_CHANGELOG: Dict[int, Dict[str, Any]] = {
    1: {
        "name": "initial_schema",
        "description": "alerts, incidents, entity_state, cooldowns, dedup_cache temel tablolar",
        "requires_restart": False,
    },
    2: {
        "name": "model_registry",
        "description": "model_registry tablosu eklendi — ML model versiyon takibi",
        "requires_restart": False,
    },
    3: {
        "name": "risk_history",
        "description": "risk_history tablosu eklendi — entity risk skoru geçmişi",
        "requires_restart": False,
    },
    4: {
        "name": "system_stats",
        "description": "system_stats tablosu eklendi — anahtar/değer sistem sayaçları",
        "requires_restart": False,
    },
    5: {
        "name": "sequence_state",
        "description": "sequence_state tablosu eklendi — çok adımlı zincir durumu kalıcı hale getirildi",
        "requires_restart": False,
    },
    6: {
        "name": "process_tree",
        "description": "process_tree tablosu eklendi — ebeveyn/çocuk süreç ilişkisi",
        "requires_restart": False,
    },
    7: {
        "name": "alerts_archive_and_events_recent",
        "description": "alerts_archive (uzun süreli arşiv) ve events_recent (kısa pencere) tabloları eklendi",
        "requires_restart": False,
    },
    8: {
        "name": "phase_history_and_cross_host",
        "description": "phase_history (faz geçiş geçmişi) ve cross_host_state (çapraz host korelasyon) tabloları eklendi",
        "requires_restart": False,
    },
    9: {
        "name": "ml_control_log_and_config",
        "description": "ml_control_log (ML açma/kapama denetim kaydı) ve system_config tabloları eklendi",
        "requires_restart": False,
    },
    10: {
        "name": "labels_table",
        "description": "labels tablosu eklendi — LabelEngine bootstrap/auto_labeled/manually_verified kayıtları",
        "requires_restart": False,
    },
    11: {
        "name": "postgresql_unified_schema",
        "description": "PostgreSQL-only unified schema baseline; SQLite kodu tamamen kaldırıldı",
        "requires_restart": False,
    },
    12: {
        "name": "ip_block_suggestions",
        "description": "ip_block_suggestions tablosu eklendi — AbuseIPDB sorgulama ve manuel engelleme önerileri",
        "requires_restart": False,
    },
    13: {
        "name": "user_actions_audit",
        "description": "Opsiyonel Action History audit tablosu user_actions eklendi",
        "requires_restart": False,
    },
    14: {
        "name": "labels_shadow_metadata",
        "description": "labels tablosuna canonical behavior shadow metadata kolonlari eklendi",
        "requires_restart": False,
    },
    15: {
        "name": "ip_block_actions",
        "description": "ip_block_actions tablosu eklendi — gerçek manual block/unblock execution state ve audit bağlantısı",
        "requires_restart": False,
    },
}

# Empty dict kept for backward-compatible imports (database_postgres.py imports it)
MIGRATIONS: dict = {}


def get_schema_manifest() -> Dict[str, Any]:
    """Return the schema-version metadata known to the application."""
    return {
        "current_version": CURRENT_VERSION,
        "versions": {ver: dict(meta) for ver, meta in sorted(SCHEMA_CHANGELOG.items())},
    }


def get_pending_schema_versions(current_version: int) -> List[Dict[str, Any]]:
    """Return metadata for schema versions that the DB still lags behind."""
    pending = []
    for ver, meta in sorted(SCHEMA_CHANGELOG.items()):
        if ver > current_version:
            row = dict(meta)
            row["version"] = ver
            pending.append(row)
    return pending


# ── Abstract Interface ────────────────────────────────────────────────────────

class Database(ABC):
    """
    Tüm DB işlemleri bu interface üzerinden yapılır.
    Uygulama kodu veritabanı implementasyonunu bilmez.
    """

    # ── Alert ─────────────────────────────────────────────────────────────────
    @abstractmethod
    def insert_alert(self, alert: Dict) -> Optional[int]: ...

    @abstractmethod
    def get_recent_alerts(self, limit: int = 100, hours: float = 24) -> List[Dict]: ...

    @abstractmethod
    def get_alert_by_id(self, alert_id: int) -> Optional[Dict]: ...

    @abstractmethod
    def get_alert_count(self, hours: float = 1) -> int: ...

    @abstractmethod
    def get_rule_stats(self, limit: int = 50, hours: float = 168) -> List[Dict]: ...

    @abstractmethod
    def get_never_fired_rules(self, all_rule_ids: List[str],
                               hours: float = 168) -> List[str]: ...

    @abstractmethod
    def get_top_entities(self, hours: float = 24, limit: int = 10) -> List[Dict]: ...

    # ── Incident ──────────────────────────────────────────────────────────────
    @abstractmethod
    def insert_incident(self, incident: Dict) -> Optional[int]: ...

    @abstractmethod
    def update_incident(self, incident_id: int, updates: Dict) -> bool: ...

    @abstractmethod
    def get_open_incidents(self) -> List[Dict]: ...

    @abstractmethod
    def get_closed_incidents(self, since_hours: int = 24) -> List[Dict]: ...

    # ── Entity State ──────────────────────────────────────────────────────────
    @abstractmethod
    def is_first_seen(self, entity_type: str, entity_key: str) -> bool: ...

    @abstractmethod
    def mark_seen(self, entity_type: str, entity_key: str) -> None: ...

    @abstractmethod
    def get_entity_state(self, entity_type: str, entity_key: str) -> Optional[Dict]: ...

    @abstractmethod
    def set_entity_state(self, entity_type: str, entity_key: str, metadata: Dict) -> None: ...

    # ── Cooldown ──────────────────────────────────────────────────────────────
    @abstractmethod
    def is_in_cooldown(self, rule_id: str, entity_key: str = "") -> bool: ...

    @abstractmethod
    def set_cooldown(self, rule_id: str, entity_key: str = "", seconds: int = 300) -> None: ...

    # ── Dedup ─────────────────────────────────────────────────────────────────
    @abstractmethod
    def is_duplicate(self, hash_str: str) -> bool: ...

    @abstractmethod
    def mark_hash(self, hash_str: str) -> None: ...

    # ── Events ────────────────────────────────────────────────────────────────
    @abstractmethod
    def insert_event(self, event_summary: Dict = None, **kwargs) -> None: ...

    # ── Sequence ──────────────────────────────────────────────────────────────
    @abstractmethod
    def get_sequence_state(self, entity: str, seq_id: str) -> Optional[Dict]: ...

    @abstractmethod
    def set_sequence_state(self, entity: str, seq_id: str, step: int, ts: float) -> None: ...

    @abstractmethod
    def delete_sequence_state(self, entity: str, seq_id: str) -> None: ...

    @abstractmethod
    def cleanup_sequence_states(self, timeout: float) -> None: ...

    # ── Process Tree ──────────────────────────────────────────────────────────
    @abstractmethod
    def update_process_tree(self, parent: str, child: str) -> None: ...

    @abstractmethod
    def get_process_children(self, parent: str) -> List[Dict]: ...

    @abstractmethod
    def is_new_process_pair(self, parent: str, child: str, min_seen: int = 5) -> bool: ...

    # ── Dedup cleanup ─────────────────────────────────────────────────────────
    @abstractmethod
    def cleanup_dedup_cache(self, hours: int = 48) -> int: ...

    @abstractmethod
    def cleanup_events_recent(self, days: int = 14) -> int: ...

    @abstractmethod
    def cleanup_risk_history(self, days: int = 30) -> int: ...

    # ── Report queries (public — PostgreSQL uyumlu) ───────────────────────────
    @abstractmethod
    def get_report_stats(self, since: float) -> Dict: ...

    # ── System Stats ──────────────────────────────────────────────────────────
    @abstractmethod
    def get_stat(self, key: str) -> Optional[str]: ...

    @abstractmethod
    def set_stat(self, key: str, value: str) -> None: ...

    # ── User Action Audit ────────────────────────────────────────────────────
    @abstractmethod
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
    ) -> None: ...

    @abstractmethod
    def get_recent_user_actions(self, limit: int = 100) -> List[Dict]: ...

    # ── ML Control ────────────────────────────────────────────────────────────
    @abstractmethod
    def log_ml_control(self, action: str, reason: str = "",
                       actor: str = "auto", source: str = "") -> None: ...

    @abstractmethod
    def get_ml_control_log(self, limit: int = 50) -> List[Dict]: ...

    # ── Health ────────────────────────────────────────────────────────────────
    @abstractmethod
    def health_check(self) -> Dict: ...

    # ── Archive ───────────────────────────────────────────────────────────────
    @abstractmethod
    def archive_old_alerts(self, days: int = 30) -> int: ...

    @abstractmethod
    def delete_old_alerts(self, days: int = 30) -> int: ...

    @abstractmethod
    def vacuum(self) -> None: ...

    @abstractmethod
    def analyze(self) -> None: ...

    # ── Cross-host State ─────────────────────────────────────────────────────
    @abstractmethod
    def save_cross_host_state(self, ip_to_hosts: dict) -> None: ...

    @abstractmethod
    def load_cross_host_state(self, ttl: float = 3600.0) -> dict: ...

    @abstractmethod
    def cleanup_cross_host_state(self, ttl: float = 3600.0) -> int: ...

    # ── Runtime / Summary helpers ────────────────────────────────────────────
    @abstractmethod
    def get_stats(self) -> dict: ...

    # ── Entity Risk Persist ──────────────────────────────────────────────────
    @abstractmethod
    def save_entity_risk_state(self, entity_state: dict) -> None: ...

    @abstractmethod
    def load_entity_risk_state(self, max_age_seconds: float = 604800.0) -> dict: ...

    # ── Labels ───────────────────────────────────────────────────────────────
    @abstractmethod
    def save_labels(self, records: list) -> int: ...

    @abstractmethod
    def load_labels(self, distro: str = "") -> list: ...

    @abstractmethod
    def cleanup_labels(self, days: int = 180, manual: bool = False) -> int: ...

    @abstractmethod
    def backfill_legacy_bootstrap_label_metadata(self, updates: list[dict]) -> int: ...

    # ── Full cleanup ─────────────────────────────────────────────────────────
    @abstractmethod
    def run_full_cleanup(self) -> dict: ...

    # ── IP Block Suggestions ──────────────────────────────────────────────────
    @abstractmethod
    def add_ip_block_suggestion(self, ip: str, reason: str = "",
                                 source: str = "alert", alert_id: int = None,
                                 abuse_score: int = None, abuse_reports: int = None,
                                 abuse_country: str = "", abuse_raw: dict = None) -> Optional[int]: ...

    @abstractmethod
    def get_ip_block_suggestions(self, reviewed: bool = False,
                                  limit: int = 100) -> List[Dict]: ...

    @abstractmethod
    def get_ip_reputation_for_alert(self, alert_id: int) -> List[Dict]: ...

    @abstractmethod
    def review_ip_block_suggestion(self, suggestion_id: int, action: str) -> bool: ...

    @abstractmethod
    def get_blocked_ips(self) -> List[str]: ...

    @abstractmethod
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
        suggestion_id: Optional[int] = None,
    ) -> Optional[int]: ...

    @abstractmethod
    def get_ip_block_actions(self, ip: str = "", limit: int = 100) -> List[Dict]: ...

    @abstractmethod
    def get_active_ip_block(self, ip: str) -> Optional[Dict]: ...


# ── Factory ───────────────────────────────────────────────────────────────────

def create_database(config=None):
    """
    PostgreSQL backend olustur.

    config:
      database:
        type: postgresql
        url: postgresql://user:pass@host/db

    veya env:
      DATABASE_URL=postgresql://...
      AEGISCORE_DB_URL=postgresql://...   (alternatif)

    URL yoksa None döner — ensure_database() bunu RuntimeError'a çevirir.
    """
    import os as _os2
    cfg    = config or {}
    db_cfg = cfg.get("database", cfg.get("storage", {}))
    url    = (
        db_cfg.get("url") or
        _os2.environ.get("DATABASE_URL", "") or
        _os2.environ.get("AEGISCORE_DB_URL", "")
    ).strip()

    if not url:
        return None   # URL yok — ensure_database() RuntimeError fırlatacak

    from .database_postgres import PostgresDatabase
    return PostgresDatabase(url)

# ── Database alias ────────────────────────────────────────────────────────────
try:
    from .database_postgres import PostgresDatabase
    SiemDatabase = PostgresDatabase
except ImportError:
    SiemDatabase = None  # type: ignore
