"""
core/phase_manager.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
System phase manager

Controls which detection layers are active and advances automatically
based on data maturity.

PHASE_0 -> PHASE_1 -> PHASE_2 -> PHASE_3
  Rules    +InstantML   +Baseline    +Mature Baseline
  (now)    (300 logs)   (3000 logs)  (5000+ logs)

Phase-transition criteria:
  - min_events       : total event count
  - min_hours/days   : elapsed time
  - min_users        : unique users observed
  - min_sources      : number of distinct log sources (diversity)
  - min_user_events  : minimum activity per user
  - min_continuity   : data continuity ratio (0.0-1.0)
  - max_dup_rate     : maximum duplicate/corrupt-record ratio
"""

import time
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, List, Mapping, Callable
from dataclasses import dataclass, field
from enum import IntEnum
from collections import defaultdict

logger = logging.getLogger(__name__)

DEFAULT_PHASE_SAVE_INTERVAL = 100
DEFAULT_BREAKDOWN_LIMIT = 8
DEFAULT_PARSE_FAIL_SAMPLE_LIMIT = 8
DEFAULT_LIVE_COUNT_DELTA_FLOOR = 25
DEFAULT_LIVE_COUNT_DELTA_RATIO = 0.15

_PHASE_COUNT_SQL = {
    "events_recent": "SELECT COUNT(*) AS count FROM events_recent",
    "dedup_cache": "SELECT COUNT(*) AS count FROM dedup_cache",
}


def compute_data_quality_metrics(
    *,
    total_events: int = 0,
    duplicate_count: int = 0,
    telemetry_duplicate_count: int = 0,
    parse_fail_count: int = 0,
) -> Dict[str, float | int]:
    """Canonical duplicate/data-quality metrics shared across runtime and UI."""
    total_events = max(0, int(total_events or 0))
    duplicate_count = max(0, int(duplicate_count or 0))
    telemetry_duplicate_count = max(0, int(telemetry_duplicate_count or 0))
    parse_fail_count = max(0, int(parse_fail_count or 0))
    quality_penalty_count = duplicate_count + parse_fail_count
    quality_seen_total = total_events + quality_penalty_count + telemetry_duplicate_count
    duplicate_rate = (quality_penalty_count / quality_seen_total) if quality_seen_total > 0 else 0.0
    parse_fail_rate = (parse_fail_count / quality_seen_total) if quality_seen_total > 0 else 0.0
    return {
        "quality_penalty_count": quality_penalty_count,
        "quality_seen_total": quality_seen_total,
        "duplicate_rate": duplicate_rate,
        "parse_fail_rate": parse_fail_rate,
    }


# -- Phase Definitions -------------------------------------------------------

class Phase(IntEnum):
    PHASE_0 = 0   # Rules/signatures/IOC only — available immediately
    PHASE_1 = 1   # + Instant ML (IF, PCA, kNN)
    PHASE_2 = 2   # + Baseline learning (user/service profile)
    PHASE_3 = 3   # + Mature baseline and stricter data-maturity checks

PHASE_NAMES = {
    Phase.PHASE_0: "Kural Motoru",
    Phase.PHASE_1: "Instant ML",
    Phase.PHASE_2: "Baseline + Davranış",
    Phase.PHASE_3: "Olgun Baseline",
}

PHASE_DESCRIPTIONS = {
    Phase.PHASE_0: "Rule/Regex/IOC/Threshold — bilinen saldırıları anında yakalar",
    Phase.PHASE_1: "Isolation Forest + PCA + kNN ile genel anomali tespiti eklendi",
    Phase.PHASE_2: "Kullanıcı/root/servis/process davranış profili öğrenildi",
    Phase.PHASE_3: "Baseline katmanları tam olgunluk eşiğine ulaştı",
}

# Active layers for each phase
PHASE_ACTIVE_LAYERS = {
    Phase.PHASE_0: {
        "rules":        True,
        "regex":        True,
        "ioc":          True,
        "threshold":    True,
        "first_seen":   True,
        "rarity":       False,
        "instant_ml":   False,
        "calibration":  False,
        "baseline":     False,
        "correlation":  True,
        "risk":         True,
        "incident":     True,
    },
    Phase.PHASE_1: {
        "rules":        True,
        "regex":        True,
        "ioc":          True,
        "threshold":    True,
        "first_seen":   True,
        "rarity":       True,
        "instant_ml":   True,
        "calibration":  True,
        "baseline":     False,
        "correlation":  True,
        "risk":         True,
        "incident":     True,
    },
    Phase.PHASE_2: {
        "rules":        True,
        "regex":        True,
        "ioc":          True,
        "threshold":    True,
        "first_seen":   True,
        "rarity":       True,
        "instant_ml":   True,
        "calibration":  True,
        "baseline":     True,
        "correlation":  True,
        "risk":         True,
        "incident":     True,
    },
    Phase.PHASE_3: {
        "rules":        True,
        "regex":        True,
        "ioc":          True,
        "threshold":    True,
        "first_seen":   True,
        "rarity":       True,
        "instant_ml":   True,
        "calibration":  True,
        "baseline":     True,
        "correlation":  True,
        "risk":         True,
        "incident":     True,
    },
}

# Expected log sources for diversity checks
CORE_SOURCES = {"auth", "process", "network", "system"}


# ── Phase Transition Conditions ────────────────────────────────────────

@dataclass
class PhaseThresholds:
    """Minimum required values for each phase."""
    # PHASE_0 → PHASE_1
    p1_min_events:      int   = 300
    p1_min_hours:       float = 1.0
    p1_min_sources:     int   = 2      # en az 2 farklı log kaynağı
    p1_max_dup_rate:    float = 0.20   # %20'den az duplicate

    # PHASE_1 → PHASE_2
    p2_min_events:      int   = 5000
    p2_min_days:        float = 3.0
    p2_min_users:       int   = 2
    p2_min_sources:     int   = 3      # en az 3 farklı log kaynağı
    p2_min_user_events: int   = 100    # kullanıcı başına min aktivite
    p2_min_continuity:  float = 0.70   # %70 veri sürekliliği
    p2_max_dup_rate:    float = 0.10   # %10'dan az duplicate

    # PHASE_2 → PHASE_3
    p3_min_events:      int   = 20000
    p3_min_days:        float = 7.0
    p3_min_users:       int   = 3
    p3_min_sources:     int   = 3      # en az 3 farklı log kaynağı
    p3_min_user_events: int   = 300    # kullanıcı başına min aktivite
    p3_min_continuity:  float = 0.80   # %80 veri sürekliliği
    p3_max_dup_rate:    float = 0.05   # %5'ten az duplicate


# ── System Statistics ──────────────────────────────────────────────────

@dataclass
class SystemStats:
    total_events:       int   = 0
    unique_users:       int   = 0
    unique_ips:         int   = 0
    start_time:         float = 0.0
    last_save:          float = 0.0
    current_phase:      int   = 0
    duplicate_count:    int   = 0
    telemetry_duplicate_count: int = 0
    parse_fail_count:   int   = 0
    duplicate_breakdown_by_source: Dict = None
    duplicate_breakdown_by_kind: Dict = None
    parse_fail_breakdown_by_source: Dict = None
    parse_fail_breakdown_by_reason: Dict = None
    parse_fail_breakdown_by_parser: Dict = None
    parse_fail_breakdown_by_distro: Dict = None
    parse_fail_breakdown_by_path: Dict = None
    parse_fail_samples: List[Dict[str, str]] = None

    # Progress tracking
    seen_users:         Dict  = None
    seen_ips:           Dict  = None

    # Log diversity — source → event count
    source_counts:      Dict  = None   # {"auth": 1200, "process": 300, ...}

    # Activity per user
    user_event_counts:  Dict  = None   # {"alice": 450, "root": 120, ...}

    # Data continuity — daily event presence
    daily_counts:       Dict  = None   # {"2025-03-01": 1200, ...}

    def __post_init__(self):
        if self.seen_users       is None: self.seen_users       = {}
        if self.seen_ips         is None: self.seen_ips         = {}
        if self.source_counts    is None: self.source_counts    = {}
        if self.user_event_counts is None: self.user_event_counts = {}
        if self.daily_counts     is None: self.daily_counts     = {}
        if self.duplicate_breakdown_by_source is None: self.duplicate_breakdown_by_source = {}
        if self.duplicate_breakdown_by_kind   is None: self.duplicate_breakdown_by_kind   = {}
        if self.parse_fail_breakdown_by_source is None: self.parse_fail_breakdown_by_source = {}
        if self.parse_fail_breakdown_by_reason is None: self.parse_fail_breakdown_by_reason = {}
        if self.parse_fail_breakdown_by_parser is None: self.parse_fail_breakdown_by_parser = {}
        if self.parse_fail_breakdown_by_distro is None: self.parse_fail_breakdown_by_distro = {}
        if self.parse_fail_breakdown_by_path is None: self.parse_fail_breakdown_by_path = {}
        if self.parse_fail_samples is None: self.parse_fail_samples = []
        if self.start_time == 0.0:
            self.start_time = time.time()

    def _bounded_increment(self, bucket: Dict, key: str, limit: int = DEFAULT_BREAKDOWN_LIMIT) -> None:
        key = str(key or "unknown")
        bucket[key] = int(bucket.get(key, 0) or 0) + 1
        if len(bucket) <= limit:
            return
        trimmed = sorted(bucket.items(), key=lambda item: (-int(item[1]), str(item[0])))[:limit]
        bucket.clear()
        bucket.update(trimmed)

    @property
    def uptime_hours(self) -> float:
        return (time.time() - self.start_time) / 3600

    @property
    def uptime_days(self) -> float:
        return self.uptime_hours / 24

    @property
    def dup_rate(self) -> float:
        """Phase quality ratio: real duplicate plus parse-failure contribution.

        Numerator:
          - duplicate_count: ingest edilen ama yinelenen kayıtlar
          - parse_fail_count: parse edilemeyip veri kalitesini düşüren kayıtlar

        Denominator:
          - total_events: başarıyla işlenen eventler
          - quality penalty: duplicate + parse_fail kayıtları
          - telemetry_duplicate_count: cross-source telemetry gölgeleri

        Telemetry shadow kopyaları numerator'a girmez; çünkü veri kalitesi
        problemi değil, korelasyon yan ürünü sayılır. Ancak toplam görülen
        akışı temsil etmesi için denominator'da tutulur.
        """
        metrics = compute_data_quality_metrics(
            total_events=self.total_events,
            duplicate_count=self.duplicate_count,
            telemetry_duplicate_count=self.telemetry_duplicate_count,
            parse_fail_count=self.parse_fail_count,
        )
        return float(metrics["duplicate_rate"])

    @property
    def quality_penalty_count(self) -> int:
        """Total quality loss included in the phase duplicate ratio."""
        return int(
            compute_data_quality_metrics(
                total_events=self.total_events,
                duplicate_count=self.duplicate_count,
                telemetry_duplicate_count=self.telemetry_duplicate_count,
                parse_fail_count=self.parse_fail_count,
            )["quality_penalty_count"]
        )

    @property
    def quality_seen_total(self) -> int:
        """Total observed flow used for the duplicate ratio.

        Parse fail kayıtları evente dönüşmese de ingest bütçesini tükettiği
        için toplam görülen akışa dahil edilir.
        """
        return int(
            compute_data_quality_metrics(
                total_events=self.total_events,
                duplicate_count=self.duplicate_count,
                telemetry_duplicate_count=self.telemetry_duplicate_count,
                parse_fail_count=self.parse_fail_count,
            )["quality_seen_total"]
        )

    @property
    def active_sources(self) -> int:
        """Return how many distinct log sources produced data."""
        return len(self.source_counts)

    @property
    def min_user_events(self) -> int:
        """Return the minimum event count observed across users."""
        if not self.user_event_counts:
            return 0
        return min(self.user_event_counts.values())

    @property
    def max_user_events(self) -> int:
        if not self.user_event_counts:
            return 0
        return max(self.user_event_counts.values())

    def continuity_rate(self, days: float) -> float:
        """
        Son N günde kaç gün veri var?
        Örnek: 7 günlük pencerede 6 gün veri varsa → 0.857
        """
        if days <= 0:
            return 1.0
        needed_days = max(1, int(days))
        now = time.time()
        covered = 0
        for d in range(needed_days):
            day_key = self._day_key(now - d * 86400)
            if self.daily_counts.get(day_key, 0) > 0:
                covered += 1
        return covered / needed_days

    def _day_key(self, ts: float) -> str:
        from datetime import datetime
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")

    def _source_category(self, source: str) -> str:
        """Map a log source to its category group."""
        s = source.lower()
        if any(x in s for x in ("auth", "ssh", "sudo", "pam", "login")):
            return "auth"
        if any(x in s for x in ("audit", "process", "execve", "syscall")):
            return "process"
        if any(x in s for x in ("ufw", "iptables", "network", "dns", "firewall", "nginx", "apache")):
            return "network"
        if any(x in s for x in ("syslog", "journal", "kern", "daemon", "cron", "systemd")):
            return "system"
        return source  # bilinmeyen → kaynak adını kullan

    def update(self, event):
        self.total_events += 1

        if event.user:
            self.seen_users[event.user] = time.time()
            self.user_event_counts[event.user] = \
                self.user_event_counts.get(event.user, 0) + 1

        if event.src_ip:
            self.seen_ips[event.src_ip] = time.time()

        # Source diversity
        if event.source:
            cat = self._source_category(event.source)
            self.source_counts[cat] = self.source_counts.get(cat, 0) + 1

        # Daily data tracking
        day_key = self._day_key(event.ts or time.time())
        self.daily_counts[day_key] = self.daily_counts.get(day_key, 0) + 1

        self.unique_users = len(self.seen_users)
        self.unique_ips   = len(self.seen_ips)

    def record_duplicate(self, kind: str = "exact", source: str = ""):
        if kind == "telemetry":
            self.telemetry_duplicate_count += 1
            return
        self.duplicate_count += 1
        self._bounded_increment(self.duplicate_breakdown_by_source, source or "unknown")
        self._bounded_increment(self.duplicate_breakdown_by_kind, kind or "exact")

    def append_parse_fail_sample(
        self,
        *,
        source: str = "",
        reason: str = "",
        parser: str = "",
        distro_family: str = "",
        path: str = "",
        sample: str = "",
    ) -> None:
        sample_text = str(sample or "").strip()
        if not sample_text:
            return
        entry = {
            "source": str(source or "unknown"),
            "reason": str(reason or "unspecified"),
            "parser": str(parser or "unknown"),
            "distro_family": str(distro_family or "unknown"),
            "path": str(path or ""),
            "sample": sample_text,
        }
        for existing in self.parse_fail_samples:
            if dict(existing or {}) == entry:
                return
        self.parse_fail_samples.append(entry)
        if len(self.parse_fail_samples) > DEFAULT_PARSE_FAIL_SAMPLE_LIMIT:
            self.parse_fail_samples = self.parse_fail_samples[-DEFAULT_PARSE_FAIL_SAMPLE_LIMIT:]

    def record_parse_fail(
        self,
        source: str = "",
        reason: str = "",
        *,
        parser: str = "",
        distro_family: str = "",
        path: str = "",
        sample: str = "",
    ):
        self.parse_fail_count += 1
        self._bounded_increment(self.parse_fail_breakdown_by_source, source or "unknown")
        self._bounded_increment(self.parse_fail_breakdown_by_reason, reason or "unspecified")
        self._bounded_increment(self.parse_fail_breakdown_by_parser, parser or "unknown")
        self._bounded_increment(self.parse_fail_breakdown_by_distro, distro_family or "unknown")
        self._bounded_increment(self.parse_fail_breakdown_by_path, path or "unknown")
        self.append_parse_fail_sample(
            source=source,
            reason=reason,
            parser=parser,
            distro_family=distro_family,
            path=path,
            sample=sample,
        )

    def to_dict(self) -> Dict:
        return {
            "total_events":       self.total_events,
            "unique_users":       self.unique_users,
            "unique_ips":         self.unique_ips,
            "uptime_hours":       round(self.uptime_hours, 2),
            "uptime_days":        round(self.uptime_days, 2),
            "start_time":         self.start_time,
            "current_phase":      self.current_phase,
            "seen_users":         list(self.seen_users.keys()),
            "active_sources":     self.active_sources,
            "source_counts":      self.source_counts,
            "dup_rate":           round(self.dup_rate, 3),
            "duplicate_count":    self.duplicate_count,
            "duplicate_breakdown_by_source": dict(self.duplicate_breakdown_by_source),
            "duplicate_breakdown_by_kind": dict(self.duplicate_breakdown_by_kind),
            "telemetry_duplicate_count": self.telemetry_duplicate_count,
            "parse_fail_count":   self.parse_fail_count,
            "parse_fail_breakdown_by_source": dict(self.parse_fail_breakdown_by_source),
            "parse_fail_breakdown_by_reason": dict(self.parse_fail_breakdown_by_reason),
            "parse_fail_breakdown_by_parser": dict(self.parse_fail_breakdown_by_parser),
            "parse_fail_breakdown_by_distro": dict(self.parse_fail_breakdown_by_distro),
            "parse_fail_breakdown_by_path": dict(self.parse_fail_breakdown_by_path),
            "parse_fail_samples": list(self.parse_fail_samples),
            "user_event_counts":  self.user_event_counts,
            "min_user_events":    self.min_user_events,
        }


# ── Phase Manager ─────────────────────────────────────────────────────────────

class PhaseManager:
    """
    Sistemin hangi fazda olduğunu belirler ve yönetir.

    Kullanım:
        pm = PhaseManager(config)
        pm.update(event)          # her event'te çağır
        if pm.is_active("instant_ml"):
            ...
    """

    def __init__(self, config: Dict = None, state_dir: str = "data",
                 announce_startup: bool = True,
                 distro_adapter=None,
                 db=None):
        cfg        = config or {}
        phases_cfg = cfg.get("phases", {})

        profile = str(cfg.get("phase_profile", "server") or "server").strip().lower()
        if phases_cfg and all(isinstance(v, dict) for v in phases_cfg.values()):
            resolved_profile = None
            if profile != "auto" and isinstance(phases_cfg.get(profile), dict):
                resolved_profile = profile
            elif isinstance(phases_cfg.get("server"), dict):
                resolved_profile = "server"
            elif len(phases_cfg) == 1:
                resolved_profile = next(iter(phases_cfg))
            profile_cfg = phases_cfg.get(resolved_profile, {}) if resolved_profile else {}
        else:
            resolved_profile = profile
            profile_cfg = phases_cfg  # geriye dönük uyum: tek profil dict

        # Fix 19: distro-aware p1_min_events override
        # RHEL 500, SUSE 400, Debian 500 (default inherited from fix 22)
        _p1_min_events_default = 500
        _p3_min_events_default = 10000
        _p3_min_days_default   = 5.0
        _p3_min_ue_default     = 150
        if distro_adapter is not None:
            try:
                _p1_min_events_default = distro_adapter.phase1_min_events()
            except Exception:
                pass

        self.thresholds = PhaseThresholds(
            p1_min_events      = profile_cfg.get("p1_min_events",      _p1_min_events_default),
            p1_min_hours       = profile_cfg.get("p1_min_hours",       2.0),   # Düzeltme 22: 1→2 saat
            p1_min_sources     = profile_cfg.get("p1_min_sources",     2),
            p1_max_dup_rate    = profile_cfg.get("p1_max_dup_rate",    0.20),

            p2_min_events      = profile_cfg.get("p2_min_events",      5000),
            p2_min_days        = profile_cfg.get("p2_min_days",        3.0),
            p2_min_users       = profile_cfg.get("p2_min_users",       2),
            p2_min_sources     = profile_cfg.get("p2_min_sources",     3),
            p2_min_user_events = profile_cfg.get("p2_min_user_events", 100),
            p2_min_continuity  = profile_cfg.get("p2_min_continuity",  0.70),
            p2_max_dup_rate    = profile_cfg.get("p2_max_dup_rate",    0.10),

            p3_min_events      = profile_cfg.get("p3_min_events",      _p3_min_events_default),  # Düzeltme 22: 20000→10000
            p3_min_days        = profile_cfg.get("p3_min_days",        _p3_min_days_default),    # Düzeltme 22: 7→5 gün
            p3_min_users       = profile_cfg.get("p3_min_users",       3),
            p3_min_sources     = profile_cfg.get("p3_min_sources",     3),
            p3_min_user_events = profile_cfg.get("p3_min_user_events", _p3_min_ue_default),      # Düzeltme 22: 300→150
            p3_min_continuity  = profile_cfg.get("p3_min_continuity",  0.80),
            p3_max_dup_rate    = profile_cfg.get("p3_max_dup_rate",    0.05),
        )
        logger.info(f"[AegisCore:Phase] Profil: {resolved_profile or 'server'} — "
                    f"P1:{self.thresholds.p1_min_events}ev "
                    f"P2:{self.thresholds.p2_min_events}ev "
                    f"P3:{self.thresholds.p3_min_events}ev")

        self.state_dir   = Path(state_dir)
        self.state_dir.mkdir(exist_ok=True)
        self._state_file = self.state_dir / "phase_state.json"

        self.stats = SystemStats()
        self._db             = db   # Faz event sayacı DB güvencesi için
        self._accounting_mode = "db_reconciled" if db else "offline_snapshot"
        self._accounting_note = (
            "DB-reconciled runtime state"
            if db else
            "Offline snapshot (phase_state.json)"
        )
        self._data_quality_context: Dict[str, Any] = self._build_data_quality_context()
        self._phase_gate_status: Dict[str, Any] = self._default_phase_gate_status()
        self._external_phase_gate_resolver: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
        self._current_phase    = Phase.PHASE_0
        self._phase_entered_at: Dict[int, float] = {0: time.time()}  # faz → giriş zamanı
        self._grace_period:     float = 7200.0  # 2 saat (saniye)
        self._phase_history: list = []
        self._save_interval  = self._resolve_save_interval(cfg, profile_cfg)

        self._load()
        if announce_startup:
            self._announce_phase(self._current_phase, startup=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def update(self, event) -> Optional[Phase]:
        self.stats.update(event)

        if self.stats.total_events % self._save_interval == 0:
            self._save()

        if self.stats.total_events % 50 == 0:
            return self._check_phase_transition()

        return None

    def _revert_phase(self) -> None:
        """Rollback the phase transition when blocked by the baseline validator."""
        if self._current_phase > Phase.PHASE_0:
            self._current_phase = Phase(int(self._current_phase) - 1)

    def record_duplicate(self, kind: str = "exact", source: str = ""):
        self.stats.record_duplicate(kind=kind, source=source)

    def record_parse_fail(
        self,
        source: str = "",
        reason: str = "",
        *,
        parser: str = "",
        distro_family: str = "",
        path: str = "",
        sample: str = "",
    ):
        self.stats.record_parse_fail(
            source=source,
            reason=reason,
            parser=parser,
            distro_family=distro_family,
            path=path,
            sample=sample,
        )

    def is_active(self, layer: str) -> bool:
        return PHASE_ACTIVE_LAYERS[self._current_phase].get(layer, False)

    @property
    def current_phase(self) -> Phase:
        return self._current_phase

    def _resolve_save_interval(self, cfg: Dict, profile_cfg: Dict) -> int:
        """Read phase-state save frequency from config, otherwise use the fallback."""
        raw_interval = (
            profile_cfg.get("save_interval")
            if isinstance(profile_cfg, dict) and "save_interval" in profile_cfg
            else cfg.get("phase_save_interval", DEFAULT_PHASE_SAVE_INTERVAL)
        )
        try:
            return max(1, int(raw_interval))
        except (TypeError, ValueError):
            return DEFAULT_PHASE_SAVE_INTERVAL

    @property
    def phase_name(self) -> str:
        return PHASE_NAMES[self._current_phase]

    def set_external_phase_gate_resolver(self, resolver: Callable[[Dict[str, Any]], Dict[str, Any]] | None) -> None:
        self._external_phase_gate_resolver = resolver

    def _default_phase_gate_status(self) -> Dict[str, Any]:
        return {
            "phase_gate_source": "label_training",
            "event_telemetry_ok": False,
            "label_training_gate_ok": False,
            "ml_paused": False,
            "open_incident_blocker": False,
            "first_model_training_completed": False,
            "first_model_training_completed_at": "",
            "first_model_training_status": "",
            "first_model_evaluation_passed": False,
            "first_model_evaluation_status": "",
            "first_ml_model_ready": False,
            "first_ml_model_ready_at": "",
            "ml_alert_family_ready": False,
            "ml_alert_family_enabled_families": [],
            "last_training_status": "",
            "last_evaluation_status": "",
            "ready_family_count": 0,
            "ready_family_ids": [],
            "seed_ready_families": [],
            "eligible_seed_families": [],
            "phase_gate_blockers": ["label_training_gate_unavailable"],
            "training_state": {},
            "no_action_contract": True,
        }

    def _resolve_phase_gate_status(self) -> Dict[str, Any]:
        payload = dict(self._default_phase_gate_status())
        payload.update(dict(getattr(self, "_phase_gate_status", {}) or {}))
        resolver = getattr(self, "_external_phase_gate_resolver", None)
        if not callable(resolver):
            self._phase_gate_status = payload
            return payload
        status_stub = {
            "current_phase": int(self._current_phase),
            "phase_name": self.phase_name,
            "stats": self.stats.to_dict(),
            "accounting_mode": self._accounting_mode,
            "accounting_note": self._accounting_note,
        }
        try:
            external = resolver(status_stub) or {}
        except Exception as exc:
            logger.warning("[AegisCore:Phase] Label/training gate resolve edilemedi: %s", exc)
            blockers = list(payload.get("phase_gate_blockers", []) or [])
            blockers.append("label_training_gate_resolver_error")
            payload["phase_gate_blockers"] = list(dict.fromkeys(blockers))
            self._phase_gate_status = payload
            return payload
        if not isinstance(external, dict):
            external = {}
        payload.update(external)
        payload["phase_gate_blockers"] = list(dict.fromkeys(list(payload.get("phase_gate_blockers", []) or [])))
        payload["ready_family_ids"] = sorted({
            str(item or "").strip().upper()
            for item in list(payload.get("ready_family_ids", []) or [])
            if str(item or "").strip()
        })
        payload["seed_ready_families"] = [dict(item or {}) for item in list(payload.get("seed_ready_families", []) or [])]
        payload["ready_family_count"] = int(payload.get("ready_family_count", len(payload["ready_family_ids"])) or 0)
        payload["eligible_seed_families"] = [dict(item or {}) for item in list(payload.get("eligible_seed_families", payload.get("seed_ready_families", [])) or [])]
        payload["event_telemetry_ok"] = bool(payload.get("event_telemetry_ok", False))
        payload["label_training_gate_ok"] = bool(payload.get("label_training_gate_ok", False))
        payload["ml_paused"] = bool(payload.get("ml_paused", False))
        payload["open_incident_blocker"] = bool(payload.get("open_incident_blocker", False))
        payload["first_model_training_completed"] = bool(payload.get("first_model_training_completed", payload.get("first_training_completed", False)))
        payload["first_model_evaluation_passed"] = bool(payload.get("first_model_evaluation_passed", payload.get("first_evaluation_passed", False)))
        payload["first_ml_model_ready"] = bool(payload.get("first_ml_model_ready", payload.get("first_shadow_model_ready", False)))
        payload["ml_alert_family_ready"] = bool(payload.get("ml_alert_family_ready", payload.get("first_ml_model_ready", False)))
        payload["ml_alert_family_enabled_families"] = sorted({str(item or "").strip() for item in list(payload.get("ml_alert_family_enabled_families", []) or []) if str(item or "").strip()})
        payload["no_action_contract"] = bool(payload.get("no_action_contract", True))
        self._phase_gate_status = payload
        return payload

    def progress_to_next(self) -> Dict:
        """
        Bir sonraki faza geçmek için ne kadar kaldığını gösterir.
        Her kriter için: name, current, needed, done, message
        """
        p  = self._current_phase
        st = self.stats
        t  = self.thresholds
        quality_context = self._build_data_quality_context()

        def ev_msg(current, needed):
            if current >= needed:
                return "✅"
            return f"⏳ {needed - current:,} event daha gerekli"

        def src_msg(current, needed):
            if current >= needed:
                return "✅"
            missing = needed - current
            return f"⏳ {missing} farklı kaynak daha gerekli (auth/process/network/system)"

        def dup_msg(rate, max_rate):
            if not bool(quality_context.get("duplicate_rate_verified", False)):
                return str(
                    quality_context.get("duplicate_rate_message", "")
                    or "Veri kalite sayacı (duplicate + parse fail) canlı DB ile doğrulanamadı; eski phase state etkisi olabilir."
                )
            if rate <= max_rate:
                return "✅"
            evidence = []
            if quality_context.get("top_duplicate_source"):
                evidence.append(f"source={quality_context['top_duplicate_source']}")
            if quality_context.get("top_duplicate_kind"):
                evidence.append(f"kind={quality_context['top_duplicate_kind']}")
            if quality_context.get("top_duplicate_categories"):
                evidence.append(
                    "category="
                    + ",".join(str(item.get("name", "")) for item in quality_context["top_duplicate_categories"][:2] if item.get("name"))
                )
            if quality_context.get("top_duplicate_actions"):
                evidence.append(
                    "action="
                    + ",".join(str(item.get("name", "")) for item in quality_context["top_duplicate_actions"][:2] if item.get("name"))
                )
            evidence_text = f" | {'; '.join(evidence)}" if evidence else ""
            return (
                f"⚠️  Veri kalite oranı yüksek: %{rate*100:.1f} (max %{max_rate*100:.0f})"
                f" — duplicate + parse fail{evidence_text}"
            )

        def user_ev_msg(min_ev, needed):
            if min_ev >= needed:
                return "✅"
            return f"⏳ Kullanıcı başına en az {needed} event gerekli (şu an en az: {min_ev})"

        def cont_msg(rate, needed):
            if rate >= needed:
                return "✅"
            return f"⏳ Veri sürekliliği %{rate*100:.0f} (gerekli %{needed*100:.0f})"

        if p == Phase.PHASE_0:
            gate = self._resolve_phase_gate_status()
            criteria = [
                {"name": "Event sayısı",
                 "current": st.total_events, "needed": t.p1_min_events,
                 "done": st.total_events >= t.p1_min_events,
                 "message": ev_msg(st.total_events, t.p1_min_events)},

                {"name": "Çalışma süresi",
                 "current": f"{st.uptime_hours:.1f} saat",
                 "needed":  f"{t.p1_min_hours} saat",
                 "done": st.uptime_hours >= t.p1_min_hours,
                 "message": "✅" if st.uptime_hours >= t.p1_min_hours
                             else f"⏳ {t.p1_min_hours - st.uptime_hours:.1f} saat daha gerekli"},

                {"name": "Log çeşitliliği",
                 "current": st.active_sources, "needed": t.p1_min_sources,
                 "done": st.active_sources >= t.p1_min_sources,
                 "message": src_msg(st.active_sources, t.p1_min_sources)},

                {"name": "Veri kalitesi",
                 "current": f"%{st.dup_rate*100:.1f}", "needed": f"max %{t.p1_max_dup_rate*100:.0f}",
                 "done": st.dup_rate <= t.p1_max_dup_rate,
                 "message": dup_msg(st.dup_rate, t.p1_max_dup_rate)},

                {"name": "Label/training gate",
                 "current": "pass" if gate.get("label_training_gate_ok", False) else "blocked",
                 "needed": "pass",
                 "done": bool(gate.get("label_training_gate_ok", False)),
                 "message": "✅" if gate.get("label_training_gate_ok", False)
                             else (
                                 "⚠️  " + ", ".join(list(gate.get("phase_gate_blockers", []) or [])[:6])
                                 if gate.get("phase_gate_blockers")
                                 else "⚠️  label_training_gate_blocked"
                             )},
            ]
            next_phase = Phase.PHASE_1

        elif p == Phase.PHASE_1:
            cont = st.continuity_rate(t.p2_min_days)
            criteria = [
                {"name": "Event sayısı",
                 "current": st.total_events, "needed": t.p2_min_events,
                 "done": st.total_events >= t.p2_min_events,
                 "message": ev_msg(st.total_events, t.p2_min_events)},

                {"name": "Çalışma süresi",
                 "current": f"{st.uptime_days:.1f} gün",
                 "needed":  f"{t.p2_min_days} gün",
                 "done": st.uptime_days >= t.p2_min_days,
                 "message": "✅" if st.uptime_days >= t.p2_min_days
                             else f"⏳ {t.p2_min_days - st.uptime_days:.1f} gün daha gerekli"},

                {"name": "Benzersiz kullanıcı",
                 "current": st.unique_users, "needed": t.p2_min_users,
                 "done": st.unique_users >= t.p2_min_users,
                 "message": "✅" if st.unique_users >= t.p2_min_users
                             else f"⏳ {t.p2_min_users - st.unique_users} kullanıcı daha gerekli"},

                {"name": "Log çeşitliliği",
                 "current": st.active_sources, "needed": t.p2_min_sources,
                 "done": st.active_sources >= t.p2_min_sources,
                 "message": src_msg(st.active_sources, t.p2_min_sources)},

                {"name": "Kullanıcı başına aktivite",
                 "current": st.min_user_events, "needed": t.p2_min_user_events,
                 "done": st.min_user_events >= t.p2_min_user_events,
                 "message": user_ev_msg(st.min_user_events, t.p2_min_user_events)},

                {"name": "Veri sürekliliği",
                 "current": f"%{cont*100:.0f}", "needed": f"%{t.p2_min_continuity*100:.0f}",
                 "done": cont >= t.p2_min_continuity,
                 "message": cont_msg(cont, t.p2_min_continuity)},

                {"name": "Veri kalitesi",
                 "current": f"%{st.dup_rate*100:.1f}", "needed": f"max %{t.p2_max_dup_rate*100:.0f}",
                 "done": st.dup_rate <= t.p2_max_dup_rate,
                 "message": dup_msg(st.dup_rate, t.p2_max_dup_rate)},
            ]
            next_phase = Phase.PHASE_2

        elif p == Phase.PHASE_2:
            cont = st.continuity_rate(t.p3_min_days)
            criteria = [
                {"name": "Event sayısı",
                 "current": st.total_events, "needed": t.p3_min_events,
                 "done": st.total_events >= t.p3_min_events,
                 "message": ev_msg(st.total_events, t.p3_min_events)},

                {"name": "Çalışma süresi",
                 "current": f"{st.uptime_days:.1f} gün",
                 "needed":  f"{t.p3_min_days} gün",
                 "done": st.uptime_days >= t.p3_min_days,
                 "message": "✅" if st.uptime_days >= t.p3_min_days
                             else f"⏳ {t.p3_min_days - st.uptime_days:.1f} gün daha gerekli"},

                {"name": "Benzersiz kullanıcı",
                 "current": st.unique_users, "needed": t.p3_min_users,
                 "done": st.unique_users >= t.p3_min_users,
                 "message": "✅" if st.unique_users >= t.p3_min_users
                             else f"⏳ {t.p3_min_users - st.unique_users} kullanıcı daha gerekli"},

                {"name": "Log çeşitliliği",
                 "current": st.active_sources, "needed": t.p3_min_sources,
                 "done": st.active_sources >= t.p3_min_sources,
                 "message": src_msg(st.active_sources, t.p3_min_sources)},

                {"name": "Kullanıcı başına aktivite",
                 "current": st.min_user_events, "needed": t.p3_min_user_events,
                 "done": st.min_user_events >= t.p3_min_user_events,
                 "message": user_ev_msg(st.min_user_events, t.p3_min_user_events)},

                {"name": "Veri sürekliliği",
                 "current": f"%{cont*100:.0f}", "needed": f"%{t.p3_min_continuity*100:.0f}",
                 "done": cont >= t.p3_min_continuity,
                 "message": cont_msg(cont, t.p3_min_continuity)},

                {"name": "Veri kalitesi",
                 "current": f"%{st.dup_rate*100:.1f}", "needed": f"max %{t.p3_max_dup_rate*100:.0f}",
                 "done": st.dup_rate <= t.p3_max_dup_rate,
                 "message": dup_msg(st.dup_rate, t.p3_max_dup_rate)},
            ]
            next_phase = Phase.PHASE_3

        else:
            return {"next_phase": None, "criteria": [],
                    "message": "Maksimum faza ulaşıldı ✅"}

        done_count = sum(1 for c in criteria if c["done"])
        pct = int(done_count / len(criteria) * 100)

        # Bloke eden kriterler
        blocking = [c["message"] for c in criteria if not c["done"]]

        return {
            "next_phase":    int(next_phase),
            "next_name":     PHASE_NAMES[next_phase],
            "criteria":      criteria,
            "progress_pct":  pct,
            "all_done":      all(c["done"] for c in criteria),
            "blocking":      blocking,
            "summary":       f"PHASE_{int(next_phase)} için {done_count}/{len(criteria)} kriter tamamlandı (%{pct})",
        }


    def ml_confidence_factor(self) -> float:
        """
        Faz geçişinden sonraki grace period boyunca ML ağırlığını azalt.
        
        PHASE_1 ilk 2 saatinde: 0.3 → 1.0 (lineer tırmanış)
        Sonrası: 1.0 (tam ağırlık)
        
        Bu, yeni faz modellerinin yetersiz örnekle yanlış alarm üretmesini önler.
        """
        entered = self._phase_entered_at.get(int(self._current_phase), 0.0)
        elapsed = time.time() - entered
        if elapsed >= self._grace_period:
            return 1.0
        # 0.3 → 1.0 lineer
        return 0.3 + 0.7 * (elapsed / self._grace_period)


    def get_model_confidence(self, model_source: str) -> float:
        """
        Kaynak modelin faz geçişi sonrası güven seviyesini döndür.
        
        Yeni faz modelleri: 0.3 → 1.0 (2 saatte)
        Önceki faz modeli:  1.0 → 0.6 (tam kapatılmaz, hâlâ katkı sağlar)
        
        model_source: risk.py DEFAULT_WEIGHTS'deki kaynak adı
        """
        grace = self.ml_confidence_factor()

        # Apply the grace factor to models of the current phase
        phase_sources = {
            1: {"ml_if", "isolation_forest", "ewma", "ml_pca", "incremental_pca", "ml_ensemble"},
            2: {"baseline_user", "user_baseline", "baseline_service", "service_baseline",
                "peer_group", "process_tree",
                "freq_anomaly"},
            3: set(),
        }
        current = int(self._current_phase)
        current_sources = phase_sources.get(current, set())
        prev_sources    = phase_sources.get(current - 1, set())

        if model_source in current_sources:
            return grace          # yeni faz modeli: kademeli güven
        elif model_source in prev_sources:
            return max(0.6, grace)  # önceki faz: min 0.6 ağırlık
        return 1.0  # kural/IOC/correlation — faz etkilemiyor

    def get_status(self) -> Dict:
        self._verify_event_count_from_db()
        phase_gate = self._resolve_phase_gate_status()
        phase_gate["event_telemetry_ok"] = bool(
            self.stats.total_events >= self.thresholds.p1_min_events
            and self.stats.uptime_hours >= self.thresholds.p1_min_hours
            and self.stats.active_sources >= self.thresholds.p1_min_sources
            and self.stats.dup_rate <= self.thresholds.p1_max_dup_rate
        )
        prog = self.progress_to_next()
        stats_payload = self.stats.to_dict()
        stats_payload.update(self._build_data_quality_context())
        return {
            "current_phase":  int(self._current_phase),
            "phase_name":     self.phase_name,
            "description":    PHASE_DESCRIPTIONS[self._current_phase],
            "active_layers":  PHASE_ACTIVE_LAYERS[self._current_phase],
            "stats":          stats_payload,
            "phase_gate":     phase_gate,
            "next_phase":     prog,
            "phase_history":  self._phase_history[-5:],
            "accounting_mode": self._accounting_mode,
            "accounting_note": self._accounting_note,
        }

    # ── Phase Transition ──────────────────────────────────────────────────

    def _check_phase_transition(self) -> Optional[Phase]:
        p  = self._current_phase
        st = self.stats
        t  = self.thresholds

        if p == Phase.PHASE_0:
            gate = self._resolve_phase_gate_status()
            if (st.total_events   >= t.p1_min_events  and
                st.uptime_hours   >= t.p1_min_hours    and
                st.active_sources >= t.p1_min_sources  and
                st.dup_rate       <= t.p1_max_dup_rate and
                bool(gate.get("label_training_gate_ok", False))):
                return self._transition_to(Phase.PHASE_1,
                    f"{st.total_events} event, {st.uptime_hours:.1f}s, "
                    f"{st.active_sources} kaynak, dup=%{st.dup_rate*100:.1f}, "
                    f"seed_families={gate.get('ready_family_ids', [])}")

        elif p == Phase.PHASE_1:
            cont = st.continuity_rate(t.p2_min_days)
            if (st.total_events    >= t.p2_min_events      and
                st.uptime_days     >= t.p2_min_days         and
                st.unique_users    >= t.p2_min_users        and
                st.active_sources  >= t.p2_min_sources      and
                st.min_user_events >= t.p2_min_user_events  and
                cont               >= t.p2_min_continuity   and
                st.dup_rate        <= t.p2_max_dup_rate):
                return self._transition_to(Phase.PHASE_2,
                    f"{st.total_events} event, {st.uptime_days:.1f}g, "
                    f"{st.unique_users} user, süreklilik=%{cont*100:.0f}")

        elif p == Phase.PHASE_2:
            cont = st.continuity_rate(t.p3_min_days)
            if (st.total_events    >= t.p3_min_events      and
                st.uptime_days     >= t.p3_min_days         and
                st.unique_users    >= t.p3_min_users        and
                st.active_sources  >= t.p3_min_sources      and
                st.min_user_events >= t.p3_min_user_events  and
                cont               >= t.p3_min_continuity   and
                st.dup_rate        <= t.p3_max_dup_rate):
                return self._transition_to(Phase.PHASE_3,
                    f"{st.total_events} event, {st.uptime_days:.1f}g, "
                    f"süreklilik=%{cont*100:.0f}, dup=%{st.dup_rate*100:.1f}")

        return None

    def _transition_to(self, new_phase: Phase, reason: str) -> Phase:
        old_phase = self._current_phase
        self._current_phase = new_phase
        self.stats.current_phase = int(new_phase)
        self._phase_entered_at[int(new_phase)] = time.time()  # grace period başlat

        entry = {
            "ts":     time.time(),
            "from":   int(old_phase),
            "to":     int(new_phase),
            "reason": reason,
        }
        self._phase_history.append(entry)
        self._save()
        self._announce_phase(new_phase, startup=False, reason=reason)
        return new_phase

    def _announce_phase(self, phase: Phase, startup: bool = False,
                         reason: str = ""):
        BOLD  = "\033[1m"
        GREEN = "\033[92m"
        CYAN  = "\033[96m"
        RESET = "\033[0m"

        if startup:
            if phase == Phase.PHASE_0:
                prog = self.progress_to_next()
                blocking = prog.get("blocking", [])
                print(f"\n{BOLD}{CYAN}{'─'*58}{RESET}")
                print(f"{BOLD}{CYAN}  🛡️  AegisCore başlatıldı{RESET}")
                print(f"  Faz: {BOLD}PHASE_0 — {PHASE_NAMES[phase]}{RESET}")
                print(f"  {PHASE_DESCRIPTIONS[phase]}")
                print(f"  Aktif: Kural / Regex / IOC / Threshold / Correlation")
                print(f"  PHASE_1 için gerekli:")
                print(f"    • {self.thresholds.p1_min_events} event")
                print(f"    • {self.thresholds.p1_min_hours:.0f} saat çalışma")
                print(f"    • {self.thresholds.p1_min_sources} farklı log kaynağı")
                print(f"    • Duplicate oranı < %{self.thresholds.p1_max_dup_rate*100:.0f}")
                print(f"{BOLD}{CYAN}{'─'*58}{RESET}\n")
            else:
                prog = self.progress_to_next()
                print(f"\n{BOLD}  🔄 Sistem PHASE_{int(phase)}'de yeniden başlatıldı: "
                      f"{PHASE_NAMES[phase]}{RESET}")
                print(f"  {prog.get('summary', '')}\n")
        else:
            print(f"\n{BOLD}{GREEN}{'═'*58}{RESET}")
            print(f"{BOLD}{GREEN}  🚀 FAZ GEÇİŞİ: PHASE_{int(phase)-1} → PHASE_{int(phase)}{RESET}")
            print(f"  {PHASE_NAMES[phase]} aktif!")
            print(f"  {PHASE_DESCRIPTIONS[phase]}")
            print(f"  Tetikleyen: {reason}")
            print(f"{BOLD}{GREEN}{'═'*58}{RESET}\n")
            logger.info(f"[AegisCore:Phase] Geçiş: PHASE_{int(phase)-1} → PHASE_{int(phase)} ({reason})")

    # ── Save / Load State ─────────────────────────────────────────────────

    def _save(self):
        try:
            state = {
                "current_phase": int(self._current_phase),
                "phase_entered_at": {str(k): v for k, v in self._phase_entered_at.items()},
                "phase_history": list(self._phase_history),
                "label_training_gate": dict(self._phase_gate_status or {}),
                "stats": {
                    "total_events":       self.stats.total_events,
                    "unique_users":       self.stats.unique_users,
                    "unique_ips":         self.stats.unique_ips,
                    "start_time":         self.stats.start_time,
                    "seen_users":         dict(self.stats.seen_users),
                    "seen_ips":           dict(self.stats.seen_ips),
                    "source_counts":      dict(self.stats.source_counts),
                    "user_event_counts":  dict(self.stats.user_event_counts),
                    "daily_counts":       dict(self.stats.daily_counts),
                    "duplicate_count":    self.stats.duplicate_count,
                    "duplicate_breakdown_by_source": dict(self.stats.duplicate_breakdown_by_source),
                    "duplicate_breakdown_by_kind": dict(self.stats.duplicate_breakdown_by_kind),
                    "telemetry_duplicate_count": self.stats.telemetry_duplicate_count,
                    "parse_fail_count":   self.stats.parse_fail_count,
                    "parse_fail_breakdown_by_source": dict(self.stats.parse_fail_breakdown_by_source),
                    "parse_fail_breakdown_by_reason": dict(self.stats.parse_fail_breakdown_by_reason),
                    "parse_fail_breakdown_by_parser": dict(self.stats.parse_fail_breakdown_by_parser),
                    "parse_fail_breakdown_by_distro": dict(self.stats.parse_fail_breakdown_by_distro),
                    "parse_fail_breakdown_by_path": dict(self.stats.parse_fail_breakdown_by_path),
                    "parse_fail_samples": list(self.stats.parse_fail_samples),
                }
            }
            with open(self._state_file, "w") as f:
                json.dump(state, f, indent=2)

            # DB safeguard: persist the event counter in the DB as well
            # The counter survives even if the file is deleted or corrupted
            if self._db:
                try:
                    self._db._execute(
                        """INSERT INTO system_config (key, value, updated_ts)
                           VALUES ('phase_event_count', %s, %s)
                           ON CONFLICT (key) DO UPDATE
                           SET value = EXCLUDED.value, updated_ts = EXCLUDED.updated_ts""",
                        (str(self.stats.total_events), time.time())
                    )
                except Exception:
                    pass  # DB yazımı opsiyonel

        except Exception as e:
            logger.error(f"[AegisCore:Phase] Kayıt hatası: {e}")

    def _load(self):
        if not self._state_file.exists():
            # Attempt recovery from the DB when the file is missing
            self._load_from_db()
            return
        try:
            with open(self._state_file) as f:
                state = json.load(f)

            self._current_phase = Phase(state.get("current_phase", 0))
            self._phase_entered_at = {
                int(k): v for k, v in state.get("phase_entered_at", {}).items()
            }
            self._phase_entered_at.setdefault(int(self._current_phase), time.time())
            self._phase_history = state.get("phase_history", [])
            self._phase_gate_status = dict(state.get("label_training_gate", {}) or self._default_phase_gate_status())

            s = state.get("stats", {})
            self.stats.total_events      = s.get("total_events",      0)
            self.stats.unique_users      = s.get("unique_users",      0)
            self.stats.unique_ips        = s.get("unique_ips",        0)
            self.stats.start_time        = s.get("start_time",        time.time())
            self.stats.seen_users        = s.get("seen_users",        {})
            self.stats.seen_ips          = s.get("seen_ips",          {})
            self.stats.source_counts     = s.get("source_counts",     {})
            self.stats.user_event_counts = s.get("user_event_counts", {})
            self.stats.daily_counts      = s.get("daily_counts",      {})
            self.stats.duplicate_count   = s.get("duplicate_count",   0)
            self.stats.duplicate_breakdown_by_source = s.get("duplicate_breakdown_by_source", {}) or {}
            self.stats.duplicate_breakdown_by_kind = s.get("duplicate_breakdown_by_kind", {}) or {}
            self.stats.telemetry_duplicate_count = s.get("telemetry_duplicate_count", 0)
            self.stats.parse_fail_count  = s.get("parse_fail_count",  0)
            self.stats.parse_fail_breakdown_by_source = s.get("parse_fail_breakdown_by_source", {}) or {}
            self.stats.parse_fail_breakdown_by_reason = s.get("parse_fail_breakdown_by_reason", {}) or {}
            self.stats.parse_fail_breakdown_by_parser = s.get("parse_fail_breakdown_by_parser", {}) or {}
            self.stats.parse_fail_breakdown_by_distro = s.get("parse_fail_breakdown_by_distro", {}) or {}
            self.stats.parse_fail_breakdown_by_path = s.get("parse_fail_breakdown_by_path", {}) or {}
            self.stats.parse_fail_samples = list(s.get("parse_fail_samples", []) or [])
            self.stats.current_phase     = int(self._current_phase)

            # DB safeguard: compare the file counter against the real DB event count
            # If the DB value is higher because the file is stale/corrupt, trust the DB counter
            self._verify_event_count_from_db()

            logger.info(f"[AegisCore:Phase] State yüklendi: PHASE_{int(self._current_phase)}, "
                        f"{self.stats.total_events} event, "
                        f"{self.stats.active_sources} kaynak")
        except Exception as e:
            logger.warning(f"[AegisCore:Phase] State yüklenemedi: {e}")
            self._load_from_db()

    def _load_from_db(self) -> None:
        """Dosya yoksa veya bozuksa DB'den faz state'ini kurtar."""
        try:
            if not hasattr(self, '_db') or not self._db:
                return
            row = self._db._execute(
                "SELECT value FROM system_config WHERE key = 'phase_event_count'",
                fetch="one"
            )
            if row:
                db_count = int(row["value"])
                if db_count > self.stats.total_events:
                    self.stats.total_events = db_count
                    logger.info(f"[AegisCore:Phase] Event sayacı DB'den kurtarıldı: {db_count}")
        except Exception as _e:
            logger.debug(f"[AegisCore:Phase] DB'den kurtarma başarısız: {_e}")

    def _top_count_entry(self, values: Mapping[str, Any] | None) -> tuple[str, int]:
        if not values:
            return "", 0
        winner = max(
            ((str(key or ""), int(value or 0)) for key, value in values.items()),
            key=lambda item: (item[1], item[0]),
            default=("", 0),
        )
        return winner if winner[1] > 0 else ("", 0)

    def _query_count(self, table_name: str) -> Optional[int]:
        if not getattr(self, "_db", None) or not hasattr(self._db, "_execute"):
            return None
        query = _PHASE_COUNT_SQL.get(str(table_name or "").strip())
        if not query:
            return None
        try:
            row = self._db._execute(query, fetch="one")
        except Exception:
            return None
        if not row:
            return None
        return max(0, int(row.get("count", 0) or 0))

    def _counts_aligned(self, phase_event_count: int, live_db_event_count: int) -> bool:
        phase_event_count = max(0, int(phase_event_count or 0))
        live_db_event_count = max(0, int(live_db_event_count or 0))
        if phase_event_count == 0 and live_db_event_count == 0:
            return True
        upper_bound = max(phase_event_count, live_db_event_count, 1)
        allowed_delta = max(DEFAULT_LIVE_COUNT_DELTA_FLOOR, int(upper_bound * DEFAULT_LIVE_COUNT_DELTA_RATIO))
        return abs(phase_event_count - live_db_event_count) <= allowed_delta

    def _query_live_duplicate_examples(self, source: str) -> Dict[str, List[Dict[str, Any]]]:
        if not source or not getattr(self, "_db", None) or not hasattr(self._db, "_execute"):
            return {"top_duplicate_categories": [], "top_duplicate_actions": []}

        def _rows(sql: str) -> List[Dict[str, Any]]:
            try:
                return list(self._db._execute(sql, (source,), fetch="all") or [])
            except Exception:
                return []

        category_rows = _rows(
            """
            SELECT COALESCE(category, '') AS name, COUNT(*) AS count
            FROM events_recent
            WHERE source = %s
            GROUP BY COALESCE(category, '')
            ORDER BY count DESC, name ASC
            LIMIT 3
            """
        )
        action_rows = _rows(
            """
            SELECT COALESCE(action, '') AS name, COUNT(*) AS count
            FROM events_recent
            WHERE source = %s
            GROUP BY COALESCE(action, '')
            ORDER BY count DESC, name ASC
            LIMIT 3
            """
        )
        return {
            "top_duplicate_categories": [
                {"name": str(row.get("name", "") or ""), "count": int(row.get("count", 0) or 0)}
                for row in category_rows
                if int(row.get("count", 0) or 0) > 0
            ],
            "top_duplicate_actions": [
                {"name": str(row.get("name", "") or ""), "count": int(row.get("count", 0) or 0)}
                for row in action_rows
                if int(row.get("count", 0) or 0) > 0
            ],
        }

    def _build_data_quality_context(self) -> Dict[str, Any]:
        metrics = compute_data_quality_metrics(
            total_events=self.stats.total_events,
            duplicate_count=self.stats.duplicate_count,
            telemetry_duplicate_count=self.stats.telemetry_duplicate_count,
            parse_fail_count=self.stats.parse_fail_count,
        )
        top_source, top_source_count = self._top_count_entry(self.stats.duplicate_breakdown_by_source)
        top_kind, top_kind_count = self._top_count_entry(self.stats.duplicate_breakdown_by_kind)
        context: Dict[str, Any] = {
            "duplicate_rate": round(float(metrics["duplicate_rate"]), 3),
            "parse_fail_rate": round(float(metrics["parse_fail_rate"]), 3),
            "quality_penalty_count": int(metrics["quality_penalty_count"]),
            "quality_seen_total": int(metrics["quality_seen_total"]),
            "duplicate_rate_verified": False,
            "duplicate_rate_source": "phase_state",
            "duplicate_rate_status": "phase_state_only",
            "duplicate_rate_message": "Veri kalite sayacı (duplicate + parse fail) canlı DB ile doğrulanamadı; eski phase state etkisi olabilir.",
            "duplicate_rate_message_en": "Data-quality counter (duplicate + parse fail) is not verified against live DB; stale phase state may be involved.",
            "live_db_event_count": None,
            "phase_event_count": int(self.stats.total_events or 0),
            "live_dedup_cache_count": None,
            "duplicate_counter_stale_possible": False,
            "top_duplicate_source": top_source,
            "top_duplicate_source_count": top_source_count,
            "top_duplicate_kind": top_kind,
            "top_duplicate_kind_count": top_kind_count,
            "top_duplicate_categories": [],
            "top_duplicate_actions": [],
        }
        context.update(dict(getattr(self, "_data_quality_context", {}) or {}))
        return context

    def _verify_event_count_from_db(self) -> None:
        """Reconcile the DB event count and flag duplicate-metric confidence."""
        context = {
            "duplicate_rate_verified": False,
            "duplicate_rate_source": "phase_state",
            "duplicate_rate_status": "phase_state_only",
            "duplicate_rate_message": "Veri kalite sayacı (duplicate + parse fail) canlı DB ile doğrulanamadı; eski phase state etkisi olabilir.",
            "duplicate_rate_message_en": "Data-quality counter (duplicate + parse fail) is not verified against live DB; stale phase state may be involved.",
            "live_db_event_count": None,
            "phase_event_count": int(self.stats.total_events or 0),
            "live_dedup_cache_count": None,
            "duplicate_counter_stale_possible": False,
            "top_duplicate_categories": [],
            "top_duplicate_actions": [],
        }
        try:
            if not hasattr(self, '_db') or not self._db:
                self._data_quality_context = context
                return
            row = self._db._execute(
                "SELECT value FROM system_config WHERE key = 'phase_event_count'",
                fetch="one"
            )
            if row:
                db_count = int(row["value"])
                if db_count > self.stats.total_events:
                    logger.info(f"[AegisCore:Phase] DB sayacı ({db_count}) > dosya sayacı "
                                f"({self.stats.total_events}) — DB alındı")
                    self.stats.total_events = db_count
            context["phase_event_count"] = int(self.stats.total_events or 0)
            live_db_event_count = self._query_count("events_recent")
            live_dedup_cache_count = self._query_count("dedup_cache")
            context["live_db_event_count"] = live_db_event_count
            context["live_dedup_cache_count"] = live_dedup_cache_count
            if live_db_event_count is None:
                context["duplicate_counter_stale_possible"] = bool(
                    self.stats.duplicate_count or self.stats.parse_fail_count or self.stats.telemetry_duplicate_count
                )
                self._data_quality_context = context
                return

            if live_db_event_count <= 0:
                context["duplicate_rate_status"] = "insufficient_live_evidence"
                context["duplicate_counter_stale_possible"] = bool(
                    self.stats.duplicate_count or self.stats.parse_fail_count or self.stats.telemetry_duplicate_count
                )
                self._data_quality_context = context
                return

            counts_aligned = self._counts_aligned(int(self.stats.total_events or 0), live_db_event_count)
            dedup_supports_duplicate = int(live_dedup_cache_count or 0) > 0
            if not counts_aligned:
                context["duplicate_rate_status"] = "stale_or_unverified"
                context["duplicate_counter_stale_possible"] = True
                self._data_quality_context = context
                return
            if int(self.stats.duplicate_count or 0) > 0 and not dedup_supports_duplicate:
                context["duplicate_rate_status"] = "stale_or_unverified"
                context["duplicate_counter_stale_possible"] = True
                self._data_quality_context = context
                return

            context["duplicate_rate_verified"] = True
            context["duplicate_rate_source"] = "live_runtime"
            context["duplicate_rate_status"] = "verified"
            context["duplicate_rate_message"] = ""
            context["duplicate_rate_message_en"] = ""
            top_source, _top_count = self._top_count_entry(self.stats.duplicate_breakdown_by_source)
            if top_source:
                context.update(self._query_live_duplicate_examples(top_source))
        except Exception:
            context["duplicate_counter_stale_possible"] = bool(
                self.stats.duplicate_count or self.stats.parse_fail_count or self.stats.telemetry_duplicate_count
            )
        self._data_quality_context = context
