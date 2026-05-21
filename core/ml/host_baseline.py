"""
core/ml/host_baseline.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Host-based baseline

Each machine behaves differently:
  - server: inactive at night
  - CI/CD machine: active at night, many process spawns
  - database: high disk, low network
"""

import time
import logging
import math
from collections import defaultdict
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)


class HostProfile:
    """Behavior profile for a single host."""

    def __init__(self, hostname: str):
        self.hostname   = hostname
        self.created_ts = time.time()
        self.updated_ts = time.time()
        self.event_count = 0

        # Hour-based activity (0-23)
        self._hour_activity: Dict[int, int] = defaultdict(int)
        # Per-source event counts
        self._source_counts: Dict[str, int] = defaultdict(int)
        # User set
        self._users: set = set()
        # Process seti
        self._processes: set = set()
        # Failed login count
        self._fail_count = 0
        # Average events/minute
        self._event_rate_samples: List[float] = []

    def update(self, event) -> None:
        self.event_count += 1
        self.updated_ts = time.time()

        ts   = event.ts or time.time()
        hour = int((ts % 86400) / 3600)
        self._hour_activity[hour] += 1
        self._source_counts[event.source or "unknown"] += 1

        if event.user:
            self._users.add(event.user)
        if event.process:
            self._processes.add(event.process)
        if event.outcome == "failure":
            self._fail_count += 1

    def anomaly_score(self, event) -> float:
        """
        How anomalous is this event for this host?
        0.0 = completely normal
        1.0 = completely anomalous
        """
        if self.event_count < 50:
            return 0.0  # not enough data

        score = 0.0
        ts    = event.ts or time.time()
        hour  = int((ts % 86400) / 3600)

        # Time-of-day anomaly
        total_hours = sum(self._hour_activity.values())
        if total_hours > 0:
            hour_freq = self._hour_activity.get(hour, 0) / total_hours
            if hour_freq < 0.01:
                score += 0.2   # keep the host time profile as a small context multiplier

        # New user on this host
        if event.user and event.user not in self._users:
            score += 0.35

        # New source
        if event.source and self._source_counts.get(event.source, 0) == 0:
            score += 0.1

        return min(score, 1.0)

    def to_dict(self) -> Dict:
        return {
            "hostname":     self.hostname,
            "created_ts":   self.created_ts,
            "updated_ts":   self.updated_ts,
            "event_count":  self.event_count,
            "hour_activity": dict(self._hour_activity),
            "source_counts": dict(self._source_counts),
            "users":         list(self._users),
            "processes":     list(self._processes),
            "fail_count":    self._fail_count,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "HostProfile":
        hp = cls(d.get("hostname", "unknown"))
        hp.created_ts  = d.get("created_ts", time.time())
        hp.updated_ts  = d.get("updated_ts", time.time())
        hp.event_count = d.get("event_count", 0)
        hp._hour_activity  = defaultdict(int, {int(k): v for k, v in d.get("hour_activity", {}).items()})
        hp._source_counts  = defaultdict(int, d.get("source_counts", {}))
        hp._users          = set(d.get("users", []))
        hp._processes      = set(d.get("processes", []))
        hp._fail_count     = d.get("fail_count", 0)
        return hp


class HostBaselineEngine:
    """
    Tum host'larin profillerini yonetir.
    should_learn=False → saldiri/IOC event'leri profili kirletmez.
    """

    def __init__(self, model_dir: str = "data/models"):
        self._hosts: Dict[str, HostProfile] = {}
        self._model_dir = model_dir
        self._save_path = None  # distro_family ile set edilecek
        self._event_count = 0
        self._save_interval = 500
        logger.info("[HostBaseline] Motor hazir.")

    def set_model_dir(self, model_dir: str, distro_family: str = "unknown") -> None:
        """Distro bazli model dizinini ayarla ve mevcut modeli yukle."""
        import os as _os
        self._model_dir = model_dir
        self._save_path = _os.path.join(model_dir, distro_family, "host_baseline.joblib")
        _os.makedirs(_os.path.dirname(self._save_path), exist_ok=True)
        self._load()

    def update(self, event, should_learn: bool = True) -> None:
        """should_learn=False ise host profilini guncelleme — poisoning korumasi."""
        if not should_learn:
            return
        hostname = getattr(event, "host", None) or getattr(event, "hostname", None) or "localhost"
        if hostname not in self._hosts:
            self._hosts[hostname] = HostProfile(hostname)
        self._hosts[hostname].update(event)
        self._event_count += 1
        if self._save_path and self._event_count % self._save_interval == 0:
            self._save()

    def anomaly_score(self, event) -> float:
        hostname = getattr(event, "host", None) or getattr(event, "hostname", None) or "localhost"
        if hostname not in self._hosts:
            return 0.0
        return self._hosts[hostname].anomaly_score(event)

    def get_profile(self, hostname: str) -> Optional[HostProfile]:
        return self._hosts.get(hostname)

    def host_count(self) -> int:
        return len(self._hosts)

    def to_dict(self) -> Dict:
        return {k: v.to_dict() for k, v in self._hosts.items()}

    def from_dict(self, d: Dict) -> None:
        self._hosts = {k: HostProfile.from_dict(v) for k, v in d.items()}

    def _save(self) -> None:
        if not self._save_path:
            return
        try:
            import joblib, tempfile, os as _os
            with tempfile.NamedTemporaryFile(
                dir=_os.path.dirname(self._save_path), delete=False, suffix=".tmp"
            ) as tf:
                joblib.dump(self.to_dict(), tf.name)
            _os.replace(tf.name, self._save_path)
            logger.debug(f"[HostBaseline] Kaydedildi: {self._save_path}")
        except Exception as e:
            logger.warning(f"[HostBaseline] Kayit hatasi: {e}")

    def _load(self) -> None:
        if not self._save_path:
            return
        import os as _os
        if not _os.path.exists(self._save_path):
            return
        try:
            import joblib
            data = joblib.load(self._save_path)
            self.from_dict(data)
            logger.info(f"[HostBaseline] {len(self._hosts)} host profili yuklendi: {self._save_path}")
        except Exception as e:
            logger.warning(f"[HostBaseline] Yukleme hatasi: {e}")
