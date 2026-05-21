"""
core/ml/baseline.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 5: Baseline Learning Layer

Learns the machine's "normal" behavior.
Improves drift detection over time.

Tracked baselines:
  1. UserBaseline        - user-level normal behavior
  2. RootBaseline        - root activity profile
  3. ServiceBaseline     - service/process-level behavior
  4. ProcessTreeBaseline - process hierarchy

Each baseline tracks:
  - Hourly / daily activity density
  - Common IP/host pairs
  - Typical command sets
  - A reference for anomaly scoring
"""

import time
import json
import logging
import joblib
import math
from pathlib import Path
from typing import Dict, List, Optional, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict

from ..normalize import NormalizedEvent

logger = logging.getLogger(__name__)


# ── 1. Behavior Baseline ───────────────────────────────────────────────────────

SYSTEM_USERS = {"root", "daemon", "nobody", "www-data", "syslog",
                "messagebus", "systemd-network", "systemd-resolve",
                "_apt", "postfix", "sshd", "ntp", "bind"}
SERVICE_SUFFIX = ("svc", "srv", "service", "daemon", "agent", "bot")


def _classify_user(user: str) -> str:
    if not user:
        return "unknown"
    u = user.lower()
    if u == "root":
        return "admin"
    if u in SYSTEM_USERS:
        return "system"
    if any(u.endswith(s) for s in SERVICE_SUFFIX):
        return "service"
    return "user"


@dataclass
class BehaviorBaseline:
    """Baseline for user behavior."""

    username:      str   = ""
    total_events:  int   = 0
    first_seen:    float = 0.0
    last_seen:     float = 0.0

    # Activity profiles
    hour_counts:   List  = field(default_factory=lambda: [0]*24)
    dow_counts:    List  = field(default_factory=lambda: [0]*7)

    # Known entities
    known_ips:      Dict = field(default_factory=dict)
    known_commands: Dict = field(default_factory=dict)
    known_targets:  Dict = field(default_factory=dict)

    # Outcome statistics
    success_count: int   = 0
    failure_count: int   = 0

    def update(self, event) -> None:
        from datetime import datetime
        self.total_events += 1
        self.last_seen = event.ts or time.time()
        if self.first_seen == 0:
            self.first_seen = self.last_seen

        dt = datetime.fromtimestamp(self.last_seen)
        self.hour_counts[dt.hour] += 1
        self.dow_counts[dt.weekday()] += 1

        if event.src_ip:
            self.known_ips[event.src_ip] = self.known_ips.get(event.src_ip, 0) + 1

        cmd = event.fields.get("sudo_command", "")
        if cmd:
            key = cmd.split()[0]
            self.known_commands[key] = self.known_commands.get(key, 0) + 1

        target = event.fields.get("sudo_target_user", event.fields.get("su_target", ""))
        if target:
            self.known_targets[target] = self.known_targets.get(target, 0) + 1

        if event.outcome == "success":
            self.success_count += 1
        elif event.outcome == "failure":
            self.failure_count += 1

    def individual_score(self, event) -> float:
        """Deviation score from this user's own history (0-100)."""
        if self.total_events < 100:
            return 0.0

        score = 0.0
        from datetime import datetime

        # Unknown IP
        if event.src_ip and event.src_ip not in self.known_ips:
            is_root_or_service = (
                event.user in ("root", "admin") or
                (event.user and event.user.endswith("d"))
            )
            try:
                parts = event.src_ip.split(".")
                o1, o2 = int(parts[0]), int(parts[1])
                ip_private = (o1 == 10 or (o1 == 172 and 16 <= o2 <= 31) or
                              (o1 == 192 and o2 == 168) or o1 == 127)
            except Exception:
                ip_private = False
            base = 25.0 if is_root_or_service else 15.0
            if ip_private:
                base *= 0.5
            score += base

        # Unusual hour
        dt = datetime.fromtimestamp(event.ts or time.time())
        hour_rate = self.hour_counts[dt.hour] / max(self.total_events, 1)
        if self.total_events >= 300:
            hw = 1.0 if self.total_events >= 1000 else 0.5
            if hour_rate < 0.01:
                score += 30.0 * hw
            elif hour_rate < 0.03:
                score += 15.0 * hw

        # Unknown command
        cmd = event.fields.get("sudo_command", "")
        if cmd and cmd.split()[0] not in self.known_commands:
            score += 20.0

        # High failure ratio
        if event.outcome == "failure":
            total = self.success_count + self.failure_count
            if total > 10 and self.failure_count / total > 0.5:
                score += 20.0

        return min(score, 100.0)

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "BehaviorBaseline":
        obj = cls()
        for k, v in d.items():
            setattr(obj, k, v)
        return obj

# Backward compatibility: legacy import name
UserBaseline = BehaviorBaseline

# ── 2. Service Baseline ───────────────────────────────────────────────────────

@dataclass
class ServiceBaseline:
    service_name: str  = ""
    total_events: int  = 0
    first_seen:   float = 0.0
    last_seen:    float = 0.0

    # Typical activity type distribution
    action_counts:  Dict = field(default_factory=dict)
    outcome_counts: Dict = field(default_factory=dict)

    # Typical source IPs
    src_ip_counts:  Dict = field(default_factory=dict)

    # Hourly activity
    hour_counts: List = field(default_factory=lambda: [0]*24)

    def update(self, event: NormalizedEvent):
        from datetime import datetime
        self.total_events += 1
        self.last_seen = event.ts or time.time()
        if self.first_seen == 0:
            self.first_seen = self.last_seen

        dt = datetime.fromtimestamp(self.last_seen)
        self.hour_counts[dt.hour] += 1

        if event.action:
            self.action_counts[event.action] = self.action_counts.get(event.action, 0) + 1
        if event.outcome:
            self.outcome_counts[event.outcome] = self.outcome_counts.get(event.outcome, 0) + 1
        if event.src_ip:
            self.src_ip_counts[event.src_ip] = self.src_ip_counts.get(event.src_ip, 0) + 1

    def anomaly_score(self, event: NormalizedEvent) -> float:
        if self.total_events < 100:
            return 0.0  # not enough baseline yet (min 100 events)

        score = 0.0

        # Unseen action
        if event.action and event.action not in self.action_counts:
            score += 30.0

        # Very rare action
        elif event.action:
            rate = self.action_counts.get(event.action, 0) / max(self.total_events, 1)
            if rate < 0.005:
                score += 20.0

        # High failure ratio
        total_outcomes = sum(self.outcome_counts.values())
        if total_outcomes > 20 and event.outcome == "failure":
            fail_rate = self.outcome_counts.get("failure", 0) / total_outcomes
            if fail_rate > 0.3:
                score += 15.0

        return min(score, 100.0)

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "ServiceBaseline":
        obj = cls()
        for k, v in d.items():
            setattr(obj, k, v)
        return obj


# ── 3. Baseline Learning Engine ───────────────────────────────────────────────

class BaselineLearningEngine:
    """
    Manage all baseline components.
    """

    # ── Simple Dynamic Threshold Calibration ───────────────────────────────

    class _DynamicThresholdCalibrator:
        """
        Set an adaptive threshold based on the percentile of the last N scores.
        It is fed with clean events and does not grow during attack periods.
        """
        def __init__(self, window: int = 1000, percentile: float = 90.0):
            self._window     = window
            self._percentile = percentile
            self._scores:    list = []
            self._threshold  = 60.0   # fixed starting point
            self._calibrated = False

        def record(self, score: float) -> None:
            self._scores.append(score)
            if len(self._scores) > self._window:
                self._scores.pop(0)
            if len(self._scores) >= 50:
                import statistics
                sorted_scores = sorted(self._scores)
                idx = int(len(sorted_scores) * self._percentile / 100)
                self._threshold  = sorted_scores[min(idx, len(sorted_scores) - 1)]
                self._calibrated = True

        @property
        def threshold(self) -> float:
            return self._threshold

    _CONTEXT_SCORE_LIMITS = {
        "freq_anomaly": (0.25, 12.0),
    }
    """
    Manage all baselines and update them based on events.

    Added context components:
      - EntityFrequencyBaseline: frequency drift
    """

    def __init__(self, model_dir: str = "data/models", db=None, config: dict = None):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        self._users:    Dict[str, BehaviorBaseline] = {}
        self._services: Dict[str, ServiceBaseline]  = {}
        self._process_tree = ProcessTreeBaseline(db=db)
        self._event_count   = 0
        self._save_interval = 500

        # Dynamic threshold — always initialize regardless of context_ok
        self._dyn_thresh = self._DynamicThresholdCalibrator()

        # Context components
        try:
            from core.context import EntityFrequencyBaseline, baseline_confidence
            self._freq         = EntityFrequencyBaseline()
            self._context_ok   = True
        except ImportError:
            self._context_ok = False

        self._load()
        logger.info("[AegisCore:Baseline] BaselineLearningEngine hazır "
                    f"(context={'ok' if self._context_ok else 'disabled'}).")

    def _context_multiplier_score(self, name: str, raw_score: float) -> float:
        if raw_score <= 0:
            return 0.0
        scale, cap = self._CONTEXT_SCORE_LIMITS.get(name, (1.0, 100.0))
        return min(raw_score * scale, cap)

    def update(self, event: NormalizedEvent,
               should_learn: bool = True) -> Dict[str, float]:
        """
        Update all baselines with the event and return anomaly scores.

        should_learn=False → compute anomaly scores only, without learning
          IOC/regex/high-critical hits must not enter training
          (drift-poisoning guard)

        Returns: ({baseline_name: anomaly_score}, ptree_results)
        """
        self._event_count += 1
        scores = {}

        # User baseline
        if event.user:
            if event.user not in self._users:
                self._users[event.user] = UserBaseline(
                    username=event.user,
                    first_seen=event.ts or time.time()
                )
            ub = self._users[event.user]

            ind_score = ub.individual_score(event)
            if ind_score > 0:
                scores["user_baseline"] = ind_score

            if should_learn:
                ub.update(event)

        # Servis baseline
        if event.process:
            svc = event.process.split("[")[0]
            if svc not in self._services:
                self._services[svc] = ServiceBaseline(
                    service_name=svc,
                    first_seen=event.ts or time.time()
                )
            sb = self._services[svc]
            scores["service_baseline"] = sb.anomaly_score(event)
            if should_learn:
                sb.update(event)

        # Process-tree baseline — always score, but learn only from clean events
        if should_learn:
            self._process_tree.update(event)
        ptree_results = self._process_tree.check(event)
        if ptree_results:
            scores["process_tree"] = ptree_results[0].score

        # Context layer
        if self._context_ok:
            from core.context import baseline_confidence

            ts = event.ts or time.time()

            # Siklik sapmasi — sadece temiz event'lerle ogren (ML-3 fix)
            entity = event.src_ip or event.user or "global"
            if should_learn:
                self._freq.record(entity, ts)
            freq_score = self._freq.frequency_score(entity, ts)
            if freq_score > 0:
                scores["freq_anomaly"] = self._context_multiplier_score("freq_anomaly", freq_score)

            # Baseline-confidence suppression
            # Scale the score when the user baseline has too few samples
            if event.user and event.user in self._users:
                ub  = self._users[event.user]
                n   = getattr(ub, '_n_events', getattr(ub, 'total_events', 100))
                conf = baseline_confidence(n, min_samples=50, full_confidence_at=300)
                if conf < 1.0 and "user_baseline" in scores:
                    scores["user_baseline"] *= conf

            # Dynamic threshold calibrator — sadece temiz event'lerle besle (ML-3 fix)
            if scores and should_learn:
                self._dyn_thresh.record(max(scores.values()))

        # Periyodik kaydet
        if should_learn and self._event_count % self._save_interval == 0:
            self._save()

        return scores, ptree_results

    def get_dynamic_threshold(self) -> float:
        """Return the current adaptive anomaly threshold."""
        if self._context_ok:
            return self._dyn_thresh.threshold
        return 60.0  # sabit fallback

    def get_context_status(self) -> Dict:
        """Status of context components."""
        if not self._context_ok:
            return {"context": "disabled"}
        return {
            "freq_entities":  len(self._freq._profiles),
            "dyn_threshold":  round(self._dyn_thresh.threshold, 2),
            "dyn_calibrated": self._dyn_thresh._calibrated,
        }

    def get_user_profile(self, username: str) -> Optional[UserBaseline]:
        return self._users.get(username)

    def get_service_profile(self, service: str) -> Optional[ServiceBaseline]:
        return self._services.get(service)

    def get_all_users(self) -> List[str]:
        return list(self._users.keys())

    def _save(self):
        try:
            data = {
                "users":    {k: v.to_dict() for k, v in self._users.items()},
                "services": {k: v.to_dict() for k, v in self._services.items()},
            }
            joblib.dump(data, self.model_dir / "baselines.joblib")
            logger.debug(f"[AegisCore:Baseline] Kaydedildi: {len(self._users)} user, {len(self._services)} service")
        except Exception as e:
            logger.error(f"[AegisCore:Baseline] Kayıt hatası: {e}")

    def _load(self):
        p = self.model_dir / "baselines.joblib"
        if not p.exists():
            return
        try:
            data = joblib.load(p)
            self._users    = {k: BehaviorBaseline.from_dict(v)  for k, v in data.get("users", {}).items()}
            self._services = {k: ServiceBaseline.from_dict(v) for k, v in data.get("services", {}).items()}
            logger.info(f"[AegisCore:Baseline] Yüklendi: {len(self._users)} user, {len(self._services)} service")
        except Exception as e:
            logger.warning(f"[AegisCore:Baseline] Yüklenemedi: {e}")

    def status(self) -> Dict:
        return {
            "users_tracked":    len(self._users),
            "services_tracked": len(self._services),
            "events_processed": self._event_count,
            "user_list":        list(self._users.keys())[:10],
        }


# ── 4. Process Tree Baseline ──────────────────────────────────────────────────

class ProcessTreeBaseline:
    """
    Process hierarchy anomaly detection.

    "nginx never runs python3"
    "sshd never runs wget"
    Learns parent→child relationships such as these.

    Source: parent/child data comes from auditd EXECVE + SYSCALL records.
    Even without auditd, inference is made from process + action data.

    How it works:
      1. Persist every parent→child pair in the DB (count++)
      2. When a new pair appears (count < min_seen) → alert
      3. Some parents have a whitelist (shell, init, etc.)

    DB persist: process_tree tablosunda tutulur, restart'ta kaybolmaz.
    """

    # These parent processes are always allowed to run any child — skip checks
    WHITELIST_PARENTS = {
        "bash", "sh", "dash", "zsh", "fish",
        "python3", "python", "ruby", "perl",
        "sudo", "su", "systemd", "init",
        "supervisord", "cron",
    }

    # These children may come from any parent — skip checks
    WHITELIST_CHILDREN = {
        "bash", "sh", "dash", "ls", "cat", "echo",
        "grep", "awk", "sed", "sort", "wc", "head", "tail",
        "date", "id", "whoami", "pwd",
    }

    def __init__(self, db=None, min_seen: int = 5):
        """
        db       : Database instance (for persistence)
        min_seen : Minimum observations for a pair to count as "normal"
        """
        self._db       = db
        self._min_seen = min_seen
        # Memory cache — avoid hitting the DB on every event
        self._cache: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._ops   = 0
        logger.info("[PTREE] ProcessTreeBaseline hazır.")

    def _clean(self, name: str) -> str:
        """sshd[1234] → sshd, /usr/sbin/sshd → sshd"""
        name = name.split("[")[0].strip()
        name = name.split("/")[-1].strip()
        return name.lower()

    def update(self, event: NormalizedEvent):
        """
        Extract and persist the parent→child relationship from an auditd EXECVE event.
        If auditd is unavailable, infer it from process + category data.
        """
        if event.source != "auditd":
            return
        if event.action not in ("exec", "lotl_exec"):
            return

        # parent: the ppid's comm value, which may be present in auditd fields
        parent = self._clean(
            event.fields.get("pcomm",
            event.fields.get("parent_comm",
            event.process or "unknown"))
        )
        # child: the executed binary
        cmdline = event.fields.get("cmdline", "")
        child_raw = cmdline.split()[0] if cmdline else event.process
        child = self._clean(child_raw or "unknown")

        if not parent or not child or parent == child:
            return
        if parent in self.WHITELIST_PARENTS:
            return
        if child in self.WHITELIST_CHILDREN:
            return

        # Update the in-memory cache
        if child not in self._cache[parent]:
            self._cache[parent][child] = 0
        self._cache[parent][child] += 1

        # DB'ye kaydet
        if self._db:
            self._db.update_process_tree(parent, child)

        self._ops += 1

    def check(self, event: NormalizedEvent) -> List:
        """
        Has this parent→child pair never been seen before?
        Or has it been seen only a few times?
        """
        from core.detection import DetectionResult

        if event.source != "auditd":
            return []
        if event.action not in ("exec", "lotl_exec"):
            return []

        parent = self._clean(
            event.fields.get("pcomm",
            event.fields.get("parent_comm",
            event.process or "unknown"))
        )
        cmdline  = event.fields.get("cmdline", "")
        child_raw = cmdline.split()[0] if cmdline else event.process
        child    = self._clean(child_raw or "unknown")

        if not parent or not child or parent == child:
            return []
        if parent in self.WHITELIST_PARENTS:
            return []
        if child in self.WHITELIST_CHILDREN:
            return []

        # Is it in the cache?
        cached_count = self._cache[parent].get(child, 0)

        # Is it in the DB? (on cache miss)
        if cached_count == 0 and self._db:
            is_new = self._db.is_new_process_pair(parent, child, self._min_seen)
        else:
            is_new = cached_count < self._min_seen

        if is_new:
            severity = "critical" if cached_count == 0 else "high"
            score    = 90 if cached_count == 0 else 70
            msg      = (
                f"Anormal process hiyerarşisi: {parent} → {child} "
                f"(daha önce {cached_count}x görüldü)"
            )
            return [DetectionResult(
                triggered        = True,
                rule_id          = "PTREE-001",
                severity         = severity,
                score            = score,
                category         = "process",
                message          = msg,
                rule_file        = "process_tree_baseline",
                mitre_tactic     = "TA0002",
                mitre_technique  = "T1059",
                tags             = ["process-tree", "anomaly", "baseline"],
                details          = {
                    "parent":        parent,
                    "child":         child,
                    "seen_count":    cached_count,
                    "min_required":  self._min_seen,
                }
            )]
        return []

    def status(self) -> Dict:
        total_pairs = sum(len(v) for v in self._cache.values())
        return {
            "parents_tracked": len(self._cache),
            "total_pairs":     total_pairs,
            "ops":             self._ops,
        }
