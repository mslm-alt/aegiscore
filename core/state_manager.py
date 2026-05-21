"""
core/state_manager.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AegisCore — Persistent state management

Allows the system to continue from where it left off after a restart.

Responsibilities:
  1. ContextStateStore   — persist/restore for context.py components
  2. MLStateStore        — ML model snapshot versioning + atomic save
  3. RuntimeStateStore   — event counters, warmup progress, phase metadata
  4. GracefulShutdown    — ordered shutdown on SIGTERM/SIGINT
  5. StateCompatibility  — version mismatch detection + safe reset

Atomic save principle:
  write -> temp file
  fsync
  rename  (atomic)
  No corrupted state remains even if power is lost.

Version format:
  {"_state_version": "2.3.0", "_feature_dim": 24, "_saved_at": 1234567890, ...}
"""

import os
import gzip
import time
import json
import math
import hashlib
import logging
import threading
import signal
from collections import deque
from pathlib import Path
from typing import Dict, Optional, Any, Callable, List

logger = logging.getLogger(__name__)

# Current state format version
STATE_VERSION   = "2.4.1"
FEATURE_DIM     = 24
SCHEMA_VERSION  = 4

# State size limits
MAX_STATE_BYTES      = 5 * 1024 * 1024   # 5MB — runaway growth guard
COMPRESS_THRESHOLD   = 50 * 1024         # above 50KB → gzip compression
MAX_FREQ_ENTITIES    = 2000              # max EntityFrequencyBaseline entries
MAX_PEER_ACTIONS     = 500              # PeerGroupBaseline max action/group

# -- Helper: Atomic JSON Save ------------------------------------------------

def _compute_checksum(raw: str) -> str:
    """Return the SHA-256 checksum of a JSON string."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def atomic_json_save(path: Path, data: Dict) -> bool:
    """
    Save JSON atomically.
    write-tmp → fsync → rename → eski silinir.
    Corrupted state should not be possible.

    Checksum : SHA-256, written to the _checksum field
    Compression: automatically gzip payloads larger than 50KB (_compressed: true)
    Max size guard: payloads above 5MB are rejected
    """
    tmp = path.with_suffix(".tmp")
    try:
        # Checksum (computed from JSON before compression)
        raw_no_cs = json.dumps(data, indent=2, ensure_ascii=False,
                               default=_json_default)
        cs = _compute_checksum(raw_no_cs)
        data["_checksum"] = cs

        raw_bytes = json.dumps(data, indent=2, ensure_ascii=False,
                               default=_json_default).encode("utf-8")

        # Max size guard
        if len(raw_bytes) > MAX_STATE_BYTES:
            logger.error(
                f"[AegisCore:State] State size limit exceeded: "
                f"{len(raw_bytes)/1024:.0f}KB > {MAX_STATE_BYTES//1024}KB "
                f"— write rejected ({path.name})"
            )
            return False

        # Compression — gzip payloads larger than 50KB
        if len(raw_bytes) > COMPRESS_THRESHOLD:
            gz_path = path.with_suffix(".json.gz")
            gz_tmp  = gz_path.with_suffix(".tmp")
            with gzip.open(gz_tmp, "wb", compresslevel=6) as fh:
                fh.write(raw_bytes)
            # fsync — reopen gzip output in binary mode
            with open(gz_tmp, "rb") as fh:
                os.fsync(fh.fileno())
            gz_tmp.rename(gz_path)
            # Remove the old .json file if it exists
            if path.exists():
                path.unlink()
            orig_kb = len(raw_bytes) // 1024
            comp_kb = gz_path.stat().st_size // 1024
            logger.debug(
                f"[AegisCore:State] Compressed: {orig_kb}KB → {comp_kb}KB ({path.name})"
            )
            return True

        # Normal JSON save
        tmp.write_bytes(raw_bytes)
        with open(tmp, "rb") as fh:
            os.fsync(fh.fileno())
        tmp.rename(path)
        gz_path = path.with_suffix(".json.gz")
        if gz_path.exists():
            gz_path.unlink()
        return True

    except Exception as e:
        logger.error(f"[AegisCore:State] Atomic save error ({path.name}): {e}")
        for t in [path.with_suffix(".tmp"), path.with_suffix(".json.gz").with_suffix(".tmp")]:
            try:
                t.unlink(missing_ok=True)
            except Exception as cleanup_exc:
                logger.debug(f"[AegisCore:State] Gecici dosya silinemedi ({t.name}): {cleanup_exc}")
        return False


def atomic_json_load(path: Path) -> Optional[str]:
    """
    Read a JSON or gzip-compressed JSON file.
    Try .json.gz first, then .json.
    Returns: raw JSON string or None
    """
    gz_path = path.with_suffix(".json.gz") if path.suffix == ".json" else path
    if gz_path.exists() and gz_path.suffix == ".gz":
        try:
            with gzip.open(gz_path, "rb") as fh:
                return fh.read().decode("utf-8")
        except Exception as e:
            logger.warning(f"[AegisCore:State] GZ okuma hatası: {e}")

    if path.exists():
        try:
            return path.read_text(encoding="utf-8")
        except Exception as e:
            logger.warning(f"[AegisCore:State] JSON okuma hatası: {e}")

    return None


def verify_checksum(data: Dict, raw: str) -> bool:
    """
    Verify the checksum of the loaded JSON.
    The _checksum field in data must match the raw payload with _checksum removed.
    """
    stored_cs = data.get("_checksum")
    if not stored_cs:
        return True   # legacy format: no checksum, allow

    # remove the _checksum field from raw data and recompute
    try:
        d_copy = {k: v for k, v in data.items() if k != "_checksum"}
        raw_no_cs = json.dumps(d_copy, indent=2, ensure_ascii=False,
                               default=_json_default)
        computed = _compute_checksum(raw_no_cs)
        return computed == stored_cs
    except Exception:
        return False


def _json_default(obj):
    """Fallback for values that cannot be serialized to JSON."""
    if hasattr(obj, "__float__"):
        return float(obj)
    if hasattr(obj, "__int__"):
        return int(obj)
    return str(obj)


def _state_header() -> Dict:
    return {
        "_state_version":  STATE_VERSION,
        "_schema_version": SCHEMA_VERSION,
        "_feature_dim":    FEATURE_DIM,
        "_saved_at":       time.time(),
    }


def _check_compatibility(data: Dict) -> bool:
    """Return whether the loaded state is compatible with the current code."""
    if not data:
        return False
    sv = data.get("_state_version", "0.0.0")
    fd = data.get("_feature_dim",   0)

    # If the feature dimension changed, the ML models are invalid
    if fd and fd != FEATURE_DIM:
        logger.warning(
            f"[AegisCore:State] Feature dim uyumsuz: "
            f"state={fd} kod={FEATURE_DIM} → güvenli reset"
        )
        return False

    # Reset when the major version differs
    try:
        saved_major = int(sv.split(".")[0])
        curr_major  = int(STATE_VERSION.split(".")[0])
        if saved_major < curr_major:
            logger.warning(
                f"[AegisCore:State] State versiyonu eski: {sv} → güvenli reset"
            )
            return False
    except Exception as exc:
        logger.debug(f"[AegisCore:State] State versiyonu parse edilemedi: {sv}: {exc}")

    return True


# ── 1. Context State Store ────────────────────────────────────────────────────

class ContextStateStore:
    """
    Manage persistent state for context.py components.

    Saved components:
      - EntityFrequencyBaseline    (profiles dict)
      - PeerGroupBaseline          (group_profiles dict)
      - DynamicThresholdCalibrator (scores window + threshold)
      - EWMADetector               (signals + n_total)

    Each component follows an "export dict" → JSON → restore flow.
    """

    FILE = "context_state.json"
    SAVE_INTERVAL = 300   # autosave every 5 minutes

    def __init__(self, state_dir: str = "data"):
        self.path = Path(state_dir) / self.FILE
        Path(state_dir).mkdir(parents=True, exist_ok=True)
        self._last_save = 0.0

    # ── EntityFrequencyBaseline ───────────────────────────────────────────────

    def save_freq_baseline(self, efb) -> Dict:
        """EntityFrequencyBaseline → serializable dict."""
        profiles = {}
        for entity, p in efb._profiles.items():
            profiles[entity] = {
                "ewma":      p["ewma"],
                "ewma_var":  p["ewma_var"],
                "n":         p["n"],
                "last_seen": p.get("last_seen", 0.0),
                # deque is not serializable, keep only the event count
                "event_count": len(p["events"]),
            }
        return profiles

    def restore_freq_baseline(self, efb, data: Dict):
        """Restore Dict → EntityFrequencyBaseline."""
        from collections import deque
        for entity, p in data.items():
            efb._profiles[entity] = {
                "ewma":      p.get("ewma"),
                "ewma_var":  p.get("ewma_var", 0.0),
                "n":         p.get("n", 0),
                "last_seen": p.get("last_seen", 0.0),
                "events":    deque(),   # event history is re-learned
            }

    # ── PeerGroupBaseline ─────────────────────────────────────────────────────

    def save_peer_baseline(self, peer) -> Dict:
        if peer is None or not hasattr(peer, "_group_profiles"):
            return {}
        result = {}
        for group, actions in peer._group_profiles.items():
            result[group] = {}
            for action, p in actions.items():
                result[group][action] = {
                    "mean": p["mean"],
                    "var":  p["var"],
                    "n":    p["n"],
                }
        return result

    def restore_peer_baseline(self, peer, data: Dict):
        if peer is None or not hasattr(peer, "_group_profiles"):
            return
        from collections import defaultdict
        for group, actions in data.items():
            for action, p in actions.items():
                peer._group_profiles[group][action] = {
                    "mean": p.get("mean"),
                    "var":  p.get("var", 0.0),
                    "n":    p.get("n", 0),
                }

    # ── DynamicThresholdCalibrator ────────────────────────────────────────────

    def save_dyn_threshold(self, dyn) -> Dict:
        return {
            "threshold":  dyn._threshold,
            "calibrated": dyn._calibrated,
            "scores":     list(dyn._scores)[-500:],   # son 500 yeterli
        }

    def restore_dyn_threshold(self, dyn, data: Dict):
        from collections import deque
        dyn._threshold  = data.get("threshold",  60.0)
        dyn._calibrated = data.get("calibrated", False)
        for s in data.get("scores", []):
            dyn._scores.append(s)

    # ── EWMA ──────────────────────────────────────────────────────────────────

    def save_ewma(self, ewma) -> Dict:
        return {
            "signals": {
                k: {"mean": v["mean"], "var": v["var"], "n": v["n"]}
                for k, v in ewma._signals.items()
            },
            "n_total": ewma._n_total,
        }

    def restore_ewma(self, ewma, data: Dict):
        for k, v in data.get("signals", {}).items():
            if k in ewma._signals:
                ewma._signals[k]["mean"] = v.get("mean")
                ewma._signals[k]["var"]  = v.get("var", 0.0)
                ewma._signals[k]["n"]    = v.get("n", 0)
        ewma._n_total = data.get("n_total", 0)
        ewma._trained = ewma._n_total >= ewma.min_samples

    # ── Bulk Save / Restore ─────────────────────────────────────────────────

    # Critical entities — protected during trimming
    PROTECTED_ENTITIES = frozenset({
        "root", "sshd", "systemd", "sudo", "cron",
        "su", "passwd", "useradd", "usermod",
    })

    def _trim_score(self, profile: dict, entity: str = "") -> float:
        """
        Compute an importance score for an entity/action profile. Lower scores are trimmed first.

        Weighted criteria:
          n_score       0.50  sample count — higher means more valuable
          recency_score 0.30  age of last sighting — older means less valuable
          var_score     0.20  variance > 0 suggests a learned baseline

        Protected entities (root, sshd, systemd, etc.) always receive the
        highest score and are never deleted.
        """
        # Protected entity → score 1.0 (never delete)
        if entity in self.PROTECTED_ENTITIES:
            return 1.0

        n         = profile.get("n", 0)
        var       = profile.get("ewma_var") or profile.get("var", 0.0)
        last_seen = profile.get("last_seen", 0.0)

        # n score: logarithmic scale, growth tapers after 1000
        n_score = min(math.log1p(n) / math.log1p(1000), 1.0)

        # Recency score: how old is the last sighting?
        # 0 days → 1.0 (fresh), 30+ days → 0.0 (stale)
        if last_seen > 0:
            age_days     = (time.time() - last_seen) / 86400
            recency_score = max(0.0, 1.0 - age_days / 30.0)
        else:
            recency_score = 0.0   # last_seen unknown → treat as stale

        # Variance score: variance > 0 means the baseline carries signal
        var_score = min(math.sqrt(var + 1e-6) / 10.0, 1.0)

        return n_score * 0.5 + recency_score * 0.3 + var_score * 0.2

    def _decay_then_trim(self, profiles: dict, max_count: int,
                         decay_factor: float = 0.5) -> int:
        """
        Two-stage trimming:
          1. Apply decay to low-score records (halve n)
          2. If still over the limit, delete the lowest-scoring records

        Returns: number of removed records
        """
        if len(profiles) <= max_count:
            return 0

        scored = [
            (entity, p, self._trim_score(p, entity))
            for entity, p in profiles.items()
        ]
        scored.sort(key=lambda x: x[2])  # lower score first

        # Overflow amount
        excess = len(profiles) - max_count

        # For the initial overflow set: try decay first
        decay_candidates = scored[:excess * 2]
        actually_deleted = 0

        for entity, p, score in decay_candidates:
            if score < 0.2:
                # Very low confidence — hard delete
                del profiles[entity]
                actually_deleted += 1
            else:
                # Medium confidence — decay first (halve n, preserve ewma)
                p["n"] = max(1, int(p.get("n", 1) * decay_factor))
                # Preserve ewma/mean so long-term memory is not lost

            if actually_deleted >= excess:
                break

        # Hard delete only if decay is still not enough
        if len(profiles) > max_count:
            scored2 = sorted(
                profiles.items(),
                key=lambda x: self._trim_score(x[1], x[0])
            )
            for entity, _ in scored2[:len(profiles) - max_count]:
                del profiles[entity]
                actually_deleted += 1

        return actually_deleted

    def _trim_state(self, baseline_engine):
        """
        Guard the maximum state size to prevent runaway growth.

        Trimming policy, in order of importance:
          1. High n + low variance stays intact (well-learned baseline)
          2. Low n + high variance gets decay first (unstable baseline)
          3. Very low score + old age → hard delete

        Prefer decay before hard delete so rare but legitimate behavior is
        not forgotten immediately and fades out gradually.
        """
        if not (hasattr(baseline_engine, "_context_ok") and baseline_engine._context_ok):
            return

        # EntityFrequencyBaseline
        freq = baseline_engine._freq
        if len(freq._profiles) > MAX_FREQ_ENTITIES:
            deleted = self._decay_then_trim(freq._profiles, MAX_FREQ_ENTITIES)
            logger.debug(
                f"[AegisCore:State] FreqBaseline budandı: {deleted} entity."
            )

        # PeerGroupBaseline — max action cap per group
        peer = getattr(baseline_engine, "_peer", None)
        if peer is None or not hasattr(peer, "_group_profiles"):
            return
        for group, actions in peer._group_profiles.items():
            if len(actions) > MAX_PEER_ACTIONS:
                deleted = self._decay_then_trim(actions, MAX_PEER_ACTIONS)
                logger.debug(
                    f"[AegisCore:State] PeerBaseline budandı: {deleted} action ({group})."
                )

    def save_all(self, baseline_engine, ewma=None) -> bool:
        """Atomically persist the full context state."""
        try:
            data = _state_header()

            if hasattr(baseline_engine, "_context_ok") and baseline_engine._context_ok:
                data["freq_baseline"]  = self.save_freq_baseline(baseline_engine._freq)
                data["dyn_threshold"]  = self.save_dyn_threshold(baseline_engine._dyn_thresh)
                peer = getattr(baseline_engine, "_peer", None)
                if peer is not None:
                    data["peer_baseline"] = self.save_peer_baseline(peer)

            if ewma is not None:
                data["ewma"] = self.save_ewma(ewma)

            t0 = time.time()
            ok = atomic_json_save(self.path, data)
            if ok:
                self._last_save = time.time()
                duration_ms = (time.time() - t0) * 1000
                _metrics.record_save(self.path, duration_ms)
                logger.info(
                    f"[AegisCore:State] Context state kaydedildi "
                    f"({duration_ms:.1f}ms, "
                    f"{self.path.stat().st_size / 1024:.1f}KB)."
                )
            return ok

        except Exception as e:
            logger.error(f"[AegisCore:State] Context save hatası: {e}")
            return False

    def restore_all(self, baseline_engine, ewma=None) -> bool:
        """Restore the context state from disk."""
        try:
            t0  = time.time()
            raw = atomic_json_load(self.path)
            if raw is None:
                logger.info("[AegisCore:State] Context state dosyası yok → sıfırdan başlatılıyor.")
                return False
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError) as _je:
                logger.warning(f"[AegisCore:State] State dosyası bozuk: {_je} — sıfırdan başlatılıyor.")
                self._backup_and_reset()
                return False

            if not _check_compatibility(data):
                self._backup_and_reset()
                return False

            # Verify checksum to detect a corrupted snapshot
            if not verify_checksum(data, raw):
                logger.warning(
                    f"[AegisCore:State] Context state checksum hatası — "
                    f"snapshot bozuk, güvenli reset uygulanıyor."
                )
                _metrics.record_checksum_error()
                self._backup_and_reset()
                return False

            if hasattr(baseline_engine, "_context_ok") and baseline_engine._context_ok:
                if "freq_baseline" in data:
                    self.restore_freq_baseline(baseline_engine._freq,
                                               data["freq_baseline"])
                peer = getattr(baseline_engine, "_peer", None)
                if "peer_baseline" in data and peer is not None:
                    self.restore_peer_baseline(peer, data["peer_baseline"])
                if "dyn_threshold" in data:
                    self.restore_dyn_threshold(baseline_engine._dyn_thresh,
                                               data["dyn_threshold"])

            if ewma is not None and "ewma" in data:
                self.restore_ewma(ewma, data["ewma"])

            saved_at    = data.get("_saved_at", 0)
            ago         = time.time() - saved_at
            duration_ms = (time.time() - t0) * 1000
            _metrics.record_restore(duration_ms)
            logger.info(
                f"[AegisCore:State] Context state restore edildi "
                f"({ago/60:.0f} dakika önce kaydedilmişti, "
                f"{duration_ms:.1f}ms)."
            )
            return True

        except Exception as e:
            logger.error(f"[AegisCore:State] Context restore hatası: {e}")
            self._backup_and_reset()
            return False

    def _backup_and_reset(self):
        """Back up a broken state file and continue from a clean slate."""
        bak = self.path.with_suffix(".bak")
        try:
            if self.path.exists():
                self.path.rename(bak)
                logger.warning(
                    f"[AegisCore:State] Bozuk/uyumsuz state yedeklendi: {bak}"
                )
        except Exception as exc:
            logger.warning(f"[AegisCore:State] State yedeklenemedi ({self.path}): {exc}")

    def should_autosave(self) -> bool:
        """
        Return whether it is time to autosave.

        Jitter prevents all machines from writing at the same instant
        (for example every exact 300 seconds), which avoids burst I/O and log floods.
        Each instance gets a deterministic but different offset.
        Offset = process PID based, in the 0–60 second range.
        """
        jitter_offset = (os.getpid() % 60)   # fixed 0-59 sec offset based on PID
        effective_interval = self.SAVE_INTERVAL + jitter_offset
        return time.time() - self._last_save > effective_interval


# ── 2. ML State Store ─────────────────────────────────────────────────────────

class MLStateStore:
    """
    Versioned management for ML model snapshots.

    For each model:
      - Preserve the existing joblib.dump/_load behavior
      - Add version metadata JSON on top
      - Perform a safe reset if incompatibility is detected

    Newer models (EWMA, OC-SVM, HMM) do not persist yet; they would be added here.
    """

    META_FILE = "model_versions.json"

    def __init__(self, model_dir: str = "data/models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self._meta_path = self.model_dir / self.META_FILE

    def save_versions(self, models: Dict[str, bool]) -> bool:
        """
        Save each model's training status and version metadata.
        models: {"isolation_forest": True, "ewma": False, ...}
        """
        data = _state_header()
        data["models"] = {
            name: {"trained": trained, "saved_at": time.time()}
            for name, trained in models.items()
        }
        return atomic_json_save(self._meta_path, data)

    def check_versions(self) -> Dict[str, bool]:
        """
        Read the stored model versions.
        Returns: {"model_name": is_compatible}
        """
        if not self._meta_path.exists():
            return {}
        try:
            data = json.loads(self._meta_path.read_text())
            if not _check_compatibility(data):
                logger.warning("[AegisCore:MLState] Model meta uyumsuz — manual müdahale olmadan model dosyalarına dokunulmayacak.")
                return {}
            return {
                name: info.get("trained", False)
                for name, info in data.get("models", {}).items()
            }
        except Exception as e:
            logger.warning(f"[AegisCore:MLState] Meta okunamadı: {e}")
            return {}

    def _invalidate_all(self):
        """Back up all model files as .bak copies."""
        for f in self.model_dir.glob("*.joblib"):
            try:
                f.rename(f.with_suffix(".bak"))
                logger.info(f"[AegisCore:MLState] Model yedeklendi: {f.name}")
            except Exception as exc:
                logger.warning(f"[AegisCore:MLState] Model yedeklenemedi ({f.name}): {exc}")


# ── 3. Runtime State Store ────────────────────────────────────────────────────

class RuntimeStateStore:
    """
    Sayaçlar, warmup ilerleme, event istatistikleri.

    Faz geçişleri için kritik:
      - total_events
      - unique_users
      - phase_flags

    Restart sonrası faz mantığı sıfırlanmaz.
    """

    FILE = "runtime_state.json"

    def __init__(self, state_dir: str = "data"):
        self.path = Path(state_dir) / self.FILE
        Path(state_dir).mkdir(parents=True, exist_ok=True)

        # Counters continue after restore
        self.total_events:   int   = 0
        self.total_alerts:   int   = 0
        self.total_incidents:int   = 0
        self.unique_users:   set   = set()
        self.unique_hosts:   set   = set()
        self.start_time:     float = time.time()
        self.last_event_ts:  float = 0.0
        self._restored        = False
        self.startup_mode:    str   = "fresh_start"
        self.last_shutdown_clean: bool = True
        self.runtime_components: Dict[str, Any] = {}
        self.runtime_restore_health: Dict[str, Any] = {
            "degraded": False,
            "failed_components": [],
            "restore_status": "fresh_start",
            "saved_at": 0.0,
            "restore_age_sec": 0.0,
        }
        # EPS tracking (son 60s pencere)
        self._eps_window = deque()            # event timestamp'lari (son 60s)
        self._eps_lock   = threading.Lock()
        # Alert kaynak breakdown
        self.alerts_by_layer: dict = {        # layer → alert count
            "rule": 0, "regex": 0, "ioc": 0, "threshold": 0,
            "first_seen": 0, "ml": 0, "sequence": 0, "monitor": 0
        }

        self.restore()

    def record_event(self, user: str = "", host: str = ""):
        self.total_events += 1
        now = time.time()
        self.last_event_ts = now
        if user:
            self.unique_users.add(user)
        if host:
            self.unique_hosts.add(host)
        # EPS sliding window (60s)
        with self._eps_lock:
            self._eps_window.append(now)
            self._prune_eps_window(now)

    def _prune_eps_window(self, now: Optional[float] = None):
        """60s disindaki timestamp'lari soldan dusur."""
        if now is None:
            now = time.time()
        cutoff = now - 60.0
        while self._eps_window and self._eps_window[0] <= cutoff:
            self._eps_window.popleft()

    def record_alert_layer(self, layer: str):
        """Record which detection layer produced the alert."""
        if layer in self.alerts_by_layer:
            self.alerts_by_layer[layer] += 1
        else:
            self.alerts_by_layer[layer] = 1

    def record_alert(self):
        self.total_alerts += 1

    def record_incident(self):
        self.total_incidents += 1

    def mark_running(self, runtime_components: Optional[Dict[str, Any]] = None) -> bool:
        """Mark this process as running so an unclean exit can trigger crash restore."""
        payload = runtime_components if isinstance(runtime_components, dict) else self.runtime_components
        return self.save(clean_shutdown=False, runtime_components=payload)

    def save(self, clean_shutdown: bool = False,
             runtime_components: Optional[Dict[str, Any]] = None,
             shutdown_metadata: Optional[Dict[str, Any]] = None) -> bool:
        t0   = time.time()
        data = _state_header()
        meta = shutdown_metadata if isinstance(shutdown_metadata, dict) else {}
        data.update({
            "total_events":    self.total_events,
            "total_alerts":    self.total_alerts,
            "total_incidents": self.total_incidents,
            "unique_users":    list(self.unique_users)[:500],
            "unique_hosts":    list(self.unique_hosts)[:200],
            "start_time":      self.start_time,
            "last_event_ts":   self.last_event_ts,
            "last_shutdown_clean": bool(clean_shutdown),
            "shutdown_attempted_at": float(meta.get("shutdown_attempted_at", 0.0) or 0.0),
            "queue_drained_ok": bool(meta.get("queue_drained_ok", False)),
            "final_flush_ok": bool(meta.get("final_flush_ok", False)),
            "final_state_save_ok": bool(clean_shutdown and meta.get("final_state_save_ok", False)),
            # ── Lifecycle manifest (v4) ───────────────────────────────────────
            # Verifiable clean marker: version plus summary counters
            "manifest": {
                "state_version":        int(CURRENT_VERSION) if "CURRENT_VERSION" in dir() else 1,
                "queue_depth_at_shutdown":  int(meta.get("queue_depth_at_shutdown", 0) or 0),
                "pending_flush_count":      int(meta.get("pending_flush_count", 0) or 0),
                "total_events_snapshot":    int(self.total_events),
                "total_alerts_snapshot":    int(self.total_alerts),
                "saved_ts":                 float(t0),
            },
        })
        if isinstance(runtime_components, dict):
            data["runtime_components"] = runtime_components
        ok = atomic_json_save(self.path, data)
        if ok:
            self.last_shutdown_clean = bool(clean_shutdown)
            if isinstance(runtime_components, dict):
                self.runtime_components = runtime_components
            _metrics.record_save(self.path, (time.time() - t0) * 1000)
        return ok

    def restore(self) -> bool:
        try:
            raw = atomic_json_load(self.path)
            if raw is None:
                self.runtime_restore_health = {
                    "degraded": False,
                    "failed_components": [],
                    "restore_status": "fresh_start",
                    "saved_at": 0.0,
                    "restore_age_sec": 0.0,
                    "marker_valid": False,
                    "manifest_valid": False,
                    "loss_possible": False,
                }
                return False
            data = json.loads(raw)
            if not _check_compatibility(data):
                logger.warning("[AegisCore:Runtime] Runtime state uyumsuz → sıfırlıyor.")
                self.startup_mode = "dirty_restore"
                self.runtime_restore_health = {
                    "degraded": True,
                    "failed_components": ["runtime_state:incompatible"],
                    "restore_status": "dirty_restore",
                    "saved_at": float(data.get("_saved_at", 0.0) or 0.0),
                    "restore_age_sec": 0.0,
                    "marker_valid": False,
                    "manifest_valid": False,
                    "loss_possible": True,
                }
                return False

            if not verify_checksum(data, raw):
                logger.warning("[AegisCore:Runtime] Runtime state checksum hatası → sıfırlıyor.")
                _metrics.record_checksum_error()
                self.path.rename(self.path.with_suffix(".bak"))
                self.startup_mode = "dirty_restore"
                self.runtime_restore_health = {
                    "degraded": True,
                    "failed_components": ["runtime_state:checksum"],
                    "restore_status": "dirty_restore",
                    "saved_at": float(data.get("_saved_at", 0.0) or 0.0),
                    "restore_age_sec": 0.0,
                    "marker_valid": False,
                    "manifest_valid": False,
                    "loss_possible": True,
                }
                return False

            self.total_events    = data.get("total_events",    0)
            self.total_alerts    = data.get("total_alerts",    0)
            self.total_incidents = data.get("total_incidents", 0)
            self.unique_users    = set(data.get("unique_users", []))
            self.unique_hosts    = set(data.get("unique_hosts", []))
            self.last_event_ts   = data.get("last_event_ts",   0.0)
            self.last_shutdown_clean = bool(data.get("last_shutdown_clean", True))
            self.runtime_components = data.get("runtime_components", {}) \
                if isinstance(data.get("runtime_components", {}), dict) else {}
            # start_time is refreshed to mark the start of this restart
            self._restored = True

            saved_at = float(data.get("_saved_at", time.time()) or time.time())
            ago = max(time.time() - saved_at, 0.0)
            marker_valid = (
                not self.last_shutdown_clean or (
                    float(data.get("shutdown_attempted_at", 0.0) or 0.0) > 0.0
                    and bool(data.get("queue_drained_ok", False))
                    and bool(data.get("final_flush_ok", False))
                    and bool(data.get("final_state_save_ok", False))
                )
            )

            # ── Manifest Validation (v4) ─────────────────────────────────────────
            manifest = data.get("manifest")
            manifest_valid = False
            loss_possible  = True   # güvenli varsayılan: belirsizse kayıp olabilir
            if isinstance(manifest, dict):
                _has_keys = all(
                    k in manifest
                    for k in ("state_version", "queue_depth_at_shutdown",
                               "pending_flush_count", "total_events_snapshot",
                               "total_alerts_snapshot", "saved_ts")
                )
                if _has_keys:
                    # The checksum was already validated above; the manifest is structurally complete
                    manifest_valid = True
                    # loss_possible: true when the queue is non-empty or flushing did not finish
                    _pending = int(manifest.get("pending_flush_count", 1))
                    _qdepth  = int(manifest.get("queue_depth_at_shutdown", 1))
                    loss_possible = (
                        not self.last_shutdown_clean
                        or _pending > 0
                        or _qdepth > 0
                        or not marker_valid
                    )
            # Manifest yoksa eski format — loss_possible=True, manifest_valid=False
            # Do not let a corrupt/incomplete marker break startup; fail open, but do not treat it as clean

            if self.last_shutdown_clean and not marker_valid:
                self.startup_mode = "dirty_restore"
                failed_components = ["runtime_state:clean_marker_incomplete"]
            elif self.last_shutdown_clean and marker_valid and not manifest_valid:
                # Eski format (manifest yok) — clean kabul etme, dirty_restore
                self.startup_mode = "dirty_restore"
                failed_components = ["runtime_state:manifest_missing"]
            else:
                self.startup_mode = "clean_restart" if self.last_shutdown_clean else "crash_restore"
                failed_components = []
            self.runtime_restore_health = {
                "degraded":          bool(failed_components),
                "failed_components": failed_components,
                "restore_status":    self.startup_mode,
                "saved_at":          saved_at,
                "restore_age_sec":   round(ago, 3),
                "marker_valid":      bool(marker_valid),
                "manifest_valid":    bool(manifest_valid),
                "loss_possible":     bool(loss_possible),
            }
            logger.info(
                f"[AegisCore:State] Runtime state restore edildi — "
                f"{self.total_events:,} event, "
                f"{len(self.unique_users)} kullanıcı, "
                f"{ago/60:.0f} dakika önce kaydedilmişti."
            )
            return True
        except Exception as e:
            logger.warning(f"[AegisCore:Runtime] Restore hatası: {e}")
            self.startup_mode = "dirty_restore"
            self.runtime_restore_health = {
                "degraded": True,
                "failed_components": [f"runtime_state:{type(e).__name__}"],
                "restore_status": "dirty_restore",
                "saved_at": 0.0,
                "restore_age_sec": 0.0,
                "marker_valid": False,
                "manifest_valid": False,
                "loss_possible": True,
            }
            return False

    @property
    def uptime_hours(self) -> float:
        return (time.time() - self.start_time) / 3600

    @property
    def events_per_second(self) -> float:
        with self._eps_lock:
            self._prune_eps_window()
            return round(len(self._eps_window) / 60.0, 3)

    def status(self) -> Dict:
        pressure = self.runtime_components.get("pipeline_pressure", {})
        base = {
            "total_events":     self.total_events,
            "total_alerts":     self.total_alerts,
            "total_incidents":  self.total_incidents,
            "unique_users":     len(self.unique_users),
            "unique_hosts":     len(self.unique_hosts),
            "uptime_hours":     round(self.uptime_hours, 2),
            "events_per_second": self.events_per_second,
            "alerts_by_layer":  dict(self.alerts_by_layer),
            "restored":         self._restored,
            "startup_mode":     self.startup_mode,
            "last_shutdown_clean": self.last_shutdown_clean,
            "runtime_restore_health": dict(self.runtime_restore_health),
            "pressure":         dict(pressure) if isinstance(pressure, dict) else {},
        }
        sm = _metrics.status()
        base["state_metrics"]        = sm
        base["last_save_ms"]         = sm.get("avg_save_ms", 0)
        base["last_restore_ms"]      = sm.get("last_restore_ms", 0)
        return base


# ── 5. State Metrics ──────────────────────────────────────────────────────────

class StateMetrics:
    """
    State operasyonlarının ölçümü.

    Takip edilenler:
      - restore süresi (ms)
      - snapshot boyutu (bytes)
      - save süresi (ms)
      - checksum hata sayısı
      - toplam save/restore sayısı

    Neden değerli:
      - Büyüyen state performans sorununa erken uyarı verir
      - Checksum hata sayısı donanım/disk sorununu gösterir
      - restore süresi SLA raporlamasında kullanılabilir
    """

    def __init__(self):
        self._saves:             int   = 0
        self._restores:          int   = 0
        self._checksum_errors:   int   = 0
        self._save_durations_ms: list  = []   # son 20 save süresi
        self._restore_duration_ms: float = 0.0
        self._last_snapshot_bytes: Dict[str, int] = {}
        self._lock = threading.Lock()

    def record_save(self, path: Path, duration_ms: float):
        with self._lock:
            self._saves += 1
            self._save_durations_ms.append(duration_ms)
            if len(self._save_durations_ms) > 20:
                self._save_durations_ms.pop(0)
            try:
                self._last_snapshot_bytes[path.name] = path.stat().st_size
            except Exception as exc:
                logger.debug(f"[AegisCore:State] Snapshot boyutu okunamadi ({path.name}): {exc}")

    def record_restore(self, duration_ms: float):
        with self._lock:
            self._restores += 1
            self._restore_duration_ms = duration_ms

    def record_checksum_error(self):
        with self._lock:
            self._checksum_errors += 1

    def status(self) -> Dict:
        with self._lock:
            avg_save_ms = (
                sum(self._save_durations_ms) / len(self._save_durations_ms)
                if self._save_durations_ms else 0.0
            )
            return {
                "saves":              self._saves,
                "restores":           self._restores,
                "checksum_errors":    self._checksum_errors,
                "avg_save_ms":        round(avg_save_ms, 2),
                "last_restore_ms":    round(self._restore_duration_ms, 2),
                "snapshot_sizes":     {
                    k: f"{v/1024:.1f}KB"
                    for k, v in self._last_snapshot_bytes.items()
                },
            }


# Singleton metrics shared by all stores
_metrics = StateMetrics()


def get_state_metrics() -> StateMetrics:
    """Global state metrics singleton."""
    return _metrics



# ── 4. Graceful Shutdown ──────────────────────────────────────────────────────

class GracefulShutdown:
    """
    SIGTERM / SIGINT geldiğinde sıralı shutdown.

    Sıra önemli:
      1. Yeni event kabul etmeyi durdur
      2. İşlenmeyi bekleyen event'leri tamamla (max 5 sn)
      3. Queue flush
      4. DB commit
      5. ML model snapshot
      6. Context state kaydet
      7. Runtime state kaydet
      8. Phase state kaydet
      9. Temiz çıkış

    Her adım try/except ile — hata olsa bile sonraki adım çalışır.
    """

    def __init__(self):
        self._handlers: List[Callable] = []
        self._triggered = False
        self._lock = threading.Lock()
        self._results: List[Dict[str, Any]] = []
        self._failed: List[str] = []

    def register(self, fn: Callable, name: str = ""):
        """Register a function to be called during shutdown."""
        self._handlers.append((fn, name or fn.__name__))

    def trigger(self, sig=None, frame=None):
        """Start shutdown; it should run only once."""
        with self._lock:
            if self._triggered:
                return
            self._triggered = True
            self._results = []
            self._failed = []

        sig_name = {2: "SIGINT", 15: "SIGTERM"}.get(sig, str(sig))
        print(f"\n[AegisCore] {sig_name} alındı — temiz kapatılıyor...")
        logger.info(f"[AegisCore:Shutdown] {sig_name} — sıralı shutdown başlıyor.")

        for fn, name in self._handlers:
            try:
                logger.debug(f"[AegisCore:Shutdown] → {name}")
                result = fn()
                ok = result is not False
                self._results.append({"name": name, "ok": ok})
                if not ok:
                    self._failed.append(name)
                    logger.error(f"[AegisCore:Shutdown] {name} başarısız döndü.")
            except Exception as e:
                self._results.append({"name": name, "ok": False, "error": str(e)})
                self._failed.append(name)
                logger.error(f"[AegisCore:Shutdown] {name} hatası: {e}")

        logger.info("[AegisCore:Shutdown] Tamamlandı.")
        print("[AegisCore] Kapatıldı.")

    def had_failures(self) -> bool:
        return bool(self._failed)

    def status(self) -> Dict[str, Any]:
        return {
            "triggered": self._triggered,
            "failed_handlers": list(self._failed),
            "results": list(self._results),
        }

    def install(self):
        """Install SIGTERM and SIGINT handlers."""
        try:
            signal.signal(signal.SIGINT,  self.trigger)
            signal.signal(signal.SIGTERM, self.trigger)
            logger.debug("[AegisCore:Shutdown] Sinyal handler'ları kuruldu.")
        except Exception as e:
            logger.warning(f"[AegisCore:Shutdown] Sinyal kurulum hatası: {e}")
