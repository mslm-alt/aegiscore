from collections import deque
import os
"""
core/ml/instant_ml.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FAZ 1-2: Instant ML Katmanı

Az veriyle çalışabilen, kurulduğu anda devreye girebilen ML modelleri.
Yüksek eşikle başlar, veri arttıkça hassaslaşır.

Modeller:
  1. IsolationForestDetector  - genel anomali (küme dışı noktalar)     [FAZ1]
  2. EWMADetector             - spike/burst tespiti, anlık anomali      [FAZ1]
  3. IncrementalPCADetector   - boyut indirgeme + reconstruction error  [FAZ1]



Feature Engineering:
  NormalizedEvent → 25-boyutlu sayısal feature vektörü
"""

import time
import logging
import tempfile
import numpy as np
import joblib
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any
from dataclasses import dataclass

from sklearn.ensemble import IsolationForest
from sklearn.decomposition import IncrementalPCA
from sklearn.preprocessing import StandardScaler


from ..normalize import NormalizedEvent

logger = logging.getLogger(__name__)

# ── Feature Engineering ───────────────────────────────────────────────────────

# Kategori → index (one-hot benzeri)
CATEGORY_MAP = {
    "auth": 0, "network": 1, "process": 2,
    "system": 3, "filesystem": 4, "unknown": 5
}
ACTION_MAP = {
    "ssh_login": 0, "ssh_invalid_user": 1, "sudo": 2, "su": 3,
    "session_open": 4, "session_close": 5, "useradd": 6, "userdel": 7,
    "cron_exec": 8, "exec": 9, "syscall": 10, "unknown": 11
}
OUTCOME_MAP = {"success": 1, "failure": -1, "unknown": 0}

FEATURE_DIM = 25  # toplam feature sayısı (24 + distro_family)


def extract_features(event: NormalizedEvent) -> np.ndarray:
    """
    NormalizedEvent → 25-boyutlu sayısal feature vektörü.

    Features:
      [0]  hour_of_day          (normalize 0-1)
      [1]  day_of_week          (normalize 0-1)
      [2]  is_weekend
      [3]  category_idx         (normalize)
      [4]  action_idx           (normalize)
      [5]  outcome              (-1/0/1)
      [6]  is_root_user
      [7]  is_system_user       (daemon, www-data vb.)
      [8]  has_src_ip
      [9]  src_ip_is_private
      [10] src_ip_is_loopback
      [11] pid_log              (log2 pid, normalize)
      [12] message_length       (normalize)
      [13] has_sudo_command
      [14] hour_sin             (cyclical encoding)
      [15] hour_cos             (cyclical encoding)
      [16] has_parent_pid       (ppid mevcut mu)
      [17] is_privileged_exec   (euid=0 ama auid!=0)
      [18] dst_port_bucket      (well-known/registered/dynamic)
      [19] is_interactive_shell (bash/sh/zsh interactive)
      [20] is_suspicious_proc   (curl,wget,nc,ncat,python vb.)
      [21] failure_streak       (arka arkaya failure normalize)
      [22] has_external_ip      (public IP = not private/loopback)
      [23] log_message_entropy  (entropy normalize — olağandışı karakter yoğunluğu)
      [24] distro_family        (dağıtım ailesi — distro_ml.get_distro_feature())
    """
    import struct, socket, math

    ts = event.ts or time.time()
    from datetime import datetime
    dt = datetime.fromtimestamp(ts)

    hour = dt.hour
    dow  = dt.weekday()

    # IP analiz
    has_ip = 1.0 if event.src_ip else 0.0
    ip_private = 0.0
    ip_loopback = 0.0
    has_external_ip = 0.0
    if event.src_ip:
        try:
            packed = socket.inet_aton(event.src_ip)
            first_octet = struct.unpack("!B", packed[:1])[0]
            ip_loopback = 1.0 if first_octet == 127 else 0.0
            try:
                parts = event.src_ip.split(".")
                if len(parts) == 4:
                    o1, o2 = int(parts[0]), int(parts[1])
                    if o1 == 10 or (o1 == 172 and 16 <= o2 <= 31) or (o1 == 192 and o2 == 168):
                        ip_private = 1.0
            except Exception:
                pass
            has_external_ip = 1.0 if (ip_private == 0.0 and ip_loopback == 0.0) else 0.0
        except Exception:
            pass

    # Port bucket: 0=yok, 0.33=well-known(<1024), 0.66=registered, 1.0=dynamic(>49151)
    dst_port = event.fields.get("dst_port", 0) or event.fields.get("port", 0)
    try:
        dst_port = int(dst_port)
    except (TypeError, ValueError):
        dst_port = 0
    if dst_port == 0:
        port_bucket = 0.0
    elif dst_port < 1024:
        port_bucket = 0.33
    elif dst_port < 49152:
        port_bucket = 0.66
    else:
        port_bucket = 1.0

    # Interactive shell — bash/sh/zsh -i veya /bin/bash gibi
    proc = (event.process or "").lower()
    cmdline = event.fields.get("cmdline", "") or ""
    is_interactive_shell = 1.0 if (
        proc in ("bash", "sh", "zsh", "fish", "dash") and
        ("-i" in cmdline or "-c" in cmdline or not cmdline)
    ) else 0.0

    # Suspicious process — tools launched from the command line
    SUSPICIOUS_PROCS = {
        "curl", "wget", "nc", "ncat", "netcat", "nmap", "masscan",
        "python", "python3", "perl", "ruby", "php", "lua",
        "socat", "ssh", "scp", "sftp", "rsync", "base64", "xxd",
    }
    is_suspicious_proc = 1.0 if proc in SUSPICIOUS_PROCS else 0.0

    # Failure streak — signal strength for consecutive failures
    fail_streak = event.fields.get("fail_count", 0)
    try:
        fail_streak = min(int(fail_streak) / 20.0, 1.0)
    except (TypeError, ValueError):
        fail_streak = 0.0

    # Message entropy — abnormal character distribution such as base64 or obfuscation
    msg = event.message or ""
    entropy = 0.0
    if len(msg) > 10:
        from collections import Counter
        freq = Counter(msg)
        total = len(msg)
        entropy = -sum((c/total) * math.log2(c/total) for c in freq.values())
        entropy = min(entropy / 8.0, 1.0)  # max teorik entropi ~8 bit

    # Distro feature (Katman 1)
    try:
        from core.ml.distro_ml import get_distro_feature
        distro_feat = get_distro_feature(getattr(event, "distro_family", "unknown"))
    except Exception:
        distro_feat = 1.0

    features = np.array([
        hour / 23.0,                                                      # [0]
        dow / 6.0,                                                        # [1]
        1.0 if dow >= 5 else 0.0,                                        # [2] weekend
        CATEGORY_MAP.get(event.category, 5) / 5.0,                      # [3]
        ACTION_MAP.get(event.action, 11) / 11.0,                         # [4]
        OUTCOME_MAP.get(event.outcome, 0),                               # [5]
        1.0 if event.user == "root" else 0.0,                            # [6]
        1.0 if event.user in ("daemon","bin","sys","www-data","nobody") else 0.0,  # [7]
        has_ip,                                                           # [8]
        ip_private,                                                       # [9]
        ip_loopback,                                                      # [10]
        min(np.log2(event.pid + 1) / 17.0, 1.0),                        # [11]
        min(len(event.message) / 500.0, 1.0),                            # [12]
        1.0 if event.fields.get("sudo_command") else 0.0,               # [13]
        np.sin(2 * np.pi * hour / 24),                                   # [14]
        np.cos(2 * np.pi * hour / 24),                                   # [15]
        1.0 if event.fields.get("ppid", "") not in ("", "0", "1") else 0.0,  # [16]
        1.0 if (                                                          # [17]
            event.fields.get("euid", "") == "0" and
            event.fields.get("session", "") not in ("", "4294967295")
        ) else 0.0,
        port_bucket,                                                      # [18]
        is_interactive_shell,                                             # [19]
        is_suspicious_proc,                                               # [20]
        fail_streak,                                                      # [21]
        has_external_ip,                                                  # [22]
        entropy,                                                          # [23]
        distro_feat,                                                      # [24] distro_family
    ], dtype=np.float32)

    return features


# ── ML Detection Result ───────────────────────────────────────────────────────

@dataclass
class MLResult:
    model:     str   = ""
    score:     float = 0.0    # 0-100, yüksek = anormal
    anomaly:   bool  = False
    threshold: float = 0.0
    details:   Dict  = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


# ── 1. Isolation Forest ───────────────────────────────────────────────────────

class IsolationForestDetector:
    """
    Isolation Forest — genel anomali tespiti.
    Az veriyle başlar, periyodik olarak yeniden eğitilir.
    """

    def __init__(self, config: Dict = None, model_dir: str = "data/models"):
        cfg = config or {}
        self.contamination   = cfg.get("contamination", 0.05)
        self.n_estimators    = cfg.get("n_estimators", 100)
        self.retrain_interval = cfg.get("retrain_interval", 3600)
        self.min_samples     = cfg.get("warmup_samples", 200)
        self.model_dir       = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        self._model: Optional[IsolationForest] = None
        self._scaler  = StandardScaler()
        _max_buf = cfg.get('if_buffer_maxlen', 5000)
        self._buffer: deque = deque(maxlen=_max_buf)  # ring buffer — sınırsız büyüme önlenir
        self._last_train = 0.0
        self._trained    = False
        self._score_min  = -0.5
        self._score_max  = 0.5

        self._try_load()

    def _model_path(self) -> Path:
        return self.model_dir / "isolation_forest.joblib"

    def _scaler_path(self) -> Path:
        return self.model_dir / "if_scaler.joblib"

    def _try_load(self):
        mp, sp = self._model_path(), self._scaler_path()
        if mp.exists() and sp.exists():
            try:
                self._model  = joblib.load(mp)
                self._scaler = joblib.load(sp)
                self._trained = True
                # Load the buffer as well to avoid losing warmup state
                bp = self.model_dir / "if_buffer.joblib"
                if bp.exists():
                    self._buffer = joblib.load(bp)
                logger.info(f"[AegisCore:IF] Kayıtlı model yüklendi (buffer={len(self._buffer)}).")
            except Exception as e:
                logger.warning(f"[AegisCore:IF] Model yüklenemedi: {e}")

    def _save(self):
        """Atomic save using a temp file plus os.replace() to prevent partial writes."""
        try:
            for data, target in [
                (self._model,  self._model_path()),
                (self._scaler, self._scaler_path()),
                (list(self._buffer), self.model_dir / "if_buffer.joblib"),
            ]:
                with tempfile.NamedTemporaryFile(
                    dir=self.model_dir, delete=False, suffix=".tmp"
                ) as tf:
                    joblib.dump(data, tf.name)
                os.replace(tf.name, target)
        except Exception as e:
            logger.error(f"[AegisCore:IF] Model kaydedilemedi: {e}")

    def update(self, features: np.ndarray):
        """Append new data to the buffer and retrain when needed."""
        try:
            features = np.asarray(features, dtype=np.float64).flatten()
            if features.shape[0] == 0:
                return
        except Exception:
            return
        self._buffer.append(features)

        now = time.time()
        should_train = (
            len(self._buffer) >= self.min_samples and
            (now - self._last_train) > self.retrain_interval
        )
        # First training starts once min_samples is reached
        if not self._trained and len(self._buffer) >= self.min_samples:
            should_train = True

        if should_train:
            self._train()

    def _train(self):
        if len(self._buffer) < 50:
            return
        X = np.array(self._buffer)
        try:
            self._scaler.fit(X)
            X_scaled = self._scaler.transform(X)
            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=42,
                n_jobs=-1
            )
            self._model.fit(X_scaled)
            self._trained    = True
            self._last_train = time.time()
            # For score-range calibration
            scores = self._model.score_samples(X_scaled)
            self._score_min = float(scores.min())
            self._score_max = float(scores.max())
            self._buffer.clear()  # ring buffer temizle — bellek boşalt
            self._save()
            logger.info(f"[AegisCore:IF] Model eğitildi, "
                        f"score_range=[{self._score_min:.3f}, {self._score_max:.3f}]")
        except Exception as e:
            logger.error(f"[AegisCore:IF] Eğitim hatası: {e}")

    def predict(self, features: np.ndarray) -> MLResult:
        if not self._trained or self._model is None:
            return MLResult(model="isolation_forest", score=0, anomaly=False,
                           details={"status": "warmup", "samples": len(self._buffer),
                                    "needed": self.min_samples})
        try:
            X = self._scaler.transform(features.reshape(1, -1))
            raw_score = float(self._model.score_samples(X)[0])
            # Normalize to 0-100 where a low IF score maps to a high anomaly score
            score_range = max(self._score_max - self._score_min, 0.001)
            anomaly_score = (1 - (raw_score - self._score_min) / score_range) * 100
            anomaly_score = float(np.clip(anomaly_score, 0, 100))
            prediction    = self._model.predict(X)[0]  # -1=anomaly, 1=normal
            return MLResult(
                model="isolation_forest",
                score=anomaly_score,
                anomaly=(prediction == -1),
                threshold=70.0,
                details={"raw_score": raw_score, "prediction": int(prediction)}
            )
        except Exception as e:
            logger.debug(f"[AegisCore:IF] Predict hatası: {e}")
            return MLResult(model="isolation_forest", score=0, anomaly=False)


# ── 2. Incremental PCA ────────────────────────────────────────────────────────

class IncrementalPCADetector:
    """
    Incremental PCA — online öğrenen boyut indirgeme.
    Reconstruction error yüksekse = anomali.
    """

    def __init__(self, config: Dict = None, model_dir: str = "data/models"):
        cfg = config or {}
        self.n_components  = min(cfg.get("n_components", 8), FEATURE_DIM - 1)
        self.batch_size    = cfg.get("batch_size", 50)
        self.min_samples   = cfg.get("warmup_samples", 200)
        self.model_dir     = Path(model_dir)

        self._ipca    = IncrementalPCA(n_components=self.n_components,
                                        batch_size=self.batch_size)
        self._scaler  = StandardScaler()
        self._buffer: List[np.ndarray] = []
        self._trained    = False
        self._err_mean   = 0.0
        self._err_std    = 1.0
        self._threshold_multiplier = 3.0  # mean + 3*std

        self._try_load()

    def _try_load(self):
        p = self.model_dir / "ipca.joblib"
        s = self.model_dir / "ipca_scaler.joblib"
        if p.exists() and s.exists():
            try:
                data = joblib.load(p)
                self._ipca       = data["ipca"]
                self._err_mean   = data["err_mean"]
                self._err_std    = data["err_std"]
                self._scaler     = joblib.load(s)
                self._trained    = True
                logger.info("[AegisCore:PCA] Kayıtlı model yüklendi.")
            except Exception as e:
                logger.warning(f"[AegisCore:PCA] Model yüklenemedi: {e}")

    def _save(self):
        """Atomic save."""
        try:
            for data, fname in [
                ({"ipca": self._ipca, "err_mean": self._err_mean,
                  "err_std": self._err_std}, "ipca.joblib"),
                (self._scaler, "ipca_scaler.joblib"),
            ]:
                target = self.model_dir / fname
                with tempfile.NamedTemporaryFile(
                    dir=self.model_dir, delete=False, suffix=".tmp"
                ) as tf:
                    joblib.dump(data, tf.name)
                os.replace(tf.name, target)
        except Exception as e:
            logger.error(f"[AegisCore:PCA] Kayıt hatası: {e}")

    def update(self, features: np.ndarray):
        try:
            features = np.asarray(features, dtype=np.float64).flatten()
            if features.shape[0] == 0:
                return
        except Exception:
            return
        self._buffer.append(features)
        if len(self._buffer) >= self.batch_size:
            self._partial_fit()

    def _partial_fit(self):
        if len(self._buffer) < self.n_components + 1:
            return
        X = np.array(self._buffer)
        try:
            if not self._trained:
                self._scaler.fit(X)
            X_scaled = self._scaler.transform(X)
            self._ipca.partial_fit(X_scaled)
            # Update reconstruction-error statistics
            X_recon = self._reconstruct(X_scaled)
            errors  = np.mean((X_scaled - X_recon) ** 2, axis=1)
            # Online mean/std update using an exponential moving average
            self._err_mean = 0.9 * self._err_mean + 0.1 * float(errors.mean())
            self._err_std  = 0.9 * self._err_std  + 0.1 * float(errors.std() + 1e-6)
            self._trained  = True
            self._buffer.clear()
            self._save()
            logger.debug(f"[AegisCore:PCA] partial_fit: err_mean={self._err_mean:.4f} std={self._err_std:.4f}")
        except Exception as e:
            logger.debug(f"[AegisCore:PCA] partial_fit hatası: {e}")
            self._buffer.clear()

    def _reconstruct(self, X_scaled: np.ndarray) -> np.ndarray:
        components = self._ipca.transform(X_scaled)
        return self._ipca.inverse_transform(components)

    def predict(self, features: np.ndarray) -> MLResult:
        if not self._trained:
            return MLResult(model="incremental_pca", score=0, anomaly=False,
                           details={"status": "warmup", "samples": len(self._buffer)})
        try:
            X = self._scaler.transform(features.reshape(1, -1))
            recon  = self._reconstruct(X)
            error  = float(np.mean((X - recon) ** 2))
            threshold = self._err_mean + self._threshold_multiplier * self._err_std
            # 0-100 normalize
            score = min((error / max(threshold, 1e-6)) * 70, 100)
            return MLResult(
                model="incremental_pca",
                score=score,
                anomaly=(error > threshold),
                threshold=threshold,
                details={"recon_error": error, "threshold": threshold,
                         "err_mean": self._err_mean, "err_std": self._err_std}
            )
        except Exception as e:
            logger.debug(f"[AegisCore:PCA] Predict hatası: {e}")
            return MLResult(model="incremental_pca", score=0, anomaly=False)



# ── 2. EWMA Detector ──────────────────────────────────────────────────────────

class EWMADetector:
    """
    Exponentially Weighted Moving Average anomali tespiti.

    Zaman serisi üzerinde ani spike ve burst'leri yakalar.
    Isolation Forest'in kaçırabileceği hızlı değişimleri tespit eder.

    Çalışma mantığı:
      - Her event için 3 EWMA sinyali takip edilir:
        * event_rate   : olay hızı (son N saniyedeki event sayısı)
        * failure_rate : başarısızlık oranı
        * score_rate   : anomali skor ortalaması
      - Her sinyal için rolling mean ve std hesaplanır
      - z-score > threshold ise anomali

    Ortam bağımsızlığı: Çok iyi
      - Kendi zaman serisini öğrenir, sabit parametre yok
      - Her makinenin kendi "normal hızını" öğrenir
    """

    def __init__(self, config: Dict = None, model_dir: str = "data/models"):
        cfg = config or {}
        self.alpha         = cfg.get("ewma_alpha", 0.1)      # düzleştirme faktörü
        self.z_threshold   = cfg.get("ewma_z_threshold", 3.5) # kaç sigma = anomali
        self.min_samples   = cfg.get("warmup_samples", 100)   # warmup için minimum
        self.model_dir     = Path(model_dir)

        # Three EWMA signals, each tracked independently
        self._signals = {
            "event_rate":   {"mean": None, "var": 0.0, "n": 0},
            "failure_rate": {"mean": None, "var": 0.0, "n": 0},
            "score":        {"mean": None, "var": 0.0, "n": 0},
        }
        # Sliding counters for the time window
        self._window_events:   int   = 0
        self._window_failures: int   = 0
        self._window_start:    float = time.time()
        self._window_size:     float = 60.0  # 60 saniyelik pencere

        self._trained  = False
        self._n_total  = 0
        self._load()

    def _load(self):
        p = self.model_dir / "ewma.joblib"
        if p.exists():
            try:
                data = joblib.load(p)
                self._signals = data["signals"]
                self._n_total = data.get("n_total", 0)
                self._trained = self._n_total >= self.min_samples
                logger.info(f"[AegisCore:EWMA] Kayitli model yuklendi (n={self._n_total}).")
            except Exception as e:
                logger.warning(f"[AegisCore:EWMA] Yuklenemedi: {e}")

    def _save(self):
        """Atomic save."""
        try:
            target = self.model_dir / "ewma.joblib"
            with tempfile.NamedTemporaryFile(
                dir=self.model_dir, delete=False, suffix=".tmp"
            ) as tf:
                joblib.dump({"signals": self._signals, "n_total": self._n_total}, tf.name)
            os.replace(tf.name, target)
        except Exception as e:
            logger.error(f"[AegisCore:EWMA] Kayit hatasi: {e}")

    def _ewma_update(self, key: str, value: float):
        """Welford online variance + EWMA guncelleme."""
        s = self._signals[key]
        if s["mean"] is None:
            s["mean"] = value
            s["var"]  = 0.0
            s["n"]    = 1
        else:
            s["n"] += 1
            old_mean = s["mean"]
            s["mean"] = (1 - self.alpha) * s["mean"] + self.alpha * value
            s["var"]  = (1 - self.alpha) * (s["var"] + self.alpha * (value - old_mean) ** 2)

    def _ewma_zscore(self, key: str, value: float) -> float:
        s = self._signals[key]
        if s["mean"] is None or s["n"] < 10:
            return 0.0
        std = max(s["var"] ** 0.5, 1e-6)
        return abs(value - s["mean"]) / std

    def update(self, event, ml_score: float = 0.0,
               should_learn: bool = True) -> "MLResult":
        """
        Event'i isle, EWMA'yi guncelle, anomali skorunu dondur.

        ml_score: diger modellerden gelen ham skor (0-100)
        """
        now = time.time()

        # Pencereyi yenile
        elapsed = now - self._window_start
        if elapsed >= self._window_size:
            event_rate   = self._window_events   / max(elapsed, 1)
            failure_rate = self._window_failures / max(self._window_events, 1)

            z_event   = self._ewma_zscore("event_rate",   event_rate)
            z_failure = self._ewma_zscore("failure_rate", failure_rate)
            z_score   = self._ewma_zscore("score",        ml_score)

            if should_learn:
                self._ewma_update("event_rate",   event_rate)
                self._ewma_update("failure_rate", failure_rate)
                self._ewma_update("score",        ml_score)
                self._n_total += 1
                if self._n_total >= self.min_samples:
                    self._trained = True
                if self._n_total % 100 == 0:
                    self._save()

            # Pencereyi sifirla
            self._window_events   = 0
            self._window_failures = 0
            self._window_start    = now

            if self._trained:
                z_max    = max(z_event, z_failure, z_score)
                anomaly  = z_max > self.z_threshold
                score    = min((z_max / self.z_threshold) * 60, 100.0)
                return MLResult(
                    model   = "ewma",
                    score   = score,
                    anomaly = anomaly,
                    details = {
                        "z_event_rate":   round(z_event,   2),
                        "z_failure_rate": round(z_failure, 2),
                        "z_score":        round(z_score,   2),
                        "z_max":          round(z_max,     2),
                        "threshold":      self.z_threshold,
                    }
                )

        # Pencere icinde sayaci artir
        self._window_events += 1
        if getattr(event, "outcome", "") == "failure":
            self._window_failures += 1

        return MLResult(model="ewma", score=0, anomaly=False,
                       details={"status": "warmup" if not self._trained else "in_window",
                                "samples": self._n_total})
# ── InstantMLEngine (orchestrator) ───────────────────────────────────

class InstantMLEngine:
    """
    ML modellerini birlikte yönetir.

    FAZ 1 modelleri (az veriyle devreye girer):
      - IsolationForest  : genel anomali, hızlı eğitim
      - EWMA             : spike/burst tespiti, sıfır gecikme
      - IncrementalPCA   : reconstruction error anomalisi
    """

    def __init__(self, config: Dict = None, model_dir: str = "data/models",
                 distro_family: str = "unknown"):
        cfg    = config or {}
        ml_cfg = cfg.get("ml", {})
        warmup = ml_cfg.get("warmup_samples", 200)

        if distro_family and distro_family not in ("unknown", ""):
            distro_model_dir = str(Path(model_dir) / distro_family)
        else:
            distro_model_dir = model_dir
        Path(distro_model_dir).mkdir(parents=True, exist_ok=True)

        base_cfg = {"warmup_samples": warmup}

        self.iso   = IsolationForestDetector(
            {**base_cfg, **ml_cfg.get("isolation_forest", {})}, distro_model_dir)
        self.ewma  = EWMADetector(
            {**base_cfg, **ml_cfg.get("ewma", {})}, distro_model_dir)
        self.pca   = IncrementalPCADetector(
            {**base_cfg, **ml_cfg.get("incremental_pca", {})}, distro_model_dir)

        self._event_count   = 0
        self._distro_family = distro_family
        self._model_dir     = distro_model_dir
        self._anomaly_count: dict = {"if": 0, "ewma": 0, "pca": 0}
        logger.info(f"[AegisCore:ML] InstantMLEngine hazir (distro={distro_family}, "
                    f"model_dir={distro_model_dir}).")

    def process(self, event: NormalizedEvent,
                should_learn: bool = True) -> List[MLResult]:
        """
        Event'i al, feature cikar, ONCE tahmin et SONRA oren.

        Siralama kritik:
          1. predict() — mevcut modelle tahmin (event henuz ogrenilmemis)
          2. update()  — modeli yeni event ile guncelle
        """
        features = extract_features(event)
        self._event_count += 1

        # ONCE predict
        iso_r = self.iso.predict(features)
        pca_r = self.pca.predict(features)

        # EWMA: event + diger model skorlarini kullanir (spike detect icin)
        avg_score = (iso_r.score + pca_r.score) / 2
        ewma_r = self.ewma.update(event, ml_score=avg_score, should_learn=should_learn)

        results = [iso_r, ewma_r, pca_r]

        # SONRA update — temiz event'lerle oren
        if should_learn:
            self.iso.update(features)
            self.pca.update(features)

        # Update the anomaly counter per model
        for r in results:
            if r.anomaly and r.score > 30:
                key = {
                    "isolation_forest": "if",
                    "ewma": "ewma",
                    "incremental_pca": "pca",
                }.get(r.model, r.model)
                if key in self._anomaly_count:
                    self._anomaly_count[key] += 1

        # Return all results, anomaly and normal alike, so the calibrator sees every score
        # Ana pipeline anomali filtrelemesini kendi yapar
        return results

    def status(self) -> Dict:
        n = max(self._event_count, 1)
        return {
            "events_processed": self._event_count,
            "anomaly_rates":    {k: round(v/n, 4) for k, v in self._anomaly_count.items()},
            "anomaly_counts":   dict(self._anomaly_count),
            "if_trained":       self.iso._trained,
            "ewma_trained":     self.ewma._trained,
            "pca_trained":      self.pca._trained,
            "if_buffer":        len(self.iso._buffer),
            "pca_buffer":       len(self.pca._buffer),
        }


# ── Test ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    logging.basicConfig(level=logging.INFO)

    from core.normalize import Normalizer
    norm = Normalizer()
    engine = InstantMLEngine(
        config={"ml": {"warmup_samples": 20}},  # test için düşük eşik
        model_dir="/tmp/test_models"
    )

    # Warm up with normal logs
    normal_logs = [
        "Mar  5 09:00:00 host sshd[100]: Accepted password for alice from 192.168.1.10 port 22222 ssh2",
        "Mar  5 09:05:00 host sudo[101]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
        "Mar  5 10:00:00 host sshd[102]: Accepted password for bob from 192.168.1.11 port 22223 ssh2",
    ] * 15  # 45 normal event

    print("Normal eventler ile ısınılıyor...")
    for raw in normal_logs:
        evt = norm.normalize(raw, "auth.log")
        if evt:
            engine.process(evt)

    print(f"\nStatus: {engine.status()}\n")

    # Anormal log
    anomaly_log = "Mar  5 03:00:00 host sshd[999]: Accepted password for root from 185.220.101.1 port 1337 ssh2"
    evt = norm.normalize(anomaly_log, "auth.log")
    results = engine.process(evt)
    print(f"Anormal event sonuçları ({len(results)} anomali):")
    for r in results:
        print(f"  [{r.model}] score={r.score:.1f} anomaly={r.anomaly} details={r.details}")
