from __future__ import annotations
"""
core/ml/calibration.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 4: Score calibration layer

Calibrates raw scores so they behave consistently across machines.
The same score can mean different things on different systems; this module normalizes it.

Methods:
  1. QuantileCalibrator      - converts a raw score to a percentile
  2. WarmupGuard             - applies a higher threshold when data is still sparse
  3. ScoreCalibrationEngine  - combines both
"""

import time
import logging
import numpy as np
import joblib
from pathlib import Path
from typing import Dict, Optional, List
from collections import deque

logger = logging.getLogger(__name__)


# -- 1. Quantile Calibrator --------------------------------------------------

class QuantileCalibrator:
    """
    Normalizes an incoming raw score against the historical score distribution.
    
    Example:
      Raw score 75 -> 95th percentile on this host -> calibrated score 95
      This keeps the percentile consistent even if a score of 75 means different threat levels on different hosts.
      
    """

    def __init__(self, window_size: int = 10000):
        self.window_size = window_size
        self._history: deque = deque(maxlen=window_size)
        self._sorted_cache: Optional[np.ndarray] = None
        self._cache_dirty = True

    def update(self, score: float):
        """Append a new score to history."""
        self._history.append(score)
        self._cache_dirty = True

    def calibrate(self, score: float) -> float:
        """
        Convert the raw score to a 0-100 percentile.
        Return the raw score if there is not enough history.
        """
        if len(self._history) < 50:
            return score  # not enough history yet

        if self._cache_dirty:
            self._sorted_cache = np.sort(list(self._history))
            self._cache_dirty  = False

        # Determine which percentile bucket the score falls into
        pct = float(np.searchsorted(self._sorted_cache, score, side='right'))
        pct = (pct / len(self._sorted_cache)) * 100
        return round(pct, 2)

    def get_threshold_for_percentile(self, pct: float) -> float:
        """Return the raw-score threshold for the requested percentile."""
        if len(self._history) < 50:
            return 70.0  # default high threshold

        if self._cache_dirty:
            self._sorted_cache = np.sort(list(self._history))
            self._cache_dirty  = False

        return float(np.percentile(self._sorted_cache, pct))

    @property
    def sample_count(self) -> int:
        return len(self._history)

    def save(self, path: str):
        joblib.dump(list(self._history), path)

    def load(self, path: str):
        p = Path(path)
        if p.exists():
            try:
                self._history = deque(joblib.load(p), maxlen=self.window_size)
                self._cache_dirty = True
                logger.info(f"[CALIBRATOR] Loaded {len(self._history)} historical scores.")
            except Exception as e:
                logger.warning(f"[CALIBRATOR] Load failed: {e}")


# -- 2. Warmup Guard ---------------------------------------------------------

class WarmupGuard:
    """
    Applies a dynamic threshold before enough data has been collected to reduce false positives.
    
    
    During warmup:
      - The ML anomaly threshold stays high (fewer alerts)
      - The threshold drops to normal after warmup completes
    
    Warmup progress: 0.0 -> 1.0
    """

    def __init__(self, warmup_samples: int = 200,
                 high_threshold: float = 90.0,
                 normal_threshold: float = 70.0):
        self.warmup_samples   = warmup_samples
        self.high_threshold   = high_threshold
        self.normal_threshold = normal_threshold
        self._sample_count    = 0
        self._warmup_complete = False
        self._warmup_start    = time.time()

    def tick(self, n: int = 1):
        """Increment the event counter."""
        self._sample_count += n
        if not self._warmup_complete and self._sample_count >= self.warmup_samples:
            self._warmup_complete = True
            elapsed = time.time() - self._warmup_start
            logger.info(f"[WARMUP] Warmup tamamlandı: {self._sample_count} sample, "
                        f"{elapsed:.0f} sn sürdü. Normal eşiğe geçiliyor.")

    @property
    def is_warmed_up(self) -> bool:
        return self._warmup_complete

    @property
    def progress(self) -> float:
        """Warmup progress ratio from 0.0 to 1.0."""
        return min(self._sample_count / self.warmup_samples, 1.0)

    def get_threshold(self) -> float:
        """Return the appropriate threshold for the current warmup state."""
        if self._warmup_complete:
            return self.normal_threshold
        # Linear interpolation: the threshold decreases gradually during warmup
        p = self.progress
        return self.high_threshold - p * (self.high_threshold - self.normal_threshold)

    def should_alert(self, calibrated_score: float) -> bool:
        """Should this score produce an alert?"""
        return calibrated_score >= self.get_threshold()

    def status(self) -> Dict:
        return {
            "warmed_up":    self._warmup_complete,
            "progress_pct": round(self.progress * 100, 1),
            "sample_count": self._sample_count,
            "threshold":    round(self.get_threshold(), 1),
        }


# ── 3. Score Calibration Engine ───────────────────────────────────────────────

class ScoreCalibrationEngine:
    """
    ML skorlarını kalibre eden ana motor.

    Pipeline:
      ham_skor → QuantileCalibrator → WarmupGuard → LabelCalibrator → final_karar

    LabelCalibrator:
      LabelEngine'den gelen (score, label, weight) üçlüleri birikir.
      < 1000 etiket → Platt scaling (parametrik, az veriye dayanıklı)
      ≥ 1000 etiket → Isotonic regression (daha esnek, overfit riski yok)
    Bu otomatik geçiş scikit-learn dökümantasyonuna dayanır.
    """

    def __init__(self, config: Dict = None, model_dir: str = "data/models",
                 label_engine=None):
        cfg = config or {}
        ml_cfg   = cfg.get("ml", {})
        risk_cfg = cfg.get("risk", {})

        warmup     = ml_cfg.get("warmup_samples", 200)
        high_thr   = 90.0
        normal_thr = risk_cfg.get("thresholds", {}).get("ml_alert", 70.0)

        self._calibrators: Dict[str, QuantileCalibrator] = {
            "isolation_forest": QuantileCalibrator(),
            "incremental_pca":  QuantileCalibrator(),
            "ensemble":         QuantileCalibrator(),
        }
        self._warmup = WarmupGuard(
            warmup_samples=warmup,
            high_threshold=high_thr,
            normal_threshold=normal_thr
        )
        self._model_dir = Path(model_dir)
        self._model_dir.mkdir(parents=True, exist_ok=True)

        # LabelEngine reference — may be None when DB is absent or not yet attached
        self._label_engine = label_engine
        # Platt/isotonic parametreleri (A*x + B → sigmoid)
        self._platt_A: float = 1.0
        self._platt_B: float = 0.0
        self._isotonic_bins: Optional[List] = None   # [(threshold, value), ...]
        self._label_count: int = 0
        self._ISOTONIC_THRESHOLD = 1000  # bu noktada platt→isotonic geçişi

        self._try_load()

    def _try_load(self):
        for name, cal in self._calibrators.items():
            path = self._model_dir / f"calibrator_{name}.joblib"
            cal.load(str(path))
        # Load the Platt parameters as well
        platt_path = self._model_dir / "label_calibration.joblib"
        if platt_path.exists():
            try:
                data = joblib.load(platt_path)
                self._platt_A      = data.get("platt_A", 1.0)
                self._platt_B      = data.get("platt_B", 0.0)
                self._isotonic_bins = data.get("isotonic_bins", None)
                self._label_count  = data.get("label_count", 0)
                logger.info(f"[Calibration] Label calibration yüklendi: "
                            f"{self._label_count} etiket, "
                            f"{'isotonic' if self._isotonic_bins else 'platt'}")
            except Exception as e:
                logger.warning(f"[Calibration] Label calibration yüklenemedi: {e}")

    def save(self):
        for name, cal in self._calibrators.items():
            path = self._model_dir / f"calibrator_{name}.joblib"
            cal.save(str(path))
        # Platt/isotonic parametrelerini kaydet
        platt_path = self._model_dir / "label_calibration.joblib"
        try:
            joblib.dump({
                "platt_A":      self._platt_A,
                "platt_B":      self._platt_B,
                "isotonic_bins": self._isotonic_bins,
                "label_count":  self._label_count,
            }, platt_path)
        except Exception as e:
            logger.warning(f"[Calibration] Label calibration kaydedilemedi: {e}")

    def set_label_engine(self, label_engine) -> None:
        """Attach LabelEngine later because of initialization order in main.py."""
        self._label_engine = label_engine
        self._fit_label_calibration()

    def _fit_label_calibration(self) -> None:
        """
        LabelEngine'den gelen etiketlerle Platt veya isotonic kalibrasyon uygula.
        < 1000 etiket → Platt scaling (sigmoid, 2 parametre, az veriye dayanıklı)
        ≥ 1000 etiket → Isotonic regression (esnek, overfit riski yok)
        Kaynak: scikit-learn calibration docs + Caruana et al. (ICML 2005)
        """
        if not self._label_engine:
            return

        data = self._label_engine.get_calibration_data()
        if len(data) < 10:
            return

        scores  = [d[0] for d in data]
        labels  = [d[1] for d in data]
        weights = [d[2] for d in data]
        n = len(data)
        self._label_count = n

        if n < self._ISOTONIC_THRESHOLD:
            # Platt scaling — logistic regression on scores
            # P(attack | score) = sigmoid(A * score + B)
            self._platt_A, self._platt_B = self._fit_platt(scores, labels, weights)
            self._isotonic_bins = None
            logger.info(f"[Calibration] Platt scaling güncellendi: "
                        f"n={n}, A={self._platt_A:.4f}, B={self._platt_B:.4f}")
        else:
            # Isotonic regression — piecewise monotone
            self._isotonic_bins = self._fit_isotonic(scores, labels, weights)
            logger.info(f"[Calibration] Isotonic regression güncellendi: "
                        f"n={n}, bins={len(self._isotonic_bins)}")

    def _fit_platt(self, scores, labels, weights):
        """Fit Platt parameters with weighted logistic regression."""
        import math
        # Gradient descent — avoid adding a scipy dependency
        A, B = 1.0, 0.0
        lr = 0.01
        for _ in range(500):
            dA = dB = 0.0
            for s, y, w in zip(scores, labels, weights):
                # Clamp exponent to avoid math.exp overflow (>709 → OverflowError)
                z = max(-500.0, min(500.0, -(A * s + B)))
                p = 1.0 / (1.0 + math.exp(z))
                err = (p - y) * w
                dA += err * s
                dB += err
            A -= lr * dA / len(scores)
            B -= lr * dB / len(scores)
        return A, B

    def _fit_isotonic(self, scores, labels, weights):
        """PAVA (Pool Adjacent Violators) ile isotonic regression."""
        paired = sorted(zip(scores, labels, weights), key=lambda x: x[0])
        bins = []
        for s, y, w in paired:
            bins.append([s, y * w, w])  # [score, weighted_sum, weight_sum]
            # PAVA — enforce monotonicity
            while len(bins) > 1:
                prev, curr = bins[-2], bins[-1]
                prev_val = prev[1] / prev[2] if prev[2] > 0 else 0
                curr_val = curr[1] / curr[2] if curr[2] > 0 else 0
                if prev_val <= curr_val:
                    break
                # Merge
                merged = [prev[0], prev[1] + curr[1], prev[2] + curr[2]]
                bins[-2:] = [merged]
        # Convert into (threshold, probability) pairs
        return [(b[0], b[1] / b[2] if b[2] > 0 else 0.0) for b in bins]

    def _apply_label_calibration(self, score: float) -> float:
        """
        Label kalibrasyonunu uygula — Platt veya isotonic.
        Sonuç: 0-100 aralığına dönüştürülmüş olasılık skoru.
        """
        import math

        if self._isotonic_bins and len(self._isotonic_bins) > 1:
            # Isotonic: find the nearest bin
            for i, (thr, prob) in enumerate(self._isotonic_bins):
                if score <= thr or i == len(self._isotonic_bins) - 1:
                    return round(prob * 100, 2)
            return round(self._isotonic_bins[-1][1] * 100, 2)

        elif self._label_count >= 10:
            # Platt scaling — clamp exponent to avoid OverflowError
            z = max(-500.0, min(500.0, -(self._platt_A * score + self._platt_B)))
            prob = 1.0 / (1.0 + math.exp(z))
            return round(prob * 100, 2)

        return score  # henüz yeterli etiket yok

    def refresh_label_calibration(self) -> None:
        """Refresh calibration when LabelEngine changes (periodic call)."""
        self._fit_label_calibration()

    def update(self, model_name: str, raw_score: float):
        """Append the raw score to the calibrator history."""
        if model_name in self._calibrators:
            self._calibrators[model_name].update(raw_score)
        self._warmup.tick()

    def calibrate(self, model_name: str, raw_score: float) -> Dict:
        """
        Ham skoru kalibre et, warmup ilerlet ve uyarı kararı ver.

        Pipeline:
          raw_score → QuantileCalibrator (percentile)
                    → LabelCalibration (Platt/isotonic, eğer etiket varsa)
                    → WarmupGuard → final karar

        Returns:
          {
            "raw_score":        float,
            "calibrated_score": float,
            "label_adjusted":   bool,    # label calibration uygulandı mı
            "threshold":        float,
            "should_alert":     bool,
            "warmup_progress":  float,
            "is_warmed_up":     bool,
            "sample_count":     int,
          }
        """
        cal = self._calibrators.get(model_name)
        if cal:
            calibrated = cal.calibrate(raw_score)
            cal.update(raw_score)
        else:
            calibrated = raw_score

        # Label calibration — etiket varsa uygula
        label_adjusted = False
        if self._label_count >= 10:
            calibrated = self._apply_label_calibration(calibrated)
            label_adjusted = True

        # Warmup
        self._warmup.tick()
        threshold    = self._warmup.get_threshold()
        should_alert = self._warmup.should_alert(calibrated)

        return {
            "raw_score":        round(raw_score, 2),
            "calibrated_score": round(calibrated, 2),
            "label_adjusted":   label_adjusted,
            "threshold":        round(threshold, 2),
            "should_alert":     should_alert,
            "warmup_progress":  round(self._warmup.progress * 100, 1),
            "is_warmed_up":     self._warmup.is_warmed_up,
            "sample_count":     cal.sample_count if cal else 0,
        }

    def calibrate_ensemble(self, model_scores: Dict[str, float]) -> Dict:
        """
        Birden fazla modelin skorunu ağırlıklı ortalamayla kalibre et.
        model_scores: {"isolation_forest": 65.0, "incremental_pca": 72.0, ...}
        """
        weights = {"isolation_forest": 0.55, "incremental_pca": 0.45}
        total_w = 0.0
        total_s = 0.0

        for model, score in model_scores.items():
            w = weights.get(model, 0.2)
            total_s += score * w
            total_w += w

        ensemble_raw = total_s / total_w if total_w > 0 else 0.0
        result = self.calibrate("ensemble", ensemble_raw)
        result["model_scores"] = model_scores
        return result

    def status(self) -> Dict:
        label_method = "none"
        if self._label_count >= self._ISOTONIC_THRESHOLD and self._isotonic_bins:
            label_method = f"isotonic (bins={len(self._isotonic_bins)})"
        elif self._label_count >= 10:
            label_method = f"platt (A={self._platt_A:.3f}, B={self._platt_B:.3f})"

        return {
            "warmup":      self._warmup.status(),
            "calibrators": {
                name: {"samples": cal.sample_count}
                for name, cal in self._calibrators.items()
            },
            "label_calibration": {
                "method":       label_method,
                "label_count":  self._label_count,
                "isotonic_threshold": self._ISOTONIC_THRESHOLD,
            },
        }


# ── Test ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = ScoreCalibrationEngine(
        config={"ml": {"warmup_samples": 50}},
        model_dir="/tmp/test_calibration"
    )

    print("Simüle edilen normal eventler ile kalibre ediliyor...\n")
    rng = np.random.RandomState(42)
    for i in range(60):
        score = float(rng.normal(30, 10))  # normal dağılım
        score = max(0, min(100, score))
        engine.update("isolation_forest", score)

    # Kalibrasyonu test et
    test_scores = [20, 35, 50, 65, 80, 95]
    print(f"{'Ham Skor':>10} | {'Kalibre':>10} | {'Eşik':>8} | {'Alert?':>8} | Warmup%")
    print("-" * 65)
    for s in test_scores:
        r = engine.calibrate("isolation_forest", s)
        print(f"{s:>10} | {r['calibrated_score']:>10.1f} | "
              f"{r['threshold']:>8.1f} | {str(r['should_alert']):>8} | "
              f"{r['warmup_progress']:.0f}%")

    print(f"\nStatus: {engine.status()}")


# ── HostCalibrationStore ──────────────────────────────────────────────────────

class HostCalibrationStore:
    """
    5a: Per-host score normalizasyonu.

    Sorun: Gürültülü bir host (örn. yoğun web sunucusu) sürekli yüksek skor
    üretir → global threshold her şeyi alert'e taşır → FP patlar.
    Sessiz bir host (örn. DB sunucusu) küçük sapmalarda bile alert üretmez
    → FN riski.

    Çözüm: Her host için ayrı QuantileCalibrator. Ham skor → host'un kendi
    geçmiş dağılımına göre normalize edilir → global threshold tutarlı çalışır.

    Kullanım:
        store = HostCalibrationStore()
        cal_score = store.calibrate("webserver01", "ml_if", raw_score=72.0)
        store.update("webserver01", "ml_if", raw_score=72.0)
    """

    def __init__(self,
                 window_size:    int   = 5000,
                 min_samples:    int   = 50,
                 max_hosts:      int   = 200,
                 save_dir:       str   = "data/models"):
        self.window_size = window_size
        self.min_samples = min_samples   # en az bu kadar veri olmadan normalizasyon yapma
        self.max_hosts   = max_hosts     # bellek koruması
        self.save_dir    = Path(save_dir)

        # {host: {model_name: QuantileCalibrator}}
        self._calibrators: Dict[str, Dict[str, QuantileCalibrator]] = {}
        # {host: sample_count}
        self._sample_counts: Dict[str, int] = {}
        # LRU-like structure: list of most recently seen hosts
        self._host_order: list = []

        self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def update(self, host: str, model_name: str, raw_score: float) -> None:
        """Ham skoru host+model kalibrasyonuna ekle."""
        if not host:
            return
        self._evict_if_needed()
        cal = self._get_or_create(host, model_name)
        cal._history.append(raw_score)
        self._sample_counts[host] = self._sample_counts.get(host, 0) + 1
        # Update LRU order
        if host in self._host_order:
            self._host_order.remove(host)
        self._host_order.append(host)

    def calibrate(self, host: str, model_name: str,
                  raw_score: float) -> float:
        """
        Ham skoru host'un baseline'ına göre normalize et.

        Yöntem: Z-score bazlı shift.
          cal = raw - (host_mean - global_mean)
        Gürültülü host (yüksek mean) → skor aşağı çekilir → FP azalır.
        Sessiz host (düşük mean) → skor yukarı itilir → FN azalır.

        Yeterli veri yoksa ham skoru döndür (pass-through).
        """
        if not host or self._sample_counts.get(host, 0) < self.min_samples:
            return raw_score

        cal_obj = self._get_or_create(host, model_name)
        history = cal_obj._history
        if len(history) < self.min_samples:
            return raw_score

        import numpy as _np
        arr       = _np.array(list(history))
        host_mean = float(_np.mean(arr))
        # Global reference: 50.0 (middle of the score range)
        GLOBAL_MEAN = 50.0
        shift     = host_mean - GLOBAL_MEAN
        cal_score = raw_score - shift
        return float(_np.clip(cal_score, 0.0, 100.0))

    def host_stats(self) -> Dict[str, Dict]:
        """Return sample count and calibration state for each host."""
        result = {}
        for host, count in self._sample_counts.items():
            result[host] = {
                "sample_count": count,
                "ready":        count >= self.min_samples,
                "models":       list(self._calibrators.get(host, {}).keys()),
            }
        return result

    def save(self) -> None:
        """Persist all host calibrations to disk."""
        try:
            self.save_dir.mkdir(parents=True, exist_ok=True)
            path = self.save_dir / "host_calibration_store.joblib"
            tmp  = path.with_suffix(".tmp")
            import joblib as _jl
            _jl.dump({
                "calibrators":   self._calibrators,
                "sample_counts": self._sample_counts,
                "host_order":    self._host_order,
            }, tmp)
            import os
            os.replace(tmp, path)
            logger.debug(f"[HostCalibStore] {len(self._calibrators)} host kaydedildi.")
        except Exception as e:
            logger.warning(f"[HostCalibStore] Kaydetme hatası: {e}")

    # ── Private ───────────────────────────────────────────────────────────────

    def _get_or_create(self, host: str, model_name: str) -> "QuantileCalibrator":
        if host not in self._calibrators:
            self._calibrators[host] = {}
        if model_name not in self._calibrators[host]:
            self._calibrators[host][model_name] = QuantileCalibrator(
                window_size=self.window_size
            )
        return self._calibrators[host][model_name]

    def _evict_if_needed(self) -> None:
        """Evict the oldest host (LRU) when max_hosts is exceeded."""
        while len(self._calibrators) >= self.max_hosts and self._host_order:
            oldest = self._host_order.pop(0)
            self._calibrators.pop(oldest, None)
            self._sample_counts.pop(oldest, None)
            logger.debug(f"[HostCalibStore] LRU evict: {oldest}")

    def _load(self) -> None:
        """Load previously saved calibrations."""
        path = self.save_dir / "host_calibration_store.joblib"
        if not path.exists():
            return
        try:
            import joblib as _jl
            data = _jl.load(path)
            self._calibrators   = data.get("calibrators", {})
            self._sample_counts = data.get("sample_counts", {})
            self._host_order    = data.get("host_order", [])
            logger.info(
                f"[HostCalibStore] {len(self._calibrators)} host kalibrasyonu yüklendi."
            )
        except Exception as e:
            logger.warning(f"[HostCalibStore] Yükleme hatası: {e}")
