from __future__ import annotations
"""
core/ml/learning_guard.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE_0 Güçlendirme Modülleri

1. ConfidenceScorer     — event'e PHASE_0 güven puanı
2. DelayedLearningBuffer — öğrenme gecikmesi (30-60dk)
3. RareEventFilter      — nadir event ML bloğu
4. AnomalyGuard         — login rate anomaly
5. BaselineValidator    — PHASE_1 geçişi için temizlik kontrolü
"""

import time
import math
import logging
from datetime import datetime, timezone
UTC = timezone.utc
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── 1. Confidence Scorer ──────────────────────────────────────────────────────

class ConfidenceScorer:
    """
    Kural tetiklenmese bile event'e risk puanı verir.
    Düşük güvenli event'ler ML'e hemen girmiyor.
    """

    def __init__(self):
        self._user_first_seen:    Dict[str, float] = {}
        self._binary_freq:        Dict[str, int]   = {}
        self._hour_counts:        Dict[int, int]   = defaultdict(int)
        self._total              = 0

    def score(self, event, should_learn: bool = True) -> float:
        """
        0.0 = tamamen guvensiz (ML'e girmesin)
        1.0 = tamamen guvenilir (ML'e girsin)

        should_learn=False: Sadece skor hesapla, iç state'i GUNCELLEME.
        Suphecli/saldiri event'leri scorer'i normalize etmesin (P-4 fix).
        """
        penalties = 0.0
        ts = getattr(event, 'ts', None) or time.time()
        # Tek zaman standardi: epoch'u her yerde UTC olarak yorumla.
        # Aksi halde gece cezasini UTC, hafta sonunu local time ile hesaplamak
        # ayni event icin tutarsiz davranis uretebilir.
        dt_utc = datetime.fromtimestamp(ts, UTC)
        hour = dt_utc.hour

        # Yeni kullanici davranisi
        user = getattr(event, 'user', '') or ""
        if user and user not in self._user_first_seen:
            if should_learn:
                self._user_first_seen[user] = ts
            penalties += 0.3
        elif user and (ts - self._user_first_seen.get(user, ts)) < 3600:
            penalties += 0.1   # ilk 1 saatte yari ceza

        # Nadir binary — only read state, don't write if not learning
        proc = getattr(event, 'process', '') or ""
        if proc:
            if should_learn:
                self._binary_freq[proc] = self._binary_freq.get(proc, 0) + 1
            total = max(self._total, 1)
            freq  = self._binary_freq.get(proc, 0) / total
            if freq < 0.01:
                penalties += 0.25   # cok nadir binary

        # Alisilagelmedik saat (gece 00-05)
        if 0 <= hour <= 5:
            penalties += 0.2

        # Hafta sonu
        if dt_utc.weekday() >= 5:
            penalties += 0.1

        # State guncelleme: sadece temiz event'ler icin
        if should_learn:
            self._total += 1
            self._hour_counts[hour] += 1

        confidence = max(0.0, 1.0 - penalties)
        return round(confidence, 3)


# ── 2. Delayed Learning Buffer ────────────────────────────────────────────────

class DelayedLearningBuffer:
    """
    Event'i hemen öğrenmez. Buffer'a alır, delay_seconds sonra
    tekrar değerlendirir. Bu sürede alarm/IOC/high-risk geldiyse öğrenmez.

    Sıkılaştırma (v2):
    - Entity key: user + src_ip + process — süreç bazlı izolasyon
    - Alarm türüne göre farklı karantina süresi (IOC > critical > high > medium)
    - Alarm gören entity'nin karantina süresi bitmeden buffer'a tekrar girse bile
      quarantine uzar (sliding window)
    - Yüksek riskli action pattern'ları (lotl, exec_suspicious) hemen trainable=False
    """

    # Quarantine multiplier by alarm type, applied on top of delay_seconds
    QUARANTINE_MULTIPLIER = {
        "ioc":      12,   # IOC: delay * 12 (varsayılan 30dk → 6 saat)
        "critical":  8,   # Kritik alarm: delay * 8 → 4 saat
        "high":      6,   # Yüksek: delay * 6 → 3 saat
        "medium":    4,   # Orta: delay * 4 → 2 saat (eski davranış)
        "low":       2,   # Düşük: delay * 2 → 1 saat
    }

    # If these actions appear, force trainable=False and keep them out of learning
    SUSPICIOUS_ACTIONS = {
        "exec_suspicious", "lotl_exec", "bash_pipe", "curl_exec",
        "wget_exec", "memfd_create", "ptrace", "ld_preload",
        "process_inject", "crontab_edit", "service_created",
    }

    def __init__(self, delay_seconds: int = 1800):  # 30 dakika
        self.delay_seconds = delay_seconds
        # {event_key: (event, ts_added, trainable)}
        self._buffer: Dict[str, Tuple] = {}
        # entity → {alarm_type: ts} — keep alarm type and timestamp separately
        self._alarm_entities: Dict[str, Dict[str, float]] = defaultdict(dict)

    def _entity_keys(self, event) -> List[str]:
        """Return all entity keys associated with an event."""
        keys = []
        user    = getattr(event, 'user',    None)
        src_ip  = getattr(event, 'src_ip',  None)
        process = getattr(event, 'process', None)
        if user:    keys.append(user)
        if src_ip:  keys.append(src_ip)
        if process: keys.append(f"proc:{process}")
        if user and src_ip:
            keys.append(f"{user}@{src_ip}")
        return keys

    def add(self, event, trainable: bool) -> None:
        # If the action is suspicious, start with trainable=False
        action = getattr(event, 'action', '') or ""
        if action in self.SUSPICIOUS_ACTIONS:
            trainable = False
        # If the LOLBin flag is present, block learning
        if getattr(event, "fields", {}).get("lotl"):
            trainable = False

        user    = getattr(event, 'user',    '') or ''
        src_ip  = getattr(event, 'src_ip',  '') or ''
        process = getattr(event, 'process', '') or ''
        key = f"{user}|{src_ip}|{process}|{action}"
        self._buffer[key] = (event, time.time(), trainable)

    def mark_alarm(self, entity: str, alarm_type: str = "medium") -> None:
        """
        Alarm gelince entity'yi işaretle.
        alarm_type: 'ioc' | 'critical' | 'high' | 'medium' | 'low'
        Eğer entity zaten karantinada ve yeni alarm daha ağırsa, güncelle.
        """
        now = time.time()
        existing = self._alarm_entities[entity]
        # Preserve the most severe alarm and extend the window on each new alarm
        existing[alarm_type] = now

    def mark_ioc(self, entity: str) -> None:
        """IOC match — longest quarantine duration."""
        self.mark_alarm(entity, "ioc")

    def _quarantine_seconds(self, entity: str) -> float:
        """Compute the active quarantine duration for this entity."""
        if entity not in self._alarm_entities:
            return 0.0
        now = time.time()
        max_quarantine = 0.0
        for alarm_type, alarm_ts in self._alarm_entities[entity].items():
            multiplier = self.QUARANTINE_MULTIPLIER.get(alarm_type, 4)
            # delay_seconds=0 (test modu) olsa bile alarm varsa minimum 1sn karantina
            base_seconds = max(self.delay_seconds, 1)
            quarantine   = base_seconds * multiplier
            elapsed      = now - alarm_ts
            remaining    = quarantine - elapsed
            if remaining > max_quarantine:
                max_quarantine = remaining
        return max_quarantine

    def flush_ready(self) -> List[Tuple]:
        """
        Süresi dolmuş eventleri döndür.
        Alarm karantinası aktif olan entity'lerin trainable'ı False'a çevrilir.
        """
        now    = time.time()
        ready  = []
        remove = []

        for key, (event, ts_added, trainable) in self._buffer.items():
            if now - ts_added >= self.delay_seconds:
                # Check every entity key
                blocked = False
                for ek in self._entity_keys(event):
                    if self._quarantine_seconds(ek) > 0:
                        blocked = True
                        break

                final_trainable = trainable and not blocked
                ready.append((event, final_trainable))
                remove.append(key)

        for k in remove:
            del self._buffer[k]

        # Remove quarantine records whose duration has expired
        now = time.time()
        for entity in list(self._alarm_entities.keys()):
            base_seconds = max(self.delay_seconds, 1)
            active = {
                t: ts for t, ts in self._alarm_entities[entity].items()
                if (now - ts) < base_seconds * self.QUARANTINE_MULTIPLIER.get(t, 4)
            }
            if active:
                self._alarm_entities[entity] = active
            else:
                del self._alarm_entities[entity]

        return ready

    def size(self) -> int:
        return len(self._buffer)

    def quarantine_status(self) -> Dict:
        """Return entities that are currently under quarantine."""
        now = time.time()
        result = {}
        for entity, alarms in self._alarm_entities.items():
            remaining = self._quarantine_seconds(entity)
            if remaining > 0:
                result[entity] = {
                    "remaining_minutes": round(remaining / 60, 1),
                    "alarm_types": list(alarms.keys()),
                }
        return result


# ── 3. Rare Event Filter ──────────────────────────────────────────────────────

class RareEventFilter:
    """
    Çok nadir görülen event'leri ML'e hemen öğretmez.
    "candidate_normal" olarak tutar, tekrar görülünce kabul eder.
    """

    def __init__(self, min_occurrences: int = 3, window_seconds: int = 3600):
        self.min_occurrences = min_occurrences
        self.window_seconds  = window_seconds
        # {fingerprint: deque of timestamps}
        self._seen: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

    def _fingerprint(self, event) -> str:
        source   = getattr(event, 'source',   '') or ''
        category = getattr(event, 'category', '') or ''
        action   = getattr(event, 'action',   '') or ''
        user     = getattr(event, 'user',     '') or ''
        return f"{source}|{category}|{action}|{user}"

    def is_rare(self, event, should_learn: bool = True) -> bool:
        """True donerse → nadir, ML'e ogretme.

        should_learn=False: Sadece sor, sayaci artirma.
        Saldiri event'leri rare filtreyi normalize etmesin (P-5 fix).
        """
        fp  = self._fingerprint(event)
        now = time.time()

        # Eski kayitlari temizle
        dq = self._seen[fp]
        while dq and now - dq[0] > self.window_seconds:
            dq.popleft()

        if should_learn:
            dq.append(now)

        count = len(dq)

        if count < self.min_occurrences:
            logger.debug(f"[RareFilter] Nadir event ({count}/{self.min_occurrences}): {fp}")
            return True
        return False

    def stats(self) -> Dict:
        return {"tracked_patterns": len(self._seen)}


# ── 4. Anomaly Guard ──────────────────────────────────────────────────────────

class AnomalyGuard:
    """
    PHASE_0 içinde basit istatistiksel kontrol.
    Kural motoru kaçırsa bile şu patternleri durdurur:
    - Event frequency spike
    - Login rate anomaly
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        # {key: deque of timestamps}
        self._counters: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))

    def _count_in_window(self, key: str, now: float) -> int:
        dq = self._counters[key]
        while dq and now - dq[0] > self.window_seconds:
            dq.popleft()
        return len(dq)

    def record(self, event) -> Optional[Dict]:
        """
        Event'i kaydet. Anomali varsa dict döndür, yoksa None.
        """
        now = time.time()
        alerts = []

        action  = getattr(event, 'action',  '') or ''
        outcome = getattr(event, 'outcome', '') or ''
        src_ip  = getattr(event, 'src_ip',  '') or ''
        user    = getattr(event, 'user',    '') or ''

        # ── Login rate anomaly ─────────────────────────────────────────────
        if action in ("ssh_login", "session_open") and outcome == "failure":
            ip_key = f"login_fail:{src_ip or 'unknown'}"
            self._counters[ip_key].append(now)
            count = self._count_in_window(ip_key, now)
            if count >= 20:
                alerts.append({
                    "type":    "login_rate_anomaly",
                    "message": f"Yüksek login failure oranı: {count}/{self.window_seconds}s — {src_ip}",
                    "score":   min(50 + count, 95),
                })

        if alerts:
            return {
                "guard_type": "anomaly_guard",
                "alerts":     alerts,
                "top_score":  max(a["score"] for a in alerts),
            }
        return None

    def stats(self) -> Dict:
        return {
            "tracked_counters": len(self._counters),
        }


# ── 5. Baseline Validator ─────────────────────────────────────────────────────

class BaselineValidator:
    """
    PHASE_1'e geçmeden önce ortamın temiz olduğunu doğrular.
    Aktif incident, IOC hit, brute force varsa geçişi engeller.
    """

    def __init__(self, clean_window_hours: float = 2.0):
        self.clean_window_seconds = clean_window_hours * 3600
        self._last_critical_ts:  Optional[float] = None
        self._last_ioc_ts:       Optional[float] = None
        self._last_bruteforce_ts: Optional[float] = None
        self._block_reason:      str = ""

    def record_incident(self, severity: str) -> None:
        if severity in ("critical", "high"):
            self._last_critical_ts = time.time()

    def record_ioc(self) -> None:
        self._last_ioc_ts = time.time()

    def record_bruteforce(self) -> None:
        self._last_bruteforce_ts = time.time()

    def can_advance_to_phase1(self) -> Tuple[bool, str]:
        """
        True, "" → geçiş onaylandı
        False, reason → geçiş engellendi
        """
        now = time.time()
        window = self.clean_window_seconds

        if self._last_critical_ts and (now - self._last_critical_ts) < window:
            remaining = (window - (now - self._last_critical_ts)) / 60
            reason = f"Kritik/yüksek incident — {remaining:.0f} dakika daha bekle"
            self._block_reason = reason
            return False, reason

        if self._last_ioc_ts and (now - self._last_ioc_ts) < window:
            remaining = (window - (now - self._last_ioc_ts)) / 60
            reason = f"IOC tespiti — {remaining:.0f} dakika daha bekle"
            self._block_reason = reason
            return False, reason

        if self._last_bruteforce_ts and (now - self._last_bruteforce_ts) < (window / 2):
            remaining = (window / 2 - (now - self._last_bruteforce_ts)) / 60
            reason = f"Brute force tespiti — {remaining:.0f} dakika daha bekle"
            self._block_reason = reason
            return False, reason

        self._block_reason = ""
        return True, ""

    def status(self) -> Dict:
        can, reason = self.can_advance_to_phase1()
        return {
            "can_advance":       can,
            "block_reason":      reason,
            "last_critical_ago": (time.time() - self._last_critical_ts) / 60 if self._last_critical_ts else None,
            "last_ioc_ago":      (time.time() - self._last_ioc_ts) / 60 if self._last_ioc_ts else None,
            "last_bf_ago":       (time.time() - self._last_bruteforce_ts) / 60 if self._last_bruteforce_ts else None,
        }

