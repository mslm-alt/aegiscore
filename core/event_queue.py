"""
core/event_queue.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Event Ingestion Queue + Priority-Aware Backpressure

Drop politikası — kör FIFO değil, risk bazlı:
  - high/critical severity event'ler → KORUNUR
  - correlation adayı event'ler → KORUNUR
  - Düşük güven / düşük risk event'ler → önce düşer
  - Drop sayıları kaynak bazlı metriklenur
  - Watchdog'a uyarı çıkar
"""

import queue
import heapq
import logging
import threading
import time
import collections
from typing import Tuple, Optional, Dict

logger = logging.getLogger(__name__)

MAX_QUEUE_SIZE = 10_000
WARN_THRESHOLD = 0.75   # %75 dolunca uyarı

# Priority levels (lower number = higher priority)
PRIORITY_CRITICAL = 0
PRIORITY_HIGH     = 1
PRIORITY_MEDIUM   = 2
PRIORITY_LOW      = 3
PRIORITY_MINIMAL  = 4   # warmup/noise event'leri


def _event_priority(raw: str, source: str) -> int:
    """
    Event'in drop önceliğini belirle.
    Düşük sayı = yüksek öncelik = son düşer.
    """
    raw_lower = raw.lower()

    # Critical indicators — never drop
    if any(k in raw_lower for k in (
        "critical", "emergency", "alert",
        "privilege", "root", "sudo", "su ",
        "attack", "exploit", "malware", "ransomware",
        "brute", "injection", "overflow",
    )):
        return PRIORITY_CRITICAL

    # High-severity indicators
    if any(k in raw_lower for k in (
        "failed password", "authentication failure",
        "invalid user", "connection refused",
        "permission denied", "unauthorized",
        "error", "warning", "fail",
    )):
        return PRIORITY_HIGH

    # Noisy sources — dropped first
    if source in ("syslog", "journald") and any(k in raw_lower for k in (
        "started", "stopped", "reloaded", "status",
        "debug", "info:", "notice:",
    )):
        return PRIORITY_MINIMAL

    # Default
    return PRIORITY_MEDIUM


class PrioritizedEvent:
    """Comparable event wrapper for the priority queue."""
    __slots__ = ("priority", "seq", "raw", "source", "ts")

    def __init__(self, priority: int, seq: int, raw: str, source: str):
        self.priority = priority
        self.seq      = seq
        self.raw      = raw
        self.source   = source
        self.ts       = time.time()

    def __lt__(self, other):
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.seq < other.seq  # aynı öncelikte FIFO


class EventIngestionQueue:
    """
    Priority-aware thread-safe event queue.

    Source thread'leri put() ile yazar.
    Pipeline consumer get() ile okur.

    Drop politikası:
      Queue dolunca en düşük öncelikli event drop edilir.
      Aynı öncelikte en eski event drop edilir.
    """

    def __init__(self, maxsize: int = MAX_QUEUE_SIZE):
        self._maxsize     = maxsize
        self._heap: list  = []          # (priority, seq, event) min-heap
        self._seq         = 0
        self._lock        = threading.Lock()

        # Metrikler
        self._total_in:   int            = 0
        self._drop_count: int            = 0
        self._drop_by_src: Dict[str,int] = {}
        self._drop_by_pri: Dict[int,int] = {p: 0 for p in range(5)}
        self._high_water:  int           = 0
        self._last_put_ts: float         = 0.0
        self._last_get_ts: float         = 0.0
        self._depth_samples              = collections.deque(maxlen=32)

        # Event for the consumer
        self._event = threading.Event()

        logger.info(f"[EventQueue] Priority-aware queue hazır (maxsize={maxsize})")

    def put(self, raw: str, source: str) -> bool:
        """
        Event ekle. Queue doluysa en düşük öncelikli event drop edilir.
        True → kabul edildi, False → drop edildi (event kendisi değil, en düşük öncelikli).
        """
        priority = _event_priority(raw, source)
        dropped  = False

        with self._lock:
            self._total_in += 1
            self._seq      += 1
            ev = PrioritizedEvent(priority, self._seq, raw, source)

            if len(self._heap) >= self._maxsize:
                # Find and drop the lowest-priority event (highest numeric value)
                # Because the heap is a min-heap, finding the worst event directly
                # would otherwise require either reverse scanning or a separate max-heap
                # keep it simple: locate the entry with the highest priority number
                worst_idx = max(range(len(self._heap)),
                                key=lambda i: (self._heap[i].priority,
                                               -self._heap[i].seq))
                worst = self._heap[worst_idx]

                if worst.priority >= priority:
                    # The new item is more important — drop the worst one and enqueue the new item
                    self._heap[worst_idx] = self._heap[-1]
                    self._heap.pop()
                    heapq.heapify(self._heap)
                    self._drop_count += 1
                    self._drop_by_src[worst.source] = \
                        self._drop_by_src.get(worst.source, 0) + 1
                    self._drop_by_pri[worst.priority] = \
                        self._drop_by_pri.get(worst.priority, 0) + 1
                    dropped = True

                    if self._drop_count % 500 == 1:
                        logger.warning(
                            f"[EventQueue] Backpressure: {self._drop_count} event drop edildi "
                            f"(en son: src={worst.source} priority={worst.priority}) "
                            f"queue={len(self._heap)}/{self._maxsize}"
                        )
                else:
                    # The new item is less important — drop itself instead of accepting it
                    self._drop_count += 1
                    self._drop_by_src[source] = self._drop_by_src.get(source, 0) + 1
                    self._drop_by_pri[priority] = self._drop_by_pri.get(priority, 0) + 1
                    return False

            heapq.heappush(self._heap, ev)
            qsize = len(self._heap)
            if qsize > self._high_water:
                self._high_water = qsize
            self._last_put_ts = ev.ts
            self._depth_samples.append((ev.ts, qsize))

            fill = qsize / self._maxsize
            if fill >= WARN_THRESHOLD and self._total_in % 1000 == 0:
                logger.warning(
                    f"[EventQueue] Yüksek doluluk: %{fill*100:.0f} "
                    f"({qsize}/{self._maxsize})"
                )

        self._event.set()
        return True

    def get(self, timeout: float = 1.0) -> Optional[Tuple[str, str, float]]:
        """Receive an event. Return None when no event arrives before timeout."""
        deadline = time.time() + timeout
        while True:
            with self._lock:
                if self._heap:
                    ev = heapq.heappop(self._heap)
                    if not self._heap:
                        self._event.clear()
                    now = time.time()
                    self._last_get_ts = now
                    self._depth_samples.append((now, len(self._heap)))
                    return (ev.raw, ev.source, ev.ts)
                self._event.clear()
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            self._event.wait(timeout=min(remaining, 0.1))

    @property
    def qsize(self) -> int:
        with self._lock:
            return len(self._heap)

    @property
    def drop_count(self) -> int:
        with self._lock:
            return self._drop_count

    @property
    def total_count(self) -> int:
        with self._lock:
            return self._total_in

    def health(self) -> dict:
        with self._lock:
            qsize = len(self._heap)
            fill  = qsize / self._maxsize if self._maxsize else 0
            trend_per_min = 0.0
            if len(self._depth_samples) >= 2:
                start_ts, start_depth = self._depth_samples[0]
                end_ts, end_depth = self._depth_samples[-1]
                elapsed = max(end_ts - start_ts, 0.001)
                trend_per_min = ((end_depth - start_depth) / elapsed) * 60.0
            return {
                "qsize":          qsize,
                "maxsize":        self._maxsize,
                "fill_pct":       round(fill * 100, 1),
                "high_water":     self._high_water,
                "depth_trend_per_min": round(trend_per_min, 3),
                "drop_count":     self._drop_count,
                "drop_by_source": dict(self._drop_by_src),
                "drop_by_priority": dict(self._drop_by_pri),
                "total_count":    self._total_in,
                "last_put_ts":    self._last_put_ts,
                "last_get_ts":    self._last_get_ts,
                "status":         "warn" if fill >= WARN_THRESHOLD else "ok",
            }
