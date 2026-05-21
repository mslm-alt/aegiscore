"""
core/source_rate_limiter.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Source-based rate limiter — auditd flood protection

Maximum events-per-second threshold for each log source.
When the threshold is exceeded, the event is dropped and a warning is logged.
"""

import time
import logging
import threading
from collections import defaultdict
from typing import Dict

logger = logging.getLogger(__name__)

# Default thresholds (events/second)
DEFAULT_LIMITS: Dict[str, int] = {
    "auditd":   2000,  # 2000/s for VMware or syscall-heavy environments (previously 500)
    "syslog":   200,
    "journald": 200,
    "auth":     100,
    "nginx":    300,
    "apache2":  300,
    "default":  150,
}


class SourceRateLimiter:
    """
    Source-based token bucket rate limiter.
    Thread-safe.
    """

    def __init__(self, limits: Dict[str, int] = None):
        self._limits   = {**DEFAULT_LIMITS, **(limits or {})}
        self._counts:  Dict[str, int]   = defaultdict(int)
        self._windows: Dict[str, float] = defaultdict(float)
        self._drops:   Dict[str, int]   = defaultdict(int)
        self._lock     = threading.Lock()

    def allow(self, source: str) -> bool:
        """
        Can an event from this source pass through?
        True → allow, False → drop.
        """
        limit = self._limits.get(source, self._limits["default"])
        now   = time.time()

        with self._lock:
            window_start = self._windows[source]

            # Start a new window
            if now - window_start >= 1.0:
                self._counts[source]  = 0
                self._windows[source] = now

            self._counts[source] += 1

            if self._counts[source] > limit:
                self._drops[source] += 1
                # Emit a warning every 1000 drops
                if self._drops[source] % 1000 == 1:
                    logger.warning(
                        f"[RateLimit] {source}: flood tespit edildi — "
                        f"{self._counts[source]} event/s (limit: {limit}) "
                        f"toplam drop: {self._drops[source]}"
                    )
                return False

        return True

    def stats(self) -> dict:
        with self._lock:
            return {
                src: {"count": self._counts[src], "drops": self._drops[src]}
                for src in set(list(self._counts) + list(self._drops))
            }
