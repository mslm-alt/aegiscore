"""
core/sources/base.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Source Adapter Interface.

The current system (the tail/journald readers in main.py) does not depend on
this interface. This module is not a mandatory part of the active ingest path;
it keeps a shared adapter contract for compatibility/scaffolding purposes.

It is not a behavioral integration guarantee, but a lightweight interface layer for
future or legacy adapter compatibility.
"""

import logging
from abc import ABC, abstractmethod
from typing import Iterator, Dict, Any

logger = logging.getLogger(__name__)


# ── Base Interface ────────────────────────────────────────────────────────────

class BaseSourceAdapter(ABC):
    """
    Interface that all source adapters must implement.
    """

    # Must be defined by subclasses
    source_name: str = "unknown"

    def __init__(self, config: Dict[str, Any] = None):
        self.config  = config or {}
        self.enabled = self.config.get("enabled", False)
        self._running = False

    @abstractmethod
    def lines(self) -> Iterator[str]:
        """
        Generator that yields log lines.
        Blocking behavior is acceptable — it runs on a separate thread.
        """
        ...

    def health(self) -> Dict[str, Any]:
        """Adapter health information. Subclasses may override this."""
        return {"source": self.source_name, "enabled": self.enabled, "running": self._running}

    def start(self) -> None:
        """Start the adapter. Subclasses may override this."""
        self._running = True
        logger.info(f"[SourceAdapter] {self.source_name} başlatıldı.")

    def stop(self) -> None:
        """Stop the adapter. Subclasses may override this."""
        self._running = False
        logger.info(f"[SourceAdapter] {self.source_name} durduruldu.")
