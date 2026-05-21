"""
core/ml_control.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ML training control system

Features:
  - Automatic pause: training stops when an active HIGH/CRITICAL incident exists
  - Automatic resume: training restarts after the clean window expires
  - Manual control: pause/resume/reset/exclude
  - All control actions are logged to the DB
"""

import time
import logging
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)


class MLController:
    """
    Control ML training.
    Integrates with the pipeline and PhaseManager.
    """

    def __init__(self, config: dict, db):
        ml_cfg = config.get("ml_control", {})

        self.pause_on_incident   = ml_cfg.get("pause_on_incident",   True)
        self.auto_resume         = ml_cfg.get("auto_resume",         True)
        self.clean_window_hours  = ml_cfg.get("clean_window_hours",  2.0)
        self.excluded_sources:   List[str] = ml_cfg.get("excluded_sources", [])

        self._db              = db
        self._paused          = False
        self._pause_reason    = ""
        self._paused_at:      Optional[float] = None
        self._last_incident_ts: Optional[float] = None

        # Load the previous state from the DB
        self._load_state()

    # ── State ────────────────────────────────────────────────────────────────

    @property
    def is_paused(self) -> bool:
        return self._paused

    @property
    def should_learn(self) -> bool:
        """Return whether ML training is currently active."""
        return not self._paused

    def status(self) -> Dict:
        return {
            "paused":           self._paused,
            "pause_reason":     self._pause_reason,
            "paused_at":        self._paused_at,
            "excluded_sources": list(self.excluded_sources),
            "auto_resume":      self.auto_resume,
            "clean_window_h":   self.clean_window_hours,
        }

    # ── Automatic Control ────────────────────────────────────────────────────

    def on_incident(self, severity: str, incident_id: str):
        """Called when a new incident is opened."""
        if not self.pause_on_incident:
            return
        if severity.upper() in ("HIGH", "CRITICAL"):
            self._last_incident_ts = time.time()
            if not self._paused:
                self._pause(reason=f"auto:incident:{incident_id}", actor="auto")

    def tick(self):
        """
        Periodic check invoked by the maintenance thread.
        Resumes automatically when the clean window has expired.
        """
        if not self._paused or not self.auto_resume:
            return
        if not self._pause_reason.startswith("auto:"):
            return  # manual pause — do not auto-resume
        if self._last_incident_ts is None:
            return

        elapsed = (time.time() - self._last_incident_ts) / 3600
        if elapsed >= self.clean_window_hours and not self._has_open_blocking_incident():
            self._resume(reason="auto:clean_window", actor="auto")

    # ── Manual Control ───────────────────────────────────────────────────────

    def pause(self, reason: str = "manual"):
        """Pause manually by an admin."""
        self._pause(reason=f"manual:{reason}", actor="admin")

    def resume(self):
        """Resume manually by an admin."""
        self._resume(reason="manual", actor="admin")

    def reset_baseline(self):
        """Reset the baseline and ML models."""
        self._log_action("reset", reason="manual:baseline_reset", actor="admin")
        logger.info("[MLControl] Baseline sıfırlama istendi.")

    def exclude_source(self, source: str):
        """Exclude a log source from ML training."""
        if source not in self.excluded_sources:
            self.excluded_sources.append(source)
            self._log_action("exclude", reason=f"manual:exclude:{source}",
                             actor="admin", source=source)
            self._save_state()
            logger.info(f"[MLControl] '{source}' ML eğitiminden çıkarıldı.")

    def include_source(self, source: str):
        """Re-add a previously excluded source."""
        if source in self.excluded_sources:
            self.excluded_sources.remove(source)
            self._log_action("include", reason=f"manual:include:{source}",
                             actor="admin", source=source)
            self._save_state()
            logger.info(f"[MLControl] '{source}' ML eğitimine geri eklendi.")

    def is_source_excluded(self, source: str) -> bool:
        return source in self.excluded_sources

    # ── Internal Methods ─────────────────────────────────────────────────────

    def _pause(self, reason: str, actor: str):
        self._paused     = True
        self._pause_reason = reason
        self._paused_at  = time.time()
        self._log_action("pause", reason=reason, actor=actor)
        self._save_state()
        logger.warning(f"[MLControl] ML eğitimi donduruldu — {reason}")

    def _resume(self, reason: str, actor: str):
        self._paused      = False
        self._pause_reason = ""
        self._paused_at   = None
        self._log_action("resume", reason=reason, actor=actor)
        self._save_state()
        logger.info(f"[MLControl] ML eğitimi devam ediyor — {reason}")

    def _log_action(self, action: str, reason: str, actor: str, source: str = ""):
        try:
            self._db.set_stat(f"ml_control_last_{action}", str(time.time()))
            self._db.log_ml_control(
                action=action, reason=reason, actor=actor, source=source
            )
        except Exception as e:
            logger.debug(f"[MLControl] DB log hatası: {e}")

    def _save_state(self):
        try:
            import json
            state = {
                "paused":           self._paused,
                "pause_reason":     self._pause_reason,
                "paused_at":        self._paused_at,
                "excluded_sources": self.excluded_sources,
                "last_incident_ts": self._last_incident_ts,
            }
            self._db.set_stat("ml_control_state", json.dumps(state))
        except Exception as e:
            logger.debug(f"[MLControl] State kayıt hatası: {e}")

    def _has_open_blocking_incident(self) -> bool:
        """Block auto-resume when an open HIGH/CRITICAL incident exists."""
        try:
            incidents = self._db.get_open_incidents()
        except Exception as e:
            logger.debug(f"[MLControl] Açık incident sorgu hatası: {e}")
            return False

        for incident in incidents or []:
            severity = str((incident or {}).get("severity", "") or "").strip().upper()
            if severity in ("HIGH", "CRITICAL"):
                return True
        return False

    def _load_state(self):
        try:
            import json
            raw = self._db.get_stat("ml_control_state")
            if raw:
                state = json.loads(raw)
                self._paused           = state.get("paused", False)
                self._pause_reason     = state.get("pause_reason", "")
                self._paused_at        = state.get("paused_at")
                self.excluded_sources  = state.get("excluded_sources", [])
                self._last_incident_ts = state.get("last_incident_ts")
                if self._paused:
                    logger.info(f"[MLControl] Önceki durum yüklendi: dondurulmuş ({self._pause_reason})")
        except Exception as e:
            logger.debug(f"[MLControl] State yükleme hatası: {e}")
