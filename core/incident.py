from __future__ import annotations
"""
core/incident.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FAZ 9: Incident Generation Katmanı

Alert'leri anlamlı incident'lere dönüştürür.
Son aşama: ne kadar gürültüyü filtreler, ne teslim eder.

Bileşenler:
  1. AlertGrouper       - ilgili alertleri gruplar
  2. IncidentDeduplicator - aynı incident'i tekrar üretmez
  3. IncidentFactory    - incident nesnesi oluşturur
  4. IncidentManager    - tüm incident yaşam döngüsünü yönetir
"""

import os
import tempfile
import time
import json
import hashlib
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Incident Severity Matrix ──────────────────────────────────────────────────

SEVERITY_PRIORITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def highest_severity(severities: List[str]) -> str:
    if not severities:
        return "low"
    return max(severities, key=lambda s: SEVERITY_PRIORITY.get(s, 0))


def _raw_event_dict(alert: Dict) -> Dict[str, Any]:
    """Safely convert the raw_event field inside an alert into a dict."""
    raw = alert.get("raw_event", {})
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = {}
    return raw if isinstance(raw, dict) else {}


# ── Alert Grouper ─────────────────────────────────────────────────────────────

class AlertGrouper:
    """
    Birbiriyle ilgili alertleri gruplar.
    
    Gruplama kriterleri:
    - Aynı entity (IP veya kullanıcı)
    - Zaman penceresi içinde
    - Benzer kategori
    """

    def __init__(self, time_window: int = 300, max_group_size: int = 50):
        self.time_window    = time_window
        self.max_group_size = max_group_size
        # group_key → [alert_dict]
        self._groups: Dict[str, List[Dict]] = defaultdict(list)
        self._group_ts: Dict[str, float]    = {}

    def _group_key(self, alert: Dict) -> str:
        """Determine which group the alert belongs to.

        Gruplama mantığı (öncelik sırasıyla):
          1. Aynı entity (IP/kullanıcı) + aynı MITRE tactic → kampanya grubu
          2. Aynı entity + aynı kategori → genel incident
          3. Sadece host → fallback
        """
        raw = _raw_event_dict(alert)

        ip   = raw.get("src_ip", "")
        user = raw.get("user", "") or alert.get("entity", "")
        host = alert.get("host", "")

        entity = ip or user or host or "global"

        # Group by campaign when a MITRE tactic is present
        # Keep different-category alerts for the same entity under one incident
        mitre_tactic = alert.get("mitre_tactic", "")
        if mitre_tactic:
            return f"{entity}:tactic:{mitre_tactic}"

        category = alert.get("category", "")
        return f"{entity}:{category}"

    def add(self, alert: Dict) -> Optional[str]:
        """
        Alert'i uygun gruba ekle.
        Returns: group_key (gruba eklendiyse)
        """
        key = self._group_key(alert)
        now = alert.get("ts", time.time())

        # Drop the group when its lifetime expires
        if key in self._group_ts:
            if now - self._group_ts[key] > self.time_window:
                self._groups[key] = []

        self._groups[key].append(alert)
        self._group_ts[key] = now

        # Memory cap
        if len(self._groups[key]) > self.max_group_size:
            self._groups[key] = self._groups[key][-self.max_group_size:]

        return key

    def get_group(self, group_key: str) -> List[Dict]:
        return self._groups.get(group_key, [])

    def get_active_groups(self, min_size: int = 2) -> List[Tuple[str, List[Dict]]]:
        """Return active groups that contain at least min_size alerts."""
        now = time.time()
        result = []
        for key, alerts in self._groups.items():
            if len(alerts) >= min_size:
                # Is it still within the time window?
                last = self._group_ts.get(key, 0)
                if now - last <= self.time_window * 2:
                    result.append((key, alerts))
        return result

    def cleanup(self, max_age: float = 3600):
        now = time.time()
        for key in list(self._group_ts.keys()):
            if now - self._group_ts[key] > max_age:
                del self._groups[key]
                del self._group_ts[key]


# ── Incident Deduplicator ─────────────────────────────────────────────────────

class IncidentDeduplicator:
    """
    Aynı incident'in tekrar tekrar üretilmesini engeller.
    
    Hash bazlı: aynı entity + aynı chain = aynı incident (cooldown süresi içinde)
    """

    def __init__(self, cooldown: int = 1800):  # 30 dakika
        self.cooldown = cooldown
        # hash → last_fired_ts
        self._fired: Dict[str, float] = {}

    def _make_hash(self, entity: str, incident_type: str, host: str) -> str:
        key = f"{entity}:{incident_type}:{host}"
        return hashlib.md5(key.encode()).hexdigest()

    def is_duplicate(self, entity: str, incident_type: str, host: str) -> bool:
        h   = self._make_hash(entity, incident_type, host)
        now = time.time()
        if h in self._fired:
            if now - self._fired[h] < self.cooldown:
                return True
        self._fired[h] = now
        return False

    def cleanup(self):
        now = time.time()
        self._fired = {h: ts for h, ts in self._fired.items()
                       if now - ts < self.cooldown * 2}


# ── Incident Factory ──────────────────────────────────────────────────────────

class IncidentFactory:
    """
    Alert grubu + risk assessment'tan Incident objesi üretir.
    """

    def create_from_alerts(self, group_key: str, alerts: List[Dict],
                            risk_score: float, chain_name: str = "") -> Dict:
        """Create an incident from an alert group."""
        if not alerts:
            return {}

        # Time range
        ts_start = min(a.get("ts", time.time()) for a in alerts)
        ts_end   = max(a.get("ts", time.time()) for a in alerts)

        # Highest severity
        severities = [a.get("severity", "low") for a in alerts]
        severity   = highest_severity(severities)

        # Entity ve host
        raw0 = _raw_event_dict(alerts[-1])
        entity = raw0.get("src_ip", "") or raw0.get("user", "") or group_key.split(":")[0]
        host   = alerts[-1].get("host", "")

        # Title
        categories = list({a.get("category", "") for a in alerts if a.get("category")})
        rule_ids   = list({a.get("rule_id", "") for a in alerts})
        title      = self._generate_title(categories, rule_ids, severity, entity)

        # Summary
        summary = self._generate_summary(alerts, entity, ts_start, ts_end)

        # Unique ID
        inc_id = f"INC-{hashlib.md5(f'{entity}:{ts_start:.0f}:{chain_name}'.encode()).hexdigest()[:10].upper()}"

        # Tags
        tags = list(set(categories))
        if chain_name:
            tags.append(chain_name.lower().replace("-", "_"))
        if severity in ("high", "critical"):
            tags.append("high_priority")

        # Evidence list — alert summary for forensic context
        evidence = [
            {
                "rule_id":  a.get("rule_id", ""),
                "severity": a.get("severity", ""),
                "ts":       a.get("ts", 0),
                "message":  a.get("message", "")[:120],
            }
            for a in alerts[:20]  # max 20 alert evidence
        ]

        return {
            "incident_id":   inc_id,
            "title":         title,
            "severity":      severity,
            "risk_score":    round(risk_score, 2),
            "ts_start":      ts_start,
            "ts_end":        ts_end,
            "duration_sec":  round(ts_end - ts_start, 1),
            "host":          host,
            "entity":        entity,
            "entity_key":    entity,          # DB entity_key alanı için
            "alert_count":   len(alerts),
            "alert_ids":     [a.get("id", a.get("alert_id", 0)) for a in alerts],
            "rule_ids":      rule_ids[:10],
            "chain":         chain_name,
            "tags":          tags,
            "summary":       summary,
            "evidence":      evidence,
            "status":        "open",
            "reopen_count":  0,
            "created_at":    time.time(),
        }

    def _generate_title(self, categories: List[str], rule_ids: List[str],
                         severity: str, entity: str) -> str:
        """Build an automatic incident title."""
        TITLE_MAP = {
            frozenset(["auth", "network"]): "Kimlik Doğrulama ve Ağ Saldırısı",
            frozenset(["auth"]):            "Kimlik Doğrulama Anomalisi",
            frozenset(["process"]):         "Şüpheli Proses Aktivitesi",
            frozenset(["network"]):         "Ağ Saldırısı",
            frozenset(["threat_intel"]):    "Tehdit İstihbaratı Eşleşmesi",
            frozenset(["ml_anomaly"]):      "ML Anomali Tespiti",
        }
        cat_set = frozenset(categories)
        for key, title in TITLE_MAP.items():
            if key.issubset(cat_set) or cat_set.issubset(key):
                return f"{title} ({entity})"

        # Known rule combinations
        rule_set = set(rule_ids)
        if {"THR-001", "AUTH-001"} & rule_set:
            return f"SSH Brute Force → Başarılı Giriş ({entity})"
        if "PROC-001" in rule_set or "REGEX-001" in rule_set:
            return f"Tehlikeli Komut Çalıştırma ({entity})"
        if "AUTH-006" in rule_set:
            return f"Arka Kapı Kullanıcı Tespiti ({entity})"

        return f"{severity.capitalize()} Güvenlik Olayı — {entity}"

    def _generate_summary(self, alerts: List[Dict], entity: str,
                           ts_start: float, ts_end: float) -> str:
        """Short incident summary."""
        duration = ts_end - ts_start
        dur_str  = (f"{int(duration/60)} dakika" if duration > 60
                    else f"{int(duration)} saniye")

        msg_parts = []
        for a in alerts[:3]:  # ilk 3 alert
            msg = a.get("message", "")
            if msg:
                msg_parts.append(f"• {msg}")

        base = (f"Entity '{entity}' için {len(alerts)} alert, "
                f"{dur_str} süre içinde tespit edildi.")
        if msg_parts:
            base += " Öne çıkan: " + " | ".join(msg_parts[:2])
        return base


# ── Incident Manager ──────────────────────────────────────────────────────────

class IncidentManager:
    """
    Tüm incident yaşam döngüsünü yönetir.
    
    Alert gelir → grupla → risk hesapla → dedup → incident üret → DB kaydet
    """

    def __init__(self, config: Dict = None, db=None):
        cfg      = config or {}
        risk_cfg = cfg.get("risk", {})

        self.grouper   = AlertGrouper(
            time_window=cfg.get("correlation", {}).get("temporal_window", 300)
        )
        self.dedup     = IncidentDeduplicator(
            cooldown=risk_cfg.get("cooldown", {}).get("default_seconds", 1800)
        )
        self.factory   = IncidentFactory()
        self.db        = db

        # Minimum alert count required for an incident
        self.min_alerts_for_incident = cfg.get("incident", {}).get("min_alerts", 2)
        # Min risk skoru → incident
        self.min_risk_score = cfg.get("incident", {}).get("min_risk_score", 50.0)

        self._incident_count = 0
        self._alert_count    = 0
        self._cleanup_counter = 0

        logger.info("[AegisCore:Incident] IncidentManager hazır.")

    def process_alert(self, alert: Dict,
                       risk_score: float = None) -> Optional[Dict]:
        """
        Alert'i al, işle, gerekirse incident üret.
        Returns: incident dict veya None
        """
        self._alert_count += 1
        score = risk_score or alert.get("risk_score", 0)

        # Gruba ekle
        group_key = self.grouper.add(alert)

        # Grubu kontrol et
        group = self.grouper.get_group(group_key)
        if len(group) < self.min_alerts_for_incident:
            return None

        # Risk skoru yeterli mi?
        max_score = max(a.get("risk_score", 0) for a in group)
        if max_score < self.min_risk_score:
            return None

        # Dedup check
        raw = _raw_event_dict(alert)

        entity   = raw.get("src_ip", "") or raw.get("user", "") or group_key.split(":")[0]
        host     = alert.get("host", "")
        category = alert.get("category", "unknown")

        if self.dedup.is_duplicate(entity, category, host):
            return None

        # Create the incident
        incident = self.factory.create_from_alerts(
            group_key  = group_key,
            alerts     = group,
            risk_score = max_score,
            chain_name = alert.get("details", {}).get("chain", "")
        )

        if not incident:
            return None

        self._incident_count += 1

        # DB'ye kaydet
        if self.db:
            self._save_to_db(incident)

        # Dosyaya kaydet
        self._save_to_file(incident)

        # Clear alerts for the group once an incident is created to avoid duplicates
        self.grouper._groups[group_key] = []

        # Periyodik temizlik
        self._cleanup_counter += 1
        if self._cleanup_counter % 100 == 0:
            self.grouper.cleanup()
            self.dedup.cleanup()

        logger.info(f"[AegisCore:Incident] Yeni incident: {incident['incident_id']} "
                    f"[{incident['severity']}] {incident['title']}")

        return incident

    def _save_to_db(self, incident: Dict):
        try:
            self.db.insert_incident(incident)
        except Exception as e:
            logger.error(f"[AegisCore:Incident] DB kayıt hatası: {e}")

    def _save_to_file(self, incident: Dict):
        Path("data").mkdir(exist_ok=True)
        _inc_path = getattr(self, "_incidents_file", "data/incidents.jsonl")
        p = Path(_inc_path)

        if p.exists() and not os.access(_inc_path, os.W_OK):
            # Root-owned or not writable: take ownership via atomic rename
            try:
                existing = p.read_bytes()
                fd, tmp = tempfile.mkstemp(
                    dir=str(p.parent), prefix=".tmp_", suffix=".jsonl"
                )
                try:
                    os.write(fd, existing)
                    os.fchmod(fd, 0o664)
                finally:
                    os.close(fd)
                os.rename(tmp, _inc_path)
                logger.info("[Incident] %s sahipliği atomik rename ile devralındı", _inc_path)
            except OSError as _re:
                logger.warning(
                    "[Incident] %s izin düzeltme başarısız: %s — DB akışı etkilenmez",
                    _inc_path, _re,
                )
                return

        try:
            with open(_inc_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(incident, ensure_ascii=False) + "\n")
        except PermissionError as _pe:
            logger.warning(
                "[Incident] %s yazılamadı: %s — DB akışı etkilenmez", _inc_path, _pe
            )
        except Exception as e:
            logger.error("[AegisCore:Incident] Dosya kayıt hatası: %s", e)

    def get_open_incidents(self) -> List[Dict]:
        """Fetch open incidents from the DB."""
        if not self.db:
            return []
        try:
            return self.db.get_open_incidents()
        except Exception as e:
            logger.error(f"[AegisCore:Incident] Sorgu hatası: {e}")
            return []

    def status(self) -> Dict:
        return {
            "incidents_created": self._incident_count,
            "alerts_processed":  self._alert_count,
            "active_groups":     len(self.grouper.get_active_groups()),
        }
