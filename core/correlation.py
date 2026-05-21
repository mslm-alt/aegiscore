"""
core/correlation.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 7: Correlation Engine

Detects chains of multiple events and turns them into real incidents.

Modules:
  1. TemporalCorrelator  - links events inside a time window
  2. EntityCorrelator    - groups events around the same user/IP
  3. EventChainDetector  - recognizes known attack chains
  4. CorrelationEngine   - orchestrates everything and produces incidents

Known chain patterns:
  - SSH Brute Force → Successful Login → Sudo/Su
  - Discovery → Lateral Movement
  - New User → Sudo → Persistence
"""

import time
import logging
import hashlib
import json
import threading
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum

logger = logging.getLogger(__name__)


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class AlertEvent:
    """Raw alert entering the correlation engine."""
    alert_id:  int
    ts:        float
    rule_id:   str
    severity:  str
    score:     float
    category:  str
    message:   str
    user:      str   = ""
    src_ip:    str   = ""
    host:      str   = ""
    action:    str   = ""
    outcome:   str   = ""
    distro_family: str = "unknown"
    details:   Dict  = field(default_factory=dict)

    def entity_key(self) -> str:
        """Return the primary entity for this alert."""
        if self.src_ip:
            return f"ip:{self.src_ip}"
        if self.user:
            return f"user:{self.user}"
        return f"host:{self.host}"


@dataclass
class Incident:
    """Incident produced by correlation."""
    incident_id:  str    = ""
    title:        str    = ""
    severity:     str    = "medium"
    risk_score:   float  = 0.0
    ts_start:     float  = 0.0
    ts_end:       float  = 0.0
    host:         str    = ""
    entity:       str    = ""
    alert_ids:    List   = field(default_factory=list)
    chain_name:   str    = ""
    tags:         List   = field(default_factory=list)
    summary:      str    = ""
    status:       str    = "open"

    def to_dict(self) -> Dict:
        return {
            "incident_id": self.incident_id,
            "title":       self.title,
            "severity":    self.severity,
            "risk_score":  self.risk_score,
            "ts_start":    self.ts_start,
            "ts_end":      self.ts_end,
            "host":        self.host,
            "entity":      self.entity,
            "alert_count": len(self.alert_ids),
            "chain":       self.chain_name,
            "tags":        self.tags,
            "summary":     self.summary,
            "status":      self.status,
        }


# ── 1. Temporal Correlator ────────────────────────────────────────────────────

class TemporalCorrelator:
    """
    Group alerts inside a time window.
    Alerts arriving in the same time period are likely related.
    Bug #8: _windows and deque access were made thread-safe.
    """

    def __init__(self, window_seconds: int = 300):
        self.window = window_seconds
        # entity_key → deque of AlertEvent
        # maxlen=5000: enough to keep 7-day slow-and-low chains
        self._windows: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=5000)
        )
        # Bug #8: lock to prevent race conditions in multi-threaded environments
        self._lock = threading.Lock()

    def add(self, alert: AlertEvent):
        key = alert.entity_key()
        with self._lock:
            self._windows[key].append(alert)

    def get_related(self, alert: AlertEvent) -> List[AlertEvent]:
        """Return related alerts within the same time window."""
        key    = alert.entity_key()
        cutoff = alert.ts - self.window
        with self._lock:
            related = [
                a for a in self._windows[key]
                if a.ts >= cutoff and a.alert_id != alert.alert_id
            ]
        return related

    def get_window_alerts(self, entity_key: str, since_ts: float) -> List[AlertEvent]:
        """Return windowed alerts for a specific entity."""
        with self._lock:
            return [a for a in self._windows.get(entity_key, []) if a.ts >= since_ts]

    def cleanup(self, max_age: float = 3600):
        """Clean up old alerts."""
        cutoff = time.time() - max_age
        with self._lock:
            for key in list(self._windows.keys()):
                dq = self._windows[key]
                while dq and dq[0].ts < cutoff:
                    dq.popleft()
                if not dq:
                    del self._windows[key]


# ── 2. Entity Correlator ──────────────────────────────────────────────────────

class EntityCorrelator:
    """
    Aggregate alerts around the same entity (user, IP, host).
    Tracks risk accumulation per entity.
    """

    def __init__(self, decay_half_life: float = 3600):
        self.decay_half_life = decay_half_life
        # entity_key → {"score": float, "alerts": list, "last_ts": float}
        self._entity_state: Dict[str, Dict] = {}

    def add(self, alert: AlertEvent):
        key = alert.entity_key()
        now = alert.ts or time.time()

        if key not in self._entity_state:
            self._entity_state[key] = {
                "score":    0.0,
                "alerts":   [],   # list of (ts, alert_id) tuples
                "last_ts":  now,
                "first_ts": now,
            }

        state = self._entity_state[key]

        # Score decay: reduce based on time since the last alert
        elapsed = now - state["last_ts"]
        decay   = 0.5 ** (elapsed / self.decay_half_life)
        state["score"] = state["score"] * decay + alert.score

        state["alerts"].append((now, alert.alert_id))
        state["last_ts"] = now

        # Memory cap
        if len(state["alerts"]) > 500:
            state["alerts"] = state["alerts"][-500:]

    def get_entity_score(self, entity_key: str) -> float:
        state = self._entity_state.get(entity_key)
        if not state:
            return 0.0
        # Apply decay
        elapsed = time.time() - state["last_ts"]
        decay   = 0.5 ** (elapsed / self.decay_half_life)
        return state["score"] * decay

    def get_entity_alert_count(self, entity_key: str,
                                window_seconds: float = 3600) -> int:
        """Return the alert count for the last N seconds."""
        state = self._entity_state.get(entity_key)
        if not state:
            return 0
        cutoff = time.time() - window_seconds
        return sum(1 for ts, _ in state["alerts"] if ts >= cutoff)

    def get_high_risk_entities(self, threshold: float = 100.0) -> List[Tuple[str, float]]:
        """Return entities whose risk score exceeds the threshold."""
        result = []
        for key, state in self._entity_state.items():
            score = self.get_entity_score(key)
            if score >= threshold:
                result.append((key, score))
        return sorted(result, key=lambda x: x[1], reverse=True)


# ── 3. Event Chain Detector ───────────────────────────────────────────────────

ATTACK_CHAINS = [
    # ── SSH Brute Force → Successful Login ───────────────────────────
    {
        "id":       "CHAIN-001",
        "name":     "SSH Brute Force Followed by Success",
        "severity": "critical",
        "score":    95,
        "tags":     ["brute_force", "initial_access"],
        "steps": [
            {"rule_ids": ["AUTH-002", "THR-001"], "min_count": 1},  # başarısız SSH
            {"rule_ids": ["AUTH-001"],             "min_count": 1},  # root SSH success
        ],
        "max_window": 300,  # 5 dakika içinde
        "summary": "Brute force saldırısının ardından başarılı SSH girişi",
    },

    # ── Brute Force → Successful Login → Privilege Escalation ───────
    {
        "id":       "CHAIN-002",
        "name":     "Brute Force → Login → Privilege Escalation",
        "severity": "critical",
        "score":    98,
        "tags":     ["brute_force", "initial_access", "privilege_escalation"],
        "steps": [
            {"rule_ids": ["THR-001", "AUTH-002"],            "min_count": 1},
            {"rule_ids": ["AUTH-001", "AUTH-003"],           "min_count": 1},
            {"rule_ids": ["AUTH-004", "AUTH-008", "PROC-001"], "min_count": 1},
        ],
        "max_window": 600,
        "summary": "Brute force → oturum açma → yetki yükseltme zinciri tespit edildi",
    },

    # ── Reconnaissance: User Scanning ────────────────────────────────
    {
        "id":       "CHAIN-003",
        "name":     "SSH User Scanning",
        "severity": "high",
        "score":    80,
        "tags":     ["reconnaissance", "scanning"],
        "steps": [
            {"rule_ids": ["AUTH-003"], "min_count": 5},  # 5+ geçersiz kullanıcı
        ],
        "max_window": 120,
        "summary": "SSH kullanıcı adı taraması tespit edildi",
    },

    # ── Persistence: New User + Sudo ──────────────────────────────────
    {
        "id":       "CHAIN-004",
        "name":     "Backdoor User Creation",
        "severity": "critical",
        "score":    95,
        "tags":     ["persistence", "privilege_escalation"],
        "steps": [
            {"rule_ids": ["AUTH-006"],              "min_count": 1},  # useradd
            {"rule_ids": ["AUTH-004", "AUTH-008"],  "min_count": 1},  # sudo/su
        ],
        "max_window": 300,
        "summary": "Yeni kullanıcı oluşturuldu ve ardından root yetkisi alındı",
    },

    # ── Dangerous Command After Login ─────────────────────────────────
    {
        "id":       "CHAIN-005",
        "name":     "Post-Login Malicious Command",
        "severity": "critical",
        "score":    95,
        "tags":     ["execution", "c2"],
        "steps": [
            {"rule_ids": ["AUTH-001"],                              "min_count": 1},
            {"rule_ids": ["PROC-001", "REGEX-001", "REGEX-003"],    "min_count": 1},
        ],
        "max_window": 180,
        "summary": "Oturum açma sonrası tehlikeli komut çalıştırıldı",
    },

    # ── ML + Rule Combo ───────────────────────────────────────────────
    {
        "id":       "CHAIN-006",
        "name":     "ML Anomaly + Rule Alert",
        "severity": "high",
        "score":    85,
        "tags":     ["anomaly", "combined_detection"],
        "steps": [
            {"rule_ids": ["ML-IF", "ML-PCA"], "min_count": 1},
            {"rule_ids": ["AUTH-001", "AUTH-004", "PROC-001", "REGEX-001"], "min_count": 1},
        ],
        "max_window": 60,
        "summary": "ML anomali + kural eşleşmesi aynı anda tespit edildi",
    },
    {
        "id":       "CHAIN-007",
        "name":     "DNS Beacon/Recon → Suspicious Execution",
        "severity": "high",
        "score":    90,
        "tags":     ["dns", "command-and-control", "reconnaissance", "execution"],
        "steps": [
            {"rule_ids": ["DNS-001", "DNS-002", "DNS-003", "DNS-004", "DNS-005", "DNS-006", "DNS-007", "DNS-008", "DNS-009", "THR-019", "THR-020", "THR-023"], "min_count": 1},
            {"rule_ids": ["PROC-001", "PROC-003", "PROC-005", "NET-PROC-001", "NET-PROC-002",
                          "NET-PROC-003", "NET-011", "NET-012", "NET-013", "MON-001"], "min_count": 1},
        ],
        "max_window": 900,
        "summary": "DNS beacon/recon sinyalini kısa sürede şüpheli process veya outbound aktivite izledi",
    },
    {
        "id":       "CHAIN-008",
        "name":     "Web Exploit/Webshell → Process or Outbound",
        "severity": "critical",
        "score":    96,
        "tags":     ["web", "initial_access", "execution", "command-and-control"],
        "steps": [
            {"rule_ids": ["NET-WEB-001", "NET-WEB-002", "NET-WEB-003", "WEB-004", "WEB-006", "WEB-007", "WEB-008"], "min_count": 1},
            {"rule_ids": ["PROC-003", "PROC-005", "NET-PROC-001", "NET-PROC-002",
                          "NET-PROC-003", "NET-011", "NET-012", "NET-013", "MON-001"], "min_count": 1},
        ],
        "max_window": 600,
        "summary": "Web exploit veya webshell staging sinyalini takip eden process spawn/outbound aktivitesi görüldü",
    },
    {
        "id":       "CHAIN-009",
        "name":     "Credential Abuse → Privilege Escalation",
        "severity": "high",
        "score":    88,
        "tags":     ["credential-access", "privilege-escalation", "post-auth"],
        "steps": [
            {"rule_ids": ["THR-016", "THR-017", "THR-018", "SEQ-021", "SEQ-023", "SEQ-040"], "min_count": 1},
            {"rule_ids": ["SEQ-036", "SEQ-039", "SEQ-044"], "min_count": 1},
        ],
        "max_window": 900,
        "summary": "Credential abuse/after-auth sinyalini kısa sürede sudo/su yetki yükseltmesi izledi",
    },
    {
        "id":       "CHAIN-010",
        "name":     "Credential Abuse → Persistence",
        "severity": "critical",
        "score":    94,
        "tags":     ["credential-access", "persistence", "account-access", "post-auth"],
        "steps": [
            {"rule_ids": ["THR-016", "THR-017", "THR-018", "SEQ-021", "SEQ-023", "SEQ-040"], "min_count": 1},
            {"rule_ids": ["PERS-003", "PERS-004", "PERS-005", "PERS-006", "PERS-015",
                          "SEQ-031", "SEQ-032", "SEQ-033", "SEQ-035", "SEQ-043"], "min_count": 1},
        ],
        "max_window": 1800,
        "summary": "Credential abuse/after-auth sinyalini takip eden persistence değişikliği görüldü",
    },
    {
        "id":       "CHAIN-011",
        "name":     "Package Tamper → Service/File Drift",
        "severity": "critical",
        "score":    92,
        "tags":     ["package", "defense-evasion", "persistence", "service-drift"],
        "steps": [
            {"rule_ids": ["PKG-001", "PKG-002", "PKG-003", "PKG-010", "RHEL-004", "RHEL-005", "SUSE-002"], "min_count": 1},
            {"rule_ids": ["PERS-004", "PERS-005", "PERS-015", "ATK-PER-002",
                          "FIM-001", "FIM-002", "FIM-SYSTEMD-001", "FIM-SYSTEMD-002"], "min_count": 1},
        ],
        "max_window": 3600,
        "summary": "Paket tamper/güvenlik aracı kaldırma sinyalini service veya kritik dosya drift'i izledi",
    },

    # ── v8: RHEL Distro-Specific Attack Chains ───────────────────────────────
    {
        "id":       "RHEL-CHAIN-001",
        "name":     "SELinux Disable + Root Login",
        "platform": ["rhel"],
        "severity": "critical",
        "score":    95,
        "steps": [
            {"rule_ids": ["RHEL-001", "RHEL-002"], "min_count": 1},
            {"rule_ids": ["AUTH-001", "AUTH-002", "AUTH-004"], "min_count": 1},
        ],
        "max_window": 300,
        "summary":  "SELinux devre disi birakildi ardindan root girisi tespit edildi",
        "mitre_tactic": "TA0005",
        "mitre_technique": "T1562",
        "tags": ["defense-evasion", "privilege-escalation", "rhel"],
    },
    {
        "id":       "RHEL-CHAIN-002",
        "name":     "Firewall Stop + Port Scan",
        "platform": ["rhel"],
        "severity": "high",
        "score":    80,
        "steps": [
            {"rule_ids": ["RHEL-003"], "min_count": 1},
            {"rule_ids": ["NET-001", "NET-002", "THRESH-004"], "min_count": 1},
        ],
        "max_window": 600,
        "summary":  "firewalld durduruldu ardindan port tarama tespit edildi",
        "tags": ["defense-evasion", "discovery", "rhel"],
    },

    # ── v8: SUSE Distro-Specific Attack Chains ───────────────────────────────
    {
        "id":       "SUSE-CHAIN-001",
        "name":     "Zypper Tamper + Cron Persistence",
        "platform": ["suse"],
        "severity": "high",
        "score":    85,
        "steps": [
            {"rule_ids": ["SUSE-001", "SUSE-002"], "min_count": 1},
            {"rule_ids": ["PERS-001", "PERS-002", "PERS-003"], "min_count": 1},
        ],
        "max_window": 600,
        "summary":  "zypper/rpm degisikligi ardindan kalicilik mekanizmasi tespit edildi",
        "tags": ["persistence", "suse"],
    },

    # ── Slow & Low: Long-Duration Attack Chains ──────────────────────
    # These chains capture stealthy attacks that unfold over hours or days.
    # max_window is expressed in seconds here: 6h = 21600, 24h = 86400, 7d = 604800

    {
        "id":       "SLOW-001",
        "name":     "SSH Fail → Başarılı Login (Uzun Aralık)",
        "severity": "high",
        "score":    85,
        "tags":     ["slow-and-low", "initial_access", "brute_force"],
        "steps": [
            {"rule_ids": ["AUTH-002", "AUTH-003", "THR-001"], "min_count": 3},  # SSH başarısızlar
            {"rule_ids": ["AUTH-001"],                         "min_count": 1},  # başarılı login
        ],
        "max_window": 21600,  # 6 saat pencere
        "summary": "Saatler içinde dağıtılmış SSH başarısız denemelerin ardından başarılı giriş",
        "mitre_tactic": "TA0001",
        "mitre_technique": "T1110",
    },

    {
        "id":       "SLOW-002",
        "name":     "Başarılı Login → Persistence (Gün İçinde)",
        "severity": "high",
        "score":    88,
        "tags":     ["slow-and-low", "persistence", "initial_access"],
        "steps": [
            {"rule_ids": ["AUTH-001"],                                       "min_count": 1},
            {"rule_ids": ["ATK-PER-001", "ATK-PER-002", "ATK-PER-003",
                          "ATK-PER-004", "ATK-PER-005"],                     "min_count": 1},
        ],
        "max_window": 86400,  # 24 saat pencere
        "summary": "Başarılı giriş sonrasında gün içinde persistence mekanizması kuruldu",
        "mitre_tactic": "TA0003",
        "mitre_technique": "T1053",
    },

    {
        "id":       "SLOW-003",
        "name":     "SSH Fail → Login → Sudo/Cron/Servis (Tam Zincir, Geniş Pencere)",
        "severity": "critical",
        "score":    95,
        "tags":     ["slow-and-low", "initial_access", "privilege_escalation", "persistence"],
        "steps": [
            {"rule_ids": ["AUTH-002", "AUTH-003", "THR-001"], "min_count": 2},
            {"rule_ids": ["AUTH-001"],                         "min_count": 1},
            {"rule_ids": ["AUTH-004", "AUTH-008",
                          "ATK-PER-001", "ATK-PER-002"],       "min_count": 1},
        ],
        "max_window": 86400,  # 24 saat pencere
        "summary": "Klasik slow & low zinciri: dağıtık brute force → giriş → yetki/persistence",
        "mitre_tactic": "TA0001",
        "mitre_technique": "T1110",
    },

    {
        "id":       "SLOW-004",
        "name":     "LOLBin Kullanımı Sonrası Persistence (Geniş Pencere)",
        "severity": "critical",
        "score":    92,
        "tags":     ["slow-and-low", "lolbin", "persistence", "defense_evasion"],
        "steps": [
            {"rule_ids": ["LOL-001", "LOL-002", "LOL-010", "LOL-011",
                          "LOL-020", "LOL-021", "LOL-030", "LOL-031"], "min_count": 1},
            {"rule_ids": ["ATK-PER-001", "ATK-PER-002", "ATK-PER-003",
                          "AUTH-004", "AUTH-008"],                     "min_count": 1},
        ],
        "max_window": 21600,  # 6 saat pencere
        "summary": "LOLBin çalıştırıldıktan sonra saatler içinde persistence mekanizması kuruldu",
        "mitre_tactic": "TA0005",
        "mitre_technique": "T1218",
    },

    {
        "id":       "SLOW-005",
        "name":     "Yüksek Riskli Entity Risk Birikimi (7 Gün)",
        "severity": "high",
        "score":    80,
        "tags":     ["slow-and-low", "risk-accumulation", "anomaly"],
        "steps": [
            {"rule_ids": ["AUTH-001", "AUTH-002", "AUTH-003",
                          "AUTH-004", "AUTH-008", "THR-001",
                          "LOL-001", "LOL-010", "LOL-020"], "min_count": 5},
        ],
        "max_window": 604800,  # 7 gün pencere
        "summary": "Aynı entity 7 gün içinde 5+ farklı şüpheli olay üretti — süregelen tehdit",
        "mitre_tactic": "TA0001",
        "mitre_technique": "T1078",
    },
]

EVENT_CHAIN_ALERT_PREFIXES = (
    "THR-", "IOC-", "REGEX-", "PROC-", "LOL-", "ML-",
    "ATK-", "PERS-", "RHEL-", "SUSE-", "NET-", "SEQ-",
    "FIM-", "DNS-", "WEB-", "PKG-", "MON-",
)


class EventChainDetector:
    """
    Bilinen saldırı zincirlerini tanır.
    Her alert geldiğinde entity'nin zaman penceresine bakar
    ve chain pattern'leri kontrol eder.
    """

    def __init__(self, temporal: TemporalCorrelator):
        self.temporal = temporal
        self.chains   = ATTACK_CHAINS
        # (entity_key, chain_id) → last trigger timestamp (cooldown)
        self._fired: Dict[Tuple[str, str], float] = {}
        self._cooldown = 300  # aynı zincir 5 dk susturulur

    def check(self, alert: AlertEvent) -> List[Incident]:
        """Check chains for an incoming alert and return an Incident if matched."""
        if not self._is_alert_level_rule(alert.rule_id):
            return []
        incidents = []
        entity = alert.entity_key()

        for chain in self.chains:
            # Cooldown check
            cooldown_key = (entity, chain["id"])
            if cooldown_key in self._fired:
                if time.time() - self._fired[cooldown_key] < self._cooldown:
                    continue

            # Zaman penceresi alertlerini al
            window = chain["max_window"]
            window_alerts = self.temporal.get_window_alerts(
                entity, alert.ts - window
            )
            window_alerts.append(alert)  # mevcut alert de dahil

            # Chain steps'i kontrol et
            if self._match_chain(chain, window_alerts):
                incident = self._build_incident(chain, alert, window_alerts)
                incidents.append(incident)
                self._fired[cooldown_key] = time.time()
                logger.info(f"[AegisCore:Chain] {chain['id']} tetiklendi: {entity} → {chain['name']}")

        return incidents

    def _match_chain(self, chain: Dict, alerts: List[AlertEvent]) -> bool:
        """Are all steps of the chain satisfied by the current alerts?"""
        eligible_alerts = [a for a in alerts if self._is_alert_level_rule(a.rule_id)]
        for step in chain["steps"]:
            required_ids = {
                rid for rid in step["rule_ids"]
                if self._is_alert_level_rule(rid)
            }
            if not required_ids:
                return False
            min_count    = step.get("min_count", 1)
            matched      = sum(
                1 for a in eligible_alerts
                if a.rule_id in required_ids
            )
            if matched < min_count:
                return False
        return True

    def _is_alert_level_rule(self, rule_id: str) -> bool:
        rid = (rule_id or "").upper()
        return rid.startswith(EVENT_CHAIN_ALERT_PREFIXES)

    def _build_incident(self, chain: Dict, trigger_alert: AlertEvent,
                         related_alerts: List[AlertEvent]) -> Incident:
        """Build an Incident from the matched chain."""
        alert_ids = list({a.alert_id for a in related_alerts})
        ts_start  = min(a.ts for a in related_alerts)
        ts_end    = max(a.ts for a in related_alerts)
        entity    = trigger_alert.entity_key()

        inc_id = hashlib.md5(
            f"{chain['id']}:{entity}:{ts_start:.0f}".encode()
        ).hexdigest()[:12]

        return Incident(
            incident_id = f"INC-{inc_id}",
            title       = chain["name"],
            severity    = chain["severity"],
            risk_score  = chain["score"],
            ts_start    = ts_start,
            ts_end      = ts_end,
            host        = trigger_alert.host,
            entity      = entity,
            alert_ids   = alert_ids,
            chain_name  = chain["id"],
            tags        = chain["tags"],
            summary     = chain["summary"],
        )


# ── 4. Correlation Engine (orchestrator) ─────────────────────────────

class CorrelationEngine:
    """
    Tüm correlation modüllerini yönetir.
    Her alert geldiğinde:
      1. Temporal window'a ekle
      2. Entity risk score'u güncelle
      3. Chain detection yap
      4. Incident varsa üret
    """

    def __init__(self, config: Dict = None, db=None):
        cfg = config or {}
        corr_cfg = cfg.get("correlation", {})

        self.temporal = TemporalCorrelator(
            window_seconds=corr_cfg.get("temporal_window", 300)
        )
        self.entity = EntityCorrelator(
            decay_half_life=cfg.get("risk", {}).get("decay", {}).get("half_life", 3600)
        )
        self.chain   = EventChainDetector(self.temporal)
        self.db      = db

        self._incident_count = 0
        self._alert_count    = 0
        self._cleanup_interval = 300
        self._last_cleanup   = time.time()

        # v8: Cross-host IP korelasyon — ip → {host: last_seen_ts}
        self._ip_to_hosts:    Dict[str, Dict[str, float]] = {}
        self._cross_host_ttl: int   = 3600   # 1 saat TTL
        self._cross_host_last_save: float = 0.0
        self._cross_host_save_interval: int = 300  # 5 dakikada bir kaydet
        # 3b: lock to prevent cross-host persist/cleanup race conditions
        self._cross_host_lock = threading.Lock()

        # v8: restore state after restart
        if self.db:
            try:
                loaded = self.db.load_cross_host_state(self._cross_host_ttl)
                self._ip_to_hosts.update(loaded)
                if loaded:
                    logger.info(f"[Corr] Cross-host state geri yüklendi: {len(loaded)} IP")
            except Exception as _e:
                logger.debug(f"[Corr] Cross-host state yüklenemedi: {_e}")

            # Entity risk accumulation is retained for up to 7 days for slow-and-low chains
            try:
                entity_state = self.db.load_entity_risk_state(max_age_seconds=604800)
                if entity_state:
                    self.entity._entity_state.update(entity_state)
                    logger.info(f"[Corr] Entity risk state geri yüklendi: {len(entity_state)} entity")
            except Exception as _e:
                logger.debug(f"[Corr] Entity risk state yüklenemedi: {_e}")

        self._entity_save_interval = 600   # 10 dakikada bir kaydet
        self._entity_last_save     = time.time()

        logger.info("[AegisCore:Corr] CorrelationEngine hazır "
                    f"({len(ATTACK_CHAINS)} zincir deseni).")

    def process(self, alert_data: Dict) -> List[Incident]:
        """
        Ham alert dict'ini al, correlation yap, incident döndür.
        
        alert_data: database.insert_alert ile aynı format
        """
        # Dict → AlertEvent
        raw_event = alert_data.get("raw_event", {})
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except Exception:
                raw_event = {}

        alert = AlertEvent(
            alert_id  = alert_data.get("id", int(time.time() * 1000)),
            ts        = alert_data.get("ts", time.time()),
            rule_id   = alert_data.get("rule_id", ""),
            severity  = alert_data.get("severity", "medium"),
            score     = alert_data.get("risk_score", 0),
            category  = alert_data.get("category", ""),
            message   = alert_data.get("message", ""),
            user      = raw_event.get("user", ""),
            src_ip    = raw_event.get("src_ip", ""),
            host      = alert_data.get("host", ""),
            action    = raw_event.get("action", ""),
            outcome   = raw_event.get("outcome", ""),
            distro_family = raw_event.get("distro_family", "unknown"),
            details   = alert_data.get("details", {}),
        )

        self._alert_count += 1

        # 1. Temporal window'a ekle
        self.temporal.add(alert)

        # 2. Update entity risk
        self.entity.add(alert)

        # 3. Chain detection
        incidents = self.chain.check(alert)
        self._incident_count += len(incidents)

        # 4. DB'ye kaydet
        if self.db and incidents:
            for inc in incidents:
                self._save_incident(inc)

        # Periyodik temizlik
        if time.time() - self._last_cleanup > self._cleanup_interval:
            # Slow-and-low chains can span up to 7 days — max_age=7 days
            self.temporal.cleanup(max_age=604800)
            self._cleanup_cross_host()
            self._last_cleanup = time.time()

        # Entity risk state periyodik persist
        if self.db and (time.time() - self._entity_last_save > self._entity_save_interval):
            try:
                self.db.save_entity_risk_state(self.entity._entity_state)
                self._entity_last_save = time.time()
            except Exception as _e:
                logger.debug(f"[Corr] Entity risk state kaydedilemedi: {_e}")

        # v8: Cross-host IP korelasyon
        cross_host_inc = self._check_cross_host(alert)
        if cross_host_inc:
            incidents.append(cross_host_inc)
            if self.db:
                self._save_incident(cross_host_inc)

        return incidents


    def _check_cross_host(self, alert: "AlertEvent"):
        """
        v8: Aynı IP farklı host'lara erişiyorsa lateral movement şüphesi.
        IP → {host: ts} haritasını günceller.
        2+ farklı host görülürse Incident üretir.
        """
        src_ip = alert.src_ip
        host   = alert.host

        if not src_ip or not host or src_ip in ("127.0.0.1", "::1", ""):
            return None

        now = time.time()
        host_key = self._canonical_cross_host_name(host, alert.distro_family)

        if src_ip not in self._ip_to_hosts:
            self._ip_to_hosts[src_ip] = {}

        self._ip_to_hosts[src_ip][host_key] = now

        hosts_seen = list(self._ip_to_hosts[src_ip].keys())
        if len(hosts_seen) < 2:
            return None

        # 2+ different hosts — suspected lateral movement
        hosts_str = ", ".join(hosts_seen[:5])
        logger.warning(
            f"[CrossHost] {src_ip} → {len(hosts_seen)} farklı host: {hosts_str}"
        )

        return Incident(
            incident_id = f"XHOST-{hash(src_ip) % 999999:06d}",
            entity      = src_ip,
            host        = host,
            chain_name  = "cross_host_lateral",
            risk_score  = min(30.0 + len(hosts_seen) * 15.0, 95.0),
            ts_start    = now,
            ts_end      = now,
            alert_ids   = [alert.alert_id],
            tags        = ["lateral-movement", "cross-host"],
            title       = f"Cross-host lateral movement: {src_ip}",
            summary     = f"{src_ip} → {len(hosts_seen)} farklı host: {', '.join(hosts_seen[:5])}",
        )

    @staticmethod
    def _canonical_cross_host_name(host: str, distro_family: str = "unknown") -> str:
        if distro_family != "rhel":
            return host
        normalized = (host or "").strip().lower().rstrip(".")
        if normalized in ("localhost", "localhost.localdomain"):
            return "localhost"
        return host

    def _cleanup_cross_host(self):
        """
        TTL süresi dolmuş IP→host kayıtlarını temizle ve DB'ye kaydet.
        3b: _cross_host_lock ile persist+cleanup aynı atomik işlemde —
        maintenance thread ile consumer thread arasındaki race condition önlenir.
        """
        with self._cross_host_lock:
            now     = time.time()
            expired = []
            for ip, hosts in self._ip_to_hosts.items():
                fresh = {h: ts for h, ts in hosts.items() if now - ts < self._cross_host_ttl}
                if fresh:
                    self._ip_to_hosts[ip] = fresh
                else:
                    expired.append(ip)
            for ip in expired:
                del self._ip_to_hosts[ip]

            # v8: periodic DB persistence under the lock to stay atomic with cleanup
            if self.db and (now - self._cross_host_last_save) > self._cross_host_save_interval:
                try:
                    self.db.save_cross_host_state(self._ip_to_hosts)
                    self.db.cleanup_cross_host_state(self._cross_host_ttl)
                    self._cross_host_last_save = now
                except Exception as _e:
                    logger.debug(f"[Corr] Cross-host persist hatası: {_e}")

    def _save_incident(self, incident: Incident):
        """Incident'i DB'ye kaydet."""
        try:
            self.db.insert_incident({
                "ts_start":     incident.ts_start,
                "ts_end":       incident.ts_end,
                "host":         incident.host,
                "title":        incident.title,
                "severity":     incident.severity,
                "risk_score":   incident.risk_score,
                "status":       incident.status,
                "alert_count":  len(incident.alert_ids),
                "tags":         incident.tags,
                "summary":      incident.summary,
                "entity_key":   incident.entity if hasattr(incident, "entity") else "",
                "reopen_count": getattr(incident, "reopen_count", 0),
            })
        except Exception as e:
            logger.error(f"[AegisCore:Corr] Incident kaydedilemedi: {e}")

    def reopen_incident_if_needed(self, entity_key: str, new_alert_score: float) -> bool:
        """
        Aynı entity için son 24 saat içinde kapanmis incident varsa yeniden ac.
        Yeni yuksek riskli alert geldiginde cagrilir.
        Donduruyor: True = incident yeniden acildi
        """
        try:
            # get_closed_incidents: WHERE status='closed' — dogru sorgu
            closed = self.db.get_closed_incidents(since_hours=24)
            for inc in closed:
                if inc.get("entity_key") != entity_key:
                    continue
                age = time.time() - inc.get("ts_end", 0)
                if age < 86400 and new_alert_score >= 70:
                    reopen_count = inc.get("reopen_count", 0) + 1
                    self.db.update_incident(
                        inc["id"],   # incidents tablosunda 'id' kolonu var (inc_id degil)
                        {"status": "open", "ts_end": time.time(),
                         "reopen_count": reopen_count}
                    )
                    logger.info(
                        f"[AegisCore:Corr] Incident #{inc['id']} yeniden acildi "
                        f"(entity={entity_key}, reopen=#{reopen_count})"
                    )
                    return True
        except Exception as e:
            logger.debug(f"[AegisCore:Corr] reopen_incident_if_needed hatasi: {e}")
        return False

    def get_high_risk_entities(self, threshold: float = 100.0) -> List[Dict]:
        entities = self.entity.get_high_risk_entities(threshold)
        return [{"entity": k, "score": round(s, 1)} for k, s in entities]

    def status(self) -> Dict:
        return {
            "alerts_processed":  self._alert_count,
            "incidents_created": self._incident_count,
            "active_entities":   len(self.entity._entity_state),
            "temporal_windows":  len(self.temporal._windows),
            "chains_defined":    len(ATTACK_CHAINS),
        }


# ── Test ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    engine = CorrelationEngine()
    now = time.time()

    # SSH brute force → successful login scenario
    scenario = [
        {"id": 1, "ts": now,      "rule_id": "AUTH-002", "severity": "high",
         "risk_score": 70, "category": "auth", "message": "SSH başarısız",
         "host": "server1",
         "raw_event": {"user": "admin", "src_ip": "10.0.0.5", "action": "ssh_login", "outcome": "failure"}},

        {"id": 2, "ts": now+10,   "rule_id": "THR-001",  "severity": "high",
         "risk_score": 80, "category": "threshold", "message": "Brute force",
         "host": "server1",
         "raw_event": {"user": "admin", "src_ip": "10.0.0.5", "action": "ssh_login", "outcome": "failure"}},

        {"id": 3, "ts": now+30,   "rule_id": "AUTH-001", "severity": "high",
         "risk_score": 75, "category": "auth", "message": "Root SSH login",
         "host": "server1",
         "raw_event": {"user": "root", "src_ip": "10.0.0.5", "action": "ssh_login", "outcome": "success"}},

        {"id": 4, "ts": now+45,   "rule_id": "PROC-001", "severity": "critical",
         "risk_score": 90, "category": "process", "message": "Tehlikeli komut",
         "host": "server1",
         "raw_event": {"user": "root", "src_ip": "10.0.0.5", "action": "sudo", "outcome": "success"}},
    ]

    print("\n=== Correlation Engine Test ===\n")
    all_incidents = []
    for alert_data in scenario:
        incidents = engine.process(alert_data)
        if incidents:
            all_incidents.extend(incidents)
            for inc in incidents:
                print(f"🚨 INCIDENT: [{inc.severity.upper()}] {inc.incident_id}")
                print(f"   Zincir  : {inc.chain_name} — {inc.title}")
                print(f"   Entity  : {inc.entity}")
                print(f"   Alertler: {inc.alert_ids}")
                print(f"   Özet    : {inc.summary}")
                print(f"   Tags    : {inc.tags}\n")

    print(f"Toplam {len(all_incidents)} incident üretildi.")
    print(f"Yüksek riskli entity'ler: {engine.get_high_risk_entities(50)}")
    print(f"Status: {engine.status()}")
