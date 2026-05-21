"""
core/hunting.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AegisCore — Threat Hunting Motoru

Pasif detection degil, aktif sorgulama.
Alert uretmeden DB uzerinde arama yapar.

Kullanim:
  aegiscore --hunt rare_processes
  aegiscore --hunt beacon_detection --days 7
  aegiscore --hunt lateral_movement --user alice
  aegiscore --hunt credential_access --last 24h
  aegiscore --hunt persistence
  aegiscore --hunt after_hours
  aegiscore --hunt data_exfil

Hatalar onlendi:
  - Performans: ts, process, user, src_ip indexleri kullanilir
  - False positive: whitelist + skorlama ile onceliklendirilir
  - Baseline yok: PHASE_1 oncesi uyari verilir
  - Stale sonuc: acknowledged flag ile tekrarlanan bulgular filtrelenir
  - Bos sonuc: net aciklama verilir
"""

import time
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Whitelist — known legitimate processes and IPs ────────────────────

DEFAULT_PROCESS_WHITELIST = {
    "systemd", "sshd", "cron", "rsyslog", "auditd",
    "python3", "bash", "sh", "ps", "top", "ls", "cat",
    "grep", "awk", "sed", "find", "cp", "mv", "rm",
    "apt", "apt-get", "dpkg", "pip", "pip3",
    "journalctl", "systemctl", "service",
    "nginx", "apache2", "mysql", "postgres",
}

DEFAULT_IP_WHITELIST = {
    "127.0.0.1", "::1", "0.0.0.0",
}


# ── Hunt Sonucu ──────────────────────────────────────────────────────────────

class HuntResult:
    def __init__(self, hunt_name: str, query_time_s: float):
        self.hunt_name    = hunt_name
        self.query_time_s = query_time_s
        self.findings:    List[Dict] = []
        self.total_found: int = 0
        self.shown:       int = 0
        self.warning:     str = ""

    def add(self, finding: Dict):
        self.findings.append(finding)
        self.total_found += 1

    def top(self, n: int = 20) -> "HuntResult":
        """Return the top-N highest-scoring results."""
        self.findings = sorted(
            self.findings, key=lambda x: x.get("score", 0), reverse=True
        )[:n]
        self.shown = len(self.findings)
        return self

    def print_report(self):
        BOLD  = "\033[1m"
        CYAN  = "\033[96m"
        YELLOW = "\033[93m"
        RED   = "\033[91m"
        RESET = "\033[0m"

        print(f"\n{BOLD}{CYAN}{'━'*60}{RESET}")
        print(f"{BOLD}  🔍 HUNT: {self.hunt_name}{RESET}")
        print(f"  Sorgu süresi: {self.query_time_s:.2f}s")
        if self.warning:
            print(f"  {YELLOW}⚠️  {self.warning}{RESET}")
        print(f"{'━'*60}")

        if not self.findings:
            print(f"  ✅ Şüpheli bulgu yok.")
            print(f"{'━'*60}\n")
            return

        print(f"  {RED}⚡ {self.total_found} bulgu — ilk {self.shown} gösteriliyor{RESET}\n")

        for i, f in enumerate(self.findings, 1):
            score = f.get("score", 0)
            score_color = RED if score >= 70 else YELLOW if score >= 40 else ""
            print(f"  [{i:02d}] {score_color}Skor:{score:3.0f}{RESET}  {f.get('summary','')}")
            for k, v in f.items():
                if k in ("summary", "score", "acknowledged"):
                    continue
                print(f"        {k}: {v}")
            print()

        if self.total_found > self.shown:
            print(f"  ... ve {self.total_found - self.shown} bulgu daha.")
        print(f"{'━'*60}\n")


# ── Threat Hunting Motoru ────────────────────────────────────────────────────

class HuntEngine:
    """
    DB üzerinde hazır hunt sorguları çalıştırır.

    Parametreler:
        db         : PostgresDatabase instance
        days       : kaç günlük veri taransın (varsayılan: 7)
        user       : belirli bir kullanıcıya filtrele (opsiyonel)
        min_phase  : minimum faz (0 = her zaman, 1 = PHASE_1+)
        top_n      : gösterilecek maksimum sonuç sayısı
    """

    HUNT_NAMES = [
        "rare_processes",
        "beacon_detection",
        "lateral_movement",
        "credential_access",
        "persistence",
        "after_hours",
        "data_exfil",
        "new_users",
        "suspicious_ports",
        "log_tampering",
    ]

    def __init__(self, db, days: float = 7.0, user: str = "",
                 min_phase: int = 0, top_n: int = 20):
        self.db        = db
        self.days      = days
        self.user      = user
        self.min_phase = min_phase
        self.top_n     = top_n
        self._since    = time.time() - days * 86400
        self._proc_wl  = DEFAULT_PROCESS_WHITELIST
        self._ip_wl    = DEFAULT_IP_WHITELIST

        # Acknowledged bulgular — tekrarlanan sonuclari filtreler
        self._ack_file = Path("data/hunt_acknowledged.txt")
        self._ack: set = self._load_ack()

    def _rows(self, sql: str, params: tuple = ()) -> List[Dict]:
        """_read() sonuclarini dict listesine cevir."""
        raw = self.db._read(sql, params) or []
        return [dict(row) for row in raw]

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self, hunt_name: str) -> HuntResult:
        """Run the specified hunt scenario."""
        if hunt_name not in self.HUNT_NAMES:
            r = HuntResult(hunt_name, 0)
            r.warning = f"Bilinmeyen hunt: '{hunt_name}'. Geçerliler: {', '.join(self.HUNT_NAMES)}"
            return r

        start = time.time()
        handler = getattr(self, f"_hunt_{hunt_name}")
        result  = handler()
        result.query_time_s = time.time() - start
        result.top(self.top_n)
        return result

    def run_all(self) -> List[HuntResult]:
        """Run all hunt scenarios."""
        results = []
        for name in self.HUNT_NAMES:
            r = self.run(name)
            if r.total_found > 0:
                results.append(r)
        return results

    def acknowledge(self, hunt_name: str, key: str):
        """Mark a finding as acknowledged so it is hidden on the next run."""
        ack_key = f"{hunt_name}:{key}"
        self._ack.add(ack_key)
        self._save_ack()

    def coverage_report(self) -> Dict:
        """Return MITRE coverage for the hunt scenarios."""
        return {
            "rare_processes":   ["T1059", "T1204"],
            "beacon_detection": ["T1071", "T1132"],
            "lateral_movement": ["T1021"],
            "credential_access":["T1552", "T1003"],
            "persistence":      ["T1053", "T1543", "T1546"],
            "after_hours":      ["T1078"],
            "data_exfil":       ["T1041", "T1048"],
            "new_users":        ["T1136"],
            "suspicious_ports": ["T1571"],
            "log_tampering":    ["T1562"],
        }

    # ── Hunt Scenarios ───────────────────────────────────────────────────

    def _hunt_rare_processes(self) -> HuntResult:
        """Processes seen for the first time or running only rarely."""
        result = HuntResult("rare_processes", 0)

        rows = self._rows("""
            SELECT process, username AS user, src_ip, COUNT(*) as cnt,
                   MIN(ts) as first_seen, MAX(ts) as last_seen
            FROM events_recent
            WHERE ts > ? AND process IS NOT NULL AND process != ''
            GROUP BY process, username
            HAVING cnt <= 3
            ORDER BY first_seen DESC
            LIMIT 200
        """, (self._since,))

        for row in rows:
            proc = row.get("process", "")
            if not proc or proc in self._proc_wl:
                continue
            ack_key = f"{proc}:{row.get('user','')}"
            if ack_key in self._ack:
                continue

            # Skorlama
            score = 30
            if row.get("cnt", 0) == 1:
                score += 30   # tek görüldü
            hour = datetime.fromtimestamp(row.get("first_seen", 0)).hour
            if hour < 6 or hour > 22:
                score += 20   # gece yarısı
            if row.get("user") in ("root", "www-data"):
                score += 20

            result.add({
                "summary":    f"{proc} (kullanıcı: {row.get('user','-')})",
                "score":      score,
                "process":    proc,
                "user":       row.get("user", "-"),
                "gorulme":    row.get("cnt", 0),
                "ilk_gorulen": datetime.fromtimestamp(row.get("first_seen", 0)).strftime("%Y-%m-%d %H:%M"),
            })

        return result

    def _hunt_beacon_detection(self) -> HuntResult:
        """Regularly spaced outbound connections that may indicate C2 beaconing."""
        result = HuntResult("beacon_detection", 0)

        rows = self._rows("""
            SELECT src_ip, process, COUNT(*) as cnt,
                   MAX(ts) - MIN(ts) as duration,
                   MIN(ts) as first_seen
            FROM events_recent
            WHERE ts > ? AND category = 'network'
              AND src_ip NOT IN ('127.0.0.1', '::1')
            GROUP BY src_ip, process
            HAVING cnt >= 5 AND duration > 0
            ORDER BY cnt DESC
            LIMIT 100
        """, (self._since,))

        for row in rows:
            cnt      = row.get("cnt", 0)
            duration = row.get("duration", 1)
            if duration <= 0 or cnt < 5:
                continue

            interval = duration / max(cnt - 1, 1)
            # Beacon indicator: regular intervals between 30s and 300s
            if not (30 <= interval <= 300):
                continue

            ip = row.get("src_ip", "")
            if ip in self._ip_wl:
                continue
            ack_key = f"{ip}:{row.get('process','')}"
            if ack_key in self._ack:
                continue

            score = 50
            if 55 <= interval <= 65:    # tam 60s — klasik beacon
                score += 30
            if cnt >= 20:
                score += 20

            result.add({
                "summary":   f"{ip} → {cnt} bağlantı, ~{interval:.0f}s aralık",
                "score":     score,
                "ip":        ip,
                "process":   row.get("process", "-"),
                "baglanti":  cnt,
                "aralik_s":  f"{interval:.0f}",
                "ilk_gorulen": datetime.fromtimestamp(row.get("first_seen", 0)).strftime("%Y-%m-%d %H:%M"),
            })

        return result

    def _hunt_lateral_movement(self) -> HuntResult:
        """SSH activity from the same user to multiple targets."""
        result = HuntResult("lateral_movement", 0)

        rows = self._rows("""
            SELECT username AS user, COUNT(DISTINCT host) as host_cnt,
                   GROUP_CONCAT(DISTINCT host) as hosts,
                   MIN(ts) as first_seen
            FROM events_recent
            WHERE ts > ? AND action LIKE '%ssh%'
              AND outcome = 'success' AND username IS NOT NULL
            GROUP BY username
            HAVING host_cnt >= 2
            ORDER BY host_cnt DESC
            LIMIT 50
        """, (self._since,))

        for row in rows:
            user = row.get("user", "")
            if not user:
                continue
            if self.user and user != self.user:
                continue
            ack_key = f"{user}:{row.get('hosts','')}"
            if ack_key in self._ack:
                continue

            score = 40 + min(row.get("host_cnt", 2) * 15, 50)
            if user == "root":
                score = min(score + 20, 100)

            result.add({
                "summary":  f"{user} → {row.get('host_cnt')} farklı host",
                "score":    score,
                "user":     user,
                "host_sayisi": row.get("host_cnt"),
                "hostlar":  row.get("hosts", ""),
                "ilk_gorulen": datetime.fromtimestamp(row.get("first_seen", 0)).strftime("%Y-%m-%d %H:%M"),
            })

        return result

    def _hunt_credential_access(self) -> HuntResult:
        """Sensitive file access such as /etc/shadow, .ssh/, or credential dumps."""
        result = HuntResult("credential_access", 0)
        SENSITIVE = ["/etc/shadow", "/etc/passwd", ".ssh/", ".gnupg/",
                     "id_rsa", "id_ed25519", "/root/."]

        rows = self._rows("""
            SELECT username AS user, process, action, COUNT(*) as cnt,
                   MIN(ts) as first_seen
            FROM events_recent
            WHERE ts > ? AND category IN ('auth', 'process')
            GROUP BY username, process, action
            ORDER BY first_seen DESC
            LIMIT 500
        """, (self._since,))

        for row in rows:
            action = str(row.get("action", ""))
            if not any(s in action for s in SENSITIVE):
                continue
            ack_key = f"{row.get('user','')}:{action}"
            if ack_key in self._ack:
                continue

            score = 70
            if "shadow" in action:
                score = 90
            if row.get("user") not in ("root",):
                score += 10

            result.add({
                "summary":  f"{row.get('user','-')} → {action[:60]}",
                "score":    score,
                "user":     row.get("user", "-"),
                "process":  row.get("process", "-"),
                "erisim":   action[:80],
                "sayi":     row.get("cnt", 1),
                "ilk_gorulen": datetime.fromtimestamp(row.get("first_seen", 0)).strftime("%Y-%m-%d %H:%M"),
            })

        return result

    def _hunt_persistence(self) -> HuntResult:
        """Persistence mechanisms such as cron, systemd, or bashrc."""
        result = HuntResult("persistence", 0)
        PERSIST_PATTERNS = ["cron", "systemd", "service", "bashrc",
                            "profile", "rc.local", "init.d", "autostart"]

        rows = self._rows("""
            SELECT username AS user, action, process, ts
            FROM events_recent
            WHERE ts > ?
            ORDER BY ts DESC
            LIMIT 1000
        """, (self._since,))

        for row in rows:
            action  = str(row.get("action", "")).lower()
            process = str(row.get("process", "")).lower()
            combined = action + " " + process
            if not any(p in combined for p in PERSIST_PATTERNS):
                continue
            ack_key = f"{row.get('user','')}:{action}"
            if ack_key in self._ack:
                continue

            score = 50
            if "crontab" in combined or "rc.local" in combined:
                score = 75
            if row.get("user") not in ("root",):
                score += 15

            result.add({
                "summary":  f"{row.get('user','-')} → {action[:60]}",
                "score":    score,
                "user":     row.get("user", "-"),
                "process":  row.get("process", "-"),
                "aksiyon":  action[:80],
                "zaman":    datetime.fromtimestamp(row.get("ts", 0)).strftime("%Y-%m-%d %H:%M"),
            })

        return result

    def _hunt_after_hours(self) -> HuntResult:
        """After-hours activity between 22:00 and 06:00."""
        result = HuntResult("after_hours", 0)

        rows = self._rows("""
            SELECT username AS user, action, src_ip, ts
            FROM events_recent
            WHERE ts > ? AND username IS NOT NULL
              AND (CAST(strftime('%H', datetime(ts, 'unixepoch')) AS INTEGER) >= 22
                   OR CAST(strftime('%H', datetime(ts, 'unixepoch')) AS INTEGER) < 6)
            ORDER BY ts DESC
            LIMIT 200
        """, (self._since,))

        seen = set()
        for row in rows:
            user = row.get("user", "")
            if not user or user in ("cron", "daemon", "nobody"):
                continue
            key = f"{user}:{row.get('action','')}"
            if key in seen or key in self._ack:
                continue
            seen.add(key)

            hour  = datetime.fromtimestamp(row.get("ts", 0)).hour
            score = 35
            if 0 <= hour <= 4:
                score += 30   # gece yarısı daha şüpheli
            if user == "root":
                score += 20

            result.add({
                "summary":  f"{user} → saat {hour:02d}:xx aktivite",
                "score":    score,
                "user":     user,
                "aksiyon":  str(row.get("action", ""))[:60],
                "src_ip":   row.get("src_ip", "-"),
                "zaman":    datetime.fromtimestamp(row.get("ts", 0)).strftime("%Y-%m-%d %H:%M"),
            })

        return result

    def _hunt_data_exfil(self) -> HuntResult:
        """Large outbound data transfer that may indicate exfiltration."""
        result = HuntResult("data_exfil", 0)

        rows = self._rows("""
            SELECT src_ip, username AS user, COUNT(*) as cnt, MIN(ts) as first_seen
            FROM events_recent
            WHERE ts > ? AND category = 'network'
              AND src_ip NOT IN ('127.0.0.1', '::1', '10.0.0.1')
            GROUP BY src_ip
            HAVING cnt >= 50
            ORDER BY cnt DESC
            LIMIT 50
        """, (self._since,))

        for row in rows:
            ip = row.get("src_ip", "")
            if ip in self._ip_wl:
                continue
            ack_key = ip
            if ack_key in self._ack:
                continue

            cnt   = row.get("cnt", 0)
            score = min(30 + cnt // 10, 85)

            result.add({
                "summary":   f"{ip} → {cnt} network event",
                "score":     score,
                "ip":        ip,
                "baglanti":  cnt,
                "ilk_gorulen": datetime.fromtimestamp(row.get("first_seen", 0)).strftime("%Y-%m-%d %H:%M"),
            })

        return result

    def _hunt_new_users(self) -> HuntResult:
        """New users created within the last N days."""
        result = HuntResult("new_users", 0)

        rows = self._rows("""
            SELECT username AS user, action, ts
            FROM events_recent
            WHERE ts > ?
              AND action IN ('user_created', 'useradd', 'adduser', 'user_add')
            ORDER BY ts DESC
            LIMIT 50
        """, (self._since,))

        for row in rows:
            user = row.get("user", "")
            ack_key = f"{user}:{row.get('ts','')}"
            if ack_key in self._ack:
                continue

            result.add({
                "summary": f"Yeni kullanıcı: {user}",
                "score":   65,
                "user":    user,
                "aksiyon": row.get("action", ""),
                "zaman":   datetime.fromtimestamp(row.get("ts", 0)).strftime("%Y-%m-%d %H:%M"),
            })

        return result

    def _hunt_suspicious_ports(self) -> HuntResult:
        """Unusual port usage that may indicate C2 or a reverse shell."""
        result = HuntResult("suspicious_ports", 0)
        SUSPICIOUS_PORTS = {4444, 4445, 1234, 31337, 8888, 9999,
                            6666, 6667, 6668, 1337, 12345}

        rows = self._rows("""
            SELECT src_ip, process, action, ts
            FROM events_recent
            WHERE ts > ? AND category = 'network'
            ORDER BY ts DESC
            LIMIT 1000
        """, (self._since,))

        for row in rows:
            action = str(row.get("action", ""))
            for port in SUSPICIOUS_PORTS:
                if str(port) in action:
                    ack_key = f"{row.get('src_ip','')}:{port}"
                    if ack_key in self._ack:
                        continue
                    result.add({
                        "summary": f"Port {port} — {row.get('src_ip','-')}",
                        "score":   80,
                        "ip":      row.get("src_ip", "-"),
                        "port":    port,
                        "process": row.get("process", "-"),
                        "zaman":   datetime.fromtimestamp(row.get("ts", 0)).strftime("%Y-%m-%d %H:%M"),
                    })
                    break

        return result

    def _hunt_log_tampering(self) -> HuntResult:
        """Tampering with log files that may indicate trace removal."""
        result = HuntResult("log_tampering", 0)
        LOG_PATHS = ["/var/log/", "/var/log/auth.log", "/var/log/syslog",
                     "/var/log/apache", "auditd", "journalctl --rotate"]

        rows = self._rows("""
            SELECT username AS user, action, process, ts
            FROM events_recent
            WHERE ts > ?
            ORDER BY ts DESC
            LIMIT 1000
        """, (self._since,))

        for row in rows:
            action = str(row.get("action", "")).lower()
            if not any(p.lower() in action for p in LOG_PATHS):
                continue
            if "read" in action or "open" in action:
                continue  # sadece yazma/silme ilgili

            ack_key = f"{row.get('user','')}:{action}"
            if ack_key in self._ack:
                continue

            score = 75
            if "delete" in action or "truncate" in action or "rm" in action:
                score = 95

            result.add({
                "summary": f"{row.get('user','-')} → log müdahalesi şüphesi",
                "score":   score,
                "user":    row.get("user", "-"),
                "aksiyon": action[:80],
                "process": row.get("process", "-"),
                "zaman":   datetime.fromtimestamp(row.get("ts", 0)).strftime("%Y-%m-%d %H:%M"),
            })

        return result

    # ── Acknowledged Management ───────────────────────────────────────────

    def _load_ack(self) -> set:
        try:
            if self._ack_file.exists():
                return set(self._ack_file.read_text().splitlines())
        except Exception as e:
            logger.warning(f"[AegisCore:Hunt] Ack dosyasi okunamadi: {e}")
        return set()

    def _save_ack(self):
        try:
            self._ack_file.parent.mkdir(exist_ok=True)
            self._ack_file.write_text("\n".join(sorted(self._ack)))
        except Exception as e:
            logger.warning(f"[AegisCore:Hunt] Ack kayıt hatası: {e}")
