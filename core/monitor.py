from __future__ import annotations
"""
core/monitor.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Aktif İzleme Modülü (PHASE_0'dan itibaren aktif)

Her 30 saniyede kontrol eder:
  1. FileIntegrityMonitor  - kritik dosya hash değişimi
  2. ProcessMonitor        - beklenmedik yeni process
  3. NetworkMonitor        - beklenmedik dış bağlantı

İyileştirmeler (v2.2):
  - Browser/sistem process allowlist
  - Process risk scoring (browser=low, bash/python/curl=critical)
  - Network cooldown (process bazında)
  - auid=4294967295 (unset) filtresi
  - NET-011: process bazlı risk seviyesi
  - PROC-011: context-aware cooldown + benign runtime suppression counters
"""

import os
import re
import time
import hashlib
import logging
import subprocess
import json
import pwd
import grp
import stat
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


def _owner_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OSError):
        return str(uid)


def _group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except (KeyError, OSError):
        return str(gid)


def _safe_read_text(path: Path, max_chars: int = 240) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        lines.append(stripped)
        if sum(len(item) for item in lines) >= max_chars:
            break
    snippet = " | ".join(lines)
    return snippet[:max_chars]


def _path_context(path: Path, include_preview: bool = False) -> Dict:
    details = {
        "path": str(path),
        "path_name": path.name,
        "path_parent": str(path.parent),
        "path_exists": path.exists(),
    }
    try:
        st = path.stat()
        details.update({
            "path_type": "directory" if stat.S_ISDIR(st.st_mode) else "file",
            "path_mode": oct(stat.S_IMODE(st.st_mode)),
            "path_size": st.st_size,
            "path_mtime": round(st.st_mtime, 3),
            "path_uid": st.st_uid,
            "path_gid": st.st_gid,
            "path_owner": _owner_name(st.st_uid),
            "path_group": _group_name(st.st_gid),
        })
    except OSError:
        return details

    if path.is_symlink():
        try:
            details["symlink_target"] = os.readlink(path)
        except OSError as exc:
            logger.debug(f"[Monitor] Symlink target okunamadi: {path}: {exc}")

    if path.is_dir():
        try:
            entries = sorted(p.name for p in path.iterdir())
            details["dir_sample"] = entries[:5]
            details["dir_entry_count"] = len(entries)
        except OSError as exc:
            logger.debug(f"[Monitor] Dizin icerigi okunamadi: {path}: {exc}")
    elif include_preview:
        preview = _safe_read_text(path)
        if preview:
            details["content_preview"] = preview
    return details

# ── Alert Callback Tipi ───────────────────────────────────────────────────────

@dataclass
class MonitorAlert:
    rule_id:   str
    severity:  str
    message:   str
    details:   Dict = field(default_factory=dict)
    ts:        float = field(default_factory=time.time)
    category:  str = "monitor"


# ── 1. File Integrity ──────────────────────────────────────────────────

CRITICAL_FILES = [
    # Kimlik / yetki
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/group",
    "/etc/gshadow",
    # SSH
    "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/known_hosts",
    # Cron
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    # System startup / persistence
    "/etc/rc.local",
    "/etc/init.d",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/environment",
    "/etc/ld.so.preload",        # LD preload injection
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    # PAM
    "/etc/pam.d/sshd",
    "/etc/pam.d/sudo",
    "/etc/pam.d/su",
    "/etc/pam.conf",
    # Systemd user persistence
    "/etc/systemd/system",
    "/usr/local/bin",            # sıkça kullanılan persistence path
    "/usr/local/sbin",
    # User profiles (directory-based hashes)
    "/home",
    "/etc/hosts",
]

class FileIntegrityMonitor:
    def __init__(self, files: List[str] = None, state_dir: str = "data"):
        self.files     = files or CRITICAL_FILES
        self.state_dir = Path(state_dir)
        self._hashes:  Dict[str, str] = {}
        self._state_file = self.state_dir / "fim_state.json"
        self._initialized = False
        self._load()

    @staticmethod
    def _hash_path_chunked(p: Path, chunk: int = 65536) -> Optional[str]:
        """Hash a file or directory in chunks to save RAM on large files."""
        try:
            h = hashlib.md5()
            if p.is_dir():
                for f in sorted(p.rglob("*")):
                    if f.is_file():
                        try:
                            with open(f, "rb") as fh:
                                for blk in iter(lambda: fh.read(chunk), b""):
                                    h.update(blk)
                        except OSError as _e:
                            logger.debug(f"[AegisCore:FIM] Dosya okunamadı: {f}: {_e}")
            elif p.is_file():
                with open(p, "rb") as fh:
                    for blk in iter(lambda: fh.read(chunk), b""):
                        h.update(blk)
            else:
                return None
            return h.hexdigest()
        except OSError as e:
            logger.debug(f"[AegisCore:FIM] Hash alınamadı: {p}: {e}")
            return None

    def _hash_file(self, path: str) -> Optional[str]:
        return self._hash_path_chunked(Path(path))

    def _collect_context(self, path: str) -> Dict:
        return _path_context(Path(path), include_preview=True)

    def _load(self):
        if self._state_file.exists():
            try:
                self._hashes = json.loads(self._state_file.read_text())
                self._initialized = True
                logger.info(f"[AegisCore:FIM] {len(self._hashes)} dosya hash yüklendi.")
            except (OSError, json.JSONDecodeError) as e:
                logger.debug(f"[AegisCore:FIM] State yüklenemedi: {e}")

    def _save(self):
        try:
            self._state_file.write_text(json.dumps(self._hashes))
        except Exception as e:
            logger.error(f"[AegisCore:FIM] Kayıt hatası: {e}")

    def check(self) -> List[MonitorAlert]:
        alerts = []
        for path in self.files:
            current = self._hash_file(path)
            if current is None:
                continue

            if not self._initialized:
                self._hashes[path] = current
                continue

            prev = self._hashes.get(path)
            if prev is None:
                self._hashes[path] = current
                alerts.append(MonitorAlert(
                    rule_id  = "FIM-002",
                    severity = "high",
                    message  = f"Kritik yolda yeni dosya: {path}",
                    details  = {
                        **self._collect_context(path),
                        "hash": current,
                    },
                    category = "filesystem"
                ))
            elif prev != current:
                self._hashes[path] = current
                alerts.append(MonitorAlert(
                    rule_id  = "FIM-001",
                    severity = "critical",
                    message  = f"Kritik dosya değişti: {path}",
                    details  = {
                        **self._collect_context(path),
                        "old_hash": prev,
                        "new_hash": current,
                    },
                    category = "filesystem"
                ))

        if not self._initialized:
            self._initialized = True
            logger.info(f"[AegisCore:FIM] Baseline oluşturuldu: {len(self._hashes)} dosya")

        self._save()
        return alerts


# ── 2. Process Monitoring ──────────────────────────────────────────────

# Normal system/user processes — should not emit PROC-011
KNOWN_PROCESSES = {
    # Sistem
    "systemd", "kthreadd", "kworker", "ksoftirqd", "migration",
    "sshd", "cron", "crond", "rsyslogd", "auditd", "dbus-daemon",
    "NetworkManager", "systemd-journal", "systemd-resolve", "systemd-logind",
    "snapd", "polkitd", "udisksd", "accounts-daemon", "atd",
    "chronyd", "avahi-daemon", "cups", "gdm3", "lightdm",
    "vmtoolsd", "dockerd", "containerd", "containerd-shim",
    # Shell / system tools
    "bash", "sh", "dash", "zsh", "fish",
    "sudo", "su", "login",
    "python3", "python", "python2",
    "apt", "apt-get", "dpkg", "snap",
    "apt-helper", "packagekitd", "initramfs-tools",
    # Desktop / GUI
    "gnome-shell", "gnome-session", "Xorg", "Xwayland",
    "pulseaudio", "pipewire", "wireplumber",
    "dconf-service", "gvfsd", "gvfsd-fuse",
    "nautilus", "gedit", "evince",
    # Web sunucu / DB
    "apache2", "nginx", "mysql", "mysqld",
    "postgres", "postgresql",
    # Browsers — allowlist entries (no PROC-011)
    "firefox", "firefox-esr", "firefox-bin",
    "chrome", "chromium", "chromium-browser",
    "google-chrome", "brave", "opera",
    # Electron / helper
    "electron", "code", "code-oss",
    # Terminal
    "gnome-terminal", "xterm", "konsole", "tmux", "screen",
    # SSH / network
    "ssh", "sftp", "rsync", "curl", "wget",
    # VMware
    "vmware-vmx", "vmtoolsd", "vmware-user",
}

# Definitely suspicious — PROC-010 CRITICAL
SUSPICIOUS_PROCESSES = {
    "nc", "ncat", "netcat", "nmap", "masscan", "rustscan",
    "hydra", "medusa", "john", "hashcat", "patator",
    "msfconsole", "msfvenom", "metasploit",
    "tcpdump", "wireshark", "tshark", "ettercap",
    "socat", "cryptcat",
    "mimikatz", "bloodhound", "sharphound",
    "sqlmap", "nikto", "dirb", "gobuster", "wfuzz",
    "aircrack-ng", "reaver", "pixiewps",
    "beef", "setoolkit",
}

# Process risk scores for NET-011 severity
PROCESS_RISK = {
    # High risk — suspicious when command-line tools open outbound connections
    "bash":    "high",
    "sh":      "high",
    "dash":    "high",
    "zsh":     "high",
    "python3": "high",
    "python":  "high",
    "python2": "high",
    "perl":    "high",
    "ruby":    "high",
    "php":     "high",
    "curl":    "medium",
    "wget":    "medium",
    "nc":      "critical",
    "ncat":    "critical",
    "socat":   "critical",
    # Low risk — browsers/system
    "firefox": "low",
    "chrome":  "low",
    "chromium":"low",
    "google-chrome": "low",
    "brave":   "low",
    "ssh":     "low",
    "curl":    "medium",
}

# Context-aware cooldown for PROC-011 (seconds)
PROC_011_COOLDOWN = 300

PROC_011_BENIGN_RUNTIME_NAMES = {
    "tracker-extract",
    "tracker-miner",
    "tracker-miner-fs",
    "udev-worker",
    "runc",
    "systemd-detect-virt",
}

PROC_011_BENIGN_RUNTIME_PREFIXES = (
    "tracker-",
    "systemd-detect",
    "gnome-terminal-",
)

PROC_011_SUSPICIOUS_PARENTS = {
    "sshd", "sudo", "su",
    "apache2", "nginx", "httpd", "php-fpm",
    "mysql", "mysqld", "postgres", "postgresql",
    "cron", "crond",
}

PROC_011_WEB_USERS = {"www-data", "apache", "nginx"}
PROC_011_LOCAL_BENIGN_PARENTS = {
    "systemd", "systemd-udevd", "dbus-daemon", "gnome-shell",
    "gnome-session", "gnome-session-binary", "tracker-miner-fs",
    "tracker-miner", "containerd", "containerd-shim", "containerd-shim-runc-v2",
    "dockerd", "NetworkManager", "vmtoolsd",
}

PROC_011_SUSPICIOUS_CMD_TOKENS = (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/dev/tcp/",
    "curl ", "wget ", " nc ", "ncat ", "socat ", "bash -i",
    "chmod ", "chown ", "systemctl ", "service ",
    "truncate ", "journalctl ", "iptables", "nft ", "ufw ", "firewalld",
)

KNOWN_PROCESS_PREFIXES = (
    "kworker",
    "ksoftirqd",
    "migration",
    "packagekit",
    "apt-helper",
    "initramfs-tools",
)

class ProcessMonitor:
    def __init__(self):
        self._known_pids:   Set[int]         = set()
        self._initialized:  bool             = False
        self._proc011_seen: Dict[str, float] = {}
        self._suppressed_stats = {
            "total": 0,
            "by_process": {},
            "by_reason": {},
        }

    def _get_processes(self) -> Dict[int, str]:
        procs = {}
        try:
            out = subprocess.check_output(
                ["ps", "-eo", "pid,comm", "--no-headers"],
                stderr=subprocess.DEVNULL, text=True
            )
            for line in out.strip().splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    try:
                        procs[int(parts[0])] = parts[1].strip()
                    except ValueError as exc:
                        logger.debug(f"[PROC] Gecersiz pid satiri atlandi: {line!r}: {exc}")
        except Exception as e:
            logger.debug(f"[PROC] ps hatası: {e}")
        return procs

    def _cooldown_ok(self, signature: str) -> bool:
        """Has the cooldown expired for this process context?"""
        last = self._proc011_seen.get(signature, 0.0)
        now = time.time()
        if now - last > PROC_011_COOLDOWN:
            self._proc011_seen[signature] = now
            return True
        return False

    def _record_proc011_suppressed(self, process_name: str, reason: str) -> None:
        stats = self._suppressed_stats
        stats["total"] = int(stats.get("total", 0) or 0) + 1
        base = str(process_name or "unknown").strip().lower() or "unknown"
        by_process = stats.setdefault("by_process", {})
        by_reason = stats.setdefault("by_reason", {})
        by_process[base] = int(by_process.get(base, 0) or 0) + 1
        by_reason[reason] = int(by_reason.get(reason, 0) or 0) + 1

    def suppression_stats(self) -> Dict:
        stats = self._suppressed_stats if isinstance(self._suppressed_stats, dict) else {}
        return {
            "total": int(stats.get("total", 0) or 0),
            "by_process": {str(k): int(v or 0) for k, v in (stats.get("by_process", {}) or {}).items()},
            "by_reason": {str(k): int(v or 0) for k, v in (stats.get("by_reason", {}) or {}).items()},
        }

    def _is_known_process(self, base: str) -> bool:
        if base in KNOWN_PROCESSES:
            return True
        return any(base.startswith(prefix) for prefix in KNOWN_PROCESS_PREFIXES)

    @staticmethod
    def _normalize_name_base(name: str) -> str:
        raw = str(name or "").strip().lower().strip("()")
        if not raw:
            return ""
        return os.path.basename(raw) if raw.startswith("/") else raw

    @staticmethod
    def _path_class(details: Dict) -> str:
        exe = str(details.get("exe", "") or "").lower()
        cwd = str(details.get("cwd", "") or "").lower()
        cmdline = str(details.get("cmdline", "") or "").lower()
        blob = " ".join(part for part in (exe, cwd, cmdline) if part)
        if any(tok in blob for tok in ("/tmp/", "/var/tmp/", "/dev/shm/")):
            return "temp"
        if any(tok in blob for tok in ("containerd", "docker", "runc", "/run/container", "/var/lib/docker/")):
            return "container"
        if exe.startswith(("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/")):
            return "system"
        if exe.startswith("/home/") or cwd.startswith("/home/"):
            return "user-home"
        return "unknown"

    def _suspicious_context(self, base: str, details: Dict) -> bool:
        parent = self._normalize_name_base(details.get("parent_name", ""))
        user = str(details.get("user", "") or "").strip().lower()
        exe = str(details.get("exe", "") or "").strip().lower()
        cmdline = str(details.get("cmdline", "") or "").strip().lower()
        cwd = str(details.get("cwd", "") or "").strip().lower()
        path_class = self._path_class(details)
        blob = " ".join(part for part in (exe, cmdline, cwd) if part)
        if base in SUSPICIOUS_PROCESSES:
            return True
        if parent in PROC_011_SUSPICIOUS_PARENTS:
            return True
        if user in PROC_011_WEB_USERS:
            return True
        if path_class == "temp":
            return True
        return any(token in blob for token in PROC_011_SUSPICIOUS_CMD_TOKENS)

    def _is_benign_runtime_process(self, base: str, details: Dict) -> bool:
        if not base:
            return False
        if not (
            base in PROC_011_BENIGN_RUNTIME_NAMES
            or any(base.startswith(prefix) for prefix in PROC_011_BENIGN_RUNTIME_PREFIXES)
        ):
            return False
        if self._suspicious_context(base, details):
            return False
        parent = self._normalize_name_base(details.get("parent_name", ""))
        path_class = self._path_class(details)
        if base == "runc" and path_class == "container":
            return True
        if parent in PROC_011_LOCAL_BENIGN_PARENTS:
            return True
        return path_class in {"system", "container", "user-home", "unknown"}

    def _proc011_signature(self, base: str, details: Dict) -> str:
        parent = self._normalize_name_base(details.get("parent_name", "")) or "unknown-parent"
        user = str(details.get("user", "") or "").strip().lower() or "unknown-user"
        path_class = self._path_class(details)
        exe = str(details.get("exe", "") or "").strip().lower()
        exe_marker = os.path.basename(exe) if exe else path_class
        host_context = str(details.get("host_context", "local_monitor") or "local_monitor")
        return f"{base}|{parent}|{user}|{path_class}|{exe_marker}|{host_context}"

    def _read_process_context(self, pid: int) -> Dict:
        proc_dir = Path("/proc") / str(pid)
        details = {"pid": pid}

        try:
            status_lines = (proc_dir / "status").read_text(encoding="utf-8", errors="replace").splitlines()
            status = {}
            for line in status_lines:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                status[key.strip()] = value.strip()
            ppid = int(status.get("PPid", "0") or 0)
            uid_field = status.get("Uid", "0").split()
            uid = int(uid_field[0]) if uid_field else 0
            details.update({
                "ppid": ppid,
                "uid": uid,
                "user": _owner_name(uid),
            })
            if ppid > 0:
                try:
                    parent_name = (Path("/proc") / str(ppid) / "comm").read_text(encoding="utf-8", errors="replace").strip()
                    if parent_name:
                        details["parent_name"] = parent_name
                except OSError as exc:
                    logger.debug(f"[PROC] Parent comm okunamadi pid={ppid}: {exc}")
        except OSError as exc:
            logger.debug(f"[PROC] /proc status okunamadi pid={pid}: {exc}")

        for key, proc_file in (("cmdline", "cmdline"), ("name", "comm")):
            try:
                raw = (proc_dir / proc_file).read_bytes()
            except OSError:
                continue
            text = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            if text:
                details[key] = text[:240]

        try:
            exe = os.readlink(proc_dir / "exe")
            if exe:
                details["exe"] = exe
        except OSError as exc:
            logger.debug(f"[PROC] exe okunamadi pid={pid}: {exc}")

        try:
            cwd = os.readlink(proc_dir / "cwd")
            if cwd:
                details["cwd"] = cwd
        except OSError as exc:
            logger.debug(f"[PROC] cwd okunamadi pid={pid}: {exc}")

        return details

    def check(self) -> List[MonitorAlert]:
        alerts  = []
        current = self._get_processes()

        if not self._initialized:
            self._known_pids = set(current.keys())
            self._initialized = True
            logger.info(f"[PROC] Baseline: {len(self._known_pids)} process")
            return alerts

        new_pids = set(current.keys()) - self._known_pids
        for pid in new_pids:
            name = current.get(pid, "")
            norm_name = name.strip()
            base = self._normalize_name_base(norm_name)
            details = {
                "name": name,
                "name_base": base,
                "host_context": "local_monitor",
                **self._read_process_context(pid),
            }

            # Definitely suspicious — always alert
            if base in SUSPICIOUS_PROCESSES:
                alerts.append(MonitorAlert(
                    rule_id  = "PROC-010",
                    severity = "critical",
                    message  = f"Şüpheli process başladı: {name} (pid={pid})",
                    details  = details,
                    category = "process"
                ))
            # Bilinmeyen — context-aware cooldown ve benign suppression ile
            elif not self._is_known_process(base) and len(base) > 2:
                if self._is_benign_runtime_process(base, details):
                    self._record_proc011_suppressed(base, "benign_known_runtime_process")
                    continue
                path_class = self._path_class(details)
                signature = self._proc011_signature(base, details)
                if self._cooldown_ok(signature):
                    alerts.append(MonitorAlert(
                        rule_id  = "PROC-011",
                        severity = "low",
                        message  = f"Beklenmeyen yeni process gözlendi: {name} (pid={pid}); parent, kullanıcı ve komut satırı bağlamı doğrulanmalı",
                        details  = {
                            **details,
                            "reason": "first_seen_process",
                            "classification": "unknown_process",
                            "path_class": path_class,
                            "cooldown_key": signature,
                        },
                        category = "process"
                    ))

        self._known_pids = set(current.keys())
        return alerts


# ── 3. Network Connection Monitoring ───────────────────────────────────

KNOWN_PORTS      = {22, 80, 443, 3306, 5432, 8080, 8443, 3000, 5000}
SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 6666, 9999, 8888, 1234, 6667}

# Browser/system processes normalized as expected outbound connectors
BROWSER_PROCESSES = {
    "firefox", "firefox-esr", "firefox-bin",
    "chrome", "chromium", "chromium-browser",
    "google-chrome", "brave", "opera",
    "electron", "code", "code-oss",
    "apt", "apt-get", "snap", "snapd",
    "curl", "wget", "ssh", "rsync",
    "update-notifier", "packagekitd",
    "vmtoolsd",
    "codex", "codex-cli",
    "node", "nodejs", "npm", "pnpm", "yarn", "bun",
    "git", "gh",
}

NORMAL_EXTERNAL_PREFIXES = (
    "chrome",
    "chromium",
    "firefox",
    "brave",
    "opera",
    "electron",
    "code",
    "codex",
    "packagekit",
    "apt",
)

# NET-011 cooldown per process (seconds)
NET_011_COOLDOWN = 120   # aynı process 2dk'da 1 alert
NET_BEHAVIOR_WINDOW = 180
NET_LONG_LIVED_SECONDS = 600

SERVER_ROLE_PROCESSES = {
    "apache2", "httpd", "nginx", "php-fpm",
    "mysqld", "mysql", "postgres", "postgresql",
    "redis-server", "redis", "tomcat", "java",
}

COMMON_OUTBOUND_PORTS = {53, 80, 123, 443, 465, 587, 993, 995}
ROLE_PORT_EXPECTATIONS = {
    "apache2": COMMON_OUTBOUND_PORTS,
    "httpd": COMMON_OUTBOUND_PORTS,
    "nginx": COMMON_OUTBOUND_PORTS,
    "php-fpm": COMMON_OUTBOUND_PORTS,
    "mysqld": COMMON_OUTBOUND_PORTS | {3306},
    "mysql": COMMON_OUTBOUND_PORTS | {3306},
    "postgres": COMMON_OUTBOUND_PORTS | {5432},
    "postgresql": COMMON_OUTBOUND_PORTS | {5432},
    "redis-server": COMMON_OUTBOUND_PORTS | {6379},
    "redis": COMMON_OUTBOUND_PORTS | {6379},
}

class NetworkMonitor:
    def __init__(self):
        self._known_connections: Set[str]        = set()
        self._initialized:       bool            = False
        self._proc_last_alert:   Dict[str, float] = {}   # proc_name → ts
        self._conn_state: Dict[str, Dict] = {}
        self._actor_dest_events: Dict[str, deque] = defaultdict(deque)
        self._actor_endpoint_events: Dict[str, deque] = defaultdict(deque)
        self._seen_destinations: Dict[str, float] = {}
        self._behavior_last_alert: Dict[str, float] = {}

    def _get_connections(self) -> List[Dict]:
        conns = []
        # ss tercih et, yoksa netstat dene
        for cmd in (
            ["ss", "-tnp", "state", "established"],
            ["netstat", "-tnp"],
        ):
            try:
                out = subprocess.check_output(
                    cmd, stderr=subprocess.DEVNULL, text=True
                )
                for line in out.strip().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        conns.append({
                            "local":  parts[2] if cmd[0] == "ss" else parts[3],
                            "remote": parts[3] if cmd[0] == "ss" else parts[4],
                            "proc":   parts[4] if (cmd[0]=="ss" and len(parts)>4) else
                                      (parts[6] if (cmd[0]=="netstat" and len(parts)>6) else ""),
                        })
                break
            except (ValueError, IndexError, subprocess.SubprocessError) as _e:
                logger.debug(f"[AegisCore:Net] Komut çıktısı parse edilemedi: {_e}")
                continue
        return conns

    def _is_private(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            first  = int(parts[0])
            second = int(parts[1])
            return (first == 10 or first == 127 or
                    (first == 172 and 16 <= second <= 31) or
                    (first == 192 and second == 168))
        except ValueError:
            return True

    def _extract_proc_name(self, proc_str: str) -> str:
        """
        ss çıktısı: users:(("firefox",pid=3859,fd=53))
        netstat   : 3859/firefox
        """
        m = re.search(r'"([^"]+)"', proc_str)
        if m:
            return m.group(1).lower()
        m = re.search(r'\d+/(\S+)', proc_str)
        if m:
            return m.group(1).lower()
        return proc_str.lower()

    def _extract_pid(self, proc_str: str) -> int:
        m = re.search(r"pid=(\d+)", proc_str)
        if m:
            return int(m.group(1))
        m = re.search(r"(\d+)/\S+", proc_str)
        if m:
            return int(m.group(1))
        return 0

    def _connection_context(self, conn: Dict, proc_name: str, remote_ip: str, remote_port: int) -> Dict:
        local = conn.get("local", "")
        local_ip, _, local_port_raw = local.rpartition(":")
        local_port = int(local_port_raw) if local_port_raw.isdigit() else 0
        pid = self._extract_pid(conn.get("proc", ""))
        details = {
            **conn,
            "proc_name": proc_name,
            "pid": pid,
            "local_ip": local_ip or local,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "socket_direction": "outbound",
            "remote_scope": "private" if self._is_private(remote_ip) else "public",
            "connection_key": f"{conn.get('local', '')}-{conn.get('remote', '')}",
        }
        if pid > 0:
            proc_ctx = ProcessMonitor()._read_process_context(pid)
            for key in ("user", "uid", "exe", "cmdline", "ppid", "parent_name", "cwd"):
                if key in proc_ctx:
                    details[f"proc_{key}"] = proc_ctx[key]
        return details

    def _net_cooldown_ok(self, proc_name: str) -> bool:
        last = self._proc_last_alert.get(proc_name, 0)
        if time.time() - last > NET_011_COOLDOWN:
            self._proc_last_alert[proc_name] = time.time()
            return True
        return False

    def _behavior_cooldown_ok(self, key: str, cooldown: int = 300) -> bool:
        last = self._behavior_last_alert.get(key, 0)
        now = time.time()
        if now - last > cooldown:
            self._behavior_last_alert[key] = now
            return True
        return False

    def _is_normal_external_process(self, proc_name: str) -> bool:
        if proc_name in BROWSER_PROCESSES:
            return True
        return any(proc_name.startswith(prefix) for prefix in NORMAL_EXTERNAL_PREFIXES)

    def _actor_key(self, details: Dict) -> str:
        proc_user = details.get("proc_user") or details.get("proc_uid") or "unknown"
        proc_name = details.get("proc_name") or "unknown"
        return f"{proc_user}:{proc_name}"

    def _is_behavior_candidate(self, proc_name: str, details: Dict) -> bool:
        if self._is_normal_external_process(proc_name):
            return False
        if proc_name in ("curl", "wget", "ssh", "rsync"):
            return False
        if proc_name in SERVER_ROLE_PROCESSES:
            return True
        if details.get("proc_parent_name") in SERVER_ROLE_PROCESSES:
            return True
        proc_parent = str(details.get("proc_parent_name") or "").lower()
        if proc_parent in {"bash", "sh", "dash", "zsh", "sshd", "sudo", "systemd-run"}:
            return True
        proc_exe = str(details.get("proc_exe") or "").lower()
        if proc_exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
            return True
        risk = PROCESS_RISK.get(proc_name)
        return risk in ("high", "critical") or not proc_name

    def _is_role_mismatch(self, proc_name: str, details: Dict) -> bool:
        if proc_name not in SERVER_ROLE_PROCESSES:
            return False
        remote_port = int(details.get("remote_port", 0) or 0)
        if remote_port == 0:
            return False
        allowed = ROLE_PORT_EXPECTATIONS.get(proc_name, COMMON_OUTBOUND_PORTS)
        return remote_port not in allowed

    def _prune_deque(self, dq: deque, now: float, window: int = NET_BEHAVIOR_WINDOW) -> None:
        while dq and now - dq[0][0] > window:
            dq.popleft()

    def _build_behavior_alert(self, rule_id: str, severity: str, message: str,
                              details: Dict, extra: Dict = None) -> MonitorAlert:
        merged = {
            **details,
            "public_outbound": details.get("remote_scope") == "public",
            "unknown_process": not self._is_normal_external_process(details.get("proc_name", "")),
            "suspicious": True,
        }
        if extra:
            merged.update(extra)
        return MonitorAlert(
            rule_id=rule_id,
            severity=severity,
            message=message,
            details=merged,
            category="network",
        )

    def _behavior_alerts_for_new_connection(self, details: Dict, proc_name: str) -> List[MonitorAlert]:
        alerts: List[MonitorAlert] = []
        now = time.time()
        actor = self._actor_key(details)
        endpoint = f"{details.get('remote_ip','')}:{details.get('remote_port',0)}"
        actor_dest_key = f"{actor}|{endpoint}"
        role_mismatch = self._is_role_mismatch(proc_name, details)
        candidate = self._is_behavior_candidate(proc_name, details)

        details["behavior_actor"] = actor
        details["role_mismatch"] = role_mismatch

        if candidate:
            if actor_dest_key not in self._seen_destinations and (
                role_mismatch or int(details.get("remote_port", 0) or 0) not in KNOWN_PORTS
            ):
                self._seen_destinations[actor_dest_key] = now
                if self._behavior_cooldown_ok(f"rare:{actor}:{endpoint}", cooldown=600):
                    alerts.append(self._build_behavior_alert(
                        "NET-014",
                        "medium" if role_mismatch else "low",
                        f"İlk kez görülen outbound hedef: {endpoint} ({proc_name or 'unknown'})",
                        details,
                        {"dest_novelty": "first_seen", "role_mismatch": role_mismatch},
                    ))
            else:
                self._seen_destinations.setdefault(actor_dest_key, now)

            if proc_name not in SERVER_ROLE_PROCESSES:
                dest_dq = self._actor_dest_events[actor]
                dest_dq.append((now, details.get("remote_ip", ""), details.get("remote_port", 0)))
                self._prune_deque(dest_dq, now)
                unique_remotes = {item[1] for item in dest_dq if item[1]}
                if len(unique_remotes) >= 5 and self._behavior_cooldown_ok(f"fanout:{actor}", cooldown=300):
                    alerts.append(self._build_behavior_alert(
                        "NET-015",
                        "high",
                        f"Kısa sürede çok sayıda farklı hedefe outbound bağlantı: {proc_name or 'unknown'}",
                        details,
                        {
                            "fanout_unique_remotes": len(unique_remotes),
                            "fanout_window_seconds": NET_BEHAVIOR_WINDOW,
                        },
                    ))

            endpoint_dq = self._actor_endpoint_events[actor_dest_key]
            endpoint_dq.append((now, details.get("local_port", 0)))
            self._prune_deque(endpoint_dq, now)
            unique_local_ports = {item[1] for item in endpoint_dq if item[1]}
            if len(unique_local_ports) >= 4 and self._behavior_cooldown_ok(f"fanin:{actor_dest_key}", cooldown=300):
                alerts.append(self._build_behavior_alert(
                    "NET-016",
                    "high" if role_mismatch else "medium",
                    f"Aynı hedefe tekrar eden outbound reconnect paterni: {endpoint} ({proc_name or 'unknown'})",
                    details,
                    {
                        "fanin_unique_local_ports": len(unique_local_ports),
                        "fanin_window_seconds": NET_BEHAVIOR_WINDOW,
                    },
                ))

        return alerts

    def _long_lived_alerts(self, current_keys: Set[str]) -> List[MonitorAlert]:
        alerts: List[MonitorAlert] = []
        now = time.time()
        for key in current_keys:
            state = self._conn_state.get(key)
            if not state:
                continue
            age = now - state.get("first_seen", now)
            proc_name = state.get("proc_name", "")
            if age < NET_LONG_LIVED_SECONDS or state.get("long_lived_alerted"):
                continue
            if state.get("remote_scope") != "public":
                continue
            if not self._is_behavior_candidate(proc_name, state):
                continue
            if not (state.get("role_mismatch") or int(state.get("remote_port", 0) or 0) not in KNOWN_PORTS):
                continue
            state["long_lived_alerted"] = True
            if not self._behavior_cooldown_ok(f"long:{key}", cooldown=900):
                continue
            alerts.append(self._build_behavior_alert(
                "NET-017",
                "high",
                f"Uzun yaşayan şüpheli outbound bağlantı: {state.get('remote')} ({proc_name or 'unknown'})",
                state,
                {"connection_age_seconds": int(age)},
            ))
        return alerts

    def check(self) -> List[MonitorAlert]:
        alerts  = []
        current = self._get_connections()
        now = time.time()

        if not self._initialized:
            self._known_connections = {
                f"{c['local']}-{c['remote']}" for c in current
            }
            for conn in current:
                key = f"{conn['local']}-{conn['remote']}"
                remote = conn["remote"].rsplit(":", 1)
                remote_ip = remote[0] if len(remote) == 2 else conn["remote"]
                remote_port = int(remote[1]) if len(remote) == 2 and remote[1].isdigit() else 0
                proc_name = self._extract_proc_name(conn.get("proc", ""))
                details = self._connection_context(conn, proc_name, remote_ip, remote_port)
                details.update({"first_seen": now, "last_seen": now, "long_lived_alerted": False})
                details["role_mismatch"] = self._is_role_mismatch(proc_name, details)
                self._conn_state[key] = details
            self._initialized = True
            return alerts

        current_keys: Set[str] = set()
        for conn in current:
            key         = f"{conn['local']}-{conn['remote']}"
            remote      = conn["remote"].rsplit(":", 1)
            remote_ip   = remote[0] if len(remote) == 2 else conn["remote"]
            remote_port = int(remote[1]) if len(remote) == 2 and remote[1].isdigit() else 0
            proc_name   = self._extract_proc_name(conn.get("proc", ""))
            conn_details = self._connection_context(conn, proc_name, remote_ip, remote_port)
            current_keys.add(key)

            existing = self._conn_state.get(key)
            first_seen = existing.get("first_seen", now) if existing else now
            long_lived_alerted = existing.get("long_lived_alerted", False) if existing else False
            conn_details.update({
                "first_seen": first_seen,
                "last_seen": now,
                "long_lived_alerted": long_lived_alerted,
            })
            conn_details["role_mismatch"] = self._is_role_mismatch(proc_name, conn_details)
            self._conn_state[key] = conn_details

            if key in self._known_connections:
                continue

            self._known_connections.add(key)

            # ── Suspicious port — always CRITICAL ─────────────────────────
            if remote_port in SUSPICIOUS_PORTS:
                alerts.append(MonitorAlert(
                    rule_id  = "NET-010",
                    severity = "critical",
                    message  = f"Şüpheli porta bağlantı: {conn['remote']} ({proc_name})",
                    details  = {**conn_details, "risk": "critical"},
                    category = "network"
                ))
                alerts.extend(self._behavior_alerts_for_new_connection(conn_details, proc_name))
                continue

            # ── External IP ─────────────────────────────────────────────────
            if self._is_private(remote_ip):
                continue

            # Process risk seviyesi belirle
            risk = PROCESS_RISK.get(proc_name, None)

            # Browser/sistem → LOW, cooldown ile
            if self._is_normal_external_process(proc_name):
                continue

            # Shell/scripting → HIGH/CRITICAL — reverse shell riski
            elif proc_name in ("bash", "sh", "dash", "zsh", "python3", "python",
                               "python2", "perl", "ruby", "php"):
                alerts.append(MonitorAlert(
                    rule_id  = "NET-012",
                    severity = "critical",
                    message  = f"Shell process dış bağlantı açtı: {proc_name} → {conn['remote']}",
                    details  = {**conn_details, "risk": "critical",
                                "note": "Olası reverse shell veya C2 beacon"},
                    category = "network"
                ))
                alerts.extend(self._behavior_alerts_for_new_connection(conn_details, proc_name))

            # Curl/wget → MEDIUM
            elif proc_name in ("curl", "wget"):
                behavior_alerts = self._behavior_alerts_for_new_connection(conn_details, proc_name)
                if not self._net_cooldown_ok(proc_name):
                    alerts.extend(behavior_alerts)
                    continue
                alerts.append(MonitorAlert(
                    rule_id  = "NET-013",
                    severity = "medium",
                    message  = f"İndirme aracı dış bağlantı: {proc_name} → {conn['remote']}",
                    details  = {**conn_details, "risk": "medium"},
                    category = "network"
                ))
                alerts.extend(behavior_alerts)

            # Bilinmeyen process → MEDIUM, cooldown ile
            else:
                behavior_alerts = self._behavior_alerts_for_new_connection(conn_details, proc_name)
                if not self._net_cooldown_ok(proc_name or remote_ip):
                    alerts.extend(behavior_alerts)
                    continue
                alerts.append(MonitorAlert(
                    rule_id  = "NET-011",
                    severity = "medium",
                    message  = f"Yeni dış bağlantı: {conn['remote']} ({proc_name or 'unknown'})",
                    details  = {**conn_details, "risk": risk or "unknown"},
                    category = "network"
                ))
                alerts.extend(behavior_alerts)

        alerts.extend(self._long_lived_alerts(current_keys))
        stale = set(self._conn_state) - current_keys
        for key in stale:
            self._conn_state.pop(key, None)
            self._known_connections.discard(key)

        return alerts


# ── 4. Systemd Service Monitoring ─────────────────────────────────────

class SystemdServiceMonitor:
    """
    /etc/systemd/system içindeki yeni .service/.timer/.socket dosyalarını izler.
    Persistence mekanizması olarak sık kullanılır (T1543.002).
    """

    WATCH_DIRS = [
        "/etc/systemd/system",
        "/usr/local/lib/systemd/system",
    ]

    def __init__(self, state_dir: str = "data", creation_only: bool = True):
        self.state_dir   = Path(state_dir)
        self._known: Dict[str, float] = {}
        self._state_file = self.state_dir / "systemd_state.json"
        self._initialized = False
        self.creation_only = creation_only
        self._load()

    def _load(self):
        if self._state_file.exists():
            try:
                with open(self._state_file) as f:
                    self._known = json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                logger.debug(f"[AegisCore:Systemd] State yüklenemedi: {e}")
                self._known = {}

    def _save(self):
        try:
            with open(self._state_file, "w") as f:
                json.dump(self._known, f)
        except OSError as e:
            logger.debug(f"[AegisCore:Systemd] State kaydedilemedi: {e}")

    def _scan(self) -> Dict[str, float]:
        found = {}
        for d in self.WATCH_DIRS:
            p = Path(d)
            if not p.exists():
                continue
            try:
                for pat in ("*.service", "*.timer", "*.socket", "*.path"):
                    for f in p.rglob(pat):
                        try:
                            found[str(f)] = f.stat().st_mtime
                        except OSError as _e:
                            logger.debug(f"[AegisCore:Systemd] stat hatası: {f}: {_e}")
            except OSError as e:
                logger.debug(f"[AegisCore:Systemd] Dizin taranamadı: {d}: {e}")
        return found

    def _unit_context(self, path: str) -> Dict:
        unit_path = Path(path)
        details = _path_context(unit_path, include_preview=True)
        details["unit"] = unit_path.name
        details["unit_type"] = unit_path.suffix.lstrip(".")
        details["unit_scope"] = "system" if "/etc/systemd/system" in path else "local"
        preview = details.get("content_preview", "")
        if preview:
            details["unit_preview"] = preview
        return details

    def check(self) -> List[MonitorAlert]:
        alerts = []
        current = self._scan()

        if not self._initialized:
            self._known = current
            self._initialized = True
            self._save()
            return []

        for path, mtime in current.items():
            fname = Path(path).name
            if path not in self._known:
                sev = "critical" if "/etc/systemd/system" in path else "high"
                alerts.append(MonitorAlert(
                    rule_id="FIM-SYSTEMD-001",
                    severity=sev,
                    message=f"Yeni systemd unit: {path}",
                    details={
                        **self._unit_context(path),
                        "mitre_tactic": "persistence",
                        "mitre_technique": "T1543.002",
                        "tags": ["persistence", "systemd", "new_unit"],
                    },
                    category="persistence",
                ))
            elif not self.creation_only and abs(mtime - self._known[path]) > 0.01:
                alerts.append(MonitorAlert(
                    rule_id="FIM-SYSTEMD-002",
                    severity="medium",
                    message=f"Systemd unit değişti: {path}",
                    details={
                        **self._unit_context(path),
                        "mitre_tactic": "persistence",
                        "mitre_technique": "T1543.002",
                        "tags": ["persistence", "systemd", "modified_unit"],
                    },
                    category="persistence",
                ))

        if not self.creation_only:
            for path in self._known:
                if path not in current:
                    alerts.append(MonitorAlert(
                        rule_id="FIM-SYSTEMD-003",
                        severity="medium",
                        message=f"Systemd unit silindi: {path}",
                        details={
                            **self._unit_context(path),
                            "mitre_tactic": "defense_evasion",
                            "mitre_technique": "T1543.002",
                            "tags": ["systemd", "deleted_unit"],
                        },
                        category="defense_evasion",
                    ))

        self._known = current
        self._save()
        return alerts


# ── Ana Monitor Engine ────────────────────────────────────────────────────────

class ActiveMonitor:
    """
    Tüm aktif monitörleri yönetir.
    Her 30 saniyede kontrol eder, alert callback'e iletir.
    """

    def __init__(self, config: Dict = None, state_dir: str = "data",
                 alert_callback: Callable = None):
        cfg     = config or {}
        mon_cfg = cfg.get("monitor", {})

        self.interval       = mon_cfg.get("interval_seconds", 30)
        self.alert_callback = alert_callback

        self.fim     = FileIntegrityMonitor(
            files=mon_cfg.get("watched_files", None),
            state_dir=state_dir
        )
        self.process = ProcessMonitor()
        self.network = NetworkMonitor()
        self.systemd  = SystemdServiceMonitor(
            state_dir=state_dir,
            creation_only=bool(mon_cfg.get("systemd_creation_only", True)),
        )

        self._running     = False
        self._thread      = None
        self._check_count = 0

        logger.info(f"[AegisCore:Monitor] ActiveMonitor hazır (interval={self.interval}s)")

    def start(self):
        import threading
        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, daemon=True, name="active-monitor"
        )
        self._thread.start()
        logger.info("[AegisCore:Monitor] Aktif izleme başlatıldı.")

    def stop(self):
        self._running = False

    def _loop(self):
        self._run_checks()
        while self._running:
            time.sleep(self.interval)
            self._run_checks()

    def _run_checks(self):
        self._check_count += 1
        all_alerts = []

        try:
            all_alerts += self.fim.check()
        except Exception as e:
            logger.error(f"[AegisCore:Monitor] FIM hatası: {e}")

        try:
            all_alerts += self.process.check()
        except Exception as e:
            logger.error(f"[AegisCore:Monitor] Process hatası: {e}")

        try:
            all_alerts += self.network.check()
        except Exception as e:
            logger.error(f"[AegisCore:Monitor] Network hatası: {e}")

        try:
            all_alerts += self.systemd.check()
        except Exception as e:
            logger.error(f"[AegisCore:Monitor] Systemd hatası: {e}")

        for alert in all_alerts:
            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception as e:
                    logger.error(f"[AegisCore:Monitor] Callback hatası: {e}")

        if all_alerts:
            logger.debug(f"[AegisCore:Monitor] {len(all_alerts)} alert üretildi.")

    def status(self) -> Dict:
        return {
            "running":      self._running,
            "check_count":  self._check_count,
            "interval":     self.interval,
            "fim_files":    len(self.fim._hashes),
            "known_procs":  len(self.process._known_pids),
            "proc_noise_suppressed": self.process.suppression_stats(),
        }
