"""
core/distro.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Linux Distribution Detection, Log Path Resolution,
and Distro-Aware Source Management

Supported distributions:
  Debian / Ubuntu          → /var/log/auth.log, /var/log/syslog
  RHEL / CentOS / Rocky
    AlmaLinux / Fedora     → /var/log/secure, /var/log/messages
  SUSE Linux Enterprise
    openSUSE               → /var/log/messages, journald
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SUPPORTED_FAMILIES = ("debian", "rhel", "suse")

# Distribution family → human-readable name
FAMILY_NAMES = {
    "debian": "Debian/Ubuntu",
    "rhel":   "RHEL/CentOS/Rocky/AlmaLinux",
    "suse":   "SUSE Linux Enterprise/openSUSE",
}


def detect_distro() -> Dict[str, str]:
    result = {
        "id":      "unknown",
        "id_like": "",
        "family":  "unknown",
        "pretty":  "Unknown Linux",
        "version": "",
    }

    os_release = Path("/etc/os-release")
    if not os_release.exists():
        os_release = Path("/usr/lib/os-release")

    if os_release.exists():
        try:
            data = {}
            for line in os_release.read_text().splitlines():
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    data[k.strip()] = v.strip().strip('"')
            result["id"]      = data.get("ID", "unknown").lower()
            result["id_like"] = data.get("ID_LIKE", "").lower()
            result["pretty"]  = data.get("PRETTY_NAME", "Unknown Linux")
            result["version"] = data.get("VERSION_ID", "")
        except Exception as e:
            logger.debug(f"[distro] failed to read os-release: {e}")

    _id      = result["id"]
    _id_like = result["id_like"]

    if _id in ("ubuntu", "debian", "raspbian", "linuxmint", "pop",
               "kali", "parrot", "mx"):
        result["family"] = "debian"
    elif "debian" in _id_like:
        result["family"] = "debian"
    elif _id in ("rhel", "centos", "centos-stream", "almalinux",
                 "rocky", "ol", "scientific", "fedora"):
        result["family"] = "rhel"
    elif "rhel" in _id_like or "fedora" in _id_like or "centos" in _id_like:
        result["family"] = "rhel"
    elif _id in ("opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles"):
        result["family"] = "suse"
    elif "suse" in _id_like:
        result["family"] = "suse"
    else:
        if Path("/etc/debian_version").exists():
            result["family"] = "debian"
        elif Path("/etc/redhat-release").exists():
            result["family"] = "rhel"
        elif Path("/etc/SuSE-release").exists() or Path("/etc/SUSE-brand").exists():
            result["family"] = "suse"

    logger.debug(f"[distro] detected: {result['pretty']} (family={result['family']})")
    return result


def is_supported(distro_info: Optional[Dict] = None) -> Tuple[bool, str]:
    """
    Return whether the distribution is supported.
    EOL or very old versions are also rejected.
    Returns: (is_supported, message)
    """
    if distro_info is None:
        distro_info = detect_distro()
    family  = distro_info.get("family", "unknown")
    version = distro_info.get("version", "")
    _id     = distro_info.get("id", "unknown")

    if family not in SUPPORTED_FAMILIES:
        return False, (
            f"Desteklenmeyen dağıtım: {distro_info.get('pretty', 'Unknown')} "
            f"— Desteklenen aileler: Debian/Ubuntu, RHEL 8+, SUSE 15+"
        )

    # EOL version check: allow through if parsing fails and report via message path
    try:
        _ver = float(version) if version else 0.0
    except (ValueError, TypeError):
        _ver = 0.0

    _EOL_MSG = ""
    if family == "rhel" and _ver > 0 and _ver < 8:
        _EOL_MSG = (
            f"RHEL/CentOS {version} desteklenmiyor (EOL) — RHEL 8+ gerekli"
        )
    elif _id == "ubuntu" and _ver > 0 and _ver < 20.04:
        _EOL_MSG = (
            f"Ubuntu {version} desteklenmiyor (EOL) — Ubuntu 20.04+ gerekli"
        )
    elif family == "suse" and _ver > 0 and _ver < 15:
        _EOL_MSG = (
            f"SUSE {version} desteklenmiyor (EOL) — SUSE 15+ gerekli"
        )
    elif _id == "debian" and _ver > 0 and _ver < 10:
        _EOL_MSG = (
            f"Debian {version} desteklenmiyor (EOL) — Debian 10+ gerekli"
        )

    if _EOL_MSG:
        return False, _EOL_MSG

    return True, FAMILY_NAMES.get(family, family)


def check_supported_or_exit(distro_info: Optional[Dict] = None) -> None:
    """
    Exit with sys.exit(1) on unsupported or EOL distributions.
    Should be called at the start of main(), before SIEMPipeline is created.
    """
    import sys
    if distro_info is None:
        distro_info = detect_distro()
    supported, reason = is_supported(distro_info)
    if not supported:
        print(
            f"\n[AegisCore] HATA: Bu sistem desteklenmiyor.\n"
            f"  Sebep  : {reason}\n"
            f"  Sistem : {distro_info.get('pretty', 'Unknown')}\n"
            f"  Desteklenenler:\n"
            f"    • Debian / Ubuntu 20.04+\n"
            f"    • RHEL / CentOS / Rocky / AlmaLinux 8+\n"
            f"    • SUSE / openSUSE 15+\n"
        )
        sys.exit(1)


def _safe_exists(path: str) -> bool:
    try:
        return Path(path).exists()
    except (OSError, PermissionError):
        return False


def _safe_is_dir(path: str) -> bool:
    try:
        return Path(path).is_dir()
    except (OSError, PermissionError):
        return False


def _first_existing(*paths: str) -> str:
    for p in paths:
        if _safe_exists(p):
            return p
    return paths[0]


def _default_apache_path(*paths: str) -> str:
    """
    Return the directory for Apache/httpd when available, otherwise a known log file.
    A directory is preferred because the source can discover multiple log files there.
    """
    existing_files: List[str] = []
    for path in paths:
        if _safe_is_dir(path):
            return path
        if _safe_exists(path):
            existing_files.append(path)
    if existing_files:
        return existing_files[0]
    return paths[0] if paths else ""


def resolve_log_paths(distro_info: Optional[Dict] = None,
                      overrides: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Resolve log paths for the detected distro.

    overrides: log path overrides coming from integrations.env.
      Example: {"auth_log": "/custom/auth.log", "audit_log": "/data/audit.log"}
      Non-empty overrides take precedence over auto-detected paths.
    """
    if distro_info is None:
        distro_info = detect_distro()
    family = distro_info.get("family", "unknown")

    if family == "debian":
        _paths = {
            "auth_log":   _first_existing("/var/log/auth.log", "/var/log/secure", "/var/log/messages"),
            "syslog":     _first_existing("/var/log/syslog"),
            "kern_log":   _first_existing("/var/log/kern.log", "/var/log/messages"),
            "audit_log":  _first_existing("/var/log/audit/audit.log"),
            "dpkg_log":   _first_existing("/var/log/dpkg.log"),
            "ufw_log":    _first_existing("/var/log/ufw.log"),
            "apache_log": _default_apache_path(
                "/var/log/apache2",
                "/var/log/httpd",
                "/var/log/apache2/access.log",
                "/var/log/apache2/error.log",
                "/var/log/apache2/access_log",
                "/var/log/apache2/error_log",
                "/var/log/httpd/access_log",
                "/var/log/httpd/error_log",
            ),
            "nginx_log":  _first_existing("/var/log/nginx"),
            "mysql_log":  _first_existing("/var/log/mysql/error.log", "/var/log/mysql.err"),
            "pg_log":     _first_existing("/var/log/postgresql"),
            "mail_log":   _first_existing("/var/log/mail.log"),
            "openvpn_log": _first_existing("/var/log/openvpn.log", "/var/log/openvpn/openvpn.log"),
            "wtmp_log":   _first_existing("/var/log/wtmp"),
            "btmp_log":   _first_existing("/var/log/btmp"),
            "journald":   True,
        }
        return _apply_log_overrides(_paths, overrides)
    elif family == "rhel":
        _paths = {
            "auth_log":   _first_existing("/var/log/secure", "/var/log/auth.log", "/var/log/messages"),
            "syslog":     _first_existing("/var/log/messages", "/var/log/auth.log", "/var/log/secure"),
            "kern_log":   _first_existing("/var/log/messages", "/var/log/secure"),
            "audit_log":  _first_existing("/var/log/audit/audit.log"),
            "dpkg_log":   _first_existing("/var/log/dnf.log", "/var/log/dnf.rpm.log",
                                          "/var/log/yum.log"),
            "ufw_log":    _first_existing("/var/log/firewalld", "/var/log/ufw.log"),
            "apache_log": _default_apache_path(
                "/var/log/httpd",
                "/var/log/apache2",
                "/var/log/httpd/access_log",
                "/var/log/httpd/error_log",
                "/var/log/apache2/access.log",
                "/var/log/apache2/error.log",
                "/var/log/apache2/access_log",
                "/var/log/apache2/error_log",
            ),
            "nginx_log":  _first_existing("/var/log/nginx"),
            "mysql_log":  _first_existing("/var/log/mysqld.log", "/var/log/mysql/error.log"),
            "pg_log":     _first_existing("/var/lib/pgsql/data/log", "/var/log/postgresql"),
            "mail_log":   _first_existing("/var/log/maillog"),
            "openvpn_log": _first_existing("/var/log/openvpn.log", "/var/log/openvpn/openvpn.log"),
            "wtmp_log":   _first_existing("/var/log/wtmp"),
            "btmp_log":   _first_existing("/var/log/btmp"),
            "journald":   True,
        }
        return _apply_log_overrides(_paths, overrides)
    elif family == "suse":
        _paths = {
            "auth_log":   _first_existing("/var/log/messages", "/var/log/auth.log", "/var/log/secure"),
            "syslog":     _first_existing("/var/log/messages", "/var/log/auth.log", "/var/log/secure"),
            "kern_log":   _first_existing("/var/log/messages", "/var/log/secure"),
            "audit_log":  _first_existing("/var/log/audit/audit.log"),
            "dpkg_log":   _first_existing("/var/log/zypp/history"),
            "ufw_log":    _first_existing("/var/log/firewall"),
            "apache_log": _default_apache_path(
                "/var/log/apache2",
                "/var/log/httpd",
                "/var/log/apache2/access.log",
                "/var/log/apache2/error.log",
                "/var/log/apache2/access_log",
                "/var/log/apache2/error_log",
                "/var/log/httpd/access_log",
                "/var/log/httpd/error_log",
            ),
            "nginx_log":  _first_existing("/var/log/nginx"),
            "mysql_log":  _first_existing("/var/log/mysql/error.log"),
            "pg_log":     _first_existing("/var/lib/pgsql/data/log", "/var/log/postgresql"),
            "mail_log":   _first_existing("/var/log/maillog"),
            "openvpn_log": _first_existing("/var/log/openvpn.log", "/var/log/openvpn/openvpn.log"),
            "wtmp_log":   _first_existing("/var/log/wtmp"),
            "btmp_log":   _first_existing("/var/log/btmp"),
            "journald":   True,
        }
        return _apply_log_overrides(_paths, overrides)
    else:
        _paths = {
            "auth_log":   _first_existing("/var/log/auth.log", "/var/log/secure",
                                          "/var/log/messages"),
            "syslog":     _first_existing("/var/log/syslog", "/var/log/messages"),
            "kern_log":   _first_existing("/var/log/kern.log", "/var/log/messages"),
            "audit_log":  _first_existing("/var/log/audit/audit.log"),
            "dpkg_log":   _first_existing("/var/log/dpkg.log"),
            "ufw_log":    _first_existing("/var/log/ufw.log"),
            "apache_log": _default_apache_path(
                "/var/log/apache2",
                "/var/log/httpd",
                "/var/log/apache2/access.log",
                "/var/log/apache2/error.log",
                "/var/log/apache2/access_log",
                "/var/log/apache2/error_log",
                "/var/log/httpd/access_log",
                "/var/log/httpd/error_log",
            ),
            "nginx_log":  _first_existing("/var/log/nginx"),
            "mysql_log":  _first_existing("/var/log/mysql/error.log", "/var/log/mysqld.log"),
            "pg_log":     _first_existing("/var/log/postgresql"),
            "mail_log":   _first_existing("/var/log/mail.log", "/var/log/maillog"),
            "openvpn_log": _first_existing("/var/log/openvpn.log", "/var/log/openvpn/openvpn.log"),
            "wtmp_log":   _first_existing("/var/log/wtmp"),
            "btmp_log":   _first_existing("/var/log/btmp"),
            "journald":   True,
        }
        return _apply_log_overrides(_paths, overrides)

    # ── Apply integrations.env overrides ───────────────────────────────────
    # This point runs after all distro branches.
    # If execution cannot reach this line because all branches return, _apply_overrides
    # must also be called elsewhere. However, unreachable code in Python
    # makes it safer to apply overrides directly inside each branch.
    # That is why the function signature was changed and call sites were updated.


def _apply_log_overrides(paths: Dict, overrides: Optional[Dict[str, str]]) -> Dict:
    """Apply the override dict to resolved paths, ignoring empty values."""
    if not overrides:
        return paths
    result = dict(paths)
    for key, val in overrides.items():
        if val and val.strip():
            result[key] = val.strip()
            logger.debug(f"[Distro] Log override: {key} = {val.strip()}")
    return result


SOURCE_MAP = {
    "auth_log":   "auth_log",
    "syslog":     "syslog",
    "ufw":        "ufw_log",
    "auditd":     "audit_log",
    "dpkg":       "dpkg_log",
    "apache2":    "apache_log",
    "nginx":      "nginx_log",
    "mysql":      "mysql_log",
    "postgresql": "pg_log",
    "mail":       "mail_log",
    "openvpn":    "openvpn_log",
    "dns":        "syslog",
    "wtmp":       "wtmp_log",
    "btmp":       "btmp_log",
}


def apply_distro_paths(config: Dict, overrides: Optional[Dict[str, str]] = None) -> Dict:
    """
    Log yollarını dağıtıma göre çöz ve geçersiz file-based source'ları kapat.
    overrides: integrations.env'den gelen log yolu override'ları.
    """
    distro = detect_distro()
    family = distro.get("family", "unknown")
    paths  = resolve_log_paths(distro, overrides=overrides)
    sources = config.get("sources", {})

    for src_key, distro_key in SOURCE_MAP.items():
        if src_key not in sources:
            continue
        src_cfg = sources[src_key]
        if not src_cfg.get("enabled", False):
            continue
        resolved = paths.get(distro_key, "")
        if not resolved or resolved is True:
            continue
        current_path = src_cfg.get("path", "")
        # Do not touch the current path if it truly exists on this system
        if current_path and Path(current_path).exists():
            continue
        # Update when the current path is missing but a distro-appropriate path exists
        if _safe_exists(resolved):
            src_cfg["path"] = resolved
            logger.info(f"[distro] {src_key} path → {resolved} ({distro['pretty']})")
        else:
            # Disable the source when neither the current nor distro path exists
            src_cfg["enabled"] = False
            missing_path = current_path or resolved or "(auto-resolve failed)"
            logger.info(f"[distro] {src_key} devre dışı — yol bulunamadı: {missing_path}")

    # ── RHEL: rename dpkg → dnf ───────────────────────────────────────────
    # Keep the config key as 'dpkg', but the normalizer expects the source name 'dnf'
    if family == "rhel" and "dpkg" in sources:
        dpkg_cfg = sources["dpkg"]
        if dpkg_cfg.get("enabled", False):
            dpkg_cfg["type"] = "dnf"   # normalizer bu type'a göre DnfParser kullanır
            logger.info("[distro] RHEL: dpkg source tipi 'dnf' olarak ayarlandı")

    # ── SUSE: rename dpkg → zypper ────────────────────────────────────────
    if family == "suse" and "dpkg" in sources:
        dpkg_cfg = sources["dpkg"]
        if dpkg_cfg.get("enabled", False):
            dpkg_cfg["type"] = "zypper"  # normalizer bu type'a göre ZypperParser kullanır
            logger.info("[distro] SUSE: dpkg source tipi 'zypper' olarak ayarlandı")

    if not paths.get("journald", True):
        if "journald" in sources:
            sources["journald"]["enabled"] = False

    # ── Debian/RHEL: dns and syslog share the same generic syslog file → avoid duplicate reads ──
    # If Debian/Ubuntu has no separate DNS log, the dns source would tail generic syslog again.
    # DNS lines are still visible through syslog-normalizer fallbacks; unrelated syslog
    # lines producing dns normalize_none should not inflate quality metrics.
    if family == "debian":
        syslog_cfg = sources.get("syslog", {})
        dns_cfg = sources.get("dns", {})
        syslog_path = syslog_cfg.get("path", "") if isinstance(syslog_cfg, dict) else ""
        dns_path = dns_cfg.get("path", "") if isinstance(dns_cfg, dict) else ""
        if (
            isinstance(dns_cfg, dict)
            and isinstance(syslog_cfg, dict)
            and dns_cfg.get("enabled", False)
            and syslog_cfg.get("enabled", False)
            and dns_path
            and dns_path == syslog_path
        ):
            dns_cfg["enabled"] = False
            logger.info("[distro] Debian: dns devre dışı — syslog ile aynı dosya (/var/log/syslog)")

    # ── RHEL: dns and syslog share /var/log/messages → avoid duplicate reads ──
    # If RHEL has no separate DNS log, the dns source tails generic syslog.
    # Real DNS lines are still caught by the DNS fallback in the syslog normalizer;
    # unrelated syslog lines becoming dns normalize_none should not harm quality metrics.
    if family == "rhel":
        syslog_cfg = sources.get("syslog", {})
        dns_cfg    = sources.get("dns", {})
        syslog_path = syslog_cfg.get("path", "") if isinstance(syslog_cfg, dict) else ""
        dns_path    = dns_cfg.get("path", "") if isinstance(dns_cfg, dict) else ""
        if (
            isinstance(dns_cfg, dict)
            and isinstance(syslog_cfg, dict)
            and dns_cfg.get("enabled", False)
            and syslog_cfg.get("enabled", False)
            and dns_path
            and dns_path == syslog_path
        ):
            dns_cfg["enabled"] = False
            logger.info("[distro] RHEL: dns devre dışı — syslog ile aynı dosya (/var/log/messages)")

    # ── SUSE: auth_log and syslog share /var/log/messages → avoid duplicate reads ──
    # On SUSE, auth_log, syslog, and dns all go to /var/log/messages.
    # Disable auth_log because syslog will read the same content.
    # Prevent dns from hitting the same issue.
    if family == "suse":
        auth_path   = sources.get("auth_log", {}).get("path", "")
        syslog_path = sources.get("syslog",   {}).get("path", "")
        dns_path    = sources.get("dns",       {}).get("path", "")
        if auth_path and auth_path == syslog_path:
            if "auth_log" in sources:
                sources["auth_log"]["enabled"] = False
                logger.info("[distro] SUSE: auth_log devre dışı — syslog ile aynı dosya (/var/log/messages)")
        if dns_path and dns_path == syslog_path:
            if "dns" in sources:
                sources["dns"]["enabled"] = False
                logger.info("[distro] SUSE: dns devre dışı — syslog ile aynı dosya (/var/log/messages)")

    # ── phase_profile otomatik tespiti ───────────────────────────────────────
    # Always auto-detect when set to 'auto' or left unset
    # The default value 'server' also allows auto-detection
    current_profile = config.get("phase_profile", "auto")
    if current_profile in ("auto", "server", ""):
        detected_profile = _detect_phase_profile()
        config["phase_profile"] = detected_profile
        logger.info(f"[distro] phase_profile otomatik → '{detected_profile}'")

    logger.info(f"[distro] Log yolları çözümlendi: {distro['pretty']} (family={distro['family']})")
    return config


def _detect_phase_profile() -> str:
    """
    Sistem tipine göre phase_profile belirle.

    server  → systemd servis olarak çalışıyor, headless, yüksek trafik beklenir
    desktop → grafik masaüstü ortamı var
    lab     → sanal makine veya konteyner, test ortamı
    """
    # Container/virtual-machine detection (lab)
    if Path("/.dockerenv").exists():
        return "lab"
    try:
        with open("/proc/1/cgroup") as f:
            if "docker" in f.read() or "lxc" in f.read() or "kubepods" in f.read():
                return "lab"
    except OSError:
        pass

    # Check for VMs with systemd-detect-virt
    import shutil, subprocess
    if shutil.which("systemd-detect-virt"):
        try:
            result = subprocess.run(
                ["systemd-detect-virt"],
                capture_output=True, timeout=3
            )
            if result.returncode == 0:  # VM veya konteyner
                stdout = result.stdout or b""
                virt = stdout.decode().strip() if isinstance(stdout, bytes) else str(stdout).strip()
                if virt not in ("none", ""):
                    return "lab"
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError):
            pass

    # Graphical desktop detection
    desktop_indicators = [
        "/usr/bin/gnome-shell",
        "/usr/bin/plasmashell",
        "/usr/bin/xfce4-session",
        "/usr/bin/mate-session",
        "/usr/bin/lxsession",
        "/usr/bin/startxfce4",
    ]
    if any(Path(p).exists() for p in desktop_indicators):
        return "desktop"

    # DISPLAY or WAYLAND_DISPLAY env var (active desktop session)
    import os
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        return "desktop"

    # Default: server
    return "server"


def audit_sources(config: Dict) -> Dict[str, Dict]:
    """
    Distro-Aware Source Manager.
    Her kaynağın gerçekten var olup olmadığını kontrol eder.
    Olmayan kaynakları otomatik kapatır, rapor döndürür.

    Dönüş: {source_name: {status, path, reason}}
    """
    distro  = detect_distro()
    paths   = resolve_log_paths(distro)
    sources = config.get("sources", {})
    report  = {}

    for src_key, src_cfg in sources.items():
        if not src_cfg.get("enabled", False):
            report[src_key] = {"status": "disabled", "path": "", "reason": "config'de kapalı"}
            continue

        # journald — command, not a file
        if src_cfg.get("type") == "journald":
            import shutil
            if shutil.which("journalctl"):
                report[src_key] = {"status": "ok", "path": "journalctl", "reason": ""}
            else:
                src_cfg["enabled"] = False
                report[src_key] = {"status": "closed", "path": "", "reason": "journalctl bulunamadı"}
            continue

        path = src_cfg.get("path", "")
        if path and Path(path).exists():
            report[src_key] = {"status": "ok", "path": path, "reason": ""}
            continue

        # Resolve the correct path for the distro
        distro_key = SOURCE_MAP.get(src_key)
        if distro_key:
            resolved = paths.get(distro_key, "")
            if resolved and resolved is not True and Path(resolved).exists():
                src_cfg["path"] = resolved
                path = resolved

        if not path:
            src_cfg["enabled"] = False
            report[src_key] = {"status": "closed", "path": "", "reason": "path tanımlı değil"}
            continue

        if Path(path).exists():
            report[src_key] = {"status": "ok", "path": path, "reason": ""}
        else:
            src_cfg["enabled"] = False
            report[src_key] = {
                "status": "closed",
                "path":   path,
                "reason": f"dosya yok: {path}"
            }
            logger.info(f"[distro] '{src_key}' kapatıldı — {path} mevcut değil")

    return report


# ── apply_distro_config helper ────────────────────────────────────────

def _apply_distro_config(config: Dict, distro_info: Dict) -> None:
    """
    config["sources"] içindeki path ve enabled değerlerini
    distro bilgisine göre günceller.

    RHEL'de auth.log yoktur → auth source'u disabled yapılır, secure aktif.
    SUSE'de /var/log/messages kullanılır.
    Bilinmeyen distro'da config dokunulmadan kalır.
    """
    family  = distro_info.get("family", "unknown") if distro_info else "unknown"
    paths   = resolve_log_paths(distro_info)
    sources = config.get("sources", {})

    # Source name → log-path key mapping
    SOURCE_PATH_MAP = {
        "auth":    "auth_log",
        "syslog":  "syslog",
        "dpkg":    "dpkg_log",
        "auditd":  "auditd_log",
        "secure":  "auth_log",   # RHEL alias
    }

    for src_name, src_cfg in sources.items():
        if not isinstance(src_cfg, dict):
            continue
        path_key = SOURCE_PATH_MAP.get(src_name)
        if path_key and path_key in paths:
            resolved = paths[path_key]
            if resolved:
                src_cfg["path"] = resolved
            else:
                # Unresolved source → disable it
                src_cfg["enabled"] = False
                logger.debug(
                    f"[distro_config] {src_name} kaynağı bu distro'da yok "
                    f"({family}) — devre dışı bırakıldı"
                )

    # Disable dpkg sources on RHEL/SUSE
    if family in ("rhel", "suse"):
        for dpkg_src in ("dpkg",):
            if dpkg_src in sources and isinstance(sources[dpkg_src], dict):
                sources[dpkg_src]["enabled"] = False
                logger.debug(f"[distro_config] {dpkg_src} {family} üzerinde desteklenmiyor — kapatıldı")


# ── DistroAwareSourceManager ──────────────────────────────────────────────────

class DistroAwareSourceManager:
    """
    Distro bilgisine göre log source path'lerini yönetir.

    unknown distro'da graceful fallback — çökmez, boş config döner.

    Kullanım:
        sm = DistroAwareSourceManager({"family": "debian"})
        config = sm.apply_distro_paths({"sources": {...}})
    """

    _warned_unknown_families = set()

    def __init__(self, distro_info=None):
        # dict veya str kabul et
        if isinstance(distro_info, dict):
            self.distro_info = distro_info
            self.family      = distro_info.get("family", "unknown")
        elif isinstance(distro_info, str):
            self.family      = distro_info
            self.distro_info = {"family": distro_info}
        else:
            self.family      = "unknown"
            self.distro_info = {"family": "unknown"}

        # unknown distro → fallback paths dene
        if self.family not in SUPPORTED_FAMILIES and self.family not in self._warned_unknown_families:
            self._warned_unknown_families.add(self.family)
            logger.warning(
                f"[DistroSourceManager] Bilinmeyen distro family: '{self.family}' "
                f"— fallback path'ler kullanılacak"
            )

        try:
            self._paths = resolve_log_paths(self.distro_info)
        except Exception as e:
            logger.warning(f"[DistroSourceManager] resolve_log_paths hatası: {e} — boş paths")
            self._paths = {}

    def apply_distro_paths(self, config: dict) -> dict:
        """
        config["sources"] içindeki path'leri distro'ya göre güncelle.
        Path yoksa source'u devre dışı bırak (enabled: false).
        unknown distro'da hata atmaz, mevcut config'i olduğu gibi döner.
        """
        if not isinstance(config, dict):
            return config

        sources = config.get("sources", {})
        if not sources:
            return config

        try:
            _apply_distro_config(config, self.distro_info)
        except Exception as e:
            logger.warning(
                f"[DistroSourceManager] apply_distro_config hatası: {e} — "
                f"config değiştirilmedi"
            )

        return config

    def get_path(self, source_key: str) -> str:
        """Return the resolved path for a specific source."""
        distro_key = SOURCE_MAP.get(source_key, source_key)
        return self._paths.get(distro_key, "")

    def supported(self) -> bool:
        """Bu distro tam destekleniyor mu?"""
        return self.family in SUPPORTED_FAMILIES
