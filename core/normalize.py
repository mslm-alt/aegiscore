from __future__ import annotations
"""
core/normalize.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 1: Log normalization layer

Converts all log sources (syslog, auditd, journald) into the shared
NormalizedEvent format.

NormalizedEvent schema:
  ts          float    Unix timestamp
  host        str      source host
  source      str      auth.log / syslog / auditd / journald
  category    str      auth / network / process / system / unknown
  action      str      login / logout / su / sudo / ssh / exec / ...
  outcome     str      success / failure / unknown
  user        str      related user
  src_ip      str      source IP (if present)
  dst_ip      str      destination IP (if present)
  process     str      process name
  pid         int      process ID
  message     str      raw message
  raw         str      original log line
  fields      dict     source-specific extra fields
"""

import re
import time
import logging
import hashlib
import subprocess
from datetime import datetime
from typing import Optional, Dict, Any, List, Iterator
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


# -- NormalizedEvent ---------------------------------------------------------

@dataclass
class NormalizedEvent:
    ts:            float = 0.0
    host:          str   = ""
    source:        str   = ""
    category:      str   = "unknown"   # auth/network/process/system/unknown
    action:        str   = "unknown"   # login/logout/sudo/ssh/exec/...
    outcome:       str   = "unknown"   # success/failure/unknown
    user:          str   = ""
    src_ip:        str   = ""
    dst_ip:        str   = ""
    process:       str   = ""
    pid:           int   = 0
    message:       str   = ""
    raw:           str   = ""
    fields:        Dict  = field(default_factory=dict)
    distro_family: str   = "unknown"   # debian/rhel/suse — ML feature[24]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def event_hash(self) -> str:
        """
        Dedup için hash.
        Includes the timestamp; the same content at a different time is not considered a duplicate.
        A real duplicate means the same source, same action, same event context, and same second.
        """
        ts_bucket = int(self.ts) if self.ts else 0  # group at second granularity
        if _hash_token(self.source) == "auditd":
            key = _auditd_event_hash_key(self, ts_bucket)
        else:
            key = f"{self.source}|{self.action}|{self.user}|{self.src_ip}|{self.message[:80]}|{ts_bucket}"
        return hashlib.md5(key.encode()).hexdigest()

    def cross_source_hash(self) -> str:
        """
        Cross-source dedup hash — source is intentionally excluded.
        If the same event arrives from auditd + auth_log + journald within the same 5-second window,
        only the first one is processed.
        """
        ts_bucket = int(self.ts / 5) if self.ts else 0  # 5-second window
        key = f"{self.action}|{self.user}|{self.src_ip}|{self.message[:60]}|{ts_bucket}"
        return hashlib.md5(key.encode()).hexdigest()


def _non_empty_str(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return text


def _hash_token(value: Any) -> str:
    return _non_empty_str(value).lower()


def _first_hash_token(*values: Any) -> str:
    for value in values:
        token = _hash_token(value)
        if token:
            return token
    return ""


def _auditd_event_hash_key(evt: NormalizedEvent, ts_bucket: int) -> str:
    fields = evt.fields if isinstance(evt.fields, dict) else {}
    audit_type = _first_hash_token(fields.get("audit_type"))
    process = _first_hash_token(evt.process, fields.get("comm"), fields.get("exe"))
    syscall = _first_hash_token(fields.get("syscall"), fields.get("syscall_name"))
    exit_code = _first_hash_token(fields.get("exit"), fields.get("res"), fields.get("result"))
    file_path = _first_hash_token(fields.get("file_path"), fields.get("path"), fields.get("name"))
    nametype = _first_hash_token(fields.get("nametype"))
    dst_ip = _first_hash_token(evt.dst_ip, fields.get("dst_ip"), fields.get("daddr"), fields.get("addr"))
    dst_port = _first_hash_token(fields.get("dst_port"), fields.get("dport"), fields.get("dest_port"))
    uid = _first_hash_token(fields.get("uid"))
    auid = _first_hash_token(fields.get("auid"), evt.user)
    euid = _first_hash_token(fields.get("euid"))
    exe = _first_hash_token(fields.get("exe"))
    comm = _first_hash_token(fields.get("comm"))
    structural_parts = [
        audit_type,
        _hash_token(evt.category),
        _hash_token(evt.action),
        _hash_token(evt.outcome),
        syscall,
        exit_code,
        process,
        comm,
        exe,
        file_path,
        nametype,
        _hash_token(evt.src_ip),
        dst_ip,
        dst_port,
        _hash_token(evt.user),
        uid,
        auid,
        euid,
    ]
    fallback_prefix = _hash_token(evt.message)[:80] if sum(1 for part in structural_parts if part) < 4 else ""
    parts = [
        "auditd",
        *structural_parts,
        fallback_prefix,
        str(ts_bucket),
    ]
    return "|".join(parts)


def _split_identity_principal(principal: str) -> tuple[str, str]:
    text = _non_empty_str(principal)
    if not text:
        return "", ""
    if "\\" in text:
        domain, account = re.split(r'\\+', text, maxsplit=1)
        return _non_empty_str(account), _non_empty_str(domain)
    return text, ""


def _set_identity_context(
    evt: NormalizedEvent,
    *,
    mechanism: str = "",
    service: str = "",
    phase: str = "",
    account: str = "",
    domain: str = "",
    session_state: str = "",
    policy: str = "",
    unit: str = "",
) -> None:
    identity = evt.fields.setdefault("identity", {})
    updates = {
        "mechanism": _non_empty_str(mechanism),
        "service": _non_empty_str(service),
        "phase": _non_empty_str(phase),
        "account": _non_empty_str(account),
        "domain": _non_empty_str(domain),
        "session_state": _non_empty_str(session_state),
        "policy": _non_empty_str(policy),
        "unit": _non_empty_str(unit),
    }
    for key, value in updates.items():
        if value:
            identity[key] = value
    if not identity:
        evt.fields.pop("identity", None)


def _enrich_identity_from_journald_metadata(evt: NormalizedEvent) -> None:
    identity = evt.fields.get("identity")
    metadata = evt.fields.get("metadata")
    if not isinstance(identity, dict) or not isinstance(metadata, dict):
        return
    journald = metadata.get("journald")
    if not isinstance(journald, dict):
        return
    if not identity.get("service"):
        service = _non_empty_str(journald.get("syslog_identifier")) or _non_empty_str(evt.process)
        if service:
            identity["service"] = service
    if not identity.get("unit"):
        unit = _non_empty_str(journald.get("systemd_unit"))
        if unit:
            identity["unit"] = unit


def _set_compact_bag(evt: NormalizedEvent, field_name: str, **values: Any) -> None:
    bag = evt.fields.setdefault(field_name, {})
    for key, value in values.items():
        text = _non_empty_str(value)
        if text:
            bag[key] = text
    if not bag:
        evt.fields.pop(field_name, None)


def _enrich_bag_from_journald_metadata(evt: NormalizedEvent, field_name: str) -> None:
    bag = evt.fields.get(field_name)
    metadata = evt.fields.get("metadata")
    if not isinstance(bag, dict) or not isinstance(metadata, dict):
        return
    journald = metadata.get("journald")
    if not isinstance(journald, dict):
        return
    if "unit" not in bag:
        unit = _non_empty_str(journald.get("systemd_unit"))
        if unit:
            bag["unit"] = unit
    if "service" not in bag:
        service = _non_empty_str(journald.get("syslog_identifier")) or _non_empty_str(evt.process)
        if service:
            bag["service"] = service


_SHELL_WRAPPER_RE = re.compile(
    r"^(?P<shell>(?:/bin/)?(?:bash|sh))\s+-c\s+(?P<payload>.+)$",
    re.IGNORECASE,
)
_CRON_WRITE_TARGET_RE = re.compile(
    r"(>>?\s*|tee\s+)(?P<target>/etc/crontab|/var/spool/cron(?:/\S+)?|/etc/cron\.(?:d|daily|hourly|weekly)(?:/\S+)?)",
    re.IGNORECASE,
)


def _sanitize_sudo_command(cmd: str) -> str:
    """
    bash/sh -c wrapper içindeki cron write payload'ını daralt.

    Cron hedef yolu korunur; payload içindeki alakasız alt-komut ve içerik
    keşif/defense-evasion kurallarına taşınmaz.
    """
    raw = (cmd or "").strip()
    m = _SHELL_WRAPPER_RE.match(raw)
    if not m:
        return raw

    payload = m.group("payload").strip()
    if len(payload) >= 2 and payload[0] == payload[-1] and payload[0] in ("'", '"'):
        payload = payload[1:-1]

    tm = _CRON_WRITE_TARGET_RE.search(payload)
    if not tm:
        return raw

    shell = m.group("shell")
    op = tm.group(1).strip()
    target = tm.group("target")
    return f"{shell} -c '<cron_redir> {op} {target}'"


# ── Syslog / auth.log Parser ──────────────────────────────────────────────────

class SyslogParser:
    """
    /var/log/auth.log ve /var/log/syslog parser.
    
    Desteklenen formatlar:
      Mar  5 12:34:56 hostname process[pid]: message
      2024-03-05T12:34:56.000000+03:00 hostname process[pid]: message
    """

    # Syslog header patterns
    _HEADER_TRADITIONAL = re.compile(
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
        r'(\S+)\s+'                                       # host
        r'(\S+?)(?:\[(\d+)\])?:\s*'                      # process[pid]
        r'(.*)$'                                          # message
    )
    _HEADER_ISO = re.compile(
        r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*[+-]\d{2}:\d{2})\s+'
        r'(\S+)\s+'
        r'(\S+?)(?:\[(\d+)\])?:\s*'
        r'(.*)$'
    )

    # Auth event pattern'leri
    _PATTERNS = {
        # Successful SSH login
        "ssh_login_success": (re.compile(
            r'Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+([\d\.a-fA-F:]+)\s+port\s+(\d+)'
        ), "auth", "ssh_login", "success"),

        # Failed SSH login
        "ssh_login_fail": (re.compile(
            r'Failed\s+(\w+)\s+for\s+(invalid user\s+)?(\S+)\s+from\s+([\d\.a-fA-F:]+)\s+port\s+(\d+)'
        ), "auth", "ssh_login", "failure"),

        # SSH invalid user (various formats)
        "ssh_invalid_user": (re.compile(
            r'(?:Connection closed by |Disconnected from )?[Ii]nvalid user\s+(\S+)\s+(?:from\s+)?([\d\.a-fA-F:]+)'
        ), "auth", "ssh_invalid_user", "failure"),

        # SSH PAM authentication failure
        "ssh_pam_fail": (re.compile(
            r'PAM\s+\d+\s+more\s+authentication\s+failure.*rhost=([\d\.a-fA-F:]+)'
        ), "auth", "ssh_login", "failure"),

        # pam_faillock hesap kilitleme
        "faillock_lock": (re.compile(
            r'pam_faillock\(\S+\):\s+Consecutive login failures for user\s+(\S+)\s+account temporarily locked'
        ), "auth", "account_locked", "failure"),
        "faillock_blocked": (re.compile(
            r'pam_faillock\(\S+\):\s+User\s+(\S+)\s+is blocked(?:.*?from\s+([\d\.a-fA-F:]+))?'
        ), "auth", "account_locked", "failure"),

        # OpenVPN session open / reject
        "openvpn_login_success": (re.compile(
            r'(?:(\S+)/([\d\.a-fA-F:]+):(\d+)\s+)?Peer Connection Initiated with \[(?:AF_INET6?|AF_INET)\]([\d\.a-fA-F:]+):(\d+)'
        ), "auth", "vpn_login", "success"),
        "openvpn_login_fail": (re.compile(
            r'(?:(\S+)/([\d\.a-fA-F:]+):(\d+)\s+)?(?:AUTH_FAILED|user/pass(?:word)? verification failed|TLS Auth Error)'
        ), "auth", "vpn_login", "failure"),
        "openvpn_session_open": (re.compile(
            r'(\S+)/([\d\.a-fA-F:]+):(\d+)\s+Peer Connection Initiated with \[(?:AF_INET6?|AF_INET)\][\d\.a-fA-F:]+:\d+'
        ), "auth", "session_open", "success"),
        "openvpn_session_close": (re.compile(
            r'(\S+)/([\d\.a-fA-F:]+):(\d+)\s+(?:SIGTERM\[soft,remote-exit\] received, client-instance exiting|Inactivity timeout \(--ping-restart\), restarting)'
        ), "auth", "session_close", "success"),
        "nftables_verdict": (re.compile(
            r'nftables:\s+(DROP|REJECT|BLOCK|BLOCKED|DENIED)\s+(?:TABLE=(\S+)\s+)?(?:CHAIN=(\S+)\s+)?IN=(\S*)\s+OUT=(\S*)\s+.*?SRC=([\d\.a-fA-F:]+)\s+DST=([\d\.a-fA-F:]+)(?:.*?\bPROTO=(\w+))?(?:.*?\bSPT=(\d+))?(?:.*?\bDPT=(\d+))?'
        ), "network", "firewall_block", "blocked"),
        "kernel_firewall_verdict": (re.compile(
            r'(?:\[\s*[\d\.]+\]\s+)?(DROP|REJECT|BLOCK|BLOCKED|DENIED)\s+IN=(\S*)\s+OUT=(\S*)\s+.*?SRC=([\d\.a-fA-F:]+)\s+DST=([\d\.a-fA-F:]+)(?:.*?\bPROTO=(\w+))?(?:.*?\bSPT=(\d+))?(?:.*?\bDPT=(\d+))?'
        ), "network", "firewall_block", "blocked"),
        "wireguard_login_success": (re.compile(
            r'wireguard:\s+(\S+):\s+Handshake for peer\s+(\S+)\s+from\s+([\d\.a-fA-F:]+):(\d+)\s+completed'
        ), "auth", "vpn_login", "success"),
        "wireguard_login_fail": (re.compile(
            r'wireguard:\s+(\S+):\s+Handshake for peer\s+(\S+)\s+from\s+([\d\.a-fA-F:]+):(\d+)\s+did not complete'
        ), "auth", "vpn_login", "failure"),
        "wireguard_session_close": (re.compile(
            r'wireguard:\s+(\S+):\s+Peer\s+(\S+)\s+disconnected(?:\s+from\s+([\d\.a-fA-F:]+):(\d+))?'
        ), "auth", "session_close", "success"),
        "strongswan_login_success": (re.compile(
            r'.*?<([^>|]+)(?:\|\d+)?>\s+IKE_SA\s+\S+\[\d+\]\s+established between .*?\.\.\.([\d\.a-fA-F:]+)\[([^\]]+)\]'
        ), "auth", "vpn_login", "success"),
        "strongswan_login_fail": (re.compile(
            r'.*?<([^>|]+)(?:\|\d+)?>\s+EAP authentication failed for\s+[\'"]?([^\'"\s]+)[\'"]?(?:\s+from\s+([\d\.a-fA-F:]+))?'
        ), "auth", "vpn_login", "failure"),
        "strongswan_session_close": (re.compile(
            r'.*?<([^>|]+)(?:\|\d+)?>\s+deleting IKE_SA .*?\.\.\.([\d\.a-fA-F:]+)\[([^\]]+)\]'
        ), "auth", "session_close", "success"),
        # SSSD PAM auth failure
        "sssd_auth_fail": (re.compile(
            r'pam_sss\(([^:]+):auth\):\s+authentication failure;.*?\buser=(\S+)'
        ), "auth", "identity_login", "failure"),
        "sssd_auth_success": (re.compile(
            r'pam_sss\(([^:]+):auth\):\s+authentication success;.*?\buser=(\S+)'
        ), "auth", "identity_login", "success"),
        "sssd_session_open": (re.compile(
            r'pam_sss\(([^:]+):session\):\s+session opened for user\s+(\S+)'
        ), "auth", "session_open", "success"),
        "sssd_session_close": (re.compile(
            r'pam_sss\(([^:]+):session\):\s+session closed for user\s+(\S+)'
        ), "auth", "session_close", "success"),
        "winbind_auth_fail_pam": (re.compile(
            r"pam_winbind\(([^:]+):auth\):.*?(?:NT_STATUS_LOGON_FAILURE|authentication failure).*?user ['\"]([^'\"]+)['\"]"
        ), "auth", "identity_login", "failure"),
        "winbind_auth_success": (re.compile(
            r"pam_winbind\(([^:]+):auth\):\s+user ['\"]([^'\"]+)['\"] granted access"
        ), "auth", "identity_login", "success"),
        "winbind_session_open": (re.compile(
            r"pam_winbind\(([^:]+):session\):\s+session opened for user\s+(\S+)"
        ), "auth", "session_open", "success"),
        "winbind_session_close": (re.compile(
            r"pam_winbind\(([^:]+):session\):\s+session closed for user\s+(\S+)"
        ), "auth", "session_close", "success"),
        "winbind_account_locked": (re.compile(
            r"pam_winbind\(([^:]+):auth\):.*?NT_STATUS_ACCOUNT_LOCKED_OUT.*?user ['\"]([^'\"]+)['\"]"
        ), "auth", "account_locked", "failure"),
        "winbind_account_policy": (re.compile(
            r"pam_winbind\(([^:]+):(?:auth|account)\):.*?(NT_STATUS_ACCOUNT_DISABLED|NT_STATUS_PASSWORD_EXPIRED|NT_STATUS_PASSWORD_MUST_CHANGE).*?user ['\"]([^'\"]+)['\"]"
        ), "auth", "account_policy", "failure"),
        "winbind_auth_fail_crap": (re.compile(
            r'winbindd_pam_auth_crap:\s+user\s+\[([^\]]+)\]\s+authentication failed'
        ), "auth", "identity_login", "failure"),

        # Successful sudo
        "sudo_success": (re.compile(
            r'(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)'
        ), "auth", "sudo", "success"),

        # Failed sudo — three formats:
        # 1) <message>: mslm : authentication failure  (process=sudo)
        # 2) <message>: mslm : 3 incorrect password attempts (process=sudo)
        # 3) pam_unix(sudo:auth)[..]: authentication failure; logname=mslm
        #    Header regex pam_unix(sudo:auth) process'ini "pam_unix(sudo" olarak keser.
        #    The message portion may appear as "auth)[pid]: authentication failure; logname=bob".
        #    Use one pattern to catch both forms:
        "sudo_fail": (re.compile(
            r'(?:(\S+)\s*:\s*.*?(?:authentication failure|incorrect password attempt)'
            r'|(?:pam_unix\(sudo:auth\)|sudo:auth\)).*?authentication failure[^\n]*?logname=(\S+))'
        ), "auth", "sudo_fail", "failure"),

        # Successful su
        "su_success": (re.compile(
            r"Successful su for (\S+) by (\S+)"
        ), "auth", "su", "success"),

        # Failed su
        "su_fail": (re.compile(
            r"FAILED SU \(to (\S+)\) (\S+) on"
        ), "auth", "su", "failure"),

        # PAM session open
        "pam_session_open": (re.compile(
            r'pam_unix\(\S+:session\):\s+session opened for user\s+(\S+)\s+by'
        ), "auth", "session_open", "success"),

        # PAM session close
        "pam_session_close": (re.compile(
            r'pam_unix\(\S+:session\):\s+session closed for user\s+(\S+)'
        ), "auth", "session_close", "success"),

        # Useradd / userdel
        "useradd": (re.compile(
            r'new user:\s+name=([^,\s]+)(?:,\s*(?:UID|uid)=(\d+))?'
        ), "auth", "useradd", "success"),
        "userdel": (re.compile(
            r'delete user\s+[\'"]?(\S+)[\'"]?'
        ), "auth", "userdel", "success"),

        # passwd change
        "passwd_change": (re.compile(
            r'password changed for\s+(\S+)'
        ), "auth", "passwd_change", "success"),

        # SSH disconnect
        "ssh_disconnect": (re.compile(
            r'Disconnected from\s+(?:user\s+\S+\s+)?([\d\.a-fA-F:]+)\s+port\s+(\d+)'
        ), "network", "ssh_disconnect", "success"),

        # cron
        "cron_exec": (re.compile(
            r'\((\S+)\) CMD \((.+)\)'
        ), "process", "cron_exec", "success"),

        # sshd child process exec — LOLBin / webshell tespiti
        # Format: child process NNN (user) exec /path/binary [args]
        "sshd_child_exec": (re.compile(
            r'child process \d+ \((\S+)\) exec (\S+)(.*)'
        ), "process", "process_exec", "success"),

        # systemd servis symlink — persistence tespiti
        "systemd_symlink": (re.compile(
            r'Created symlink\s+(\S+)\s+'
        ), "process", "service_created", "success"),
    }

    def parse_line(self, line: str, source_name: str = "syslog") -> Optional[NormalizedEvent]:
        line = line.strip()
        if not line:
            return None

        # Header parse
        m = self._HEADER_TRADITIONAL.match(line)
        if m:
            ts_str, host, process, pid, message = m.groups()
            ts = self._parse_traditional_ts(ts_str)
        else:
            m = self._HEADER_ISO.match(line)
            if m:
                ts_str, host, process, pid, message = m.groups()
                ts = self._parse_iso_ts(ts_str)
            else:
                # Header parse edilemedi, ham mesaj olarak kaydet
                return NormalizedEvent(
                    ts=time.time(), source=source_name,
                    message=line, raw=line, category="unknown"
                )

        evt = NormalizedEvent(
            ts=ts or time.time(),
            host=host,
            source=source_name,
            process=process,
            pid=int(pid) if pid else 0,
            message=message,
            raw=line,
        )

        # Pattern matching
        self._apply_patterns(evt, message, process)
        return evt

    def _apply_patterns(self, evt: NormalizedEvent, message: str, process: str):
        """Try known patterns and apply the first match."""
        # Process names like pam_unix(sudo:auth) are truncated by the header regex.
        # Example: process="pam_unix(sudo", message="auth)[456]: authentication failure..."
        # To catch this case, also inspect the combined process+message string.
        full_msg = message
        if process and "(" in process:
            full_msg = f"{process}:{message}"

        for name, (pattern, category, action, outcome) in self._PATTERNS.items():
            m = pattern.search(full_msg) or pattern.search(message)
            if not m:
                continue
            if name == "sudo_fail":
                is_real_sudo_failure = (
                    process == "sudo" or
                    "pam_unix(sudo:auth)" in full_msg or
                    "sudo:auth)" in full_msg
                )
                if not is_real_sudo_failure:
                    continue
            evt.category = category
            evt.action   = action
            evt.outcome  = outcome
            groups = m.groups()

            if name == "ssh_login_success":
                evt.user, evt.src_ip = groups[1], groups[2]
                evt.fields["auth_method"] = groups[0]
                evt.fields["src_port"]    = groups[3]
                evt.fields["auth_mechanism"] = "ssh"
                _set_identity_context(
                    evt,
                    mechanism="ssh",
                    service=evt.process or "sshd",
                    phase="auth",
                    account=evt.user,
                )

            elif name == "ssh_login_fail":
                evt.user, evt.src_ip = groups[2], groups[3]
                evt.fields["auth_method"] = groups[0]
                evt.fields["src_port"]    = groups[4]
                evt.fields["auth_mechanism"] = "ssh"
                if groups[1]:
                    evt.fields["invalid_user"] = True
                _set_identity_context(
                    evt,
                    mechanism="ssh",
                    service=evt.process or "sshd",
                    phase="auth",
                    account=evt.user,
                )

            elif name == "ssh_invalid_user":
                evt.user, evt.src_ip = groups[0], groups[1]

            elif name == "ssh_pam_fail":
                evt.src_ip = groups[0]
                evt.user = "unknown"

            elif name == "faillock_lock":
                evt.user = groups[0]
                evt.fields["auth_mechanism"] = "faillock"
                _set_identity_context(
                    evt,
                    mechanism="faillock",
                    service=evt.process or "pam_faillock",
                    phase="account",
                    account=evt.user,
                    policy="lockout",
                )

            elif name == "faillock_blocked":
                evt.user = groups[0]
                evt.src_ip = groups[1] or ""
                evt.fields["auth_mechanism"] = "faillock"
                _set_identity_context(
                    evt,
                    mechanism="faillock",
                    service=evt.process or "pam_faillock",
                    phase="account",
                    account=evt.user,
                    policy="lockout",
                )

            elif name == "openvpn_login_success":
                evt.user = groups[0] or ""
                evt.src_ip = groups[1] or groups[3]
                evt.fields["src_port"] = groups[2] or groups[4]
                evt.fields["auth_mechanism"] = "openvpn"
                _set_identity_context(
                    evt,
                    mechanism="openvpn",
                    service=evt.process,
                    phase="auth",
                    account=evt.user,
                    session_state="connected",
                )
                _set_compact_bag(
                    evt,
                    "vpn",
                    common_name=evt.user,
                    peer_ip=evt.src_ip,
                    peer_port=evt.fields["src_port"],
                    session_state="connected",
                )

            elif name == "openvpn_login_fail":
                evt.user = groups[0] or ""
                evt.src_ip = groups[1] or ""
                if groups[2]:
                    evt.fields["src_port"] = groups[2]
                evt.fields["auth_mechanism"] = "openvpn"
                _set_identity_context(
                    evt,
                    mechanism="openvpn",
                    service=evt.process,
                    phase="auth",
                    account=evt.user,
                )
                _set_compact_bag(
                    evt,
                    "vpn",
                    service=evt.process,
                    common_name=evt.user,
                    peer_ip=evt.src_ip,
                    peer_port=evt.fields.get("src_port", ""),
                )

            elif name in ("openvpn_session_open", "openvpn_session_close"):
                evt.user = groups[0]
                evt.src_ip = groups[1]
                evt.fields["src_port"] = groups[2]
                evt.fields["auth_mechanism"] = "openvpn"
                _set_identity_context(
                    evt,
                    mechanism="openvpn",
                    service=evt.process,
                    phase="session",
                    account=evt.user,
                    session_state="opened" if name.endswith("open") else "closed",
                )
                _set_compact_bag(
                    evt,
                    "vpn",
                    common_name=evt.user,
                    peer_ip=evt.src_ip,
                    peer_port=evt.fields["src_port"],
                    session_state="opened" if name.endswith("open") else "closed",
                )

            elif name == "nftables_verdict":
                verdict, table, chain, in_if, out_if, src_ip, dst_ip, proto, src_port, dst_port = groups
                evt.action = "firewall_reject" if verdict == "REJECT" else "firewall_block"
                evt.outcome = "rejected" if verdict == "REJECT" else "blocked"
                evt.src_ip = src_ip
                evt.dst_ip = dst_ip
                evt.fields["protocol"] = (proto or "").upper()
                evt.fields["protocol_lc"] = (proto or "").lower()
                evt.fields["src_port"] = src_port or ""
                evt.fields["dst_port"] = dst_port or ""
                evt.fields["firewall_verdict"] = verdict.lower()
                _set_compact_bag(
                    evt,
                    "firewall",
                    provider="nftables",
                    verdict=verdict.lower(),
                    table=table,
                    chain=chain,
                    in_interface=in_if,
                    out_interface=out_if,
                    protocol=proto,
                    src_port=src_port,
                    dst_port=dst_port,
                )

            elif name == "kernel_firewall_verdict":
                verdict, in_if, out_if, src_ip, dst_ip, proto, src_port, dst_port = groups
                evt.action = "firewall_reject" if verdict == "REJECT" else "firewall_block"
                evt.outcome = "rejected" if verdict == "REJECT" else "blocked"
                evt.src_ip = src_ip
                evt.dst_ip = dst_ip
                evt.fields["protocol"] = (proto or "").upper()
                evt.fields["protocol_lc"] = (proto or "").lower()
                evt.fields["src_port"] = src_port or ""
                evt.fields["dst_port"] = dst_port or ""
                evt.fields["firewall_verdict"] = verdict.lower()
                _set_compact_bag(
                    evt,
                    "firewall",
                    provider="kernel",
                    verdict=verdict.lower(),
                    in_interface=in_if,
                    out_interface=out_if,
                    protocol=proto,
                    src_port=src_port,
                    dst_port=dst_port,
                )

            elif name == "wireguard_login_success":
                evt.fields["auth_mechanism"] = "wireguard"
                tunnel, peer_id, peer_ip, peer_port = groups
                evt.user = peer_id or ""
                evt.src_ip = peer_ip
                evt.fields["src_port"] = peer_port
                _set_identity_context(
                    evt,
                    mechanism="wireguard",
                    service=evt.process,
                    phase="auth",
                    account=evt.user,
                    session_state="connected",
                )
                _set_compact_bag(
                    evt,
                    "vpn",
                    provider="wireguard",
                    tunnel=tunnel,
                    peer_id=peer_id,
                    peer_ip=peer_ip,
                    peer_port=peer_port,
                    session_state="connected",
                )

            elif name == "wireguard_login_fail":
                evt.fields["auth_mechanism"] = "wireguard"
                tunnel, peer_id, peer_ip, peer_port = groups
                evt.user = peer_id or ""
                evt.src_ip = peer_ip
                evt.fields["src_port"] = peer_port
                _set_identity_context(
                    evt,
                    mechanism="wireguard",
                    service=evt.process,
                    phase="auth",
                    account=evt.user,
                )
                _set_compact_bag(
                    evt,
                    "vpn",
                    provider="wireguard",
                    tunnel=tunnel,
                    peer_id=peer_id,
                    peer_ip=peer_ip,
                    peer_port=peer_port,
                )

            elif name == "wireguard_session_close":
                evt.fields["auth_mechanism"] = "wireguard"
                tunnel, peer_id, peer_ip, peer_port = groups
                evt.user = peer_id or ""
                evt.src_ip = peer_ip or ""
                if peer_port:
                    evt.fields["src_port"] = peer_port
                _set_identity_context(
                    evt,
                    mechanism="wireguard",
                    service=evt.process,
                    phase="session",
                    account=evt.user,
                    session_state="closed",
                )
                _set_compact_bag(
                    evt,
                    "vpn",
                    provider="wireguard",
                    tunnel=tunnel,
                    peer_id=peer_id,
                    peer_ip=evt.src_ip,
                    peer_port=evt.fields.get("src_port", ""),
                    session_state="closed",
                )

            elif name == "strongswan_login_success":
                evt.fields["auth_mechanism"] = "strongswan"
                connection, remote_ip, remote_id = groups
                evt.user = remote_id
                evt.src_ip = remote_ip
                _set_identity_context(
                    evt,
                    mechanism="strongswan",
                    service=evt.process,
                    phase="auth",
                    account=evt.user,
                    session_state="established",
                )
                _set_compact_bag(
                    evt,
                    "vpn",
                    provider="strongswan",
                    connection=connection,
                    peer_id=remote_id,
                    peer_ip=remote_ip,
                    session_state="established",
                )

            elif name == "strongswan_login_fail":
                evt.fields["auth_mechanism"] = "strongswan"
                connection, remote_id, remote_ip = groups
                evt.user = remote_id
                evt.src_ip = remote_ip or ""
                _set_identity_context(
                    evt,
                    mechanism="strongswan",
                    service=evt.process,
                    phase="auth",
                    account=evt.user,
                )
                _set_compact_bag(
                    evt,
                    "vpn",
                    provider="strongswan",
                    connection=connection,
                    peer_id=remote_id,
                    peer_ip=evt.src_ip,
                )

            elif name == "strongswan_session_close":
                evt.fields["auth_mechanism"] = "strongswan"
                connection, remote_ip, remote_id = groups
                evt.user = remote_id
                evt.src_ip = remote_ip
                _set_identity_context(
                    evt,
                    mechanism="strongswan",
                    service=evt.process,
                    phase="session",
                    account=evt.user,
                    session_state="closed",
                )
                _set_compact_bag(
                    evt,
                    "vpn",
                    provider="strongswan",
                    connection=connection,
                    peer_id=remote_id,
                    peer_ip=remote_ip,
                    session_state="closed",
                )

            elif name in ("sssd_auth_fail", "sssd_auth_success"):
                service = groups[0]
                evt.user = groups[1]
                evt.fields["auth_mechanism"] = "sssd"
                account, domain = _split_identity_principal(evt.user)
                _set_identity_context(
                    evt,
                    mechanism="sssd",
                    service=service,
                    phase="auth",
                    account=account or evt.user,
                    domain=domain,
                )

            elif name in ("sssd_session_open", "sssd_session_close"):
                service = groups[0]
                evt.user = groups[1]
                evt.fields["auth_mechanism"] = "sssd"
                account, domain = _split_identity_principal(evt.user)
                _set_identity_context(
                    evt,
                    mechanism="sssd",
                    service=service,
                    phase="session",
                    account=account or evt.user,
                    domain=domain,
                    session_state="opened" if name.endswith("open") else "closed",
                )

            elif name == "winbind_auth_fail_pam":
                service = groups[0]
                evt.user = groups[1]
                evt.fields["auth_mechanism"] = "winbind"
                account, domain = _split_identity_principal(evt.user)
                _set_identity_context(
                    evt,
                    mechanism="winbind",
                    service=service,
                    phase="auth",
                    account=account or evt.user,
                    domain=domain,
                )

            elif name == "winbind_auth_success":
                service = groups[0]
                evt.user = groups[1]
                evt.fields["auth_mechanism"] = "winbind"
                account, domain = _split_identity_principal(evt.user)
                _set_identity_context(
                    evt,
                    mechanism="winbind",
                    service=service,
                    phase="auth",
                    account=account or evt.user,
                    domain=domain,
                )

            elif name == "winbind_auth_fail_crap":
                evt.user = groups[0]
                evt.fields["auth_mechanism"] = "winbind"
                account, domain = _split_identity_principal(evt.user)
                _set_identity_context(
                    evt,
                    mechanism="winbind",
                    service=evt.process,
                    phase="auth",
                    account=account or evt.user,
                    domain=domain,
                )

            elif name in ("winbind_session_open", "winbind_session_close"):
                service = groups[0]
                evt.user = groups[1]
                evt.fields["auth_mechanism"] = "winbind"
                account, domain = _split_identity_principal(evt.user)
                _set_identity_context(
                    evt,
                    mechanism="winbind",
                    service=service,
                    phase="session",
                    account=account or evt.user,
                    domain=domain,
                    session_state="opened" if name.endswith("open") else "closed",
                )

            elif name == "winbind_account_locked":
                service = groups[0]
                evt.user = groups[1]
                evt.fields["auth_mechanism"] = "winbind"
                account, domain = _split_identity_principal(evt.user)
                _set_identity_context(
                    evt,
                    mechanism="winbind",
                    service=service,
                    phase="account",
                    account=account or evt.user,
                    domain=domain,
                    policy="lockout",
                )

            elif name == "winbind_account_policy":
                service = groups[0]
                policy_code = groups[1]
                evt.user = groups[2]
                evt.fields["auth_mechanism"] = "winbind"
                evt.fields["identity_policy_code"] = policy_code
                account, domain = _split_identity_principal(evt.user)
                policy_map = {
                    "NT_STATUS_ACCOUNT_DISABLED": "account_disabled",
                    "NT_STATUS_PASSWORD_EXPIRED": "password_expired",
                    "NT_STATUS_PASSWORD_MUST_CHANGE": "password_change_required",
                }
                _set_identity_context(
                    evt,
                    mechanism="winbind",
                    service=service,
                    phase="account",
                    account=account or evt.user,
                    domain=domain,
                    policy=policy_map.get(policy_code, "policy_denied"),
                )

            elif name == "sudo_success":
                evt.user = groups[0]
                raw_cmd = groups[2]
                evt.fields["sudo_target_user"] = groups[1]
                evt.fields["sudo_command_raw"] = raw_cmd
                evt.fields["sudo_command"]     = _sanitize_sudo_command(raw_cmd)

                # Dangerous sudo command → mark as lotl_exec (for SEQ-002)
                # NOTE: shell spawns like /bin/bash or /bin/sh remain sudo=success
                # Only genuinely dangerous commands are promoted to lotl_exec
                cmd = raw_cmd.lower()
                DANGEROUS_SUDO = [
                    (r'wget\s.*(http|ftp).*\|\s*(bash|sh)',   "wget_pipe"),
                    (r'curl\s.*(http|ftp).*\|\s*(bash|sh)',   "curl_pipe"),
                    (r'bash\s+-i\s*>&',                       "bash_reverse_shell"),
                    (r'python[23]?\s+-c\s+.*import\s+socket', "python_shell"),
                    (r'nc\s+.*-e\s+/bin/(bash|sh)',           "netcat_shell"),
                    (r'(nmap|hydra|medusa|sqlmap|nikto|msfconsole)', "attack_tool"),
                    (r'base64\s.*(--decode|-d)\s*\|',         "base64_decode_pipe"),
                ]
                import re as _re
                for pattern, attack_name in DANGEROUS_SUDO:
                    if _re.search(pattern, cmd):
                        evt.category          = "process"
                        evt.action            = "lotl_exec"
                        evt.fields["attack"]  = attack_name
                        evt.fields["cmdline"] = groups[2]
                        evt.fields["lotl"]    = True
                        break

            elif name == "sudo_fail":
                evt.fields["auth_service"] = "sudo"
                # groups[0] = candidate user matched by \S+
                # groups[1] = pam format logname (logname=X)
                u0 = groups[0] or ""
                u1 = groups[1] or ""
                # Because of the broken pam_unix(sudo:auth) process header case
                # u0 may carry a value like "pam_unix(sudo:auth)[pid]" — filter it out
                if u0 and not any(c in u0 for c in ("(", ")", "[", "]", ":")):
                    evt.user = u0
                elif u1:
                    evt.user = u1
                else:
                    # Extract the pam format containing logname= from the raw message
                    import re as _re
                    _lm = _re.search(r'logname=(\S+)', full_msg)
                    if _lm and _lm.group(1):
                        evt.user = _lm.group(1)

            elif name in ("pam_session_open", "pam_session_close",
                          "userdel", "passwd_change"):
                evt.user = groups[0] if groups[0] else ""
                if name in ("userdel", "passwd_change"):
                    _set_identity_context(
                        evt,
                        mechanism="local",
                        service=evt.process,
                        phase="account",
                        account=evt.user,
                        policy="deleted" if name == "userdel" else "password_changed",
                    )

            elif name == "useradd":
                evt.user = groups[0] if groups[0] else ""
                if len(groups) > 1 and groups[1]:
                    evt.fields["new_user_uid"] = groups[1]
                _set_identity_context(
                    evt,
                    mechanism="local",
                    service=evt.process,
                    phase="account",
                    account=evt.user,
                    policy="created",
                )

            elif name == "su_success":
                evt.fields["su_target"] = groups[0]
                evt.user = groups[1]

            elif name == "su_fail":
                evt.fields["su_target"] = groups[0]
                evt.user = groups[1]

            elif name == "ssh_disconnect":
                evt.src_ip = groups[0]
                evt.fields["src_port"] = groups[1]

            elif name == "cron_exec":
                evt.user = groups[0]
                cron_cmd = groups[1]
                evt.fields["cron_command"] = cron_cmd
                # Mark known system cron commands to prevent PERS-002 false positives
                _CRON_SAFE_WHITELIST = (
                    "sessionclean", "run-parts", "apt-get", "apt ", "dpkg",
                    "logrotate", "updatedb", "mandb", "makewhatis",
                    "sysstat", "sar", "iostat", "ntpdate", "chronyc",
                    "debian-sa1", "debian-sa2", "sa1", "sa2",
                    "anacron", "/usr/sbin/anacron", "/usr/bin/anacron",
                    "certbot", "tmpwatch", "tmpfiles", "journalctl",
                    "systemctl", "service ", "update-rc.d", "rkhunter",
                    "clamscan", "freshclam", "aide", "tripwire",
                    "/usr/bin/php", "/usr/sbin/php", "php-fpm",
                    "/usr/sbin/cron", "/usr/sbin/anacron",
                )
                if any(s in cron_cmd for s in _CRON_SAFE_WHITELIST):
                    evt.fields["cron_safe"] = True  # Kural motoru bu field'ı kontrol eder

            elif name == "sshd_child_exec":
                # child process NNN (user) exec /path/binary [args]
                evt.user    = groups[0]
                binary      = groups[1]
                args        = groups[2].strip() if groups[2] else ""
                evt.process = binary.split("/")[-1]
                evt.fields["exec_binary"] = binary
                evt.fields["exec_args"]   = args
                evt.fields["exec_full"]   = f"{binary} {args}".strip()
                # Use the binary name in the process field for LOLBin detection
                evt.fields["parent_process"] = "sshd"

            elif name == "systemd_symlink":
                # Created symlink /etc/systemd/system/...service
                symlink_path = groups[0]
                evt.fields["service_path"] = symlink_path
                evt.fields["service_name"] = symlink_path.split("/")[-1]
                evt.user = "root"

            _enrich_identity_from_journald_metadata(evt)
            _enrich_bag_from_journald_metadata(evt, "vpn")
            _enrich_bag_from_journald_metadata(evt, "firewall")
            return  # ilk eşleşmede dur

        # If no pattern matches, infer the category from the process name
        if process in ("sshd", "ssh"):
            evt.category = "network"
        elif process in ("sudo", "su", "login", "passwd"):
            evt.category = "auth"
        elif process in ("cron", "crond", "anacron"):
            evt.category = "process"
        elif process in ("kernel",):
            evt.category = "system"

        # SUSE: AppArmor profile disabled
        if process in ("apparmor", "apparmor_parser") or "apparmor" in message.lower():
            if any(kw in message.lower() for kw in ("disabled", "complain mode", "unloaded", "profile removed")):
                evt.category = "system"
                evt.action   = "apparmor_disabled"
                evt.outcome  = "success"
                evt.message  = f"AppArmor profil devre dışı: {message[:120]}"
                return

        # Generic firewalld stop for syslog/journald fallback paths
        if "firewalld" in process.lower() and any(kw in message.lower() for kw in ("stop", "stopped", "exiting", "shutting down")):
            evt.category = "network"
            evt.action   = "firewalld_stopped"
            evt.outcome  = "success"
            evt.fields["firewall_control"] = "stop"
            evt.fields["service_name"] = "firewalld"
            evt.message  = f"firewalld durduruldu: {message[:120]}"
            return

        # SUSE: SuSEfirewall2 stop
        if "susefirewall" in process.lower() or "SuSEfirewall2" in message:
            if any(kw in message.lower() for kw in ("stop", "disabled", "shutting down")):
                evt.category = "network"
                evt.action   = "susefirewall_stopped"
                evt.outcome  = "success"
                evt.fields["firewall_control"] = "stop"
                evt.fields["service_name"] = "SuSEfirewall2"
                evt.message  = f"SuSEfirewall2 durduruldu: {message[:120]}"
                return

    def _parse_traditional_ts(self, ts_str: str) -> float:
        """'Mar  5 12:34:56' → unix timestamp using the current year."""
        try:
            year = datetime.now().year
            dt = datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
            return dt.timestamp()
        except (TypeError, ValueError, OverflowError):
            return time.time()

    def _parse_iso_ts(self, ts_str: str) -> float:
        try:
            # Python 3.7+ fromisoformat misses some formats, normalize them first
            ts_str = re.sub(r'(\.\d{6})\d+', r'\1', ts_str)
            return datetime.fromisoformat(ts_str).timestamp()
        except (TypeError, ValueError, OverflowError):
            return time.time()


# ── Journald Parser ────────────────────────────────────────────────────────────

class JournaldParser:
    """Parse journalctl --output=json output."""

    _METADATA_FIELD_MAP = {
        "_SYSTEMD_UNIT": "systemd_unit",
        "SYSLOG_IDENTIFIER": "syslog_identifier",
        "_COMM": "comm",
        "_EXE": "exe",
        "_CMDLINE": "cmdline",
        "_PID": "pid",
        "_UID": "uid",
        "_GID": "gid",
        "_HOSTNAME": "hostname",
        "_BOOT_ID": "boot_id",
        "_TRANSPORT": "transport",
        "MESSAGE_ID": "message_id",
    }

    def _build_metadata_bag(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        journald_meta: Dict[str, Any] = {}
        for src_key, dst_key in self._METADATA_FIELD_MAP.items():
            value = entry.get(src_key)
            if value in (None, ""):
                continue
            journald_meta[dst_key] = str(value)
        return {"journald": journald_meta} if journald_meta else {}

    def parse_entry(self, entry: Dict[str, Any]) -> NormalizedEvent:
        ts_usec = int(entry.get("__REALTIME_TIMESTAMP", 0))
        ts = ts_usec / 1_000_000 if ts_usec else time.time()

        message  = entry.get("MESSAGE", "")
        process  = entry.get("_COMM", entry.get("SYSLOG_IDENTIFIER", ""))
        pid_str  = entry.get("_PID", "0")
        host     = entry.get("_HOSTNAME", "")
        uid_str  = entry.get("_UID", "")

        evt = NormalizedEvent(
            ts=ts,
            host=host,
            source="journald",
            process=process,
            pid=int(pid_str) if str(pid_str).isdigit() else 0,
            message=str(message),
            raw=str(entry),
            fields={"metadata": self._build_metadata_bag(entry)}
        )

        if not evt.fields["metadata"]:
            evt.fields.pop("metadata")

        # Also apply the syslog parser to the message body
        syslog_parser = SyslogParser()
        syslog_parser._apply_patterns(evt, str(message), process)
        return evt


# ── Auditd Parser ─────────────────────────────────────────────────────────────

class AuditdParser:
    """
    /var/log/audit/audit.log parser — genişletilmiş versiyon.

    Format: type=SYSCALL msg=audit(1234567890.123:456): arch=... syscall=...

    Desteklenen audit tipleri:
      SYSCALL  → sistem çağrısı (execve, open, connect...)
      EXECVE   → komut çalıştırma + tam argüman listesi
      PATH     → dosya erişimi
      SOCKADDR → ağ bağlantısı hedefi
      USER_*   → kullanıcı işlemleri
      ADD_USER → yeni kullanıcı

    Living-off-the-land tespiti:
      EXECVE kaydından tam komut satırı çıkarılır.
      python3 -c "import socket...", curl http://evil.com gibi
      meşru araçların kötü kullanımı yakalanır.

    Auditd kurulum (VM'de bir kere):
      sudo apt install auditd
      sudo auditctl -w /etc/passwd -p rwa -k passwd_access
      sudo auditctl -w /etc/shadow -p rwa -k shadow_access
      sudo auditctl -w /etc/sudoers -p rwa -k sudoers_access
      sudo auditctl -a always,exit -F arch=b64 -S execve -k exec_all
      sudo auditctl -a always,exit -F arch=b64 -S connect -k net_connect
    """

    _HEADER = re.compile(r'^type=(\S+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)$')
    _KV     = re.compile(r'(\w+)=(?:"([^"]*)"|([\S]*))')

    # Living-off-the-land: suspicious use of legitimate tools
    LOTL_PATTERNS = [
        # Python / Perl / Ruby / PHP inline
        (re.compile(r'python[23]?\s.*(-c\s*["\']|import\s+(socket|subprocess|os|pty|base64))'), "python_inline"),
        (re.compile(r'perl\s.*(-e|-n|-p)\s*["\']'), "perl_inline"),
        (re.compile(r'ruby\s.*-e\s*["\']'), "ruby_exec"),
        (re.compile(r'php\s.*(-r|-c)\s*["\']'), "php_exec"),
        # Bash/sh inline
        (re.compile(r'bash\s+-[ci]\s+["\']'), "bash_inline"),
        (re.compile(r'bash\s+-i\s*>&'), "bash_reverse_shell"),
        (re.compile(r'sh\s+-c\s+["\']'), "bash_inline"),
        # Curl/wget pipe → shell
        (re.compile(r'curl\s.{0,60}(http|ftp).{0,60}\|\s*(bash|sh|python[23]?)'), "curl_pipe"),
        (re.compile(r'wget\s.{0,60}(http|ftp).{0,60}(-O\s*-|--output-document=-).{0,30}\|\s*(bash|sh)'), "wget_pipe"),
        # Wget download + chmod + execute
        (re.compile(r'wget\s.{0,80}(http|ftp).{0,80}&&\s*(chmod|bash|sh|\./)'), "wget_chmod_exec"),
        # Base64 decode → pipe
        (re.compile(r'base64\s.*(--decode|-d)\s*\|'), "base64_exec"),
        (re.compile(r'echo\s+[A-Za-z0-9+/]{20,}={0,2}\s*\|\s*(base64|openssl|python)'), "base64_exec"),
        # Netcat / socat reverse shell
        (re.compile(r'\bnc\b.{0,30}(-e\s+/bin/(bash|sh)|--exec)'), "nc_reverse_shell"),
        (re.compile(r'\bncat\b.{0,30}(-e\s+/bin/(bash|sh)|--exec)'), "nc_reverse_shell"),
        (re.compile(r'socat\s.{0,60}(EXEC|exec):/bin/(bash|sh)'), "socat_reverse_shell"),
        (re.compile(r'socat\s.{0,60}TCP.{0,40}EXEC'), "socat_reverse_shell"),
        # Parent → child zincir: web sunucu / sshd / db → shell
        (re.compile(r'(nginx|apache2?|httpd|lighttpd)\s.*\|\s*(bash|sh|python|perl|nc)'), "webserver_shell_spawn"),
        (re.compile(r'sshd\s.*(wget|curl|nc|ncat|python|perl|bash\s+-c)'), "sshd_tool_spawn"),
        (re.compile(r'(cron|atd|at)\s.*(bash|sh|python|perl|nc)\s'), "cron_shell_spawn"),
        (re.compile(r'(mysql|mysqld|postgres|mongod)\s.*(bash|sh|system\()'), "db_shell_spawn"),
        # LD_PRELOAD enjeksiyonu
        (re.compile(r'LD_PRELOAD\s*=\s*/'), "ld_preload"),
        (re.compile(r'export\s+LD_PRELOAD'), "ld_preload"),
        # Common pentest tools
        (re.compile(r'\bnmap\s'), "nmap_scan"),
        (re.compile(r'(hydra|medusa|patator)\s'), "brute_force_tool"),
        (re.compile(r'(msfconsole|msfvenom|metasploit)'), "metasploit"),
        (re.compile(r'(sqlmap|nikto|dirb|gobuster|wfuzz)\s'), "web_attack_tool"),
        (re.compile(r'dd\s.*if=/dev/.*of=/dev/'), "disk_copy"),
        (re.compile(r'(tcpdump|wireshark)\s'), "packet_capture"),
    ]

    # LOLBin rule → MITRE mapping (for the rule engine)
    LOTL_ATTACK_RULE = {
        "curl_pipe":           "LOL-001",
        "wget_pipe":           "LOL-002",
        "wget_chmod_exec":     "LOL-003",
        "python_inline":       "LOL-010",
        "perl_inline":         "LOL-011",
        "bash_inline":         "LOL-012",
        "base64_exec":         "LOL-013",
        "nc_reverse_shell":    "LOL-020",
        "socat_reverse_shell": "LOL-021",
        "webserver_shell_spawn":"LOL-030",
        "sshd_tool_spawn":     "LOL-031",
        "cron_shell_spawn":    "LOL-032",
        "db_shell_spawn":      "LOL-033",
        "ld_preload":          "LOL-040",
    }

    # LotL whitelist — package-manager processes cause false positives
    LOTL_WHITELIST = re.compile(
        r'/usr/(bin|sbin|lib)/(apt|dpkg|python3|perl)'
        r'.*(apt-check|dpkg-preconfigure|update-notifier|apt-get|apt-cache'
        r'|debconf|dh_|dpkg-|update-manager|unattended-upgrade|packagekit)',
        re.IGNORECASE
    )

    # Critical file access
    SENSITIVE_FILES = {
        # Kimlik / yetki
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/group", "/etc/gshadow",
        # SSH
        "/etc/ssh/sshd_config", "/root/.ssh/authorized_keys",
        # Cron
        "/etc/crontab", "/var/spool/cron", "/etc/cron.d",
        # Persistence
        "/etc/ld.so.preload", "/etc/ld.so.conf",
        "/etc/pam.d", "/etc/pam.conf",
        "/etc/bash.bashrc", "/etc/profile", "/etc/environment",
        "/etc/systemd/system",
        "/usr/local/bin", "/usr/local/sbin",
        "/etc/rc.local", "/etc/init.d",
        # Firewall config
        "/etc/ufw", "/etc/firewalld",
        "/etc/sysconfig/iptables", "/etc/nftables.conf",
        # Repo / package-manager config
        "/etc/yum.repos.d", "/etc/dnf",
        "/etc/zypp/repos.d", "/etc/zypp/credentials.d",
        "/etc/rhsm/rhsm.conf",
    }

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        line = line.strip()
        if not line:
            return None

        m = self._HEADER.match(line)
        if not m:
            return None

        audit_type, ts_str, seq, rest = m.groups()
        ts = float(ts_str)

        # Extract key-value pairs
        kvs = {k: (v1 or v2) for k, v1, v2 in self._KV.findall(rest)}

        evt = NormalizedEvent(
            ts      = ts,
            source  = "auditd",
            process = kvs.get("comm", kvs.get("exe", "")).strip('"'),
            pid     = int(kvs.get("pid", 0) or 0),
            user    = (lambda u: "" if u in ("4294967295", "-1", "unset") else u)(
                            # For cred_acquire and auth events, acct is more reliable than auid
                            kvs.get("acct",
                                kvs.get("auid",
                                    kvs.get("uid", "")))
                        ),
            message = rest[:300],
            raw     = line,
            fields  = {
                "audit_type": audit_type,
                "seq":        seq,
                # Process-lineage fields
                "ppid":    kvs.get("ppid", ""),
                "euid":    kvs.get("euid", ""),
                "fsuid":   kvs.get("fsuid", ""),
                "comm":    kvs.get("comm", "").strip('"'),
                "exe":     kvs.get("exe", "").strip('"'),
                "tty":     kvs.get("tty", ""),
                "session": kvs.get("ses", ""),
                **kvs
            }
        )

        # Audit type → kategori/action
        type_map = {
            "SYSCALL":       ("process",    "syscall"),
            "EXECVE":        ("process",    "exec"),
            "PATH":          ("filesystem", "file_access"),
            "SOCKADDR":      ("network",    "connect"),
            "NETFILTER_PKT": ("network",    "packet"),
            "USER_LOGIN":    ("auth",       "login"),
            "USER_LOGOUT":   ("auth",       "logout"),
            "USER_AUTH":     ("auth",       "auth"),
            "CRED_ACQ":      ("auth",       "cred_acquire"),
            "USER_CMD":      ("auth",       "user_cmd"),
            "ADD_USER":      ("auth",       "useradd"),
            "DEL_USER":      ("auth",       "userdel"),
            "USER_CHAUTHTOK":("auth",       "passwd"),
            # RHEL/SELinux — distro-specific
            "MAC_STATUS":    ("system",     "selinux_disabled"),
            "MAC_POLICY_LOAD":("system",    "selinux_policy_change"),
            "ANOM_RBAC_FAIL":("system",     "selinux_policy_change"),
            # RPM tampering (caught via auditd SYSCALL)
            "SOFTWARE_UPDATE":("process",   "rpm_tampering"),
            # AppArmor (SUSE/Debian)
            "AVC":           ("system",     "apparmor_event"),
        }
        if audit_type in type_map:
            evt.category, evt.action = type_map[audit_type]

        # Result
        result = kvs.get("res", kvs.get("result", ""))
        if result in ("success", "0"):
            evt.outcome = "success"
        elif result in ("failed", "failure", "1"):
            evt.outcome = "failure"

        # IP
        raw_ip = kvs.get("saddr", kvs.get("addr", ""))
        evt.src_ip = "" if raw_ip in ("?", "unknown", "0.0.0.0") else raw_ip

        # ── EXECVE: build the full command line ───────────────────────────────
        if audit_type == "EXECVE":
            argc = int(kvs.get("argc", 0) or 0)
            args = []
            for i in range(min(argc, 20)):
                arg = kvs.get(f"a{i}", "")
                if arg:
                    args.append(arg.strip('"'))
            cmd = " ".join(args)
            evt.fields["cmdline"] = cmd
            evt.message = f"EXEC: {cmd[:200]}"

            # Living-off-the-land tespiti
            if not self.LOTL_WHITELIST.search(cmd):
                for pattern, attack_type in self.LOTL_PATTERNS:
                    if pattern.search(cmd):
                        evt.category = "process"
                        evt.action   = "lotl_exec"
                        evt.fields["attack"]    = attack_type
                        evt.fields["lotl"]      = True
                        evt.fields["cmdline"]   = cmd
                        evt.message = f"LotL [{attack_type}]: {cmd[:150]}"
                        break

        # ── PATH: critical file access ────────────────────────────────────────
        elif audit_type == "PATH":
            path = kvs.get("name", "").strip('"')
            evt.fields["file_path"] = path
            if any(path.startswith(s) for s in self.SENSITIVE_FILES):
                # Match only WRITE operations — reads create false positives.
                # nametype=CREATE|DELETE|RENAME → kesin yazma/silme
                # oflags: hex value — treat O_WRONLY(0x1) or O_RDWR(0x2) as write access
                nametype = kvs.get("nametype", "").upper()
                write_nametype = nametype in ("CREATE", "DELETE", "RENAME", "PARENT")
                oflags_raw = kvs.get("oflags", "0")
                try:
                    oflags = int(oflags_raw, 16) if oflags_raw.startswith("0x") else int(oflags_raw, 0)
                except (ValueError, TypeError):
                    oflags = 0
                write_oflags = bool(oflags & 0x3)  # O_WRONLY=0x1, O_RDWR=0x2
                is_write = write_nametype or write_oflags
                if is_write:
                    evt.category = "filesystem"
                    evt.action   = "sensitive_file_access"
                    evt.fields["sensitive"]    = True
                    evt.fields["write_access"] = True
                    evt.fields["nametype"]     = nametype
                    evt.message  = f"Kritik dosya yazma: {path}"

        # ── SYSCALL: flag important syscalls ──────────────────────────────────
        elif audit_type == "SYSCALL":
            syscall = kvs.get("syscall", "")
            syscall_map = {
                "59":  "execve",
                "322": "execveat",
                "41":  "socket",
                "42":  "connect",
                "2":   "open",
                "257": "openat",
            }
            if syscall in syscall_map:
                evt.fields["syscall_name"] = syscall_map[syscall]

        # ── MAC_STATUS: SELinux enforcing → permissive transition ────────────
        elif audit_type == "MAC_STATUS":
            enforcing = kvs.get("enforcing", "1")
            if enforcing == "0":
                evt.action  = "selinux_disabled"
                evt.message = "SELinux devre dışı (Permissive/Disabled)"
            else:
                evt.action  = "selinux_enabled"
                evt.message = "SELinux etkinleştirildi (Enforcing)"

        # ── AVC: mark AppArmor deny as apparmor_disabled ─────────────────────
        elif audit_type == "AVC":
            if "apparmor" in rest.lower() and ("KILL" in rest or "denied" in rest.lower()):
                evt.action  = "apparmor_event"
                evt.message = f"AppArmor event: {rest[:150]}"

        return evt


# ── Web Log Parser (Apache / Nginx) ──────────────────────────────────────────

class WebLogParser:
    """
    Apache/Nginx Combined Log Format parser.
    
    Format:
      IP - user [date] "METHOD /path HTTP/1.1" status size "referer" "ua"
    
    Tespit edilen saldırılar:
      - SQL injection
      - Path traversal
      - Scanner (nikto, sqlmap, dirbuster vb.)
      - XSS
      - Shell upload
    """

    COMBINED_RE = re.compile(
        r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
        r'"(?P<request>[^"]*)" '
        r'(?P<status>\d{3}) (?P<size>\S+)'
        r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
    )
    VHOST_COMBINED_RE = re.compile(
        r'(?P<vhost>\S+:\d+) (?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
        r'"(?P<request>[^"]*)" '
        r'(?P<status>\d{3}) (?P<size>\S+)'
        r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
    )
    APACHE_ERROR_RE = re.compile(
        r'^\[(?P<ts>[^\]]+)\] '
        r'\[(?P<module>[^\]:]+):(?P<severity>[^\]]+)\]'
        r'(?: \[pid (?P<pid>\d+)(?::tid (?P<tid>\d+))?\])?'
        r'(?: \[client (?P<client>[^\]]+)\])?'
        r'\s*(?:(?P<ah_code>AH\d+):\s*)?(?P<message>.+)$'
    )

    SQLI_PATTERNS = re.compile(
        r"(?i)(union\s+select|or\s+1=1|and\s+1=1|'--|\"\s*or\s*\"|"
        r";\s*drop\s+table|xp_cmdshell|exec\s*\(|cast\s*\(|convert\s*\()",
        re.IGNORECASE
    )

    TRAVERSAL_RE = re.compile(r"\.\./|\.\./\.\.|/etc/passwd|/etc/shadow|/proc/self")

    SHELL_RE = re.compile(r"(?i)\.(php|asp|aspx|jsp|cgi|sh|py|pl)\s*$")

    SCANNER_UA = re.compile(
        r"(?i)(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|"
        r"hydra|metasploit|burpsuite|nessus|openvas|zgrab|nuclei)"
    )

    BAD_STATUS = {400, 401, 403, 404, 405, 429, 500, 502, 503}

    def parse_line(self, raw: str, source: str = "apache2") -> Optional[NormalizedEvent]:
        line = raw.strip()
        if source == "apache2":
            evt = self._parse_apache_error(line, raw, source)
            if evt is not None:
                return evt
        evt = self._parse_access(line, raw, source)
        return evt

    def _parse_access(self, line: str, raw: str, source: str) -> Optional[NormalizedEvent]:
        m = self.VHOST_COMBINED_RE.match(line) or self.COMBINED_RE.match(line)
        if not m:
            return None

        evt = NormalizedEvent(
            source   = source,
            category = "network",
            action   = "http_request",
            outcome  = "unknown",
            raw      = raw,
        )

        try:
            evt.src_ip = m.group("ip")
            request    = (m.group("request") or "").strip()
            method, path, proto, malformed = self._parse_request(request)
            status     = int(m.group("status"))
            ua         = m.group("ua") or ""
            vhost      = m.groupdict().get("vhost") or ""

            evt.outcome  = "success" if status < 400 else "failure"
            evt.message  = f"{method} {path} → {status}"

            # Zaman
            evt.ts = self._parse_access_ts(m.group("ts"))

            # Attack detection — decode request target/path/query (+ and %xx encodings)
            try:
                from urllib.parse import unquote_plus as _unq, urlsplit as _urlsplit
                parsed_target = _urlsplit(path or request)

                def _decode_http_value(value: str) -> str:
                    decoded = value or ""
                    for _ in range(2):
                        next_decoded = _unq(decoded)
                        if next_decoded == decoded:
                            break
                        decoded = next_decoded
                    return decoded

                request_target = path or request
                path_only = request_target if malformed else (parsed_target.path or path or request)
                query = parsed_target.query or ""
                request_target_decoded = _decode_http_value(request_target)
                path_decoded = _decode_http_value(path_only)
                query_decoded = _decode_http_value(query)
            except ImportError as exc:
                logger.debug(f"[Normalize] urllib.parse import edilemedi: {exc}")
                request_target = path or request
                request_target_decoded = request_target.replace("+", " ")
                path_only = request_target.split("?", 1)[0]
                query = request_target.split("?", 1)[1] if "?" in request_target else ""
                path_decoded = path_only.replace("+", " ")
                query_decoded = query.replace("+", " ")
            evt.fields   = {
                "method": method,
                "proto": proto,
                "request_target": request_target,
                "request_target_decoded": request_target_decoded,
                "request_target_lc": request_target.lower(),
                "request_target_decoded_lc": request_target_decoded.lower(),
                "path": path_only,
                "path_decoded": path_decoded,
                "path_lc": path_only.lower(),
                "path_decoded_lc": path_decoded.lower(),
                "query": query,
                "query_decoded": query_decoded,
                "query_lc": query.lower(),
                "query_decoded_lc": query_decoded.lower(),
                "status": status,
                "ua": ua[:200],
                "ua_lc": ua.lower(),
            }
            if vhost:
                evt.fields["vhost"] = vhost
            if malformed:
                evt.fields["request_malformed"] = True
            full = f"{request_target_decoded} {ua}"
            if self.SQLI_PATTERNS.search(full):
                evt.category = "web_attack"
                evt.action   = "sqli_attempt"
                evt.fields["attack"] = "sql_injection"
            elif self.TRAVERSAL_RE.search(request_target):
                evt.category = "web_attack"
                evt.action   = "path_traversal"
                evt.fields["attack"] = "path_traversal"
            elif self.SCANNER_UA.search(ua):
                evt.category = "network"
                evt.action   = "scanner_detected"
                evt.fields["attack"] = "scanner"
            elif self.SHELL_RE.search(request_target) and method == "POST":
                evt.category = "web_attack"
                evt.action   = "shell_upload"
                evt.fields["attack"] = "shell_upload"

        except Exception as e:
            logger.debug(f"[WEBLOG] Parse hatası: {e}")

        return evt

    def _parse_apache_error(self, line: str, raw: str, source: str) -> Optional[NormalizedEvent]:
        m = self.APACHE_ERROR_RE.match(line)
        if not m:
            return None

        evt = NormalizedEvent(
            source=source,
            category="network",
            action="http_error",
            outcome="failure",
            raw=raw,
        )
        evt.ts = self._parse_apache_error_ts(m.group("ts"))

        module = m.group("module") or ""
        severity = m.group("severity") or ""
        pid = m.group("pid") or ""
        tid = m.group("tid") or ""
        ah_code = m.group("ah_code") or ""
        message = (m.group("message") or "").strip()
        client = (m.group("client") or "").strip()
        client_ip, client_port = self._split_client_address(client)

        evt.process = module or "apache2"
        evt.pid = int(pid) if pid.isdigit() else 0
        evt.src_ip = client_ip
        evt.message = f"{ah_code}: {message}" if ah_code else message
        evt.fields = {
            "module": module,
            "severity": severity,
            "pid": pid,
            "tid": tid,
            "client_ip": client_ip,
            "client_port": client_port,
            "ah_code": ah_code,
            "error_message": message,
        }
        return evt

    @staticmethod
    def _parse_request(request: str) -> tuple[str, str, str, bool]:
        parts = (request or "").split()
        if not parts:
            return "", "", "", True
        method = parts[0]
        proto = ""
        malformed = False
        if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
            proto = parts[-1]
            path = " ".join(parts[1:-1]) or parts[1]
        elif len(parts) >= 2:
            path = " ".join(parts[1:])
            malformed = True
        else:
            path = ""
            malformed = True
        return method, path, proto, malformed

    @staticmethod
    def _parse_access_ts(ts: str) -> float:
        try:
            dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
            return dt.timestamp()
        except (TypeError, ValueError, OverflowError):
            return time.time()

    @staticmethod
    def _parse_apache_error_ts(ts: str) -> float:
        for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
            try:
                return datetime.strptime(ts, fmt).timestamp()
            except (TypeError, ValueError, OverflowError):
                continue
        return time.time()

    @staticmethod
    def _split_client_address(client: str) -> tuple[str, str]:
        text = (client or "").strip()
        if not text:
            return "", ""
        if ":" not in text:
            return text, ""
        host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            return host, maybe_port
        return text, ""


# ── UFW Parser ────────────────────────────────────────────────────────────────

class UFWParser:
    """
    UFW (Uncomplicated Firewall) log parser.
    
    Format:
      Mar 5 12:00:00 host kernel: [UFW BLOCK] IN=eth0 OUT= ... SRC=x.x.x.x DST=y.y.y.y
    """

    UFW_RE = re.compile(
        r"(?P<ts>(?:\w{3}\s+\d+\s+\d+:\d+:\d+)|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2}))\s+(?P<host>\S+)\s+kernel:.*?"
        r"\[UFW (?P<action>BLOCK|ALLOW|LIMIT)\].*?"
        r"SRC=(?P<src>\S+).*?DST=(?P<dst>\S+)"
    )
    # Extract SPT and DPT with separate patterns to avoid greedy overlap
    _SPT_RE = re.compile(r"SPT=(\d+)")
    _DPT_RE = re.compile(r"DPT=(\d+)")
    _PROTO_RE = re.compile(r"PROTO=(\w+)")

    def parse_line(self, raw: str) -> Optional[NormalizedEvent]:
        m = self.UFW_RE.search(raw)
        if not m:
            return None

        action = m.group("action")
        src    = m.group("src")
        dst    = m.group("dst")

        # Extract SPT and DPT with separate patterns — no greedy overlap
        spt_m  = self._SPT_RE.search(raw)
        dpt_m  = self._DPT_RE.search(raw)
        proto_m = self._PROTO_RE.search(raw)
        sport  = spt_m.group(1) if spt_m else ""
        dport  = dpt_m.group(1) if dpt_m else ""
        proto  = proto_m.group(1).upper() if proto_m else ""

        evt = NormalizedEvent(
            source   = "ufw",
            category = "network",
            action   = f"firewall_{action.lower()}",
            outcome  = "blocked" if action == "BLOCK" else "allowed",
            src_ip   = src,
            dst_ip   = dst,
            message  = f"UFW {action}: {src} → {dst}:{dport}",
            raw      = raw,
        )

        try:
            ts_str = m.group("ts")
            if "T" in ts_str and ("+" in ts_str[10:] or "-" in ts_str[10:]):
                evt.ts = datetime.fromisoformat(ts_str).timestamp()
            else:
                dt = datetime.strptime(
                    f"{datetime.now().year} {ts_str}", "%Y %b %d %H:%M:%S"
                )
                evt.ts = dt.timestamp()
        except (TypeError, ValueError, OverflowError):
            evt.ts = time.time()

        evt.fields = {
            "ufw_action": action,
            "protocol":   proto,
            "dst_port":   dport,
            "src_port":   sport,
        }

        return evt


# ── DB Log Parser (MySQL / PostgreSQL) ───────────────────────────────────────

class DBLogParser:
    """
    MySQL error log ve PostgreSQL log parser.
    
    Tespit:
      - Başarısız authentication
      - Şüpheli sorgu
      - Bağlantı flood
    """

    MYSQL_AUTH_RE = re.compile(
        r"Access denied for user '(?P<user>[^']+)'@'(?P<host>[^']+)'"
    )
    MYSQL_AUTH_OK_RE = re.compile(
        r"Connect\s+(?P<user>[^\s@]+)@(?P<host>[^\s]+)(?:\s+on\s+(?P<db>\S+))?"
    )
    PG_AUTH_RE = re.compile(
        r'FATAL:\s+password authentication failed for user (?:"(?P<user1>[^"]+)"|(?P<user2>\S+))'
    )
    PG_AUTH_TR_RE = re.compile(
        r'(?:ÖLÜMCÜL\s+\(FATAL\)|FATAL):\s+'
        r'"(?P<user>[^"]+)"\s+kullanıcısı\s+için\s+'
        r'şifre\s+doğrulaması\s+başarısız\s+oldu',
        re.IGNORECASE,
    )
    PG_PREFIX_TS_RE = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)'
        r'(?:\s+[A-Z]+|[+-]\d{2}(?::?\d{2})?)?'
    )
    PG_PREFIX_PID_RE = re.compile(
        r'(?:\[(?P<pid1>\d+)\]|pid=(?P<pid2>\d+))'
    )
    PG_CLIENT_RE = re.compile(
        r'(?:\b(?:client_addr|host|client)=(?P<host1>[\d\.a-fA-F:]+)|'
        r'\[(?P<host2>[\d\.a-fA-F:]+)\]:\s*FATAL:)'
    )
    PG_AUTH_OK_RE = re.compile(
        r'connection authorized:\s+user=(?P<user>\S+)(?:\s+database=(?P<db>\S+))?(?:.*?\bclient_addr=(?P<host>[\d\.a-fA-F:]+))?'
    )
    PG_CONN_RE = re.compile(
        r'connection received: host=(?P<host>\S+) port=(?P<port>\d+)'
    )
    PG_INVALID_ROLE_RE = re.compile(
        r'(?:FATAL|ERROR):\s+role\s+"(?P<user>[^"]+)"\s+does\s+not\s+exist',
        re.IGNORECASE,
    )
    PG_HBA_REJECT_RE = re.compile(
        r'(?:FATAL|ERROR):\s+no\s+pg_hba\.conf\s+entry\s+for\s+host\s+"(?P<host>[^"]+)"'
        r'(?:,\s+user\s+"(?P<user>[^"]+)")?'
        r'(?:,\s+database\s+"(?P<db>[^"]+)")?',
        re.IGNORECASE,
    )
    PG_STATEMENT_RE = re.compile(
        r'(?:STATEMENT|statement):\s+(?P<stmt>.+)$',
        re.IGNORECASE,
    )
    PG_ROUTINE_NOISE_RE = re.compile(
        r'(?:'
        r'DETAIL:\s+Connection matched|'
        r'connection authenticated:|'
        r'(?:received\s+)?SIGHUP(?:,\s+reloading configuration files)?|'
        r'parameter\s+"log_connections"\s+changed|'
        r'checkpoint(?:\s|$)|'
        r'disconnection:|disconnect(?:ed|ing)?\b|client disconnected|'
        r'could not receive data from client|could not send data to client|'
        r'duration:\s+|statement:\s+|'
        r'ERROR:\s+|WARNING:\s+|LOG:\s+checkpoint'
        r')',
        re.IGNORECASE,
    )
    PG_PRIVILEGED_USER_RE = re.compile(
        r'^(?:postgres|admin|administrator|root|replication|superuser)$',
        re.IGNORECASE,
    )
    PG_ROLE_ESCALATION_RE = re.compile(
        r'^\s*(?:ALTER\s+ROLE|CREATE\s+ROLE)\b.*\bSUPERUSER\b',
        re.IGNORECASE,
    )
    PG_GRANT_ADMIN_RE = re.compile(
        r'^\s*GRANT\b.*\b(?:pg_(?:read_all_data|write_all_data|monitor|execute_server_program|read_server_files|write_server_files)|postgres|admin|dba|superuser)\b.*\bTO\b',
        re.IGNORECASE,
    )
    PG_DESTRUCTIVE_SQL_RE = re.compile(
        r'^\s*(?:DROP\s+DATABASE|DROP\s+TABLE|TRUNCATE\s+TABLE|DROP\s+SCHEMA)\b',
        re.IGNORECASE,
    )
    PG_CONFIG_TAMPER_RE = re.compile(
        r'^\s*(?:ALTER\s+SYSTEM\b|SELECT\s+pg_reload_conf\s*\()',
        re.IGNORECASE,
    )

    def _apply_postgresql_prefix(self, evt: NormalizedEvent, raw: str) -> None:
        ts_m = self.PG_PREFIX_TS_RE.search(raw)
        if ts_m:
            ts_str = ts_m.group("ts").replace("T", " ")
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    evt.ts = datetime.strptime(ts_str, fmt).timestamp()
                    break
                except (TypeError, ValueError, OverflowError):
                    pass
        pid_m = self.PG_PREFIX_PID_RE.search(raw)
        if pid_m:
            try:
                evt.pid = int(pid_m.group("pid1") or pid_m.group("pid2") or 0)
            except (TypeError, ValueError):
                evt.pid = 0
        host_m = self.PG_CLIENT_RE.search(raw)
        if host_m:
            evt.src_ip = host_m.group("host1") or host_m.group("host2") or ""

    def _postgresql_statement_event(self, evt: NormalizedEvent, stmt: str) -> Optional[NormalizedEvent]:
        stmt_clean = " ".join((stmt or "").split())
        if not stmt_clean:
            return None
        evt.fields["db_statement"] = stmt_clean
        evt.fields["db_statement_lc"] = stmt_clean.lower()
        if self.PG_ROLE_ESCALATION_RE.search(stmt_clean) or self.PG_GRANT_ADMIN_RE.search(stmt_clean):
            evt.category = "auth"
            evt.action = "db_role_escalation"
            evt.outcome = "success"
            evt.message = f"PostgreSQL role escalation statement: {stmt_clean[:160]}"
            evt.fields["db_statement_class"] = "role_escalation"
            return evt
        if self.PG_DESTRUCTIVE_SQL_RE.search(stmt_clean):
            evt.category = "database"
            evt.action = "db_destructive_command"
            evt.outcome = "success"
            evt.message = f"PostgreSQL destructive statement: {stmt_clean[:160]}"
            evt.fields["db_statement_class"] = "destructive"
            return evt
        if self.PG_CONFIG_TAMPER_RE.search(stmt_clean):
            evt.category = "system"
            evt.action = "db_config_tamper"
            evt.outcome = "success"
            evt.message = f"PostgreSQL config change statement: {stmt_clean[:160]}"
            evt.fields["db_statement_class"] = "config_tamper"
            return evt
        return None

    def parse_line(self, raw: str, source: str = "mysql") -> Optional[NormalizedEvent]:
        evt = NormalizedEvent(
            source   = source,
            category = "auth",
            action   = "db_connect",
            outcome  = "unknown",
            raw      = raw,
            ts       = time.time(),
        )

        if source == "mysql":
            m = self.MYSQL_AUTH_RE.search(raw)
            if m:
                evt.user    = m.group("user")
                evt.src_ip  = m.group("host")
                evt.action  = "db_login"
                evt.outcome = "failure"
                evt.message = f"MySQL auth failed: {evt.user}@{evt.src_ip}"
                return evt

            m = self.MYSQL_AUTH_OK_RE.search(raw)
            if m:
                evt.user    = m.group("user")
                evt.src_ip  = m.group("host")
                evt.action  = "db_login"
                evt.outcome = "success"
                if m.group("db"):
                    evt.fields["database"] = m.group("db")
                evt.message = f"MySQL auth success: {evt.user}@{evt.src_ip}"
                return evt

        elif source == "postgresql":
            m = self.PG_AUTH_RE.search(raw)
            m_tr = self.PG_AUTH_TR_RE.search(raw) if not m else None
            if m or m_tr:
                evt.user = (
                    (m.group("user1") or m.group("user2") or "")
                    if m
                    else (m_tr.group("user") or "")
                )
                self._apply_postgresql_prefix(evt, raw)
                evt.action = "db_login"
                evt.outcome = "failure"
                evt.fields["db_user"] = evt.user
                evt.fields["remote_client"] = bool(evt.src_ip)
                evt.fields["privileged_user"] = bool(self.PG_PRIVILEGED_USER_RE.match(evt.user or ""))
                pid_part = f" pid={evt.pid}" if evt.pid else ""
                src_part = f" src={evt.src_ip}" if evt.src_ip else ""
                evt.message = f"PostgreSQL auth failed: {evt.user}{src_part}{pid_part}"
                return evt

            m = self.PG_INVALID_ROLE_RE.search(raw)
            if m:
                self._apply_postgresql_prefix(evt, raw)
                evt.user = m.group("user") or ""
                evt.category = "auth"
                evt.action = "db_invalid_role"
                evt.outcome = "failure"
                evt.fields["db_user"] = evt.user
                evt.fields["db_reason"] = "invalid_role"
                evt.fields["remote_client"] = bool(evt.src_ip)
                evt.message = f"PostgreSQL invalid role: {evt.user}"
                return evt

            m = self.PG_HBA_REJECT_RE.search(raw)
            if m:
                self._apply_postgresql_prefix(evt, raw)
                evt.user = m.group("user") or ""
                evt.src_ip = m.group("host") or evt.src_ip
                evt.category = "auth"
                evt.action = "db_hba_reject"
                evt.outcome = "failure"
                evt.fields["db_user"] = evt.user
                evt.fields["db_reason"] = "pg_hba_reject"
                evt.fields["remote_client"] = bool(evt.src_ip)
                if m.group("db"):
                    evt.fields["database"] = m.group("db")
                evt.message = f"PostgreSQL pg_hba reject: {evt.src_ip or 'unknown'}"
                return evt

            m = self.PG_AUTH_OK_RE.search(raw)
            if m:
                self._apply_postgresql_prefix(evt, raw)
                evt.user = m.group("user")
                evt.src_ip = m.group("host") or evt.src_ip or ""
                evt.action = "db_login"
                evt.outcome = "success"
                evt.fields["db_user"] = evt.user
                evt.fields["remote_client"] = bool(evt.src_ip)
                if m.group("db"):
                    evt.fields["database"] = m.group("db")
                evt.message = f"PostgreSQL auth success: {evt.user}"
                return evt

            m = self.PG_CONN_RE.search(raw)
            if m:
                evt.src_ip = m.group("host")
                evt.action = "db_connect"
                evt.outcome = "unknown"
                evt.message = f"PostgreSQL connection: {evt.src_ip}"
                return evt

            m = self.PG_STATEMENT_RE.search(raw)
            if m:
                self._apply_postgresql_prefix(evt, raw)
                stmt_evt = self._postgresql_statement_event(evt, m.group("stmt") or "")
                if stmt_evt is not None:
                    return stmt_evt

        return None

    def is_routine_noise(self, raw: str, source: str = "mysql") -> bool:
        if source != "postgresql":
            return False
        return bool(self.PG_ROUTINE_NOISE_RE.search(raw))


class PostfixParser:
    """
    Postfix mail.log / maillog parser.

    Desteklenen olaylar:
      - SASL auth failure
      - NOQUEUE reject
    """

    _HDR = re.compile(
        r'^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<proc>postfix/\S+)\[(?P<pid>\d+)\]:\s+'
        r'(?P<msg>.+)$'
    )
    _SASL_FAIL = re.compile(
        r'warning:\s+(?P<peer>[^\[]+)\[(?P<src>[\d\.a-fA-F:]+)\]:\s+'
        r'SASL (?P<method>\S+) authentication failed'
    )
    _SASL_SUCCESS = re.compile(
        r'warning:\s+(?P<peer>[^\[]+)\[(?P<src>[\d\.a-fA-F:]+)\]:\s+'
        r'SASL (?P<method>\S+) authentication succeeded:\s+sasl_username=(?P<user>\S+)'
    )
    _REJECT = re.compile(
        r'NOQUEUE:\s+reject:\s+\w+\s+from\s+(?P<peer>[^\[]+)\[(?P<src>[\d\.a-fA-F:]+)\]:\s+'
        r'(?P<reason>.+)'
    )

    def parse_line(self, raw: str) -> Optional[NormalizedEvent]:
        m = self._HDR.match(raw.strip())
        if not m:
            return None

        ts_str = m.group("ts")
        host   = m.group("host")
        proc   = m.group("proc").lower()
        pid    = int(m.group("pid") or 0)
        msg    = m.group("msg")

        evt = NormalizedEvent(
            host    = host,
            source  = "mail",
            process = proc,
            pid     = pid,
            raw     = raw,
            message = msg[:300],
        )

        try:
            now = datetime.now()
            ts_parsed = datetime.strptime(f"{now.year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
            evt.ts = ts_parsed.timestamp()
        except (TypeError, ValueError, OverflowError):
            evt.ts = time.time()

        sm = self._SASL_FAIL.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "smtp_login"
            evt.outcome  = "failure"
            evt.src_ip   = sm.group("src")
            evt.fields["peer"] = sm.group("peer").strip()
            evt.fields["auth_mechanism"] = "sasl"
            _set_identity_context(
                evt,
                mechanism="sasl",
                service=proc,
                phase="auth",
            )
            _set_compact_bag(
                evt,
                "mail",
                service=proc,
                peer=evt.fields["peer"],
                sasl_method=sm.group("method"),
            )
            evt.message  = f"Postfix SASL auth failed: {evt.src_ip}"
            return evt

        sm = self._SASL_SUCCESS.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "smtp_login"
            evt.outcome  = "success"
            evt.user     = sm.group("user")
            evt.src_ip   = sm.group("src")
            evt.fields["peer"] = sm.group("peer").strip()
            evt.fields["auth_mechanism"] = "sasl"
            _set_identity_context(
                evt,
                mechanism="sasl",
                service=proc,
                phase="auth",
                account=evt.user,
            )
            _set_compact_bag(
                evt,
                "mail",
                service=proc,
                peer=evt.fields["peer"],
                sasl_method=sm.group("method"),
                sasl_username=evt.user,
            )
            evt.message  = f"Postfix SASL auth success: {evt.user} from {evt.src_ip}"
            return evt

        sm = self._REJECT.search(msg)
        if sm:
            evt.category = "network"
            evt.action   = "smtp_reject"
            evt.outcome  = "failure"
            evt.src_ip   = sm.group("src")
            evt.fields["peer"] = sm.group("peer").strip()
            evt.fields["reject_reason"] = sm.group("reason")[:200]
            _set_compact_bag(
                evt,
                "mail",
                service=proc,
                peer=evt.fields["peer"],
            )
            evt.message  = f"Postfix reject: {evt.src_ip}"
            return evt

        return None


# ── dpkg Log Parser ───────────────────────────────────────────────────────────

class DpkgParser:
    """
    /var/log/dpkg.log parser.

    Format:
      2026-03-05 12:00:00 install nmap:amd64 <none> 7.93+dfsg1-1

    Tespit:
      - Saldırı aracı kurulumu (nmap, hydra, netcat vb.)
      - Şüpheli paket kaldırma (auditd, ufw, fail2ban)
      - Toplu paket kurulumu (çok sayıda paket kısa sürede)
    """

    _INSTALL_REMOVE_RE = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
        r'(?P<operation>install|remove|purge)\s+'
        r'(?P<package>\S+)\s+'
        r'(?P<old_version>\S+)'
        r'(?:\s+(?P<new_version>\S+))?$'
    )
    _UPGRADE_RE = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
        r'upgrade\s+'
        r'(?P<package>\S+)\s+'
        r'(?P<old_version>\S+)\s+'
        r'(?P<new_version>\S+)$'
    )
    _STATUS_RE = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
        r'status\s+'
        r'(?P<status>\S+)\s+'
        r'(?P<package>\S+)\s+'
        r'(?P<version>\S+)$'
    )
    _STARTUP_RE = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
        r'startup\s+'
        r'(?P<operation>\S+)'
        r'(?:\s+(?P<extra>.+))?$'
    )
    _TRIGGER_RE = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
        r'trigproc\s+'
        r'(?P<package>\S+)'
        r'(?:\s+(?P<version>\S+))?'
        r'(?:\s+(?P<trigger_state>\S+))?$'
    )
    _CONFIGURE_RE = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
        r'configure\s+'
        r'(?P<package>\S+)\s+'
        r'(?P<version>\S+)'
        r'(?:\s+(?P<status>\S+))?$'
    )
    _APT_LINE_RE = re.compile(
        r'^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+'
        r'(?:apt|apt-get|unattended-upgrade)\[\d+\]:\s+'
        r'(?P<action>Installed|Removed|Upgraded):\s+'
        r'(?P<package>[A-Za-z0-9.+_-]+)'
    )
    _APT_HISTORY_COMMAND_RE = re.compile(
        r'^Commandline:\s+(?P<cmd>.+)$'
    )
    _APT_HISTORY_ACTION_RE = re.compile(
        r'^(?P<action>Install|Remove|Purge|Upgrade):\s+(?P<body>.+)$'
    )

    ATTACK_TOOLS = {
        "hydra", "medusa", "john", "hashcat",
        "metasploit-framework", "msfconsole",
        "sqlmap", "nikto", "dirb", "gobuster", "wfuzz",
        "ettercap", "dsniff", "arpspoof",
        "mimikatz", "crackmapexec", "impacket",
        "beef-xss", "setoolkit",
        "masscan", "zmap", "rustscan",
    }
    DUAL_USE_TOOLS = {
        "nmap", "netcat", "netcat-openbsd", "netcat-traditional", "ncat",
        "wireshark", "tcpdump", "aircrack-ng",
    }
    SECURITY_TOOLS = {
        "auditd", "ufw", "fail2ban", "apparmor",
        "aide", "tripwire", "rkhunter", "chkrootkit",
        "clamav",
    }

    def _split_package_token(self, raw_package: str) -> tuple[str, str]:
        pkg = (raw_package or "").strip()
        if pkg.endswith(".deb"):
            pkg = pkg[:-4]
        if ":" in pkg:
            name, arch = pkg.rsplit(":", 1)
            return name.lower(), arch.lower()
        return pkg.lower(), ""

    @staticmethod
    def _parse_ts(ts_text: str) -> float:
        try:
            return datetime.strptime(ts_text, "%Y-%m-%d %H:%M:%S").timestamp()
        except (TypeError, ValueError, OverflowError):
            return time.time()

    def _base_event(self, raw: str, line: str) -> NormalizedEvent:
        return NormalizedEvent(
            source="dpkg",
            category="process",
            action="package_status",
            outcome="success",
            raw=raw,
            message=line[:300],
            fields={},
        )

    def parse_line(self, raw: str) -> Optional[NormalizedEvent]:
        line = raw.strip()
        if not line:
            return None

        apt_m = None
        apt_hist_cmd = None
        apt_hist_action = None
        evt = self._base_event(raw, line)

        install_remove_m = self._INSTALL_REMOVE_RE.match(line)
        if install_remove_m:
            raw_operation = install_remove_m.group("operation")
            operation = "remove" if raw_operation == "purge" else raw_operation
            package_name, arch = self._split_package_token(install_remove_m.group("package"))
            evt.ts = self._parse_ts(install_remove_m.group("ts"))
            evt.action = f"package_{operation}"
            evt.message = f"Package {operation}: {package_name}"
            evt.fields = {
                "package": package_name,
                "package_name": package_name,
                "arch": arch,
                "old_version": install_remove_m.group("old_version"),
                "new_version": install_remove_m.group("new_version") or "",
                "dpkg_operation": raw_operation,
            }
            return evt

        upgrade_m = self._UPGRADE_RE.match(line)
        if upgrade_m:
            package_name, arch = self._split_package_token(upgrade_m.group("package"))
            evt.ts = self._parse_ts(upgrade_m.group("ts"))
            evt.action = "package_upgrade"
            evt.message = f"Package upgrade: {package_name}"
            evt.fields = {
                "package": package_name,
                "package_name": package_name,
                "arch": arch,
                "old_version": upgrade_m.group("old_version"),
                "new_version": upgrade_m.group("new_version"),
                "dpkg_operation": "upgrade",
            }
            return evt

        status_m = self._STATUS_RE.match(line)
        if status_m:
            package_name, arch = self._split_package_token(status_m.group("package"))
            evt.ts = self._parse_ts(status_m.group("ts"))
            evt.action = "package_status"
            evt.message = f"Package status {status_m.group('status')}: {package_name}"
            evt.fields = {
                "package": package_name,
                "package_name": package_name,
                "arch": arch,
                "version": status_m.group("version"),
                "dpkg_status": status_m.group("status"),
                "dpkg_operation": "status",
            }
            return evt

        startup_m = self._STARTUP_RE.match(line)
        if startup_m:
            evt.ts = self._parse_ts(startup_m.group("ts"))
            evt.action = "package_startup"
            evt.message = f"Package startup: {startup_m.group('operation')}"
            evt.fields = {
                "dpkg_operation": startup_m.group("operation"),
            }
            extra = (startup_m.group("extra") or "").strip()
            if extra:
                evt.fields["startup_detail"] = extra
            return evt

        trigger_m = self._TRIGGER_RE.match(line)
        if trigger_m:
            package_name, arch = self._split_package_token(trigger_m.group("package"))
            evt.ts = self._parse_ts(trigger_m.group("ts"))
            evt.action = "package_trigger"
            evt.message = f"Package trigger: {package_name}"
            evt.fields = {
                "package": package_name,
                "package_name": package_name,
                "arch": arch,
                "version": trigger_m.group("version") or "",
                "dpkg_operation": "trigproc",
            }
            return evt

        configure_m = self._CONFIGURE_RE.match(line)
        if configure_m:
            package_name, arch = self._split_package_token(configure_m.group("package"))
            evt.ts = self._parse_ts(configure_m.group("ts"))
            evt.action = "package_status"
            evt.message = f"Package status configure: {package_name}"
            evt.fields = {
                "package": package_name,
                "package_name": package_name,
                "arch": arch,
                "version": configure_m.group("version"),
                "dpkg_status": configure_m.group("status") or "configure",
                "dpkg_operation": "configure",
            }
            return evt
        else:
            apt_m = self._APT_LINE_RE.match(line)
            if apt_m:
                action_map = {"Installed": "install", "Removed": "remove", "Upgraded": "upgrade"}
                action = action_map.get(apt_m.group("action"), "install")
                package_name, arch = self._split_package_token(apt_m.group("package"))
                evt.action = f"package_{action}"
                evt.message = f"Package {action}: {package_name}"
                evt.fields = {
                    "package": package_name,
                    "package_name": package_name,
                    "arch": arch,
                    "dpkg_operation": action,
                }
                try:
                    dt = datetime.strptime(f"{datetime.now().year} {apt_m.group('ts')}", "%Y %b %d %H:%M:%S")
                    evt.ts = dt.timestamp()
                except (TypeError, ValueError, OverflowError):
                    evt.ts = time.time()
                return evt
            else:
                apt_hist_cmd = self._APT_HISTORY_COMMAND_RE.match(line)
                if apt_hist_cmd:
                    cmd = apt_hist_cmd.group("cmd").strip()
                    evt.action = "exec"
                    evt.process = cmd.split()[0] if cmd else "apt-get"
                    evt.message = f"Paket komutu: {cmd[:200]}"
                    evt.fields = {"cmdline": cmd}
                    evt.ts = time.time()
                    return evt

                apt_hist_action = self._APT_HISTORY_ACTION_RE.match(line)
                if not apt_hist_action:
                    return None

                action_map = {
                    "install": "install",
                    "remove": "remove",
                    "purge": "remove",
                    "upgrade": "upgrade",
                }
                action = action_map.get(apt_hist_action.group("action").lower(), "install")
                raw_action = apt_hist_action.group("action").lower()
                body = apt_hist_action.group("body").strip()
                package_token = body.split(",", 1)[0].strip()
                package_name, arch = self._split_package_token(package_token.split(" ", 1)[0])
                evt.action = f"package_{action}"
                evt.process = "apt-get"
                evt.message = f"Package {action}: {package_name}"
                evt.fields = {
                    "package": package_name,
                    "package_name": package_name,
                    "arch": arch,
                    "dpkg_operation": raw_action,
                }
                evt.ts = time.time()
                return evt


# ── RHEL /var/log/secure Log Parser ──────────────────────────────────────────

class RHELSecureParser:
    """
    RHEL/CentOS/Rocky/AlmaLinux /var/log/secure parser.

    Format: Mar  5 12:34:56 hostname sshd[1234]: message
    Debian auth.log ile aynı format ama bazı farklar var:
      - PAM mesajları daha ayrıntılı
      - sudo log formatı farklı
      - SELinux AVC mesajları eklenebilir
    """

    # Standart syslog header
    _HDR = re.compile(
        r'^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<proc>\w[\w\-\.]*)\[?(?P<pid>\d+)?\]?:\s+'
        r'(?P<msg>.+)$'
    )

    # SSH patterns
    _SSH_ACCEPT  = re.compile(r'Accepted (\w+) for (\S+) from ([\d\.]+) port (\d+)')
    _SSH_FAIL    = re.compile(r'Failed (\w+) for (invalid user )?(\S+) from ([\d\.]+)')
    _SSH_INVALID = re.compile(r'Invalid user (\S+) from ([\d\.]+)')

    # sudo patterns — RHEL format
    _SUDO_RE = re.compile(
        r'(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*'
        r'USER=(?P<runas>\S+)\s*;\s*COMMAND=(?P<cmd>.+)'
    )
    _SUDO_FAIL_RE = re.compile(r'(?P<user>\S+)\s*:\s*\d+ incorrect password')

    # PAM patterns
    _PAM_FAIL  = re.compile(r'pam_unix.*authentication failure.*user=(\S+)')
    _PAM_DENY  = re.compile(r'pam_unix.*user unknown to the underlying.*acct.*[=:](\S+)')
    _FAILLOCK_LOCK = re.compile(
        r'pam_faillock\(\S+\):\s+Consecutive login failures for user\s+(\S+)\s+account temporarily locked'
    )
    _FAILLOCK_BLOCKED = re.compile(
        r'pam_faillock\(\S+\):\s+User\s+(\S+)\s+is blocked(?:.*?from\s+([\d\.a-fA-F:]+))?'
    )
    _SSSD_AUTH_FAIL = re.compile(
        r'pam_sss\(([^:]+):auth\):\s+authentication failure;.*?\buser=(\S+)'
    )
    _SSSD_AUTH_SUCCESS = re.compile(
        r'pam_sss\(([^:]+):auth\):\s+authentication success;.*?\buser=(\S+)'
    )
    _SSSD_SESSION = re.compile(
        r'pam_sss\(([^:]+):session\):\s+session (opened|closed) for user\s+(\S+)'
    )
    _WINBIND_AUTH_FAIL_PAM = re.compile(
        r"pam_winbind\(([^:]+):auth\):.*?(?:NT_STATUS_LOGON_FAILURE|authentication failure).*?user ['\"]([^'\"]+)['\"]"
    )
    _WINBIND_AUTH_SUCCESS = re.compile(
        r"pam_winbind\(([^:]+):auth\):\s+user ['\"]([^'\"]+)['\"] granted access"
    )
    _WINBIND_SESSION = re.compile(
        r"pam_winbind\(([^:]+):session\):\s+session (opened|closed) for user\s+(\S+)"
    )
    _WINBIND_ACCOUNT_LOCKED = re.compile(
        r"pam_winbind\(([^:]+):auth\):.*?NT_STATUS_ACCOUNT_LOCKED_OUT.*?user ['\"]([^'\"]+)['\"]"
    )
    _WINBIND_ACCOUNT_POLICY = re.compile(
        r"pam_winbind\(([^:]+):(?:auth|account)\):.*?(NT_STATUS_ACCOUNT_DISABLED|NT_STATUS_PASSWORD_EXPIRED|NT_STATUS_PASSWORD_MUST_CHANGE).*?user ['\"]([^'\"]+)['\"]"
    )
    _WINBIND_AUTH_FAIL_CRAP = re.compile(
        r'winbindd_pam_auth_crap:\s+user\s+\[([^\]]+)\]\s+authentication failed'
    )

    def parse_line(self, raw: str) -> Optional[NormalizedEvent]:
        m = self._HDR.match(raw.strip())
        if not m:
            return None

        ts_str = m.group("ts")
        host   = m.group("host")
        proc   = m.group("proc").lower()
        pid    = int(m.group("pid") or 0)
        msg    = m.group("msg")

        evt = NormalizedEvent(
            host    = host,
            source  = "auth",
            process = proc,
            pid     = pid,
            raw     = raw,
            message = msg[:300],
        )

        try:
            from datetime import datetime as _dt
            now = _dt.now()
            ts_parsed = _dt.strptime(f"{now.year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
            evt.ts = ts_parsed.timestamp()
        except Exception:
            evt.ts = time.time()

        # SSH accepted
        sm = self._SSH_ACCEPT.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "ssh_login"
            evt.outcome  = "success"
            evt.user     = sm.group(2)
            evt.src_ip   = sm.group(3)
            evt.message  = f"SSH login: {evt.user} from {evt.src_ip}"
            return evt

        # SSH failed
        sm = self._SSH_FAIL.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "ssh_login"   # fix: kurallar ssh_login+outcome=failure bekler
            evt.outcome  = "failure"
            evt.user     = sm.group(3)
            evt.src_ip   = sm.group(4)
            if sm.group(2):
                evt.fields["invalid_user"] = True
                evt.fields["auth_invalid_user"] = True
            evt.message  = f"SSH auth failed: {evt.user} from {evt.src_ip}"
            return evt

        # SSH invalid user
        sm = self._SSH_INVALID.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "ssh_invalid_user"
            evt.outcome  = "failure"
            evt.user     = sm.group(1)
            evt.src_ip   = sm.group(2)
            evt.message  = f"SSH invalid user: {evt.user} from {evt.src_ip}"
            return evt

        # sudo success
        sm = self._SUDO_RE.search(msg)
        if sm and proc == "sudo":
            evt.category = "auth"
            evt.action   = "sudo"
            evt.outcome  = "success"
            evt.user     = sm.group("user")
            raw_cmd = sm.group("cmd").strip()
            evt.fields["sudo_command_raw"] = raw_cmd
            evt.fields["sudo_command"] = _sanitize_sudo_command(raw_cmd)
            evt.fields["sudo_runas"]   = sm.group("runas")
            evt.message  = f"sudo: {evt.user} → {sm.group('runas')}: {raw_cmd[:80]}"
            return evt

        # sudo fail
        sm = self._SUDO_FAIL_RE.search(msg)
        if sm and proc == "sudo":
            evt.category = "auth"
            evt.action   = "sudo_fail"
            evt.outcome  = "failure"
            evt.user     = sm.group("user")
            evt.message  = f"sudo fail: {evt.user}"
            return evt

        # PAM failure
        sm = self._PAM_FAIL.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "auth_fail"
            evt.outcome  = "failure"
            evt.user     = sm.group(1)
            evt.message  = f"PAM auth failure: {evt.user}"
            return evt

        sm = self._FAILLOCK_LOCK.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "account_locked"
            evt.outcome  = "failure"
            evt.user     = sm.group(1)
            evt.fields["auth_mechanism"] = "faillock"
            evt.message  = f"Faillock hesap kilitlendi: {evt.user}"
            return evt

        sm = self._FAILLOCK_BLOCKED.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "account_locked"
            evt.outcome  = "failure"
            evt.user     = sm.group(1)
            evt.src_ip   = sm.group(2) or ""
            evt.fields["auth_mechanism"] = "faillock"
            evt.message  = f"Faillock hesap bloklu: {evt.user}"
            return evt

        sm = self._SSSD_AUTH_FAIL.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "identity_login"
            evt.outcome  = "failure"
            evt.user     = sm.group(2)
            evt.fields["auth_mechanism"] = "sssd"
            account, domain = _split_identity_principal(evt.user)
            _set_identity_context(
                evt,
                mechanism="sssd",
                service=sm.group(1),
                phase="auth",
                account=account or evt.user,
                domain=domain,
            )
            evt.message  = f"SSSD auth failure: {evt.user}"
            return evt

        sm = self._SSSD_AUTH_SUCCESS.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "identity_login"
            evt.outcome  = "success"
            evt.user     = sm.group(2)
            evt.fields["auth_mechanism"] = "sssd"
            account, domain = _split_identity_principal(evt.user)
            _set_identity_context(
                evt,
                mechanism="sssd",
                service=sm.group(1),
                phase="auth",
                account=account or evt.user,
                domain=domain,
            )
            evt.message  = f"SSSD auth success: {evt.user}"
            return evt

        sm = self._SSSD_SESSION.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "session_open" if sm.group(2) == "opened" else "session_close"
            evt.outcome  = "success"
            evt.user     = sm.group(3)
            evt.fields["auth_mechanism"] = "sssd"
            account, domain = _split_identity_principal(evt.user)
            _set_identity_context(
                evt,
                mechanism="sssd",
                service=sm.group(1),
                phase="session",
                account=account or evt.user,
                domain=domain,
                session_state=sm.group(2),
            )
            evt.message  = f"SSSD session {sm.group(2)}: {evt.user}"
            return evt

        sm = self._WINBIND_AUTH_FAIL_PAM.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "identity_login"
            evt.outcome  = "failure"
            evt.user     = sm.group(2)
            evt.fields["auth_mechanism"] = "winbind"
            account, domain = _split_identity_principal(evt.user)
            _set_identity_context(
                evt,
                mechanism="winbind",
                service=sm.group(1),
                phase="auth",
                account=account or evt.user,
                domain=domain,
            )
            evt.message  = f"Winbind auth failure: {evt.user}"
            return evt

        sm = self._WINBIND_AUTH_SUCCESS.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "identity_login"
            evt.outcome  = "success"
            evt.user     = sm.group(2)
            evt.fields["auth_mechanism"] = "winbind"
            account, domain = _split_identity_principal(evt.user)
            _set_identity_context(
                evt,
                mechanism="winbind",
                service=sm.group(1),
                phase="auth",
                account=account or evt.user,
                domain=domain,
            )
            evt.message  = f"Winbind auth success: {evt.user}"
            return evt

        sm = self._WINBIND_SESSION.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "session_open" if sm.group(2) == "opened" else "session_close"
            evt.outcome  = "success"
            evt.user     = sm.group(3)
            evt.fields["auth_mechanism"] = "winbind"
            account, domain = _split_identity_principal(evt.user)
            _set_identity_context(
                evt,
                mechanism="winbind",
                service=sm.group(1),
                phase="session",
                account=account or evt.user,
                domain=domain,
                session_state=sm.group(2),
            )
            evt.message  = f"Winbind session {sm.group(2)}: {evt.user}"
            return evt

        sm = self._WINBIND_ACCOUNT_LOCKED.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "account_locked"
            evt.outcome  = "failure"
            evt.user     = sm.group(2)
            evt.fields["auth_mechanism"] = "winbind"
            account, domain = _split_identity_principal(evt.user)
            _set_identity_context(
                evt,
                mechanism="winbind",
                service=sm.group(1),
                phase="account",
                account=account or evt.user,
                domain=domain,
                policy="lockout",
            )
            evt.message  = f"Winbind account locked: {evt.user}"
            return evt

        sm = self._WINBIND_ACCOUNT_POLICY.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "account_policy"
            evt.outcome  = "failure"
            evt.user     = sm.group(3)
            evt.fields["auth_mechanism"] = "winbind"
            evt.fields["identity_policy_code"] = sm.group(2)
            account, domain = _split_identity_principal(evt.user)
            policy_map = {
                "NT_STATUS_ACCOUNT_DISABLED": "account_disabled",
                "NT_STATUS_PASSWORD_EXPIRED": "password_expired",
                "NT_STATUS_PASSWORD_MUST_CHANGE": "password_change_required",
            }
            _set_identity_context(
                evt,
                mechanism="winbind",
                service=sm.group(1),
                phase="account",
                account=account or evt.user,
                domain=domain,
                policy=policy_map.get(sm.group(2), "policy_denied"),
            )
            evt.message  = f"Winbind account policy denied: {evt.user}"
            return evt

        sm = self._WINBIND_AUTH_FAIL_CRAP.search(msg)
        if sm:
            evt.category = "auth"
            evt.action   = "identity_login"
            evt.outcome  = "failure"
            evt.user     = sm.group(1)
            evt.fields["auth_mechanism"] = "winbind"
            account, domain = _split_identity_principal(evt.user)
            _set_identity_context(
                evt,
                mechanism="winbind",
                service=evt.process,
                phase="auth",
                account=account or evt.user,
                domain=domain,
            )
            evt.message  = f"Winbind auth failure: {evt.user}"
            return evt

        # SELinux disable/policy change (journald/syslog messages may land here too)
        if "setenforce" in msg.lower() or "selinux" in msg.lower():
            if "0" in msg or "disabled" in msg.lower() or "permissive" in msg.lower():
                evt.category = "system"
                evt.action   = "selinux_disabled"
                evt.outcome  = "success"
                evt.message  = f"SELinux devre dışı: {msg[:120]}"
                return evt
            if "policy" in msg.lower() or "load" in msg.lower():
                evt.category = "system"
                evt.action   = "selinux_policy_change"
                evt.outcome  = "success"
                evt.message  = f"SELinux politika değişikliği: {msg[:120]}"
                return evt

        # firewalld stop
        if "firewalld" in proc and ("stop" in msg.lower() or "exiting" in msg.lower()):
            evt.category = "network"
            evt.action   = "firewalld_stopped"
            evt.outcome  = "success"
            evt.fields["firewall_control"] = "stop"
            evt.fields["service_name"] = "firewalld"
            evt.message  = f"firewalld durduruldu: {msg[:120]}"
            return evt

        # Genel auth event
        evt.category = "auth"
        evt.action   = "auth_event"
        evt.outcome  = "unknown"
        return evt


# ── DNF / RPM Log Parser (RHEL) ───────────────────────────────────────────────

class DnfParser:
    """
    RHEL/CentOS /var/log/dnf.log ve dnf5.log parser.

    Format: 2026-03-05T12:34:56+03:00 INFO  --- Install nmap-7.93
            2026-03-05T12:34:56+03:00 DEBUG Installed: nmap-7.93-1.x86_64

    Ayrıca rpm komut satırı logları:
      rpm -ivh <package> tarzı işlemler auditd EXECVE'den yakalanır.
    """

    _DNF_LINE = re.compile(
        r'(?P<ts>\d{4}-\d{2}-\d{2}T[\d:+\-]+)\s+'
        r'(?P<level>\w+)\s+'
        r'(?P<msg>.+)'
    )
    _DNF_INSTALL = re.compile(r'(?:Install|Installed|Upgrade|Upgraded)[:\s]+(?P<pkg>[\w\.\-]+)')
    _DNF_REMOVE  = re.compile(r'(?:Remove|Removed|Erased):\s+(?P<pkg>\S+)')
    _DNF_KNOWN_MESSAGE = re.compile(
        r'^(?:DNF version|Command|Base command|Extra commands|User-Agent|No match for argument|'
        r'Unable to find a match|Argüman için eşleşme yok|Hata:|'
        r'Error:|Transaction failed|Failed:|Problem:|Depsolve Error|Nothing to do)',
        re.IGNORECASE,
    )
    _DNF_FAILURE = re.compile(
        r'(?:No match for argument|Unable to find a match|Transaction failed|'
        r'Argüman için eşleşme yok|Bir eşleşme bulunamadı|'
        r'Depsolve Error|Dependency resolution failed|Problem:|nothing provides|'
        r'conflicting requests|cannot install|failed to|Error:\s+Unable)',
        re.IGNORECASE,
    )
    _DNF_COMMAND = re.compile(r'^(?P<key>Command|Base command|Extra commands):\s*(?P<value>.+)$', re.IGNORECASE)
    _ANSI_ESCAPE = re.compile(r'\x1B(?:\[[0-?]*[ -/]*[@-~]|\([0-?]*[ -/]*[@-~])')

    # Lists shared with DpkgParser, including dual-use separation
    ATTACK_TOOLS   = DpkgParser.ATTACK_TOOLS if hasattr(DpkgParser, 'ATTACK_TOOLS') else set()
    DUAL_USE_TOOLS = DpkgParser.DUAL_USE_TOOLS if hasattr(DpkgParser, 'DUAL_USE_TOOLS') else set()
    SECURITY_TOOLS = DpkgParser.SECURITY_TOOLS if hasattr(DpkgParser, 'SECURITY_TOOLS') else {
        "auditd", "firewalld", "fail2ban", "aide",
        "rkhunter", "chkrootkit", "clamav",
    }

    @classmethod
    def _strip_ansi(cls, text: str) -> str:
        return cls._ANSI_ESCAPE.sub("", text or "")

    def parse_line(self, raw: str) -> Optional[NormalizedEvent]:
        raw = raw.strip()
        if not raw:
            return None

        m = self._DNF_LINE.match(raw)
        if m:
            msg = self._strip_ansi(m.group("msg")).strip()
        elif self._DNF_KNOWN_MESSAGE.match(self._strip_ansi(raw)):
            msg = self._strip_ansi(raw).strip()
        else:
            return None

        evt = NormalizedEvent(
            source   = "dnf",
            category = "process",
            action   = "pkg_event",
            outcome  = "success",
            raw      = raw,
            message  = msg[:300],
        )

        try:
            import re as _re
            from datetime import datetime as _dt
            # Parse timezone offsets correctly: +HH:MM, +HHMM, -HH:MM, -HHMM
            if m:
                ts_str = _re.sub(r'[+-]\d{2}:?\d{2}$', '', m.group("ts").strip())
                evt.ts = _dt.fromisoformat(ts_str).timestamp()
            else:
                evt.ts = time.time()
        except (ValueError, AttributeError):
            evt.ts = time.time()

        evt.fields["package_manager"] = "dnf"

        cm = self._DNF_COMMAND.search(msg)
        if cm:
            key = cm.group("key").strip().lower().replace(" ", "_")
            value = cm.group("value").strip()
            evt.fields[key] = value
            if key == "command":
                evt.fields["cmdline"] = value
                evt.process = "dnf" if "dnf" in value else ("yum" if "yum" in value else "")
            evt.message = f"DNF {key}: {value[:180]}"
            return evt

        if msg.lower().startswith(("dnf version", "user-agent")):
            evt.fields["dnf_metadata"] = True
            return evt

        if self._DNF_FAILURE.search(msg):
            evt.outcome = "failure"
            evt.fields["package_error"] = True
            evt.message = f"DNF failure: {msg[:180]}"
            return evt

        # Install
        im = self._DNF_INSTALL.search(msg)
        if im:
            pkg = im.group("pkg").split("-")[0].lower()  # nmap-7.93 → nmap
            evt.action = "pkg_install"
            evt.fields["package"] = pkg
            evt.message = f"DNF install: {pkg}"
            if pkg in self.ATTACK_TOOLS:
                evt.action          = "attack_tool_installed"
                evt.fields["attack"] = "tool_install"
                evt.fields["tool"]   = pkg
                evt.message         = f"Saldırı aracı kuruldu (dnf): {pkg}"
            elif pkg in self.DUAL_USE_TOOLS:
                evt.fields["dual_use"] = True
                evt.fields["tool"]     = pkg
                evt.message            = f"Dual-use araç kuruldu (dnf): {pkg}"
            return evt

        # Remove
        rm = self._DNF_REMOVE.search(msg)
        if rm:
            pkg = rm.group("pkg").split("-")[0].lower()
            evt.action = "pkg_remove"
            evt.fields["package"] = pkg
            evt.message = f"DNF remove: {pkg}"
            if pkg in self.SECURITY_TOOLS:
                evt.action            = "security_tool_removed"
                evt.fields["security"] = "tool_remove"
                evt.fields["tool"]     = pkg
                evt.message           = f"Güvenlik aracı kaldırıldı (dnf): {pkg}"
            return evt

        return evt


# ── Zypper Log Parser (SUSE) ──────────────────────────────────────────────────

class ZypperParser:
    """
    SUSE/openSUSE /var/log/zypp/history parser.

    Format: 2026-03-05 12:34:56|install|nmap|7.93|x86_64||repo|...
            2026-03-05 12:34:56|remove |auditd|...

    Alanlar: tarih | işlem | paket | sürüm | arch | ...
    """

    _LINE_RE = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\|'
        r'(?P<action>install|remove|purge|update|patch)\|'
        r'(?P<pkg>[^\|]+)'
    )

    ATTACK_TOOLS   = DpkgParser.ATTACK_TOOLS
    DUAL_USE_TOOLS = DpkgParser.DUAL_USE_TOOLS
    SECURITY_TOOLS = DpkgParser.SECURITY_TOOLS

    def parse_line(self, raw: str) -> Optional[NormalizedEvent]:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            return None

        m = self._LINE_RE.match(raw)
        if not m:
            return None

        action = m.group("action").strip()
        pkg    = m.group("pkg").strip().lower()

        evt = NormalizedEvent(
            source   = "zypper",
            category = "process",
            action   = f"pkg_{action}",
            outcome  = "success",
            raw      = raw,
            message  = f"zypper {action}: {pkg}",
            fields   = {"package": pkg, "pkg_action": action},
        )

        try:
            from datetime import datetime as _dt
            evt.ts = _dt.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S").timestamp()
        except (TypeError, ValueError, OverflowError):
            evt.ts = time.time()

        if action == "install" and pkg in self.ATTACK_TOOLS:
            evt.action          = "attack_tool_installed"
            evt.fields["attack"] = "tool_install"
            evt.fields["tool"]   = pkg
            evt.message         = f"Saldırı aracı kuruldu (zypper): {pkg}"

        elif action == "install" and pkg in self.DUAL_USE_TOOLS:
            evt.fields["dual_use"] = True
            evt.fields["tool"]     = pkg
            evt.message            = f"Dual-use araç kuruldu (zypper): {pkg}"

        elif action in ("remove", "purge") and pkg in self.SECURITY_TOOLS:
            evt.action             = "security_tool_removed"
            evt.fields["security"] = "tool_remove"
            evt.fields["tool"]     = pkg
            evt.message            = f"Güvenlik aracı kaldırıldı (zypper): {pkg}"

        return evt


class UtmpParser:
    """
    `last` / `lastb` çıktısından wtmp / btmp login kayıtlarını parse eder.
    """

    _LINE_RE = re.compile(
        r'^(?P<user>\S+)\s+'
        r'(?P<tty>\S+)\s+'
        r'(?P<src>\S+)\s+'
        r'(?P<dow>\w{3})\s+(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2})'
    )
    _SKIP_USERS = {"reboot", "shutdown", "runlevel"}
    _SKIP_TTYS = {"system", "system-boot"}

    def parse_line(self, raw: str, failed: bool = False) -> Optional[NormalizedEvent]:
        raw = raw.strip()
        if not raw or raw.startswith(("wtmp begins", "btmp begins")):
            return None

        m = self._LINE_RE.match(raw)
        if not m:
            return None

        user = m.group("user")
        tty  = m.group("tty")
        src  = m.group("src")
        if user in self._SKIP_USERS or tty in self._SKIP_TTYS:
            return None

        evt = NormalizedEvent(
            source   = "btmp" if failed else "wtmp",
            category = "auth",
            action   = "login",
            outcome  = "failure" if failed else "success",
            user     = user,
            src_ip   = "" if src in ("0.0.0.0", "-", ":0") else src,
            process  = "login",
            raw      = raw,
            message  = f"{'Başarısız' if failed else 'Başarılı'} oturum kaydı: {user}",
            fields   = {
                "tty": tty,
                "utmp_source": "btmp" if failed else "wtmp",
            },
        )

        try:
            from datetime import datetime as _dt
            now = _dt.now()
            ts  = _dt.strptime(
                f"{now.year} {m.group('mon')} {m.group('day')} {m.group('time')}",
                "%Y %b %d %H:%M"
            )
            evt.ts = ts.timestamp()
        except (TypeError, ValueError, OverflowError):
            evt.ts = time.time()

        if tty.startswith(("ssh", "pts/")):
            evt.fields["session_type"] = "remote"
        else:
            evt.fields["session_type"] = "local"

        return evt


# ── DNS Log Parser ────────────────────────────────────────────────────────────

class DNSParser:
    """
    DNS sorgu logları parser.

    Kaynaklar:
      - /var/log/syslog (systemd-resolved)
      - /var/log/named/ (bind9)
      - /var/log/dnsmasq.log

    Tespit:
      - IOC domain eşleşmesi
      - DGA (Domain Generation Algorithm) — yüksek entropi
      - C2 callback pattern (çok sayıda sorgu, kısa TTL)
    """

    # systemd-resolved log line
    _RESOLVED_RE = re.compile(
        r'systemd-resolved.*IN (?P<qtype>\w+) (?P<domain>[\w\.\-]+)'
    )
    # dnsmasq
    _DNSMASQ_RE = re.compile(
        r'dnsmasq.*query\[(?P<qtype>\w+)\] (?P<domain>[\w\.\-]+) from (?P<src>[\d\.]+)'
    )
    _DNSMASQ_NXDOMAIN_RE = re.compile(
        r'dnsmasq.*reply (?P<domain>[\w\.\-]+) is NXDOMAIN'
    )
    # named/bind
    _NAMED_RE = re.compile(
        r'named.*client .*?(?P<src>[\d\.]+)#\d+.*query: (?P<domain>[\w\.\-]+) IN (?P<qtype>\w+)'
    )
    _NAMED_FAILURE_RE = re.compile(
        r'named.*client .*?(?P<src>[\d\.]+)#\d+.*query failed \((?P<rcode>NXDOMAIN|SERVFAIL)\) '
        r'for (?P<domain>[\w\.\-]+)/IN/(?P<qtype>\w+)',
        re.IGNORECASE,
    )

    # Suspicious TLDs commonly used for abuse
    SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".xyz", ".click"}

    def _entropy(self, s: str) -> float:
        """Shannon entropy for DGA detection."""
        import math
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        return -sum(f/len(s) * math.log2(f/len(s)) for f in freq.values())

    def _is_dga(self, domain: str) -> bool:
        """High entropy + long subdomain → suspected DGA."""
        parts = domain.split(".")
        if not parts:
            return False
        subdomain = parts[0]
        # 12+ characters and entropy > 3.5 → suspicious
        if len(subdomain) >= 12 and self._entropy(subdomain) > 3.5:
            return True
        # High digit ratio → suspicious
        digits = sum(1 for c in subdomain if c.isdigit())
        if len(subdomain) > 8 and digits / len(subdomain) > 0.4:
            return True
        return False

    def parse_line(self, raw: str, source: str = "dns") -> Optional[NormalizedEvent]:
        domain = None
        src_ip = ""
        qtype  = ""
        outcome = "unknown"
        upper_raw = raw.upper()

        for pattern in [self._RESOLVED_RE, self._DNSMASQ_RE, self._NAMED_RE, self._NAMED_FAILURE_RE, self._DNSMASQ_NXDOMAIN_RE]:
            m = pattern.search(raw)
            if m:
                domain = m.group("domain").rstrip(".")
                qtype  = m.group("qtype") if "qtype" in pattern.groupindex else ""
                src_ip = m.group("src") if "src" in pattern.groupindex else ""
                if "rcode" in pattern.groupindex:
                    outcome = "failure"
                break

        if not domain:
            return None

        # Loopback / yerel domainleri atla
        if domain in ("localhost", "localdomain") or domain.endswith(".local"):
            return None

        evt = NormalizedEvent(
            ts       = time.time(),
            source   = source,
            category = "network",
            action   = "dns_query",
            outcome  = "failure" if outcome == "failure" or "NXDOMAIN" in upper_raw else "unknown",
            src_ip   = src_ip,
            raw      = raw,
            message  = f"DNS sorgu: {domain}",
            fields   = {
                "domain": domain,
                "qtype":  qtype,
                "entropy": round(self._entropy(domain.split(".")[0]), 2),
            },
        )

        # Suspicious TLD check
        sus_tld = ""
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                sus_tld = tld
                break

        # DGA detection — check first because it has priority
        if self._is_dga(domain):
            evt.action              = "dga_detected"
            evt.fields["dga"]       = True
            evt.message             = f"DGA şüphesi: {domain}"
            # If a suspicious TLD is also present, attach it as supporting info
            if sus_tld:
                evt.fields["sus_tld"] = sus_tld

        # Suspicious TLD — mark as action if it is not DGA
        elif sus_tld:
            evt.action              = "suspicious_tld"
            evt.fields["sus_tld"]   = sus_tld
            evt.message             = f"Şüpheli TLD: {domain}"

        return evt


# ── Normalizer (main class) ────────────────────────────────────────────

class Normalizer:
    """
    Tüm parser'ları bir araya getirir.
    Gelen ham log → NormalizedEvent dönüşümü burada yönetilir.

    Desteklenen kaynaklar:
      auth.log, syslog, journald, auditd
      apache2, nginx, ufw
      mysql, postgresql
      mail       → Postfix mail.log / maillog
      openvpn    → OpenVPN logları
      wtmp, btmp  → başarılı/başarısız login kayıtları
      dpkg       → paket kurulum/kaldırma (Debian)
      dnf/rpm    → paket kurulum/kaldırma (RHEL)
      zypper     → paket kurulum/kaldırma (SUSE)
      dns        → DNS sorguları (DGA tespiti dahil)

    Bilinçli no-go:
      faillog / lastlog → snapshot/rapor çıktısı; append-only telemetry değil.
      Yanlış correlation/dupe üretmemek için event kaynağı olarak parse edilmez.
    """

    def __init__(self, distro_family: str = "unknown"):
        self.distro_family   = distro_family
        self.syslog_parser   = SyslogParser()
        self.journald_parser = JournaldParser()
        self.auditd_parser   = AuditdParser()
        self.web_parser      = WebLogParser()
        self.ufw_parser      = UFWParser()
        self.db_parser       = DBLogParser()
        self.mail_parser     = PostfixParser()
        self.dpkg_parser     = DpkgParser()
        self.dns_parser      = DNSParser()
        self.utmp_parser     = UtmpParser()
        # Distro-specific parsers
        self.rhel_secure_parser = RHELSecureParser()
        self.dnf_parser         = DnfParser()
        self.zypper_parser      = ZypperParser()
        self._stats = {"total": 0, "parsed": 0, "failed": 0}
        # Source-based parse-failure counter: {source: {"total": N, "failed": N}}
        self._source_stats: Dict[str, Dict[str, int]] = {}
        # Empty critical-field warning counter
        self._missing_field_warn: Dict[str, int] = {}

    _SUSE_FIREWALL_KV_RE = re.compile(r"\b([A-Z][A-Z0-9_]*)=([^\s]+)")
    _SUSE_FIREWALL_PREFIX_RE = re.compile(
        r"(?P<prefix>\b(?:filter_[A-Za-z0-9_]+_(?:REJECT|DROP)"
        r"|AEGIS_TEST_DROP"
        r"|[A-Z0-9_][A-Z0-9_-]*(?:REJECT|DROP|BLOCK|DENY|DENIED)[A-Z0-9_-]*)\b):?",
        re.IGNORECASE,
    )

    def _normalize_suse_firewall_event(
        self,
        evt: NormalizedEvent,
        raw: str,
        source: str,
    ) -> NormalizedEvent:
        if self.distro_family != "suse":
            return evt

        text = evt.message or raw or ""
        if "SRC=" not in text or "DST=" not in text:
            return evt

        prefix_match = self._SUSE_FIREWALL_PREFIX_RE.search(text)
        if not prefix_match:
            return evt

        kv = {key: value for key, value in self._SUSE_FIREWALL_KV_RE.findall(text)}
        src_ip = kv.get("SRC", "")
        dst_ip = kv.get("DST", "")
        if not src_ip or not dst_ip:
            return evt

        prefix = prefix_match.group("prefix")
        prefix_lc = prefix.lower()
        is_reject = "reject" in prefix_lc
        verdict = "reject" if is_reject else "drop"

        evt.source = evt.source or source
        evt.category = "network"
        evt.action = "firewall_reject" if is_reject else "firewall_block"
        evt.outcome = "rejected" if is_reject else "blocked"
        evt.src_ip = src_ip
        evt.dst_ip = dst_ip
        evt.message = f"SUSE firewalld {verdict}: {src_ip} -> {dst_ip}:{kv.get('DPT', '')}"

        proto = kv.get("PROTO", "")
        in_if = kv.get("IN", "")
        out_if = kv.get("OUT", "")
        src_port = kv.get("SPT", "")
        dst_port = kv.get("DPT", "")

        evt.fields["protocol"] = proto.upper()
        evt.fields["protocol_lc"] = proto.lower()
        evt.fields["src_port"] = src_port
        evt.fields["dst_port"] = dst_port
        evt.fields["interface"] = in_if
        evt.fields["firewall_verdict"] = verdict
        evt.fields["firewall_prefix"] = prefix
        _set_compact_bag(
            evt,
            "firewall",
            provider="firewalld",
            verdict=verdict,
            prefix=prefix,
            in_interface=in_if,
            out_interface=out_if,
            protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
        )
        return evt

    def _source_class_for_duplicate_candidate(self, source: str) -> Optional[str]:
        if source == "journald":
            return "auth_log"
        if source == "wtmp":
            return "accounting"
        if source == "btmp":
            return "accounting"
        if source in ("auth.log", "secure"):
            return "auth_log"
        if source in ("auth", "auth_log"):
            return "auth_log"
        return None

    def _auth_login_kind(self, evt: NormalizedEvent, source: str) -> Optional[str]:
        source_class = self._source_class_for_duplicate_candidate(source)
        if evt.category != "auth" or source_class is None:
            return None
        if evt.action not in ("login", "ssh_login", "identity_login", "vpn_login"):
            return None
        if evt.outcome == "success":
            return "login_success"
        if evt.outcome == "failure":
            return "login_failed"
        return None

    def _attach_duplicate_candidate_metadata(self, evt: NormalizedEvent, source: str) -> None:
        kind = self._auth_login_kind(evt, source)
        if not kind or not evt.user or not evt.src_ip:
            return

        source_class = self._source_class_for_duplicate_candidate(source)
        if source_class is None:
            return

        fingerprint_parts = ["auth_login", kind, evt.user, evt.src_ip]
        if evt.host:
            fingerprint_parts.append(evt.host)
        fingerprint = hashlib.md5("|".join(fingerprint_parts).encode()).hexdigest()

        metadata = evt.fields.setdefault("metadata", {})
        metadata["duplicate_candidate"] = {
            "family": "auth_login",
            "kind": kind,
            "fingerprint": fingerprint,
            "source_class": source_class,
        }

    def _attach_duplicate_policy_metadata(self, evt: NormalizedEvent) -> None:
        metadata = evt.fields.get("metadata")
        if not isinstance(metadata, dict):
            return

        candidate = metadata.get("duplicate_candidate")
        if not isinstance(candidate, dict):
            return

        fingerprint = candidate.get("fingerprint")
        source_class = candidate.get("source_class")
        if not fingerprint or not source_class:
            return

        source_priorities = {
            "auth_log": 2,
            "accounting": 1,
        }
        source_priority = source_priorities.get(source_class)
        preferred_source = "auth_log"
        if source_priority is None:
            return

        metadata["duplicate_policy"] = {
            "family": "auth_login",
            "source_rank": source_priority,
            "preferred_source_class": preferred_source,
            "event_source_class": source_class,
        }

    def normalize(self, raw: str, source: str = "syslog") -> NormalizedEvent:
        """
        Tek bir ham log satırı/entry'yi normalize et.
        Her zaman geçerli bir NormalizedEvent döner (asla None dönemez).
        """
        if not raw or not raw.strip():
            self._stats["total"] += 1
            self._stats["failed"] += 1
            return self._fallback(raw or "", source, "empty_line")

        self._stats["total"] += 1
        # Initialize source-based counters
        ss = self._source_stats.setdefault(source, {"total": 0, "failed": 0})
        ss["total"] += 1

        try:
            if source in ("faillog", "lastlog"):
                self._stats["failed"] += 1
                ss["failed"] += 1
                return self._fallback(raw, source, "unsupported_snapshot_source")
            if source == "auditd":
                evt = self.auditd_parser.parse_line(raw)
                # Internal SIEM test format fallback:
                # "2026-03-05 12:00:00 exec root LotL [attack]: cmdline"
                if evt is None:
                    evt = self.syslog_parser.parse_line(raw, source)
                    if evt:
                        evt.source = "auditd" 
            elif source == "journald":
                import json as _json
                try:
                    entry = _json.loads(raw)
                    evt = self.journald_parser.parse_entry(entry)
                except Exception:
                    evt = self.syslog_parser.parse_line(raw, source)
            elif source in ("apache2", "nginx"):
                evt = self.web_parser.parse_line(raw, source)
            elif source == "ufw":
                evt = self.ufw_parser.parse_line(raw)
            elif source in ("mysql", "postgresql"):
                evt = self.db_parser.parse_line(raw, source)
                if evt is None and source == "postgresql" and self.db_parser.is_routine_noise(raw, source):
                    evt = NormalizedEvent(
                        ts=time.time(),
                        source=source,
                        category="unknown",
                        action="unknown",
                        outcome="unknown",
                        message=raw[:300],
                        raw=raw,
                        fields={"ignored_noise": "postgresql_routine"},
                    )
            elif source in ("mail", "maillog"):
                evt = self.mail_parser.parse_line(raw)
                if evt:
                    evt.source = source
            elif source == "wtmp":
                evt = self.utmp_parser.parse_line(raw, failed=False)
            elif source == "btmp":
                evt = self.utmp_parser.parse_line(raw, failed=True)
            elif source in ("dpkg", "dpkg.log", "/var/log/dpkg.log"):
                # Use the dnf parser on RHEL and the zypper parser on SUSE
                if self.distro_family == "rhel":
                    evt = self.dnf_parser.parse_line(raw)
                elif self.distro_family == "suse":
                    evt = self.zypper_parser.parse_line(raw)
                else:
                    evt = self.dpkg_parser.parse_line(raw)
            elif source in ("dnf", "rpm", "yum"):
                # RHEL paket logu
                evt = self.dnf_parser.parse_line(raw)
            elif source == "zypper":
                # SUSE paket logu
                evt = self.zypper_parser.parse_line(raw)
            elif source in ("dns", "dnsmasq", "named"):
                evt = self.dns_parser.parse_line(raw, source)
                # If the DNS source tails syslog, most lines may not be in DNS format.
                # Return None instead of falling back when there is no match, so it does not count as a failure.
                if evt is None:
                    # The syslog line does not contain DNS — that is normal, do not increment the counter
                    self._stats["parsed"] += 1
                    ss["total"] += 1
                    return None
            elif source in ("auth", "auth_log", "secure", "auth.log"):
                # RHEL'de auth_log → /var/log/secure → RHELSecureParser dene
                if self.distro_family == "rhel":
                    evt = self.rhel_secure_parser.parse_line(raw)
                    if evt is None:
                        evt = self.syslog_parser.parse_line(raw, source)
                    elif evt:
                        evt.source = source
                else:
                    evt = self.syslog_parser.parse_line(raw, source)
            else:
                # Also catch DNS lines embedded in syslog
                evt = self.syslog_parser.parse_line(raw, source)
                if evt and ("systemd-resolved" in raw or "dnsmasq" in raw or "named" in raw):
                    dns_evt = self.dns_parser.parse_line(raw, source)
                    if dns_evt:
                        evt = dns_evt
            if evt:
                evt = self._normalize_suse_firewall_event(evt, raw, source)
                # Fix 17: stamp distro_family onto every event — ML feature[24]
                evt.distro_family = self.distro_family
                evt = self._ensure_minimum_fields(evt, raw, source)
                self._attach_duplicate_candidate_metadata(evt, source)
                self._attach_duplicate_policy_metadata(evt)
                self._stats["parsed"] += 1
                # Empty critical-field warning — detect it before broken features reach ML
                self._warn_missing_fields(evt, source)
                return evt
            else:
                self._stats["failed"] += 1
                ss["failed"] += 1
                return self._fallback(raw, source, "parse_none")

        except Exception as e:
            self._stats["failed"] += 1
            ss["failed"] += 1
            logger.debug(f"[NORMALIZE] Parse hatası ({source}): {e} | {raw[:80]}")
            return self._fallback(raw, source, "exception")

    def _warn_missing_fields(self, evt: NormalizedEvent, source: str) -> None:
        """
        Auth/network event'lerde user veya src_ip boşsa uyarı logla.
        Bu field'lar boş kalırsa ML'e "" / 0 gider — feature kalitesini bozar.
        Uyarı throttle edilir: aynı source için 60 saniyede 1 kez.
        """
        import time as _time
        if evt.category not in ("auth", "network"):
            return
        now = _time.time()
        missing = []
        if evt.category == "auth" and not evt.user:
            missing.append("user")
        if evt.action in ("ssh_login", "ssh_invalid_user", "ssh_pam_fail",
                          "firewall_block", "http_request") and not evt.src_ip:
            missing.append("src_ip")
        if not missing:
            return
        key = f"{source}:{','.join(missing)}"
        last = self._missing_field_warn.get(key, 0)
        if now - last >= 60:
            self._missing_field_warn[key] = now
            logger.warning(
                f"[NORMALIZE] Boş kritik field [{','.join(missing)}] "
                f"source={source} action={evt.action} — "
                f"ML feature kalitesi etkilenebilir."
            )

    def parse_fail_stats(self) -> Dict[str, Dict[str, float]]:
        """
        Source bazlı parse fail oranı döndürür.
        Watchdog bu metodu kullanarak %10+ fail olan source'ları uyarır.
        Dönüş: {source: {"total": N, "failed": N, "fail_rate": 0.XX}}
        """
        result = {}
        for src, counts in self._source_stats.items():
            total  = counts["total"]
            failed = counts["failed"]
            result[src] = {
                "total":     total,
                "failed":    failed,
                "fail_rate": round(failed / total, 3) if total > 0 else 0.0,
            }
        return result

    def _fallback(self, raw: str, source: str, reason: str) -> NormalizedEvent:
        """
        Parser başarısız olsa bile tutarlı, işlenebilir event döner.
        category/action/outcome her zaman dolu gelir.
        Kurallar "unknown" action'ı görmezden gelir ama
        event sayısı ve faz geçişi için yine de sayılır.
        """
        return NormalizedEvent(
            ts       = time.time(),
            source   = source,
            category = "unknown",
            action   = "unknown",
            outcome  = "unknown",
            message  = raw[:500],
            raw      = raw,
            fields   = {"parse_failure": reason},
        )

    def _ensure_minimum_fields(self, evt: NormalizedEvent,
                                raw: str, source: str) -> NormalizedEvent:
        """
        Zorunlu minimum alan seti:
          ts, source, category, action, outcome, message
        Bunlardan herhangi biri eksikse güvenli varsayılanı koy.
        """
        if not evt.ts or evt.ts == 0.0:
            evt.ts = time.time()
        if not evt.source:
            evt.source = source
        if not evt.category:
            evt.category = "unknown"
        if not evt.action:
            evt.action = "unknown"
        if not evt.outcome:
            evt.outcome = "unknown"
        if not evt.message:
            evt.message = raw[:200]
        return evt

    def normalize_batch(self, lines: List[str], source: str = "syslog") -> List[NormalizedEvent]:
        events = []
        for line in lines:
            evt = self.normalize(line, source)
            if evt:
                events.append(evt)
        return events

    def stats(self) -> Dict[str, int]:
        return self._stats.copy()


# ── Test ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    n = Normalizer()

    test_lines = [
        ("Mar  5 12:34:56 myhost sshd[1234]: Accepted password for root from 192.168.1.100 port 22345 ssh2", "auth.log"),
        ("Mar  5 12:35:00 myhost sshd[1235]: Failed password for admin from 10.0.0.1 port 54321 ssh2", "auth.log"),
        ("Mar  5 12:35:30 myhost sudo[999]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash", "auth.log"),
        ("Mar  5 12:36:00 myhost sshd[1236]: Invalid user testuser from 192.168.1.200", "auth.log"),
        ("type=EXECVE msg=audit(1234567890.123:456): argc=2 a0=\"/bin/bash\" a1=\"-c\"", "auditd"),
    ]

    print("\n=== Normalize Test ===\n")
    for raw, src in test_lines:
        evt = n.normalize(raw, src)
        if evt:
            print(f"[{evt.category}] {evt.action} | user={evt.user} ip={evt.src_ip} outcome={evt.outcome}")
            print(f"  → {evt.message[:80]}\n")

    print(f"Stats: {n.stats()}")
