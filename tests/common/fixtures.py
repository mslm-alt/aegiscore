"""
tests/common/fixtures.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Shared fixtures and helper functions used across all distros.
"""

import time
from typing import Optional


class FakeEvent:
    """Minimal mock used in tests instead of NormalizedEvent."""

    def __init__(
        self,
        user:     str = "alice",
        src_ip:   str = "10.0.0.1",
        action:   str = "ssh_login",
        outcome:  str = "success",
        process:  str = "sshd",
        source:   str = "auth_log",
        category: str = "auth",
        host:     str = "server01",
        ts:       Optional[float] = None,
        fields:   Optional[dict] = None,
        raw:      str = "",
        pid:      int = 0,
        message:  str = "",
        distro_family: str = "debian",
    ):
        self.user     = user
        self.src_ip   = src_ip
        self.action   = action
        self.outcome  = outcome
        self.process  = process
        self.source   = source
        self.category = category
        self.host     = host
        self.ts       = ts or time.time()
        self.fields   = fields or {}
        self.raw      = raw
        self.pid      = pid
        self.message  = message
        self.distro_family = distro_family


# ── Shared log line samples ─────────────────────────────────────────────────

SSH_LOGIN_OK   = "Mar  5 09:00:00 server01 sshd[100]: Accepted password for alice from 10.0.0.1 port 22345 ssh2"
SSH_LOGIN_FAIL = "Mar  5 09:00:00 server01 sshd[101]: Failed password for root from 185.220.101.5 port 11111 ssh2"
SUDO_OK        = "Mar  5 09:05:00 server01 sudo[102]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls"

UFW_BLOCK = (
    "Mar  5 10:00:00 server01 kernel: [UFW BLOCK] IN=eth0 OUT= "
    "SRC=185.220.101.5 DST=192.168.1.1 LEN=60 PROTO=TCP SPT=54321 DPT=22 WINDOW=65535"
)

APACHE_ATTACK = (
    '192.168.1.200 - - [05/Mar/2026:23:00:00 +0300] '
    '"GET /admin/../../../etc/passwd HTTP/1.1" 404 512 "-" "nikto/2.1"'
)


def make_ssh_brute(ip: str = "185.220.101.5", count: int = 5) -> list:
    """Build SSH brute-force log lines."""
    lines = []
    for i in range(count):
        lines.append(
            f"Mar  5 23:01:0{i} server01 sshd[{200+i}]: "
            f"Failed password for root from {ip} port {11111+i} ssh2"
        )
    return lines
