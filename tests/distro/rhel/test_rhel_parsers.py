"""
tests/distro/rhel/test_rhel_parsers.py
Parser tests specific to the RHEL/CentOS/Rocky/AlmaLinux family.

Run:
    pytest tests/distro/rhel/ -v
"""

import sys
import time
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.normalize import Normalizer, RHELSecureParser, DnfParser, AuditdParser
from core.detection import DetectionEngine


@pytest.fixture
def normalizer_rhel():
    return Normalizer(distro_family="rhel")

@pytest.fixture
def secure_parser():
    return RHELSecureParser()

@pytest.fixture
def dnf_parser():
    return DnfParser()

@pytest.fixture
def auditd_parser():
    return AuditdParser()


@pytest.fixture
def detection_rhel():
    return DetectionEngine(
        config={"rules_dir": "rules", "rules_source": "yaml"},
        allow_empty_rules=True,
        distro_family="rhel",
    )


class TestRHELSecureParser:

    def test_ssh_accepted(self, secure_parser):
        line = "Mar  5 12:34:56 server01 sshd[1234]: Accepted password for alice from 10.0.0.1 port 22345 ssh2"
        evt = secure_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "ssh_login"
        assert evt.outcome == "success"
        assert evt.user == "alice"
        assert evt.src_ip == "10.0.0.1"

    def test_ssh_failed(self, secure_parser):
        line = "Mar  5 12:34:56 server01 sshd[1234]: Failed password for root from 185.220.101.5 port 11111 ssh2"
        evt = secure_parser.parse_line(line)
        assert evt is not None
        assert evt.outcome == "failure"
        assert evt.user == "root"
        assert evt.fields.get("invalid_user") is None

    def test_ssh_invalid_user_failed_password_marks_rhel_invalid_field(self, normalizer_rhel):
        line = (
            "Mar  5 12:34:56 localhost.localdomain sshd[1234]: "
            "Failed password for invalid user invaliduser_4 from 192.168.91.129 port 51111 ssh2"
        )
        evt = normalizer_rhel.normalize(line, "auth_log")

        assert evt is not None
        assert evt.distro_family == "rhel"
        assert evt.action == "ssh_login"
        assert evt.outcome == "failure"
        assert evt.user == "invaliduser_4"
        assert evt.src_ip == "192.168.91.129"
        assert evt.fields.get("invalid_user") is True

    def test_sudo_success(self, secure_parser):
        line = "Mar  5 12:34:56 server01 sudo[500]: alice : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash"
        evt = secure_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "sudo"
        assert evt.user == "alice"

    def test_invalid_returns_none(self, secure_parser):
        assert secure_parser.parse_line("") is None

    def test_faillock_lock(self, secure_parser):
        line = "Mar  5 12:34:56 server01 sshd[1234]: pam_faillock(sshd:auth): Consecutive login failures for user root account temporarily locked"
        evt = secure_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "account_locked"
        assert evt.outcome == "failure"
        assert evt.user == "root"
        assert evt.fields.get("auth_mechanism") == "faillock"

    def test_sssd_auth_fail(self, secure_parser):
        line = "Mar  5 12:34:56 server01 sshd[1234]: pam_sss(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice"
        evt = secure_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "identity_login"
        assert evt.outcome == "failure"
        assert evt.user == "alice"
        assert evt.fields.get("auth_mechanism") == "sssd"
        assert evt.fields["identity"]["service"] == "sshd"

    def test_winbind_auth_fail(self, secure_parser):
        line = "Mar  5 12:34:56 server01 sshd[1234]: pam_winbind(sshd:auth): request failed, NT_STATUS_LOGON_FAILURE for user 'EXAMPLE\\\\alice'"
        evt = secure_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "identity_login"
        assert evt.outcome == "failure"
        assert evt.user == r"EXAMPLE\\alice"
        assert evt.fields.get("auth_mechanism") == "winbind"
        assert evt.fields["identity"]["domain"] == "EXAMPLE"

    def test_sssd_auth_success(self, secure_parser):
        line = "Mar  5 12:34:57 server01 sshd[1234]: pam_sss(sshd:auth): authentication success; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice"
        evt = secure_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "identity_login"
        assert evt.outcome == "success"
        assert evt.fields["identity"]["account"] == "alice"

    def test_winbind_account_policy(self, secure_parser):
        line = "Mar  5 12:34:58 server01 sshd[1234]: pam_winbind(sshd:account): request failed, NT_STATUS_ACCOUNT_DISABLED for user 'EXAMPLE\\\\alice'"
        evt = secure_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "account_policy"
        assert evt.outcome == "failure"
        assert evt.fields["identity"]["policy"] == "account_disabled"


class TestDnfParser:

    def test_install_package(self, dnf_parser):
        line = "2026-03-05T14:30:00+0000 INFO Installed: curl-7.76.1.x86_64"
        evt = dnf_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "pkg_install"

    def test_install_attack_tool(self, dnf_parser):
        line = "2026-03-05T14:30:00+0000 INFO Installed: nmap-7.93.x86_64"
        evt = dnf_parser.parse_line(line)
        assert evt is not None
        # nmap is dual-use; action should stay pkg_install and fields["dual_use"]=True
        assert evt.action == "pkg_install"
        assert evt.fields.get("dual_use") is True

    def test_install_pure_attack_tool(self, dnf_parser):
        """Pure attack tools like hydra must still map to attack_tool_installed."""
        line = "2026-03-05T14:30:00+0000 INFO Installed: hydra-9.4.x86_64"
        evt = dnf_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "attack_tool_installed"

    def test_timestamp_no_crash(self, dnf_parser):
        """Fix 12: a timestamp parse error must not crash."""
        line = "2026-03-05T14:30:00+0000 INFO Installed: curl-7.76.1.x86_64"
        evt = dnf_parser.parse_line(line)
        assert evt is not None
        assert evt.ts > 0

    def test_timestamp_with_plus_offset(self, dnf_parser):
        """Fix 12: the +HH:MM offset must be trimmed correctly."""
        line = "2026-03-15T08:30:00+0300 INFO Installed: python3-7.9.x86_64"
        evt = dnf_parser.parse_line(line)
        assert evt is not None
        assert evt.ts > 0

    def test_remove_security_tool(self, dnf_parser):
        line = "2026-03-05T14:30:00+0000 INFO Erased: auditd-3.0.7.x86_64"
        evt = dnf_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "security_tool_removed"

    def test_command_line_is_rhel_dnf_package_event(self, dnf_parser):
        line = "2026-05-10T22:30:00+0300 INFO Command: dnf install -y htop"
        evt = dnf_parser.parse_line(line)

        assert evt is not None
        assert evt.source == "dnf"
        assert evt.category == "process"
        assert evt.action == "pkg_event"
        assert evt.outcome == "success"
        assert evt.fields.get("package_manager") == "dnf"
        assert evt.fields.get("cmdline") == "dnf install -y htop"

    @pytest.mark.parametrize(
        "line",
        [
            "2026-05-10T22:30:01+0300 ERROR No match for argument: htop",
            "2026-05-10T22:30:02+0300 ERROR Error: Unable to find a match: htop",
            "2026-05-10T22:30:03+0300 ERROR Argüman için eşleşme yok: \x1B[1maegiscore-nonexistent-package-xyz\x1B(B\x1B[m",
            "2026-05-10T22:30:04+0300 ERROR Hata: Bir eşleşme bulunamadı: aegiscore-nonexistent-package-xyz",
            "No match for argument: htop",
            "Error: Unable to find a match: htop",
            "Argüman için eşleşme yok: \x1B[1maegiscore-nonexistent-package-xyz\x1B(B\x1B[m",
            "Hata: Bir eşleşme bulunamadı: aegiscore-nonexistent-package-xyz",
        ],
    )
    def test_failed_install_attempts_are_failures(self, dnf_parser, line):
        evt = dnf_parser.parse_line(line)

        assert evt is not None
        assert evt.source == "dnf"
        assert evt.action == "pkg_event"
        assert evt.outcome == "failure"
        assert evt.fields.get("package_error") is True
        assert "\x1B" not in evt.message

    @pytest.mark.parametrize(
        "line,expected_action",
        [
            ("2026-03-05T14:30:00+0000 INFO Installed: curl-7.76.1.x86_64", "pkg_install"),
            ("2026-03-05T14:30:00+0000 INFO Upgraded: curl-7.76.1.x86_64", "pkg_install"),
            ("2026-03-05T14:30:00+0000 INFO Erased: curl-7.76.1.x86_64", "pkg_remove"),
        ],
    )
    def test_successful_dnf_package_operations_remain_success(self, dnf_parser, line, expected_action):
        evt = dnf_parser.parse_line(line)

        assert evt is not None
        assert evt.source == "dnf"
        assert evt.action == expected_action
        assert evt.outcome == "success"

    def test_invalid_returns_none(self, dnf_parser):
        assert dnf_parser.parse_line("") is None
        assert dnf_parser.parse_line("unrelated garbage") is None

    def test_yum_command_remove_parses_as_pkg_event(self, dnf_parser):
        line = "2026-05-10T22:30:00+0300 INFO Command: yum remove auditd -y"
        evt = dnf_parser.parse_line(line)

        assert evt is not None
        assert evt.action == "pkg_event"
        assert evt.fields.get("cmdline") == "yum remove auditd -y"
        assert evt.process == "yum"


class TestAuditdParserRHEL:

    def test_mac_status_selinux_disabled(self, auditd_parser):
        """Fix 14: MAC_STATUS enforcing=0 → selinux_disabled."""
        line = 'type=MAC_STATUS msg=audit(1234567890.001:100): enforcing=0 old_enforcing=1 auid=0'
        evt = auditd_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "selinux_disabled"
        assert evt.category == "system"

    def test_mac_status_selinux_enabled(self, auditd_parser):
        line = 'type=MAC_STATUS msg=audit(1234567890.001:100): enforcing=1 old_enforcing=0 auid=0'
        evt = auditd_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "selinux_enabled"


class TestNormalizerRHEL:

    def test_auth_log_uses_rhel_parser(self, normalizer_rhel):
        """Fix 10: auth_log source → RHELSecureParser must be used on RHEL."""
        line = "Mar  5 12:34:56 server01 sshd[1234]: Accepted password for alice from 10.0.0.1 port 22345 ssh2"
        evt = normalizer_rhel.normalize(line, "auth_log")
        assert evt is not None
        assert evt.action == "ssh_login"
        assert evt.user == "alice"

    def test_dpkg_source_uses_dnf_parser(self, normalizer_rhel):
        """Fix 11: dpkg source → DnfParser must be used on RHEL."""
        line = "2026-03-05T14:30:00+0000 INFO Installed: nmap-7.93.x86_64"
        evt = normalizer_rhel.normalize(line, "dpkg")
        assert evt is not None
        assert evt.source == "dnf"
        # nmap dual-use; pkg_install + dual_use=True
        assert evt.action == "pkg_install"
        assert evt.fields.get("dual_use") is True

    def test_dpkg_source_command_uses_dnf_source_name_on_rhel(self, normalizer_rhel):
        line = "2026-05-10T22:30:00+0300 INFO Command: dnf install -y htop"
        evt = normalizer_rhel.normalize(line, "dpkg")

        assert evt is not None
        assert evt.source == "dnf"
        assert evt.action == "pkg_event"
        assert evt.fields.get("cmdline") == "dnf install -y htop"

    def test_rhel_invalid_user_failed_password_emits_auth003_not_auth002(
        self,
        normalizer_rhel,
        detection_rhel,
    ):
        line = (
            "Mar  5 12:34:56 localhost.localdomain sshd[1234]: "
            "Failed password for invalid user invaliduser_4 from 192.168.91.129 port 51111 ssh2"
        )
        evt = normalizer_rhel.normalize(line, "auth_log")
        hits = {result.rule_id for result in detection_rhel.analyze(evt)}

        assert "AUTH-003" in hits
        assert "AUTH-002" not in hits

    def test_rhel_pam_unknown_summary_during_invalid_burst_skips_auth002(
        self,
        normalizer_rhel,
        detection_rhel,
    ):
        line = (
            "Mar  5 12:34:57 localhost.localdomain sshd[1234]: "
            "PAM 2 more authentication failures; logname= uid=0 euid=0 "
            "tty=ssh ruser= rhost=192.168.91.129"
        )
        evt = normalizer_rhel.normalize(line, "journald")
        hits = {result.rule_id for result in detection_rhel.analyze(evt)}

        assert evt.distro_family == "rhel"
        assert evt.action == "ssh_login"
        assert evt.outcome == "failure"
        assert evt.user == "unknown"
        assert evt.src_ip == "192.168.91.129"
        assert "AUTH-002" not in hits

    def test_rhel_valid_user_failed_password_still_emits_auth002(
        self,
        normalizer_rhel,
        detection_rhel,
    ):
        line = (
            "Mar  5 12:35:56 localhost.localdomain sshd[1235]: "
            "Failed password for rocky from 192.168.91.129 port 51112 ssh2"
        )
        evt = normalizer_rhel.normalize(line, "auth_log")
        hits = {result.rule_id for result in detection_rhel.analyze(evt)}

        assert "AUTH-002" in hits
        assert "AUTH-003" not in hits

    def test_rhel_invalid_user_burst_keeps_threshold_signals(
        self,
        normalizer_rhel,
        detection_rhel,
    ):
        hits = set()
        for idx in range(20):
            line = (
                f"Mar  5 12:36:{idx:02d} localhost.localdomain sshd[{2000 + idx}]: "
                f"Failed password for invalid user invaliduser_{idx} "
                f"from 192.168.91.129 port {52000 + idx} ssh2"
            )
            evt = normalizer_rhel.normalize(line, "auth_log")
            hits.update(result.rule_id for result in detection_rhel.analyze(evt))

        assert "AUTH-002" not in hits
        assert {"AUTH-003", "THR-001", "THR-003", "THR-004", "THR-005"}.issubset(hits)

    def test_rhel_syslog_dns_line_still_hits_dns_rules_when_messages_shared(self, normalizer_rhel, detection_rhel):
        line = (
            "Apr  8 12:00:00 rhel-node named[123]: client @0x7f 192.0.2.70#53000 "
            "(aaaaaaaaaabbbbbbbbbbcccccccccc.payloadsegment123456789.control.example.com): "
            "query: aaaaaaaaaabbbbbbbbbbcccccccccc.payloadsegment123456789.control.example.com IN TXT +"
        )
        evt = normalizer_rhel.normalize(line, "syslog")

        assert evt is not None
        assert evt.action == "dns_query"
        hits = {result.rule_id for result in detection_rhel.analyze(evt)}
        assert "DNS-007" in hits

    def test_rhel_repo_config_tamper_alerts_pkg_014(self, normalizer_rhel, detection_rhel):
        line = 'type=PATH msg=audit(1710000000.000:88): item=0 name="/etc/yum.repos.d/evil.repo" nametype=CREATE oflags=0x1 comm="vim" exe="/usr/bin/vim"'
        evt = normalizer_rhel.normalize(line, "auditd")

        assert evt is not None
        assert evt.action == "sensitive_file_access"
        hits = {result.rule_id for result in detection_rhel.analyze(evt)}
        assert "PKG-014" in hits

    def test_rhel_messages_sudo_auditd_stop_still_alerts_defense_evasion(self, normalizer_rhel, detection_rhel):
        line = (
            "Mar  5 12:34:56 server01 sudo[500]: alice : TTY=pts/0 ; PWD=/root ; USER=root ; "
            "COMMAND=systemctl stop auditd"
        )
        evt = normalizer_rhel.normalize(line, "syslog")

        assert evt is not None
        hits = {result.rule_id for result in detection_rhel.analyze(evt)}
        assert hits & {"DE-002", "DE-017"}


class TestPostgreSQLRHEL:

    def test_postgresql_pg_hba_reject_normalized_and_alerts(self, normalizer_rhel, detection_rhel):
        line = (
            '2026-05-10 13:43:13.786 +03 rhel-db postgres[14421]: '
            'FATAL:  no pg_hba.conf entry for host "198.51.100.90", '
            'user "postgres", database "appdb", SSL encryption'
        )
        evt = normalizer_rhel.normalize(line, "postgresql")

        assert evt is not None
        assert evt.source == "postgresql"
        assert evt.action == "db_hba_reject"
        assert evt.src_ip == "198.51.100.90"
        hits = {result.rule_id for result in detection_rhel.analyze(evt)}
        assert "DB-003" in hits


class TestRHELFirewallCoverage:

    def test_firewalld_exit_normalized_and_alerts_fw_002(self, normalizer_rhel, detection_rhel):
        line = '{"__REALTIME_TIMESTAMP":"1710000000000000","_HOSTNAME":"rhel-node","_COMM":"firewalld","_PID":"910","MESSAGE":"exiting"}'
        evt = normalizer_rhel.normalize(line, "journald")

        assert evt is not None
        assert evt.action == "firewalld_stopped"
        assert evt.fields.get("firewall_control") == "stop"
        hits = {result.rule_id for result in detection_rhel.analyze(evt)}
        assert "FW-002" in hits
