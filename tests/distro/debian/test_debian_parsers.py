"""
tests/distro/debian/test_debian_parsers.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Parser tests specific to the Debian/Ubuntu family.

Run:
    pytest tests/distro/debian/ -v
"""

import sys
import time
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.normalize import Normalizer, DpkgParser, SyslogParser
from core.detection import DetectionEngine


@pytest.fixture
def normalizer():
    return Normalizer(distro_family="debian")


@pytest.fixture
def dpkg():
    return DpkgParser()


@pytest.fixture
def detection_debian():
    return DetectionEngine(
        config={"rules_dir": "rules", "rules_source": "yaml"},
        allow_empty_rules=True,
        distro_family="debian",
    )


class TestDebianAuthLog:
    """auth.log parser — Debian format."""

    def test_ssh_accepted(self, normalizer):
        raw = "Mar  5 09:00:00 server01 sshd[100]: Accepted password for alice from 10.0.0.1 port 22345 ssh2"
        evt = normalizer.normalize(raw, "auth_log")
        assert evt is not None
        assert evt.action  == "ssh_login"
        assert evt.outcome == "success"
        assert evt.user    == "alice"
        assert evt.src_ip  == "10.0.0.1"

    def test_ssh_failed(self, normalizer):
        raw = "Mar  5 09:00:00 server01 sshd[101]: Failed password for root from 1.2.3.4 port 11111 ssh2"
        evt = normalizer.normalize(raw, "auth_log")
        assert evt is not None
        assert evt.action  in ("ssh_fail", "ssh_login")
        assert evt.outcome == "failure"
        assert evt.user    == "root"
        assert evt.src_ip  == "1.2.3.4"

    def test_sudo_success(self, normalizer):
        raw = "Mar  5 09:05:00 server01 sudo[102]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls"
        evt = normalizer.normalize(raw, "auth_log")
        assert evt is not None
        assert evt.action == "sudo"
        assert evt.user   == "alice"


class TestDebianDpkg:
    """dpkg.log parser."""

    def test_install(self, dpkg):
        raw = "2026-03-05 10:00:00 install nmap:amd64 <none> 7.93"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "package_install"
        assert evt.fields.get("package_name") == "nmap"
        assert evt.fields.get("arch") == "amd64"
        assert evt.fields.get("old_version") == "<none>"
        assert evt.fields.get("new_version") == "7.93"

    def test_remove(self, dpkg):
        raw = "2026-03-05 10:05:00 remove ufw:amd64 0.36 <none>"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "package_remove"
        assert evt.fields.get("package_name") == "ufw"
        assert evt.fields.get("dpkg_operation") == "remove"

    def test_upgrade(self, dpkg):
        raw = "2026-03-05 10:15:00 upgrade openssl:amd64 3.0.2 3.0.2-0ubuntu1.16"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "package_upgrade"
        assert evt.fields.get("package_name") == "openssl"
        assert evt.fields.get("old_version") == "3.0.2"
        assert evt.fields.get("new_version") == "3.0.2-0ubuntu1.16"

    def test_status(self, dpkg):
        raw = "2026-03-05 10:16:00 status installed openssl:amd64 3.0.2-0ubuntu1.16"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "package_status"
        assert evt.fields.get("package_name") == "openssl"
        assert evt.fields.get("dpkg_status") == "installed"
        assert evt.fields.get("version") == "3.0.2-0ubuntu1.16"

    def test_startup(self, dpkg):
        raw = "2026-03-05 10:17:00 startup archives unpack"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "package_startup"
        assert evt.fields.get("dpkg_operation") == "archives"
        assert evt.fields.get("startup_detail") == "unpack"

    def test_trigger(self, dpkg):
        raw = "2026-03-05 10:18:00 trigproc libc-bin:amd64 2.39-0ubuntu8"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "package_trigger"
        assert evt.fields.get("package_name") == "libc-bin"
        assert evt.fields.get("arch") == "amd64"
        assert evt.fields.get("version") == "2.39-0ubuntu8"

    def test_trigger_with_none_tail(self, dpkg):
        raw = "2026-03-05 10:19:00 trigproc man-db:amd64 2.12.0-4build2 <none>"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "package_trigger"
        assert evt.fields.get("package_name") == "man-db"
        assert evt.fields.get("arch") == "amd64"
        assert evt.fields.get("version") == "2.12.0-4build2"
        assert evt.fields.get("dpkg_operation") == "trigproc"

    def test_apt_installed_style_line(self, dpkg):
        raw = "Mar  5 10:20:00 web-srv apt[4100]: Installed: openssl (3.0.2-0ubuntu1.15)"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "package_install"
        assert evt.fields.get("package_name") == "openssl"

    def test_apt_removed_style_line(self, dpkg):
        raw = "Mar  5 10:21:00 web-srv apt[4100]: Removed: ufw (0.36)"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "package_remove"
        assert evt.fields.get("package_name") == "ufw"

    def test_apt_history_commandline(self, dpkg):
        raw = "Commandline: apt-get update"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "exec"
        assert evt.process == "apt-get"
        assert evt.fields.get("cmdline") == "apt-get update"

    def test_apt_history_install_line(self, dpkg):
        raw = "Install: curl:amd64 (7.88.1-10ubuntu1)"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "package_install"
        assert evt.process == "apt-get"
        assert evt.fields.get("package_name") == "curl"

    def test_apt_history_remove_security_tool(self, dpkg):
        raw = "Remove: ufw:amd64 (0.36.2-1)"
        evt = dpkg.parse_line(raw)
        assert evt is not None
        assert evt.action == "package_remove"
        assert evt.process == "apt-get"
        assert evt.fields.get("package_name") == "ufw"

    def test_normalizer_routes_dpkg(self, normalizer):
        """Debian'da dpkg source DpkgParser'a gitmeli."""
        raw = "2026-03-05 10:00:00 install nmap:amd64 <none> 7.93"
        evt = normalizer.normalize(raw, "dpkg")
        assert evt is not None
        assert evt.action == "package_install"

    def test_normalizer_routes_dpkg_log_path(self, normalizer):
        raw = "Mar  5 10:20:00 web-srv apt[4100]: Installed: openssl (3.0.2-0ubuntu1.15)"
        evt = normalizer.normalize(raw, "/var/log/dpkg.log")
        assert evt is not None
        assert evt.action == "package_install"
        assert evt.source == "dpkg"


class TestDebianUFW:
    """ufw.log parser."""

    def test_ufw_block(self, normalizer):
        raw = (
            "Mar  5 10:00:00 server01 kernel: [UFW BLOCK] IN=eth0 OUT= "
            "SRC=185.220.101.5 DST=192.168.1.1 LEN=60 PROTO=TCP SPT=54321 DPT=22 WINDOW=65535"
        )
        evt = normalizer.normalize(raw, "ufw")
        assert evt is not None
        assert evt.category == "network"
        assert evt.src_ip   == "185.220.101.5"


class TestDebianDistroRouting:
    """Verify that the correct parsers are selected on Debian."""

    def test_dpkg_not_dnf(self, normalizer):
        """Debian'da dpkg source DnfParser'a gitmemeli."""
        raw = "2026-03-05 10:00:00 install nmap:amd64 <none> 7.93"
        evt = normalizer.normalize(raw, "dpkg")
        # DpkgParser should handle it, and source should be 'dpkg'
        assert evt is not None
        assert evt.source == "dpkg"

    def test_auth_log_not_rhel_parser(self, normalizer):
        """RHELSecureParser must not be used on Debian."""
        raw = "Mar  5 09:00:00 server01 sshd[100]: Accepted password for alice from 10.0.0.1 port 22345 ssh2"
        evt = normalizer.normalize(raw, "auth_log")
        # The normal syslog parser should handle it
        assert evt is not None
        assert evt.user == "alice"

    def test_syslog_dns_line_still_hits_dns_rules_when_dns_source_is_guarded(self, normalizer, detection_debian):
        raw = (
            "May 20 12:00:00 ubuntu-host systemd-resolved[200]: "
            "query: cache miss for qname IN TXT aaaaaaaaaabbbbbbbbbbcccccccccc.payloadsegment123456789.control.example.com"
        )
        evt = normalizer.normalize(raw, "syslog")

        assert evt is not None
        assert evt.action == "dns_query"
        hits = {result.rule_id for result in detection_debian.analyze(evt)}
        assert "DNS-007" in hits


class TestDebianApacheParser:
    """Ubuntu/Debian apache2 log parsing fixes."""

    def test_apache_error_ah10244(self, normalizer):
        raw = (
            "[Wed Mar 05 12:06:00.123456 2026] [core:error] "
            "[pid 1234:tid 140012345678912] [client 203.0.113.9:54444] "
            "AH10244: invalid URI path (/..%2f..%2fetc/passwd)"
        )
        evt = normalizer.normalize(raw, "apache2")
        assert evt is not None
        assert evt.action == "http_error"
        assert evt.outcome == "failure"
        assert evt.src_ip == "203.0.113.9"
        assert evt.pid == 1234
        assert evt.fields.get("module") == "core"
        assert evt.fields.get("severity") == "error"
        assert evt.fields.get("ah_code") == "AH10244"

    def test_apache_php_error(self, normalizer):
        raw = (
            "[Wed Mar 05 12:06:30.123456 2026] [php:error] "
            "[pid 1235] [client 198.51.100.7:60000] "
            "PHP Fatal error: Uncaught Error: Call to undefined function foo()"
        )
        evt = normalizer.normalize(raw, "apache2")
        assert evt is not None
        assert evt.action == "http_error"
        assert evt.src_ip == "198.51.100.7"
        assert evt.fields.get("module") == "php"
        assert evt.fields.get("severity") == "error"

    def test_apache_vhost_access(self, normalizer):
        raw = 'example.com:80 10.0.0.6 - - [05/Mar/2026:12:04:00 +0000] "GET / HTTP/1.1" 200 64 "-" "curl/8.0"'
        evt = normalizer.normalize(raw, "apache2")
        assert evt is not None
        assert evt.action == "http_request"
        assert evt.src_ip == "10.0.0.6"
        assert evt.fields.get("vhost") == "example.com:80"

    def test_apache_malformed_request_is_controlled(self, normalizer):
        raw = '10.0.0.7 - - [05/Mar/2026:12:05:00 +0000] "GET /wp-login.php?id=%27" 400 0 "-" "curl/8.0"'
        evt = normalizer.normalize(raw, "apache2")
        assert evt is not None
        assert evt.action == "http_request"
        assert evt.outcome == "failure"
        assert evt.fields.get("request_malformed") is True
        assert evt.fields.get("path") == "/wp-login.php?id=%27"
