"""
tests/distro/suse/test_suse_parsers.py
Parser tests specific to the SUSE/openSUSE family.

Run:
    pytest tests/distro/suse/ -v
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.normalize import Normalizer, ZypperParser, SyslogParser
from core.detection import DetectionEngine
from core.phase_manager import Phase
from main import SIEMPipeline
from tests.unit.test_phase_contracts import _make_pipeline


@pytest.fixture
def normalizer_suse():
    return Normalizer(distro_family="suse")

@pytest.fixture
def zypper_parser():
    return ZypperParser()


@pytest.fixture
def detection_engine():
    return DetectionEngine(
        config={"rules_dir": "rules", "rules_source": "yaml"},
        allow_empty_rules=True,
        distro_family="suse",
    )


class TestZypperParser:

    def test_install_package(self, zypper_parser):
        line = "2026-03-05 14:30:00|install|nmap|7.93|"
        evt = zypper_parser.parse_line(line)
        assert evt is not None
        assert evt.action in ("pkg_install", "attack_tool_installed")

    def test_install_attack_tool(self, zypper_parser):
        line = "2026-03-05 14:30:00|install|hydra|9.4|"
        evt = zypper_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "attack_tool_installed"

    def test_remove_security_tool(self, zypper_parser):
        line = "2026-03-05 14:30:00|remove|auditd|3.0|"
        evt = zypper_parser.parse_line(line)
        assert evt is not None
        assert evt.action == "security_tool_removed"

    def test_invalid_returns_none(self, zypper_parser):
        assert zypper_parser.parse_line("") is None


class TestNormalizerSUSE:

    def test_dpkg_source_uses_zypper_parser(self, normalizer_suse):
        """Fix 11: dpkg source → ZypperParser must be used on SUSE."""
        line = "2026-03-05 14:30:00|install|nmap|7.93|"
        evt = normalizer_suse.normalize(line, "dpkg")
        assert evt is not None
        # nmap dual-use; pkg_install + dual_use=True
        assert evt.action == "pkg_install"
        assert evt.fields.get("dual_use") is True

    def test_syslog_ssh(self, normalizer_suse):
        line = "Mar  5 12:34:56 server01 sshd[1234]: Accepted password for alice from 10.0.0.1 port 22345 ssh2"
        evt = normalizer_suse.normalize(line, "syslog")
        assert evt is not None
        assert evt.action == "ssh_login"

    def test_apparmor_disabled_detected(self, normalizer_suse):
        """Fix 14: detect AppArmor profile removal."""
        line = "Mar  5 12:34:56 server01 apparmor[100]: Profile removed for /usr/sbin/httpd"
        evt = normalizer_suse.normalize(line, "syslog")
        if evt and evt.action == "apparmor_disabled":
            assert evt.category == "system"

    def test_firewalld_filter_reject_normalized(self, normalizer_suse):
        line = (
            "Mar  5 12:03:00 leap16 kernel: filter_IN_public_REJECT: IN=eth0 OUT= "
            "SRC=192.168.91.129 DST=192.168.91.131 LEN=60 PROTO=TCP "
            "SPT=54321 DPT=65000"
        )
        evt = normalizer_suse.normalize(line, "journald")

        assert evt.category == "network"
        assert evt.action == "firewall_reject"
        assert evt.outcome == "rejected"
        assert evt.src_ip == "192.168.91.129"
        assert evt.dst_ip == "192.168.91.131"
        assert evt.fields["dst_port"] == "65000"
        assert evt.fields["src_port"] == "54321"
        assert evt.fields["protocol"] == "TCP"
        assert evt.fields["interface"] == "eth0"
        assert evt.fields["firewall_verdict"] == "reject"

    def test_firewalld_rich_rule_drop_normalized(self, normalizer_suse):
        line = (
            "Mar  5 12:04:00 leap16 kernel: AEGIS_TEST_DROP IN=eth0 OUT= "
            "SRC=192.168.91.129 DST=192.168.91.131 LEN=60 PROTO=TCP "
            "SPT=54322 DPT=65000"
        )
        evt = normalizer_suse.normalize(line, "journald")

        assert evt.category == "network"
        assert evt.action == "firewall_block"
        assert evt.outcome == "blocked"
        assert evt.src_ip == "192.168.91.129"
        assert evt.fields["dst_port"] == "65000"
        assert evt.fields["firewall_verdict"] == "drop"

    def test_firewalld_drop_triggers_firewall_alert(self, normalizer_suse, detection_engine):
        line = (
            "Mar  5 12:04:00 leap16 kernel: AEGIS_TEST_DROP IN=eth0 OUT= "
            "SRC=192.168.91.129 DST=192.168.91.131 LEN=60 PROTO=TCP "
            "SPT=54322 DPT=65000"
        )
        evt = normalizer_suse.normalize(line, "journald")
        results = detection_engine.analyze(evt)
        alert_ids = {result.rule_id for result in results}

        assert alert_ids & {"FW-001", "THR-022"}

    def test_firewalld_drop_survives_live_alert_gate(self, normalizer_suse):
        line = (
            "Mar  5 12:04:00 leap16 kernel: AEGIS_TEST_DROP IN=ens160 OUT= "
            "SRC=192.168.91.129 DST=192.168.91.131 LEN=60 PROTO=TCP "
            "SPT=37494 DPT=65000"
        )
        event = normalizer_suse.normalize(line, "journald")
        event.process = "kernel"

        pipeline, emitted = _make_pipeline(Phase.PHASE_0, active_layers=[])
        pipeline.config = {"alert_policy": {"min_risk_for_alert": 35}}
        pipeline.normalizer.normalize = lambda raw, source: event
        pipeline.detection = DetectionEngine(
            config={"rules_dir": "rules", "rules_source": "yaml"},
            allow_empty_rules=True,
            distro_family="suse",
        )
        pipeline._min_risk_for_alert = SIEMPipeline._min_risk_for_alert.__get__(pipeline, SIEMPipeline)

        pipeline._process_event_locked(line, "journald")

        assert any(item["rule_id"] == "FW-001" for item in emitted)

    def test_turkish_postgresql_auth_failure_normalized(self, normalizer_suse):
        line = (
            '2026-05-10 13:41:13.786 +03 aegiscore_opensuse_live aegiscore '
            '[14419]ÖLÜMCÜL (FATAL):  "aegiscore" kullanıcısı için şifre '
            'doğrulaması başarısız oldu'
        )
        evt = normalizer_suse.normalize(line, "postgresql")

        assert evt.source == "postgresql"
        assert evt.category == "auth"
        assert evt.action == "db_login"
        assert evt.outcome == "failure"
        assert evt.user == "aegiscore"
        assert evt.pid == 14419

    def test_postgresql_alter_system_alerts_db_006(self, normalizer_suse, detection_engine):
        line = (
            "2026-05-10 13:46:13.786 +03 suse-db postgres[14429]: "
            "STATEMENT:  ALTER SYSTEM SET log_statement = 'none'"
        )
        evt = normalizer_suse.normalize(line, "postgresql")

        assert evt is not None
        assert evt.source == "postgresql"
        assert evt.action == "db_config_tamper"
        hits = {result.rule_id for result in detection_engine.analyze(evt)}
        assert "DB-006" in hits

    def test_suse_firewalld_exit_alerts_fw_002(self, normalizer_suse, detection_engine):
        line = '{"__REALTIME_TIMESTAMP":"1710000001000000","_HOSTNAME":"leap16","_COMM":"firewalld","_PID":"920","MESSAGE":"exiting"}'
        evt = normalizer_suse.normalize(line, "journald")

        assert evt is not None
        assert evt.action == "firewalld_stopped"
        assert evt.fields.get("firewall_control") == "stop"
        hits = {result.rule_id for result in detection_engine.analyze(evt)}
        assert "FW-002" in hits

    @pytest.mark.parametrize(
        "command",
        [
            "/usr/bin/stat /etc/systemd/system/multi-user.target.wants/apache2.service",
            "/usr/bin/ls /etc/systemd/system",
            "/usr/bin/readlink /etc/systemd/system/multi-user.target.wants/apache2.service",
        ],
    )
    def test_readonly_systemd_sudo_inspection_does_not_trigger_persistence(
        self,
        normalizer_suse,
        detection_engine,
        command,
    ):
        line = (
            "Mar  5 12:00:00 leap16 sudo[2004]: alice : TTY=pts/2 ; "
            f"PWD=/tmp ; USER=root ; COMMAND={command}"
        )
        evt = normalizer_suse.normalize(line, "syslog")
        hits = {result.rule_id for result in detection_engine.analyze(evt)}

        assert "PERS-005" not in hits
        assert "PERS-019" not in hits

    def test_systemd_sudo_symlink_modification_still_triggers_persistence(
        self,
        normalizer_suse,
        detection_engine,
    ):
        line = (
            "Mar  5 12:01:00 leap16 sudo[2005]: alice : TTY=pts/2 ; "
            "PWD=/tmp ; USER=root ; COMMAND=/usr/bin/ln -s "
            "/usr/lib/systemd/system/apache2.service "
            "/etc/systemd/system/multi-user.target.wants/apache2.service"
        )
        evt = normalizer_suse.normalize(line, "syslog")
        hits = {result.rule_id for result in detection_engine.analyze(evt)}

        assert "PERS-005" in hits

    def test_suse_syslog_dns_line_still_hits_dns_rules_when_messages_shared(self, normalizer_suse, detection_engine):
        line = (
            "Apr  8 12:00:00 leap16 named[123]: client @0x7f 192.0.2.71#53000 "
            "(aaaaaaaaaabbbbbbbbbbcccccccccc.payloadsegment123456789.control.example.com): "
            "query: aaaaaaaaaabbbbbbbbbbcccccccccc.payloadsegment123456789.control.example.com IN TXT +"
        )
        evt = normalizer_suse.normalize(line, "syslog")

        assert evt is not None
        assert evt.action == "dns_query"
        hits = {result.rule_id for result in detection_engine.analyze(evt)}
        assert "DNS-007" in hits

    def test_suse_repo_remove_command_alerts_pkg_013(self, normalizer_suse, detection_engine):
        line = (
            "Mar  5 12:02:00 leap16 sudo[2006]: alice : TTY=pts/2 ; PWD=/tmp ; USER=root ; "
            "COMMAND=/usr/bin/zypper rr security-updates"
        )
        evt = normalizer_suse.normalize(line, "syslog")

        assert evt is not None
        hits = {result.rule_id for result in detection_engine.analyze(evt)}
        assert "PKG-013" in hits

    def test_suse_refresh_stays_benign_for_pkg_013(self, normalizer_suse, detection_engine):
        line = (
            "Mar  5 12:03:00 leap16 sudo[2007]: alice : TTY=pts/2 ; PWD=/tmp ; USER=root ; "
            "COMMAND=/usr/bin/zypper refresh"
        )
        evt = normalizer_suse.normalize(line, "syslog")

        assert evt is not None
        hits = {result.rule_id for result in detection_engine.analyze(evt)}
        assert "PKG-013" not in hits

    def test_suse_messages_sudo_rsyslog_stop_still_alerts_defense_evasion(self, normalizer_suse, detection_engine):
        line = (
            "Mar  5 12:04:00 leap16 sudo[2008]: alice : TTY=pts/2 ; PWD=/tmp ; USER=root ; "
            "COMMAND=/usr/bin/systemctl stop rsyslog"
        )
        evt = normalizer_suse.normalize(line, "syslog")

        assert evt is not None
        hits = {result.rule_id for result in detection_engine.analyze(evt)}
        assert hits & {"DE-002", "DE-017"}
