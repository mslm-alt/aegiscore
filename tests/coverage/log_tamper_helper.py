import sys
import time
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.normalize import NormalizedEvent

from tests.coverage.credential_access_helper import CoverageScenario


def _auth_evt(
    ts,
    *,
    action="ssh_login",
    outcome="success",
    user="alice",
    host="tamper-host",
    src_ip="203.0.113.10",
    source="auth.log",
    distro_family="unknown",
):
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
        fields={},
        distro_family=distro_family,
    )


def _proc_evt(
    ts,
    cmdline,
    *,
    host="tamper-host",
    user="root",
    process=None,
    source="journald",
    action="process_exec",
    outcome="success",
    fields=None,
    distro_family="unknown",
):
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


def build_attack_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="auditd-stop",
            events=[_proc_evt(now + 1, "systemctl stop auditd", host="tamper-attack-01", process="systemctl")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="kill-stop-auditd",
            events=[_proc_evt(now + 2, "kill -STOP $(pidof auditd)", host="tamper-attack-02", process="kill")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="pkill-sigstop-auditd",
            events=[_proc_evt(now + 3, "pkill -SIGSTOP auditd", host="tamper-attack-03", process="pkill")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="killall-stop-rsyslog",
            events=[_proc_evt(now + 4, "killall -STOP rsyslogd", host="tamper-attack-04", process="killall")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="journald-stop-disable-mask",
            events=[_proc_evt(now + 5, "systemctl stop systemd-journald && systemctl disable systemd-journald && systemctl mask systemd-journald", host="tamper-attack-05", process="systemctl")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="auditctl-delete-rules",
            events=[_proc_evt(now + 6, "auditctl -D", host="tamper-attack-06", process="auditctl")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="auditctl-disable",
            events=[_proc_evt(now + 7, "auditctl -e 0", host="tamper-attack-07", process="auditctl")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="truncate-var-log",
            events=[_proc_evt(now + 8, "truncate -s 0 /var/log/auth.log", host="tamper-attack-08", process="truncate")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rm-var-log-journal",
            events=[_proc_evt(now + 9, "rm -rf /var/log/journal", host="tamper-attack-09", process="rm")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="journal-vacuum",
            events=[_proc_evt(now + 10, "journalctl --vacuum-time=1s", host="tamper-attack-10", process="journalctl")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="history-clear",
            events=[_proc_evt(now + 11, "history -c && unset HISTFILE", host="tamper-attack-11", user="alice", process="bash")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="disable-then-truncate-sequence",
            events=[
                _proc_evt(now + 20, "systemctl stop auditd", host="tamper-attack-12", process="systemctl"),
                _proc_evt(now + 25, "truncate -s 0 /var/log/auth.log && journalctl --vacuum-time=1s", host="tamper-attack-12", process="truncate"),
            ],
            expected_ids={"DE-017", "SEQ-049"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="login-then-history-clear",
            events=[
                _auth_evt(now + 40, host="tamper-attack-13", user="alice"),
                _proc_evt(now + 45, "history -c && unset HISTFILE", host="tamper-attack-13", user="alice", process="bash"),
            ],
            expected_ids={"DE-017", "SEQ-050"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="vpn-login-then-auditctl-disable",
            events=[
                _auth_evt(now + 60, action="vpn_login", host="tamper-attack-14", user="alice"),
                _proc_evt(now + 65, "auditctl -e 0", host="tamper-attack-14", user="alice", process="auditctl"),
            ],
            expected_ids={"DE-017", "SEQ-050"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="debian-authlog-truncate",
            events=[_proc_evt(now + 66, "truncate -s 0 /var/log/auth.log", host="tamper-attack-15", user="root", process="truncate", distro_family="debian")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-secure-shred",
            events=[_proc_evt(now + 67, "shred /var/log/secure", host="tamper-attack-16", user="root", process="shred", distro_family="rhel")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-messages-journal-purge",
            events=[_proc_evt(now + 68, "shred /var/log/messages && journalctl --vacuum-files=1", host="tamper-attack-17", user="root", process="shred", distro_family="suse")],
            expected_ids={"DE-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
    ]


def build_benign_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="logrotate-maintenance",
            events=[_proc_evt(now + 101, "logrotate -f /etc/logrotate.conf && systemctl restart rsyslog", host="tamper-benign-01", process="logrotate")],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-049", "SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="journal-rotate-sync",
            events=[_proc_evt(now + 102, "journalctl --rotate && journalctl --sync", host="tamper-benign-02", process="journalctl")],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-049", "SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="auditd-restart-reload",
            events=[_proc_evt(now + 103, "systemctl restart auditd && systemctl reload rsyslog", host="tamper-benign-03", process="systemctl")],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-049", "SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="auditd-service-reload",
            events=[_proc_evt(now + 104, "service auditd reload && service rsyslog restart", host="tamper-benign-04", process="service")],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-049", "SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="tmpfiles-clean",
            events=[_proc_evt(now + 105, "tmpfiles --clean", host="tamper-benign-05", process="systemd-tmpfiles")],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-049", "SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="package-maintenance-upgrade",
            events=[_proc_evt(now + 106, "apt-get upgrade -y && systemctl restart systemd-journald", host="tamper-benign-06", process="apt-get")],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-049", "SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="config-management-rsyslog",
            events=[_proc_evt(now + 107, "ansible-playbook logging.yml && systemctl restart rsyslog", host="tamper-benign-07", process="ansible-playbook")],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-049", "SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="chef-auditd-maintenance",
            events=[_proc_evt(now + 108, "chef-client && service auditd restart", host="tamper-benign-08", process="chef-client")],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-049", "SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="interactive-admin-login-routine",
            events=[
                _auth_evt(now + 109, host="tamper-benign-09", user="alice"),
                _proc_evt(now + 114, "ls /var/log && uptime", host="tamper-benign-09", user="alice", process="bash"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="post-login-journal-maintenance",
            events=[
                _auth_evt(now + 120, action="identity_login", host="tamper-benign-10", user="alice"),
                _proc_evt(now + 125, "journalctl --rotate && journalctl --sync", host="tamper-benign-10", user="alice", process="journalctl"),
            ],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="debian-needrestart-journal-maintenance",
            events=[_proc_evt(now + 126, "needrestart && journalctl --rotate && systemctl restart systemd-journald", host="tamper-benign-11", user="root", process="needrestart", distro_family="debian")],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-049", "SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-subscription-rsyslog-maintenance",
            events=[_proc_evt(now + 127, "subscription-manager refresh && journalctl --rotate && systemctl restart rsyslog", host="tamper-benign-12", user="root", process="subscription-manager", distro_family="rhel")],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-049", "SEQ-050"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-transactional-journal-maintenance",
            events=[_proc_evt(now + 128, "transactional-update run journalctl --rotate && systemctl restart systemd-journald", host="tamper-benign-13", user="root", process="transactional-update", distro_family="suse")],
            expected_ids=set(),
            forbidden_ids={"DE-017", "SEQ-049", "SEQ-050"},
            kind="benign",
        ),
    ]
