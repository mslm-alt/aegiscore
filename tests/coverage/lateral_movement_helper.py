import sys
import time
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.normalize import NormalizedEvent

from tests.coverage.credential_access_helper import CoverageScenario


def _auth_evt(ts, *, action="ssh_login", user="alice", host="lm-host", source="auth.log", distro_family="unknown"):
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


def _proc_evt(ts, cmdline, *, host="lm-host", user="alice", process=None, source="journald", distro_family="unknown"):
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
            name="debian-ssh-prep-then-scp",
            events=[
                _auth_evt(now + 1, action="ssh_login", host="lm-attack-01", distro_family="debian"),
                _proc_evt(now + 6, "ssh-keygen -t ed25519 -f /home/alice/.ssh/id_ed25519 && echo '10.0.5.20 db01' >> /etc/hosts", host="lm-attack-01", process="bash", distro_family="debian"),
                _proc_evt(now + 11, "scp /tmp/bootstrap.sh alice@10.0.5.20:/tmp/bootstrap.sh", host="lm-attack-01", process="scp", distro_family="debian"),
            ],
            expected_ids={"ATK-LM-003", "ATK-LM-004", "SEQ-060"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-ssh-copy-id-then-rsync",
            events=[
                _auth_evt(now + 2, action="identity_login", host="lm-attack-02", distro_family="rhel"),
                _proc_evt(now + 7, "ssh-copy-id ops@10.0.6.10", host="lm-attack-02", process="ssh-copy-id", source="auditd", distro_family="rhel"),
                _proc_evt(now + 12, "rsync /var/tmp/bootstrap.sh ops@10.0.6.10:/var/tmp/bootstrap.sh", host="lm-attack-02", process="rsync", source="auditd", distro_family="rhel"),
            ],
            expected_ids={"ATK-LM-003", "ATK-LM-004", "SEQ-060"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-ssh-config-then-proxyjump",
            events=[
                _auth_evt(now + 3, action="vpn_login", host="lm-attack-03", distro_family="suse"),
                _proc_evt(now + 8, "printf 'Host jump\\n  ProxyJump bastion\\n' >> /home/alice/.ssh/config", host="lm-attack-03", process="printf", source="syslog", distro_family="suse"),
                _proc_evt(now + 13, "ssh -J bastion alice@192.168.10.44 'sh /tmp/bootstrap.sh'", host="lm-attack-03", process="ssh", source="syslog", distro_family="suse"),
            ],
            expected_ids={"ATK-LM-003", "ATK-LM-004", "SEQ-060"},
            forbidden_ids=set(),
            kind="attack",
        ),
    ]


def build_benign_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="debian-repo-mirror",
            events=[
                _auth_evt(now + 101, action="ssh_login", host="lm-benign-01", user="root", distro_family="debian"),
                _proc_evt(now + 106, "unattended-upgrades && ssh-keygen -A", host="lm-benign-01", user="root", process="unattended-upgrades", distro_family="debian"),
                _proc_evt(now + 111, "scp /tmp/pkg.deb repo@10.0.5.20:/srv/repo/pkg.deb", host="lm-benign-01", user="root", process="scp", distro_family="debian"),
            ],
            expected_ids=set(),
            forbidden_ids={"ATK-LM-003", "ATK-LM-004", "SEQ-060"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-rpm-mirror",
            events=[
                _auth_evt(now + 102, action="identity_login", host="lm-benign-02", user="root", distro_family="rhel"),
                _proc_evt(now + 107, "subscription-manager refresh && ssh-keygen -A", host="lm-benign-02", user="root", process="subscription-manager", source="auditd", distro_family="rhel"),
                _proc_evt(now + 112, "rsync /var/tmp/agent.rpm repo@10.0.6.10:/srv/repo/agent.rpm", host="lm-benign-02", user="root", process="rsync", source="auditd", distro_family="rhel"),
            ],
            expected_ids=set(),
            forbidden_ids={"ATK-LM-003", "ATK-LM-004", "SEQ-060"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-repodata-mirror",
            events=[
                _auth_evt(now + 103, action="vpn_login", host="lm-benign-03", user="root", distro_family="suse"),
                _proc_evt(now + 108, "transactional-update run ssh-keygen -A", host="lm-benign-03", user="root", process="transactional-update", source="syslog", distro_family="suse"),
                _proc_evt(now + 113, "scp /tmp/repomd.xml mirror@192.168.10.44:/srv/www/repo/repodata/repomd.xml", host="lm-benign-03", user="root", process="scp", source="syslog", distro_family="suse"),
            ],
            expected_ids=set(),
            forbidden_ids={"ATK-LM-003", "ATK-LM-004", "SEQ-060"},
            kind="benign",
        ),
        CoverageScenario(
            name="debian-known-hosts-and-ansible-sync",
            events=[
                _auth_evt(now + 104, action="ssh_login", host="lm-benign-04", user="root", distro_family="debian"),
                _proc_evt(now + 109, "ssh-keygen -R 10.0.5.20", host="lm-benign-04", user="root", process="ssh-keygen", distro_family="debian"),
                _proc_evt(now + 114, "scp /etc/ansible/hosts ops@10.0.5.20:/etc/ansible/hosts", host="lm-benign-04", user="root", process="scp", distro_family="debian"),
            ],
            expected_ids=set(),
            forbidden_ids={"ATK-LM-003", "ATK-LM-004", "SEQ-060"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-known-hosts-and-puppet-sync",
            events=[
                _auth_evt(now + 105, action="identity_login", host="lm-benign-05", user="root", distro_family="rhel"),
                _proc_evt(now + 110, "ssh-keygen -F 10.0.6.10", host="lm-benign-05", user="root", process="ssh-keygen", source="auditd", distro_family="rhel"),
                _proc_evt(now + 115, "rsync /etc/puppetlabs/puppet/ssl/certs/node.pem ops@10.0.6.10:/var/lib/puppet/ssl/certs/node.pem", host="lm-benign-05", user="root", process="rsync", source="auditd", distro_family="rhel"),
            ],
            expected_ids=set(),
            forbidden_ids={"ATK-LM-003", "ATK-LM-004", "SEQ-060"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-known-hosts-and-salt-sync",
            events=[
                _auth_evt(now + 106, action="vpn_login", host="lm-benign-06", user="root", distro_family="suse"),
                _proc_evt(now + 111, "ssh-keygen -R 192.168.10.44", host="lm-benign-06", user="root", process="ssh-keygen", source="syslog", distro_family="suse"),
                _proc_evt(now + 116, "scp /srv/salt/top.sls ops@192.168.10.44:/srv/salt/top.sls", host="lm-benign-06", user="root", process="scp", source="syslog", distro_family="suse"),
            ],
            expected_ids=set(),
            forbidden_ids={"ATK-LM-003", "ATK-LM-004", "SEQ-060"},
            kind="benign",
        ),
    ]
