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
    host="persist-host",
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


def _sudo_evt(ts, sudo_command, *, host="persist-host", user="alice", source="auth.log", distro_family="unknown"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        source=source,
        category="auth",
        action="sudo",
        outcome="success",
        user=user,
        process="sudo",
        message=f"sudo:{sudo_command}",
        fields={"sudo_command": sudo_command},
        distro_family=distro_family,
    )


def _auth_evt(ts, *, user="alice", host="persist-host", src_ip="203.0.113.10", source="auth.log", distro_family="unknown"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        src_ip=src_ip,
        source=source,
        category="auth",
        action="ssh_login",
        outcome="success",
        user=user,
        message="ssh_login:success",
        fields={},
        distro_family=distro_family,
    )


def _service_evt(ts, service_path, *, host="persist-host", user="root", source="journald"):
    return NormalizedEvent(
        ts=ts,
        host=host,
        source=source,
        category="process",
        action="service_created",
        outcome="success",
        user=user,
        process="systemd",
        message=f"service_created:{service_path}",
        fields={"service_path": service_path, "cmdline": service_path},
    )


def build_attack_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="sudo-authorized-keys-write",
            events=[_sudo_evt(now + 1, "/usr/bin/tee /home/alice/.ssh/authorized_keys", host="persist-attack-01")],
            expected_ids={"PERS-006"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="login-then-authorized-keys",
            events=[
                _auth_evt(now + 2, host="persist-attack-02"),
                _sudo_evt(now + 7, "/usr/bin/tee /home/alice/.ssh/authorized_keys", host="persist-attack-02"),
            ],
            expected_ids={"PERS-006", "SEQ-031", "SEQ-055"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="login-then-crontab-write",
            events=[
                _auth_evt(now + 10, host="persist-attack-03"),
                _sudo_evt(now + 15, "/bin/sh -c 'echo * * * * * root /tmp/run.sh >> /etc/crontab'", host="persist-attack-03"),
            ],
            expected_ids={"PERS-003", "SEQ-032"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="login-then-systemd-enable",
            events=[
                _auth_evt(now + 20, host="persist-attack-04"),
                _sudo_evt(now + 25, "systemctl enable --now backdoor.service", host="persist-attack-04"),
            ],
            expected_ids={"PERS-004", "SEQ-033"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="login-then-systemd-unit-write",
            events=[
                _auth_evt(now + 30, host="persist-attack-05"),
                _sudo_evt(now + 35, "/bin/cp backdoor.service /etc/systemd/system/backdoor.service", host="persist-attack-05"),
            ],
            expected_ids={"PERS-005", "SEQ-033"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="login-then-sudoersd-change",
            events=[
                _auth_evt(now + 40, host="persist-attack-06"),
                _sudo_evt(now + 45, "/usr/sbin/visudo -f /etc/sudoers.d/alice", host="persist-attack-06"),
            ],
            expected_ids={"SEQ-035", "SEQ-055"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="systemd-timer-create-enable",
            events=[
                _proc_evt(now + 50, "cp updater.timer /etc/systemd/system/updater.timer", host="persist-attack-07", process="cp"),
                _proc_evt(now + 55, "systemctl enable --now updater.timer", host="persist-attack-07", process="systemctl"),
            ],
            expected_ids={"PERS-017", "SEQ-047"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="login-process-authorized-keys-drop",
            events=[
                _auth_evt(now + 60, host="persist-attack-08"),
                _proc_evt(now + 65, "tee /home/alice/.ssh/authorized_keys", host="persist-attack-08", process="tee"),
            ],
            expected_ids={"PERS-017", "SEQ-048"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="user-systemd-service-write",
            events=[_proc_evt(now + 70, "cp agent.service /home/alice/.config/systemd/user/agent.service", host="persist-attack-09", process="cp")],
            expected_ids={"PERS-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="sshd-config-modification",
            events=[_proc_evt(now + 80, "echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config", host="persist-attack-10", user="root", process="bash")],
            expected_ids={"PERS-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="shell-profile-modification",
            events=[_sudo_evt(now + 90, "/bin/sh -c 'echo export PATH=/tmp:$PATH >> /home/alice/.bashrc'", host="persist-attack-11")],
            expected_ids={"PERS-008"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="profiled-script-drop",
            events=[_sudo_evt(now + 100, "/usr/bin/install -m 644 aegis.sh /etc/profile.d/aegis.sh", host="persist-attack-12")],
            expected_ids={"PERS-009"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="sudo-group-addition",
            events=[_proc_evt(now + 110, "usermod -aG sudo bob", host="persist-attack-13", user="root", process="usermod")],
            expected_ids={"PERS-012"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="service-created-direct",
            events=[_service_evt(now + 120, "/etc/systemd/system/backdoor.service", host="persist-attack-14")],
            expected_ids={"ATK-PER-002", "PERS-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="account-identity-abuse-process",
            events=[_proc_evt(now + 130, "usermod -U -s /bin/bash -d /home/bob -m bob", host="persist-attack-15", user="root", process="usermod", distro_family="rhel")],
            expected_ids={"PERS-018"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="service-override-hijack",
            events=[_proc_evt(now + 140, "printf '[Service]\\nExecStart=/usr/local/bin/sshd-wrapper\\n' > /etc/systemd/system/sshd.service.d/override.conf && systemctl daemon-reload && systemctl restart sshd", host="persist-attack-16", user="root", process="printf", distro_family="rhel")],
            expected_ids={"PERS-019"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="debian-ssh-service-override-create",
            events=[_proc_evt(now + 150, "install -m 644 override.conf /etc/systemd/system/ssh.service.d/override.conf", host="persist-attack-17", user="root", process="install", distro_family="debian")],
            expected_ids={"PERS-017"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="rhel-crond-init-enable",
            events=[
                _proc_evt(now + 160, "install -m 755 crond-wrapper /etc/rc.d/init.d/crond-wrapper", host="persist-attack-18", user="root", process="install", distro_family="rhel"),
                _proc_evt(now + 165, "chkconfig crond-wrapper on && service crond-wrapper start", host="persist-attack-18", user="root", process="chkconfig", distro_family="rhel"),
            ],
            expected_ids={"PERS-017", "SEQ-047"},
            forbidden_ids=set(),
            kind="attack",
        ),
        CoverageScenario(
            name="suse-cron-init-enable",
            events=[
                _proc_evt(now + 170, "install -m 755 cron-wrapper /etc/init.d/cron-wrapper", host="persist-attack-19", user="root", process="install", distro_family="suse"),
                _proc_evt(now + 175, "insserv cron-wrapper && service cron-wrapper restart", host="persist-attack-19", user="root", process="insserv", distro_family="suse"),
            ],
            expected_ids={"PERS-017", "SEQ-047"},
            forbidden_ids=set(),
            kind="attack",
        ),
    ]


def build_benign_scenarios() -> List[CoverageScenario]:
    now = time.time()
    return [
        CoverageScenario(
            name="package-maintenance-apt-daily",
            events=[_proc_evt(now + 201, "apt-get install --yes packagekit && systemctl preset apt-daily.timer", host="persist-benign-01", user="root", process="apt-get")],
            expected_ids=set(),
            forbidden_ids={"PERS-017", "SEQ-047", "SEQ-048"},
            kind="benign",
        ),
        CoverageScenario(
            name="routine-service-restart",
            events=[_proc_evt(now + 202, "systemctl restart app.service && systemctl reload nginx", host="persist-benign-02", user="root", process="systemctl")],
            expected_ids=set(),
            forbidden_ids={"PERS-017", "PERS-004", "SEQ-047"},
            kind="benign",
        ),
        CoverageScenario(
            name="config-management-systemd-path",
            events=[_proc_evt(now + 203, "ansible-playbook deploy.yml --extra-vars service_path=/etc/systemd/system/app.service", host="persist-benign-03", process="ansible-playbook")],
            expected_ids=set(),
            forbidden_ids={"PERS-017", "SEQ-047"},
            kind="benign",
        ),
        CoverageScenario(
            name="chef-client-cron-maintenance",
            events=[_proc_evt(now + 204, "chef-client --once --cron /etc/cron.daily/chef-client", host="persist-benign-04", user="root", process="chef-client")],
            expected_ids=set(),
            forbidden_ids={"PERS-017", "PERS-003"},
            kind="benign",
        ),
        CoverageScenario(
            name="system-user-management-benign",
            events=[_proc_evt(now + 205, "ansible-playbook users.yml && useradd --system --shell /usr/sbin/nologin svc-app", host="persist-benign-05", user="root", process="ansible-playbook", distro_family="debian")],
            expected_ids=set(),
            forbidden_ids={"PERS-018"},
            kind="benign",
        ),
        CoverageScenario(
            name="puppet-sshd-config-management",
            events=[_proc_evt(now + 205, "puppet apply manifests/sshd.pp /etc/ssh/sshd_config", host="persist-benign-05", user="root", process="puppet")],
            expected_ids=set(),
            forbidden_ids={"PERS-017"},
            kind="benign",
        ),
        CoverageScenario(
            name="salt-profile-management",
            events=[_proc_evt(now + 206, "salt-call state.apply profile path=/etc/profile.d/corp.sh", host="persist-benign-06", user="root", process="salt-call")],
            expected_ids=set(),
            forbidden_ids={"PERS-017", "PERS-009"},
            kind="benign",
        ),
        CoverageScenario(
            name="service-created-logrotate-timer",
            events=[_service_evt(now + 207, "/etc/systemd/system/logrotate.timer", host="persist-benign-07")],
            expected_ids=set(),
            forbidden_ids={"PERS-017"},
            kind="benign",
        ),
        CoverageScenario(
            name="service-created-apt-daily",
            events=[_service_evt(now + 208, "/etc/systemd/system/apt-daily.timer", host="persist-benign-08")],
            expected_ids=set(),
            forbidden_ids={"PERS-017"},
            kind="benign",
        ),
        CoverageScenario(
            name="routine-admin-enable-known-timer",
            events=[_proc_evt(now + 209, "systemctl preset logrotate.timer && systemctl reenable man-db.timer", host="persist-benign-09", user="root", process="systemctl")],
            expected_ids=set(),
            forbidden_ids={"PERS-017", "SEQ-047"},
            kind="benign",
        ),
        CoverageScenario(
            name="post-login-config-management-sudoers",
            events=[
                _auth_evt(now + 210, host="persist-benign-10"),
                _proc_evt(now + 215, "ansible-playbook users.yml && visudo -f /etc/sudoers.d/alice", host="persist-benign-10", process="ansible-playbook"),
            ],
            expected_ids=set(),
            forbidden_ids={"SEQ-055", "SEQ-048", "PERS-017"},
            kind="benign",
        ),
        CoverageScenario(
            name="routine-daemon-reload-restart",
            events=[_proc_evt(now + 211, "dnf update -y openssh-server && systemctl daemon-reload && systemctl restart sshd", host="persist-benign-11", user="root", process="dnf", distro_family="rhel")],
            expected_ids=set(),
            forbidden_ids={"PERS-019", "SEQ-069"},
            kind="benign",
        ),
        CoverageScenario(
            name="debian-unattended-upgrades-service-sync",
            events=[_proc_evt(now + 212, "unattended-upgrades && install -m 644 /lib/systemd/system/ssh.service /etc/systemd/system/ssh.service && systemctl preset ssh.service", host="persist-benign-12", user="root", process="unattended-upgrades", distro_family="debian")],
            expected_ids=set(),
            forbidden_ids={"PERS-017", "SEQ-047"},
            kind="benign",
        ),
        CoverageScenario(
            name="rhel-subscription-service-sync",
            events=[_proc_evt(now + 213, "subscription-manager refresh && install -m 644 /usr/lib/systemd/system/sshd.service /etc/systemd/system/sshd.service && systemctl daemon-reload && systemctl restart sshd", host="persist-benign-13", user="root", process="subscription-manager", distro_family="rhel")],
            expected_ids=set(),
            forbidden_ids={"PERS-017", "PERS-019", "SEQ-047", "SEQ-069"},
            kind="benign",
        ),
        CoverageScenario(
            name="suse-transactional-service-sync",
            events=[_proc_evt(now + 214, "transactional-update run install -m 644 /usr/lib/systemd/system/cron.service /etc/systemd/system/cron.service && systemctl daemon-reload && systemctl restart cron", host="persist-benign-14", user="root", process="transactional-update", distro_family="suse")],
            expected_ids=set(),
            forbidden_ids={"PERS-017", "PERS-019", "SEQ-047", "SEQ-069"},
            kind="benign",
        ),
    ]
