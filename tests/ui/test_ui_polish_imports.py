from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def test_ui_polish_no_write_guard():
    targets = [
        "ui/theme.py",
        "ui/components.py",
        "ui/app.py",
        "ui/main_window.py",
        "ui/preflight.py",
        "ui/views/overview.py",
        "ui/views/alerts.py",
        "ui/views/live_logs.py",
        "ui/views/ml_center_compact.py",
        "ui/views/ip_reputation.py",
        "ui/views/settings_compact.py",
        "ui/views/reports.py",
        "ui/views/diagnostics.py",
    ]
    forbidden = [
        "write_text(",
        ".write(",
        ".commit(",
        "block_ip",
        "unblock_ip",
        "firewall_executor",
        "reset_database",
        "update_incident(",
        "insert into ",
        "delete from ",
        "create bundle\")\n        self._create_bundle.setenabled(true)",
    ]

    for target in targets:
        source = Path(target).read_text(encoding="utf-8").lower()
        for token in forbidden:
            assert token not in source
