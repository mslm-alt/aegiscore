from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def test_no_write_guard_reports_diagnostics_sources():
    targets = {
        "ui/backend_facade.py": [
            " open(",
            "block_ip",
            "unblock_ip",
            "reset_database",
        ],
        "ui/actions/secret_store.py": [
            "block_ip",
            "unblock_ip",
            "firewall-cmd",
            "reset_database",
            "close_incident(",
            ".sendmail(",
        ],
        "ui/views/reports.py": [
            " open(",
            ".write(",
            "self._export_now.setEnabled(True)",
            "self._generate.setEnabled(True)",
        ],
        "ui/views/diagnostics.py": [
            " open(",
            ".write(",
            "Create bundle\")\n        self._create_bundle.setEnabled(True)",
        ],
    }

    for path_text, forbidden_tokens in targets.items():
        source = Path(path_text).read_text(encoding="utf-8").lower()
        for token in forbidden_tokens:
            assert token.lower() not in source
