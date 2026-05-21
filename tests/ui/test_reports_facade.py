from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import ui.backend_facade as backend_facade


def test_collect_report_artifacts_no_files_graceful_empty(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    result = backend_facade.collect_report_artifacts(limit=10)

    assert result["status"] == "ok"
    assert result["empty"] is True
    assert result["artifacts"] == []
    assert "reports/" in result["paths_checked"]


def test_collect_report_preview_path_traversal_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = backend_facade.collect_report_preview("../secret.txt")

    assert result["status"] == "blocked"
    assert result["error"] == "path_traversal_blocked"


def test_collect_report_preview_redacts_secret_like_content(tmp_path, monkeypatch):
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    report_path = report_dir / "report.txt"
    report_path.write_text("smtp_pass=hunter2\nAuthorization: Bearer secret-token-9999\nok=value\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = backend_facade.collect_report_preview(str(report_path))

    assert result["status"] == "ok"
    assert "hunter2" not in result["preview"]
    assert "secret-token-9999" not in result["preview"]
    assert "ok=value" in result["preview"]


def test_collect_safe_export_preview_returns_preview_only():
    result = backend_facade.collect_safe_export_preview("diagnostic_bundle")

    assert result["status"] == "preview_only"
    assert result["export_type"] == "diagnostic_bundle"
    assert "File writing is disabled in Phase 1" in result["message"]


def test_collect_diagnostic_bundle_preview_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "collect_diagnostics_summary", lambda config_path=None: {
        "db_health": {"status": "ok"},
        "schema_version": "v1",
        "rule_count": 9,
        "parse_fail_summary": {"count": 0},
        "duplicate_summary": {"count": 0},
    })
    monkeypatch.setattr(backend_facade, "collect_overview_status", lambda config_path=None: {
        "distro": {"family": "debian"},
        "alert_count": 4,
        "open_incidents": 1,
        "phase": {"current_phase": 1},
    })
    monkeypatch.setattr(backend_facade, "collect_ml_summary", lambda config_path=None: {
        "status": "ok",
        "overall": {"families": 2},
    })

    result = backend_facade.collect_diagnostic_bundle_preview()

    assert result["status"] == "ok"
    assert {"would_include", "would_redact", "would_exclude", "snapshot", "message", "requires_phase"} <= set(result)


def test_collect_report_readiness_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "collect_report_artifacts", lambda limit=50: {
        "status": "ok",
        "artifacts": [{"path": "/tmp/report.html"}],
        "paths_checked": ["reports/"],
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_llm_config_status", lambda config_path=None: {
        "enabled": True,
        "has_api_key": True,
    })
    monkeypatch.setattr(backend_facade, "main_module", SimpleNamespace(build_deterministic_alert_explanation=lambda payload: {}))

    result = backend_facade.collect_report_readiness()

    assert result["status"] == "ok"
    assert result["artifacts_found_count"] == 1
    assert result["generation_locked"] is True
    assert result["write_locked"] is True
