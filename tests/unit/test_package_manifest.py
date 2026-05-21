import subprocess
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _prepare_package_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "package-repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "core").mkdir()
    (repo / "app" / "runtime").mkdir(parents=True)
    (repo / "rules").mkdir()
    (repo / "config").mkdir()
    (repo / "data" / "labels" / "debian" / "attack").mkdir(parents=True)
    (repo / "data" / "models").mkdir(parents=True)
    (repo / "data" / "exports").mkdir(parents=True)
    (repo / "data" / "diagnostic_bundles").mkdir(parents=True)
    (repo / "data" / "ml_label_scan").mkdir(parents=True)
    (repo / ".git").mkdir(parents=True)
    (repo / "data" / "state_backup_20260507_003332").mkdir(parents=True)

    (repo / "scripts" / "package.sh").write_text(
        (REPO_ROOT / "scripts" / "package.sh").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (repo / ".packageignore").write_text(
        (REPO_ROOT / ".packageignore").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    (repo / "main.py").write_text("# main\n", encoding="utf-8")
    (repo / "README.md").write_text("# readme\n", encoding="utf-8")
    (repo / "AGENTS.md").write_text("internal agent instructions\n", encoding="utf-8")
    (repo / "DEVELOPER_NOTE_VERIFY_PATCH.md").write_text("internal release note\n", encoding="utf-8")
    (repo / "core" / "notifier.py").write_text("# notifier\n", encoding="utf-8")
    (repo / "app" / "runtime" / "pipeline.py").write_text("# pipeline\n", encoding="utf-8")
    (repo / "core" / "artifact.py.bak.utc_20260521_010203").write_text("backup\n", encoding="utf-8")
    (repo / "rules" / "auth.yml").write_text("- id: AUTH-001\n", encoding="utf-8")
    (repo / "scripts" / "install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    (repo / "config" / "config.yml").write_text("siem: {}\n", encoding="utf-8")
    (repo / "config" / "example.env").write_text("DATABASE_URL=postgresql://aegiscore:change_me@localhost:5432/aegiscore\n", encoding="utf-8")
    (repo / "config" / "integrations.example.env").write_text("GEMINI_API_KEY=put_your_gemini_api_key_here\n", encoding="utf-8")
    (repo / "config" / "integrations.env").write_text("OPENAI_API_KEY=real-should-not-ship\n", encoding="utf-8")
    (repo / "config" / "ioc_list.txt").write_text(
        "\n".join(
            [
                "# static",
                "203.0.113.10",
                "",
                "# --- AUTO FEED ---",
                "# generated",
                "198.51.100.77",
                "bad.example.test",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (repo / "data" / "labels" / "debian" / "attack" / "brute_force.jsonl").write_text(
        '{"label":"attack"}\n',
        encoding="utf-8",
    )
    (repo / "data" / "alerts.jsonl").write_text('{"alert":1}\n', encoding="utf-8")
    (repo / "data" / "incidents.jsonl").write_text('{"incident":1}\n', encoding="utf-8")
    (repo / "data" / "backend_only_start_20260508_143251.log").write_text("log\n", encoding="utf-8")
    (repo / "data" / "phase_state.json").write_text('{"phase":0}\n', encoding="utf-8")
    (repo / "data" / "runtime_state.json.gz").write_bytes(b"gz")
    (repo / "data" / "context_state.json").write_text('{"ctx":1}\n', encoding="utf-8")
    (repo / "data" / "systemd_state.json").write_text('{"svc":1}\n', encoding="utf-8")
    (repo / "data" / "threat_intel_cache.json").write_text('{"cache":1}\n', encoding="utf-8")
    (repo / "data" / "models" / "host_calibration_store.joblib").write_bytes(b"joblib")
    (repo / "data" / "exports" / "report.json").write_text("{}\n", encoding="utf-8")
    (repo / "data" / "diagnostic_bundles" / "bundle.tar.gz").write_bytes(b"bundle")
    (repo / "data" / "ml_label_scan" / "scan.json").write_text("{}\n", encoding="utf-8")
    (repo / ".env").write_text("DATABASE_URL=postgresql://aegiscore:aegiscore123@localhost:5432/aegiscore\n", encoding="utf-8")
    (repo / ".env.production").write_text("OPENAI_API_KEY=real-should-not-ship\n", encoding="utf-8")
    (repo / ".git" / "config").write_text("[core]\nrepositoryformatversion = 0\n", encoding="utf-8")
    (repo / "private.pem").write_text("-----BEGIN PRIVATE KEY-----\nreal\n", encoding="utf-8")
    (repo / "data" / "state_backup_20260507_003332" / "context_state.json").write_text(
        '{"backup":1}\n',
        encoding="utf-8",
    )
    return repo


def test_package_dry_run_reports_manifest_summary(tmp_path):
    repo = _prepare_package_repo(tmp_path)

    result = subprocess.run(
        ["bash", str(repo / "scripts" / "package.sh"), "--dry-run"],
        cwd=repo,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "DRY_RUN include=" in result.stdout


def test_package_dry_run_is_non_mutating(tmp_path):
    repo = _prepare_package_repo(tmp_path)
    pycache_dir = repo / "core" / "__pycache__"
    pytest_cache_dir = repo / ".pytest_cache"
    rules_core_dir = repo / "rules" / "core"
    rules_config_dir = repo / "rules" / "config"
    hydra_restore = repo / "hydra.restore"
    pyc_file = repo / "core" / "stale.pyc"

    pycache_dir.mkdir()
    pytest_cache_dir.mkdir()
    rules_core_dir.mkdir()
    rules_config_dir.mkdir()
    hydra_restore.write_text("restore", encoding="utf-8")
    pyc_file.write_bytes(b"pyc")
    (pycache_dir / "dummy.pyc").write_bytes(b"cache")

    result = subprocess.run(
        ["bash", str(repo / "scripts" / "package.sh"), "--dry-run"],
        cwd=repo,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "Dry-run read-only" in result.stdout
    assert pycache_dir.exists()
    assert pytest_cache_dir.exists()
    assert rules_core_dir.exists()
    assert rules_config_dir.exists()
    assert hydra_restore.exists()
    assert pyc_file.exists()


def test_package_manifest_keeps_labels_and_excludes_runtime_artifacts(tmp_path):
    repo = _prepare_package_repo(tmp_path)
    version = "manifest-test"

    result = subprocess.run(
        ["bash", str(repo / "scripts" / "package.sh"), version],
        cwd=repo,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr + result.stdout

    zip_path = repo / "dist" / f"github_clean_export_{version}" / f"AegisCore_github_clean_{version}.zip"
    assert zip_path.exists(), result.stdout

    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())

    included = {
        "main.py",
        "README.md",
        "app/runtime/pipeline.py",
        "core/notifier.py",
        "rules/auth.yml",
        "scripts/install.sh",
        "scripts/package.sh",
        "config/config.yml",
        "config/example.env",
        "config/integrations.example.env",
        "config/ioc_list.txt",
        "data/labels/debian/attack/brute_force.jsonl",
    }
    excluded = {
        "data/alerts.jsonl",
        "data/incidents.jsonl",
        "data/backend_only_start_20260508_143251.log",
        "data/models/host_calibration_store.joblib",
        "data/phase_state.json",
        "data/runtime_state.json.gz",
        "data/context_state.json",
        "data/systemd_state.json",
        "data/threat_intel_cache.json",
        "data/state_backup_20260507_003332/context_state.json",
        "config/integrations.env",
        "data/exports/report.json",
        "data/diagnostic_bundles/bundle.tar.gz",
        "data/ml_label_scan/scan.json",
        ".env",
        ".env.production",
        ".git/config",
        "private.pem",
        "AGENTS.md",
        "DEVELOPER_NOTE_VERIFY_PATCH.md",
        "core/artifact.py.bak.utc_20260521_010203",
    }

    for path in included:
        assert path in names, f"{path} package içinde olmalı"
    for path in excluded:
        assert path not in names, f"{path} package dışında kalmalı"

    with zipfile.ZipFile(zip_path) as zf:
        ioc_text = zf.read("config/ioc_list.txt").decode("utf-8")

    assert "203.0.113.10" in ioc_text
    assert "# --- AUTO FEED ---" in ioc_text
    assert "release paketinde sanitize edilmiştir" in ioc_text
    assert "198.51.100.77" not in ioc_text
    assert "bad.example.test" not in ioc_text


def test_env_templates_separate_database_url_and_integration_secrets():
    example_env = (REPO_ROOT / "config" / "example.env").read_text(encoding="utf-8")
    integrations_example = (REPO_ROOT / "config" / "integrations.example.env").read_text(encoding="utf-8")

    assert "DATABASE_URL=postgresql://aegiscore:change_me@localhost:5432/aegiscore" in example_env
    assert "\nDATABASE_URL=" not in "\n" + integrations_example
    assert "GEMINI_API_KEY=put_your_gemini_api_key_here" in integrations_example
    assert "OPENAI_API_KEY=put_your_openai_api_key_here" in integrations_example
    assert "ANTHROPIC_API_KEY=put_your_anthropic_api_key_here" in integrations_example
    assert "ABUSEIPDB_API_KEY=put_your_abuseipdb_api_key_here" in integrations_example
    assert "TELEGRAM_BOT_TOKEN=put_your_telegram_bot_token_here" in integrations_example
    assert "TELEGRAM_CHAT_ID=put_your_telegram_chat_id_here" in integrations_example
    assert "EMAIL_SMTP_PASS=put_your_email_password_here" in integrations_example
    for forbidden in ("sk-", "AIza", "xoxb-", "ghp_", "real-should-not-ship"):
        assert forbidden not in example_env
        assert forbidden not in integrations_example


def test_git_and_package_ignore_secret_runtime_env_files():
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    packageignore = (REPO_ROOT / ".packageignore").read_text(encoding="utf-8")

    for token in (".env", ".env.*", "config/integrations.env"):
        assert token in gitignore
        assert token in packageignore


def test_default_config_keeps_secret_values_empty():
    config_text = (REPO_ROOT / "config" / "config.yml").read_text(encoding="utf-8")

    assert "api_key: ''" in config_text
    assert "otx_api_key: ''" in config_text
    assert "put_your_" not in config_text
    assert "change_me" not in config_text


def test_release_package_excludes_runtime_and_secret_patterns(tmp_path):
    repo = _prepare_package_repo(tmp_path)
    version = "secret-scan"

    result = subprocess.run(
        ["bash", str(repo / "scripts" / "package.sh"), version],
        cwd=repo,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr + result.stdout

    zip_path = repo / "dist" / f"github_clean_export_{version}" / f"AegisCore_github_clean_{version}.zip"
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        payload = "\n".join(
            zf.read(name).decode("utf-8", errors="ignore")
            for name in zf.namelist()
            if not name.endswith("/") and any(name.endswith(ext) for ext in (".env", ".yml", ".md", ".py", ".txt"))
        )

    forbidden_names = {
        ".env",
        ".env.production",
        "config/integrations.env",
        "data/exports/report.json",
        "data/diagnostic_bundles/bundle.tar.gz",
        "data/ml_label_scan/scan.json",
        ".git/config",
        "private.pem",
    }
    for name in forbidden_names:
        assert name not in names

    forbidden_fragments = (
        "postgresql://aegiscore:aegiscore123",
        "DATABASE_URL=postgresql://aegiscore:aegiscore123",
        "OPENAI_API_KEY=real-should-not-ship",
        "-----BEGIN PRIVATE KEY-----",
    )
    for fragment in forbidden_fragments:
        assert fragment not in payload
