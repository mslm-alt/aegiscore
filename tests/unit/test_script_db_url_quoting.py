from __future__ import annotations
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import main as main_module
import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _make_python_wrapper(wrapper_path: Path, shim_dir: Path) -> None:
    wrapper = f"""#!/usr/bin/env bash
set -e
if [ -n "${{PYTHONPATH:-}}" ]; then
  export PYTHONPATH="{shim_dir}:$PYTHONPATH"
else
  export PYTHONPATH="{shim_dir}"
fi
exec "{sys.executable}" "$@"
"""
    _write_executable(wrapper_path, wrapper)


def _prepare_install_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "install-repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "config").mkdir()
    (repo / ".venv" / "bin").mkdir(parents=True)
    (repo / "data").mkdir()
    shim_dir = repo / "shims"
    shim_dir.mkdir()

    (repo / "scripts" / "install.sh").write_text(
        (REPO_ROOT / "scripts" / "install.sh").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    _write_executable(
        repo / "scripts" / "preflight.sh",
        "#!/usr/bin/env bash\nexit 0\n",
    )
    (repo / "config" / "config.yml").write_text("database: {}\n", encoding="utf-8")
    (repo / "config" / "example.env").write_text("DATABASE_URL=\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("", encoding="utf-8")

    _make_python_wrapper(repo / ".venv" / "bin" / "python", shim_dir)
    (repo / ".venv" / "bin" / "python3").symlink_to(repo / ".venv" / "bin" / "python")
    _write_executable(repo / ".venv" / "bin" / "pip", "#!/usr/bin/env bash\nexit 0\n")
    for module_name in ("numpy", "sklearn", "joblib", "psycopg2"):
        (shim_dir / f"{module_name}.py").write_text("# shim\n", encoding="utf-8")
    return repo


def _prepare_preflight_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "preflight-repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "config").mkdir()
    (repo / ".venv" / "bin").mkdir(parents=True)
    (repo / "rules").mkdir()
    (repo / "data" / "models").mkdir(parents=True)
    shim_dir = repo / "shims"
    shim_dir.mkdir()

    (repo / "scripts" / "preflight.sh").write_text(
        (REPO_ROOT / "scripts" / "preflight.sh").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (repo / "main.py").write_text(
        "import sys\n"
        "if '--validate-rules' in sys.argv:\n"
        "    print('Tüm kurallar geçerli')\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    _make_python_wrapper(repo / ".venv" / "bin" / "python", shim_dir)
    (repo / ".venv" / "bin" / "python3").symlink_to(repo / ".venv" / "bin" / "python")
    (shim_dir / "psycopg2.py").write_text(
        "class _Conn:\n"
        "    def close(self):\n"
        "        return None\n\n"
        "def connect(url, connect_timeout=0):\n"
        "    if not isinstance(url, str) or not url:\n"
        "        raise ValueError('missing url')\n"
        "    return _Conn()\n",
        encoding="utf-8",
    )

    for name in (
        "auth.yml",
        "network.yml",
        "process.yml",
        "auditd.yml",
        "dns.yml",
        "threshold.yml",
        "regex.yml",
    ):
        (repo / "rules" / name).write_text("# stub\n", encoding="utf-8")

    return repo


def test_install_script_writes_single_quote_database_url_without_syntax_break(tmp_path):
    repo = _prepare_install_repo(tmp_path)
    db_url = "postgresql://user:p'ass!word@db.example/aegis?sslmode=require&x=$value"

    result = subprocess.run(
        ["bash", str(repo / "scripts" / "install.sh"), "install"],
        cwd=repo,
        env={**os.environ, "DATABASE_URL": db_url},
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    config = yaml.safe_load((repo / "config" / "config.yml").read_text(encoding="utf-8"))
    assert config["database"]["url"] == db_url


def test_preflight_accepts_database_url_with_special_characters_without_syntax_break(tmp_path):
    repo = _prepare_preflight_repo(tmp_path)
    db_url = "postgresql://user:p'ass!word@db.example/aegis?sslmode=require&application_name=aegis$test"
    (repo / "config" / "config.yml").write_text(
        yaml.safe_dump({"database": {"type": "postgresql", "url": db_url}}, sort_keys=False),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["bash", str(repo / "scripts" / "preflight.sh")],
        cwd=repo,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "PostgreSQL URL formatı geçerli" in result.stdout
    assert "PostgreSQL bağlantısı başarılı" in result.stdout


def test_preflight_keeps_normal_database_url_flow(tmp_path):
    repo = _prepare_preflight_repo(tmp_path)
    db_url = "postgresql://user:password@db.example:5432/aegiscore"
    (repo / "config" / "config.yml").write_text(
        yaml.safe_dump({"database": {"type": "postgresql", "url": db_url}}, sort_keys=False),
        encoding="utf-8",
    )

    result = subprocess.run(
        ["bash", str(repo / "scripts" / "preflight.sh")],
        cwd=repo,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "PostgreSQL URL formatı geçerli" in result.stdout
    assert "PostgreSQL bağlantısı başarılı" in result.stdout


def test_preflight_uses_explicit_config_path_for_db_and_validate_rules(tmp_path):
    repo = _prepare_preflight_repo(tmp_path)
    custom_config = repo / "custom" / "aegis.yml"
    custom_config.parent.mkdir()
    db_url = "postgresql://user:custom@db.example:5432/aegiscore"
    custom_config.write_text(
        yaml.safe_dump({"database": {"type": "postgresql", "url": db_url}}, sort_keys=False),
        encoding="utf-8",
    )
    (repo / "main.py").write_text(
        "import sys\n"
        "if '--validate-rules' in sys.argv:\n"
        "    idx = sys.argv.index('--config')\n"
        f"    if sys.argv[idx + 1] != {str(custom_config)!r}:\n"
        "        raise SystemExit(1)\n"
        "    print('Tüm kurallar geçerli')\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        ["bash", str(repo / "scripts" / "preflight.sh"), str(custom_config)],
        cwd=repo,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "PostgreSQL URL formatı geçerli" in result.stdout
    assert "PostgreSQL bağlantısı başarılı" in result.stdout
    assert "Tüm kurallar geçerli" in result.stdout


def test_main_passes_config_path_to_preflight_script(monkeypatch, tmp_path):
    config_path = tmp_path / "custom-config.yml"
    captured = {}

    monkeypatch.setattr(sys, "argv", ["aegiscore", "--doctor", "--config", str(config_path)])
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {})
    monkeypatch.setattr(
        main_module.IntegrationSettings,
        "load",
        staticmethod(lambda config_dir: SimpleNamespace(log_overrides={})),
    )
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides: config)

    def fake_run(argv):
        captured["argv"] = argv
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(main_module.subprocess, "run", fake_run)

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert captured["argv"] == [
        "bash",
        str(Path(main_module.__file__).parent / "scripts" / "preflight.sh"),
        str(config_path),
    ]
