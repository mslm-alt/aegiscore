import logging
import sys
import types

from app.configuration import read_version, resolve_output_language
from app.startup import print_startup_banner
from core.formatters import BOLD, CYAN, GREEN, RED, RESET, YELLOW
from core.language import system_text
from core.phase_manager import PhaseManager


def _base_config(tmp_path):
    log_path = tmp_path / "sample.log"
    log_path.write_text("", encoding="utf-8")
    sources = {
        name: {"enabled": True, "path": str(log_path), "type": "file"}
        for name in (
            "apache2",
            "nginx",
            "auth_log",
            "syslog",
            "auditd",
            "ufw",
            "mysql",
            "postgresql",
            "mail",
            "dpkg",
            "journald",
        )
    }
    return {
        "database": {"url": "postgresql://user:pass@db:5432/aegis"},
        "llm": {"enabled": False, "backend": "mock"},
        "threat_intel": {"enabled": False},
        "sources": sources,
    }


def _install_fake_distro(monkeypatch):
    distro_mod = types.ModuleType("core.distro")
    distro_mod.detect_distro = lambda: {"pretty": "Ubuntu 24.04", "family": "debian"}
    distro_mod.is_supported = lambda info: (True, "")
    monkeypatch.setitem(sys.modules, "core.distro", distro_mod)


def _print_banner(cfg, **kwargs):
    print_startup_banner(
        cfg,
        read_version=read_version,
        output_language=resolve_output_language,
        system_text=system_text,
        logger=logging.getLogger("siem.main"),
        bold=BOLD,
        cyan=CYAN,
        green=GREEN,
        yellow=YELLOW,
        red=RED,
        reset=RESET,
        phase_manager_cls=PhaseManager,
        **kwargs,
    )


def test_startup_banner_preserves_normal_display(monkeypatch, tmp_path, capsys):
    _install_fake_distro(monkeypatch)
    cfg = _base_config(tmp_path)

    _print_banner(cfg)
    out = capsys.readouterr().out

    assert "Log Kaynakları" in out
    assert "11 aktif" in out


def test_startup_banner_shows_selected_source_summary(monkeypatch, tmp_path, capsys):
    _install_fake_distro(monkeypatch)
    cfg = _base_config(tmp_path)

    _print_banner(cfg, selected_source="apache2")
    out = capsys.readouterr().out

    assert "Log Kaynakları" in out
    assert "tek kaynak: apache2" in out
    assert "11 aktif" not in out
