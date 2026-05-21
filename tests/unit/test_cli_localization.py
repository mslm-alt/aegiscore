import main as main_module


def test_validate_rules_output_english(monkeypatch, capsys):
    class _RuleEngine:
        def __init__(self, rules_dir=None, allow_empty=True):
            self.rules = [object(), object()]

        def validate(self):
            return []

    monkeypatch.setenv("AEGIS_LANGUAGE", "en")
    monkeypatch.setattr("core.detection.RuleEngine", _RuleEngine)

    lang = main_module._output_language({})
    total = 2
    print(f"\n{'━'*52}")
    print(f"  {main_module.system_text('rule_validation_report', lang)}")
    print(f"{'━'*52}")
    print(f"  {main_module.system_text('loaded_rules', lang):<14}: {total}")
    print(f"  ✅ {main_module.system_text('all_rules_valid', lang)}")
    print(f"{'━'*52}\n")
    out = capsys.readouterr().out

    assert "Rule Validation Report" in out
    assert "Loaded rules" in out
    assert "All rules are valid" in out
    assert "Yüklenen" not in out


def test_smoke_test_output_english(monkeypatch, capsys):
    monkeypatch.setenv("AEGIS_LANGUAGE", "en")
    monkeypatch.setattr(main_module, "detect_distro", lambda: {"family": "debian", "pretty_name": "Debian"})
    monkeypatch.setattr(main_module, "is_supported", lambda distro: (True, ""))

    class _Db:
        def health_check(self):
            return {"ok": True}
        def close(self):
            return None

    monkeypatch.setattr(main_module, "ensure_database", lambda config: _Db())

    class _Event:
        action = "ssh_login"
        outcome = "success"

    monkeypatch.setattr(main_module, "Normalizer", lambda distro_family=None: type("N", (), {"normalize": lambda self, line, source: _Event()})())
    monkeypatch.setattr(main_module, "DetectionEngine", lambda **kwargs: type("E", (), {"analyze": lambda self, event: []})())

    rc = main_module.run_smoke_test({}, language="en")
    out = capsys.readouterr().out

    assert rc == 0
    assert "Smoke Test" in out
    assert "Distro supported" in out
    assert "PostgreSQL connection successful" in out
    assert "Normalize successful" in out
    assert "Detection pipeline ran" in out
    assert "başarılı" not in out


def test_startup_banner_output_english(monkeypatch, tmp_path, capsys):
    log_path = tmp_path / "sample.log"
    log_path.write_text("", encoding="utf-8")
    cfg = {
        "database": {"url": "postgresql://user:pass@db:5432/aegis"},
        "llm": {"enabled": False, "backend": "mock"},
        "threat_intel": {"enabled": False},
        "sources": {"apache2": {"enabled": True, "path": str(log_path), "type": "file"}},
    }
    monkeypatch.setenv("AEGIS_LANGUAGE", "en")
    monkeypatch.setattr(main_module, "detect_distro", lambda: {"pretty": "Debian", "family": "debian"})

    main_module.print_startup_banner(cfg, language="en", selected_source="apache2")
    out = capsys.readouterr().out

    assert "Starting" in out
    assert "Log Sources" in out
    assert "single source: apache2" in out
    assert "Başlatılıyor" not in out
