from __future__ import annotations

from core.language import resolve_language, system_text


def _output_language(config: dict | None = None, explicit: str | None = None) -> str:
    import os

    return resolve_language(explicit=explicit, env=os.environ, config=config or {}, default="tr")


def run_smoke_test(
    config: dict,
    language: str | None = None,
    *,
    detect_distro,
    is_supported,
    ensure_database,
    normalizer_cls,
    detection_engine_cls,
) -> int:
    lang = _output_language(config, explicit=language)
    distro_info = detect_distro()
    supported, reason = is_supported(distro_info)
    family = distro_info.get("family", "unknown")

    print(f"\n{'━'*52}")
    print(f"  {system_text('smoke_test', lang)}")
    print(f"{'━'*52}")
    print(f"  {system_text('distro', lang):<13}: {distro_info.get('pretty_name', family)}")
    if not supported:
        print(f"  ❌ {system_text('unsupported_distro', lang)}: {reason}")
        return 1
    print(f"  ✅ {system_text('distro_supported', lang)}: {family}")

    try:
        db = ensure_database(config)
    except RuntimeError as exc:
        print(f"  ❌ {exc}")
        print(f"{'━'*52}\n")
        return 1
    try:
        health = db.health_check()
        if not health.get("ok", False):
            print(f"  ❌ {system_text('db_health_failed', lang)}: {health}")
            return 1
        print(f"  ✅ {system_text('postgres_connection_ok', lang)}")

        auth_source = "auth.log"
        auth_line = "Mar  5 09:00:00 server01 sshd[100]: Accepted password for alice from 192.168.1.10 port 22345 ssh2"
        if family == "rhel":
            auth_source = "auth_log"
        elif family == "suse":
            auth_source = "syslog"

        normalizer = normalizer_cls(distro_family=family)
        event = normalizer.normalize(auth_line, auth_source)
        if not event:
            print(f"  ❌ {system_text('normalize_failed', lang)}: source={auth_source}")
            return 1
        print(f"  ✅ {system_text('normalize_ok', lang)}: action={event.action}, outcome={event.outcome}")

        det_cfg = config.get("detection", {})
        engine = detection_engine_cls(
            config={
                "rules_dir": det_cfg.get("rules_dir", "rules"),
                "rules_source": det_cfg.get("rules_source", "yaml"),
            },
            db=db,
            ioc_file=det_cfg.get("ioc", {}).get("ioc_file", "config/ioc_list.txt"),
            allow_empty_rules=False,
            distro_family=family,
        )
        results = engine.analyze(event)
        print(f"  ✅ {system_text('detection_pipeline_ok', lang)}: {len(results)} alert")
        print(f"{'━'*52}\n")
        return 0
    finally:
        db.close()


def run_test_precheck(
    config: dict,
    allow_empty_rules: bool = False,
    *,
    detect_distro,
    is_supported,
    ensure_database,
    normalizer_cls,
) -> tuple[int, bool]:
    from core.detection import RuleEngine

    distro_info = detect_distro()
    family = distro_info.get("family", "unknown")
    supported, reason = is_supported(distro_info)

    print(f"\n{'━'*52}")
    print("  Test Precheck")
    print(f"{'━'*52}")
    print(f"  Distro        : {distro_info.get('pretty_name', family)}")
    if supported:
        print(f"  ✅ Distro destekleniyor: {family}")
    else:
        print(f"  ⚠️  Desteklenmeyen distro: {reason}")

    try:
        det_cfg = config.get("detection", {})
        engine = RuleEngine(
            rules_dir=det_cfg.get("rules_dir", "rules"),
            rules_source=det_cfg.get("rules_source", "yaml"),
            allow_empty=allow_empty_rules,
            distro_family=family,
        )
        print(f"  ✅ Kurallar yüklendi: {len(engine.rules)}")
    except Exception as exc:
        print(f"  ❌ Kural yükleme başarısız: {exc}")
        print(f"{'━'*52}\n")
        return 1, False

    try:
        auth_source = "auth.log"
        if family == "rhel":
            auth_source = "auth_log"
        elif family == "suse":
            auth_source = "syslog"
        auth_line = "Mar  5 09:00:00 server01 sshd[100]: Accepted password for alice from 192.168.1.10 port 22345 ssh2"
        event = normalizer_cls(distro_family=family).normalize(auth_line, auth_source)
        if not event:
            print(f"  ❌ Normalize başarısız: source={auth_source}")
            print(f"{'━'*52}\n")
            return 1, False
        print(f"  ✅ Normalize başarılı: action={event.action}, outcome={event.outcome}")
    except Exception as exc:
        print(f"  ❌ Normalize kontrolü başarısız: {exc}")
        print(f"{'━'*52}\n")
        return 1, False

    try:
        db = ensure_database(config)
    except RuntimeError as exc:
        print(f"  ⚠️  DB testi atlandı: {exc}")
        print(f"{'━'*52}\n")
        return 0, False
    else:
        db.close()
        print("  ✅ PostgreSQL bağlantısı hazır")
        print(f"{'━'*52}\n")
        return 0, True
