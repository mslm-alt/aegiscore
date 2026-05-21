from __future__ import annotations

import os
from pathlib import Path
from typing import Callable


def print_startup_banner(
    config: dict,
    llm_client=None,
    threat_intel=None,
    *,
    selected_source=None,
    language: str | None = None,
    read_version: Callable[..., str],
    output_language: Callable[..., str],
    system_text: Callable[..., str],
    logger,
    bold: str,
    cyan: str,
    green: str,
    yellow: str,
    red: str,
    reset: str,
    phase_manager_cls,
) -> None:
    _ = threat_intel
    try:
        version = read_version(default="16.0.0")
    except OSError:
        version = "16.0.0"

    width = 58
    sep = "═" * width
    lang = output_language(config, explicit=language)

    def ok(label, detail=""):
        pad = f"  {label:<14} : "
        suf = f"  {detail}" if detail else ""
        print(f"{pad}{green}✅{suf}{reset}")

    def warn(label, detail=""):
        pad = f"  {label:<14} : "
        print(f"{pad}{yellow}⚠️  {detail}{reset}")

    def err(label, detail=""):
        pad = f"  {label:<14} : "
        print(f"{pad}{red}❌ {detail}{reset}")

    print(f"\n{bold}{cyan}{sep}{reset}")
    print(f"{bold}  🛡️  AegisCore v{version} — {system_text('startup', lang)}{reset}")
    print(f"{bold}{cyan}{sep}{reset}")

    db_cfg = config.get("database", {})
    db_url = (
        db_cfg.get("url", "")
        or os.environ.get("DATABASE_URL", "")
        or os.environ.get("AEGISCORE_DB_URL", "")
    ).strip()
    if db_url:
        ok(system_text("db", lang), f"PostgreSQL  {db_url[:40]}{'…' if len(db_url) > 40 else ''}")
    else:
        err(system_text("db", lang), system_text("db_url_missing", lang))
        print(f"  {'':14}   {yellow}  → {system_text('db_url_hint_env', lang)}{reset}")
        print(f"  {'':14}   {yellow}  → {system_text('db_url_hint_config', lang)}{reset}")

    llm_cfg = config.get("llm", {})
    llm_enabled = llm_cfg.get("enabled", False)
    llm_backend = llm_cfg.get("backend", "mock").lower()

    if llm_client and getattr(llm_client, "is_active", False):
        st = llm_client.status()
        ok(system_text("llm", lang), f"{system_text('active', lang)}  backend={st.get('backend','?')}  language={st.get('language','?')}")
    elif not llm_enabled:
        err(system_text("llm", lang), system_text("disabled_config", lang))
        hint = ""
        if llm_backend == "anthropic":
            hint = "  → config.yml: llm.api_key  veya  env: ANTHROPIC_API_KEY"
        elif llm_backend == "openai":
            hint = "  → config.yml: llm.api_key  veya  env: OPENAI_API_KEY"
        elif llm_backend == "gemini":
            hint = "  → env: GEMINI_API_KEY"
        elif llm_backend == "local":
            hint = "  → config.yml: llm.base_url  (Ollama/LM Studio)"
        if hint:
            print(f"  {' '*14}   {yellow}{hint}{reset}")
        print(f"  {' '*14}   {yellow}  → {system_text('enable_hint', lang)}{reset}")
    elif llm_backend in ("anthropic", "openai", "gemini"):
        env_name = "ANTHROPIC_API_KEY" if llm_backend == "anthropic" else "OPENAI_API_KEY" if llm_backend == "openai" else "GEMINI_API_KEY"
        err(system_text("llm", lang), f"{system_text('missing_api_key', lang)}  (backend: {llm_backend})")
        if llm_backend == "gemini":
            print(f"  {' '*14}   {yellow}  → env: {env_name}{reset}")
        else:
            print(f"  {' '*14}   {yellow}  → config.yml: llm.api_key  veya  env: {env_name}{reset}")
    elif llm_backend == "mock":
        warn(system_text("llm", lang), system_text("mock_backend", lang))
    else:
        warn(system_text("llm", lang), f"backend={llm_backend}  ({system_text('status_unknown', lang)})")

    ti_cfg = config.get("threat_intel", {})
    ti_on = ti_cfg.get("enabled", True)
    otx_key = ti_cfg.get("otx_api_key", "").strip() or os.environ.get("OTX_API_KEY", "").strip()

    if not ti_on:
        err(system_text("threat_intel", lang), system_text("disabled_threat_intel", lang))
    else:
        try:
            from core.threat_intel import FREE_FEEDS

            free_count = len(FREE_FEEDS)
        except (ImportError, AttributeError):
            free_count = 3

        if otx_key:
            ok(system_text("threat_intel", lang), system_text("free_feeds_otx_active", lang, count=free_count))
        else:
            warn(system_text("otx", lang), system_text("otx_key_missing", lang, count=free_count))
            print(f"  {' '*14}   {yellow}  → {system_text('otx_hint', lang)}{reset}")
            ok(system_text("threat_intel", lang), system_text("free_feeds_active", lang, count=free_count))

    try:
        from core.distro import detect_distro, is_supported

        distro_info = detect_distro()
        pretty = distro_info.get("pretty", system_text("unknown", lang))
        family = distro_info.get("family", "unknown")
        supported, why = is_supported(distro_info)
        if supported:
            ok(system_text("distro_label", lang), f"{pretty}  ({system_text('family_label', lang)}: {family})")
        else:
            warn(system_text("distro_label", lang), f"{pretty}  ⚠️  {system_text('unsupported', lang)}: {why}")
    except Exception as exc:
        warn(system_text("distro_label", lang), f"{system_text('detect_error', lang)}: {exc}")

    sources = config.get("sources", {})
    active_srcs = [name for name, cfg in sources.items() if cfg.get("enabled", False)]
    if selected_source:
        ok(system_text("log_sources", lang), f"{system_text('single_source', lang)}: {selected_source}")
    elif active_srcs:
        ok(system_text("log_sources", lang), f"{len(active_srcs)} {system_text('active_count', lang)}  ({', '.join(active_srcs[:5])}{'…' if len(active_srcs) > 5 else ''})")
    else:
        warn(system_text("log_sources", lang), system_text("none_enabled_test_mode", lang))

    for src_name, src_cfg in sources.items():
        if not src_cfg.get("enabled", False):
            continue
        src_type = src_cfg.get("type", "syslog")
        if src_type == "journald":
            continue
        path = src_cfg.get("path", "")
        if not path:
            warn(f"  {src_name}", system_text("path_not_defined", lang))
            continue
        if not Path(path).exists():
            warn(
                f"  {src_name}",
                f"{system_text('file_missing', lang)}: {path}"
                + (" — 'sudo apt install auditd && sudo systemctl enable auditd'" if src_name == "auditd" else "")
                + f" — {system_text('source_disabled_quietly', lang)}",
            )

    phase_names = {0: system_text("phase_name_rule_engine", lang), 1: "Instant ML", 2: "Baseline", 3: "Advanced ML"}
    try:
        pm = phase_manager_cls(config=config, state_dir="data", announce_startup=False)
        ps = pm.get_status()
        phase_value = ps.get("current_phase", 0)
        phase_name = ps.get("phase_name", phase_names.get(phase_value, ""))
        ok(system_text("phase", lang), f"PHASE_{phase_value}  ({phase_name})")
    except Exception as exc:
        logger.debug(f"[Banner] Faz durumu alınamadı: {exc}")
        ok(system_text("phase", lang), f"PHASE_0  ({system_text('phase_name_rule_engine', lang)})")

    print(f"{bold}{cyan}{sep}{reset}\n")


__all__ = ["print_startup_banner"]
