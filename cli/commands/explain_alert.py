from __future__ import annotations

from pathlib import Path

from core.integrations import IntegrationSettings
from core.language import explanation_text, resolve_language
from core.llm import LLMClient


def _load_llm_client_for_cli(config: dict, config_path: str) -> LLMClient:
    cfg_dir = str(Path(config_path).parent) if config_path else "config"
    int_settings = IntegrationSettings.load(config_dir=cfg_dir)
    llm_from_env = int_settings.to_llm_config()
    if llm_from_env.get("backend", "mock") != "mock" or llm_from_env.get("enabled"):
        merged = dict(config)
        merged["llm"] = {**config.get("llm", {}), **llm_from_env}
        return LLMClient(merged)
    return LLMClient(config)


def run_explain_alert_cli(
    config: dict,
    args,
    *,
    ensure_database,
    load_llm_client_for_cli,
    build_deterministic_alert_explanation,
    sys_module,
) -> int:
    db = ensure_database(config)
    try:
        alert_id = int(args.explain_alert)
        alert = db.get_alert_by_id(alert_id) if hasattr(db, "get_alert_by_id") else None
        if not alert:
            print(f"Alert bulunamadı: id={alert_id}", file=sys_module.stderr)
            return 2

        reputation = []
        if hasattr(db, "get_ip_reputation_for_alert"):
            reputation = db.get_ip_reputation_for_alert(alert_id) or []
        llm_client = load_llm_client_for_cli(config, args.config)
        explain_language = getattr(llm_client, "language", "") or resolve_language(config=config, default="tr")
        alert_payload = dict(alert)
        alert_payload["ip_reputation"] = reputation
        deterministic = build_deterministic_alert_explanation(alert_payload, language=explain_language)
        llm_text = ""
        if not llm_client.is_active:
            llm_reason = getattr(llm_client, "disable_reason", "") or explanation_text("llm_disabled", explain_language)
        else:
            llm_reason = ""
            llm_text = llm_client.explain_selected_alert(alert_payload, related_events=[]) or ""

        print(deterministic["text"])
        if llm_text:
            print(f"\n{explanation_text('llm_note', explain_language)}:")
            print(llm_text)
        elif llm_reason:
            print(f"\n{explanation_text('llm_note', explain_language)}: {llm_reason}")
        return 0
    finally:
        db.close()
