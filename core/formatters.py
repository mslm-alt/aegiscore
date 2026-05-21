from __future__ import annotations
"""
core/formatters.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Terminal output formatters.

Split out of main.py — fmt_* and print_* functions live here.
"""

import time
import logging
from typing import Dict
from core.language import normalize_language, system_text

logger = logging.getLogger(__name__)

# ── Colors ─────────────────────────────────────────────────────────────────

COLORS = {"low": "\033[94m", "medium": "\033[93m",
          "high": "\033[91m", "critical": "\033[95m"}
ICONS  = {"low": "ℹ️ ", "medium": "⚠️ ", "high": "🔴", "critical": "🚨"}
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"


def _fmt_top_breakdown(bucket: Dict, limit: int = 3) -> str:
    if not isinstance(bucket, dict) or not bucket:
        return "-"
    top = sorted(
        ((str(key), int(value or 0)) for key, value in bucket.items()),
        key=lambda item: (-item[1], item[0]),
    )[:limit]
    return ", ".join(f"{key}={value}" for key, value in top)


def fmt_alert(event, rule_id: str, severity: str,
              score: float, message: str, tag: str = "") -> None:
    c  = COLORS.get(severity, "")
    ic = ICONS.get(severity, "⚡")
    ts = time.strftime("%H:%M:%S", time.localtime(event.ts))
    # Bug #19: use getattr instead of direct event field access to avoid AttributeError
    host    = getattr(event, "host",    "") or "localhost"
    user    = getattr(event, "user",    "")
    src_ip  = getattr(event, "src_ip",  "")
    process = getattr(event, "process", "")
    pid     = getattr(event, "pid",     "")
    msg_txt = getattr(event, "message", "")
    lines = [
        f"\n{c}{BOLD}{'─'*58}{RESET}",
        f"{c}{ic} [{severity.upper()}] {rule_id}{tag}{RESET}",
        f"  {ts}  {host}",
        f"  {message}",
    ]
    if user:    lines.append(f"  user={user}")
    if src_ip:  lines.append(f"  ip={src_ip}")
    if process: lines.append(f"  proc={process}[{pid}]")
    lines.append(f"  score={score:.0f}/100")
    lines.append(f"  → {msg_txt[:90]}")
    lines.append(f"{c}{'─'*58}{RESET}")
    print("\n".join(lines))


def fmt_monitor_alert(alert) -> None:
    c  = COLORS.get(alert.severity, "")
    ic = ICONS.get(alert.severity, "⚡")
    ts = time.strftime("%H:%M:%S")
    print(f"\n{c}{BOLD}{'─'*58}{RESET}")
    print(f"{c}{ic} [{alert.severity.upper()}] {alert.rule_id} [MONITOR]{RESET}")
    print(f"  {ts}")
    print(f"  {alert.message}")
    if alert.details:
        for k, v in list(alert.details.items())[:3]:
            print(f"  {k}={v}")
    print(f"{c}{'─'*58}{RESET}")


def fmt_incident(inc: dict, language: str = "tr") -> None:
    lang = normalize_language(language, default="tr")
    sev = inc.get("severity", "high")
    c   = COLORS.get(sev, "")
    print(f"\n{c}{BOLD}{'═'*58}{RESET}")
    print(f"{c}⚡ INCIDENT: {inc['incident_id']}{RESET}")
    print(f"  {inc['title']}")
    print(f"  {system_text('severity', lang):<8}: {sev.upper()} | {system_text('risk_score', lang)}: {inc['risk_score']:.0f}/100")
    print(f"  {system_text('entity', lang):<8}: {inc.get('entity','')}")
    print(f"  {system_text('alerts', lang).capitalize():<8}: {inc.get('alert_count',0)} ({inc.get('duration_sec',0):.0f}s)")
    print(f"  Tags   : {', '.join(inc.get('tags',[]))}")
    print(f"  {system_text('description', lang):<8}: {inc.get('summary','')[:120]}")
    print(f"{c}{'═'*58}{RESET}")


def fmt_rule_stats(db, detection_engine, language: str = "tr") -> None:
    lang = normalize_language(language, default="tr")
    """Show rule statistics in the terminal."""
    stats   = db.get_rule_stats(limit=30, hours=168)
    all_ids = []
    try:
        for rule in detection_engine.rules:
            all_ids.append(rule.id)
    except AttributeError as _re:
        logger.debug(f"[RuleStats] Kural listesi alınamadı: {_re}")

    never_fired = db.get_never_fired_rules(all_ids, hours=168) if all_ids else []

    sep72 = "─"*72
    print(f"\n{BOLD}{CYAN}{sep72}{RESET}")
    print(f"{BOLD}  📋 {system_text('rule_statistics', lang)} ({system_text('last_7_days_short', lang)}){RESET}")
    print("─"*72)

    if not stats:
        print(f"  {YELLOW}{system_text('no_rule_hits_7d', lang)}{RESET}")
    else:
        print(f"  {system_text('rule_id', lang):<28} {system_text('hit', lang):>6}  {system_text('avg_score', lang):>9}  {system_text('last_hit', lang):<20}  {system_text('tactic', lang)}")
        print(f"  {'─'*28} {'─'*6}  {'─'*9}  {'─'*20}  {'─'*12}")
        import datetime
        for r in stats:
            last   = datetime.datetime.fromtimestamp(r["last_hit"]).strftime("%m-%d %H:%M") if r["last_hit"] else "-"
            tactic = (r.get("mitre_tactic") or "")[:12]
            rid    = r["rule_id"][:27]
            score  = r["avg_score"] or 0
            fp_warn = f" {YELLOW}⚠ {system_text('fp_warn', lang)}{RESET}" if r["hit_count"] > 100 else ""
            print(f"  {rid:<28} {r['hit_count']:>6}  {score:>9.1f}  {last:<20}  {tactic}{fp_warn}")

    if never_fired:
        print(f"\n  {YELLOW}⚠ {system_text('never_fired_rules', lang)} ({len(never_fired)}){RESET}:")
        for rid in never_fired[:15]:
            print(f"    - {rid}")
        if len(never_fired) > 15:
            print(f"    {system_text('and_more', lang, count=len(never_fired)-15)}")

    top_entities = db.get_top_entities(hours=24, limit=5)
    if top_entities:
        print(f"\n  {BOLD}{system_text('top_entities_24h', lang)}{RESET}")
        for e in top_entities:
            print(f"    {e['entity']:<30} {e['alert_count']:>5} {system_text('alerts', lang)}  max:{e['max_score']:.0f}")

    print("─"*72)


def fmt_phase_status(status: dict, language: str = "tr") -> None:
    lang = normalize_language(language, default="tr")
    p    = status["current_phase"]
    prog = status["next_phase"]
    st   = status["stats"]
    accounting_note = status.get("accounting_note", "").strip()
    print(f"\n{BOLD}{CYAN}{'─'*58}{RESET}")
    print(f"{BOLD}  📊 {system_text('system_phase_status', lang)}{RESET}")
    print(f"  {system_text('current_phase', lang)} : PHASE_{p} — {status['phase_name']}")
    print(f"  {system_text('description', lang):<10}: {status['description']}")
    if accounting_note:
        print(f"  {system_text('accounting', lang):<10}: {accounting_note}")
    print(f"  {system_text('uptime', lang):<10}: {st['uptime_days']:.1f} {system_text('days', lang)} ({st['uptime_hours']:.1f} {system_text('hours', lang)})")
    print(f"  {system_text('event', lang):<10}: {st['total_events']:,}")
    print(f"  {system_text('user', lang):<10}: {st['unique_users']} | IP: {st['unique_ips']}")
    print(
        f"  {system_text('duplicate', lang):<10}: {st.get('duplicate_count', 0)} | "
        f"src: {_fmt_top_breakdown(st.get('duplicate_breakdown_by_source', {}))} | "
        f"kind: {_fmt_top_breakdown(st.get('duplicate_breakdown_by_kind', {}))}"
    )
    print(
        f"  {system_text('parse_fail', lang):<10}: {st.get('parse_fail_count', 0)} | "
        f"src: {_fmt_top_breakdown(st.get('parse_fail_breakdown_by_source', {}))} | "
        f"reason: {_fmt_top_breakdown(st.get('parse_fail_breakdown_by_reason', {}))}"
    )
    if prog.get("next_phase") is not None:
        print(f"\n  {system_text('next_phase_label', lang)}: PHASE_{prog['next_phase']} — {prog.get('next_name','')}")
        print(f"  {system_text('progress', lang)}: %{prog['progress_pct']}")
        for c in prog["criteria"]:
            tick = "✅" if c["done"] else "⏳"
            print(f"    {tick} {c['name']}: {c['current']} / {c['needed']}")
    else:
        print(f"\n  {GREEN}✅ {system_text('max_phase_reached', lang)}{RESET}")
    gate = dict(status.get("phase_gate", {}) or {})
    if gate:
        ready_families = ", ".join(list(gate.get("ready_family_ids", []) or [])) or "-"
        ml_ready_families = ", ".join(list(gate.get("ml_alert_family_enabled_families", []) or [])) or "-"
        blockers = ", ".join(list(gate.get("phase_gate_blockers", []) or [])[:8]) or "-"
        print("\n  Label-based phase gate:")
        print(f"    phase_gate_source={gate.get('phase_gate_source', 'label_training')}")
        print(f"    event_telemetry_ok={gate.get('event_telemetry_ok', False)}")
        print(f"    label_training_gate_ok={gate.get('label_training_gate_ok', False)}")
        print(f"    ready_seed_families={ready_families}")
        print(f"    ready_family_count={gate.get('ready_family_count', 0)}")
        print(f"    ml_paused={gate.get('ml_paused', False)}")
        print(f"    open_incident_blocker={gate.get('open_incident_blocker', False)}")
        print(f"    blockers={blockers}")
        print(
            "    training_state="
            f"first_model_training_completed={gate.get('first_model_training_completed', False)} "
            f"first_model_evaluation_passed={gate.get('first_model_evaluation_passed', False)} "
            f"first_ml_model_ready={gate.get('first_ml_model_ready', False)} "
            f"ml_alert_family_ready={gate.get('ml_alert_family_ready', False)} "
            f"ml_alert_family_enabled_families={ml_ready_families} "
            f"last_training_status={gate.get('last_training_status', '') or '-'} "
            f"last_evaluation_status={gate.get('last_evaluation_status', '') or '-'}"
        )
    layers = status["active_layers"]
    aktif  = [k for k, v in layers.items() if v]
    pasif  = [k for k, v in layers.items() if not v]
    print(f"\n  {system_text('active_layers', lang)} : {', '.join(aktif)}")
    if pasif:
        print(f"  {system_text('inactive_layers', lang)} : {', '.join(pasif)}")
    print(f"{BOLD}{CYAN}{'─'*58}{RESET}\n")
