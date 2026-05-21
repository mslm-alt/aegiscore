"""
core/rule_schema.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Rule Lint / Schema Validation

Checks:
  1. Required fields (id, condition, severity, score, message)
  2. severity enum (low/medium/high/critical)
  3. score is numeric and in the 0-100 range
  4. whether platform is a valid enum
  5. whether source alias is valid
  6. whether the condition structure is complete
  7. MITRE format (TA####, T####)
  8. Duplicate ID (across files)
  9. Platform variant format (whether the id + platform combination is unique)
 10. name field is recommended (warning)
"""

import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

# ── Valid enum values ───────────────────────────────────────────────────────

VALID_PLATFORMS = {"debian", "rhel", "suse", "generic"}

VALID_SOURCES = {
    "auth", "syslog", "journald", "auditd",
    "nginx", "apache2", "mysql", "postgresql",
    "kernel", "ufw", "firewalld", "iptables",
    "cron", "dpkg", "rpm", "dnf", "zypper", "systemd",
    "network", "process", "dns", "ssh",
    "sudo", "su", "pam",
    # DNS sub-sources
    "dnsmasq", "named",
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}

VALID_MITRE_TACTIC_PREFIX  = "TA"
VALID_MITRE_TECHNIQUE_PREFIX = "T"

# Required nested fields inside condition
# fields: event.fields dict matching (web attack rules)
# action_contains: action string partial match (MON-002 vb.)
CONDITION_REQUIRED_ONE_OF = {"action", "pattern", "field", "source", "type", "fields", "action_contains", "lotl", "first_seen"}

FIELD_COMPOUND_KEYS = {"__any__", "__all__", "__not__"}

OPTIONAL_LOCALIZED_FIELDS = (
    "message_en",
    "message_tr",
    "summary_en",
    "summary_tr",
    "operator_note_en",
    "operator_note_tr",
)


def _validate_field_conditions(field_cond: Dict, loc: str,
                               errors: List[str], warnings: List[str]) -> None:
    if not isinstance(field_cond, dict):
        errors.append(f"[{loc}] condition.fields dict olmali")
        return

    for key, value in field_cond.items():
        if key in ("__any__", "__all__"):
            if not isinstance(value, list) or not value:
                errors.append(f"[{loc}] condition.fields.{key} dolu liste olmali")
                continue
            for idx, item in enumerate(value):
                if not isinstance(item, dict):
                    errors.append(f"[{loc}] condition.fields.{key}[{idx}] dict olmali")
                    continue
                _validate_field_conditions(item, loc, errors, warnings)
        elif key == "__not__":
            if isinstance(value, dict):
                _validate_field_conditions(value, loc, errors, warnings)
            elif isinstance(value, list):
                for idx, item in enumerate(value):
                    if not isinstance(item, dict):
                        errors.append(f"[{loc}] condition.fields.__not__[{idx}] dict olmali")
                        continue
                    _validate_field_conditions(item, loc, errors, warnings)
            else:
                errors.append(f"[{loc}] condition.fields.__not__ dict veya liste olmali")


# ── Main validation function ────────────────────────────────────────────────

def validate_rule(rule: Dict, filename: str,
                  seen_ids: Dict[str, str]) -> Tuple[List[str], List[str]]:
    """
    Validate a single rule dict.

    Returns:
        (errors, warnings)
        errors   → sistemi durdurur
        warnings → logged, but the system continues
    """
    errors:   List[str] = []
    warnings: List[str] = []
    rid = rule.get("id", "")
    loc = f"{filename}:{rid or '?'}"

    # ── 1. Zorunlu alanlar ───────────────────────────────────────────────────
    for field in ("id", "severity", "score", "message", "condition"):
        val = rule.get(field)
        if val is None or (isinstance(val, str) and not val.strip()):
            errors.append(f"[{loc}] Zorunlu alan eksik veya boş: '{field}'")

    if not rid:
        return errors, warnings  # id yoksa geri kalan kontroller anlamsız

    # ── 2. severity enum ─────────────────────────────────────────────────────
    sev = rule.get("severity", "")
    if sev and sev not in VALID_SEVERITIES:
        errors.append(
            f"[{loc}] Geçersiz severity '{sev}' "
            f"(geçerli: {sorted(VALID_SEVERITIES)})"
        )

    # ── 3. score range ────────────────────────────────────────────────────────
    score = rule.get("score")
    if score is not None:
        if not isinstance(score, (int, float)):
            errors.append(f"[{loc}] score sayı olmalı, '{type(score).__name__}' geldi")
        elif not (0 <= score <= 100):
            errors.append(f"[{loc}] score 0-100 aralığında olmalı, {score} geldi")

    # ── 4. platform enum ─────────────────────────────────────────────────────
    platforms = rule.get("platform", [])
    if platforms:
        if not isinstance(platforms, list):
            errors.append(f"[{loc}] 'platform' liste olmalı, {type(platforms).__name__} geldi")
        else:
            invalid = [p for p in platforms if p not in VALID_PLATFORMS]
            if invalid:
                errors.append(
                    f"[{loc}] Geçersiz platform değeri: {invalid} "
                    f"(geçerli: {sorted(VALID_PLATFORMS)})"
                )

    # ── 5. source alias ──────────────────────────────────────────────────────
    condition = rule.get("condition", {})
    if isinstance(condition, dict):
        sources = condition.get("source", [])
        if isinstance(sources, str):
            sources = [sources]
        if isinstance(sources, list):
            invalid_src = [s for s in sources if s not in VALID_SOURCES]
            if invalid_src:
                errors.append(
                    f"[{loc}] Geçersiz source alias: {invalid_src} "
                    f"(geçerli: {sorted(VALID_SOURCES)})"
                )

        # ── 6. condition structure ─────────────────────────────────────────────
        has_trigger = any(k in condition for k in CONDITION_REQUIRED_ONE_OF)
        if not has_trigger:
            errors.append(
                f"[{loc}] condition içinde tetikleyici alan yok "
                f"(biri gerekli: {sorted(CONDITION_REQUIRED_ONE_OF)})"
            )
        if "fields" in condition:
            _validate_field_conditions(condition["fields"], loc, errors, warnings)
    elif condition:
        # string condition (regex gibi) — kabul edilebilir
        pass

    # ── 7. MITRE format ──────────────────────────────────────────────────────
    tactic    = rule.get("mitre_tactic", "")
    technique = rule.get("mitre_technique", "")
    if tactic and not (tactic.startswith(VALID_MITRE_TACTIC_PREFIX) and
                       tactic[2:].isdigit() and len(tactic) == 6):
        warnings.append(f"[{loc}] mitre_tactic format hatalı: '{tactic}' (beklenen: TA####)")
    if technique and not (technique.startswith(VALID_MITRE_TECHNIQUE_PREFIX) and
                          technique[1:].replace(".", "").isdigit()):
        warnings.append(f"[{loc}] mitre_technique format hatalı: '{technique}' (beklenen: T####)")

    # ── 8. Duplicate ID ──────────────────────────────────────────────────────
    if rid in seen_ids:
        errors.append(
            f"[{loc}] Duplicate rule ID '{rid}' "
            f"(ilk tanım: {seen_ids[rid]})"
        )
    else:
        seen_ids[rid] = loc

    # ── 9. Platform variant uniqueness ───────────────────────────────────────
    if platforms:
        for p in platforms:
            variant_key = f"{rid}@{p}"
            if variant_key in seen_ids:
                warnings.append(
                    f"[{loc}] Platform varyantı çakışıyor: '{rid}' platform='{p}' "
                    f"zaten {seen_ids[variant_key]}'de tanımlı"
                )
            else:
                seen_ids[variant_key] = loc

    # ── 10. Recommended fields ───────────────────────────────────────────────
    for field in OPTIONAL_LOCALIZED_FIELDS:
        value = rule.get(field)
        if value is not None and not isinstance(value, str):
            errors.append(f"[{loc}] '{field}' string olmalı")

    if not rule.get("name"):
        warnings.append(f"[{loc}] 'name' alanı önerilir (tanımlayıcı başlık)")
    if not rule.get("tags"):
        warnings.append(f"[{loc}] 'tags' alanı önerilir (kategorilendirme)")

    return errors, warnings


def validate_ruleset(rules: List[Dict], filename: str,
                     seen_ids: Dict[str, str] = None,
                     strict: bool = True) -> Tuple[List[str], List[str]]:
    """
    Validate all rules in a file.

    strict=True  → error varsa sys.exit(1)
    strict=False → sadece raporla
    """
    if seen_ids is None:
        seen_ids = {}

    all_errors:   List[str] = []
    all_warnings: List[str] = []

    for rule in rules:
        if not isinstance(rule, dict):
            all_errors.append(f"[{filename}] Kural dict olmalı, {type(rule).__name__} geldi")
            continue
        errs, warns = validate_rule(rule, filename, seen_ids)
        all_errors.extend(errs)
        all_warnings.extend(warns)

    return all_errors, all_warnings


def report_and_exit_if_errors(errors: List[str],
                               warnings: List[str],
                               strict: bool = True):
    """
    Report errors and warnings. Exit in strict mode if errors are present.
    """
    SEP = "━" * 60

    if warnings:
        print(f"\n{SEP}")
        print(f"  ⚠️  Kural Uyarıları ({len(warnings)} adet)")
        print(SEP)
        for w in warnings:
            print(f"  ⚠  {w}")

    if errors:
        print(f"\n{SEP}")
        print(f"  ❌ Kural Hataları ({len(errors)} adet) — sistem başlatılamaz")
        print(SEP)
        for e in errors:
            print(f"  ❌ {e}")
        print(f"\n  Yukarıdaki hataları düzelt ve yeniden başlat.")
        print(f"{SEP}\n")
        if strict:
            import sys
            sys.exit(1)

    return len(errors) == 0
