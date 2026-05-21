from __future__ import annotations

from pathlib import Path
import sys

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.detection import DetectionEngine, REGEX_PATTERNS, SequenceDetector, get_localized_rule_text
from core.normalize import NormalizedEvent
from core.rule_schema import validate_ruleset


def _write_rules(tmp_path: Path, rules: list[dict]) -> Path:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "auth.yml").write_text(yaml.safe_dump(rules, sort_keys=False), encoding="utf-8")
    return rules_dir


def _event() -> NormalizedEvent:
    return NormalizedEvent(
        ts=1_715_000_000.0,
        host="host01",
        source="auth.log",
        category="auth",
        action="ssh_login",
        outcome="success",
        user="alice",
        src_ip="203.0.113.10",
        message="ssh_login:success",
        fields={},
    )


def _rule(**overrides) -> dict:
    payload = {
        "id": "AUTH-LOC-001",
        "name": "Localized auth rule",
        "severity": "high",
        "score": 77,
        "category": "auth",
        "message": "Default message",
        "summary": "Default summary",
        "operator_note": "Default operator note",
        "condition": {"action": "ssh_login"},
        "tags": ["auth"],
        "pack": "test",
        "pack_version": "1.0",
    }
    payload.update(overrides)
    return payload


def test_get_localized_rule_text_prefers_language_specific_field():
    rule = _rule(
        message_en="English message",
        message_tr="Turkish message",
        summary_en="English summary",
        summary_tr="Turkish summary",
        operator_note_en="English operator note",
        operator_note_tr="Turkish operator note",
    )

    assert get_localized_rule_text(rule, "message", "en") == "English message"
    assert get_localized_rule_text(rule, "message", "tr") == "Turkish message"
    assert get_localized_rule_text(rule, "summary", "en") == "English summary"
    assert get_localized_rule_text(rule, "operator_note", "tr") == "Turkish operator note"


def test_get_localized_rule_text_falls_back_to_message_for_missing_language_fields():
    rule = _rule(summary="Default summary", operator_note="Default operator note", message_en=None, message_tr=None)

    assert get_localized_rule_text(rule, "message", "en") == "Default message"
    assert get_localized_rule_text(rule, "message", "tr") == "Default message"
    assert get_localized_rule_text(rule, "summary", "en") == "Default summary"
    assert get_localized_rule_text(rule, "operator_note", "tr") == "Default operator note"


def test_get_localized_rule_text_uses_message_fallback_when_summary_or_note_missing():
    rule = _rule(summary="", operator_note="")

    assert get_localized_rule_text(rule, "summary", "en") == "Default message"
    assert get_localized_rule_text(rule, "operator_note", "tr") == "Default message"


def test_detection_engine_uses_english_localized_rule_text(tmp_path: Path):
    rules_dir = _write_rules(
        tmp_path,
        [
            _rule(
                message_en="English message",
                message_tr="Turkish message",
                summary_en="English summary",
                summary_tr="Turkish summary",
                operator_note_en="English operator note",
                operator_note_tr="Turkish operator note",
            )
        ],
    )
    engine = DetectionEngine(config={"rules_dir": str(rules_dir), "rules_source": "yaml", "language": "en"}, allow_empty_rules=False)

    results = engine.analyze(_event())

    assert len(results) == 1
    hit = results[0]
    assert hit.rule_id == "AUTH-LOC-001"
    assert hit.severity == "high"
    assert hit.score == 77
    assert hit.message == "English message"
    assert hit.details["summary"] == "English summary"
    assert hit.details["operator_note"] == "English operator note"


def test_detection_engine_uses_turkish_localized_rule_text(tmp_path: Path):
    rules_dir = _write_rules(
        tmp_path,
        [
            _rule(
                message_en="English message",
                message_tr="Turkish message",
                summary_en="English summary",
                summary_tr="Turkish summary",
                operator_note_en="English operator note",
                operator_note_tr="Turkish operator note",
            )
        ],
    )
    engine = DetectionEngine(config={"rules_dir": str(rules_dir), "rules_source": "yaml", "language": "tr"}, allow_empty_rules=False)

    results = engine.analyze(_event())

    assert len(results) == 1
    hit = results[0]
    assert hit.message == "Turkish message"
    assert hit.details["summary"] == "Turkish summary"
    assert hit.details["operator_note"] == "Turkish operator note"


def test_detection_engine_falls_back_to_default_message_when_language_specific_missing(tmp_path: Path):
    rules_dir = _write_rules(
        tmp_path,
        [
            _rule(
                message="Legacy message",
                summary="Legacy summary",
                operator_note="Legacy operator note",
            )
        ],
    )
    engine = DetectionEngine(config={"rules_dir": str(rules_dir), "rules_source": "yaml", "language": "en_US"}, allow_empty_rules=False)

    results = engine.analyze(_event())

    assert len(results) == 1
    hit = results[0]
    assert hit.message == "Legacy message"
    assert hit.details["summary"] == "Legacy summary"
    assert hit.details["operator_note"] == "Legacy operator note"
    assert hit.rule_id == "AUTH-LOC-001"
    assert hit.severity == "high"
    assert hit.score == 77


def test_validate_ruleset_accepts_legacy_and_localized_rule_fields():
    legacy_rule = _rule()
    localized_rule = _rule(
        id="AUTH-LOC-002",
        message_en="English message",
        message_tr="Turkish message",
        summary_en="English summary",
        summary_tr="Turkish summary",
        operator_note_en="English operator note",
        operator_note_tr="Turkish operator note",
    )

    errors, warnings = validate_ruleset([legacy_rule, localized_rule], "auth.yml", strict=False)

    assert errors == []
    assert isinstance(warnings, list)


def test_internal_regex_rule_prefers_english_localized_message_without_turkish_fallback():
    rule = next(rule for rule in REGEX_PATTERNS if rule["id"] == "REGEX-001")

    assert get_localized_rule_text(rule, "message", "en") == "Reverse Shell Pattern"
    assert get_localized_rule_text(rule, "message", "tr") == "Reverse shell girişimi tespit edildi"
    assert rule["severity"] == "critical"
    assert rule["score"] == 95


def test_internal_sequence_rule_prefers_english_localized_metadata_without_turkish_fallback():
    seq = next(rule for rule in SequenceDetector.SEQUENCES if rule["id"] == "SEQ-061")

    assert get_localized_rule_text(seq, "message", "en") == "Login Success → Tunnel or Reverse Shell"
    assert "ş" not in get_localized_rule_text(seq, "message", "en").lower()
    assert get_localized_rule_text(seq, "summary", "en").startswith("This internal detection matched the defined conditions")
    assert get_localized_rule_text(seq, "operator_note", "en").startswith("Validate the related context")
    assert get_localized_rule_text(seq, "message", "tr") == "Başarılı erişim ardından tunnel veya reverse shell davranışı görüldü"
    assert seq["severity"] == "critical"
    assert seq["score"] == 94
