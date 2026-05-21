from __future__ import annotations

from pathlib import Path
import re
import sys

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


RULES_ROOT = Path(__file__).resolve().parents[2] / "rules"
TURKISH_CHAR_RE = re.compile(r"[çğıöşüÇĞİÖŞÜ]")
TURKISH_WORD_RE = re.compile(
    r"\b(?:saldırı|giriş|tespit|şüpheli|engellendi|başarılı|başarısız|kullanıcı|oturum|kanıt|kural|uyarı)\b",
    re.IGNORECASE,
)
EN_LOCALIZED_FIELDS = ("message_en", "summary_en", "operator_note_en")


def _rule_files() -> list[Path]:
    return sorted(RULES_ROOT.rglob("*.yml"))


def test_all_rule_yaml_files_parse_as_lists():
    files = _rule_files()
    assert files, "No rule YAML files found."
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(data, list), f"{path} did not parse to a rule list."


def test_every_rule_has_non_empty_bilingual_messages():
    for path in _rule_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for rule in data:
            assert isinstance(rule, dict), f"{path} contains a non-dict rule entry."
            rid = rule.get("id", "?")
            assert str(rule.get("message", "") or "").strip(), f"{path}:{rid} missing message"
            assert str(rule.get("message_en", "") or "").strip(), f"{path}:{rid} missing message_en"
            assert str(rule.get("message_tr", "") or "").strip(), f"{path}:{rid} missing message_tr"


def test_message_en_has_no_turkish_leakage():
    leaks: list[str] = []
    for path in _rule_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for rule in data:
            rid = rule.get("id", "?")
            text = str(rule.get("message_en", "") or "").strip()
            if TURKISH_CHAR_RE.search(text) or TURKISH_WORD_RE.search(text):
                leaks.append(f"{path}:{rid}:{text}")
    assert not leaks, "Turkish leakage found in message_en:\n" + "\n".join(leaks[:50])


def test_english_localized_fields_have_no_turkish_leakage():
    leaks: list[str] = []
    for path in _rule_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for rule in data:
            rid = rule.get("id", "?")
            for field in EN_LOCALIZED_FIELDS:
                text = str(rule.get(field, "") or "").strip()
                if text and (TURKISH_CHAR_RE.search(text) or TURKISH_WORD_RE.search(text)):
                    leaks.append(f"{path}:{rid}:{field}:{text}")
    assert not leaks, "Turkish leakage found in English localized fields:\n" + "\n".join(leaks[:50])


def test_summary_and_operator_note_have_bilingual_variants_when_present():
    for path in _rule_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for rule in data:
            rid = rule.get("id", "?")
            summary = str(rule.get("summary", "") or "").strip()
            note = str(rule.get("operator_note", "") or "").strip()
            if summary:
                assert str(rule.get("summary_en", "") or "").strip(), f"{path}:{rid} missing summary_en"
                assert str(rule.get("summary_tr", "") or "").strip(), f"{path}:{rid} missing summary_tr"
            if note:
                assert str(rule.get("operator_note_en", "") or "").strip(), f"{path}:{rid} missing operator_note_en"
                assert str(rule.get("operator_note_tr", "") or "").strip(), f"{path}:{rid} missing operator_note_tr"
