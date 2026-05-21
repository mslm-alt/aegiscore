import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.rule_schema import validate_rule


def _build_rule(source):
    return {
        "id": f"RULE-{source}",
        "name": "source validation test",
        "severity": "low",
        "score": 10,
        "message": "test message",
        "tags": ["unit"],
        "condition": {"source": source},
    }


def test_validate_rule_accepts_dnf_source():
    errors, warnings = validate_rule(_build_rule("dnf"), "test.yml", {})

    assert errors == []
    assert warnings == []


def test_validate_rule_accepts_zypper_source():
    errors, warnings = validate_rule(_build_rule("zypper"), "test.yml", {})

    assert errors == []
    assert warnings == []


def test_validate_rule_existing_sources_still_pass():
    for source in ("auth", "syslog", "rpm", "dnsmasq"):
        errors, warnings = validate_rule(_build_rule(source), "test.yml", {})

        assert errors == [], source
        assert warnings == [], source


def test_validate_rule_accepts_compound_field_logic_shape():
    rule = _build_rule("auth")
    rule["condition"] = {
        "action": "exec",
        "fields": {
            "__all__": [
                {"cmdline_token_contains": "python3"},
                {"__any__": [{"cmdline_contains": "| bash"}, {"cmdline_contains": "| sh"}]},
                {"__not__": {"exit_code_eq": 0}},
            ]
        },
    }

    errors, warnings = validate_rule(rule, "test.yml", {})

    assert errors == []
    assert warnings == []


def test_validate_rule_rejects_malformed_compound_field_logic():
    rule = _build_rule("auth")
    rule["condition"] = {
        "action": "exec",
        "fields": {"__any__": ["cmdline_contains"]},
    }

    errors, _ = validate_rule(rule, "test.yml", {})

    assert errors
    assert "condition.fields.__any__[0]" in errors[0]
