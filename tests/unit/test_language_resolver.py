from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.language import explanation_text, normalize_language, resolve_language
from core.llm import LLMClient
from ui.i18n import current_language, get_language, set_language


def test_normalize_language_accepts_english_aliases():
    for value in ("en", "eng", "english", "English", "EN", "en_US", "en-GB"):
        assert normalize_language(value, default="tr") == "en"


def test_normalize_language_accepts_turkish_aliases():
    for value in ("tr", "turkish", "Türkçe", "Turkce", "TR", "tr_TR"):
        assert normalize_language(value, default="en") == "tr"


def test_normalize_language_uses_default_for_invalid_or_empty_values():
    assert normalize_language(None, default="tr") == "tr"
    assert normalize_language("", default="en") == "en"
    assert normalize_language("de", default="tr") == "tr"
    assert normalize_language("123", default="en") == "en"


def test_resolve_language_precedence_explicit_overrides_all():
    assert resolve_language(
        explicit="EN",
        ui_language="tr",
        env={"LLM_LANGUAGE": "tr"},
        config={"language": "tr", "llm": {"language": "tr"}},
        default="tr",
    ) == "en"


def test_resolve_language_ui_overrides_env_and_config():
    assert resolve_language(
        ui_language="English",
        env={"LLM_LANGUAGE": "tr"},
        config={"language": "tr", "llm": {"language": "tr"}},
        default="tr",
    ) == "en"


def test_resolve_language_prefers_aegis_env_over_llm_env_and_config():
    assert resolve_language(
        env={"AEGIS_LANGUAGE": "en", "LLM_LANGUAGE": "tr"},
        config={"language": "tr", "llm": {"language": "tr"}},
        default="tr",
    ) == "en"
    assert resolve_language(
        env={"AEGIS_LANGUAGE": "en"},
        config={"language": "tr", "llm": {"language": "tr"}},
        default="tr",
    ) == "en"


def test_resolve_language_uses_root_config_before_llm_config():
    assert resolve_language(
        config={"language": "en", "llm": {"language": "tr"}},
        default="tr",
    ) == "en"


def test_resolve_language_uses_llm_config_when_root_missing():
    assert resolve_language(
        config={"llm": {"language": "English"}},
        default="tr",
    ) == "en"


def test_resolve_language_returns_default_when_all_inputs_invalid():
    assert resolve_language(
        ui_language="xx",
        env={"LLM_LANGUAGE": "yy"},
        config={"language": "zz"},
        default="tr",
    ) == "tr"


def test_ui_i18n_normalizes_language_aliases():
    previous = current_language()
    try:
        assert set_language("Türkçe") == "tr"
        assert current_language() == "tr"
        assert get_language() == "tr"
        assert set_language("en_US") == "en"
        assert current_language() == "en"
    finally:
        set_language(previous)


def test_llm_client_uses_canonical_language_from_config_alias():
    client = LLMClient({"llm": {"enabled": False, "backend": "mock", "language": "English"}})
    assert client.language == "en"


def test_llm_client_preserves_backward_compatible_default_language():
    client = LLMClient({"llm": {"enabled": False, "backend": "mock"}})
    assert client.language == "tr"


def test_explanation_text_uses_canonical_language_aliases():
    assert explanation_text("summary_heading", "English") == "Short Summary"
    assert explanation_text("summary_heading", "Türkçe") == "Kısa Özet"
