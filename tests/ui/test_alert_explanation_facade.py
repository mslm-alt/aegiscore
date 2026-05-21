from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import ui.backend_facade as backend_facade
from ui.models import bounded_history
import pytest


class _AlertDb:
    def __init__(self, alert=None, alerts=None):
        self._alert = alert
        self._alerts = alerts or []

    def get_recent_alerts(self, limit=100, hours=24):
        return list(self._alerts)[:limit]

    def get_alert_by_id(self, alert_id):
        if self._alert and int(self._alert.get("id", -1)) == int(alert_id):
            return dict(self._alert)
        return None

    def close(self):
        return None


def _integrations_stub(**overrides):
    defaults = {
        "_raw": {},
        "llm_api_key": lambda self: "",
        "llm_backend": "mock",
        "llm_model": "",
        "llm_language": "tr",
    }
    defaults.update(overrides)
    return type("I", (), defaults)()


def _sample_alert():
    return {
        "id": 11,
        "ts": 1710000000,
        "severity": "high",
        "rule_id": "AUTH-001",
        "risk_score": 88,
        "entity": "alice",
        "source": "auth_log",
        "message": "ssh brute force",
        "context_json": {"src_ip": "8.8.8.8", "why_triggered_human": "Aynı kaynaktan tekrar eden auth başarısızlıkları."},
    }


def test_collect_explainable_alerts_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "collect_alerts", lambda **kwargs: {
        "status": "ok",
        "alerts": [backend_facade._normalize_alert(_sample_alert())],
        "error": None,
    })

    result = backend_facade.collect_explainable_alerts(limit=10)

    assert result["status"] == "ok"
    assert result["alerts"]
    assert {"id", "timestamp_text", "severity", "rule_id", "risk_score", "entity", "source_ip", "message", "source"} <= set(result["alerts"][0])


def test_explain_alert_for_ui_missing_alert_graceful(monkeypatch):
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "degraded",
        "alert": None,
        "detail": {},
        "error": "alert_not_found:999",
    })

    result = backend_facade.explain_alert_for_ui(999)

    assert result["status"] == "degraded"
    assert "alert_not_found" in result["error"]


def test_alert_explanation_facade_fallback_path_no_exception(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {
            "related_alert_count": 3,
            "same_source_ip_count": 2,
            "same_rule_count": 2,
            "high_critical_related_count": 1,
            "first_seen": "2024-03-09 00:00:00",
            "last_seen": "2024-03-09 00:10:00",
            "top_related_rules": [{"rule_id": "AUTH-001", "count": 2}],
        },
    })
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"llm": {"enabled": False}}})

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)

    assert result["status"] in {"ok", "degraded"}
    assert result["fallback_used"] is True
    assert result["used_llm"] is False
    assert result["rule_id"] == "AUTH-001"
    assert result["severity"] == "high"
    assert float(result["risk_score"]) == 88.0
    assert result["summary"].strip()
    assert result["why"].strip()
    assert result["risk"].strip()
    assert result["evidence"].strip()
    assert isinstance(result["recommended_review_steps"], list)
    assert result["metadata"]["investigation_context"]["same_source_ip_count"] == 2
    assert "ilişkili alarm sayısı: 3" in result["raw_text"].lower()
    assert "İlişkili olay özeti" in result["raw_text"]
    assert "Aynı IP/kullanıcı/kural ilişkisi" in result["raw_text"]
    assert "Zaman aralığı" in result["raw_text"]
    assert "High/Critical ilişkili alarm sayısı" in result["raw_text"]
    assert "Önlem / Mitigation" in result["full_explanation"]
    assert "False Positive Kontrolü" in result["full_explanation"]
    assert "Kanıtlar" in result["full_explanation"]
    assert len(result["full_explanation"]) >= 700


def test_explain_alert_for_ui_disabled_llm_marks_deterministic_mode(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {},
    })
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"llm": {"enabled": False}}})

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)

    assert result["fallback_used"] is True
    assert "deterministik açıklama gösteriliyor" in result["full_explanation"].lower()
    assert "LLM devre dışı" in result["full_explanation"]


def test_explain_alert_for_ui_english_disabled_llm_returns_english_fallback(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {},
    })
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"language": "en", "llm": {"enabled": False}}})

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)

    assert result["language"] == "en"
    assert result["fallback_used"] is True
    assert "LLM is disabled, showing the deterministic explanation." in result["full_explanation"]
    assert "Short Summary" in result["full_explanation"]
    assert "Technical Meaning" in result["full_explanation"]
    assert "Evidence" in result["full_explanation"]
    for token in ("Açıklama", "Kanıt", "Kural", "tespit edildi", "kaynak"):
        assert token not in result["full_explanation"]


def test_explain_alert_for_ui_context_sanitized(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {
            "related_alert_count": 1,
            "same_source_ip_count": 1,
            "same_rule_count": 1,
            "high_critical_related_count": 1,
            "first_seen": "2024-03-09 00:00:00",
            "last_seen": "2024-03-09 00:01:00",
            "top_related_rules": [{"rule_id": "token=SECRET-RULE", "count": 1}],
        },
    })
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"llm": {"enabled": False}}})

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)
    text = backend_facade._stringify_payload(result["metadata"]["investigation_context"])

    assert "SECRET-RULE" not in text
    assert "redacted" in text.lower()


def test_explain_alert_for_ui_metadata_investigation_context_schema(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {
            "related_alert_count": 4,
            "same_source_ip_count": 3,
            "same_entity_count": 2,
            "same_rule_count": 3,
            "nearby_time_count": 1,
            "same_incident_count": 0,
            "high_critical_related_count": 2,
            "first_seen": "2024-03-09 00:00:00",
            "last_seen": "2024-03-09 00:04:00",
            "top_related_rules": [{"rule_id": "AUTH-001", "count": 3}],
        },
    })
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"llm": {"enabled": False}}})

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=False)
    context = dict(result["metadata"]["investigation_context"])

    assert {"related_alert_count", "same_source_ip_count", "same_entity_count", "same_rule_count", "nearby_time_count", "same_incident_count", "high_critical_related_count", "first_seen", "last_seen", "top_related_rules"} <= set(context)


def test_explain_alert_for_ui_llm_response_sections_fill_popup_fields(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {},
    })

    class _Client:
        backend_name = "mock"
        is_active = True
        disable_reason = ""

        def __init__(self, config):
            return None

        def explain_selected_alert(self, alert, related_events=None):
            return (
                "Kısa Özet\nSSH brute force davranışı gözlendi.\n\n"
                "Teknik Anlam\nKısa sürede tekrar eden başarısız kimlik doğrulama denemeleri var.\n\n"
                "Risk Değerlendirmesi\nHesap ele geçirme denemesi olabilir.\n\n"
                "Kanıtlar\n- Kural=AUTH-001\n- Kaynak IP=8.8.8.8\n\n"
                "Olası Saldırı Senaryosu\nParola tahmini veya credential stuffing.\n\n"
                "False Positive Kontrolü\nBakım otomasyonu olup olmadığını kontrol et.\n\n"
                "Önlem / Mitigation\nRate limit ve MFA zorunluluğunu değerlendir.\n\n"
                "Sonraki İnceleme Adımları\n- Aynı IP için diğer alarmları incele.\n\n"
                "Güven Skoru\n82/100"
            )

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"llm": {"enabled": True}}})
    import core.llm as llm_module
    monkeypatch.setattr(llm_module, "LLMClient", _Client)

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)

    assert result["used_llm"] is True
    assert result["fallback_used"] is False
    assert result["llm_quality_passed"] is True
    assert result["summary"] == "SSH brute force davranışı gözlendi."
    assert "başarısız kimlik doğrulama" in result["why"].lower()
    assert "hesap ele geçirme" in result["risk"].lower()
    assert "Kural=AUTH-001" in result["evidence"]
    assert "Rate limit" in result["full_explanation"]


def test_explain_alert_for_ui_accepts_high_quality_partial_heading_response(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {},
    })

    class _Client:
        backend_name = "gemini"
        is_active = True
        disable_reason = ""

        def __init__(self, config):
            return None

        def explain_selected_alert(self, alert, related_events=None):
            return (
                "Özet: AUTH-001 alarmı auth_log kaynağında alice için tekrar eden başarısız SSH giriş denemeleri nedeniyle üretildi.\n"
                "Teknik değerlendirme: 8.8.8.8 adresinden kısa sürede yoğun deneme var ve bu davranış brute force veya credential stuffing ile uyumlu görünüyor.\n"
                "Risk analizi: high severity ve 88 risk skoru nedeniyle hesap ele geçirme ihtimali operasyonel olarak ciddiye alınmalı.\n"
                "Kanıt alanları: rule_id=AUTH-001, severity=high, entity=alice, source=auth_log, src_ip=8.8.8.8, message=ssh brute force.\n"
                "Yanlış pozitif kontrolü: planlı bakım, yanlış parola giren meşru kullanıcı veya test otomasyonu olup olmadığını auth.log ve erişim kayıtlarıyla doğrula.\n"
                "Mitigasyon: MFA zorunluluğunu kontrol et, rate limiting ayarlarını gözden geçir ve aynı IP için ek alarm korelasyonu yap.\n"
                "Doğrulama adımları: Aynı kullanıcı ve IP için son 15 dakikadaki eventleri incele, başarılı giriş olup olmadığını ayrıca kontrol et.\n"
                "Güven skoru: 84/100"
            )

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"llm": {"enabled": True}}})
    import core.llm as llm_module
    monkeypatch.setattr(llm_module, "LLMClient", _Client)

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)

    assert result["used_llm"] is True
    assert result["fallback_used"] is False
    assert result["provider"] == "gemini"
    assert result["llm_quality_passed"] is True
    assert result["llm_quality_reason"] in {"structured_sections", "partial_structured_sections", "contextual_actionable"}
    assert "AUTH-001 alarmı" in result["full_explanation"]
    assert "brute force" in result["why"].lower()
    assert "risk skoru" in result["risk"].lower() or "high severity" in result["risk"].lower()
    assert "rule_id=AUTH-001" in result["evidence"]
    assert result["recommended_review_steps"]
    assert "bakım" in result["false_positive_notes"].lower()


def test_explain_alert_for_ui_accepts_contextual_longform_response_without_strict_headings(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {},
    })

    class _Client:
        backend_name = "openai"
        is_active = True
        disable_reason = ""

        def __init__(self, config):
            return None

        def explain_selected_alert(self, alert, related_events=None):
            return (
                "AUTH-001 kuralı, auth_log içinde alice hesabına karşı 8.8.8.8 adresinden gelen tekrar eden ssh brute force davranışını işaret ediyor. "
                "Bu alarmın high severity ve 88 risk skoru taşıması, denemelerin sadece kullanıcı hatası değil potansiyel hesap ele geçirme hazırlığı olabileceğini gösterir. "
                "Kanıt olarak rule_id, source, source_ip, entity ve ssh brute force mesajı birlikte değerlidir. "
                "Yanlış pozitif ihtimali için bakım penceresi, parola senkronizasyon problemi veya test otomasyonu kontrol edilmelidir. "
                "Mitigation tarafında MFA, rate limit ve aynı IP için korelasyon incelemesi önerilir; sonraki adım olarak son başarılı girişler ve komşu alarmlar doğrulanmalıdır."
            )

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"llm": {"enabled": True}}})
    import core.llm as llm_module
    monkeypatch.setattr(llm_module, "LLMClient", _Client)

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)

    assert result["used_llm"] is True
    assert result["fallback_used"] is False
    assert result["provider"] == "openai"
    assert result["llm_quality_passed"] is True
    assert result["llm_quality_reason"] in {"contextual_longform", "contextual_actionable", "contextual_detailed"}
    assert result["full_explanation"].startswith("AUTH-001 kuralı")
    assert "Kural: AUTH-001" in result["evidence"]
    assert result["summary"].strip()
    assert result["risk"].strip()


@pytest.mark.parametrize(
    "provider_text",
    [
        "LLM açıklaması üretilemedi: HTTP UNAVAILABLE: This model is currently experiencing high demand.",
        "LLM açıklaması üretilemedi: rate limit exceeded",
        "LLM açıklaması üretilemedi: request timeout",
    ],
)
def test_explain_alert_for_ui_provider_errors_fall_back_to_deterministic_explanation(monkeypatch, provider_text):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {},
    })

    class _Client:
        backend_name = "gemini"
        is_active = True
        disable_reason = ""

        def __init__(self, config):
            return None

        def explain_selected_alert(self, alert, related_events=None):
            return provider_text

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"llm": {"enabled": True}}})
    import core.llm as llm_module
    monkeypatch.setattr(llm_module, "LLMClient", _Client)

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)

    assert result["used_llm"] is False
    assert result["fallback_used"] is True
    assert result["provider"] == "gemini"
    assert result["error"]
    assert "deterministik açıklama gösteriliyor" in result["full_explanation"].lower()
    assert "Kısa Özet" in result["full_explanation"]
    assert "Kanıtlar" in result["full_explanation"]
    assert "False Positive Kontrolü" in result["full_explanation"]
    assert "Önlem / Mitigation" in result["full_explanation"]
    assert "Sonraki İnceleme Adımları" in result["full_explanation"]
    assert not result["full_explanation"].strip().startswith("LLM açıklaması üretilemedi:")
    assert result["summary"].strip()
    assert result["why"].strip()
    assert result["risk"].strip()
    assert result["evidence"].strip()
    assert result["recommended_review_steps"]
    assert result["false_positive_notes"].strip()


def test_explain_alert_for_ui_very_short_provider_response_falls_back(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {},
    })

    class _Client:
        backend_name = "anthropic"
        is_active = True
        disable_reason = ""

        def __init__(self, config):
            return None

        def explain_selected_alert(self, alert, related_events=None):
            return "Tamam."

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"llm": {"enabled": True}}})
    import core.llm as llm_module
    monkeypatch.setattr(llm_module, "LLMClient", _Client)

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)

    assert result["used_llm"] is False
    assert result["fallback_used"] is True
    assert result["llm_quality_passed"] is False
    assert result["llm_quality_reason"] == "too_short"
    assert "çok kısa" in result["error"].lower()
    assert "Önlem / Mitigation" in result["full_explanation"]
    assert "False Positive Kontrolü" in result["full_explanation"]


def test_explain_alert_for_ui_short_203_char_provider_response_falls_back_with_rejected_preview(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {},
    })

    short_text = (
        "AUTH-001 alarmı auth_log üzerinde üretildi. 8.8.8.8 kaynağından alice hesabına yönelik başarısız "
        "denemeler var. İnceleme önerilir fakat kanıt, mitigation ve false positive değerlendirmesi yetersiz kaldı."
    )
    assert len(short_text) == 203

    class _Client:
        backend_name = "gemini"
        is_active = True
        disable_reason = ""

        def __init__(self, config):
            self.last_selected_alert_debug = {
                "prompt_len": 812,
                "response_len": len(short_text),
                "finish_reason": "STOP",
                "raw_preview": short_text,
                "rejected_preview": short_text,
            }

        def explain_selected_alert(self, alert, related_events=None):
            return short_text

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"llm": {"enabled": True}}})
    import core.llm as llm_module
    monkeypatch.setattr(llm_module, "LLMClient", _Client)

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)

    assert result["used_llm"] is False
    assert result["fallback_used"] is True
    assert result["llm_quality_passed"] is False
    assert result["llm_quality_reason"] == "too_short"
    assert result["llm_response_len"] == 203
    assert result["llm_raw_preview"] == ""
    assert result["rejected_llm_preview"] == short_text
    assert "çok kısa" in result["error"].lower()


def test_explain_alert_for_ui_rejected_preview_is_secret_safe(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {},
    })

    raw_preview = "Gemini key=abcd-1234-secret-value ile AUTH-001 için kısa yanıt."

    class _Client:
        backend_name = "gemini"
        is_active = True
        disable_reason = ""

        def __init__(self, config):
            self.last_selected_alert_debug = {
                "prompt_len": 600,
                "response_len": 42,
                "finish_reason": "STOP",
                "raw_preview": raw_preview,
                "rejected_preview": raw_preview,
            }

        def explain_selected_alert(self, alert, related_events=None):
            return "Kısa yanıt"

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {"llm": {"enabled": True}}})
    import core.llm as llm_module
    monkeypatch.setattr(llm_module, "LLMClient", _Client)

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)
    serialized = backend_facade._stringify_payload(result)

    assert "secret-value" not in serialized
    assert "abcd-1234" not in serialized


def test_collect_llm_config_status_secret_masking(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {
        "config": {"llm": {"enabled": True, "backend": "openai", "model": "gpt-test", "api_key": "secret-key", "timeout_seconds": 12, "language": "tr"}},
        "integrations": _integrations_stub(llm_api_key=lambda self: "secret-key"),
    })

    result = backend_facade.collect_llm_config_status()

    assert result["status"] == "ok"
    assert result["has_api_key"] is True
    assert result["key_masked"].endswith("-key"[-4:])
    assert result["key_masked"] != "secret-key"
    assert "secret-key" not in backend_facade._stringify_payload(result)


def test_collect_llm_config_status_merges_integrations_env_for_gemini(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yml"
    env_path = tmp_path / "integrations.env"
    config_path.write_text("llm: {}\n", encoding="utf-8")
    env_path.write_text(
        "LLM_BACKEND=gemini\n"
        "LLM_MODEL=gemini-2.5-flash\n"
        "LLM_LANGUAGE=tr\n"
        "GEMINI_API_KEY=test-gemini-key-1234\n",
        encoding="utf-8",
    )
    for name in ("LLM_BACKEND", "LLM_MODEL", "LLM_LANGUAGE", "GEMINI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(backend_facade, "_load_config", lambda path: {"llm": {"enabled": False, "backend": "mock", "language": "en"}})

    result = backend_facade.collect_llm_config_status(config_path=str(config_path))

    assert result["status"] == "ok"
    assert result["enabled"] is True
    assert result["backend"] == "gemini"
    assert result["model"] == "gemini-2.5-flash"
    assert result["language"] == "tr"
    assert result["has_api_key"] is True
    assert result["key_masked"]
    assert "test-gemini-key-1234" not in backend_facade._stringify_payload(result)


def test_explain_alert_for_ui_uses_merged_integrations_env_config(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yml"
    env_path = tmp_path / "integrations.env"
    config_path.write_text("llm: {}\n", encoding="utf-8")
    env_path.write_text(
        "LLM_BACKEND=gemini\n"
        "LLM_MODEL=gemini-2.5-flash\n"
        "LLM_LANGUAGE=tr\n"
        "GEMINI_API_KEY=test-gemini-key-1234\n",
        encoding="utf-8",
    )
    for name in ("LLM_BACKEND", "LLM_MODEL", "LLM_LANGUAGE", "GEMINI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(backend_facade, "_load_config", lambda path: {"llm": {"enabled": False, "backend": "mock"}})
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {},
    })

    captured = {}

    class _Client:
        backend_name = "gemini"
        disable_reason = ""

        def __init__(self, config):
            captured["config"] = dict((config or {}).get("llm", {}) or {})
            self.is_active = bool(captured["config"].get("enabled"))

        def explain_selected_alert(self, alert, related_events=None):
            return (
                "Kısa Özet\nGerçek LLM yolu test edildi.\n\n"
                "Teknik Anlam\nGemini config merge başarılı.\n\n"
                "Risk Değerlendirmesi\nYüksek risk inceleme gerekli.\n\n"
                "Kanıtlar\n- Kural=AUTH-001\n\n"
                "Olası Saldırı Senaryosu\nBrute force denemesi.\n\n"
                "False Positive Kontrolü\nBakım penceresini kontrol et.\n\n"
                "Önlem / Mitigation\nMFA ve rate limit gözden geçirilsin.\n\n"
                "Sonraki İnceleme Adımları\n- Aynı IP olaylarını aç.\n\n"
                "Güven Skoru\n87/100"
            )

    import core.llm as llm_module
    monkeypatch.setattr(llm_module, "LLMClient", _Client)

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True, config_path=str(config_path))

    assert captured["config"]["enabled"] is True
    assert captured["config"]["backend"] == "gemini"
    assert captured["config"]["model"] == "gemini-2.5-flash"
    assert captured["config"]["language"] == "tr"
    assert captured["config"]["api_key"] == "test-gemini-key-1234"
    assert result["used_llm"] is True
    assert result["fallback_used"] is False
    assert "Gerçek LLM yolu test edildi." in result["full_explanation"]


def test_fallback_explanation_does_not_duplicate_sections(monkeypatch):
    sample = backend_facade._normalize_alert(_sample_alert())
    monkeypatch.setattr(backend_facade, "collect_alert_detail", lambda alert_id, config_path=None: {
        "status": "ok",
        "alert": sample,
        "detail": {},
        "error": None,
    })
    monkeypatch.setattr(backend_facade, "collect_alert_investigation_summary", lambda alert_id, config_path=None: {
        "status": "ok",
        "summary": {},
    })
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {
        "config": {"llm": {"enabled": False}},
        "integrations": _integrations_stub(),
    })

    result = backend_facade.explain_alert_for_ui(11, prefer_llm=True)

    assert result["full_explanation"].count("Önlem / Mitigation") == 1
    assert result["full_explanation"].count("Sonraki İnceleme Adımları") == 1


def test_deterministic_explanation_helper_schema():
    result = backend_facade.build_deterministic_alert_explanation(_sample_alert())

    assert {"status", "summary", "why_triggered", "risk_assessment", "recommended_review_steps", "false_positive_notes", "raw_text", "metadata", "language"} <= set(result)


def test_deterministic_explanation_helper_normalizes_language():
    result = backend_facade.build_deterministic_alert_explanation(_sample_alert(), language="English")

    assert result["language"] == "en"
    assert "Short Summary" in result["full_explanation"]


def test_session_history_bounded_helper():
    history = []
    for index in range(55):
        history = bounded_history(history, {"alert_id": index}, max_items=50)

    assert len(history) == 50
    assert history[0]["alert_id"] == 5
    assert history[-1]["alert_id"] == 54


def test_alert_explanation_backend_facade_no_write_guard():
    source = Path("ui/backend_facade.py").read_text(encoding="utf-8").lower()
    forbidden_tokens = [
        "insert into ",
        "delete from ",
        ".commit(",
        "write_text(",
        "log_ml_control(",
        "add_ip_block_action",
        "review_ip_block_suggestion",
        "update_incident(",
    ]
    for token in forbidden_tokens:
        assert token not in source
