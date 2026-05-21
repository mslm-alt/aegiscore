from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.llm import LLMClient, _GeminiBackend


def _long_tr_response() -> str:
    return (
        "Kısa Özet\n"
        "AUTH-001 alarmı auth_log kaynağında alice hesabına yönelik tekrar eden SSH brute force davranışı nedeniyle üretildi.\n"
        "Bu davranış operasyonel olarak yüksek önem taşır ve çevresindeki kayıtlarla birlikte analist incelemesi gerektirir.\n\n"
        "Teknik Anlam\n"
        "8.8.8.8 adresinden kısa süre içinde çok sayıda başarısız kimlik doğrulama denemesi görülmesi kaba kuvvet veya credential stuffing olasılığını güçlendirir.\n"
        "Rule ID, severity, risk score ve message alanları bir arada değerlendirildiğinde olay yalnızca kullanıcı hatası olarak görülmemelidir.\n\n"
        "Risk Değerlendirmesi\n"
        "High severity ve 88 risk skoru, hesabın hedefli şekilde deneniyor olabileceğini gösterir.\n"
        "Başarılı giriş kayıtlarıyla birleşirse yetkisiz erişim veya sonraki privilege abuse adımları görülebilir.\n\n"
        "Kanıtlar\n"
        "- rule_id=AUTH-001\n"
        "- severity=high\n"
        "- source=auth_log\n"
        "- source_ip=8.8.8.8\n"
        "- entity=alice\n"
        "- message=ssh brute force\n\n"
        "Olası Saldırı Senaryosu\n"
        "Saldırgan önce parola denemeleriyle erişim elde etmeye, ardından aynı hesabı lateral movement veya veri erişimi için kullanmaya çalışıyor olabilir.\n"
        "Yakın zamanlı başarılı giriş, sudo veya servis erişim logları bu senaryoyu güçlendirebilir.\n\n"
        "False Positive Kontrolü\n"
        "Bakım otomasyonu, parola senkronizasyon hatası veya yanlış parola giren meşru kullanıcı olasılığı auth loglarıyla doğrulanmalıdır.\n"
        "Aynı zaman aralığında helpdesk, planlı bakım veya test aktivitesi olup olmadığı kontrol edilmelidir.\n\n"
        "Önlem / Mitigation\n"
        "- MFA zorunluluğunu kontrol et\n"
        "- Rate limiting ve SSH korumalarını gözden geçir\n"
        "- Gerekirse hesabı ve IP'yi manuel korumalı akışla incele\n\n"
        "Sonraki İnceleme Adımları\n"
        "- Aynı IP için komşu alarmları aç\n"
        "- Son başarılı girişleri ve sudo aktivitelerini kontrol et\n"
        "- Aynı kullanıcı için farklı hostlarda korelasyon yap\n\n"
        "Güven Skoru\n"
        "86/100\n\n"
        "Ek Operasyonel Notlar\n"
        "Bu alarm tek başına otomatik aksiyon üretmemeli; ancak korelasyon ve zaman çizelgesi ile birlikte ele alındığında saldırı zincirinin erken aşamasını gösterebilir.\n"
        "Özellikle aynı source_ip üzerinden farklı kullanıcı denemeleri, aynı kullanıcı için farklı host erişimleri veya kısa süre sonra gelen sudo denemeleri birlikte değerlendirilmelidir.\n"
        "Ayrıca authentication subsystem, PAM, sshd ve bastion kayıtları karşılaştırılarak denemelerin gerçekten tek bir dış kaynaktan mı geldiği doğrulanmalıdır.\n"
        "Operatör, olası credential stuffing varyasyonları için kullanıcı adının farklı yazımlarla denenip denenmediğini de kontrol etmelidir.\n\n"
        "Detaylı İnceleme\n"
        "- source_ip çevresinde son 24 saatte kaç farklı entity görüldüğünü çıkar.\n"
        "- Aynı rule_id için benzer message kalıplarını grupla.\n"
        "- Başarılı login sonrası process, sudo veya network pivot davranışı olup olmadığını doğrula.\n"
        "- Varsa ilgili host üzerinde SSH hardening, MFA ve fail2ban benzeri korumaların durumunu teyit et.\n"
        "- AbuseIPDB veya benzeri kaynaklardan gelen geçmiş gözlemleri destekleyici kanıt olarak kullan ama tek karar noktası yapma.\n\n"
        "Analist Yorumu\n"
        "Risk skoru ile severity birlikte, olayın basit bir kullanıcı hatasından daha fazlası olabileceğini gösteriyor.\n"
        "Bununla birlikte planlı bakım, otomasyon ya da parola senkronizasyon sorunları dışlanmadan ihlal kararı verilmemelidir.\n"
        "İnceleme sırasında false positive kontrolünü destekleyen kayıtlar ve saldırı hipotezini güçlendiren kayıtlar ayrı işaretlenmelidir.\n"
        "Bu yöntem, daha sonra raporlama veya incident açma kararlarında daha tutarlı sonuç verir."
    )


def test_gemini_backend_uses_generate_content_and_collects_all_text_parts(monkeypatch):
    captured = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({
                "candidates": [{
                    "finishReason": "STOP",
                    "content": {
                        "parts": [
                            {"text": "Kısa Özet\nİlk bölüm."},
                            {"text": "\n\nTeknik Anlam\nİkinci bölüm."},
                        ]
                    },
                }]
            }).encode("utf-8")

    def _fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        captured["payload"] = json.loads(req.data.decode("utf-8"))
        return _Response()

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    backend = _GeminiBackend(api_key="secret", model="gemini-flash-latest", timeout=21)
    text = backend.complete("sys prompt", "user body", max_tokens=3072)

    assert ":generateContent?key=secret" in captured["url"]
    assert captured["payload"]["contents"][0]["parts"][0]["text"] == "sys prompt\n\nuser body"
    assert captured["payload"]["contents"][0]["role"] == "user"
    assert captured["payload"]["generationConfig"]["maxOutputTokens"] == 3072
    assert "Kısa Özet" in text
    assert "Teknik Anlam" in text
    assert backend.last_finish_reason == "STOP"


def test_gemini_backend_prefers_first_candidate_text_and_joins_all_parts(monkeypatch):
    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({
                "candidates": [
                    {
                        "finishReason": "STOP",
                        "content": {
                            "parts": [
                                {"text": "Kısa Özet\nBirinci parça."},
                                {"text": "\n\nTeknik Anlam\nİkinci parça."},
                            ]
                        },
                    },
                    {
                        "finishReason": "STOP",
                        "content": {
                            "parts": [{"text": "Bu ikinci aday karışmamalı."}]
                        },
                    },
                ]
            }).encode("utf-8")

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=0: _Response())

    backend = _GeminiBackend(api_key="secret", model="gemini-flash-latest", timeout=21)
    text = backend.complete("sys prompt", "user body", max_tokens=3072)

    assert "Birinci parça." in text
    assert "İkinci parça." in text
    assert "ikinci aday" not in text.lower()


def test_llm_client_selected_alert_uses_large_default_output_budget_and_debug_metadata(monkeypatch):
    captured = {}
    assert len(_long_tr_response()) >= 3000
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")

    def _fake_complete(self, system, user, max_tokens=300):
        captured["system"] = system
        captured["user"] = user
        captured["max_tokens"] = max_tokens
        self.last_finish_reason = "STOP"
        return _long_tr_response()

    monkeypatch.setattr(_GeminiBackend, "complete", _fake_complete)

    client = LLMClient({"llm": {"enabled": True, "backend": "gemini", "language": "tr"}})
    text = client.explain_selected_alert({
        "rule_id": "AUTH-001",
        "severity": "high",
        "risk_score": 88,
        "source": "auth_log",
        "source_ip": "8.8.8.8",
        "entity": "alice",
        "message": "ssh brute force",
    })

    assert captured["max_tokens"] >= 2048
    assert "source" in captured["user"]
    assert "source_ip" in captured["user"]
    assert "Güven Skoru" in text
    assert client.last_selected_alert_debug["prompt_len"] > 0
    assert client.last_selected_alert_debug["response_len"] == len(text)
    assert client.last_selected_alert_debug["finish_reason"] == "STOP"
    assert client.last_selected_alert_debug["raw_preview"]
    assert "secret" not in json.dumps(client.last_selected_alert_debug, ensure_ascii=False)


def test_llm_client_selected_alert_honors_explicit_selected_alert_budget(monkeypatch):
    captured = {}
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")

    def _fake_complete(self, system, user, max_tokens=300):
        captured["max_tokens"] = max_tokens
        self.last_finish_reason = "STOP"
        return _long_tr_response()

    monkeypatch.setattr(_GeminiBackend, "complete", _fake_complete)

    client = LLMClient({
        "llm": {
            "enabled": True,
            "backend": "gemini",
            "language": "tr",
            "max_tokens": 512,
            "selected_alert_max_output_tokens": 3072,
        }
    })
    client.explain_selected_alert({
        "rule_id": "AUTH-001",
        "severity": "high",
        "risk_score": 88,
        "source": "auth_log",
        "source_ip": "8.8.8.8",
        "entity": "alice",
        "message": "ssh brute force",
    })

    assert captured["max_tokens"] == 3072
