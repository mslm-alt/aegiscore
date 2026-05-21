from __future__ import annotations
"""
core/llm.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LLM layer — manual alert and optional incident explanation

The V1 flow is manual-only by default.
The incident summary callback is preserved, but becomes a no-op when auto_incident_summary=false.
Prompts are kept minimal to save tokens; for manual selected-alert flows
a higher output budget may be used when needed.

Backend options:
  anthropic  → Claude API (Haiku — fast and inexpensive)
  openai     → OpenAI GPT-4o-mini
  gemini     → Google Gemini API
  local      → HTTP endpoint (Ollama, LM Studio, etc.)
  mock       → no API call (test/offline)

Usage:
  from core.llm import LLMClient
  client = LLMClient(config)
  text = client.explain_selected_alert(alert_dict, related_events=[...])
  text = client.summarize_incident(incident_dict, alerts=[...])
"""

import os
import json
import time
import re
import hashlib
import logging
import threading
from typing import Any, Dict, List, Optional

from .language import explanation_text, resolve_language

logger = logging.getLogger(__name__)

# LLM is enabled only for these severities
LLM_SEVERITY_FILTER = {"critical", "high"}
_REDACT_USER_KEYS = {"user", "entity", "entity_key", "account", "actor", "target_user"}
_REDACT_PATH_KEYS = {"path", "file", "filepath", "target", "command", "cmdline"}
_REDACT_IP_KEYS = {"src_ip", "dst_ip", "ip", "source_ip", "dest_ip"}

# ── Kisa prompt sablonlari (token tasarrufu) ──────────────────────────────────

_TEMPLATES = {
    "tr": {
        "alert_system": (
            "Linux SIEM analisti. Alert'i 3 cümlede özetle: "
            "ne oldu, risk seviyesi, hemen yapılacak 1 eylem. Türkçe."
        ),
        "alert_user": "Alert:\n{alert_json}\nÖzetle.",
        "incident_system": (
            "SOC analisti. Incident için 4 cümlede: "
            "saldırı zinciri, etkilenen varlık, aciliyet, ilk 2 adım. Türkçe."
        ),
        "incident_user": (
            "Incident:\n{incident_json}\n"
            "Alertler ({alert_count}):\n{alerts_summary}\n"
            "Özet yaz."
        ),
        "selected_alert_system": (
            "Bir SOC analisti gibi aşağıdaki SIEM alarmını açıkla. "
            "Yalnızca verilen redakte alarm, itibar ve ilişkili olay özetlerine dayan. "
            "Aşağıdaki başlıkların TAMAMINI aynen ve bu sırayla kullan: "
            "Kısa Özet, Teknik Anlam, Risk Değerlendirmesi, Kanıtlar, "
            "Olası Saldırı Senaryosu, False Positive Kontrolü, "
            "Önlem / Mitigation, Sonraki İnceleme Adımları, Güven Skoru. "
            "Her başlık ayrı satırda olsun ve hiçbirini atlama. "
            "Her başlık altında en az 2 cümle veya 2-4 kısa madde ver. "
            "Yanıt Türkçe, operasyonel, detaylı ve analist tarafından doğrudan kullanılabilir olsun. "
            "Alert alanları sınırlıysa rule_id, severity, risk_score, source, source_ip, entity, message ve related alert count gibi alanlardan makul operasyonel yorum üret. "
            "Kanıtlar, false positive kontrolü, mitigation ve inceleme adımları boş bırakılamaz. "
            "Belirsiz alanlarda 'belirsiz' de ama yine de uygulanabilir yorum üret. "
            "Son başlık mutlaka 'Güven Skoru' olsun ve yanıt onunla bitsin."
        ),
        "selected_alert_user": (
            "Seçili alarm:\n{alert_json}\n"
            "IP reputation:\n{reputation_text}\n"
            "İlgili olay özetleri:\n{events_json}\n"
            "Yanıtı tam başlıklarla ver. Her başlık altında en az 2 cümle veya 2-4 kısa madde kullan. "
            "Hiçbir bölümü boş bırakma; gerekli yerde belirsiz diyerek analist için uygulanabilir yönlendirme üret."
        ),
        "mock_alert":    "Kural '{rule_id}' tetiklendi | {entity} | {severity} | {message}",
        "mock_incident": "Incident '{incident_id}' — {severity} | {alert_count} alert | {entity}",
        "mock_selected": (
            "Kısa Özet: {rule_id} alarmı {entity} için üretildi ve kullanıcı incelemesi gerektiriyor.\n"
            "Teknik Anlam: Alarm mesajı {message} olduğu için bu davranış kural kapsamındaki anormal veya riskli olayı işaret ediyor.\n"
            "Risk Değerlendirmesi: Olay orta-yüksek riskli kabul edilmeli ve ilişkili kayıtlarla birlikte incelenmeli.\n"
            "Kanıtlar: Kural={rule_id}; Kategori={category}; Mesaj={message}\n"
            "Olası Saldırı Senaryosu: Yetkisiz erişim, parola denemesi veya servis kötüye kullanımı ihtimali vardır.\n"
            "False Positive Kontrolü: Bakım işlemi, meşru otomasyon veya kullanıcı hatası kaynaklı olup olmadığını ham loglarla kontrol et.\n"
            "Önlem / Mitigation: İlgili hesabı, hostu ve erişim kontrollerini gözden geçir; gerekirse manuel korumalı aksiyon uygula.\n"
            "Sonraki İnceleme Adımları: Aynı IP, aynı kullanıcı ve aynı kural için yakın zamanlı kayıtları korele et.\n"
            "Güven Skoru: {score}/100"
        ),
    },
    "en": {
        "alert_system": (
            "Linux SIEM analyst. Summarize alert in 3 sentences: "
            "what happened, risk level, 1 immediate action. English."
        ),
        "alert_user": "Alert:\n{alert_json}\nSummarize.",
        "incident_system": (
            "SOC analyst. 4 sentences: "
            "attack chain, affected asset, urgency, first 2 steps. English."
        ),
        "incident_user": (
            "Incident:\n{incident_json}\n"
            "Alerts ({alert_count}):\n{alerts_summary}\n"
            "Write summary."
        ),
        "selected_alert_system": (
            "Act as a Linux SIEM analyst. "
            "Use only the provided redacted alert and event summaries. "
            "Return ALL of these exact headings, in this order, each on its own line, "
            "and do not omit any heading. "
            "Keep each section to at least 2 explanatory sentences or 2-4 short bullets. "
            "The answer must be operationally useful, not shallow. "
            "When available, explicitly reference the rule ID, severity, source, entity, source IP, and relevant message fields. "
            "Do not leave the evidence, false positive check, or mitigation sections empty. "
            "The final heading must be 'Confidence Score' and the answer must end with it. "
            "You may use markdown bold, but the heading text must appear exactly. "
            "Respond with these exact headings: "
            "Short Summary, Technical Meaning, Risk Assessment, Evidence, "
            "Possible Attack Scenario, False Positive Check, "
            "Mitigation, Next Investigation Steps, Confidence Score. "
            "Use 'unknown' when data is missing."
        ),
        "selected_alert_user": (
            "Selected alert:\n{alert_json}\n"
            "IP reputation:\n{reputation_text}\n"
            "Related event summaries:\n{events_json}\n"
            "Return the answer with all headings. Do not leave sections empty; use 'unknown' only when data is missing and still provide actionable analyst guidance."
        ),
        "mock_alert":    "Rule '{rule_id}' triggered | {entity} | {severity} | {message}",
        "mock_incident": "Incident '{incident_id}' — {severity} | {alert_count} alerts | {entity}",
        "mock_selected": (
            "Short Summary: Alert {rule_id} was generated for {entity} and requires analyst review.\n"
            "Technical Meaning: The message {message} indicates behavior covered by the detection rule and may reflect suspicious activity.\n"
            "Risk Assessment: Treat the event as medium-to-high risk until surrounding evidence disproves it.\n"
            "Evidence: Rule={rule_id}; Category={category}; Message={message}\n"
            "Possible Attack Scenario: Unauthorized access, password guessing, or service abuse may be in progress.\n"
            "False Positive Check: Compare the alert with maintenance logs, expected automation, and legitimate user activity.\n"
            "Mitigation: Review the affected account, host, and access controls; apply guarded manual actions if needed.\n"
            "Next Investigation Steps: Correlate nearby alerts for the same IP, user, and rule.\n"
            "Confidence Score: {score}/100"
        ),
    },
}

def _resolve_api_key(config_key: str, env_vars: List[str], *, allow_config: bool = True) -> str:
    if allow_config and config_key and config_key.strip():
        return config_key.strip()
    for env in env_vars:
        val = os.environ.get(env, "").strip()
        if val:
            return val
    return ""


def _redact_text(value: Any) -> str:
    return _redact_text_with_users(value)


def _redact_text_with_users(
    value: Any,
    usernames: Optional[List[str]] = None,
    *,
    max_len: Optional[int] = 240,
) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = re.sub(r'https?://\S+', "[URL]", text)
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', "[IP]", text)
    text = re.sub(r'\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]*\b', "[IP]", text)
    text = re.sub(r'/(?:[A-Za-z_.-][\w.-]*/?)+', "[PATH]", text)
    for username in sorted(set(usernames or []), key=len, reverse=True):
        u = (username or "").strip()
        if not u or len(u) < 2:
            continue
        text = re.sub(rf'\b{re.escape(u)}\b', "[USER]", text, flags=re.IGNORECASE)
    if max_len is not None:
        return text[:max_len]
    return text


def _redact_kv(key: str, value: Any) -> str:
    if value in (None, ""):
        return ""
    key_lc = str(key or "").strip().lower()
    if key_lc in _REDACT_USER_KEYS:
        return "[USER]"
    if key_lc in _REDACT_PATH_KEYS:
        return "[PATH]"
    if key_lc in _REDACT_IP_KEYS:
        return "[IP]"
    return _redact_text(value)


def _redact_output_text(text: str, usernames: Optional[List[str]] = None) -> str:
    known_headings = {
        "özet", "saldırı türü", "kaynak/hedef", "kanıt", "etki",
        "acil aksiyon", "kalıcı önlem", "ek kontrol", "fp ihtimali", "güven skoru",
        "summary", "attack type", "source/target", "evidence", "impact",
        "immediate action", "long-term mitigation", "additional checks",
        "false positive likelihood", "confidence score",
    }
    lines = []
    for line in str(text or "").splitlines():
        normalized = re.sub(r'^[#*\s`_]+|[#*\s`_]+$', "", line.strip()).rstrip(":").strip().lower()
        if normalized in known_headings:
            lines.append(line)
            continue
        if ":" in line:
            head, tail = line.split(":", 1)
            lines.append(f"{head}:{_redact_text_with_users(tail, usernames, max_len=None)}")
        else:
            lines.append(_redact_text_with_users(line, usernames, max_len=None))
    return "\n".join(lines)


def _format_ip_reputation_summary(ip_reputation: Any) -> str:
    if not ip_reputation:
        return "No reputation enrichment available."
    items = ip_reputation if isinstance(ip_reputation, list) else [ip_reputation]
    lines: List[str] = []
    for item in items[:3]:
        if not isinstance(item, dict):
            continue
        ip = _redact_kv("ip", item.get("ip", ""))
        score = item.get("abuse_score", "")
        reports = item.get("abuse_reports", item.get("total_reports", ""))
        country = _redact_text(item.get("abuse_country", item.get("country_code", "")))
        if item.get("reviewed"):
            status = str(item.get("action", "") or "reviewed")
        else:
            status = "pending"
        source = _redact_text(item.get("source", "abuseipdb") or "abuseipdb")
        lines.append(
            f"{ip} — AbuseIPDB score={score}, reports={reports}, country={country}, "
            f"suggestion_status={status}, source={source}"
        )
    return "\n".join(lines) if lines else "No reputation enrichment available."


def _collect_known_usernames(alert: Dict[str, Any], related_events: Optional[List[Dict[str, Any]]] = None) -> List[str]:
    names = set()

    def _add(candidate: Any):
        text = str(candidate or "").strip()
        if not text:
            return
        if "@" in text:
            text = text.split("@", 1)[0].strip()
        if not text or text.startswith("[") or "/" in text or "." in text:
            return
        if len(text) < 2:
            return
        names.add(text)

    def _extract_from_text(candidate: Any):
        text = str(candidate or "").strip()
        if not text:
            return
        for match in re.findall(r'/home/([A-Za-z0-9_.-]+)', text):
            _add(match)
        patterns = [
            r'\buser(?:name)?\s*[:=]\s*([A-Za-z0-9_.-]+)\b',
            r'\bfor\s+([A-Za-z0-9_.-]+)\s+from\b',
            r'\baccount\s*[:=]\s*([A-Za-z0-9_.-]+)\b',
            r'\bentity\s*[:=]\s*([A-Za-z0-9_.@-]+)\b',
        ]
        for pat in patterns:
            for match in re.findall(pat, text, flags=re.IGNORECASE):
                _add(match)

    _add(alert.get("user"))
    _add(alert.get("entity"))
    _add(alert.get("entity_key"))
    _extract_from_text(alert.get("message"))
    for evt in related_events or []:
        _add(evt.get("user"))
        _add(evt.get("account"))
        _add(evt.get("entity"))
        _extract_from_text(evt.get("message"))
    return sorted(names, key=len, reverse=True)


# ── Backend implementasyonlari ─────────────────────────────────────────────────

class _AnthropicBackend:
    DEFAULT_MODEL = "claude-haiku-4-5-20251001"   # hızlı + ucuz

    def __init__(self, api_key: str, model: str = "", timeout: int = 15):
        self.api_key = api_key
        self.model   = model or self.DEFAULT_MODEL
        self.timeout = timeout

    def complete(self, system: str, user: str, max_tokens: int = 300) -> str:
        try:
            import urllib.request
            payload = json.dumps({
                "model":      self.model,
                "max_tokens": max_tokens,
                "system":     system,
                "messages":   [{"role": "user", "content": user}],
            }).encode()
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type":      "application/json",
                    "x-api-key":         self.api_key,
                    "anthropic-version": "2023-06-01",
                },
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
                return data["content"][0]["text"].strip()
        except Exception as e:
            logger.warning(f"[LLM:Anthropic] API hatası: {e}")
            return ""


class _OpenAIBackend:
    DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(self, api_key: str, model: str = "", timeout: int = 15):
        self.api_key = api_key
        self.model   = model or self.DEFAULT_MODEL
        self.timeout = timeout

    def complete(self, system: str, user: str, max_tokens: int = 300) -> str:
        try:
            import urllib.request
            payload = json.dumps({
                "model":      self.model,
                "max_tokens": max_tokens,
                "messages":   [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user},
                ],
            }).encode()
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=payload,
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            logger.warning(f"[LLM:OpenAI] API hatası: {e}")
            return ""


class _GeminiBackend:
    DEFAULT_MODEL = "gemini-2.5-flash"

    def __init__(self, api_key: str, model: str = "", timeout: int = 15):
        self.api_key = api_key
        self.model   = model or self.DEFAULT_MODEL
        self.timeout = timeout
        self.last_error = ""
        self.last_finish_reason = ""
        self.last_block_reason = ""

    def _set_error(self, message: str) -> str:
        self.last_error = message[:300]
        return ""

    def complete(self, system: str, user: str, max_tokens: int = 300) -> str:
        self.last_error = ""
        self.last_finish_reason = ""
        self.last_block_reason = ""
        try:
            import urllib.error
            import urllib.request
            prompt_text = f"{str(system or '').strip()}\n\n{str(user or '').strip()}".strip()
            bounded_max_tokens = max(256, min(int(max_tokens or 0), 4096))
            payload = json.dumps({
                "contents": [{
                    "role": "user",
                    "parts": [{"text": prompt_text}],
                }],
                "generationConfig": {
                    "maxOutputTokens": bounded_max_tokens,
                },
            }).encode()
            req = urllib.request.Request(
                f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
                api_error = data.get("error", {})
                if api_error:
                    message = _redact_text(api_error.get("message") or "Gemini API error")
                    logger.warning(
                        f"[LLM:Gemini] API response error — model={self.model}, "
                        f"status={api_error.get('status', 'unknown')}, message={message}"
                    )
                    return self._set_error(message)

                candidates = data.get("candidates", [])
                if not candidates:
                    block_reason = data.get("promptFeedback", {}).get("blockReason", "unknown")
                    self.last_block_reason = str(block_reason or "")
                    message = f"Gemini boş aday döndürdü (block_reason={block_reason})"
                    logger.warning(f"[LLM:Gemini] {message} — model={self.model}")
                    return self._set_error(message)

                chosen_candidate = None
                chosen_text_chunks: List[str] = []
                for cand in candidates:
                    parts = list(dict(cand.get("content", {}) or {}).get("parts", []) or [])
                    text_chunks = [str(part.get("text", "") or "").strip() for part in parts if part.get("text")]
                    if text_chunks:
                        chosen_candidate = cand
                        chosen_text_chunks = text_chunks
                        break
                if chosen_candidate is None:
                    chosen_candidate = dict(candidates[0] or {})
                self.last_finish_reason = str(chosen_candidate.get("finishReason", "") or "")
                text = "\n".join(chunk for chunk in chosen_text_chunks if chunk).strip()
                text = text.strip()
                if text:
                    return text

                finish_reason = self.last_finish_reason or "unknown"
                message = f"Gemini metin döndürmedi (finish_reason={finish_reason})"
                logger.warning(f"[LLM:Gemini] {message} — model={self.model}")
                return self._set_error(message)
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                api_error = data.get("error", {})
                status = api_error.get("status") or e.code
                message = _redact_text(api_error.get("message") or body)
            except Exception:
                status = e.code
                message = _redact_text(str(e))
            logger.warning(
                f"[LLM:Gemini] HTTP error — model={self.model}, status={status}, message={message}"
            )
            return self._set_error(f"HTTP {status}: {message}")
        except Exception as e:
            message = _redact_text(str(e))
            logger.warning(f"[LLM:Gemini] API hatası — model={self.model}, message={message}")
            return self._set_error(message)


class _LocalBackend:
    """Lokal LLM — Ollama, LM Studio vb. (OpenAI uyumlu endpoint)."""

    def __init__(self, base_url: str, model: str = "llama3", timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.model    = model
        self.timeout  = timeout

    def complete(self, system: str, user: str, max_tokens: int = 300) -> str:
        try:
            import urllib.request
            payload = json.dumps({
                "model":      self.model,
                "max_tokens": max_tokens,
                "messages":   [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user},
                ],
            }).encode()
            req = urllib.request.Request(
                f"{self.base_url}/v1/chat/completions",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            logger.warning(f"[LLM:Local] API hatası: {e}")
            return ""


class _MockBackend:
    def complete(self, system: str, user: str, max_tokens: int = 300) -> str:
        return ""


# ── Ana LLM Istemcisi ──────────────────────────────────────────────────────────

class LLMClient:
    """
    Alert ve incident açıklama istemcisi.
    Sadece critical/high severity alertlerde devreye girer.
    Varsayılan düşük token bütçesi korunur; manual selected-alert için
    ayrı minimum output clamp uygulanır.
    """

    def __init__(self, config: Dict = None):
        raw_cfg = config or {}
        llm_keys = {
            "enabled", "backend", "model", "api_key", "base_url", "language",
            "max_tokens", "max_output_tokens", "timeout_seconds", "cache_ttl",
            "auto_incident_summary",
        }
        if isinstance(raw_cfg.get("llm"), dict):
            cfg = raw_cfg.get("llm", {})
        elif any(k in raw_cfg for k in llm_keys):
            cfg = raw_cfg
        else:
            cfg = {}
        lang     = resolve_language(explicit=cfg.get("language"), config=raw_cfg, default="tr")
        backend  = cfg.get("backend", "mock").lower()
        model    = cfg.get("model", "")
        base_url = cfg.get("base_url", "")
        timeout  = int(cfg.get("timeout_seconds", 15))
        explicit_max_tokens = "max_output_tokens" in cfg or "max_tokens" in cfg
        max_tok_raw = cfg.get("max_output_tokens", cfg.get("max_tokens", 300))
        max_tok  = int(max_tok_raw)
        selected_alert_tok_raw = cfg.get("selected_alert_max_output_tokens", cfg.get("selected_alert_max_tokens"))
        self.backend_name = backend
        self.auto_incident_summary = bool(cfg.get("auto_incident_summary", False))
        self.disable_reason = ""

        self.language   = lang if lang in _TEMPLATES else "tr"
        self.max_tokens = max(64, min(max_tok, 4096))
        if selected_alert_tok_raw is not None:
            self.selected_alert_max_tokens = max(256, min(int(selected_alert_tok_raw), 4096))
        elif explicit_max_tokens:
            self.selected_alert_max_tokens = max(2048, min(self.max_tokens, 4096))
        else:
            self.selected_alert_max_tokens = 4096
        self._cache: Dict[str, tuple] = {}
        self._cache_ttl = int(cfg.get("cache_ttl", 300))
        self._lock = threading.Lock()
        self.last_selected_alert_debug: Dict[str, Any] = {}

        config_key = cfg.get("api_key", "")
        if backend == "anthropic":
            api_key = _resolve_api_key(config_key, ["ANTHROPIC_API_KEY"])
        elif backend == "openai":
            api_key = _resolve_api_key(config_key, ["OPENAI_API_KEY"])
        elif backend == "gemini":
            api_key = _resolve_api_key("", ["GEMINI_API_KEY"], allow_config=False)
        else:
            api_key = config_key

        config_enabled = cfg.get("enabled", False)
        needs_key = backend in ("anthropic", "openai", "gemini")

        if not config_enabled:
            self.enabled  = False
            self._backend = None
            self.disable_reason = explanation_text("llm_disabled", self.language)
            logger.debug("[LLM] Devre dışı (enabled: false)")
        elif needs_key and not api_key:
            self.enabled  = False
            self._backend = None
            if backend == "anthropic":
                _env = "ANTHROPIC_API_KEY"
            elif backend == "openai":
                _env = "OPENAI_API_KEY"
            else:
                _env = "GEMINI_API_KEY"
            self.disable_reason = explanation_text("llm_missing_api_key", self.language, env=_env)
            logger.warning(
                f"[LLM] api_key bulunamadı — devre dışı. "
                f"integrations.env veya {_env} ile girin."
            )
        else:
            self.enabled = True
            if backend == "anthropic":
                self._backend = _AnthropicBackend(api_key, model, timeout)
            elif backend == "openai":
                self._backend = _OpenAIBackend(api_key, model, timeout)
            elif backend == "gemini":
                self._backend = _GeminiBackend(api_key, model, timeout)
            elif backend == "local":
                self._backend = _LocalBackend(
                    base_url or "http://localhost:11434",
                    model or "llama3",
                    timeout,
                )
            else:
                self._backend = _MockBackend()
            logger.info(
                f"[LLM] Aktif — backend={backend}, dil={self.language}, "
                f"max_tokens={self.max_tokens}, selected_alert_max_tokens={self.selected_alert_max_tokens}, "
                f"filtre={sorted(LLM_SEVERITY_FILTER)}, "
                f"auto_incident_summary={self.auto_incident_summary}"
            )

    # ── Severity filtresi ──────────────────────────────────────────────────────

    @staticmethod
    def _severity_allowed(severity: str) -> bool:
        return str(severity).lower() in LLM_SEVERITY_FILTER

    def _required_selected_headings(self) -> List[str]:
        if self.language == "tr":
            return [
                "Kısa Özet",
                "Teknik Anlam",
                "Risk Değerlendirmesi",
                "Kanıtlar",
                "Olası Saldırı Senaryosu",
                "False Positive Kontrolü",
                "Önlem / Mitigation",
                "Sonraki İnceleme Adımları",
                "Güven Skoru",
            ]
        return [
            "Short Summary",
            "Technical Meaning",
            "Risk Assessment",
            "Evidence",
            "Possible Attack Scenario",
            "False Positive Check",
            "Mitigation",
            "Next Investigation Steps",
            "Confidence Score",
        ]

    def _selected_score_fallback(self) -> str:
        if self.language == "tr":
            return "Güven Skoru: belirsiz"
        return "Confidence Score: unknown"

    # ── Cache ──────────────────────────────────────────────────────────────────

    def _cache_key(self, data: Dict) -> str:
        return hashlib.md5(
            json.dumps(data, sort_keys=True, default=str).encode()
        ).hexdigest()

    def _from_cache(self, key: str) -> Optional[str]:
        with self._lock:
            entry = self._cache.get(key)
            if entry and (time.time() - entry[1]) < self._cache_ttl:
                return entry[0]
            if entry:
                del self._cache[key]
        return None

    def _to_cache(self, key: str, text: str):
        with self._lock:
            self._cache[key] = (text, time.time())
            if len(self._cache) > 200:
                oldest = sorted(self._cache.items(), key=lambda x: x[1][1])[:50]
                for k, _ in oldest:
                    del self._cache[k]

    # ── Alert Explanation ──────────────────────────────────────────────────────

    def explain_alert(self, alert: Dict) -> str:
        """
        Generate an alert explanation.
        Only for critical/high severity — others return an empty string.
        """
        if not self.enabled:
            return ""
        if not self._severity_allowed(alert.get("severity", "")):
            return ""

        cache_key = self._cache_key({
            "t": "alert",
            "r": alert.get("rule_id", ""),
            "e": alert.get("entity", ""),
            "m": alert.get("message", "")[:60],
        })
        cached = self._from_cache(cache_key)
        if cached:
            return cached

        tmpl = _TEMPLATES[self.language]
        clean = {
            "rule":   alert.get("rule_id", ""),
            "sev":    alert.get("severity", ""),
            "score":  alert.get("risk_score", 0),
            "cat":    alert.get("category", ""),
            "msg":    alert.get("message", "")[:120],
            "entity": alert.get("entity", ""),
            "mitre":  alert.get("mitre_tactic", ""),
        }
        user   = tmpl["alert_user"].format(alert_json=json.dumps(clean, ensure_ascii=False))
        result = self._backend.complete(tmpl["alert_system"], user, self.max_tokens)

        if not result and isinstance(self._backend, _MockBackend):
            result = tmpl["mock_alert"].format(
                rule_id=clean["rule"], entity=clean["entity"] or "?",
                severity=clean["sev"], message=clean["msg"],
            )
        if result:
            self._to_cache(cache_key, result)
        return result

    # ── Incident Summary ───────────────────────────────────────────────────────

    def summarize_incident(self, incident: Dict,
                            alerts: Optional[List[Dict]] = None) -> str:
        """Generate a summary for the incident plus related alerts."""
        if not self.enabled or not self.auto_incident_summary:
            return ""
        if not self._severity_allowed(incident.get("severity", "high")):
            return ""

        cache_key = self._cache_key({"t": "inc", "id": incident.get("incident_id", "")})
        cached = self._from_cache(cache_key)
        if cached:
            return cached

        tmpl      = _TEMPLATES[self.language]
        clean_inc = {
            "id":     incident.get("incident_id", ""),
            "sev":    incident.get("severity", ""),
            "score":  incident.get("risk_score", 0),
            "entity": incident.get("entity_key", incident.get("entity", "")),
            "count":  incident.get("alert_count", 0),
        }
        alerts_summary = ""
        if alerts:
            for a in alerts[:5]:
                alerts_summary += (
                    f"[{a.get('severity','').upper()}] {a.get('rule_id','')} "
                    f"{a.get('message','')[:60]}\n"
                )

        user = tmpl["incident_user"].format(
            incident_json  = json.dumps(clean_inc, ensure_ascii=False),
            alert_count    = clean_inc["count"],
            alerts_summary = alerts_summary or "-",
        )
        result = self._backend.complete(tmpl["incident_system"], user, self.max_tokens)

        if not result and isinstance(self._backend, _MockBackend):
            result = tmpl["mock_incident"].format(
                incident_id=clean_inc["id"], severity=clean_inc["sev"],
                alert_count=clean_inc["count"], entity=clean_inc["entity"],
            )
        if result:
            self._to_cache(cache_key, result)
        return result

    # ── Async wrappers ─────────────────────────────────────────────────────────

    def explain_alert_async(self, alert: Dict, callback=None):
        """Does not block the pipeline — runs in a background thread."""
        if not self.enabled or not self._severity_allowed(alert.get("severity", "")):
            return
        def _run():
            text = self.explain_alert(alert)
            if callback and text:
                callback(text)
        threading.Thread(target=_run, daemon=True).start()

    def summarize_incident_async(self, incident: Dict,
                                  alerts: Optional[List[Dict]] = None,
                                  callback=None):
        if not self.enabled or not self.auto_incident_summary:
            return
        def _run():
            text = self.summarize_incident(incident, alerts)
            if callback and text:
                callback(text)
        threading.Thread(target=_run, daemon=True).start()

    def _build_selected_alert_payload(
        self, alert: Dict, related_events: Optional[List[Dict]] = None
    ) -> tuple[Dict[str, Any], List[Dict[str, Any]], str]:
        known_usernames = _collect_known_usernames(alert, related_events)
        clean_alert = {
            "rule_id": _redact_text(alert.get("rule_id", "")),
            "severity": _redact_text(alert.get("severity", "")),
            "risk_score": alert.get("risk_score", alert.get("score", 0)),
            "source": _redact_text(alert.get("source", "")),
            "source_ip": _redact_kv("source_ip", alert.get("source_ip", alert.get("src_ip", ""))),
            "category": _redact_text(alert.get("category", "")),
            "entity": _redact_kv("entity", alert.get("entity", alert.get("entity_key", ""))),
            "host": _redact_text(alert.get("host", "")),
            "message": _redact_text_with_users(alert.get("message", ""), known_usernames),
            "mitre_tactic": _redact_text(alert.get("mitre_tactic", "")),
            "mitre_technique": _redact_text(alert.get("mitre_technique", "")),
        }
        reputation_text = _format_ip_reputation_summary(alert.get("ip_reputation"))
        event_summaries: List[Dict[str, Any]] = []
        for evt in (related_events or [])[:5]:
            event_summaries.append({
                "ts": evt.get("ts", 0),
                "source": _redact_text(evt.get("source", "")),
                "category": _redact_text(evt.get("category", "")),
                "action": _redact_text(evt.get("action", "")),
                "outcome": _redact_text(evt.get("outcome", "")),
                "user": _redact_kv("user", evt.get("user", "")),
                "src_ip": _redact_kv("src_ip", evt.get("src_ip", "")),
                "process": _redact_text(evt.get("process", "")),
                "message": _redact_text_with_users(evt.get("message", ""), known_usernames),
            })
        return clean_alert, event_summaries, reputation_text

    def _set_selected_alert_debug(self, **kwargs):
        self.last_selected_alert_debug = dict(kwargs or {})

    def explain_selected_alert(
        self, alert_dict: Dict, related_events: Optional[List[Dict]] = None
    ) -> str:
        """
        Manual V1 alert explanation.
        No severity filter is applied; it is called for the user-selected alert.
        Raw logs are not sent; only redacted summary fields are used.
        """
        if not self.enabled:
            if self.backend_name == "gemini":
                return self.disable_reason or explanation_text("llm_not_enabled", self.language)
            return ""

        clean_alert, clean_events, reputation_text = self._build_selected_alert_payload(alert_dict, related_events)
        cache_key = self._cache_key({
            "t": "selected_alert",
            "alert": clean_alert,
            "events": clean_events,
            "reputation": reputation_text,
        })
        cached = self._from_cache(cache_key)
        if cached:
            self._set_selected_alert_debug(
                prompt_len=0,
                response_len=len(cached),
                raw_preview=_redact_output_text(cached[:500], _collect_known_usernames(alert_dict, related_events)),
                response_preview=_redact_output_text(cached[:500], _collect_known_usernames(alert_dict, related_events)),
                rejected_preview="",
                finish_reason=getattr(self._backend, "last_finish_reason", ""),
                from_cache=True,
            )
            return cached

        tmpl = _TEMPLATES[self.language]
        user = tmpl["selected_alert_user"].format(
            alert_json=json.dumps(clean_alert, ensure_ascii=False),
            reputation_text=reputation_text,
            events_json=json.dumps(clean_events, ensure_ascii=False),
        )
        prompt_len = len(tmpl["selected_alert_system"]) + len(user)
        result = self._backend.complete(
            tmpl["selected_alert_system"],
            user,
            self.selected_alert_max_tokens,
        )

        if not result and isinstance(self._backend, _MockBackend):
            result = tmpl["mock_selected"].format(
                rule_id=clean_alert.get("rule_id", "?"),
                category=clean_alert.get("category", "belirsiz" if self.language == "tr" else "unknown"),
                entity=clean_alert.get("entity", "?"),
                message=clean_alert.get("message", ""),
                score=clean_alert.get("risk_score", 0),
            )
        elif not result and isinstance(self._backend, _GeminiBackend) and self._backend.last_error:
            result = f"{explanation_text('llm_generic_error_prefix', self.language)}: {self._backend.last_error}"
        elif not result and isinstance(self._backend, _GeminiBackend):
            result = explanation_text("llm_empty_gemini", self.language)
        elif result and isinstance(self._backend, _GeminiBackend):
            score_heading = "Güven Skoru" if self.language == "tr" else "Confidence Score"
            finish_reason = (self._backend.last_finish_reason or "").upper()
            if score_heading not in result and finish_reason != "MAX_TOKENS":
                result = f"{result.rstrip()}\n{self._selected_score_fallback()}"
        known_usernames = _collect_known_usernames(alert_dict, related_events)
        if result:
            result = _redact_output_text(result, known_usernames)
        preview = _redact_output_text(result[:500], known_usernames) if result else ""
        self._set_selected_alert_debug(
            prompt_len=prompt_len,
            response_len=len(result or ""),
            raw_preview=preview,
            response_preview=preview,
            rejected_preview=preview,
            finish_reason=getattr(self._backend, "last_finish_reason", ""),
            from_cache=False,
        )
        if result:
            self._to_cache(cache_key, result)
        return result

    @property
    def is_active(self) -> bool:
        return self.enabled

    def status(self) -> Dict:
        return {
            "enabled":        self.enabled,
            "backend":        type(self._backend).__name__ if self._backend else "none",
            "language":       self.language,
            "max_tokens":     self.max_tokens,
            "selected_alert_max_tokens": self.selected_alert_max_tokens,
            "auto_incident_summary": self.auto_incident_summary,
            "severity_filter": sorted(LLM_SEVERITY_FILTER),
            "cache_size":     len(self._cache),
        }
