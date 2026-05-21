"""
core/integrations.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Integration settings loader

Reads config/integrations.env, loads discovered values into
os.environ, and provides easily accessible settings helpers.

Usage:
  from core.integrations import IntegrationSettings
  s = IntegrationSettings.load()
  print(s.abuseipdb_key)
  print(s.log_paths["auth_log"])
"""

import os
import logging
from pathlib import Path
from typing import Dict, Optional

from .language import normalize_language

logger = logging.getLogger(__name__)

# Supported log path fields (integrations.env → distro field)
_LOG_KEY_MAP: Dict[str, str] = {
    "LOG_AUTH":     "auth_log",
    "LOG_SYSLOG":   "syslog",
    "LOG_AUDIT":    "audit_log",
    "LOG_DPKG":     "dpkg_log",
    "LOG_UFW":      "ufw_log",
    "LOG_APACHE":   "apache_log",
    "LOG_NGINX":    "nginx_log",
    "LOG_MYSQL":    "mysql_log",
    "LOG_POSTGRES": "pg_log",
    "LOG_MAIL":     "mail_log",
    "LOG_OPENVPN":  "openvpn_log",
    "LOG_WTMP":     "wtmp_log",
    "LOG_BTMP":     "btmp_log",
}

_ENV_OVERRIDE_KEYS = {
    "DATABASE_URL",
    "LLM_BACKEND",
    "LLM_MODEL",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "LLM_LOCAL_URL",
    "LLM_LOCAL_MODEL",
    "LLM_LANGUAGE",
    "AEGIS_LANGUAGE",
    "ABUSEIPDB_API_KEY",
    "OTX_API_KEY",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "EMAIL_SMTP_HOST",
    "EMAIL_SMTP_PORT",
    "EMAIL_SMTP_USER",
    "EMAIL_SMTP_PASS",
    "EMAIL_FROM",
    "EMAIL_TO",
    *_LOG_KEY_MAP.keys(),
}


def _load_env_file(path: Path) -> Dict[str, str]:
    """
    Simple .env file reader.
    KEY=VALUE format, comment lines, and blank lines are supported.
    """
    result: Dict[str, str] = {}
    if not path.exists():
        return result
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            logger.debug("[Integrations] Satır %s atlandı (= yok)", lineno)
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            result[key] = val
    return result


class IntegrationSettings:
    """
    Settings loaded from integrations.env.
    Not a singleton — reads the current file on every call.
    """

    def __init__(self, raw: Dict[str, str]):
        self._raw = raw

    # ── DB ───────────────────────────────────────────────────────────────────

    @property
    def database_url(self) -> str:
        return self._raw.get("DATABASE_URL", "").strip()

    # ── LLM ──────────────────────────────────────────────────────────────────

    @property
    def llm_backend(self) -> str:
        return self._raw.get("LLM_BACKEND", "mock").strip().lower()

    @property
    def anthropic_key(self) -> str:
        return self._raw.get("ANTHROPIC_API_KEY", "").strip()

    @property
    def openai_key(self) -> str:
        return self._raw.get("OPENAI_API_KEY", "").strip()

    @property
    def gemini_key(self) -> str:
        return self._raw.get("GEMINI_API_KEY", "").strip()

    @property
    def llm_local_url(self) -> str:
        return self._raw.get("LLM_LOCAL_URL", "").strip()

    @property
    def llm_local_model(self) -> str:
        return self._raw.get("LLM_LOCAL_MODEL", "llama3").strip()

    @property
    def llm_model(self) -> str:
        return self._raw.get("LLM_MODEL", "").strip()

    @property
    def llm_language(self) -> str:
        return normalize_language(
            self._raw.get("LLM_LANGUAGE") or self._raw.get("AEGIS_LANGUAGE"),
            default="tr",
        )

    def llm_api_key(self) -> str:
        """Return the correct API key for the active backend."""
        if self.llm_backend == "anthropic":
            return self.anthropic_key
        if self.llm_backend == "openai":
            return self.openai_key
        if self.llm_backend == "gemini":
            return self.gemini_key
        return ""

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────

    @property
    def abuseipdb_key(self) -> str:
        return self._raw.get("ABUSEIPDB_API_KEY", "").strip()

    @property
    def abuseipdb_enabled(self) -> bool:
        return bool(self.abuseipdb_key)

    # ── OTX ──────────────────────────────────────────────────────────────────

    @property
    def otx_key(self) -> str:
        return self._raw.get("OTX_API_KEY", "").strip()

    # ── Notifications / Notifier ────────────────────────────────────────────

    @property
    def telegram_bot_token(self) -> str:
        return self._raw.get("TELEGRAM_BOT_TOKEN", "").strip()

    @property
    def telegram_chat_id(self) -> str:
        return self._raw.get("TELEGRAM_CHAT_ID", "").strip()

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)

    @property
    def email_smtp_host(self) -> str:
        return self._raw.get("EMAIL_SMTP_HOST", "").strip()

    @property
    def email_to(self) -> str:
        return self._raw.get("EMAIL_TO", "").strip()

    @property
    def email_enabled(self) -> bool:
        return bool(self.email_smtp_host and self.email_to)

    # ── Log path overrides ───────────────────────────────────────────────────

    @property
    def log_overrides(self) -> Dict[str, str]:
        """
        Return only populated overrides.
        {"auth_log": "/custom/path", ...}
        """
        result: Dict[str, str] = {}
        for env_key, distro_key in _LOG_KEY_MAP.items():
            val = self._raw.get(env_key, "").strip()
            if val:
                result[distro_key] = val
        return result

    # ── Config dict builder (for merging with config.yml) ────────────────────

    def to_llm_config(self) -> Dict:
        """
        Build a dict in LLMClient(config) format.
        integrations.env values override config.yml.
        """
        backend = self.llm_backend
        cfg: Dict = {
            "enabled":          backend != "mock" and bool(self.llm_api_key() or backend == "local"),
            "backend":          backend,
            "api_key":          self.llm_api_key(),
            "language":         self.llm_language,
            "max_tokens":       300,   # reduced to save tokens
            "timeout_seconds":  15,
            "cache_ttl":        300,
        }
        if self.llm_model:
            cfg["model"] = self.llm_model
        if backend == "local":
            cfg["base_url"] = self.llm_local_url
            cfg["model"] = self.llm_local_model
        return cfg

    # ── Factory ──────────────────────────────────────────────────────────────

    @classmethod
    def load(cls, config_dir: str = "config") -> "IntegrationSettings":
        """
        Load integrations.env and also export discovered values to os.environ
        without overwriting existing environment variables.
        """
        env_path = Path(config_dir) / "integrations.env"
        raw = _load_env_file(env_path)

        # The real process environment may override file values.
        # This keeps DATABASE_URL passed via systemd/unit or shell preferred in CLI/runtime as well
        # over the config file values.
        for key in _ENV_OVERRIDE_KEYS:
            env_val = os.environ.get(key, "").strip()
            if env_val:
                raw[key] = env_val

        if raw:
            logger.info(f"[Integrations] {env_path} yüklendi — {len(raw)} ayar")
        else:
            logger.debug(f"[Integrations] {env_path} bulunamadı veya boş — varsayılanlar kullanılıyor")

        # Export to os.environ without overwriting existing values
        for key, val in raw.items():
            if val and key not in os.environ:
                os.environ[key] = val

        return cls(raw)

    def summary(self) -> Dict:
        """Summary status information suitable for CLI/status surfaces."""
        return {
            "database_url":      "✓ ayarlı" if self.database_url else "✗ eksik",
            "llm_backend":       self.llm_backend,
            "llm_key":           "✓ ayarlı" if self.llm_api_key() else ("— (mock)" if self.llm_backend == "mock" else "✗ eksik"),
            "abuseipdb":         "✓ aktif" if self.abuseipdb_enabled else "✗ key girilmemiş",
            "otx":               "✓ aktif" if self.otx_key else "— (ücretsiz feed)",
            "telegram":          "✓ aktif" if self.telegram_enabled else "✗ eksik",
            "email":             "✓ aktif" if self.email_enabled else "✗ eksik",
            "log_overrides":     list(self.log_overrides.keys()) or ["— (otomatik algılama)"],
        }
