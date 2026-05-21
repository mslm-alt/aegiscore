from __future__ import annotations
"""
core/notifier.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Bildirim Katmanı — Telegram ve E-posta

Tetiklenme koşulları (her ikiside de geçerli):
  1. Severity: sadece critical
  2. VEYA: aynı entity'den kısa sürede tekrar eden high/critical
  3. VEYA: incident oluştuğunda (korelasyon zinciri tamamlandı)

Gürültü önleme:
  - Aynı rule_id + entity için NOTIFY_COOLDOWN_SEC (varsayılan 900s) geçmeden ikinci bildirim gitmez
  - Tekrar sayacı: aynı entity'den REPEAT_WINDOW_SEC içinde REPEAT_THRESHOLD kadar
    alert gelirse bildirim gider (high seviyeler için devreye girer)
  - Bir dakikada MAX_PER_MINUTE'den fazla bildirim gitmez (burst koruması)

Yapılandırma (integrations.env):
  TELEGRAM_BOT_TOKEN=...
  TELEGRAM_CHAT_ID=...
  EMAIL_SMTP_HOST=smtp.gmail.com
  EMAIL_SMTP_PORT=587
  EMAIL_SMTP_USER=...
  EMAIL_SMTP_PASS=...
  EMAIL_FROM=aegiscore@example.com
  EMAIL_TO=admin@example.com
"""

import time
import json
import logging
import threading
import collections
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Threshold Constants ───────────────────────────────────────────────
NOTIFY_COOLDOWN_SEC  = 900    # aynı rule+entity için min 15 dk arayla bildirim
REPEAT_WINDOW_SEC    = 300    # 5 dk içinde tekrar sayısı takibi
REPEAT_THRESHOLD     = 3      # bu kadar alert gelirse high da bildirimi tetikler
MAX_PER_MINUTE       = 6      # dakikada en fazla bildirim (burst koruması)
INCIDENT_NOTIFY      = True   # incident oluştuğunda her zaman bildir


class _RateLimiter:
    """Burst protection on a per-minute basis."""
    def __init__(self, max_per_minute: int = MAX_PER_MINUTE):
        self._max   = max_per_minute
        self._times: collections.deque = collections.deque()
        self._lock  = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now    = time.time()
            cutoff = now - 60
            while self._times and self._times[0] < cutoff:
                self._times.popleft()
            if len(self._times) >= self._max:
                return False
            self._times.append(now)
            return True


class _TelegramSender:
    """Send a message through the Telegram Bot API."""

    def __init__(self, token: str, chat_id: str, timeout: int = 10):
        self.token   = token.strip()
        self.chat_id = str(chat_id).strip()
        self.timeout = timeout

    def send(self, text: str) -> bool:
        if not self.token or not self.chat_id:
            return False
        try:
            import urllib.request
            import urllib.parse
            url     = f"https://api.telegram.org/bot{self.token}/sendMessage"
            payload = json.dumps({
                "chat_id":    self.chat_id,
                "text":       text[:4096],   # Telegram karakter sınırı
                "parse_mode": "HTML",
            }).encode()
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read())
                if result.get("ok"):
                    logger.debug(f"[Notifier:Telegram] Gönderildi — chat={self.chat_id}")
                    return True
                logger.warning(f"[Notifier:Telegram] API hatası: {result}")
                return False
        except Exception as e:
            logger.warning(f"[Notifier:Telegram] Gönderme hatası: {e}")
            return False


class _EmailSender:
    """Send email through SMTP with STARTTLS support."""

    def __init__(self, host: str, port: int, user: str, password: str,
                 from_addr: str, to_addr: str, timeout: int = 15):
        self.host      = host.strip()
        self.port      = int(port)
        self.user      = user.strip()
        self.password  = password.strip()
        self.from_addr = from_addr.strip()
        self.to_addr   = to_addr.strip()
        self.timeout   = timeout

    def send(self, subject: str, body: str) -> bool:
        if not self.host or not self.to_addr:
            return False
        try:
            import smtplib
            from email.mime.text import MIMEText
            msg            = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject[:150]
            msg["From"]    = self.from_addr
            msg["To"]      = self.to_addr
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                if self.user and self.password:
                    smtp.login(self.user, self.password)
                smtp.sendmail(self.from_addr, [self.to_addr], msg.as_string())
            logger.debug(f"[Notifier:Email] Gönderildi — to={self.to_addr}")
            return True
        except Exception as e:
            logger.warning(f"[Notifier:Email] Gönderme hatası: {e}")
            return False


class Notifier:
    """
    Merkezi bildirim yöneticisi.

    Koşullar:
      - critical severity → her zaman bildir (cooldown'a tabi)
      - high severity + REPEAT_WINDOW içinde aynı entity'den >= REPEAT_THRESHOLD → bildir
      - incident oluştu → bildir
      - Burst koruması: dakikada MAX_PER_MINUTE'den fazla gitmiyor
    """

    def __init__(self, settings=None):
        """
        settings: IntegrationSettings nesnesi veya ham dict.
        Key yoksa ilgili kanal devre dışı kalır — sistem hata vermez.
        """
        self._telegram: Optional[_TelegramSender] = None
        self._email:    Optional[_EmailSender]    = None
        self._limiter   = _RateLimiter(MAX_PER_MINUTE)
        self._cooldowns: Dict[str, float] = {}    # "rule_id:entity" → last_sent_ts
        self._repeat_counts: Dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque()
        )
        self._lock = threading.Lock()
        self._hostname = self._get_hostname()

        if settings is not None:
            self._init_from_settings(settings)

    def _get_hostname(self) -> str:
        try:
            import socket
            return socket.gethostname()
        except Exception:
            return "unknown-host"

    def _init_from_settings(self, settings) -> None:
        """Initialize channels from IntegrationSettings or a dict."""
        # Telegram
        if hasattr(settings, "_raw"):
            raw = settings._raw
        elif isinstance(settings, dict):
            raw = settings
        else:
            raw = {}

        tg_token   = raw.get("TELEGRAM_BOT_TOKEN", "").strip()
        tg_chat    = raw.get("TELEGRAM_CHAT_ID", "").strip()
        if tg_token and tg_chat:
            self._telegram = _TelegramSender(tg_token, tg_chat)
            logger.info("[Notifier] Telegram aktif")
        else:
            logger.debug("[Notifier] Telegram devre dışı (token/chat_id eksik)")

        # Email
        smtp_host = raw.get("EMAIL_SMTP_HOST", "").strip()
        smtp_port = int(raw.get("EMAIL_SMTP_PORT", 587) or 587)
        smtp_user = raw.get("EMAIL_SMTP_USER", "").strip()
        smtp_pass = raw.get("EMAIL_SMTP_PASS", "").strip()
        email_from = raw.get("EMAIL_FROM", smtp_user).strip()
        email_to   = raw.get("EMAIL_TO", "").strip()
        if smtp_host and email_to:
            self._email = _EmailSender(
                smtp_host, smtp_port, smtp_user, smtp_pass,
                email_from, email_to
            )
            logger.info(f"[Notifier] E-posta aktif → {email_to}")
        else:
            logger.debug("[Notifier] E-posta devre dışı (SMTP host/to eksik)")

    @property
    def is_active(self) -> bool:
        return bool(self._telegram or self._email)

    # ── Condition Evaluation ──────────────────────────────────────────────

    def _should_notify_alert(self, severity: str, rule_id: str,
                              entity: str) -> tuple:
        """
        (should_send: bool, reason: str) döndür.
        True döndürürse cooldown otomatik kaydedilir.

        Kurallar:
          1. critical → her zaman (cooldown'a tabi)
          2. high + repeat → REPEAT_WINDOW içinde >= REPEAT_THRESHOLD gelirse
          3. Diğerleri → asla
        """
        sev = str(severity).lower()

        # Only critical and high severities are evaluated
        if sev not in ("critical", "high"):
            return False, ""

        cooldown_key = f"{rule_id}:{entity}"
        now = time.time()

        with self._lock:
            # Cooldown check
            last_sent = self._cooldowns.get(cooldown_key, 0.0)
            if now - last_sent < NOTIFY_COOLDOWN_SEC:
                return False, ""

            if sev == "critical":
                self._cooldowns[cooldown_key] = now
                return True, "critical_severity"

            # high: update the repeat counter
            dq = self._repeat_counts[entity]
            dq.append(now)
            cutoff = now - REPEAT_WINDOW_SEC
            while dq and dq[0] < cutoff:
                dq.popleft()
            count = len(dq)

            if count >= REPEAT_THRESHOLD:
                self._cooldowns[cooldown_key] = now
                return True, f"repeat_burst_{count}"

        return False, ""

    # ── Message Formats ───────────────────────────────────────────────────

    def _format_alert_telegram(self, alert: Dict, reason: str) -> str:
        sev    = str(alert.get("severity", "")).upper()
        emoji  = "🚨" if sev == "CRITICAL" else "⚠️"
        repeat = f" (tekrar x{reason.split('_')[-1]})" if "repeat" in reason else ""
        return (
            f"{emoji} <b>AegisCore Alert{repeat}</b>\n"
            f"🖥 Host: <code>{alert.get('host','?')}</code>\n"
            f"📋 Kural: <code>{alert.get('rule_id','?')}</code>\n"
            f"⚡ Seviye: <b>{sev}</b> | Skor: {alert.get('risk_score',0)}\n"
            f"🔍 Mesaj: {str(alert.get('message',''))[:200]}\n"
            f"🌐 Entity: <code>{alert.get('entity','?')}</code>\n"
            f"🕐 {self._ts_str(alert.get('ts'))}"
        )

    def _format_alert_email_subject(self, alert: Dict, reason: str) -> str:
        sev    = str(alert.get("severity", "")).upper()
        repeat = " [TEKRAR]" if "repeat" in reason else ""
        return f"[AegisCore{repeat}] {sev} — {alert.get('rule_id','?')} @ {alert.get('host','?')}"

    def _format_alert_email_body(self, alert: Dict, reason: str) -> str:
        lines = [
            f"AegisCore Güvenlik Alarmı",
            f"{'='*40}",
            f"Host      : {alert.get('host','?')}",
            f"Kural     : {alert.get('rule_id','?')}",
            f"Seviye    : {str(alert.get('severity','')).upper()}",
            f"Skor      : {alert.get('risk_score',0)}",
            f"Kategori  : {alert.get('category','')}",
            f"Mesaj     : {alert.get('message','')}",
            f"Entity    : {alert.get('entity','?')}",
            f"MITRE     : {alert.get('mitre_tactic','')} / {alert.get('mitre_technique','')}",
            f"Zaman     : {self._ts_str(alert.get('ts'))}",
            f"Neden     : {reason}",
        ]
        ctx = alert.get("context_json", {})
        if ctx:
            lines += [
                "",
                "Bağlam:",
                f"  Kaynak IP : {ctx.get('src_ip','-')}",
                f"  Kullanıcı : {ctx.get('user','-')}",
                f"  Süreç     : {ctx.get('process','-')}",
                f"  Eylem     : {ctx.get('action','-')}",
            ]
        return "\n".join(lines)

    def _format_incident_telegram(self, incident: Dict) -> str:
        sev   = str(incident.get("severity", "")).upper()
        count = incident.get("alert_count", "?")
        return (
            f"🔴 <b>AegisCore Incident</b>\n"
            f"🖥 Host: <code>{incident.get('host', self._hostname)}</code>\n"
            f"🆔 ID: <code>{incident.get('incident_id','?')}</code>\n"
            f"📊 Seviye: <b>{sev}</b> | {count} alert\n"
            f"🎯 Entity: <code>{incident.get('entity_key', incident.get('entity','?'))}</code>\n"
            f"📝 {str(incident.get('title', incident.get('message','')))[:200]}\n"
            f"🕐 {self._ts_str(incident.get('ts'))}"
        )

    def _format_incident_email(self, incident: Dict) -> tuple:
        sev = str(incident.get("severity", "")).upper()
        subject = f"[AegisCore] Incident {sev} — {incident.get('incident_id','?')}"
        body = (
            f"AegisCore Güvenlik Incident\n"
            f"{'='*40}\n"
            f"ID       : {incident.get('incident_id','?')}\n"
            f"Başlık   : {incident.get('title', incident.get('message',''))}\n"
            f"Seviye   : {sev}\n"
            f"Entity   : {incident.get('entity_key', incident.get('entity','?'))}\n"
            f"Alert    : {incident.get('alert_count','?')} adet\n"
            f"Zaman    : {self._ts_str(incident.get('ts'))}\n"
        )
        return subject, body

    @staticmethod
    def _ts_str(ts) -> str:
        try:
            import datetime
            return datetime.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "-"

    # ── Delivery ──────────────────────────────────────────────────────────

    def _dispatch(self, tg_text: str, email_subject: str, email_body: str) -> None:
        """Check rate limits and send in the background."""
        if not self._limiter.allow():
            logger.debug("[Notifier] Rate limit — bildirim atlandı")
            return

        def _send():
            if self._telegram:
                self._telegram.send(tg_text)
            if self._email:
                self._email.send(email_subject, email_body)

        threading.Thread(target=_send, daemon=True).start()

    # ── Public API ────────────────────────────────────────────────────────

    def on_alert(self, alert: Dict) -> None:
        """
        _emit_alert'den sonra çağrılır.
        Koşulları sağlamıyorsa sessizce döner.
        """
        if not self.is_active:
            return
        severity  = alert.get("severity", "")
        rule_id   = alert.get("rule_id", "")
        entity    = alert.get("entity", "")

        should_send, reason = self._should_notify_alert(severity, rule_id, entity)
        if not should_send:
            return

        tg_text      = self._format_alert_telegram(alert, reason)
        email_subj   = self._format_alert_email_subject(alert, reason)
        email_body   = self._format_alert_email_body(alert, reason)
        self._dispatch(tg_text, email_subj, email_body)
        logger.info(
            f"[Notifier] Bildirim gönderildi — {rule_id} | {severity} | {entity} | {reason}"
        )

    def on_incident(self, incident: Dict) -> None:
        """
        Incident oluştuğunda çağrılır.
        critical/high incident'larda her zaman bildir (cooldown'a tabi).
        """
        if not self.is_active or not INCIDENT_NOTIFY:
            return
        sev = str(incident.get("severity", "")).lower()
        if sev not in ("critical", "high"):
            return

        entity      = incident.get("entity_key", incident.get("entity", ""))
        cooldown_key = f"INC:{incident.get('incident_id', entity)}"
        with self._lock:
            last = self._cooldowns.get(cooldown_key, 0.0)
            if time.time() - last < NOTIFY_COOLDOWN_SEC:
                return
            self._cooldowns[cooldown_key] = time.time()

        if not self._limiter.allow():
            return

        tg_text          = self._format_incident_telegram(incident)
        email_subj, body = self._format_incident_email(incident)

        def _send():
            if self._telegram:
                self._telegram.send(tg_text)
            if self._email:
                self._email.send(email_subj, body)

        threading.Thread(target=_send, daemon=True).start()
        logger.info(f"[Notifier] Incident bildirimi gönderildi — {incident.get('incident_id','?')}")

    def test_send(self) -> Dict[str, bool]:
        """
        Bağlantı testi — CLI/operator health check yüzeyinden çağrılabilir.
        Her iki kanala da test mesajı gönderir.
        """
        results = {}
        msg = (
            f"✅ <b>AegisCore Test</b>\n"
            f"Bildirim sistemi çalışıyor.\n"
            f"Host: <code>{self._hostname}</code>"
        )
        if self._telegram:
            results["telegram"] = self._telegram.send(msg)
        else:
            results["telegram"] = False

        if self._email:
            results["email"] = self._email.send(
                "[AegisCore] Test Bildirimi",
                f"AegisCore bildirim sistemi çalışıyor.\nHost: {self._hostname}"
            )
        else:
            results["email"] = False

        return results

    def status(self) -> Dict:
        return {
            "telegram_active": self._telegram is not None,
            "email_active":    self._email is not None,
            "cooldowns_count": len(self._cooldowns),
        }

    def cleanup_old_cooldowns(self) -> None:
        """Clean expired cooldown records; called from the maintenance loop."""
        now = time.time()
        cutoff = now - NOTIFY_COOLDOWN_SEC * 2
        with self._lock:
            stale = [k for k, ts in self._cooldowns.items() if ts < cutoff]
            for k in stale:
                del self._cooldowns[k]
