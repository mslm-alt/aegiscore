"""
core/abuseipdb.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AbuseIPDB IP lookup module

Performs lookups only — blocking remains a user action.
Query results are written to the DB ip_block_suggestions table.

Usage:
  from core.abuseipdb import AbuseIPDBClient
  client = AbuseIPDBClient(api_key="...", db=db)
  result = client.query("1.2.3.4")
  # result: {"ip": ..., "abuse_score": 87, "total_reports": 42, ...}
"""

import json
import ipaddress
import time
import logging
import urllib.request
import urllib.error
from typing import Dict, Optional

logger = logging.getLogger(__name__)

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
_DEFAULT_TIMEOUT = 10
_CACHE_TTL       = 3600  # the same IP is queried at most once per hour
_RATE_LIMIT_BACKOFF = 300
_DEFAULT_SUGGESTION_MIN_ABUSE_SCORE = 0
_DEFAULT_SUGGESTION_MIN_REPORTS = 0


class AbuseIPDBClient:
    """
    AbuseIPDB v2 API client.

    query(ip)       → return the raw lookup result
    query_and_save(ip, db, alert_id) → sorguyu yap + DB'ye kaydet
    """

    def __init__(
        self,
        api_key: str,
        db=None,
        timeout: int = _DEFAULT_TIMEOUT,
        cache_ttl: int = _CACHE_TTL,
        rate_limit_backoff: int = _RATE_LIMIT_BACKOFF,
        suggestion_min_abuse_score: int = _DEFAULT_SUGGESTION_MIN_ABUSE_SCORE,
        suggestion_min_reports: int = _DEFAULT_SUGGESTION_MIN_REPORTS,
        always_suggest_for_high_severity: bool = False,
    ):
        self._key     = api_key.strip() if api_key else ""
        self._db      = db
        self._timeout = timeout
        self._cache_ttl = max(0, int(cache_ttl or _CACHE_TTL))
        self._rate_limit_backoff = max(0, int(rate_limit_backoff or _RATE_LIMIT_BACKOFF))
        self._suggestion_min_abuse_score = max(0, int(suggestion_min_abuse_score or 0))
        self._suggestion_min_reports = max(0, int(suggestion_min_reports or 0))
        self._always_suggest_for_high_severity = bool(always_suggest_for_high_severity)
        self._rate_limited_until = 0.0
        self._cache: Dict[str, tuple] = {}  # ip → (result, ts)
        self.enabled  = bool(self._key)
        if not self.enabled:
            logger.debug("[AbuseIPDB] API key girilmemiş — sorgu devre dışı")

    # ── Sorgu ─────────────────────────────────────────────────────────────────

    @staticmethod
    def is_queryable_public_ip(ip: str) -> bool:
        token = str(ip or "").strip()
        if not token:
            return False
        try:
            ip_obj = ipaddress.ip_address(token)
        except ValueError:
            return False
        if ip_obj.is_unspecified or ip_obj.is_loopback or ip_obj.is_multicast:
            return False
        if getattr(ip_obj, "is_link_local", False):
            return False
        if ip_obj.version == 4 and token == "255.255.255.255":
            return False
        if ip_obj.is_reserved or ip_obj.is_private:
            return False
        return True

    def query(self, ip: str, max_age_days: int = 90) -> Optional[Dict]:
        """
        Query the IP in AbuseIPDB.
        Returns:
          {
            "ip":            str,
            "abuse_score":   int (0-100),
            "total_reports": int,
            "country_code":  str,
            "is_public":     bool,
            "is_tor":        bool,
            "domain":        str,
            "last_reported": str,
            "raw":           dict   ← full API response
          }
        Returns None on error or when no API key is configured.
        """
        if not self.enabled:
            return None
        if not ip or not ip.strip():
            return None

        ip = ip.strip()
        if not self.is_queryable_public_ip(ip):
            logger.debug(f"[AbuseIPDB] Skip non-public IP: {ip}")
            return None
        if self._rate_limited_until and time.time() < self._rate_limited_until:
            logger.debug("[AbuseIPDB] Rate limit backoff aktif — sorgu atlandı")
            return None

        # Cache check
        cached = self._cache.get(ip)
        if cached and (time.time() - cached[1]) < self._cache_ttl:
            logger.debug(f"[AbuseIPDB] Cache hit: {ip}")
            return cached[0]

        try:
            url = (
                f"{ABUSEIPDB_CHECK_URL}"
                f"?ipAddress={ip}&maxAgeInDays={max_age_days}&verbose"
            )
            req = urllib.request.Request(
                url,
                headers={
                    "Key":    self._key,
                    "Accept": "application/json",
                }
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw_body = resp.read().decode("utf-8")
                raw      = json.loads(raw_body)

            data = raw.get("data", {})
            result = {
                "ip":            data.get("ipAddress", ip),
                "abuse_score":   int(data.get("abuseConfidenceScore", 0)),
                "total_reports": int(data.get("totalReports", 0)),
                "country_code":  data.get("countryCode", ""),
                "is_public":     bool(data.get("isPublic", True)),
                "is_tor":        bool(data.get("isTor", False)),
                "domain":        data.get("domain", ""),
                "last_reported": data.get("lastReportedAt", ""),
                "raw":           data,
            }

            # Cache'e al
            self._cache[ip] = (result, time.time())
            if len(self._cache) > 500:
                oldest = sorted(self._cache, key=lambda k: self._cache[k][1])
                for old in oldest[:100]:
                    del self._cache[old]

            logger.info(
                f"[AbuseIPDB] {ip} → score={result['abuse_score']}, "
                f"reports={result['total_reports']}, country={result['country_code']}"
            )
            return result

        except urllib.error.HTTPError as e:
            if e.code == 422:
                logger.warning(f"[AbuseIPDB] {ip}: geçersiz IP formatı (422)")
            elif e.code == 401:
                logger.error("[AbuseIPDB] Geçersiz API key (401)")
            elif e.code == 429:
                logger.warning("[AbuseIPDB] Rate limit aşıldı (429)")
                self._rate_limited_until = time.time() + self._rate_limit_backoff
            else:
                logger.warning(f"[AbuseIPDB] HTTP {e.code}: {ip}")
            return None
        except Exception as e:
            logger.warning(f"[AbuseIPDB] Sorgu hatası {ip}: {e}")
            return None

    def _should_save_suggestion(
        self,
        result: Dict,
        alert_severity: str = "",
        force_save: bool = False,
    ) -> bool:
        if force_save:
            return True
        severity = str(alert_severity or "").strip().lower()
        if self._always_suggest_for_high_severity and severity in {"high", "critical"}:
            return True
        abuse_score = int(result.get("abuse_score", 0) or 0)
        total_reports = int(result.get("total_reports", 0) or 0)
        return (
            abuse_score >= self._suggestion_min_abuse_score
            or total_reports >= self._suggestion_min_reports
        )

    def query_and_save(self, ip: str, db=None,
                        alert_id: int = None,
                        reason: str = "abuseipdb_lookup",
                        max_age_days: int = 90,
                        alert_severity: str = "",
                        force_save: bool = False) -> Optional[Dict]:
        """
        IP'yi sorgula ve sonucu DB'ye kaydet.
        Engelleme kararı kullanıcıya bırakılır (reviewed=False olarak gider).
        """
        result = self.query(ip, max_age_days=max_age_days)
        if not result:
            return None
        should_save = self._should_save_suggestion(
            result,
            alert_severity=alert_severity,
            force_save=force_save,
        )
        result["suggestion_written"] = bool(should_save)
        if not should_save:
            logger.debug(
                "[AbuseIPDB] Suggestion skip %s: score=%s reports=%s severity=%s thresholds=(score>=%s,reports>=%s)",
                ip,
                result.get("abuse_score", 0),
                result.get("total_reports", 0),
                alert_severity,
                self._suggestion_min_abuse_score,
                self._suggestion_min_reports,
            )
            return result

        target_db = db or self._db
        if target_db and hasattr(target_db, "add_ip_block_suggestion"):
            try:
                target_db.add_ip_block_suggestion(
                    ip            = ip,
                    reason        = reason,
                    source        = "abuseipdb",
                    alert_id      = alert_id,
                    abuse_score   = result["abuse_score"],
                    abuse_reports = result["total_reports"],
                    abuse_country = result["country_code"],
                    abuse_raw     = result["raw"],
                )
            except Exception as e:
                logger.warning(f"[AbuseIPDB] DB kayıt hatası: {e}")

        return result

    def enrich_alert_ips(
        self,
        src_ip: str = "",
        dst_ip: str = "",
        db=None,
        alert_id: int = None,
        reason_prefix: str = "alert_abuseipdb",
        max_age_days: int = 90,
        query_dst_ip: bool = True,
        alert_severity: str = "",
    ) -> Dict[str, Optional[Dict]]:
        """
        Alert context içindeki public IP'leri enrichment/suggestion için sorgula.
        Firewall executor çağrılmaz; sadece AbuseIPDB + ip_block_suggestions kullanılır.
        """
        results: Dict[str, Optional[Dict]] = {"src_ip": None, "dst_ip": None}
        candidates = [("src_ip", src_ip)]
        if query_dst_ip:
            candidates.append(("dst_ip", dst_ip))
        seen = set()
        for field, ip in candidates:
            token = str(ip or "").strip()
            if not token or token in seen:
                continue
            seen.add(token)
            if not self.is_queryable_public_ip(token):
                logger.debug(f"[AbuseIPDB] Alert enrichment skip {field}: {token}")
                continue
            results[field] = self.query_and_save(
                token,
                db=db,
                alert_id=alert_id,
                reason=f"{reason_prefix}:{field}",
                max_age_days=max_age_days,
                alert_severity=alert_severity,
            )
        return results

    def bulk_query(self, ips: list, db=None, alert_id: int = None) -> Dict[str, Optional[Dict]]:
        """
        Birden fazla IP için toplu sorgulama.
        Returns: {ip: result_or_None}
        """
        results = {}
        for ip in ips:
            results[ip] = self.query_and_save(ip, db=db, alert_id=alert_id)
        return results

    @property
    def is_active(self) -> bool:
        return self.enabled

    def status(self) -> Dict:
        return {
            "enabled":    self.enabled,
            "cache_size": len(self._cache),
            "rate_limited": bool(self._rate_limited_until and time.time() < self._rate_limited_until),
        }
