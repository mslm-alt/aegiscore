from __future__ import annotations
"""
core/threat_intel.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Threat Intelligence Feed Otomasyonu

Ücretsiz feed'ler (API key gerekmez — her zaman aktif):
  - Feodo Tracker     botnet C2 IP listesi   (abuse.ch)
  - URLhaus           kötü amaçlı URL/domain (abuse.ch)
  - Emerging Threats  bilinen kötü IP'ler    (proofpoint)
  - CINS Army         saldırgan IP listesi

API key gerektiren feed'ler (key yoksa atlanır):
  - AlienVault OTX    (OTX_API_KEY)

Çalışma mantığı:
  - update_interval_hours saatte bir feed'leri çeker
  - İndirilen IOC'ler config/ioc_list.txt içinde "# --- AUTO FEED ---" sonrası
    generated bölümü yeniden oluşturarak statik satırlarla birleştirilir
  - detection.IOCMatcher.reload() çağrılır — restart gerekmez
  - Ağ erişimi yoksa mevcut IOC listesiyle devam eder
  - Tüm hatalar sessizce loglanır, pipeline durdurmaz

API key öncelik sırası:
  1. config.yml → threat_intel.otx_api_key
  2. OTX_API_KEY environment variable
"""

import os
import re
import time
import json
import logging
import hashlib
import threading
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ── Feed Definitions ───────────────────────────────────────────────────

# Her feed: (url, parser_type, description)
# parser_type: "plain_ip" | "plain_domain" | "csv_ip" | "json_otx"
FREE_FEEDS: List[Tuple[str, str, str]] = [
    (
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "plain_ip",
        "Feodo Tracker — Botnet C2 IP",
    ),
    (
        "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "plain_ip",
        "IPsum Level 3 — Kötü amaçlı IP",
    ),
    (
        "https://cinsscore.com/list/ci-badguys.txt",
        "plain_ip",
        "CINS Army — Saldırgan IP",
    ),
    (
        "https://urlhaus.abuse.ch/downloads/text_online/",
        "plain_domain",
        "URLhaus — Aktif kötü amaçlı URL",
    ),
]

OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20&modified_since={since}"
OTX_INDICATORS_URL = "https://otx.alienvault.com/api/v1/indicators/export"


# ── Helper Parsers ─────────────────────────────────────────────────────

_RE_IPV4 = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_RE_HASH = re.compile(r'^[a-fA-F0-9]{32,64}$')
_RE_DOMAIN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$')


def _parse_plain_ip(text: str) -> Set[str]:
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # "IP #comment" veya sadece IP
        ip = line.split()[0]
        if _RE_IPV4.match(ip):
            ips.add(ip)
    return ips


def _parse_plain_domain(text: str) -> Set[str]:
    domains = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        # Extract the domain from the URL
        try:
            if "://" in line:
                line = line.split("://", 1)[1].split("/")[0].split(":")[0]
            if _RE_DOMAIN.match(line):
                domains.add(line)
        except Exception:
            continue
    return domains


def _parse_otx_json(data: Dict) -> Tuple[Set[str], Set[str], Set[str]]:
    ips, domains, hashes = set(), set(), set()
    results = data.get("results", [])
    for pulse in results:
        for ind in pulse.get("indicators", []):
            t    = ind.get("type", "")
            val  = ind.get("indicator", "").strip().lower()
            if not val:
                continue
            if t in ("IPv4", "IPv6") and _RE_IPV4.match(val):
                ips.add(val)
            elif t in ("domain", "hostname") and _RE_DOMAIN.match(val):
                domains.add(val)
            elif t in ("FileHash-MD5", "FileHash-SHA256") and _RE_HASH.match(val):
                hashes.add(val)
    return ips, domains, hashes


# ── HTTP Helper ────────────────────────────────────────────────────────

def _fetch(url: str, headers: Dict = None, timeout: int = 20) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers=headers or {})
        req.add_header("User-Agent", "AegisCore-ThreatIntel/1.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except urllib.error.URLError as e:
        logger.debug(f"[ThreatIntel] Fetch hatası {url}: {e}")
        return None
    except Exception as e:
        logger.debug(f"[ThreatIntel] Beklenmeyen hata {url}: {e}")
        return None


# ── Main Class ─────────────────────────────────────────────────────────

class ThreatIntelUpdater:
    """
    Periyodik threat intel feed güncelleyici.

    ioc_matcher  : detection.IOCMatcher örneği (reload için)
    ioc_file     : config/ioc_list.txt yolu (statik bölüm + generated AUTO FEED bölümü)
    config       : config.yml threat_intel bölümü
    """

    # Cache file for IOCs pulled from feeds
    CACHE_FILE = "data/threat_intel_cache.json"

    def __init__(self, ioc_matcher, ioc_file: str, config: Dict = None):
        self._matcher   = ioc_matcher
        self._ioc_file  = Path(ioc_file)
        cfg             = (config or {}).get("threat_intel", {})

        self.enabled           = cfg.get("enabled", True)
        self.update_interval   = int(cfg.get("update_interval_hours", 24)) * 3600
        self.timeout           = int(cfg.get("fetch_timeout_seconds", 20))
        self.max_iocs_per_feed = int(cfg.get("max_iocs_per_feed", 50000))
        # IOC TTL: track age in hours for each IOC coming from feeds
        # Remove the IOC on the next refresh once its TTL expires
        self.ioc_ttl_hours     = int(cfg.get("ioc_ttl_hours", 72))
        # Feed freshness: warn when a feed returns the same content for N refreshes
        self.stale_feed_threshold = int(cfg.get("stale_feed_threshold", 3))

        # Resolve the OTX API key
        self._otx_key = self._resolve_otx_key(cfg.get("otx_api_key", ""))

        # Toplanan IOC setleri (feed'lerden)
        self._feed_ips:     Set[str] = set()
        self._feed_domains: Set[str] = set()
        self._feed_hashes:  Set[str] = set()

        # TTL tracking: IOC → first_seen_timestamp
        self._ioc_first_seen: Dict[str, float] = {}

        # Feed freshness tracking: feed_url → (hash_of_last_content, consecutive_same_count)
        self._feed_hashes_content: Dict[str, Tuple[str, int]] = {}
        self._stale_feeds:   List[str] = []

        # Last refresh time
        self._last_update   = 0.0
        self._update_count  = 0
        self._last_counts   = {}
        self._running       = False
        self._thread: Optional[threading.Thread] = None

        if not self.enabled:
            logger.info("[ThreatIntel] Devre dışı (threat_intel.enabled: false)")
            return

        # Load previous feed IOCs from cache
        self._load_cache()

        if self._otx_key:
            logger.info("[ThreatIntel] OTX aktif — API key bulundu")
        else:
            logger.info("[ThreatIntel] OTX pasif — ücretsiz feed'ler aktif")

    @staticmethod
    def _resolve_otx_key(config_key: str) -> str:
        if config_key and config_key.strip():
            return config_key.strip()
        return os.environ.get("OTX_API_KEY", "").strip()

    # ── Cache ──────────────────────────────────────────────────────────────────

    def _load_cache(self):
        try:
            p = Path(self.CACHE_FILE)
            if not p.exists():
                return
            data = json.loads(p.read_text())
            self._feed_ips        = set(data.get("ips",     []))
            self._feed_domains    = set(data.get("domains", []))
            self._feed_hashes     = set(data.get("hashes",  []))
            self._last_update     = data.get("last_update", 0.0)
            self._ioc_first_seen  = {k: float(v) for k,v in data.get("first_seen", {}).items()}
            age_hours = (time.time() - self._last_update) / 3600
            total = len(self._feed_ips) + len(self._feed_domains) + len(self._feed_hashes)
            logger.info(
                f"[ThreatIntel] Cache yüklendi: {total} IOC "
                f"({age_hours:.1f} saat önce güncellenmiş)"
            )
        except Exception as e:
            logger.debug(f"[ThreatIntel] Cache yükleme hatası: {e}")

    def _save_cache(self):
        try:
            Path(self.CACHE_FILE).parent.mkdir(parents=True, exist_ok=True)
            data = {
                "ips":         list(self._feed_ips)[:self.max_iocs_per_feed],
                "domains":     list(self._feed_domains)[:self.max_iocs_per_feed],
                "hashes":      list(self._feed_hashes)[:self.max_iocs_per_feed],
                "last_update": self._last_update,
                "first_seen":  dict(list(self._ioc_first_seen.items())[:100000]),
            }
            Path(self.CACHE_FILE).write_text(json.dumps(data))
        except Exception as e:
            logger.debug(f"[ThreatIntel] Cache kaydetme hatası: {e}")

    # ── Feed Fetching ──────────────────────────────────────────────────────

    def _check_feed_freshness(self, url: str, content: str) -> bool:
        """
        Feed içeriği hash'ine bakarak bayatlık tespiti.
        stale_feed_threshold kadar ardışık aynı içerik → stale olarak işaretle.
        True = fresh, False = stale (yine de kullanılır ama uyarı loglanır).
        """
        h = hashlib.md5(content[:4096].encode()).hexdigest()
        prev_hash, count = self._feed_hashes_content.get(url, ("", 0))
        if h == prev_hash:
            count += 1
            self._feed_hashes_content[url] = (h, count)
            if count >= self.stale_feed_threshold:
                if url not in self._stale_feeds:
                    self._stale_feeds.append(url)
                logger.warning(
                    f"[ThreatIntel] Stale feed ({count}x aynı içerik): {url}"
                )
                return False
        else:
            # Content changed — reset the counter and remove the feed from the stale list
            self._feed_hashes_content[url] = (h, 1)
            if url in self._stale_feeds:
                self._stale_feeds.remove(url)
                logger.info(f"[ThreatIntel] Feed yenilendi (stale → fresh): {url}")
            return True  # fresh
        return True

    def _apply_ioc_ttl(self, new_ips: Set[str], new_domains: Set[str],
                        new_hashes: Set[str]):
        """
        Yeni IOC'leri first_seen ile kayıt altına al.
        TTL süresi dolmuş eski IOC'leri temizle.
        """
        now = time.time()
        ttl_sec = self.ioc_ttl_hours * 3600

        # Yeni IOC'lerin first_seen'ini kaydet
        for ioc in new_ips | new_domains | new_hashes:
            if ioc not in self._ioc_first_seen:
                self._ioc_first_seen[ioc] = now

        # TTL check — remove expired IOCs
        expired = {ioc for ioc, ts in self._ioc_first_seen.items()
                   if now - ts > ttl_sec}
        if expired:
            logger.debug(f"[ThreatIntel] TTL süresi dolmuş {len(expired)} IOC kaldırıldı")
            for ioc in expired:
                del self._ioc_first_seen[ioc]
            new_ips      -= expired
            new_domains  -= expired
            new_hashes   -= expired

        return new_ips, new_domains, new_hashes

    def _fetch_free_feeds(self) -> Tuple[Set[str], Set[str]]:
        ips, domains = set(), set()
        for url, ptype, desc in FREE_FEEDS:
            text = _fetch(url, timeout=self.timeout)
            if not text:
                logger.debug(f"[ThreatIntel] Feed alınamadı: {desc}")
                continue
            try:
                self._check_feed_freshness(url, text)
                if ptype == "plain_ip":
                    new_ips = _parse_plain_ip(text)
                    ips.update(list(new_ips)[:self.max_iocs_per_feed])
                    logger.debug(f"[ThreatIntel] {desc}: {len(new_ips)} IP")
                elif ptype == "plain_domain":
                    new_dom = _parse_plain_domain(text)
                    domains.update(list(new_dom)[:self.max_iocs_per_feed])
                    logger.debug(f"[ThreatIntel] {desc}: {len(new_dom)} domain")
            except Exception as e:
                logger.debug(f"[ThreatIntel] Parse hatası {desc}: {e}")
        return ips, domains

    def _fetch_otx(self) -> Tuple[Set[str], Set[str], Set[str]]:
        if not self._otx_key:
            return set(), set(), set()
        ips, domains, hashes = set(), set(), set()
        try:
            since = time.strftime(
                "%Y-%m-%dT%H:%M:%S",
                time.gmtime(self._last_update or (time.time() - 7 * 86400))
            )
            url  = OTX_PULSES_URL.format(since=since)
            text = _fetch(url, headers={"X-OTX-API-KEY": self._otx_key}, timeout=30)
            if text:
                data = json.loads(text)
                i, d, h = _parse_otx_json(data)
                ips.update(i); domains.update(d); hashes.update(h)
                logger.debug(f"[ThreatIntel] OTX: {len(i)} IP, {len(d)} domain, {len(h)} hash")
        except Exception as e:
            logger.debug(f"[ThreatIntel] OTX hatası: {e}")
        return ips, domains, hashes

    # ── Main Refresh ───────────────────────────────────────────────────────

    def update_now(self) -> Dict:
        """
        Feed'leri şimdi çek ve IOC listesini güncelle.
        Sonuç istatistiklerini döndürür.
        """
        if not self.enabled:
            return {}

        t0 = time.time()
        logger.info("[ThreatIntel] Feed güncelleme başladı...")

        # Free feeds
        free_ips, free_domains = self._fetch_free_feeds()

        # OTX (key varsa)
        otx_ips, otx_domains, otx_hashes = self._fetch_otx()

        # Apply TTL and clear expired IOCs
        free_ips, free_domains, otx_hashes = self._apply_ioc_ttl(
            free_ips | otx_ips, free_domains | otx_domains, otx_hashes
        )
        # Merge
        all_ips     = free_ips
        all_domains = free_domains
        all_hashes  = otx_hashes

        if not all_ips and not all_domains and not all_hashes:
            logger.warning("[ThreatIntel] Hiçbir feed'den IOC alınamadı — mevcut liste korunuyor")
            return {"status": "no_data", "duration_sec": time.time() - t0}

        # Update
        self._feed_ips     = all_ips
        self._feed_domains = all_domains
        self._feed_hashes  = all_hashes
        self._last_update  = time.time()
        self._update_count += 1

        # Cache kaydet
        self._save_cache()

        # Rebuild the IOC list: static entries + feed entries
        self._rebuild_ioc_file()

        # Reload the detection engine without requiring a restart
        try:
            self._matcher.reload(str(self._ioc_file))
        except Exception as e:
            logger.error(f"[ThreatIntel] IOCMatcher reload hatası: {e}")

        duration = time.time() - t0
        stats = {
            "status":       "ok",
            "ips":          len(all_ips),
            "domains":      len(all_domains),
            "hashes":       len(all_hashes),
            "total":        len(all_ips) + len(all_domains) + len(all_hashes),
            "duration_sec": round(duration, 2),
            "otx_active":   bool(self._otx_key),
        }
        self._last_counts = stats
        logger.info(
            f"[ThreatIntel] Güncelleme tamamlandı: "
            f"{stats['total']} IOC "
            f"(IP:{stats['ips']}, domain:{stats['domains']}, hash:{stats['hashes']}) "
            f"— {duration:.1f}sn"
        )
        return stats

    def _rebuild_ioc_file(self):
        """
        Statik IOC'ler + feed IOC'lerini birleştirerek ioc_list.txt'yi yeniden yaz.
        Marker öncesindeki statik bölüm korunur, AUTO FEED sonrası rebuild edilebilir.
        """
        try:
            # Read the existing static lines
            static_lines = []
            feed_marker  = "# --- AUTO FEED ---"
            if self._ioc_file.exists():
                for line in self._ioc_file.read_text().splitlines():
                    if line.strip() == feed_marker:
                        break
                    static_lines.append(line)

            # Write the new file
            lines = static_lines[:]
            lines.append("")
            lines.append(feed_marker)
            lines.append(f"# Son güncelleme: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"# IP: {len(self._feed_ips)} | Domain: {len(self._feed_domains)} | Hash: {len(self._feed_hashes)}")
            lines.append("")

            # IP'leri yaz (limit: 50k)
            lines.append("# Bilinen kötü IP'ler (feed)")
            for ip in sorted(self._feed_ips)[:50000]:
                lines.append(ip)

            # Domain'leri yaz (limit: 20k)
            lines.append("")
            lines.append("# Bilinen kötü domain'ler (feed)")
            for d in sorted(self._feed_domains)[:20000]:
                lines.append(d)

            # Hash'leri yaz (limit: 10k)
            if self._feed_hashes:
                lines.append("")
                lines.append("# Bilinen kötü hash'ler (feed)")
                for h in sorted(self._feed_hashes)[:10000]:
                    lines.append(h)

            self._ioc_file.parent.mkdir(parents=True, exist_ok=True)
            self._ioc_file.write_text("\n".join(lines) + "\n")

        except Exception as e:
            logger.error(f"[ThreatIntel] IOC dosyası yazma hatası: {e}")

    # ── Background Thread ──────────────────────────────────────────────────────

    def start(self):
        """Start the periodic refresh thread."""
        if not self.enabled:
            return
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, daemon=True, name="AegisThreatIntel"
        )
        self._thread.start()
        logger.info(
            f"[ThreatIntel] Güncelleme servisi başlatıldı "
            f"(interval: {self.update_interval//3600}s)"
        )

    def stop(self):
        self._running = False

    def _loop(self):
        # Refresh immediately on first start if no cache exists
        # Cache varsa ve yeni ise bekle
        age = time.time() - self._last_update
        if age > self.update_interval:
            self.update_now()

        while self._running:
            time.sleep(60)  # Her dakika kontrol et
            if not self._running:
                break
            if time.time() - self._last_update >= self.update_interval:
                self.update_now()

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> Dict:
        age_hours = (time.time() - self._last_update) / 3600 if self._last_update else None
        return {
            "enabled":        self.enabled,
            "running":        self._running,
            "otx_active":     bool(self._otx_key),
            "update_count":   self._update_count,
            "last_update_ago_hours": round(age_hours, 1) if age_hours else None,
            "ioc_ttl_hours":  self.ioc_ttl_hours,
            "tracked_ioc_ages": len(self._ioc_first_seen),
            "stale_feeds":    list(self._stale_feeds),
            "stale_feed_count": len(self._stale_feeds),
            "ioc_counts": {
                "ips":     len(self._feed_ips),
                "domains": len(self._feed_domains),
                "hashes":  len(self._feed_hashes),
                "total":   len(self._feed_ips) + len(self._feed_domains) + len(self._feed_hashes),
            },
            "last_update_stats": self._last_counts,
        }
