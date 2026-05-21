from __future__ import annotations

import argparse


def build_parser(version: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegiscore",
        description=(
            f"{version}\n"
            "Adaptive Linux Threat Intelligence Platform\n"
            "─────────────────────────────────────────────\n"
            "Kural motoru + Instant ML + Baseline + Advanced ML\n"
            "PHASE_0 → PHASE_1 → PHASE_2 → PHASE_3 otomatik geçiş"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Örnekler:\n"
            "  aegiscore                        # Normal başlatma\n"
            "  aegiscore --config /etc/aegiscore/config.yml\n"
            "  aegiscore --status               # Faz ve sistem durumu\n"
            "  aegiscore --phase                # Faz ilerleme detayı\n"
            "  aegiscore --report               # HTML rapor üret\n"
            "  aegiscore --validate-rules       # Kural dosyalarını doğrula\n"
            "  aegiscore --doctor               # Operasyonel hazırlık kontrolü\n"
            "  aegiscore --smoke-test           # Küçük runtime sağlık testi\n"
            "  aegiscore --bootstrap-label-scan --dry-run\n"
            "  aegiscore --bootstrap-label-scan --dry-run\n"
            "  aegiscore --db-doctor            # DB sağlık ve migration görünümü\n"
            "  aegiscore --db-version           # DB schema versiyonu\n"
            "  aegiscore --db-pending           # Bekleyen schema versiyonları\n"
            "  aegiscore --explain-alert 123    # Tek bir alert için LLM açıklaması\n"
            "  aegiscore --test                 # Pipeline testi\n"
        ),
    )
    parser.add_argument("--config",    default="config/config.yml",
                        metavar="PATH", help="Config dosyası (varsayılan: config/config.yml)")
    parser.add_argument("--test",      action="store_true",
                        help="Pipeline testi çalıştır ve çık")
    parser.add_argument("--status",    action="store_true",
                        help="Sistem durumu ve faz bilgisi göster")
    parser.add_argument("--phase",     action="store_true",
                        help="Faz ilerleme detayını göster")
    parser.add_argument("--metrics",   action="store_true",
                        help="Detection metrikleri göster")
    parser.add_argument("--report",    action="store_true",
                        help="HTML rapor üret")
    parser.add_argument("--validate-rules", action="store_true",
                        help="YAML kural dosyalarını doğrula")
    parser.add_argument("--doctor", action="store_true",
                        help="Operasyonel hazırlık kontrolünü çalıştır ve çık")
    parser.add_argument("--smoke-test", action="store_true",
                        help="Küçük runtime smoke test çalıştır ve çık")
    parser.add_argument("--diagnose-parse-fail", action="store_true",
                        help="Read-only parse fail breakdown çıktısı üretir; source/parser/reason/path/sample seviyesinde sanitize edilmiş teşhis verir")
    parser.add_argument("--diagnose-event-growth", action="store_true",
                        help="Read-only phase counter vs live runtime event growth teşhisi üretir; duplicate/parse fail/source dağılımlarını ayırır")
    parser.add_argument("--bootstrap-label-scan", action="store_true",
                        help="Read-only maintenance label scan; normal runtime pipeline bunu otomatik çalıştırmaz")
    parser.add_argument("--dry-run", action="store_true",
                        help="Seçilen maintenance/audit komutunu DB write yapmadan çalıştır; yalnız lokal audit artifact üretebilir")
    parser.add_argument("--apply", action="store_true",
                        help="Seçilen maintenance backfill/repair komutunu açıkça uygular; --apply olmadan DB write yapılmaz")
    parser.add_argument("--db-doctor", action="store_true",
                        help="DB sağlık ve migration durumunu göster")
    parser.add_argument("--db-version", action="store_true",
                        help="DB schema versiyonunu göster")
    parser.add_argument("--db-pending", action="store_true",
                        help="Bekleyen DB schema versiyonlarını göster")
    parser.add_argument("--explain-alert", type=int, default=None, metavar="ALERT_ID",
                        help="Belirtilen alert için read-only LLM açıklaması üret")
    parser.add_argument("--alert-explanation-contract-audit", action="store_true",
                        help="Read-only rule-based ve ML-based alert explanation metadata contract örneklerini bas; DB write veya alert emit yapmaz")
    parser.add_argument("--list-ip-block-suggestions", action="store_true",
                        help="Bekleyen manuel IP block suggestion kayıtlarını listele")
    parser.add_argument("--block-ip", default="", metavar="IP",
                        help="Belirtilen IP için manuel block işlemi başlat")
    parser.add_argument("--unblock-ip", default="", metavar="IP",
                        help="Daha önce uygulanmış IP block kaydını kaldır")
    parser.add_argument("--block-suggestion-id", type=int, default=None, metavar="ID",
                        help="Bekleyen suggestion id üzerinden manuel IP block uygula")
    parser.add_argument("--preflight", action="store_true",
                        help="Sistem hazırlık kontrolünü çalıştır ve çık")
    parser.add_argument("--allow-empty-rules", action="store_true",
                        help="Kural yoksa bile başlat (debug modu)")
    parser.add_argument("--source",    default=None, metavar="NAME",
                        help="Tek log kaynağı belirt")
    parser.add_argument("--log-level", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Log seviyesi (varsayılan: WARNING)")
    parser.add_argument("--version",   action="version", version=version)
    parser.add_argument("--hunt",      default=None, metavar="SENARYO",
                        help=f"Threat hunt calistir. Senaryolar: rare_processes, beacon_detection, lateral_movement, credential_access, persistence, after_hours, data_exfil, new_users, suspicious_ports, log_tampering, ALL")
    parser.add_argument("--hunt-days", default=7, type=float, metavar="N",
                        help="Hunt icin kac gunluk veri taransın (varsayilan: 7)")
    parser.add_argument("--hunt-user", default="", metavar="USER",
                        help="Hunt sorgusunu belirli bir kullaniciya filtrele")
    parser.add_argument("--pack-status", action="store_true",
                        help="Rule pack durumunu ve MITRE coverage'ini goster")
    parser.add_argument("--ml-pause",   action="store_true",
                        help="ML eğitimini manuel dondur")
    parser.add_argument("--ml-resume",  action="store_true",
                        help="ML eğitimini devam ettir")
    parser.add_argument("--ml-reset",   action="store_true",
                        help="ML baseline ve modelleri sıfırla")
    parser.add_argument("--ml-status",  action="store_true",
                        help="ML kontrol durumunu göster")
    parser.add_argument("--ml-readiness", "--ml-readiness-report", dest="ml_readiness", action="store_true",
                        help="Read-only ML readiness / data-quality audit raporu üret; runtime detection davranışını değiştirmez")
    parser.add_argument("--ml-family-readiness", default="", metavar="FAMILY_ID",
                        help="Read-only tek ML family readiness evaluator çıktısı üret; DB write, scoring veya alert emit yapmaz")
    parser.add_argument("--ml-support-score-family", default="", metavar="FAMILY_ID",
                        help="Read-only tek ML family için audit-only support score çıktısı üret; alert emit, risk değişikliği veya DB write yapmaz")
    parser.add_argument("--ml-active-emit-dry-run", default="", metavar="FAMILY_ID",
                        help="Read-only tek ML family için active emit candidate dry-run çıktısı üret; active config simülasyonu yapar ama DB write veya alert emit yapmaz")
    parser.add_argument("--ml-mapping-audit", "--ml-family-map-audit", dest="ml_mapping_audit", action="store_true",
                        help="Read-only ML rule mapping coverage audit raporu üret; DB write ve alert üretimi yapmaz")
    parser.add_argument("--ml-runtime-label-candidate-audit", default="", metavar="RULE_ID",
                        help="Read-only runtime rule hit -> ML label candidate audit çıktısı üret; DB write, label insert ve risk değişikliği yapmaz")
    parser.add_argument("--ml-historical-scan-plan", "--ml-label-scan-plan", dest="ml_historical_scan_plan", action="store_true",
                        help="Read-only per-family historical label scan threshold planı üret; label yazmaz, runtime değişikliği yapmaz")
    parser.add_argument("--ml-normal-label-plan", "--ml-clean-window-plan", dest="ml_normal_label_plan", action="store_true",
                        help="Read-only clean-window normal label aday planı üret; label yazmaz, runtime davranışını değiştirmez")
    parser.add_argument("--ml-label-trust-audit", "--ml-poisoning-audit", dest="ml_label_trust_audit", action="store_true",
                        help="Read-only label trust-tier ve poisoning guard audit raporu üret; DB write yapmaz")
    parser.add_argument("--ml-label-metadata-plan", "--ml-label-backfill-plan", dest="ml_label_metadata_plan", action="store_true",
                        help="Read-only legacy/bootstrap label metadata backfill planı üret; label update veya runtime değişikliği yapmaz")
    parser.add_argument("--ml-backfill-legacy-bootstrap-metadata", action="store_true",
                        help="Legacy bootstrap_historical labels için explicit rejected metadata backfill dry-run/apply komutu; training başlatmaz")
    parser.add_argument("--ml-label-extraction-audit", "--ml-label-metadata-audit", dest="ml_label_extraction_audit", action="store_true",
                        help="Read-only existing label metadata extraction audit raporu üret; DB write ve label update yapmaz")
    parser.add_argument("--ml-summary", "--ml-readiness-summary", dest="ml_summary", action="store_true",
                        help="Read-only unified ML readiness summary üret; mevcut audit helper'larını özetler, DB write yapmaz")
    parser.add_argument("--ml-train-scheduler-dry-run", action="store_true",
                        help="Read-only weekly/new-label-threshold ML training scheduler contract çıktısı üretir; training başlatmaz, DB write yapmaz, active ML açmaz")
    parser.add_argument("--ml-training-status", action="store_true",
                        help="Read-only training mode/status çıktısı üretir; manual/scheduled/threshold/disabled policy ve eligibility durumunu gösterir")
    parser.add_argument("--ml-train-now-dry-run", action="store_true",
                        help="Read-only future manual Train Models aksiyonu için on-demand training dry-run eligibility çıktısı üretir; gerçek training başlatmaz")
    parser.add_argument("--ml-train-now", action="store_true",
                        help="Manual execute training başlatır; evaluation pass olursa modeli promote eder, fail olursa mevcut modeli korur")
    parser.add_argument("--ml-model-status", action="store_true",
                        help="Read-only promoted model metadata/load/scoring status çıktısı üretir; scoring dışında runtime davranışını değiştirmez")
    parser.add_argument("--ml-config-audit", action="store_true",
                        help="Read-only ML config/schema contract audit raporu üret; active ML açmaz, DB write yapmaz")
    parser.add_argument("--ml-label-contract-audit", action="store_true",
                        help="Read-only future ML label write metadata contract audit raporu üret; DB write yapmaz")
    parser.add_argument("--ml-verified-manifest-dry-run", action="store_true",
                        help="Read-only live DB events_recent+alerts snapshot'ından ML-AUTH/ML-PROC/ML-IMPACT verified label manifest dry-run üretir; label write veya active ML yapmaz")
    parser.add_argument("--ml-verified-manifest-out", default="", metavar="PATH",
                        help="Verified manifest dry-run çıktısını workspace içindeki güvenli bir JSON dosyasına yazar; varsayılan olarak dosya yazmaz")
    parser.add_argument("--ml-verified-manifest-limit", default=5000, type=int, metavar="N",
                        help="Verified manifest dry-run için events/alerts snapshot limiti (default=5000)")
    parser.add_argument("--ml-verified-manifest-family", action="append", default=[], metavar="FAMILY_ID",
                        help="Verified manifest dry-run için hedef family filtresi (ML-AUTH, ML-PROC, ML-IMPACT). Birden çok kez veya virgülle kullanılabilir")
    parser.add_argument("--ml-verified-manifest-audit", default="", metavar="PATH",
                        help="Read-only verified manifest JSON kalite audit çıktısı üretir; DB write veya active ML yapmaz")
    parser.add_argument("--ml-exclude", default=None, metavar="SOURCE",
                        help="Belirtilen kaynağı ML eğitiminden çıkar (örn: auditd)")
    parser.add_argument("--ml-include", default=None, metavar="SOURCE",
                        help="Daha önce çıkarılmış kaynağı ML eğitimine geri ekle")
    parser.add_argument("--maintenance-mode", action="store_true",
                        help="ML öğrenmesini bakım modunda dondur (sistem güncellemesi vb.)")
    parser.add_argument("--pentest-mode", action="store_true",
                        help="ML öğrenmesini pentest modunda dondur (test trafik baseline'ı kirletmesin)")
    parser.add_argument("--maintenance-off", action="store_true",
                        help="Bakım/pentest modunu kapat, ML öğrenmesini devam ettir")
    parser.add_argument("--maintenance-reason", default="", metavar="REASON",
                        help="Bakım modunu açma nedeni (opsiyonel açıklama)")
    parser.add_argument("--maintenance-timeout", default=8, type=float, metavar="HOURS",
                        help="Bakım modu otomatik kapanma süresi (saat, default=8, 0=kapatma yok)")
    return parser
