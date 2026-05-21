**AegisCore**  
**AegisCore**, Linux sistemler için geliştirilen alpha aşamasındaki bir güvenlik izleme ve log analiz projesidir.  
Projenin ana odağı **kural tabanlı tespit** yapısıdır: Linux güvenlik loglarını okumak, olayları normalize etmek, kuralları uygulamak ve savunma amaçlı uyarılar üretmek. Projede ayrıca  **deneysel bir ML destek katmanı** bulunur. Bu ML tarafı, kullanıcıya/sisteme özel anomali analizi ve özel ML alarm aileleri üretme fikrini desteklemek için tasarlanmıştır. ML katmanı hâlâ test aşamasındadır; kural tabanlı motorun yerine geçmez ve otomatik yaptırım uygulamaz.  
*Durum: * ***Alpha / deneysel***  
 *  
 Kullanım amacı: savunma amaçlı izleme, eğitim, laboratuvar testi ve yetkili Linux log analizi.*  
AegisCore saldırı yapmak veya yetkisiz sistemleri izlemek için kullanılmamalıdır.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNBCUrfDqrYGVDAgAU2QtIq6DIzW7UHAMBfHGt1V+fXEwAAXrseHCQGBEuErVgAAAAASUVORK5CYII=)  
**AegisCore Ne Yapar?**  
AegisCore aşağıdaki türde güvenlik aktivitelerini analiz etmeyi hedefler:  
- SSH brute-force denemeleri ve invalid-user enumeration  
- Şüpheli kimlik doğrulama aktiviteleri  
- SQL injection, XSS, path traversal ve webshell benzeri web istekleri  
- PostgreSQL girişleri ve şüpheli database davranışları  
- Firewall flush, disable, broad allow veya policy değişikliği gibi müdahaleler  
- DGA benzeri veya yüksek entropili DNS sorguları  
- Process, package, service, auditd, log ve persistence ilişkili davranışlar  
- Deneysel ML akışları için rule-backed label candidate ve readiness bilgileri  
Proje CLI-first tasarlanmıştır. Yerel operatör kullanımı için opsiyonel masaüstü UI da bulunur.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OsQ1AABRAwSdRaPXGMOCv7WkPK+hEcjfBLTNzVFcAAPzFvVZbdX49AQDgtf0BSpoDXv5TGXgAAAAASUVORK5CYII=)  
**Mevcut Proje Durumu**  
AegisCore hâlâ test ve refactor aşamasındadır.  
Daha stabil olan ana odaklar:  
- Kural tabanlı detection  
- Log normalizasyonu  
- Alert üretimi  
- Güvenli/manual response akışları  
- CLI diagnostic ve validation komutları  
- PostgreSQL tabanlı saklama  
- Modüler runtime ve ML helper mimarisi  
Deneysel odaklar:  
- ML readiness takibi  
- Rule-backed label candidate üretimi  
- Kullanıcıya/sisteme özel anomali odaklı alarm aileleri  
- Advisory ML scoring ve reporting  
- Güvenli dry-run historical label akışları  
ML çıktıları destekleyici sinyal olarak değerlendirilmelidir. Otomatik karar mekanizması değildir.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSPBCUZfEnoYmFDBhAU2QtIq6DIzW7UHAMBfnGt1V8fXEwAAXrse/wcF74lXkIsAAAAASUVORK5CYII=)  
**Güvenlik Modeli**  
AegisCore bilinçli olarak korumacı davranır.  
Önemli güvenlik kuralları:  
- IP blocking otomatik değildir.  
- Firewall işlemleri guarded/manual akış gerektirir.  
- ML, kural tabanlı tespit kararlarını override etmez.  
- Active ML decision layer varsayılan olarak kapalıdır.  
- ML çıktısı advisory ve deneysel kabul edilmelidir.  
- Yıkıcı işlemler confirmation, audit veya dry-run kontrolleriyle korunmalıdır.  
- Secret dosyaları, gerçek loglar, runtime state, model dosyaları ve database dump dosyaları commit edilmemelidir.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsaeILbwZ9Fewo0Gs4E2ELcGWmTmqKwAA/uLeqr06v54AAPDa+gAthwNEfGhnhAAAAABJRU5ErkJggg==)  
**Desteklenen Linux Aileleri**  
| | |  
|-|-|  
| **Dağıtım Ailesi** | **Örnekler** |   
| Debian ailesi | Debian, Ubuntu |   
| RHEL ailesi | RHEL, Rocky Linux, Fedora |   
| SUSE ailesi | openSUSE, SUSE |   
   
AegisCore dağıtım ailesine göre log yolu, parser davranışı ve source ayarlarını uyarlamaya çalışır. Gerçek log yolları sistem yapılandırmasına göre değişebilir.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSd49m4v6wg/pwmMYQVvImwJtszMXp0BAPAX91pt1fH1BACA164Hoq8EQMMPmF8AAAAASUVORK5CYII=)  
**Ana Özellikler**  
- Linux loglarını okuma ve normalize etme  
- Kural tabanlı detection engine  
- Threshold ve correlation desteği  
- Alert ve incident odaklı akışlar  
- PostgreSQL persistence  
- Manuel IP block / unblock candidate akışları  
- Opsiyonel AbuseIPDB ve OTX enrichment  
- Opsiyonel LLM destekli alert açıklaması  
- Opsiyonel masaüstü operatör UI  
- ML label readiness ve phase takibi  
- Deneysel kullanıcı/sistem özel anomali alarm ailesi desteği  
- Güvenli dry-run historical label candidate üretimi  
- Report ve diagnostic komutları  
- Secret redaction ve guarded security kontrolleri  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSfYxKK/kYXEkyk8WcGbCFuCLTOzVXsAAPzFuVZ3dXw9AQDgtesB/v8F8JQadPwAAAAASUVORK5CYII=)  
**Proje Yapısı**  
Güncel refactor sonrası yapı modülerdir:  
AegisCore/  
 ├── main.py                    # CLI entrypoint ve compatibility yüzeyi  
 ├── app/  
 │   ├── bootstrap.py  
 │   ├── configuration.py  
 │   ├── database_bootstrap.py  
 │   ├── startup.py  
 │   ├── alert_explanations.py  
 │   ├── runtime/               # SIEMPipeline runtime implementasyonu ve mixinler  
 │   └── ml/                    # ML reporting, readiness, labels, training helperları  
 ├── cli/  
 │   ├── parser.py  
 │   ├── dispatcher.py  
 │   └── commands/  
 ├── core/  
 ├── ui/  
 ├── rules/  
 ├── scripts/  
 ├── packaging/  
 ├── config/  
 ├── data/labels/  
 ├── tests/  
 ├── requirements.txt  
 ├── pytest.ini  
 └── VERSION  
   
main.py artık ana implementasyon dosyası değildir. Runtime, ML, CLI, startup, diagnostic ve explanation mantığının büyük kısmı app/, app/ml/, app/runtime/ ve cli/ altına taşınmıştır.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OQQmAABRAsSfYxZo/jVEMYQLPJrCCNxG2BFtmZquOAAD4i3Ot7mr/egIAwGvXA4rLBc059ysnAAAAAElFTkSuQmCC)  
**Gereksinimler**  
Temel gereksinimler:  
- Desteklenen Linux dağıtım ailelerinden biri  
- Python 3.8+  
- PostgreSQL  
- pip ve Python sanal ortam desteği  
- İlgili sistem loglarını okuma izni  
- Opsiyonel UI için PySide6  
- Opsiyonel entegrasyonlar için API keyler  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBCUpfDq4wwIAABiywEZJWQZeZ2ao9AAD+4liruzq/ngAA8Nr1ABweBgdur/QFAAAAAElFTkSuQmCC)  
**Hızlı Kurulum**  
**1. Sanal ortam oluştur ve bağımlılıkları kur**  
python3 -m venv .venv  
 .venv/bin/python -m pip install --upgrade pip  
 .venv/bin/python -m pip install -r requirements.txt  
   
**2. PostgreSQL hazırla**  
PostgreSQL kullanıcı ve database oluştur:  
sudo -u postgres createuser --pwprompt aegiscore  
 sudo -u postgres createdb --owner=aegiscore aegiscore  
   
Bağlantıyı test et:  
psql "postgresql://aegiscore:YOUR_PASSWORD@localhost:5432/aegiscore" -c "select 1;"  
   
**3. Environment dosyasını hazırla**  
Güvenli örnek dosyayı kopyala:  
cp config/example.env .env  
   
.env içeriğini düzenle:  
DATABASE_URL=postgresql://aegiscore:YOUR_PASSWORD@localhost:5432/aegiscore  
   
Opsiyonel entegrasyon secretları için:  
cp config/integrations.example.env config/integrations.env  
   
.env ve config/integrations.env commit edilmemelidir.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSPBCUbfEm6YmFDBhAU2QtIq6DIzW7UHAMBfnGt1V8fXEwAAXrse/w8F7pbTa1oAAAAASUVORK5CYII=)  
**Temel Doğrulama**  
Kuralları doğrula:  
.venv/bin/python main.py --validate-rules  
   
Yardımı göster:  
.venv/bin/python main.py --help  
   
Versiyonu göster:  
.venv/bin/python main.py --version  
   
Smoke test çalıştır:  
.venv/bin/python main.py --smoke-test  
   
Durum ve ML özetini kontrol et:  
.venv/bin/python main.py --status  
 .venv/bin/python main.py --phase  
 .venv/bin/python main.py --ml-summary  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhZscZXlheJwqQgQU2QtIq6DIze3UGAMBf3Gu1VcfXEwAAXrseop8EQrmJduIAAAAASUVORK5CYII=)  
**Backend Çalıştırma**  
Manuel backend çalıştırma:  
sudo -E .venv/bin/python main.py  
   
Belirli config dosyasıyla çalıştırma:  
sudo -E .venv/bin/python main.py --config config/config.yml  
   
/var/log/* altındaki logları okumak için çoğu sistemde sudo gerekebilir. DATABASE_URL environment üzerinden veriliyorsa sudo -E önemlidir.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBCkLfFDZwwIgHRiywEZJWQZeZ2ao9AAD+4lyruzq+ngAA8Nr1AOH0BedHjjlfAAAAAElFTkSuQmCC)  
**Opsiyonel Masaüstü UI**  
Masaüstü UI opsiyoneldir ve yerel operatör görünürlüğü için tasarlanmıştır.  
PySide6 kontrol/kurulum:  
.venv/bin/python -m pip show PySide6  
 .venv/bin/python -m pip install PySide6  
   
UI başlatma:  
.venv/bin/python -m ui.app  
   
UI açılır ama veri görünmezse backend ve UI’ın aynı database/config kullandığını kontrol et.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAM0lEQVR4nO3OUQmAQBBAwSdcjsu6HYxoDsEK/okwk2COmdnVGQAAf3GtalX76wkAAK/dDxFWBDkFf6+SAAAAAElFTkSuQmCC)  
**Faydalı Komutlar**  
**Rule ve Sağlık Kontrolleri**  
.venv/bin/python main.py --validate-rules  
 .venv/bin/python main.py --smoke-test  
 .venv/bin/python main.py --status  
 .venv/bin/python main.py --phase  
 .venv/bin/python main.py --ml-summary  
   
**Database Kontrolleri**  
.venv/bin/python main.py --db-version  
 .venv/bin/python main.py --db-pending  
 .venv/bin/python main.py --db-doctor  
   
**Historical Label / ML Readiness Akışları**  
.venv/bin/python main.py --ml-historical-scan-plan  
 .venv/bin/python main.py --bootstrap-label-scan --dry-run  
 .venv/bin/python main.py --ml-readiness  
 .venv/bin/python main.py --ml-summary  
   
Bu komutlar güvenli inceleme ve dry-run akışları içindir. Active ML kararlarını veya otomatik response işlemlerini kendiliğinden açmaz.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSfYxKK/kYXEkyk8WcGbCFuCLTOzVXsAAPzFuVZ3dXw9AQDgtesB/v8F8JQadPwAAAAASUVORK5CYII=)  
**ML Katmanı**  
AegisCore deneysel bir ML destek katmanı içerir. Amaç deterministik kuralların yerine geçmek değildir. ML tarafı şunları desteklemek için tasarlanmıştır:  
- rule-backed label hazırlığı  
- readiness ve phase takibi  
- historical dry-run label candidate üretimi  
- özel anomali odaklı alarm ailesi denemeleri  
- kullanıcıya/sisteme özel davranış analizi desteği  
Varsayılan güvenli beklentiler:  
- ML advisory çalışır.  
- ML otomatik IP block yapmaz.  
- ML rule-based alertleri override etmez.  
- Active ML behavior açıkça yapılandırılıp doğrulanmadan kapalı kalmalıdır.  
- Training yalnız readiness, metadata ve safety gate koşulları sağlandığında değerlendirilmelidir.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhwgJOUPcjIpnRgQU2QtIq6DIze3UGAMBf3Gu1VcfXEwAAXrseaJEEL8XMiYMAAAAASUVORK5CYII=)  
**Log Kaynakları**  
AegisCore dağıtım ve yapılandırmaya göre farklı log kaynaklarını okuyabilir.  
Yaygın kaynaklar:  
| | |  
|-|-|  
| **Kaynak** | **Yaygın Yollar** |   
| Auth / SSH | /var/log/auth.log, /var/log/secure, journald |   
| Syslog / Messages | /var/log/syslog, /var/log/messages |   
| Audit | /var/log/audit/audit.log |   
| PostgreSQL | /var/log/postgresql, /var/lib/pgsql/data/log |   
| Web | /var/log/nginx, /var/log/apache2, /var/log/httpd |   
   
Sisteminde farklı yollar kullanılıyorsa config/config.yml güncellenmelidir.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OQQmAABRAsSeYxZw/lVeDGMACBrCCNxG2BFtmZquOAAD4i3Ot7mr/egIAwGvXA6fOBdd+dKAKAAAAAElFTkSuQmCC)  
**Opsiyonel Entegrasyonlar**  
Opsiyonel entegrasyonlar local olarak ayarlanır ve commit edilmemelidir:  
ABUSEIPDB_API_KEY=put_your_abuseipdb_api_key_here  
 OTX_API_KEY=put_your_otx_api_key_here  
 GEMINI_API_KEY=put_your_gemini_api_key_here  
 OPENAI_API_KEY=put_your_openai_api_key_here  
 ANTHROPIC_API_KEY=put_your_anthropic_api_key_here  
   
LLM açıklamaları ve enrichment kaynakları sadece operatöre yardımcı olmak içindir. Otomatik güvenlik aksiyonu tetiklememelidir.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsSdYxKa/i8WMIR7ECt5E2BJsmZmt2gMA4C+Otbqr8+sJAACvXQ85PAYartXEogAAAABJRU5ErkJggg==)  
**Test**  
Hedefli doğrulama:  
.venv/bin/python -m py_compile main.py app/*.py app/ml/*.py app/runtime/*.py cli/parser.py cli/dispatcher.py cli/commands/*.py  
 .venv/bin/python -m pytest tests/unit -q  
   
UI testleri PySide6 gerektirir:  
.venv/bin/python -m pytest tests/ui -q  
   
PySide6 kurulu değilse backend testleri sağlıklı olsa bile UI test collection aşamasında hata verebilir.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhwgJuUPYDMpnRgQU2QtIq6DIze3UGAMBf3Gu1VcfXEwAAXrseaHEEM+cJoFcAAAAASUVORK5CYII=)  
**Paketleme / Release Hijyeni**  
Public paket sadece kaynak kod ve güvenli örnek dosyaları içermelidir.  
Güvenli örnekler:  
config/example.env  
 config/integrations.example.env  
 data/labels/  
   
Dahil edilmemesi gerekenler:  
.env  
 .env.*  
 config/integrations.env  
 data/*.log  
 data/models/  
 data/runtime_state*  
 data/exports/  
 data/diagnostic_bundles/  
 data/bootstrap_label_scan/  
 .venv/  
 venv/  
 __pycache__/  
 .pytest_cache/  
 dist/  
 release_staging/  
 temp_verify/  
 *.sqlite  
 *.db  
 *.dump  
 *.sql  
 *.pem  
 *.key  
 *.crt  
   
Paketleme sürecinde app/runtime/ klasörünün dahil edildiği doğrulanmalıdır; bu klasör runtime artifact değil, kaynak koddur.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAUBBAwSd8bOHVnBvBkAaxgjcRZhLMNjNHdQUAwF/cq9qr8+sJAACvrQctgQNH4A++9QAAAABJRU5ErkJggg==)  
**Geliştirme Notu**  
AegisCore bir üniversite bitirme projesi olarak, AI-assisted coding desteğiyle geliştirilmiştir. AI araçları çoğunlukla implementasyon ve refactor hızını artırmak için kullanılmıştır. Proje yönü, mimari kararlar, güvenlik sınırları, çıktıların kabul/red kararları ve test öncelikleri geliştirici tarafından belirlenmiştir.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQmAABRAsSd4NIGJjPWxpgGsYQVvImwJtszMXp0BAPAX91pt1fH1BACA164HhZwEOFrXVOsAAAAASUVORK5CYII=)  
**Kullanım Amacı**  
AegisCore şu amaçlarla tasarlanmıştır:  
- savunma amaçlı izleme  
- eğitim  
- kontrollü laboratuvar testi  
- kurum içi güvenlik araştırması  
- yetkili Linux log analizi  
Yalnızca sahibi olduğun veya izleme yetkin bulunan sistemlerde kullanılmalıdır.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OQQmAABRAsSeYxZw/lieLGMACBrCCNxG2BFtmZquOAAD4i3Ot7mr/egIAwGvXA6fGBdgoVMwYAAAAAElFTkSuQmCC)  
**Lisans**  
**## Lisans**  
   
**Bu proje **Apache License 2.0** lisansı ile yayımlanmaktadır.**  
   
**Detaylar için proje kök dizinindeki [`LICENSE`](LICENSE) dosyasına bakabilirsiniz.**  
