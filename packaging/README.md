# Packaging Plan

Bu dizin production-ready paketleme kaniti degil, sadece scaffold/placeholder
paketleme iskeletidir. Buradaki dosyalar tek basina desteklenen release artefakti
veya tamamlanmis install/upgrade/uninstall akisi olarak yorumlanmamalidir.

Bu dizin `.deb` ve `.rpm` paketleme icin temel iskeleti tutar.

## Hedefler

1. Tek servis adi: `aegiscore`
2. Ortak env dosyasi: `/etc/default/aegiscore`
3. Ortak servis dosyasi: `/etc/systemd/system/aegiscore.service`
4. Uygulama kok dizini: `/opt/aegiscore`

## Debian plan

1. Debian metadata dosyasi paketleme agaci icinde tek kaynak olacak.
2. `postinst` script'i service file kopyalama, `daemon-reload`, `enable` ve opsiyonel bootstrap yapacak.
3. `prerm` script'i stop/disable islemlerini yapacak.
4. Paket icine `opt/aegiscore`, `etc/default/aegiscore`, `lib/systemd/system/aegiscore.service` alinacak.

## RPM plan

1. `packaging/rpm/aegiscore.spec` tek spec kaynagi olacak.
2. `%post` icinde systemd reload/enable akisi olacak.
3. `%preun` ve `%postun` icinde stop/disable/reload akislari olacak.
4. Paket icine `opt/aegiscore`, `etc/default/aegiscore`, systemd service alinacak.

## Sonraki faz

Asagidaki maddeler henuz tamamlanmamis paketleme backlog'unu tarif eder.
Production paket cikisi icin smoke test ve servis yasam dongusu dogrulamalari
ayrica tamamlanmalidir.

1. Staging dizini ureten build script ekle.
2. `.deb` icin `dpkg-deb --build` akisini bagla.
3. `.rpm` icin `rpmbuild` staging akisini bagla.
4. Paket smoke test: install -> doctor -> smoke-test -> uninstall.
