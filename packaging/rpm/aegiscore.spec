Name:           aegiscore
Version:        16.0.0
Release:        1%{?dist}
Summary:        Adaptive Linux Threat Intelligence Platform
License:        Proprietary
BuildArch:      noarch
Requires:       python3
Requires:       postgresql

%description
Scaffold RPM spec only. This file is a packaging placeholder and does not by
itself represent a production-ready, validated RPM delivery path.

PostgreSQL-backed Linux SIEM pipeline with detection, baseline, and ML phases.

%prep

%build

%install
# Scaffold only: build/staging payload burada henuz tamamlanmadi.

%post
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

%preun
if [ $1 -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now aegiscore >/dev/null 2>&1 || true
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

%files
# Scaffold only: gercek payload listesi ve install ownership sonraki fazda eklenecek.
