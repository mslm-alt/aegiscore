#!/usr/bin/env bash
# scripts/uninstall.sh
# AegisCore uninstall helper

set -euo pipefail

SIEM_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_FILE="/etc/systemd/system/aegiscore.service"
ENV_FILE="/etc/default/aegiscore"
PURGE_VENV=0
PURGE_DATA=0

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}[OK]${NC}   $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; exit 1; }

usage() {
    cat <<EOF
Kullanim:
  bash scripts/uninstall.sh [--purge-venv] [--purge-data]

Varsayilan davranis:
  - systemd servis dosyasini ve /etc/default/aegiscore env dosyasini kaldirir
  - proje dizinindeki .venv ve data/ klasorlerini KORUR

Opsiyonlar:
  --purge-venv   .venv klasorunu da sil
  --purge-data   data/ klasorunu da sil
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --purge-venv) PURGE_VENV=1 ;;
        --purge-data) PURGE_DATA=1 ;;
        -h|--help|help)
            usage
            exit 0
            ;;
        *)
            fail "Gecersiz arguman: $1"
            ;;
    esac
    shift
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AegisCore — Uninstall"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ "$EUID" -eq 0 ]; then
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files | grep -q '^aegiscore\.service'; then
            systemctl disable --now aegiscore >/dev/null 2>&1 || warn "aegiscore service durdurulamadı"
            ok "aegiscore service devre dışı bırakıldı"
        else
            ok "aegiscore service kayıtlı değil"
        fi
    else
        warn "systemctl yok — service yönetimi atlandı"
    fi

    if [ -f "$SERVICE_FILE" ]; then
        rm -f "$SERVICE_FILE"
        ok "Service dosyası kaldırıldı: $SERVICE_FILE"
        command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true
    else
        ok "Service dosyası yok: $SERVICE_FILE"
    fi

    if [ -f "$ENV_FILE" ]; then
        rm -f "$ENV_FILE"
        ok "Env dosyası kaldırıldı: $ENV_FILE"
    else
        ok "Env dosyası yok: $ENV_FILE"
    fi
else
    warn "Root değil — /etc/systemd/system ve /etc/default temizliği atlandı"
fi

if [ "$PURGE_VENV" -eq 1 ]; then
    if [ -d "$SIEM_DIR/.venv" ]; then
        rm -rf "$SIEM_DIR/.venv"
        ok ".venv kaldırıldı"
    else
        ok ".venv yok"
    fi
else
    warn ".venv korundu (silmek için: --purge-venv)"
fi

if [ "$PURGE_DATA" -eq 1 ]; then
    if [ -d "$SIEM_DIR/data" ]; then
        rm -rf "$SIEM_DIR/data"
        ok "data/ kaldırıldı"
    else
        ok "data/ yok"
    fi
else
    warn "data/ korundu (silmek için: --purge-data)"
fi

echo ""
echo "Uninstall tamamlandı."
