#!/usr/bin/env bash
# scripts/install.sh
# AegisCore — Cross-Distro Kurulum Scripti
# Desteklenen: Ubuntu/Debian, RHEL/CentOS/Rocky/AlmaLinux/Fedora, SUSE/openSUSE
#
# Kullanım:
#   sudo bash scripts/install.sh
#   sudo bash scripts/install.sh install
#   sudo bash scripts/install.sh upgrade

set -euo pipefail

SIEM_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$SIEM_DIR/.venv"
ACTION="${1:-install}"
EXAMPLE_ENV="$SIEM_DIR/config/example.env"
SYSTEMD_ENV_FILE="/etc/default/aegiscore"
LOCAL_ENV_FILE="$SIEM_DIR/data/aegiscore.env"
SERVICE_USER="siem"
SERVICE_GROUP="siem"
RUN_SMOKE_AFTER_INSTALL="${AEGISCORE_RUN_SMOKE_AFTER_INSTALL:-0}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'

ok()   { echo -e "  ${GREEN}[OK]${NC}   $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; exit 1; }

detect_pypi_reachability() {
    python3 - <<'PY'
import socket
try:
    sock = socket.create_connection(("pypi.org", 443), timeout=2)
    sock.close()
    raise SystemExit(0)
except OSError:
    raise SystemExit(1)
PY
}

python_deps_ready() {
    "$VENV/bin/python" - <<'PY'
mods = ["yaml", "numpy", "sklearn", "joblib", "psycopg2"]
for mod in mods:
    __import__(mod)
PY
}

ensure_service_account() {
    if [ "$EUID" -ne 0 ]; then
        warn "Root değil — service user oluşturma atlandı"
        return 0
    fi
    if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        groupadd --system "$SERVICE_GROUP"
        ok "Service group oluşturuldu: $SERVICE_GROUP"
    else
        ok "Service group mevcut: $SERVICE_GROUP"
    fi
    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        useradd --system --gid "$SERVICE_GROUP" \
            --home-dir "$SIEM_DIR" --shell /usr/sbin/nologin \
            --comment "AegisCore service user" "$SERVICE_USER"
        ok "Service user oluşturuldu: $SERVICE_USER"
    else
        ok "Service user mevcut: $SERVICE_USER"
    fi
    for extra_group in adm systemd-journal; do
        if getent group "$extra_group" >/dev/null 2>&1; then
            usermod -a -G "$extra_group" "$SERVICE_USER" || true
        fi
    done
}

usage() {
    cat <<EOF
Kullanim:
  bash scripts/install.sh [install|upgrade]

Komutlar:
  install   Varsayilan kurulum akisi
  upgrade   Mevcut kurulumda bagimliliklari ve dogrulamalari gunceller
EOF
}

case "$ACTION" in
    install|upgrade) ;;
    -h|--help|help)
        usage
        exit 0
        ;;
    *)
        fail "Gecersiz komut: $ACTION (beklenen: install veya upgrade)"
        ;;
esac

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AegisCore — ${ACTION^}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

detect_distro_family() {
    local id="" id_like="" family="unknown"
    if [ -f /etc/os-release ]; then
        id=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')
        id_like=$(grep "^ID_LIKE=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]' || true)
    fi
    case "$id" in
        ubuntu|debian|raspbian|linuxmint|pop|kali|parrot|mx)
            family="debian" ;;
        rhel|centos|centos-stream|almalinux|rocky|ol|scientific|fedora)
            family="rhel" ;;
        opensuse*|sles)
            family="suse" ;;
        *)
            echo "$id_like" | grep -q "debian"               && family="debian"
            echo "$id_like" | grep -q "rhel\|fedora\|centos" && family="rhel"
            echo "$id_like" | grep -q "suse"                 && family="suse"
            [ -f /etc/debian_version ] && family="debian"
            [ -f /etc/redhat-release ] && family="rhel"
            [ -f /etc/SuSE-release ]   && family="suse"
            ;;
    esac
    echo "$family"
}

DISTRO_FAMILY=$(detect_distro_family)
PRETTY_NAME="Unknown Linux"
[ -f /etc/os-release ] && PRETTY_NAME=$(grep "^PRETTY_NAME=" /etc/os-release | cut -d= -f2 | tr -d '"') || true

echo "  Sistem   : $PRETTY_NAME"
echo "  Aile     : $DISTRO_FAMILY"
echo ""

CONFIG_FILE="$SIEM_DIR/config/config.yml"
DB_URL="${DATABASE_URL:-}"   # Önce ortam değişkenine bak

if [ -n "$DB_URL" ]; then
    ok "DATABASE_URL ortam değişkeni algılandı — config.yml atlanacak"
fi


# ── Sistem Bağımlılıkları ────────────────────────────────────────────────────
echo "[1/6] Sistem bağımlılıkları..."

if [ "$EUID" -ne 0 ]; then
    warn "Root değil — sistem bağımlılıkları atlanıyor"
    warn "Gerekli paketler: python3 python3-venv python3-dev auditd"
else
    case "$DISTRO_FAMILY" in
        debian)
            apt-get update -qq 2>/dev/null || warn "apt-get update başarısız (devam ediliyor)"
            apt-get install -y -qq python3 python3-pip python3-venv python3-dev \
                build-essential auditd 2>/dev/null && ok "Sistem paketleri (apt)" || \
                warn "apt kurulumu kısmen başarısız"
            ;;
        rhel)
            if command -v dnf &>/dev/null; then
                dnf install -y python3 python3-pip python3-devel \
                    gcc gcc-c++ make audit 2>/dev/null && ok "Sistem paketleri (dnf)" || \
                    warn "dnf kurulumu kısmen başarısız"
            else
                yum install -y python3 python3-pip python3-devel \
                    gcc gcc-c++ make audit 2>/dev/null && ok "Sistem paketleri (yum)" || \
                    warn "yum kurulumu kısmen başarısız"
            fi
            ;;
        suse)
            zypper install -y python3 python3-pip python3-devel \
                gcc make audit 2>/dev/null && ok "Sistem paketleri (zypper)" || \
                warn "zypper kurulumu kısmen başarısız"
            ;;
        *)
            warn "Desteklenmeyen dağıtım — sistem bağımlılıkları manuel kurulmalı"
            warn "Gerekli: python3 python3-venv python3-dev auditd"
            ;;
    esac
fi

# ── Python Kontrolü ──────────────────────────────────────────────────────────
echo ""
echo "[2/6] Python kontrolü..."
command -v python3 &>/dev/null || fail "python3 bulunamadı"
PY_VER=$(python3 -c "import sys; print('.'.join(map(str,sys.version_info[:2])))")
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" || \
    fail "Python 3.8+ gerekli (mevcut: $PY_VER)"
ok "Python $PY_VER"

# ── Virtual Environment ───────────────────────────────────────────────────────
echo ""
echo "[3/6] Virtual environment..."
if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
    ok ".venv oluşturuldu"
else
    ok ".venv zaten mevcut"
fi

# ── Python Bağımlılıkları ─────────────────────────────────────────────────────
echo ""
echo "[4/6] Python bağımlılıkları..."
PIP_BASE=("$VENV/bin/pip" "--disable-pip-version-check")
PYPI_ONLINE=0
if detect_pypi_reachability; then
    PYPI_ONLINE=1
    ok "PyPI erişimi mevcut"
else
    warn "PyPI erişimi yok — offline-aware mod"
fi

if [ "$PYPI_ONLINE" -eq 1 ]; then
    "${PIP_BASE[@]}" install --quiet --upgrade pip
else
    warn "pip self-upgrade atlandı (offline)"
fi

if [ "$PYPI_ONLINE" -eq 1 ]; then
    "${PIP_BASE[@]}" install --quiet -r "$SIEM_DIR/requirements.txt"
    ok "Zorunlu bağımlılıklar kuruldu/güncellendi"
elif python_deps_ready && "${PIP_BASE[@]}" check >/dev/null 2>&1; then
    ok "Mevcut bağımlılıklar geçerli, online kurulum atlandı"
else
    fail "Offline modda eksik bağımlılık var — ağ erişimi veya yerel wheel gerekli"
fi

if python_deps_ready; then
    ok "psycopg2-binary"
else
    fail "psycopg2-binary kullanılamıyor — PostgreSQL bağlantısı için zorunludur"
fi

# ── Veritabanı Yapılandırması ──────────────────────────────────────────────
# Öncelik: 1) DATABASE_URL env var  2) config.yml  3) interaktif soru
if [ -z "$DB_URL" ] && [ -f "$CONFIG_FILE" ]; then
    DB_URL=$("$VENV/bin/python3" - <<PY2
import yaml, sys
try:
    cfg = yaml.safe_load(open('$SIEM_DIR/config/config.yml', encoding='utf-8')) or {}
    print((cfg.get('database', {}) or {}).get('url', ''))
except Exception:
    print('')
PY2
)
fi

if [ -z "$DB_URL" ]; then
    echo ""
    echo "  ┌─────────────────────────────────────────────────────┐"
    echo "  │           PostgreSQL Bağlantısı                     │"
    echo "  └─────────────────────────────────────────────────────┘"
    echo ""
    echo "  Format: postgresql://kullanici:sifre@sunucu:5432/aegiscore"
    echo "  PostgreSQL URL zorunludur — boş bırakırsan kurulum tamamlanmaz"
    echo ""
    if [ -t 0 ] && [ -r /dev/tty ]; then
        printf "  DB URL > "
        read -r DB_URL_INPUT </dev/tty || DB_URL_INPUT=""
        DB_URL="${DB_URL_INPUT:-}"
    else
        warn "Interaktif terminal yok — DB URL sorusu atlandı"
    fi
fi

if [ -n "$DB_URL" ]; then
    # URL'yi config.yml'e yaz
    DB_URL="$DB_URL" SIEM_CFG_PATH="$SIEM_DIR/config/config.yml" "$VENV/bin/python3" - <<'PY3'
import os
import yaml, sys
cfg_path = os.environ.get('SIEM_CFG_PATH', 'config/config.yml')
try:
    with open(cfg_path, encoding='utf-8') as f:
        cfg = yaml.safe_load(f) or {}
    if 'database' not in cfg:
        cfg['database'] = {}
    cfg['database']['url'] = os.environ.get('DB_URL', '')
    with open(cfg_path, 'w', encoding='utf-8') as f:
        yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print('  [OK]   config.yml güncellendi')
except Exception as e:
    print(f'  [WARN] config.yml yazılamadı: {e}', file=sys.stderr)
PY3
    ok "PostgreSQL URL kaydedildi: ${DB_URL%%:*}://***@${DB_URL##*@}"
else
    warn "DB URL girilmedi — AegisCore PostgreSQL olmadan başlamaz"
    warn "Sonradan eklemek için: DATABASE_URL=... veya config.yml -> database.url"
fi

# ── Klasörler ─────────────────────────────────────────────────────────────────
echo ""
echo "[5/6] Klasörler..."
mkdir -p "$SIEM_DIR/data/models"
ok "data/ hazır"
ensure_service_account
if [ "$EUID" -eq 0 ]; then
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$SIEM_DIR/data"
    chmod 0750 "$SIEM_DIR/data"
    ok "data/ sahiplik ve izinleri sıkılaştırıldı"
else
    warn "Root ile çalıştırırsan data/ sahipliği $SERVICE_USER kullanıcısına verilir"
fi

echo ""
echo "[5b/6] First-run bootstrap..."
if [ -f "$EXAMPLE_ENV" ]; then
    if [ "$EUID" -eq 0 ]; then
        if [ ! -f "$SYSTEMD_ENV_FILE" ]; then
            install -D -m 0640 "$EXAMPLE_ENV" "$SYSTEMD_ENV_FILE"
            ok "Örnek env oluşturuldu: $SYSTEMD_ENV_FILE"
        else
            ok "Env mevcut, atlandı: $SYSTEMD_ENV_FILE"
        fi
    else
        if [ ! -f "$LOCAL_ENV_FILE" ]; then
            install -D -m 0640 "$EXAMPLE_ENV" "$LOCAL_ENV_FILE"
            ok "Yerel örnek env oluşturuldu: $LOCAL_ENV_FILE"
        else
            ok "Yerel env mevcut, atlandı: $LOCAL_ENV_FILE"
        fi
        warn "Root ile çalıştırırsan systemd için $SYSTEMD_ENV_FILE oluşturulur"
    fi
else
    warn "Örnek env bulunamadı: $EXAMPLE_ENV"
fi

# ── auditd ────────────────────────────────────────────────────────────────────
echo ""
echo "[6/6] auditd yapılandırması..."

if command -v auditctl &>/dev/null; then
    ok "auditd mevcut"
    if [ "$EUID" -eq 0 ] && command -v systemctl &>/dev/null; then
        systemctl enable auditd 2>/dev/null && systemctl start auditd 2>/dev/null && \
            ok "auditd servisi aktif" || warn "auditd servisi başlatılamadı"
        if [ -f "$SIEM_DIR/config/audit.rules" ]; then
            auditctl -R "$SIEM_DIR/config/audit.rules" 2>/dev/null && \
                ok "auditd kuralları yüklendi" || warn "auditd kuralları yüklenemedi"
        fi
    fi
else
    case "$DISTRO_FAMILY" in
        debian) warn "auditd yok — kur: sudo apt install auditd" ;;
        rhel)   warn "auditd yok — kur: sudo dnf install audit"  ;;
        suse)   warn "auditd yok — kur: sudo zypper install audit" ;;
        *)      warn "auditd bulunamadı (opsiyonel)" ;;
    esac
fi

echo ""
if ! bash "$SIEM_DIR/scripts/preflight.sh"; then
    fail "Preflight başarısız — kurulum tamamlanmadı."
fi

if [ "$RUN_SMOKE_AFTER_INSTALL" = "1" ]; then
    echo ""
    echo "[post] Paket smoke-test..."
    bash "$SIEM_DIR/scripts/package-smoke-test.sh" "$SIEM_DIR"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ Kurulum tamamlandı."
echo ""
echo "  Başlatmak için:"
echo "    sudo $VENV/bin/python $SIEM_DIR/main.py"
echo ""
echo "  Test için:"
echo "    $VENV/bin/python $SIEM_DIR/main.py --test"
echo ""
if [ -z "$DB_URL" ]; then
echo "  ❌  Veritabanı: PostgreSQL URL girilmedi — AegisCore başlamayacak"
echo "     Kalıcı depolama için aşağıdakilerden birini kullan:"
echo ""
echo "     A) Ortam değişkeni (her oturumda veya .bashrc'a ekle):"
echo "        export DATABASE_URL=postgresql://kullanici:sifre@sunucu/aegiscore"
echo ""
echo "     B) Tek seferlik:"
echo "        DATABASE_URL=postgresql://... sudo $VENV/bin/python $SIEM_DIR/main.py"
echo ""
echo "     C) config.yml -> database.url alanını doldur"
else
echo "  🗄  Veritabanı: PostgreSQL bağlantısı yapılandırıldı"
echo ""
echo "     Farklı DB kullanmak için:"
echo "        export DATABASE_URL=postgresql://yeni_url"
echo "        veya config.yml -> database.url"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
