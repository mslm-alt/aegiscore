#!/usr/bin/env bash
# scripts/preflight.sh
# AegisCore — PostgreSQL-only sistem hazırlık kontrolü

set -euo pipefail

SIEM_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${1:-$SIEM_DIR/config/config.yml}"
VENV_PY="$SIEM_DIR/.venv/bin/python"
RULECHECK_OUT="$(mktemp /tmp/aegiscore_rulecheck.XXXXXX)"
PASS=0
FAIL=0
WARN=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
export AEGISCORE_CONFIG_PATH="$CONFIG"

PYTHON_BIN="python3"
[ -x "$VENV_PY" ] && PYTHON_BIN="$VENV_PY"

ok()   { echo -e "  ${GREEN}[OK]${NC}   $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARN=$((WARN+1)); }
section() { echo ""; echo "[ $1 ]"; }
cleanup() { rm -f "$RULECHECK_OUT"; }
trap cleanup EXIT

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AegisCore — Preflight Kontrol (PostgreSQL)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

section "Yetkiler"
if [ "$EUID" -eq 0 ]; then
  ok "Root yetkisi mevcut"
else
  warn "Root değil — bazı log dosyaları okunamayabilir"
fi

section "Python"
if command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  PY_VER=$("$PYTHON_BIN" -c "import sys; print('.'.join(map(str,sys.version_info[:3])))")
  if "$PYTHON_BIN" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,8) else 1)"; then
    ok "Python $PY_VER ($PYTHON_BIN)"
  else
    fail "Python 3.8+ gerekli (mevcut: $PY_VER)"
  fi
else
  fail "Python bulunamadı"
fi

section "Bağımlılıklar"
for pkg in yaml sklearn numpy joblib psycopg2; do
  if "$PYTHON_BIN" -c "import $pkg" 2>/dev/null; then
    ok "$pkg"
  else
    fail "$pkg bulunamadı — $PYTHON_BIN -m pip install -r requirements.txt"
  fi
done

section "Config"
if [ -f "$CONFIG" ]; then
  ok "config.yml mevcut"
  if "$PYTHON_BIN" -c "import os, yaml; yaml.safe_load(open(os.environ['AEGISCORE_CONFIG_PATH'], encoding='utf-8'))" 2>/dev/null; then
    ok "config.yml geçerli YAML"
  else
    fail "config.yml parse hatası"
  fi
else
  fail "config.yml bulunamadı: $CONFIG"
fi

section "Kurallar"
for f in auth.yml network.yml process.yml auditd.yml dns.yml threshold.yml regex.yml; do
  if [ -f "$SIEM_DIR/rules/$f" ]; then
    ok "rules/$f"
  else
    fail "rules/$f bulunamadı"
  fi
done

section "Log Dosyaları"
check_log_target() {
  local label="$1"
  local required="$2"
  shift 2
  local found=""
  for candidate in "$@"; do
    [ -n "$candidate" ] || continue
    if [ -e "$candidate" ]; then
      found="$candidate"
      break
    fi
  done

  if [ -z "$found" ]; then
    if [ "$required" = "required" ]; then
      warn "$label bulunamadı (runtime auto-resolve deneyecek)"
    else
      warn "$label bulunamadı (opsiyonel)"
    fi
    return
  fi

  if [ -r "$found" ]; then
    ok "$label → $found"
  else
    warn "$label mevcut ama okunamıyor: $found (root gerekebilir)"
  fi
}

check_log_target "Auth/System log" required \
  /var/log/auth.log /var/log/secure /var/log/messages
check_log_target "Audit log" optional \
  /var/log/audit/audit.log
check_log_target "Package log" optional \
  /var/log/dpkg.log /var/log/dnf.log /var/log/dnf.rpm.log /var/log/yum.log /var/log/zypp/history
check_log_target "Mail log" optional \
  /var/log/mail.log /var/log/maillog
check_log_target "OpenVPN log" optional \
  /var/log/openvpn.log /var/log/openvpn/openvpn.log
if command -v journalctl >/dev/null 2>&1; then
  ok "journald erişimi (journalctl)"
else
  warn "journalctl bulunamadı — journald kaynağı çalışmaz"
fi

section "auditd"
if command -v auditctl >/dev/null 2>&1; then
  ok "auditctl mevcut"
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
      ok "auditd servisi aktif"
    else
      warn "auditd kurulu ama servis aktif değil"
    fi
  fi
else
  warn "auditd bulunamadı — auditd kuralları çalışmaz"
fi

section "Veri Klasörü"
DATA_DIR="$SIEM_DIR/data"
mkdir -p "$DATA_DIR/models"
ok "data/ hazır"
if [ -w "$DATA_DIR" ]; then
  ok "data/ yazılabilir"
else
  fail "data/ klasörüne yazma izni yok"
fi

section "Veritabanı"
DB_URL=$("$PYTHON_BIN" - <<PY
import os
from pathlib import Path
import yaml

config_path = Path(os.environ["AEGISCORE_CONFIG_PATH"])
cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
cfg = cfg or {}
print((cfg.get('database', {}) or {}).get('url', '') or os.environ.get('DATABASE_URL', ''))
PY
)
DB_TYPE=$("$PYTHON_BIN" - <<PY
import os
from pathlib import Path
import yaml

config_path = Path(os.environ["AEGISCORE_CONFIG_PATH"])
cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
cfg = cfg or {}
print((cfg.get('database', {}) or {}).get('type', 'postgresql'))
PY
)
if [ "$DB_TYPE" != "postgresql" ]; then
  fail "AegisCore PostgreSQL-only çalışır — database.type: postgresql olmalı"
elif [ -z "$DB_URL" ]; then
  fail "PostgreSQL URL eksik — config.yml: database.url veya env: DATABASE_URL"
elif DB_URL="$DB_URL" "$PYTHON_BIN" - <<'PY'
import sys
import os
url = os.environ.get("DB_URL", "").strip()
sys.exit(0 if (url.startswith('postgresql://') or url.startswith('postgres://')) else 1)
PY
then
  ok "PostgreSQL URL formatı geçerli"
  if DB_URL="$DB_URL" "$PYTHON_BIN" - <<'PY'
import sys, psycopg2
import os
try:
    conn = psycopg2.connect(os.environ.get("DB_URL", ""), connect_timeout=5)
    conn.close()
    raise SystemExit(0)
except Exception:
    raise SystemExit(1)
PY
  then
    ok "PostgreSQL bağlantısı başarılı"
  else
    fail "PostgreSQL bağlantısı başarısız — URL, kullanıcı/şifre ve servis durumunu kontrol edin"
  fi
else
  fail "PostgreSQL URL formatı hatalı (postgresql://user:pass@host:5432/db olmalı)"
fi

section "Kural Validasyonu"
if "$PYTHON_BIN" "$SIEM_DIR/main.py" --config "$CONFIG" --validate-rules >"$RULECHECK_OUT" 2>&1; then
  if grep -q "Tüm kurallar geçerli" "$RULECHECK_OUT"; then
    ok "Tüm kurallar geçerli"
  else
    warn "Kural validasyonu çalıştı ama beklenen başarı metni bulunamadı"
    cat "$RULECHECK_OUT"
  fi
else
  fail "Kural validasyon hatası — $PYTHON_BIN main.py --validate-rules"
  cat "$RULECHECK_OUT"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Sonuç: ${GREEN}$PASS OK${NC}  ${YELLOW}$WARN UYARI${NC}  ${RED}$FAIL HATA${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ $FAIL -gt 0 ]; then
  echo "Sistem hazır DEĞİL. Hataları düzeltin."
  exit 1
elif [ $WARN -gt 0 ]; then
  echo "Sistem hazır (uyarılarla). Uyarıları inceleyin."
  exit 0
else
  echo "Sistem hazır. Başlatabilirsiniz:"
  echo "  sudo -E .venv/bin/python main.py"
  exit 0
fi
