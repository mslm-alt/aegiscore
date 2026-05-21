#!/bin/bash
# package.sh — AegisCore temiz release zip'i oluşturur
#
# Zip açılınca dosyalar DOĞRUDAN mevcut klasöre gelir:
#   unzip aegiscore-2.1.1.zip   →  ./main.py, ./core/, ./rules/ ...
#
# Kullanım:
#   bash scripts/package.sh          # tarih damgasıyla
#   bash scripts/package.sh 2.1.1    # versiyon etiketiyle
set -e

DRY_RUN=0
VERSION=""
for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=1
            ;;
        *)
            if [ -z "$VERSION" ]; then
                VERSION="$arg"
            else
                echo "Bilinmeyen argüman: $arg" >&2
                exit 1
            fi
            ;;
    esac
done

VERSION="${VERSION:-$(date +%Y%m%d_%H%M%S)}"
EXPORT_DIR_NAME="github_clean_export_${VERSION}"
OUT="AegisCore_github_clean_${VERSION}.zip"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
STAGE="$TMP_DIR/stage"
DIST_ROOT="$ROOT/dist/$EXPORT_DIR_NAME"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AegisCore — Paketleniyor: $OUT"
if [ "$DRY_RUN" -eq 1 ]; then
    echo "  Mod     : dry-run"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1-2. Cleanup sadece gerçek build'de çalışır; dry-run read-only kalır.
if [ "$DRY_RUN" -eq 1 ]; then
    echo "  [1/4] Dry-run read-only: workspace temizliği atlanıyor"
    echo "  [2/4] Dry-run read-only: rules/ düzeltmeleri atlanıyor"
else
    # 1. Kirli dosyaları temizle
    echo "  [1/4] Temizleniyor..."
    find "$ROOT" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$ROOT" -name "*.pyc" -o -name "*.pyo" | xargs rm -f 2>/dev/null || true
    find "$ROOT" -name "hydra.restore" -delete 2>/dev/null || true
    find "$ROOT" -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true

    # 2. rules/ altındaki yanlış core/ / config/ kopyalarını temizle
    echo "  [2/4] rules/ doğrulanıyor..."
    if [ -d "$ROOT/rules/core" ]; then
        echo "    rules/core/ bulundu — siliniyor"
        rm -rf "$ROOT/rules/core"
    fi
    if [ -d "$ROOT/rules/config" ]; then
        echo "    rules/config/ bulundu — siliniyor"
        rm -rf "$ROOT/rules/config"
    fi
fi

# 3. Python ile temiz zip oluştur
echo "  [3/4] Paket içeriği hazırlanıyor..."
python3 - << PYEOF
import fnmatch
import os
import zipfile
from pathlib import Path

ROOT  = Path("$ROOT")
OUT   = Path("$TMP_DIR/$OUT")
IGNORE_FILE = ROOT / ".packageignore"
DRY_RUN = bool(int("$DRY_RUN"))

DEFAULT_PATTERNS = [
    ".git/",
    ".pytest_cache/",
    ".venv/",
    "venv/",
    ".tox/",
    "node_modules/",
    "*.pyo",
    "*.zip",
    "*.db",
    "*.db-wal",
    "*.db-shm",
    "*.joblib",
    "*.log",
    "*.tmp",
    "hydra.restore",
    ".DS_Store",
    ".env",
    "*.egg-info/",
]

def load_patterns(path: Path):
    patterns = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    return patterns

PATTERNS = DEFAULT_PATTERNS + load_patterns(IGNORE_FILE)

AUTO_FEED_MARKER = "# --- AUTO FEED ---"


def sanitize_ioc_text(raw: str) -> str:
    lines = raw.splitlines()
    kept = []
    for line in lines:
        if line.strip() == AUTO_FEED_MARKER:
            break
        kept.append(line)
    while kept and not kept[-1].strip():
        kept.pop()
    kept.extend(
        [
            "",
            AUTO_FEED_MARKER,
            "# AUTO FEED bölümü runtime/generated içeriktir ve release paketinde sanitize edilmiştir.",
            "# Threat intel feed verisi runtime'da yeniden oluşturulabilir; statik seed IOC'ler yukarıda korunur.",
        ]
    )
    return "\n".join(kept) + "\n"

def _matches_pattern(rel: Path, pattern: str) -> bool:
    rel_str = rel.as_posix()
    rel_parts = rel.parts
    if pattern.endswith("/"):
        dir_pat = pattern.rstrip("/")
        if "/" in dir_pat:
            return rel_str == dir_pat or rel_str.startswith(dir_pat + "/")
        return dir_pat in rel_parts
    if "/" in pattern:
        return fnmatch.fnmatch(rel_str, pattern)
    if fnmatch.fnmatch(rel.name, pattern):
        return True
    return any(fnmatch.fnmatch(part, pattern) for part in rel_parts)

def is_excluded(rel: Path) -> tuple[bool, str]:
    matched_reason = ""
    excluded = False
    for raw_pattern in PATTERNS:
        negated = raw_pattern.startswith("!")
        pattern = raw_pattern[1:] if negated else raw_pattern
        if not pattern:
            continue
        if _matches_pattern(rel, pattern):
            excluded = not negated
            matched_reason = raw_pattern
    return excluded, matched_reason

included = []
excluded = []
for f in sorted(ROOT.rglob("*")):
    try:
        rel = f.relative_to(ROOT)
    except ValueError:
        continue
    if not f.is_file():
        continue
    excluded_flag, reason = is_excluded(rel)
    if excluded_flag:
        excluded.append((rel.as_posix(), reason))
        continue
    included.append((f, rel))

if DRY_RUN:
    print(f"DRY_RUN include={len(included)} exclude={len(excluded)}")
    for rel_str, reason in excluded[:40]:
        print(f"EXCLUDE {reason:<24} {rel_str}")
else:
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for f, rel in included:
            rel_str = rel.as_posix()
            if rel_str == "config/ioc_list.txt":
                zf.writestr(rel_str, sanitize_ioc_text(f.read_text(encoding="utf-8")))
                continue
            zf.write(f, rel)
    print(f"OK: {OUT}")
    print(f"INCLUDE {len(included)}")
    print(f"EXCLUDE {len(excluded)}")
PYEOF

if [ "$DRY_RUN" -eq 1 ]; then
    echo "  [4/4] Dry-run tamamlandı."
    rm -rf "$TMP_DIR"
    exit 0
fi

# 4. Zip'i dist export klasörüne taşı
mkdir -p "$DIST_ROOT"
mv "$TMP_DIR/$OUT" "$DIST_ROOT/$OUT"
rm -rf "$TMP_DIR"

SIZE=$(du -sh "$DIST_ROOT/$OUT" | cut -f1)
FILES=$(python3 -c "import zipfile; z=zipfile.ZipFile('$DIST_ROOT/$OUT'); print(len(z.namelist()))")

echo "  [4/4] Tamamlandı."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Dosya : $DIST_ROOT/$OUT"
echo "  Boyut : $SIZE  |  İçerik: $FILES dosya"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
