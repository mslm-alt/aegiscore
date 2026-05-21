#!/usr/bin/env bash
# scripts/build-rpm.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION" 2>/dev/null || echo 16.0.0)"
DIST_DIR="$ROOT/dist"
RPMROOT="$DIST_DIR/staging/rpmbuild"
SPEC="$ROOT/packaging/rpm/aegiscore.spec"
TARBALL_DIR="$RPMROOT/SOURCES"
TARBALL="$TARBALL_DIR/aegiscore-${VERSION}.tar.gz"
OUT_DIR="$DIST_DIR/rpm"

command -v rpmbuild >/dev/null 2>&1 || {
  echo "rpmbuild bulunamadı" >&2
  exit 1
}

rm -rf "$RPMROOT"
mkdir -p "$RPMROOT"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$OUT_DIR"

tar -C "$ROOT" \
  --exclude='./.git' \
  --exclude='./.venv' \
  --exclude='./dist' \
  --exclude='./data' \
  --exclude='./__pycache__' \
  --exclude='./.pytest_cache' \
  -czf "$TARBALL" .

cp "$SPEC" "$RPMROOT/SPECS/aegiscore.spec"
sed -i "s/^Version: .*/Version:        ${VERSION}/" "$RPMROOT/SPECS/aegiscore.spec"

rpmbuild --define "_topdir $RPMROOT" -bb "$RPMROOT/SPECS/aegiscore.spec" >/dev/null
find "$RPMROOT/RPMS" -type f -name '*.rpm' -exec cp {} "$OUT_DIR/" \;
find "$OUT_DIR" -type f -name '*.rpm' | head -n 1
