#!/usr/bin/env bash
# scripts/package-smoke-test.sh

set -euo pipefail

ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
PY="$ROOT/.venv/bin/python"
ENV_FILE="/etc/default/aegiscore"
RUN_DOCTOR="${AEGISCORE_SMOKE_RUN_DOCTOR:-1}"
TMP_HOME="$(mktemp -d /tmp/aegiscore-smoke-home.XXXXXX)"
TMP_XDG="$(mktemp -d /tmp/aegiscore-smoke-xdg.XXXXXX)"

[ -x "$PY" ] || { echo ".venv python bulunamadı: $PY" >&2; exit 1; }
cleanup() { rm -rf "$TMP_HOME" "$TMP_XDG"; }
trap cleanup EXIT

export HOME="$TMP_HOME"
export XDG_RUNTIME_DIR="$TMP_XDG"
export XDG_CACHE_HOME="$TMP_HOME/.cache"
export XDG_CONFIG_HOME="$TMP_HOME/.config"

if [ -f "$ENV_FILE" ]; then
    # shellcheck disable=SC1090
    set -a; . "$ENV_FILE"; set +a
fi

if [ "$RUN_DOCTOR" = "1" ]; then
    echo "[smoke] doctor"
    "$PY" "$ROOT/main.py" --doctor
fi

if [ -n "${DATABASE_URL:-}" ]; then
    echo "[smoke] smoke-test"
    "$PY" "$ROOT/main.py" --smoke-test
else
    echo "[smoke] DATABASE_URL yok, runtime smoke-test atlandı"
fi
