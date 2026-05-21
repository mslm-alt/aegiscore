#!/usr/bin/env bash
# scripts/verify_patch.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTEST_BIN="$ROOT/.venv/bin/pytest"
PYTHON_BIN="$ROOT/.venv/bin/python"

[ -x "$PYTEST_BIN" ] || { echo ".venv pytest bulunamadı: $PYTEST_BIN" >&2; exit 1; }
[ -x "$PYTHON_BIN" ] || { echo ".venv python bulunamadı: $PYTHON_BIN" >&2; exit 1; }

run_step() {
    echo "[verify] $*"
    "$@"
}

run_step "$PYTEST_BIN" tests/test_parse_contracts.py -v
run_step "$PYTEST_BIN" tests/test_retention_and_calibration.py -v
run_step "$PYTEST_BIN" tests/test_maintenance_integration.py -v
run_step "$PYTEST_BIN" tests/test_unknown_distro.py -v
run_step "$PYTEST_BIN" tests/unit/test_database_postgres_patch.py -q
run_step "$PYTEST_BIN" tests/unit/test_phase_duplicate_rate.py -q
run_step "$PYTEST_BIN" tests/unit/test_main_logging.py -q
run_step "$PYTEST_BIN" tests/unit/test_event_queue.py -q
run_step "$PYTEST_BIN" tests/unit/test_hunting_visibility.py -q
run_step "$PYTEST_BIN" tests/unit/test_guard_contracts.py -k baseline_validator -q
run_step "$PYTEST_BIN" tests/unit/test_detection.py -k nested_event_match_fields_gate_threshold_window -q
# ── Lifecycle contract testleri (v4 patch) ────────────────────────────────────
# clean marker + manifest doğrulaması; clean_restart vs dirty_restore kontratı;
# loss_possible / marker_valid / manifest_valid yüzeyleri
run_step "$PYTEST_BIN" tests/unit/test_lifecycle_runtime_state.py -q
run_step "$PYTEST_BIN" tests/unit/test_lifecycle_manifest.py -q
# ─────────────────────────────────────────────────────────────────────────────
run_step "$PYTEST_BIN" -q
run_step "$PYTHON_BIN" "$ROOT/main.py" --validate-rules
