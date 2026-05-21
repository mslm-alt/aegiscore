"""
tests/unit/test_lifecycle_manifest.py
────────────────────────────────────────────────────────
Lifecycle manifest contract testleri (v4 patch).

Kapsamı:
  - valid marker + manifest  → clean_restart
  - bozuk checksum           → dirty_restore, loss_possible=True
  - eksik/corrupt marker     → dirty_restore ama sistem açılır (fail-open)
  - manifest alanları eksik  → dirty_restore, manifest_valid=False
  - queue pending varken     → loss_possible=True
  - tekrar eden restart döngüsü → clean/crash ayrımı bozulmaz
  - idempotent restore       → ikinci açılışta yanlış crash izi yok
"""

import json
import time
import tempfile
from pathlib import Path

import pytest

from core.state_manager import (
    RuntimeStateStore,
    atomic_json_save,
    atomic_json_load,
    _state_header,
    _compute_checksum,
)


# ─── helper ────────────────────────────────────────────────────────────

def _clean_save(state_dir: str, **meta_overrides) -> RuntimeStateStore:
    """Perform a valid clean shutdown and return a new store."""
    store = RuntimeStateStore(state_dir=state_dir)
    store.total_events = meta_overrides.pop("total_events", 100)
    store.total_alerts = meta_overrides.pop("total_alerts", 5)
    store.mark_running()
    meta = {
        "shutdown_attempted_at": time.time(),
        "queue_drained_ok": True,
        "final_flush_ok": True,
        "final_state_save_ok": True,
        "queue_depth_at_shutdown": 0,
        "pending_flush_count": 0,
        **meta_overrides,
    }
    ok = store.save(clean_shutdown=True, shutdown_metadata=meta)
    assert ok, "save() başarısız olmamalı"
    return store


# ─── Temel contract ──────────────────────────────────────────────────────────

def test_valid_manifest_yields_clean_restart(tmp_path):
    """Valid marker + manifest → clean_restart, with marker_valid and manifest_valid set to True."""
    _clean_save(str(tmp_path))
    rs = RuntimeStateStore(state_dir=str(tmp_path))

    assert rs.startup_mode == "clean_restart"
    h = rs.runtime_restore_health
    assert h["marker_valid"]   is True
    assert h["manifest_valid"] is True
    assert h["loss_possible"]  is False
    assert h["restore_status"] == "clean_restart"


def test_corrupt_checksum_yields_dirty_restore(tmp_path):
    """Checksum bozulursa → dirty_restore, manifest_valid=False, loss_possible=True."""
    _clean_save(str(tmp_path))

    state_path = tmp_path / "runtime_state.json"
    raw = state_path.read_text(encoding="utf-8")
    data = json.loads(raw)
    # Corrupt the checksum field
    data["_checksum"] = "00000000deadbeef"
    state_path.write_text(json.dumps(data), encoding="utf-8")

    rs = RuntimeStateStore(state_dir=str(tmp_path))

    assert rs.startup_mode == "dirty_restore"
    h = rs.runtime_restore_health
    assert h["marker_valid"]   is False
    assert h["manifest_valid"] is False
    assert h["loss_possible"]  is True


def test_missing_marker_file_is_fail_open(tmp_path):
    """
    Marker dosyası yoksa sistem açılır (fail-open),
    ama fresh_start olarak kabul edilir — clean sayılmaz.
    """
    rs = RuntimeStateStore(state_dir=str(tmp_path))

    # Dosya yok → fresh_start
    assert rs.startup_mode == "fresh_start"
    h = rs.runtime_restore_health
    assert h["marker_valid"]   is False
    assert h["manifest_valid"] is False
    # On fresh_start, loss_possible=False because there was no data to lose
    assert h["loss_possible"]  is False
    assert h.get("restore_status") == "fresh_start"


def test_corrupt_json_is_fail_open_dirty_restore(tmp_path):
    """A file containing invalid JSON should lead to dirty_restore while the system still starts."""
    state_path = tmp_path / "runtime_state.json"
    state_path.write_text("{NOT VALID JSON!!!}", encoding="utf-8")

    rs = RuntimeStateStore(state_dir=str(tmp_path))

    assert rs.startup_mode == "dirty_restore"
    h = rs.runtime_restore_health
    assert h["degraded"]      is True
    assert h["loss_possible"] is True


def test_manifest_missing_fields_yields_dirty_restore(tmp_path):
    """Manifest var ama zorunlu alanlar eksikse → dirty_restore."""
    _clean_save(str(tmp_path))

    state_path = tmp_path / "runtime_state.json"
    raw = state_path.read_text(encoding="utf-8")
    data = json.loads(raw)
    # Remove one required field from the manifest
    data.get("manifest", {}).pop("pending_flush_count", None)
    # Recompute the checksum so the failure is treated as a manifest error, not just a checksum error
    raw2 = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    data["_checksum"] = _compute_checksum(raw2)
    state_path.write_text(json.dumps(data), encoding="utf-8")

    rs = RuntimeStateStore(state_dir=str(tmp_path))

    h = rs.runtime_restore_health
    assert h["manifest_valid"] is False
    assert h["loss_possible"]  is True
    # The system should still start as dirty_restore or crash_restore, but without raising an exception
    assert rs.startup_mode in ("dirty_restore", "crash_restore")


def test_queue_pending_at_shutdown_sets_loss_possible(tmp_path):
    """If the queue still contains events during shutdown, loss_possible should be True."""
    _clean_save(
        str(tmp_path),
        queue_depth_at_shutdown=12,
        pending_flush_count=3,
    )
    rs = RuntimeStateStore(state_dir=str(tmp_path))

    h = rs.runtime_restore_health
    assert h["manifest_valid"] is True
    assert h["loss_possible"]  is True   # kuyruk boş değildi


def test_zero_pending_clean_shutdown_no_loss(tmp_path):
    """With an empty queue and a clean shutdown, loss_possible should be False."""
    _clean_save(
        str(tmp_path),
        queue_depth_at_shutdown=0,
        pending_flush_count=0,
    )
    rs = RuntimeStateStore(state_dir=str(tmp_path))

    h = rs.runtime_restore_health
    assert h["manifest_valid"] is True
    assert h["loss_possible"]  is False


# ─── Loop / idempotency tests ─────────────────────────────────────────

def test_repeated_clean_restarts_preserve_clean_status(tmp_path):
    """Five clean shutdowns in a row should keep every startup in clean_restart."""
    state_dir = str(tmp_path)
    for i in range(5):
        _clean_save(state_dir)
        rs = RuntimeStateStore(state_dir=state_dir)
        assert rs.startup_mode == "clean_restart", f"Döngü {i}: beklenen clean_restart"
        assert rs.runtime_restore_health["marker_valid"]   is True
        assert rs.runtime_restore_health["manifest_valid"] is True


def test_dirty_stop_then_clean_restart_cycle(tmp_path):
    """dirty stop → clean restart loop: crash_restore → clean_restart."""
    state_dir = str(tmp_path)

    # 1. dirty stop: clean_shutdown=False
    store = RuntimeStateStore(state_dir=state_dir)
    store.total_events = 50
    store.mark_running()
    store.save(clean_shutdown=False)

    rs1 = RuntimeStateStore(state_dir=state_dir)
    assert rs1.startup_mode == "crash_restore"
    assert rs1.runtime_restore_health["loss_possible"] is True

    # 2. Now perform a clean shutdown
    _clean_save(state_dir, total_events=51)

    rs2 = RuntimeStateStore(state_dir=state_dir)
    assert rs2.startup_mode == "clean_restart"
    assert rs2.runtime_restore_health["manifest_valid"] is True
    assert rs2.runtime_restore_health["loss_possible"]  is False


def test_idempotent_restore_no_ghost_crash_on_second_open(tmp_path):
    """The second startup must not preserve a false crash trace (idempotency)."""
    state_dir = str(tmp_path)
    _clean_save(state_dir)

    rs1 = RuntimeStateStore(state_dir=state_dir)
    assert rs1.startup_mode == "clean_restart"

    # Read the same file again without any additional save
    rs2 = RuntimeStateStore(state_dir=state_dir)
    assert rs2.startup_mode == "clean_restart"
    assert rs2.runtime_restore_health["marker_valid"]   is True
    assert rs2.runtime_restore_health["manifest_valid"] is True


def test_marker_bozuldu_then_clean_save_clears_dirty(tmp_path):
    """
    Marker bozulunca dirty_restore; ardından clean save yapınca
    bir sonraki açılış clean_restart olmalı.
    """
    state_dir = str(tmp_path)
    _clean_save(state_dir)

    # Corrupt the file
    state_path = tmp_path / "runtime_state.json"
    state_path.write_text("{bad json}", encoding="utf-8")

    rs_dirty = RuntimeStateStore(state_dir=state_dir)
    assert rs_dirty.startup_mode == "dirty_restore"

    # Temiz kaydet
    _clean_save(state_dir)

    rs_clean = RuntimeStateStore(state_dir=state_dir)
    assert rs_clean.startup_mode == "clean_restart"
    assert rs_clean.runtime_restore_health["manifest_valid"] is True


# ─── Manifest Content Validation ───────────────────────────────────────

def test_manifest_fields_present_in_saved_state(tmp_path):
    """After save(), the JSON should contain a complete set of manifest fields."""
    _clean_save(str(tmp_path), queue_depth_at_shutdown=7, pending_flush_count=2)
    raw = (tmp_path / "runtime_state.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    manifest = data.get("manifest", {})

    required = (
        "state_version",
        "queue_depth_at_shutdown",
        "pending_flush_count",
        "total_events_snapshot",
        "total_alerts_snapshot",
        "saved_ts",
    )
    for field in required:
        assert field in manifest, f"manifest.{field} eksik"
    assert manifest["queue_depth_at_shutdown"] == 7
    assert manifest["pending_flush_count"] == 2


def test_restore_health_always_has_three_new_keys(tmp_path):
    """
    Her restore sonucunda marker_valid, manifest_valid, loss_possible
    keyleri mutlaka bulunmalı.
    """
    # fresh_start
    rs0 = RuntimeStateStore(state_dir=str(tmp_path))
    for key in ("marker_valid", "manifest_valid", "loss_possible"):
        assert key in rs0.runtime_restore_health, f"fresh_start: {key} eksik"

    # clean_restart
    _clean_save(str(tmp_path))
    rs1 = RuntimeStateStore(state_dir=str(tmp_path))
    for key in ("marker_valid", "manifest_valid", "loss_possible"):
        assert key in rs1.runtime_restore_health, f"clean_restart: {key} eksik"

    # dirty
    (tmp_path / "runtime_state.json").write_text("{}", encoding="utf-8")
    rs2 = RuntimeStateStore(state_dir=str(tmp_path))
    for key in ("marker_valid", "manifest_valid", "loss_possible"):
        assert key in rs2.runtime_restore_health, f"dirty: {key} eksik"
