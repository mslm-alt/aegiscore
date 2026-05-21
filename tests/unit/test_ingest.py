import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import json
import pytest
from core.event_queue import EventIngestionQueue
from core.ingest import approved_log_roots, tail_file, tail_utmp, validate_log_file_path


def test_tail_utmp_skips_initial_backlog_and_yields_new_entries():
    first = SimpleNamespace(
        stdout="alice    pts/0        192.168.1.10     Mon Mar  5 12:34   still logged in\n",
        returncode=0,
    )
    second = SimpleNamespace(
        stdout=(
            "bob      ssh:notty    203.0.113.5      Mon Mar  5 12:35 - 12:35  (00:00)\n"
            "alice    pts/0        192.168.1.10     Mon Mar  5 12:34   still logged in\n"
        ),
        returncode=0,
    )

    with patch.object(Path, "exists", return_value=True):
        with patch("core.ingest.subprocess.run", side_effect=[first, second]):
            with patch("core.ingest._time.sleep", return_value=None):
                gen = tail_utmp("/var/log/wtmp")
                assert next(gen).startswith("bob")


def test_event_queue_health_exposes_trend_and_timestamps():
    q = EventIngestionQueue(maxsize=4)

    with patch("core.event_queue.time.time", side_effect=[100.0, 106.0, 112.0, 112.0, 124.0, 124.0]):
        assert q.put("evt-1", "auth.log") is True
        assert q.put("evt-2", "auth.log") is True
        raw, source, queued_ts = q.get(timeout=0.1)
        q.get(timeout=0.1)

    health = q.health()

    assert (raw, source, queued_ts) == ("evt-1", "auth.log", 100.0)
    assert health["last_put_ts"] == 106.0
    assert health["last_get_ts"] == 124.0
    assert health["high_water"] == 2
    assert health["depth_trend_per_min"] == -2.5


def test_validate_log_file_path_allows_approved_var_log_file(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("line\n", encoding="utf-8")

    resolved, error = validate_log_file_path(str(log_file), approved_roots=[tmp_path])

    assert error is None
    assert resolved == log_file


def test_validate_log_file_path_allows_approved_postgresql_path(tmp_path):
    root = tmp_path / "var" / "lib" / "postgresql"
    log_file = root / "postgresql.log"
    log_file.parent.mkdir(parents=True)
    log_file.write_text("db line\n", encoding="utf-8")

    resolved, error = validate_log_file_path(str(log_file), approved_roots=[root])

    assert error is None
    assert resolved == log_file


def test_workspace_fixture_path_requires_explicit_approval(tmp_path, monkeypatch):
    log_file = tmp_path / "auth.log"
    log_file.write_text("line\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    resolved, error = validate_log_file_path(str(log_file))

    assert resolved is None
    assert error == "path_outside_approved_roots"


def test_validate_log_file_path_blocks_outside_approved_roots():
    resolved, error = validate_log_file_path("/etc/shadow")

    assert resolved is None
    assert error == "path_outside_approved_roots"


def test_validate_log_file_path_blocks_relative_traversal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    resolved, error = validate_log_file_path("../../etc/shadow", approved_roots=[tmp_path])

    assert resolved is None
    assert error == "path_outside_approved_roots"


def test_validate_log_file_path_blocks_symlink_to_outside(tmp_path):
    allowed_root = tmp_path / "logs"
    allowed_root.mkdir()
    target = tmp_path / "outside.log"
    target.write_text("secret\n", encoding="utf-8")
    link = allowed_root / "auth.log"
    link.symlink_to(target)

    resolved, error = validate_log_file_path(str(link), approved_roots=[allowed_root])

    assert resolved is None
    assert error == "path_outside_approved_roots"


def test_validate_log_file_path_blocks_parent_symlink_escape(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "logs"
    root.mkdir()
    parent_link = root / "nested"
    parent_link.symlink_to(outside, target_is_directory=True)
    candidate = parent_link / "auth.log"
    candidate.parent.mkdir(exist_ok=True) if False else None

    resolved, error = validate_log_file_path(str(candidate), approved_roots=[root])

    assert resolved is None
    assert error == "parent_symlink_blocked"


def test_validate_log_file_path_blocks_directory(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    resolved, error = validate_log_file_path(str(log_dir), approved_roots=[tmp_path])

    assert resolved is None
    assert error == "directory_blocked"


def test_validate_log_file_path_blocks_fifo(tmp_path):
    fifo_path = tmp_path / "fifo.log"
    os.mkfifo(fifo_path)

    resolved, error = validate_log_file_path(str(fifo_path), approved_roots=[tmp_path])

    assert resolved is None
    assert error == "non_regular_file_blocked"


def test_tail_file_missing_approved_file_keeps_existing_behavior(tmp_path):
    missing = tmp_path / "missing.log"

    assert list(tail_file(str(missing), approved_roots=[tmp_path])) == []


def test_tail_file_blocks_unapproved_path():
    assert list(tail_file("/etc/shadow")) == []


def test_approved_log_roots_includes_explicit_extra_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    roots = approved_log_roots(["fixtures/logs"])

    assert (tmp_path / "fixtures" / "logs").resolve() in roots
