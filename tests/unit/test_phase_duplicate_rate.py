from types import SimpleNamespace

from core import database_postgres as dbpg
from core.phase_manager import SystemStats
from core.phase_manager import PhaseManager


def test_duplicate_rate_counts_exact_duplicates_but_not_telemetry_shadows():
    stats = SystemStats()

    for _ in range(10):
        stats.total_events += 1

    for _ in range(3):
        stats.record_duplicate()

    for _ in range(20):
        stats.record_duplicate(kind="telemetry")

    assert stats.duplicate_count == 3
    assert stats.telemetry_duplicate_count == 20
    assert round(stats.dup_rate, 3) == round(3 / 33, 3)


def test_duplicate_rate_stays_bounded_when_telemetry_shadows_dominate():
    stats = SystemStats(total_events=4, parse_fail_count=1)

    for _ in range(25):
        stats.record_duplicate(kind="telemetry")

    assert stats.dup_rate <= 1.0
    assert round(stats.dup_rate, 3) == round(1 / 30, 3)


def test_duplicate_rate_counts_parse_fail_as_quality_penalty():
    stats = SystemStats(total_events=10, duplicate_count=2, parse_fail_count=3)

    assert stats.quality_penalty_count == 5
    assert stats.quality_seen_total == 15
    assert round(stats.dup_rate, 3) == round(5 / 15, 3)


def test_exact_duplicate_breakdown_tracks_source_and_kind():
    stats = SystemStats()

    stats.record_duplicate(kind="exact_same_source", source="auditd")
    stats.record_duplicate(kind="exact_same_source", source="auditd")
    stats.record_duplicate(kind="exact_same_source", source="auth.log")

    assert stats.duplicate_count == 3
    assert stats.duplicate_breakdown_by_source == {"auditd": 2, "auth.log": 1}
    assert stats.duplicate_breakdown_by_kind == {"exact_same_source": 3}


def test_telemetry_duplicates_stay_out_of_duplicate_breakdown():
    stats = SystemStats()

    stats.record_duplicate(kind="telemetry", source="wtmp")
    stats.record_duplicate(kind="telemetry", source="journald")

    assert stats.duplicate_count == 0
    assert stats.telemetry_duplicate_count == 2
    assert stats.duplicate_breakdown_by_source == {}
    assert stats.duplicate_breakdown_by_kind == {}


def test_parse_fail_breakdown_tracks_source_and_reason():
    stats = SystemStats()

    stats.record_parse_fail(source="auditd", reason="normalize_none")
    stats.record_parse_fail(source="auditd", reason="normalize_none")
    stats.record_parse_fail(source="mail", reason="normalize_none")

    assert stats.parse_fail_count == 3
    assert stats.parse_fail_breakdown_by_source == {"auditd": 2, "mail": 1}
    assert stats.parse_fail_breakdown_by_reason == {"normalize_none": 3}


def test_parse_fail_breakdown_tracks_parser_distro_path_and_sample():
    stats = SystemStats()

    stats.record_parse_fail(
        source="postgresql",
        reason="normalize_none",
        parser="file",
        distro_family="debian",
        path="/var/log/postgresql/postgresql-16-main.log",
        sample="password=*** token=*** connection refused",
    )

    assert stats.parse_fail_breakdown_by_parser == {"file": 1}
    assert stats.parse_fail_breakdown_by_distro == {"debian": 1}
    assert stats.parse_fail_breakdown_by_path == {"/var/log/postgresql/postgresql-16-main.log": 1}
    assert stats.parse_fail_samples == [{
        "source": "postgresql",
        "reason": "normalize_none",
        "parser": "file",
        "distro_family": "debian",
        "path": "/var/log/postgresql/postgresql-16-main.log",
        "sample": "password=*** token=*** connection refused",
    }]


def test_phase_manager_auto_profile_falls_back_to_single_safe_profile(tmp_path):
    pm = PhaseManager(
        config={
            "phase_profile": "auto",
            "phases": {
                "server": {
                    "p1_min_events": 111,
                    "p2_min_events": 222,
                    "p3_min_events": 333,
                },
                "desktop": {
                    "p1_min_events": 9999,
                    "p2_min_events": 9999,
                    "p3_min_events": 9999,
                },
            },
        },
        state_dir=str(tmp_path),
        announce_startup=False,
    )

    assert pm.thresholds.p1_min_events == 111
    assert pm.thresholds.p2_min_events == 222
    assert pm.thresholds.p3_min_events == 333


def test_phase_manager_invalid_profile_does_not_read_whole_phases_dict(tmp_path):
    pm = PhaseManager(
        config={
            "phase_profile": "invalid-profile",
            "phases": {
                "server": {
                    "p1_min_events": 123,
                    "p1_min_hours": 4.0,
                },
                "desktop": {
                    "p1_min_events": 9999,
                    "p1_min_hours": 0.5,
                },
            },
        },
        state_dir=str(tmp_path),
        announce_startup=False,
    )

    assert pm.thresholds.p1_min_events == 123
    assert pm.thresholds.p1_min_hours == 4.0


def test_phase_manager_ambiguous_profile_uses_safe_defaults_instead_of_merging(tmp_path):
    pm = PhaseManager(
        config={
            "phase_profile": "invalid-profile",
            "phases": {
                "desktop": {
                    "p1_min_events": 123,
                    "p2_min_events": 234,
                },
                "lab": {
                    "p1_min_hours": 4.0,
                    "p3_min_events": 345,
                },
            },
        },
        state_dir=str(tmp_path),
        announce_startup=False,
    )

    assert pm.thresholds.p1_min_events == 500
    assert pm.thresholds.p1_min_hours == 2.0
    assert pm.thresholds.p2_min_events == 5000
    assert pm.thresholds.p3_min_events == 10000


def test_phase_manager_save_interval_uses_safe_config_fallback(tmp_path):
    pm_default = PhaseManager(config={}, state_dir=str(tmp_path / "default"), announce_startup=False)
    pm_cfg = PhaseManager(
        config={"phase_save_interval": 25},
        state_dir=str(tmp_path / "cfg"),
        announce_startup=False,
    )
    pm_profile = PhaseManager(
        config={"phases": {"server": {"save_interval": 7}}},
        state_dir=str(tmp_path / "profile"),
        announce_startup=False,
    )
    pm_invalid = PhaseManager(
        config={"phase_save_interval": 0},
        state_dir=str(tmp_path / "invalid"),
        announce_startup=False,
    )

    assert pm_default._save_interval == 100
    assert pm_cfg._save_interval == 25
    assert pm_profile._save_interval == 7
    assert pm_invalid._save_interval == 1


def test_postgres_pool_limits_use_env_with_safe_fallback(monkeypatch):
    created = []

    class FakePool:
        def __init__(self, minconn, maxconn, dsn):
            self.minconn = minconn
            self.maxconn = maxconn
            self.dsn = dsn
            created.append((minconn, maxconn, dsn))

    fake_psycopg2 = SimpleNamespace(pool=SimpleNamespace(ThreadedConnectionPool=FakePool))

    monkeypatch.setattr(dbpg, "HAS_PSYCOPG2", True)
    monkeypatch.setattr(dbpg, "psycopg2", fake_psycopg2)
    monkeypatch.setattr(dbpg.PostgresDatabase, "_run_migrations", lambda self: None)

    monkeypatch.setenv("AEGISCORE_PG_POOL_MIN", "3")
    monkeypatch.setenv("AEGISCORE_PG_POOL_MAX", "12")
    db = dbpg.PostgresDatabase(url="postgresql://user:pass@localhost:5432/db")
    assert created[-1] == (3, 12, "postgresql://user:pass@localhost:5432/db")
    assert db._pool.minconn == 3
    assert db._pool.maxconn == 12

    monkeypatch.setenv("AEGISCORE_PG_POOL_MIN", "14")
    monkeypatch.setenv("AEGISCORE_PG_POOL_MAX", "4")
    fallback_db = dbpg.PostgresDatabase(url="postgresql://user:pass@localhost:5432/db")
    assert created[-1] == (2, 10, "postgresql://user:pass@localhost:5432/db")
    assert fallback_db._pool.minconn == 2
    assert fallback_db._pool.maxconn == 10


def test_phase_0_paths_do_not_compute_unused_continuity(tmp_path, monkeypatch):
    pm = PhaseManager(
        config={
            "phase_profile": "server",
            "phases": {
                "server": {
                    "p1_min_events": 10,
                    "p1_min_hours": 1.0,
                    "p1_min_sources": 2,
                    "p1_max_dup_rate": 0.2,
                },
            },
        },
        state_dir=str(tmp_path),
        announce_startup=False,
    )

    def fail_continuity(_days):
        raise AssertionError("continuity_rate P0->P1 akışında çağrılmamalı")

    monkeypatch.setattr(pm.stats, "continuity_rate", fail_continuity)
    pm.set_external_phase_gate_resolver(lambda _status: {
        "phase_gate_source": "label_training",
        "label_training_gate_ok": True,
        "phase_gate_blockers": [],
        "ready_family_ids": ["ML-AUTH"],
        "ready_family_count": 1,
        "first_training_completed": True,
        "first_evaluation_passed": True,
        "first_shadow_model_ready": True,
        "no_action_contract": True,
    })
    pm.stats.total_events = 10
    pm.stats.start_time -= 3600
    pm.stats.source_counts = {"auth": 5, "process": 5}

    progress = pm.progress_to_next()
    transitioned = pm._check_phase_transition()

    assert progress["next_phase"] == 1
    assert transitioned == 1
