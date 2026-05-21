import json

from core.normalize import Normalizer
from main import SIEMPipeline


def _make_pipeline(enabled=True, window_seconds=5):
    pipeline = SIEMPipeline.__new__(SIEMPipeline)
    pipeline._auth_shadow_dedup_enabled = enabled
    pipeline._auth_shadow_peer_cache = {}
    pipeline._auth_shadow_peer_ttl = window_seconds
    pipeline._shadow_dedup_stats = {
        "shadow_dedup_peer_cached": {"total": 0, "by_source": {}},
        "shadow_dedup_suppressed": {"total": 0, "by_source": {}},
        "shadow_dedup_kept_no_peer": {"total": 0, "by_source": {}},
        "shadow_dedup_kept_high_priority": {"total": 0, "by_source": {}},
    }
    return pipeline


def test_wtmp_suppressed_after_matching_journald_peer():
    normalizer = Normalizer()
    pipeline = _make_pipeline()
    now = 100.0

    journald_raw = json.dumps({
        "__REALTIME_TIMESTAMP": "1710000000123456",
        "MESSAGE": "Accepted password for alice from 192.168.1.10 port 22 ssh2",
        "_COMM": "sshd",
        "_PID": "1234",
        "_HOSTNAME": "node-1",
        "_SYSTEMD_UNIT": "sshd.service",
        "SYSLOG_IDENTIFIER": "sshd",
    })
    journald_evt = normalizer.normalize(journald_raw, "journald")
    wtmp_evt = normalizer.normalize(
        "alice    pts/0        192.168.1.10     Mon Mar  5 12:34   still logged in",
        "wtmp"
    )

    assert pipeline._should_suppress_wtmp_shadow_copy(journald_evt, now) is False
    assert pipeline._should_suppress_wtmp_shadow_copy(wtmp_evt, now + 1) is True
    assert pipeline._shadow_dedup_stats["shadow_dedup_peer_cached"] == {
        "total": 1,
        "by_source": {"auth_log": 1},
    }
    assert pipeline._shadow_dedup_stats["shadow_dedup_kept_high_priority"] == {
        "total": 1,
        "by_source": {"auth_log": 1},
    }
    assert pipeline._shadow_dedup_stats["shadow_dedup_suppressed"] == {
        "total": 1,
        "by_source": {"accounting": 1},
    }
    assert pipeline._shadow_dedup_stats["shadow_dedup_kept_no_peer"]["total"] == 0


def test_btmp_suppressed_after_matching_auth_log_peer():
    normalizer = Normalizer()
    pipeline = _make_pipeline()
    now = 100.0

    auth_evt = normalizer.normalize(
        "Mar  5 12:35:00 host sshd[1235]: Failed password for root from 203.0.113.5 port 54321 ssh2",
        "auth.log"
    )
    btmp_evt = normalizer.normalize(
        "root     ssh:notty    203.0.113.5      Mon Mar  5 12:35 - 12:35  (00:00)",
        "btmp"
    )

    assert pipeline._should_suppress_wtmp_shadow_copy(auth_evt, now) is False
    assert pipeline._should_suppress_wtmp_shadow_copy(btmp_evt, now + 1) is True
    assert pipeline._shadow_dedup_stats["shadow_dedup_peer_cached"]["by_source"] == {"auth_log": 1}
    assert pipeline._shadow_dedup_stats["shadow_dedup_suppressed"]["by_source"] == {"accounting": 1}


def test_wtmp_not_suppressed_without_matching_high_priority_peer():
    normalizer = Normalizer()
    pipeline = _make_pipeline()

    wtmp_evt = normalizer.normalize(
        "alice    pts/0        192.168.1.10     Mon Mar  5 12:34   still logged in",
        "wtmp"
    )

    assert pipeline._should_suppress_wtmp_shadow_copy(wtmp_evt, 100.0) is False
    assert pipeline._shadow_dedup_stats["shadow_dedup_kept_no_peer"] == {
        "total": 1,
        "by_source": {"accounting": 1},
    }


def test_high_priority_sources_do_not_suppress_each_other():
    normalizer = Normalizer()
    pipeline = _make_pipeline()
    now = 100.0

    journald_raw = json.dumps({
        "__REALTIME_TIMESTAMP": "1710000000123456",
        "MESSAGE": "Accepted password for alice from 192.168.1.10 port 22 ssh2",
        "_COMM": "sshd",
        "_PID": "1234",
        "_HOSTNAME": "node-1",
        "_SYSTEMD_UNIT": "sshd.service",
        "SYSLOG_IDENTIFIER": "sshd",
    })
    journald_evt = normalizer.normalize(journald_raw, "journald")
    auth_evt = normalizer.normalize(
        "Mar  5 12:34:56 host sshd[1]: Accepted password for alice from 192.168.1.10 port 22 ssh2",
        "auth.log"
    )

    assert pipeline._should_suppress_wtmp_shadow_copy(journald_evt, now) is False
    assert pipeline._should_suppress_wtmp_shadow_copy(auth_evt, now + 1) is False
    assert pipeline._shadow_dedup_stats["shadow_dedup_peer_cached"] == {
        "total": 2,
        "by_source": {"auth_log": 2},
    }
    assert pipeline._shadow_dedup_stats["shadow_dedup_kept_high_priority"] == {
        "total": 2,
        "by_source": {"auth_log": 2},
    }
    assert pipeline._shadow_dedup_stats["shadow_dedup_suppressed"]["total"] == 0


def test_disabled_shadow_dedup_skips_cache_and_suppression():
    normalizer = Normalizer()
    pipeline = _make_pipeline(enabled=False, window_seconds=5)
    now = 100.0

    journald_raw = json.dumps({
        "__REALTIME_TIMESTAMP": "1710000000123456",
        "MESSAGE": "Accepted password for alice from 192.168.1.10 port 22 ssh2",
        "_COMM": "sshd",
        "_PID": "1234",
        "_HOSTNAME": "node-1",
        "_SYSTEMD_UNIT": "sshd.service",
        "SYSLOG_IDENTIFIER": "sshd",
    })
    journald_evt = normalizer.normalize(journald_raw, "journald")
    wtmp_evt = normalizer.normalize(
        "alice    pts/0        192.168.1.10     Mon Mar  5 12:34   still logged in",
        "wtmp"
    )

    assert pipeline._should_suppress_wtmp_shadow_copy(journald_evt, now) is False
    assert pipeline._should_suppress_wtmp_shadow_copy(wtmp_evt, now + 1) is False
    assert pipeline._auth_shadow_peer_cache == {}
    assert all(bucket["total"] == 0 for bucket in pipeline._shadow_dedup_stats.values())


def test_shadow_dedup_window_seconds_controls_matching():
    normalizer = Normalizer()
    pipeline = _make_pipeline(enabled=True, window_seconds=1)
    now = 100.0

    auth_evt = normalizer.normalize(
        "Mar  5 12:35:00 host sshd[1235]: Failed password for root from 203.0.113.5 port 54321 ssh2",
        "auth.log"
    )
    btmp_evt = normalizer.normalize(
        "root     ssh:notty    203.0.113.5      Mon Mar  5 12:35 - 12:35  (00:00)",
        "btmp"
    )

    assert pipeline._should_suppress_wtmp_shadow_copy(auth_evt, now) is False
    assert pipeline._should_suppress_wtmp_shadow_copy(btmp_evt, now + 2) is False
    assert pipeline._shadow_dedup_stats["shadow_dedup_peer_cached"]["total"] == 1
    assert pipeline._shadow_dedup_stats["shadow_dedup_suppressed"]["total"] == 0
    assert pipeline._shadow_dedup_stats["shadow_dedup_kept_no_peer"]["by_source"] == {"accounting": 1}


def test_auth_shadow_dedup_acceptance_enabled_vs_disabled():
    normalizer = Normalizer()
    enabled_pipeline = _make_pipeline(enabled=True, window_seconds=5)
    disabled_pipeline = _make_pipeline(enabled=False, window_seconds=5)
    now = 100.0

    auth_evt = normalizer.normalize(
        "Mar  5 12:35:00 host sshd[1235]: Failed password for root from 203.0.113.5 port 54321 ssh2",
        "auth.log"
    )
    btmp_evt = normalizer.normalize(
        "root     ssh:notty    203.0.113.5      Mon Mar  5 12:35 - 12:35  (00:00)",
        "btmp"
    )

    # Regression guard: metadata cleanup must not change auth detection semantics.
    assert auth_evt.category == "auth"
    assert auth_evt.action == "ssh_login"
    assert auth_evt.outcome == "failure"
    assert auth_evt.fields["metadata"]["duplicate_candidate"]["source_class"] == "auth_log"
    assert btmp_evt.action == "login"
    assert btmp_evt.outcome == "failure"

    # Enabled: high-priority auth_log is kept, matching accounting shadow copy is suppressed.
    assert enabled_pipeline._should_suppress_wtmp_shadow_copy(auth_evt, now) is False
    assert enabled_pipeline._should_suppress_wtmp_shadow_copy(btmp_evt, now + 1) is True
    assert enabled_pipeline._shadow_dedup_stats == {
        "shadow_dedup_peer_cached": {"total": 1, "by_source": {"auth_log": 1}},
        "shadow_dedup_suppressed": {"total": 1, "by_source": {"accounting": 1}},
        "shadow_dedup_kept_no_peer": {"total": 0, "by_source": {}},
        "shadow_dedup_kept_high_priority": {"total": 1, "by_source": {"auth_log": 1}},
    }

    # Disabled: same high-priority event is still kept, but no peer cache or suppression happens.
    assert disabled_pipeline._should_suppress_wtmp_shadow_copy(auth_evt, now) is False
    assert disabled_pipeline._should_suppress_wtmp_shadow_copy(btmp_evt, now + 1) is False
    assert disabled_pipeline._shadow_dedup_stats == {
        "shadow_dedup_peer_cached": {"total": 0, "by_source": {}},
        "shadow_dedup_suppressed": {"total": 0, "by_source": {}},
        "shadow_dedup_kept_no_peer": {"total": 0, "by_source": {}},
        "shadow_dedup_kept_high_priority": {"total": 0, "by_source": {}},
    }
