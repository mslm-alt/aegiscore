from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import ui.backend_facade as backend_facade


class _FakeDb:
    def close(self):
        return None


def test_collect_ip_reputation_status_schema_and_secret_masking(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {
        "config": {
            "abuseipdb": {"enrich_alert_ips": True},
            "ip_blocking": {"enabled": True, "default_backend": "auto", "real_backend": "firewalld"},
        }
    })
    monkeypatch.setattr(backend_facade.ip_actions, "preview_guarded_ip_action", lambda **kwargs: {
        "capability": {
            "backend": "firewalld",
            "real_apply_supported": True,
            "dry_run_supported": True,
            "reason": "ready",
        }
    })
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "super-secret-abcd")

    result = backend_facade.collect_ip_reputation_status()

    assert result["status"] in {"ok", "degraded"}
    assert {"status", "abuseipdb", "ip_blocking", "security_locks", "error"} <= set(result)
    assert result["abuseipdb"]["has_api_key"] is True
    assert result["abuseipdb"]["key_masked"].endswith("abcd")
    assert "super-secret-abcd" not in backend_facade._stringify_payload(result)


def test_collect_ip_block_suggestions_missing_table_graceful(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _FakeDb())
    monkeypatch.setattr(backend_facade, "_table_columns", lambda db, table_name: (set(), ["missing_table"]))

    result = backend_facade.collect_ip_block_suggestions(limit=20)

    assert result["status"] == "degraded"
    assert result["suggestions"] == []
    assert result["empty"] is True


def test_collect_ip_block_actions_missing_table_graceful(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _FakeDb())
    monkeypatch.setattr(backend_facade, "_table_columns", lambda db, table_name: (set(), ["missing_table"]))

    result = backend_facade.collect_ip_block_actions(limit=20)

    assert result["status"] == "degraded"
    assert result["actions"] == []
    assert result["empty"] is True


def test_collect_ip_context_empty_ip_graceful():
    result = backend_facade.collect_ip_context("", limit=20)

    assert result["status"] == "ok"
    assert result["ip"] == ""
    assert result["related_alerts"] == []
    assert result["related_events"] == []


def test_collect_ip_block_candidates_dedupes_and_classifies(monkeypatch):
    class _Db(_FakeDb):
        def get_active_ip_block(self, ip):
            if ip == "9.9.9.9":
                return {"backend": "firewalld", "status": "applied"}
            return None

        def get_alert_by_id(self, alert_id):
            if alert_id == 11:
                return {
                    "id": 11,
                    "rule_id": "RULE-11",
                    "severity": "high",
                    "risk_score": 95.0,
                    "message": "ssh brute force",
                }
            return None

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _Db())
    monkeypatch.setattr(backend_facade, "collect_ip_block_suggestions", lambda **kwargs: {
        "status": "ok",
        "suggestions": [
            {"id": 2, "ip": "9.9.9.9", "reason": "repeat offender", "source": "manual", "alert_id": 11, "timestamp_text": "2026-05-19 12:10:00", "created_at": 20},
            {"id": 1, "ip": "9.9.9.9", "reason": "duplicate", "source": "manual", "alert_id": 11, "timestamp_text": "2026-05-19 12:00:00", "created_at": 10},
            {"id": 3, "ip": "8.8.8.8", "reason": "candidate", "source": "manual", "alert_id": 11, "timestamp_text": "2026-05-19 12:20:00", "created_at": 30},
        ],
        "error": None,
    })
    monkeypatch.setattr(backend_facade.ip_actions, "preview_guarded_ip_action", lambda **kwargs: {
        "capability": {
            "backend": "firewalld",
            "real_apply_supported": True,
            "dry_run_supported": True,
            "reason": "ready",
        },
        "ip_validation": {"allowed": True},
    })

    result = backend_facade.collect_ip_block_candidates(limit=10)

    assert result["status"] == "ok"
    assert [item["ip"] for item in result["candidates"]] == ["8.8.8.8", "9.9.9.9"]
    assert result["candidates"][0]["status"] == "not_blocked"
    assert result["candidates"][0]["rule_id"] == "RULE-11"
    assert result["candidates"][1]["status"] == "blocked"
    assert result["candidates"][1]["can_unblock"] is True


def test_collect_ip_block_candidates_ufw_blocked_can_unblock(monkeypatch):
    class _Db(_FakeDb):
        def get_active_ip_block(self, ip):
            if ip == "8.8.8.8":
                return {"backend": "ufw", "status": "applied"}
            return None

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _Db())
    monkeypatch.setattr(backend_facade, "collect_ip_block_suggestions", lambda **kwargs: {
        "status": "ok",
        "suggestions": [
            {"id": 1, "ip": "8.8.8.8", "reason": "candidate", "source": "manual", "alert_id": 11, "timestamp_text": "2026-05-19 12:20:00", "created_at": 30},
        ],
        "error": None,
    })
    monkeypatch.setattr(backend_facade.ip_actions, "preview_guarded_ip_action", lambda **kwargs: {
        "capability": {
            "backend": "ufw",
            "real_apply_supported": True,
            "dry_run_supported": True,
            "backend_supported": True,
            "requires_elevation": False,
            "reason": "ready",
            "message": "",
        },
        "ip_validation": {"allowed": True},
    })

    result = backend_facade.collect_ip_block_candidates(limit=10)

    assert result["status"] == "ok"
    assert result["candidates"][0]["status"] == "blocked"
    assert result["candidates"][0]["can_unblock"] is True


def test_collect_ip_block_candidates_elevated_privileges_keep_block_enabled(monkeypatch):
    class _Db(_FakeDb):
        def get_active_ip_block(self, ip):
            return None

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _Db())
    monkeypatch.setattr(backend_facade, "collect_ip_block_suggestions", lambda **kwargs: {
        "status": "ok",
        "suggestions": [
            {"id": 1, "ip": "8.8.8.8", "reason": "candidate", "source": "manual", "alert_id": 11, "timestamp_text": "2026-05-19 12:20:00", "created_at": 30},
        ],
        "error": None,
    })
    monkeypatch.setattr(backend_facade.ip_actions, "preview_guarded_ip_action", lambda **kwargs: {
        "capability": {
            "backend": "ufw",
            "real_apply_supported": False,
            "dry_run_supported": True,
            "backend_supported": True,
            "requires_elevation": True,
            "reason": "elevated_privileges_required",
            "message": "AegisCore must be run with elevated privileges to apply firewall rules.",
        },
        "ip_validation": {"allowed": True},
    })

    result = backend_facade.collect_ip_block_candidates(limit=10)

    assert result["status"] == "ok"
    candidate = result["candidates"][0]
    assert candidate["status"] == "elevated_privileges_required"
    assert candidate["can_block"] is True
    assert candidate["backend_capability"] == "AegisCore must be run with elevated privileges to apply firewall rules."


def test_collect_ip_block_candidates_includes_dynamic_alert_source_ips(monkeypatch):
    class _Db(_FakeDb):
        def get_recent_alerts(self, limit=0, hours=0):
            return [
                {
                    "id": 51,
                    "created_at": 200,
                    "severity": "high",
                    "rule_id": "AUTH-BRUTE-1",
                    "risk_score": 88.0,
                    "source_ip": "8.8.8.8",
                    "source": "auth_log",
                    "message": "SSH brute force attack detected",
                }
            ]

        def get_active_ip_block(self, ip):
            return None

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _Db())
    monkeypatch.setattr(backend_facade, "collect_ip_block_suggestions", lambda **kwargs: {"status": "ok", "suggestions": [], "error": None})
    monkeypatch.setattr(backend_facade.ip_actions, "preview_guarded_ip_action", lambda **kwargs: {
        "capability": {"backend": "firewalld", "real_apply_supported": True, "dry_run_supported": True, "reason": "ready"},
        "ip_validation": {"allowed": True},
    })

    result = backend_facade.collect_ip_block_candidates(limit=10)

    assert result["status"] == "ok"
    assert len(result["candidates"]) == 1
    candidate = result["candidates"][0]
    assert candidate["ip"] == "8.8.8.8"
    assert candidate["source"] == "alert"
    assert candidate["alert_id"] == 51
    assert candidate["rule_id"] == "AUTH-BRUTE-1"
    assert candidate["severity"] == "high"
    assert candidate["risk_score"] == 88.0
    assert candidate["related_alert_count"] == 1


def test_collect_ip_block_candidates_excludes_private_and_ml_alerts(monkeypatch):
    class _Db(_FakeDb):
        def get_recent_alerts(self, limit=0, hours=0):
            return [
                {
                    "id": 61,
                    "created_at": 200,
                    "severity": "critical",
                    "rule_id": "RULE-PRIVATE-1",
                    "risk_score": 99.0,
                    "source_ip": "10.0.0.8",
                    "source": "auth_log",
                    "message": "Suspicious private source",
                },
                {
                    "id": 62,
                    "created_at": 210,
                    "severity": "high",
                    "rule_id": "ML-AUTH-001",
                    "risk_score": 85.0,
                    "source_ip": "8.8.4.4",
                    "source": "ml",
                    "message": "Behavioral anomaly",
                },
            ]

        def get_active_ip_block(self, ip):
            return None

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _Db())
    monkeypatch.setattr(backend_facade, "collect_ip_block_suggestions", lambda **kwargs: {"status": "ok", "suggestions": [], "error": None})
    monkeypatch.setattr(backend_facade.ip_actions, "preview_guarded_ip_action", lambda **kwargs: {
        "capability": {"backend": "firewalld", "real_apply_supported": True, "dry_run_supported": True, "reason": "ready"},
        "ip_validation": {"allowed": True},
    })

    result = backend_facade.collect_ip_block_candidates(limit=10)

    assert result["status"] == "ok"
    assert result["candidates"] == []


def test_collect_ip_block_candidates_merges_duplicate_alerts_and_existing_suggestion(monkeypatch):
    class _Db(_FakeDb):
        def get_recent_alerts(self, limit=0, hours=0):
            return [
                {
                    "id": 71,
                    "created_at": 100,
                    "severity": "medium",
                    "rule_id": "AUTH-FAIL-1",
                    "risk_score": 65.0,
                    "source_ip": "8.8.8.8",
                    "source": "auth_log",
                    "message": "Failed login attempts from remote IP",
                },
                {
                    "id": 72,
                    "created_at": 200,
                    "severity": "critical",
                    "rule_id": "AUTH-BRUTE-2",
                    "risk_score": 91.0,
                    "source_ip": "8.8.8.8",
                    "source": "auth_log",
                    "message": "SSH brute force attack detected",
                },
            ]

        def get_active_ip_block(self, ip):
            return None

        def get_alert_by_id(self, alert_id):
            return None

    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _Db())
    monkeypatch.setattr(backend_facade, "collect_ip_block_suggestions", lambda **kwargs: {
        "status": "ok",
        "suggestions": [
            {
                "id": 8,
                "ip": "8.8.8.8",
                "reason": "Operator flagged remote attacker",
                "source": "abuseipdb",
                "alert_id": "",
                "timestamp_text": "2026-05-19 12:40:00",
                "created_at": 300,
            }
        ],
        "error": None,
    })
    monkeypatch.setattr(backend_facade.ip_actions, "preview_guarded_ip_action", lambda **kwargs: {
        "capability": {"backend": "firewalld", "real_apply_supported": True, "dry_run_supported": True, "reason": "ready"},
        "ip_validation": {"allowed": True},
    })

    result = backend_facade.collect_ip_block_candidates(limit=10)

    assert result["status"] == "ok"
    assert len(result["candidates"]) == 1
    candidate = result["candidates"][0]
    assert candidate["ip"] == "8.8.8.8"
    assert candidate["source"] == "abuseipdb"
    assert candidate["related_alert_count"] == 2
    assert candidate["alert_id"] == 72
    assert candidate["rule_id"] == "AUTH-BRUTE-2"
    assert candidate["severity"] == "critical"
    assert candidate["risk_score"] == 91.0
    assert candidate["reason"] == "Operator flagged remote attacker"
    assert candidate["first_seen"] == 100
    assert candidate["last_seen"] == 200


def test_build_ip_action_preview_schema(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {
        "config": {"ip_blocking": {"enabled": True, "default_backend": "firewalld", "real_backend": "firewalld"}},
    })
    monkeypatch.setattr(backend_facade.ip_actions, "preview_guarded_ip_action", lambda **kwargs: {
        "status": "denied",
        "action": "block",
        "ip": "1.2.3.4",
        "guard": {"action_type": "ip_block", "required_guards": ["actor", "reason", "typed confirmation"]},
        "message": "preview",
    })

    result = backend_facade.build_ip_action_preview("1.2.3.4", "block")

    assert result["status"] == "denied"
    assert result["ip"] == "1.2.3.4"
    assert result["action"] == "block"
    assert "typed confirmation" in result["would_require"]
    assert result["guard_result"]["action_type"] == "ip_block"


def test_ip_reputation_no_write_guard_backend_facade_source():
    source = Path("ui/backend_facade.py").read_text(encoding="utf-8").lower()
    forbidden_tokens = [
        "abuseipdbclient(",
        "ipblocker(",
        "review_ip_block_suggestion(",
        "add_ip_block_suggestion(",
        "add_ip_block_action(",
        "block_ip(",
        "unblock_ip(",
        ".commit(",
        "insert into ip_block_suggestions",
        "insert into ip_block_actions",
        "update ip_block_suggestions",
        "delete from ip_block",
        "close_incident(",
        "reset_database(",
    ]

    for token in forbidden_tokens:
        assert token not in source
