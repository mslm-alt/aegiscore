#!/usr/bin/env python3
"""
tests/test_ip_block_state.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Blocked IP state akış testi (in-memory mock DB — PostgreSQL gerektirmez).
"""

import sys
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

# ── In-memory mock DB ─────────────────────────────────────────────────────────

class MockDB:
    is_connected = True

    def __init__(self):
        self._store: Dict[int, Dict] = {}
        self._seq = 0

    def add_ip_block_suggestion(self, ip, reason="", source="alert",
                                 alert_id=None, abuse_score=None,
                                 abuse_reports=None, abuse_country="",
                                 abuse_raw=None) -> Optional[int]:
        if not ip:
            return None
        for rec in self._store.values():
            if rec["ip"] == ip and not rec["reviewed"]:
                rec.update(reason=reason, source=source, suggested_at=time.time())
                return rec["id"]
        self._seq += 1
        self._store[self._seq] = {
            "id": self._seq, "ip": ip, "reason": reason, "source": source,
            "alert_id": alert_id, "abuse_score": abuse_score,
            "abuse_reports": abuse_reports, "abuse_country": abuse_country,
            "abuse_raw": abuse_raw, "suggested_at": time.time(),
            "reviewed": False, "reviewed_at": None, "action": None,
        }
        return self._seq

    def get_ip_block_suggestions(self, reviewed=False, limit=100) -> List[Dict]:
        return [dict(r) for r in self._store.values()
                if r["reviewed"] == reviewed][:limit]

    def get_blocked_ip_suggestions(self, limit=100) -> List[Dict]:
        return [dict(r) for r in self._store.values()
                if r["reviewed"] and r["action"] == "blocked"][:limit]

    def review_ip_block_suggestion(self, suggestion_id: int, action: str) -> bool:
        if action not in ("blocked", "ignored"):
            return False
        rec = self._store.get(suggestion_id)
        if not rec:
            return False
        rec["reviewed"] = True
        rec["reviewed_at"] = time.time()
        rec["action"] = action
        return True

    def get_blocked_ips(self) -> List[str]:
        return list(dict.fromkeys(
            r["ip"] for r in self.get_blocked_ip_suggestions(limit=10000)
            if r.get("ip")
        ))


class StubBridge:
    def __init__(self, db=None):
        self._db = db
        self._connected = db is not None

    @property
    def is_connected(self): return self._connected

    def get_ip_block_suggestions(self, reviewed=False, limit=200):
        if not self.is_connected: return []
        return self._db.get_ip_block_suggestions(reviewed=reviewed, limit=limit)

    def get_blocked_ip_suggestions(self, limit=200):
        if not self.is_connected: return []
        return self._db.get_blocked_ip_suggestions(limit=limit)

    def add_ip_block_suggestion(self, ip, reason="", source="manual"):
        if not self.is_connected: return None
        return self._db.add_ip_block_suggestion(ip=ip, reason=reason, source=source)

    def review_ip_block_suggestion(self, suggestion_id, action):
        if not self.is_connected: return False
        return self._db.review_ip_block_suggestion(suggestion_id, action)

    def get_blocked_ips(self):
        if not self.is_connected: return []
        return self._db.get_blocked_ips()


# ── Pytest test functions ─────────────────────────────────────────────────────

def test_add_appears_in_pending_not_blocked():
    db = MockDB()
    sid = db.add_ip_block_suggestion(ip="1.2.3.4", reason="scan", source="alert")
    assert sid is not None
    assert any(r["ip"] == "1.2.3.4" for r in db.get_ip_block_suggestions(reviewed=False))
    assert not any(r["ip"] == "1.2.3.4" for r in db.get_blocked_ip_suggestions())
    assert "1.2.3.4" not in db.get_blocked_ips()


def test_review_blocked_appears_in_blocked_and_fw():
    db = MockDB()
    sid = db.add_ip_block_suggestion(ip="1.2.3.4", reason="scan", source="alert")
    assert db.review_ip_block_suggestion(sid, "blocked")
    assert not any(r["ip"] == "1.2.3.4" for r in db.get_ip_block_suggestions(reviewed=False))
    assert any(r["ip"] == "1.2.3.4" for r in db.get_blocked_ip_suggestions())
    assert "1.2.3.4" in db.get_blocked_ips()


def test_unblock_ignored_disappears_from_blocked_and_fw():
    db = MockDB()
    sid = db.add_ip_block_suggestion(ip="1.2.3.4", reason="scan", source="alert")
    db.review_ip_block_suggestion(sid, "blocked")
    assert db.review_ip_block_suggestion(sid, "ignored")
    assert not any(r["ip"] == "1.2.3.4" for r in db.get_blocked_ip_suggestions())
    assert "1.2.3.4" not in db.get_blocked_ips()
    # remains in history
    history = db.get_ip_block_suggestions(reviewed=True)
    assert any(r["ip"] == "1.2.3.4" and r["action"] == "ignored" for r in history)


def test_ignored_history_does_not_leak_into_blocked():
    db = MockDB()
    for ip in ("1.2.3.4", "9.8.7.6"):
        hid = db.add_ip_block_suggestion(ip=ip, reason="old", source="alert")
        db.review_ip_block_suggestion(hid, "ignored")
    # Add a legitimately blocked IP
    bid = db.add_ip_block_suggestion(ip="5.5.5.5", reason="ioc", source="ioc")
    db.review_ip_block_suggestion(bid, "blocked")

    blocked = db.get_blocked_ip_suggestions()
    fw = db.get_blocked_ips()
    assert all(r["ip"] not in ("1.2.3.4", "9.8.7.6") for r in blocked)
    assert "1.2.3.4" not in fw and "9.8.7.6" not in fw
    assert "5.5.5.5" in fw


def test_idempotent_add_no_duplicate():
    db = MockDB()
    id1 = db.add_ip_block_suggestion(ip="7.7.7.7", reason="r1", source="alert")
    id2 = db.add_ip_block_suggestion(ip="7.7.7.7", reason="r2", source="alert")
    assert id1 == id2
    pending = [r for r in db.get_ip_block_suggestions(reviewed=False) if r["ip"] == "7.7.7.7"]
    assert len(pending) == 1


def test_invalid_action_rejected():
    db = MockDB()
    sid = db.add_ip_block_suggestion(ip="10.0.0.1", reason="t", source="manual")
    for bad in ("approved", "deleted", "", "BLOCKED"):
        assert db.review_ip_block_suggestion(sid, bad) is False


def test_bridge_offline_returns_safe_defaults():
    bridge = StubBridge(db=None)
    assert bridge.get_ip_block_suggestions(reviewed=False) == []
    assert bridge.get_blocked_ip_suggestions() == []
    assert bridge.get_blocked_ips() == []
    assert bridge.add_ip_block_suggestion("1.1.1.1") is None
    assert bridge.review_ip_block_suggestion(1, "blocked") is False


def test_bridge_online_full_cycle():
    db = MockDB()
    bridge = StubBridge(db=db)
    bid = bridge.add_ip_block_suggestion("8.8.8.8", reason="test", source="manual")
    assert bid is not None
    assert any(r["ip"] == "8.8.8.8" for r in bridge.get_ip_block_suggestions(reviewed=False))
    assert bridge.review_ip_block_suggestion(bid, "blocked")
    assert "8.8.8.8" in bridge.get_blocked_ips()
    assert bridge.review_ip_block_suggestion(bid, "ignored")
    assert "8.8.8.8" not in bridge.get_blocked_ips()
