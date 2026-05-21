import time

from core.event_queue import EventIngestionQueue


def test_get_does_not_miss_event_arriving_around_wait(monkeypatch):
    q = EventIngestionQueue(maxsize=8)
    original_wait = q._event.wait
    injected = {"done": False}

    def fake_wait(timeout=None):
        if not injected["done"]:
            injected["done"] = True
            q.put("failed password", "auth.log")
        return original_wait(timeout)

    monkeypatch.setattr(q._event, "wait", fake_wait)

    item = q.get(timeout=0.2)

    assert item is not None
    assert item[0] == "failed password"
    assert item[1] == "auth.log"


def test_event_flag_tracks_queue_empty_and_non_empty_states():
    q = EventIngestionQueue(maxsize=8)

    q.put("event one", "auth.log")
    q.put("event two", "auth.log")

    assert q._event.is_set() is True

    first = q.get(timeout=0.01)
    assert first is not None
    assert q.qsize == 1
    assert q._event.is_set() is True

    second = q.get(timeout=0.01)
    assert second is not None
    assert q.qsize == 0
    assert q._event.is_set() is False


def test_get_timeout_behavior_is_preserved_on_empty_queue():
    q = EventIngestionQueue(maxsize=8)

    start = time.time()
    result = q.get(timeout=0.05)
    elapsed = time.time() - start

    assert result is None
    assert elapsed >= 0.04
