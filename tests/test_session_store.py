import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import fakeredis
from core.session_store import SessionStore


def _store():
    # fakeredis simulates a real Redis server in-process, so SessionStore's
    # Redis-facing code is exercised without needing a live server in CI.
    client = fakeredis.FakeStrictRedis(decode_responses=True)
    return SessionStore(client=client)


def test_empty_history_for_unknown_session():
    store = _store()
    assert store.get_history("unknown") == []


def test_records_and_retrieves_turns_in_order():
    store = _store()
    store.record_turn("s1", "first prompt")
    store.record_turn("s1", "second prompt")
    assert store.get_history("s1") == ["first prompt", "second prompt"]


def test_sessions_are_isolated():
    store = _store()
    store.record_turn("s1", "prompt for s1")
    store.record_turn("s2", "prompt for s2")
    assert store.get_history("s1") == ["prompt for s1"]
    assert store.get_history("s2") == ["prompt for s2"]


def test_history_capped_at_max_per_session():
    store = _store()
    for i in range(15):
        store.record_turn("s1", f"prompt {i}")
    history = store.get_history("s1")
    assert len(history) == 10
    # Oldest entries are dropped, most recent 10 kept in order.
    assert history == [f"prompt {i}" for i in range(5, 15)]


def test_empty_session_id_is_a_noop():
    store = _store()
    store.record_turn("", "should not be stored")
    assert store.get_history("") == []


class _BrokenClient:
    """Simulates a Redis outage - every call raises."""
    def lrange(self, *a, **kw):
        raise ConnectionError("redis unavailable")

    def pipeline(self):
        raise ConnectionError("redis unavailable")


def test_get_history_degrades_to_empty_on_redis_failure():
    store = SessionStore(client=_BrokenClient())
    assert store.get_history("s1") == []


def test_record_turn_does_not_raise_on_redis_failure():
    store = SessionStore(client=_BrokenClient())
    store.record_turn("s1", "prompt")  # should not raise
