"""Durable per-session prompt history for context_analyzer's multi-turn
reasoning. Replaces the old in-memory, process-local _SESSION_HISTORY dict
so history survives restarts and is shared across worker processes."""
import os
from typing import List, Optional

try:
    import redis as _redis
    from redis.backoff import NoBackoff as _NoBackoff
    from redis.retry import Retry as _Retry
except Exception:
    _redis = None

_MAX_HISTORY_PER_SESSION = 10
_SESSION_TTL_SECONDS = 24 * 60 * 60
_KEY_PREFIX = "aegis:session:"


class SessionStore:
    def __init__(self, client=None, redis_url: Optional[str] = None):
        if client is not None:
            self._client = client
        else:
            if _redis is None:
                raise RuntimeError("redis package is required unless a client is injected")
            url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
            # Short, no-retry timeouts: this is on the hot path of every WAF
            # request, so a Redis outage must fail in milliseconds, not the
            # default multi-second retry/backoff behavior.
            self._client = _redis.from_url(
                url,
                decode_responses=True,
                socket_connect_timeout=0.2,
                socket_timeout=0.2,
                retry_on_timeout=False,
                retry_on_error=[],
                retry=_Retry(_NoBackoff(), 0),
            )

    def _key(self, session_id: str) -> str:
        return f"{_KEY_PREFIX}{session_id}"

    def get_history(self, session_id: str) -> List[str]:
        if not session_id:
            return []
        try:
            return self._client.lrange(self._key(session_id), 0, -1)
        except Exception as e:
            # Missing multi-turn context degrades context_analyzer's
            # reasoning quality, but it's not a security-critical failure -
            # a Redis outage shouldn't take down the whole WAF request path.
            print(f"[SESSION_STORE] get_history failed, degrading to empty history: {e}")
            return []

    def record_turn(self, session_id: str, prompt: str) -> None:
        if not session_id:
            return
        key = self._key(session_id)
        try:
            # Oldest-first order preserved: RPUSH appends, LTRIM keeps the
            # most recent _MAX_HISTORY_PER_SESSION entries via negative indices.
            pipe = self._client.pipeline()
            pipe.rpush(key, prompt)
            pipe.ltrim(key, -_MAX_HISTORY_PER_SESSION, -1)
            pipe.expire(key, _SESSION_TTL_SECONDS)
            pipe.execute()
        except Exception as e:
            print(f"[SESSION_STORE] record_turn failed, this turn won't be in future history: {e}")
