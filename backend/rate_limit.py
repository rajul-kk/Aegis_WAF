"""In-memory sliding-window rate limiter. Local/demo deployment scope (see
docker-compose.yml) - single process, so no shared store needed; a real
multi-worker deployment would back this with Redis instead."""
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Callable, Deque, Dict


class RateLimiter:
    def __init__(
        self,
        max_requests: int = 30,
        window_seconds: float = 60.0,
        time_fn: Callable[[], float] = time.time,
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._time_fn = time_fn
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str) -> bool:
        """Records a hit for `key` and returns whether it's within the
        limit. Returns False (and does not count the hit) if already over."""
        now = self._time_fn()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window_seconds:
                hits.popleft()
            if len(hits) >= self.max_requests:
                return False
            hits.append(now)
            return True
