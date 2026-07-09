import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.rate_limit import RateLimiter


def test_allows_requests_under_the_limit():
    limiter = RateLimiter(max_requests=3, window_seconds=60.0)
    assert limiter.check("client-a") is True
    assert limiter.check("client-a") is True
    assert limiter.check("client-a") is True


def test_blocks_requests_over_the_limit():
    limiter = RateLimiter(max_requests=2, window_seconds=60.0)
    assert limiter.check("client-a") is True
    assert limiter.check("client-a") is True
    assert limiter.check("client-a") is False


def test_clients_are_tracked_independently():
    limiter = RateLimiter(max_requests=1, window_seconds=60.0)
    assert limiter.check("client-a") is True
    assert limiter.check("client-b") is True
    assert limiter.check("client-a") is False
    assert limiter.check("client-b") is False


def test_old_hits_expire_out_of_the_window():
    now = [1000.0]
    limiter = RateLimiter(max_requests=1, window_seconds=10.0, time_fn=lambda: now[0])
    assert limiter.check("client-a") is True
    assert limiter.check("client-a") is False
    now[0] += 11.0
    assert limiter.check("client-a") is True
