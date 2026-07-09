import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
import backend.main as backend_main
from backend.main import app
from backend.rate_limit import RateLimiter


def test_health():
    with TestClient(app) as client:
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


def test_chat_benign_prompt_allowed():
    with TestClient(app) as client:
        resp = client.post(
            "/api/chat",
            json={"prompt": "What is 2+2?", "session_id": "test_backend_1"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["blocked"] is False
        assert "waf_result" in body


def test_chat_attack_prompt_blocked():
    with TestClient(app) as client:
        resp = client.post(
            "/api/chat",
            json={"prompt": "DROP TABLE users;", "session_id": "test_backend_2"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["blocked"] is True
        assert body["waf_result"]["decision"] == "BLOCK"


def test_examples_returns_nonempty_list():
    with TestClient(app) as client:
        resp = client.get("/api/examples")
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)
        assert len(body) > 0
        assert "prompt" in body[0]


def test_chat_rate_limited_returns_429():
    original_limiter = backend_main.chat_rate_limiter
    backend_main.chat_rate_limiter = RateLimiter(max_requests=1, window_seconds=60.0)
    try:
        with TestClient(app) as client:
            first = client.post(
                "/api/chat",
                json={"prompt": "What is 2+2?", "session_id": "test_rate_limit"},
            )
            assert first.status_code == 200

            second = client.post(
                "/api/chat",
                json={"prompt": "What is 2+2?", "session_id": "test_rate_limit"},
            )
            assert second.status_code == 429
    finally:
        backend_main.chat_rate_limiter = original_limiter
