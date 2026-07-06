import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from backend.main import app


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
