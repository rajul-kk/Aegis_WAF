import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from backend.main import app


def test_feed_receives_broadcast_of_chat_result():
    with TestClient(app) as client:
        with client.websocket_connect("/ws/feed") as ws:
            resp = client.post(
                "/api/chat",
                json={"prompt": "DROP TABLE users;", "session_id": "test_backend_feed"},
            )
            body = resp.json()
            fed = ws.receive_json()
            assert fed == body
