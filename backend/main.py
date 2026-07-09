import logging
import sys
import os
from contextlib import asynccontextmanager

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from core.gateway import AegisGateway
from backend.connection_manager import ConnectionManager
from backend.rate_limit import RateLimiter
from backend.schemas import ChatRequest
from frontend.examples import load_examples

# Structured (timestamp/level/logger/message), single-line-per-record output -
# every core/agents module logs via logging.getLogger(__name__) and inherits
# this config, so this is the one place that needs to set it.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

manager = ConnectionManager()
chat_rate_limiter = RateLimiter(max_requests=30, window_seconds=60.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.gateway = AegisGateway()
    yield


app = FastAPI(title="Aegis WAF API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/examples")
async def examples():
    return load_examples()


@app.post("/api/chat")
async def chat(req: ChatRequest, request: Request):
    client_key = request.client.host if request.client else "unknown"
    if not chat_rate_limiter.check(client_key):
        raise HTTPException(status_code=429, detail="Rate limit exceeded, try again shortly")

    gateway: AegisGateway = app.state.gateway
    try:
        result = await run_in_threadpool(
            gateway.chat, req.prompt, session_id=req.session_id, context=req.context
        )
    except Exception as e:
        result = {"error": str(e)}
    await manager.broadcast(result)
    return result


@app.websocket("/ws/feed")
async def feed(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
