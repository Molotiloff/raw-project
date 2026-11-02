"""Synthetic-data research gateway. Never expose directly to an untrusted network."""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass

import asyncpg
from fastapi import FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

log = logging.getLogger("gateway")
logging.basicConfig(level=logging.INFO, format="%(message)s")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://gateway:gateway@db:5432/gateway")
MODE = os.getenv("LAB_MODE", "secure")
if MODE not in ("secure", "baseline"):
    raise RuntimeError("LAB_MODE must be secure or baseline")
MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS_PER_CLIENT", "4"))
MAX_RATE = int(os.getenv("MAX_MESSAGES_PER_MINUTE", "60"))
MAX_MESSAGE_BYTES = int(os.getenv("MAX_MESSAGE_BYTES", "4096"))
POLL_SECONDS = float(os.getenv("POLL_SECONDS", "0.5"))
SEND_TIMEOUT = float(os.getenv("SEND_TIMEOUT", "5"))
IDLE_SECONDS = int(os.getenv("IDLE_SECONDS", "60"))

@dataclass(frozen=True)
class Client:
    name: str
    token: str
    objects: frozenset[str]
    producer: bool = False
    metrics: bool = False


def load_clients(raw: str) -> list[Client]:
    value = json.loads(raw)
    if not isinstance(value, list) or not value:
        raise ValueError("CLIENTS_JSON must be a nonempty array")
    clients = [Client(x["name"], x["token"], frozenset(x.get("objects", [])), x.get("producer", False), x.get("metrics", False)) for x in value]
    if any(not c.name or len(c.token) < 16 for c in clients):
        raise ValueError("client names and tokens of at least 16 characters required")
    if len({c.name for c in clients}) != len(clients) or len({c.token for c in clients}) != len(clients):
        raise ValueError("client names and tokens must be unique")
    return clients


def identity(authorization: str | None, clients: list[Client]) -> Client | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    presented = authorization[7:]
    return next((c for c in clients if hmac.compare_digest(c.token, presented)), None)


def allowed(client: Client, object_id: str, mode: str = MODE) -> bool:
    return mode == "baseline" or object_id in client.objects


def audit(action: str, client: str = "unknown", **values):
    log.info(json.dumps({"event": action, "client": client, **values}, ensure_ascii=False))

class Window:
    def __init__(self, limit: int, seconds: int = 60):
        self.limit, self.seconds = limit, seconds
        self.entries = defaultdict(deque)
    def accept(self, key: str) -> bool:
        now = time.monotonic()
        queue = self.entries[key]
        while queue and queue[0] <= now - self.seconds:
            queue.popleft()
        if len(queue) >= self.limit:
            return False
        queue.append(now)
        return True

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.clients = load_clients(os.environ["CLIENTS_JSON"])
    app.state.pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=int(os.getenv("DB_POOL_SIZE", "5")))
    async with app.state.pool.acquire() as conn:
        await conn.execute("""CREATE TABLE IF NOT EXISTS events (
            id BIGSERIAL PRIMARY KEY, object_id TEXT NOT NULL,
            payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())""")
        await conn.execute("CREATE INDEX IF NOT EXISTS events_object_id_id_idx ON events (object_id, id)")
    app.state.connections = defaultdict(int)
    app.state.rate = Window(MAX_RATE)
    yield
    await app.state.pool.close()

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

class EventInput(BaseModel):
    object_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    payload: dict


def require(request: Request, authorization: str | None) -> Client:
    client = identity(authorization, request.app.state.clients)
    if not client:
        audit("auth_denied")
        raise HTTPException(401, "Unauthorized")
    if not request.app.state.rate.accept(client.name):
        audit("rate_limited", client.name)
        raise HTTPException(429, "Rate limit")
    return client


def event_dict(row):
    return {"id": row["id"], "object_id": row["object_id"], "payload": json.loads(row["payload"]), "created_at": row["created_at"].isoformat()}

@app.get("/health/live")
async def live():
    return {"status": "ok"}

@app.get("/health/ready")
async def ready(request: Request):
    try:
        async with request.app.state.pool.acquire(timeout=2) as conn:
            await conn.fetchval("SELECT 1", timeout=2)
        return {"status": "ok"}
    except Exception:
        raise HTTPException(503, "Unavailable")

@app.post("/events", status_code=201)
async def create_event(event: EventInput, request: Request, authorization: str | None = Header(default=None)):
    client = require(request, authorization)
    if not client.producer or not allowed(client, event.object_id):
        audit("publish_denied", client.name, object_id=event.object_id)
        raise HTTPException(403, "Forbidden")
    payload = json.dumps(event.payload, ensure_ascii=False)
    if len(payload.encode()) > MAX_MESSAGE_BYTES:
        raise HTTPException(413, "Too large")
    row = await request.app.state.pool.fetchrow("INSERT INTO events(object_id,payload) VALUES($1,$2::jsonb) RETURNING id,object_id,payload,created_at", event.object_id, payload)
    audit("published", client.name, object_id=event.object_id, event_id=row["id"])
    return event_dict(row)

@app.get("/query")
async def query(request: Request, object_id: str, after: int = 0, limit: int = 50, authorization: str | None = Header(default=None)):
    client = require(request, authorization)
    if not allowed(client, object_id):
        audit("query_denied", client.name, object_id=object_id[:128])
        raise HTTPException(403, "Forbidden")
    if after < 0 or not 1 <= limit <= 100 or len(object_id) > 128:
        raise HTTPException(400, "Invalid query")
    rows = await request.app.state.pool.fetch("SELECT id,object_id,payload,created_at FROM events WHERE object_id=$1 AND id>$2 ORDER BY id LIMIT $3", object_id, after, limit, timeout=3)
    audit("query", client.name, object_id=object_id, count=len(rows))
    return {"events": [event_dict(row) for row in rows], "next_cursor": rows[-1]["id"] if rows else after}

@app.get("/metric", response_class=PlainTextResponse)
async def metric(request: Request, authorization: str | None = Header(default=None)):
    client = require(request, authorization)
    if not client.metrics:
        raise HTTPException(403, "Forbidden")
    return f"gateway_active_connections {sum(request.app.state.connections.values())}\n"

@app.websocket("/subscription")
async def subscription(ws: WebSocket):
    client = identity(ws.headers.get("authorization"), ws.app.state.clients)
    object_id = ws.query_params.get("object_id", "")
    if not client or len(object_id) > 128 or not allowed(client, object_id):
        audit("subscription_denied", client.name if client else "unknown", object_id=object_id[:128])
        await ws.close(code=1008)
        return
    counts = ws.app.state.connections
    if counts[client.name] >= MAX_CONNECTIONS:
        audit("connection_limited", client.name)
        await ws.close(code=1013)
        return
    counts[client.name] += 1
    try:
        # Subscribe from current database position. Clients can use /query for history.
        last_id = await ws.app.state.pool.fetchval("SELECT COALESCE(MAX(id), 0) FROM events WHERE object_id=$1", object_id)
        await ws.accept()
        audit("subscription_open", client.name, object_id=object_id)
        last_activity = time.monotonic()
        while True:
            rows = await ws.app.state.pool.fetch("SELECT id,object_id,payload,created_at FROM events WHERE object_id=$1 AND id>$2 ORDER BY id LIMIT 100", object_id, last_id, timeout=3)
            for row in rows:
                await asyncio.wait_for(ws.send_json({"type": "event", "data": event_dict(row)}), timeout=SEND_TIMEOUT)
                last_id = row["id"]
            if time.monotonic() - last_activity > IDLE_SECONDS:
                await ws.close(code=1001, reason="Heartbeat timeout")
                break
            try:
                message = await asyncio.wait_for(ws.receive_text(), timeout=POLL_SECONDS)
            except asyncio.TimeoutError:
                continue
            if len(message.encode()) > MAX_MESSAGE_BYTES or not ws.app.state.rate.accept(client.name):
                await ws.close(code=1008)
                break
            if message == "ping":
                last_activity = time.monotonic()
                await asyncio.wait_for(ws.send_text("pong"), timeout=SEND_TIMEOUT)
            elif message == "complete":
                await ws.close(code=1000)
                break
            else:
                await ws.close(code=1003)
                break
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        counts[client.name] -= 1
        audit("subscription_closed", client.name, object_id=object_id)
