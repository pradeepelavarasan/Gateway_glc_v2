"""FastAPI app for glc_v1. Port 8111 by default. V9 routes are mounted
as-is (S9 Browser / S10 Computer-Use clients work unchanged); the new
S11 surfaces (transcribe, speak, channels WS, control) sit alongside.
"""

from __future__ import annotations

import os
import signal
import time
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

ROOT = Path(__file__).parent
load_dotenv(ROOT.parent / ".env")  # repo .env, if present

from glc import db  # noqa: E402
from glc import embedders as E  # noqa: E402
from glc import providers as P  # noqa: E402
from glc.audit import init_store as init_audit  # noqa: E402
from glc.cache import GeminiCache  # noqa: E402
from glc.config import get_or_create_install_token  # noqa: E402
from glc.policy import reload_engine  # noqa: E402
from glc.routes import channels as channels_route  # noqa: E402
from glc.routes import chat as chat_route  # noqa: E402
from glc.routes import control as control_route  # noqa: E402
from glc.routes import speak as speak_route  # noqa: E402
from glc.routes import transcribe as transcribe_route  # noqa: E402
from glc.routing import Router, RouterPool  # noqa: E402

PORT = int(os.getenv("GLC_PORT", "8111"))

# Off unless explicitly opted into (e.g. GLC_ENABLE_DOCS=1 for local dev).
# Production deployments never set this, so the schema route isn't even
# registered there (a probe gets 404, not a 401 confirming it exists).
DOCS_ENABLED = os.getenv("GLC_ENABLE_DOCS", "0") == "1"

# Paths reachable without the install token. Keep this list minimal: healthz
# leaks nothing beyond {"ok": true} and is the conventional liveness-check
# exception for cloud platforms.
PUBLIC_PATHS = {"/healthz"}


def _install_sighup_reload() -> None:
    """Hot-reload policy.yaml on SIGHUP. Windows lacks SIGHUP so this is
    a no-op there."""
    if not hasattr(signal, "SIGHUP"):
        return

    def _handler(signum, frame):  # noqa: ARG001
        try:
            reload_engine()
            print("[glc] policy.yaml reloaded via SIGHUP")
        except Exception as e:
            print(f"[glc] SIGHUP reload failed: {e!r}")

    try:
        signal.signal(signal.SIGHUP, _handler)
    except ValueError:
        # signal() only works on the main thread; tests using TestClient
        # spawn lifespan from a worker thread. Silent skip is correct here.
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    init_audit()
    get_or_create_install_token()
    _install_sighup_reload()
    app.state.cache = GeminiCache(ttl_seconds=300)
    app.state.providers = P.build_providers(app.state.cache)
    app.state.router = Router(app.state.providers, chat_route.ORDER)
    app.state.router_providers = P.build_router_providers()
    app.state.router_pool = RouterPool(app.state.router_providers, chat_route.ROUTER_ORDER)
    app.state.embedders, app.state.embed_order = E.build_embedders()
    app.state.started_at = time.time()
    app.state.registered_channels = []
    yield


app = FastAPI(
    title="GLC v1 — Gateway for LLMs and Channels",
    lifespan=lifespan,
    docs_url="/docs" if DOCS_ENABLED else None,
    redoc_url="/redoc" if DOCS_ENABLED else None,
    openapi_url="/openapi.json" if DOCS_ENABLED else None,
)


@app.middleware("http")
async def require_install_token(request: Request, call_next):
    """Every HTTP route requires the per-installation token, except the
    public-path allowlist above. Channel adapters authenticate separately
    at the websocket handshake (glc/routes/channels.py); this middleware
    only sees HTTP-scope requests."""
    if request.url.path not in PUBLIC_PATHS:
        expected = get_or_create_install_token()
        authorization = request.headers.get("authorization")
        if not authorization or not authorization.startswith("Bearer "):
            return JSONResponse(
                {"detail": "missing bearer token (Authorization: Bearer <install_token>)"},
                status_code=401,
            )
        if authorization.removeprefix("Bearer ").strip() != expected:
            return JSONResponse({"detail": "install token mismatch"}, status_code=403)
    return await call_next(request)


app.include_router(chat_route.router)
app.include_router(transcribe_route.router)
app.include_router(speak_route.router)
app.include_router(control_route.router)
app.include_router(channels_route.router)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    docs_line = "<p>Open <code>/docs</code> for the OpenAPI explorer.</p>" if DOCS_ENABLED else ""
    return (
        "<html><body style='font-family:sans-serif;max-width:680px;margin:2em auto'>"
        "<h1>GLC v1</h1>"
        "<p>Gateway for LLMs and Channels — Session 11 scaffold.</p>"
        f"{docs_line}"
        "<p>Channel adapters connect over <code>WS /v1/channels/&lt;name&gt;</code>."
        " V9 callers should point at this port unchanged: chat, vision, embed,"
        " batch, cost-by-agent, providers, capabilities, status, calls."
        "</p>"
        "</body></html>"
    )


@app.get("/healthz")
async def healthz():
    return {"ok": True, "port": PORT}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("glc.main:app", host="0.0.0.0", port=PORT, reload=False)
