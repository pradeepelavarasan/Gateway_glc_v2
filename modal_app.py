"""
Modal deployment for glc — provider-key isolation (leak 1 fix).

Two components, two containers:

  - broker_exec: the ONLY component with provider keys (the `glc-llm-keys`
    secret). It verifies a short-lived, provider-scoped capability token and
    then executes exactly one keyed call (chat / routing / embed / stt / tts).

  - fastapi_app (gateway): the public app. It has NO provider keys — only the
    broker-signing secret used to mint capability tokens. Every keyed call is
    delegated to broker_exec. So `os.environ["GEMINI_API_KEY"]` in the gateway
    container raises KeyError, and an adapter running in the gateway can never
    read a provider key.

Deploy with:   uv run modal deploy modal_app.py

Prereqs (mock values only — never real provider keys):
    modal secret create glc-llm-keys GEMINI_API_KEY=... GROQ_API_KEY=... ...
    modal secret create glc-broker-sign GLC_BROKER_SIGN_KEY=<random string>
"""

from pathlib import Path

import modal

app = modal.App("glc-v1-gateway")

LOCAL_GLC = Path(__file__).parent / "glc"

# Pinned by digest (python:3.11-slim, resolved 2026-07-19) rather than a rolling
# tag, so the base layer can't shift under us between builds. Dependencies come
# from uv.lock via uv_sync(frozen=True) instead of a hand-copied pip_install
# list, so the image can't silently drift from what's actually locked and
# tested — a typosquatted or bumped transitive dependency can't enter quietly.
_PYTHON_SLIM_PINNED = (
    "python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93"
)
_base = modal.Image.from_registry(_PYTHON_SLIM_PINNED).uv_sync()

# `.env(...)` must come before `.add_local_dir(...)`, which has to be the last
# build step. The broker uses a container-local config dir (no shared volume).
# GLC_BROKER=sandbox: chat/router calls go through per-provider Sandboxes with
# an egress allowlist (glc/security/broker.py SandboxBroker) — A3 + A4
# combined. embed/stt/tts still go through the Function-based broker_exec_*
# below (RemoteBroker), which the Sandbox path is composed with.
broker_image = _base.env({"GLC_CONFIG_DIR": "/tmp/glc"}).add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
gateway_image = _base.env({"GLC_CONFIG_DIR": "/data/glc", "GLC_BROKER": "sandbox"}).add_local_dir(
    str(LOCAL_GLC), remote_path="/root/glc"
)

data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)
sign_secret = modal.Secret.from_name("glc-broker-sign")  # token-signing key — all broker/gateway functions
install_token_secret = modal.Secret.from_name("glc-install-token")  # control token — gateway only

# Per-slot Secrets: each LLM provider gets its own Secret holding only its own
# key, so a compromised broker_exec_<provider> container never had the other
# five keys in its environment. embed/stt/tts still run against the full
# bundle (glc-llm-keys) via broker_exec_shared — see FINDINGS.md for the scope
# note on that residual gap.
from glc.security.broker import LLM_PROVIDERS  # noqa: E402

_PROVIDER_SECRET_NAME = {
    "gemini": "glc-key-gemini",
    "nvidia": "glc-key-nvidia",
    "groq": "glc-key-groq",
    "cerebras": "glc-key-cerebras",
    "openrouter": "glc-key-openrouter",
    "github": "glc-key-github",
}
provider_secrets = {p: modal.Secret.from_name(_PROVIDER_SECRET_NAME[p]) for p in LLM_PROVIDERS}
llm_secret = modal.Secret.from_name("glc-llm-keys")  # full bundle — broker_exec_shared only


# ── broker: the only containers that hold provider keys ──────────────────────

# Built once per warm container.
_broker = None


def _get_broker():
    global _broker
    if _broker is None:
        from glc.cache import GeminiCache
        from glc.security.broker import InProcessBroker

        _broker = InProcessBroker(GeminiCache(ttl_seconds=300))
    return _broker


async def _broker_exec_handler(kind: str, payload: dict, provider: str | None = None, token: str = ""):
    """Execute one keyed call inside a broker container.

    `__enabled__` reports provider descriptors (no secret leaves the broker);
    every other kind requires a valid, provider-scoped capability token. This
    same handler body backs every broker_exec_* function below — only the
    Secret each is deployed with differs.
    """
    if kind == "__enabled__":
        return await _get_broker().enabled(payload["kind"])
    from glc.security.capabilities import verify

    verify(token, provider=provider or kind, purpose=kind)
    return await _get_broker().call(kind, payload, provider=provider)


# One function per provider, each with only that provider's own Secret.
for _p in LLM_PROVIDERS:
    app.function(
        image=broker_image,
        secrets=[provider_secrets[_p], sign_secret],
        min_containers=0,
        name=f"broker_exec_{_p}",
    )(_broker_exec_handler)

# embed/stt/tts — still the full key bundle (residual scope, documented).
broker_exec_shared = app.function(
    image=broker_image,
    secrets=[llm_secret, sign_secret],
    min_containers=0,
    name="broker_exec_shared",
)(_broker_exec_handler)


# ── gateway: public app, no provider keys ────────────────────────────────────


@app.function(
    image=gateway_image,
    volumes={"/data": data_volume},
    # broker-signing key + the install token as a Secret (never a file); NO provider keys
    secrets=[sign_secret, install_token_secret],
    min_containers=0,  # scale to zero when idle -> protects the free tier
    # The audit/pairing/gateway SQLite databases live on this Volume. SQLite
    # doesn't arbitrate concurrent writers across separate containers, so this
    # gateway is pinned to exactly one container — a second writer would corrupt
    # the files and split the audit trail (see FINDINGS.md).
    max_containers=1,
)
@modal.asgi_app()
def fastapi_app():
    """Serve the glc gateway. Provider keys are absent here — LLM/embed/voice
    calls are delegated to broker_exec via RemoteBroker."""
    import asyncio
    import os
    from contextlib import asynccontextmanager

    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import app as web

    # Volume writes aren't durable or visible elsewhere until committed. With a
    # single container (max_containers=1, above) there's no cross-container
    # visibility problem, but an uncommitted write is still lost if this
    # container is evicted/restarted — so commit periodically and on graceful
    # shutdown rather than relying on implicit background commit. Wraps the
    # app's existing lifespan rather than using FastAPI's deprecated on_event.
    inner_lifespan = web.router.lifespan_context

    @asynccontextmanager
    async def _lifespan_with_commit(app):
        async def _commit_loop():
            while True:
                await asyncio.sleep(30)
                try:
                    data_volume.commit()
                except Exception as e:
                    print(f"[glc] volume commit failed: {e!r}")

        async with inner_lifespan(app):
            task = asyncio.create_task(_commit_loop())
            try:
                yield
            finally:
                task.cancel()
                try:
                    data_volume.commit()
                except Exception as e:
                    print(f"[glc] final volume commit failed: {e!r}")

    web.router.lifespan_context = _lifespan_with_commit
    return web


# ── isolation check (the leak-1 "after" proof) ───────────────────────────────

_PROVIDER_KEYS = [
    "GEMINI_API_KEY",
    "GROQ_API_KEY",
    "NVIDIA_API_KEY",
    "CEREBRAS_API_KEY",
    "OPEN_ROUTER_API_KEY",
    "GITHUB_ACCESS_TOKEN",
]


@app.function(image=gateway_image, secrets=[sign_secret])
def check_gateway_env() -> dict:
    """Runs the leak-1 snippet in the GATEWAY's secret config (no provider keys).
    Every value should be False — the keys are not present in this container."""
    import os

    present = {k: (os.environ.get(k) is not None) for k in _PROVIDER_KEYS}
    print("[gateway container] provider keys present:")
    for k, v in present.items():
        print(f"    {k} = {v}")
    return present


@app.function(image=broker_image, secrets=[llm_secret, sign_secret])
def check_broker_env() -> dict:
    """Runs the same snippet in broker_exec_shared's secret config (the full
    key bundle, used for embed/stt/tts). Every value should be True."""
    import os

    present = {k: (os.environ.get(k) is not None) for k in _PROVIDER_KEYS}
    print("[broker_exec_shared] provider keys present:")
    for k, v in present.items():
        print(f"    {k} = {v}")
    return present


_PROVIDER_ENV_VAR = {
    "gemini": "GEMINI_API_KEY",
    "nvidia": "NVIDIA_API_KEY",
    "groq": "GROQ_API_KEY",
    "cerebras": "CEREBRAS_API_KEY",
    "openrouter": "OPEN_ROUTER_API_KEY",
    "github": "GITHUB_ACCESS_TOKEN",
}

def _check_provider_env_handler() -> dict:
    """Per-slot proof (A4): this container should hold ONLY its own provider's
    key — every other provider's key must be absent. Registered under six
    names below (one per provider); which key is True identifies which
    provider's container answered. A top-level, parameterless function (not a
    closure) because @app.function requires global-scope functions."""
    import os

    present = {k: (os.environ.get(k) is not None) for k in _PROVIDER_KEYS}
    print("[broker_exec_<provider>] provider keys present:")
    for k, v in present.items():
        print(f"    {k} = {v}")
    return present


for _p in LLM_PROVIDERS:
    app.function(
        image=broker_image,
        secrets=[provider_secrets[_p], sign_secret],
        name=f"check_provider_env_{_p}",
    )(_check_provider_env_handler)


@app.function(image=gateway_image, volumes={"/data": data_volume}, secrets=[sign_secret, install_token_secret])
def check_inprocess_fixes() -> dict:
    """Runs the leak-2 and leak-4 repros INSIDE the gateway container (the same
    process an in-process attacker would have) to prove the fixes on deploy."""
    import os

    os.makedirs("/data/glc", exist_ok=True)

    # leak 4 — the install-token file must not exist (bound as a Secret).
    from glc.config import get_or_create_install_token, install_token_path

    get_or_create_install_token()  # resolves from the Secret; removes any stale file
    token_file_exists = install_token_path().exists()

    # leak 2 — a DELETE is now detected by the hash chain.
    from glc.audit import store as audit

    audit.init_store()
    audit.append(channel="t", channel_user_id="u", trust_level="owner_paired", event_type="e")
    import sqlite3

    con = sqlite3.connect(os.getenv("GLC_AUDIT_DB", os.path.expanduser("~/.glc/audit.sqlite")))
    con.execute("DELETE FROM audit_log")
    con.commit()
    con.close()
    chain = audit.verify_chain()

    out = {"install_token_file_exists": token_file_exists, "audit_verify_after_delete": chain}
    print("[gateway container] install_token file exists:", token_file_exists, " (expected False)")
    print("[gateway container] audit verify after DELETE:", chain["ok"], "-", chain["reason"])
    return out
