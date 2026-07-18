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

_base = modal.Image.debian_slim(python_version="3.11").pip_install(
    "fastapi>=0.110",
    "uvicorn[standard]>=0.27",
    "httpx>=0.27",
    "python-dotenv>=1.0",
    "pydantic>=2.6",
    "jsonschema>=4.21",
    "pyyaml>=6.0",
    "websockets>=12.0",
    "twilio>=9.0",
)

# `.env(...)` must come before `.add_local_dir(...)`, which has to be the last
# build step. The broker uses a container-local config dir (no shared volume);
# the gateway keeps the persistent volume and runs in remote-broker mode.
broker_image = _base.env({"GLC_CONFIG_DIR": "/tmp/glc"}).add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
gateway_image = _base.env({"GLC_CONFIG_DIR": "/data/glc", "GLC_BROKER": "remote"}).add_local_dir(
    str(LOCAL_GLC), remote_path="/root/glc"
)

data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)
llm_secret = modal.Secret.from_name("glc-llm-keys")  # provider keys — broker only
sign_secret = modal.Secret.from_name("glc-broker-sign")  # token-signing key — both


# ── broker: the only container that holds provider keys ──────────────────────

# Built once per warm container.
_broker = None


def _get_broker():
    global _broker
    if _broker is None:
        from glc.cache import GeminiCache
        from glc.security.broker import InProcessBroker

        _broker = InProcessBroker(GeminiCache(ttl_seconds=300))
    return _broker


@app.function(image=broker_image, secrets=[llm_secret, sign_secret], min_containers=0)
async def broker_exec(kind: str, payload: dict, provider: str | None = None, token: str = ""):
    """Execute one keyed call inside the broker container (which holds the keys).

    `__enabled__` reports provider descriptors (no secret leaves the broker);
    every other kind requires a valid, provider-scoped capability token.
    """
    if kind == "__enabled__":
        return await _get_broker().enabled(payload["kind"])
    from glc.security.capabilities import verify

    verify(token, provider=provider or kind, purpose=kind)
    return await _get_broker().call(kind, payload, provider=provider)


# ── gateway: public app, no provider keys ────────────────────────────────────


@app.function(
    image=gateway_image,
    volumes={"/data": data_volume},
    secrets=[sign_secret],  # broker-signing key only; NO provider keys
    min_containers=0,  # scale to zero when idle -> protects the free tier
)
@modal.asgi_app()
def fastapi_app():
    """Serve the glc gateway. Provider keys are absent here — LLM/embed/voice
    calls are delegated to broker_exec via RemoteBroker."""
    import os

    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import app as web
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
    """Runs the same snippet in the BROKER's secret config — the only container
    that holds the provider keys. Every value should be True."""
    import os

    present = {k: (os.environ.get(k) is not None) for k in _PROVIDER_KEYS}
    print("[broker container] provider keys present:")
    for k, v in present.items():
        print(f"    {k} = {v}")
    return present
