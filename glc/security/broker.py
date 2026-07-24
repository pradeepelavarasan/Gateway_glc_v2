"""The provider-key broker.

Provider keys live only in the broker. Every keyed call — chat, routing,
embedding, speech-to-text, text-to-speech — is executed by the broker; the
gateway (and the adapters/tools running in it) holds no provider key and only
mints a short-lived, provider-scoped capability token to ask the broker to make
one call.

Two implementations:
  - InProcessBroker: builds the real keyed providers in-process and runs the
    call directly. Used inside the broker container, and for local dev / tests
    (where it is dev convenience, not an isolation boundary).
  - RemoteBroker: forwards the call to the broker Modal container (which holds
    the keys) via a Modal function call, minting a capability token per call.
    Used by the deployed gateway, whose environment has no provider keys.

Selected by GLC_BROKER: "remote" -> RemoteBroker, otherwise InProcessBroker.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Protocol

# Kinds of keyed call the broker executes.
CHAT_WORKER = "chat_worker"
CHAT_ROUTER = "chat_router"
EMBED = "embed"
STT = "stt"
TTS = "tts"

# The chat/router LLM providers. Each gets its own per-provider Modal Secret
# and its own Sandbox with an outbound_domain_allowlist restricted to that
# provider's exact API host — the "per-slot" isolation (a compromised sandbox
# only ever had one key, for one provider) combined with the egress wall
# (it cannot reach any host but that provider's). embed/stt/tts still run in a
# shared Function with the full key bundle and no egress restriction — see
# FINDINGS.md for that residual scope.
LLM_PROVIDERS = ["gemini", "nvidia", "groq", "cerebras", "openrouter", "github"]

LLM_PROVIDER_DOMAIN = {
    "gemini": "generativelanguage.googleapis.com",
    "nvidia": "integrate.api.nvidia.com",
    "groq": "api.groq.com",
    "cerebras": "api.cerebras.ai",
    "openrouter": "openrouter.ai",
    "github": "models.github.ai",
}


class Broker(Protocol):
    async def enabled(self, kind: str) -> list[dict]: ...
    async def call(self, kind: str, payload: dict, *, provider: str | None = None) -> Any: ...


class InProcessBroker:
    """Runs keyed calls directly. Lives wherever the provider keys live —
    the broker container on Modal, or the single process in local/test runs."""

    def __init__(self, cache: Any) -> None:
        from glc import providers as P

        self._workers = P.build_providers(cache)
        self._routers = P.build_router_providers()
        self._embedders: list[Any] | None = None
        self._embed_order: list[str] | None = None

    def _ensure_embedders(self) -> None:
        if self._embedders is None:
            from glc import embedders as E

            self._embedders, self._embed_order = E.build_embedders()

    async def enabled(self, kind: str) -> list[dict]:
        """Descriptors (name/model/capabilities) for the providers the broker
        can serve — the metadata the gateway needs to route without a key."""
        if kind == EMBED:
            self._ensure_embedders()
            return [{"name": e.name, "model": getattr(e, "model", ""), "capabilities": {}} for e in (self._embedders or [])]
        pool = self._routers if kind == CHAT_ROUTER else self._workers
        return [
            {"name": n, "model": p.model, "capabilities": dict(getattr(p, "capabilities", {}))}
            for n, p in pool.items()
        ]

    async def call(self, kind: str, payload: dict, *, provider: str | None = None) -> Any:
        if kind == CHAT_WORKER:
            return await self._workers[provider].chat(**payload)
        if kind == CHAT_ROUTER:
            return await self._routers[provider].chat(**payload)
        if kind == EMBED:
            from glc import embedders as E

            self._ensure_embedders()
            name, result, attempts, latency = await E.embed_with_failover(
                self._embedders or [],
                payload["text"],
                payload["task_type"],
                explicit=payload.get("explicit"),
            )
            return {"name": name, "result": result, "attempts": attempts, "latency": latency}
        if kind == STT:
            from glc.voice.stt import transcribe

            return await transcribe(payload["audio"], payload["mime"], prefer=payload.get("prefer", "default"))
        if kind == TTS:
            from glc.voice.tts import synthesize

            return await synthesize(
                payload["text"], voice_id=payload.get("voice_id"), prefer=payload.get("prefer", "default")
            )
        raise ValueError(f"unknown broker call kind {kind!r}")


class RemoteBroker:
    """Forwards keyed calls to the broker Modal container(s). Holds no
    provider key — only mints a short-lived, provider-scoped capability token
    per call. Chat/router calls for a known LLM provider go to that provider's
    own single-secret function (broker_exec_<provider>); everything else goes
    to the shared-bundle function (broker_exec_shared)."""

    def __init__(self, app_name: str = "glc-v1-gateway") -> None:
        self._app_name = app_name
        self._fns: dict[str, Any] = {}

    def _func(self, name: str) -> Any:
        if name not in self._fns:
            import modal

            self._fns[name] = modal.Function.from_name(self._app_name, name)
        return self._fns[name]

    def _func_name(self, kind: str, provider: str | None) -> str:
        if kind in (CHAT_WORKER, CHAT_ROUTER) and provider in LLM_PROVIDERS:
            return f"broker_exec_{provider}"
        return "broker_exec_shared"

    async def enabled(self, kind: str) -> list[dict]:
        if kind in (CHAT_WORKER, CHAT_ROUTER):
            # Each provider's descriptor lives only in that provider's own
            # single-secret function, so fan out and merge.
            results = await asyncio.gather(
                *(
                    self._func(f"broker_exec_{p}").remote.aio("__enabled__", {"kind": kind}, None, "")
                    for p in LLM_PROVIDERS
                ),
                return_exceptions=True,
            )
            out: list[dict] = []
            for r in results:
                if isinstance(r, list):
                    out.extend(r)
            return out
        return await self._func("broker_exec_shared").remote.aio("__enabled__", {"kind": kind}, None, "")

    async def call(self, kind: str, payload: dict, *, provider: str | None = None) -> Any:
        from glc.security.capabilities import mint

        token = mint(provider or kind, purpose=kind)
        fn_name = self._func_name(kind, provider)
        return await self._func(fn_name).remote.aio(kind, payload, provider, token)


def _sandbox_image() -> Any:
    """The image a broker Sandbox runs. Must be built with copy=True — a
    Sandbox does not receive the live-synced local-dir mount that
    @app.function invocations get, so the glc package has to be baked into
    the image layer, not synced at container startup.

    This is built from *inside a running container* (whichever Modal function
    calls SandboxBroker), so it cannot use uv_sync() the way modal_app.py's
    deploy-time images do — uv_sync needs pyproject.toml/uv.lock on the local
    machine invoking `modal deploy`/`modal run`, which isn't present at
    runtime inside an already-deployed container. Only glc/providers.py's
    request path is exercised here (InProcessBroker -> providers/cache), plus
    whatever `glc.security.__init__` eagerly imports (it pulls in the whole
    security subpackage on any submodule import, including glc.config, hence
    pyyaml below). Both deps are pinned to their exact uv.lock versions so
    this doesn't reintroduce the version-drift problem the pinned base image
    and uv_sync close for the main deploy-time images (see modal_app.py, A5).
    Keep these pins in sync with uv.lock.
    """
    import modal

    glc_dir = __import__("pathlib").Path(__file__).resolve().parent.parent
    pinned = "python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93"
    return (
        modal.Image.from_registry(pinned)
        .pip_install("httpx==0.28.1", "pyyaml==6.0.3")
        .add_local_dir(str(glc_dir), remote_path="/root/glc", copy=True)
    )


class SandboxBroker:
    """Chat/router calls only. One Sandbox per provider, lazily created and
    reused: each Sandbox has only that provider's Secret AND an
    outbound_domain_allowlist restricted to that provider's exact API host —
    combining per-slot key isolation (A4) with an egress wall (A3). A
    compromised sandbox for one provider cannot reach any other provider's
    key or any other network destination."""

    def __init__(self) -> None:
        self._sandboxes: dict[str, Any] = {}
        self._image = None

    def _image_ref(self) -> Any:
        if self._image is None:
            self._image = _sandbox_image()
        return self._image

    def _sandbox_for(self, provider: str) -> Any:
        sb = self._sandboxes.get(provider)
        if sb is not None:
            try:
                if sb.poll() is None:  # still running
                    return sb
            except Exception:
                pass
        import modal

        sb = modal.Sandbox.create(
            image=self._image_ref(),
            secrets=[modal.Secret.from_name(f"glc-key-{provider}"), modal.Secret.from_name("glc-broker-sign")],
            outbound_domain_allowlist=[LLM_PROVIDER_DOMAIN[provider]],
            timeout=3600,  # hard cap; recreated if it outlives this
            idle_timeout=300,  # torn down by Modal after 5 min unused -> cost control
        )
        self._sandboxes[provider] = sb
        return sb

    def _exec(self, provider: str, req: dict) -> Any:
        import base64
        import json

        sb = self._sandbox_for(provider)
        arg = base64.b64encode(json.dumps(req).encode()).decode()
        p = sb.exec("python", "-m", "glc.security.broker_entrypoint", arg, workdir="/root", timeout=60)
        p.wait()
        out = p.stdout.read()
        if p.returncode != 0 or not out:
            raise RuntimeError(f"sandbox exec failed (rc={p.returncode}): {p.stderr.read()[:500]}")
        resp = json.loads(out.strip().splitlines()[-1])
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "sandbox call failed"))
        return resp["result"]

    async def enabled(self, kind: str) -> list[dict]:
        loop = asyncio.get_running_loop()

        async def _one(p: str) -> list[dict]:
            try:
                return await loop.run_in_executor(
                    None, self._exec, p, {"kind": "__enabled__", "payload": {"kind": kind}}
                )
            except Exception:
                return []

        results = await asyncio.gather(*(_one(p) for p in LLM_PROVIDERS))
        out: list[dict] = []
        for r in results:
            out.extend(r)
        return out

    async def call(self, kind: str, payload: dict, *, provider: str | None = None) -> Any:
        from glc.security.capabilities import mint

        if provider is None or provider not in LLM_PROVIDERS:
            raise ValueError(f"SandboxBroker only serves {LLM_PROVIDERS}, got {provider!r}")
        token = mint(provider, purpose=kind)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._exec, provider, {"kind": kind, "payload": payload, "provider": provider, "token": token}
        )


class HybridBroker:
    """Chat/router through SandboxBroker (per-slot keys + egress wall);
    embed/stt/tts through RemoteBroker (shared-bundle Function, no egress
    restriction — see FINDINGS.md for that residual scope)."""

    def __init__(self) -> None:
        self._sandbox = SandboxBroker()
        self._remote = RemoteBroker()

    async def enabled(self, kind: str) -> list[dict]:
        if kind in (CHAT_WORKER, CHAT_ROUTER):
            return await self._sandbox.enabled(kind)
        return await self._remote.enabled(kind)

    async def call(self, kind: str, payload: dict, *, provider: str | None = None) -> Any:
        if kind in (CHAT_WORKER, CHAT_ROUTER):
            return await self._sandbox.call(kind, payload, provider=provider)
        return await self._remote.call(kind, payload, provider=provider)


def build_broker(cache: Any) -> Broker:
    """Pick the broker implementation from the environment."""
    mode = os.getenv("GLC_BROKER", "").lower()
    if mode == "sandbox":
        return HybridBroker()
    if mode == "remote":
        return RemoteBroker()
    return InProcessBroker(cache)
