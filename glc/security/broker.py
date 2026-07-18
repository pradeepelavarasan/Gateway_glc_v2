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

import os
from typing import Any, Protocol

# Kinds of keyed call the broker executes.
CHAT_WORKER = "chat_worker"
CHAT_ROUTER = "chat_router"
EMBED = "embed"
STT = "stt"
TTS = "tts"


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
    """Forwards keyed calls to the broker Modal container. Holds no provider
    key — only mints a short-lived, provider-scoped capability token per call."""

    def __init__(self, app_name: str = "glc-v1-gateway", fn_name: str = "broker_exec") -> None:
        self._app_name = app_name
        self._fn_name = fn_name
        self._fn: Any = None

    def _func(self) -> Any:
        if self._fn is None:
            import modal

            self._fn = modal.Function.from_name(self._app_name, self._fn_name)
        return self._fn

    async def enabled(self, kind: str) -> list[dict]:
        return await self._func().remote.aio("__enabled__", {"kind": kind}, None, "")

    async def call(self, kind: str, payload: dict, *, provider: str | None = None) -> Any:
        from glc.security.capabilities import mint

        token = mint(provider or kind, purpose=kind)
        return await self._func().remote.aio(kind, payload, provider, token)


def build_broker(cache: Any) -> Broker:
    """Pick the broker implementation from the environment."""
    if os.getenv("GLC_BROKER", "").lower() == "remote":
        return RemoteBroker()
    return InProcessBroker(cache)
