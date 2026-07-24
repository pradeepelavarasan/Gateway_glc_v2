"""SandboxBroker/HybridBroker dispatch logic — mocked, since real Sandboxes
only exist on the live Modal deployment (verified separately via
modal_app.py::check_* diagnostics)."""

from __future__ import annotations

import pytest

from glc.security.broker import LLM_PROVIDER_DOMAIN, LLM_PROVIDERS, HybridBroker, SandboxBroker


def test_every_llm_provider_has_exactly_one_allowed_domain():
    for p in LLM_PROVIDERS:
        assert p in LLM_PROVIDER_DOMAIN
        assert LLM_PROVIDER_DOMAIN[p].count(".") >= 1  # looks like a real hostname


async def test_sandbox_broker_rejects_unknown_provider():
    b = SandboxBroker()
    with pytest.raises(ValueError, match="only serves"):
        await b.call("chat_worker", {}, provider="not-a-real-provider")
    with pytest.raises(ValueError, match="only serves"):
        await b.call("chat_worker", {}, provider=None)


async def test_hybrid_broker_routes_chat_to_sandbox_and_embed_to_remote(monkeypatch):
    calls = []

    async def fake_sandbox_call(self, kind, payload, *, provider=None):
        calls.append(("sandbox", kind, provider))
        return {"via": "sandbox"}

    async def fake_remote_call(self, kind, payload, *, provider=None):
        calls.append(("remote", kind, provider))
        return {"via": "remote"}

    monkeypatch.setattr(SandboxBroker, "call", fake_sandbox_call)
    monkeypatch.setattr("glc.security.broker.RemoteBroker.call", fake_remote_call)

    hb = HybridBroker()
    r1 = await hb.call("chat_worker", {}, provider="gemini")
    r2 = await hb.call("chat_router", {}, provider="groq")
    r3 = await hb.call("embed", {})
    r4 = await hb.call("stt", {})

    assert r1 == {"via": "sandbox"}
    assert r2 == {"via": "sandbox"}
    assert r3 == {"via": "remote"}
    assert r4 == {"via": "remote"}
    assert calls == [
        ("sandbox", "chat_worker", "gemini"),
        ("sandbox", "chat_router", "groq"),
        ("remote", "embed", None),
        ("remote", "stt", None),
    ]
