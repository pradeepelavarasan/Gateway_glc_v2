"""Provider-key isolation: short-lived scoped capability tokens + broker."""

from __future__ import annotations

import pytest

from glc.security import capabilities as cap
from glc.security.capabilities import CapabilityError


@pytest.fixture(autouse=True)
def _sign_key(monkeypatch):
    monkeypatch.setenv("GLC_BROKER_SIGN_KEY", "test-sign-key")


def test_mint_verify_roundtrip():
    token = cap.mint("gemini", purpose="chat_worker")
    cap.verify(token, provider="gemini", purpose="chat_worker")  # must not raise


def test_verify_rejects_wrong_provider():
    token = cap.mint("gemini", purpose="chat_worker")
    with pytest.raises(CapabilityError):
        cap.verify(token, provider="groq", purpose="chat_worker")


def test_verify_rejects_wrong_purpose():
    token = cap.mint("gemini", purpose="chat_worker")
    with pytest.raises(CapabilityError):
        cap.verify(token, provider="gemini", purpose="embed")


def test_verify_rejects_expired():
    token = cap.mint("gemini", purpose="chat_worker", ttl=-1)
    with pytest.raises(CapabilityError):
        cap.verify(token, provider="gemini", purpose="chat_worker")


def test_verify_rejects_tampered_signature():
    token = cap.mint("gemini", purpose="chat_worker")
    body, sig = token.rsplit("|", 1)
    tampered = f"{body}|{'0' * len(sig)}"
    with pytest.raises(CapabilityError):
        cap.verify(tampered, provider="gemini", purpose="chat_worker")


def test_verify_rejects_different_sign_key(monkeypatch):
    token = cap.mint("gemini", purpose="chat_worker")
    monkeypatch.setenv("GLC_BROKER_SIGN_KEY", "a-different-key")
    with pytest.raises(CapabilityError):
        cap.verify(token, provider="gemini", purpose="chat_worker")


def test_mint_fails_closed_without_sign_key(monkeypatch):
    monkeypatch.delenv("GLC_BROKER_SIGN_KEY", raising=False)
    with pytest.raises(CapabilityError):
        cap.mint("gemini")


async def test_inprocess_broker_reports_no_workers_without_keys():
    from glc.cache import GeminiCache
    from glc.security.broker import InProcessBroker

    broker = InProcessBroker(GeminiCache(ttl_seconds=1))
    # No provider keys in the test env, so the broker offers no chat workers.
    assert await broker.enabled("chat_worker") == []
