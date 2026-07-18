"""Upstream provider failures must return a generic message to the client
while the full detail is kept in server-side logs only."""

from __future__ import annotations

import logging

from glc.routes.errors import upstream_error

_UPSTREAM_DETAIL = "gemini HTTP 400: API key not valid ... generativelanguage.googleapis.com"


def test_upstream_error_client_detail_is_generic():
    exc = upstream_error(502, log_detail=_UPSTREAM_DETAIL)
    assert exc.status_code == 502
    assert exc.detail == "upstream provider request failed"
    # The raw upstream detail must never reach the client.
    assert "gemini" not in exc.detail
    assert "googleapis" not in exc.detail


def test_upstream_error_logs_full_detail_server_side(caplog):
    with caplog.at_level(logging.WARNING, logger="glc.upstream"):
        upstream_error(502, log_detail=_UPSTREAM_DETAIL)
    assert any(_UPSTREAM_DETAIL in r.getMessage() for r in caplog.records)


def test_upstream_error_custom_client_detail():
    exc = upstream_error(
        503,
        log_detail="all providers unavailable. attempts: [...]. last_error: boom",
        client_detail="all upstream providers are currently unavailable",
    )
    assert exc.status_code == 503
    assert exc.detail == "all upstream providers are currently unavailable"
    assert "last_error" not in exc.detail
    assert "attempts" not in exc.detail


def test_chat_upstream_failure_returns_generic_body(app_client, caplog):
    # No provider keys in the test env, so every provider is unavailable and
    # the chat route hits the all-providers-fail path. The client response
    # must not leak provider names, upstream bodies, or internal attempt state.
    with caplog.at_level(logging.WARNING, logger="glc.upstream"):
        r = app_client.post("/v1/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code in (502, 503)
    body = r.text.lower()
    for leaked in ("last_error", "attempts", "gemini http", "googleapis", "traceback"):
        assert leaked not in body, f"client response leaked {leaked!r}: {r.text}"
    # The detail is still captured server-side.
    assert any("all providers unavailable" in rec.getMessage() for rec in caplog.records)
