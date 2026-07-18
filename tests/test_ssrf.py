"""SSRF guard for the image URL resolver.

The IP checks use numeric-literal addresses (and `localhost` from
/etc/hosts) so the suite resolves them without any real network I/O.
"""

from __future__ import annotations

import ipaddress

import httpx
import pytest
from fastapi import HTTPException

from glc.routes.chat import _resolve_image_urls
from glc.security.ssrf import BlockedURLError, _is_blocked_ip, validate_url

# ─────────────────────────── _is_blocked_ip ───────────────────────────

BLOCKED = [
    "127.0.0.1",  # loopback v4
    "10.0.0.1",  # private v4
    "192.168.1.1",  # private v4
    "169.254.169.254",  # link-local v4 (cloud metadata)
    "0.0.0.0",  # unspecified v4
    "::1",  # loopback v6
    "fe80::1",  # link-local v6
    "::ffff:127.0.0.1",  # IPv4-mapped loopback
]

ALLOWED = [
    "93.184.216.34",  # public v4
    "2606:2800:220:1:248:1893:25c8:1946",  # public v6
]


@pytest.mark.parametrize("addr", BLOCKED)
def test_is_blocked_ip_blocks_internal(addr):
    assert _is_blocked_ip(ipaddress.ip_address(addr)) is True


@pytest.mark.parametrize("addr", ALLOWED)
def test_is_blocked_ip_allows_public(addr):
    assert _is_blocked_ip(ipaddress.ip_address(addr)) is False


# ─────────────────────────── validate_url ───────────────────────────


async def test_validate_url_rejects_non_http_scheme():
    with pytest.raises(BlockedURLError):
        await validate_url("file:///etc/passwd")
    with pytest.raises(BlockedURLError):
        await validate_url("ftp://example.com/x")


async def test_validate_url_rejects_loopback_and_metadata():
    with pytest.raises(BlockedURLError):
        await validate_url("http://127.0.0.1/x")
    with pytest.raises(BlockedURLError):
        await validate_url("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(BlockedURLError):
        await validate_url("http://localhost/x")


async def test_validate_url_allows_public_literal():
    # A public numeric address resolves to itself with no DNS lookup.
    await validate_url("http://93.184.216.34/image.png")


async def test_validate_url_allowlist_blocks_unlisted(monkeypatch):
    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWLIST", "images.example.com")
    with pytest.raises(BlockedURLError):
        await validate_url("http://93.184.216.34/image.png")


async def test_validate_url_allowlist_allows_listed(monkeypatch):
    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWLIST", "93.184.216.34")
    await validate_url("http://93.184.216.34/image.png")


# ─────────────────────── redirect re-check ───────────────────────


class _FakeResp:
    def __init__(self, *, status=200, location=None, content=b"\x89PNG", content_type="image/png"):
        self.status_code = status
        self.is_redirect = location is not None
        self.headers = {"location": location} if location else {"content-type": content_type}
        self.content = content
        self.url = httpx.URL("http://93.184.216.34/img")

    def raise_for_status(self):
        # All fake responses in these tests are 2xx/3xx, so this never raises.
        return None


class _FakeClient:
    def __init__(self, responses, **_kw):
        self._responses = list(responses)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def get(self, _url, **_kw):
        return self._responses.pop(0)


def _msgs(url):
    return [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": url}}]}]


async def test_redirect_to_internal_is_blocked(monkeypatch):
    # Public first hop is allowed, but its 302 points at loopback and must be
    # re-validated and rejected before the second fetch happens.
    responses = [_FakeResp(status=302, location="http://127.0.0.1/evil")]
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeClient(responses))
    with pytest.raises(HTTPException) as ei:
        await _resolve_image_urls(_msgs("http://93.184.216.34/start"))
    assert ei.value.status_code == 400
    assert "blocked image url" in str(ei.value.detail)


async def test_redirect_to_public_is_followed(monkeypatch):
    responses = [
        _FakeResp(status=302, location="http://93.184.216.34/final"),
        _FakeResp(status=200, content=b"\x89PNG\r\n", content_type="image/png"),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeClient(responses))
    out = await _resolve_image_urls(_msgs("http://93.184.216.34/start"))
    block = out[0]["content"][0]
    assert block["image_url"]["url"].startswith("data:image/png;base64,")


class _RecordingClient:
    """Records the args each .get() is called with."""

    def __init__(self, **_kw):
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def get(self, url, *, headers=None, extensions=None):
        self.calls.append({"url": url, "headers": headers or {}, "extensions": extensions or {}})
        return _FakeResp(status=200, content=b"\x89PNG", content_type="image/png")


async def test_fetch_pins_to_resolved_ip(monkeypatch):
    # resolve_validated is unit-tested separately; here we stub it so the URL
    # host and the resolved IP differ, proving the fetch connects to the IP
    # while keeping the Host header and TLS SNI as the original hostname.
    from glc.security.ssrf import ValidatedTarget

    async def _fake_resolve(url):
        return ValidatedTarget(scheme="https", host="images.example.com", port=443, ip="93.184.216.34")

    monkeypatch.setattr("glc.security.ssrf.resolve_validated", _fake_resolve)
    recorder = _RecordingClient()
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: recorder)

    await _resolve_image_urls(_msgs("https://images.example.com/logo.png"))

    call = recorder.calls[0]
    assert call["url"].host == "93.184.216.34"  # connects to the pinned IP, no re-resolution
    assert call["headers"]["Host"] == "images.example.com"
    assert call["extensions"]["sni_hostname"] == "images.example.com"
