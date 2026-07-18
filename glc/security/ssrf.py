"""SSRF guard for server-side URL fetches (the image URL resolver).

Before the gateway fetches any caller-supplied URL, we must ensure it can't
be pointed at internal infrastructure. This module:

  - allows only http/https,
  - resolves the hostname and rejects if ANY resolved address is loopback /
    private / link-local / reserved / multicast / unspecified (covers IPv4
    and IPv6, including IPv4-mapped IPv6),
  - optionally enforces a host allowlist (GLC_IMAGE_URL_ALLOWLIST),
  - returns the validated IP so the caller can connect straight to it.

Connecting to the returned IP (rather than the hostname) closes the
DNS-rebinding gap: there is no second DNS lookup at connect time that an
attacker-controlled resolver could flip from a public to a private address
between validation and the fetch. The caller must also disable httpx's
automatic redirects and re-run this guard for every hop.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlparse


class BlockedURLError(Exception):
    """Raised when a URL is not allowed to be fetched server-side."""


@dataclass(frozen=True)
class ValidatedTarget:
    """A URL that passed the guard, plus the IP to pin the connection to."""

    scheme: str
    host: str
    port: int
    ip: str


def _allowlist() -> list[str]:
    raw = os.getenv("GLC_IMAGE_URL_ALLOWLIST", "")
    return [h.strip().lower() for h in raw.split(",") if h.strip()]


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if `ip` is an address the gateway must never fetch from.

    IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) is normalized to its IPv4 form
    first, so loopback/private targets can't be smuggled through the v6 form.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


async def resolve_validated(url: str) -> ValidatedTarget:
    """Validate `url` and return the target to connect to, or raise.

    Every resolved address is checked, so a host that returns a mix of
    public and private records is rejected rather than partially allowed.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise BlockedURLError(f"scheme {parsed.scheme!r} not allowed (http/https only)")
    host = parsed.hostname
    if not host:
        raise BlockedURLError("url has no host")

    allow = _allowlist()
    if allow and host.lower() not in allow:
        raise BlockedURLError(f"host {host!r} is not in the image-url allowlist")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise BlockedURLError(f"cannot resolve host {host!r}: {e}") from e

    safe: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _is_blocked_ip(ip):
            raise BlockedURLError(f"host {host!r} resolves to blocked address {addr}")
        safe.append(addr)

    if not safe:
        raise BlockedURLError(f"host {host!r} did not resolve to any usable address")
    return ValidatedTarget(scheme=parsed.scheme, host=host, port=port, ip=safe[0])


async def validate_url(url: str) -> None:
    """Raise BlockedURLError if `url` must not be fetched server-side."""
    await resolve_validated(url)
