"""Short-lived, provider-scoped capability tokens.

The gateway holds no provider keys. When it needs an upstream call it mints a
capability token scoped to one provider, for a few seconds, and hands it to the
broker (the only component with the keys). The broker verifies the token before
making the call. This is the "per-tool credential issuance" that replaces
handing every component the shared provider secret.

The signing key (GLC_BROKER_SIGN_KEY) is shared only between the gateway and the
broker; it is not a provider key. If it is unset, minting/verifying raises, so a
misconfigured deployment fails closed rather than skipping the check.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time

_DEFAULT_TTL = 30  # seconds


class CapabilityError(Exception):
    """Raised when a capability token is missing, malformed, or invalid."""


def _sign_key() -> bytes:
    key = os.getenv("GLC_BROKER_SIGN_KEY")
    if not key:
        raise CapabilityError("GLC_BROKER_SIGN_KEY is not set")
    return key.encode()


def _sign(msg: str) -> str:
    return hmac.new(_sign_key(), msg.encode(), hashlib.sha256).hexdigest()


def mint(provider: str, *, purpose: str = "complete", ttl: int = _DEFAULT_TTL) -> str:
    """Mint a token authorizing one call to `provider` for `purpose`, expiring soon."""
    exp = int(time.time()) + ttl
    nonce = secrets.token_urlsafe(8)
    body = f"{provider}|{purpose}|{exp}|{nonce}"
    return f"{body}|{_sign(body)}"


def verify(token: str, *, provider: str, purpose: str = "complete") -> None:
    """Raise CapabilityError unless `token` is a valid, unexpired token scoped
    to exactly this `provider` and `purpose`."""
    parts = token.split("|")
    if len(parts) != 5:
        raise CapabilityError("malformed capability token")
    tok_provider, tok_purpose, exp_s, nonce, sig = parts
    body = f"{tok_provider}|{tok_purpose}|{exp_s}|{nonce}"
    if not hmac.compare_digest(sig, _sign(body)):
        raise CapabilityError("bad capability signature")
    if tok_provider != provider or tok_purpose != purpose:
        raise CapabilityError(
            f"capability scoped to {tok_provider}/{tok_purpose}, not {provider}/{purpose}"
        )
    try:
        expired = int(exp_s) < int(time.time())
    except ValueError:
        raise CapabilityError("malformed capability expiry") from None
    if expired:
        raise CapabilityError("capability token expired")
