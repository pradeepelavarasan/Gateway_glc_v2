"""Client-facing error helpers.

Upstream/provider failures must not leak their raw detail — the provider
name, its endpoint, or its raw error response — to the client, since that
hands an attacker a map of the gateway's backends for free. `upstream_error`
records the full detail server-side and returns a generic message instead.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException

_log = logging.getLogger("glc.upstream")


def upstream_error(
    status_code: int,
    *,
    log_detail: str,
    client_detail: str = "upstream provider request failed",
) -> HTTPException:
    """Log the full upstream detail server-side; return a generic HTTPException.

    The returned exception carries only `client_detail` — never the provider
    name, endpoint, or raw upstream body. `log_detail` goes to the server log.
    """
    _log.warning("upstream error [%s]: %s", status_code, log_detail)
    return HTTPException(status_code, client_detail)
