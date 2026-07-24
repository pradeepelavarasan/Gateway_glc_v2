"""Runs inside a broker Sandbox. Invoked as:

    python -m glc.security.broker_entrypoint <base64-json-request>

request = {"kind": ..., "payload": ..., "provider": ..., "token": ...}

Prints one line of JSON to stdout: either {"ok": true, "result": ...} or
{"ok": false, "error": ...}. Kept a thin CLI wrapper around the same
InProcessBroker/capabilities logic the Function-based broker uses, so the
dispatch behavior is identical regardless of transport.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys


async def _run(req: dict) -> dict:
    from glc.cache import GeminiCache
    from glc.security.broker import InProcessBroker
    from glc.security.capabilities import verify

    kind = req["kind"]
    payload = req["payload"]
    provider = req.get("provider")
    token = req.get("token", "")

    broker = InProcessBroker(GeminiCache(ttl_seconds=300))
    if kind == "__enabled__":
        return await broker.enabled(payload["kind"])
    verify(token, provider=provider or kind, purpose=kind)
    return await broker.call(kind, payload, provider=provider)


def main() -> None:
    req = json.loads(base64.b64decode(sys.argv[1]))
    try:
        result = asyncio.run(_run(req))
        print(json.dumps({"ok": True, "result": result}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))


if __name__ == "__main__":
    main()
