"""WS /v1/channels/{name} must reject an envelope whose channel field doesn't
match the route it was sent on — otherwise an adapter connected as one channel
could impersonate another channel's trust/allowlist/pairing rules."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from starlette.websockets import WebSocketDisconnect


def _envelope(channel: str, channel_user_id: str) -> dict:
    return {
        "channel": channel,
        "channel_user_id": channel_user_id,
        "user_handle": channel_user_id,
        "text": "hi",
        "trust_level": "untrusted",
        "arrived_at": datetime.now(UTC).isoformat(),
    }


def test_matching_channel_passes_the_spoof_check(app_client):
    # channels.yaml disables telegram by default in the test env, so the
    # allowlist step still rejects it — but that's a separate, later check.
    # What matters here is that a matching channel never trips the spoof
    # check, i.e. the reply is never the channel-mismatch error.
    with app_client.websocket_connect("/v1/channels/telegram") as ws:
        ws.send_text(json.dumps(_envelope("telegram", "u1")))
        reply = json.loads(ws.receive_text())
        assert "does not match route" not in reply.get("error", "")


def test_mismatched_channel_is_rejected_and_socket_closed(app_client):
    with app_client.websocket_connect("/v1/channels/telegram") as ws:
        # Connected on the telegram route, but the envelope claims discord.
        ws.send_text(json.dumps(_envelope("discord", "attacker")))
        reply = json.loads(ws.receive_text())
        assert "error" in reply
        assert "telegram" in reply["error"] and "discord" in reply["error"]
        # The server closes the connection after a spoof attempt.
        try:
            ws.receive_text()
            raise AssertionError("expected the socket to be closed after a channel spoof attempt")
        except WebSocketDisconnect:
            pass
