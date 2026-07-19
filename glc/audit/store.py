"""Append-only SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. Append-only is enforced at the application layer: only
`append()` is exposed; there is no update or delete function. The schema
ships with `audit_schema` version 1; bumping it requires a documented
migration step (see schema.sql).

Each append commits immediately so writes survive a hard kill.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
_log = logging.getLogger("glc.audit")
_GENESIS = "0" * 64


def _row_hash(prev_hash: str, payload: dict) -> str:
    """sha256 over the previous row's hash plus this row's canonical content."""
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def _payload(row) -> dict:
    """The content fields that go into a row's hash (never id/prev_hash/row_hash)."""
    return {
        "ts": row["ts"],
        "session_id": row["session_id"],
        "channel": row["channel"],
        "channel_user_id": row["channel_user_id"],
        "trust_level": row["trust_level"],
        "event_type": row["event_type"],
        "tool": row["tool"],
        "policy_verdict": row["policy_verdict"],
        "params_json": row["params_json"],
        "result_json": row["result_json"],
    }


def _resolve_path() -> str:
    """Resolve at call time, not import time, so tests that swap the env
    var see the change."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)  # autocommit; each insert flushes
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def init_store() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA_PATH.read_text())


def _jsonify(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return json.dumps({"_repr": repr(v)})


class AuditStore:
    """Application-layer write-once store. The class exposes no update or
    delete methods, and each row is hash-chained to the previous one so that
    tampering with the underlying file is detectable by verify_chain()."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def append(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        session_id: str | None = None,
        tool: str | None = None,
        policy_verdict: str | None = None,
        params: Any = None,
        result: Any = None,
    ) -> int:
        payload = {
            "ts": time.time(),
            "session_id": session_id,
            "channel": channel,
            "channel_user_id": channel_user_id,
            "trust_level": trust_level,
            "event_type": event_type,
            "tool": tool,
            "policy_verdict": policy_verdict,
            "params_json": _jsonify(params),
            "result_json": _jsonify(result),
        }
        with self._lock, _conn() as c:
            head = c.execute("SELECT last_hash, count FROM audit_head WHERE id=1").fetchone()
            prev_hash = head["last_hash"] if head else _GENESIS
            count = head["count"] if head else 0
            row_hash = _row_hash(prev_hash, payload)
            cur = c.execute(
                """INSERT INTO audit_log
                   (ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json,
                    prev_hash, row_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*payload.values(), prev_hash, row_hash),
            )
            new_id = int(cur.lastrowid or 0)
            c.execute(
                """INSERT INTO audit_head (id, last_id, last_hash, count) VALUES (1, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       last_id=excluded.last_id, last_hash=excluded.last_hash, count=excluded.count""",
                (new_id, row_hash, count + 1),
            )
        # External anchor: the head also goes to the server log, which on Modal is
        # off-box and append-only — so even a full-table wipe leaves a trail.
        _log.info("audit head id=%s hash=%s count=%s", new_id, row_hash, count + 1)
        return new_id


def verify_chain() -> dict:
    """Walk the audit log and check the hash chain against the head anchor.

    Returns {"ok", "reason", "rows", "expected"}. Detects content edits (row
    hash mismatch), mid-sequence deletion (broken link), and full/partial wipes
    (row count below the anchor).
    """
    with _conn() as c:
        head = c.execute("SELECT last_hash, count FROM audit_head WHERE id=1").fetchone()
        rows = c.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    expected = head["count"] if head else 0
    result = {"rows": len(rows), "expected": expected}
    if len(rows) != expected:
        return {**result, "ok": False, "reason": f"row count {len(rows)} != expected {expected} (rows deleted)"}
    prev = _GENESIS
    for r in rows:
        if r["prev_hash"] != prev:
            return {**result, "ok": False, "reason": f"row id={r['id']}: broken link (chain tampered)"}
        if r["row_hash"] != _row_hash(prev, _payload(r)):
            return {**result, "ok": False, "reason": f"row id={r['id']}: content hash mismatch (row edited)"}
        prev = r["row_hash"]
    if head and prev != head["last_hash"]:
        return {**result, "ok": False, "reason": "tail hash does not match anchor"}
    return {**result, "ok": True, "reason": "chain intact"}


_singleton: AuditStore | None = None


def get_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        init_store()
        _singleton = AuditStore()
    return _singleton


def append(**kwargs: Any) -> int:
    return get_store().append(**kwargs)


def query(limit: int = 100, session_id: str | None = None, channel: str | None = None) -> list[dict]:
    q = "SELECT * FROM audit_log"
    where, args = [], []
    if session_id:
        where.append("session_id=?")
        args.append(session_id)
    if channel:
        where.append("channel=?")
        args.append(channel)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def schema_version() -> int:
    with _conn() as c:
        row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
        return int(row["v"] or 0)
