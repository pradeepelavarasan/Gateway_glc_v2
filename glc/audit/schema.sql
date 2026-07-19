-- glc_v1 audit log. Append-only + hash-chained: each row carries the hash of
-- the previous row's hash plus its own content, so any mid-sequence edit or
-- deletion breaks the chain. A separate audit_head anchor records the expected
-- tail so a full `DELETE FROM audit_log` (which leaves an empty, trivially-valid
-- table) is still caught.

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    session_id      TEXT,
    channel         TEXT    NOT NULL,
    channel_user_id TEXT    NOT NULL,
    trust_level     TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    tool            TEXT,
    policy_verdict  TEXT,
    params_json     TEXT,
    result_json     TEXT,
    prev_hash       TEXT    NOT NULL,
    row_hash        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_channel ON audit_log(channel, ts DESC);

-- Single-row anchor: the expected tail of the chain. Updated on every append.
CREATE TABLE IF NOT EXISTS audit_head (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    last_id   INTEGER NOT NULL,
    last_hash TEXT    NOT NULL,
    count     INTEGER NOT NULL
);

-- Schema version table: any change to the columns above requires a
-- documented version bump. Migrations are not automatic.
CREATE TABLE IF NOT EXISTS audit_schema (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);
INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (1, strftime('%s','now'));
