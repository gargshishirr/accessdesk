"""SQLite storage: schema, per-thread connections and explicit write transactions.

Every state change runs inside ``BEGIN IMMEDIATE``, which takes SQLite's write lock up front.
Writers are therefore serialized: two approvers clicking at the same moment cannot both create
a grant, and the audit hash chain always grows in a single line.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL,
    team        TEXT NOT NULL,
    title       TEXT NOT NULL DEFAULT '',
    manager_id  TEXT REFERENCES users(id),
    is_security INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS resources (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL,
    owner_id           TEXT NOT NULL REFERENCES users(id),
    sensitivity        TEXT NOT NULL CHECK (sensitivity IN ('low', 'medium', 'high', 'critical')),
    max_hours          INTEGER NOT NULL CHECK (max_hours > 0),
    roles              TEXT NOT NULL,
    auto_approve_teams TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sod_rules (
    id              TEXT PRIMARY KEY,
    description     TEXT NOT NULL,
    first_resource  TEXT NOT NULL REFERENCES resources(id),
    first_role      TEXT NOT NULL,
    second_resource TEXT NOT NULL REFERENCES resources(id),
    second_role     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id  TEXT NOT NULL REFERENCES users(id),
    resource_id   TEXT NOT NULL REFERENCES resources(id),
    role          TEXT NOT NULL,
    hours         INTEGER NOT NULL,
    justification TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'cancelled')),
    required      TEXT NOT NULL,
    reasons       TEXT NOT NULL,
    detail        TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    decided_at    INTEGER,
    version       INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_requests_status ON requests(status);
CREATE INDEX IF NOT EXISTS ix_requests_requester ON requests(requester_id, created_at);

CREATE TABLE IF NOT EXISTS approvals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id  INTEGER NOT NULL REFERENCES requests(id),
    approver_id TEXT NOT NULL REFERENCES users(id),
    kind        TEXT NOT NULL,
    verdict     TEXT NOT NULL CHECK (verdict IN ('approve', 'deny')),
    comment     TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    UNIQUE (request_id, approver_id)
);

CREATE TABLE IF NOT EXISTS grants (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id  INTEGER NOT NULL UNIQUE REFERENCES requests(id),
    user_id     TEXT NOT NULL REFERENCES users(id),
    resource_id TEXT NOT NULL REFERENCES resources(id),
    role        TEXT NOT NULL,
    granted_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    ended_at    INTEGER,
    end_reason  TEXT CHECK (end_reason IN ('expired', 'revoked', 'released')),
    ended_by    TEXT,
    end_note    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_grants_active ON grants(user_id, resource_id) WHERE ended_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_grants_expiry ON grants(expires_at) WHERE ended_at IS NULL;

CREATE TABLE IF NOT EXISTS audit_log (
    seq       INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    subject   TEXT NOT NULL,
    details   TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
"""


class Database:
    """Hands out one connection per thread and opens explicit transactions."""

    def __init__(self, path: str) -> None:
        if path == ":memory:":
            raise ValueError("use a file path: each thread needs its own connection to the same database")
        self.path = path
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []
        self._lock = threading.Lock()
        with self.connection() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(SCHEMA)

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute("PRAGMA synchronous = NORMAL")
        with self._lock:
            self._all.append(conn)
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._open()
            self._local.conn = conn
        yield conn

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        """A transaction that holds SQLite's write lock from the first statement to commit."""
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            for conn in self._all:
                conn.close()
            self._all.clear()
        self._local = threading.local()
