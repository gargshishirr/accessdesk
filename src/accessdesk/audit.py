"""Tamper-evident audit log.

Each entry stores the SHA-256 of the previous entry's hash plus its own canonical JSON, so
changing, inserting, deleting or reordering any entry breaks every hash after it. Entries are
appended inside the same transaction as the change they describe, so the log and the data can
never disagree.

A hash chain cannot detect someone deleting the newest entries. Publishing the head hash
(``GET /api/v1/audit/verify``) to another system closes that gap.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any

GENESIS_HASH = "0" * 64


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(
    prev_hash: str, seq: int, ts: int, actor: str, action: str, subject: str, details: dict[str, Any]
) -> str:
    body = canonical(
        {"seq": seq, "ts": ts, "actor": actor, "action": action, "subject": subject, "details": details}
    )
    return hashlib.sha256(f"{prev_hash}\n{body}".encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditEvent:
    seq: int
    ts: int
    actor: str
    action: str
    subject: str
    details: dict[str, Any]
    hash: str


@dataclass(frozen=True, slots=True)
class Verification:
    ok: bool
    events: int
    head_hash: str
    first_invalid_seq: int | None = None
    problem: str = ""


def append(
    conn: sqlite3.Connection, *, ts: int, actor: str, action: str, subject: str, details: dict[str, Any]
) -> AuditEvent:
    """Append one entry. Must run inside the caller's write transaction."""
    if not conn.in_transaction:
        raise RuntimeError("audit entries must be written inside the transaction that makes the change")
    last = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    prev_seq, prev_hash = (last["seq"], last["hash"]) if last else (0, GENESIS_HASH)
    seq = prev_seq + 1
    digest = entry_hash(prev_hash, seq, ts, actor, action, subject, details)
    conn.execute(
        "INSERT INTO audit_log (seq, ts, actor, action, subject, details, prev_hash, hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (seq, ts, actor, action, subject, canonical(details), prev_hash, digest),
    )
    return AuditEvent(seq, ts, actor, action, subject, details, digest)


def verify(conn: sqlite3.Connection) -> Verification:
    expected_prev = GENESIS_HASH
    count = 0
    for row in conn.execute("SELECT * FROM audit_log ORDER BY seq"):
        count += 1
        seq = row["seq"]
        if seq != count:
            return Verification(False, count, expected_prev, seq, f"Expected entry {count} but found {seq}")
        if row["prev_hash"] != expected_prev:
            return Verification(False, count, expected_prev, seq, "The link to the previous entry is broken")
        try:
            details = json.loads(row["details"])
        except json.JSONDecodeError:
            return Verification(False, count, expected_prev, seq, "The details are not valid JSON")
        recomputed = entry_hash(
            row["prev_hash"], seq, row["ts"], row["actor"], row["action"], row["subject"], details
        )
        if recomputed != row["hash"]:
            return Verification(
                False, count, expected_prev, seq, "The entry's content does not match its hash"
            )
        expected_prev = row["hash"]
    return Verification(True, count, expected_prev)


def recent(conn: sqlite3.Connection, limit: int = 100) -> list[AuditEvent]:
    rows = conn.execute("SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
    return [
        AuditEvent(
            r["seq"], r["ts"], r["actor"], r["action"], r["subject"], json.loads(r["details"]), r["hash"]
        )
        for r in rows
    ]
