from __future__ import annotations

import pytest

from accessdesk import audit
from accessdesk.db import Database


def _write(db: Database, n: int) -> None:
    with db.write() as conn:
        for i in range(n):
            audit.append(
                conn, ts=100 + i, actor="tester", action="test.event", subject=f"thing:{i}", details={"i": i}
            )


def test_chain_verifies_and_reports_head(db: Database) -> None:
    _write(db, 5)
    with db.connection() as conn:
        result = audit.verify(conn)
        head = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()[0]
    assert result.ok
    assert result.events == 5
    assert result.head_hash == head


@pytest.mark.parametrize(
    ("tamper", "first_bad"),
    [
        ("UPDATE audit_log SET details = '{\"i\":99}' WHERE seq = 3", 3),
        ("UPDATE audit_log SET actor = 'mallory' WHERE seq = 2", 2),
        ("DELETE FROM audit_log WHERE seq = 2", 3),
        ("UPDATE audit_log SET prev_hash = '" + "f" * 64 + "' WHERE seq = 4", 4),
    ],
)
def test_tampering_is_detected_at_the_exact_entry(db: Database, tamper: str, first_bad: int) -> None:
    _write(db, 5)
    with db.connection() as conn:
        conn.execute(tamper)
        result = audit.verify(conn)
    assert not result.ok
    assert result.first_invalid_seq == first_bad
    assert result.problem


def test_rewriting_the_whole_tail_changes_the_head_hash(db: Database) -> None:
    """A full rewrite re-links cleanly, which is why the head hash should be pinned elsewhere."""
    _write(db, 3)
    with db.connection() as conn:
        pinned = audit.verify(conn).head_hash
        conn.execute("DELETE FROM audit_log WHERE seq >= 2")
    with db.write() as conn:
        audit.append(conn, ts=101, actor="mallory", action="test.event", subject="thing:1", details={"i": 1})
        audit.append(conn, ts=102, actor="mallory", action="test.event", subject="thing:2", details={"i": 2})
        result = audit.verify(conn)
    assert result.ok
    assert result.head_hash != pinned


def test_append_outside_a_transaction_is_refused(db: Database) -> None:
    with db.connection() as conn, pytest.raises(RuntimeError):
        audit.append(conn, ts=1, actor="x", action="y", subject="z", details={})
