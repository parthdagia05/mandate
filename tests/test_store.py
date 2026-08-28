"""The store opens the only way REQ-2 and REQ-5 allow.

``synchronous=FULL`` is the pragma that carries REQ-2. WAL defaults to
``NORMAL``, which does not fsync on commit — under the default, check 9 would
report "appended" for an entry a power cut can still lose. That is not a
performance tuning question; it is whether the audit chain is a record or a
hope.
"""

from __future__ import annotations

import sqlite3

import pytest

from kernel.stores.db import MIN_SQLITE_VERSION, connect


@pytest.fixture
def conn(tmp_path):
    connection = connect(tmp_path / "kernel.db")
    try:
        yield connection
    finally:
        connection.close()


def test_sqlite_is_new_enough_for_strict_tables():
    assert sqlite3.sqlite_version_info >= MIN_SQLITE_VERSION


def test_pragmas_are_what_the_invariants_assume(conn):
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL


def test_every_table_is_strict(conn):
    """STRICT is what stops SQLite storing a string in an INTEGER column, which
    is how a paise amount would quietly become text."""
    rows = conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    assert rows
    for row in rows:
        assert row["sql"].rstrip().endswith("STRICT"), f"{row['name']} is not STRICT"


def test_strict_typing_rejects_a_string_amount(conn):
    conn.execute(
        "INSERT INTO spend_ledger (mandate_id, intent_json) VALUES ('im_x', '{}')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE spend_ledger SET committed_paise = 'lots' WHERE mandate_id='im_x'"
        )


def test_ledger_money_ordering_is_enforced_by_the_database(conn):
    """P-03 belongs in the schema as well as the model: a ledger that can hold
    an impossible position is fiction whichever layer wrote it."""
    conn.execute(
        "INSERT INTO spend_ledger (mandate_id, intent_json, committed_paise, "
        "captured_paise) VALUES ('im_y', '{}', 100, 50)"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE spend_ledger SET captured_paise = 200 WHERE mandate_id='im_y'"
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE spend_ledger SET refunded_paise = 60 WHERE mandate_id='im_y'"
        )


def test_foreign_keys_are_enforced(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO payment (payment_id, mandate_id, cart_hash, source_json, "
            "amount_paise, currency, state, client_ref) VALUES "
            "('pay_1', 'im_missing', 'sha256:x', '{}', 100, 'INR', 'created', 'ref')"
        )


def test_business_dedup_key_is_unique(conn):
    """REQ-7: a PSP resending with a fresh event id is normal at-least-once
    behaviour, so dedup is on (mandate_id, cart_hash), not the event id."""
    conn.execute(
        "INSERT INTO spend_ledger (mandate_id, intent_json) VALUES ('im_z', '{}')"
    )
    insert = (
        "INSERT INTO payment (payment_id, mandate_id, cart_hash, source_json, "
        "amount_paise, currency, state, client_ref) VALUES "
        "(?, 'im_z', 'sha256:abc', '{}', 100, 'INR', 'captured', 'ref')"
    )
    conn.execute(insert, ("pay_1",))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(insert, ("pay_2",))


def test_audit_seq_is_a_primary_key(conn):
    row = (
        "INSERT INTO audit_entry (seq, ts, actor, action, payload_json, "
        "prev_hash, entry_hash) VALUES (0, '2026-01-01T00:00:00Z', 'kernel', "
        "'authorize.allow', '{}', 'sha256:a', ?)"
    )
    conn.execute(row, ("sha256:b",))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(row, ("sha256:c",))
