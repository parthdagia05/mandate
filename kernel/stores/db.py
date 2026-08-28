"""SQLite, opened the only way the kernel is allowed to open it.

``PRAGMA synchronous=FULL`` is the one that matters and the one that is easy to
miss. WAL defaults to ``NORMAL``, which does *not* fsync on commit — under the
default, check 9 would report "appended" for an entry a power cut can still
lose, and REQ-2 would quietly be false. The overhead column in ``results.md``
pays for this.

``STRICT`` tables need SQLite 3.37+, so the version is asserted at connect
time rather than discovered as a confusing syntax error later.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

__all__ = ["MIN_SQLITE_VERSION", "connect", "SCHEMA_SQL", "StoreUnavailable"]

MIN_SQLITE_VERSION = (3, 37, 0)


class StoreUnavailable(RuntimeError):
    """The store cannot answer. Every caller of this denies (REQ-5)."""


SCHEMA_SQL = """
-- The audit chain. payload_json holds the *canonical* JCS text, so the hash
-- is taken over exactly the bytes that were stored.
CREATE TABLE IF NOT EXISTS audit_entry (
    seq          INTEGER PRIMARY KEY,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL UNIQUE
) STRICT;

-- One row per intent. Authority and money position terminate independently,
-- which is why there are two state columns and not one.
CREATE TABLE IF NOT EXISTS spend_ledger (
    mandate_id          TEXT PRIMARY KEY,
    intent_json         TEXT NOT NULL,
    confirmed_cart_hash TEXT,
    execution_count     INTEGER NOT NULL DEFAULT 0,
    committed_paise     INTEGER NOT NULL DEFAULT 0,
    captured_paise      INTEGER NOT NULL DEFAULT 0,
    refunded_paise      INTEGER NOT NULL DEFAULT 0,
    mandate_state       TEXT NOT NULL DEFAULT 'active',
    ledger_state        TEXT NOT NULL DEFAULT 'empty',
    CHECK (refunded_paise >= 0),
    CHECK (refunded_paise <= captured_paise),
    CHECK (captured_paise <= committed_paise)
) STRICT;

-- A nonce is usable exactly once (REQ-6). The store is the enforcement, not
-- a check in code that someone can forget to call.
CREATE TABLE IF NOT EXISTS nonce_seen (
    nonce      TEXT PRIMARY KEY,
    mandate_id TEXT NOT NULL,
    seen_at    TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS idempotency_record (
    key          TEXT PRIMARY KEY,
    action       TEXT NOT NULL,
    state        TEXT NOT NULL,
    result_json  TEXT,
    reserved_at  TEXT NOT NULL,
    committed_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS payment (
    payment_id   TEXT PRIMARY KEY,
    mandate_id   TEXT NOT NULL REFERENCES spend_ledger(mandate_id),
    cart_hash    TEXT NOT NULL,
    source_json  TEXT NOT NULL,
    amount_paise INTEGER NOT NULL,
    currency     TEXT NOT NULL,
    state        TEXT NOT NULL,
    client_ref   TEXT NOT NULL,
    CHECK (amount_paise >= 0)
) STRICT;

-- Business-level dedup key. A PSP resending with a fresh event id is normal
-- at-least-once behaviour, so (mandate_id, cart_hash) is what dedups, not the
-- webhook's own identifier.
CREATE UNIQUE INDEX IF NOT EXISTS payment_business_key
    ON payment(mandate_id, cart_hash);

CREATE TABLE IF NOT EXISTS refund (
    refund_id        TEXT PRIMARY KEY,
    payment_id       TEXT NOT NULL REFERENCES payment(payment_id),
    amount_paise     INTEGER NOT NULL,
    destination_json TEXT NOT NULL,
    kind             TEXT NOT NULL,
    state            TEXT NOT NULL,
    idempotency_key  TEXT NOT NULL,
    CHECK (amount_paise >= 0)
) STRICT;
"""


def _assert_version() -> None:
    if sqlite3.sqlite_version_info < MIN_SQLITE_VERSION:
        raise StoreUnavailable(
            "SQLite "
            + ".".join(str(part) for part in MIN_SQLITE_VERSION)
            + f"+ is required for STRICT tables; this build is "
            f"{sqlite3.sqlite_version}"
        )


def connect(path: str | Path) -> sqlite3.Connection:
    """Open the kernel's database with the pragmas REQ-2 and REQ-5 depend on."""
    _assert_version()
    # ``check_same_thread=False`` because the API server serves from a thread
    # other than the one that opened the store. It is not a licence for
    # concurrency: SQLite has a single writer, the chain allocates ``seq`` by
    # reading the head and inserting after it, and two interleaved requests
    # would race on both. The API is single-threaded and serialises dispatch
    # for exactly that reason (see :mod:`kernel.api`), and SPEC.md §08 runs one
    # kernel process per run with cases sequential inside it.
    conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=FULL")

    # Assert rather than assume: a pragma that silently failed to apply would
    # make REQ-2 false in a way nothing else in the system would notice.
    if conn.execute("PRAGMA synchronous").fetchone()[0] != 2:  # 2 == FULL
        raise StoreUnavailable("synchronous=FULL did not take; refusing to run")
    if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise StoreUnavailable("foreign_keys=ON did not take; refusing to run")

    conn.executescript(SCHEMA_SQL)
    return conn
