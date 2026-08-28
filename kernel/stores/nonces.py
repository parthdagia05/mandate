"""The nonce store. Single-use authority, enforced by a unique index.

Check 1's third conjunct is ``nonce ∉ store``, and the enforcement is the
``PRIMARY KEY`` on ``nonce_seen.nonce`` rather than a branch in Python. The
difference shows up under concurrency and under a crash: two registrations
racing on the same nonce both pass a read-then-write check and exactly one
survives an insert.

The row records *which mandate* consumed the nonce, not merely that one did.
That is what lets check 1 ask two different questions of the same store — "is
this nonce free?" when minting authority, and "is it bound to this mandate?" on
every later call — instead of burning the nonce at registration and then having
nothing to compare against for the rest of the mandate's life.
"""

from __future__ import annotations

import sqlite3

from kernel.clock import Clock
from kernel.stores.base import Store, StoreGuard, no_guard

__all__ = ["NonceStore", "NonceAlreadyUsed"]


class NonceAlreadyUsed(RuntimeError):
    """Lost the race to consume a nonce. The loser denies (NONCE_REPLAYED)."""


class NonceStore(Store):
    name = "nonces"

    def __init__(
        self, conn: sqlite3.Connection, clock: Clock, guard: StoreGuard = no_guard
    ) -> None:
        super().__init__(conn, guard)
        self._clock = clock

    def owner(self, nonce: str) -> str | None:
        """The mandate that consumed ``nonce``, or ``None`` if it is unused."""

        def read() -> str | None:
            row = self._conn.execute(
                "SELECT mandate_id FROM nonce_seen WHERE nonce = ?", (nonce,)
            ).fetchone()
            return row["mandate_id"] if row else None

        return self._guarded("read", read)

    def consume(self, nonce: str, mandate_id: str) -> None:
        """Bind ``nonce`` to ``mandate_id``, exactly once, or raise."""

        def write() -> None:
            try:
                self._conn.execute(
                    "INSERT INTO nonce_seen (nonce, mandate_id, seen_at)"
                    " VALUES (?, ?, ?)",
                    (nonce, mandate_id, self._clock.now_rfc3339()),
                )
            except sqlite3.IntegrityError as exc:
                # Not a store failure: the store worked and the answer is no.
                raise NonceAlreadyUsed(nonce) from exc

        self._guarded("write", write)
