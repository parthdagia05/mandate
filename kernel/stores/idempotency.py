"""Check 7's store: reserve, execute, commit — and recover when that is cut short.

``key = SHA256(mandate_id ‖ cart_hash ‖ action)``

Three states, not two, because **"reserved but outcome unknown" is a real
position** and a two-state design has to pretend it is not. A crash between the
PSP call and the commit leaves a row that means "someone started this and we do
not know how it ended", and the only correct thing to do with it is ask the PSP
— never blindly retry, which double-charges, and never silently skip, which is
how a debit ends up with nothing recording it. **Skipping is not a transition.**

::

    absent ──reserve──▶ in_flight ──commit──▶ terminal
                            │                     ▲
                            └──TTL──▶ recovering──┘

The reservation is an ``INSERT`` against a ``PRIMARY KEY``, so two concurrent
requests for the same key do not both see "absent" and both proceed; exactly
one insert survives and the other is told the key is held.

``result_json`` is the response replayed verbatim on a retry. Verbatim matters:
a replay that recomputed its answer could return a *different* decision for the
same key — the ledger having moved underneath it — and the caller would have no
way to tell a replay from a second, differently-judged action.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from kernel.canonical import sha256_hex
from kernel.clock import Clock, from_rfc3339
from kernel.enums import ActionType, IdempotencyState
from kernel.models import IdempotencyRecord
from kernel.stores.base import Store, StoreGuard, no_guard

__all__ = ["RECOVERY_TTL_S", "KEY_SEPARATOR", "idempotency_key", "Reservation", "IdempotencyStore"]

#: How long an ``in_flight`` row is respected before the recovery scan claims
#: it. Thirty seconds of *injected* clock, so the failure suite reaches it by
#: advancing the control port rather than by waiting.
RECOVERY_TTL_S = 30

#: The same U+001F the audit chain uses. RFC 8785 escapes every control
#: character, so it cannot appear inside any field being joined, which is what
#: stops ``(im_1, cart_2)`` and ``(im_1cart, _2)`` hashing alike.
KEY_SEPARATOR = "\x1f"


def idempotency_key(mandate_id: str, cart_hash: str, action: ActionType | str) -> str:
    """``H(mandate_id ‖ cart_hash ‖ action)``, SPEC.md §05.

    The cart hash is in the key, not the cart id: two carts with different ids
    and identical contents are the same purchase, and giving them different keys
    would let the same debit through twice.
    """
    joined = KEY_SEPARATOR.join([mandate_id, cart_hash, str(action)])
    return sha256_hex(joined.encode("utf-8"))


@dataclass(frozen=True)
class Reservation:
    """What ``reserve`` found. ``outcome`` drives the lifecycle's next step."""

    #: ``fresh`` — the key is ours, proceed to the PSP.
    #: ``in_flight`` — someone else holds it inside the TTL; answer 202.
    #: ``recovering`` — the TTL lapsed; poll the PSP for the true outcome.
    #: ``terminal`` — already finished; replay ``record.result_json`` verbatim.
    outcome: str
    key: str
    record: IdempotencyRecord | None = None


class IdempotencyStore(Store):
    name = "idempotency"

    def __init__(
        self, conn: sqlite3.Connection, clock: Clock, guard: StoreGuard = no_guard
    ) -> None:
        super().__init__(conn, guard)
        self._clock = clock

    def get(self, key: str) -> IdempotencyRecord | None:
        def read() -> IdempotencyRecord | None:
            row = self._conn.execute(
                "SELECT * FROM idempotency_record WHERE key = ?", (key,)
            ).fetchone()
            if row is None:
                return None
            return IdempotencyRecord(
                key=row["key"],
                action=ActionType(row["action"]),
                state=IdempotencyState(row["state"]),
                result_json=row["result_json"],
                reserved_at=row["reserved_at"],
                committed_at=row["committed_at"],
            )

        return self._guarded("read", read)

    def reserve(self, key: str, action: ActionType) -> Reservation:
        """Claim ``key``, or report who holds it and in what state."""
        now = self._clock.now_rfc3339()

        def write() -> Reservation | None:
            try:
                self._conn.execute(
                    "INSERT INTO idempotency_record"
                    " (key, action, state, result_json, reserved_at, committed_at)"
                    " VALUES (?, ?, ?, NULL, ?, NULL)",
                    (key, str(action), str(IdempotencyState.IN_FLIGHT), now),
                )
                return Reservation(outcome="fresh", key=key)
            except sqlite3.IntegrityError:
                # Someone holds it. Which someone, and in what state, is the
                # question the caller actually needs answered.
                return None

        claimed = self._guarded("write", write)
        if claimed is not None:
            return claimed

        held = self.get(key)
        if held is None:  # pragma: no cover - deleted between insert and read
            return Reservation(outcome="in_flight", key=key)

        if held.state == IdempotencyState.TERMINAL:
            return Reservation(outcome="terminal", key=key, record=held)

        age = (
            from_rfc3339(now) - from_rfc3339(held.reserved_at)
        ).total_seconds()
        if held.state == IdempotencyState.RECOVERING or age >= RECOVERY_TTL_S:
            return Reservation(outcome="recovering", key=key, record=held)
        return Reservation(outcome="in_flight", key=key, record=held)

    def mark_recovering(self, key: str) -> None:
        self._guard(self.name, "write")
        self._conn.execute(
            "UPDATE idempotency_record SET state = ? WHERE key = ?",
            (str(IdempotencyState.RECOVERING), key),
        )

    def commit(self, key: str, result_json: str) -> None:
        """Move to ``terminal``. Runs inside the caller's transaction.

        No ``BEGIN`` here on purpose: SPEC.md §08 step 8 requires this and the
        ledger write to be one transaction. If they could diverge, the ledger is
        fiction.
        """
        self._guard(self.name, "write")
        self._conn.execute(
            "UPDATE idempotency_record"
            "   SET state = ?, result_json = ?, committed_at = ?"
            " WHERE key = ?",
            (str(IdempotencyState.TERMINAL), result_json, self._clock.now_rfc3339(), key),
        )

    def release(self, key: str) -> None:
        """Drop a reservation whose action never reached the rail.

        Used only when the kernel is certain no PSP call happened — a fault
        fired before it, or the call itself refused to start. A reservation
        released after a call the PSP may have accepted would let the next
        request produce a second debit, which is why this is not the general
        error path: the general error path leaves the row ``in_flight`` for
        recovery to resolve against the PSP.
        """
        self._guard(self.name, "write")
        self._conn.execute("DELETE FROM idempotency_record WHERE key = ?", (key,))
