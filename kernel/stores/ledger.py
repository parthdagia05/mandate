"""The spend ledger: one row per intent, and the kernel's record of payments.

This is the only account of how much of a mandate is left. Two state columns,
not one, because **authority and money terminate independently**: a fully
refunded purchase leaves ``ledger_state`` at ``fully_refunded`` and
``mandate_state`` at ``exhausted``. The money came back; the permission did
not, and a single column would have to pick one of those to be wrong about.

**There is no widening transition anywhere in this module.** Nothing raises a
ceiling, resets a count, or moves a terminal ``mandate_state`` back to
``active``. An escalation a human approves produces a *new* signed intent with
its own row — because the signature on the old one covers the old scope, and
editing the scope would leave a signature that no longer says what the row now
permits.

**When the execution count moves.** At authorize, not at capture. Check 6 reads
``execution_count`` and ``committed_paise`` together, and ``committed`` moves
when funds are reserved; if the count moved a step later the two conjuncts
would be reading the mandate at two different moments and an agent could hold
any number of simultaneous authorizations against a one-transaction mandate. A
capture that follows its own authorize is the same transaction settling, not a
second one.

**Expiry is not stored.** SPEC.md §06 evaluates it lazily on the next call, and
check 1 does exactly that from the kernel's clock. Writing an ``expired`` row on
a denied request would mean the deny path takes a write lock, which is the one
path that must never depend on being able to write anything but the chain.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from kernel.canonical import jcs
from kernel.enums import LedgerState, MandateState
from kernel.models import IntentMandate, SpendLedger
from kernel.stores.base import Store, StoreGuard, no_guard
from kernel.stores.db import StoreUnavailable

__all__ = ["LedgerStore", "AlreadyRegistered"]


class AlreadyRegistered(RuntimeError):
    """This intent already has a row. Registering again would re-mint authority."""


class LedgerStore(Store):
    name = "ledger"

    def __init__(self, conn: sqlite3.Connection, guard: StoreGuard = no_guard) -> None:
        super().__init__(conn, guard)

    # -- the intent's row -------------------------------------------------

    def open_row(self, intent: IntentMandate, confirmed_cart_hash: str) -> SpendLedger:
        """Open the ledger row for a freshly registered intent.

        ``confirmed_cart_hash`` comes from the user-confirmed CartMandate the
        registration carried, never from a field the agent can set. Check 4's
        second conjunct compares against this value, so a hash the agent chose
        would make that conjunct compare a request to itself.
        """

        def write() -> None:
            try:
                self._conn.execute(
                    "INSERT INTO spend_ledger"
                    " (mandate_id, intent_json, confirmed_cart_hash,"
                    "  execution_count, committed_paise, captured_paise,"
                    "  refunded_paise, mandate_state, ledger_state)"
                    " VALUES (?, ?, ?, 0, 0, 0, 0, ?, ?)",
                    (
                        intent.mandate_id,
                        # Canonical, so the stored intent is byte-identical to
                        # the bytes the signature was verified over.
                        jcs(intent.canonical_dict()),
                        confirmed_cart_hash,
                        str(MandateState.ACTIVE),
                        str(LedgerState.EMPTY),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise AlreadyRegistered(intent.mandate_id) from exc

        self._guarded("write", write)
        row = self.get(intent.mandate_id)
        if row is None:  # pragma: no cover - the insert above just succeeded
            raise StoreUnavailable("ledger row vanished immediately after insert")
        return row

    def get(self, mandate_id: str) -> SpendLedger | None:
        def read() -> SpendLedger | None:
            row = self._conn.execute(
                "SELECT * FROM spend_ledger WHERE mandate_id = ?", (mandate_id,)
            ).fetchone()
            if row is None:
                return None
            return SpendLedger(
                mandate_id=row["mandate_id"],
                intent_json=row["intent_json"],
                confirmed_cart_hash=row["confirmed_cart_hash"],
                execution_count=row["execution_count"],
                committed_paise=row["committed_paise"],
                captured_paise=row["captured_paise"],
                refunded_paise=row["refunded_paise"],
                mandate_state=MandateState(row["mandate_state"]),
                ledger_state=LedgerState(row["ledger_state"]),
            )

        return self._guarded("read", read)

    # -- money movements, all of them inside the caller's transaction -----
    #
    # None of these open a transaction of their own. SPEC.md §08 step 8 requires
    # the idempotency commit, the ledger write and the settle-leg audit entry to
    # be one transaction: if the idempotency record and the ledger can diverge,
    # the ledger is fiction. So the service owns the BEGIN and these are the
    # statements that run inside it.

    def apply_authorize(self, mandate_id: str, amount_paise: int) -> None:
        """Reserve funds: committed moves, one transaction slot is spent."""
        self._guard(self.name, "write")
        self._conn.execute(
            "UPDATE spend_ledger"
            "   SET committed_paise = committed_paise + ?,"
            "       execution_count = execution_count + 1,"
            "       ledger_state = ?"
            " WHERE mandate_id = ?",
            (amount_paise, str(LedgerState.COMMITTED), mandate_id),
        )

    def apply_capture(
        self, mandate_id: str, amount_paise: int, scope: dict[str, Any]
    ) -> None:
        """Settle, and exhaust the mandate if this spent the last of it.

        ``exhausted`` is reached when either ceiling is met — the count or the
        money — because either one alone ends the authority.
        """
        self._guard(self.name, "write")
        self._conn.execute(
            "UPDATE spend_ledger"
            "   SET captured_paise = captured_paise + ?,"
            "       ledger_state = ?"
            " WHERE mandate_id = ?",
            (amount_paise, str(LedgerState.CAPTURED), mandate_id),
        )
        row = self._conn.execute(
            "SELECT execution_count, committed_paise FROM spend_ledger"
            " WHERE mandate_id = ?",
            (mandate_id,),
        ).fetchone()
        spent = (
            row["execution_count"] >= scope["max_transactions"]
            or row["committed_paise"] >= scope["max_amount"]
        )
        if spent:
            self._conn.execute(
                "UPDATE spend_ledger SET mandate_state = ? WHERE mandate_id = ?",
                (str(MandateState.EXHAUSTED), mandate_id),
            )

    def apply_refund(self, mandate_id: str, amount_paise: int) -> None:
        self._guard(self.name, "write")
        self._conn.execute(
            "UPDATE spend_ledger"
            "   SET refunded_paise = refunded_paise + ?"
            " WHERE mandate_id = ?",
            (amount_paise, mandate_id),
        )
        row = self._conn.execute(
            "SELECT captured_paise, refunded_paise FROM spend_ledger"
            " WHERE mandate_id = ?",
            (mandate_id,),
        ).fetchone()
        state = (
            LedgerState.FULLY_REFUNDED
            if row["refunded_paise"] >= row["captured_paise"]
            else LedgerState.PARTIALLY_REFUNDED
        )
        # The mandate_state is deliberately untouched: refunding money does not
        # give the authority back.
        self._conn.execute(
            "UPDATE spend_ledger SET ledger_state = ? WHERE mandate_id = ?",
            (str(state), mandate_id),
        )

    # -- the kernel's own payment records ---------------------------------

    def record_payment(
        self,
        *,
        payment_id: str,
        mandate_id: str,
        cart_hash: str,
        source: dict[str, Any],
        amount_paise: int,
        currency: str,
        state: str,
        client_ref: str,
    ) -> None:
        """Bind a PSP payment to the authority that permitted it.

        The adapter cannot build this row: a PSP has never heard of a mandate,
        and an adapter that could mint a ``mandate_id`` would be an adapter that
        could mint authority. ``source`` is the account check 8 later refunds
        to, and it is recorded here because the request has no field for it.
        """
        self._guard(self.name, "write")
        self._conn.execute(
            "INSERT OR REPLACE INTO payment"
            " (payment_id, mandate_id, cart_hash, source_json, amount_paise,"
            "  currency, state, client_ref)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                payment_id,
                mandate_id,
                cart_hash,
                jcs(source),
                amount_paise,
                currency,
                state,
                client_ref,
            ),
        )

    def get_payment(self, payment_id: str) -> dict[str, Any] | None:
        def read() -> dict[str, Any] | None:
            row = self._conn.execute(
                "SELECT * FROM payment WHERE payment_id = ?", (payment_id,)
            ).fetchone()
            if row is None:
                return None
            return {
                "payment_id": row["payment_id"],
                "mandate_id": row["mandate_id"],
                "cart_hash": row["cart_hash"],
                "source": json.loads(row["source_json"]),
                "amount_paise": row["amount_paise"],
                "currency": row["currency"],
                "state": row["state"],
                "client_ref": row["client_ref"],
            }

        return self._guarded("read", read)

    def payment_for_cart(self, mandate_id: str, cart_hash: str) -> dict[str, Any] | None:
        """The payment this mandate opened for this cart, if any.

        ``(mandate_id, cart_hash)`` is the business key — a unique index, not a
        convention — and it is what links a capture back to the authorize that
        preceded it. Deliberately not the PSP's payment id: the capture request
        carries no such field, and a field the agent supplied would let it name
        someone else's payment.
        """

        def read() -> str | None:
            row = self._conn.execute(
                "SELECT payment_id FROM payment"
                " WHERE mandate_id = ? AND cart_hash = ?",
                (mandate_id, cart_hash),
            ).fetchone()
            return row["payment_id"] if row else None

        payment_id = self._guarded("read", read)
        return self.get_payment(payment_id) if payment_id else None

    def set_payment_state(self, payment_id: str, state: str) -> None:
        """Move a recorded payment forward. Runs inside the caller's transaction."""
        self._guard(self.name, "write")
        self._conn.execute(
            "UPDATE payment SET state = ? WHERE payment_id = ?", (state, payment_id)
        )

    # -- the kernel's own refund records ----------------------------------

    def record_refund(
        self,
        *,
        refund_id: str,
        payment_id: str,
        amount_paise: int,
        destination: dict[str, Any],
        kind: str,
        state: str,
        idempotency_key: str,
    ) -> None:
        """Write the refund row. Runs inside the caller's transaction.

        ``destination`` is check 8's output, which is
        ``payment.source_json`` and nothing else. It is stored on the refund
        rather than merely passed to the rail because the row is the kernel's
        own account of where the money went: a refund whose destination lived
        only in a PSP call is a refund nobody local can later be held to.

        ``state`` is very often ``processing``, and that is the point. A UPI
        refund's deemed-success position — debited, credit unconfirmed — is a
        state the ledger holds rather than a wait the kernel resolves.
        """
        self._guard(self.name, "write")
        self._conn.execute(
            "INSERT OR REPLACE INTO refund"
            " (refund_id, payment_id, amount_paise, destination_json, kind,"
            "  state, idempotency_key)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                refund_id,
                payment_id,
                amount_paise,
                jcs(destination),
                kind,
                state,
                idempotency_key,
            ),
        )

    def refunds_for_payment(self, payment_id: str) -> list[dict[str, Any]]:
        def read() -> list[dict[str, Any]]:
            return [
                {
                    "refund_id": row["refund_id"],
                    "payment_id": row["payment_id"],
                    "amount_paise": row["amount_paise"],
                    "destination": json.loads(row["destination_json"]),
                    "kind": row["kind"],
                    "state": row["state"],
                    "idempotency_key": row["idempotency_key"],
                }
                for row in self._conn.execute(
                    "SELECT * FROM refund WHERE payment_id = ? ORDER BY refund_id",
                    (payment_id,),
                )
            ]

        return self._guarded("read", read)

    def refunded_for_payment(self, payment_id: str) -> int:
        """What this payment has already given back.

        Check 8's cumulative conjunct reads this. Per payment as well as per
        mandate: a mandate with room left over from other purchases must not be
        able to fund a second refund of the *same* debit.
        """

        def read() -> int:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(amount_paise), 0) AS total FROM refund"
                " WHERE payment_id = ?",
                (payment_id,),
            ).fetchone()
            return int(row["total"])

        return self._guarded("read", read)

    def payments_for(self, mandate_id: str) -> list[dict[str, Any]]:
        def read() -> list[str]:
            return [
                row["payment_id"]
                for row in self._conn.execute(
                    "SELECT payment_id FROM payment WHERE mandate_id = ?"
                    " ORDER BY payment_id",
                    (mandate_id,),
                )
            ]

        return [
            payment
            for payment in (self.get_payment(pid) for pid in self._guarded("read", read))
            if payment is not None
        ]
