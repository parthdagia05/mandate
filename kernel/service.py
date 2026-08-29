"""The kernel itself: one request in, one recorded decision out.

Everything on :mod:`kernel.api` is a thin shell over this class, and
``mk run --config kernel`` calls it in process. One implementation, two
transports — the same argument :mod:`sim.control` makes for the control port,
for the same reason: two paths that could disagree eventually do.

The lifecycle, SPEC.md §08, and the two orderings that carry the whole guarantee::

    1  parse + validate                     -> 422 on failure
    2  load ledger row                      -> 503 on store error   (REQ-5)
       (a terminal idempotency record short-circuits here: this exact
        action already ran, so its recorded outcome is replayed verbatim
        rather than judged a second time against a ledger it moved)
    3  run checks in order, collect results
    4  if any failed:
           append audit (decision)          -> 503 if append fails   (REQ-2)
           return deny / escalate           -> 200
    5  reserve idempotency key              -> 202 if in_flight inside the TTL
    6  append audit (decision, pre-call)    -> 503 if append fails
    7  call the PSP through the adapter     <- the only place money moves
    8  ONE TRANSACTION:
           idempotency -> terminal
           ledger update
           append audit (settle leg)
    9  return allow                         -> 200

**Step 6 before step 7 is the whole of REQ-2.** Reversing them turns a crash
into an unrecorded debit: money leaves and nothing says it did. In the order
above a crash leaves a recorded decision with no debit, which the recovery scan
can resolve against the PSP. One of those two failures is repairable and the
other is not, and that is the entire reason for the ordering.

**Step 8 is one SQLite transaction.** If the idempotency record and the ledger
can diverge, the ledger is fiction.

**Every failure resolves to deny.** A store that cannot answer, a chain that
cannot record, a chain that does not verify — all of them 503 and none of them
reach the rail. Availability is traded for integrity on purpose: the kernel
being down is a utility loss, and the README says so.

Three paths can be the first to learn that a debit happened, and they all have
to agree
--------------------------------------------------------------------------

The lifecycle above is the ordinary one. Two others exist because it can be
cut short, and between them they are the whole of class A6:

:meth:`~KernelService.ingest_webhook`
    A PSP callback. Dedup is at the business level, on the kernel's own payment
    row, never on the event id — a redelivery arrives with a *fresh* id, so an
    id-keyed dedup answers wrongly on exactly the delivery it exists to catch.
    A claim earlier than what the kernel holds is refused at the payment state
    machine rather than absorbed by the dedup layer.
:meth:`~KernelService.recovery_scan`
    A reservation whose owner never came back. Past the TTL it moves to
    ``recovering``, polls the rail by ``client_ref``, and commits the true
    outcome. Never blindly retried, which double-charges; never silently
    skipped, which strands a debit. **Skipping is not a transition.**

Booking a capture is therefore **idempotent**, and :meth:`_capture_delta` is
the single question all three ask. Without that, a crash whose webhook landed
before the scan would count the same rupees twice — and the ledger's own CHECK
constraint would refuse it, turning a repaired crash into a failed recovery.

The two crash windows, which resolve in opposite directions
-----------------------------------------------------------

``after_reserve``
    Reserved and recorded, rail untouched. The poll finds nothing and the key
    is released. Zero debits.
``after_psp_call``
    The debit exists and the ledger does not know. The poll finds it and the
    scan commits it. Exactly one debit.

The reservation looks identical in both. Only the rail can say which happened,
which is why the scan asks rather than assumes — and why the recovery context
is written down at reserve time, since after a crash there is no request left
to read it from and the key is a hash.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from kernel.audit.chain import AuditChain, ChainBroken
from kernel.audit.verify import verify_entries
from kernel.canonical import jcs
from kernel.checks import CHECKS_FOR_ACTION, CheckContext, CheckResult, run_checks
from kernel.checks.base import CHECK_NAMES, ON_FAIL
from kernel.checks.refund_binding import refund_binding
from kernel.clock import Clock
from kernel.decision import (
    AuditRef,
    CheckEntry,
    DecisionResponse,
    IntentRegistration,
    WebhookIngest,
)
from kernel.enums import (
    ActionType,
    AuditAction,
    AuditActor,
    Decision,
    IdempotencyState,
    PaymentState,
    ReasonCode,
)
from kernel.latency import Stopwatch
from kernel.models import IdempotencyRecord, PaymentRequest
from kernel.payments import is_forward_payment, is_settled
from kernel.stores.base import StoreGuard, no_guard
from kernel.stores.db import StoreUnavailable
from kernel.stores.idempotency import (
    IdempotencyStore,
    Reservation,
    idempotency_key,
)
from kernel.stores.ledger import AlreadyRegistered, LedgerStore
from kernel.stores.nonces import NonceAlreadyUsed, NonceStore

__all__ = [
    "Outcome",
    "Resolution",
    "KernelService",
    "AUDIT_ACTION",
    "REPLAY_ACTION",
    "CRASH_AFTER_RESERVE",
    "CRASH_AFTER_PSP_CALL",
]

#: The two named windows a crash can open, and the only two the kernel offers.
#: They are named rather than "somewhere in capture" so a failure test can
#: assert *which* window it opened: the first leaves a reservation with no
#: debit behind it, the second leaves a debit with no ledger entry, and those
#: are resolved in opposite directions.
CRASH_AFTER_RESERVE = "after_reserve"
CRASH_AFTER_PSP_CALL = "after_psp_call"

#: Which audit action each ``(action, decision)`` pair records. A table rather
#: than string building, because the action enum is closed and a name that can
#: be constructed is a name that can be invented.
AUDIT_ACTION: dict[tuple[ActionType, bool], AuditAction] = {
    (ActionType.AUTHORIZE, True): AuditAction.AUTHORIZE_ALLOW,
    (ActionType.AUTHORIZE, False): AuditAction.AUTHORIZE_DENY,
    (ActionType.CAPTURE, True): AuditAction.CAPTURE_ALLOW,
    (ActionType.CAPTURE, False): AuditAction.CAPTURE_DENY,
    (ActionType.REFUND, True): AuditAction.REFUND_ALLOW,
    (ActionType.REFUND, False): AuditAction.REFUND_DENY,
    # There is no ``mandate.create.allow``: M3 has no recurring-mandate store,
    # so the only reachable outcome is the denial check 5 produces. An allow
    # branch with nowhere to write would be a lie in the enum.
    (ActionType.MANDATE_CREATE, False): AuditAction.MANDATE_CREATE_DENY,
}

#: Which audit action a *replay* records, by action. A table for the same
#: reason as the one above, and a table with a hole in it on purpose:
#: ``mandate.create`` never reserves a key, so it can never reach a replay, and
#: an entry here would be a name for something that cannot happen. A KeyError
#: is the right failure if that ever stops being true.
REPLAY_ACTION: dict[ActionType, AuditAction] = {
    ActionType.AUTHORIZE: AuditAction.AUTHORIZE_REPLAYED,
    ActionType.CAPTURE: AuditAction.CAPTURE_REPLAYED,
    ActionType.REFUND: AuditAction.REFUND_REPLAYED,
}


@dataclass(frozen=True)
class Resolution:
    """What the PSP said about a reservation whose owner never came back.

    Three outcomes, and the third one is the honest one rather than the tidy
    one:

    ``settled``
        The rail did the thing. Commit it — the ledger has been behind the
        truth since the crash and this is what catches it up.
    ``released``
        The rail never did it. Drop the reservation so a later attempt may
        proceed. Only ever reached when the PSP is positive nothing happened.
    ``unresolved``
        The PSP could not be asked, or its answer does not settle the question.
        The row stays where it is and the next scan asks again. **Skipping is
        never a transition**, and a row quietly dropped here is a debit nothing
        is looking for any more.
    """

    outcome: str
    detail: str
    payment: dict[str, Any] | None = None


@dataclass(frozen=True)
class Outcome:
    """An HTTP status and the body that goes with it.

    ``decision`` is present whenever a decision was actually reached — which is
    every 200 and every fail-closed 503. It is absent on 202, because
    "the key is held and we do not yet know how it ends" is not a decision and
    dressing it as one would put a deny in the results table for a request
    nobody refused.
    """

    status: int
    body: dict[str, Any]
    decision: DecisionResponse | None = None


class KernelService:
    """The enforcement path. No model, no network, no wall clock but one.

    Stores, clock and PSP adapter are injected. The clock in particular is
    *owned* rather than read: an agent-supplied clock would defeat check 1's
    expiry by lying about the hour, so ``client_ts`` never reaches a comparison.
    """

    def __init__(
        self,
        *,
        conn,
        clock: Clock,
        psp,
        trusted_keys: dict[str, str],
        client_ref: str = "ref_kernel",
        instrument_token: str = "tok_scoped_01",
        guard: StoreGuard = no_guard,
        crash: Callable[[str, str], None] | None = None,
        sidecar_path: Path | None = None,
    ) -> None:
        self._conn = conn
        self._clock = clock
        self._psp = psp
        #: ``user_id -> public key``. The kernel's trust root, held here and
        #: never read out of a message: a key travelling inside the object it
        #: signs is a claim, not a signature.
        self._trusted_keys = dict(trusted_keys)
        self._client_ref = client_ref
        self._instrument_token = instrument_token

        self.chain = AuditChain(conn, clock, guard)
        self.ledger = LedgerStore(conn, guard)
        self.nonces = NonceStore(conn, clock, guard)
        self.idempotency = IdempotencyStore(conn, clock, guard)

        #: The two named sites SPEC.md §09's ``crash_after_reserve`` can fire
        #: at, as one callable taking ``(site, action)``. A callable rather than
        #: a flag so the kernel neither knows nor can find out that a simulator
        #: is behind it — and one callable rather than two hooks so the set of
        #: windows the kernel admits to having is a single list.
        self._crash_hook = crash or (lambda _site, _action: None)
        self._sidecar_path = sidecar_path

        #: Set once a chain break is detected, and never cleared by the kernel
        #: itself. Everything denies from then on and the run's results are
        #: discarded rather than reported — a number produced by a kernel whose
        #: own record is untrustworthy is worse than no number.
        self.poisoned: str | None = None

    # -- public API -------------------------------------------------------

    def healthz(self) -> Outcome:
        """Liveness plus store availability. 503 while poisoned or store-down."""
        try:
            self.ledger.get("im_healthz")
        except StoreUnavailable as exc:
            return Outcome(503, {"ok": False, "store": "unavailable", "detail": str(exc)})
        if self.poisoned is not None:
            return Outcome(503, {"ok": False, "poisoned": self.poisoned})
        return Outcome(
            200,
            {
                "ok": True,
                "now": self._clock.now_rfc3339(),
                "audit_entries": self.chain.count(),
                "audit_head": self.chain.head()[1],
            },
        )

    def audit_chain(self, start: int = 0, end: int | None = None) -> Outcome:
        try:
            entries = [e.model_dump(mode="json") for e in self.chain.read(start, end)]
        except StoreUnavailable as exc:
            return Outcome(503, {"error": "store unavailable", "detail": str(exc)})
        return Outcome(200, {"entries": entries, "count": len(entries)})

    def audit_verify(self) -> Outcome:
        """Verify the chain end to end, and poison the kernel if it is broken.

        This is the convenient path. The load-bearing one is
        ``scripts/verify_chain.py``, which shares no code with the kernel: a
        verifier that imports the thing it is checking proves less than one
        that does not.
        """
        try:
            count, head = verify_entries(self.chain.read())
        except ChainBroken as exc:
            self.poison(str(exc))
            return Outcome(503, {"ok": False, "broken_at": exc.seq, "detail": exc.detail})
        except StoreUnavailable as exc:
            return Outcome(503, {"ok": False, "detail": str(exc)})
        return Outcome(200, {"ok": True, "entries": count, "head": head})

    def poison(self, detail: str) -> None:
        """Enter ``poisoned``. Only an operator clears it, and not from here."""
        self.poisoned = detail

    def register_intent(self, body: IntentRegistration) -> Outcome:
        """Mint the ledger row. Check 1 only — nothing here spends anything.

        The registration carries the **user-confirmed** cart, and the kernel
        keeps one field from it: ``cart_hash``, as ``confirmed_cart_hash``.
        That is the value check 4's second conjunct compares against for the
        rest of the mandate's life, which is why it has to arrive inside
        something the user signed rather than as a hash the agent can name.
        """
        watch = Stopwatch()
        poisoned = self._refuse_if_poisoned(ActionType.AUTHORIZE, body.intent.mandate_id, watch)
        if poisoned is not None:
            return poisoned

        # A registration is shaped like a request so one CheckContext serves
        # both paths. ``params.amount`` is zero: registering spends nothing.
        request = PaymentRequest(
            action=ActionType.AUTHORIZE,
            intent=body.intent,
            cart=body.confirmed_cart,
            params={"amount": 0},
            client_ts=body.intent.issued_at,
        )

        try:
            ctx = self._context(request, ledger=None, registering=True)
            results = run_checks(ctx, (1,))
            if results[-1].passed and body.confirmed_cart.confirmed_by != "user":
                # A cart the agent confirmed to itself is not a confirmation.
                results.append(
                    CheckResult.failed(
                        1,
                        ReasonCode.SIG_INVALID,
                        conjunct="ceremony",
                        detail="registration cart is not user-confirmed",
                        confirmed_by=str(body.confirmed_cart.confirmed_by),
                    )
                )
            if not results[-1].passed:
                return self._refuse(request, results, watch, AuditAction.INTENT_REGISTERED)

            # One transaction: the nonce, the ledger row and the chain entry
            # that records them. Registration mints authority, and authority
            # that exists without a chain entry saying so is authority nothing
            # can later account for — the same argument as step 8, one call
            # earlier.
            payload = {
                "mandate_id": body.intent.mandate_id,
                "utterance_hash": body.intent.utterance_hash,
                "confirmed_cart_hash": body.confirmed_cart.cart_hash,
                "scope": body.intent.scope.canonical_dict(),
                "checks": [r.as_entry() for r in results],
                "check_detail": self._check_detail(results),
                "decision": str(Decision.ALLOW),
                "reason_code": str(ReasonCode.OK),
            }
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self.nonces.consume(body.intent.nonce, body.intent.mandate_id)
                self.ledger.open_row(body.intent, body.confirmed_cart.cart_hash)
                entry = self.chain.append_within(
                    AuditActor.KERNEL, AuditAction.INTENT_REGISTERED, payload
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        except NonceAlreadyUsed:
            results = [
                CheckResult.failed(
                    1, ReasonCode.NONCE_REPLAYED, conjunct="nonce", lost_the_race=True
                )
            ]
            return self._refuse(request, results, watch, AuditAction.INTENT_REGISTERED)
        except AlreadyRegistered:
            results = [
                CheckResult.failed(
                    1,
                    ReasonCode.NONCE_REPLAYED,
                    conjunct="registration",
                    detail="this intent already has a ledger row",
                    mandate_id=body.intent.mandate_id,
                )
            ]
            return self._refuse(request, results, watch, AuditAction.INTENT_REGISTERED)
        except StoreUnavailable as exc:
            # Covers the nonce store, the ledger and the chain alike — they
            # share one guard, and the transaction rolled back whichever it
            # was, so no authority exists that the chain does not record.
            # ``_fail_closed`` tries to write a ``kernel.fail_closed`` entry and
            # falls back to the sidecar when the chain is the thing that failed.
            return self._fail_closed(request, exc, watch)

        return self._respond(
            200,
            request,
            Decision.ALLOW,
            ReasonCode.OK,
            results + [CheckResult.ok(9, appended_seq=entry.seq)],
            entry,
            watch,
        )

    def authorize(self, request: PaymentRequest) -> Outcome:
        return self._money_action(request, ActionType.AUTHORIZE)

    def capture(self, request: PaymentRequest) -> Outcome:
        return self._money_action(request, ActionType.CAPTURE)

    def refund(self, request: PaymentRequest) -> Outcome:
        return self._money_action(request, ActionType.REFUND)

    def mandate_create(self, request: PaymentRequest) -> Outcome:
        return self._money_action(request, ActionType.MANDATE_CREATE)

    #: Which audit action each ingest outcome records. Three names because
    #: there are three different things that can have happened, and one of them
    #: is a finding.
    WEBHOOK_ACTION: dict[str, AuditAction] = {
        "ingested": AuditAction.WEBHOOK_INGESTED,
        "deduped": AuditAction.WEBHOOK_DEDUPED,
        "refused": AuditAction.WEBHOOK_REFUSED,
    }

    def ingest_webhook(self, body: WebhookIngest) -> Outcome:
        """Reconcile a PSP callback against the kernel's own payment row.

        **Dedup is at the business level**, on the kernel's own record of the
        payment — reached through ``(mandate_id, cart_hash)``, the unique index
        on the payment table — and never on the webhook's ``event_id``. A PSP
        redelivering with a fresh id is ordinary at-least-once behaviour, and a
        dedup layer keyed on the id answers "have I seen this event?" when the
        question is "have I already acted on this outcome?". The duplicate
        arrives with a *new* id precisely so that the wrong answer is available.

        **Three outcomes, and the middle one is not the last one.**

        ``ingested``
            The claim is later in the payment's forward order than what the
            kernel holds. This is news, and the ledger is reconciled against it.
        ``deduped``
            The claim is what the kernel already holds. Nothing moves, and the
            chain says so under its own name so a redelivery is countable.
        ``refused``
            The claim is *earlier* — ``authorized`` arriving after ``captured``.
            Refused at the payment state machine, which answers "can that have
            happened next?", a question no event id can lie about. This is not a
            duplicate and is not recorded as one: absorbing it into the dedup
            count would hide F-08 entirely.
        """
        if self.poisoned is not None:
            return Outcome(503, {"error": "kernel poisoned", "detail": self.poisoned})

        try:
            payment = self.ledger.get_payment(body.payment_id)
            if payment is None:
                # Not an error and not a finding: the kernel is told about
                # payments it did not open (another tenant, another run). It
                # declines to invent a row for one.
                return Outcome(
                    200, {"ingested": False, "reason": "no payment with that id"}
                )

            current = PaymentState(payment["state"])
            claimed = PaymentState(body.state)
            if claimed is current:
                outcome = "deduped"
            elif is_forward_payment(current, claimed):
                outcome = "ingested"
            else:
                outcome = "refused"

            payload: dict[str, Any] = {
                "event": body.event,
                "event_id": body.event_id,
                "mandate_id": payment["mandate_id"],
                "cart_hash": payment["cart_hash"],
                "payment_id": body.payment_id,
                "current_state": str(current),
                "claimed_state": str(claimed),
                "amount_paise": body.amount_paise,
                "outcome": outcome,
                # Kept for readers of older chains, and true either way.
                "deduped": outcome == "deduped",
            }
            if outcome == "refused":
                payload["refused_by"] = "payment_state_machine"

            if outcome != "ingested":
                entry = self.chain.append(
                    AuditActor.PSP, self.WEBHOOK_ACTION[outcome], payload
                )
                return Outcome(
                    200,
                    {
                        "ingested": False,
                        "deduped": outcome == "deduped",
                        "refused": outcome == "refused",
                        "audit_seq": entry.seq,
                    },
                )

            booked = self._ledger_delta_for(payment, claimed)
            payload["ledger_reconciled"] = booked
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self.ledger.set_payment_state(body.payment_id, str(claimed))
                if booked["applied"]:
                    self.ledger.apply_capture(
                        payment["mandate_id"],
                        booked["amount_paise"],
                        self._scope_for(payment["mandate_id"]),
                    )
                payload["ledger"] = self._ledger_snapshot(payment["mandate_id"])
                entry = self.chain.append_within(
                    AuditActor.PSP, AuditAction.WEBHOOK_INGESTED, payload
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        except StoreUnavailable as exc:
            return Outcome(503, {"error": "store unavailable", "detail": str(exc)})

        return Outcome(
            200,
            {
                "ingested": True,
                "deduped": False,
                "refused": False,
                "reconciled": payload["ledger_reconciled"]["applied"],
                "audit_seq": entry.seq,
            },
        )

    def _ledger_delta_for(
        self, payment: dict[str, Any], claimed: PaymentState
    ) -> dict[str, Any]:
        """Whether this callback is the first the ledger hears of a debit.

        The case this exists for is a capture the kernel never got to record —
        it crashed, or the response never came back — where the webhook is the
        first thing that tells the ledger a debit happened. Everything else is
        confirmation, and :meth:`_capture_delta` is the shared judgement of
        which is which.
        """
        if claimed is not PaymentState.CAPTURED:
            return {"applied": False, "why": "not a settlement", "amount_paise": 0}
        return self._capture_delta(payment["payment_id"], payment["amount_paise"])

    # -- the lifecycle ----------------------------------------------------

    def _money_action(self, request: PaymentRequest, action: ActionType) -> Outcome:
        watch = Stopwatch()
        if request.action != action:
            # The envelope's action and the endpoint must agree. A capture body
            # posted to /v1/authorize would otherwise run the authorize check
            # set over a capture, and the checks array would describe a request
            # nobody sent.
            return Outcome(
                422,
                {
                    "error": "action mismatch",
                    "detail": f"body says {request.action}, endpoint is {action}",
                },
            )

        poisoned = self._refuse_if_poisoned(action, request.intent.mandate_id, watch)
        if poisoned is not None:
            return poisoned

        key = idempotency_key(request.intent.mandate_id, request.cart.cart_hash, action)

        # -- 2. load the ledger row -------------------------------------
        try:
            # A *terminal* record means this exact action already ran and its
            # outcome is recorded. Re-evaluating the checks first would judge it
            # against a ledger the action itself moved — a repeated capture
            # would be refused for exhausting a budget it is the reason for.
            # This is a read, not the reservation: step 5 still owns the write,
            # and everything else still goes through the checks in order.
            finished = self.idempotency.get(key)
            if finished is not None and finished.state == IdempotencyState.TERMINAL:
                return self._replay(request, Reservation("terminal", key, finished), watch)

            row = self.ledger.get(request.intent.mandate_id)
            ctx = self._context(request, ledger=row)

            # -- 3. run the checks, in order, first failure short-circuits
            results = run_checks(ctx, CHECKS_FOR_ACTION[action])
            if results[-1].passed and action == ActionType.REFUND:
                original = request.params.original_payment_id
                payment_row = self.ledger.get_payment(original) if original else None
                results.append(
                    refund_binding(
                        ctx,
                        payment_row,
                        # Read here rather than in the check: a check may not
                        # touch a store, so REQ-5's "every store failure denies"
                        # stays one branch instead of nine.
                        already_refunded=(
                            self.ledger.refunded_for_payment(original)
                            if original
                            else 0
                        ),
                    )
                )
        except StoreUnavailable as exc:
            return self._fail_closed(request, exc, watch)

        # -- 4. any failure: record it, then answer -----------------------
        if not results[-1].passed:
            return self._refuse(request, results, watch)

        if action == ActionType.MANDATE_CREATE:
            # The checks passed, and there is still nowhere to go. SPEC.md
            # §07's audit-action enum is closed and has no
            # ``mandate.create.allow``: issuing standing authority needs a
            # recurring-mandate store this milestone does not have. So the
            # kernel fails closed rather than minting authority it cannot
            # record — an allow with no chain entry is the one outcome the
            # whole design exists to prevent, and a widened enum would be a
            # bigger lie than a 503.
            return Outcome(
                503,
                {
                    "decision": str(Decision.DENY),
                    "reason_code": str(ReasonCode.STORE_UNAVAILABLE),
                    "mandate_id": request.intent.mandate_id,
                    "action": str(action),
                    "latency_us": watch.micros(),
                    "detail": "recurring mandate issuance is not implemented; "
                    "the kernel will not mint authority it cannot record",
                },
            )

        # -- 5. reserve the idempotency key -------------------------------
        try:
            reservation = self.idempotency.reserve(
                key,
                action,
                # The recovery context, written now because after a crash there
                # is no request left to read it from and the key is a hash.
                mandate_id=request.intent.mandate_id,
                cart_hash=request.cart.cart_hash,
                amount_paise=request.params.amount,
                client_ref=self._client_ref,
                payment_id=request.params.original_payment_id,
            )
        except StoreUnavailable as exc:
            return self._fail_closed(request, exc, watch)

        if reservation.outcome == "terminal":
            # Committed between the read above and here. Replayed verbatim:
            # recomputing could return a *different* decision for the same key,
            # and the caller could not tell a replay from a second judgement.
            return self._replay(request, reservation, watch)
        if reservation.outcome == "in_flight":
            return Outcome(
                202,
                {
                    "status": "retry_later",
                    "idempotency_key": key,
                    "detail": "this key is in flight inside the recovery TTL",
                },
            )
        if reservation.outcome == "recovering":
            return self._recover(request, reservation, results, watch)

        results.append(CheckResult.ok(7, idempotency_key=key, replayed=False))

        # -- 6. record the decision BEFORE the rail is touched ------------
        try:
            entry = self.chain.append(
                AuditActor.KERNEL,
                AUDIT_ACTION[(action, True)],
                self._payload(request, Decision.ALLOW, ReasonCode.OK, results, key=key),
            )
        except Exception as exc:  # noqa: BLE001
            self.idempotency.release(key)
            return self._audit_unwritable(request, exc, watch)

        # The first crash window: reserved and recorded, but the rail has not
        # been touched. Recovery finds no payment and releases the key.
        self._crash_hook(CRASH_AFTER_RESERVE, str(action))

        # -- 7. the only place money moves --------------------------------
        try:
            settled = self._call_psp(request, action)
        except Exception as exc:  # noqa: BLE001
            # The reservation **stays in place**. The PSP may have accepted the
            # call, so the outcome is *unknown* rather than failed, and unknown
            # is resolved by polling, never by retrying. Releasing the key here
            # would let the next attempt produce a second debit.
            #
            # 202 rather than 503 for the same reason: no decision changed, the
            # key is held, and the honest answer is "ask again". Reporting a
            # deny would record a refusal for a payment that may have gone
            # through.
            self.chain.append(
                AuditActor.KERNEL,
                AuditAction.KERNEL_FAIL_CLOSED,
                {
                    "mandate_id": request.intent.mandate_id,
                    "stage": "psp_call",
                    "action": str(action),
                    "idempotency_key": key,
                    "error": type(exc).__name__,
                    "idempotency_state": "in_flight",
                    "note": "outcome unknown; recovery polls by client_ref",
                },
            )
            return Outcome(
                202,
                {
                    "status": "retry_later",
                    "idempotency_key": key,
                    "detail": f"the rail did not answer ({type(exc).__name__}); "
                    "the outcome is unknown and the key stays held",
                },
            )

        # The second crash window, and the one recovery exists for: the debit
        # has happened and the ledger does not know. This is SPEC.md §06's
        # "crash mid-capture" row — payment ``captured`` at the PSP only, key
        # still ``in_flight`` — and the scan is what closes it.
        self._crash_hook(CRASH_AFTER_PSP_CALL, str(action))

        # -- 8. one transaction: idempotency, ledger, settle-leg audit ----
        results.append(CheckResult.ok(9, appended_seq=entry.seq))
        response = self._response(
            request, Decision.ALLOW, ReasonCode.OK, results, entry, watch, key=key,
            payment=settled,
        )
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._apply_settlement(
                action,
                mandate_id=request.intent.mandate_id,
                cart_hash=request.cart.cart_hash,
                amount=request.params.amount,
                currency=request.cart.currency,
                key=key,
                settled=settled,
            )
            self.idempotency.commit(key, jcs(response.to_json_dict()))
            self.chain.append_within(
                AuditActor.KERNEL,
                AUDIT_ACTION[(action, True)],
                {
                    "mandate_id": request.intent.mandate_id,
                    "leg": "settle",
                    "action": str(action),
                    "idempotency_key": key,
                    "payment_id": settled.get("payment_id"),
                    "state": settled.get("state"),
                    "amount_paise": settled.get("captured_paise")
                    or settled.get("amount_paise"),
                    "ledger": self._ledger_snapshot(request.intent.mandate_id),
                },
            )
            self._conn.execute("COMMIT")
        except Exception as exc:  # noqa: BLE001
            # All three or none. The rollback is what makes "if the idempotency
            # record and the ledger can diverge, the ledger is fiction" a
            # property rather than an intention — and the key stays in flight,
            # because the debit at step 7 already happened and recovery has to
            # be the thing that reconciles it.
            self._conn.execute("ROLLBACK")
            return Outcome(
                503,
                {
                    "decision": str(Decision.DENY),
                    "reason_code": str(ReasonCode.STORE_UNAVAILABLE),
                    "mandate_id": request.intent.mandate_id,
                    "action": str(action),
                    "idempotency_key": key,
                    "latency_us": watch.micros(),
                    "detail": f"settlement did not commit: {exc}",
                    "psp_called": True,
                    "note": "the ledger did not move and the key is still in "
                    "flight; recovery reconciles against the PSP",
                },
            )

        return Outcome(200, response.to_json_dict(), response)

    # -- the PSP boundary -------------------------------------------------

    def _call_psp(self, request: PaymentRequest, action: ActionType) -> dict[str, Any]:
        cart = request.cart
        idem = f"{self._client_ref}:{action}"

        if action == ActionType.AUTHORIZE:
            order = self._psp.create_order(
                request.params.amount,
                cart.currency,
                self._client_ref,
                payee=cart.payee,
            )
            payment = self._psp.authorize(
                order.order_id, self._instrument_token, idem=idem
            )
            return payment.view()

        if action == ActionType.CAPTURE:
            recorded = self.ledger.payment_for_cart(
                request.intent.mandate_id, cart.cart_hash
            )
            if recorded is None:
                raise StoreUnavailable(
                    "capture with no recorded authorize for this cart; the "
                    "kernel will not capture a payment it did not open"
                )
            payment = self._psp.capture(
                recorded["payment_id"], request.params.amount, idem=idem
            )
            return payment.view()

        if action == ActionType.REFUND:
            recorded = self.ledger.get_payment(request.params.original_payment_id or "")
            if recorded is None:  # pragma: no cover - check 8 already refused
                raise StoreUnavailable("refund with no recorded payment")
            from kernel.models import Account

            refund = self._psp.refund(
                recorded["payment_id"],
                request.params.amount,
                # The destination is the recorded source. Not a request field —
                # there is no request field, which is the answer to class A7.
                Account.model_validate(recorded["source"]),
                idem=idem,
            )
            return {
                "refund_id": refund.refund_id,
                "payment_id": refund.payment_id,
                "amount_paise": refund.amount_paise,
                "destination": recorded["source"],
                "kind": str(refund.kind),
                # Very often ``processing``. That is UPI's deemed-success
                # position — debited, credit unconfirmed — and the kernel
                # records the wait rather than resolving it.
                "state": str(refund.state),
            }

        raise StoreUnavailable(f"no PSP call for action {action}")

    def _apply_settlement(
        self,
        action: ActionType,
        *,
        mandate_id: str,
        cart_hash: str,
        amount: int,
        currency: str,
        key: str,
        settled: dict[str, Any],
    ) -> None:
        """The ledger half of step 8. Runs inside the caller's transaction.

        Takes values rather than a :class:`~kernel.models.PaymentRequest`
        because **the recovery scan calls it with no request in hand** — the
        process that held the request died, which is why there is a scan at
        all. One implementation for both paths, so a recovered capture and a
        live one cannot move the ledger differently.
        """
        if action == ActionType.AUTHORIZE:
            self.ledger.apply_authorize(mandate_id, amount)
            self.ledger.record_payment(
                payment_id=settled["payment_id"],
                mandate_id=mandate_id,
                cart_hash=cart_hash,
                source=settled["source"],
                amount_paise=amount,
                currency=currency,
                state=settled["state"],
                client_ref=settled["client_ref"],
            )
        elif action == ActionType.CAPTURE:
            # **Booking a capture is idempotent, and it has to be.** Three
            # different things can be the first to learn that a debit happened:
            # the capture response, the ``payment.captured`` webhook, and the
            # recovery scan's poll. In an ordinary run only the first of them
            # arrives before the ledger moves; after a crash any of the three
            # can. If each booked unconditionally, a crash whose webhook landed
            # before the scan would count the same rupees twice — and the
            # ledger's own CHECK constraint would refuse it, turning a repaired
            # crash into a failed recovery. So all three ask the same question
            # of the same marker.
            booked = self._capture_delta(settled["payment_id"], amount)
            if booked["applied"]:
                self.ledger.apply_capture(
                    mandate_id, booked["amount_paise"], self._scope_for(mandate_id)
                )
            self.ledger.set_payment_state(
                settled["payment_id"], str(PaymentState.CAPTURED)
            )
        elif action == ActionType.REFUND:
            self.ledger.apply_refund(mandate_id, amount)
            # The refund row, with the destination check 8 chose. Written here
            # rather than left to the PSP call because the row is the kernel's
            # own account of where the money went: a destination that lived
            # only inside an adapter call is one nobody local can be held to.
            self.ledger.record_refund(
                refund_id=settled["refund_id"],
                payment_id=settled["payment_id"],
                amount_paise=amount,
                destination=settled["destination"],
                kind=settled["kind"],
                state=settled["state"],
                idempotency_key=key,
            )

    def _capture_delta(self, payment_id: str, amount: int) -> dict[str, Any]:
        """Is this debit already on the ledger, or is this the first news of it?

        The kernel's own payment row is the marker, and that is not an
        accident: the capture request moves the row and the ledger inside one
        transaction, so a row that already reads ``captured`` is a row whose
        money has been booked. Anything arriving later about it — a webhook, a
        recovery poll — is confirmation rather than news.

        This is what makes P-06 hold. The captured total is a function of the
        payment's state and not of how many callbacks arrived, in what order,
        or whether a scan got there first.
        """
        payment = self.ledger.get_payment(payment_id)
        if payment is None:
            # Nothing recorded, so nothing to compare against. Refusing to book
            # is the safe direction: an unbooked debit is visible as a
            # reconciliation gap, and a double-booked one is a wrong number.
            return {
                "applied": False,
                "why": "no recorded payment with that id",
                "amount_paise": 0,
            }
        if is_settled(PaymentState(payment["state"])):
            return {
                "applied": False,
                "why": "this debit is already on the ledger",
                "amount_paise": 0,
            }
        return {
            "applied": True,
            "why": "the ledger had not recorded this capture",
            "amount_paise": amount,
        }

    def _scope_for(self, mandate_id: str) -> dict[str, Any]:
        """The scope from the ledger's *stored* intent, not from the request.

        Exhaustion is judged against the authority the kernel registered, which
        is the one whose bytes it kept. Reading the scope off the presented
        request would let a re-signed intent widen the ceiling it is about to
        be measured against — and the recovery scan has no request to read
        anyway, so this is also the only version of the question both callers
        can ask.
        """
        row = self.ledger.get(mandate_id)
        if row is None:  # pragma: no cover - check 6 refused long before here
            raise StoreUnavailable(f"no ledger row for {mandate_id}")
        return json.loads(row.intent_json)["scope"]

    # -- responses --------------------------------------------------------

    def _context(
        self, request: PaymentRequest, *, ledger, registering: bool = False
    ) -> CheckContext:
        return CheckContext(
            request=request,
            user_pubkey=self._trusted_keys.get(request.intent.principal.user_id),
            ledger=ledger,
            now=self._clock.now_rfc3339(),
            nonce_owner=self.nonces.owner,
            registering=registering,
        )

    @staticmethod
    def _check_detail(results: list[CheckResult]) -> list[dict[str, Any]]:
        """The evidence half of the audit payload.

        Every evaluated check's compared values, in order — which is what lets
        ``mk explain`` name the payee the user allowed and the payee the request
        carried, instead of reporting that check 2 said no.
        """
        return [
            {"id": r.id, "name": r.name, "result": "pass" if r.passed else "fail", **r.detail}
            for r in results
        ]

    def _payload(
        self,
        request: PaymentRequest,
        decision: Decision,
        reason: ReasonCode,
        results: list[CheckResult],
        *,
        key: str | None = None,
    ) -> dict[str, Any]:
        """The audit payload. Deterministic by construction.

        No signature bytes (the chain refuses them outright) and no measured
        duration — two runs of one seed produce byte-identical chains, and both
        of those would break that.
        """
        payload: dict[str, Any] = {
            "mandate_id": request.intent.mandate_id,
            "cart_id": request.cart.mandate_id,
            "cart_hash": request.cart.cart_hash,
            "action": str(request.action),
            "amount_paise": request.params.amount,
            "payee": request.cart.payee.canonical_dict(),
            "utterance_hash": request.intent.utterance_hash,
            "checks": [r.as_entry() for r in results],
            "check_detail": self._check_detail(results),
            "decision": str(decision),
            "reason_code": str(reason),
            "denied_by": [r.id for r in results if not r.passed],
        }
        if key is not None:
            payload["idempotency_key"] = key
        return payload

    def _response(
        self,
        request: PaymentRequest,
        decision: Decision,
        reason: ReasonCode,
        results: list[CheckResult],
        entry,
        watch: Stopwatch,
        *,
        key: str | None = None,
        replayed: bool = False,
        payment: dict[str, Any] | None = None,
    ) -> DecisionResponse:
        return DecisionResponse(
            decision=decision,
            action=request.action,
            mandate_id=request.intent.mandate_id,
            cart_id=request.cart.mandate_id,
            checks=[CheckEntry.model_validate(r.as_entry()) for r in results],
            denied_by=[r.id for r in results if not r.passed],
            reason_code=reason,
            idempotency_key=key,
            replayed=replayed,
            audit=(
                AuditRef(
                    seq=entry.seq, entry_hash=entry.entry_hash, prev_hash=entry.prev_hash
                )
                if entry is not None
                else None
            ),
            latency_us=watch.micros(),
            payment=payment,
        )

    def _respond(self, status, request, decision, reason, results, entry, watch, **kw):
        response = self._response(
            request, decision, reason, results, entry, watch, **kw
        )
        return Outcome(status, response.to_json_dict(), response)

    def _refuse(
        self,
        request: PaymentRequest,
        results: list[CheckResult],
        watch: Stopwatch,
        audit_action: AuditAction | None = None,
    ) -> Outcome:
        """Step 4: record the refusal, then answer 200.

        A policy denial is not an HTTP error. Returning 403 would make a
        working defence indistinguishable from a broken deployment in every
        results table that counts status codes.
        """
        failed = results[-1]
        decision = ON_FAIL[failed.id]
        reason = failed.reason_code
        action = audit_action or AUDIT_ACTION[(request.action, False)]

        try:
            entry = self.chain.append(
                AuditActor.KERNEL,
                action,
                self._payload(request, decision, reason, results),
            )
        except Exception as exc:  # noqa: BLE001
            return self._audit_unwritable(request, exc, watch)

        results = results + [CheckResult.ok(9, appended_seq=entry.seq)]
        if decision == Decision.ESCALATE:
            # Escalation opens its own entry. A human resolving it mints a new
            # signed intent; nothing here widens the one that just refused.
            self.chain.append(
                AuditActor.KERNEL,
                AuditAction.ESCALATION_OPENED,
                {
                    "mandate_id": request.intent.mandate_id,
                    "reason_code": str(reason),
                    "denied_by": [failed.id],
                    "utterance_hash": request.intent.utterance_hash,
                    "note": "escalated to a human; never to the model",
                },
            )
        return self._respond(200, request, decision, reason, results, entry, watch)

    def _replay(self, request, reservation, watch) -> Outcome:
        """Hand back the recorded outcome, unchanged. No second debit.

        Verbatim rather than recomputed. The ledger has moved since — this
        action is why — so a fresh evaluation could return a different answer
        for the same key, and the caller would have no way to tell a replay
        from a second, differently-judged action.
        """
        stored = json.loads(reservation.record.result_json or "{}")
        stored["replayed"] = True
        stored["latency_us"] = watch.micros()
        self.chain.append(
            AuditActor.KERNEL,
            REPLAY_ACTION[ActionType(request.action)],
            {
                "mandate_id": request.intent.mandate_id,
                "idempotency_key": reservation.key,
                "action": str(request.action),
                "checks": [{"id": 7, "name": CHECK_NAMES[7], "result": "pass"}],
                "reason_code": str(ReasonCode.IDEMPOTENT_REPLAY),
                "note": "prior result replayed verbatim; no second debit",
            },
        )
        return Outcome(200, stored)

    def _recover(self, request, reservation, results, watch) -> Outcome:
        """A request arrived on a key past its TTL. Resolve it, then answer.

        The resolution is the same one :meth:`recovery_scan` performs — one
        implementation, so a key resolved because a retry arrived and a key
        resolved because the clock moved cannot reach different conclusions
        about the same debit.
        """
        record = reservation.record or self.idempotency.get(reservation.key)
        if record is None:  # pragma: no cover - released between read and here
            return Outcome(
                202,
                {
                    "status": "retry_later",
                    "idempotency_key": reservation.key,
                    "detail": "the reservation is gone; ask again",
                },
            )

        reconciled = self._reconcile(record)

        if reconciled["outcome"] == "settled":
            # The key is terminal now, so the caller gets the recorded outcome
            # rather than a fresh judgement of a ledger this very action moved.
            settled_record = self.idempotency.get(reservation.key)
            if settled_record is not None:
                return self._replay(
                    request,
                    Reservation("terminal", reservation.key, settled_record),
                    watch,
                )

        return Outcome(
            202,
            {
                "status": "retry_later",
                "idempotency_key": reservation.key,
                "recovery": reconciled["outcome"],
                "detail": reconciled["detail"],
            },
        )

    # -- the recovery scan ------------------------------------------------

    def recovery_scan(self) -> dict[str, Any]:
        """Resolve every reservation whose owner never came back.

        Runs at the clock barrier (SPEC.md §15) rather than on a timer, so a
        recovery happens at a point in the run that the seed and the schedule
        determine and nothing else. It needs no request and no live caller —
        that is the whole point of it, the caller is the thing that died.

        The scan is the answer to the one failure mode a payments kernel cannot
        wave away: **a debit exists and nothing local knows.** It is never a
        blind retry, which double-charges, and never a silent skip, which
        strands the debit. It asks the PSP and writes down the answer.
        """
        if self.poisoned is not None:
            # A kernel whose own record is untrustworthy must not be moving a
            # ledger on the strength of it.
            return {"scanned": 0, "resolved": [], "poisoned": self.poisoned}
        try:
            open_rows = self.idempotency.open_reservations()
        except StoreUnavailable as exc:
            return {"scanned": 0, "resolved": [], "error": str(exc)}

        return {
            "scanned": len(open_rows),
            "resolved": [self._reconcile(record) for record in open_rows],
        }

    def _resolve(self, record: IdempotencyRecord) -> Resolution:
        """Ask the rail what happened to one reserved action.

        The poll is by ``client_ref`` because after a crash that is the only
        identifier the kernel is certain it had — a payment id it never got to
        write down is not an identifier, it is a hope.

        The answer is read differently per action, and that is the substance of
        this method. A poll returning a payment does not mean "your capture
        went through"; it means "a payment exists". For an authorize that is
        the whole question. For a capture it is not: a payment sitting at
        ``authorized`` is proof the capture never reached the rail, and
        committing a capture against it would book a debit that did not happen.
        """
        found = self._psp.poll(record.client_ref)
        if found is None:
            return Resolution(
                "released", "the PSP has no record of this client_ref"
            )

        view = found.view()
        state = PaymentState(view["state"])

        if record.action == ActionType.AUTHORIZE:
            # A payment exists at all, so the authorize reached the rail.
            return Resolution("settled", f"the rail holds a payment in {state}", view)

        if record.action == ActionType.CAPTURE:
            if is_settled(state):
                return Resolution("settled", "the rail captured; the debit exists", view)
            return Resolution(
                "released",
                f"the rail never captured; the payment is still {state}",
                view,
            )

        # A refund's outcome is not readable from a payment poll: the rail's
        # payment state says nothing about whether a credit was raised. Left
        # unresolved on purpose rather than guessed — and safe to leave, because
        # the PSP dedups a refund on the idempotency key, so a later retry of
        # the *same* key cannot become a second credit.
        return Resolution(
            "unresolved",
            "a refund's outcome cannot be read from a payment poll; the key is "
            "held and a retry carries the same idempotency key",
            view,
        )

    def _reconcile(self, record: IdempotencyRecord) -> dict[str, Any]:
        """Resolve one reservation and write down what was decided.

        Every exit from this method leaves either a terminal row, a released
        key, or a ``recovering`` row the next scan will pick up again. There is
        no path that leaves a reservation unexamined, because skipping is not a
        transition.
        """
        summary: dict[str, Any] = {
            "idempotency_key": record.key,
            "action": str(record.action),
            "mandate_id": record.mandate_id,
            "cart_hash": record.cart_hash,
            "amount_paise": record.amount_paise,
            "polled_by": "client_ref",
        }
        try:
            if record.state != IdempotencyState.RECOVERING:
                self.idempotency.mark_recovering(record.key)
            resolution = self._resolve(record)
        except Exception as exc:  # noqa: BLE001 — an unreachable rail is a state
            summary.update(outcome="unresolved", detail=f"{type(exc).__name__}: {exc}")
            self._append_recovery(summary, within=False)
            return summary

        summary.update(outcome=resolution.outcome, detail=resolution.detail)
        payment = resolution.payment
        summary["found"] = payment is not None
        summary["state"] = payment["state"] if payment else None

        if resolution.outcome == "settled" and payment is not None:
            try:
                self._commit_recovered(record, payment, summary)
            except Exception as exc:  # noqa: BLE001
                # The row stays ``recovering``; the next scan asks again. A
                # failure to write the reconciliation must not look like a
                # reconciliation that found nothing.
                summary.update(
                    outcome="unresolved",
                    detail=f"recovered state did not commit: {exc}",
                )
                self._append_recovery(summary, within=False)
            return summary

        if resolution.outcome == "released":
            self.idempotency.release(record.key)

        self._append_recovery(summary, within=False)
        return summary

    def _commit_recovered(
        self, record: IdempotencyRecord, payment: dict[str, Any], summary: dict[str, Any]
    ) -> None:
        """Ledger, idempotency and chain in one transaction, as at step 8.

        The same all-or-nothing rule, for the same reason: a recovery that
        moved the ledger without recording itself would be indistinguishable
        from the crash it is repairing.
        """
        ledger_before = self._ledger_snapshot(record.mandate_id)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._apply_settlement(
                ActionType(record.action),
                mandate_id=record.mandate_id,
                cart_hash=record.cart_hash,
                amount=record.amount_paise,
                currency=payment.get("currency", "INR"),
                key=record.key,
                settled=payment,
            )
            # Often ``False``, and that is the system working: a webhook may
            # have reconciled the ledger before the TTL elapsed, and then all
            # the scan has left to do is close the key. Recorded either way, so
            # "the scan ran and moved nothing" and "the scan did not run" are
            # different facts in the chain rather than the same silence.
            summary["ledger_moved"] = ledger_before != self._ledger_snapshot(
                record.mandate_id
            )
            entry = self._append_recovery(
                {**summary, "ledger": self._ledger_snapshot(record.mandate_id)},
                within=True,
            )
            self.idempotency.commit(
                record.key,
                jcs(
                    {
                        "decision": str(Decision.ALLOW),
                        "action": str(record.action),
                        "mandate_id": record.mandate_id,
                        "checks": [
                            {"id": 7, "name": CHECK_NAMES[7], "result": "pass"},
                            {"id": 9, "name": CHECK_NAMES[9], "result": "pass"},
                        ],
                        "denied_by": [],
                        "reason_code": str(ReasonCode.OK),
                        "idempotency_key": record.key,
                        "recovered": True,
                        "audit": {
                            "seq": entry.seq,
                            "entry_hash": entry.entry_hash,
                            "prev_hash": entry.prev_hash,
                        },
                        "payment": payment,
                    }
                ),
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        summary["audit_seq"] = entry.seq

    def _append_recovery(self, payload: dict[str, Any], *, within: bool):
        append = self.chain.append_within if within else self.chain.append
        return append(AuditActor.KERNEL, AuditAction.RECOVERY_RECONCILED, payload)

    # -- fail-closed ------------------------------------------------------

    def _refuse_if_poisoned(self, action, mandate_id, watch) -> Outcome | None:
        if self.poisoned is None:
            return None
        return Outcome(
            503,
            {
                "decision": str(Decision.DENY),
                "reason_code": str(ReasonCode.STORE_UNAVAILABLE),
                "mandate_id": mandate_id,
                "action": str(action),
                "poisoned": self.poisoned,
                "latency_us": watch.micros(),
                "detail": "the audit chain does not verify; every action is "
                "denied until an operator clears this",
            },
        )

    def _fail_closed(
        self, request: PaymentRequest, exc: Exception, watch: Stopwatch
    ) -> Outcome:
        """A store could not answer. Deny, 503, and never reach the rail.

        An unreadable budget is not an empty budget. The distinction is the
        whole of REQ-5: treating "I could not read it" as "there is nothing
        there" turns every transient disk error into an unbounded spend.
        """
        body = {
            "decision": str(Decision.DENY),
            "reason_code": str(ReasonCode.STORE_UNAVAILABLE),
            "mandate_id": request.intent.mandate_id,
            "action": str(request.action),
            "checks": [],
            "denied_by": [],
            "latency_us": watch.micros(),
            "detail": str(exc),
        }
        try:
            entry = self.chain.append(
                AuditActor.KERNEL,
                AuditAction.KERNEL_FAIL_CLOSED,
                {
                    "mandate_id": request.intent.mandate_id,
                    "action": str(request.action),
                    "stage": "store",
                    "reason_code": str(ReasonCode.STORE_UNAVAILABLE),
                    "error": type(exc).__name__,
                },
            )
            body["audit"] = {
                "seq": entry.seq,
                "entry_hash": entry.entry_hash,
                "prev_hash": entry.prev_hash,
            }
        except Exception as chain_exc:  # noqa: BLE001
            body["audit_gap"] = self._sidecar(request, chain_exc)
        return Outcome(503, body)

    def _audit_unwritable(
        self, request: PaymentRequest, exc: Exception, watch: Stopwatch
    ) -> Outcome:
        """The chain could not record. Deny **before** any PSP call (REQ-2).

        If the chain cannot record its own failure either, that is reported as
        a gap rather than hidden: a best-effort sidecar line, and the response
        says the chain has a hole in it. A silently unrecorded decision is the
        one failure this project cannot recover from, so it is the one failure
        the response is loudest about.
        """
        return Outcome(
            503,
            {
                "decision": str(Decision.DENY),
                "reason_code": str(ReasonCode.STORE_UNAVAILABLE),
                "mandate_id": request.intent.mandate_id,
                "action": str(request.action),
                "latency_us": watch.micros(),
                "detail": f"audit append failed: {exc}",
                "audit_gap": self._sidecar(request, exc),
                "psp_called": False,
            },
        )

    def _sidecar(self, request: PaymentRequest, exc: Exception) -> dict[str, Any]:
        """Best-effort record of a decision the chain could not take.

        Outside the chain, so it is *not* evidence in the chain's sense — it
        cannot be, that is the point. It exists so the gap has a description,
        and the response reports the gap either way.
        """
        record = {
            "gap": True,
            "mandate_id": request.intent.mandate_id,
            "action": str(request.action),
            "cart_hash": request.cart.cart_hash,
            "error": f"{type(exc).__name__}: {exc}",
            "at": self._clock.now_rfc3339(),
        }
        if self._sidecar_path is not None:
            try:
                self._sidecar_path.parent.mkdir(parents=True, exist_ok=True)
                with self._sidecar_path.open("a") as handle:
                    handle.write(jcs(record) + "\n")
                record["sidecar"] = str(self._sidecar_path)
            except OSError as write_exc:
                record["sidecar_failed"] = str(write_exc)
        return record

    # -- helpers ----------------------------------------------------------

    def _ledger_snapshot(self, mandate_id: str) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT execution_count, committed_paise, captured_paise,"
            "       refunded_paise, mandate_state, ledger_state"
            "  FROM spend_ledger WHERE mandate_id = ?",
            (mandate_id,),
        ).fetchone()
        return dict(row) if row is not None else {}
