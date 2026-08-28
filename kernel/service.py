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
from kernel.models import PaymentRequest
from kernel.stores.base import StoreGuard, no_guard
from kernel.stores.db import StoreUnavailable
from kernel.stores.idempotency import (
    IdempotencyStore,
    Reservation,
    idempotency_key,
)
from kernel.stores.ledger import AlreadyRegistered, LedgerStore
from kernel.stores.nonces import NonceAlreadyUsed, NonceStore

__all__ = ["Outcome", "KernelService", "AUDIT_ACTION"]

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
        after_reserve: Callable[[], None] | None = None,
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

        #: The named site SPEC.md §09's ``crash_after_reserve`` fires at. A
        #: callable rather than a flag so the kernel neither knows nor can find
        #: out that a simulator is behind it.
        self._after_reserve = after_reserve or (lambda: None)
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

    def ingest_webhook(self, body: WebhookIngest) -> Outcome:
        """Reconcile a PSP callback against the kernel's own payment row.

        Dedup is on ``(mandate_id, cart_hash)`` — the kernel's business key —
        not on the webhook's ``event_id``. A PSP redelivering with a fresh id is
        ordinary at-least-once behaviour, and a dedup layer keyed on the id
        answers "have I seen this event?" when the question is "have I already
        acted on this outcome?".
        """
        if self.poisoned is not None:
            return Outcome(503, {"error": "kernel poisoned", "detail": self.poisoned})
        try:
            payment = self.ledger.get_payment(body.payment_id)
            if payment is None:
                return Outcome(
                    200,
                    {"ingested": False, "reason": "no payment with that id"},
                )
            already = payment["state"] == str(body.state)
            action = (
                AuditAction.WEBHOOK_DEDUPED if already else AuditAction.WEBHOOK_INGESTED
            )
            if not already:
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    self.ledger.set_payment_state(body.payment_id, str(body.state))
                    self._conn.execute("COMMIT")
                except Exception:
                    self._conn.execute("ROLLBACK")
                    raise
            entry = self.chain.append(
                AuditActor.PSP,
                action,
                {
                    "event": body.event,
                    "event_id": body.event_id,
                    "mandate_id": payment["mandate_id"],
                    "cart_hash": payment["cart_hash"],
                    "payment_id": body.payment_id,
                    "state": str(body.state),
                    "amount_paise": body.amount_paise,
                    "deduped": already,
                },
            )
        except StoreUnavailable as exc:
            return Outcome(503, {"error": "store unavailable", "detail": str(exc)})
        return Outcome(
            200,
            {"ingested": not already, "deduped": already, "audit_seq": entry.seq},
        )

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
            payment_row = None
            if results[-1].passed and action == ActionType.REFUND:
                payment_row = (
                    self.ledger.get_payment(request.params.original_payment_id)
                    if request.params.original_payment_id
                    else None
                )
                results.append(refund_binding(ctx, payment_row))
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
            reservation = self.idempotency.reserve(key, action)
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

        self._after_reserve()

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

        # -- 8. one transaction: idempotency, ledger, settle-leg audit ----
        results.append(CheckResult.ok(9, appended_seq=entry.seq))
        response = self._response(
            request, Decision.ALLOW, ReasonCode.OK, results, entry, watch, key=key,
            payment=settled,
        )
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._apply_settlement(request, action, settled)
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
                "state": str(refund.state),
            }

        raise StoreUnavailable(f"no PSP call for action {action}")

    def _apply_settlement(
        self, request: PaymentRequest, action: ActionType, settled: dict[str, Any]
    ) -> None:
        """The ledger half of step 8. Runs inside the caller's transaction."""
        mandate_id = request.intent.mandate_id
        amount = request.params.amount

        if action == ActionType.AUTHORIZE:
            self.ledger.apply_authorize(mandate_id, amount)
            self.ledger.record_payment(
                payment_id=settled["payment_id"],
                mandate_id=mandate_id,
                cart_hash=request.cart.cart_hash,
                source=settled["source"],
                amount_paise=amount,
                currency=request.cart.currency,
                state=settled["state"],
                client_ref=settled["client_ref"],
            )
        elif action == ActionType.CAPTURE:
            self.ledger.apply_capture(
                mandate_id, amount, request.intent.scope.canonical_dict()
            )
            self.ledger.set_payment_state(settled["payment_id"], str(PaymentState.CAPTURED))
        elif action == ActionType.REFUND:
            self.ledger.apply_refund(mandate_id, amount)

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
            AuditAction.CAPTURE_REPLAYED
            if request.action == ActionType.CAPTURE
            else AuditAction.REFUND_REPLAYED,
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
        """An ``in_flight`` row past its TTL: ask the PSP what really happened.

        Never blindly retried and never silently skipped — skipping is not a
        transition. The poll is by ``client_ref`` because after a crash that is
        the only identifier the kernel is certain it had.
        """
        self.idempotency.mark_recovering(reservation.key)
        found = self._psp.poll(self._client_ref)
        self.chain.append(
            AuditActor.KERNEL,
            AuditAction.RECOVERY_RECONCILED,
            {
                "mandate_id": request.intent.mandate_id,
                "idempotency_key": reservation.key,
                "polled_by": "client_ref",
                "found": found is not None,
                "state": str(found.state) if found is not None else None,
            },
        )
        if found is None:
            self.idempotency.release(reservation.key)
            return Outcome(
                202,
                {
                    "status": "retry_later",
                    "idempotency_key": reservation.key,
                    "detail": "reservation released; the PSP has no record",
                },
            )
        settled = found.view()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._apply_settlement(request, request.action, settled)
            self.idempotency.commit(reservation.key, jcs({"recovered": True}))
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        return Outcome(200, {"recovered": True, "payment": settled})

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
