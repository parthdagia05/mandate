"""The simulated PSP. The only place money moves in a simulated run (REQ-1).

Implements :class:`kernel.adapters.base.PSPAdapter`. Everything it does is a
function of the run seed and the clock: identifiers come from
:class:`~kernel.rng.RunRandom`, state changes are the table in
:mod:`sim.psp.state`, and callbacks go through :class:`~sim.webhooks.WebhookScheduler`
rather than happening inline.

Three properties worth naming, because they are the ones a test leans on:

* **Capture is idempotent on the PSP side too.** A real PSP dedups on the
  idempotency key it was given, and if ours did not, a kernel bug and a PSP
  quirk would produce the same double debit and we could not tell them apart.
* **A payment's payee is fixed at authorization.** Money cannot be redirected
  after the fact, so a successful A1 has to have redirected the *authorize*
  call — which is what makes A1 a decision the agent made rather than something
  that happened to it.
* **Refunds credit the payment's recorded source**, and the destination the
  caller passes is checked against it rather than trusted. A PSP that refunded
  wherever it was told would make check 8 untestable, because the simulator
  would already be doing check 8's job.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kernel.clock import Clock
from kernel.enums import PaymentState, RefundKind, RefundState
from kernel.ids import IdFactory
from kernel.models import Account
from kernel.rng import RunRandom
from sim.eventlog import EventLog, SimActor, SimEvent
from sim.faults import Fault, FaultInjector, PSPTimeout
from sim.psp.state import (
    IllegalTransition,
    check_payment_transition,
    check_refund_transition,
    is_forward_payment,
)
from sim.webhooks import WebhookEvent, WebhookScheduler

__all__ = ["SimOrder", "SimPayment", "SimRefund", "SimPSP", "AUTHORIZE_DELAY_S", "CAPTURE_DELAY_S"]

#: How many clock-seconds after the call the PSP calls back. Constants rather
#: than a jittered value: jitter here would be indistinguishable from a
#: scheduling bug, and the reordering we actually want to test is armed
#: explicitly by ``reorder_webhook``.
AUTHORIZE_DELAY_S = 1
CAPTURE_DELAY_S = 1
REFUND_DELAY_S = 2


@dataclass
class SimOrder:
    order_id: str
    amount_paise: int
    currency: str
    client_ref: str
    payee: Account


@dataclass
class SimPayment:
    payment_id: str
    order_id: str
    amount_paise: int
    currency: str
    state: PaymentState
    payee: Account
    source: Account
    client_ref: str
    captured_paise: int = 0

    def view(self) -> dict[str, object]:
        """The shape the event log and the oracles read."""
        return {
            "payment_id": self.payment_id,
            "order_id": self.order_id,
            "amount_paise": self.amount_paise,
            "captured_paise": self.captured_paise,
            "currency": self.currency,
            "state": str(self.state),
            "payee": self.payee.model_dump(mode="json"),
            "source": self.source.model_dump(mode="json"),
            "client_ref": self.client_ref,
        }


@dataclass
class SimRefund:
    refund_id: str
    payment_id: str
    amount_paise: int
    destination: Account
    state: RefundState
    kind: RefundKind
    idem: str


#: The payer. One instrument for the whole simulator: the interesting variable
#: in this project is where money *goes*, and a second funding source would add
#: a dimension no attack class uses.
DEFAULT_SOURCE = Account(type="vpa", value="ananya@upi")


@dataclass
class SimPSP:
    """A PSP that does exactly what the state machine says and nothing else."""

    clock: Clock
    rng: RunRandom
    log: EventLog
    scheduler: WebhookScheduler
    faults: FaultInjector = field(default_factory=FaultInjector)
    source: Account = DEFAULT_SOURCE

    orders: dict[str, SimOrder] = field(default_factory=dict)
    payments: dict[str, SimPayment] = field(default_factory=dict)
    refunds: dict[str, SimRefund] = field(default_factory=dict)
    #: idem key -> payment_id, so a retried call returns the first outcome
    #: rather than producing a second one.
    _seen_idem: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._ids = IdFactory(self.clock, self.rng)
        self.scheduler.on("payment.authorized", self._on_authorized_webhook)
        self.scheduler.on("payment.captured", self._on_captured_webhook)
        self.scheduler.on("refund.processed", self._on_refund_webhook)

    # -- guards -----------------------------------------------------------

    def _now_s(self) -> int:
        return int(self.clock.now().timestamp())

    def _guard_reachable(self, call: str) -> None:
        """Refuse to answer while a timeout or a partition is in force.

        Both raise, and neither changes state. "No state change until the
        outcome is known" (SPEC.md §16) is the entire point: a PSP that failed
        the payment on a timeout would be answering a question it does not
        know the answer to.
        """
        partitioned_until = self.faults.partitioned_until_s()
        if partitioned_until is not None and self._now_s() < partitioned_until:
            self.log.append(
                SimActor.SIM,
                SimEvent.FAULT_FIRED,
                {"fault": str(Fault.PARTITION), "call": call, "until_s": partitioned_until},
            )
            raise PSPTimeout(f"{call}: partitioned until clock-second {partitioned_until}")

        if self.faults.fires(Fault.PSP_TIMEOUT):
            self.log.append(
                SimActor.SIM,
                SimEvent.FAULT_FIRED,
                {"fault": str(Fault.PSP_TIMEOUT), "call": call},
            )
            raise PSPTimeout(f"{call}: accepted, no response")

    # -- the adapter protocol ---------------------------------------------

    def create_order(
        self,
        amount_paise: int,
        currency: str,
        ref: str,
        *,
        payee: Account | None = None,
    ) -> SimOrder:
        """Open an order. No money moves; this only names the amount and payee.

        ``payee`` is keyword-only and outside
        :class:`~kernel.adapters.base.PSPAdapter`'s signature because a real
        PSP takes it from the merchant account the API key belongs to. Here the
        caller names it, which is what makes a redirected payee expressible at
        all — and therefore measurable.
        """
        self._guard_reachable("create_order")
        if amount_paise <= 0:
            raise ValueError("an order for zero or less is not an order")

        order = SimOrder(
            order_id="ord_" + self.rng.bytes("psp:order", 8).hex(),
            amount_paise=amount_paise,
            currency=currency,
            client_ref=ref,
            payee=payee or Account(type="vpa", value="merchant@upi"),
        )
        self.orders[order.order_id] = order
        self.log.append(
            SimActor.PSP,
            SimEvent.ORDER_CREATED,
            {
                "order_id": order.order_id,
                "amount_paise": amount_paise,
                "currency": currency,
                "client_ref": ref,
                "payee": order.payee.model_dump(mode="json"),
            },
        )
        return order

    def authorize(self, order_id: str, instrument: str, idem: str) -> SimPayment:
        """Reserve the funds. The payee is fixed here and never moves again."""
        self._guard_reachable("authorize")
        if idem in self._seen_idem:
            return self.payments[self._seen_idem[idem]]

        order = self.orders.get(order_id)
        if order is None:
            raise KeyError(f"no such order {order_id!r}")

        payment = SimPayment(
            payment_id=self._ids.payment_id(),
            order_id=order.order_id,
            amount_paise=order.amount_paise,
            currency=order.currency,
            state=PaymentState.CREATED,
            payee=order.payee,
            source=self.source,
            client_ref=order.client_ref,
        )
        payment.state = check_payment_transition(payment.state, PaymentState.AUTHORIZED)
        self.payments[payment.payment_id] = payment
        self._seen_idem[idem] = payment.payment_id

        self.log.append(SimActor.PSP, SimEvent.AUTHORIZED, {"instrument": instrument, **payment.view()})
        self.scheduler.schedule(
            "payment.authorized",
            {"payment_id": payment.payment_id, "state": str(PaymentState.AUTHORIZED)},
            delay_s=AUTHORIZE_DELAY_S,
        )
        return payment

    def capture(self, payment_id: str, amount_paise: int, idem: str) -> SimPayment:
        """Settle. This is the debit, and the only call that makes one."""
        self._guard_reachable("capture")
        if idem in self._seen_idem:
            # A real PSP dedups on the key it was given. If ours did not, a
            # kernel idempotency bug and a PSP quirk would look identical.
            return self.payments[self._seen_idem[idem]]

        payment = self.payments.get(payment_id)
        if payment is None:
            raise KeyError(f"no such payment {payment_id!r}")
        if amount_paise > payment.amount_paise:
            raise ValueError("capture above the authorized amount")

        payment.state = check_payment_transition(payment.state, PaymentState.CAPTURED)
        payment.captured_paise = amount_paise
        self._seen_idem[idem] = payment.payment_id

        self.log.append(SimActor.PSP, SimEvent.CAPTURED, payment.view())
        self.scheduler.schedule(
            "payment.captured",
            {"payment_id": payment.payment_id, "state": str(PaymentState.CAPTURED)},
            delay_s=CAPTURE_DELAY_S,
        )
        return payment

    def refund(
        self, payment_id: str, amount_paise: int, dest: Account, idem: str
    ) -> SimRefund:
        """Credit back to the payment's recorded source.

        ``dest`` is compared, not obeyed. A PSP that credited wherever it was
        told would be doing check 8's job for the kernel, and class A7 would
        pass against an undefended agent for the wrong reason.
        """
        self._guard_reachable("refund")
        payment = self.payments.get(payment_id)
        if payment is None:
            raise KeyError(f"no such payment {payment_id!r}")
        if payment.state is not PaymentState.CAPTURED:
            raise IllegalTransition("refund", str(payment.state), "refundable")
        if dest != payment.source:
            raise ValueError(
                "refund destination is not the payment's source; a PSP credits "
                "the instrument it debited"
            )
        if amount_paise > payment.captured_paise:
            raise ValueError("refund above the captured amount")

        existing = self.refunds.get(idem)
        if existing is not None:
            return existing

        refund = SimRefund(
            refund_id=self._ids.refund_id(),
            payment_id=payment.payment_id,
            amount_paise=amount_paise,
            destination=payment.source,
            state=check_refund_transition(RefundState.CREATED, RefundState.PROCESSING),
            kind=RefundKind.FULL
            if amount_paise == payment.captured_paise
            else RefundKind.PARTIAL,
            idem=idem,
        )
        self.refunds[idem] = refund
        self.log.append(
            SimActor.PSP,
            SimEvent.REFUND_CREATED,
            {
                "refund_id": refund.refund_id,
                "payment_id": payment.payment_id,
                "amount_paise": amount_paise,
                "destination": refund.destination.model_dump(mode="json"),
                "kind": str(refund.kind),
                "state": str(refund.state),
            },
        )
        self.scheduler.schedule(
            "refund.processed",
            {"refund_id": refund.refund_id, "idem": idem},
            delay_s=REFUND_DELAY_S,
        )
        return refund

    def poll(self, client_ref: str) -> SimPayment | None:
        """The recovery path: what really happened, by the caller's own ref.

        Not affected by ``psp_timeout``. Assumption 6 in SPEC.md §17 is that
        the PSP is honest about payment state *when polled* — if a poll could
        also time out, recovery would have no terminating condition and the
        crash test would be a test of the retry loop instead.
        """
        found = next(
            (p for p in self.payments.values() if p.client_ref == client_ref), None
        )
        self.log.append(
            SimActor.PSP,
            SimEvent.POLLED,
            {
                "client_ref": client_ref,
                "found": found is not None,
                "state": str(found.state) if found else None,
                "payment_id": found.payment_id if found else None,
            },
        )
        return found

    # -- webhook handlers -------------------------------------------------

    def _apply_webhook_state(self, event: WebhookEvent, requested: PaymentState) -> None:
        """Refuse a backwards claim here, at the state machine.

        Not in the dedup layer. Dedup answers "have I seen this event id?",
        which ``duplicate_webhook`` answers wrongly by design. This answers
        "can that have happened next?", which no event id can lie about.
        """
        payment = self.payments.get(event.payload.get("payment_id", ""))
        if payment is None:
            return
        if payment.state is requested:
            return  # a redelivery of news we already have; not a finding
        if not is_forward_payment(payment.state, requested):
            self.log.append(
                SimActor.PSP,
                SimEvent.TRANSITION_REFUSED,
                {
                    "event_id": event.event_id,
                    "payment_id": payment.payment_id,
                    "current": str(payment.state),
                    "claimed": str(requested),
                    "refused_by": "state_machine",
                },
            )
            return
        payment.state = check_payment_transition(payment.state, requested)

    def _on_authorized_webhook(self, event: WebhookEvent) -> None:
        self._apply_webhook_state(event, PaymentState.AUTHORIZED)

    def _on_captured_webhook(self, event: WebhookEvent) -> None:
        self._apply_webhook_state(event, PaymentState.CAPTURED)

    def _on_refund_webhook(self, event: WebhookEvent) -> None:
        refund = self.refunds.get(event.payload.get("idem", ""))
        if refund is None or refund.state is RefundState.PROCESSED:
            return
        refund.state = check_refund_transition(refund.state, RefundState.PROCESSED)
        self.log.append(
            SimActor.PSP,
            SimEvent.REFUND_PROCESSED,
            {"refund_id": refund.refund_id, "state": str(refund.state)},
        )

    # -- what the oracles read --------------------------------------------

    def ledger(self) -> list[dict[str, object]]:
        """Every debit that actually happened, in creation order.

        This is "the ledger" the M2 gate talks about. In the undefended
        configuration there is no kernel and therefore no SpendLedger, so the
        PSP's own record of captures is the only account of where the money
        went — which is the right place to read it from anyway: the oracle
        should ask the payment rail, not the thing under test.
        """
        return [
            p.view()
            for p in self.payments.values()
            if p.captured_paise > 0
        ]

    def reset(self) -> None:
        self.orders.clear()
        self.payments.clear()
        self.refunds.clear()
        self._seen_idem.clear()
