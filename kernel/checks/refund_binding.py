"""Check 8 — refund_binding. Does the money go back where it came from, and is
there anything left to give back?

``destination == payments[id].source_json``, read from the ledger and never
from the request.

Class A7 is "refund this to a different account", and the kernel's answer is
structural rather than evaluative: :class:`~kernel.models.PaymentRequest` has
no destination field. There is nowhere in the wire format to put one, so there
is nothing for a merchant's support page to redirect. This check is what makes
that structure hold at the boundary — it fills the destination in from the
recorded payment source, so a refund is a reversal of a specific debit rather
than a transfer that happens to be labelled one.

**The cumulative conjunct, and why there are two of them.** A refund is bounded
twice: by what *this payment* still has outstanding, and by what *this mandate*
has captured and not yet given back. Neither implies the other. A mandate with
three purchases has room under the second bound long after the first purchase
is fully refunded, so a per-mandate check alone would let one debit be refunded
twice; and a mandate that has refunded everything it captured has nothing left
to give back even though a particular payment looks untouched, so a per-payment
check alone would let the ledger go negative. Both are here, and the failure
detail says which one bit.

**Refunds are never a reason to trust an uncaptured payment.** The payment must
actually have settled. Reversing a debit that never happened is not a refund,
it is a payout — the same money movement A7 is trying to produce, arrived at
through a different door.
"""

from __future__ import annotations

from typing import Any

from kernel.checks.base import CheckContext, CheckResult
from kernel.enums import PaymentState, ReasonCode, RefundKind

__all__ = ["CHECK_ID", "SETTLED_STATES", "refund_binding"]

CHECK_ID = 8

#: The payment states that imply money actually left. Only these are
#: refundable, because only these have anything to reverse.
SETTLED_STATES = frozenset({str(PaymentState.CAPTURED), str(PaymentState.REVERSED)})


def refund_binding(
    ctx: CheckContext,
    payment: dict[str, Any] | None,
    *,
    already_refunded: int = 0,
) -> CheckResult:
    """``payment`` is the kernel's own recorded row, already read by the caller.

    ``already_refunded`` is the sum of this payment's prior refunds, likewise
    read by the caller — a check may not touch a store, so both arrive as
    values (see :mod:`kernel.checks.base`).
    """
    requested = ctx.request.params.original_payment_id
    amount = ctx.request.params.amount

    def refuse(detail: str, **evidence: Any) -> CheckResult:
        return CheckResult.failed(
            CHECK_ID, ReasonCode.REFUND_DESTINATION_MISMATCH, detail=detail, **evidence
        )

    if requested is None:
        return refuse("refund names no original payment")
    if payment is None:
        return refuse(
            "no recorded payment with that id under this mandate",
            payment_id=requested,
        )
    if payment["mandate_id"] != ctx.intent.mandate_id:
        return refuse("payment belongs to a different mandate", payment_id=requested)
    if payment["state"] not in SETTLED_STATES:
        # Nothing settled, so there is nothing to reverse. A "refund" here
        # would be a fresh credit wearing a reversal's name.
        return refuse(
            "the payment never settled; there is no debit to reverse",
            payment_id=requested,
            payment_state=payment["state"],
        )

    captured = payment["amount_paise"]
    if already_refunded + amount > captured:
        return refuse(
            "cumulative refunds above what this payment captured",
            conjunct="payment_cumulative",
            payment_id=requested,
            captured_paise=captured,
            already_refunded_paise=already_refunded,
            requested_amount=amount,
        )

    ledger = ctx.ledger
    if ledger is None:
        # An unreadable or absent ledger is not an empty one (SPEC.md §16).
        return refuse(
            "no ledger row for this intent; it was never registered",
            conjunct="mandate_cumulative",
            payment_id=requested,
        )
    if ledger.refunded_paise + amount > ledger.captured_paise:
        return refuse(
            "cumulative refunds above what this mandate captured",
            conjunct="mandate_cumulative",
            payment_id=requested,
            captured_paise=ledger.captured_paise,
            already_refunded_paise=ledger.refunded_paise,
            requested_amount=amount,
        )

    return CheckResult.ok(
        CHECK_ID,
        payment_id=requested,
        # The destination is *reported*, not accepted. It is here in the chain
        # so the entry shows which account the kernel chose and why.
        destination=payment["source"],
        destination_from="ledger.payment.source_json",
        kind=str(
            RefundKind.FULL
            if already_refunded + amount == captured
            else RefundKind.PARTIAL
        ),
        captured_paise=captured,
        already_refunded_paise=already_refunded,
        requested_amount=amount,
    )
