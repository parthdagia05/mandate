"""Check 8 — refund_binding. Does the money go back where it came from?

``destination == payments[id].source_json``, read from the ledger and never
from the request.

Class A7 is "refund this to a different account", and the kernel's answer is
structural rather than evaluative: :class:`~kernel.models.PaymentRequest` has
no destination field. There is nowhere in the wire format to put one, so there
is nothing for a merchant's support page to redirect. This check is what makes
that structure hold at the boundary — it fills the destination in from the
recorded payment source, so a refund is a reversal of a specific debit rather
than a transfer that happens to be labelled one.

The simulator refuses a mismatched destination too, which is not the kernel
doing the work twice: a PSP that credited wherever it was told would make this
check untestable, because the rail would already be enforcing it.
"""

from __future__ import annotations

from typing import Any

from kernel.checks.base import CheckContext, CheckResult
from kernel.enums import ReasonCode

__all__ = ["CHECK_ID", "refund_binding"]

CHECK_ID = 8


def refund_binding(ctx: CheckContext, payment: dict[str, Any] | None) -> CheckResult:
    """``payment`` is the kernel's own recorded row, already read by the caller."""
    requested = ctx.request.params.original_payment_id

    if requested is None:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.REFUND_DESTINATION_MISMATCH,
            detail="refund names no original payment",
        )
    if payment is None:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.REFUND_DESTINATION_MISMATCH,
            detail="no recorded payment with that id under this mandate",
            payment_id=requested,
        )
    if payment["mandate_id"] != ctx.intent.mandate_id:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.REFUND_DESTINATION_MISMATCH,
            detail="payment belongs to a different mandate",
            payment_id=requested,
        )
    if ctx.request.params.amount > payment["amount_paise"]:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.REFUND_DESTINATION_MISMATCH,
            detail="refund above the captured amount",
            payment_id=requested,
            captured_paise=payment["amount_paise"],
            requested_amount=ctx.request.params.amount,
        )

    return CheckResult.ok(
        CHECK_ID,
        payment_id=requested,
        # The destination is *reported*, not accepted. It is here in the chain
        # so the entry shows which account the kernel chose and why.
        destination=payment["source"],
        destination_from="ledger.payment.source_json",
    )
