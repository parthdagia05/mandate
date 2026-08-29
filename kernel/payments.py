"""The forward order of a payment, owned by the kernel.

The rank table lives here rather than in :mod:`sim.psp.state` because **both
sides of the trust boundary need it and only one of them is trusted.** The
simulator uses it to refuse an impossible transition on its own payments; the
kernel uses it, in :meth:`~kernel.service.KernelService.ingest_webhook`, to
decide whether a PSP callback is news, a redelivery, or a claim about the past.
A kernel that imported the simulator for that answer would be taking the
simulator's word for what can have happened — and the simulator is the thing
delivering the webhook.

Copying the table into both would be worse than either: two tables that could
drift, and the drift would show up as a webhook the PSP considers backwards and
the kernel considers progress. So there is one table, it is here, and
:mod:`sim.psp.state` imports it.

``failed`` and ``voided`` sit at the rank of the state they leave from. They are
exits, not progress: a ``voided`` payment has not got further than the
``authorized`` one it used to be, and ranking it higher would make a later
``captured`` look backwards.
"""

from __future__ import annotations

from kernel.enums import PaymentState

__all__ = ["PAYMENT_RANK", "is_forward_payment", "is_settled"]

#: Rank in the forward order. Used to tell a stale callback (ignorable) from a
#: backwards one (refusable). Both are refused; only the second is a finding.
PAYMENT_RANK: dict[PaymentState, int] = {
    PaymentState.CREATED: 0,
    PaymentState.FAILED: 0,
    PaymentState.AUTHORIZED: 1,
    PaymentState.VOIDED: 1,
    PaymentState.CAPTURED: 2,
    PaymentState.REVERSED: 3,
}


def is_forward_payment(current: PaymentState, requested: PaymentState) -> bool:
    """Whether ``requested`` is later in the forward order than ``current``."""
    return PAYMENT_RANK[requested] > PAYMENT_RANK[current]


def is_settled(state: PaymentState) -> bool:
    """Whether money has actually left. The recovery scan's whole question.

    ``captured`` and ``reversed`` are the two states that imply a debit
    happened; everything else means the rail either never charged or charged
    and gave it back before we looked, which is not a position the kernel can
    settle a capture against.
    """
    return PAYMENT_RANK[state] >= PAYMENT_RANK[PaymentState.CAPTURED]
