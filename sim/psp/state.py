"""The payment and refund state machines, SPEC.md §06.

```
payment:  created ──▶ authorized ──▶ captured ──▶ reversed
             │            │
             └──▶ failed  └──▶ voided

refund:   created ──▶ processing ──┬──▶ processed
                                    └──▶ failed ──retry──▶ processing
```

**Forward transitions only, and refusal happens here.** A webhook claiming
``authorized`` after ``captured`` is rejected by this table, not absorbed by the
dedup layer. The distinction matters: dedup answers "have I seen this event?",
which a redelivery with a fresh event id answers wrongly. The state machine
answers "is this a thing that can happen next?", which no event id can lie
about. A6 turns on that being true.

The refund machine has the one backwards-looking edge in the system:
``failed → processing`` on a retry with the same key. It is not a widening —
the key is the same, so a retry cannot become a second credit — and it is where
UPI's deemed-success position lives: debited, credit unconfirmed.

The **forward order** these tables are read against lives in
:mod:`kernel.payments`, not here, and is re-exported for callers that only know
about the simulator. The kernel needs the same order to judge a webhook, and it
cannot get it from the simulator — the simulator is the thing sending the
webhook.
"""

from __future__ import annotations

from kernel.enums import PaymentState, RefundState
from kernel.payments import PAYMENT_RANK, is_forward_payment

__all__ = [
    "PAYMENT_TRANSITIONS",
    "REFUND_TRANSITIONS",
    "PAYMENT_TERMINAL",
    "REFUND_TERMINAL",
    "PAYMENT_RANK",
    "IllegalTransition",
    "check_payment_transition",
    "check_refund_transition",
    "is_forward_payment",
]


class IllegalTransition(ValueError):
    """A transition the machine does not have an edge for."""

    def __init__(self, kind: str, current: str, requested: str) -> None:
        super().__init__(
            f"{kind}: {current} -> {requested} is not a transition; "
            "only forward edges exist"
        )
        self.kind = kind
        self.current = current
        self.requested = requested


PAYMENT_TRANSITIONS: dict[PaymentState, frozenset[PaymentState]] = {
    PaymentState.CREATED: frozenset({PaymentState.AUTHORIZED, PaymentState.FAILED}),
    PaymentState.AUTHORIZED: frozenset({PaymentState.CAPTURED, PaymentState.VOIDED}),
    PaymentState.CAPTURED: frozenset({PaymentState.REVERSED}),
    PaymentState.FAILED: frozenset(),
    PaymentState.VOIDED: frozenset(),
    PaymentState.REVERSED: frozenset(),
}

REFUND_TRANSITIONS: dict[RefundState, frozenset[RefundState]] = {
    RefundState.CREATED: frozenset({RefundState.PROCESSING, RefundState.FAILED}),
    RefundState.PROCESSING: frozenset({RefundState.PROCESSED, RefundState.FAILED}),
    # The retry edge. Same key, so a retry cannot become a second credit.
    RefundState.FAILED: frozenset({RefundState.PROCESSING}),
    RefundState.PROCESSED: frozenset(),
}

PAYMENT_TERMINAL = frozenset(
    state for state, onward in PAYMENT_TRANSITIONS.items() if not onward
)
REFUND_TERMINAL = frozenset(
    state for state, onward in REFUND_TRANSITIONS.items() if not onward
)


def check_payment_transition(
    current: PaymentState, requested: PaymentState
) -> PaymentState:
    """Return ``requested`` or raise. Never silently returns ``current``."""
    if requested not in PAYMENT_TRANSITIONS[current]:
        raise IllegalTransition("payment", str(current), str(requested))
    return requested


def check_refund_transition(
    current: RefundState, requested: RefundState
) -> RefundState:
    if requested not in REFUND_TRANSITIONS[current]:
        raise IllegalTransition("refund", str(current), str(requested))
    return requested
