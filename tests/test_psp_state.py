"""The payment and refund machines, SPEC.md §06.

The tests worth having here are the *refusals*. That a payment can go
``created → authorized → captured`` is one assertion; that it cannot go
anywhere else is a hundred, and only the second kind stops A6.
"""

from __future__ import annotations

import pytest

from kernel.enums import PaymentState, RefundState
from sim.psp.state import (
    PAYMENT_TERMINAL,
    PAYMENT_TRANSITIONS,
    REFUND_TERMINAL,
    REFUND_TRANSITIONS,
    IllegalTransition,
    check_payment_transition,
    check_refund_transition,
    is_forward_payment,
)


def test_the_happy_path_exists():
    state = PaymentState.CREATED
    state = check_payment_transition(state, PaymentState.AUTHORIZED)
    state = check_payment_transition(state, PaymentState.CAPTURED)
    assert state is PaymentState.CAPTURED


@pytest.mark.parametrize(
    "current,requested",
    [
        (PaymentState.CAPTURED, PaymentState.AUTHORIZED),
        (PaymentState.CAPTURED, PaymentState.CREATED),
        (PaymentState.AUTHORIZED, PaymentState.CREATED),
        (PaymentState.REVERSED, PaymentState.CAPTURED),
        (PaymentState.CREATED, PaymentState.CAPTURED),  # no skipping either
    ],
)
def test_backwards_and_skipping_are_refused(current, requested):
    with pytest.raises(IllegalTransition):
        check_payment_transition(current, requested)


def test_every_payment_state_has_a_row():
    """A state with no row would raise KeyError rather than refuse, and a
    KeyError is a crash where a refusal was the specified behaviour."""
    assert set(PAYMENT_TRANSITIONS) == set(PaymentState)
    assert set(REFUND_TRANSITIONS) == set(RefundState)


def test_terminal_states_absorb():
    assert PAYMENT_TERMINAL == {
        PaymentState.FAILED,
        PaymentState.VOIDED,
        PaymentState.REVERSED,
    }
    assert REFUND_TERMINAL == {RefundState.PROCESSED}
    for state in PAYMENT_TERMINAL:
        for onward in PaymentState:
            with pytest.raises(IllegalTransition):
                check_payment_transition(state, onward)


def test_the_refund_retry_edge_exists_and_is_the_only_one():
    """``failed → processing`` on the same key is the one non-forward edge."""
    state = check_refund_transition(RefundState.CREATED, RefundState.PROCESSING)
    state = check_refund_transition(state, RefundState.FAILED)
    assert check_refund_transition(state, RefundState.PROCESSING) is RefundState.PROCESSING

    with pytest.raises(IllegalTransition):
        check_refund_transition(RefundState.PROCESSED, RefundState.PROCESSING)


def test_forward_order_separates_stale_from_backwards():
    """Both are refused; only one of them is a finding."""
    assert is_forward_payment(PaymentState.CREATED, PaymentState.CAPTURED)
    assert not is_forward_payment(PaymentState.CAPTURED, PaymentState.AUTHORIZED)
    assert not is_forward_payment(PaymentState.CAPTURED, PaymentState.CAPTURED)
