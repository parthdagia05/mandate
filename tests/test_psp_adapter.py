"""The simulated PSP — the only place money moves in a simulated run (REQ-1)."""

from __future__ import annotations

import pytest

from kernel.enums import PaymentState, RefundState
from kernel.models import Account
from sim.control import ControlPlane
from sim.psp.state import IllegalTransition
from sim.world import World

MERCHANT = Account(type="vpa", value="merchant@upi")
ATTACKER = Account(type="vpa", value="attacker@upi")


@pytest.fixture
def world():
    return World(seed="psp-tests")


@pytest.fixture
def plane(world):
    return ControlPlane(world)


def _pay(world, ref="ref_1", payee=MERCHANT, amount=1000):
    order = world.psp.create_order(amount, "INR", ref, payee=payee)
    payment = world.psp.authorize(order.order_id, "tok", idem=f"{ref}:auth")
    return world.psp.capture(payment.payment_id, amount, idem=f"{ref}:cap")


def test_created_authorized_captured(world):
    captured = _pay(world)
    assert captured.state is PaymentState.CAPTURED
    assert captured.captured_paise == 1000
    assert captured.payee == MERCHANT
    assert captured.source == Account(type="vpa", value="ananya@upi")


def test_capture_dedups_on_the_idempotency_key(world):
    """A real PSP dedups on the key it was given. If ours did not, a kernel
    idempotency bug and a PSP quirk would produce the same double debit and we
    could not tell them apart."""
    order = world.psp.create_order(1000, "INR", "ref_d", payee=MERCHANT)
    payment = world.psp.authorize(order.order_id, "tok", idem="ref_d:auth")
    first = world.psp.capture(payment.payment_id, 1000, idem="ref_d:cap")
    second = world.psp.capture(payment.payment_id, 1000, idem="ref_d:cap")

    assert first.payment_id == second.payment_id
    assert len(world.psp.ledger()) == 1


def test_the_payee_is_fixed_at_authorization(world):
    """Money cannot be redirected after the fact, so a successful A1 has to
    have redirected the *authorize* call — which makes it a decision the agent
    made rather than something that happened to it."""
    order = world.psp.create_order(1000, "INR", "ref_f", payee=MERCHANT)
    payment = world.psp.authorize(order.order_id, "tok", idem="ref_f:auth")
    captured = world.psp.capture(payment.payment_id, 1000, idem="ref_f:cap")
    assert captured.payee == MERCHANT


def test_capture_above_the_authorized_amount_is_refused(world):
    order = world.psp.create_order(1000, "INR", "ref_o", payee=MERCHANT)
    payment = world.psp.authorize(order.order_id, "tok", idem="ref_o:auth")
    with pytest.raises(ValueError, match="above the authorized amount"):
        world.psp.capture(payment.payment_id, 5000, idem="ref_o:cap")


def test_capturing_twice_with_different_keys_is_refused_by_the_machine(world):
    """Not by the dedup layer. Two keys means two calls, and the second one
    asks for a transition ``captured`` does not have."""
    captured = _pay(world, ref="ref_t")
    with pytest.raises(IllegalTransition):
        world.psp.capture(captured.payment_id, 1000, idem="ref_t:cap-again")


def test_a_refund_credits_the_source_and_ignores_the_destination_asked_for(world):
    """Class A7's floor. A PSP that credited wherever it was told would be
    doing check 8's job, and A7 would pass for the wrong reason."""
    captured = _pay(world, ref="ref_r")
    with pytest.raises(ValueError, match="not the payment's source"):
        world.psp.refund(captured.payment_id, 1000, ATTACKER, idem="ref_r:refund")

    refund = world.psp.refund(
        captured.payment_id, 1000, captured.source, idem="ref_r:refund"
    )
    assert refund.destination == captured.source
    assert refund.state is RefundState.PROCESSING


def test_a_refund_settles_at_the_barrier(world, plane):
    captured = _pay(world, ref="ref_s")
    refund = world.psp.refund(
        captured.payment_id, 1000, captured.source, idem="ref_s:refund"
    )
    assert refund.state is RefundState.PROCESSING  # UPI deemed-success lives here
    plane.clock_advance({"seconds": 2})
    assert world.psp.refunds["ref_s:refund"].state is RefundState.PROCESSED


def test_refunding_an_uncaptured_payment_is_refused(world):
    order = world.psp.create_order(1000, "INR", "ref_u", payee=MERCHANT)
    payment = world.psp.authorize(order.order_id, "tok", idem="ref_u:auth")
    with pytest.raises(IllegalTransition):
        world.psp.refund(payment.payment_id, 1000, payment.source, idem="ref_u:refund")


def test_poll_finds_a_payment_by_the_callers_own_reference(world):
    """The recovery path's only handle: after a crash, ``client_ref`` is the
    one identifier the kernel is certain it had."""
    captured = _pay(world, ref="ref_p")
    assert world.psp.poll("ref_p").payment_id == captured.payment_id
    assert world.psp.poll("ref_never") is None


def test_the_ledger_holds_only_actual_debits(world):
    order = world.psp.create_order(1000, "INR", "ref_a", payee=MERCHANT)
    world.psp.authorize(order.order_id, "tok", idem="ref_a:auth")
    assert world.psp.ledger() == [], "an authorization is not a debit"

    _pay(world, ref="ref_b")
    assert len(world.psp.ledger()) == 1


def test_an_order_for_nothing_is_not_an_order(world):
    with pytest.raises(ValueError):
        world.psp.create_order(0, "INR", "ref_z", payee=MERCHANT)
