"""The fault injector, SPEC.md §09.

M4 is where these faults get exercised against the kernel's recovery path. What
M2 owes is that each one *fires at the site it claims*, deterministically, and
that arming one does not change a run that did not arm it.
"""

from __future__ import annotations

import pytest

from kernel.enums import PaymentState
from kernel.models import Account
from sim.control import ControlPlane
from sim.eventlog import SimEvent
from sim.faults import FAULT_SITES, Fault, FaultInjector, PSPTimeout
from sim.world import World


def _world():
    world = World(seed="fault-tests")
    return world, ControlPlane(world)


def _order_and_authorize(world, ref="ref_1"):
    order = world.psp.create_order(
        1000, "INR", ref, payee=Account(type="vpa", value="merchant@upi")
    )
    return world.psp.authorize(order.order_id, "tok", idem=f"{ref}:auth")


def test_every_fault_has_a_site():
    """A fault with no site could not fire, and would pass as armed forever."""
    assert set(FAULT_SITES) == set(Fault)


def test_arming_is_one_shot_by_default():
    injector = FaultInjector()
    injector.arm(Fault.PSP_TIMEOUT)
    assert injector.fires(Fault.PSP_TIMEOUT)
    assert not injector.fires(Fault.PSP_TIMEOUT)


def test_asking_consumes_a_firing():
    """Otherwise the injector's count and what happened can disagree."""
    injector = FaultInjector()
    injector.arm(Fault.PSP_TIMEOUT, count=2)
    assert injector.fires(Fault.PSP_TIMEOUT)
    assert injector.fires(Fault.PSP_TIMEOUT)
    assert not injector.is_armed(Fault.PSP_TIMEOUT)


def test_store_unavailable_is_scoped_to_its_target():
    """One bad store must not make every store bad — that would hide which
    store the check actually needed."""
    injector = FaultInjector()
    injector.arm(Fault.STORE_UNAVAILABLE, target="ledger")
    assert not injector.fires(Fault.STORE_UNAVAILABLE, target="audit")
    assert injector.fires(Fault.STORE_UNAVAILABLE, target="ledger")


def test_psp_timeout_changes_no_state():
    """"No state change until the outcome is known" (SPEC.md §16).

    A PSP that failed the payment on a timeout would be answering a question it
    does not have the answer to, and the recovery path would have nothing left
    to reconcile.
    """
    world, plane = _world()
    payment = _order_and_authorize(world)
    plane.fault({"fault": "psp_timeout"})

    with pytest.raises(PSPTimeout):
        world.psp.capture(payment.payment_id, 1000, idem="ref_1:capture")

    assert world.psp.payments[payment.payment_id].state is PaymentState.AUTHORIZED
    assert world.psp.payments[payment.payment_id].captured_paise == 0


def test_poll_still_answers_through_a_timeout():
    """Assumption 6: the PSP is honest when polled. If a poll could time out
    too, recovery would have no terminating condition."""
    world, plane = _world()
    payment = _order_and_authorize(world)
    plane.fault({"fault": "psp_timeout"})

    found = world.psp.poll("ref_1")
    assert found is not None and found.payment_id == payment.payment_id


def test_partition_drops_responses_for_n_clock_seconds():
    world, plane = _world()
    plane.fault({"fault": "partition", "duration_s": 3})

    with pytest.raises(PSPTimeout):
        world.psp.create_order(1000, "INR", "ref_p")

    plane.clock_advance({"seconds": 3})
    assert world.psp.create_order(1000, "INR", "ref_p").amount_paise == 1000


def test_duplicate_webhook_redelivers_with_a_fresh_event_id():
    """The fresh id is the whole point: dedup cannot be built on it."""
    world, plane = _world()
    plane.fault({"fault": "duplicate_webhook"})
    payment = _order_and_authorize(world, ref="ref_d")
    plane.clock_advance({"seconds": 1})

    delivered = [e for e in world.scheduler.delivered if e.kind == "payment.authorized"]
    assert len(delivered) == 2
    assert delivered[0].event_id != delivered[1].event_id
    assert delivered[0].payload == delivered[1].payload
    assert world.psp.payments[payment.payment_id].state is PaymentState.AUTHORIZED


def test_reorder_webhook_produces_authorized_after_captured_and_it_is_refused():
    """Refused at the state machine, not absorbed by the dedup layer."""
    world, plane = _world()
    plane.fault({"fault": "reorder_webhook"})

    payment = _order_and_authorize(world, ref="ref_r")  # authorized held back 1s
    world.psp.capture(payment.payment_id, 1000, idem="ref_r:capture")
    plane.clock_advance({"seconds": 1})
    plane.clock_advance({"seconds": 1})

    kinds = [e.kind for e in world.scheduler.delivered]
    assert kinds.index("payment.captured") < kinds.index("payment.authorized")

    refused = world.log.of(SimEvent.TRANSITION_REFUSED)
    assert refused, "the late authorized was silently absorbed"
    assert refused[0]["payload"]["current"] == "captured"
    assert refused[0]["payload"]["claimed"] == "authorized"
    assert refused[0]["payload"]["refused_by"] == "state_machine"
    assert world.psp.payments[payment.payment_id].state is PaymentState.CAPTURED


def test_an_unarmed_run_is_unaffected():
    world, plane = _world()
    payment = _order_and_authorize(world, ref="ref_clean")
    world.psp.capture(payment.payment_id, 1000, idem="ref_clean:capture")
    plane.clock_advance({"seconds": 1})

    assert not world.log.of(SimEvent.FAULT_FIRED)
    assert world.psp.payments[payment.payment_id].state is PaymentState.CAPTURED


def test_an_unknown_fault_name_is_refused():
    _, plane = _world()
    with pytest.raises(ValueError, match="not a fault"):
        plane.fault({"fault": "make_it_all_work"})
