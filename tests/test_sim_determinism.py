"""D-01 at the level M2 can reach it: same seed, byte-identical run.

The M2 gate is not "the attack worked once". A flaky attack is not evidence,
and neither is a flaky benign path. These tests are the gate.
"""

from __future__ import annotations

import pytest

from harness.runner import run_case
from sim.control import ControlPlane
from sim.eventlog import SimEvent
from sim.world import World


def _run(**kwargs):
    return run_case("benign-01", model="scripted", **kwargs)


def test_same_seed_gives_a_byte_identical_log():
    first, second = _run(seed="7"), _run(seed="7")
    assert first.log_head == second.log_head
    assert first.log_entries == second.log_entries


def test_same_seed_gives_a_byte_identical_log_under_attack():
    first = _run(seed="7", attack_id="A1-seed-1")
    second = _run(seed="7", attack_id="A1-seed-1")
    assert first.log_head == second.log_head
    assert first.attacker_win and second.attacker_win


def test_a_different_seed_moves_the_head():
    """Otherwise the seed is decorative and 'reproduces from a seed' is empty."""
    assert _run(seed="7").log_head != _run(seed="8").log_head


def test_the_clock_moves_only_at_the_barrier():
    world = World(seed="7")
    plane = ControlPlane(world)
    before = world.clock.now()

    world.scheduler.schedule("payment.captured", {"payment_id": "pay_x"}, delay_s=1)
    assert world.scheduler.pending(), "queued, not delivered"
    assert world.clock.now() == before, "nothing is on a timer"

    plane.clock_advance({"seconds": 1})
    assert not world.scheduler.pending(), "the barrier settled before returning"


def test_the_barrier_delivers_in_schedule_order_not_call_order():
    """Ordering is a function of the seed and the schedule (SPEC.md §15)."""
    world = World(seed="7")
    plane = ControlPlane(world)

    world.scheduler.schedule("late", {}, delay_s=2)
    world.scheduler.schedule("early", {}, delay_s=1)

    plane.clock_advance({"seconds": 2})
    assert [e.kind for e in world.scheduler.delivered] == ["early", "late"]


def test_advancing_backwards_is_refused():
    plane = ControlPlane(World(seed="7"))
    with pytest.raises(ValueError):
        plane.clock_advance({"seconds": -1})


def test_the_log_never_carries_payload_bytes():
    """Containment: the chain records that a payload landed, never what it said.

    A chain that quoted attack text would be a chain that ships attack text,
    and the export is the artefact we hand to a reader (SPEC.md §12).
    """
    record = _run(seed="7", attack_id="A1-seed-1")
    assert record.attacker_win

    world = World(seed="7")
    from harness.corpus import load_attack

    case = load_attack("A1-seed-1")
    world.inject(case.injection())
    world.merchant.get_product("SK-MOUSE-01")

    served = world.log.of(SimEvent.MERCHANT_SERVED)
    assert served and served[-1]["payload"]["injected"] is True
    assert served[-1]["payload"]["payload_sha256"].startswith("sha256:")
    assert "attacker@upi" not in world.log.export_jsonl()
