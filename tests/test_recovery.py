"""The recovery scan. An ``in_flight`` row past its TTL, and what closes it.

SPEC.md §08 step 4: a row older than ``RECOVERY_TTL`` moves to ``recovering``,
polls the PSP by ``client_ref``, and commits the true terminal state. **Never
blindly retried, never silently skipped.**

The two crash windows are the whole subject and they resolve in opposite
directions, which is why every test here says which one it opened:

``after_reserve``
    The rail was never touched. The poll finds no capture, the key is
    **released**, and there are zero debits. A blind retry here would be
    harmless; a blind retry in the other window would double-charge, and the
    scan cannot tell which window it is in without asking.
``after_psp_call``
    The debit exists and the ledger does not know. The poll finds it, the scan
    **commits** it, and there is exactly one debit. A silent skip here is how a
    debit ends up with nothing recording it.

The bench has no webhook subscriber, so these exercise the scan on its own.
:mod:`tests.test_m4_gate` runs the same crash through a full run, where a
webhook may reconcile the ledger first and the answer must still be one debit.
"""

from __future__ import annotations

import pytest

from kernel.enums import IdempotencyState
from kernel.service import CRASH_AFTER_PSP_CALL, CRASH_AFTER_RESERVE
from kernel.stores.idempotency import RECOVERY_TTL_S, idempotency_key
from sim.faults import Fault, KernelCrashed
from tests.kernel_bench import Bench


def crash_at(window: str, during: str = "capture"):
    """A crash hook that fires once, in one named window of one action.

    Both halves matter. Without the window the crash lands wherever the code
    reaches first; without the action it lands on the authorize, and a capture
    that never ran is not the position recovery exists for.
    """
    fired = {"done": False}

    def hook(site: str, action: str) -> None:
        if site == window and action == during and not fired["done"]:
            fired["done"] = True
            raise KernelCrashed(f"{Fault.CRASH_AFTER_RESERVE}:{action}.{site}")  # type: ignore[arg-type]

    return hook


@pytest.fixture
def crashed_after_call(tmp_path):
    """A bench whose capture died after the rail answered."""
    bench = Bench(tmp_path=tmp_path, crash=crash_at(CRASH_AFTER_PSP_CALL))
    bench.register()
    bench.authorize()
    with pytest.raises(KernelCrashed):
        bench.capture()
    yield bench
    bench.close()


@pytest.fixture
def crashed_before_call(tmp_path):
    """A bench whose capture died before the rail was touched."""
    bench = Bench(tmp_path=tmp_path, crash=crash_at(CRASH_AFTER_RESERVE))
    bench.register()
    bench.authorize()
    with pytest.raises(KernelCrashed):
        bench.capture()
    yield bench
    bench.close()


def capture_key(bench):
    return idempotency_key(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"], "capture"
    )


def reconciliations(bench):
    return [
        e for e in bench.service.chain.read() if e.action == "recovery.reconciled"
    ]


# --- the position a crash leaves ------------------------------------------


def test_a_crash_after_the_call_leaves_a_debit_the_ledger_does_not_know_about(
    crashed_after_call,
):
    """SPEC.md §06's "crash mid-capture" row, reproduced exactly.

    Payment ``captured`` at the PSP only; ledger still ``committed``; key still
    ``in_flight``. This is the position that needs a scan, and asserting it
    before the scan runs is what makes the scan's result mean something.
    """
    bench = crashed_after_call

    assert len(bench.world.psp.ledger()) == 1
    row = bench.service.ledger.get(bench.intent["mandate_id"])
    assert row.committed_paise == 49900
    assert row.captured_paise == 0
    assert bench.service.idempotency.get(capture_key(bench)).state == (
        IdempotencyState.IN_FLIGHT
    )


def test_the_scan_leaves_a_reservation_inside_the_ttl_alone(crashed_after_call):
    """Its owner may still be coming back. Thirty seconds of injected clock."""
    result = crashed_after_call.service.recovery_scan()

    assert result == {"scanned": 0, "resolved": []}
    assert not reconciliations(crashed_after_call)


# --- after the TTL --------------------------------------------------------


def test_past_the_ttl_the_scan_commits_the_debit_that_really_happened(
    crashed_after_call,
):
    """Exactly one debit, and the ledger finally agrees with the rail."""
    bench = crashed_after_call
    bench.world.clock.advance(RECOVERY_TTL_S)

    result = bench.service.recovery_scan()
    assert result["scanned"] == 1
    assert result["resolved"][0]["outcome"] == "settled"
    assert result["resolved"][0]["ledger_moved"] is True

    row = bench.service.ledger.get(bench.intent["mandate_id"])
    assert row.captured_paise == 49900
    assert len(bench.world.psp.ledger()) == 1
    assert bench.service.idempotency.get(capture_key(bench)).state == (
        IdempotencyState.TERMINAL
    )


def test_past_the_ttl_a_crash_before_the_call_releases_rather_than_commits(
    crashed_before_call,
):
    """The opposite direction, from an identically-shaped row.

    The reservation looks the same; only the rail can say which window it was.
    Committing a capture here would book a debit that never happened.
    """
    bench = crashed_before_call
    assert bench.world.psp.ledger() == []
    bench.world.clock.advance(RECOVERY_TTL_S)

    result = bench.service.recovery_scan()
    assert result["resolved"][0]["outcome"] == "released"
    assert "never captured" in result["resolved"][0]["detail"]

    assert bench.world.psp.ledger() == []
    assert bench.service.ledger.get(bench.intent["mandate_id"]).captured_paise == 0
    # Released, so the caller may legitimately try again — and does.
    assert bench.service.idempotency.get(capture_key(bench)) is None
    assert bench.capture().body["decision"] == "allow"
    assert len(bench.world.psp.ledger()) == 1


def test_the_scan_never_double_charges_when_it_runs_twice(crashed_after_call):
    """The property the whole milestone rests on. Idempotent by construction:
    the second scan finds a terminal row and has nothing to look at."""
    bench = crashed_after_call
    bench.world.clock.advance(RECOVERY_TTL_S)

    bench.service.recovery_scan()
    second = bench.service.recovery_scan()

    assert second["scanned"] == 0
    assert len(bench.world.psp.ledger()) == 1
    assert bench.service.ledger.get(bench.intent["mandate_id"]).captured_paise == 49900


def test_a_retry_arriving_after_the_ttl_resolves_and_then_replays(
    crashed_after_call,
):
    """The request-driven path and the scan reach the same conclusion.

    One implementation, so a key resolved because a retry arrived and a key
    resolved because the clock moved cannot disagree about the same debit.
    """
    bench = crashed_after_call
    bench.world.clock.advance(RECOVERY_TTL_S)

    out = bench.capture()
    assert out.status == 200
    assert out.body["replayed"] is True
    assert out.body["recovered"] is True
    assert len(bench.world.psp.ledger()) == 1


# --- what the chain says --------------------------------------------------


def test_every_reconciliation_is_recorded_with_what_the_rail_said(
    crashed_after_call,
):
    bench = crashed_after_call
    bench.world.clock.advance(RECOVERY_TTL_S)
    bench.service.recovery_scan()

    entry = reconciliations(bench)[-1]
    assert entry.payload["polled_by"] == "client_ref"
    assert entry.payload["outcome"] == "settled"
    assert entry.payload["state"] == "captured"
    assert entry.payload["ledger"]["captured_paise"] == 49900


def test_a_poisoned_kernel_does_not_move_a_ledger_on_its_own_authority(
    crashed_after_call,
):
    """A kernel whose own record is untrustworthy must not be repairing one."""
    bench = crashed_after_call
    bench.world.clock.advance(RECOVERY_TTL_S)
    bench.service.poison("BROKEN at seq 3")

    result = bench.service.recovery_scan()
    assert result["scanned"] == 0
    assert result["poisoned"] == "BROKEN at seq 3"
    assert bench.service.ledger.get(bench.intent["mandate_id"]).captured_paise == 0


def test_a_scan_that_cannot_read_its_store_reports_rather_than_skipping(
    tmp_path,
):
    """An unreadable store is not an empty one. The rows are still there and
    the next scan will find them; what must not happen is a scan reporting
    "nothing to do" because it could not look."""
    from tests.test_fail_closed import Breaker

    breaker = Breaker()
    bench = Bench(tmp_path=tmp_path, guard=breaker)
    try:
        bench.register()
        breaker.break_("idempotency", "read")
        result = bench.service.recovery_scan()

        assert result["scanned"] == 0
        assert "error" in result
    finally:
        bench.close()
