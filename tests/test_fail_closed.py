"""Every failure resolves to deny. Availability is traded for integrity here.

SPEC.md §16's table, one test per row, plus the two rules underneath it:

* **Append then call, never call then append.** Reversing them turns a crash
  into an unrecorded debit — money leaves and nothing says it did.
* **Kernel down is a utility loss, never a money loss.** Denial of service is
  conceded on purpose, and the README says so.

The distinction these tests keep making is between *no* and *I could not tell*.
An unreadable budget is not an empty budget; a chain that cannot record is not
a chain with nothing to record. Both resolve to deny, and both say which one
happened.
"""

from __future__ import annotations

import json

import pytest

from kernel.enums import ActionType
from kernel.stores.db import StoreUnavailable
from tests.kernel_bench import Bench


class Breaker:
    """A store guard that fails on demand, one named store at a time."""

    def __init__(self) -> None:
        self.broken: set[tuple[str, str]] = set()

    def __call__(self, store: str, operation: str) -> None:
        if (store, operation) in self.broken or (store, "*") in self.broken:
            raise StoreUnavailable(f"{store}.{operation}: injected")

    def break_(self, store: str, operation: str = "*") -> None:
        self.broken.add((store, operation))

    def fix(self) -> None:
        self.broken.clear()


@pytest.fixture
def breaker():
    return Breaker()


@pytest.fixture
def fragile(tmp_path, breaker):
    made = Bench(tmp_path=tmp_path, guard=breaker)
    yield made
    made.close()


# --- ledger unreadable ----------------------------------------------------


def test_an_unreadable_ledger_denies_rather_than_reading_as_empty(fragile, breaker):
    """The whole of REQ-5 in one assertion.

    Treating "I could not read the budget" as "the budget is untouched" turns
    every transient disk error into an unbounded spend.
    """
    fragile.register()
    breaker.break_("ledger", "read")

    out = fragile.authorize()
    assert out.status == 503
    assert out.body["decision"] == "deny"
    assert out.body["reason_code"] == "STORE_UNAVAILABLE"
    assert fragile.world.psp.ledger() == []


def test_a_store_failure_is_recorded_in_the_chain(fragile, breaker):
    fragile.register()
    breaker.break_("nonces", "read")
    out = fragile.authorize()

    assert out.status == 503
    recorded = [e for e in fragile.service.chain.read() if e.action == "kernel.fail_closed"]
    assert recorded, "a fail-closed denial that nothing recorded is not a denial"
    assert recorded[-1].payload["stage"] == "store"


# --- audit unwritable -----------------------------------------------------


def test_an_unwritable_chain_denies_before_the_rail_is_touched(fragile, breaker):
    """REQ-2. A decision the chain did not record is a decision not made."""
    fragile.register()
    breaker.break_("audit", "write")

    out = fragile.authorize()
    assert out.status == 503
    assert out.body["psp_called"] is False
    assert fragile.world.psp.ledger() == []
    assert fragile.world.psp.payments == {}


def test_a_chain_that_cannot_record_its_own_failure_reports_a_gap(fragile, breaker):
    """Not hidden. The one failure this design cannot recover from is the one
    the response is loudest about."""
    breaker.break_("audit", "write")
    out = fragile.register()

    gap = out.body["audit_gap"]
    assert gap["gap"] is True
    assert "sidecar" in gap

    written = json.loads((fragile.tmp_path / "audit_gap.jsonl").read_text().splitlines()[0])
    assert written["mandate_id"] == fragile.intent["mandate_id"]
    # And it really is outside the chain — a sidecar cannot be evidence in the
    # chain's sense, which is exactly why the gap is reported as a gap.
    assert fragile.service.chain.count() == 0


def test_registration_is_all_or_nothing(fragile, breaker):
    """Authority the chain does not record must not exist.

    The nonce, the ledger row and the entry recording them go in one
    transaction, so a chain failure leaves no half-minted mandate behind.
    """
    breaker.break_("audit", "write")
    fragile.register()
    breaker.fix()

    assert fragile.service.ledger.get(fragile.intent["mandate_id"]) is None
    assert fragile.service.nonces.owner(fragile.intent["nonce"]) is None
    # And the nonce is still usable, so retrying once the store is back works.
    assert fragile.register().status == 200


# --- the chain does not verify -------------------------------------------


def test_a_tampered_chain_poisons_the_kernel(fragile):
    fragile.register()
    fragile.conn.execute(
        "UPDATE audit_entry SET payload_json = ? WHERE seq = 0",
        (json.dumps({"decision": "allow", "tampered": True}),),
    )

    verdict = fragile.service.audit_verify()
    assert verdict.status == 503
    assert verdict.body["broken_at"] == 0
    assert fragile.service.poisoned is not None


def test_a_poisoned_kernel_denies_everything_until_an_operator_clears_it(fragile):
    fragile.register()
    fragile.service.poison("BROKEN at seq 0: entry_hash does not match its contents")

    for call in (fragile.authorize, fragile.capture):
        out = call()
        assert out.status == 503
        assert out.body["decision"] == "deny"
        assert "poisoned" in out.body

    assert fragile.service.healthz().status == 503
    assert fragile.world.psp.ledger() == []


def test_the_harness_discards_a_run_whose_chain_does_not_verify(fragile):
    """A poisoned run is discarded, not reported.

    :meth:`harness.kernel_arm.KernelArm.verify` is what decides that, and this
    exercises the same predicate over the same chain. A number produced by a
    kernel whose own record is untrustworthy is worse than a missing number.
    """
    from kernel.audit.verify import verify_entries
    from kernel.audit.chain import ChainBroken

    fragile.register()
    fragile.conn.execute(
        "UPDATE audit_entry SET ts = '2000-01-01T00:00:00Z' WHERE seq = 0"
    )

    with pytest.raises(ChainBroken):
        verify_entries(fragile.service.chain.read())

    assert fragile.service.audit_verify().status == 503
    assert fragile.service.poisoned is not None


# --- the rail did not answer ---------------------------------------------


def test_a_psp_timeout_holds_the_key_and_asks_for_a_retry(fragile):
    """No state change until the outcome is known.

    A timeout is not a failure — the outcome is *unknown*, which is a different
    position and the reason recovery polls rather than retries. Releasing the
    key here would let the next attempt debit twice.
    """
    from sim.faults import Fault

    fragile.register()
    fragile.world.faults.arm(Fault.PSP_TIMEOUT, count=None)

    out = fragile.authorize()
    assert out.status == 202
    assert out.body["status"] == "retry_later"

    held = fragile.service.idempotency.get(out.body["idempotency_key"])
    assert held is not None and held.state == "in_flight"

    recorded = [e for e in fragile.service.chain.read() if e.action == "kernel.fail_closed"]
    assert recorded[-1].payload["stage"] == "psp_call"
    # The decision entry went in *before* the rail was called, so the chain
    # holds a recorded allow with no debit behind it — which is the repairable
    # half of the pair, and the whole reason for the ordering.
    allows = [e for e in fragile.service.chain.read() if e.action == "authorize.allow"]
    assert allows and allows[0].payload["decision"] == "allow"
    assert fragile.world.psp.ledger() == []


def test_a_settlement_that_cannot_commit_leaves_nothing_half_written(
    fragile, breaker
):
    """Step 8 is one transaction, so the ledger and the key cannot diverge."""
    fragile.register()
    breaker.break_("ledger", "write")

    out = fragile.authorize()
    assert out.status == 503
    assert out.body["psp_called"] is True

    row = fragile.service.ledger.get(fragile.intent["mandate_id"])
    held = fragile.service.idempotency.get(out.body["idempotency_key"])
    assert row.committed_paise == 0
    assert row.execution_count == 0
    assert held.state == "in_flight"


# --- the concession, stated ----------------------------------------------


def test_kernel_down_is_a_utility_loss_and_never_a_money_loss(fragile, breaker):
    """Denial of service is conceded. Money movement is not."""
    fragile.register()
    breaker.break_("ledger")
    breaker.break_("audit")
    breaker.break_("idempotency")
    breaker.break_("nonces")

    for action in (ActionType.AUTHORIZE, ActionType.CAPTURE, ActionType.REFUND):
        out = getattr(fragile.service, str(action).replace(".", "_"))(
            fragile.request(action)
        )
        assert out.status == 503

    assert fragile.world.psp.ledger() == []
