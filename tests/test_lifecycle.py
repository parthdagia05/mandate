"""The request lifecycle, and the two orderings the whole guarantee rests on.

SPEC.md §08 step 6 before step 7, and step 8 as one transaction. Both are
tested by their consequences rather than by reading the code, because the code
can be reordered and a comment cannot notice.

**Append then call.** A crash after the append leaves a recorded decision with
no debit, which recovery can resolve against the PSP. A crash after the call
and before the append leaves a debit nothing recorded, which nothing can
resolve. One of those is repairable; the ordering is what chooses which one
this system can suffer.

**Checks 6 and 7 are not redundant**, and the tests here say why in the only
way that counts: 7 collapses *the same* action repeated into one debit, and 6
refuses a *different* action beyond the signed count. A system with only
idempotency double-charges nothing and spends forever; a system with only a
budget double-charges on every network retry.
"""

from __future__ import annotations

import pytest

from kernel.enums import ActionType
from kernel.service import CRASH_AFTER_RESERVE
from kernel.stores.idempotency import RECOVERY_TTL_S, idempotency_key
from sim.faults import Fault, KernelCrashed
from tests.kernel_bench import Bench


def entries(bench, action=None):
    return [
        e for e in bench.service.chain.read() if action is None or e.action == action
    ]


# --- ordering -------------------------------------------------------------


def test_the_decision_is_recorded_before_the_rail_is_called(bench: Bench):
    bench.register()
    bench.authorize()

    allow = entries(bench, "authorize.allow")
    assert len(allow) == 2, "a pre-call decision leg and a settle leg"

    decision, settle = allow
    assert decision.seq < settle.seq
    # The pre-call entry cannot name a payment id, because at the moment it was
    # written there was no payment. That is the ordering, stated as evidence.
    assert "payment_id" not in decision.payload
    assert decision.payload["decision"] == "allow"
    assert settle.payload["leg"] == "settle"
    assert settle.payload["payment_id"].startswith("pay_")


def test_a_crash_between_reserve_and_call_leaves_a_reservation_and_no_debit(tmp_path):
    """The repairable half of the pair, in the first of the two crash windows."""
    fired = {"once": False}

    def crash(site, action):
        if site == CRASH_AFTER_RESERVE and not fired["once"]:
            fired["once"] = True
            raise KernelCrashed(Fault.CRASH_AFTER_RESERVE.value)  # type: ignore[arg-type]

    bench = Bench(tmp_path=tmp_path, crash=crash)
    try:
        bench.register()
        with pytest.raises(KernelCrashed):
            bench.authorize()

        key = idempotency_key(
            bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"], "authorize"
        )
        held = bench.service.idempotency.get(key)
        assert held is not None and held.state == "in_flight"
        assert bench.world.psp.ledger() == []
        # And the decision is already in the chain, so the crash is legible.
        assert entries(bench, "authorize.allow")
    finally:
        bench.close()


def test_the_settle_leg_and_the_ledger_move_together(bench: Bench):
    bench.buy()
    row = bench.service.ledger.get(bench.intent["mandate_id"])
    key = idempotency_key(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"], "capture"
    )
    record = bench.service.idempotency.get(key)

    assert row.captured_paise == 49900
    assert record.state == "terminal"
    assert record.result_json is not None


# --- check 7: the same action, repeated ----------------------------------


def test_a_repeated_capture_replays_the_prior_result_and_debits_once(bench: Bench):
    bench.register()
    bench.authorize()
    first = bench.capture()
    second = bench.capture()

    assert first.status == 200 and first.body["decision"] == "allow"
    assert second.status == 200
    assert second.body["replayed"] is True
    # Verbatim, not recomputed. A recomputed answer could differ — the ledger
    # has moved underneath it — and the caller could not tell a replay from a
    # second judgement.
    assert second.body["audit"] == first.body["audit"]
    assert second.body["decision"] == first.body["decision"]

    ledger = bench.world.psp.ledger()
    assert len(ledger) == 1
    assert ledger[0]["captured_paise"] == 49900
    assert entries(bench, "capture.replayed")


def test_the_key_is_the_cart_hash_not_the_cart_id(bench: Bench):
    """Two carts with different ids and identical contents are one purchase."""
    bench.register()
    first = bench.agent_cart()
    second = bench.agent_cart()

    assert first["mandate_id"] != second["mandate_id"]
    assert first["cart_hash"] == second["cart_hash"]

    bench.authorize(first)
    replayed = bench.service.authorize(bench.request(ActionType.AUTHORIZE, second))
    assert replayed.body["replayed"] is True
    assert len(bench.world.psp.payments) == 1


def test_a_key_held_inside_the_ttl_answers_202_and_not_a_decision(bench: Bench):
    """202 is "ask again", and it is deliberately not shaped like a decision.

    Dressing "the outcome is unknown" as a deny would put a refusal in the
    results table for a request nobody refused.
    """
    bench.register()
    key = idempotency_key(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"], "authorize"
    )
    bench.service.idempotency.reserve(
        key,
        ActionType.AUTHORIZE,
        mandate_id=bench.intent["mandate_id"],
        cart_hash=bench.confirmed_cart["cart_hash"],
        amount_paise=bench.confirmed_cart["total_amount"],
        client_ref="ref_bench",
    )

    out = bench.authorize()
    assert out.status == 202
    assert out.body["status"] == "retry_later"
    assert "decision" not in out.body
    assert bench.world.psp.ledger() == []


def test_past_the_ttl_the_kernel_polls_the_psp_rather_than_retrying(bench: Bench):
    """Never blindly retried, never silently skipped. Skipping is not a
    transition, so the reservation is resolved rather than ignored."""
    bench.register()
    key = idempotency_key(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"], "authorize"
    )
    bench.service.idempotency.reserve(
        key,
        ActionType.AUTHORIZE,
        mandate_id=bench.intent["mandate_id"],
        cart_hash=bench.confirmed_cart["cart_hash"],
        amount_paise=bench.confirmed_cart["total_amount"],
        client_ref="ref_bench",
    )
    bench.world.clock.advance(RECOVERY_TTL_S + 1)

    out = bench.authorize()
    assert out.status == 202
    assert "the PSP has no record" in out.body["detail"]

    reconciled = entries(bench, "recovery.reconciled")
    assert reconciled and reconciled[-1].payload["polled_by"] == "client_ref"
    assert reconciled[-1].payload["outcome"] == "released"
    assert reconciled[-1].payload["found"] is False
    # The reservation was released because the poll proved nothing happened,
    # so the next attempt is allowed to proceed.
    assert bench.service.idempotency.get(key) is None
    assert bench.authorize().status == 200


# --- check 6 and check 7 are different questions -------------------------


def test_idempotency_does_not_substitute_for_a_budget(bench: Bench):
    """A *different* action is not a replay, and the count still bounds it."""
    bench.register()
    bench.authorize()

    row = bench.service.ledger.get(bench.intent["mandate_id"])
    assert row.execution_count == 1

    # The capture is a different action, so it gets its own key and is not
    # collapsed into the authorize — check 7 says nothing about it at all.
    capture_key = idempotency_key(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"], "capture"
    )
    authorize_key = idempotency_key(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"], "authorize"
    )
    assert capture_key != authorize_key
    assert bench.capture().body["decision"] == "allow"


# --- the ledger's own arithmetic -----------------------------------------


def test_authority_and_money_terminate_independently(bench: Bench):
    bench.buy()
    row = bench.service.ledger.get(bench.intent["mandate_id"])

    assert row.ledger_state == "captured"
    # Two of three transactions still available, so the authority is not spent
    # even though this purchase is complete. One column could not say both.
    assert row.mandate_state == "active"
    assert row.execution_count == 1


def test_the_ledger_refuses_an_impossible_money_position(bench: Bench):
    """``refunded <= captured <= committed`` is a table constraint, not a
    convention — a negative or out-of-order value is a bug, not a state."""
    import sqlite3

    bench.buy()
    with pytest.raises(sqlite3.IntegrityError):
        bench.conn.execute(
            "UPDATE spend_ledger SET refunded_paise = captured_paise + 1"
        )


def test_a_capture_settles_its_own_authorize_and_is_not_charged_twice(
    bench: Bench,
):
    """The tight mandate: ``per_txn_cap == max_amount``, the ordinary shape.

    The authorize commits the whole budget. If the capture were bounded by
    ``max_amount`` as well, the same rupees would be counted twice and the
    user's own purchase would be refused at the last step — a false block on
    the benign path, which is the failure mode this project's utility column
    exists to catch.
    """
    total = bench.confirmed_cart["total_amount"]
    tight = bench.user_signed_intent(
        max_amount=total, per_txn_cap=total, max_transactions=1
    )
    bench.register(intent=tight)

    cart = bench.agent_cart()
    assert bench.service.authorize(
        bench.request("authorize", cart, intent=tight)
    ).body["decision"] == "allow"
    captured = bench.service.capture(bench.request("capture", cart, intent=tight))

    assert captured.body["decision"] == "allow"
    assert bench.world.psp.ledger()[0]["captured_paise"] == total

    # And the mandate is now spent, both ways.
    row = bench.service.ledger.get(tight["mandate_id"])
    assert row.mandate_state == "exhausted"
    assert row.ledger_state == "captured"


def test_a_capture_above_what_was_committed_is_refused(bench: Bench):
    """Money nothing reserved is the thing check 6 refuses at settlement."""
    bench.register()
    bench.authorize()
    bench.conn.execute(
        "UPDATE spend_ledger SET committed_paise = 100, captured_paise = 0"
        " WHERE mandate_id = ?",
        (bench.intent["mandate_id"],),
    )

    out = bench.capture()
    assert out.body["reason_code"] == "BUDGET_EXHAUSTED"
    assert out.body["denied_by"] == [6]
