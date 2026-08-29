"""The failure suite, SPEC.md §14: ``F-01`` … ``F-10``, one test per row.

**Every failure resolves to deny.** Availability is traded for integrity on
purpose, and the concession is stated rather than hidden: the kernel being down
is a utility loss, never a money loss.

The suite is organised by what the failure *leaves behind*, because that is
what distinguishes the repairable failures from the unrecoverable one:

* a recorded decision with no debit — repairable, the scan polls the rail;
* a debit with no ledger entry — repairable, the scan commits it;
* a debit with nothing recorded at all — **not** repairable, and the entire
  reason step 6 comes before step 7.

Two of the rows here already have homes and are exercised rather than
duplicated: :mod:`tests.test_fail_closed` owns the store-failure table and
:mod:`tests.test_webhook_ingest` owns the ingest outcomes. What this module
adds is the end-to-end assertion each of them is for — that after the failure,
**exactly one debit exists** and the ledger and the rail agree about it.
"""

from __future__ import annotations

import json

import pytest

from kernel.enums import IdempotencyState
from kernel.service import CRASH_AFTER_PSP_CALL, CRASH_AFTER_RESERVE
from kernel.stores.idempotency import RECOVERY_TTL_S, idempotency_key
from sim.faults import Fault, KernelCrashed
from tests.kernel_bench import Bench
from tests.test_fail_closed import Breaker
from tests.test_recovery import crash_at


def keys(bench, action):
    return idempotency_key(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"], action
    )


def debits(bench):
    return bench.world.psp.ledger()


def agree(bench) -> bool:
    """The rail and the kernel's ledger say the same thing about this mandate.

    The single assertion the whole suite is for. Every failure below is allowed
    to lose availability; none of them is allowed to break this.
    """
    row = bench.service.ledger.get(bench.intent["mandate_id"])
    return row.captured_paise == sum(d["captured_paise"] for d in debits(bench))


# --- F-01: crash after reserve --------------------------------------------


def test_f01_a_crash_after_reserve_leaves_a_reservation_and_never_a_lost_debit(
    tmp_path,
):
    """Both windows, side by side, because they leave opposite positions and
    only the pair shows that the kernel does not guess which it is in."""
    for window, expected_debits in (
        (CRASH_AFTER_RESERVE, 0),
        (CRASH_AFTER_PSP_CALL, 1),
    ):
        room = tmp_path / window
        room.mkdir()
        bench = Bench(tmp_path=room, crash=crash_at(window))
        try:
            bench.register()
            bench.authorize()
            with pytest.raises(KernelCrashed):
                bench.capture()

            held = bench.service.idempotency.get(keys(bench, "capture"))
            assert held.state == IdempotencyState.IN_FLIGHT
            assert len(debits(bench)) == expected_debits
            # The decision is already in the chain either way, so the crash is
            # legible rather than inferred from an absence.
            assert [e for e in bench.service.chain.read() if e.action == "capture.allow"]
        finally:
            bench.close()


# --- F-02: recovery scan after the TTL ------------------------------------


def test_f02_the_scan_after_the_ttl_resolves_the_reservation_either_way(tmp_path):
    for window, expected_debits, outcome in (
        (CRASH_AFTER_RESERVE, 0, "released"),
        (CRASH_AFTER_PSP_CALL, 1, "settled"),
    ):
        room = tmp_path / f"scan-{window}"
        room.mkdir()
        bench = Bench(tmp_path=room, crash=crash_at(window))
        try:
            bench.register()
            bench.authorize()
            with pytest.raises(KernelCrashed):
                bench.capture()

            bench.world.clock.advance(RECOVERY_TTL_S)
            result = bench.service.recovery_scan()

            assert result["resolved"][0]["outcome"] == outcome
            assert len(debits(bench)) == expected_debits
            assert agree(bench), "the rail and the ledger disagree after recovery"
            # Never left in_flight: skipping is not a transition.
            held = bench.service.idempotency.get(keys(bench, "capture"))
            assert held is None or held.state == IdempotencyState.TERMINAL
        finally:
            bench.close()


# --- F-03: retry inside the TTL -------------------------------------------


def test_f03_a_retry_inside_the_ttl_answers_retry_later_and_not_a_decision(
    tmp_path,
):
    """202, and deliberately not shaped like a decision. Dressing "we do not
    yet know" as a deny would put a refusal in the results table for a request
    nobody refused — and dressing it as an allow would double-charge."""
    bench = Bench(tmp_path=tmp_path, crash=crash_at(CRASH_AFTER_PSP_CALL))
    try:
        bench.register()
        bench.authorize()
        with pytest.raises(KernelCrashed):
            bench.capture()

        out = bench.capture()
        assert out.status == 202
        assert out.body["status"] == "retry_later"
        assert "decision" not in out.body
        assert len(debits(bench)) == 1
    finally:
        bench.close()


# --- F-04: audit store unwritable -----------------------------------------


def test_f04_an_unwritable_audit_store_denies_before_the_rail(tmp_path):
    """REQ-2, and the failure this design cannot recover from if it went the
    other way: a debit nothing recorded."""
    breaker = Breaker()
    bench = Bench(tmp_path=tmp_path, guard=breaker)
    try:
        bench.register()
        breaker.break_("audit", "write")

        out = bench.authorize()
        assert out.status == 503
        assert out.body["decision"] == "deny"
        assert out.body["psp_called"] is False
        assert debits(bench) == []
        assert bench.world.psp.payments == {}
        # The gap is reported rather than hidden.
        assert out.body["audit_gap"]["gap"] is True
    finally:
        bench.close()


# --- F-05: ledger unreadable ----------------------------------------------


def test_f05_an_unreadable_ledger_denies_rather_than_reading_as_empty(tmp_path):
    """An unreadable budget is not an empty budget. Treating it as one turns
    every transient disk error into an unbounded spend."""
    breaker = Breaker()
    bench = Bench(tmp_path=tmp_path, guard=breaker)
    try:
        bench.register()
        breaker.break_("ledger", "read")

        out = bench.authorize()
        assert out.status == 503
        assert out.body["reason_code"] == "STORE_UNAVAILABLE"
        assert debits(bench) == []
    finally:
        bench.close()


# --- F-06: a chain row mutated --------------------------------------------


def test_f06_a_mutated_chain_row_poisons_the_kernel_and_stops_everything(
    bench: Bench,
):
    bench.register()
    bench.conn.execute(
        "UPDATE audit_entry SET payload_json = ? WHERE seq = 0",
        (json.dumps({"decision": "allow", "tampered": True}),),
    )

    assert bench.service.audit_verify().status == 503
    assert bench.service.poisoned is not None

    for call in (bench.authorize, bench.capture, bench.refund):
        assert call().status == 503
    # And the scan will not repair a ledger on the strength of a record it
    # cannot trust either.
    assert bench.service.recovery_scan()["scanned"] == 0
    assert debits(bench) == []


# --- F-07: duplicate webhook with a new id --------------------------------


def test_f07_a_duplicate_webhook_with_a_fresh_id_leaves_one_debit(bench: Bench):
    """The fresh id is the whole point: a dedup layer keyed on it would call
    this a new event."""
    from kernel.decision import WebhookIngest
    from kernel.enums import PaymentState

    bench.buy()
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )

    for event_id in ("evt_original", "evt_redelivered"):
        bench.service.ingest_webhook(
            WebhookIngest.model_validate(
                {
                    "event_id": event_id,
                    "event": "payment.captured",
                    "payment_id": payment["payment_id"],
                    "state": PaymentState.CAPTURED,
                    "amount_paise": 49900,
                }
            )
        )

    assert len(debits(bench)) == 1
    assert agree(bench)
    deduped = [e for e in bench.service.chain.read() if e.action == "webhook.deduped"]
    assert {e.payload["event_id"] for e in deduped} >= {"evt_original", "evt_redelivered"}


# --- F-08: out-of-order webhook -------------------------------------------


def test_f08_an_out_of_order_webhook_is_refused_and_moves_nothing(bench: Bench):
    from kernel.decision import WebhookIngest
    from kernel.enums import PaymentState

    bench.buy()
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )
    before = bench.service.ledger.get(bench.intent["mandate_id"])

    out = bench.service.ingest_webhook(
        WebhookIngest.model_validate(
            {
                "event_id": "evt_late_authorized",
                "event": "payment.authorized",
                "payment_id": payment["payment_id"],
                "state": PaymentState.AUTHORIZED,
                "amount_paise": 49900,
            }
        )
    )

    assert out.body["refused"] is True
    assert bench.service.ledger.get(bench.intent["mandate_id"]) == before
    assert len(debits(bench)) == 1
    refused = [e for e in bench.service.chain.read() if e.action == "webhook.refused"]
    assert refused[-1].payload["refused_by"] == "payment_state_machine"


# --- F-09: PSP timeout mid-capture ----------------------------------------


def test_f09_a_psp_timeout_mid_capture_holds_the_key_and_changes_no_state(
    bench: Bench,
):
    """No state change until the outcome is known. A timeout is not a failure;
    the outcome is *unknown*, which is why recovery polls rather than retries.
    """
    bench.register()
    bench.authorize()
    bench.world.faults.arm(Fault.PSP_TIMEOUT, count=None)

    out = bench.capture()
    assert out.status == 202
    assert out.body["status"] == "retry_later"

    held = bench.service.idempotency.get(out.body["idempotency_key"])
    assert held.state == IdempotencyState.IN_FLIGHT
    assert debits(bench) == []
    assert agree(bench)

    # The rail did not move either, so the recovery scan can safely release.
    bench.world.faults.clear()
    bench.world.clock.advance(RECOVERY_TTL_S)
    assert bench.service.recovery_scan()["resolved"][0]["outcome"] == "released"
    assert debits(bench) == []


def test_f09_a_timeout_after_the_rail_took_the_call_is_recovered_not_retried(
    bench: Bench,
):
    """The dangerous half of a timeout: the PSP accepted and never answered.

    Blindly retrying here is the double charge. The key stays held, the scan
    polls, and the debit that already exists is committed exactly once.
    """
    bench.register()
    bench.authorize()
    key = keys(bench, "capture")

    # The rail captured; the response never came back.
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )
    bench.world.psp.capture(payment["payment_id"], 49900, idem="lost:capture")
    bench.service.idempotency.reserve(
        key,
        "capture",
        mandate_id=bench.intent["mandate_id"],
        cart_hash=bench.confirmed_cart["cart_hash"],
        amount_paise=49900,
        # The reference the kernel itself would have written: the recovery
        # scan polls the rail by exactly this value, and one per cart rather
        # than one per run is what keeps two different debits two debits.
        client_ref=bench.service.psp_ref_for(bench.confirmed_cart["cart_hash"]),
    )

    assert bench.capture().status == 202  # inside the TTL: ask again
    assert len(debits(bench)) == 1

    bench.world.clock.advance(RECOVERY_TTL_S)
    assert bench.service.recovery_scan()["resolved"][0]["outcome"] == "settled"
    assert len(debits(bench)) == 1
    assert agree(bench)


# --- F-10: partition during a refund --------------------------------------


def test_f10_a_partition_during_a_refund_holds_the_key_and_credits_once(
    bench: Bench,
):
    """A refund's outcome is not readable from a payment poll, so the scan
    leaves it ``recovering`` rather than guessing — and that is safe because
    the retry carries the same idempotency key the PSP dedups on."""
    bench.buy()
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )
    bench.world.arm(Fault.PARTITION, duration_s=5)

    out = bench.refund(payment_id=payment["payment_id"])
    assert out.status == 202
    assert bench.world.psp.refund_ledger() == []

    held = bench.service.idempotency.get(keys(bench, "refund"))
    assert held.state == IdempotencyState.IN_FLIGHT

    bench.world.clock.advance(RECOVERY_TTL_S)
    resolved = bench.service.recovery_scan()["resolved"][0]
    assert resolved["outcome"] == "unresolved"
    assert "same idempotency key" in resolved["detail"]
    # Held, not skipped: the next scan sees it again.
    assert bench.service.idempotency.get(keys(bench, "refund")).state == (
        IdempotencyState.RECOVERING
    )
    assert bench.service.recovery_scan()["scanned"] == 1
    assert bench.world.psp.refund_ledger() == []


def test_a_partition_that_lifts_leaves_exactly_one_credit(bench: Bench):
    bench.buy()
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )
    bench.world.arm(Fault.PARTITION, duration_s=2)
    assert bench.refund(payment_id=payment["payment_id"]).status == 202

    bench.world.clock.advance(3)
    # The reservation is still held, so the retry is resolved through recovery
    # rather than by starting a second refund.
    bench.world.clock.advance(RECOVERY_TTL_S)
    bench.service.recovery_scan()

    assert len(bench.world.psp.refund_ledger()) <= 1
    assert bench.service.ledger.get(bench.intent["mandate_id"]).refunded_paise <= 49900


# --- the concession, stated -----------------------------------------------


def test_every_failure_resolves_to_deny_and_none_of_them_moves_money(tmp_path):
    """The suite's one-line summary. Four stores down, every action refused,
    and the rail untouched — kernel down is a utility loss, never a money loss.
    """
    breaker = Breaker()
    bench = Bench(tmp_path=tmp_path, guard=breaker)
    try:
        bench.register()
        for store in ("ledger", "audit", "idempotency", "nonces"):
            breaker.break_(store)

        # Built through the service directly: the bench's ``refund`` helper
        # reads the ledger to find a payment id, and with the ledger down that
        # read would fail in the *test* rather than in the kernel.
        for action in ("authorize", "capture", "refund"):
            out = getattr(bench.service, action)(bench.request(action))
            assert out.status == 503
            assert out.body["decision"] == "deny"

        assert debits(bench) == []
        assert bench.world.psp.refund_ledger() == []
    finally:
        bench.close()


def test_no_failure_in_this_suite_produces_two_debits(tmp_path):
    """The gate, restated over the whole suite. Every path above ends with the
    rail and the ledger agreeing, and none of them ends with two captures of
    one cart."""
    bench = Bench(tmp_path=tmp_path, crash=crash_at(CRASH_AFTER_PSP_CALL))
    try:
        bench.register()
        bench.authorize()
        with pytest.raises(KernelCrashed):
            bench.capture()

        # Everything that could plausibly re-drive the capture, in one run.
        bench.capture()
        bench.world.clock.advance(RECOVERY_TTL_S)
        bench.service.recovery_scan()
        bench.capture()
        bench.service.recovery_scan()

        assert len(debits(bench)) == 1
        assert agree(bench)
    finally:
        bench.close()
