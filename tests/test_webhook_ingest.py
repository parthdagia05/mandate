"""Webhook ingest: dedup, out-of-order refusal, and the ledger reconciled.

Three outcomes and three names, because they are three different things:

``ingested``   the claim is news, and the ledger is brought into line with it;
``deduped``    the claim is what the kernel already holds;
``refused``    the claim is *earlier* than what the kernel holds.

**Dedup is at the business level, not on the event id.** A PSP redelivering
with a fresh id is ordinary at-least-once behaviour, so the duplicate that
matters arrives with an id nothing has ever seen. A dedup layer keyed on the id
answers "have I seen this event?" when the question is "have I already acted on
this outcome?", and it answers it wrongly on exactly the delivery it exists to
catch.

**Refusal happens at the payment state machine.** Dedup cannot do it: a
backwards claim with a fresh id is, to a dedup layer, a new event. The state
machine answers "can that have happened next?", which no event id can lie
about, and folding a refusal into the dedup count would make F-08 invisible.
"""

from __future__ import annotations

import pytest

from kernel.decision import WebhookIngest
from kernel.enums import PaymentState
from tests.kernel_bench import Bench


def ingest(bench, payment_id, state, *, event_id="evt_0001", amount=49900):
    return bench.service.ingest_webhook(
        WebhookIngest.model_validate(
            {
                "event_id": event_id,
                "event": "payment.state",
                "payment_id": payment_id,
                "state": state,
                "amount_paise": amount,
            }
        )
    )


def entries(bench, action):
    return [e for e in bench.service.chain.read() if e.action == action]


@pytest.fixture
def authorized(bench: Bench):
    """A mandate with one authorized, not yet captured, payment."""
    bench.register()
    bench.authorize()
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )
    return bench, payment["payment_id"]


# --- news -----------------------------------------------------------------


def test_a_forward_claim_is_ingested_and_moves_the_payment(authorized):
    bench, payment_id = authorized
    out = ingest(bench, payment_id, PaymentState.CAPTURED)

    assert out.status == 200
    assert out.body["ingested"] is True
    assert bench.service.ledger.get_payment(payment_id)["state"] == "captured"


def test_the_ledger_is_reconciled_on_ingest(authorized):
    """The case this exists for: a capture the kernel never got to record.

    Here the webhook is the first thing that tells the ledger a debit happened,
    and booking it is what keeps the kernel's captured total equal to the
    rail's.
    """
    bench, payment_id = authorized
    assert bench.service.ledger.get(bench.intent["mandate_id"]).captured_paise == 0

    ingest(bench, payment_id, PaymentState.CAPTURED)

    row = bench.service.ledger.get(bench.intent["mandate_id"])
    assert row.captured_paise == 49900
    assert row.ledger_state == "captured"
    entry = entries(bench, "webhook.ingested")[-1]
    assert entry.payload["ledger_reconciled"]["applied"] is True
    assert entry.payload["ledger"]["captured_paise"] == 49900


def test_a_capture_the_kernel_already_booked_is_not_booked_again(bench: Bench):
    """P-06. The captured total is a function of the payment's state, not of
    how many callbacks arrived."""
    bench.buy()
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )

    ingest(bench, payment["payment_id"], PaymentState.CAPTURED, event_id="evt_a")
    ingest(bench, payment["payment_id"], PaymentState.CAPTURED, event_id="evt_b")

    assert bench.service.ledger.get(bench.intent["mandate_id"]).captured_paise == 49900


# --- dedup ----------------------------------------------------------------


def test_a_redelivery_with_a_fresh_event_id_is_deduped_not_ingested(authorized):
    """The whole point of the fresh id: dedup cannot be built on it."""
    bench, payment_id = authorized
    first = ingest(bench, payment_id, PaymentState.CAPTURED, event_id="evt_first")
    second = ingest(bench, payment_id, PaymentState.CAPTURED, event_id="evt_second")

    assert first.body["ingested"] is True
    assert second.body["ingested"] is False
    assert second.body["deduped"] is True

    deduped = entries(bench, "webhook.deduped")[-1]
    assert deduped.payload["event_id"] == "evt_second"
    assert deduped.payload["event_id"] != entries(bench, "webhook.ingested")[-1].payload[
        "event_id"
    ]


def test_dedup_is_keyed_on_the_kernels_own_payment_row(authorized):
    """Reached through ``(mandate_id, cart_hash)`` — the business key — and the
    chain records both, so a reader can see what the dedup was actually on."""
    bench, payment_id = authorized
    ingest(bench, payment_id, PaymentState.AUTHORIZED, event_id="evt_dup")

    entry = entries(bench, "webhook.deduped")[-1]
    assert entry.payload["mandate_id"] == bench.intent["mandate_id"]
    assert entry.payload["cart_hash"] == bench.confirmed_cart["cart_hash"]


# --- out of order ---------------------------------------------------------


def test_authorized_after_captured_is_refused_at_the_state_machine(bench: Bench):
    """F-08. Refused, not absorbed — and named as a refusal in the chain."""
    bench.buy()
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )

    out = ingest(bench, payment["payment_id"], PaymentState.AUTHORIZED, event_id="evt_late")

    assert out.body["refused"] is True
    assert out.body["ingested"] is False
    assert out.body["deduped"] is False

    entry = entries(bench, "webhook.refused")[-1]
    assert entry.payload["current_state"] == "captured"
    assert entry.payload["claimed_state"] == "authorized"
    assert entry.payload["refused_by"] == "payment_state_machine"


def test_a_refused_claim_never_moves_the_payment_backwards(bench: Bench):
    bench.buy()
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )
    before = bench.service.ledger.get(bench.intent["mandate_id"])

    ingest(bench, payment["payment_id"], PaymentState.CREATED, event_id="evt_older")

    assert bench.service.ledger.get_payment(payment["payment_id"])["state"] == "captured"
    assert bench.service.ledger.get(bench.intent["mandate_id"]) == before


def test_a_refusal_is_not_counted_as_a_dedup(bench: Bench):
    """Two names, because collapsing them would leave F-08 with no signature
    in the chain at all."""
    bench.buy()
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )
    before = len(entries(bench, "webhook.deduped"))

    ingest(bench, payment["payment_id"], PaymentState.AUTHORIZED, event_id="evt_x")

    assert len(entries(bench, "webhook.deduped")) == before
    assert entries(bench, "webhook.refused")


# --- the edges ------------------------------------------------------------


def test_a_callback_about_an_unknown_payment_invents_nothing(bench: Bench):
    """The kernel is told about payments it did not open. It declines to
    create a row for one rather than treating the callback as authority."""
    bench.register()
    out = ingest(bench, "pay_01ZZZZZZZZZZZZZZZZZZZZZZZZ", PaymentState.CAPTURED)

    assert out.status == 200
    assert out.body["ingested"] is False
    assert out.body["reason"] == "no payment with that id"
    assert bench.service.ledger.get(bench.intent["mandate_id"]).captured_paise == 0


def test_a_store_failure_during_ingest_denies_rather_than_half_writing(
    tmp_path,
):
    from tests.test_fail_closed import Breaker

    breaker = Breaker()
    bench = Bench(tmp_path=tmp_path, guard=breaker)
    try:
        bench.register()
        bench.authorize()
        payment = bench.service.ledger.payment_for_cart(
            bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
        )
        breaker.break_("ledger", "read")

        out = ingest(bench, payment["payment_id"], PaymentState.CAPTURED)
        assert out.status == 503
        assert out.body["error"] == "store unavailable"
    finally:
        bench.close()


def test_a_poisoned_kernel_ingests_nothing(bench: Bench):
    bench.buy()
    bench.service.poison("BROKEN at seq 2")

    out = ingest(bench, "pay_01ZZZZZZZZZZZZZZZZZZZZZZZZ", PaymentState.CAPTURED)
    assert out.status == 503
    assert out.body["error"] == "kernel poisoned"
