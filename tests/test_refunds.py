"""Check 8 and the refund flow: where a credit goes, and how much is left.

**The destination is not a field.** :class:`~kernel.models.RequestParams` has
``amount`` and ``original_payment_id`` and nothing else, so a support page that
talks an agent into a refund destination has nowhere on the wire to put it.
Check 8 fills the destination in from ``payment.source_json``. That is the
answer to class A7, and it is structural rather than evaluative — there is no
filter to misconfigure and no predicate to ablate, because there is no input.

**The cap is cumulative and it is two caps.** Per payment, so one debit cannot
be refunded twice out of a mandate with room left over from other purchases;
per mandate, so the ledger cannot be talked past ``refunded <= captured``.
Neither implies the other, and the failure detail says which one bit.

**A refund's key is the purchase's key.** ``H(mandate ‖ cart_hash ‖ refund)``
carries no amount, deliberately: an amount in the key would let a caller mint a
fresh key by varying it by one paisa, which is precisely the thing check 7
exists to prevent. The cost is one refund per cart, and the mandate-level cap
is what covers the multi-purchase case.
"""

from __future__ import annotations

import pytest

from kernel.checks.refund_binding import refund_binding
from kernel.enums import RefundState
from kernel.stores.idempotency import idempotency_key
from tests.kernel_bench import Bench

ATTACKER = {"type": "vpa", "value": "attacker@upi"}
SOURCE = {"type": "vpa", "value": "ananya@upi"}


@pytest.fixture
def purchased(bench: Bench):
    """A settled ₹499 purchase, ready to be refunded."""
    bench.buy()
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )
    return bench, payment


def entries(bench, action):
    return [e for e in bench.service.chain.read() if e.action == action]


def check_8(decision_body):
    return next(c for c in decision_body["checks"] if c["id"] == 8)


# --- U-14: the destination comes from the ledger --------------------------


def test_the_refund_credits_the_payments_recorded_source(purchased):
    bench, payment = purchased
    out = bench.refund(payment_id=payment["payment_id"])

    assert out.status == 200
    assert out.body["decision"] == "allow"
    assert check_8(out.body)["result"] == "pass"
    assert out.body["payment"]["destination"] == payment["source"]
    assert bench.world.psp.refund_ledger()[0]["destination"]["value"] == "ananya@upi"


def test_the_request_has_nowhere_to_name_a_destination(purchased):
    """A7's answer, stated as a property of the schema rather than of a check.

    ``extra="forbid"`` means the field is not ignored, it is *refused* — so an
    agent that tried to supply one would get a 422 rather than a silently
    dropped value that somebody could later decide to honour.
    """
    from pydantic import ValidationError

    from kernel.models import RequestParams

    assert "destination" not in RequestParams.model_fields
    with pytest.raises(ValidationError):
        RequestParams.model_validate({"amount": 100, "destination": ATTACKER})


def test_the_chain_records_which_account_was_chosen_and_from_where(purchased):
    bench, payment = purchased
    bench.refund(payment_id=payment["payment_id"])

    detail = next(
        d
        for d in entries(bench, "refund.allow")[0].payload["check_detail"]
        if d["id"] == 8
    )
    assert detail["destination"] == payment["source"]
    assert detail["destination_from"] == "ledger.payment.source_json"


def test_a_refund_naming_no_payment_is_refused(purchased):
    """``original_payment_id`` is optional on the schema — a capture has no use
    for it — so check 8 is what makes it mandatory for a refund. Without that,
    a refund that named nothing would have no source to read a destination from
    and the kernel would have to invent one."""
    bench, _ = purchased
    out = bench.service.refund(bench.request("refund"))

    assert out.body["decision"] == "deny"
    assert out.body["reason_code"] == "REFUND_DESTINATION_MISMATCH"
    assert out.body["denied_by"] == [8]


def test_a_refund_naming_another_mandates_payment_is_refused(purchased):
    """Checked against the predicate directly: the foreign key makes a
    cross-mandate payment row unconstructible in the store, which is a second
    line of defence and not a reason to leave the first one untested."""
    bench, payment = purchased
    ctx = bench.service._context(
        bench.request("refund", original_payment_id=payment["payment_id"]),
        ledger=bench.service.ledger.get(bench.intent["mandate_id"]),
    )
    borrowed = {**payment, "mandate_id": "im_01OTHEROTHEROTHEROTHEROTH"}

    result = refund_binding(ctx, borrowed)
    assert not result.passed
    assert "different mandate" in result.detail["detail"]


def test_a_refund_naming_a_payment_that_does_not_exist_is_refused(purchased):
    bench, _ = purchased
    out = bench.service.refund(
        bench.request(
            "refund", original_payment_id="pay_01ZZZZZZZZZZZZZZZZZZZZZZZZ"
        )
    )

    assert out.body["decision"] == "deny"
    assert out.body["denied_by"] == [8]
    assert bench.world.psp.refund_ledger() == []


def test_a_payment_that_never_settled_cannot_be_reversed(bench: Bench):
    """Reversing a debit that never happened is a payout wearing a refund's
    name — the same money movement A7 wants, through a different door."""
    bench.register()
    bench.authorize()
    payment = bench.service.ledger.payment_for_cart(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]
    )

    out = bench.refund(payment_id=payment["payment_id"])
    assert out.body["denied_by"] == [8]
    assert bench.world.psp.refund_ledger() == []


# --- U-15: cumulative caps ------------------------------------------------


def test_a_refund_above_what_the_payment_captured_is_refused(purchased):
    bench, payment = purchased
    out = bench.refund(amount=49901, payment_id=payment["payment_id"])

    assert out.body["denied_by"] == [8]
    assert out.body["reason_code"] == "REFUND_DESTINATION_MISMATCH"
    assert bench.world.psp.refund_ledger() == []


def test_the_per_payment_cap_is_cumulative(purchased):
    """Checked directly, because the idempotency key deliberately makes a
    second refund of one cart unreachable through the service — see the module
    docstring. The predicate still has to be right for the multi-payment case.
    """
    bench, payment = purchased
    ctx = bench.service._context(
        bench.request("refund", amount=30000, original_payment_id=payment["payment_id"]),
        ledger=bench.service.ledger.get(bench.intent["mandate_id"]),
    )

    fresh = refund_binding(ctx, payment, already_refunded=0)
    assert fresh.passed and fresh.detail["kind"] == "partial"

    on_top = refund_binding(ctx, payment, already_refunded=30000)
    assert not on_top.passed
    assert on_top.detail["conjunct"] == "payment_cumulative"
    assert on_top.detail["already_refunded_paise"] == 30000


def test_the_mandate_level_cap_stops_a_refund_the_ledger_cannot_fund(purchased):
    """A mandate with three transactions has room under the per-payment cap
    long after it has given back everything it took. Neither cap implies the
    other, so both are here."""
    bench, payment = purchased
    bench.conn.execute(
        "UPDATE spend_ledger SET refunded_paise = captured_paise WHERE mandate_id = ?",
        (bench.intent["mandate_id"],),
    )

    ctx = bench.service._context(
        bench.request("refund", amount=100, original_payment_id=payment["payment_id"]),
        ledger=bench.service.ledger.get(bench.intent["mandate_id"]),
    )
    result = refund_binding(ctx, payment, already_refunded=0)

    assert not result.passed
    assert result.detail["conjunct"] == "mandate_cumulative"


def test_the_ledger_invariant_holds_after_a_full_refund(purchased):
    bench, payment = purchased
    bench.refund(payment_id=payment["payment_id"])

    row = bench.service.ledger.get(bench.intent["mandate_id"])
    assert row.refunded_paise == 49900
    assert row.ledger_state == "fully_refunded"
    # The money came back; the permission did not. One column could not say both.
    assert row.mandate_state == "active"


# --- kinds, and the wait we model rather than resolve ---------------------


def test_a_full_refund_is_marked_full_and_a_partial_one_partial(purchased):
    bench, payment = purchased

    out = bench.refund(amount=20000, payment_id=payment["payment_id"])
    assert check_8(out.body)["result"] == "pass"
    stored = bench.service.ledger.refunds_for_payment(payment["payment_id"])[0]
    assert stored["kind"] == "partial"
    assert stored["amount_paise"] == 20000


def test_a_refund_rests_in_processing_and_the_kernel_records_the_wait(purchased):
    """``processing`` is where UPI's deemed-success position lives: debited,
    credit unconfirmed. We model the wait rather than resolving it."""
    bench, payment = purchased
    bench.refund(payment_id=payment["payment_id"])

    stored = bench.service.ledger.refunds_for_payment(payment["payment_id"])[0]
    assert stored["state"] == str(RefundState.PROCESSING)
    # And the ledger has already moved: the debit is reversed from the payer's
    # side whether or not the credit has landed.
    assert bench.service.ledger.get(bench.intent["mandate_id"]).refunded_paise == 49900


def test_the_refund_row_carries_the_destination_check_8_chose(purchased):
    """Issue 38's requirement, on the ledger rather than only in a PSP call: a
    destination that lived only inside an adapter call is one nobody local can
    be held to."""
    bench, payment = purchased
    bench.refund(payment_id=payment["payment_id"])

    stored = bench.service.ledger.refunds_for_payment(payment["payment_id"])[0]
    assert stored["destination"] == payment["source"]
    assert stored["idempotency_key"] == idempotency_key(
        bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"], "refund"
    )


# --- compensations are retried too ----------------------------------------


def test_a_repeated_refund_replays_and_credits_once(purchased):
    """Same key, same credit. The PSP dedups on the key it was given, so the
    retry cannot become a second credit even if it reached the rail."""
    bench, payment = purchased
    first = bench.refund(payment_id=payment["payment_id"])
    second = bench.refund(payment_id=payment["payment_id"])

    assert first.body["decision"] == "allow"
    assert second.body["replayed"] is True
    assert len(bench.world.psp.refund_ledger()) == 1
    assert bench.service.ledger.get(bench.intent["mandate_id"]).refunded_paise == 49900
    assert entries(bench, "refund.replayed")


def test_the_refund_key_is_not_the_capture_key(purchased):
    """A refund is a different action against the same purchase, so it gets
    its own key. Sharing one would make a refund replay its own capture."""
    bench, _ = purchased
    mandate, cart = bench.intent["mandate_id"], bench.confirmed_cart["cart_hash"]

    assert idempotency_key(mandate, cart, "refund") != idempotency_key(
        mandate, cart, "capture"
    )
