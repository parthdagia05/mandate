"""The six predicates, one at a time, with no store and no kernel.

SPEC.md §14 asks for unit tests that exercise one check with no I/O, and the
:class:`~kernel.checks.base.CheckContext` is shaped to make that possible: every
value a check needs has already been read for it, including the single nonce
lookup, which arrives as a callable a test can supply from a dict.

Each check is tested on **every conjunct separately**. A check with four
conjuncts and one test is a check with three untested conjuncts, and the ones
that go untested are the ones an attacker gets to use.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.credentials import AgentCredentials
from kernel.canonical import cart_hash
from kernel.checks import (
    amount_lattice,
    cart_binding,
    execution_budget,
    mandate_integrity,
    payee_allowlist,
    recurrence_scope,
)
from kernel.checks.base import ON_FAIL, CheckContext
from kernel.enums import ActionType, Decision, MandateState, ReasonCode
from kernel.models import PaymentRequest, SpendLedger

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
USER_PUBKEY = (FIXTURES / "keys" / "user.pub.b64u").read_text().strip()
CREDENTIALS = AgentCredentials()


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


INTENT = _fixture("mandates/intent_benign_01.json")
CONFIRMED_CART = _fixture("mandates/cart_benign_01.json")


def agent_cart(*, rehash: bool = True, **overrides) -> dict:
    """A cart signed with the delegated key the intent names."""
    body = {
        "mandate_id": "cm_01KDVDNA00697893VCSXERE2VQ",
        "parent": INTENT["mandate_id"],
        "payee": dict(CONFIRMED_CART["payee"]),
        "line_items": [dict(i) for i in CONFIRMED_CART["line_items"]],
        "total_amount": CONFIRMED_CART["total_amount"],
        "currency": CONFIRMED_CART["currency"],
        "instrument": dict(CONFIRMED_CART["instrument"]),
        "confirmed_by": "auto_within_intent_scope",
    }
    body.update(overrides)
    if rehash and "cart_hash" not in overrides:
        body["cart_hash"] = cart_hash(
            body["line_items"], body["total_amount"], body["payee"]
        )
    body.setdefault("cart_hash", CONFIRMED_CART["cart_hash"])
    return CREDENTIALS.signed(body)


def ledger_row(**overrides) -> SpendLedger:
    values = {
        "mandate_id": INTENT["mandate_id"],
        "intent_json": "{}",
        "confirmed_cart_hash": CONFIRMED_CART["cart_hash"],
        "execution_count": 0,
        "committed_paise": 0,
        "captured_paise": 0,
        "refunded_paise": 0,
        "mandate_state": MandateState.ACTIVE,
    }
    values.update(overrides)
    return SpendLedger(**values)


#: ``ledger=None`` has to mean "there is no row", which is a case under test.
#: A default of ``None`` would make it unsayable.
_KEEP = object()


def context(
    *,
    cart: dict | None = None,
    intent: dict | None = None,
    action: str = "authorize",
    now: str = "2026-01-01T00:05:00Z",
    ledger: SpendLedger | None | object = _KEEP,
    nonces: dict[str, str] | None = None,
    amount: int | None = None,
    user_pubkey: str | None = USER_PUBKEY,
    registering: bool = False,
) -> CheckContext:
    cart = cart if cart is not None else agent_cart()
    seen = dict(nonces or {})
    request = PaymentRequest.model_validate(
        {
            "action": action,
            "intent": intent or INTENT,
            "cart": cart,
            "params": {"amount": cart["total_amount"] if amount is None else amount},
            # Deliberately a lie in every one of these contexts: the kernel
            # reads its own clock, never this.
            "client_ts": "2020-01-01T00:00:00Z",
        }
    )
    return CheckContext(
        request=request,
        user_pubkey=user_pubkey,
        ledger=ledger_row() if ledger is _KEEP else ledger,
        now=now,
        nonce_owner=seen.get,
        registering=registering,
    )


# --- check 1 --------------------------------------------------------------


def test_check1_passes_on_a_well_formed_request():
    result = mandate_integrity(context())
    assert result.passed
    assert result.detail["verified_against"] == "intent.agent.pubkey"


def test_check1_verifies_a_user_confirmed_cart_against_the_user_key():
    result = mandate_integrity(context(cart=CONFIRMED_CART))
    assert result.passed
    assert result.detail["verified_against"] == "principal"


def test_check1_rejects_a_tampered_intent():
    forged = {**INTENT, "scope": {**INTENT["scope"], "max_amount": 10_000_000}}
    result = mandate_integrity(context(intent=forged))
    assert not result.passed
    assert result.reason_code == ReasonCode.SIG_INVALID
    assert result.detail["over"] == "intent"


def test_check1_rejects_a_cart_the_delegated_key_did_not_sign():
    unsigned = agent_cart()
    tampered = {**unsigned, "total_amount": 1}
    result = mandate_integrity(context(cart=tampered))
    assert not result.passed
    assert result.reason_code == ReasonCode.SIG_INVALID
    assert result.detail["over"] == "cart"


def test_check1_rejects_an_agent_signature_on_a_user_confirmed_cart():
    """``confirmed_by`` selects the key, so it cannot also be a free choice.

    An agent that could mark its own cart ``confirmed_by: user`` would be
    claiming a ceremony happened. The claim is checked against the user's key
    and fails.
    """
    forged = agent_cart(confirmed_by="user")
    result = mandate_integrity(context(cart=forged))
    assert not result.passed
    assert result.detail["verified_against"] == "principal"


def test_check1_rejects_a_cart_pointing_at_a_different_intent():
    other = agent_cart(parent="im_01KDVDNA00E2H3VDJMCGYW7QCK")
    result = mandate_integrity(context(cart=other))
    assert not result.passed
    assert result.detail["conjunct"] == "binding"


def test_check1_reads_expiry_from_the_kernel_clock_not_the_request():
    """``client_ts`` in every context above says 2020. It is never consulted."""
    fine = mandate_integrity(context(now="2026-01-01T00:14:59Z"))
    late = mandate_integrity(context(now="2026-01-01T00:15:00Z"))

    assert fine.passed
    assert not late.passed
    assert late.reason_code == ReasonCode.MANDATE_EXPIRED
    assert late.detail["client_ts"] == "2020-01-01T00:00:00Z"


def test_check1_rejects_a_mandate_presented_before_it_was_issued():
    result = mandate_integrity(context(now="2025-12-31T23:59:59Z"))
    assert not result.passed
    assert result.reason_code == ReasonCode.MANDATE_EXPIRED


def test_check1_nonce_is_single_use_when_minting_authority():
    seen = {INTENT["nonce"]: INTENT["mandate_id"]}
    again = mandate_integrity(context(nonces=seen, registering=True))
    assert not again.passed
    assert again.reason_code == ReasonCode.NONCE_REPLAYED


def test_check1_later_calls_refuse_a_nonce_bound_to_another_mandate():
    ours = mandate_integrity(context(nonces={INTENT["nonce"]: INTENT["mandate_id"]}))
    theirs = mandate_integrity(context(nonces={INTENT["nonce"]: "im_someone_else"}))
    unseen = mandate_integrity(context(nonces={}))

    assert ours.passed
    assert not theirs.passed and theirs.reason_code == ReasonCode.NONCE_REPLAYED
    # An unseen nonce on a later call means the intent was never registered,
    # which checks 4 and 6 refuse with reason codes that say so. Calling it a
    # replay here would put the wrong word in the results table.
    assert unseen.passed


def test_check1_refuses_an_unregistered_principal():
    result = mandate_integrity(context(user_pubkey=None))
    assert not result.passed
    assert result.reason_code == ReasonCode.SIG_INVALID


# --- check 2 --------------------------------------------------------------


def test_check2_passes_the_allowlisted_payee():
    assert payee_allowlist(context()).passed


def test_check2_refuses_an_address_the_intent_never_named():
    payee = {**CONFIRMED_CART["payee"], "value": "attacker@upi"}
    result = payee_allowlist(context(cart=agent_cart(payee=payee)))

    assert not result.passed
    assert result.reason_code == ReasonCode.PAYEE_NOT_ALLOWED
    assert result.detail["requested_payee"]["value"] == "attacker@upi"
    assert result.detail["allowed_payees"] == [{"type": "vpa", "value": "merchant@upi"}]


def test_check2_escalates_rather_than_denying():
    """A payee the intent does not name may be legitimate; *this* authority
    paying it is not. A human can mint new authority; nothing widens the old."""
    assert ON_FAIL[2] is Decision.ESCALATE


@pytest.mark.parametrize(
    "value",
    [
        "notmerchant@upi",          # substring: contains the allowed address
        "merchant@upi.attacker.in", # prefix: starts with it
        "merchant@up",              # one character off
        "merchant.settlements@upi", # a dot is not a fold
        "merchant+tag@upi",         # a plus-tag is not a fold
    ],
)
def test_check2_has_no_tolerance_of_any_kind(value):
    payee = {**CONFIRMED_CART["payee"], "value": value}
    assert not payee_allowlist(context(cart=agent_cart(payee=payee))).passed


def test_a_homoglyph_payee_never_reaches_check_2_at_all():
    """Two layers, and the outer one is the schema.

    ``Token`` is ASCII-only, so a Cyrillic lookalike is a 422 before any check
    runs. The normaliser refuses it independently, because a defence that
    exists only in the parser is a defence that moves when the parser does.
    """
    import pydantic

    from kernel.vpa import normalise_account

    payee = {**CONFIRMED_CART["payee"], "value": "merchan\u0442@upi"}
    with pytest.raises(pydantic.ValidationError):
        agent_cart(payee=payee)
        context(cart=agent_cart(payee=payee))

    assert normalise_account("vpa", "merchan\u0442@upi") is None


def test_check2_forgives_ascii_case_because_upi_does():
    payee = {**CONFIRMED_CART["payee"], "value": "Merchant@UPI"}
    assert payee_allowlist(context(cart=agent_cart(payee=payee))).passed


def test_check2_ignores_merchant_id_when_comparing():
    """A shop name an attacker can claim must not affect the comparison."""
    payee = {**CONFIRMED_CART["payee"], "merchant_id": "definitely-shopkart"}
    assert payee_allowlist(context(cart=agent_cart(payee=payee))).passed


# --- check 3 --------------------------------------------------------------


def test_check3_passes_a_cart_inside_every_ceiling():
    assert amount_lattice(context()).passed


def test_check3_ceiling_stops_gross_inflation():
    cart = agent_cart(
        line_items=[{"sku": "SK-MOUSE-01", "qty": 1, "unit_amount": 70000}],
        total_amount=70000,
    )
    result = amount_lattice(context(cart=cart))
    assert result.reason_code == ReasonCode.AMOUNT_EXCEEDS_SCOPE
    assert result.detail["conjunct"] == "per_txn_cap"


def test_check3_sum_equality_stops_sub_ceiling_skimming():
    """Under every cap, and still wrong."""
    cart = agent_cart(total_amount=CONFIRMED_CART["total_amount"] + 100)
    result = amount_lattice(context(cart=cart))
    assert result.reason_code == ReasonCode.LINE_ITEM_SUM_MISMATCH
    assert result.detail["difference"] == 100


def test_check3_currency_is_part_of_an_amount():
    result = amount_lattice(context(cart=agent_cart(currency="JPY")))
    assert result.reason_code == ReasonCode.CURRENCY_MISMATCH


def test_check3_anchors_the_action_amount_to_the_cart():
    """Two separately movable fields, tied together."""
    result = amount_lattice(context(amount=1))
    assert result.reason_code == ReasonCode.AMOUNT_EXCEEDS_SCOPE
    assert result.detail["conjunct"] == "action_amount"


# --- check 4 --------------------------------------------------------------


def test_check4_passes_the_confirmed_cart():
    assert cart_binding(context()).passed


def test_check4_internal_conjunct_catches_a_tampered_hash_field():
    cart = agent_cart(
        rehash=False,
        line_items=[{"sku": "SK-MOUSE-01", "qty": 9, "unit_amount": 44900}],
    )
    result = cart_binding(context(cart=cart))
    assert result.reason_code == ReasonCode.CART_HASH_MISMATCH
    assert result.detail["conjunct"] == "internal"


def test_check4_external_conjunct_catches_a_valid_cart_nobody_approved():
    cart = agent_cart(
        line_items=[{"sku": "SK-MOUSE-01", "qty": 1, "unit_amount": 44900}],
        total_amount=44900,
    )
    result = cart_binding(context(cart=cart))
    assert result.reason_code == ReasonCode.CART_HASH_MISMATCH
    assert result.detail["conjunct"] == "external"


def test_check4_refuses_when_there_is_no_ledger_row():
    """Absence of a confirmation is not a confirmation."""
    assert not cart_binding(context(ledger=None)).passed


# --- check 5 --------------------------------------------------------------


def test_check5_refuses_a_recurring_mandate_against_a_one_shot_intent():
    result = recurrence_scope(context(action="mandate.create"))
    assert result.reason_code == ReasonCode.RECURRENCE_NOT_AUTHORISED


def test_check5_allows_it_when_the_intent_says_recurring():
    from kernel.crypto import b64u_encode

    recurring = {**INTENT, "scope": {**INTENT["scope"], "recurring": True}}
    # The signature no longer covers this scope; check 1 is what notices that,
    # and check 5 is a separate predicate over a separate question.
    recurring["sig"] = b64u_encode(b"\x00" * 64)
    assert recurrence_scope(
        context(intent=recurring, action="mandate.create")
    ).passed


def test_check5_passes_vacuously_elsewhere_and_says_so():
    result = recurrence_scope(context(action="authorize"))
    assert result.passed
    assert result.detail["applicable"] is False


# --- check 6 --------------------------------------------------------------


def test_check6_passes_with_budget_left():
    assert execution_budget(context()).passed


def test_check6_counts_and_money_exhaust_independently():
    by_count = execution_budget(
        context(ledger=ledger_row(execution_count=INTENT["scope"]["max_transactions"]))
    )
    by_money = execution_budget(
        context(
            ledger=ledger_row(
                committed_paise=INTENT["scope"]["max_amount"],
                captured_paise=0,
            )
        )
    )
    assert by_count.detail["conjunct"] == "max_transactions"
    assert by_money.detail["conjunct"] == "max_amount"
    assert by_count.reason_code == by_money.reason_code == ReasonCode.BUDGET_EXHAUSTED


@pytest.mark.parametrize(
    "state,reason",
    [
        (MandateState.EXHAUSTED, ReasonCode.BUDGET_EXHAUSTED),
        (MandateState.REVOKED, ReasonCode.MANDATE_EXPIRED),
        (MandateState.EXPIRED, ReasonCode.MANDATE_EXPIRED),
    ],
)
def test_check6_terminal_mandate_states_absorb(state, reason):
    result = execution_budget(context(ledger=ledger_row(mandate_state=state)))
    assert not result.passed
    assert result.reason_code == reason
    # The closed reason enum loses the distinction between revoked and expired;
    # the audit detail does not.
    assert result.detail["mandate_state"] == str(state)


def test_check6_refuses_when_the_budget_could_not_be_read():
    """An unreadable budget is not an empty budget."""
    assert not execution_budget(context(ledger=None)).passed


# --- the ordering itself --------------------------------------------------


def test_checks_run_in_the_declared_order_and_stop_at_the_first_failure():
    from kernel.checks import CHECKS_FOR_ACTION, run_checks

    payee = {**CONFIRMED_CART["payee"], "value": "attacker@upi"}
    # Both 2 and 4 would refuse this cart: the payee is not allowed, and the
    # hash is not the confirmed one. Only 2 gets to speak.
    ctx = context(cart=agent_cart(payee=payee))
    results = run_checks(ctx, CHECKS_FOR_ACTION[ActionType.AUTHORIZE])

    assert [r.id for r in results] == [1, 2]
    assert results[-1].reason_code == ReasonCode.PAYEE_NOT_ALLOWED
