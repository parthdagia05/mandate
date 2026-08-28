"""P-01, P-02, P-10 — the canonicalisation properties, plus RFC 8785 vectors.

This is the day-1 deliverable SPEC.md §05 asks for: two semantically identical
carts built by different code paths produce byte-identical ``cart_hash``. Every
signature and every audit hash in the project is taken over the bytes this
module produces, so these tests are the foundation the rest of the results
stand on.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from kernel.canonical import (
    CanonicalisationError,
    canonical_number,
    cart_hash,
    jcs,
    signing_input,
)

# --------------------------------------------------------------------------
# RFC 8785 reference behaviour
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, "0"),
        (-0.0, "0"),
        (1000, "1000"),
        (1000.0, "1000"),
        (1.0e3, "1000"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (5e-324, "5e-324"),
        (0.1, "0.1"),
        (-1.5, "-1.5"),
        (1.5e300, "1.5e+300"),
    ],
)
def test_number_forms_match_ecmascript(value, expected):
    """RFC 8785 defers to ES6 ``Number::toString``: shortest round-trip."""
    assert canonical_number(value) == expected


def test_nan_and_infinity_are_refused():
    for bad in [float("nan"), float("inf"), float("-inf")]:
        with pytest.raises(CanonicalisationError):
            canonical_number(bad)


def test_oversized_integers_are_refused():
    """Beyond 2^53 a JSON parser could not round-trip the value back."""
    with pytest.raises(CanonicalisationError):
        jcs({"amount": 2**53})


def test_keys_sort_by_utf16_code_unit():
    """Above the BMP, UTF-16 order and code-point order disagree.

    U+10000 is a surrogate pair beginning D800, so it sorts *before* U+FFFF in
    UTF-16 order and after it by code point. Sorting the wrong way here would
    make two implementations disagree on a signature.
    """
    assert jcs({"￿": 1, "\U00010000": 2}) == '{"\U00010000":2,"￿":1}'


def test_control_characters_are_escaped():
    # This is what makes U+001F safe as the audit chain's field separator.
    assert jcs({"a": "x\x1fy"}) == '{"a":"x\\u001fy"}'
    assert jcs({"a": "\n\t\"\\"}) == '{"a":"\\n\\t\\\"\\\\"}'


def test_non_ascii_is_not_escaped():
    assert jcs({"a": "café"}) == '{"a":"café"}'


def test_no_insignificant_whitespace():
    assert jcs({"b": [1, 2], "a": {"c": None}}) == '{"a":{"c":null},"b":[1,2]}'


def test_bools_are_not_numbers():
    with pytest.raises(CanonicalisationError):
        canonical_number(True)


# --------------------------------------------------------------------------
# P-10 — JCS is stable under key reordering and equivalent number forms
# --------------------------------------------------------------------------

_JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1),
    st.text(max_size=20).filter(lambda s: not any(0xD800 <= ord(c) <= 0xDFFF for c in s)),
)

_JSON_VALUES = st.recursive(
    _JSON_SCALARS,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=8), children, max_size=4),
    ),
    max_leaves=12,
)


@given(_JSON_VALUES)
@settings(max_examples=200, deadline=None)
def test_jcs_survives_a_json_round_trip(value):
    """Serialise, reparse, recanonicalise — the bytes must not move."""
    once = jcs(value)
    assert jcs(json.loads(once)) == once


@given(st.dictionaries(st.text(max_size=8), _JSON_SCALARS, min_size=1, max_size=6))
@settings(max_examples=200, deadline=None)
def test_jcs_ignores_key_insertion_order(mapping):
    reversed_mapping = {k: mapping[k] for k in reversed(list(mapping))}
    assert jcs(mapping) == jcs(reversed_mapping)


# --------------------------------------------------------------------------
# P-01 / P-02 — the cart hash
# --------------------------------------------------------------------------

PAYEE = {"type": "vpa", "value": "merchant@upi", "merchant_id": "shopkart"}

LINE_ITEMS = [
    {"sku": "SK-MOUSE-01", "qty": 1, "unit_amount": 44900},
    {"sku": "SK-SHIP-STD", "qty": 1, "unit_amount": 1000},
    {"sku": "SK-CABLE-USBC", "qty": 2, "unit_amount": 2000},
]

TOTAL = 49900


def test_p01_two_carts_built_differently_hash_identically():
    """The property SPEC.md §05 names as the day-1 deliverable."""
    one_way = cart_hash(LINE_ITEMS, TOTAL, PAYEE)

    other_way = cart_hash(
        # different order, different key order, exponential amounts
        [
            {"unit_amount": 2.0e3, "qty": 2, "sku": "SK-CABLE-USBC"},
            {"qty": 1, "sku": "SK-MOUSE-01", "unit_amount": 4.49e4},
            {"sku": "SK-SHIP-STD", "unit_amount": 1.0e3, "qty": 1},
        ],
        4.99e4,
        {"merchant_id": "shopkart", "value": "merchant@upi", "type": "vpa"},
    )
    assert one_way == other_way


@given(st.permutations(LINE_ITEMS))
@settings(max_examples=50, deadline=None)
def test_p01_line_item_order_never_matters(permutation):
    assert cart_hash(list(permutation), TOTAL, PAYEE) == cart_hash(
        LINE_ITEMS, TOTAL, PAYEE
    )


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda items: [{**items[0], "sku": "SK-MOUSE-02"}, *items[1:]], id="sku"),
        pytest.param(lambda items: [{**items[0], "qty": 2}, *items[1:]], id="qty"),
        pytest.param(
            lambda items: [{**items[0], "unit_amount": 44901}, *items[1:]], id="unit_amount"
        ),
        pytest.param(lambda items: items[1:], id="dropped-item"),
        pytest.param(
            lambda items: [*items, {"sku": "SK-EXTRA", "qty": 1, "unit_amount": 1}],
            id="added-item",
        ),
    ],
)
def test_p02_any_line_item_edit_moves_the_hash(mutate):
    assert cart_hash(mutate(LINE_ITEMS), TOTAL, PAYEE) != cart_hash(
        LINE_ITEMS, TOTAL, PAYEE
    )


def test_p02_one_character_in_a_sku_moves_the_hash():
    """Milestone M1, "Prove it" step 2, at unit scale."""
    tweaked = [{**LINE_ITEMS[0], "sku": "SK-MOUSE-0l"}, *LINE_ITEMS[1:]]
    assert cart_hash(tweaked, TOTAL, PAYEE) != cart_hash(LINE_ITEMS, TOTAL, PAYEE)


def test_p02_payee_and_total_are_bound_too():
    attacker = {**PAYEE, "value": "attacker@upi"}
    assert cart_hash(LINE_ITEMS, TOTAL, attacker) != cart_hash(LINE_ITEMS, TOTAL, PAYEE)
    assert cart_hash(LINE_ITEMS, TOTAL + 1, PAYEE) != cart_hash(LINE_ITEMS, TOTAL, PAYEE)


def test_cart_hash_covers_only_the_three_bound_fields():
    """Adding a field to the cart must not move the hash.

    The binding is deliberately narrow: what is bought, for how much, to whom.
    A wider hash would let a merchant change the binding by changing something
    the user never saw.
    """
    assert cart_hash(LINE_ITEMS, TOTAL, PAYEE) == cart_hash(
        [dict(item) for item in LINE_ITEMS], TOTAL, dict(PAYEE)
    )


# --------------------------------------------------------------------------
# Signing input
# --------------------------------------------------------------------------


def test_signing_input_drops_the_signature():
    body = {"a": 1, "b": 2}
    assert signing_input(body) == signing_input({**body, "sig": "anything"})


def test_signing_input_normalises_line_item_order():
    """Order is non-semantic for the hash, so it must be non-semantic here too.

    Otherwise the same cart written two ways would agree on ``cart_hash`` and
    disagree on its signature, and the kernel would hold two different notions
    of "the same cart".
    """
    body = {"line_items": LINE_ITEMS, "total_amount": TOTAL}
    shuffled = {"line_items": list(reversed(LINE_ITEMS)), "total_amount": TOTAL}
    assert signing_input(body) == signing_input(shuffled)
