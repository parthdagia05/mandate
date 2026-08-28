"""U-01 and the fixture-signing discipline (SPEC.md §15).

The point of this file is less "does ECDSA work" and more "is the signature
bound to the thing we think it is bound to". A signature over a
non-canonical serialisation would verify for one rendering of a cart and fail
for another, which is the same bug as having no binding at all.
"""

from __future__ import annotations

import json

import pytest

from kernel.crypto import (
    b64u_decode,
    generate_keypair,
    public_key_b64u,
    sign_object,
    utterance_hash,
    verify_object,
)


def test_u01_shipped_fixtures_verify(intent_json, cart_json, user_pubkey):
    assert verify_object(user_pubkey, intent_json)
    assert verify_object(user_pubkey, cart_json)


def test_u01_a_flipped_byte_is_rejected(cart_json, user_pubkey):
    raw = bytearray(b64u_decode(cart_json["sig"]))
    raw[0] ^= 0x01
    from kernel.crypto import b64u_encode

    with_flipped = {**cart_json, "sig": b64u_encode(bytes(raw))}
    assert not verify_object(user_pubkey, with_flipped)


@pytest.mark.parametrize(
    "field,value",
    [
        ("total_amount", 999999),
        ("cart_hash", "sha256:" + "0" * 64),
        ("confirmed_by", "auto_within_intent_scope"),
    ],
)
def test_u01_editing_any_signed_field_breaks_the_signature(
    cart_json, user_pubkey, field, value
):
    assert not verify_object(user_pubkey, {**cart_json, field: value})


def test_u01_swapping_the_payee_breaks_the_signature(cart_json, user_pubkey):
    """A1 at the cryptographic layer: the payee is inside the signature, so a
    substituted payee cannot even reach check 2 with a valid mandate."""
    tampered = {**cart_json, "payee": {**cart_json["payee"], "value": "attacker@upi"}}
    assert not verify_object(user_pubkey, tampered)


def test_u01_a_missing_signature_is_a_failure_not_a_crash(cart_json, user_pubkey):
    unsigned = {k: v for k, v in cart_json.items() if k != "sig"}
    assert verify_object(user_pubkey, unsigned) is False


def test_u01_a_malformed_signature_is_a_failure_not_a_crash(cart_json, user_pubkey):
    for bad in ["", "not-base64!!", "AAAA", 42, None]:
        assert verify_object(user_pubkey, {**cart_json, "sig": bad}) is False


def test_the_wrong_key_does_not_verify(cart_json):
    stranger = public_key_b64u(generate_keypair())
    assert not verify_object(stranger, cart_json)


def test_signature_survives_reserialisation(cart_json, user_pubkey):
    """The signature is over the canonical form, so it must not care how the
    document happened to be written."""
    rewritten = json.loads(json.dumps({k: cart_json[k] for k in reversed(list(cart_json))}))
    assert verify_object(user_pubkey, rewritten)


def test_signature_survives_line_item_reordering(cart_json, user_pubkey):
    shuffled = {**cart_json, "line_items": list(reversed(cart_json["line_items"]))}
    assert verify_object(user_pubkey, shuffled)


def test_both_cart_renderings_verify(fixtures_dir, user_pubkey):
    """M1's two fixture carts differ in key order, line-item order and number
    form, and carry the same signature bytes."""
    a = json.loads((fixtures_dir / "cart_a.json").read_text())
    b = json.loads((fixtures_dir / "cart_b.json").read_text())
    assert a["sig"] == b["sig"]
    assert verify_object(user_pubkey, a)
    assert verify_object(user_pubkey, b)


def test_signatures_are_fixed_length_raw_r_s(cart_json):
    """Raw ``r ‖ s`` rather than DER: one encoding, so a signature cannot be
    malleated into a second valid representation of itself."""
    assert len(b64u_decode(cart_json["sig"])) == 64


def test_signing_is_not_deterministic():
    """The reason nothing signs at run time (SPEC.md §15).

    Two signatures over identical bytes differ, so a run that signed would not
    be byte-reproducible and REQ-3 would be false. Both still verify.
    """
    key = generate_keypair()
    body = {"a": 1}
    first = sign_object(key, body)
    second = sign_object(key, body)
    assert first != second
    pub = public_key_b64u(key)
    assert verify_object(pub, {**body, "sig": first})
    assert verify_object(pub, {**body, "sig": second})


def test_utterance_hash_is_normalisation_stable():
    """Two visually identical sentences must not buy two different authorities."""
    composed = "café order"          # é as one code point
    decomposed = "café order"        # e + combining acute
    assert utterance_hash(composed) == utterance_hash(decomposed)


def test_utterance_hash_distinguishes_different_sentences():
    assert utterance_hash("pay ShopKart 500") != utterance_hash("pay ShopKart 5000")
