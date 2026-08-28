"""ECDSA P-256 over ``JCS(object minus sig)``.

Signing lives here for the fixture-building script's benefit only. **Nothing
signs during a run** (SPEC.md §15): standard ECDSA picks a random nonce per
signature, so signing the same bytes twice gives different bytes and REQ-3
would be false. Every mandate is signed once, offline, and shipped as a
fixture; the manifest hash covers the signatures.

Ed25519 would be the better cryptographic choice here — deterministic by
construction, faster, no nonce footgun. We take P-256 because AP2 specifies it
and the 1:1 mapping is worth more to this project than the ergonomics.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

from kernel.canonical import signing_input

__all__ = [
    "b64u_encode",
    "b64u_decode",
    "generate_keypair",
    "public_key_b64u",
    "load_public_key_b64u",
    "sign_object",
    "verify_object",
    "utterance_hash",
]

CURVE = ec.SECP256R1()


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keypair() -> ec.EllipticCurvePrivateKey:
    """Offline use only — key generation never happens inside a run."""
    return ec.generate_private_key(CURVE)


def public_key_b64u(private_key: ec.EllipticCurvePrivateKey) -> str:
    """The public key as base64url DER, the form that fits in a schema field."""
    der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return b64u_encode(der)


def load_public_key_b64u(encoded: str) -> ec.EllipticCurvePublicKey:
    key = serialization.load_der_public_key(b64u_decode(encoded))
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("not an elliptic curve public key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(f"expected P-256, got {key.curve.name}")
    return key


def sign_object(
    private_key: ec.EllipticCurvePrivateKey, obj: dict[str, Any]
) -> str:
    """Sign ``JCS(obj minus sig)``. Offline, at fixture-freeze time only.

    The signature is stored as base64url of the raw ``r ‖ s`` pair rather than
    DER, so the encoding has exactly one form and cannot be malleated into a
    second valid representation of the same signature.
    """
    der = private_key.sign(signing_input(obj), ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    return b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify_object(public_key_encoded: str, obj: dict[str, Any]) -> bool:
    """Check 1's first conjunct: does this object carry its signer's signature?

    Returns a bool rather than raising, because a bad signature is a policy
    denial with a reason code, not an exception path.
    """
    signature = obj.get("sig")
    if not isinstance(signature, str) or not signature:
        return False
    try:
        raw = b64u_decode(signature)
        if len(raw) != 64:
            return False
        der = asym_utils.encode_dss_signature(
            int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        )
        load_public_key_b64u(public_key_encoded).verify(
            der, signing_input(obj), ec.ECDSA(hashes.SHA256())
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def utterance_hash(sentence: str) -> str:
    """SHA-256 of the exact sentence the user said, NFC-normalised.

    Normalisation matters: two visually identical sentences with different
    Unicode composition must not produce two different authorities.
    """
    import hashlib
    import unicodedata

    normalised = unicodedata.normalize("NFC", sentence)
    return "sha256:" + hashlib.sha256(normalised.encode("utf-8")).hexdigest()
