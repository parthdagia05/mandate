"""Check 1 — mandate_integrity. Is this authority real, current and unspent?

``ecdsa_verify(pubkey, JCS(body − sig), sig) ∧ now < expires_at ∧ nonce ∉ store``

Three conjuncts, three different forgeries, and each one has to be tested
separately or the other two go untested:

* the **signature** catches a mandate the user never signed;
* the **expiry** catches a real mandate presented after its window, read from
  the kernel's clock and never from ``client_ts`` — an agent that supplied the
  time would defeat this conjunct by lying about the hour;
* the **nonce** catches a real, unexpired mandate presented twice.

**Where the public keys come from.** The intent is verified against the
principal's key from the kernel's own trust store, never against a key carried
in the message: a key travelling inside the object it signs is a claim, not a
signature.

The cart is verified against whichever key its ``confirmed_by`` names:

``user``
    the principal's key. The user saw this cart and confirmed it.
``auto_within_intent_scope``
    ``intent.agent.pubkey`` — the key the *user-signed intent* delegated to.
    The agent assembles carts on the user's behalf inside an authority the user
    already granted, so it holds a signing key of its own.

That second case is the interesting one and it is not a weakness. The agent is
fully untrusted (SPEC.md §17.7), so assume it is compromised and signs whatever
a product page tells it to: it produces a perfectly valid cart naming
``attacker@upi``, check 1 passes, and checks 2, 3 and 4 refuse it anyway. That
is the claim worth making — not "we caught a forged signature", which any
system catches, but "a correctly signed request from a compromised agent still
cannot move money outside the sentence the user said".

**Determinism.** Signing at run time is fine here even though ECDSA is not
deterministic, because SPEC.md §15's second rule already holds: raw ``sig``
bytes never enter an audit payload, and no hash in the project is taken over a
signature. Two runs of one seed differ in the agent's signature bytes and agree
on every chain entry, every ``cart_hash`` and every identifier.
"""

from __future__ import annotations

from kernel.checks.base import CheckContext, CheckResult
from kernel.clock import from_rfc3339
from kernel.crypto import verify_object
from kernel.enums import ConfirmedBy, ReasonCode

__all__ = ["CHECK_ID", "mandate_integrity"]

CHECK_ID = 1


def _cart_signing_key(ctx: CheckContext) -> tuple[str | None, str]:
    """``(key, whose)`` for the cart's signature. See the module docstring."""
    if ctx.cart.confirmed_by == ConfirmedBy.AUTO_WITHIN_INTENT_SCOPE:
        return ctx.intent.agent.pubkey, "intent.agent.pubkey"
    return ctx.user_pubkey, "principal"


def mandate_integrity(ctx: CheckContext) -> CheckResult:
    intent, cart = ctx.intent, ctx.cart

    if ctx.user_pubkey is None:
        # An unregistered principal is not a principal. Failing here rather
        # than skipping the verification is the difference between "we could
        # not check" and "we checked and it was fine".
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.SIG_INVALID,
            conjunct="signature",
            detail="no registered public key for this principal",
            user_id=intent.principal.user_id,
        )

    if not verify_object(ctx.user_pubkey, intent.canonical_dict()):
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.SIG_INVALID,
            conjunct="signature",
            over="intent",
            mandate_id=intent.mandate_id,
        )

    cart_key, whose = _cart_signing_key(ctx)
    if cart_key is None or not verify_object(cart_key, cart.canonical_dict()):
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.SIG_INVALID,
            conjunct="signature",
            over="cart",
            cart_id=cart.mandate_id,
            confirmed_by=str(cart.confirmed_by),
            verified_against=whose,
        )

    if cart.parent != intent.mandate_id:
        # A validly signed cart pointing at a different intent spends authority
        # it was not issued under. The closed reason enum has no code of its
        # own for it; SIG_INVALID is the honest one, because what failed is the
        # binding the signature exists to establish.
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.SIG_INVALID,
            conjunct="binding",
            cart_parent=cart.parent,
            intent_id=intent.mandate_id,
        )

    now = from_rfc3339(ctx.now)
    if now >= from_rfc3339(intent.expires_at):
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.MANDATE_EXPIRED,
            conjunct="expiry",
            expired="intent",
            expires_at=intent.expires_at,
            kernel_now=ctx.now,
            # Recorded so the chain shows the kernel ignored it, rather than
            # leaving "we did not read client_ts" as an unevidenced claim.
            client_ts=ctx.request.client_ts,
        )
    if now < from_rfc3339(intent.issued_at):
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.MANDATE_EXPIRED,
            conjunct="expiry",
            expired="intent",
            detail="presented before it was issued",
            issued_at=intent.issued_at,
            kernel_now=ctx.now,
        )
    if now >= from_rfc3339(cart.instrument.expires_at):
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.MANDATE_EXPIRED,
            conjunct="expiry",
            expired="instrument",
            expires_at=cart.instrument.expires_at,
            kernel_now=ctx.now,
        )

    # The nonce is single-use and the *store* is the enforcement, not a branch
    # in code that a later caller can forget to run. Two different questions
    # are asked of it, which is why ``registering`` exists:
    #
    #   registering — the nonce must be unseen. An intent presented for
    #       registration a second time is minting the same authority twice, and
    #       "it is the same mandate" is the replay, not an excuse for it.
    #   every later call — the nonce must not be bound *elsewhere*. Finding it
    #       under another mandate means one signed structure is being presented
    #       as authority for another.
    #
    # An unseen nonce on a later call is deliberately not check 1's problem.
    # It means the intent was never registered, which checks 4 and 6 refuse
    # with reason codes that say so; reporting it as NONCE_REPLAYED here would
    # put the wrong word in the results table for the commonest ordinary
    # mistake there is.
    owner = ctx.nonce_owner(intent.nonce)
    replayed = owner is not None if ctx.registering else (
        owner is not None and owner != intent.mandate_id
    )
    if replayed:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.NONCE_REPLAYED,
            conjunct="nonce",
            registering=ctx.registering,
            bound_to=owner,
            presented_by=intent.mandate_id,
        )

    return CheckResult.ok(
        CHECK_ID,
        mandate_id=intent.mandate_id,
        cart_id=cart.mandate_id,
        confirmed_by=str(cart.confirmed_by),
        verified_against=whose,
        expires_at=intent.expires_at,
        kernel_now=ctx.now,
    )
