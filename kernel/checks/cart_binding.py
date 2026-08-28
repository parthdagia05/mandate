"""Check 4 — cart_binding. Is this the cart the user actually approved?

``recompute(cart) == cart.cart_hash ∧ cart.cart_hash == ledger.confirmed_cart_hash``

Two conjuncts, and the reason both are needed is that they catch opposite
forgeries:

* the **first** is internal consistency — it catches a cart whose contents were
  edited while its ``cart_hash`` field was left alone, or vice versa;
* the **second** is external binding — it catches a cart that is *perfectly
  self-consistent* and was never approved. A compromised agent holding a
  delegated signing key can produce as many internally valid carts as it likes;
  what it cannot produce is one whose hash the user's confirmation ceremony
  recorded.

Only the second conjunct is a real defence. The first is there because without
it the second could be satisfied by a cart that lies about its own contents.

``confirmed_cart_hash`` is written once, at intent registration, from the
user-confirmed CartMandate. It is never taken from a request field: a
confirmation the agent supplies is not a confirmation.
"""

from __future__ import annotations

from kernel.checks.base import CheckContext, CheckResult
from kernel.enums import ReasonCode

__all__ = ["CHECK_ID", "cart_binding"]

CHECK_ID = 4


def cart_binding(ctx: CheckContext) -> CheckResult:
    cart = ctx.cart
    recomputed = cart.recompute_cart_hash()

    if recomputed != cart.cart_hash:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.CART_HASH_MISMATCH,
            conjunct="internal",
            declared_cart_hash=cart.cart_hash,
            recomputed_cart_hash=recomputed,
        )

    if ctx.ledger is None:
        # An unregistered intent has no record of what the user approved.
        # Absence of a confirmation is not a confirmation (REQ-5).
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.CART_HASH_MISMATCH,
            conjunct="external",
            detail="no ledger row for this intent; it was never registered",
            cart_hash=cart.cart_hash,
        )

    if ctx.ledger.confirmed_cart_hash != cart.cart_hash:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.CART_HASH_MISMATCH,
            conjunct="external",
            cart_hash=cart.cart_hash,
            confirmed_cart_hash=ctx.ledger.confirmed_cart_hash,
        )

    return CheckResult.ok(
        CHECK_ID,
        cart_hash=cart.cart_hash,
        confirmed_cart_hash=ctx.ledger.confirmed_cart_hash,
    )
