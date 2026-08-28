"""Check 2 — payee_allowlist. Is this where the user said the money goes?

``cart.payee`` byte-equals an entry in ``intent.scope.allowed_payees`` after
the one normalisation in :mod:`kernel.vpa`. No fuzzy match, no substring, no
homoglyph tolerance.

This is the check that kills class A1, and it kills it by being boring. Every
sophistication available here is a way for an attacker-controlled address to be
declared "close enough" to an authorised one: an edit-distance threshold is an
address an attacker can walk towards, a substring test makes
``notmerchant@upi`` contain ``merchant@upi``, and Unicode folding maps a
Cyrillic lookalike straight onto the real thing. So there is one comparison,
it is equality, and the only difference forgiven is ASCII case because UPI
addresses are genuinely case-insensitive.

**On fail this escalates rather than denying outright.** A payee the intent
does not name may be perfectly legitimate — a merchant that really did change
its settlement account. What is not legitimate is *this authority* paying it.
A human can mint a new intent naming the new address; nothing can widen the old
one. Escalation goes to a person, never back to the model: asking the model
whether the injection it just believed was really an injection is not a review.
"""

from __future__ import annotations

from kernel.checks.base import CheckContext, CheckResult
from kernel.enums import ReasonCode
from kernel.vpa import account_in, normalise_account

__all__ = ["CHECK_ID", "payee_allowlist"]

CHECK_ID = 2


def payee_allowlist(ctx: CheckContext) -> CheckResult:
    payee = ctx.cart.payee.canonical_dict()
    allowed = [entry.canonical_dict() for entry in ctx.intent.scope.allowed_payees]

    if account_in(payee, allowed):
        return CheckResult.ok(
            CHECK_ID,
            payee={"type": payee["type"], "value": payee["value"]},
            allowed_payees=allowed,
        )

    return CheckResult.failed(
        CHECK_ID,
        ReasonCode.PAYEE_NOT_ALLOWED,
        # Both sides, in full, because this is the pair ``mk explain`` reads
        # out: the payee the user allowed and the payee the request carried.
        requested_payee={"type": payee["type"], "value": payee["value"]},
        allowed_payees=allowed,
        normalised=normalise_account(payee["type"], payee["value"]),
        utterance_hash=ctx.intent.utterance_hash,
    )
