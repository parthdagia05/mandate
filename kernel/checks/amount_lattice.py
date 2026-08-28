"""Check 3 — amount_lattice. Is this amount inside the sentence the user said?

``total ≤ max_amount ∧ total ≤ per_txn_cap ∧ total == Σ(qty × unit_amount)
∧ currency equal``

Four conjuncts doing two different jobs, and dropping either job leaves a whole
attack shape open:

* the **ceilings** stop gross inflation — ₹499 becoming ₹49,900;
* the **sum equality** stops sub-ceiling skimming — a cart whose line items add
  to ₹499 while ``total_amount`` says ₹599. That is under every cap, looks
  ordinary in a ledger, and is the version of A2 a ceiling alone never sees.

The **currency equality** is the third shape: an amount is a number *and* a
unit, and 49900 JPY is not 49900 INR. Comparing the numbers while ignoring the
units would let a currency swap pass every other conjunct in this check.

``params.amount`` is compared to the cart total as well. The action's amount and
the cart's total are two fields an attacker can move independently, and a
capture for more than the cart says is exactly that move.
"""

from __future__ import annotations

from kernel.checks.base import CheckContext, CheckResult
from kernel.enums import ReasonCode

__all__ = ["CHECK_ID", "amount_lattice"]

CHECK_ID = 3


def amount_lattice(ctx: CheckContext) -> CheckResult:
    cart, scope = ctx.cart, ctx.intent.scope
    total = cart.total_amount
    line_item_sum = cart.line_item_total()

    if cart.currency != scope.currency:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.CURRENCY_MISMATCH,
            conjunct="currency",
            cart_currency=cart.currency,
            scope_currency=scope.currency,
        )

    if total != line_item_sum:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.LINE_ITEM_SUM_MISMATCH,
            conjunct="sum",
            total_amount=total,
            line_item_sum=line_item_sum,
            difference=total - line_item_sum,
        )

    if ctx.request.params.amount != total:
        # The action's amount and the cart's total are separately movable
        # fields. Anchor the action to the cart the user's authority covers.
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.AMOUNT_EXCEEDS_SCOPE,
            conjunct="action_amount",
            requested_amount=ctx.request.params.amount,
            cart_total=total,
        )

    if total > scope.per_txn_cap:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.AMOUNT_EXCEEDS_SCOPE,
            conjunct="per_txn_cap",
            total_amount=total,
            per_txn_cap=scope.per_txn_cap,
        )

    if total > scope.max_amount:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.AMOUNT_EXCEEDS_SCOPE,
            conjunct="max_amount",
            total_amount=total,
            max_amount=scope.max_amount,
        )

    return CheckResult.ok(
        CHECK_ID,
        total_amount=total,
        line_item_sum=line_item_sum,
        per_txn_cap=scope.per_txn_cap,
        max_amount=scope.max_amount,
        currency=cart.currency,
    )
