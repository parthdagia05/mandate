"""Check 6 — execution_budget. Is there any authority left to spend?

``execution_count < max_transactions ∧ committed + amount ≤ max_amount``
plus the one thing that is not arithmetic: **the mandate's state must still be
active.**

Two counters, because "how many times" and "how much" are separately
exhaustible. A mandate for three transactions of up to ₹2,000 total is spent by
three ₹1 purchases and by one ₹2,000 purchase, and a check that watched only
the money would let the first case run forever.

**Checks 6 and 7 are not redundant.** Check 7 collapses *the same* action
repeated — a retry, a redelivered webhook — into one debit. Check 6 refuses a
*different* action beyond the signed count. A system with only idempotency
lets an agent spend the mandate an unlimited number of times as long as each
request differs; a system with only a budget double-charges on every network
retry.

**Authorize commits; capture settles.** The money conjunct asks a different
question of each, because they are different questions. An authorize adds to
the committed position, so it is bounded by ``max_amount``. A capture settles
funds *already* committed by its own authorize, so it is bounded by what was
committed and not yet captured — comparing it to ``max_amount`` again would
count the same rupees twice and refuse the user's own purchase at the last
step. The same applies to the count: the transaction slot is spent at
authorize, so re-checking it at capture would refuse the settlement of the
mandate's final transaction.

That is a real false block rather than a hypothetical one. A mandate whose
``per_txn_cap`` equals its ``max_amount`` — the ordinary shape for "buy me this
one thing" — commits its whole budget at authorize and would then be unable to
capture it.

**Terminal mandate states are absorbing.** ``exhausted``, ``revoked`` and
``expired`` have no outgoing edge, and this check is where that is enforced at
run time. There is no transition anywhere in the kernel that widens an existing
authority: an escalation that a human approves mints a *new* intent, which the
user signs, which gets its own ledger row. Editing the old one would mean the
signature on it no longer covers what it now permits.

``mandate_state`` and ``ledger_state`` are read as two separate enums because
authority and money terminate independently: a fully refunded purchase leaves
the ledger at ``fully_refunded`` while the mandate stays ``exhausted`` — the
money came back, the permission did not.
"""

from __future__ import annotations

from kernel.checks.base import CheckContext, CheckResult
from kernel.enums import ActionType, MandateState, ReasonCode

__all__ = ["CHECK_ID", "TERMINAL_REASON", "execution_budget"]

CHECK_ID = 6

#: What a terminal authority state reports. The reason enum is closed and has
#: no ``MANDATE_REVOKED``; a revoked mandate reports ``MANDATE_EXPIRED``
#: because from the request's side both are "this authority has ended", and the
#: audit detail carries the actual state so nothing is lost in the chain.
TERMINAL_REASON = {
    MandateState.EXHAUSTED: ReasonCode.BUDGET_EXHAUSTED,
    MandateState.REVOKED: ReasonCode.MANDATE_EXPIRED,
    MandateState.EXPIRED: ReasonCode.MANDATE_EXPIRED,
}


def execution_budget(ctx: CheckContext) -> CheckResult:
    scope = ctx.intent.scope
    ledger = ctx.ledger
    amount = ctx.request.params.amount

    if ledger is None:
        # An unreadable or absent budget is not an empty budget (SPEC.md §16).
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.BUDGET_EXHAUSTED,
            detail="no ledger row for this intent; it was never registered",
            mandate_id=ctx.intent.mandate_id,
        )

    if ledger.mandate_state != MandateState.ACTIVE:
        return CheckResult.failed(
            CHECK_ID,
            TERMINAL_REASON[MandateState(ledger.mandate_state)],
            conjunct="mandate_state",
            mandate_state=str(ledger.mandate_state),
            ledger_state=str(ledger.ledger_state),
        )

    settling = ctx.action == ActionType.CAPTURE

    if settling:
        # Bounded by its own authorize, not by the mandate's lifetime ceiling.
        # A capture beyond what was committed is money nothing reserved, which
        # is the thing worth refusing here.
        uncaptured = ledger.committed_paise - ledger.captured_paise
        if amount > uncaptured:
            return CheckResult.failed(
                CHECK_ID,
                ReasonCode.BUDGET_EXHAUSTED,
                conjunct="uncaptured",
                committed_paise=ledger.committed_paise,
                captured_paise=ledger.captured_paise,
                requested_amount=amount,
            )
    else:
        if ledger.execution_count >= scope.max_transactions:
            return CheckResult.failed(
                CHECK_ID,
                ReasonCode.BUDGET_EXHAUSTED,
                conjunct="max_transactions",
                execution_count=ledger.execution_count,
                max_transactions=scope.max_transactions,
            )

        if ledger.committed_paise + amount > scope.max_amount:
            return CheckResult.failed(
                CHECK_ID,
                ReasonCode.BUDGET_EXHAUSTED,
                conjunct="max_amount",
                committed_paise=ledger.committed_paise,
                requested_amount=amount,
                max_amount=scope.max_amount,
            )

    return CheckResult.ok(
        CHECK_ID,
        conjunct="uncaptured" if settling else "max_amount",
        execution_count=ledger.execution_count,
        max_transactions=scope.max_transactions,
        committed_paise=ledger.committed_paise,
        captured_paise=ledger.captured_paise,
        requested_amount=amount,
        max_amount=scope.max_amount,
        mandate_state=str(ledger.mandate_state),
        ledger_state=str(ledger.ledger_state),
    )
