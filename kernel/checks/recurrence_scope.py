"""Check 5 — recurrence_scope. Was standing authority ever authorised?

``action == mandate.create ⇒ intent.scope.recurring``

One line, one attack class. A4 is the move from "buy this once" to "and keep
buying it every month", and it is worth its own check rather than being folded
into the budget because the two fail differently. An over-budget purchase is a
bounded loss the ledger can name; a recurring mandate the user never authorised
is an *unbounded* one that keeps drawing after everyone has stopped looking.

The implication is vacuously true for every other action, and a vacuous pass is
still recorded. A check that quietly did not run on some actions would make the
ablation table read as though it had.
"""

from __future__ import annotations

from kernel.checks.base import CheckContext, CheckResult
from kernel.enums import ActionType, ReasonCode

__all__ = ["CHECK_ID", "recurrence_scope"]

CHECK_ID = 5


def recurrence_scope(ctx: CheckContext) -> CheckResult:
    creating = ctx.action == ActionType.MANDATE_CREATE
    recurring = ctx.intent.scope.recurring

    if creating and not recurring:
        return CheckResult.failed(
            CHECK_ID,
            ReasonCode.RECURRENCE_NOT_AUTHORISED,
            action=str(ctx.action),
            scope_recurring=recurring,
            utterance_hash=ctx.intent.utterance_hash,
        )

    return CheckResult.ok(
        CHECK_ID,
        action=str(ctx.action),
        scope_recurring=recurring,
        # Says so explicitly, so a reader of the chain can tell a vacuous pass
        # from a pass that had something to refuse.
        applicable=creating,
    )
