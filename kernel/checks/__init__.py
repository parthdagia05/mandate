"""The nine checks, in evaluation order (SPEC.md §08).

Order matters and is fixed here: the cheapest and most fundamental first, so a
request with a broken signature never reaches the code that reads a budget.
**First failure short-circuits, but the audit payload keeps the full evaluated
prefix** — every check that ran, passes included. Recording only the refusal
would make the per-check ablation in ``results.md`` unreadable: "check 2
refused" and "checks 1 and 2 ran, 2 refused" are different facts, and only the
second one says what was still being enforced.

Checks 7 (idempotency) and 9 (audit_append) are not predicates over a request —
they are steps in the lifecycle, so :mod:`kernel.service` contributes their
results. Check 8 needs a ledger row the service reads for it, so it takes a
second argument and is called directly rather than through this table.
"""

from __future__ import annotations

from kernel.checks.amount_lattice import amount_lattice
from kernel.checks.base import (
    CHECK_NAMES,
    CHECKS_FOR_ACTION,
    ON_FAIL,
    Check,
    CheckContext,
    CheckResult,
)
from kernel.checks.cart_binding import cart_binding
from kernel.checks.execution_budget import execution_budget
from kernel.checks.mandate_integrity import mandate_integrity
from kernel.checks.payee_allowlist import payee_allowlist
from kernel.checks.recurrence_scope import recurrence_scope
from kernel.checks.refund_binding import refund_binding

__all__ = [
    "CHECK_NAMES",
    "CHECKS_FOR_ACTION",
    "ON_FAIL",
    "PREDICATES",
    "Check",
    "CheckContext",
    "CheckResult",
    "run_checks",
    "mandate_integrity",
    "payee_allowlist",
    "amount_lattice",
    "cart_binding",
    "recurrence_scope",
    "execution_budget",
    "refund_binding",
]

#: Check number -> predicate. The numbers are the contract; ``denied_by`` in
#: the decision response and the ablation columns both key off them.
PREDICATES: dict[int, Check] = {
    1: mandate_integrity,
    2: payee_allowlist,
    3: amount_lattice,
    4: cart_binding,
    5: recurrence_scope,
    6: execution_budget,
}


def run_checks(ctx: CheckContext, ids: tuple[int, ...]) -> list[CheckResult]:
    """Evaluate ``ids`` in order, stopping at the first failure.

    Returns the evaluated prefix — which is what goes in the audit payload, and
    the reason this returns a list rather than the first failure.
    """
    results: list[CheckResult] = []
    for check_id in ids:
        result = PREDICATES[check_id](ctx)
        results.append(result)
        if not result.passed:
            break
    return results
