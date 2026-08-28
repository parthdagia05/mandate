"""What a check is, and what one is allowed to see.

Nine checks, SPEC.md §08. Each is a **pure function** of a
:class:`CheckContext` returning a :class:`CheckResult`. Purity is not
tidiness here: it is what makes ``tests/test_checks_*.py`` able to exercise a
check with no store, no clock and no kernel, and what makes the per-check
ablation in ``results.md`` mean "this predicate was removed" rather than "this
code path was disturbed".

Two things a check may never do, both of which the type makes awkward rather
than merely discouraged:

* **Read a store.** Anything from a store arrives on the context, already read
  — including the one lookup check 1 genuinely needs, which comes in as
  ``nonce_owner``, a callable the caller supplies. A check that opened its own
  connection would have its own failure mode, and REQ-5's "every store failure
  denies" would then have nine places to be got wrong instead of one.
* **Decide.** A check reports pass or fail and the reason code for a fail. The
  *decision* — deny versus escalate — is a property of the check, declared once
  in :data:`ON_FAIL`, not something an individual result argues for. Otherwise
  the same failure could escalate on Tuesday and deny on Wednesday.

**Evaluation order is fixed and first failure short-circuits**, but the audit
payload keeps the full evaluated prefix — every check that ran, including the
ones that passed. That is what makes an ablation readable: "checks 1 and 2 ran,
2 refused" is a different fact from "something refused".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from kernel.enums import ActionType, Decision, ReasonCode
from kernel.models import CartMandate, IntentMandate, PaymentRequest, SpendLedger

__all__ = [
    "CHECK_NAMES",
    "ON_FAIL",
    "CHECKS_FOR_ACTION",
    "CheckContext",
    "CheckResult",
    "Check",
]

#: The nine, by number. Numbers rather than names are what the decision
#: response's ``denied_by`` carries and what the results table groups by, so
#: they are fixed here once and never renumbered.
CHECK_NAMES: dict[int, str] = {
    1: "mandate_integrity",
    2: "payee_allowlist",
    3: "amount_lattice",
    4: "cart_binding",
    5: "recurrence_scope",
    6: "execution_budget",
    7: "idempotency",
    8: "refund_binding",
    9: "audit_append",
}

#: What a failure of each check *is*. SPEC.md §08's "On fail" column.
#:
#: The split is not severity. ``escalate`` says the request may well be
#: legitimate and a human could mint fresh authority for it — a payee the user
#: has not named yet, a total above the cap. ``deny`` says no authority can
#: exist for this request as written: a bad signature, an expired mandate, a
#: budget already spent. Escalation mints new authority; it never widens old
#: authority, so nothing on the deny side can be escalated into an allow.
ON_FAIL: dict[int, Decision] = {
    1: Decision.DENY,
    2: Decision.ESCALATE,
    3: Decision.ESCALATE,
    4: Decision.ESCALATE,
    5: Decision.ESCALATE,
    6: Decision.DENY,
    7: Decision.DENY,
    8: Decision.DENY,
    9: Decision.DENY,
}

#: Which checks each action runs, SPEC.md §07. Checks 7 and 9 are lifecycle
#: steps rather than predicates over the request, so they are appended by the
#: service; this table is the predicate half.
CHECKS_FOR_ACTION: dict[ActionType, tuple[int, ...]] = {
    ActionType.AUTHORIZE: (1, 2, 3, 4, 5, 6),
    ActionType.CAPTURE: (1, 3, 6),
    ActionType.REFUND: (1,),
    ActionType.MANDATE_CREATE: (1, 5),
}


@dataclass(frozen=True)
class CheckContext:
    """Everything a check may look at, and nothing it may not.

    Assembled once per request by the service. A check receives values that
    have already been read from stores, so a store failure is a single
    fail-closed branch in one place rather than nine.
    """

    request: PaymentRequest
    #: The registered public key of ``request.intent.principal.user_id``, from
    #: the kernel's own trust store. Never from the message: a key carried
    #: inside the object it signs is not a signature, it is a claim.
    user_pubkey: str | None
    #: The ledger row opened at intent registration, or ``None`` if this intent
    #: was never registered. ``None`` is not an empty budget — checks 4 and 6
    #: fail on it rather than treating an unknown mandate as a fresh one.
    ledger: SpendLedger | None
    #: ``now`` from the kernel's clock, as RFC 3339. Never ``request.client_ts``.
    now: str
    #: ``nonce -> mandate_id`` for a nonce the store has already seen, else
    #: ``None``. A callable rather than a dict so the service can hand a check
    #: a single point lookup without handing it the store.
    nonce_owner: Callable[[str], str | None] = lambda _nonce: None
    #: True on the one call that mints authority — intent registration. The
    #: nonce is single-use *for minting*: an already-seen nonce registering
    #: again is a replay even when it is its own mandate presenting it, because
    #: registering twice is minting authority twice. Every later call re-reads
    #: the same nonce and must find it bound to this mandate, which is a
    #: different question with a different answer.
    registering: bool = False

    @property
    def intent(self) -> IntentMandate:
        return self.request.intent

    @property
    def cart(self) -> CartMandate:
        return self.request.cart

    @property
    def action(self) -> ActionType:
        return self.request.action


@dataclass(frozen=True)
class CheckResult:
    """One row of the decision response's ``checks`` array.

    ``detail`` is the check's contribution to the audit payload: the specific
    values it compared, so that ``mk explain`` can say "you allowed
    merchant@upi, this carried attacker@upi" rather than "check 2 refused".
    It must contain no signature bytes and nothing non-deterministic — the
    chain hashes it.
    """

    id: int
    name: str
    passed: bool
    reason_code: ReasonCode = ReasonCode.OK
    detail: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def ok(cls, check_id: int, **detail: Any) -> "CheckResult":
        return cls(id=check_id, name=CHECK_NAMES[check_id], passed=True, detail=detail)

    @classmethod
    def failed(
        cls, check_id: int, reason_code: ReasonCode, **detail: Any
    ) -> "CheckResult":
        return cls(
            id=check_id,
            name=CHECK_NAMES[check_id],
            passed=False,
            reason_code=reason_code,
            detail=detail,
        )

    @property
    def decision_on_fail(self) -> Decision:
        return ON_FAIL[self.id]

    def as_entry(self) -> dict[str, Any]:
        """The ``{id, name, result}`` shape SPEC.md §07 puts in the response."""
        return {
            "id": self.id,
            "name": self.name,
            "result": "pass" if self.passed else "fail",
        }


#: A check. Pure, total, and it never raises: a check that could raise would
#: turn a policy denial into a 500, and a 500 is not a decision.
Check = Callable[[CheckContext], CheckResult]
