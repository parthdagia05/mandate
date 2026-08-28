"""The wire format: what the kernel is asked, and what it answers.

Every body on :mod:`kernel.api` is one of these models, and every one of them
inherits :class:`~kernel.base.StrictModel` — ``extra="forbid"``,
``strict=True``, frozen, and built entirely out of the bounded scalar types in
:mod:`kernel.base`. **There is no free-text field anywhere in this module.**
That is the anti-prompt property, and it is a property of the schema rather
than of a filter: an injection cannot reach the kernel's parser because every
string field is a token with no whitespace, so there is nowhere to put a
sentence. ``tests/test_api_fuzz.py`` posts prose into every field of every
endpoint and requires 422.

The decision response is deliberately verbose. It carries **every check that
was evaluated, passes included** — not only the one that refused. That is what
makes the per-check ablation readable and what lets ``mk explain`` say which
predicates were still standing when a request got through.

``latency_us`` is the one field that is not a function of the seed. It is in
the response and never in the audit payload; see :mod:`kernel.latency`.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from kernel.base import (
    CartId,
    IntentId,
    PaymentId,
    Sha256,
    StrictModel,
    Token,
    closed_enum,
)
from kernel.enums import ActionType, Decision, PaymentState, ReasonCode
from kernel.models import CartMandate, IntentMandate, PaymentRequest

__all__ = [
    "DecisionField",
    "ReasonCodeField",
    "IntentRegistration",
    "WebhookIngest",
    "CheckEntry",
    "AuditRef",
    "DecisionResponse",
]

DecisionField = closed_enum(Decision)
ReasonCodeField = closed_enum(ReasonCode)
ActionField = closed_enum(ActionType)
PaymentStateField = closed_enum(PaymentState)


class IntentRegistration(StrictModel):
    """``POST /v1/intent/register`` — the only call that mints a ledger row.

    It carries the **user-confirmed cart** as well as the intent, and that is
    not redundancy. ``confirmed_cart_hash`` is what check 4's second conjunct
    compares against, so it has to arrive as something the user signed. A plain
    ``confirmed_cart_hash`` field would be a hash the agent chooses, and check 4
    would then be comparing a request to itself.
    """

    intent: IntentMandate
    #: Must be ``confirmed_by: user`` and carry the principal's own signature.
    #: The kernel records ``cart.cart_hash`` and nothing else from it.
    confirmed_cart: CartMandate


class WebhookIngest(StrictModel):
    """``POST /v1/webhook/ingest`` — a PSP callback, reconciled against the ledger.

    Typed to the point of boredom: an event id, a payment id, a claimed state
    and an amount. A real PSP body carries more, and none of the rest is
    anything the kernel is allowed to believe — the dedup key is
    ``(mandate_id, cart_hash)`` from the kernel's own payment row, not anything
    in here.
    """

    event_id: Token
    event: Token
    payment_id: PaymentId
    state: PaymentStateField
    amount_paise: Annotated[int, Field(ge=0)]


class CheckEntry(StrictModel):
    """One row of the ``checks`` array: ``{id, name, result}``."""

    id: Annotated[int, Field(ge=1, le=9)]
    name: Token
    result: Token


class AuditRef(StrictModel):
    """Where in the chain this decision is recorded.

    Present on every 200. A decision the caller cannot locate in the chain is a
    decision the caller has to take our word for.
    """

    seq: Annotated[int, Field(ge=0)]
    entry_hash: Sha256
    prev_hash: Sha256


class DecisionResponse(StrictModel):
    """SPEC.md §07's decision response, exactly.

    ``allow``, ``deny`` and ``escalate`` are all HTTP 200: a policy denial is
    not an HTTP error, and returning 403 for one would make every results
    table's denial column indistinguishable from a broken deployment.
    """

    decision: DecisionField
    action: ActionField
    mandate_id: IntentId
    cart_id: CartId | None = None
    checks: list[CheckEntry]
    #: The check numbers that refused. A list because the shape has to hold
    #: when a later milestone evaluates checks in parallel; today, at most one.
    denied_by: list[Annotated[int, Field(ge=1, le=9)]] = Field(default_factory=list)
    reason_code: ReasonCodeField
    idempotency_key: Sha256 | None = None
    replayed: bool = False
    audit: AuditRef | None = None
    #: Non-deterministic by construction, and therefore response-only. It is
    #: never hashed and never enters an audit payload.
    latency_us: Annotated[int, Field(ge=0)] = 0
    #: The PSP payment this decision produced, when it produced one. Present
    #: only on ``allow``.
    payment: dict[str, Any] | None = None

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


__all__ += ["PaymentRequest"]
