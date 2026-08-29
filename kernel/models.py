"""The frozen data model, SPEC.md §05.

Signed by the user: IntentMandate, CartMandate.
Written only by the kernel: SpendLedger, IdempotencyRecord, AuditEntry,
Payment, Refund.
Sent by the agent: PaymentRequest.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, StringConstraints, model_validator

from kernel.base import (
    B64u,
    closed_enum,
    CartId,
    Currency,
    IntentId,
    Nonce,
    Paise,
    PaymentId,
    PubKey,
    RefundId,
    Rfc3339,
    Sha256,
    StrictModel,
    Token,
)
from kernel.canonical import cart_hash as compute_cart_hash
from kernel.enums import (
    ActionType,
    AuditAction,
    AuditActor,
    AuthMethod,
    ConfirmedBy,
    IdempotencyState,
    LedgerState,
    MandateState,
    PayeeType,
    PaymentState,
    RefundKind,
    RefundState,
)

#: Closed enums, readable from JSON but not wider for it — see
#: :func:`kernel.base.closed_enum`.
ActionTypeField = closed_enum(ActionType)
AuditActionField = closed_enum(AuditAction)
AuditActorField = closed_enum(AuditActor)
AuthMethodField = closed_enum(AuthMethod)
ConfirmedByField = closed_enum(ConfirmedBy)
IdempotencyStateField = closed_enum(IdempotencyState)
LedgerStateField = closed_enum(LedgerState)
MandateStateField = closed_enum(MandateState)
PayeeTypeField = closed_enum(PayeeType)
PaymentStateField = closed_enum(PaymentState)
RefundKindField = closed_enum(RefundKind)
RefundStateField = closed_enum(RefundState)

__all__ = [
    "Account",
    "Payee",
    "LineItem",
    "Principal",
    "AgentRef",
    "IntentScope",
    "IntentMandate",
    "Instrument",
    "CartMandate",
    "RequestParams",
    "PaymentRequest",
    "SpendLedger",
    "IdempotencyRecord",
    "AuditEntry",
    "Payment",
    "Refund",
]


class Account(StrictModel):
    """Somewhere money can sit. Two fields, both exact-match compared."""

    type: PayeeTypeField
    value: Token


class Payee(Account):
    """Where the money goes. Check 2 compares this byte for byte."""

    merchant_id: Token


class LineItem(StrictModel):
    """Merchant provenance is allowed here, and only here.

    ``sku`` is the one field on the whole model that a merchant's response
    populates, which is why it is a bounded token: a SKU cannot be a sentence.
    """

    sku: Token
    qty: Annotated[int, Field(ge=1, le=10_000)]
    unit_amount: Paise


class Principal(StrictModel):
    user_id: Token
    auth: AuthMethodField


class AgentRef(StrictModel):
    agent_id: Token
    pubkey: PubKey


class IntentScope(StrictModel):
    """The whole of what a sentence bought.

    Everything here is a ceiling or an allowlist. There is no field an agent
    can widen, because widening is a new mandate, never an edit to this one.
    """

    max_amount: Paise
    per_txn_cap: Paise
    currency: Currency
    allowed_payees: Annotated[list[Account], Field(min_length=1, max_length=32)]
    allowed_categories: Annotated[list[Token], Field(max_length=32)]
    max_transactions: Annotated[int, Field(ge=1, le=1000)]
    recurring: bool

    @model_validator(mode="after")
    def _cap_within_ceiling(self) -> "IntentScope":
        if self.per_txn_cap > self.max_amount:
            raise ValueError(
                "per_txn_cap above max_amount; a per-transaction cap that "
                "exceeds the lifetime ceiling is not a cap"
            )
        return self


class IntentMandate(StrictModel):
    """What the user authorised, bound to the sentence they said."""

    mandate_id: IntentId
    issued_at: Rfc3339
    expires_at: Rfc3339
    nonce: Nonce
    principal: Principal
    agent: AgentRef
    utterance_hash: Sha256
    scope: IntentScope
    sig: B64u

    @model_validator(mode="after")
    def _window_is_forward(self) -> "IntentMandate":
        if self.expires_at <= self.issued_at:
            # Lexicographic comparison is chronological for this timestamp form.
            raise ValueError("expires_at is not after issued_at")
        return self


class Instrument(StrictModel):
    """A scoped payment token, modelled on ACP. Not a real credential vault."""

    token: Token
    max_amount: Paise
    expires_at: Rfc3339


class CartMandate(StrictModel):
    """The exact thing being bought, hashed to what the user saw."""

    mandate_id: CartId
    parent: IntentId
    payee: Payee
    line_items: Annotated[list[LineItem], Field(min_length=1, max_length=64)]
    total_amount: Paise
    currency: Currency
    cart_hash: Sha256
    instrument: Instrument
    confirmed_by: ConfirmedByField
    sig: B64u

    def recompute_cart_hash(self) -> str:
        """The hash this cart's contents actually imply.

        Check 4's first conjunct is ``recompute_cart_hash() == cart_hash``.
        The schema deliberately does *not* enforce that: a cart whose stated
        hash disagrees with its contents has to be constructible, or the
        tampering case could never be tested.
        """
        return compute_cart_hash(
            [item.model_dump(mode="json") for item in self.line_items],
            self.total_amount,
            self.payee.model_dump(mode="json"),
        )

    def line_item_total(self) -> int:
        return sum(item.qty * item.unit_amount for item in self.line_items)


class RequestParams(StrictModel):
    amount: Paise
    original_payment_id: PaymentId | None = None


class PaymentRequest(StrictModel):
    """The action envelope the agent sends.

    There is deliberately no refund destination field. A destination the agent
    can name is a destination merchant copy can redirect; check 8 reads the
    destination from the ledger's recorded payment source instead (class A7).
    """

    action: ActionTypeField
    intent: IntentMandate
    cart: CartMandate
    params: RequestParams
    #: Advisory only. Expiry is judged by the kernel's clock, never by this —
    #: an agent-supplied clock would defeat check 1 by lying about the hour.
    client_ts: Rfc3339


class SpendLedger(StrictModel):
    """One row per intent. Authority and money position, tracked separately."""

    mandate_id: IntentId
    #: Kernel-written, never parsed from an agent body — the "no free text"
    #: rule binds the request schemas, not the kernel's own records.
    intent_json: str
    confirmed_cart_hash: Sha256 | None = None
    execution_count: Annotated[int, Field(ge=0)] = 0
    committed_paise: Paise = 0
    captured_paise: Paise = 0
    refunded_paise: Paise = 0
    mandate_state: MandateStateField = MandateState.ACTIVE
    ledger_state: LedgerStateField = LedgerState.EMPTY

    @model_validator(mode="after")
    def _money_ordering(self) -> "SpendLedger":
        # P-03. A negative or out-of-order value is a bug, not a state.
        if not (self.refunded_paise <= self.captured_paise <= self.committed_paise):
            raise ValueError(
                "ledger invariant broken: refunded <= captured <= committed"
            )
        return self


class IdempotencyRecord(StrictModel):
    """One reservation, and everything recovery needs to resolve it alone.

    The last five fields are the recovery context. A scan runs with no request
    — the process that held it died — and the key is a hash, so nothing about
    the action can be recovered from the key itself. What was not written down
    at reserve time is not available at recovery time.
    """

    key: Sha256
    action: ActionTypeField
    state: IdempotencyStateField
    result_json: str | None = None
    reserved_at: Rfc3339
    committed_at: Rfc3339 | None = None
    mandate_id: IntentId
    cart_hash: Sha256
    amount_paise: Paise
    #: What the recovery scan polls the PSP by. After a crash it is the only
    #: identifier the kernel is certain it had.
    client_ref: Token
    #: Refunds only: the payment being reversed.
    payment_id: PaymentId | None = None


class AuditEntry(StrictModel):
    """One row of the chain. Hashed by :mod:`kernel.audit.chain`."""

    seq: Annotated[int, Field(ge=0)]
    ts: Rfc3339
    actor: AuditActorField
    action: AuditActionField
    payload: dict
    prev_hash: Sha256
    entry_hash: Sha256


class Payment(StrictModel):
    payment_id: PaymentId
    mandate_id: IntentId
    cart_hash: Sha256
    #: The only source of truth for a refund destination. Check 8 reads here.
    source: Account
    amount_paise: Paise
    currency: Currency
    state: PaymentStateField
    client_ref: Token


class Refund(StrictModel):
    refund_id: RefundId
    payment_id: PaymentId
    amount_paise: Paise
    #: Copied from ``payment.source``, never from the request.
    destination: Account
    kind: RefundKindField
    state: RefundStateField
    idempotency_key: Sha256
