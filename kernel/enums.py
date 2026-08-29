"""Closed enums. Every one of these is exhaustive by design.

An open enum is a place an attacker can put a value nobody wrote a branch for.
Reason codes and audit actions in particular are closed because the results
table counts them: a reason code that can be invented is a row that can be
invented.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "Decision",
    "ActionType",
    "ReasonCode",
    "AuditActor",
    "AuditAction",
    "AuthMethod",
    "PayeeType",
    "ConfirmedBy",
    "MandateState",
    "LedgerState",
    "PaymentState",
    "RefundState",
    "RefundKind",
    "IdempotencyState",
]


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    # A third outcome, not a flavour of deny: the request may be legitimate and
    # a human can mint fresh authority for it. Never escalate to the model.
    ESCALATE = "escalate"


class ActionType(StrEnum):
    AUTHORIZE = "authorize"
    CAPTURE = "capture"
    REFUND = "refund"
    MANDATE_CREATE = "mandate.create"


class ReasonCode(StrEnum):
    OK = "OK"
    SIG_INVALID = "SIG_INVALID"
    MANDATE_EXPIRED = "MANDATE_EXPIRED"
    NONCE_REPLAYED = "NONCE_REPLAYED"
    PAYEE_NOT_ALLOWED = "PAYEE_NOT_ALLOWED"
    AMOUNT_EXCEEDS_SCOPE = "AMOUNT_EXCEEDS_SCOPE"
    LINE_ITEM_SUM_MISMATCH = "LINE_ITEM_SUM_MISMATCH"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    CART_HASH_MISMATCH = "CART_HASH_MISMATCH"
    RECURRENCE_NOT_AUTHORISED = "RECURRENCE_NOT_AUTHORISED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"
    REFUND_DESTINATION_MISMATCH = "REFUND_DESTINATION_MISMATCH"
    TAINT_VIOLATION = "TAINT_VIOLATION"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"


class AuditActor(StrEnum):
    USER = "user"
    AGENT = "agent"
    KERNEL = "kernel"
    PSP = "psp"


class AuditAction(StrEnum):
    """Closed. Two members extend SPEC.md §07's list, and both are there
    because the alternative was recording an event that did not happen.

    ``authorize.replayed`` — the spec named ``capture.replayed`` and
    ``refund.replayed`` and stopped. An authorize *is* replayable (two carts
    with different ids and identical contents share an idempotency key, and the
    second one replays the first), so without this name the only options were
    to file it under ``refund.replayed`` — putting a refund in the results
    table for a run that refunded nothing — or to leave a money-adjacent replay
    unrecorded. Both are worse than one more name.

    ``webhook.refused`` — a backwards delivery is neither ingested nor
    deduped. Dedup means "I already have this outcome"; a webhook claiming
    ``authorized`` after ``captured`` is claiming something that cannot have
    happened, which is a finding rather than a duplicate. Collapsing the two
    would make F-08 invisible in the chain, and F-08 is one of the failures the
    suite exists to show.
    """

    INTENT_REGISTERED = "intent.registered"
    AUTHORIZE_ALLOW = "authorize.allow"
    AUTHORIZE_DENY = "authorize.deny"
    AUTHORIZE_REPLAYED = "authorize.replayed"
    CAPTURE_ALLOW = "capture.allow"
    CAPTURE_DENY = "capture.deny"
    CAPTURE_REPLAYED = "capture.replayed"
    REFUND_ALLOW = "refund.allow"
    REFUND_DENY = "refund.deny"
    REFUND_REPLAYED = "refund.replayed"
    MANDATE_CREATE_DENY = "mandate.create.deny"
    ESCALATION_OPENED = "escalation.opened"
    ESCALATION_RESOLVED = "escalation.resolved"
    WEBHOOK_INGESTED = "webhook.ingested"
    WEBHOOK_DEDUPED = "webhook.deduped"
    WEBHOOK_REFUSED = "webhook.refused"
    RECOVERY_RECONCILED = "recovery.reconciled"
    KERNEL_FAIL_CLOSED = "kernel.fail_closed"


class AuthMethod(StrEnum):
    DEVICE_BIOMETRIC = "device_biometric"
    PIN = "pin"


class PayeeType(StrEnum):
    VPA = "vpa"
    BANK_ACCOUNT = "bank_account"
    CARD_TOKEN = "card_token"


class ConfirmedBy(StrEnum):
    USER = "user"
    AUTO_WITHIN_INTENT_SCOPE = "auto_within_intent_scope"


class MandateState(StrEnum):
    """Authority. All three terminal states absorb; there is no widening edge."""

    ACTIVE = "active"
    EXHAUSTED = "exhausted"
    REVOKED = "revoked"
    EXPIRED = "expired"


class LedgerState(StrEnum):
    """Money position, which terminates independently of authority."""

    EMPTY = "empty"
    COMMITTED = "committed"
    CAPTURED = "captured"
    PARTIALLY_REFUNDED = "partially_refunded"
    FULLY_REFUNDED = "fully_refunded"


class PaymentState(StrEnum):
    CREATED = "created"
    AUTHORIZED = "authorized"
    CAPTURED = "captured"
    FAILED = "failed"
    VOIDED = "voided"
    REVERSED = "reversed"


class RefundState(StrEnum):
    CREATED = "created"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"


class RefundKind(StrEnum):
    FULL = "full"
    PARTIAL = "partial"


class IdempotencyState(StrEnum):
    """Three states, because "reserved but outcome unknown" is a real position."""

    IN_FLIGHT = "in_flight"
    RECOVERING = "recovering"
    TERMINAL = "terminal"
