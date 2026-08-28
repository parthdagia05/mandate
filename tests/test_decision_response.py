"""The decision response, and the closed enums it is made of.

SPEC.md §07 fixes both the shape and the vocabulary. The vocabulary is the part
worth testing hardest: **a reason code that can be invented is a results-table
row that can be invented.** The whole point of publishing an ASR broken down by
reason code is that the codes are enumerable in advance, so the enum is
asserted against the spec's list here rather than being trusted to have stayed
in step.
"""

from __future__ import annotations

import json

import pydantic
import pytest

from kernel.decision import DecisionResponse
from kernel.enums import AuditAction, Decision, ReasonCode
from tests.kernel_bench import Bench

#: SPEC.md §07, transcribed. If this list and the enum disagree, one of them
#: moved without the other, and the test says which.
SPEC_REASON_CODES = {
    "OK",
    "SIG_INVALID",
    "MANDATE_EXPIRED",
    "NONCE_REPLAYED",
    "PAYEE_NOT_ALLOWED",
    "AMOUNT_EXCEEDS_SCOPE",
    "LINE_ITEM_SUM_MISMATCH",
    "CURRENCY_MISMATCH",
    "CART_HASH_MISMATCH",
    "RECURRENCE_NOT_AUTHORISED",
    "BUDGET_EXHAUSTED",
    "IDEMPOTENT_REPLAY",
    "REFUND_DESTINATION_MISMATCH",
    "TAINT_VIOLATION",
    "STORE_UNAVAILABLE",
}

SPEC_AUDIT_ACTIONS = {
    "intent.registered",
    "authorize.allow",
    "authorize.deny",
    "capture.allow",
    "capture.deny",
    "capture.replayed",
    "refund.allow",
    "refund.deny",
    "refund.replayed",
    "mandate.create.deny",
    "escalation.opened",
    "escalation.resolved",
    "webhook.ingested",
    "webhook.deduped",
    "recovery.reconciled",
    "kernel.fail_closed",
}


def test_the_reason_code_enum_is_exactly_the_spec_list():
    assert {member.value for member in ReasonCode} == SPEC_REASON_CODES


def test_the_audit_action_enum_is_exactly_the_spec_list():
    assert {member.value for member in AuditAction} == SPEC_AUDIT_ACTIONS


def test_the_decision_enum_has_three_members_and_escalate_is_one_of_them():
    """Escalation is a third outcome, not a flavour of deny.

    A denial says no authority can exist for this request. An escalation says a
    human could mint some — and it goes to a human, never back to the model.
    """
    assert {member.value for member in Decision} == {"allow", "deny", "escalate"}


def test_an_invented_reason_code_is_refused(bench: Bench):
    with pytest.raises(pydantic.ValidationError):
        DecisionResponse.model_validate(
            {
                "decision": "deny",
                "action": "authorize",
                "mandate_id": bench.intent["mandate_id"],
                "checks": [],
                "reason_code": "PAYEE_PROBABLY_FINE",
            }
        )


def test_an_invented_decision_is_refused(bench: Bench):
    with pytest.raises(pydantic.ValidationError):
        DecisionResponse.model_validate(
            {
                "decision": "allow_with_warning",
                "action": "authorize",
                "mandate_id": bench.intent["mandate_id"],
                "checks": [],
                "reason_code": "OK",
            }
        )


# --- the shape ------------------------------------------------------------


def test_an_allow_carries_every_field_the_spec_names(bench: Bench):
    bench.register()
    body = bench.authorize().body

    assert body["decision"] == "allow"
    assert body["action"] == "authorize"
    assert body["mandate_id"].startswith("im_")
    assert body["cart_id"].startswith("cm_")
    assert body["reason_code"] == "OK"
    assert body["denied_by"] == []
    assert body["replayed"] is False
    assert body["idempotency_key"].startswith("sha256:")
    assert body["audit"]["entry_hash"].startswith("sha256:")
    assert body["audit"]["prev_hash"].startswith("sha256:")
    assert isinstance(body["audit"]["seq"], int)
    assert body["latency_us"] >= 0


def test_the_checks_array_lists_every_evaluated_check_including_passes(bench: Bench):
    """The ablation table is only readable because passes are recorded.

    "Check 2 refused" and "checks 1 and 2 ran, 2 refused" are different facts,
    and only the second says what was still being enforced.
    """
    bench.register()
    body = bench.authorize().body
    assert [c["id"] for c in body["checks"]] == [1, 2, 3, 4, 5, 6, 7, 9]
    assert {c["result"] for c in body["checks"]} == {"pass"}

    names = {c["id"]: c["name"] for c in body["checks"]}
    assert names[2] == "payee_allowlist"
    assert names[9] == "audit_append"


def test_a_denial_names_the_check_that_refused(bench: Bench):
    bench.register()
    body = bench.authorize(
        bench.agent_cart(
            payee={**bench.confirmed_cart["payee"], "value": "attacker@upi"}
        )
    ).body

    assert body["denied_by"] == [2]
    assert body["reason_code"] == "PAYEE_NOT_ALLOWED"
    assert [(c["id"], c["result"]) for c in body["checks"]] == [
        (1, "pass"),
        (2, "fail"),
        (9, "pass"),
    ]


def test_an_escalation_opens_its_own_audit_entry(bench: Bench):
    bench.register()
    bench.authorize(
        bench.agent_cart(
            payee={**bench.confirmed_cart["payee"], "value": "attacker@upi"}
        )
    )
    opened = [e for e in bench.service.chain.read() if e.action == "escalation.opened"]

    assert opened, "an escalation nobody recorded is not an escalation"
    assert opened[-1].payload["reason_code"] == "PAYEE_NOT_ALLOWED"
    assert "never to the model" in opened[-1].payload["note"]


# --- what must never be in a response or a payload -----------------------


def test_no_signature_bytes_reach_the_audit_chain(bench: Bench):
    """ECDSA is not deterministic, so a hashed signature would break D-01.

    The chain refuses one outright rather than stripping it, because a caller
    that put a signature in a payload has misunderstood something and silently
    dropping it would hide that.
    """
    bench.buy()
    for entry in bench.service.chain.read():
        serialised = json.dumps(entry.payload)
        assert "sig" not in entry.payload
        assert bench.intent["sig"] not in serialised


def test_the_measured_latency_never_enters_the_chain(bench: Bench):
    """Response-only. Two runs of one seed produce byte-identical chains, and a
    microsecond count is the fastest way to lose that."""
    bench.buy()
    for entry in bench.service.chain.read():
        assert "latency_us" not in json.dumps(entry.payload)
