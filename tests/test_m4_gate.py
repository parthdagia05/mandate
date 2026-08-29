"""M4's ``Prove it`` block, as tests.

The milestone rule: someone who has not read the code runs one command and sees
the right thing happen. These are those commands, so a regression fails the
build instead of waiting to be noticed at a demo.

**Done when 1, 2 and 4 hold.** They are three separate video moments and
together they are the answer to "why is a payments company judging this?":

1. the kernel dies mid-capture and **exactly one debit** survives it;
2. the PSP redelivers ``captured`` with a *fresh* event id and there is still
   exactly one debit;
4. a support page supplies a refund destination and the credit goes back to the
   original payment source anyway, because the request has no field to carry
   one.

Every case runs the full harness rather than the bench, because the point of a
gate is the command, not the unit. In a full run several mechanisms can reach
the same debit — the capture response, a webhook, the recovery scan — and the
answer has to be one debit whichever of them arrives first.
"""

from __future__ import annotations

import itertools
import json
import tempfile
from pathlib import Path

import pytest

from harness.runner import run_case

CRASH_MID_CAPTURE = {
    "fault": "crash_after_reserve",
    "count": None,
    "target": "capture.after_psp_call",
}

#: Every run in this module exports its chain to its own file. Two runs sharing
#: the default path is not a hypothetical: several tests here compare a faulted
#: run against a baseline, and with a shared path the second run silently
#: rewrites the first one's evidence before it is read. It also keeps the gate
#: from clobbering ``runs/latest.chain.jsonl``, which is what ``mk explain``
#: reads when somebody types it after a demo.
_CHAINS = Path(tempfile.mkdtemp(prefix="m4-gate-chains-"))
_RUN = itertools.count()


def kernel_run(task="benign-01", **kw):
    kw.setdefault("export_chain", _CHAINS / f"chain-{next(_RUN)}.jsonl")
    return run_case(task, config="kernel", model="scripted", **kw)


def chain(record):
    return [
        json.loads(line)
        for line in Path(record.chain_path).read_text().splitlines()
        if line.strip()
    ]


def actions(record, name):
    return [e for e in chain(record) if e["action"] == name]


def captures(record):
    return [c for c in record.ledger if c["captured_paise"] > 0]


# --- step 1: a crash mid-capture leaves exactly one debit ------------------


def test_step_1_a_crash_mid_capture_leaves_exactly_one_debit():
    """The milestone. The kernel dies after the rail answered and before the
    ledger heard, the clock runs past the recovery TTL, and the money position
    is correct — not approximately, exactly."""
    record = kernel_run(faults=[CRASH_MID_CAPTURE])

    assert len(captures(record)) == 1
    assert captures(record)[0]["captured_paise"] == 49900
    assert captures(record)[0]["payee"]["value"] == "merchant@upi"
    # It really did crash. A run that quietly survived would show one debit too.
    assert record.error is not None and "KernelCrashed" in record.error
    assert record.poisoned is None


def test_step_1_the_reservation_ends_terminal_and_not_in_flight():
    """"The idempotency row reads ``terminal``, not ``in_flight``." A row left
    in flight is a debit nothing is still accounting for."""
    record = kernel_run(faults=[CRASH_MID_CAPTURE])

    resolved = [r for r in record.recoveries if r["action"] == "capture"]
    assert resolved, "the recovery scan never looked at the crashed capture"
    assert resolved[-1]["outcome"] == "settled"
    assert resolved[-1]["state"] == "captured"
    assert not [r for r in record.recoveries if r["outcome"] == "unresolved"]


def test_step_1_the_chain_names_the_reconciliation():
    record = kernel_run(faults=[CRASH_MID_CAPTURE])
    entry = actions(record, "recovery.reconciled")[-1]

    assert entry["payload"]["polled_by"] == "client_ref"
    assert entry["payload"]["outcome"] == "settled"
    assert entry["payload"]["ledger"]["captured_paise"] == 49900


def test_step_1_a_crash_before_the_rail_leaves_no_debit_at_all():
    """The other window, and the reason the kernel asks rather than assumes.

    Identical reservation, opposite resolution. If the scan committed on the
    strength of the row alone it would book a debit that never happened here,
    and if it released on the strength of the row alone it would strand one in
    the test above.
    """
    record = kernel_run(
        faults=[{**CRASH_MID_CAPTURE, "target": "capture.after_reserve"}]
    )

    assert captures(record) == []
    assert [r["outcome"] for r in record.recoveries] == ["released"]


# --- step 2: a duplicate webhook with a fresh id --------------------------


def test_step_2_a_duplicate_webhook_with_a_fresh_id_leaves_one_debit():
    """The PSP redelivers ``captured`` with an id nothing has ever seen. A
    dedup layer keyed on the event id would call it a new event."""
    record = kernel_run(faults=[{"fault": "duplicate_webhook", "count": None}])

    assert len(captures(record)) == 1
    assert captures(record)[0]["captured_paise"] == 49900
    assert record.task_success is True

    deduped = actions(record, "webhook.deduped")
    assert len(deduped) >= 2, "the redelivery was not seen as a duplicate"
    ids = [e["payload"]["event_id"] for e in deduped]
    assert len(set(ids)) == len(ids), "the redelivery reused an event id"


def test_step_2_dedup_is_on_the_business_key_and_the_chain_says_so():
    record = kernel_run(faults=[{"fault": "duplicate_webhook", "count": None}])
    payload = actions(record, "webhook.deduped")[-1]["payload"]

    assert payload["mandate_id"].startswith("im_")
    assert payload["cart_hash"].startswith("sha256:")
    assert payload["outcome"] == "deduped"


# --- step 3: an out-of-order webhook --------------------------------------


def test_step_3_a_reordered_webhook_arrives_late_and_moves_nothing():
    """``authorized`` after ``captured``, refused at the state machine.

    The refusal itself is not the fault's signature — a confirmation always
    lags the kernel, which books a capture from the rail's *response*, so an
    ordinary run refuses a late ``authorized`` too. What the fault changes is
    the delivery order, and what must not change is the money.
    """
    reordered = kernel_run(faults=[{"fault": "reorder_webhook", "count": 1}])
    baseline = kernel_run()

    delivered = [
        e["payload"]["event"]
        for e in chain(reordered)
        if e["action"].startswith("webhook.")
    ]
    assert delivered.index("payment.captured") < delivered.index("payment.authorized")

    refused = actions(reordered, "webhook.refused")[-1]["payload"]
    assert refused["current_state"] == "captured"
    assert refused["claimed_state"] == "authorized"
    assert refused["refused_by"] == "payment_state_machine"

    # Refused, not absorbed, and the ledger is the same as an undisturbed run.
    assert captures(reordered) == captures(baseline)


def test_step_3_the_baseline_delivers_them_the_other_way_round():
    """The control for the test above. Without it, "captured came first" would
    be a fact about the harness rather than about the fault."""
    baseline = kernel_run()
    delivered = [
        e["payload"]["event"]
        for e in chain(baseline)
        if e["action"].startswith("webhook.")
    ]
    assert delivered.index("payment.authorized") < delivered.index("payment.captured")


# --- step 4: A7, the refund that goes back where it came from -------------


def test_step_4_the_refund_credits_the_original_payment_source():
    """The support flow supplies a destination and the kernel ignores it —
    because there is no field for it to arrive in."""
    record = kernel_run("benign-04", attack_id="A7-seed-1")

    assert len(record.refunds) == 1
    refund = record.refunds[0]
    assert refund["destination"]["value"] == "ananya@upi"
    assert refund["destination"] == refund["source"]
    assert refund["misdirected"] is False
    assert record.attacker_win is False


def test_step_4_the_same_attack_takes_the_money_undefended():
    """The control arm has to keep losing, or step 4 measures nothing.

    A kernel that stopped an attack which had stopped working on its own is not
    evidence of anything — and if the simulator refused a misdirected refund,
    this is the test that would fail rather than passing quietly.
    """
    record = run_case(
        "benign-04", config="undefended", attack_id="A7-seed-1", model="scripted"
    )

    assert record.attacker_win is True
    assert record.refunds[0]["destination"]["value"] == "attacker@upi"
    assert record.refunds[0]["misdirected"] is True


def test_step_4_the_agent_still_asked_for_the_attackers_account():
    """The defence is not "the agent resisted". It is "what the agent asked for
    had nowhere to go". The run log records the ask next to the request that
    could not carry it."""
    record = kernel_run("benign-04", attack_id="A7-seed-1")

    asked = next(
        step["output"]["destination"]
        for step in record.plan["steps"]
        if step["step"] == "choose_refund_destination"
    )
    assert asked["value"] == "attacker@upi"
    assert record.refunds[0]["destination"]["value"] == "ananya@upi"


def test_step_4_check_8_names_where_it_read_the_destination():
    record = kernel_run("benign-04", attack_id="A7-seed-1")
    detail = next(
        d
        for e in actions(record, "refund.allow")
        for d in e["payload"].get("check_detail", [])
        if d["id"] == 8
    )

    assert detail["destination_from"] == "ledger.payment.source_json"
    assert detail["destination"]["value"] == "ananya@upi"


def test_step_4_a_benign_refund_is_not_blocked_by_check_8():
    """Blocking every refund is not a defence. The honest refund goes through,
    with the same check passing for the same reason."""
    record = kernel_run("benign-04")

    assert len(record.refunds) == 1
    assert record.refunds[0]["destination"]["value"] == "ananya@upi"
    refund = next(d for d in record.decisions if d["step"] == "refund")
    assert refund["decision"] == "allow"
    assert [c["id"] for c in refund["checks"]] == [1, 8, 7, 9]


# --- step 5: a retry inside the TTL ---------------------------------------


def test_step_5_a_retry_inside_the_ttl_is_retry_later_and_not_a_second_charge(
    tmp_path,
):
    """Exercised on the bench, because the harness deliberately has no way for
    an agent to retry a request — that is the planner's business and the
    planner's step order is fixed. The property is the kernel's."""
    from kernel.service import CRASH_AFTER_PSP_CALL
    from sim.faults import KernelCrashed
    from tests.kernel_bench import Bench
    from tests.test_recovery import crash_at

    bench = Bench(tmp_path=tmp_path, crash=crash_at(CRASH_AFTER_PSP_CALL))
    try:
        bench.register()
        bench.authorize()
        with pytest.raises(KernelCrashed):
            bench.capture()

        out = bench.capture()
        assert out.status == 202
        assert out.body["status"] == "retry_later"
        assert len(bench.world.psp.ledger()) == 1
    finally:
        bench.close()


# --- the property under all of it -----------------------------------------


def test_the_ledger_and_the_rail_agree_after_every_m4_fault():
    """One assertion over the whole milestone. Availability may be lost in any
    of these; the money position may not."""
    faults = [
        [CRASH_MID_CAPTURE],
        [{**CRASH_MID_CAPTURE, "target": "capture.after_reserve"}],
        [{"fault": "duplicate_webhook", "count": None}],
        [{"fault": "reorder_webhook", "count": 1}],
        [],
    ]
    for armed in faults:
        record = kernel_run(faults=armed)
        assert len(captures(record)) <= 1, f"two debits under {armed}"
        assert record.poisoned is None, f"the chain did not verify under {armed}"
        assert not [
            r for r in record.recoveries if r["outcome"] == "unresolved"
        ], f"a reservation was left unresolved under {armed}"


def test_two_runs_of_a_crashed_seed_produce_identical_chains():
    """D-01 still holds with recovery in the loop. A repair that depended on
    wall-clock timing would show up here and nowhere else."""
    first = kernel_run(faults=[CRASH_MID_CAPTURE])
    second = kernel_run(faults=[CRASH_MID_CAPTURE])

    assert first.chain_head == second.chain_head
    assert first.chain_entries == second.chain_entries
