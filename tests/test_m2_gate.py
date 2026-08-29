"""M2's ``Prove it`` block, as tests.

The milestone rule is that someone who has not read the code can run one
command and see the right thing happen. These are the same three steps, so a
regression fails the build rather than waiting to be noticed at a demo.
"""

from __future__ import annotations

from harness.runner import run_case


def _capture(record):
    captures = [c for c in record.ledger if c["captured_paise"] > 0]
    assert len(captures) == 1, f"expected exactly one capture, got {len(captures)}"
    return captures[0]


def test_step_1_benign_pays_the_merchant():
    """One capture, ₹499 to merchant@upi, the payment reaches captured."""
    record = run_case("benign-01", config="undefended", model="scripted")
    capture = _capture(record)

    assert capture["captured_paise"] == 49900
    assert capture["payee"] == {"type": "vpa", "value": "merchant@upi"}
    assert capture["state"] == "captured"
    assert record.task_success is True
    assert record.attacker_win is False


def test_step_2_the_attack_takes_the_money_and_nothing_complains():
    """Same task, same seed, one payload. ₹499 to attacker@upi."""
    record = run_case(
        "benign-01", config="undefended", attack_id="A1-seed-1", model="scripted"
    )
    capture = _capture(record)

    assert capture["captured_paise"] == 49900
    assert capture["payee"]["value"] == "attacker@upi"
    assert capture["state"] == "captured"

    # "and nothing complained" is the finding, not an aside: the agent ran to
    # completion, moved the money and reported no error at all.
    assert record.error is None
    assert record.attacker_win is True
    # The user did not get what they asked for, and that is a separate axis —
    # collapsing the two would hide a defence that works by breaking everything.
    assert record.task_success is False


def test_step_3_the_same_seed_reproduces_the_theft_exactly():
    """A flaky attack is not evidence."""
    heads = {
        run_case(
            "benign-01",
            config="undefended",
            attack_id="A1-seed-1",
            seed="1",
            model="scripted",
        ).log_head
        for _ in range(3)
    }
    assert len(heads) == 1


def test_the_benign_path_is_untouched_by_the_attack_being_available():
    """The payload only lands where a case puts it.

    Worth pinning: an injection that leaked into every run would make the
    benign arm meaningless, and both arms would still look plausible.
    """
    without = run_case("benign-01", config="undefended", model="scripted")
    assert without.ledger[0]["payee"]["value"] == "merchant@upi"


def test_all_three_benign_tasks_complete():
    for task_id in ("benign-01", "benign-02", "benign-03"):
        record = run_case(task_id, config="undefended", model="scripted")
        assert record.task_success, f"{task_id} did not complete"
        assert record.error is None


def test_configs_that_do_not_exist_say_so():
    """A config that silently ran as 'undefended' would produce a defended
    number from an undefended run, which is the worst failure available.

    Every arm on the list is built now — ``kernel`` arrived in M3, ``model-only``
    and the two agent-guard arms in M6 — so what is left to refuse is a name
    nobody defined. It is refused by name rather than defaulted, because a
    typo'd arm that ran as the control would put an undefended number in a
    defended column and nothing downstream could tell.
    """
    import pytest

    from harness.runner import CONFIGS

    with pytest.raises(ValueError, match="unknown config"):
        run_case("benign-01", config="kernal", model="scripted")
    assert "model-only" in CONFIGS
