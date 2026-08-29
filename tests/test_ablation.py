"""The per-check ablation. Issue #58.

Two things are being tested and they are different. One: the mechanism removes a
*predicate*, provably, rather than disturbing a code path — the evidence is the
evaluated prefix getting longer. Two: the resulting table is readable, which
here means the two questions ("necessary given the others?" and "sufficient on
its own?") are kept apart, because the checks overlap and only asking the first
would report almost every check as worthless.
"""

from __future__ import annotations

import pytest

from harness.matrix import ABLATABLE, run_ablation
from harness.metrics import asr_by_class
from harness.report import ablation_verdicts, render_ablation
from harness.runner import run_case
from kernel.checks import CHECK_NAMES


def test_a_disabled_check_is_absent_from_the_evaluated_prefix():
    """The evidence that the predicate was removed, not merely bypassed."""
    full = run_case(config="kernel", attack_id="A1-seed-1", model="scripted")
    ablated = run_case(
        config="kernel",
        attack_id="A1-seed-1",
        model="scripted",
        disabled_checks=(2,),
    )
    authorize_full = next(d for d in full.decisions if d["step"] == "authorize")
    authorize_ablated = next(d for d in ablated.decisions if d["step"] == "authorize")

    assert 2 in [c["id"] for c in authorize_full["checks"]]
    assert 2 not in [c["id"] for c in authorize_ablated["checks"]]
    assert len(authorize_ablated["checks"]) > len(authorize_full["checks"]), (
        "evaluation should get further once the refusing check is gone"
    )


def test_the_run_record_says_a_line_came_from_an_ablation():
    """A line produced with a check off must never be mistakable for one
    produced with all nine running."""
    record = run_case(
        config="kernel", attack_id="A1-seed-1", model="scripted", disabled_checks=(2,)
    )
    assert record.disabled_checks == [2]
    assert any("ablated" in note for note in record.notes)


def test_the_audit_chain_records_the_ablation():
    """A kernel running with a check switched off says so in its own record.

    Every claim in this project reduces to "the chain says so", and an ablation
    run whose chain looked like a real one would make that sentence false.
    """
    import json
    from pathlib import Path

    record = run_case(
        config="kernel", attack_id="A1-seed-1", model="scripted", disabled_checks=(2,)
    )
    entries = [
        json.loads(line)
        for line in Path(record.chain_path).read_text().splitlines()
        if line
    ]
    ablated = [e for e in entries if "ablated" in e["payload"]]
    assert ablated and ablated[0]["payload"]["ablated"] == [2]


def test_a_normal_run_carries_no_ablation_field():
    """Its presence is the flag, so a published run's chain is byte-identical
    to what it was before the ablation existed."""
    import json
    from pathlib import Path

    record = run_case(config="kernel", attack_id="A1-seed-1", model="scripted")
    entries = [
        json.loads(line)
        for line in Path(record.chain_path).read_text().splitlines()
        if line
    ]
    assert all("ablated" not in e["payload"] for e in entries)


def test_ablating_an_arm_with_no_kernel_is_refused():
    """A line labelled as an ablation that is byte-identical to the un-ablated
    one is a row in the table that means nothing."""
    with pytest.raises(ValueError, match="nothing to ablate"):
        run_case(config="undefended", attack_id="A1-seed-1", disabled_checks=(2,))


def test_the_lifecycle_steps_are_not_ablatable():
    """Checks 7 and 9 are not predicates. Removing the audit append leaves a run
    with no chain, and a run with no chain is discarded rather than scored."""
    assert 7 not in ABLATABLE and 9 not in ABLATABLE
    assert set(ABLATABLE) == set(CHECK_NAMES) - {7, 9}
    with pytest.raises(ValueError, match="lifecycle steps"):
        run_ablation(checks=(7,), model="scripted")


def test_an_unknown_check_cannot_be_ablated():
    from kernel.service import KernelService
    import inspect

    assert "disabled_checks" in inspect.signature(KernelService.__init__).parameters
    with pytest.raises(ValueError, match="cannot ablate"):
        run_ablation(checks=(42,), model="scripted")


@pytest.fixture(scope="module")
def small_ablation(tmp_path_factory):
    """One class, every mode. Small enough to run in the test suite and still
    exercise the shape the published table is rendered from."""
    return run_ablation(
        dataset="batch_a",
        checks=(2, 4),
        seed="0",
        model="scripted",
        out_dir=tmp_path_factory.mktemp("ablate"),
        limit=None,
    )


def test_every_mode_produces_its_rows(small_ablation):
    modes = {row.mode for row in small_ablation.rows}
    assert modes == {"single", "isolated", "floor"}
    assert small_ablation.baseline, "the baseline is re-run inside the ablation"


def test_the_floor_row_is_the_kernel_with_its_predicates_off(small_ablation):
    """How much of the arm's result comes from the checks, and how much from the
    plumbing around them. A floor equal to the baseline would mean the checks
    were not doing the work."""
    floor = next(row for row in small_ablation.rows if row.mode == "floor")
    floor_asr = asr_by_class(floor.records)
    base_asr = asr_by_class(small_ablation.baseline)
    assert any(
        floor_asr[cls].k > base_asr[cls].k for cls in floor_asr if cls in base_asr
    ), "no class landed with every predicate removed; the checks are not what stopped them"


def test_check_four_is_necessary_and_check_two_is_only_sufficient(small_ablation):
    """The overlap, made explicit.

    A redirected payee changes the cart's hash, so check 4 refuses class A1 even
    with check 2 removed. Turning off check 2 alone therefore moves nothing —
    and reporting only that would say check 2 is worthless, which the isolation
    row contradicts.
    """
    verdicts = ablation_verdicts(small_ablation)
    assert verdicts[2]["necessary_for"] == [], (
        "check 4 masks check 2; if this changed, the two-table presentation in "
        "results.md needs revisiting"
    )
    assert "A1" in verdicts[2]["sufficient_for"]
    assert verdicts[4]["necessary_for"], "check 4 is the one nothing else masks"
    assert verdicts[2]["earns_row"] and verdicts[4]["earns_row"]


def test_the_rendered_table_names_what_it_could_not_ablate(small_ablation):
    text = render_ablation(small_ablation)
    assert "not ablated" in text
    assert "`idempotency`" in text and "`audit_append`" in text
    assert "earns its row" in text
    # every proportion carries its interval
    assert "[" in text and "]" in text


def test_two_ablation_rows_are_two_experiments(small_ablation):
    """Without the disabled set in the suite id, every row would share the
    baseline's id and a reader could not tell which file produced which row."""
    ids = {row.suite_id for row in small_ablation.rows}
    ids.add(small_ablation.baseline_suite_id)
    assert len(ids) == len(small_ablation.rows) + 1
