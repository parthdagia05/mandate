"""The matrix, the batch B seal, and the rendered report. Issues #50, #57, #59.

The seal tests are the ones that matter. Batch B is the held-out set and the
headline number comes from it; nothing here can *prevent* a second read, and
none of these tests pretends to. What they establish is that a second read
cannot happen **silently** — which is the whole of "opened once" as an
enforceable claim rather than an intention.
"""

from __future__ import annotations

import json

import pytest

from harness import corpus as corpus_module
from harness.matrix import load_matrix, run_matrix
from harness.metrics import benign_utility, targeted_asr
from harness.report import render_results
from harness.runner import CONFIGS, HEADLINE_CONFIGS


@pytest.fixture
def sealed(tmp_path, monkeypatch):
    """A fresh openings log and a re-sealed batch B, for this test only.

    The real log is a durable record of every time the held-out set was read.
    A test that appended to it would be writing a false entry into the file
    ``results.md`` quotes.
    """
    monkeypatch.setattr(corpus_module, "OPENINGS_LOG", tmp_path / "openings.jsonl")
    monkeypatch.setattr(corpus_module, "_OPEN", set())
    return tmp_path / "openings.jsonl"


# --- the seal -------------------------------------------------------------


def test_a_batch_b_payload_is_unreadable_until_the_batch_is_opened(sealed):
    case = corpus_module.load_attack("A1-b-01")
    assert case.attack_class == "A1", "metadata stays readable; only the payload is sealed"
    with pytest.raises(corpus_module.BatchBSealed, match="held-out"):
        _ = case.payload


def test_opening_batch_b_needs_a_reason_and_writes_it_down(sealed):
    with pytest.raises(corpus_module.CorpusError, match="needs a reason"):
        corpus_module.open_batch_b("   ")

    entry = corpus_module.open_batch_b("M6 headline measurement", who="pytest")
    assert entry["sequence"] == 1 and entry["override"] is False
    logged = [json.loads(line) for line in sealed.read_text().splitlines() if line]
    assert logged == [entry]
    assert corpus_module.load_attack("A1-b-01").payload


def test_a_second_opening_is_refused_without_an_override_and_logged_as_one(sealed):
    corpus_module.open_batch_b("first", who="pytest")
    monkey = corpus_module
    monkey._OPEN.discard("b")  # a fresh process would start sealed again

    with pytest.raises(corpus_module.BatchBSealed, match="already opened"):
        corpus_module.open_batch_b("second", who="pytest")

    entry = corpus_module.open_batch_b("second", override=True, who="pytest")
    assert entry["override"] is True and entry["sequence"] == 2
    logged = [json.loads(line) for line in sealed.read_text().splitlines() if line]
    assert [e["override"] for e in logged] == [False, True]


def test_a_batch_b_matrix_without_a_reason_is_refused(sealed):
    with pytest.raises(ValueError, match="needs a reason"):
        run_matrix(datasets=("batch_b",), configs=("undefended",), model="scripted")
    assert not sealed.exists(), "nothing was opened, so nothing was logged"


def test_the_openings_log_is_outside_the_manifest():
    """The manifest must survive its own measurement.

    That file changes precisely when someone reads the held-out set, and
    covering it would mean taking the headline measurement invalidated the hash
    the headline is published under.
    """
    from harness.manifest import EXCLUDED, corpus_files

    assert "harness/attacks/openings.jsonl" in EXCLUDED
    assert "harness/attacks/openings.jsonl" not in corpus_files()


def test_the_seal_is_covered_by_the_manifest():
    """A seal that could be edited afterwards is not a seal."""
    from harness.manifest import corpus_files

    assert "harness/attacks/seal.json" in corpus_files()


# --- the matrix -----------------------------------------------------------


@pytest.fixture(scope="module")
def small_matrix(tmp_path_factory):
    return run_matrix(
        datasets=("benign", "batch_a"),
        configs=("undefended", "model-only", "kernel"),
        seed="0",
        model="scripted",
        out_dir=tmp_path_factory.mktemp("matrix"),
        limit=6,
    )


def test_every_cell_of_the_experiment_is_run(small_matrix):
    assert {(c.dataset, c.config) for c in small_matrix.cells} == {
        (d, c) for d in ("benign", "batch_a") for c in HEADLINE_CONFIGS
    }
    for cell in small_matrix.cells:
        assert cell.records, f"{cell.dataset}/{cell.config} produced no lines"


def test_the_matrix_pins_the_corpus_hash_to_its_lines(small_matrix):
    """A table whose lines were measured against different corpora is a table of
    unrelated numbers."""
    for cell in small_matrix.cells:
        for record in cell.records:
            assert record["corpus_manifest"] == small_matrix.corpus_manifest
    assert not small_matrix.corpus_drift


def test_the_lines_carry_the_dataset_so_overhead_cannot_be_subtracted_across_them(
    small_matrix,
):
    for cell in small_matrix.cells:
        assert all(r["dataset"] == cell.dataset for r in cell.records)


def test_a_matrix_can_be_rebuilt_from_the_files_it_left(small_matrix):
    """The published table has to be reproducible by somebody who did not run
    the suites."""
    reloaded = load_matrix(small_matrix.out_dir)
    assert reloaded.matrix_id == small_matrix.matrix_id
    assert reloaded.corpus_manifest == small_matrix.corpus_manifest
    assert [c.suite_id for c in reloaded.cells] == [
        c.suite_id for c in small_matrix.cells
    ]
    for original, copy in zip(small_matrix.cells, reloaded.cells):
        assert original.records == copy.records


def test_the_undefended_arm_is_the_one_the_attacks_land_against(small_matrix):
    """The gate. If the attacks do not succeed against an undefended agent there
    is nothing to defend, and every other column is a number about nothing."""
    undefended = targeted_asr(small_matrix.records("batch_a", "undefended"))
    assert undefended.k > 0, "no attack landed undefended; the experiment has no floor"


def test_the_kernel_arm_keeps_the_ordinary_path_working(small_matrix):
    """Blocking everything is not a defence."""
    kernel = small_matrix.records("benign", "kernel")
    assert benign_utility(kernel).k > 0


def test_every_run_behind_the_matrix_had_containment_armed(small_matrix):
    """REQ-10, as a field on every record rather than a sentence in a README."""
    for cell in small_matrix.cells:
        for record in cell.records:
            containment = record["containment"]
            assert containment["enforced"] is True
            assert containment["breaches"] == []
            assert containment["allowed_hosts"] == [], (
                "the stand-in needs no allowance; the strong claim is zero "
                "non-local sockets"
            )


# --- the report -----------------------------------------------------------


def test_the_report_never_prints_an_estimate_without_its_interval(small_matrix):
    import re

    text = render_results(small_matrix)
    # Every percentage in a table cell is followed by a bracketed interval.
    for line in text.splitlines():
        if not line.startswith("|") or "%" not in line:
            continue
        for cell in line.split("|"):
            if "%" not in cell or "ms" in cell:
                continue
            assert re.search(r"\d+\.\d%\s*\[", cell), (
                f"a bare percentage reached the table: {cell.strip()!r}"
            )


def test_the_report_prints_the_false_block_rate_and_the_utility_columns(small_matrix):
    text = render_results(small_matrix)
    assert "false block rate" in text
    assert "utility under attack" in text
    assert "turned the agent off" in text, (
        "the sentence that explains why those two columns sit together"
    )


def test_the_report_states_which_mind_drove_the_runs(small_matrix):
    """A scripted run quoted as an ASR figure is the single worst mistake
    available here, so the caveat is in the document rather than a footnote."""
    text = render_results(small_matrix)
    assert "scripted-gullible-v1" in text
    assert "no ASR figure below is a model" in text


def test_the_report_names_the_corpus_and_the_openings(small_matrix):
    text = render_results(small_matrix)
    assert small_matrix.corpus_manifest in text
    assert "batch B openings on record" in text


def test_the_report_states_the_containment_result(small_matrix):
    text = render_results(small_matrix)
    assert "## Containment" in text
    assert "non-local connections refused" in text


def test_every_arm_has_a_description_in_the_report():
    from harness.report import CONFIG_BLURB

    assert set(CONFIG_BLURB) == set(CONFIGS)
