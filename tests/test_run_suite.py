"""The runner and the run record — SPEC.md §11, issue #51.

Two things are under test here and they fail in different directions.

**The record.** A line that is missing a field is a column ``results.md``
cannot have. Worse, a line whose ``corpus_manifest`` or ``latency_us`` is
wrong is a column ``results.md`` *can* have and should not — a number that
looks computed and is not traceable to the corpus that produced it.

**The suite.** One kernel per case, cases in sequence, one line per case
whatever happens to it. Each of those is a rule whose violation is silent: a
shared database still produces a full JSONL, a parallel suite still produces a
p99, and a suite that drops its failures still produces a proportion. All three
would be wrong and none of them would look wrong.
"""

from __future__ import annotations

import json
import pathlib
import statistics

import pytest

from harness import suite as suite_module
from harness.manifest import build_manifest
from harness.runner import percentiles, run_case
from harness.suite import (
    SuiteAlreadyRunning,
    SuiteCase,
    run_suite,
    select,
)

#: SPEC.md §11's run record, field for field. Named here rather than asserted
#: loosely, so dropping one from the dataclass fails a test that says which.
SPEC_FIELDS = (
    "run_id",
    "seed",
    "case_id",
    "config",
    "model",
    "attacker_win",
    "task_success",
    "decisions",
    "chain_head",  # SPEC.md writes it ``audit_head``
    "latency_us",
    "corpus_manifest",
)


def _suite(tmp_path, cases, **kwargs):
    kwargs.setdefault("dataset", "batch_a")
    kwargs.setdefault("config", "undefended")
    kwargs.setdefault("model", "scripted")
    kwargs.setdefault("out", tmp_path / "suite.jsonl")
    return run_suite(cases, **kwargs)


def _lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field_name", SPEC_FIELDS)
def test_the_record_carries_every_field_the_spec_names(field_name):
    record = run_case("benign-01", config="kernel", model="scripted")
    assert field_name in record.__dict__, f"SPEC.md §11 names {field_name}"


def test_the_manifest_on_the_line_is_the_corpus_as_it_is_now():
    """Computed, not quoted from ``manifest.json``.

    A record that read the frozen file would keep reporting the frozen hash
    after somebody edited a payload — which is the one event the field exists
    to make visible.
    """
    record = run_case("benign-01", config="undefended", model="scripted")
    assert record.corpus_manifest == build_manifest()["manifest_hash"]


def test_every_money_call_is_measured_in_both_arms():
    """Same boundary, both arms. Otherwise 'added latency' is not a subtraction."""
    for config in ("undefended", "kernel"):
        record = run_case("benign-01", config=config, model="scripted")
        assert record.money_calls, f"{config} recorded no money-moving call"
        assert all(c["latency_us"] >= 0 for c in record.money_calls)
        assert record.latency_us["n"] == len(record.money_calls)


def test_the_kernel_arm_costs_more_than_the_undefended_one():
    """The overhead column has something in it, and it has the sign it should.

    Medians of three runs rather than one comparison, because a single pair on
    a loaded machine is a coin toss and a flaky test in this project would be
    embarrassing for the same reason a flaky attack would be. The two arms are
    separated by roughly a factor of five, so the median is not a close call.
    """

    def median(config):
        return statistics.median(
            run_case("benign-01", config=config, model="scripted").latency_us["p50"]
            for _ in range(3)
        )

    assert median("kernel") > median("undefended")


def test_no_measured_duration_reaches_the_log_or_the_chain(tmp_path):
    """The rule ``kernel/latency.py`` states, at the level the harness can break it.

    A duration in a hashed record would destroy byte-identical replay, and
    every other claim in the project reduces to "the chain says so".
    """
    log, chain = tmp_path / "log.jsonl", tmp_path / "chain.jsonl"
    first = run_case(
        "benign-01", config="kernel", model="scripted", seed="7",
        export_log=log, export_chain=chain,
    )
    exported_log, exported_chain = log.read_text(), chain.read_text()
    second = run_case("benign-01", config="kernel", model="scripted", seed="7")

    assert first.money_calls and first.decisions
    assert "latency_us" not in exported_log
    assert "latency_us" not in exported_chain
    assert first.log_head == second.log_head
    assert first.chain_head == second.chain_head


def test_the_decisions_say_where_the_time_went():
    """Per decision, not only per call. One ``pay`` is three kernel decisions."""
    record = run_case("benign-01", config="kernel", model="scripted")
    assert [step["step"] for step in record.decisions] == [
        "intent.register",
        "authorize",
        "capture",
    ]
    assert all("latency_us" in step for step in record.decisions)


def test_percentiles_are_nearest_rank():
    """Every figure reported is a duration that was measured, not between two.

    Interpolation invents a number, and at n=3 the invented one is the one a
    reader would quote.
    """
    assert percentiles([]) == {"n": 0, "p50": 0, "p99": 0}
    assert percentiles([5]) == {"n": 1, "p50": 5, "p99": 5}
    assert percentiles([1, 2, 3, 4]) == {"n": 4, "p50": 2, "p99": 4}
    hundred = list(range(1, 101))
    assert percentiles(hundred) == {"n": 100, "p50": 50, "p99": 99}


# ---------------------------------------------------------------------------
# The suite
# ---------------------------------------------------------------------------


def test_one_jsonl_line_per_case(tmp_path):
    cases = select("batch_a", attack_class="A1")[:4]
    result = _suite(tmp_path, cases)

    lines = _lines(result.path)
    assert len(lines) == len(cases) == len(result.records)
    assert [line["case_id"] for line in lines] == [c.attack_id for c in cases]
    assert {line["corpus_manifest"] for line in lines} == {result.corpus_manifest}


def test_the_sidecar_records_what_took_the_measurement(tmp_path):
    result = _suite(tmp_path, select("batch_a", attack_class="A1")[:2])
    meta = json.loads(result.meta_path.read_text())

    assert meta["cases"] == 2
    assert meta["sequential"] is True
    assert meta["corpus_manifest"] == result.corpus_manifest
    # The overhead column is the one number a different CPU would move.
    assert meta["host"]["machine"]


def test_every_kernel_case_keeps_the_chain_it_is_judged_from(tmp_path):
    """Not one chain overwritten 105 times.

    ``mk run`` leaves its chain at a fixed path so ``mk explain <seq>`` needs no
    argument. A suite doing the same would leave a table of rows backed by the
    last case's chain, and every claim in this project reduces to "the chain
    says so".
    """
    cases = select("batch_a", attack_class="A1")[:3]
    result = _suite(tmp_path, cases, config="kernel")

    paths = [record.chain_path for record in result.records]
    assert all(paths), "a kernel run with no exported chain is unauditable"
    assert len(set(paths)) == 3
    for record in result.records:
        entries = pathlib.Path(record.chain_path).read_text().splitlines()
        assert len(entries) == record.chain_entries


def test_a_case_that_could_not_run_is_still_a_line(tmp_path, monkeypatch):
    """The denominator does not shrink when things go badly.

    A proportion over a denominator that drops its failures is biased in the
    defence's favour every single time, and nothing downstream could see it:
    the file is well formed and the percentage is plausible.
    """
    cases = select("batch_a", attack_class="A1")[:3]
    real = suite_module.run_case

    def flaky(task_id=None, **kwargs):
        if kwargs.get("attack_id") == cases[1].attack_id:
            raise RuntimeError("the world did not settle")
        return real(task_id, **kwargs)

    monkeypatch.setattr(suite_module, "run_case", flaky)
    result = _suite(tmp_path, cases)

    lines = _lines(result.path)
    assert len(lines) == 3
    assert lines[1]["error"].endswith("the world did not settle")
    assert len(result.errors) == 1
    assert len(result.scored) == 2, "a case that did not run is scored in neither column"


def test_a_failed_case_keeps_the_run_id_it_would_have_had(tmp_path, monkeypatch):
    """An error line nobody can join back to the case is a hole in the record."""
    case = select("batch_a", attack_class="A1")[0]
    expected = run_case(
        case.task_id, config="undefended", attack_id=case.attack_id, model="scripted"
    ).run_id

    monkeypatch.setattr(
        suite_module, "run_case", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no"))
    )
    result = _suite(tmp_path, [case])
    assert result.records[0].run_id == expected


def test_no_two_kernel_cases_share_a_database(tmp_path, monkeypatch):
    """SQLite has a single writer, and the stores are global to a database.

    Two cases in one database would put case one's audit chain, idempotency
    keys and ledger in front of case two's checks — check 6's replay window and
    check 7's key space are both store-wide — so a case would be judged against
    history it was never written against. The full JSONL it produced would look
    exactly like a correct one.
    """
    from harness import kernel_arm

    opened: list[str] = []
    real_connect = kernel_arm.connect

    def recording_connect(path, *args, **kwargs):
        opened.append(str(path))
        return real_connect(path, *args, **kwargs)

    monkeypatch.setattr(kernel_arm, "connect", recording_connect)
    _suite(tmp_path, select("batch_a", attack_class="A1")[:3], config="kernel")

    assert len(opened) == 3
    assert len(set(opened)) == 3, f"cases shared a database: {opened}"


def test_a_suite_refuses_to_run_beside_another_in_one_process(tmp_path):
    """Cases run in sequence; parallelism is across processes.

    Not enforced by a comment. Two suites in one process would each produce a
    complete file, and the only trace of the collision would be a p99 that was
    really a measurement of lock contention between two runs that would never
    have met.
    """
    cases = select("batch_a", attack_class="A1")[:2]
    raised: list[BaseException] = []

    def reenter(index, total, record):
        try:
            _suite(tmp_path, cases, out=tmp_path / "second.jsonl")
        except SuiteAlreadyRunning as exc:
            raised.append(exc)

    _suite(tmp_path, cases[:1], progress=reenter)
    assert raised, "a second suite started inside the first"
    assert not (tmp_path / "second.jsonl").exists()


def test_a_second_suite_may_run_once_the_first_has_finished(tmp_path):
    """The guard is about overlap, not about a one-shot process."""
    cases = select("batch_a", attack_class="A1")[:1]
    _suite(tmp_path, cases, out=tmp_path / "a.jsonl")
    _suite(tmp_path, cases, out=tmp_path / "b.jsonl")
    assert (tmp_path / "a.jsonl").read_text() != ""


def test_the_suite_id_identifies_the_experiment_not_the_invocation(tmp_path):
    cases = select("batch_a", attack_class="A1")[:2]
    first = _suite(tmp_path, cases, out=tmp_path / "a.jsonl")
    again = _suite(tmp_path, cases, out=tmp_path / "b.jsonl")
    other_seed = _suite(tmp_path, cases, seed="99", out=tmp_path / "c.jsonl")

    assert first.suite_id == again.suite_id, "re-running is reproduction, not new evidence"
    assert first.suite_id != other_seed.suite_id


def test_pooled_latency_is_taken_over_calls_not_over_runs(tmp_path):
    """A p99 of per-run p99s is a p99 of nothing.

    Run over A7, whose task buys and then refunds: two money calls per run,
    which is what makes "over calls" and "over runs" different numbers. An A1
    suite makes one call per run and would pass this either way.
    """
    result = _suite(tmp_path, select("batch_a", attack_class="A7")[:4])
    calls = sum(len(record.money_calls) for record in result.scored)
    assert result.latency_us["n"] == calls
    assert calls > len(result.scored), "the dataset must make more than one call per run"


# ---------------------------------------------------------------------------
# The refusals
# ---------------------------------------------------------------------------


def test_batch_b_stays_sealed(tmp_path):
    """The held-out set is opened deliberately and the opening is logged.

    A suite runner that opened it on the caller's behalf would make "opened
    once" untrue in the one place it is load-bearing.
    """
    with pytest.raises(RuntimeError, match="open_batch_b"):
        run_suite(
            [SuiteCase(task_id="benign-01", attack_id="A1-b-05")],
            dataset="batch_b",
            config="undefended",
            model="scripted",
            out=tmp_path / "b.jsonl",
        )
    assert not (tmp_path / "b.jsonl").exists()


def test_a_moved_corpus_refuses_to_start(tmp_path, monkeypatch):
    monkeypatch.setattr(
        suite_module, "verify_manifest", lambda: ("sha256:old", ["changed: A1-a-05.json"])
    )
    with pytest.raises(RuntimeError, match="A1-a-05.json"):
        _suite(tmp_path, select("batch_a", attack_class="A1")[:1])
    assert not (tmp_path / "suite.jsonl").exists()


def test_a_corpus_that_moves_mid_suite_is_reported_not_published(tmp_path, monkeypatch):
    """Every line quotes a hash taken before case one; this is the check that it held."""
    calls = {"n": 0}

    def drifting():
        calls["n"] += 1
        return ("sha256:x", [] if calls["n"] == 1 else ["changed: benign_01.json"])

    monkeypatch.setattr(suite_module, "verify_manifest", drifting)
    result = _suite(tmp_path, select("batch_a", attack_class="A1")[:1])

    assert result.corpus_drift == ["changed: benign_01.json"]
    assert result.records, "the lines are still written; they are just not publishable"


def test_an_arm_that_does_not_exist_is_refused_before_the_file_is_opened(tmp_path):
    """A hundred identical error lines is a worse way to find out.

    The check is up front, before the output file is opened, which is what the
    second assertion is for: a suite that discovered a bad arm on case one would
    leave a JSONL of a hundred identical failures and a denominator nobody could
    interpret.
    """
    with pytest.raises(ValueError, match="unknown config"):
        _suite(tmp_path, select("batch_a", attack_class="A1")[:2], config="kernal")
    assert not (tmp_path / "suite.jsonl").exists()


def test_selecting_nothing_is_an_error():
    """An empty table reads like a perfect score."""
    with pytest.raises(ValueError, match="no cases selected"):
        select("batch_a", attack_class="A1", task="benign-25")
    with pytest.raises(ValueError, match="attack classes"):
        select("benign", attack_class="A1")


def test_the_plan_is_the_whole_dataset_in_a_fixed_order():
    assert len(select("benign")) == 25
    assert len(select("batch_a")) == 105
    assert len(select("batch_b")) == 105, "planning batch B needs no payload"
    assert select("batch_a") == select("batch_a")
    assert all(case.attack_id is None for case in select("benign"))
