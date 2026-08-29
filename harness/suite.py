"""Many cases, one process, one JSONL line each. What ``mk suite`` calls.

:mod:`harness.runner` runs one case. This runs a *dataset* — the 25 benign
tasks, or the 105 cases of a batch — and lays the results out as the record
``results.md`` is computed from. Four rules shape it, and each of them exists
because breaking it would corrupt a published number rather than merely be
untidy.

**One kernel per case.** Every kernel-arm case builds its own
:class:`~harness.kernel_arm.KernelArm`, with its own SQLite file in its own
temporary directory, and tears it down before the next case starts. Sharing a
database across cases would put every case's audit chain, idempotency rows and
ledger in front of the next case's checks — check 6's replay window and check 7's
key space are both *global* to a store — so case 40 would be judged against 39
cases of history that the case was not written against.

**Cases run in sequence.** SQLite has a single writer, and two cases writing at
once would serialise behind each other's locks. The overhead column is a
measurement of the kernel, and a p99 that is really a measurement of lock
contention between two cases that would never run together in production is not
a number worth publishing. :func:`run_suite` refuses to be entered twice in one
process for exactly that reason.

**Parallelism is across runs, never within one.** A whole suite is one process;
if you want three configs at once, start three processes. They share nothing —
separate worlds, separate databases, separate output files — so the only thing
they contend for is CPU, and the overhead figure that matters is quoted from a
suite that had a machine to itself anyway.

**The corpus is hashed before and after.** Every line carries the manifest hash
(REQ-11), and the hash is cached for the process, so an edit made *while* the
suite was running would go unnoticed by the lines themselves. Verifying at the
end as well is what turns "the corpus did not change" from an assumption into a
check. A suite that ends on a moved corpus is reported as invalid rather than
quietly published.

A case that raises is written as a line with ``error`` set and the suite carries
on. The alternative — aborting — loses the ninety cases that did run, and the
run record already has to be able to describe a crashed run because
``crash_after_reserve`` produces one deliberately.
"""

from __future__ import annotations

import json
import platform
import sys
import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from harness.corpus import (
    CLASSES,
    batch_b_is_open,
    batch_b_openings,
    list_batch,
    list_tasks,
    load_attack,
)
from harness.manifest import current_hash, verify_manifest
from harness.runner import (
    RunRecord,
    check_config,
    percentiles,
    run_case,
    run_id_for,
)
from kernel.canonical import sha256_of

__all__ = [
    "DATASETS",
    "RUNS_DIR",
    "SuiteAlreadyRunning",
    "SuiteCase",
    "SuiteResult",
    "select",
    "run_suite",
]

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Where a suite leaves its JSONL unless told otherwise. One directory, one
#: file per suite, named by the suite id — so two configs over the same dataset
#: cannot overwrite each other by both being called ``latest``.
RUNS_DIR = REPO_ROOT / "runs"

#: The selectable datasets, and what each one is for. ``benign`` is where the
#: benign-utility, false-block and overhead numbers come from; the batches are
#: where ASR comes from.
DATASETS: tuple[str, ...] = ("benign", "batch_a", "batch_b")

#: Held while a suite is running. Not a re-entrancy nicety: it is how "cases
#: run in sequence, parallelism across runs only" is enforced rather than
#: merely documented. A caller that puts :func:`run_suite` in a thread pool
#: gets an exception instead of a corrupted overhead distribution.
_RUNNING = threading.Lock()


class SuiteAlreadyRunning(RuntimeError):
    """A second suite was started in a process that already had one.

    See the module docstring. The failure this prevents is silent: two suites
    in one process would still produce two complete JSONL files, and the only
    sign that anything was wrong would be a p99 nobody could reproduce.
    """


@dataclass(frozen=True)
class SuiteCase:
    """One row of the plan: a task, and optionally the attack placed in it."""

    task_id: str
    attack_id: str | None = None

    @property
    def label(self) -> str:
        return self.attack_id or self.task_id


@dataclass
class SuiteResult:
    """What one suite produced, and everything needed to judge whether to trust it."""

    suite_id: str
    dataset: str
    config: str
    seed: str
    model: str
    corpus_manifest: str
    path: Path
    meta_path: Path
    started_at: str
    finished_at: str = ""
    records: list[RunRecord] = field(default_factory=list)
    #: Checks the ablation switched off for this suite. Empty for every suite
    #: whose numbers may be published as a configuration result; its presence
    #: in the metadata is what marks a file as an ablation row.
    disabled_checks: tuple[int, ...] = ()
    #: Set when the corpus moved between the first hash and the last. The
    #: suite is **not** deleted — the lines are still evidence of something —
    #: but it may not be published, and this says why.
    corpus_drift: list[str] = field(default_factory=list)

    # -- the counts ``results.md`` is built from ---------------------------

    @property
    def scored(self) -> list[RunRecord]:
        """Lines that may be counted. Poisoned runs are discarded, not reported.

        A run whose audit chain did not verify is excluded here rather than
        counted as a defended one. Counting it would let a kernel improve its
        own score by corrupting its own record, which is the one incentive this
        project cannot afford to leave lying around.
        """
        return [r for r in self.records if r.poisoned is None and r.error is None]

    @property
    def attacker_wins(self) -> int:
        return sum(1 for r in self.scored if r.attacker_win)

    @property
    def task_successes(self) -> int:
        return sum(1 for r in self.scored if r.task_success)

    @property
    def errors(self) -> list[RunRecord]:
        return [r for r in self.records if r.error is not None]

    @property
    def poisoned(self) -> list[RunRecord]:
        return [r for r in self.records if r.poisoned is not None]

    @property
    def latency_us(self) -> dict[str, int]:
        """Percentiles over **every** money-moving call in the suite.

        Taken over the pooled raw samples, not over the per-run percentiles. A
        p99 of p99s is a p99 of nothing: with two or three calls per run the
        per-run figures are mostly maxima, and averaging maxima would report
        the tail as though it were the body.

        Only scored runs contribute. A crashed case has a truncated call in it
        and a poisoned one may not be reported at all, so neither belongs in a
        distribution that goes in a table.
        """
        return percentiles(
            [
                int(call["latency_us"])
                for record in self.scored
                for call in record.money_calls
            ]
        )

    def summary(self) -> dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "dataset": self.dataset,
            "config": self.config,
            "seed": self.seed,
            "model": self.model,
            "corpus_manifest": self.corpus_manifest,
            "corpus_drift": self.corpus_drift,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "cases": len(self.records),
            "scored": len(self.scored),
            "errors": len(self.errors),
            "poisoned": len(self.poisoned),
            "attacker_wins": self.attacker_wins,
            "task_successes": self.task_successes,
            "latency_us": self.latency_us,
            "records": self.path.name,
            "chains": f"{self.path.stem}.chains" if self.config == "kernel" else None,
            # Provenance for the machine that took the measurement. The
            # overhead column is the one number here that a different CPU
            # would move, so the CPU is written down beside it.
            "host": {
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "machine": platform.machine(),
            },
            "sequential": True,
            "disabled_checks": sorted(self.disabled_checks),
            "batch_b_openings": len(batch_b_openings()),
        }


def select(
    dataset: str,
    *,
    attack_class: str | None = None,
    task: str | None = None,
    limit: int | None = None,
) -> list[SuiteCase]:
    """The plan for one suite, in a fixed order.

    Sorted by case id, and by task id for the benign set, so two suites over
    the same dataset visit the same cases in the same order. Ordering is not
    cosmetic here: each case advances the run's own seeded world, and a plan
    that arrived in a different order every time would make "same seed, same
    numbers" false at the suite level while remaining true at the case level.

    Reads case *metadata* only — ``list_batch`` never touches a payload — so
    planning a batch B suite is possible while batch B is still sealed. The
    seal is enforced when the payload is read, and :func:`run_suite` checks it
    up front rather than letting case one discover it.
    """
    if dataset not in DATASETS:
        raise ValueError(f"unknown dataset {dataset!r}; known: {list(DATASETS)}")
    if attack_class is not None and attack_class not in CLASSES:
        raise ValueError(f"unknown class {attack_class!r}; known: {list(CLASSES)}")

    cases: list[SuiteCase]
    if dataset == "benign":
        if attack_class is not None:
            raise ValueError(
                "the benign suite has no attack classes; it is the arm with no "
                "payload anywhere, and filtering it by class would silently "
                "select nothing"
            )
        cases = [SuiteCase(task_id=t) for t in list_tasks()]
    else:
        batch = dataset.removeprefix("batch_")
        cases = []
        for case_id in list_batch(batch):
            case = load_attack(case_id)
            if attack_class is not None and case.attack_class != attack_class:
                continue
            cases.append(SuiteCase(task_id=case.task_id, attack_id=case_id))

    if task is not None:
        cases = [c for c in cases if c.task_id == task]
    if not cases:
        raise ValueError(
            f"no cases selected from {dataset!r} with "
            f"class={attack_class!r} task={task!r}; an empty suite would "
            "produce an empty table that reads like a perfect score"
        )
    return cases[:limit] if limit else cases


def _suite_id(
    cases: Sequence[SuiteCase],
    *,
    config: str,
    seed: str,
    model: str,
    manifest: str,
    disabled_checks: tuple[int, ...] = (),
) -> str:
    """Identifies the *experiment*, not the invocation.

    Two runs of the same plan share an id, because they are the same
    measurement and re-running one is how it gets reproduced. Change the seed,
    the arm, the model or one byte of the corpus and the id moves — which is
    what makes an id in ``results.md`` worth quoting.
    """
    return sha256_of(
        {
            "cases": [[c.task_id, c.attack_id] for c in cases],
            "config": config,
            "seed": seed,
            "model": model,
            "corpus_manifest": manifest,
            # In the id, so the ablation's seven suites are seven experiments
            # rather than one experiment run seven times. Without it every
            # ablation row would share the baseline's id and a reader could not
            # tell which file produced which row.
            "disabled_checks": sorted(disabled_checks),
        }
    )


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _failed_record(
    case: SuiteCase, *, config: str, seed: str, model: str, error: str
) -> RunRecord:
    """A line for a case that never produced one.

    Written rather than dropped. A suite of 105 that emits 103 lines is a suite
    whose denominator is wrong, and a proportion computed over a denominator
    that quietly shrank when things went badly is biased in the defence's
    favour every single time.
    """
    return RunRecord(
        run_id=run_id_for(
            seed=seed, task_id=case.task_id, case_id=case.attack_id, config=config
        ),
        seed=seed,
        task_id=case.task_id,
        case_id=case.attack_id,
        config=config,
        model=model,
        attacker_win=False,
        task_success=False,
        ledger=[],
        log_head="",
        log_entries=0,
        plan={},
        error=error,
        notes=["the case did not run; it is counted in the denominator and scored in neither column"],
        corpus_manifest=current_hash(),
    )


def run_suite(
    cases: Iterable[SuiteCase],
    *,
    dataset: str,
    config: str,
    seed: str = "0",
    model: str = "auto",
    out: Path | None = None,
    cassette: Path | None = None,
    faults: list[dict[str, Any]] | None = None,
    disabled_checks: tuple[int, ...] = (),
    progress: Callable[[int, int, RunRecord], None] | None = None,
) -> SuiteResult:
    """Run every case in sequence and stream one JSONL line each.

    Lines are written and flushed **as each case finishes**, not collected and
    dumped at the end. A suite is minutes of work and the machine can lose
    power in the middle of it; the difference between a partial file and no
    file is the difference between re-running twelve cases and re-running a
    hundred.
    """
    plan = list(cases)
    if not plan:
        raise ValueError("an empty suite would produce a table with no denominator")
    check_config(config)

    # Up front, before a file is opened. A batch B suite that discovered the
    # seal on case one would leave a JSONL of a hundred identical errors, and
    # opening the batch is a decision with its own log — not something a suite
    # runner gets to make on the caller's behalf.
    if dataset == "batch_b" and not batch_b_is_open():
        raise RuntimeError(
            "batch B is sealed and this suite would read its payloads. It is "
            "the held-out set and the headline number comes from it, so it is "
            "opened explicitly and the opening is logged: call "
            "harness.corpus.open_batch_b(reason=...) first."
        )

    manifest, drift = verify_manifest()
    if drift:
        raise RuntimeError(
            "the corpus does not match harness/manifest.json, so no number "
            "from this suite could be published (REQ-11):\n  "
            + "\n  ".join(drift)
        )
    manifest = current_hash()

    suite_id = _suite_id(
        plan,
        config=config,
        seed=seed,
        model=model,
        manifest=manifest,
        disabled_checks=disabled_checks,
    )
    path = Path(out) if out is not None else RUNS_DIR / f"{suite_id[7:23]}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)

    # Every kernel case gets its own exported chain, and its line points at it.
    # ``mk run`` leaves one chain at a fixed path so ``mk explain <seq>`` needs
    # no argument; a suite that did the same would leave a table of 105 rows
    # backed by the last case's chain and 104 that had been overwritten. The
    # project's every claim reduces to "the chain says so", so each row has to
    # keep the chain it is making the claim from.
    chains = path.parent / f"{path.stem}.chains" if config == "kernel" else None
    if chains is not None:
        chains.mkdir(parents=True, exist_ok=True)

    result = SuiteResult(
        suite_id=suite_id,
        dataset=dataset,
        config=config,
        seed=seed,
        model=model,
        corpus_manifest=manifest,
        path=path,
        meta_path=path.with_suffix(".meta.json"),
        started_at=_now(),
        disabled_checks=tuple(disabled_checks),
    )

    if not _RUNNING.acquire(blocking=False):
        raise SuiteAlreadyRunning(
            "a suite is already running in this process. Cases run in "
            "sequence because SQLite has a single writer and the overhead "
            "column must not be a measurement of lock contention; run the "
            "second suite in a second process."
        )
    try:
        with path.open("w") as handle:
            for index, case in enumerate(plan, start=1):
                try:
                    record = run_case(
                        case.task_id,
                        config=config,
                        attack_id=case.attack_id,
                        seed=seed,
                        model=model,
                        cassette=cassette,
                        faults=faults,
                        disabled_checks=disabled_checks,
                        export_chain=(
                            chains / f"{case.label}.chain.jsonl"
                            if chains is not None
                            else None
                        ),
                    )
                except Exception as exc:  # noqa: BLE001 — a case that could not run is a line
                    record = _failed_record(
                        case,
                        config=config,
                        seed=seed,
                        model=model,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                handle.write(record.to_json() + "\n")
                handle.flush()
                result.records.append(record)
                if progress is not None:
                    progress(index, len(plan), record)
    finally:
        _RUNNING.release()

    # The corpus is hashed once per process, so every line above quotes the
    # hash taken before case one. This is the check that the quote is still
    # true — an edit made mid-suite is invisible to the lines and visible here.
    _, drift = verify_manifest()
    result.corpus_drift = drift
    result.finished_at = _now()
    result.meta_path.write_text(json.dumps(result.summary(), indent=2, sort_keys=True) + "\n")
    return result
