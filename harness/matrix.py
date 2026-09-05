"""The whole experiment: every arm over every dataset, and the per-check ablation.

:mod:`harness.suite` runs one dataset in one arm. This runs the *matrix* — the
thing ``results.md`` is a rendering of — and it exists as its own module because
three of its rules are about the experiment rather than about any one suite.

**The batch B seal is opened here, once, by name.** Batch B is the held-out set
and the headline number comes from it. :func:`run_matrix` calls
:func:`~harness.corpus.open_batch_b` with the reason it was given, and the
opening is appended to ``harness/attacks/openings.jsonl``. A second matrix over
batch B needs ``override=True`` and is recorded as an override. Nothing here can
*prevent* a second read; what it can do is make a second read impossible to
perform silently, so ``results.md`` can state how many times the held-out set
was looked at and a reader can check the file.

**The manifest is pinned to the results.** The matrix records the corpus hash it
ran against and every suite in it verifies the same hash; a mismatch is a
refusal, not a footnote, because a table whose lines were measured against
different corpora is a table of unrelated numbers.

**Suites run in sequence, in one process, and that is the measurement.** SQLite
has a single writer, and two arms writing at once would serialise behind each
other's locks — the overhead column would then be a measurement of contention
between two runs that would never happen together in production. Parallelism is
across whole matrices, never inside one.

**The ablation turns off one predicate at a time.** :func:`run_ablation` runs
the kernel arm once per check, with that check removed from every action's
evaluation list, and compares each class's ASR against the un-ablated kernel
run. A check whose removal moves nothing has not earned its row — that is what
the table is for, and it is written so that the answer can come out
uncomfortable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from harness.corpus import SEALED_BATCHES, batch_is_open, openings, open_batch
from harness.manifest import hash_for_dataset, verify_all
from harness.runner import CONFIGS, HEADLINE_CONFIGS
from harness.suite import DATASET_BATCH, DATASETS, RUNS_DIR, SuiteResult, run_suite, select

__all__ = [
    "ABLATABLE",
    "MatrixCell",
    "MatrixResult",
    "AblationRow",
    "AblationResult",
    "run_matrix",
    "run_ablation",
    "load_matrix",
]

#: The checks the ablation switches off, one at a time.
#:
#: Checks 1–6 and 8 are predicates over a request and each is removable on its
#: own. **7 and 9 are not in this list**, and leaving them out is a decision
#: rather than an oversight: check 7 is the idempotency reservation and check 9
#: is the audit append, and removing either does not weaken a predicate — it
#: removes the lifecycle step that makes every *other* row of the table
#: meaningful. A kernel with no audit append has no chain, and a run with no
#: chain is discarded rather than scored, so the row would be empty. A kernel
#: with no idempotency reservation cannot answer a crash, so its "ASR" would be
#: a measurement of the recovery path falling over.
#:
#: They are named in ``results.md`` as un-ablated, with that reason, rather than
#: quietly omitted. A missing row in an ablation table reads as a check nobody
#: thought about.
ABLATABLE: tuple[int, ...] = (1, 2, 3, 4, 5, 6, 8)


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass
class MatrixCell:
    """One (dataset, config) suite, and where its lines live."""

    dataset: str
    config: str
    suite_id: str
    path: Path
    records: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "config": self.config,
            "suite_id": self.suite_id,
            "records": self.path.name,
            "cases": len(self.records),
        }


@dataclass
class MatrixResult:
    """Every cell of the experiment, plus what makes it quotable."""

    matrix_id: str
    seed: str
    model: str
    corpus_manifest: str
    out_dir: Path
    datasets: tuple[str, ...]
    configs: tuple[str, ...]
    started_at: str
    finished_at: str = ""
    cells: list[MatrixCell] = field(default_factory=list)
    #: The batch B opening this matrix performed, if any. ``None`` when the
    #: matrix did not touch the held-out set.
    batch_b_opening: dict[str, Any] | None = None
    #: Every opening ever recorded, at the time this matrix ran. Carried into
    #: the report so "opened once" is a number a reader can see rather than a
    #: claim they have to take.
    batch_b_openings: list[dict[str, Any]] = field(default_factory=list)
    #: Set when the corpus moved during the matrix. Not deleted — the lines are
    #: still evidence of something — but it may not be published.
    corpus_drift: list[str] = field(default_factory=list)
    #: ``dataset -> manifest hash``. A matrix may span the hand-written corpus
    #: and the generated one, and the two have separate manifests on purpose;
    #: one hash for a mixed matrix would name one corpus and imply the other.
    corpus_manifests: dict[str, str] = field(default_factory=dict)

    def cell(self, dataset: str, config: str) -> MatrixCell | None:
        for entry in self.cells:
            if entry.dataset == dataset and entry.config == config:
                return entry
        return None

    def records(self, dataset: str, config: str) -> list[dict[str, Any]]:
        found = self.cell(dataset, config)
        return list(found.records) if found else []

    def as_dict(self) -> dict[str, Any]:
        return {
            "matrix_id": self.matrix_id,
            "seed": self.seed,
            "model": self.model,
            "corpus_manifest": self.corpus_manifest,
            "corpus_manifests": dict(self.corpus_manifests),
            "datasets": list(self.datasets),
            "configs": list(self.configs),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "cells": [c.as_dict() for c in self.cells],
            "batch_b_opening": self.batch_b_opening,
            "batch_b_openings": list(self.batch_b_openings),
            "corpus_drift": list(self.corpus_drift),
        }


@dataclass
class AblationRow:
    """One configuration of the check set, and what it did to every class's ASR.

    ``mode`` is why this class is not simply "one check off":

    ``single``
        That check removed, the rest on. Answers **is this check necessary?**
    ``isolated``
        Only that check on, every other ablatable check removed. Answers
        **what does this check stop on its own?**
    ``floor``
        Every ablatable check removed. The kernel arm with its predicates
        switched off, which is the row that says how much of the arm's result
        comes from the checks and how much from the plumbing around them.

    Both of the first two are needed, and running only ``single`` is the mistake
    this project nearly made. The checks overlap on purpose — a redirected payee
    changes the cart's hash, so check 4 catches class A1 even with check 2
    removed — and a single-ablation table therefore shows almost every check
    stopping nothing. That is a true statement about *necessity given the
    others* and a false impression about *value*. The isolation row is what
    separates them.
    """

    check_ids: tuple[int, ...]
    label: str
    mode: str
    suite_id: str
    path: Path
    records: list[dict[str, Any]] = field(default_factory=list)

    @property
    def check_id(self) -> int | None:
        """The check this row is *about*, or ``None`` for the floor row."""
        return self.check_ids[0] if len(self.check_ids) == 1 and self.mode != "floor" else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "check_ids": list(self.check_ids),
            "label": self.label,
            "mode": self.mode,
            "suite_id": self.suite_id,
            "records": self.path.name,
            "cases": len(self.records),
        }


@dataclass
class AblationResult:
    """The whole ablation: a baseline, and one row per check removed."""

    dataset: str
    seed: str
    model: str
    corpus_manifest: str
    out_dir: Path
    baseline: list[dict[str, Any]] = field(default_factory=list)
    baseline_suite_id: str = ""
    rows: list[AblationRow] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "seed": self.seed,
            "model": self.model,
            "corpus_manifest": self.corpus_manifest,
            "baseline_suite_id": self.baseline_suite_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "rows": [r.as_dict() for r in self.rows],
        }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _tag(records: Iterable[dict[str, Any]], dataset: str) -> list[dict[str, Any]]:
    """Stamp each line with the dataset it came from.

    The field is not in :class:`~harness.runner.RunRecord` because a *run* does
    not have a dataset — a case belongs to a batch and a run is one case. It is
    added here, where lines from several suites are about to sit in one list,
    because :func:`~harness.metrics.overhead` refuses to subtract across two
    datasets and needs something to refuse on.
    """
    return [{**record, "dataset": dataset} for record in records]


def _open_sealed_batches(
    datasets: Sequence[str], *, reason: str, override: bool, who: str
) -> list[dict[str, Any]]:
    """Open every held-out batch this matrix would read, and log each opening.

    Per batch, because there are two held-out sets now and they are two
    separate claims: opening ``gen-b`` says nothing about ``b``, and a guard
    that treated one opening as unsealing both would let the generated corpus's
    measurement quietly consume the hand-written one's held-out status.
    """
    wanted = [
        DATASET_BATCH[d]
        for d in datasets
        if DATASET_BATCH.get(d) in SEALED_BATCHES
    ]
    entries: list[dict[str, Any]] = []
    for batch in wanted:
        if batch_is_open(batch):
            # Already open in this process. Not re-logged: the log records
            # *openings*, and a second call inside one process is the same one.
            prior = openings(batch)
            if prior:
                entries.append(prior[-1])
            continue
        if not reason.strip():
            raise ValueError(
                f"a matrix over batch {batch!r} needs a reason; it is a "
                "held-out set and the reason goes in "
                "harness/attacks/openings.jsonl beside the timestamp, which is "
                "what makes 'opened once' checkable"
            )
        entries.append(open_batch(batch, reason, override=override, who=who))
    return entries


def run_matrix(
    *,
    datasets: Sequence[str] = ("benign", "batch_a"),
    configs: Sequence[str] = HEADLINE_CONFIGS,
    seed: str = "0",
    model: str = "auto",
    out_dir: Path | None = None,
    reason: str = "",
    override: bool = False,
    who: str = "mk matrix",
    limit: int | None = None,
    progress: Callable[[str, str, int, int], None] | None = None,
) -> MatrixResult:
    """Run every (dataset, config) pair in sequence and write the lines down.

    The benign dataset is always worth including even when the question is an
    ASR: benign utility, the false-block rate and the overhead column all come
    from it, and an ASR published without the first two is a number with the
    inconvenient half removed.
    """
    for dataset in datasets:
        if dataset not in DATASETS:
            raise ValueError(f"unknown dataset {dataset!r}; known: {list(DATASETS)}")
    for config in configs:
        if config not in CONFIGS:
            raise ValueError(f"unknown config {config!r}; known: {list(CONFIGS)}")

    drift = verify_all()
    if drift:
        raise RuntimeError(
            "a corpus does not match its manifest, so nothing this matrix "
            "produced could be published (REQ-11):\n  " + "\n  ".join(drift)
        )
    # One matrix may span both corpora; the id and the record carry the hash of
    # each corpus it actually touched, because a single "corpus_manifest" over a
    # mixed matrix would name one of two and quietly imply the other.
    manifests = {dataset: hash_for_dataset(dataset) for dataset in datasets}
    manifest = manifests[datasets[0]]

    opened = _open_sealed_batches(
        datasets, reason=reason, override=override, who=who
    )
    opening = opened[0] if opened else None

    from kernel.canonical import sha256_of

    matrix_id = sha256_of(
        {
            "datasets": list(datasets),
            "configs": list(configs),
            "seed": seed,
            "model": model,
            "corpus_manifest": manifest,
            "corpus_manifests": dict(sorted(manifests.items())),
            "limit": limit,
        }
    )
    directory = Path(out_dir) if out_dir else RUNS_DIR / f"matrix-{matrix_id[7:23]}"
    directory.mkdir(parents=True, exist_ok=True)

    result = MatrixResult(
        matrix_id=matrix_id,
        seed=seed,
        model=model,
        corpus_manifest=manifest,
        out_dir=directory,
        datasets=tuple(datasets),
        configs=tuple(configs),
        started_at=_now(),
        batch_b_opening=opening,
        batch_b_openings=openings(),
        corpus_manifests=dict(sorted(manifests.items())),
    )

    for dataset in datasets:
        for config in configs:
            cases = select(dataset, limit=limit)
            path = directory / f"{dataset}.{config.replace('+', '_')}.jsonl"
            suite: SuiteResult = run_suite(
                cases,
                dataset=dataset,
                config=config,
                seed=seed,
                model=model,
                out=path,
                progress=(
                    (lambda i, n, _r, d=dataset, c=config: progress(d, c, i, n))
                    if progress
                    else None
                ),
            )
            result.corpus_drift.extend(suite.corpus_drift)
            result.cells.append(
                MatrixCell(
                    dataset=dataset,
                    config=config,
                    suite_id=suite.suite_id,
                    path=path,
                    records=_tag(_read_jsonl(path), dataset),
                )
            )

    result.finished_at = _now()
    (directory / "matrix.json").write_text(
        json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n"
    )
    return result


def run_ablation(
    *,
    dataset: str = "batch_a",
    checks: Sequence[int] = ABLATABLE,
    seed: str = "0",
    model: str = "auto",
    out_dir: Path | None = None,
    limit: int | None = None,
    modes: Sequence[str] = ("single", "isolated", "floor"),
    progress: Callable[[str, int, int], None] | None = None,
) -> AblationResult:
    """The kernel arm with all checks on, then once per check in each mode.

    Only the ``kernel`` arm is ablated, and only it can be: the other arms have
    no checks. The baseline is re-run here rather than reused from a matrix so
    that every row was produced in one process, against one corpus hash, on one
    machine — a baseline borrowed from a different run would make every delta
    partly a difference between two environments.

    See :class:`AblationRow` for why there are three modes rather than one.
    """
    unknown = sorted(set(checks) - set(ABLATABLE))
    if unknown:
        raise ValueError(
            f"cannot ablate {unknown}. Checks 7 and 9 are lifecycle steps, not "
            "predicates: removing either does not weaken a rule, it removes "
            "the thing that makes every other row meaningful. See ABLATABLE."
        )
    bad_modes = sorted(set(modes) - {"single", "isolated", "floor"})
    if bad_modes:
        raise ValueError(f"unknown ablation mode(s) {bad_modes}")

    drift = verify_all()
    if drift:
        raise RuntimeError(
            "a corpus does not match its manifest (REQ-11):\n  " + "\n  ".join(drift)
        )
    manifest = hash_for_dataset(dataset)

    from kernel.canonical import sha256_of

    ablation_id = sha256_of(
        {
            "dataset": dataset,
            "checks": list(checks),
            "modes": list(modes),
            "seed": seed,
            "model": model,
            "corpus_manifest": manifest,
            "limit": limit,
        }
    )
    directory = Path(out_dir) if out_dir else RUNS_DIR / f"ablate-{ablation_id[7:23]}"
    directory.mkdir(parents=True, exist_ok=True)

    result = AblationResult(
        dataset=dataset,
        seed=seed,
        model=model,
        corpus_manifest=manifest,
        out_dir=directory,
        started_at=_now(),
    )

    cases = select(dataset, limit=limit)

    # The plan, built before anything runs so the progress counter can say how
    # far through it is rather than counting up from nowhere.
    plan: list[tuple[str, tuple[int, ...], str, str]] = []
    if "single" in modes:
        for check_id in checks:
            plan.append(
                (
                    "single",
                    (check_id,),
                    f"check {check_id} off",
                    f"{dataset}.kernel.no{check_id}.jsonl",
                )
            )
    if "isolated" in modes:
        for check_id in checks:
            others = tuple(c for c in ABLATABLE if c != check_id)
            plan.append(
                (
                    "isolated",
                    others,
                    f"only check {check_id} on",
                    f"{dataset}.kernel.only{check_id}.jsonl",
                )
            )
    if "floor" in modes:
        plan.append(
            (
                "floor",
                tuple(ABLATABLE),
                "every predicate off",
                f"{dataset}.kernel.floor.jsonl",
            )
        )

    baseline_path = directory / f"{dataset}.kernel.jsonl"
    if progress:
        progress("baseline", 0, len(plan))
    baseline = run_suite(
        cases, dataset=dataset, config="kernel", seed=seed, model=model,
        out=baseline_path,
    )
    result.baseline = _tag(_read_jsonl(baseline_path), dataset)
    result.baseline_suite_id = baseline.suite_id

    for index, (mode, disabled, label, filename) in enumerate(plan, start=1):
        if progress:
            progress(label, index, len(plan))
        path = directory / filename
        suite = run_suite(
            cases,
            dataset=dataset,
            config="kernel",
            seed=seed,
            model=model,
            out=path,
            disabled_checks=disabled,
        )
        about = (
            disabled
            if mode == "single"
            else tuple(c for c in checks if c not in disabled)
            if mode == "isolated"
            else disabled
        )
        result.rows.append(
            AblationRow(
                check_ids=about if mode != "floor" else tuple(disabled),
                label=label,
                mode=mode,
                suite_id=suite.suite_id,
                path=path,
                records=_tag(_read_jsonl(path), dataset),
            )
        )

    result.finished_at = _now()
    (directory / "ablation.json").write_text(
        json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n"
    )
    return result


def load_matrix(directory: Path) -> MatrixResult:
    """Rebuild a matrix from the files it left behind.

    The reason ``mk report`` is a separate command from ``mk matrix``: the
    published table has to be reproducible from the JSONL on disk by somebody
    who did not run the suites, and a renderer that could only read an in-memory
    object would make the numbers a property of the process that produced them.
    """
    directory = Path(directory)
    body = json.loads((directory / "matrix.json").read_text())
    result = MatrixResult(
        matrix_id=body["matrix_id"],
        seed=body["seed"],
        model=body["model"],
        corpus_manifest=body["corpus_manifest"],
        out_dir=directory,
        datasets=tuple(body["datasets"]),
        configs=tuple(body["configs"]),
        started_at=body["started_at"],
        finished_at=body.get("finished_at", ""),
        batch_b_opening=body.get("batch_b_opening"),
        batch_b_openings=list(body.get("batch_b_openings", [])),
        corpus_drift=list(body.get("corpus_drift", [])),
        corpus_manifests=dict(body.get("corpus_manifests", {})),
    )
    for cell in body["cells"]:
        path = directory / cell["records"]
        result.cells.append(
            MatrixCell(
                dataset=cell["dataset"],
                config=cell["config"],
                suite_id=cell["suite_id"],
                path=path,
                records=_tag(_read_jsonl(path), cell["dataset"]),
            )
        )
    return result
