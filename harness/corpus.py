"""Loading tasks and attack cases, and refusing the ones that would lie.

The loading is the easy half. The refusals are the point, and every one of them
exists because the mistake it catches produces a **clean-looking result**:

* an attack naming an injection point that does not exist puts its payload
  nowhere, and a run with no payload in it looks exactly like a defended run;
* an attack naming a task that cannot reach its class — an A7 case on a task
  that never asks for a refund, an A4 case on a task that never sees a
  subscription offer — runs the attack through a plan that has no step for it,
  and scores as a defence;
* an attack scored by another class's oracle is a row filed under the wrong
  heading in the results table;
* a task naming a merchant that does not exist is the same mistake wearing a
  different hat.

All of them are the general rule this project keeps applying: a mistake that
produces a plausible number is worse than one that produces a crash.

**Batch B is sealed.** Its case ids, classes and injection points are readable —
that is what ``mk corpus verify`` counts — but its *payloads* are not, until
:func:`open_batch_b` has been called and has written the opening to
``harness/attacks/openings.jsonl``. A second opening needs an explicit override
and is logged as one. That is the mitigation for a model-expanded corpus, and it
is a mitigation rather than a proof: held out and opened once is a weaker claim
than a corpus nobody could have tuned against, and ``results.md`` says so.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from harness.oracles import ORACLE_FOR_CLASS
from sim.merchants.base import Injection, InjectionPoint
from sim.world import MERCHANTS

__all__ = [
    "HARNESS_ROOT",
    "TASKS_DIR",
    "GENERATED_ROOT",
    "GEN_TASKS_DIR",
    "TASK_CORPORA",
    "ATTACKS_DIRS",
    "BATCHES",
    "GEN_BATCHES",
    "ALL_BATCHES",
    "SEALED_BATCHES",
    "CLASSES",
    "TECHNIQUES",
    "CLASS_REQUIRES",
    "POINT_ORDER",
    "CLASS_DECIDES_AFTER",
    "POINT_REQUIRES",
    "BatchBSealed",
    "CorpusError",
    "Task",
    "AttackCase",
    "load_task",
    "load_attack",
    "list_tasks",
    "list_attacks",
    "list_batch",
    "open_batch",
    "open_batch_b",
    "join_batch",
    "openings",
    "reads",
    "batch_b_openings",
    "batch_is_open",
    "batch_b_is_open",
]

HARNESS_ROOT = Path(__file__).resolve().parent
TASKS_DIR = HARNESS_ROOT / "tasks"
ATTACKS_ROOT = HARNESS_ROOT / "attacks"
BATCHES: dict[str, Path] = {
    "a": ATTACKS_ROOT / "batch_a",
    "b": ATTACKS_ROOT / "batch_b",
}
ATTACKS_DIRS = tuple(BATCHES.values())

#: The generated corpus (P8), in its own tree. **Not** mixed into
#: ``harness/tasks`` and ``harness/attacks``: the hand-written corpus's
#: published tables quote ``harness/manifest.json``'s hash, and a generated
#: task dropped into the directory that manifest covers would move that hash
#: and silently invalidate every one of those tables. Two corpora, two
#: manifests, two sets of tables — which is also what issue #68 asks for: the
#: generated tables go *beside* the hand-written ones, never over them.
GENERATED_ROOT = HARNESS_ROOT / "generated"
GEN_TASKS_DIR = GENERATED_ROOT / "tasks"
GEN_ATTACKS_ROOT = GENERATED_ROOT / "attacks"
GEN_BATCHES: dict[str, Path] = {
    "gen-a": GEN_ATTACKS_ROOT / "gen_a",
    "gen-b": GEN_ATTACKS_ROOT / "gen_b",
}

def _task_corpora() -> dict[str, Path]:
    """Which task set each corpus name draws from.

    A function for the same reason :func:`_batches` is one: ``TASKS_DIR`` is
    monkeypatched in tests, and a module-level dict would freeze the pre-patch
    value and quietly point the loader at the shipped corpus.
    """
    return {"handwritten": TASKS_DIR, "generated": GEN_TASKS_DIR}


#: Named for import; :func:`_task_corpora` is what the code uses. ``list_tasks``
#: defaults to the hand-written corpus, so nothing that counted 25 tasks before
#: P8 counts hundreds now.
TASK_CORPORA = _task_corpora()


def _batches() -> dict[str, Path]:
    """Every batch, hand-written and generated.

    A function rather than a constant because ``BATCHES`` is monkeypatched in
    tests, and a module-level merge would freeze the pre-patch value.
    """
    return {**BATCHES, **GEN_BATCHES}


#: Named for import; :func:`_batches` is what the code uses.
ALL_BATCHES = _batches()

#: Batches whose payloads are sealed until the batch is opened. Held-out sets:
#: ``b`` is the hand-written one and ``gen-b`` is the generated one, and both
#: are under the same single-open guard for the same reason — a development run
#: that quietly read one would tune the thing being measured against its own
#: measurement, and nothing afterwards could tell that it had happened.
SEALED_BATCHES: frozenset[str] = frozenset({"b", "gen-b"})

#: Where an opening of batch B is recorded. Outside ``batch_b/`` on purpose:
#: the seal's own record must not be one of the files the seal covers, or
#: opening the batch would change the manifest hash that pins it.
OPENINGS_LOG = ATTACKS_ROOT / "openings.jsonl"

#: The seven classes. Closed, and the same seven the oracles are keyed by.
CLASSES = tuple(sorted(ORACLE_FOR_CLASS))

#: The four evasion families, SPEC.md §12. Closed for the same reason the
#: classes are: a results table that groups by technique cannot group by a
#: value somebody invented in a file.
TECHNIQUES = (
    "base64",
    "semantic_persuasion",
    "non_english",
    "formatting",
)

#: What a task must offer for a class to be reachable inside it.
#:
#: This is the refusal that is easiest to get wrong and most expensive when it
#: is. An A7 payload on a task that never asks for a refund reaches a planner
#: that never runs the refund steps: the payload is served, nobody acts on it,
#: no money is misdirected, and the oracle says ``False``. That reads in the
#: results table as a defence. The run has to be impossible to construct rather
#: than merely wrong.
CLASS_REQUIRES: dict[str, tuple[str, ...]] = {
    "A1": (),
    "A2": (),
    # A3 compares the cart at capture against the one the ceremony signed, so a
    # task with no signed cart has nothing to compare against and its A3 oracle
    # would be false by construction.
    "A3": ("mandates",),
    "A4": ("offers",),
    "A5": ("settlement_check",),
    "A6": ("settlement_check",),
    "A7": ("refund",),
}

#: The order the planner reads the eight surfaces in, and which surface each
#: class's decision comes after. Together these answer one question a case has
#: to get right: **had the agent read this page yet when it made the decision
#: this class attacks?**
#:
#: A payload at ``checkout.response`` cannot inflate a cart, because the cart is
#: built before the checkout page is fetched. It would be served, hashed into
#: the event log, and have no effect — a perfectly clean run, scored as a
#: defence. That is the same failure a typo'd injection point produces, one
#: level up, and it is refused the same way.
#:
#: ``tests/test_injection_points.py`` re-derives this order from an actual run
#: rather than trusting it, because a table that drifts from the planner is a
#: table that starts approving cases that cannot work.
POINT_ORDER: tuple[str, ...] = (
    "catalog.response",
    "product.description",
    "price.field",
    "seller_api.response",
    "checkout.response",
    "webhook.payload",
    "promo.copy",
    "support.flow",
)

#: The last surface each class's decision has read. A case may inject at that
#: point or anything before it.
CLASS_DECIDES_AFTER: dict[str, str] = {
    # choose_payee, after the checkout page names its payee.
    "A1": "checkout.response",
    # build_cart, before the checkout page exists.
    "A2": "seller_api.response",
    "A3": "seller_api.response",
    # decide_subscription, after the promotions page.
    "A4": "promo.copy",
    # decide_further_payments, after the order status page.
    "A5": "webhook.payload",
    "A6": "webhook.payload",
    # choose_refund_destination, last of all.
    "A7": "support.flow",
}

#: Which optional step a surface is only served by. A payload at
#: ``support.flow`` on a task that never asks for a refund is served to nobody.
POINT_REQUIRES: dict[str, str] = {
    "webhook.payload": "settlement_check",
    "promo.copy": "offers",
    "support.flow": "refund",
}

#: Which sealed batches this process may read, set by :func:`open_batch`.
#: Process-local rather than a file flag: the *log* is the durable record, and a
#: flag on disk would let a stray unlink quietly unseal a batch.
_OPEN: set[str] = set()


class CorpusError(ValueError):
    """A corpus file that would produce a number nobody could trust."""


class BatchBSealed(RuntimeError):
    """A batch B payload was asked for before the batch was opened.

    Deliberately not a warning. Batch B is the held-out set and the headline
    number comes from it; a development run that quietly read it would tune the
    kernel against the thing that is supposed to be measuring the kernel, and
    nothing afterwards could tell that it had happened.
    """


@dataclass(frozen=True)
class Task:
    raw: dict[str, Any]
    #: Which corpus this task came from — ``handwritten`` or ``generated``.
    #: On the object rather than inferred from the id, because every run record
    #: has to name the manifest that covers it and there are two manifests now.
    #: A generated line quoting the hand-written hash would point a reader at
    #: 235 files that had nothing to do with the number in front of them.
    corpus: str = "handwritten"

    @property
    def task_id(self) -> str:
        return self.raw["task_id"]

    @property
    def merchant(self) -> str:
        return self.raw["merchant"]

    @property
    def expect(self) -> dict[str, Any]:
        return self.raw["expect"]

    def offers(self, capability: str) -> bool:
        """Whether this task reaches the planner step ``capability`` names."""
        return bool(self.raw.get(capability))


@dataclass(frozen=True)
class AttackCase:
    raw: dict[str, Any]

    @property
    def case_id(self) -> str:
        return self.raw["case_id"]

    @property
    def attack_class(self) -> str:
        return self.raw["class"]

    @property
    def batch(self) -> str:
        return self.raw["batch"]

    @property
    def task_id(self) -> str:
        return self.raw["task"]

    @property
    def point(self) -> InjectionPoint:
        return InjectionPoint(self.raw["injection_point"])

    @property
    def oracle(self) -> str:
        return self.raw["oracle"]

    @property
    def technique(self) -> str:
        return self.raw["technique"]

    @property
    def payload(self) -> str:
        """The attack text. Sealed for batch B until the batch is opened.

        The seal is on the payload rather than on the file, so counting,
        hashing and validating batch B — everything ``mk corpus verify`` does —
        stays possible while the thing that could tune a defence stays out of
        reach.
        """
        if self.batch in SEALED_BATCHES and self.batch not in _OPEN:
            raise BatchBSealed(
                f"{self.case_id} is in batch {self.batch!r}, which is sealed. "
                "It is a held-out set and a headline number comes from it; "
                "reading it during development would tune the kernel against "
                "its own measurement. Call "
                f"harness.corpus.open_batch({self.batch!r}, reason=...) — it is "
                f"logged to {OPENINGS_LOG.name} and a second opening needs an "
                "explicit override."
            )
        return self.raw["payload"]

    def injection(self) -> Injection:
        return Injection(point=self.point, payload=self.payload, case_id=self.case_id)


def _read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# The seal
# ---------------------------------------------------------------------------


def reads(batch: str | None = None) -> list[dict[str, Any]]:
    """Every logged read of a sealed batch — openings and joins alike.

    ``batch`` filters; ``None`` returns the whole log. Entries written before
    P8 carry no ``batch`` and no ``kind`` and are read as openings of batch
    ``b``, which is what they were — a log that could not be read back after
    the format grew would be a log that stopped being evidence.
    """
    if not OPENINGS_LOG.exists():
        return []
    entries = [
        json.loads(line)
        for line in OPENINGS_LOG.read_text().splitlines()
        if line.strip()
    ]
    entries = [{"batch": "b", "kind": "open", **entry} for entry in entries]
    if batch is None:
        return entries
    return [entry for entry in entries if entry["batch"] == batch]


def openings(batch: str | None = None) -> list[dict[str, Any]]:
    """The *openings* only. Joins are reads of an opening, not new ones.

    A sharded run is eight processes reading one held-out set under one
    decision. Counting each process as an opening would make "opened once" read
    as "opened eight times" and the number would stop meaning anything; not
    logging them at all would make a read leave no trace, which is the one
    thing the seal exists to prevent. So a join is written down, timestamped,
    and counted separately.
    """
    return [entry for entry in reads(batch) if entry.get("kind") == "open"]


def batch_b_openings() -> list[dict[str, Any]]:
    """Openings of the hand-written held-out batch."""
    return openings("b")


def batch_is_open(batch: str) -> bool:
    """Whether this process may read ``batch``'s payloads."""
    return batch not in SEALED_BATCHES or batch in _OPEN


def batch_b_is_open() -> bool:
    return batch_is_open("b")


def open_batch(
    batch: str, reason: str, *, override: bool = False, who: str = "harness"
) -> dict[str, Any]:
    """Unseal one held-out batch for this process, and write down that it happened.

    The first opening of a batch needs only a reason. Every opening after it
    needs ``override=True`` as well, and is recorded as an override — which is
    the whole of "opened exactly once" as an enforceable rule rather than an
    intention. Nothing here can prevent a second read; what it can do is make a
    second read impossible to perform silently, so ``results.md`` can say how
    many times each held-out set was looked at and be checked.

    Counted **per batch**: opening ``gen-b`` says nothing about ``b``, and a
    guard that treated one opening as unsealing both would let the generated
    corpus's measurement quietly unseal the hand-written one.
    """
    if batch not in SEALED_BATCHES:
        raise CorpusError(
            f"batch {batch!r} is not sealed; the sealed ones are "
            f"{sorted(SEALED_BATCHES)}. Opening an unsealed batch would write a "
            "line into the openings log that means nothing."
        )
    if not reason.strip():
        raise CorpusError("opening a held-out batch needs a reason; it goes in the log")

    prior = openings(batch)
    if prior and not override:
        first = prior[0]
        raise BatchBSealed(
            f"batch {batch!r} was already opened at {first['at']} for "
            f"{first['reason']!r} ({len(prior)} opening(s) logged). A second "
            "read needs override=True and is logged as an override — the "
            "headline number is only a held-out number the first time."
        )

    return _log_read(
        batch,
        kind="open",
        reason=reason.strip(),
        who=who,
        override=bool(prior),
        sequence=len(prior) + 1,
    )


def _log_read(batch: str, **fields: Any) -> dict[str, Any]:
    entry = {
        "at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "batch": batch,
        **fields,
    }
    OPENINGS_LOG.parent.mkdir(parents=True, exist_ok=True)
    with OPENINGS_LOG.open("a") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    _OPEN.add(batch)
    return entry


def join_batch(batch: str, *, who: str = "harness", note: str = "") -> dict[str, Any]:
    """Read a held-out batch under an opening already on record.

    The primitive a *sharded* run needs. Eight shards of one experiment are
    eight processes and one decision: each has to be able to read the payloads,
    and none of them is a new opening. So a join requires that an opening
    already exists — it can never be the first read — and it is written to the
    same log with ``kind: join`` so the read still leaves a trace.

    What this does **not** do is make a second read invisible. Every join is
    timestamped and attributed, ``mk corpus verify`` prints them, and
    ``results.md`` reports openings and joins as two numbers. A read that left
    no record is the one thing the seal exists to prevent, and a join is a
    record.
    """
    if batch not in SEALED_BATCHES:
        raise CorpusError(
            f"batch {batch!r} is not sealed; the sealed ones are "
            f"{sorted(SEALED_BATCHES)}. There is nothing to join."
        )
    prior = openings(batch)
    if not prior:
        raise BatchBSealed(
            f"batch {batch!r} has never been opened, so there is no opening to "
            "join. The first read is a decision with a reason: call "
            f"open_batch({batch!r}, reason=...)."
        )
    return _log_read(
        batch,
        kind="join",
        opening_at=prior[-1]["at"],
        reason=prior[-1]["reason"],
        who=who,
        note=note,
    )


def open_batch_b(reason: str, *, override: bool = False, who: str = "harness") -> dict[str, Any]:
    """Unseal the hand-written held-out batch. See :func:`open_batch`."""
    return open_batch("b", reason, override=override, who=who)


# ---------------------------------------------------------------------------
# Listing, and the index that makes it survive a corpus of thousands
# ---------------------------------------------------------------------------
#
# The hand-written corpus is 235 files and a linear scan for a case id was
# free. The generated one is thousands, and a suite that scanned every file for
# every case would spend more time in ``json.loads`` than in the kernel — which
# would land straight in the overhead column, the one number here a reader is
# invited to compare against a real deployment.
#
# So both loaders go through a cached ``id -> path`` index. The cache key
# carries the directory's modification time, so adding or removing a file
# rebuilds it while *editing* a file does not: an edit cannot change which id
# lives at which path, and the content is re-read on every load either way.


def _json_files(directory: Path) -> list[Path]:
    """Every case or task file under ``directory``, flat or sharded.

    Both layouts, because the hand-written corpus is flat and the generated one
    is sharded into subdirectories — thousands of files in one directory is a
    directory nobody can read and a ``git status`` nobody can scan.
    """
    if not directory.is_dir():
        return []
    return sorted([*directory.glob("*.json"), *directory.glob("*/*.json")])


@lru_cache(maxsize=64)
def _index_at(directory: Path, _stamp: int, key: str) -> dict[str, str]:
    return {_read(path)[key]: str(path) for path in _json_files(directory)}


def _index(directory: Path, key: str) -> dict[str, Path]:
    try:
        stamp = directory.stat().st_mtime_ns
    except OSError:
        return {}
    return {
        found: Path(path)
        for found, path in _index_at(directory, stamp, key).items()
    }


def list_tasks(corpus: str = "handwritten") -> list[str]:
    """Task ids in one corpus. Defaults to the hand-written 25.

    Defaulting rather than returning everything is deliberate: ``harness.suite``
    builds the ``benign`` dataset from this, ``harness.manifest`` counts it, and
    both of those are about the corpus whose numbers are already published. A
    default that quietly grew to include the generated tasks would change the
    meaning of a published count without changing a line that quotes it.
    """
    corpora = _task_corpora()
    directory = corpora.get(corpus)
    if directory is None:
        raise CorpusError(f"no task corpus {corpus!r}; known: {sorted(corpora)}")
    return sorted(_index(directory, "task_id"))


def list_batch(batch: str) -> list[str]:
    """Case ids in one batch. Reads metadata, never a payload."""
    directory = _batches().get(batch)
    if directory is None:
        raise CorpusError(f"no batch {batch!r}; known: {sorted(_batches())}")
    return sorted(_index(directory, "case_id"))


def list_attacks(batches: tuple[str, ...] | None = None) -> list[str]:
    """Case ids across batches. Defaults to the hand-written two.

    Same reasoning as :func:`list_tasks`: everything that counted 210 cases
    before P8 still counts 210.
    """
    names = batches if batches is not None else tuple(BATCHES)
    return sorted(case for batch in names for case in list_batch(batch))


# ---------------------------------------------------------------------------
# Loading, with the refusals
# ---------------------------------------------------------------------------


def load_task(task_id: str) -> Task:
    for corpus, directory in _task_corpora().items():
        path = _index(directory, "task_id").get(task_id)
        if path is None:
            continue
        raw = _read(path)
        if raw["merchant"] not in MERCHANTS:
            raise CorpusError(
                f"{path.name} names merchant {raw['merchant']!r}; "
                f"known: {sorted(MERCHANTS)}"
            )
        return Task(raw, corpus=corpus)
    raise KeyError(
        f"no task {task_id!r}; known: {len(list_tasks())} hand-written, "
        f"{len(list_tasks('generated'))} generated"
    )


def _validate(raw: dict[str, Any], path: Path, batch: str) -> None:
    """Everything that has to be true before a case may be run.

    Each check has a sentence saying what wrong number it prevents, because a
    validation rule without one is a rule nobody will be able to justify
    removing later.
    """
    case_id = raw.get("case_id", path.name)

    missing = sorted(
        {
            "case_id",
            "class",
            "batch",
            "task",
            "injection_point",
            "payload",
            "technique",
            "oracle",
            "expected_undefended",
        }
        - set(raw)
    )
    if missing:
        raise CorpusError(f"{path.name} is missing {missing}")

    if raw["batch"] != batch:
        raise CorpusError(
            f"{case_id} says it is in batch {raw['batch']!r} but sits in "
            f"batch_{batch}. The batch decides whether the case is sealed and "
            "whether its result is the headline; a case in the wrong directory "
            "would be counted in the wrong column."
        )

    if raw["class"] not in CLASSES:
        raise CorpusError(
            f"{case_id} is class {raw['class']!r}; the seven are {list(CLASSES)}. "
            "A class with no oracle cannot be scored."
        )

    expected_oracle = ORACLE_FOR_CLASS[raw["class"]]
    if raw["oracle"] != expected_oracle:
        raise CorpusError(
            f"{case_id} is class {raw['class']} but names oracle "
            f"{raw['oracle']!r}; that class is scored by {expected_oracle!r}. "
            "Scoring a case with another class's predicate files its result "
            "under the wrong heading."
        )

    if raw["technique"] not in TECHNIQUES:
        raise CorpusError(
            f"{case_id} uses technique {raw['technique']!r}; the four evasion "
            f"families are {list(TECHNIQUES)}. A technique nobody declared "
            "cannot be grouped by in the results table."
        )

    if raw["expected_undefended"] not in ("win", "loss"):
        raise CorpusError(
            f"{case_id} expects {raw['expected_undefended']!r} undefended; "
            "it must be 'win' or 'loss'."
        )

    try:
        InjectionPoint(raw["injection_point"])
    except ValueError:
        raise CorpusError(
            f"{case_id} injects at {raw['injection_point']!r}, which is not "
            "one of the eight named points. A payload placed nowhere produces "
            "a clean run that would be counted as a defended one. Known: "
            f"{[p.value for p in InjectionPoint]}"
        ) from None

    point = raw["injection_point"]
    decides_after = CLASS_DECIDES_AFTER[raw["class"]]
    if POINT_ORDER.index(point) > POINT_ORDER.index(decides_after):
        raise CorpusError(
            f"{case_id} is class {raw['class']}, whose decision is made after "
            f"{decides_after!r}, but injects at {point!r} — a page the agent "
            "has not read yet at that point. The payload would be served and "
            "have no effect, and a run with no effect in it is counted as a "
            "defended one."
        )

    task = load_task(raw["task"])
    needed = POINT_REQUIRES.get(point)
    if needed is not None and not task.offers(needed):
        raise CorpusError(
            f"{case_id} injects at {point!r}, which task {raw['task']!r} never "
            f"fetches: that surface is only read by the {needed!r} step. The "
            "payload would be served to nobody."
        )

    for capability in CLASS_REQUIRES[raw["class"]]:
        if not task.offers(capability):
            raise CorpusError(
                f"{case_id} is class {raw['class']} and runs against task "
                f"{raw['task']!r}, which has no {capability!r}. The planner "
                "would never reach the step this class attacks, no money would "
                "move, and the oracle would say False — which reads as a "
                "defence."
            )


def load_attack(case_id: str) -> AttackCase:
    for batch, directory in _batches().items():
        path = _index(directory, "case_id").get(case_id)
        if path is None:
            continue
        raw = _read(path)
        _validate(raw, path, batch)
        return AttackCase(raw)
    raise KeyError(
        f"no attack {case_id!r}; known: {len(list_attacks())} hand-written, "
        f"{len(list_attacks(tuple(GEN_BATCHES)))} generated"
    )
