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
from pathlib import Path
from typing import Any

from harness.oracles import ORACLE_FOR_CLASS
from sim.merchants.base import Injection, InjectionPoint
from sim.world import MERCHANTS

__all__ = [
    "HARNESS_ROOT",
    "TASKS_DIR",
    "ATTACKS_DIRS",
    "BATCHES",
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
    "open_batch_b",
    "batch_b_openings",
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

#: Set once :func:`open_batch_b` succeeds, for this process only. Process-local
#: rather than a file flag: the *log* is the durable record, and a flag on disk
#: would let a stray unlink quietly unseal the batch.
_BATCH_B_OPEN = False


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
        if self.batch == "b" and not _BATCH_B_OPEN:
            raise BatchBSealed(
                f"{self.case_id} is in batch B, which is sealed. Batch B is the "
                "held-out set and the headline number comes from it; reading it "
                "during development would tune the kernel against its own "
                "measurement. Call harness.corpus.open_batch_b(reason=...) — it "
                f"is logged to {OPENINGS_LOG.name} and a second opening needs an "
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


def batch_b_openings() -> list[dict[str, Any]]:
    """Every time batch B has been opened, in order. Empty if never."""
    if not OPENINGS_LOG.exists():
        return []
    return [json.loads(line) for line in OPENINGS_LOG.read_text().splitlines() if line.strip()]


def batch_b_is_open() -> bool:
    """Whether this process may read batch B payloads."""
    return _BATCH_B_OPEN


def open_batch_b(reason: str, *, override: bool = False, who: str = "harness") -> dict[str, Any]:
    """Unseal batch B for this process, and write down that it happened.

    The first opening needs only a reason. Every opening after it needs
    ``override=True`` as well, and is recorded as an override — which is the
    whole of "opened exactly once" as an enforceable rule rather than an
    intention. Nothing here can prevent a second read; what it can do is make a
    second read impossible to perform silently, so ``results.md`` can say how
    many times the held-out set was looked at and be checked.
    """
    global _BATCH_B_OPEN
    if not reason.strip():
        raise CorpusError("opening batch B needs a reason; it goes in the log")

    prior = batch_b_openings()
    if prior and not override:
        first = prior[0]
        raise BatchBSealed(
            f"batch B was already opened at {first['at']} for "
            f"{first['reason']!r} ({len(prior)} opening(s) logged). A second "
            "read needs override=True and is logged as an override — the "
            "headline number is only a held-out number the first time."
        )

    entry = {
        "at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "reason": reason.strip(),
        "who": who,
        "override": bool(prior),
        "sequence": len(prior) + 1,
    }
    OPENINGS_LOG.parent.mkdir(parents=True, exist_ok=True)
    with OPENINGS_LOG.open("a") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    _BATCH_B_OPEN = True
    return entry


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


def list_tasks() -> list[str]:
    return sorted(_read(p)["task_id"] for p in TASKS_DIR.glob("*.json"))


def list_batch(batch: str) -> list[str]:
    """Case ids in one batch. Reads metadata, never a payload."""
    directory = BATCHES.get(batch)
    if directory is None:
        raise CorpusError(f"no batch {batch!r}; known: {sorted(BATCHES)}")
    return sorted(_read(p)["case_id"] for p in directory.glob("*.json"))


def list_attacks() -> list[str]:
    return sorted(case for batch in BATCHES for case in list_batch(batch))


# ---------------------------------------------------------------------------
# Loading, with the refusals
# ---------------------------------------------------------------------------


def load_task(task_id: str) -> Task:
    for path in sorted(TASKS_DIR.glob("*.json")):
        raw = _read(path)
        if raw["task_id"] != task_id:
            continue
        if raw["merchant"] not in MERCHANTS:
            raise CorpusError(
                f"{path.name} names merchant {raw['merchant']!r}; "
                f"known: {sorted(MERCHANTS)}"
            )
        return Task(raw)
    raise KeyError(f"no task {task_id!r}; known: {list_tasks()}")


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
    for batch, directory in BATCHES.items():
        for path in sorted(directory.glob("*.json")):
            raw = _read(path)
            if raw.get("case_id") != case_id:
                continue
            _validate(raw, path, batch)
            return AttackCase(raw)
    raise KeyError(f"no attack {case_id!r}; known: {len(list_attacks())} cases")
