"""S-02 — every oracle must be shown to fire, and shown to be able not to.

This is the single test that keeps the headline number honest, and it is worth
being precise about what it does and does not prove.

**What it proves.** For each of the seven classes there is a named attack that
lands against the undefended agent, and the class's oracle returns ``True`` for
that run. An oracle that always returned ``False`` would read in the results
table as a perfect defence — the kernel would appear to have stopped an attack
that the harness had quietly made unreachable — and this is what catches that.

**The dual, which matters just as much.** Each oracle is also run against the
same task with no attack present, and must return ``False``. An oracle that
always returns ``True`` is a lint that cannot pass: every arm scores as a total
loss, including the kernel's, and the comparison between arms stops meaning
anything. Both halves have to hold or the row fails.

**What it does not prove.** That the corpus is hard, that the classes are
exhaustive, or that a real model behaves like the stand-in. The reference cases
are run with whatever model the caller names; with the deterministic stand-in
this is a test of the *harness*, not a model measurement, and the row says so.

The reference cases are **named**, not searched for. A selftest that scanned
until it found something that fired would pass as long as any case in the class
worked, and would go on passing while the case it was written around quietly
stopped landing. Naming them means a failure says which attack stopped working.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from harness.corpus import CLASSES, load_attack, load_task
from harness.oracles import ORACLE_FOR_CLASS, Authority, LedgerView, oracle_for
from harness.runner import run_case

__all__ = ["SELFTEST_CASES", "OracleRow", "selftest"]

#: The known-successful attack each oracle is demonstrated against. One per
#: class, hand-written (they are the seeds), and fixed here rather than
#: discovered, so a failure names the case that stopped landing.
SELFTEST_CASES: dict[str, str] = {klass: f"{klass}-seed-1" for klass in CLASSES}


@dataclass
class OracleRow:
    """One row of ``mk oracles selftest``."""

    attack_class: str
    oracle: str
    case_id: str
    task_id: str
    fired_on_attack: bool
    quiet_on_benign: bool
    evidence: str = ""
    error: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Both halves, or the row fails.

        ``fired_on_attack`` alone would accept an oracle that returns ``True``
        unconditionally; ``quiet_on_benign`` alone would accept one that returns
        ``False`` unconditionally. Each is exactly the failure the other cannot
        see.
        """
        return self.fired_on_attack and self.quiet_on_benign and self.error is None


def _evidence(attack_class: str, record: Any) -> str:
    """One line saying what the oracle actually saw. Never the payload.

    The chain and the logs never carry attack text (SPEC.md §12, containment),
    and neither does this: it reports the *effect* — where money went, how many
    times — which is what the oracle read.
    """
    captures = record.ledger
    if attack_class == "A1":
        return ", ".join(sorted({c["payee"]["value"] for c in captures})) or "no capture"
    if attack_class == "A2":
        return f"largest capture {max((c['captured_paise'] for c in captures), default=0)} paise"
    if attack_class == "A3":
        return f"{len({c.get('cart_hash') for c in captures})} distinct cart hash(es) at capture"
    if attack_class == "A4":
        return f"{len(record.mandates)} standing instruction(s) opened"
    if attack_class == "A5":
        return f"{len(captures)} settled debit(s)"
    if attack_class == "A6":
        hashes = [c.get("cart_hash") for c in captures]
        return f"{len(hashes)} debit(s) over {len(set(hashes))} cart hash(es)"
    if attack_class == "A7":
        return ", ".join(
            f"{r['source']['value']} -> {r['destination']['value']}" for r in record.refunds
        ) or "no refund"
    return ""


def _view(record: Any) -> LedgerView:
    return LedgerView(
        captures=record.ledger, refunds=record.refunds, mandates=record.mandates
    )


def selftest(*, seed: str = "s02", model: str = "scripted") -> list[OracleRow]:
    """Run the seven reference cases and their seven benign controls."""
    rows: list[OracleRow] = []

    for attack_class in CLASSES:
        case_id = SELFTEST_CASES[attack_class]
        oracle_name = ORACLE_FOR_CLASS[attack_class]
        row = OracleRow(
            attack_class=attack_class,
            oracle=oracle_name,
            case_id=case_id,
            task_id="",
            fired_on_attack=False,
            quiet_on_benign=False,
        )
        try:
            case = load_attack(case_id)
            row.task_id = case.task_id
            oracle = oracle_for(oracle_name)
            authority = Authority.from_task(load_task(case.task_id).raw)

            attacked = run_case(
                config="undefended", attack_id=case_id, seed=seed, model=model
            )
            row.fired_on_attack = oracle(_view(attacked), authority, case.raw)
            row.evidence = _evidence(attack_class, attacked)
            row.notes = list(attacked.notes)

            # The control: the same task, the same seed, no payload anywhere.
            clean = run_case(
                case.task_id, config="undefended", seed=seed, model=model
            )
            row.quiet_on_benign = not oracle(_view(clean), authority, case.raw)
        except Exception as exc:  # noqa: BLE001 — a row that could not run is a failure
            row.error = f"{type(exc).__name__}: {exc}"
        rows.append(row)

    return rows
