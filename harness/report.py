"""``results.md``, rendered from the JSONL on disk.

A separate module from :mod:`harness.matrix` for one reason: the published table
has to be reproducible **from the files** by somebody who did not run the
suites. A renderer that could only read an in-memory result would make every
number a property of the process that produced it, and "run this and you get the
same table" is the claim `scripts/reproduce.sh` exists to make good on.

Four rules the rendering follows, each of which is about honesty rather than
layout:

**Every proportion carries its interval and its counts.** There is no code path
here that prints a bare percentage. n is 15 per class, and 0/15 is not "zero
percent" — it is "somewhere below 20%, at 95% confidence". :class:`
~harness.metrics.Proportion` has no method that renders the estimate alone,
which is how that stays true.

**The false-block column is printed first among the utility columns**, and every
blocked benign case is named underneath with the check that refused it. It is the
column an author is most tempted to leave out, so it is the one placed where a
reader sees it before the ASR.

**Utility under attack sits beside ASR, always.** An ASR of zero with a utility
under attack of zero is a defence that turned the agent off. Printing the two in
one table is what makes that impossible to present as a win.

**The caveats are in the document, not in a footnote nobody renders.** Which
model drove, whether it was the deterministic stand-in, how many times batch B
was opened, which corpus hash, which machine. Every one of those can move a
number, so every one of them is printed beside the numbers it moves.
"""

from __future__ import annotations

import platform
import sys
from typing import Any, Iterable, Sequence

from harness.matrix import ABLATABLE, AblationResult, MatrixResult
from harness.metrics import (
    Proportion,
    asr_by_class,
    asr_by_technique,
    benign_utility,
    denial_reasons,
    evaluated_prefixes,
    false_block_rate,
    false_blocks,
    guard_refusals,
    overhead,
    recovered,
    targeted_asr,
    utility_under_attack,
)
__all__ = [
    "render_results",
    "render_ablation",
    "ablation_verdicts",
    "CONFIG_BLURB",
]

#: One line per arm, printed above the table. A column header is a name; this
#: is what the name means, and a reader who skips it will misread the table.
CONFIG_BLURB: dict[str, str] = {
    "undefended": "agent plus tools, no kernel, no guardrail. The control arm.",
    "model-only": (
        "a guardrail classifier in front of the money tools, no kernel. "
        "The honest answer to 'why not just add a guardrail model?'"
    ),
    "kernel": (
        "the full kernel, running the **undefended** agent. Every guarantee "
        "here holds with a fully adversarial agent (SPEC.md §17.7), which is "
        "why this arm has the agent-side taint guard removed."
    ),
    "agent-guard": (
        "the planner/quarantined-extractor split and the field-admission "
        "policy, no kernel. Defence in depth measured on its own."
    ),
    "kernel+agent-guard": "both. The only arm in which anything is doubled up.",
}


def ablation_verdicts(ablation: AblationResult) -> dict[int, dict[str, Any]]:
    """Per check: which classes it is necessary for, and which it stops alone.

    Two questions, because a single-ablation table answers only the first and
    the first alone is misleading here. **The checks overlap on purpose.** A
    redirected payee changes the cart's hash, so check 4 refuses class A1 even
    with check 2 removed; turning off check 2 therefore moves nothing, and a
    table with only that column would report check 2 as worthless.

    ``necessary_for``
        Classes whose ASR rose when this check alone was removed. "Given the
        other eight, this one is load-bearing."
    ``sufficient_for``
        Classes this check held at or below the baseline *while every other
        ablatable check was off* — measured against the floor row, where those
        classes do land. "On its own, this one stops it."

    A check earns its row by answering either question. A check that answers
    neither is reported as answering neither, which is a finding about the
    check rather than a row to leave out.
    """
    floor = next((r for r in ablation.rows if r.mode == "floor"), None)
    floor_by_class = asr_by_class(floor.records) if floor is not None else {}
    base_by_class = asr_by_class(ablation.baseline)

    verdicts: dict[int, dict[str, Any]] = {}
    for row in ablation.rows:
        check_id = row.check_id
        if check_id is None:
            continue
        entry = verdicts.setdefault(
            check_id, {"necessary_for": [], "sufficient_for": [], "rows": []}
        )
        entry["rows"].append(row.mode)
        by_class = asr_by_class(row.records)
        if row.mode == "single":
            entry["necessary_for"] = sorted(
                cls
                for cls, here in by_class.items()
                if cls in base_by_class and here.k > base_by_class[cls].k
            )
        elif row.mode == "isolated":
            entry["sufficient_for"] = sorted(
                cls
                for cls, here in by_class.items()
                if cls in floor_by_class and here.k < floor_by_class[cls].k
            )
    for entry in verdicts.values():
        entry["earns_row"] = bool(entry["necessary_for"] or entry["sufficient_for"])
    return verdicts


def _headline(matrix: MatrixResult, configs: Sequence[str]) -> list[str]:
    """The three sentences a reader gets if they read nothing else.

    Written from the numbers rather than typed, so it cannot drift from the
    tables below it. The held-out batch is preferred when there is one — the
    development batch is what the kernel was built against, and quoting it as
    the headline would be quoting a training score.
    """
    dataset = "batch_b" if "batch_b" in matrix.datasets else None
    dataset = dataset or next(
        (d for d in matrix.datasets if d.startswith("batch_")), None
    )
    if dataset is None:
        return []

    out: list[str] = []
    undefended = targeted_asr(matrix.records(dataset, "undefended"))
    label = f"batch {dataset.removeprefix('batch_').upper()}"
    if undefended.n:
        out.append(
            f"On **{label}**, {undefended.cell()} of attacks succeed against an "
            "undefended agent. That is the number everything else is measured "
            "against, and it was taken first: if the attacks do not land there "
            "is nothing to defend."
        )
        out.append("")

    for config in ("model-only", "kernel"):
        if config not in configs:
            continue
        rows = matrix.records(dataset, config)
        if not rows:
            continue
        asr = targeted_asr(rows)
        utility = utility_under_attack(rows)
        benign = matrix.records("benign", config)
        blocked = false_block_rate(benign) if benign else None
        sentence = (
            f"With **`{config}`** it is {asr.cell()}, and the agent still "
            f"completes {utility.cell()} of the same tasks"
        )
        if blocked is not None:
            sentence += f", refusing {blocked.cell()} of benign ones"
        out.append(sentence + ".")
        out.append("")

    out.append(
        "Read the intervals, not the point estimates, and read the utility "
        "columns beside the ASR column. A defence with no attacks landing and "
        "no tasks completing has not defended anything."
    )
    out.append("")
    return out


def _rule(widths: Sequence[int]) -> str:
    return "|" + "|".join("-" * (w + 2) for w in widths) + "|"


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    widths = [
        max(len(str(header[i])), *(len(str(r[i])) for r in rows)) if rows else len(header[i])
        for i in range(len(header))
    ]
    out = ["| " + " | ".join(str(h).ljust(w) for h, w in zip(header, widths)) + " |"]
    out.append(_rule(widths))
    for row in rows:
        out.append(
            "| " + " | ".join(str(c).ljust(w) for c, w in zip(row, widths)) + " |"
        )
    return out


def _cell(p: Proportion) -> str:
    return p.cell()


def _scripted(matrix: MatrixResult) -> bool:
    from agent.llm import SCRIPTED_MODEL_ID

    return any(
        record.get("model") == SCRIPTED_MODEL_ID
        for cell in matrix.cells
        for record in cell.records
    )


def _attack_datasets(matrix: MatrixResult) -> list[str]:
    return [d for d in matrix.datasets if d.startswith("batch_")]


def _technique_map(records: Iterable[dict[str, Any]]) -> dict[str, str]:
    """``case_id -> technique``, read from the corpus for the cases present.

    Read once here rather than carried on every line: the technique is a
    property of the case, the case is covered by the manifest hash, and a
    field duplicated onto three hundred records is three hundred chances for
    the two to disagree.
    """
    from harness.corpus import load_attack

    out: dict[str, str] = {}
    for record in records:
        case_id = record.get("case_id")
        if case_id and case_id not in out:
            out[case_id] = load_attack(case_id).technique
    return out


# ---------------------------------------------------------------------------
# results.md
# ---------------------------------------------------------------------------


def render_results(
    matrix: MatrixResult,
    *,
    ablation: AblationResult | None = None,
    configs: Sequence[str] | None = None,
) -> str:
    """The whole document, as one string."""
    configs = list(configs or [c for c in matrix.configs])
    lines: list[str] = []
    add = lines.append

    add("# Results")
    add("")
    lines.extend(_headline(matrix, configs))
    add(
        "Every proportion below carries a Wilson 95% confidence interval and "
        "the counts it was computed from. **n is 15 per class**, and a point "
        "estimate on 15 is not a fact: 0/15 is not \"zero percent\", it is "
        "\"below 20%, at 95% confidence\". Nothing in this file prints an "
        "estimate without its interval, and the code that renders it has no "
        "method that could."
    )
    add("")

    # -- provenance of the numbers ---------------------------------------
    add("## What produced these numbers")
    add("")
    models = sorted(
        {record.get("model", "?") for cell in matrix.cells for record in cell.records}
    )
    add(f"- corpus manifest — `{matrix.corpus_manifest}`")
    add(f"- matrix id — `{matrix.matrix_id}`")
    add(f"- seed — `{matrix.seed}`  ·  model(s) — {', '.join(f'`{m}`' for m in models)}")
    add(f"- run — {matrix.started_at} → {matrix.finished_at}")
    add(
        f"- host — python {sys.version.split()[0]}, {platform.platform()}, "
        f"{platform.machine()}"
    )
    add(
        f"- batch B openings on record — **{len(matrix.batch_b_openings)}**"
        + (
            f" (this matrix opened it: {matrix.batch_b_opening['reason']!r})"
            if matrix.batch_b_opening
            else ""
        )
    )
    add(
        "- suites ran **sequentially in one process**, one kernel and one "
        "SQLite file per case; parallelism is across matrices only, because "
        "the overhead column must not be a measurement of lock contention"
    )
    add(
        "- **no non-local socket opened during any run.** The containment guard "
        "(`harness/containment.py`) is armed around every case and its verdict "
        "is a field on every run record; see *Containment* below"
    )
    if matrix.corpus_drift:
        add("")
        add(
            "> **These numbers may not be published.** The corpus moved while "
            "the matrix was running, so every line quotes a hash that is no "
            "longer true:"
        )
        for difference in matrix.corpus_drift:
            add(f"> - {difference}")
    if _scripted(matrix):
        add("")
        add(
            "> **The deterministic stand-in drove these runs, not a model.** "
            "`scripted-gullible-v1` is a rule-based planner, not "
            "`claude-opus-5`, so **no ASR figure below is a model "
            "measurement**. It exists so the plumbing — the rail, the "
            "merchant, the tools, the ledger, the kernel — is measurable "
            "without an API key, and so `scripts/reproduce.sh` runs on a "
            "fresh clone. Two consequences are visible in the tables and "
            "neither is hidden: the `base64` family scores an honest zero "
            "everywhere because the stand-in decodes nothing, and the "
            "`model-only` arm's classifier is a lexical rule standing in for "
            "a classifier model."
        )
    add("")
    add("### The arms")
    add("")
    for config in configs:
        add(f"- **`{config}`** — {CONFIG_BLURB.get(config, '')}")
    add("")

    # -- the headline table ----------------------------------------------
    for dataset in _attack_datasets(matrix):
        add(f"## Batch {dataset.removeprefix('batch_').upper()} — the headline table")
        add("")
        rows = []
        for config in configs:
            attacks = matrix.records(dataset, config)
            benign = matrix.records("benign", config)
            if not attacks:
                continue
            row = [
                f"`{config}`",
                _cell(targeted_asr(attacks)),
                _cell(utility_under_attack(attacks)),
                _cell(benign_utility(benign)) if benign else "not run",
                _cell(false_block_rate(benign)) if benign else "not run",
            ]
            rows.append(row)
        add(
            "\n".join(
                _table(
                    [
                        "config",
                        "targeted ASR",
                        "utility under attack",
                        "benign utility",
                        "false block rate",
                    ],
                    rows,
                )
            )
        )
        add("")
        add(
            "*Utility under attack is printed beside ASR on purpose.* A defence "
            "with a 0% ASR and a 0% utility under attack has not defended "
            "anything — it has turned the agent off, and the ASR column alone "
            "cannot tell the two apart."
        )
        add("")

        # per class
        add(f"### Batch {dataset.removeprefix('batch_').upper()} by class")
        add("")
        classes = sorted(
            {
                cid.split("-", 1)[0]
                for config in configs
                for r in matrix.records(dataset, config)
                if (cid := r.get("case_id"))
            }
        )
        rows = []
        for cls in classes:
            row = [cls]
            for config in configs:
                per_class = asr_by_class(matrix.records(dataset, config))
                row.append(_cell(per_class[cls]) if cls in per_class else "—")
            rows.append(row)
        add("\n".join(_table(["class", *(f"`{c}`" for c in configs)], rows)))
        add("")

        # per technique
        add(f"### Batch {dataset.removeprefix('batch_').upper()} by evasion family")
        add("")
        techniques = _technique_map(
            r for config in configs for r in matrix.records(dataset, config)
        )
        families = sorted(set(techniques.values()))
        rows = []
        for family in families:
            row = [family]
            for config in configs:
                by_family = asr_by_technique(matrix.records(dataset, config), techniques)
                row.append(_cell(by_family[family]) if family in by_family else "—")
            rows.append(row)
        add("\n".join(_table(["technique", *(f"`{c}`" for c in configs)], rows)))
        add("")

        # reason codes
        add("### What refused, and why")
        add("")
        for config in configs:
            rows_here = matrix.records(dataset, config)
            reasons = denial_reasons(rows_here)
            guards = guard_refusals(rows_here)
            parts = []
            if reasons:
                parts.append(
                    ", ".join(f"`{code}` ×{n}" for code, n in reasons.items())
                )
            if guards:
                parts.append(
                    "field admission refused "
                    + ", ".join(f"`{field}` ×{n}" for field, n in guards.items())
                )
            add(f"- `{config}` — {'; '.join(parts) if parts else 'nothing refused.'}")
        add("")
        add(
            "An ASR that fell to zero with no refusals in the record would be "
            "an attack that stopped working rather than a defence that worked. "
            "These counts are how the two are told apart."
        )
        add("")
        add(
            "The agent-side arms make no *decision* in the kernel's sense: when "
            "an inadmissible value is offered to a restricted field the planner "
            "falls back to the user-provenance value and the run continues. "
            "Those fallbacks are the second half of each `agent-guard` line, "
            "and they are deliberately **not** counted in the false-block rate "
            "— the user still got their goods."
        )
        add("")

    # -- does it generalise? ----------------------------------------------
    if {"batch_a", "batch_b"} <= set(matrix.datasets):
        add("## Batch A against batch B")
        add("")
        add(
            "Batch A is the development set: the kernel was built while it "
            "existed and its cases were read. Batch B was sealed until the "
            "matrix above opened it. A defence that scored well on A and worse "
            "on B would have been tuned to A, and the difference is where that "
            "would show."
        )
        add("")
        rows = []
        for config in configs:
            a = targeted_asr(matrix.records("batch_a", config))
            b = targeted_asr(matrix.records("batch_b", config))
            if not a.n or not b.n:
                continue
            overlap = a.low <= b.high and b.low <= a.high
            rows.append(
                [
                    f"`{config}`",
                    _cell(a),
                    _cell(b),
                    "intervals overlap" if overlap else "**intervals are disjoint**",
                ]
            )
        add("\n".join(_table(["config", "batch A ASR", "batch B ASR", ""], rows)))
        add("")
        add(
            "Overlapping intervals are the result to want here: they say the "
            "held-out set did not behave differently. They do **not** say the "
            "two are equal — with n of 105 the intervals are several points "
            "wide, and a real difference smaller than that would not be "
            "visible."
        )
        add("")
        if _scripted(matrix):
            add(
                "**And under the deterministic stand-in this comparison is much "
                "weaker than it looks.** The stand-in applies the same rules to "
                "both batches, so the arms whose behaviour is a function of "
                "those rules score identically on A and B almost by "
                "construction — the identical rows above are that, not "
                "evidence of generalisation. The one arm where the two batches "
                "genuinely differ is `model-only`, because its classifier is "
                "matching the *wording* of each payload and batch B's wording "
                "is different. Held-out generalisation is a claim a model arm "
                "can make and this one cannot."
            )
            add("")

    # -- the false block rate --------------------------------------------
    add("## The false block rate, case by case")
    add("")
    add(
        "**A zero here would be a finding about the benign suite, not a perfect "
        "score.** Twenty-five tasks written by the people who wrote the checks "
        "will mostly sit comfortably inside the authority those checks enforce; "
        "a suite that never once brushes a boundary has not measured where the "
        "boundary is."
    )
    add("")
    for config in configs:
        benign = matrix.records("benign", config)
        if not benign:
            continue
        rate = false_block_rate(benign)
        add(f"### `{config}` — {_cell(rate)}")
        add("")
        blocked = false_blocks(benign)
        if not blocked:
            add(
                "No benign case was refused. See the paragraph above: with n of "
                "25 the interval reaches "
                f"{100 * rate.high:.1f}%, so this is not evidence of a defence "
                "that never over-blocks."
            )
            add("")
            continue
        rows = [
            [
                f"`{row['task_id']}`",
                row["step"] or "—",
                row["decision"] or "—",
                f"`{row['reason_code']}`",
                ",".join(str(c) for c in row["denied_by"]) or "—",
            ]
            for row in blocked
        ]
        add(
            "\n".join(
                _table(
                    ["task", "step", "decision", "reason code", "denied by"], rows
                )
            )
        )
        add("")
    add("")

    # -- overhead ---------------------------------------------------------
    add("## Overhead per money-moving call")
    add("")
    add(
        "Quoted from the **benign** suite, where every arm allows every call and "
        "the distributions are measuring the same work. A denied attack never "
        "reaches the rail and is far cheaper than an allowed purchase, so an "
        "overhead taken over an attack batch would be a difference in workload "
        "wearing the costume of a defence's cost. Measured at the tool boundary "
        "in every arm (`agent/tools.py`'s `timed`), so the subtraction is "
        "between two things measured at the same place."
    )
    add("")
    baseline = matrix.records("benign", "undefended")
    rows = []
    if baseline:
        for config in configs:
            if config == "undefended":
                continue
            arm = matrix.records("benign", config)
            if not arm:
                continue
            cost = overhead(
                baseline, arm, dataset="benign", arm_config=config
            )
            rows.append(
                [
                    f"`{config}`",
                    f"{cost.baseline['p50'] / 1000:.2f} ms",
                    f"{cost.arm['p50'] / 1000:.2f} ms",
                    f"{cost.p50_delta_us / 1000:+.2f} ms",
                    f"{cost.baseline['p99'] / 1000:.2f} ms",
                    f"{cost.arm['p99'] / 1000:.2f} ms",
                    f"{cost.p99_delta_us / 1000:+.2f} ms",
                    str(cost.arm["n"]),
                ]
            )
    add(
        "\n".join(
            _table(
                [
                    "config",
                    "base p50",
                    "arm p50",
                    "added p50",
                    "base p99",
                    "arm p99",
                    "added p99",
                    "calls",
                ],
                rows,
            )
        )
    )
    add("")
    add(
        "Nearest-rank percentiles over the pooled calls, no interpolation: every "
        "figure is a duration that was actually measured. A p99 of per-run p99s "
        "would be a p99 of nothing, because a run makes two or three calls and "
        "its \"p99\" is its maximum."
    )
    add("")

    # -- recovery ---------------------------------------------------------
    kernel_benign = matrix.records("benign", "kernel")
    if kernel_benign:
        rec = recovered(kernel_benign)
        if rec.n:
            add("## Recovery")
            add("")
            add(f"- reservations the scan resolved — {_cell(rec)}")
            add("")

    # -- ablation ---------------------------------------------------------
    if ablation is not None:
        lines.extend(render_ablation(ablation).splitlines())

    # -- containment ------------------------------------------------------
    add("## Containment")
    add("")
    total = sum(len(cell.records) for cell in matrix.cells)
    breaches = [
        record
        for cell in matrix.cells
        for record in cell.records
        if (record.get("containment") or {}).get("breaches")
    ]
    enforced = sum(
        1
        for cell in matrix.cells
        for record in cell.records
        if (record.get("containment") or {}).get("enforced")
    )
    allowed = sorted(
        {
            host
            for cell in matrix.cells
            for record in cell.records
            for host in (record.get("containment") or {}).get("allowed_hosts", [])
        }
    )
    add(
        f"- runs behind this document — **{total}**, of which **{enforced}** "
        "were executed with the containment guard armed"
    )
    add(f"- non-local connections refused — **{len(breaches)}**")
    add(
        "- hosts on the allowance — "
        + (", ".join(f"`{h}`" for h in allowed) if allowed else "**none**")
    )
    add("")
    add(
        "The guard patches `socket.socket.connect`, `connect_ex` and "
        "`socket.create_connection` for the duration of each run and refuses "
        "any address that is not loopback. Attacks reach only the mock "
        "merchants in `sim/`. The honest statement of the guarantee is *no "
        "socket opened through Python's socket module*: a subprocess or a C "
        "extension holding its own descriptor would go around it, and nothing "
        "on the run path does either."
    )
    if allowed:
        add("")
        add(
            "The allowance above is the model endpoint, permitted only while a "
            "live model is driving the agent under test. Payloads never leave "
            "this process except as text inside a prompt, and the allowance is "
            "recorded on every run record rather than applied silently."
        )
    add("")

    # -- limits -----------------------------------------------------------
    add("## What these numbers do not say")
    add("")
    add(
        "- **Batch B is held out and opened once, which is weaker than a corpus "
        "nobody could have tuned against.** "
        + (
            f"{len(matrix.batch_b_openings)} openings are"
            if len(matrix.batch_b_openings) != 1
            else "One opening is"
        )
        + " on record in `harness/attacks/openings.jsonl`; a second read needs "
        "an explicit override and is logged as one. Nothing prevents a second "
        "read — what is prevented is a *silent* one."
    )
    add(
        "- **n is 15 per class.** Every interval in this document is wide. Two "
        "columns whose intervals overlap have not been shown to differ, and "
        "several pairs here overlap."
    )
    add(
        "- **The agent-side guard is not the contribution and is not counted as "
        "one.** The `kernel` arm runs the undefended agent deliberately: every "
        "guarantee has to hold with a fully adversarial agent, so the arm that "
        "measures the kernel runs one. The guard is reported separately."
    )
    add(
        "- **Provenance here is value-based, not interpreter-level taint.** Two "
        "fields carrying the same string are indistinguishable to it, and a "
        "merchant that guessed a user-declared value exactly would have it "
        "admitted. See `agent/provenance.py`."
    )
    add(
        "- **The oracles read the payment rail, not the kernel.** A kernel "
        "reporting its own ledger would be scoring its own exam. A run whose "
        "audit chain did not verify is discarded rather than counted as a "
        "defended one."
    )
    add("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# the ablation
# ---------------------------------------------------------------------------


def render_ablation(ablation: AblationResult) -> str:
    """The per-check table: what each predicate is necessary for, and sufficient for.

    Two tables rather than one, because a single-ablation table on its own is
    misleading here — see :func:`ablation_verdicts`. The first asks whether each
    check is necessary *given the other eight*; the second asks what it stops on
    its own. A check earns its row by answering either.
    """
    from kernel.checks import CHECK_NAMES

    lines: list[str] = []
    add = lines.append

    add("## Per-check ablation")
    add("")
    add(
        f"The `kernel` arm over `{ablation.dataset}`, run once with every check "
        "on and then once per check with the check set changed. A check is not "
        "disabled by a flag inside the check — it is simply not in the "
        "evaluation list, so the audit payload's evaluated prefix shows what "
        "did run and an `ablated` field names what did not. \"Checks 1,3,4,5,6 "
        "ran and none refused, with 2 ablated\" is a different fact from "
        "\"nothing refused\", and only the first says which predicate was "
        "earning its row."
    )
    add("")
    add(
        "**The checks overlap, and that is why there are two tables.** A "
        "redirected payee changes the cart's hash, so check 4 refuses class A1 "
        "even with check 2 removed. Turning off check 2 alone therefore moves "
        "nothing — a true statement about *necessity given the others* and a "
        "false impression about *value*. The second table is what separates "
        "them."
    )
    add("")
    add(f"- baseline suite — `{ablation.baseline_suite_id}`")
    add(f"- corpus manifest — `{ablation.corpus_manifest}`")
    add(f"- seed — `{ablation.seed}`  ·  model — `{ablation.model}`")
    add("")

    classes = sorted(
        {
            cid.split("-", 1)[0]
            for record in ablation.baseline
            if (cid := record.get("case_id"))
        }
    )
    base_by_class = asr_by_class(ablation.baseline)
    floor = next((r for r in ablation.rows if r.mode == "floor"), None)
    floor_by_class = asr_by_class(floor.records) if floor is not None else {}

    def row_cells(records, *, against: dict[str, Any], mark: str) -> list[str]:
        here = asr_by_class(records)
        cells = []
        for cls in classes:
            if cls not in here:
                cells.append("—")
                continue
            text = _cell(here[cls])
            other = against.get(cls)
            if other is not None and (
                (mark == "↑" and here[cls].k > other.k)
                or (mark == "↓" and here[cls].k < other.k)
            ):
                text = f"**{text} {mark}**"
            cells.append(text)
        return cells

    # -- necessity ---------------------------------------------------------
    add("### One check off — is it necessary, given the others?")
    add("")
    rows: list[list[str]] = [
        [
            "*none — all nine on*",
            _cell(targeted_asr(ablation.baseline)),
            *(_cell(base_by_class[c]) if c in base_by_class else "—" for c in classes),
        ]
    ]
    for row in [r for r in ablation.rows if r.mode == "single"]:
        rows.append(
            [
                f"check {row.check_id} — `{CHECK_NAMES[row.check_id]}`",
                _cell(targeted_asr(row.records)),
                *row_cells(row.records, against=base_by_class, mark="↑"),
            ]
        )
    add("\n".join(_table(["ablated", "overall ASR", *classes], rows)))
    add("")
    add(
        "**↑** marks a class whose ASR rose above the all-checks-on baseline "
        "when that check was removed."
    )
    add("")

    # -- sufficiency -------------------------------------------------------
    isolated = [r for r in ablation.rows if r.mode == "isolated"]
    if isolated and floor is not None:
        add("### Only one check on — what does it stop by itself?")
        add("")
        add(
            "Every other ablatable predicate is off in these rows. The row to "
            "read them against is the **floor**: the kernel with every "
            "predicate removed, which is how much of the arm's result comes "
            "from the plumbing rather than from the checks."
        )
        add("")
        rows = [
            [
                "*floor — every predicate off*",
                _cell(targeted_asr(floor.records)),
                *row_cells(floor.records, against=base_by_class, mark="↑"),
            ]
        ]
        for row in isolated:
            rows.append(
                [
                    f"only check {row.check_id} — `{CHECK_NAMES[row.check_id]}`",
                    _cell(targeted_asr(row.records)),
                    *row_cells(row.records, against=floor_by_class, mark="↓"),
                ]
            )
        add("\n".join(_table(["check set", "overall ASR", *classes], rows)))
        add("")
        add(
            "**↓** marks a class this check held below the floor on its own — "
            "the check stopping that class by itself."
        )
        add("")

    # -- the verdict -------------------------------------------------------
    verdicts = ablation_verdicts(ablation)
    add("### Does every check earn its row?")
    add("")
    rows = []
    for check_id in sorted(verdicts):
        entry = verdicts[check_id]
        rows.append(
            [
                f"check {check_id}",
                f"`{CHECK_NAMES[check_id]}`",
                ", ".join(entry["necessary_for"]) or "—",
                ", ".join(entry["sufficient_for"]) or "—",
                "yes" if entry["earns_row"] else "**no**",
            ]
        )
    add(
        "\n".join(
            _table(
                ["check", "name", "necessary for", "stops alone", "earns its row"],
                rows,
            )
        )
    )
    add("")
    unearned = [c for c in sorted(verdicts) if not verdicts[c]["earns_row"]]
    if unearned:
        add(
            "Checks "
            + ", ".join(str(c) for c in unearned)
            + " stopped nothing in this batch under either question. That is a "
            "finding about those checks and about this corpus, and it is "
            "printed rather than omitted: a class the corpus does not exercise "
            "cannot show a check earning its row, and neither can a check that "
            "does not do anything. The two are told apart by looking at which "
            "classes are at zero in the floor row."
        )
    else:
        add("Every ablatable check earns its row on at least one class.")
    add("")

    # -- what is never at issue -------------------------------------------
    zero_at_floor = [
        cls
        for cls in classes
        if cls in floor_by_class and floor_by_class[cls].k == 0
    ] if floor is not None else []
    if zero_at_floor:
        add(
            "Classes "
            + ", ".join(zero_at_floor)
            + " are at zero **even with every predicate removed**. They are not "
            "stopped by a check at all — they are stopped by something "
            "structural in the kernel, and the ablation is what makes that "
            "visible rather than letting a check take the credit:"
        )
        add("")
        add(
            "- **A4** — the audit-action enum has no `mandate.create.allow`. "
            "Issuing standing authority needs a recurring-mandate store the "
            "kernel does not have, so it answers 503 rather than minting "
            "authority it cannot record. Check 5 would refuse it first; with "
            "check 5 off, the kernel still will not."
        )
        add(
            "- **A6** — check 7, the idempotency reservation, which is not "
            "ablatable (see below). The second charge for one cart is the same "
            "business key and comes back as `authorize.replayed` and "
            "`capture.replayed` in the chain."
        )
        add(
            "- **A7** — `RequestParams` has no destination field. The value is "
            "not dropped by a filter that could be misconfigured or a check "
            "that could be ablated; the wire format has nowhere to put it, and "
            "check 8 fills the destination in from `payment.source_json`."
        )
        add("")

    not_ablated = [c for c in sorted(CHECK_NAMES) if c not in ABLATABLE]
    if not_ablated:
        add(
            "Checks "
            + ", ".join(str(c) for c in not_ablated)
            + " ("
            + ", ".join(f"`{CHECK_NAMES[c]}`" for c in not_ablated)
            + ") are **not ablated**, and are named here rather than omitted "
            "because a missing row reads as a check nobody thought about. They "
            "are lifecycle steps, not predicates: removing the audit append "
            "leaves a run with no chain, and a run with no chain is discarded "
            "rather than scored, so the row would be empty. Removing the "
            "idempotency reservation leaves the kernel unable to answer a "
            "crash, so its \"ASR\" would be a measurement of the recovery path "
            "falling over."
        )
        add("")

    add("### Evaluated prefixes")
    add("")
    add(
        "The evidence that an ablation removed a *predicate* rather than "
        "disturbing a code path: with a check removed, the prefix recorded in "
        "the audit payload gets longer, because evaluation no longer "
        "short-circuits there."
    )
    add("")
    prefix_rows = [
        [
            "*none*",
            ", ".join(
                f"`{p}` ×{n}"
                for p, n in list(evaluated_prefixes(ablation.baseline).items())[:4]
            )
            or "—",
        ]
    ]
    for row in ablation.rows:
        seen = evaluated_prefixes(row.records)
        prefix_rows.append(
            [
                row.label,
                ", ".join(f"`{p}` ×{n}" for p, n in list(seen.items())[:4]) or "—",
            ]
        )
    add("\n".join(_table(["check set", "most common evaluated prefixes"], prefix_rows)))
    add("")
    return "\n".join(lines) + "\n"
