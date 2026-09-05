"""The generated corpus's tables, and the four things they do not say.

A separate renderer from :func:`harness.report.render_results`, and separate on
purpose. The hand-written batch A and batch B tables are already published
against a corpus hash that has not moved; the generated tables go **beside**
them, never over them, and a renderer that could produce one from the other's
data would eventually be asked to.

**Narrower intervals are a statement about n, not about the kernel getting
better.** 0/735 is ``[0.0–0.5]`` where 0/105 is ``[0.0–3.5]``. The kernel is
byte-for-byte the same kernel; what changed is how much evidence there is. That
sentence is printed in the document, because a reader comparing the two tables
will otherwise read the narrower interval as a stronger defence.

**The case-by-case false-block section does not scale and is not attempted.**
Twenty-five tasks got a table of three rows naming each refusal. Four hundred
and twenty would get a table of seventy, which nobody reads. What replaces it is
what actually explains the number: the **declared cap policy**, the price
distribution it was applied to, and the distribution of refusals across
categories. A stated policy plus a distribution is a better account of a false
block rate than seventy paragraphs, and it is the account that lets a reader
predict what a different policy would cost.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from harness.metrics import (
    Proportion,
    asr_by_class,
    asr_by_technique,
    benign_utility,
    denial_reasons,
    false_block_rate,
    false_blocks,
    guard_refusals,
    overhead,
    targeted_asr,
    utility_under_attack,
)
from harness.report import _table

__all__ = [
    "SECTION_FENCE",
    "CAVEAT_FENCE",
    "GeneratedRun",
    "load_generated",
    "render_generated",
    "generated_caveats",
    "compare_runs",
    "DETERMINISTIC_FIELDS",
    "splice",
]

#: The fences the generated section lives between in ``results.md``.
#:
#: Fenced rather than appended, because the generated tables have to be
#: *re-renderable* into a document whose other numbers must not move. The
#: hand-written tables were measured against a corpus hash and a batch B
#: opening that still stand; regenerating the whole document to add a section
#: would mean re-running those suites and opening the held-out set again, and
#: the numbers would change for no reason anyone could point at.
SECTION_FENCE = ("<!-- generated-corpus:begin -->", "<!-- generated-corpus:end -->")
CAVEAT_FENCE = ("<!-- generated-caveats:begin -->", "<!-- generated-caveats:end -->")

#: Where the section goes when the document has no fences yet.
SECTION_BEFORE = "## Containment"

#: Where the caveat bullets go when the document has no fences yet: the end of
#: the limits section, which is the last heading in the document.
CAVEATS_AFTER = "## What these numbers do not say"


@dataclass
class GeneratedRun:
    """Every merged (dataset, config) file of one generated measurement."""

    directory: Path
    corpus_manifest: str = ""
    report: dict[str, Any] = field(default_factory=dict)
    manifest: dict[str, Any] = field(default_factory=dict)
    cells: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)
    metas: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    configs: tuple[str, ...] = ()
    datasets: tuple[str, ...] = ()
    openings: list[dict[str, Any]] = field(default_factory=list)
    #: The hosted run's own record of its session, when this directory came
    #: from one: the machine, the library versions, and what the containment
    #: guard saw. Absent for a local run.
    index: dict[str, Any] = field(default_factory=dict)

    def records(self, dataset: str, config: str) -> list[dict[str, Any]]:
        return self.cells.get((dataset, config), [])


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def load_generated(
    directory: Path,
    *,
    configs: Sequence[str],
    datasets: Sequence[str] = ("gen_benign", "gen_a", "gen_b"),
) -> GeneratedRun:
    """Read a directory of merged JSONL, the generation report and the manifest.

    From the *files*, like ``mk report``, so the generated tables are
    reproducible by somebody who did not run the suites.
    """
    from harness.corpus import reads
    from harness.generate.build import REPORT_PATH
    from harness.manifest import read_generated_manifest

    directory = Path(directory)
    run = GeneratedRun(
        directory=directory,
        report=json.loads(REPORT_PATH.read_text()) if REPORT_PATH.exists() else {},
        manifest=read_generated_manifest(),
        configs=tuple(configs),
        openings=[e for e in reads() if e["batch"].startswith("gen-")],
    )
    run.corpus_manifest = run.manifest.get("manifest_hash", "")
    for candidate in (directory / "digests.json", directory.parent / "digests.json"):
        if candidate.is_file():
            run.index = json.loads(candidate.read_text())
            break

    present: list[str] = []
    for dataset in datasets:
        found = False
        for config in configs:
            path = directory / f"{dataset}.{config.replace('+', '_')}.jsonl"
            if not path.exists():
                continue
            run.cells[(dataset, config)] = _read_jsonl(path)
            meta = path.with_suffix(".meta.json")
            if meta.exists():
                run.metas[(dataset, config)] = json.loads(meta.read_text())
            found = True
        if found:
            present.append(dataset)
    run.datasets = tuple(present)
    return run


def _cells(run: GeneratedRun, dataset: str, metric) -> list[str]:
    return [metric(run.records(dataset, config)).cell() for config in run.configs]


def _headline_table(run: GeneratedRun, dataset: str) -> list[str]:
    header = ["config", "targeted ASR", "utility under attack", "benign utility", "false block rate"]
    rows = []
    for config in run.configs:
        attack = run.records(dataset, config)
        benign = run.records("gen_benign", config)
        rows.append(
            [
                f"`{config}`",
                targeted_asr(attack).cell(),
                utility_under_attack(attack).cell(),
                benign_utility(benign).cell() if benign else "—",
                false_block_rate(benign).cell() if benign else "—",
            ]
        )
    return _table(header, rows)


def _by_class(run: GeneratedRun, dataset: str) -> list[str]:
    from harness.corpus import CLASSES

    per_config = {c: asr_by_class(run.records(dataset, c)) for c in run.configs}
    header = ["class", *[f"`{c}`" for c in run.configs]]
    rows = [
        [klass, *[per_config[c].get(klass, Proportion("", 0, 0)).cell() for c in run.configs]]
        for klass in CLASSES
        if any(klass in per_config[c] for c in run.configs)
    ]
    return _table(header, rows)


def _by_technique(run: GeneratedRun, dataset: str) -> list[str]:
    from harness.report import _technique_map

    # Read from the corpus for the cases present, not carried on every line:
    # the technique is a property of the case, the case is covered by the
    # manifest hash, and a field duplicated onto fifteen hundred records is
    # fifteen hundred chances for the two to disagree.
    techniques = _technique_map(
        record for c in run.configs for record in run.records(dataset, c)
    )
    per_config = {
        c: asr_by_technique(run.records(dataset, c), techniques) for c in run.configs
    }
    families = sorted({t for m in per_config.values() for t in m})
    header = ["technique", *[f"`{c}`" for c in run.configs]]
    rows = [
        [family, *[per_config[c].get(family, Proportion("", 0, 0)).cell() for c in run.configs]]
        for family in families
    ]
    return _table(header, rows)


def _refusals(run: GeneratedRun, dataset: str) -> list[str]:
    out: list[str] = []
    for config in run.configs:
        records = run.records(dataset, config)
        reasons = denial_reasons(records)
        guards = guard_refusals(records)
        parts = []
        if reasons:
            parts.append(
                ", ".join(
                    f"`{code}` ×{count}"
                    for code, count in sorted(reasons.items(), key=lambda kv: -kv[1])
                )
            )
        if guards:
            parts.append(
                "field admission refused "
                + ", ".join(
                    f"`{field}` ×{count}"
                    for field, count in sorted(guards.items(), key=lambda kv: -kv[1])
                )
            )
        out.append(f"- `{config}` — " + ("; ".join(parts) if parts else "nothing refused."))
    return out


def render_generated(
    run: GeneratedRun, *, hosted: GeneratedRun | None = None
) -> list[str]:
    """The whole generated-corpus section, as lines.

    ``hosted`` is the same corpus measured on a hosted runner. When it is
    given, the two are compared case by case and the comparison is printed —
    which is the strongest thing this document can say about REQ-3, and the one
    claim in it that a second machine is required to make at all.
    """
    lines: list[str] = []
    add = lines.append

    add("## The generated corpus")
    add("")
    add(
        "Everything above this line comes from the hand-written corpus and is "
        "unchanged. This section is a **second, larger measurement of the same "
        "kernel** — same nine checks, same seven oracles, same seed rule — over "
        "a corpus generated from two pinned Kaggle datasets. It sits beside the "
        "hand-written tables rather than replacing them because it is a "
        "**weaker claim**, in the specific ways listed at the end of this "
        "section and repeated under *What these numbers do not say*."
    )
    add("")

    report = run.report
    carriers = report.get("carriers", {})
    catalogue = report.get("catalogue", {})
    tasks = report.get("tasks", {})

    add("### What produced these numbers")
    add("")
    add(f"- generated corpus hash — `{run.corpus_manifest}`")
    add(
        f"- generator — `{run.manifest.get('generator_version', '?')}`  ·  "
        f"seed — `{run.manifest.get('seed', '?')}`"
    )
    for role, digest in sorted(run.manifest.get("dataset_digests", {}).items()):
        add(f"- dataset digest — `{role}` `{digest}`")
    for role, entry in sorted(_dataset_pins().items()):
        add(f"  - `{role}` — {entry['pin']}, {entry['licence']}, {entry['rows']} rows, pulled {entry['pulled_at']}")
    counts = run.manifest.get("counts", {})
    add(
        f"- corpus — {counts.get('tasks', 0)} benign tasks, "
        f"{counts.get('gen_a', 0)} cases in `gen-a`, "
        f"{counts.get('gen_b', 0)} in the held-out `gen-b`"
    )
    opens = [e for e in run.openings if e.get("kind") == "open"]
    joins = [e for e in run.openings if e.get("kind") == "join"]
    add(
        f"- `gen-b` openings on record — **{len(opens)}**, plus {len(joins)} "
        "logged joins (a sharded run is many processes reading under one "
        "opening; each join is timestamped in `harness/attacks/openings.jsonl`)"
    )
    for entry in opens:
        add(f"  - {entry['at']} — {entry['reason']}")
    shard_counts = {
        meta.get("shards", [{}])[0].get("shard", {}).get("count")
        if meta.get("shards")
        else None
        for meta in run.metas.values()
    }
    shard_counts.discard(None)
    if shard_counts:
        add(
            f"- each suite ran as **{max(shard_counts)} shards in separate "
            "processes** and was merged; `mk merge` refuses a missing shard, a "
            "repeated case and a mix of corpus hashes"
        )
    add("")
    add(
        "**Two different things are reproducible here and they need different "
        "inputs.** Re-running these *numbers* needs only a clone: the corpus is "
        "committed, the storefront it is served from is committed, and the "
        "datasets are not read at run time — `mk suite --dataset gen_a "
        "--shard i/n`, then `mk merge`, then `mk report-generated`. Re-deriving "
        "the *corpus* needs the three datasets above, pulled by slug and "
        "version, and it produces a **new** corpus rather than this one: "
        "signing is not deterministic, so a rebuild moves every mandate and the "
        "hash with them. That is why the corpus is generated once, at freeze "
        "time, and why `mk generate corpus` demands `--force`."
    )
    add("")

    # -- how the corpus was built ----------------------------------------
    add("### How much of each dataset survived, and why the rest did not")
    add("")
    add(
        f"The retail crawl offered {catalogue.get('rows_read', 0)} rows and "
        f"{catalogue.get('admitted', 0)} were admitted. Rows are **dropped, "
        "never coerced** — a coerced price is a silent change to the amount "
        "lattice and a coerced category is a silent change to what an intent "
        "authorises:"
    )
    add("")
    add(_counts_table(catalogue.get("dropped", {}), "reason", "rows"))
    add("")
    add(
        f"The two injection corpora offered {carriers.get('attack_rows', 0)} "
        f"attack rows and {carriers.get('admitted', 0)} were admitted "
        f"({100 * carriers.get('drop_rate_of_attack_rows', 0):.1f}% dropped):"
    )
    add("")
    add(_counts_table(carriers.get("dropped", {}), "reason", "rows"))
    add("")
    add(
        f"**Of those {carriers.get('admitted', 0)} carriers, "
        f"{carriers.get('carriers_naming_a_rail_goal', 0)} name a payment "
        "decision at all.** Each carrier was asked, with the gullible planner's "
        "own predicates, which of the seven decisions its text would already "
        "move; the answer was *none* for "
        f"{carriers.get('carriers_naming_no_rail_goal', 0)} of them. That is "
        "not a defect in the corpus. It is what a corpus written against "
        "chatbots contains, and it is the reason a generated payload is two "
        "parts: a **carrier** taken verbatim from the corpus, and one "
        "**directive** line written by the generator carrying the class's "
        "operative parameter. The evasion is theirs. The payment instruction is "
        "ours, because there was none to take — and so, in practice, is the "
        "class."
    )
    add("")
    add(
        "Benign tasks were refused too, and one refusal is worth naming: a task "
        "whose utterance matched "
        "more than one product in a storefront of a thousand real items. The "
        "agent buys *a* product, the total differs from the signed cart's, and "
        "check 4 refuses it — which would appear in the table as a false block "
        "on a benign task and would be a lie. A control the agent cannot "
        "resolve is not a control."
    )
    add("")
    add(_counts_table(tasks.get("dropped", {}), "reason", "tasks"))
    add("")

    # -- the tables -------------------------------------------------------
    for dataset, title in (("gen_a", "gen-a"), ("gen_b", "gen-b — held out")):
        if dataset not in run.datasets:
            continue
        add(f"### {title} — the headline table")
        add("")
        lines.extend(_headline_table(run, dataset))
        add("")
        add(f"#### {title} by class")
        add("")
        lines.extend(_by_class(run, dataset))
        add("")
        add(f"#### {title} by evasion family")
        add("")
        lines.extend(_by_technique(run, dataset))
        add("")
        add(
            "**Read the `model-only` and `agent-guard` columns as a "
            "measurement of one sentence.** Every case of a class carries the "
            "*same* directive template, so a classifier or an admission policy "
            "that catches one A1 case catches all 105 of them; the hand-written "
            "corpus, where each payload was written separately, is the better "
            "measurement of those two arms and its numbers are above. What the "
            "generated corpus measures well is the `undefended` control and the "
            "`kernel` arm, neither of which reads the payload's wording at all."
        )
        add("")
        add(
            "The family mix is the corpus's, not a quota: carriers are spent "
            "scarcest-family-first, so every non-English and every formatting "
            "carrier the corpus contains is used before a plain-prose one. "
            "`base64` is applied as a transform to a declared share and scores "
            "an honest zero against the deterministic stand-in, which decodes "
            "nothing — the same honest zero it scores in the hand-written "
            "tables."
        )
        add("")
        add(f"#### {title} — what refused, and why")
        add("")
        lines.extend(_refusals(run, dataset))
        add("")

    if "gen_a" in run.datasets and "gen_b" in run.datasets:
        add("### gen-a against gen-b")
        add("")
        rows = []
        for config in run.configs:
            a = targeted_asr(run.records("gen_a", config))
            b = targeted_asr(run.records("gen_b", config))
            overlap = "intervals overlap" if a.low <= b.high and b.low <= a.high else "**intervals do not overlap**"
            rows.append([f"`{config}`", a.cell(), b.cell(), overlap])
        lines.extend(
            _table(["config", "gen-a ASR", "gen-b ASR", ""], rows)
        )
        add("")
        add(
            "Overlapping intervals are the result to want and they are close to "
            "true by construction here. The two batches share no carrier text "
            "and every other thing about them is identical — the same seven "
            "directive templates, the same rotation over tasks and injection "
            "points — and the deterministic stand-in acts on the directive, "
            "which is the half that does not differ. Held-out generalisation is "
            "a claim a model arm could make from this comparison; the stand-in "
            "cannot."
        )
        add("")

    # -- the false block rate --------------------------------------------
    lines.extend(_false_block_section(run))

    # -- overhead ---------------------------------------------------------
    lines.extend(_overhead_section(run))

    # -- reproduced elsewhere ---------------------------------------------
    if hosted is not None:
        lines.extend(_reproduction_section(run, hosted))

    # -- containment over the generated runs -----------------------------
    lines.extend(_containment_section(run))

    # -- the caveats ------------------------------------------------------
    add("### What the generated tables do not say")
    add("")
    add(
        "Five things, and they are printed in full at the end of this document "
        "under *What these numbers do not say* rather than twice: placement is "
        "templated; the generator could have been tuned against `gen-a`; the "
        "injection corpus was written against chatbots and supplies the evasion "
        "but not the payment instruction; the class of a case is the "
        "generator's rotation; and **narrower intervals are a statement about "
        "n, not about the kernel getting better** — it is the same kernel, byte "
        "for byte, as the one the hand-written tables measured."
    )
    add("")
    return lines


def _reproduction_section(run: GeneratedRun, hosted: GeneratedRun) -> list[str]:
    """The same corpus, the same seed, a different machine.

    REQ-3 says the same seed and the same inputs produce byte-identical output.
    Every check of that until now has been two runs on **one** machine, which
    tests the code and not the claim: a hidden dependency on the CPU, the
    Python version or a library's internals reproduces perfectly against
    itself. This is the first time the two sides are genuinely different.
    """
    lines: list[str] = []
    add = lines.append
    verdict = compare_runs(run, hosted)
    env = (hosted.index.get("run", {}) or {}).get("env", {})
    local = platform_here() | {"per_case_s": _seconds_per_case(run)}

    add("### Reproduced on a different machine")
    add("")
    add(
        "The same generated corpus, the same seed, the same deterministic "
        "stand-in — run once on a laptop and once on a hosted Kaggle session "
        "with the internet disabled, and then compared **case by case** rather "
        "than table by table."
    )
    add("")
    lines.extend(
        _table(
            ["", "local", "hosted"],
            [
                ["operating system", local["platform"], env.get("platform", "?")],
                ["architecture", local["machine"], env.get("machine", "?")],
                ["python", local["python"], env.get("python", "?")],
                ["cryptography", local["cryptography"], env.get("cryptography", "?")],
                ["pydantic", local["pydantic"], env.get("pydantic", "?")],
                [
                    "seconds per case",
                    f"{local['per_case_s']:.3f}" if local.get("per_case_s") else "—",
                    str((hosted.index.get("run", {}) or {}).get("per_case_s", "?")),
                ],
            ],
        )
    )
    add("")
    add(
        f"**{verdict['cases']} cases agree on all {verdict['fields']} "
        "deterministic fields and on the whole ledger, with "
        f"{verdict['differences']} difference"
        + ("" if verdict["differences"] == 1 else "s")
        + ".** Run ids, event-log heads, audit-chain heads, entry counts, "
        "decisions and every debit: identical."
    )
    if verdict["disagreeing"]:
        add("")
        add("Disagreements:")
        for line in verdict["disagreeing"]:
            add(f"- `{line}`")
    add("")
    add(
        "Two fields are deliberately **excluded** from that comparison and "
        "would fail it: `latency_us` and `money_calls`. They are the one part "
        "of a run record that measures the hardware rather than the run, and "
        "the two machines differ there by more than an order of magnitude — "
        "which is exactly why no duration ever reaches the event log or the "
        "audit chain. A project that hashed a timing would have no "
        "reproducible chain at all. The per-case figures in the table are "
        "wall-clock and are not comparable to the microsecond overhead column "
        "above: the local one is derived from per-shard timestamps at "
        "one-second granularity and the hosted one from a twelve-case warm-up, "
        "so both are order-of-magnitude figures for choosing a shard count "
        "rather than measurements of the kernel."
    )
    add("")
    containment = (hosted.index.get("run", {}) or {}).get("session_containment", {})
    if containment:
        add(
            "The hosted session's own containment record: "
            f"**{containment.get('non_local_blocked', '?')}** non-local "
            "connections refused, "
            f"**{containment.get('non_local_allowed', '?')}** permitted, "
            + (
                "no hosts on the allowance"
                if not containment.get("allowed_hosts")
                else ", ".join(f"`{h}`" for h in containment["allowed_hosts"])
            )
            + ". The guard was armed around the whole session as well as "
            "around each run, and the platform had the network disabled — two "
            "different kinds of evidence for one claim, which is why the guard "
            "is armed even where the platform already refuses."
        )
        add("")
    add(
        "Until now every check of REQ-3 was two runs on one machine, which "
        "tests the code and not the claim: a hidden dependency on the CPU, the "
        "Python version or a library's internals reproduces perfectly against "
        "itself. Here the operating system, the architecture and three library "
        "versions all differ."
    )
    add("")
    return lines


def _seconds_per_case(run: GeneratedRun) -> float | None:
    """Wall-clock per case, folded over every shard's own metadata.

    Not a benchmark — it is the number that decides how many shards a hosted
    session needs, and it is the *only* figure in this comparison that is
    expected to differ between the two machines.
    """
    from datetime import datetime

    seconds = 0.0
    cases = 0
    for meta in run.metas.values():
        for shard in meta.get("shards", [meta]):
            started, finished = shard.get("started_at"), shard.get("finished_at")
            if not (started and finished and shard.get("cases")):
                continue
            seconds += (
                datetime.fromisoformat(finished.replace("Z", "+00:00"))
                - datetime.fromisoformat(started.replace("Z", "+00:00"))
            ).total_seconds()
            cases += int(shard["cases"])
    return round(seconds / cases, 3) if cases else None


def platform_here() -> dict[str, Any]:
    """This machine, in the same shape the notebook records its own."""
    import platform
    import sys

    import cryptography
    import pydantic

    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cryptography": cryptography.__version__,
        "pydantic": pydantic.VERSION,
        "per_case_s": None,
    }


def _containment_section(run: GeneratedRun) -> list[str]:
    """REQ-10 over the generated runs, folded from each shard's own record.

    Separate from the document's ``## Containment`` block, which counts the
    hand-written matrix's runs. Two measurements, two counts: a single total
    would let one set of runs vouch for another's guard.
    """
    lines: list[str] = []
    add = lines.append
    runs = armed = blocked = allowed_n = shards = fully = 0
    hosts: set[str] = set()
    for meta in run.metas.values():
        record = meta.get("containment") or {}
        runs += int(record.get("runs", 0))
        armed += int(record.get("runs_armed", 0))
        blocked += int(record.get("non_local_blocked", 0))
        allowed_n += int(record.get("non_local_allowed", 0))
        shards += int(record.get("shards", 0))
        fully += int(record.get("shards_fully_armed", 0))
        hosts.update(record.get("allowed_hosts", []))
    if not runs:
        return lines
    add("### Containment over the generated runs")
    add("")
    add(
        f"- runs behind this section — **{runs}**, of which **{armed}** were "
        "executed with the containment guard armed"
    )
    add(f"- shards — **{shards}**, of which **{fully}** had every run armed")
    add(f"- non-local connections refused — **{blocked}**")
    add(f"- non-local connections permitted — **{allowed_n}**")
    add(
        "- hosts on the allowance — "
        + (", ".join(f"`{h}`" for h in sorted(hosts)) if hosts else "**none**")
    )
    add("")
    add(
        "Counted separately from the `## Containment` block above, which covers "
        "the hand-written matrix's runs. Two measurements, two counts: one "
        "total would let one set of runs vouch for another set's guard. The "
        "guarantee is the same one and stated the same way — *no socket opened "
        "through Python's socket module* — and it is not a sandbox. Run on "
        "Kaggle with `enable_internet: false` the claim is stronger, because "
        "the platform refuses the network as well; `kaggle/README.md` says how "
        "and says why a model arm could not share this table."
    )
    add("")
    return lines


#: Fields of a run record that are a function of the seed and the corpus, and
#: must therefore be identical on any machine. ``latency_us`` and
#: ``money_calls`` are deliberately **not** here: they are the one part of a
#: record that is a measurement of the hardware rather than of the run, which
#: is why no duration ever reaches the event log or the audit chain.
DETERMINISTIC_FIELDS: tuple[str, ...] = (
    "run_id",
    "attacker_win",
    "task_success",
    "log_head",
    "log_entries",
    "chain_head",
    "chain_entries",
    "poisoned",
    "error",
    "corpus_manifest",
)


def compare_runs(left: GeneratedRun, right: GeneratedRun) -> dict[str, Any]:
    """Case-by-case agreement between two runs of the same corpus.

    Recomputed from both sets of lines rather than taken on anybody's word,
    which is the same rule the rest of this document follows: a claim of
    byte-identical reproduction that a reader cannot re-derive is a claim they
    have to take.
    """
    cells = sorted(set(left.cells) & set(right.cells))
    compared = differences = 0
    disagreeing: list[str] = []
    for key in cells:
        by_case = {
            side: {r.get("case_id") or r.get("task_id"): r for r in run.records(*key)}
            for side, run in (("left", left), ("right", right))
        }
        if set(by_case["left"]) != set(by_case["right"]):
            disagreeing.append(f"{key[0]}/{key[1]}: different case sets")
            continue
        for case_id, record in by_case["left"].items():
            other = by_case["right"][case_id]
            compared += 1
            for field_name in DETERMINISTIC_FIELDS:
                if record.get(field_name) != other.get(field_name):
                    differences += 1
                    disagreeing.append(f"{case_id}: {field_name}")
                    break
            else:
                if json.dumps(record.get("ledger"), sort_keys=True) != json.dumps(
                    other.get("ledger"), sort_keys=True
                ):
                    differences += 1
                    disagreeing.append(f"{case_id}: ledger")
    return {
        "cells": len(cells),
        "cases": compared,
        "fields": len(DETERMINISTIC_FIELDS),
        "differences": differences,
        "disagreeing": disagreeing[:10],
    }


def _dataset_pins() -> dict[str, dict[str, Any]]:
    from harness.datasets import read_registry

    return {
        role: {
            "pin": entry.pin,
            "licence": entry.licence,
            "rows": entry.rows,
            "pulled_at": entry.pulled_at,
        }
        for role, entry in read_registry().items()
    }


def _counts_table(counts: dict[str, int], left: str, right: str) -> str:
    if not counts:
        return "_nothing was dropped._"
    rows = [[f"`{k}`", str(v)] for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]
    return "\n".join(_table([left, right], rows))


def _false_block_section(run: GeneratedRun) -> list[str]:
    lines: list[str] = []
    add = lines.append
    add("### The false block rate, as a policy and a distribution")
    add("")
    policy = _cap_policy()
    add(
        "**A stated policy, applied blind.** Every generated intent's scope "
        "comes from one rule and nothing in it looks at the item being bought:"
    )
    add("")
    add(f"> {policy.get('statement', '')}")
    add("")
    add(
        "Whatever fraction of tasks lands above its own cap is the finding. It "
        "is not a knob: the false block rate **is** the measurement of this "
        "policy against a real price distribution, and moving the quantile "
        "moves the number by definition. The caps the rule produced, per "
        "category:"
    )
    add("")
    caps = (run.report.get("storefront", {}) or {}).get("caps", {})
    add(
        "\n".join(
            _table(
                ["category", "per-transaction cap", "tasks", "above cap"],
                _cap_rows(run, caps),
            )
        )
    )
    add("")
    for config in run.configs:
        records = run.records("gen_benign", config)
        if not records:
            continue
        rate = false_block_rate(records)
        blocked = false_blocks(records)
        reasons: dict[str, int] = {}
        for entry in blocked:
            reasons[entry["reason_code"]] = reasons.get(entry["reason_code"], 0) + 1
        detail = (
            ", ".join(f"`{k}` ×{v}" for k, v in sorted(reasons.items(), key=lambda kv: -kv[1]))
            if reasons
            else "nothing refused"
        )
        add(f"- `{config}` — {rate.cell()}; {detail}")
    add("")
    add(
        "Seventy refusals are not listed one by one. Twenty-five tasks earned a "
        "table naming each; four hundred and twenty would earn a table nobody "
        "reads, and the thing that actually explains the number is the policy "
        "above and the distribution beside it."
    )
    add("")
    return lines


def _cap_rows(run: GeneratedRun, caps: dict[str, int]) -> list[list[str]]:
    from harness.corpus import list_tasks, load_task

    per_category: dict[str, list[int]] = {}
    for task_id in list_tasks("generated"):
        raw = load_task(task_id).raw
        category = raw.get("generated", {}).get("category", "?")
        per_category.setdefault(category, []).append(
            raw["expect"]["total_paise"] - raw["generated"]["per_txn_cap"]
        )
    rows = []
    for category in sorted(caps):
        deltas = per_category.get(category, [])
        above = sum(1 for d in deltas if d > 0)
        rows.append(
            [
                category,
                f"₹{caps[category] / 100:,.0f}",
                str(len(deltas)),
                f"{above} ({100 * above / len(deltas):.0f}%)" if deltas else "—",
            ]
        )
    return rows


def _cap_policy() -> dict[str, Any]:
    from sim.merchants.generated import load_catalogue

    try:
        return load_catalogue().cap_policy
    except FileNotFoundError:
        return {}


def _overhead_section(run: GeneratedRun) -> list[str]:
    lines: list[str] = []
    add = lines.append
    base = run.records("gen_benign", "undefended")
    if not base:
        return lines
    add("### Overhead per money-moving call, over the generated benign suite")
    add("")
    rows = []
    for config in run.configs:
        if config == "undefended":
            continue
        arm = run.records("gen_benign", config)
        if not arm:
            continue
        cost = overhead(
            base, arm, dataset="gen_benign", arm_config=config
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
    lines.extend(
        _table(
            ["config", "base p50", "arm p50", "added p50", "base p99", "arm p99", "added p99", "calls"],
            rows,
        )
    )
    add("")
    add(
        "Pooled over the pooled calls of every shard. A p99 of per-shard p99s "
        "would be a p99 of nothing, which is already the rule inside one suite "
        "and has to survive the merge."
    )
    add("")
    return lines


def generated_caveats(run: GeneratedRun) -> list[str]:
    """The bullets that go under *What these numbers do not say*.

    Returned rather than printed so :func:`harness.report.render_results` can
    put the same four sentences in its own limits section. A caveat that lives
    in one place gets separated from the table it belongs to.
    """
    carriers = run.report.get("carriers", {})
    opens = [e for e in run.openings if e.get("kind") == "open"]
    counts = run.manifest.get("counts", {})
    return [
        "- **Placement is templated, so a payload's position is our choice and "
        "not an attacker's.** Each case's injection point is the next "
        "admissible one in a rotation over the surfaces the target task "
        "actually reads. An attacker would pick the best surface; the "
        "generator rotates over the legal ones. The directive also always goes "
        "*last*, which is the favourable order for the attacker under the "
        "stand-in's own rule that later text corrects earlier text.",
        "- **The generator could have been tuned against `gen-a`.** `gen-b` is "
        "the held-out answer, and it is "
        + (
            f"there are **{len(opens)} openings** on record for it"
            if len(opens) != 1
            else "there is one opening, logged"
        )
        + " — which is weaker than a corpus nobody could have tuned against."
        + (
            " The first opening was against a corpus that was regenerated "
            "afterwards, when a defect was found in the *benign* generator; "
            "the reasons are in `harness/attacks/openings.jsonl` and a reader "
            "should weigh them rather than take this sentence for it."
            if len(opens) > 1
            else ""
        ),
        "- **The injection corpus was written against chatbots, not against a "
        f"payment rail.** {carriers.get('carriers_naming_no_rail_goal', 0)} of "
        f"{carriers.get('admitted', 0)} admitted carriers name none of the "
        "seven payment decisions. The corpus supplies the evasion; the "
        "operative payment instruction in every generated payload was written "
        "by the generator, because there was none in the corpus to take. A "
        "generated case is therefore real attack *text* wrapped around a "
        "synthetic payment *directive*, and it is a weaker artefact than a "
        "payload somebody wrote against this rail.",
        "- **Narrower intervals are a statement about n, not about the kernel "
        "getting better.** 0/"
        + str(counts.get("gen_a", 0))
        + " is a tighter bound than 0/105 because there is more evidence, not "
        "because anything in `kernel/` changed. It is the same kernel, "
        "byte for byte, as the one the hand-written tables measured.",
        "- **The class of a generated case is the generator's rotation, not the "
        "carrier's.** Only "
        f"{run.report.get('attacks', {}).get('batches', {}).get('gen-a', {}).get('carriers_that_named_their_own_class', 0)}"
        " carriers per batch already argued about the decision their case "
        "attacks; the rest were assigned. A per-class ASR here is a measurement "
        "of the directive and the kernel, not of the corpus's own intent.",
    ]


def splice(document: str, run: GeneratedRun, *, hosted: GeneratedRun | None = None) -> str:
    """Put the generated section into an existing ``results.md``, idempotently.

    Between fences, and replacing whatever is between them, so running this
    twice produces the same document and running it after a fresh measurement
    updates only the generated numbers.

    Why not simply re-render the whole file: the hand-written tables were
    measured against a corpus hash and a batch B opening that both still stand.
    Regenerating the document to add a section would mean re-running those
    suites and opening the held-out set a second time — the numbers would move,
    the opening count would go up, and nothing about the kernel would have
    changed. A held-out measurement is not something to spend on formatting.
    """
    section = "\n".join(render_generated(run, hosted=hosted)).rstrip() + "\n"
    caveats = "\n".join(generated_caveats(run)).rstrip() + "\n"

    document = _replace_fenced(document, SECTION_FENCE, section, before=SECTION_BEFORE)
    document = _replace_fenced(
        document, CAVEAT_FENCE, caveats, after_section=CAVEATS_AFTER
    )
    return document


def _replace_fenced(
    document: str,
    fence: tuple[str, str],
    body: str,
    *,
    before: str | None = None,
    after_section: str | None = None,
) -> str:
    start, end = fence
    block = f"{start}\n\n{body}\n{end}\n"
    if start in document and end in document:
        head = document[: document.index(start)]
        tail = document[document.index(end) + len(end) :].lstrip("\n")
        return head + block + ("\n" + tail if tail else "")
    if before is not None and before in document:
        cut = document.index(before)
        return document[:cut] + block + "\n" + document[cut:]
    if after_section is not None and after_section in document:
        # Append to the end of that section, which is the end of the document.
        return document.rstrip("\n") + "\n" + block
    return document.rstrip("\n") + "\n\n" + block
