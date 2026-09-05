"""What the pages need, assembled from the files the harness already wrote.

Every number in here is :mod:`harness.metrics`' own, serialised through
``Proportion.as_dict()``. Nothing is computed locally, nothing is rounded, and
nothing is renamed. The reason is issue #91's: a page that recomputes will one
day disagree with ``results.md`` and nobody will be able to say which is wrong.
That argument bars a second implementation here as firmly as it bars one in
TypeScript, so this module is a *projection* — it selects and labels, and it
does no arithmetic that is not already in the harness.

Two consequences worth naming, because both look like omissions:

**The chain is verified by a subprocess.** ``scripts/verify_chain.py`` imports
nothing from the project and carries its own RFC 8785, which is the whole reason
REQ-9 asks reviewers to trust it. Calling into it in-process would defeat that,
and reimplementing it here — or in the browser (#88) — would produce the second
implementation the verifier exists to be checked against.

**``overhead`` is absent unless the dataset is the one it was measured over.**
:func:`harness.metrics.overhead` refuses to subtract across datasets, because
the benign suite and an attack batch do not make the same tool calls and the
difference between them would be a difference in workload wearing the costume
of a defence's cost. This module does not work around that refusal.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

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
    recovered,
    targeted_asr,
    utility_under_attack,
)

__all__ = [
    "matrix_provenance",
    "results",
    "ablation",
    "chain",
    "verify_chain_file",
    "run_detail",
    "VERIFIER",
]

#: The standalone verifier. Run as a subprocess, deliberately — see the module
#: docstring.
VERIFIER = Path(__file__).resolve().parents[2] / "scripts" / "verify_chain.py"

#: ``OK, 5 entries, head sha256:…`` / ``BROKEN at seq 3: <why>``
_OK = re.compile(r"^OK,\s*(\d+)\s*entries?,\s*head\s*(sha256:[0-9a-f]{64})")
_BROKEN = re.compile(r"^BROKEN at seq (\d+):\s*(.*)$")

#: The benign dataset in a matrix — the one the false-block rate and the
#: overhead difference are computed over.
_BENIGN = ("benign", "gen_benign")


def _prop(value: Proportion | None) -> dict[str, Any] | None:
    """A proportion on the wire: ``as_dict()``, untouched.

    ``label``, ``k``, ``n``, ``p`` and ``ci95`` — the estimate *and* the counts
    *and* the Wilson interval, together, because the type on the Python side has
    no method that renders the estimate alone and the wire format must not
    invent one.
    """
    return value.as_dict() if value is not None else None


# ---------------------------------------------------------------------------
# provenance
# ---------------------------------------------------------------------------


def matrix_provenance(matrix: Any) -> dict[str, Any]:
    """What a screenshot has to carry to be evidence rather than a picture.

    Issue #85 wants the corpus hash, the seed, the model id and the arm at the
    top of the results page. All four are here, plus the two that ``results.md``
    prints for the same reason: how many times batch B has been opened, and
    whether the corpus moved during the run.
    """
    return {
        "matrix_id": matrix.matrix_id,
        "seed": matrix.seed,
        "model": matrix.model,
        "corpus_manifest": matrix.corpus_manifest,
        "corpus_manifests": dict(matrix.corpus_manifests),
        "datasets": list(matrix.datasets),
        "configs": list(matrix.configs),
        "started_at": matrix.started_at,
        "finished_at": matrix.finished_at,
        "batch_b_openings": len(matrix.batch_b_openings),
        "corpus_drift": list(matrix.corpus_drift),
        "out_dir": str(matrix.out_dir),
    }


def _stand_in(matrix: Any) -> bool:
    """Whether the deterministic stand-in drove these runs.

    Reuses ``harness.report``'s own predicate rather than comparing model ids
    here: the banner it gates is the sentence ``results.md`` prints in bold —
    "no ASR figure below is a model measurement" — and a page that decided this
    differently from the document would drop that line on exactly the runs that
    need it.
    """
    from harness.report import _scripted

    return _scripted(matrix)


# ---------------------------------------------------------------------------
# results (#85)
# ---------------------------------------------------------------------------


def results(matrix: Any, dataset: str) -> dict[str, Any]:
    """Every table on the results page, for one dataset."""
    from harness.report import CONFIG_BLURB, _technique_map

    configs = list(matrix.configs)
    if dataset not in matrix.datasets:
        raise KeyError(dataset)

    benign = next((d for d in matrix.datasets if d in _BENIGN), None)
    attack = dataset not in _BENIGN

    techniques = _technique_map(
        record for config in configs for record in matrix.records(dataset, config)
    )

    headline: list[dict[str, Any]] = []
    by_class: dict[str, dict[str, Any]] = {}
    by_family: dict[str, dict[str, Any]] = {}
    refusals: dict[str, list[dict[str, Any]]] = {}
    guards: dict[str, list[dict[str, Any]]] = {}
    blocked: dict[str, list[dict[str, Any]]] = {}

    for config in configs:
        records = matrix.records(dataset, config)
        benign_records = matrix.records(benign, config) if benign else []

        headline.append(
            {
                "config": config,
                "targeted_asr": _prop(targeted_asr(records)) if attack else None,
                "utility_under_attack": (
                    _prop(utility_under_attack(records)) if attack else None
                ),
                "benign_utility": _prop(benign_utility(benign_records or records)),
                "false_block_rate": _prop(
                    false_block_rate(benign_records or records)
                ),
                "recovered": _prop(recovered(records)),
                "overhead": _overhead(matrix, benign, config),
            }
        )

        for cls, value in asr_by_class(records).items():
            by_class.setdefault(cls, {})[config] = _prop(value)
        for family, value in asr_by_technique(records, techniques).items():
            by_family.setdefault(family, {})[config] = _prop(value)

        refusals[config] = [
            {"reason_code": code, "count": count}
            for code, count in sorted(
                denial_reasons(records).items(), key=lambda kv: (-kv[1], kv[0])
            )
        ]
        guards[config] = [
            {"refusal": name, "count": count}
            for name, count in sorted(
                guard_refusals(records).items(), key=lambda kv: (-kv[1], kv[0])
            )
        ]
        blocked[config] = false_blocks(benign_records or records)

    return {
        "schema": "mandate.web.results/1",
        "dataset": dataset,
        "is_attack_dataset": attack,
        "benign_dataset": benign,
        "stand_in": _stand_in(matrix),
        "matrix": matrix_provenance(matrix),
        "arms": [
            {"config": config, "blurb": CONFIG_BLURB.get(config, "")}
            for config in configs
        ],
        "headline": headline,
        "by_class": by_class,
        "by_family": by_family,
        "refusals": refusals,
        "guard_refusals": guards,
        "false_blocks": blocked,
    }


def _overhead(matrix: Any, benign: str | None, config: str) -> dict[str, Any] | None:
    """The kernel's cost, as a difference over the benign suite.

    ``None`` for the baseline arm and whenever the matrix has no benign
    dataset: a defence's overhead against itself is zero and printing that as a
    measurement would be a column of noise.
    """
    if benign is None or config == "undefended":
        return None
    baseline = matrix.records(benign, "undefended")
    arm = matrix.records(benign, config)
    if not baseline or not arm:
        return None
    return overhead(
        baseline, arm, dataset=benign, baseline_config="undefended", arm_config=config
    ).as_dict()


# ---------------------------------------------------------------------------
# ablation
# ---------------------------------------------------------------------------


def ablation(result: Any) -> dict[str, Any]:
    """The per-check tables, from ``harness.report``'s own verdicts.

    ``ablation_verdicts`` answers two questions per check — necessary given the
    others, and sufficient alone — and both are carried, because the checks
    overlap on purpose and a single-ablation table reports an overlapped check
    as worthless.
    """
    from harness.report import ablation_verdicts

    verdicts = ablation_verdicts(result)
    rows = []
    for row in result.rows:
        rows.append(
            {
                "check_ids": list(row.check_ids),
                "check_id": row.check_id,
                "label": row.label,
                "mode": row.mode,
                "suite_id": row.suite_id,
                "targeted_asr": _prop(targeted_asr(row.records)),
                "by_class": {
                    cls: _prop(value)
                    for cls, value in asr_by_class(row.records).items()
                },
            }
        )
    return {
        "schema": "mandate.web.ablation/1",
        "dataset": result.dataset,
        "seed": result.seed,
        "model": result.model,
        "corpus_manifest": result.corpus_manifest,
        "baseline_suite_id": result.baseline_suite_id,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "baseline": {
            "targeted_asr": _prop(targeted_asr(result.baseline)),
            "by_class": {
                cls: _prop(value)
                for cls, value in asr_by_class(result.baseline).items()
            },
        },
        "rows": rows,
        "verdicts": {
            str(check_id): {
                "necessary_for": entry["necessary_for"],
                "sufficient_for": entry["sufficient_for"],
                "earns_row": entry["earns_row"],
            }
            for check_id, entry in sorted(verdicts.items())
        },
    }


# ---------------------------------------------------------------------------
# the chain (#88)
# ---------------------------------------------------------------------------


def verify_chain_file(path: Path) -> dict[str, Any]:
    """Run the standalone verifier and report what it said.

    Not a reimplementation, in this file or in the browser. The verifier's
    verdict is the artifact; this parses its one line of output.

    A non-zero exit with unparseable output is reported as ``ok: false`` with
    the raw text, rather than as an exception: a broken chain is a *finding* the
    page has to show, and a viewer that 500s on the run it most needs to display
    would hide it.
    """
    try:
        done = subprocess.run(
            [sys.executable, str(VERIFIER), str(path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        return {
            "ok": False,
            "entries": None,
            "head": None,
            "broken_at": None,
            "message": f"verifier could not be run: {exc}",
            "verifier": str(VERIFIER),
        }

    text = (done.stdout or done.stderr or "").strip()
    first = text.splitlines()[0] if text else ""

    ok_match = _OK.match(first)
    if done.returncode == 0 and ok_match:
        return {
            "ok": True,
            "entries": int(ok_match.group(1)),
            "head": ok_match.group(2),
            "broken_at": None,
            "message": first,
            "verifier": str(VERIFIER),
        }

    broken = _BROKEN.match(first)
    return {
        "ok": False,
        "entries": None,
        "head": None,
        "broken_at": int(broken.group(1)) if broken else None,
        "message": first or f"verifier exited {done.returncode}",
        "verifier": str(VERIFIER),
    }


def chain(index: Any, entry: Any) -> dict[str, Any]:
    """One run's audit chain, with the verifier's verdict beside it.

    A run with no chain is not a failure. The undefended arm appends nothing,
    so ``entries`` is empty, ``verify`` is ``None``, and the page must render
    "no chain" rather than "unverified" — those are different claims and only
    one of them is true.
    """
    path = index.chain_file(entry)
    if path is None:
        return {
            "schema": "mandate.web.chain/1",
            "run_id": entry.run_id,
            "path": None,
            "entries": [],
            "head": None,
            "verify": None,
            "note": (
                "this arm appends no audit chain; absence of a chain is not a "
                "failed verification"
            ),
        }

    entries: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    return {
        "schema": "mandate.web.chain/1",
        "run_id": entry.run_id,
        "path": str(path),
        "entries": entries,
        "head": entries[-1]["entry_hash"] if entries else None,
        "verify": verify_chain_file(path),
        "note": None,
    }


# ---------------------------------------------------------------------------
# one run (#87)
# ---------------------------------------------------------------------------


def run_detail(index: Any, entry: Any) -> dict[str, Any]:
    """The record as written, plus the joins the page cannot make itself."""
    record = index.record(entry)
    return {
        "schema": "mandate.web.run/1",
        "record": record,
        "outcome": entry.outcome,
        "counterparts": index.counterparts(entry),
        "task": _task(record.get("task_id")),
        "attack": _attack(record.get("case_id")),
        "utterance_binding": _binding(index, entry, record),
    }


def _task(task_id: str | None) -> dict[str, Any] | None:
    """The task, including the utterance the whole project is about.

    The utterance is not on the run record — it is a property of the task, and
    the chain binds to it by *hash*. So the page needs this join to show the
    sentence at all.
    """
    if not task_id:
        return None
    from harness.corpus import load_task

    try:
        task = load_task(task_id)
    except (KeyError, ValueError):
        return None
    return {
        "task_id": task.task_id,
        "corpus": task.corpus,
        "merchant": task.merchant,
        "utterance": task.raw.get("utterance"),
        "query": task.raw.get("query"),
        "wants": task.raw.get("wants"),
        "scope": task.raw.get("scope"),
        "expect": task.expect,
    }


def _attack(case_id: str | None) -> dict[str, Any] | None:
    """The attack case, with the payload only if the batch is open.

    ``AttackCase.payload`` raises :class:`harness.corpus.BatchBSealed` for a
    held-out batch. That is caught here and reported as ``held_out: true`` with
    no payload — the seal is the feature, and a viewer must neither break on it
    nor route around it. Class, technique, oracle and injection point are all
    outside the seal, so a held-out case is still describable.
    """
    if not case_id:
        return None
    from harness.corpus import BatchBSealed, load_attack

    try:
        case = load_attack(case_id)
    except (KeyError, ValueError):
        return None

    out: dict[str, Any] = {
        "case_id": case.case_id,
        "class": case.attack_class,
        "batch": case.batch,
        "task": case.task_id,
        "technique": case.technique,
        "oracle": case.oracle,
        "injection_point": str(case.point),
        "expected_undefended": case.raw.get("expected_undefended"),
        "held_out": False,
        "payload": None,
    }
    try:
        out["payload"] = case.payload
    except BatchBSealed:
        out["held_out"] = True
    return out


def _binding(index: Any, entry: Any, record: dict[str, Any]) -> dict[str, Any] | None:
    """Does the chain's ``utterance_hash`` name the sentence we are showing?

    This is the join Shot 5 turns on. The chain does not carry the utterance in
    plaintext — it carries ``utterance_hash`` in the ``intent.registered``
    payload — so a page that simply printed the task's utterance beside the
    chain would be *asserting* the binding rather than showing it.

    The hash is recomputed here from the utterance text using the kernel's own
    hashing, and ``matches`` is the comparison. A ``False`` is a real finding
    and must render as one, not as a missing field.
    """
    chain_path = index.chain_file(entry)
    if chain_path is None:
        return None

    recorded: str | None = None
    with chain_path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            parsed = json.loads(line)
            if parsed.get("action") == "intent.registered":
                recorded = (parsed.get("payload") or {}).get("utterance_hash")
                break
    if recorded is None:
        return None

    task = _task(record.get("task_id"))
    utterance = (task or {}).get("utterance")
    computed = _utterance_hash(utterance) if utterance else None
    return {
        "utterance_hash": recorded,
        "utterance": utterance,
        "computed": computed,
        "matches": bool(computed) and computed == recorded,
    }


def _utterance_hash(utterance: str) -> str | None:
    """The kernel's own utterance hash, from the kernel's own code.

    Imported rather than reimplemented: this is the one place the web layer
    computes a hash at all, and it exists to *check* a binding rather than to
    assert one. Using anything but the kernel's function would make a mismatch
    mean "the web layer disagrees" instead of "the chain does not name this
    sentence".
    """
    try:
        from kernel.crypto import utterance_hash

        return utterance_hash(utterance)
    except Exception:  # pragma: no cover - kernel absent or renamed
        return None
