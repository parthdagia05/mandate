"""Putting shards back together, and refusing the merges that would lie.

A sharded run is many processes writing many JSONL files, and the arithmetic
that turns them into one table is trivial. The refusals are not, and each one
here exists because its failure produces a **complete-looking table**:

**Mixed corpora.** Two shards measured against different manifest hashes are two
experiments. Merged, they produce one table with a denominator, an ASR and an
interval, and nothing about it says that half its rows were measured against a
corpus the other half never saw.

**A missing shard.** A shard that died leaves the other seven finishing
normally, and seven eighths of a suite is a suite — smaller, and otherwise
indistinguishable. The merge is the only place this can be noticed, because it
is the only place that knows how many shards there were meant to be. That is
why each shard's metadata records ``i of n`` and why this refuses without the
full set.

**A case counted twice.** Re-running a shard and forgetting to remove the old
file doubles some cases and not others, which biases whichever way those cases
went. Case ids are unique within a suite by construction, so a repeat is
detectable — and ``run_id`` deliberately does *not* carry the shard index
(:mod:`harness.shard`), so the same case run twice really is the same id and
the duplicate is visible rather than disguised.

**Percentiles are pooled over pooled calls.** A p99 of per-shard p99s is a p99
of nothing. This is already the rule inside one suite
(:attr:`~harness.suite.SuiteResult.latency_us`) and it has to survive the merge,
so the raw ``money_calls`` samples are pooled and the percentile is taken once
over all of them.

**Wilson intervals are recomputed on the pooled n**, never averaged. An average
of two intervals is not an interval.

**Every shard's metadata is kept**, including its containment record. A merged
run record that dropped them could not say whether every shard ran with the
guard armed — and "no non-local socket opened during any of the runs behind
this table" is a claim about every run, not about the last shard's metadata.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from harness.runner import percentiles

__all__ = ["MergeError", "MergedRun", "merge", "write_merged"]


class MergeError(ValueError):
    """A merge that would produce a table of unrelated numbers."""


@dataclass
class MergedRun:
    """One dataset's lines, reassembled, with every shard's provenance kept."""

    dataset: str
    config: str
    seed: str
    model: str
    corpus_manifest: str
    records: list[dict[str, Any]] = field(default_factory=list)
    shards: list[dict[str, Any]] = field(default_factory=list)

    @property
    def scored(self) -> list[dict[str, Any]]:
        return [
            r for r in self.records if not r.get("poisoned") and not r.get("error")
        ]

    @property
    def latency_us(self) -> dict[str, int]:
        """Percentiles over every money-moving call in every shard."""
        return percentiles(
            [
                int(call["latency_us"])
                for record in self.scored
                for call in record.get("money_calls", [])
            ]
        )

    def containment(self) -> dict[str, Any]:
        """Folded over the shards' own records, and honest about gaps.

        ``shards_armed`` is counted separately from ``runs_armed`` because the
        two failures are different: one shard whose guard was off is a hole in
        the claim, and one *run* whose guard was off inside an otherwise-armed
        shard is a different hole. A single boolean would hide both.
        """
        hosts: set[str] = set()
        runs = armed = blocked = allowed = 0
        shards_armed = 0
        for shard in self.shards:
            record = shard.get("containment") or {}
            runs += int(record.get("runs", 0))
            armed += int(record.get("armed", 0))
            blocked += int(record.get("non_local_blocked", 0))
            allowed += int(record.get("non_local_allowed", 0))
            hosts.update(record.get("allowed_hosts", []))
            if record.get("runs") and record.get("armed") == record.get("runs"):
                shards_armed += 1
        return {
            "runs": runs,
            "runs_armed": armed,
            "shards": len(self.shards),
            "shards_fully_armed": shards_armed,
            "non_local_blocked": blocked,
            "non_local_allowed": allowed,
            "allowed_hosts": sorted(hosts),
            "model_endpoint_allowed": bool(hosts),
        }

    def summary(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "config": self.config,
            "seed": self.seed,
            "model": self.model,
            "corpus_manifest": self.corpus_manifest,
            "cases": len(self.records),
            "scored": len(self.scored),
            "errors": sum(1 for r in self.records if r.get("error")),
            "poisoned": sum(1 for r in self.records if r.get("poisoned")),
            "attacker_wins": sum(1 for r in self.scored if r.get("attacker_win")),
            "task_successes": sum(1 for r in self.scored if r.get("task_success")),
            "latency_us": self.latency_us,
            "containment": self.containment(),
            # Every shard's metadata, kept whole. A merged record that
            # summarised these away could not answer "which machine ran shard
            # 5, and was its guard armed?".
            "shards": self.shards,
        }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _meta_for(path: Path) -> dict[str, Any]:
    meta = path.with_suffix(".meta.json")
    if not meta.exists():
        raise MergeError(
            f"{path.name} has no {meta.name} beside it. A shard's metadata is "
            "where its shard index, its host and its containment record live, "
            "and a merge without them cannot notice a missing shard."
        )
    return json.loads(meta.read_text())


def merge(paths: Sequence[Path]) -> MergedRun:
    """Reassemble one dataset from its shards, or refuse and say why."""
    if not paths:
        raise MergeError("nothing to merge; an empty merge is an empty table")

    metas = [(Path(p), _meta_for(Path(p))) for p in paths]

    for field_name in ("dataset", "config", "seed", "model", "corpus_manifest"):
        values = {meta.get(field_name) for _, meta in metas}
        if len(values) > 1:
            raise MergeError(
                f"the shards disagree about {field_name}: {sorted(map(str, values))}. "
                "Merging them would produce one table whose rows were measured "
                "under different conditions, with nothing in the table saying so."
            )

    counts = {
        (meta.get("shard") or {}).get("count")
        for _, meta in metas
        if meta.get("shard")
    }
    if len(counts) > 1:
        raise MergeError(
            f"the shards disagree about how many shards there are: {sorted(counts)}"
        )
    if counts:
        total = counts.pop()
        seen = {
            (meta.get("shard") or {}).get("index")
            for _, meta in metas
            if meta.get("shard")
        }
        missing = sorted(set(range(total)) - seen)
        if missing:
            raise MergeError(
                f"{len(missing)} shard(s) missing from the merge: "
                + ", ".join(f"{i + 1}/{total}" for i in missing)
                + ". A shard that died leaves the others finishing normally, "
                "and a table short one shard is otherwise indistinguishable "
                "from a smaller suite. Re-run the missing shard alone."
            )
        if len(metas) != total:
            raise MergeError(
                f"{len(metas)} file(s) for {total} shard(s): a shard is "
                "present twice. Every case in it would be counted twice."
            )

    first = metas[0][1]
    merged = MergedRun(
        dataset=first.get("dataset", ""),
        config=first.get("config", ""),
        seed=first.get("seed", ""),
        model=first.get("model", ""),
        corpus_manifest=first.get("corpus_manifest", ""),
    )

    order = sorted(metas, key=lambda pair: (pair[1].get("shard") or {}).get("index", 0))
    seen_cases: dict[str, str] = {}
    for path, meta in order:
        merged.shards.append(meta)
        for record in _read_jsonl(path):
            key = record.get("case_id") or record.get("task_id") or ""
            if key in seen_cases:
                raise MergeError(
                    f"{key} appears in both {seen_cases[key]} and {path.name}. "
                    "A case counted twice biases the table towards whichever "
                    "way that case went; re-run the shard, do not merge both."
                )
            seen_cases[key] = path.name
            if record.get("corpus_manifest") != merged.corpus_manifest:
                raise MergeError(
                    f"{key} in {path.name} quotes corpus "
                    f"{record.get('corpus_manifest')} but the shard's metadata "
                    f"says {merged.corpus_manifest}. The corpus moved while the "
                    "shard was running and nothing from it may be published."
                )
            merged.records.append(record)
    return merged


def write_merged(merged: MergedRun, out: Path) -> tuple[Path, Path]:
    """Write the pooled JSONL and its metadata. Returns both paths.

    The output is the *same shape* a single-process suite writes — one JSONL
    and one ``.meta.json`` — so ``mk report`` and every metric function read a
    merged run and an unsharded one through the same code. A merged run that
    needed its own reader would be a second implementation of the table.
    """
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as handle:
        for record in merged.records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    meta = out.with_suffix(".meta.json")
    meta.write_text(json.dumps(merged.summary(), indent=2, sort_keys=True) + "\n")
    return out, meta
