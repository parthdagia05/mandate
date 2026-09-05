"""The merge, and the four merges it refuses.

Every refusal here exists because its failure produces a *complete-looking
table*. That is the whole reason the merge is a step with opinions rather than
``cat *.jsonl``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.merge import MergeError, merge, write_merged


def _shard(directory: Path, name: str, *, index: int, count: int, cases, **meta):
    path = directory / f"{name}.jsonl"
    with path.open("w") as handle:
        for case in cases:
            handle.write(json.dumps(case, sort_keys=True) + "\n")
    body = {
        "dataset": "gen_a",
        "config": "kernel",
        "seed": "0",
        "model": "scripted",
        "corpus_manifest": "sha256:corpus",
        "shard": {"index": index, "count": count},
        "containment": {
            "runs": len(cases),
            "armed": len(cases),
            "non_local_blocked": 0,
            "non_local_allowed": 0,
            "allowed_hosts": [],
        },
        **meta,
    }
    path.with_suffix(".meta.json").write_text(json.dumps(body, indent=2, sort_keys=True))
    return path


def _case(case_id: str, *, win=False, calls=(100,)):
    return {
        "case_id": case_id,
        "task_id": "gen-0001",
        "attacker_win": win,
        "task_success": True,
        "corpus_manifest": "sha256:corpus",
        "money_calls": [{"call": "pay", "latency_us": c} for c in calls],
        "poisoned": None,
        "error": None,
    }


@pytest.fixture
def two_shards(tmp_path):
    a = _shard(tmp_path, "a", index=0, count=2, cases=[_case("A1-gen-a-001", win=True)])
    b = _shard(tmp_path, "b", index=1, count=2, cases=[_case("A1-gen-a-002")])
    return [a, b]


def test_a_complete_merge_pools_the_cases(two_shards, tmp_path):
    merged = merge(two_shards)
    assert len(merged.records) == 2
    assert merged.summary()["attacker_wins"] == 1
    path, meta = write_merged(merged, tmp_path / "merged.jsonl")
    assert len(path.read_text().splitlines()) == 2
    assert json.loads(meta.read_text())["cases"] == 2


def test_a_missing_shard_is_refused(two_shards):
    """Seven eighths of a suite is a suite — smaller, and otherwise
    indistinguishable. The merge is the only place this can be noticed."""
    with pytest.raises(MergeError, match="missing from the merge"):
        merge(two_shards[:1])


def test_a_shard_present_twice_is_refused(tmp_path, two_shards):
    again = _shard(
        tmp_path, "again", index=0, count=2, cases=[_case("A1-gen-a-001", win=True)]
    )
    with pytest.raises(MergeError, match="present twice"):
        merge(two_shards + [again])


def test_a_case_appearing_twice_is_refused(tmp_path):
    """Counting a case twice biases the table towards whichever way it went."""
    a = _shard(tmp_path, "a", index=0, count=2, cases=[_case("dup")])
    b = _shard(tmp_path, "b", index=1, count=2, cases=[_case("dup")])
    with pytest.raises(MergeError, match="appears in both"):
        merge([a, b])


def test_two_corpora_are_refused(tmp_path):
    """A table whose rows were measured against different corpora is a table of
    unrelated numbers, and nothing in it would say so."""
    a = _shard(tmp_path, "a", index=0, count=2, cases=[_case("one")])
    b = _shard(
        tmp_path,
        "b",
        index=1,
        count=2,
        cases=[_case("two")],
        corpus_manifest="sha256:other",
    )
    with pytest.raises(MergeError, match="corpus_manifest"):
        merge([a, b])


def test_a_line_that_disagrees_with_its_own_shards_metadata_is_refused(tmp_path):
    """The corpus moved mid-shard: the lines quote a hash that is no longer true."""
    drifted = _case("one")
    drifted["corpus_manifest"] = "sha256:moved"
    a = _shard(tmp_path, "a", index=0, count=1, cases=[drifted])
    with pytest.raises(MergeError, match="corpus moved"):
        merge([a])


def test_a_shard_with_no_metadata_is_refused(tmp_path):
    path = tmp_path / "lonely.jsonl"
    path.write_text(json.dumps(_case("one")) + "\n")
    with pytest.raises(MergeError, match="no lonely.meta.json"):
        merge([path])


def test_percentiles_are_pooled_over_pooled_calls(tmp_path):
    """A p99 of per-shard p99s is a p99 of nothing.

    Each shard here has a maximum of its own; the pooled p99 has to be the
    maximum of everything, not the average of the two maxima.
    """
    a = _shard(tmp_path, "a", index=0, count=2, cases=[_case("one", calls=(10, 20, 30))])
    b = _shard(tmp_path, "b", index=1, count=2, cases=[_case("two", calls=(1000,))])
    merged = merge([a, b])
    assert merged.latency_us["n"] == 4
    assert merged.latency_us["p99"] == 1000


def test_every_shards_metadata_survives_the_merge(two_shards):
    """Including its containment record: 'no non-local socket opened during any
    of the runs behind this table' is a claim about every run."""
    merged = merge(two_shards)
    assert len(merged.summary()["shards"]) == 2
    containment = merged.containment()
    assert containment["runs"] == 2 and containment["runs_armed"] == 2
    assert containment["shards_fully_armed"] == 2
    assert containment["non_local_blocked"] == 0


def test_a_shard_whose_guard_was_not_armed_is_visible(tmp_path):
    """A single boolean would hide the difference between one unarmed run and
    one unarmed shard."""
    a = _shard(tmp_path, "a", index=0, count=2, cases=[_case("one")])
    b = _shard(
        tmp_path,
        "b",
        index=1,
        count=2,
        cases=[_case("two")],
        containment={"runs": 1, "armed": 0, "non_local_blocked": 0,
                     "non_local_allowed": 0, "allowed_hosts": []},
    )
    containment = merge([a, b]).containment()
    assert containment["runs"] == 2 and containment["runs_armed"] == 1
    assert containment["shards_fully_armed"] == 1


def test_an_empty_merge_is_refused():
    with pytest.raises(MergeError, match="empty merge"):
        merge([])
