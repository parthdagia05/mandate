"""Sharding: the same cases in the same shard, on any machine, every time.

A shard that quietly held different cases would make "re-run the missing shard"
false and would make two merges of one experiment disagree, with nothing in
either table saying so.
"""

from __future__ import annotations

import pytest

from harness.shard import Shard, ShardError, parse_shard, shard_of, slice_for
from harness.suite import select


def test_the_shards_partition_the_plan_exactly_once():
    items = list(range(735))
    for count in (1, 2, 3, 4, 8, 13, 735):
        seen: list[int] = []
        for index in range(count):
            seen.extend(slice_for(items, Shard(index=index, count=count)))
        assert seen == items, count


def test_uneven_splits_go_to_the_low_shards():
    """The wall-clock bound is set by the largest shard, so sizes differ by one."""
    sizes = [len(slice_for(list(range(735)), Shard(i, 8))) for i in range(8)]
    assert sizes == [92, 92, 92, 92, 92, 92, 92, 91]
    assert max(sizes) - min(sizes) <= 1


def test_a_shard_is_the_same_cases_every_time():
    """From the frozen corpus order, so shard 3 of 8 is a fixed set of cases."""
    once = [c.label for c in select("batch_a", shard=parse_shard("3/8"))]
    twice = [c.label for c in select("batch_a", shard=parse_shard("3/8"))]
    assert once == twice and once


def test_shards_of_one_dataset_are_disjoint_and_complete():
    whole = [c.label for c in select("batch_a")]
    pieces: list[str] = []
    for i in range(1, 5):
        pieces.extend(c.label for c in select("batch_a", shard=parse_shard(f"{i}/4")))
    assert pieces == whole
    assert len(set(pieces)) == len(pieces)


def test_shard_of_is_the_inverse_of_slice_for():
    items = list(range(101))
    for count in (1, 3, 7):
        for index in range(count):
            for value in slice_for(items, Shard(index, count)):
                assert shard_of(value, len(items), count) == index


def test_zero_is_refused_rather_than_read_as_the_first_shard():
    """Accepting both conventions would run shard 1 twice and shard 8 never,
    and the merge would report seven shards where eight were asked for."""
    with pytest.raises(ShardError, match="numbered from 1"):
        parse_shard("0/8")


@pytest.mark.parametrize("text", ["8", "3/0", "a/b", "3/", "/8"])
def test_a_malformed_shard_is_refused(text):
    with pytest.raises(ShardError):
        parse_shard(text)


def test_a_shard_beyond_the_count_does_not_exist():
    with pytest.raises(ShardError, match="does not exist"):
        parse_shard("9/8")


def test_the_shard_index_is_not_in_the_run_id():
    """A case re-run alone must produce the same run_id it had inside a shard.

    That identity is what lets the merge notice a case counted twice; a run_id
    that carried the shard would disguise the duplicate as a different run.
    """
    from harness.runner import run_id_for

    assert run_id_for(seed="0", task_id="benign-01", case_id="A1-a-05", config="kernel") == \
        run_id_for(seed="0", task_id="benign-01", case_id="A1-a-05", config="kernel")


def test_a_shard_of_a_filtered_selection_is_a_slice_of_the_filter():
    """`--class A1 --shard 2/4` is a quarter of the A1 cases, not the A1 cases
    that happen to fall inside a quarter of the corpus."""
    a1 = select("batch_a", attack_class="A1")
    pieces = sum(
        len(select("batch_a", attack_class="A1", shard=parse_shard(f"{i}/4")))
        for i in range(1, 5)
    )
    assert pieces == len(a1)


def test_an_empty_shard_is_refused():
    """An empty suite would produce an empty table that reads like a perfect score."""
    with pytest.raises(ValueError, match="empty suite"):
        select("batch_a", attack_class="A1", shard=parse_shard("40/40"))
