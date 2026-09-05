"""Splitting a suite across processes, deterministically.

``run_suite`` refuses to be entered twice in one process **by design**: SQLite
has a single writer, and two cases writing at once would serialise behind each
other's locks — the overhead column would become a measurement of contention
between two runs that would never happen together in production. So the
parallelism axis the harness sanctions is *separate processes*, and this is how
a run is cut up along it.

**A shard is a contiguous block of the frozen corpus order.** The plan
``harness.suite.select`` returns is already sorted by case id and is a function
of the corpus alone, so shard 3 of 8 is the same cases today and tomorrow and on
somebody else's machine. Contiguous rather than round-robin because a shard that
dies is re-run alone, and a block is a range a person can read in a filename.

**Uneven splits go to the low shards.** 735 cases over 8 shards is 92, 92, 92,
92, 92, 92, 92, 91 — never 105 and a stub, because the point of sharding is a
wall-clock bound and the bound is set by the largest shard.

**The shard index is deliberately not in ``run_id``.**
:func:`~harness.runner.run_id_for` is a function of the seed, the case and the
arm, and adding the shard would mean a case re-run alone produced a *different*
identifier from the same case run inside a shard — which is exactly the join
the merge step needs in order to notice a case appearing twice. The shard
appears in the *suite* id, because a shard is a different plan, and in the
filename, because two shards must not overwrite each other.

**No cross-shard state.** Each shard is its own process with its own world, its
own SQLite files and its own output. Nothing is shared, so nothing has to be
merged except the lines — and the merge step is what notices a shard that never
arrived.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence, TypeVar

__all__ = ["ShardError", "Shard", "parse_shard", "slice_for", "shard_of"]

T = TypeVar("T")


class ShardError(ValueError):
    """A shard specification that would silently run the wrong cases."""


@dataclass(frozen=True)
class Shard:
    """``index`` of ``count``, zero-based internally, one-based on the wire."""

    index: int
    count: int

    def __post_init__(self) -> None:
        if self.count < 1:
            raise ShardError(f"a suite cannot be split into {self.count} shards")
        if not 0 <= self.index < self.count:
            raise ShardError(
                f"shard {self.index + 1} of {self.count} does not exist; "
                f"shards are 1..{self.count}"
            )

    @property
    def label(self) -> str:
        return f"{self.index + 1}of{self.count}"

    def __str__(self) -> str:  # pragma: no cover - convenience
        return f"{self.index + 1}/{self.count}"


def parse_shard(text: str) -> Shard:
    """``"3/8"`` -> shard 3 of 8. One-based, because that is how people say it.

    Refuses ``0/8`` rather than treating it as the first shard: a runner that
    accepted both conventions would silently run shard 1 twice and shard 8
    never, and the merge would report seven shards where eight were asked for.
    """
    if "/" not in text:
        raise ShardError(f"--shard wants i/n, e.g. 3/8; got {text!r}")
    left, _, right = text.partition("/")
    try:
        index, count = int(left), int(right)
    except ValueError:
        raise ShardError(f"--shard wants two integers, e.g. 3/8; got {text!r}") from None
    if index < 1:
        raise ShardError(
            f"shards are numbered from 1; got {text!r}. Zero-based here would "
            "quietly run the first shard twice and the last one never."
        )
    return Shard(index=index - 1, count=count)


def slice_for(items: Sequence[T], shard: Shard) -> list[T]:
    """This shard's contiguous block of ``items``, in the order given.

    The caller passes the *frozen corpus order* — ``select`` sorts by case id —
    so this is a pure function of the corpus and the split.
    """
    total = len(items)
    base, remainder = divmod(total, shard.count)
    start = shard.index * base + min(shard.index, remainder)
    size = base + (1 if shard.index < remainder else 0)
    return list(items[start : start + size])


def shard_of(position: int, total: int, count: int) -> int:
    """Which shard the item at ``position`` lands in. The inverse of :func:`slice_for`."""
    if count < 1:
        raise ShardError(f"a suite cannot be split into {count} shards")
    base, remainder = divmod(total, count)
    boundary = remainder * (base + 1)
    if position < boundary:
        return position // (base + 1)
    return remainder + (position - boundary) // base if base else remainder
