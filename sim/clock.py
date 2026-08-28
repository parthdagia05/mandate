"""There is deliberately no simulator clock.

SPEC.md §09 lists this file, and SPEC.md §15 says the clock is owned by the
kernel. Both are true, and the resolution is that the simulator has no clock of
its own: it holds a reference to :class:`kernel.clock.Clock` and moves it only
through the control port's barrier.

A second clock would be a second authority on what time it is, and the two would
disagree the first time one of them was advanced and the other was not. Mandate
expiry is judged against the kernel's clock; a simulator that could drift from
it would be a simulator that could expire a mandate the kernel still considers
live, and check 1's result would depend on which clock the test happened to
read.

The re-exports below exist so that ``from sim.clock import Clock`` reads
naturally in simulator code without implying a separate implementation.
"""

from __future__ import annotations

from kernel.clock import DEFAULT_EPOCH, Clock, from_rfc3339, to_rfc3339

__all__ = ["Clock", "DEFAULT_EPOCH", "to_rfc3339", "from_rfc3339", "advance_barrier"]


def advance_barrier(world, seconds: int) -> dict[str, object]:
    """Move time forward and settle the world before returning.

    Thin by design — :meth:`sim.world.World.advance` is the implementation, and
    :class:`sim.control.ControlPlane` is the door. This name exists because
    "advance the clock" and "advance the clock *and settle*" are different
    operations, and only the second one is ever correct here.
    """
    return world.advance(seconds)
