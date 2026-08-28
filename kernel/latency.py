"""The one wall-clock read in the kernel, isolated so it is visible in a diff.

``tests/test_determinism.py`` bans wall-clock calls under ``kernel/`` —
including ``time.perf_counter``, which is a duration rather than a date but
would break D-01 just as surely if it reached a hashed record. SPEC.md §07's
decision response nonetheless carries ``latency_us``, and a measured latency has
to come from somewhere real.

So the exemption is one module, one function, and a rule the chain enforces
rather than the docstring:

**A measured duration may enter a response. It may never enter an audit
payload.** Two runs of one seed produce byte-identical chains, and a microsecond
count is the fastest way to lose that. The check is not left to discipline —
``tests/test_m3_gate.py`` re-exports every chain entry from two runs of the same
seed and compares them byte for byte, which fails the moment a duration leaks
into one.

``perf_counter_ns`` rather than ``time.time``: this measures an interval, and an
interval taken from a clock that can be stepped by NTP is not an interval.
"""

from __future__ import annotations

import time

__all__ = ["Stopwatch"]


class Stopwatch:
    """Elapsed microseconds since construction. Response-only."""

    def __init__(self) -> None:
        self._started_ns = time.perf_counter_ns()

    def micros(self) -> int:
        return (time.perf_counter_ns() - self._started_ns) // 1000
