"""The clock, owned by the kernel.

The agent never supplies time. An agent-supplied clock would defeat check 1's
expiry test by simply lying about the hour, so ``client_ts`` on a
PaymentRequest is advisory and is never read for expiry. Time moves only when
the control port says so, and it moves at a synchronous barrier: an advance
delivers every webhook now due and runs any recovery scan now due before it
returns (SPEC.md §15).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

__all__ = ["Clock", "RFC3339_PATTERN", "to_rfc3339", "from_rfc3339", "DEFAULT_EPOCH"]

#: RFC 3339, UTC, second precision, ``Z`` suffix. Anything else is rejected at
#: the schema boundary, because a timestamp that can be written two ways is a
#: timestamp that can be canonicalised two ways.
RFC3339_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"

#: Every run starts here unless told otherwise, so two runs of the same seed
#: produce the same ULIDs and the same timestamps.
DEFAULT_EPOCH = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def to_rfc3339(moment: datetime) -> str:
    """Render an aware datetime in the one accepted textual form."""
    if moment.tzinfo is None:
        raise ValueError("naive datetime; the kernel only handles aware UTC")
    moment = moment.astimezone(timezone.utc).replace(microsecond=0)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def from_rfc3339(text: str) -> datetime:
    """Parse the one accepted textual form back to an aware datetime."""
    import re

    if not re.match(RFC3339_PATTERN, text):
        raise ValueError(f"not RFC 3339 UTC second-precision: {text!r}")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


class Clock:
    """A clock that only moves when it is pushed.

    Nothing in the kernel reads a wall clock; ``tests/test_determinism.py``
    lints for it. The only way to reach this class from outside the process is
    the loopback control port, which the agent process is not given.
    """

    def __init__(self, epoch: datetime = DEFAULT_EPOCH) -> None:
        if epoch.tzinfo is None:
            raise ValueError("naive epoch; the kernel only handles aware UTC")
        self._now = epoch.astimezone(timezone.utc).replace(microsecond=0)

    def now(self) -> datetime:
        return self._now

    def now_rfc3339(self) -> str:
        return to_rfc3339(self._now)

    def now_ms(self) -> int:
        """Milliseconds since the Unix epoch — the ULID timestamp field."""
        return int(self._now.timestamp() * 1000)

    def advance(self, seconds: int) -> datetime:
        """Move forward. Backwards is not a direction a clock travels."""
        if not isinstance(seconds, int) or isinstance(seconds, bool):
            raise TypeError("advance takes whole seconds")
        if seconds < 0:
            raise ValueError("the clock does not run backwards")
        self._now = self._now + timedelta(seconds=seconds)
        return self._now
