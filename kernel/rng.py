"""One seed, everything downstream.

Every ULID, nonce and idempotency key in a run derives from a single run seed,
so REQ-3 ("same seed and same inputs produce byte-identical output") holds
without anyone having to remember to thread a seed through. Nothing in the
kernel calls ``random`` or ``secrets`` or ``os.urandom`` directly;
``tests/test_determinism.py`` lints for that too.
"""

from __future__ import annotations

import hashlib
import random

__all__ = ["RunRandom", "DEFAULT_SEED"]

DEFAULT_SEED = "mandate-kernel-run-seed-0"


class RunRandom:
    """A named, seeded byte source.

    Streams are namespaced: ``rng.stream("nonce")`` and ``rng.stream("ulid")``
    advance independently, so adding a call in one place does not shift every
    identifier in the run and churn the fixtures.
    """

    def __init__(self, seed: str = DEFAULT_SEED) -> None:
        self._seed = seed
        self._streams: dict[str, random.Random] = {}

    @property
    def seed(self) -> str:
        return self._seed

    def stream(self, name: str) -> random.Random:
        existing = self._streams.get(name)
        if existing is None:
            derived = hashlib.sha256(
                f"{self._seed}\x1f{name}".encode("utf-8")
            ).digest()
            existing = random.Random(int.from_bytes(derived, "big"))
            self._streams[name] = existing
        return existing

    def bytes(self, name: str, count: int) -> bytes:
        return self.stream(name).randbytes(count)

    def reset(self) -> None:
        """Rewind every stream to the start of the run."""
        self._streams.clear()
