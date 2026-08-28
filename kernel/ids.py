"""ULIDs with a type prefix, minted from the clock and the run seed.

A ULID is 48 bits of millisecond timestamp followed by 80 bits of randomness,
rendered in Crockford base32. Here the timestamp comes from the kernel clock
and the randomness from the run's seeded stream, so identifiers are stable
across runs of the same seed while still sorting by creation order.
"""

from __future__ import annotations

import re

from kernel.clock import Clock
from kernel.rng import RunRandom

__all__ = ["ULID_ALPHABET", "ULID_PATTERN", "IdFactory", "id_pattern", "encode_ulid"]

#: Crockford base32: no I, L, O or U, so a transcribed identifier cannot be
#: misread as a different valid one.
ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ULID_PATTERN = "[0-9A-HJKMNP-TV-Z]{26}"

#: The type prefixes SPEC.md §05 fixes for each entity.
PREFIXES = {
    "intent": "im",
    "cart": "cm",
    "payment": "pay",
    "refund": "rfn",
}


def id_pattern(prefix: str) -> str:
    """The anchored regex a typed identifier field validates against."""
    return f"^{prefix}_{ULID_PATTERN}$"


def encode_ulid(timestamp_ms: int, randomness: bytes) -> str:
    """Render the 128-bit ULID value as 26 Crockford base32 characters."""
    if not 0 <= timestamp_ms < 2**48:
        raise ValueError("ULID timestamp does not fit in 48 bits")
    if len(randomness) != 10:
        raise ValueError("ULID randomness is exactly 80 bits")

    value = (timestamp_ms << 80) | int.from_bytes(randomness, "big")
    out = []
    for shift in range(125, -1, -5):
        out.append(ULID_ALPHABET[(value >> shift) & 0x1F])
    return "".join(out)


class IdFactory:
    """Mints every identifier a run needs, deterministically."""

    def __init__(self, clock: Clock, rng: RunRandom) -> None:
        self._clock = clock
        self._rng = rng

    def new(self, kind: str) -> str:
        prefix = PREFIXES.get(kind)
        if prefix is None:
            raise KeyError(f"no id prefix for {kind!r}")
        ulid = encode_ulid(self._clock.now_ms(), self._rng.bytes(f"ulid:{kind}", 10))
        return f"{prefix}_{ulid}"

    def intent_id(self) -> str:
        return self.new("intent")

    def cart_id(self) -> str:
        return self.new("cart")

    def payment_id(self) -> str:
        return self.new("payment")

    def refund_id(self) -> str:
        return self.new("refund")

    def nonce(self) -> str:
        """128 bits, base64url, unpadded — single-use, store-enforced."""
        import base64

        raw = self._rng.bytes("nonce", 16)
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
