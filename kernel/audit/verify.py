"""In-process chain verification, behind ``GET /v1/audit/verify``.

This is the convenient path. The load-bearing one is
``scripts/verify_chain.py``, which shares no code with the kernel at all —
a verifier that imports the thing it is checking proves less than one that
does not (REQ-9).
"""

from __future__ import annotations

from typing import Iterable

from kernel.audit.chain import GENESIS_HASH, ChainBroken, compute_entry_hash
from kernel.models import AuditEntry

__all__ = ["verify_entries"]


def verify_entries(entries: Iterable[AuditEntry]) -> tuple[int, str]:
    """Return ``(count, head_hash)``, or raise :class:`ChainBroken`."""
    expected_seq = 0
    prev_hash = GENESIS_HASH
    count = 0

    for entry in entries:
        if entry.seq != expected_seq:
            raise ChainBroken(entry.seq, f"expected seq {expected_seq}")
        if entry.prev_hash != prev_hash:
            raise ChainBroken(entry.seq, "prev_hash does not match the entry before it")
        recomputed = compute_entry_hash(
            entry.seq,
            entry.ts,
            str(entry.actor),
            str(entry.action),
            entry.payload,
            entry.prev_hash,
        )
        if recomputed != entry.entry_hash:
            raise ChainBroken(entry.seq, "entry_hash does not match its contents")
        prev_hash = entry.entry_hash
        expected_seq += 1
        count += 1

    return count, prev_hash
