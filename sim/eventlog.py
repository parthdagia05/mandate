"""The simulator's own hash-chained record of what the world did.

Deliberately *not* the kernel's audit chain. That chain records decisions, and
in the undefended configuration there is no kernel and therefore no decisions —
only money moving. Borrowing ``kernel.audit`` for an undefended run would let
that run quietly inherit the kernel's credibility, which is exactly the thing
M2 exists to measure the absence of.

What is shared is the hash rule (:func:`kernel.audit.chain.compute_entry_hash`)
and the export format, so ``mk verify-chain`` and the standalone verifier read
a simulator log without knowing it is one. The verifier checks linkage, not
vocabulary — which is why the two logs can keep separate closed enums and still
have one verifier.

Two runs of the same seed produce byte-identical logs: every timestamp comes
from the kernel clock, which only moves at a control-port barrier, and every
identifier comes from the run seed.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Iterator

from kernel.audit.chain import GENESIS_HASH, compute_entry_hash
from kernel.canonical import jcs
from kernel.clock import Clock

__all__ = ["SimActor", "SimEvent", "EventLog"]


class SimActor(StrEnum):
    """Who did the thing. Closed, for the same reason the kernel's is."""

    PSP = "psp"
    MERCHANT = "merchant"
    AGENT = "agent"
    SIM = "sim"


class SimEvent(StrEnum):
    """Every observable thing the simulated world can do.

    ``merchant.served`` carries the injection point that produced the content,
    which is what lets a case say *where* a payload landed rather than merely
    that one did.
    """

    ORDER_CREATED = "psp.order_created"
    AUTHORIZED = "psp.authorized"
    CAPTURED = "psp.captured"
    MANDATE_CREATED = "psp.mandate_created"
    REFUND_CREATED = "psp.refund_created"
    REFUND_PROCESSED = "psp.refund_processed"
    POLLED = "psp.polled"
    TRANSITION_REFUSED = "psp.transition_refused"

    WEBHOOK_SCHEDULED = "webhook.scheduled"
    WEBHOOK_DELIVERED = "webhook.delivered"

    MERCHANT_SERVED = "merchant.served"
    AGENT_TOOL_CALL = "agent.tool_call"

    FAULT_ARMED = "fault.armed"
    FAULT_FIRED = "fault.fired"
    CLOCK_ADVANCED = "clock.advanced"


class EventLog:
    """Append-only, in memory, hash-linked.

    In memory rather than SQLite because nothing here is the record of record:
    the kernel's chain is fsynced because losing a decision is a correctness
    bug, whereas losing the simulator's log only loses a run that can be
    reproduced from its seed.
    """

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._entries: list[dict[str, Any]] = []

    def __len__(self) -> int:
        return len(self._entries)

    def head(self) -> str:
        if not self._entries:
            return GENESIS_HASH
        return self._entries[-1]["entry_hash"]

    def append(
        self, actor: SimActor, event: SimEvent, payload: dict[str, Any]
    ) -> dict[str, Any]:
        seq = len(self._entries)
        ts = self._clock.now_rfc3339()
        prev_hash = self.head()
        entry = {
            "seq": seq,
            "ts": ts,
            "actor": str(actor),
            "action": str(event),
            "payload": payload,
            "prev_hash": prev_hash,
            "entry_hash": compute_entry_hash(
                seq, ts, str(actor), str(event), payload, prev_hash
            ),
        }
        self._entries.append(entry)
        return entry

    def read(self) -> Iterator[dict[str, Any]]:
        return iter(list(self._entries))

    def of(self, *events: SimEvent) -> list[dict[str, Any]]:
        """Every entry whose action is one of ``events``. The oracles read this."""
        wanted = {str(e) for e in events}
        return [e for e in self._entries if e["action"] in wanted]

    def export_jsonl(self) -> str:
        """The format ``scripts/verify_chain.py`` consumes, canonically serialised."""
        return "".join(jcs(entry) + "\n" for entry in self._entries)
