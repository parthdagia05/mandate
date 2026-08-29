"""The webhook scheduler. Deterministic by construction, SPEC.md §15.

**Nothing here is on a timer, ever.** An event is queued with the clock-second
it becomes due; it is delivered when the control port advances the clock past
that second, inside the same synchronous barrier that returns to the caller. So
ordering is a function of the seed and the schedule and never of scheduler luck,
which is what lets D-01 hold across three processes rather than just within one.

The queue is drained in ``(due_at, sequence)`` order. The sequence number is the
tie-break, and it exists because two events due in the same clock-second are
otherwise ordered by whatever the sort happens to do — stable today, and a
silent reordering the first time the queue type changes.

Delivery can re-enter: a handler may itself queue an event due at the current
second. The drain loop therefore re-checks the queue after every delivery
instead of taking a snapshot, and bounds the number of rounds so a handler that
queues itself fails loudly rather than hanging the barrier.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Any, Callable

from kernel.clock import Clock
from kernel.rng import RunRandom
from sim.eventlog import EventLog, SimActor, SimEvent
from sim.faults import Fault, FaultInjector

__all__ = ["WebhookEvent", "WebhookScheduler", "MAX_DRAIN_ROUNDS"]

#: A handler that keeps queueing work due now is a bug in the handler, not a
#: reason to spin forever inside a barrier that is supposed to return.
MAX_DRAIN_ROUNDS = 1000


@dataclass(order=True)
class WebhookEvent:
    """One PSP callback, waiting for the clock to reach it."""

    due_at_s: int
    sequence: int
    event_id: str = field(compare=False)
    kind: str = field(compare=False)
    payload: dict[str, Any] = field(compare=False, default_factory=dict)


class WebhookScheduler:
    """Queue in, drain at the barrier.

    The scheduler owns two of the six faults, because both are about *delivery*
    rather than about the payment:

    ``duplicate_webhook``
        Redeliver the event with a **fresh** event id. Deduping on the event id
        would call this a new event, which is why the kernel dedups on the
        business key instead. The fresh id is the whole point of the fault.
    ``reorder_webhook``
        Hold the next event back one second so a later one overtakes it —
        ``authorized`` arriving after ``captured``. The state machine refuses
        it; nothing here decides that.

    Delivery fans out to every subscriber for a kind, in registration order.
    That is what lets the kernel ingest the same callback the PSP just applied,
    without the scheduler knowing there is a kernel.
    """

    def __init__(
        self,
        clock: Clock,
        rng: RunRandom,
        log: EventLog,
        faults: FaultInjector | None = None,
    ) -> None:
        self._clock = clock
        self._rng = rng
        self._log = log
        self._faults = faults or FaultInjector()
        self._queue: list[WebhookEvent] = []
        self._sequence = 0
        #: kind -> handlers, in registration order. A *list*, because in a
        #: kernel run two parties want the same callback: the PSP, which owns
        #: the payment's state, and the kernel, which reconciles its ledger
        #: against it. Registration order is delivery order and the PSP
        #: registers first, so the kernel always sees a payment the rail has
        #: already moved rather than one it is about to.
        self._handlers: dict[str, list[Callable[[WebhookEvent], None]]] = {}
        self._delivered: list[WebhookEvent] = []

    # -- wiring -----------------------------------------------------------

    def on(self, kind: str, handler: Callable[[WebhookEvent], None]) -> None:
        """Subscribe to one webhook kind. Subscribers are additive."""
        self._handlers.setdefault(kind, []).append(handler)

    @property
    def delivered(self) -> list[WebhookEvent]:
        return list(self._delivered)

    def pending(self) -> list[WebhookEvent]:
        return sorted(self._queue)

    # -- queueing ---------------------------------------------------------

    def _new_event_id(self) -> str:
        """Seeded, so a redelivery's *fresh* id is still a reproducible one."""
        return "evt_" + self._rng.bytes("webhook:event_id", 6).hex()

    def _now_s(self) -> int:
        return int(self._clock.now().timestamp())

    def schedule(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        delay_s: int = 1,
        event_id: str | None = None,
    ) -> WebhookEvent:
        """Queue one callback ``delay_s`` clock-seconds from now.

        ``delay_s=0`` is legal and means "due at this barrier": a webhook the
        PSP emits as part of the call that caused it. It still goes through the
        queue rather than being called inline, so the ordering rule has no
        exceptions to reason about.
        """
        if delay_s < 0:
            raise ValueError("a webhook cannot be due before it was scheduled")

        event = WebhookEvent(
            due_at_s=self._now_s() + delay_s,
            sequence=self._sequence,
            event_id=event_id or self._new_event_id(),
            kind=kind,
            payload=payload,
        )
        self._sequence += 1

        if self._faults.fires(Fault.REORDER_WEBHOOK):
            # Hold this one back one second and let whatever comes next
            # overtake it. authorized-after-captured is exactly this.
            event.due_at_s += 1
            self._log.append(
                SimActor.SIM,
                SimEvent.FAULT_FIRED,
                {
                    "fault": str(Fault.REORDER_WEBHOOK),
                    "event_id": event.event_id,
                    "kind": kind,
                    "held_back_s": 1,
                },
            )

        heapq.heappush(self._queue, event)
        self._log.append(
            SimActor.PSP,
            SimEvent.WEBHOOK_SCHEDULED,
            {"event_id": event.event_id, "kind": kind, "due_at_s": event.due_at_s},
        )

        if self._faults.fires(Fault.DUPLICATE_WEBHOOK):
            twin = WebhookEvent(
                due_at_s=event.due_at_s,
                sequence=self._sequence,
                # Fresh id. At-least-once delivery does not promise a stable
                # one, so dedup cannot be built on it.
                event_id=self._new_event_id(),
                kind=kind,
                payload=dict(payload),
            )
            self._sequence += 1
            heapq.heappush(self._queue, twin)
            self._log.append(
                SimActor.SIM,
                SimEvent.FAULT_FIRED,
                {
                    "fault": str(Fault.DUPLICATE_WEBHOOK),
                    "original_event_id": event.event_id,
                    "duplicate_event_id": twin.event_id,
                    "kind": kind,
                },
            )

        return event

    # -- draining ---------------------------------------------------------

    def drain_due(self) -> list[WebhookEvent]:
        """Deliver everything due at or before the current clock-second.

        Called only from the control port's barrier. Returns what it delivered,
        in delivery order, so a test can assert the order rather than the
        outcome that order happened to produce.
        """
        now_s = self._now_s()
        delivered: list[WebhookEvent] = []

        for _ in range(MAX_DRAIN_ROUNDS):
            if not self._queue or self._queue[0].due_at_s > now_s:
                break
            event = heapq.heappop(self._queue)
            self._log.append(
                SimActor.PSP,
                SimEvent.WEBHOOK_DELIVERED,
                {
                    "event_id": event.event_id,
                    "kind": event.kind,
                    "due_at_s": event.due_at_s,
                    "payload": event.payload,
                },
            )
            for handler in self._handlers.get(event.kind, ()):
                handler(event)
            self._delivered.append(event)
            delivered.append(event)
        else:
            raise RuntimeError(
                f"webhook drain did not settle in {MAX_DRAIN_ROUNDS} rounds; "
                "a handler is queueing work due at the same second"
            )

        return delivered

    def reset(self) -> None:
        self._queue.clear()
        self._delivered.clear()
        self._sequence = 0
