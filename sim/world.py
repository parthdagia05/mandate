"""One seeded world: clock, RNG, event log, faults, scheduler, PSP, merchant.

Assembled in one place because these six share exactly one seed and one clock,
and a run that built two of anything would be a run whose determinism depended
on nobody making that mistake. ``World.reset(seed)`` rebuilds all of it, which
is what ``POST /control/reset`` calls.

The clock lives here rather than in ``sim/`` having its own: SPEC.md §15 says
the kernel owns the clock, and a simulator with a second clock would be a second
authority on what time it is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from kernel.clock import DEFAULT_EPOCH, Clock
from kernel.rng import RunRandom
from sim.eventlog import EventLog, SimActor, SimEvent
from sim.faults import Fault, FaultInjector
from sim.merchants.base import Injection, Merchant
from sim.merchants.shopkart import ShopKart
from sim.psp.adapter import SimPSP
from sim.webhooks import WebhookScheduler

__all__ = ["World", "MERCHANTS"]

#: Storefronts a task can name. Closed, for the same reason the injection
#: points are: a task naming a merchant that does not exist should fail to
#: load, not run against a default one.
MERCHANTS: dict[str, type[Merchant]] = {"shopkart": ShopKart}


@dataclass
class World:
    seed: str = "0"
    epoch: datetime = DEFAULT_EPOCH
    merchant_name: str = "shopkart"

    clock: Clock = field(init=False)
    rng: RunRandom = field(init=False)
    log: EventLog = field(init=False)
    faults: FaultInjector = field(init=False)
    scheduler: WebhookScheduler = field(init=False)
    psp: SimPSP = field(init=False)
    merchant: Merchant = field(init=False)

    def __post_init__(self) -> None:
        self._build()

    def _build(self) -> None:
        self.clock = Clock(self.epoch)
        self.rng = RunRandom(self.seed)
        self.log = EventLog(self.clock)
        self.faults = FaultInjector()
        self.scheduler = WebhookScheduler(self.clock, self.rng, self.log, self.faults)
        self.psp = SimPSP(
            clock=self.clock,
            rng=self.rng,
            log=self.log,
            scheduler=self.scheduler,
            faults=self.faults,
        )
        merchant_cls = MERCHANTS.get(self.merchant_name)
        if merchant_cls is None:
            raise KeyError(
                f"no merchant {self.merchant_name!r}; known: {sorted(MERCHANTS)}"
            )
        self.merchant = merchant_cls(log=self.log)

    # -- the barrier ------------------------------------------------------

    def advance(self, seconds: int) -> dict[str, object]:
        """Move the clock and settle the world before returning.

        This is the synchronous barrier SPEC.md §15 requires, and the reason
        D-01 holds across three processes. It delivers every webhook now due,
        then every webhook those deliveries made due, and only then returns.
        Nothing in this project is on a timer; if it were, two runs of the same
        seed would differ by whatever the OS scheduler felt like.

        Recovery scans hook in here in M4. The barrier's contract — settle
        everything, then return — is fixed now so that adding them is not a
        change to the determinism argument.
        """
        self.clock.advance(seconds)
        self.log.append(
            SimActor.SIM,
            SimEvent.CLOCK_ADVANCED,
            {"by_s": seconds, "now": self.clock.now_rfc3339()},
        )
        delivered = self.scheduler.drain_due()
        return {
            "now": self.clock.now_rfc3339(),
            "delivered": [
                {"event_id": e.event_id, "kind": e.kind} for e in delivered
            ],
            "log_head": self.log.head(),
        }

    # -- control ----------------------------------------------------------

    def arm(self, fault: Fault, **kwargs: object) -> dict[str, object]:
        armed = self.faults.arm(
            fault, now_s=int(self.clock.now().timestamp()), **kwargs  # type: ignore[arg-type]
        )
        self.log.append(
            SimActor.SIM,
            SimEvent.FAULT_ARMED,
            {
                "fault": str(armed.fault),
                "site": str(armed.site),
                "remaining": armed.remaining,
                "duration_s": armed.duration_s,
                "target": armed.target,
            },
        )
        return {"armed": self.faults.describe()}

    def inject(self, injection: Injection) -> None:
        self.merchant.inject(injection)

    def reset(self, seed: str | None = None) -> dict[str, object]:
        """Fresh seeded state. Everything, including the log and the clock."""
        if seed is not None:
            self.seed = seed
        self._build()
        return {"seed": self.seed, "now": self.clock.now_rfc3339()}
