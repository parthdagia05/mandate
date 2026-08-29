"""The fault injector, SPEC.md §09.

This is the argument for the simulator being the primary path rather than a
convenience. No real PSP can be asked to die between an idempotency reserve and
its commit, or to redeliver a webhook with a fresh event id at a chosen moment.
A6 and the whole failure suite are unreachable without these six.

Every fault is **armed, then fires at a named site**. Nothing here is
probabilistic and nothing is on a timer: a fault fires when the code reaches the
site it was armed for, so the same seed and the same arming produce the same
run. A fault that fired at random would make the failure suite a coin toss
dressed as a test.

Arming is one-shot by default. ``crash_after_reserve`` that fired on every
capture forever would make the recovery path untestable, because the recovery
itself captures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

__all__ = [
    "Fault",
    "FaultSite",
    "CrashWindow",
    "CRASH_WINDOWS",
    "crash_window",
    "ArmedFault",
    "FaultInjector",
    "KernelCrashed",
    "PSPTimeout",
    "StoreUnavailableFault",
]


class Fault(StrEnum):
    """Closed. A fault name that can be invented is a result row that can be."""

    CRASH_AFTER_RESERVE = "crash_after_reserve"
    PSP_TIMEOUT = "psp_timeout"
    STORE_UNAVAILABLE = "store_unavailable"
    DUPLICATE_WEBHOOK = "duplicate_webhook"
    REORDER_WEBHOOK = "reorder_webhook"
    PARTITION = "partition"


class FaultSite(StrEnum):
    """Where in the code a fault can fire.

    Named sites rather than "somewhere in capture" so a test can assert the
    fault fired at the point it claims to test, not merely that something
    failed.
    """

    AFTER_RESERVE = "kernel.idempotency.after_reserve"
    PSP_CALL = "psp.call"
    STORE_READ = "kernel.store.read"
    STORE_WRITE = "kernel.store.write"
    WEBHOOK_EMIT = "sim.webhook.emit"


class CrashWindow(StrEnum):
    """The two gaps ``crash_after_reserve`` can open, both between the
    idempotency reserve and its commit — which is the whole of what the fault's
    name claims.

    They are not interchangeable and the difference is the point:

    ``after_reserve``
        Before the rail is touched. The kernel dies holding a key with nothing
        behind it. Recovery polls, finds no debit, and **releases** the key.
        Zero debits, and the run can be retried.
    ``after_psp_call``
        After the rail answered and before the ledger heard about it. This is
        SPEC.md §06's "crash mid-capture" row — ``captured`` at the PSP only,
        key still ``in_flight`` — and recovery **commits** the debit that
        already exists. Exactly one debit, which is the property A6 turns on.

    A single fault with two windows rather than two faults, because "the kernel
    died between reserve and commit" is one failure; where in that window it
    landed is what the failure suite varies.
    """

    AFTER_RESERVE = "after_reserve"
    AFTER_PSP_CALL = "after_psp_call"


#: ``<action>.<window>`` — the ``target`` a ``crash_after_reserve`` may name.
#: Enumerated rather than parsed so a typo is a refusal at arming time. A crash
#: armed at a site that does not exist would never fire, and a fault that never
#: fires produces a clean run that reads as a defended one.
CRASH_WINDOWS: frozenset[str] = frozenset(
    f"{action}.{window}"
    for action in ("authorize", "capture", "refund")
    for window in CrashWindow
)


def crash_window(action: str, window: CrashWindow | str) -> str:
    """The ``target`` string naming one window of one action."""
    return f"{action}.{window}"


#: Which site each fault fires at. Kept as data so ``mk fault --list`` and the
#: control port describe the same thing the code does.
FAULT_SITES: dict[Fault, FaultSite] = {
    Fault.CRASH_AFTER_RESERVE: FaultSite.AFTER_RESERVE,
    Fault.PSP_TIMEOUT: FaultSite.PSP_CALL,
    Fault.STORE_UNAVAILABLE: FaultSite.STORE_READ,
    Fault.DUPLICATE_WEBHOOK: FaultSite.WEBHOOK_EMIT,
    Fault.REORDER_WEBHOOK: FaultSite.WEBHOOK_EMIT,
    Fault.PARTITION: FaultSite.PSP_CALL,
}


class KernelCrashed(BaseException):
    """The kernel process died mid-request.

    Derived from ``BaseException``, not ``Exception``, on purpose: a crash that
    a stray ``except Exception`` could swallow would be a simulated crash the
    system under test gets to clean up after, which is not a crash. The harness
    catches this one class explicitly and restarts.
    """

    def __init__(self, site: FaultSite) -> None:
        super().__init__(f"simulated kernel crash at {site}")
        self.site = site


class PSPTimeout(RuntimeError):
    """The PSP accepted the call and will never answer.

    Not a failure: the outcome is *unknown*, which is a different position and
    the reason the recovery path polls rather than retries.
    """


class StoreUnavailableFault(RuntimeError):
    """A named store cannot be read or written. Every caller of this denies."""


@dataclass
class ArmedFault:
    fault: Fault
    site: FaultSite
    #: How many times it may still fire. ``None`` means until disarmed.
    remaining: int | None = 1
    #: ``partition`` only: how many clock-seconds responses stay dropped.
    duration_s: int = 0
    #: What the fault is scoped to, and it means something different per fault.
    #: ``store_unavailable`` — which store, so one bad store does not make every
    #: store bad and hide which one the check actually needed.
    #: ``crash_after_reserve`` — which ``<action>.<window>`` to die in; see
    #: :class:`CrashWindow`. ``None`` means the first site reached.
    target: str | None = None
    armed_at_s: int = 0


@dataclass
class FaultInjector:
    """Holds what is armed and answers "does a fault fire here, now?"."""

    armed: dict[Fault, ArmedFault] = field(default_factory=dict)

    def arm(
        self,
        fault: Fault,
        *,
        count: int | None = 1,
        duration_s: int = 0,
        target: str | None = None,
        now_s: int = 0,
    ) -> ArmedFault:
        if (
            fault is Fault.CRASH_AFTER_RESERVE
            and target is not None
            and target not in CRASH_WINDOWS
        ):
            raise ValueError(
                f"{target!r} is not a crash window; known: "
                f"{sorted(CRASH_WINDOWS)}. A crash armed at a site that does "
                "not exist never fires, and a run with no crash in it looks "
                "exactly like a run that survived one."
            )
        entry = ArmedFault(
            fault=fault,
            site=FAULT_SITES[fault],
            remaining=count,
            duration_s=duration_s,
            target=target,
            armed_at_s=now_s,
        )
        self.armed[fault] = entry
        return entry

    def disarm(self, fault: Fault) -> None:
        self.armed.pop(fault, None)

    def clear(self) -> None:
        self.armed.clear()

    def is_armed(self, fault: Fault) -> bool:
        return fault in self.armed

    def fires(self, fault: Fault, *, target: str | None = None) -> bool:
        """Consume one firing of ``fault`` if it is armed for ``target``.

        Consuming on the query rather than on a separate call means a caller
        cannot ask "will it fire?" and then not fire it, which would leave the
        injector's count disagreeing with what actually happened.
        """
        entry = self.armed.get(fault)
        if entry is None:
            return False
        if entry.target is not None and entry.target != target:
            return False
        if entry.remaining is not None:
            entry.remaining -= 1
            if entry.remaining <= 0:
                del self.armed[fault]
        return True

    def partitioned_until_s(self) -> int | None:
        """The clock-second a ``partition`` stops dropping responses, if armed."""
        entry = self.armed.get(Fault.PARTITION)
        if entry is None:
            return None
        return entry.armed_at_s + entry.duration_s

    def describe(self) -> list[dict[str, object]]:
        return [
            {
                "fault": str(e.fault),
                "site": str(e.site),
                "remaining": e.remaining,
                "duration_s": e.duration_s,
                "target": e.target,
            }
            for e in sorted(self.armed.values(), key=lambda a: a.fault.value)
        ]
