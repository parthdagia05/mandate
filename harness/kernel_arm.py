"""Standing the kernel up for one run, and taking it down again.

The kernel arm is deliberately assembled *around* an unchanged M2 run: the same
seeded world, the same merchant, the same payload at the same injection point,
the same planner taking the same five steps. What this module adds is a
:class:`~kernel.service.KernelService` between the agent's money tools and the
rail, and nothing else. If it added anything else the difference between the two
arms would stop being attributable to the kernel.

Three wirings here are load-bearing:

**The store guard.** ``kernel/`` knows nothing about the simulator, so the
fault injector reaches it as a callable that raises. That keeps REQ-5 testable —
a named store can be made unavailable at a chosen moment, which no real disk
will do on request — without the enforcement path importing the thing that is
supposed to be attacking it.

**The clock.** One clock, the world's, which is the kernel's. Two clocks would
be two authorities on whether a mandate has expired.

**The database is a real file.** Not ``:memory:``. ``PRAGMA synchronous=FULL``
is the whole of check 9's "appended and fsynced before the response returns",
and an in-memory database would let that claim pass a test it cannot pass on
disk.

A run that ends with a chain that does not verify is **discarded, not
reported**. :meth:`KernelArm.verify` is what decides that, and the run record
carries the reason.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent.credentials import AgentCredentials
from harness.corpus import Task
from kernel.audit.chain import ChainBroken
from kernel.audit.verify import verify_entries
from kernel.service import KernelService
from kernel.stores.db import StoreUnavailable, connect
from sim.faults import Fault, KernelCrashed
from sim.world import World

__all__ = ["REPO_ROOT", "DEFAULT_CHAIN_PATH", "TaskHasNoMandates", "KernelArm"]

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Where ``mk run --config kernel`` leaves the chain so ``mk explain <seq>``
#: can be typed with no other argument. The milestone's ``Prove it`` block says
#: ``mk explain <audit-seq>``, and a step that needs a path pasted in is a step
#: that does not get run at a demo.
DEFAULT_CHAIN_PATH = REPO_ROOT / "runs" / "latest.chain.jsonl"


class TaskHasNoMandates(ValueError):
    """This task ships no signed mandates, so the kernel arm cannot run it.

    A hard error rather than a run with a generated mandate. Signing at run
    time would mean the kernel was checking a signature the harness had just
    minted for it, which tests nothing and would quietly pass.
    """


@dataclass
class KernelArm:
    """One kernel, its stores, and the mandates the task ships."""

    task: Task
    world: World
    client_ref: str

    service: KernelService = field(init=False)
    credentials: AgentCredentials = field(init=False)
    intent: dict[str, Any] = field(init=False)
    confirmed_cart: dict[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        mandates = self.task.raw.get("mandates")
        if not mandates:
            raise TaskHasNoMandates(
                f"task {self.task.task_id!r} ships no signed mandates. The "
                "kernel arm verifies a signature the user made offline at "
                "corpus-freeze time; minting one here would have the kernel "
                "check the harness's own arithmetic. Add the fixtures, or run "
                "this task in the undefended arm."
            )
        self.intent = json.loads((REPO_ROOT / mandates["intent"]).read_text())
        self.confirmed_cart = json.loads((REPO_ROOT / mandates["cart"]).read_text())
        self.credentials = AgentCredentials()

        self._tmp = Path(tempfile.mkdtemp(prefix="mandate-kernel-"))
        self._conn = connect(self._tmp / "kernel.db")

        self.service = KernelService(
            conn=self._conn,
            clock=self.world.clock,
            psp=self.world.psp,
            trusted_keys=self._trusted_keys(),
            client_ref=self.client_ref,
            instrument_token=self.confirmed_cart["instrument"]["token"],
            guard=self._store_guard,
            after_reserve=self._after_reserve,
            sidecar_path=self._tmp / "audit_gap.jsonl",
        )

    # -- trust ------------------------------------------------------------

    def _trusted_keys(self) -> dict[str, str]:
        """``user_id -> public key``, read from the corpus, not from the request.

        The kernel's trust root. A key carried inside the object it signs is a
        claim rather than a signature, so the only key that counts is one the
        kernel already held.
        """
        pubkey = (REPO_ROOT / "fixtures" / "keys" / "user.pub.b64u").read_text().strip()
        return {self.intent["principal"]["user_id"]: pubkey}

    # -- the seams the fault injector reaches through ---------------------

    def _store_guard(self, store: str, operation: str) -> None:
        """Make a named store unavailable when the injector says so.

        ``target`` is the store's name, so one unavailable store does not make
        every store unavailable — otherwise a test could not tell which store
        the check under examination actually needed.
        """
        if self.world.faults.fires(Fault.STORE_UNAVAILABLE, target=store):
            raise StoreUnavailable(f"{store}.{operation}: injected fault")

    def arm(self, spec: dict[str, Any]) -> None:
        """Arm one fault through the same plane the control port serves."""
        from sim.control import ControlPlane

        ControlPlane(self.world).fault(spec)

    def _after_reserve(self) -> None:
        """``crash_after_reserve``: die between the reserve and the PSP call.

        Raises :class:`~sim.faults.KernelCrashed`, which derives from
        ``BaseException`` so no stray ``except Exception`` can turn a simulated
        crash into something the system under test gets to clean up after.
        """
        if self.world.faults.fires(Fault.CRASH_AFTER_RESERVE):
            raise KernelCrashed(Fault.CRASH_AFTER_RESERVE.value)  # type: ignore[arg-type]

    # -- the chain --------------------------------------------------------

    def verify(self) -> str | None:
        """``None`` when the chain verifies, else why it does not.

        Uses the in-process verifier for speed; ``mk verify-chain`` runs the
        standalone one over the exported file, and the two agreeing is itself
        part of what M1 established.
        """
        if self.service.poisoned is not None:
            return self.service.poisoned
        try:
            verify_entries(self.service.chain.read())
        except ChainBroken as exc:
            self.service.poison(str(exc))
            return str(exc)
        except StoreUnavailable as exc:
            return f"chain unreadable: {exc}"
        return None

    def head(self) -> tuple[str, int]:
        try:
            return self.service.chain.head()[1], self.service.chain.count()
        except StoreUnavailable:
            return "", 0

    def export(self, path: Path | None = None) -> Path:
        """Write the chain where ``mk explain`` and the standalone verifier read it."""
        target = Path(path) if path is not None else DEFAULT_CHAIN_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.service.chain.export_jsonl())
        return target

    def close(self) -> None:
        self._conn.close()
        shutil.rmtree(self._tmp, ignore_errors=True)
