"""Razorpay test mode — the credibility path, smoke only.

Not a source of any published number, and the architecture doc says so. It
exists to answer one question a panel will ask: does the model survive contact
with a real rail? Razorpay test mode has manual capture, so
``created → authorized → captured`` maps onto §06 without invention, and its
webhook payloads are real ones.

What it **cannot** do is the thing the simulator exists for. It will not crash
between an idempotency reserve and its commit on request, and it will not
redeliver a webhook with a fresh event id at a chosen moment. Class A6 and the
whole failure suite are therefore unreachable here, which is why the simulator
is the primary path rather than the fallback.

Deliberately unimplemented. A stub that raises names the shape of the work
without pretending the work is done; a stub that returned plausible objects
would let a smoke test pass against nothing. M6 fills these in as a
thirty-minute smoke against test-mode keys, or the milestone plan's cut order
drops it and this file is the record of that choice.
"""

from __future__ import annotations

from kernel.models import Account

__all__ = ["RazorpayTestMode"]


class RazorpayTestMode:
    """Implements :class:`kernel.adapters.base.PSPAdapter` against test mode.

    Every method raises. See the module docstring — this is scaffolding with a
    stated completion condition, not a silent no-op.
    """

    #: Keeps REQ-10's containment test honest: an adapter that talked to a
    #: non-local host during an *attack* run would be a finding, so the
    #: hostname is declared here rather than buried in a client.
    BASE_URL = "https://api.razorpay.com/v1"

    def __init__(self, key_id: str, key_secret: str) -> None:
        self.key_id = key_id
        self.key_secret = key_secret

    def _todo(self, call: str) -> None:
        raise NotImplementedError(
            f"RazorpayTestMode.{call} is not implemented. Test mode is a "
            "smoke path (M6), never a source of published numbers; the "
            "simulator is primary because no live PSP can be asked to crash "
            "between reserve and commit."
        )

    def create_order(self, amount_paise: int, currency: str, ref: str):
        self._todo("create_order")

    def authorize(self, order_id: str, instrument: str, idem: str):
        self._todo("authorize")

    def capture(self, payment_id: str, amount_paise: int, idem: str):
        self._todo("capture")

    def refund(self, payment_id: str, amount_paise: int, dest: Account, idem: str):
        self._todo("refund")

    def poll(self, client_ref: str):
        self._todo("poll")
