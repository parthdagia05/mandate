"""A kernel on a bench: one service, real stores, and mandates you can bend.

The M3 tests need to present the kernel with requests an agent could not
produce by accident — a cart whose declared hash disagrees with its contents, a
recurring mandate against a one-shot intent, a total above the cap. Building
those through the planner would mean writing a new gullibility rule for each
one, which measures the stand-in rather than the check.

So this builds the same requests directly, through the same strict models the
socket parses, and hands them to the same
:class:`~kernel.service.KernelService` the harness uses. Nothing here is a mock:
real SQLite with ``synchronous=FULL``, the real chain, the real simulator PSP.
The only thing the bench does that the harness does not is let a test choose
what the agent signs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent.credentials import AgentCredentials
from kernel.canonical import cart_hash
from kernel.decision import IntentRegistration
from kernel.enums import ActionType
from kernel.ids import IdFactory
from kernel.models import PaymentRequest
from kernel.service import KernelService
from kernel.stores.base import no_guard
from kernel.stores.db import connect
from sim.world import World

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "fixtures"


def load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


@dataclass
class Bench:
    """One kernel, wired the way ``harness/kernel_arm.py`` wires it."""

    tmp_path: Path
    seed: str = "bench"
    guard: Any = no_guard
    #: The named site ``crash_after_reserve`` fires at. A callable so a test
    #: can die exactly between the reservation and the rail, which is the one
    #: window recovery exists for.
    after_reserve: Any = None

    world: World = field(init=False)
    service: KernelService = field(init=False)
    credentials: AgentCredentials = field(init=False)
    intent: dict[str, Any] = field(init=False)
    confirmed_cart: dict[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        self.world = World(seed=self.seed)
        self.intent = load("mandates/intent_benign_01.json")
        self.confirmed_cart = load("mandates/cart_benign_01.json")
        self.credentials = AgentCredentials()
        self.conn = connect(self.tmp_path / "kernel.db")
        self.service = KernelService(
            conn=self.conn,
            clock=self.world.clock,
            psp=self.world.psp,
            trusted_keys={
                self.intent["principal"]["user_id"]: (
                    FIXTURES / "keys" / "user.pub.b64u"
                ).read_text().strip()
            },
            client_ref="ref_bench",
            guard=self.guard,
            after_reserve=self.after_reserve,
            sidecar_path=self.tmp_path / "audit_gap.jsonl",
        )
        self._ids = IdFactory(self.world.clock, self.world.rng)

    # -- registration -----------------------------------------------------

    def register(self, intent: dict[str, Any] | None = None, cart=None):
        return self.service.register_intent(
            IntentRegistration.model_validate(
                {
                    "intent": intent or self.intent,
                    "confirmed_cart": cart or self.confirmed_cart,
                }
            )
        )

    # -- a differently-scoped mandate --------------------------------------

    def user_signed_intent(self, **scope: Any) -> dict[str, Any]:
        """The shipped intent with a different scope, re-signed by the user.

        Signing here is a test constructing an input, not a run minting one:
        the private key is a committed fixture and the corpus freeze covers
        what is *shipped*, not what a unit test builds. Some scopes — a
        ``per_txn_cap`` equal to ``max_amount``, the ordinary shape for "buy me
        this one thing" — cannot be reached from the frozen corpus at all, and
        that is exactly the shape check 6 used to false-block.
        """
        from cryptography.hazmat.primitives import serialization

        from kernel.crypto import sign_object

        key = serialization.load_pem_private_key(
            (FIXTURES / "keys" / "user.key.pem").read_bytes(), password=None
        )
        body = {
            k: v for k, v in self.intent.items() if k != "sig"
        }
        body["scope"] = {**body["scope"], **scope}
        return {**body, "sig": sign_object(key, body)}

    # -- carts ------------------------------------------------------------

    def agent_cart(self, *, rehash: bool = True, **overrides: Any) -> dict[str, Any]:
        """A cart the agent signs with its delegated key.

        Defaults to the contents the user confirmed, so a test states only what
        it is changing. ``rehash=False`` leaves ``cart_hash`` as the confirmed
        cart's while the contents move — which is check 4's first conjunct,
        and is not otherwise expressible.
        """
        body = {
            "mandate_id": self._ids.cart_id(),
            "parent": self.intent["mandate_id"],
            "payee": dict(self.confirmed_cart["payee"]),
            "line_items": [dict(i) for i in self.confirmed_cart["line_items"]],
            "total_amount": self.confirmed_cart["total_amount"],
            "currency": self.confirmed_cart["currency"],
            "instrument": dict(self.confirmed_cart["instrument"]),
            "confirmed_by": "auto_within_intent_scope",
        }
        body.update(overrides)
        if rehash and "cart_hash" not in overrides:
            body["cart_hash"] = cart_hash(
                body["line_items"], body["total_amount"], body["payee"]
            )
        body.setdefault("cart_hash", self.confirmed_cart["cart_hash"])
        return self.credentials.signed(body)

    def request(
        self,
        action: ActionType | str,
        cart: dict[str, Any] | None = None,
        amount: int | None = None,
        intent: dict[str, Any] | None = None,
        **params: Any,
    ) -> PaymentRequest:
        cart = cart if cart is not None else self.agent_cart()
        return PaymentRequest.model_validate(
            {
                "action": str(action),
                "intent": intent or self.intent,
                "cart": cart,
                "params": {
                    "amount": cart["total_amount"] if amount is None else amount,
                    **params,
                },
                "client_ts": self.world.clock.now_rfc3339(),
            }
        )

    # -- shorthand --------------------------------------------------------

    def authorize(self, cart=None, amount=None, **kw):
        return self.service.authorize(
            self.request(ActionType.AUTHORIZE, cart, amount, **kw)
        )

    def capture(self, cart=None, amount=None, **kw):
        return self.service.capture(
            self.request(ActionType.CAPTURE, cart, amount, **kw)
        )

    def buy(self, cart=None, amount=None):
        """Register, authorize and capture — the whole happy path."""
        self.register()
        return self.authorize(cart, amount), self.capture(cart, amount)

    def close(self) -> None:
        self.conn.close()
