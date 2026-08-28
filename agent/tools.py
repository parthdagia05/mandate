"""The agent's tools. Two kinds, and the difference is the whole project.

**Storefront tools** read merchant content. They return prose, and prose is the
attack surface — everything the kernel later parses is a bounded token with no
whitespace, so an injection has to reach the agent's reasoning rather than the
kernel's parser.

**Money tools** move money. In the undefended configuration they call the PSP
adapter directly, with nothing in front of them: no kernel, no taint guard, no
field-admission policy. That is not an oversight to be fixed later, it is the
control arm. M3 puts the kernel in front of exactly these calls and changes
nothing else, so the difference between the two runs is attributable.

The tools carry no policy of their own. A tool that quietly refused a suspicious
payee would be a defence nobody declared, and the undefended number would be
measuring it instead of measuring nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kernel.models import Account
from sim.eventlog import SimActor, SimEvent
from sim.merchants.base import MerchantResponse
from sim.world import World

__all__ = ["ToolResult", "UndefendedTools", "KernelTools"]


@dataclass
class ToolResult:
    """What a tool hands back to the planner.

    ``prose`` and ``data`` stay separate all the way through. The undefended
    agent puts both in front of its planner, which is precisely why A1 works;
    M6's quarantined extractor is the same split with the prose routed
    somewhere that has no tools.
    """

    prose: str
    data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def of(cls, response: MerchantResponse) -> "ToolResult":
        return cls(prose=response.text, data=response.data)


@dataclass
class UndefendedTools:
    """Storefront plus money, with nothing between them and the rail."""

    world: World
    client_ref: str

    #: Everything the storefront has said this run, in order. The undefended
    #: planner reads all of it, which is the point.
    transcript: list[str] = field(default_factory=list)

    def _log_call(self, tool: str, **args: Any) -> None:
        self.world.log.append(
            SimActor.AGENT,
            SimEvent.AGENT_TOOL_CALL,
            {"tool": tool, "args": args},
        )

    def _read(self, tool: str, response: MerchantResponse, **args: Any) -> ToolResult:
        self._log_call(tool, **args)
        result = ToolResult.of(response)
        self.transcript.append(result.prose)
        return result

    # -- storefront -------------------------------------------------------

    def search_catalog(self, query: str) -> ToolResult:
        return self._read(
            "search_catalog", self.world.merchant.search_catalog(query), query=query
        )

    def get_product(self, sku: str) -> ToolResult:
        return self._read("get_product", self.world.merchant.get_product(sku), sku=sku)

    def checkout(self, line_items: list[dict[str, Any]]) -> ToolResult:
        return self._read(
            "checkout",
            self.world.merchant.checkout(line_items),
            line_item_count=len(line_items),
        )

    def support(self, topic: str) -> ToolResult:
        return self._read("support", self.world.merchant.support(topic), topic=topic)

    # -- money ------------------------------------------------------------

    def pay(
        self,
        payee: dict[str, Any],
        amount_paise: int,
        currency: str = "INR",
        line_items: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Order, authorise, capture. Three calls, no questions asked.

        ``payee`` arrives from the planner and is passed straight through. In
        the kernel configuration this is where a decision happens; here there
        is nothing to decide with, because there is no mandate in this process
        and nothing that has read one.

        ``line_items`` is accepted and ignored. A payment rail wants an amount
        and a destination and has no use for a basket — but the kernel arm needs
        the basket to build the cart it presents for checking, and the *planner*
        must call the same method with the same arguments in both arms or the
        difference between the two runs stops being attributable to the kernel.
        """
        self._log_call("pay", payee=payee, amount_paise=amount_paise)
        account = Account(type=payee["type"], value=payee["value"])

        order = self.world.psp.create_order(
            amount_paise, currency, self.client_ref, payee=account
        )
        payment = self.world.psp.authorize(
            order.order_id, "tok_scoped_01", idem=f"{self.client_ref}:authorize"
        )
        captured = self.world.psp.capture(
            payment.payment_id, amount_paise, idem=f"{self.client_ref}:capture"
        )
        return captured.view()

    def refund(self, payment_id: str, amount_paise: int, destination: dict[str, Any]):
        """Refund with a caller-supplied destination — class A7's target.

        The parameter exists here and deliberately does not exist on
        ``PaymentRequest``: an undefended agent can be told where to send a
        refund, and the kernel's answer to A7 is that there is no such field to
        tell it about.
        """
        self._log_call("refund", payment_id=payment_id, amount_paise=amount_paise)
        return self.world.psp.refund(
            payment_id,
            amount_paise,
            Account(type=destination["type"], value=destination["value"]),
            idem=f"{self.client_ref}:refund",
        )

    # -- what the planner has read ----------------------------------------

    def prose_so_far(self) -> str:
        return "\n\n".join(self.transcript)


@dataclass
class KernelTools(UndefendedTools):
    """The same tools, with the kernel in front of the money ones.

    **Nothing else changes.** The storefront methods are inherited unmodified,
    the planner is the same object running the same five steps, the world is
    the same seeded world, and the payload lands at the same injection point.
    The only difference between an undefended run and a kernel run is that
    ``pay`` goes through :class:`~kernel.service.KernelService` instead of
    straight to the rail — which is what makes the difference between the two
    numbers attributable to the kernel and not to an agent that was also
    quietly improved.

    The agent still decides everything it decided before. It reads the product
    page, believes it, and asks to pay ``attacker@upi`` — and because it holds
    the delegated signing key the intent names, it produces a *validly signed*
    cart saying so. Check 1 passes. Check 2 refuses. That ordering is the whole
    demonstration: the defence is not "the agent could not sign", it is "what
    the agent signed was not inside the sentence the user said".
    """

    service: Any = None
    credentials: Any = None
    #: The task's shipped mandates: the user-signed intent, and the cart the
    #: user confirmed at the ceremony. Both are fixtures, pre-signed offline.
    intent: dict[str, Any] = field(default_factory=dict)
    confirmed_cart: dict[str, Any] = field(default_factory=dict)

    #: Every decision the kernel returned this run, in order. The run record
    #: carries these so a denial is visible as a decision with a reason code
    #: rather than as an absence of money movement.
    decisions: list[dict[str, Any]] = field(default_factory=list)
    _registered: bool = False

    # -- mandate assembly -------------------------------------------------

    def _agent_cart(
        self, payee: dict[str, Any], line_items: list[dict[str, Any]], total: int,
        currency: str,
    ) -> dict[str, Any]:
        """The cart the agent proposes, signed with its delegated key.

        ``confirmed_by: auto_within_intent_scope`` says truthfully who stood
        behind this cart: not the user at a ceremony, but the agent acting
        inside an authority the user already granted. The kernel verifies it
        against ``intent.agent.pubkey`` for exactly that reason, and then holds
        it to checks 2, 3 and 4 anyway.

        Every field here is the agent's own claim, including ``cart_hash``. It
        is computed honestly by this method because this agent is gullible
        rather than malicious about hashes — a cart whose stated hash disagrees
        with its contents is class A3 and is constructed deliberately in the
        M3 gate tests, where check 4's first conjunct catches it.
        """
        from kernel.canonical import cart_hash

        body = {
            "mandate_id": self.world_cart_id(),
            "parent": self.intent["mandate_id"],
            "payee": payee,
            "line_items": line_items,
            "total_amount": total,
            "currency": currency,
            "cart_hash": cart_hash(line_items, total, payee),
            "instrument": dict(self.confirmed_cart["instrument"]),
            "confirmed_by": "auto_within_intent_scope",
        }
        return self.credentials.signed(body)

    def world_cart_id(self) -> str:
        """A cart id from the run's seeded stream, so it is stable per seed."""
        from kernel.ids import IdFactory

        return IdFactory(self.world.clock, self.world.rng).cart_id()

    def _request(
        self, action: str, cart: dict[str, Any], amount: int, **params: Any
    ) -> dict[str, Any]:
        return {
            "action": action,
            "intent": self.intent,
            "cart": cart,
            "params": {"amount": amount, **params},
            # Advisory, and the kernel ignores it. Sent because a real client
            # would send it, and because check 1 records that it was ignored.
            "client_ts": self.world.clock.now_rfc3339(),
        }

    # -- the money path ---------------------------------------------------

    def _register(self) -> dict[str, Any] | None:
        if self._registered:
            return None
        from kernel.decision import IntentRegistration

        outcome = self.service.register_intent(
            IntentRegistration.model_validate(
                {"intent": self.intent, "confirmed_cart": self.confirmed_cart}
            )
        )
        self._registered = True
        self._record("intent.register", outcome)
        return outcome.body

    def _record(self, step: str, outcome: Any) -> dict[str, Any]:
        body = dict(outcome.body)
        entry = {
            "step": step,
            "status": outcome.status,
            "decision": body.get("decision"),
            "reason_code": body.get("reason_code"),
            "denied_by": body.get("denied_by", []),
            "checks": body.get("checks", []),
            "audit_seq": (body.get("audit") or {}).get("seq"),
        }
        self.decisions.append(entry)
        # The event log gets ids and a reason code, never mandate bytes and
        # never a signature: the log is exported and compared byte for byte.
        self.world.log.append(
            SimActor.AGENT,
            SimEvent.AGENT_TOOL_CALL,
            {"tool": f"kernel.{step}", "args": entry},
        )
        return body

    def pay(
        self,
        payee: dict[str, Any],
        amount_paise: int,
        currency: str = "INR",
        line_items: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Register, authorise, capture — each one a decision the kernel makes.

        Three calls rather than one because authority is checked at each of
        them: an authorize that passed does not entitle a capture, and a
        mandate that was live at authorize can be exhausted by the time the
        capture arrives. A single fused call would check once and settle later,
        which is the gap the whole lifecycle exists to close.
        """
        self._log_call("pay", payee=payee, amount_paise=amount_paise)
        self._register()

        cart = self._agent_cart(payee, list(line_items or []), amount_paise, currency)

        authorized = self._record(
            "authorize",
            self.service.authorize(
                _payment_request(self._request("authorize", cart, amount_paise))
            ),
        )
        if authorized.get("decision") != "allow":
            # No PSP call happened. The kernel refused before the rail, which
            # is the only ordering under which a denial is worth anything.
            return authorized

        captured = self._record(
            "capture",
            self.service.capture(
                _payment_request(self._request("capture", cart, amount_paise))
            ),
        )
        return captured


def _payment_request(body: dict[str, Any]):
    """Parse an agent-built body the way the API would.

    Deliberately routed through the same strict model the socket uses, so the
    in-process path cannot accept a body the HTTP path would reject with 422.
    """
    from kernel.models import PaymentRequest

    return PaymentRequest.model_validate(body)
