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

__all__ = ["ToolResult", "UndefendedTools"]


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
        self, payee: dict[str, Any], amount_paise: int, currency: str = "INR"
    ) -> dict[str, Any]:
        """Order, authorise, capture. Three calls, no questions asked.

        ``payee`` arrives from the planner and is passed straight through. In
        the kernel configuration this is where a decision happens; here there
        is nothing to decide with, because there is no mandate in this process
        and nothing that has read one.
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
