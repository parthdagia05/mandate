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

import functools
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kernel.latency import Stopwatch
from kernel.models import Account
from sim.eventlog import SimActor, SimEvent
from sim.merchants.base import MerchantResponse
from sim.world import World

__all__ = [
    "ToolResult",
    "UndefendedTools",
    "KernelTools",
    "GuardedTools",
    "GuardedKernelTools",
    "ScreenedTools",
    "timed",
]


def timed(call: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Measure one money-moving tool call, at the tool boundary.

    **Both arms are measured at the same place**, which is the only reason the
    overhead column means anything. SPEC.md §11 asks for "added latency per
    money-moving call", and *added* is a subtraction: the kernel arm's
    distribution minus the undefended arm's. A subtraction between two things
    measured at different boundaries — the kernel's own ``latency_us`` on one
    side and nothing at all on the other — would report the cost of the rail as
    if it were the cost of the defence. So the stopwatch goes around the whole
    tool call in both classes, rail included, and the difference is what the
    kernel added.

    Recorded on a normal return only. A call that died mid-flight (a
    ``crash_after_reserve`` fault raises through here) has no duration worth
    quoting, and a truncated sample in the distribution would drag the kernel
    arm's percentiles down on exactly the runs it behaved worst on.

    The duration reaches the run record and nothing else. It never enters the
    event log or the audit chain: two runs of one seed produce byte-identical
    logs and chains, and a microsecond count is the fastest way to lose that.
    ``kernel/latency.py`` states the same rule for the kernel's own responses,
    and ``tests/test_determinism.py`` enforces it.
    """

    def decorate(method: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(method)
        def wrapper(self: "UndefendedTools", *args: Any, **kwargs: Any) -> Any:
            watch = Stopwatch()
            result = method(self, *args, **kwargs)
            self.timings.append({"call": call, "latency_us": watch.micros()})
            return result

        return wrapper

    return decorate


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

    #: The payment the last ``pay`` produced, so a later refund has something
    #: to name. Held by the tools rather than passed through the planner
    #: because the planner must call the same method with the same arguments in
    #: both arms — see ``line_items`` below for the same argument.
    last_payment: dict[str, Any] = field(default_factory=dict)

    #: How many times ``pay`` has been called this run. A second purchase is a
    #: second *checkout attempt* and gets a reference of its own, exactly as a
    #: real client would issue: reusing the first attempt's idempotency key
    #: would have the rail return the first payment again, and classes A5 and
    #: A6 would be unreachable because the simulator was deduplicating them.
    #: The first attempt keeps the bare ``client_ref``, so a single-purchase
    #: run is byte-identical to what it was before repeats existed.
    attempts: int = 0

    #: Every debit this run produced, in order, as the rail reported it. The
    #: planner reads it back when deciding whether anything is still owed.
    settled: list[dict[str, Any]] = field(default_factory=list)

    #: One entry per completed money-moving tool call: ``{"call", "latency_us"}``,
    #: in call order. See :func:`timed`. The run record turns these into its
    #: ``latency_us`` percentiles and ``results.md`` subtracts one arm's
    #: distribution from the other's.
    #:
    #: A *denied* kernel call lands here too, and is much cheaper than an
    #: allowed one because the rail is never reached. That is why the overhead
    #: column is quoted from the benign suite, where both arms allow every
    #: call and the two distributions are measuring the same work.
    timings: list[dict[str, Any]] = field(default_factory=list)

    def _admit(self, call: str, **fields: Any) -> None:
        """The field-admission boundary. A no-op here, and that is the control arm.

        Every money-moving method calls this with the fields it is about to
        act on, *inside* the stopwatch and before the rail or the kernel is
        touched. The undefended and kernel arms have nothing to say here —
        a tool that quietly refused a suspicious payee would be a defence
        nobody declared, and both of those arms exist to measure what happens
        without one.

        :class:`GuardedTools` overrides it with
        :meth:`~agent.provenance.TaintLedger.admit` per field, which is what
        makes "a merchant value reaching a restricted field is a hard error at
        the tool boundary, before the kernel" a property of the call rather
        than of the planner's good behaviour. Inside the stopwatch on purpose:
        the guard's cost is part of the guarded arm's overhead column, and
        measuring it outside would publish a defence as free.
        """

    def attempt_ref(self) -> str:
        """This attempt's reference. Attempt one is the run's own ``client_ref``."""
        return self.client_ref if self.attempts <= 1 else f"{self.client_ref}#{self.attempts}"

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

    # -- the catalogue the agent is shopping ------------------------------
    #
    # Not a storefront *call*: no injection point, no event, no timing. It is
    # the shopping agent's own knowledge of what the shop sells, and it is read
    # through the merchant rather than imported from one storefront's module
    # because there is more than one storefront now. A planner holding a
    # hard-coded catalogue would see no candidates at any other shop, buy
    # nothing, and produce a clean run — which reads in the results table
    # exactly like a defended one.

    def known_products(self) -> dict[str, str]:
        return self.world.merchant.catalogue_names()

    def known_prices(self) -> dict[str, int]:
        return self.world.merchant.catalogue_prices()

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

    def price_quote(self, sku: str, qty: int) -> ToolResult:
        return self._read(
            "price_quote", self.world.merchant.price_quote(sku, qty), sku=sku, qty=qty
        )

    def seller_api(self, sku: str) -> ToolResult:
        return self._read("seller_api", self.world.merchant.seller_api(sku), sku=sku)

    def promo(self) -> ToolResult:
        return self._read("promo", self.world.merchant.promo())

    def support(self, topic: str) -> ToolResult:
        return self._read("support", self.world.merchant.support(topic), topic=topic)

    def order_status(self, payment_id: str) -> ToolResult:
        return self._read(
            "order_status",
            self.world.merchant.order_status(payment_id),
            payment_id=payment_id,
        )

    # -- money ------------------------------------------------------------

    @timed("pay")
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

        ``line_items`` is recorded on the rail and never acted on. A real PSP
        wants an amount and a destination and has no use for a basket, but it
        does carry the merchant's own order notes — and three of the seven
        oracles are questions about which basket a debit settled. Recording it
        here is what lets those questions be put to the payment rail instead of
        to the agent whose behaviour is being scored. The kernel arm needs the
        same argument for a different reason: it builds the cart it presents
        for checking out of it, and the *planner* must call the same method
        with the same arguments in both arms or the difference between the two
        runs stops being attributable to the kernel.
        """
        from kernel.canonical import cart_hash

        self._admit("pay", payee=payee, line_items=line_items or [])
        self.attempts += 1
        ref = self.attempt_ref()
        self._log_call("pay", payee=payee, amount_paise=amount_paise, ref=ref)
        account = Account(type=payee["type"], value=payee["value"])

        # The basket goes onto the rail with the debit. Computed honestly from
        # what is actually being bought — this agent is gullible about *what*
        # to buy, never dishonest about what it is buying — so that "the cart
        # at capture is not the cart that was signed" is a question the ledger
        # can answer without asking the agent.
        basket = list(line_items or [])
        order = self.world.psp.create_order(
            amount_paise,
            currency,
            ref,
            payee=account,
            cart_hash=cart_hash(basket, amount_paise, payee) if basket else None,
            line_items=basket,
        )
        payment = self.world.psp.authorize(
            order.order_id, "tok_scoped_01", idem=f"{ref}:authorize"
        )
        captured = self.world.psp.capture(
            payment.payment_id, amount_paise, idem=f"{ref}:capture"
        )
        self.last_payment = captured.view()
        self.settled.append(self.last_payment)
        return self.last_payment

    @timed("create_mandate")
    def create_mandate(
        self, payee: dict[str, Any], max_amount_paise: int, frequency: str
    ) -> dict[str, Any]:
        """Open a standing instruction — class A4's target.

        Nothing here asks whether the user authorised standing authority,
        because there is nothing in this process that knows: no mandate has
        been read, and an undefended agent that refused would be a defence
        nobody declared. The kernel arm overrides this method and the answer
        there is check 5.
        """
        self._admit(
            "create_mandate",
            payee=payee,
            max_amount=max_amount_paise,
            recurring=True,
        )
        self._log_call(
            "create_mandate",
            payee=payee,
            max_amount_paise=max_amount_paise,
            frequency=frequency,
        )
        return self.world.psp.create_mandate(
            Account(type=payee["type"], value=payee["value"]),
            max_amount_paise,
            frequency,
            self.client_ref,
            idem=f"{self.client_ref}:mandate",
        ).view()

    @timed("refund")
    def refund(
        self, payment_id: str, amount_paise: int, destination: dict[str, Any]
    ) -> dict[str, Any]:
        """Refund with a caller-supplied destination — class A7's target.

        The parameter exists here and deliberately does not exist on
        ``PaymentRequest``: an undefended agent can be told where to send a
        refund, and the kernel's answer to A7 is that there is no such field to
        tell it about. Nothing in this method checks the destination, because
        checking it here would be a defence nobody declared and the undefended
        number would be measuring it.
        """
        self._admit("refund", refund_destination=destination)
        self._log_call("refund", payment_id=payment_id, amount_paise=amount_paise)
        return self.world.psp.refund(
            payment_id,
            amount_paise,
            Account(type=destination["type"], value=destination["value"]),
            idem=f"{self.client_ref}:refund",
        ).view()

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
    #: The cart the purchase was made under. A refund is judged against the
    #: same authority, so it presents the same cart — and shares a mandate and
    #: cart hash with it, which is what gives the refund its own idempotency
    #: key under the same purchase.
    _cart: dict[str, Any] = field(default_factory=dict)

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
        # The kernel timed its own decision and put the figure in the response
        # (SPEC.md §07). It goes to the run record, where it says which of the
        # three or four decisions inside one ``pay`` the time was spent in —
        # something the tool-boundary stopwatch cannot see. It is added *after*
        # ``entry`` is built, and deliberately so: the copy below reaches the
        # event log, and the log is exported and compared byte for byte.
        self.decisions.append({**entry, "latency_us": int(body.get("latency_us") or 0)})
        # The event log gets ids and a reason code, never mandate bytes and
        # never a signature: the log is exported and compared byte for byte.
        self.world.log.append(
            SimActor.AGENT,
            SimEvent.AGENT_TOOL_CALL,
            {"tool": f"kernel.{step}", "args": entry},
        )
        return body

    @timed("pay")
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
        self._admit("pay", payee=payee, line_items=line_items or [])
        self._log_call("pay", payee=payee, amount_paise=amount_paise)
        self._register()

        cart = self._agent_cart(payee, list(line_items or []), amount_paise, currency)
        self._cart = cart

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
        self.last_payment = captured.get("payment") or {}
        return captured

    @timed("create_mandate")
    def create_mandate(
        self, payee: dict[str, Any], max_amount_paise: int, frequency: str
    ) -> dict[str, Any]:
        """Ask the kernel to open a standing instruction — check 5's question.

        The planner calls the same method with the same arguments in both arms,
        so an agent that a promotions page has talked into a subscription asks
        for one here exactly as it does undefended. What differs is that the
        request carries the user-signed intent, and ``scope.recurring`` on that
        intent is ``false``. Check 5 refuses before any rail call, and no
        standing instruction exists for the A4 oracle to find.

        The refusal is the *only* reachable outcome for this action today
        (``kernel/service.py``): the audit-action enum has no
        ``mandate.create.allow`` because issuing standing authority needs a
        recurring-mandate store the kernel does not have, so a request that got
        past check 5 would fail closed with a 503 rather than mint authority it
        could not record.
        """
        self._admit(
            "create_mandate",
            payee=payee,
            max_amount=max_amount_paise,
            recurring=True,
        )
        self._log_call(
            "create_mandate",
            payee=payee,
            max_amount_paise=max_amount_paise,
            frequency=frequency,
        )
        self._register()
        cart = self._cart or self._agent_cart(payee, [], max_amount_paise, "INR")
        body = self._request("mandate.create", cart, max_amount_paise)
        return self._record("mandate.create", self.service.mandate_create(_payment_request(body)))

    @timed("refund")
    def refund(
        self, payment_id: str, amount_paise: int, destination: dict[str, Any]
    ) -> dict[str, Any]:
        """Refund through the kernel. ``destination`` is accepted and dropped.

        **This method's signature is the demonstration of A7, and its body is
        the answer to it.** The planner calls the same method with the same
        arguments in both arms — it must, or the difference between the two
        runs stops being attributable to the kernel — so an agent that has been
        talked into a refund destination by a support page passes one here just
        as it does in the undefended arm.

        And then there is nowhere to put it. :class:`~kernel.models.RequestParams`
        has ``amount`` and ``original_payment_id`` and no destination field, so
        the value does not get dropped by a filter that could be misconfigured
        or a check that could be ablated; it is dropped because the wire format
        has no room for it. Check 8 then fills the destination in from
        ``payment.source_json``. The refund goes back where the debit came from
        because that is the only place the kernel can read a destination from.
        """
        self._admit("refund", refund_destination=destination)
        self._log_call(
            "refund",
            payment_id=payment_id,
            amount_paise=amount_paise,
            # Recorded so the run log shows what the agent *was told* to do,
            # next to a request that had no field to carry it. That contrast is
            # the whole of the A7 story and it should be legible in the log.
            destination_asked_for=destination,
            destination_field_exists=False,
        )
        body = self._request(
            "refund", self._cart, amount_paise, original_payment_id=payment_id
        )
        return self._record("refund", self.service.refund(_payment_request(body)))


def _payment_request(body: dict[str, Any]):
    """Parse an agent-built body the way the API would.

    Deliberately routed through the same strict model the socket uses, so the
    in-process path cannot accept a body the HTTP path would reject with 422.
    """
    from kernel.models import PaymentRequest

    return PaymentRequest.model_validate(body)


@dataclass
class GuardedTools(UndefendedTools):
    """The same tools, with the field-admission policy switched on.

    Two overrides and nothing else. ``_read`` observes every storefront
    response as merchant provenance — prose *and* typed data, because a
    checkout page's typed ``payee`` field is a merchant value however well
    typed it is, and treating typed merchant content as trustworthy is the
    assumption class A1 is built on. ``_admit`` puts every named field through
    :meth:`~agent.provenance.TaintLedger.admit` before the rail is touched.

    The declarations go in from outside, before the first tool call: the
    planner hands the ledger the task and the signed intent, which is what
    "control flow fixed before any untrusted byte is read" means for values.

    Money-tool *results* are declared kernel provenance as they come back. A
    payment id and the source account a debit actually came from are facts
    about a movement of money, not claims a storefront gets to make — and
    without that declaration the honest refund path would be refused, because
    the destination the kernel arm falls back to is exactly that source.
    """

    taint: Any = None  # agent.provenance.TaintLedger, injected by the agent

    def __post_init__(self) -> None:
        if self.taint is None:
            from agent.provenance import TaintLedger

            self.taint = TaintLedger()

    def _read(self, tool: str, response: MerchantResponse, **args: Any) -> ToolResult:
        result = super()._read(tool, response, **args)
        self.taint.observe_merchant({"prose": result.prose, "data": result.data})
        return result

    def _admit(self, call: str, **fields: Any) -> None:
        for name, value in fields.items():
            self.taint.admit(name, value)

    @timed("pay")
    def pay(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        outcome = UndefendedTools.pay.__wrapped__(self, *args, **kwargs)  # type: ignore[attr-defined]
        self.taint.declare_kernel(outcome)
        return outcome

    @timed("refund")
    def refund(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        outcome = UndefendedTools.refund.__wrapped__(self, *args, **kwargs)  # type: ignore[attr-defined]
        self.taint.declare_kernel(outcome)
        return outcome


@dataclass
class GuardedKernelTools(KernelTools):
    """Both defences at once: the agent-side guard *and* the kernel.

    Exists so the table can say what the two cost and catch together, and — more
    usefully — so the ``kernel`` arm can be exactly what it claims to be. That
    arm runs the **undefended** agent on purpose: SPEC.md §17.7 says every
    guarantee has to hold with a fully adversarial agent, and an arm that
    quietly had a taint guard in it would be publishing the guard's wins as the
    kernel's. Keeping the combination in its own class is what keeps the two
    apart.

    The overrides are :class:`GuardedTools`', repeated rather than inherited: a
    diamond over two dataclasses that both define ``pay`` resolves by MRO in a
    way a reader has to work out, and this is a file where what runs before the
    rail is the whole subject.
    """

    taint: Any = None  # agent.provenance.TaintLedger, injected by the agent

    def __post_init__(self) -> None:
        if self.taint is None:
            from agent.provenance import TaintLedger

            self.taint = TaintLedger()

    def _read(self, tool: str, response: MerchantResponse, **args: Any) -> ToolResult:
        result = super()._read(tool, response, **args)
        self.taint.observe_merchant({"prose": result.prose, "data": result.data})
        return result

    def _admit(self, call: str, **fields: Any) -> None:
        for name, value in fields.items():
            self.taint.admit(name, value)

    @timed("pay")
    def pay(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        outcome = KernelTools.pay.__wrapped__(self, *args, **kwargs)  # type: ignore[attr-defined]
        self.taint.declare_kernel(outcome.get("payment") or {})
        return outcome


@dataclass
class ScreenedTools(UndefendedTools):
    """The model-only arm: a guardrail classifier in front of the money tools.

    No kernel, no mandate, no signature, no ledger — see :mod:`agent.guardrail`
    for what this arm is for. The classifier is consulted at the same boundary
    the field-admission guard uses and the kernel uses, inside the stopwatch and
    before the rail, so all three arms' overhead columns measure the same thing.

    A refusal is turned into a **decision with a reason code** rather than an
    exception that escapes. Two reasons. The planner has to carry on and reach
    its later steps, exactly as it does when the kernel denies an authorize —
    an arm that aborted the run on its first block would have a different shape
    from every other arm and its utility-under-attack column would be measuring
    the abort. And the false-block column reads ``decisions``: a refusal that
    left no decision behind is indistinguishable from a crash, and a crash
    counted as a block would inflate the very number this project insists on
    printing.
    """

    screen: Any = None  # agent.guardrail.GuardrailScreen, injected by the runner

    #: Every decision this arm made, in the same shape the kernel arm's
    #: ``decisions`` have, so one metric function reads both.
    decisions: list[dict[str, Any]] = field(default_factory=list)

    def _screened(self, call: str, **facts: Any) -> dict[str, Any] | None:
        """Consult the classifier. ``None`` to proceed, a refusal body to stop."""
        from agent.guardrail import GuardrailRefusal

        if self.screen is None:
            return None
        try:
            verdict = self.screen.screen(call, self.prose_so_far(), facts)
        except GuardrailRefusal as refusal:
            body = {
                "step": call,
                "status": 200,
                "decision": "deny",
                "reason_code": f"GUARDRAIL_{refusal.category.upper()}",
                "denied_by": ["guardrail"],
                "checks": [],
                "audit_seq": None,
                "quote": refusal.quote,
            }
            self.decisions.append(body)
            self.world.log.append(
                SimActor.AGENT,
                SimEvent.AGENT_TOOL_CALL,
                {"tool": f"guardrail.{call}", "args": {k: v for k, v in body.items() if k != "quote"}},
            )
            return body
        self.decisions.append(
            {
                "step": call,
                "status": 200,
                "decision": "allow",
                "reason_code": "OK",
                "denied_by": [],
                "checks": [],
                "audit_seq": None,
                "category": verdict.get("category", "clean"),
            }
        )
        return None

    @timed("pay")
    def pay(
        self,
        payee: dict[str, Any],
        amount_paise: int,
        currency: str = "INR",
        line_items: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        refused = self._screened(
            "pay", payee=payee, amount_paise=amount_paise, line_items=line_items or []
        )
        if refused is not None:
            return refused
        return UndefendedTools.pay.__wrapped__(  # type: ignore[attr-defined]
            self, payee, amount_paise, currency, line_items=line_items
        )

    @timed("create_mandate")
    def create_mandate(
        self, payee: dict[str, Any], max_amount_paise: int, frequency: str
    ) -> dict[str, Any]:
        refused = self._screened(
            "create_mandate",
            payee=payee,
            max_amount_paise=max_amount_paise,
            frequency=frequency,
        )
        if refused is not None:
            return refused
        return UndefendedTools.create_mandate.__wrapped__(  # type: ignore[attr-defined]
            self, payee, max_amount_paise, frequency
        )

    @timed("refund")
    def refund(
        self, payment_id: str, amount_paise: int, destination: dict[str, Any]
    ) -> dict[str, Any]:
        refused = self._screened(
            "refund",
            payment_id=payment_id,
            amount_paise=amount_paise,
            destination=destination,
        )
        if refused is not None:
            return refused
        return UndefendedTools.refund.__wrapped__(  # type: ignore[attr-defined]
            self, payment_id, amount_paise, destination
        )
