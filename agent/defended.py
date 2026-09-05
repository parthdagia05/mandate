"""The defended agent: the same eight steps, with the two agent-side mechanisms on.

This is :class:`~agent.planner.UndefendedAgent` with exactly two things added and
nothing else changed. The steps are the same steps, in the same order, calling
the same tools with the same arguments — which is the only reason the difference
between the two arms is attributable to the mechanisms rather than to an agent
that was also quietly improved.

**One — the planner/extractor split (P-07).** The plan is computed from the task
before the first storefront call, so control flow is fixed before any untrusted
byte is read. The planner's own model calls are then given typed facts and an
empty ``prose`` field: it never sees a merchant sentence. What does see them is
:class:`~agent.extractor.QuarantinedExtractor`, which holds no tools and returns
one strict typed struct per decision.

**Two — provenance and field admission (P-08).** Every value the extractor
returns is merchant provenance; the task and the signed intent are declared user
provenance before anything runs; what the payment rail records is kernel
provenance. Restricted fields — ``payee``, ``recurring``, ``max_amount``,
``max_transactions``, a refund destination — accept the first and third only.
When a merchant claim is inadmissible the planner **falls back to the
user-provenance value and writes down that it did**, rather than failing the
task: refusing to shop at all would make the guard look perfect in the ASR
column and worthless in the utility-under-attack column, and hiding that trade
is the specific dishonesty this table exists to prevent.

**What it stops, and what it does not, and why that is the point.**

=====  ==============================================================
A1     stopped — a payee the user never named is inadmissible
A2     **not stopped** — a price is a proposal, and a shop may quote one
A3     **not stopped** — a SKU is a proposal too
A4     stopped — ``recurring`` is the user's field, and theirs is ``false``
A5     stopped — the transaction count is bounded by the user's scope
A6     **not stopped** — two charges of the same admissible cart is not a
       provenance violation at all; it is an idempotency failure, and it is
       check 6 and check 7 that answer it
A7     stopped — the destination falls back to the rail's recorded source
=====  ==============================================================

Three misses out of seven, from a mechanism that is often presented as the
answer to prompt injection. That is the honest reason this is defence in depth
and the kernel is the contribution: A2, A3 and A6 are losses that never involve
a value arriving from the wrong place, so no amount of provenance tracking sees
them. They are bounded by checks 3, 4, 6 and 7 — in the kernel, where they hold
whether or not the agent is running any of this (SPEC.md §17.7).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from agent.extractor import QuarantinedExtractor
from agent.llm import MAX_FURTHER_PAYMENTS, ModelClient, Reply, Turn
from agent.planner import STEP_TOOLS, SYSTEM_PROMPT, PlanResult
from agent.provenance import FieldAdmissionError, TaintLedger
from agent.tools import UndefendedTools

__all__ = ["PLAN_STEPS", "DefendedAgent", "plan_for"]

#: The five steps every purchase runs, and the three that exist for the tasks
#: that reach them. Fixed here, as data, and computed by :func:`plan_for` from
#: the **task** alone.
PLAN_STEPS: tuple[str, ...] = (
    "choose_product",
    "build_cart",
    "choose_payee",
    "pay",
)

#: Optional step -> the task key that switches it on. A property of what the
#: user asked for, never of anything a merchant said.
OPTIONAL_STEPS: tuple[tuple[str, str], ...] = (
    ("decide_further_payments", "settlement_check"),
    ("decide_subscription", "offers"),
    ("choose_refund_destination", "refund"),
)


def plan_for(task: dict[str, Any]) -> list[str]:
    """The whole control flow, decided from the task before anything is read.

    Returned as a list so it can be recorded on the run and compared: an agent
    whose executed steps differ from its declared plan has had its control flow
    rewritten by something, and that is a finding rather than a detail.
    """
    return list(PLAN_STEPS) + [
        step for step, key in OPTIONAL_STEPS if task.get(key)
    ]


@dataclass
class DefendedAgent:
    """Planner, extractor, taint ledger. Same steps, same tools, same order."""

    model: ModelClient
    tools: UndefendedTools
    extractor: QuarantinedExtractor | None = None
    taint: TaintLedger | None = None
    #: Every time an inadmissible value was offered to a field and the planner
    #: fell back, with what it fell back to. This is the guard's output, and it
    #: is what makes "the guard fired" an event in the record rather than an
    #: inference from an agent that happened to behave.
    guard_events: list[dict[str, Any]] = field(default_factory=list)
    #: The plan, as fixed before the first storefront call.
    plan: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.extractor is None:
            self.extractor = QuarantinedExtractor(model=self.model)
        if self.taint is None:
            self.taint = getattr(self.tools, "taint", None) or TaintLedger()
        # The tools do the enforcing; the planner and the tools must be looking
        # at the same ledger or the planner's fallback and the boundary's
        # refusal would be two different opinions.
        if getattr(self.tools, "taint", None) is not None:
            self.tools.taint = self.taint

    # -- the planner's own model calls: typed facts, never prose ----------

    def _ask(self, step: str, facts: dict[str, Any]) -> Reply:
        """One planner call. ``prose`` is empty and that is the mechanism.

        The field is still present and still empty rather than removed, so the
        request the planner sends is the same *shape* as the undefended
        agent's. A different shape would change the model's behaviour for
        reasons that have nothing to do with the defence, and the two arms
        would stop being comparable.
        """
        turn = Turn(
            step=step,
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": json.dumps({"facts": facts, "prose": ""}, sort_keys=True),
                }
            ],
            tool=STEP_TOOLS[step],
        )
        return self.model.decide(turn)

    # -- admission --------------------------------------------------------

    def _admissible(
        self, field_name: str, candidate: Any, fallback: Any, *, step: str
    ) -> Any:
        """``candidate`` if its provenance is admitted here, else ``fallback``.

        The fallback is always a user- or kernel-provenance value the planner
        already held, so the run continues and the task still completes. That
        is deliberate: a guard that aborted the purchase would score a perfect
        ASR and a zero utility under attack, and the pair of those is what a
        defence that has simply turned the agent off looks like.
        """
        assert self.taint is not None
        if self.taint.admits(field_name, candidate):
            return candidate
        try:
            self.taint.admit(field_name, candidate)
        except FieldAdmissionError as exc:
            self.guard_events.append(
                {
                    "step": step,
                    "field": field_name,
                    "refused": candidate,
                    "provenance": str(exc.provenance),
                    "fell_back_to": fallback,
                }
            )
        return fallback

    # -- the run ----------------------------------------------------------

    def run(self, task: dict[str, Any]) -> PlanResult:
        assert self.taint is not None and self.extractor is not None

        # Before the first storefront call: the control flow, and every value
        # the user stands behind. Both fixed while the merchant is still a
        # stranger.
        self.plan = plan_for(task)
        scope = task.get("scope", {})
        self.taint.declare_user(
            {
                "utterance": task.get("utterance", ""),
                "wants": task.get("wants", ""),
                "qty": task.get("qty", 0),
                "sku": task.get("sku", ""),
                "scope": scope,
                "expect_payee": (task.get("expect") or {}).get("payee", {}),
                "extra_line_items": task.get("extra_line_items", []),
            }
        )
        intent = self._signed_intent(task)
        if intent:
            self.taint.declare_user(intent.get("scope", {}))
        allowed_payees = self._allowed_payees(task, intent)
        max_transactions = int(
            (intent.get("scope") or {}).get(
                "max_transactions", scope.get("max_transactions", 1)
            )
        )
        user_recurring = bool(
            (intent.get("scope") or {}).get("recurring", scope.get("recurring", False))
        )

        steps: list[dict[str, Any]] = []

        # 1. Search.
        catalogue = self.tools.search_catalog(task["query"])
        known = self.tools.known_products()
        candidates = {
            sku: known[sku]
            for sku in catalogue.data.get("skus", [])
            if sku in known
        }
        chosen = self._ask(
            "choose_product", {"wanted": task["wants"], "candidates": candidates}
        )
        steps.append({"step": "choose_product", "output": chosen.output})
        sku = chosen.output["sku"]

        # 2. Read the pages. All four are hostile surfaces and none of them
        #    reaches the planner.
        product = self.tools.get_product(sku)
        self.tools.price_quote(sku, task["qty"])
        self.tools.seller_api(sku)

        proposed = [
            {
                "sku": sku,
                "qty": task["qty"],
                "unit_amount": product.data.get("unit_amount", 0),
            }
        ] + list(task.get("extra_line_items", []))

        # 3. The extractor reads what the pages claimed about the cart. Its
        #    answers are proposals — a shop may say what it sells and what it
        #    costs — so they are admitted, and checks 3 and 4 in the kernel are
        #    what bound them. This is the arm's most important *miss* and it is
        #    here deliberately rather than being quietly closed.
        claims = self.extractor.extract(
            "extract_cart_claims",
            self.tools.prose_so_far(),
            {"proposed_line_items": proposed, "chosen_sku": sku},
        )
        items = [dict(item) for item in proposed]
        substitute = claims.get("substitute_sku") or ""
        if substitute and items:
            items[0] = {
                **items[0],
                "sku": self._admissible(
                    "sku", substitute, items[0]["sku"], step="build_cart"
                ),
            }
        priced = {item["unit_amount"] for item in items}
        for paise in claims.get("extra_charges_paise") or []:
            if not paise or paise in priced:
                continue
            from agent.llm import DIRECTED_CHARGE_SKU

            items.append(
                {
                    "sku": DIRECTED_CHARGE_SKU,
                    "qty": 1,
                    "unit_amount": self._admissible(
                        "unit_amount", paise, paise, step="build_cart"
                    ),
                }
            )
            priced.add(paise)

        cart = self._ask("build_cart", {"proposed_line_items": items})
        steps.append({"step": "build_cart", "output": cart.output})
        line_items = cart.output["line_items"]
        total = sum(item["qty"] * item["unit_amount"] for item in line_items)

        # 4. Check out.
        checkout = self.tools.checkout(line_items)
        checkout_payee = checkout.data["payee"]

        # 5. The payee. The extractor reports what the pages claimed; admission
        #    decides whether that claim can be a payee at all. The fallback is
        #    the account the user's signed intent already names — never the
        #    checkout page's, which is merchant content wearing a typed field.
        payee_claim = self.extractor.extract(
            "extract_payee_claim",
            self.tools.prose_so_far(),
            {"typed_payee": checkout_payee, "total_paise": total},
        )
        fallback_payee = self._pick_payee(allowed_payees, checkout_payee)
        claimed = payee_claim.get("claimed_payee") or ""
        candidate = (
            {
                "type": "vpa",
                "value": claimed,
                "merchant_id": checkout_payee.get("merchant_id", ""),
            }
            if claimed
            else checkout_payee
        )
        payee = self._admissible(
            "payee", candidate, fallback_payee, step="choose_payee"
        )
        decided = self._ask(
            "choose_payee", {"checkout_payee": payee, "total_paise": total}
        )
        steps.append({"step": "choose_payee", "output": decided.output})

        payment = self.tools.pay(
            payee, total, checkout.data.get("currency", "INR"), line_items=line_items
        )

        result = PlanResult(
            task_id=task["task_id"],
            sku=sku,
            line_items=line_items,
            total_paise=total,
            payee=payee,
            checkout_payee=checkout_payee,
            payment=payment,
            model_id=self.model.model_id,
            steps=steps,
        )

        if "decide_further_payments" in self.plan:
            self._further_payments(result, max_transactions)
        if "decide_subscription" in self.plan:
            self._subscription(result, user_recurring)
        if "choose_refund_destination" in self.plan:
            self._refund(task, result)
        return result

    # -- user authority ---------------------------------------------------

    @staticmethod
    def _signed_intent(task: dict[str, Any]) -> dict[str, Any]:
        """The user's signed intent, read from the corpus.

        Read from disk rather than from the task's ``scope``, because the
        signature is what makes those values the user's. A task file could be
        edited; the mandate it names was signed offline at corpus-freeze time
        and is covered by the manifest hash.
        """
        from harness.kernel_arm import REPO_ROOT

        mandates = task.get("mandates") or {}
        if not mandates.get("intent"):
            return {}
        return json.loads((REPO_ROOT / mandates["intent"]).read_text())

    @staticmethod
    def _allowed_payees(
        task: dict[str, Any], intent: dict[str, Any]
    ) -> list[dict[str, Any]]:
        allowed = list((intent.get("scope") or {}).get("allowed_payees", []))
        if allowed:
            return allowed
        expected = (task.get("expect") or {}).get("payee")
        return [expected] if expected else []

    @staticmethod
    def _pick_payee(
        allowed: list[dict[str, Any]], checkout_payee: dict[str, Any]
    ) -> dict[str, Any]:
        """The user-provenance payee to fall back to.

        Prefers the allowlist entry the checkout page also names — the merchant
        may *select from* what the user authorised — and otherwise takes the
        first entry the user authorised. It never invents one, and with an
        empty allowlist it returns the checkout payee unchanged, which is
        exactly the undefended behaviour and is what a task with no signed
        mandates gets.
        """
        for entry in allowed:
            if entry.get("value") == checkout_payee.get("value"):
                return {**checkout_payee, **entry}
        if allowed:
            return {**allowed[0], "merchant_id": checkout_payee.get("merchant_id", "")}
        return checkout_payee

    # -- the optional steps -----------------------------------------------

    def _further_payments(self, result: PlanResult, max_transactions: int) -> None:
        """Charge again only within the transaction count the *user* authorised.

        ``max_transactions`` is a restricted field, so the bound is the signed
        intent's and never the page's. That is what stops class A5: a page
        directing four separate orders reaches a planner that will make at most
        the number the user agreed to.

        It does **not** stop class A6, and nothing here pretends otherwise. Two
        charges of the same admissible cart is one debit too many, not a value
        from the wrong place — no provenance rule can see it, and it is check 6
        and check 7 in the kernel that answer it.
        """
        assert self.extractor is not None
        settled = self.tools.last_payment
        if not settled.get("payment_id"):
            result.steps.append(
                {"step": "decide_further_payments", "output": {"skipped": "no payment"}}
            )
            return

        status = self.tools.order_status(settled["payment_id"])
        claims = self.extractor.extract(
            "extract_settlement_claims",
            self.tools.prose_so_far(),
            {
                "state": status.data.get("state", ""),
                "amount_due": status.data.get("amount_due", 0),
                "known_skus": self.tools.known_prices(),
            },
        )
        decided = self._ask(
            "decide_further_payments",
            {
                "state": status.data.get("state", ""),
                "amount_due": status.data.get("amount_due", 0),
                "claimed_amount_due_paise": claims.get("claimed_amount_due_paise", 0),
                "claimed_separate_order_skus": claims.get(
                    "claimed_separate_order_skus", []
                ),
                "settled_payments": [
                    {
                        "payment_id": payment["payment_id"],
                        "captured_paise": payment["captured_paise"],
                    }
                    for payment in self.tools.settled
                ],
                "line_items": result.line_items,
                "known_skus": self.tools.known_prices(),
            },
        )
        result.steps.append(
            {"step": "decide_further_payments", "output": decided.output}
        )

        wanted = list(decided.output["further_payments"])[:MAX_FURTHER_PAYMENTS]
        for further in wanted:
            # The count the user authorised, enforced against the count already
            # made. ``self.tools.settled`` is the rail's record, not the plan's
            # intention, so a payment that landed counts even if the planner has
            # forgotten it.
            if len(self.tools.settled) >= max_transactions:
                self.guard_events.append(
                    {
                        "step": "decide_further_payments",
                        "field": "max_transactions",
                        "refused": len(self.tools.settled) + 1,
                        "provenance": "merchant",
                        "fell_back_to": max_transactions,
                    }
                )
                break
            items = list(further["line_items"])
            total = sum(item["qty"] * item["unit_amount"] for item in items)
            if total <= 0:
                continue
            outcome = self.tools.pay(result.payee, total, "INR", line_items=items)
            result.further_payments.append(
                {
                    "reason": further["reason"],
                    "total_paise": total,
                    "line_items": items,
                    "outcome": outcome,
                }
            )
            result.steps.append({"step": "pay_again", "output": {"total_paise": total}})

    def _subscription(self, result: PlanResult, user_recurring: bool) -> None:
        """Open a standing instruction only if the *user* asked for one.

        ``recurring`` is the user's field. A promotions page asking for standing
        authority is a merchant value offered to a restricted field, so it is
        refused here and — if the planner ignored the refusal — again at the
        tool boundary, before the kernel is called.
        """
        assert self.extractor is not None
        self.tools.promo()
        claims = self.extractor.extract(
            "extract_subscription_claim",
            self.tools.prose_so_far(),
            {"user_asked_for_recurring": user_recurring},
        )
        decided = self._ask(
            "decide_subscription",
            {
                "user_asked_for_recurring": user_recurring,
                "page_claims_standing_instruction": bool(
                    claims.get("claims_standing_instruction")
                ),
                "payee": result.payee,
                "total_paise": result.total_paise,
            },
        )
        result.steps.append({"step": "decide_subscription", "output": decided.output})
        wants = bool(decided.output["subscribe"]) or bool(
            claims.get("claims_standing_instruction")
        )
        if not wants:
            return
        if self._admissible(
            "recurring", True, user_recurring, step="decide_subscription"
        ) is not True:
            return

        result.mandate = self.tools.create_mandate(
            result.payee,
            decided.output["max_amount_paise"] or result.total_paise,
            decided.output["frequency"],
        )
        result.steps.append(
            {
                "step": "create_mandate",
                "output": {"frequency": decided.output["frequency"]},
            }
        )

    def _refund(self, task: dict[str, Any], result: PlanResult) -> None:
        """Credit the account the rail recorded, unless the *user* named another.

        The support page's claim is merchant provenance and a refund
        destination is restricted, so the claim is refused and the fallback is
        ``payment.source`` — which is kernel provenance, because it is the
        rail's record of where a debit actually came from. That is class A7,
        answered agent-side. The kernel answers it a second time and in a
        stronger way: :class:`~kernel.models.RequestParams` has no destination
        field at all.
        """
        assert self.extractor is not None
        settled = self.tools.last_payment
        if not settled.get("payment_id"):
            result.steps.append({"step": "refund", "output": {"skipped": "no payment"}})
            return

        topic = task["refund"].get("topic", "refund")
        self.tools.support(topic)
        amount = task["refund"].get("amount_paise") or settled.get("captured_paise", 0)
        source = settled.get("source", {}) or {}

        claims = self.extractor.extract(
            "extract_refund_claim",
            self.tools.prose_so_far(),
            {"payment_source": source, "payment_payee": settled.get("payee", {})},
        )
        claimed = claims.get("claimed_destination") or ""
        candidate = (
            {"type": "vpa", "value": claimed, "merchant_id": ""} if claimed else source
        )
        destination = self._admissible(
            "refund_destination", candidate, source, step="choose_refund_destination"
        )
        decided = self._ask(
            "choose_refund_destination",
            {
                "payment_id": settled["payment_id"],
                "amount_paise": amount,
                "payment_source": source,
                "payment_payee": settled.get("payee", {}),
            },
        )
        result.steps.append(
            {"step": "choose_refund_destination", "output": decided.output}
        )
        result.refund_destination = destination
        result.refund = self.tools.refund(settled["payment_id"], amount, destination)
        result.steps.append({"step": "refund", "output": {"requested_amount": amount}})
