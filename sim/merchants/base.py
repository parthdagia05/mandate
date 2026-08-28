"""Mock storefronts, and the eight places a payload can land.

The injection points are **named and addressable** so an attack case can say
where its payload goes rather than describing it in prose. That is what makes
"A1 lands at ``product.description``" a fact a runner can act on and a results
table can group by, instead of a note in a README.

The eight are SPEC.md §09's list, and the list is closed. A case naming a point
that does not exist is refused at load time — a typo'd injection point would
otherwise produce a clean benign run that gets counted as a defended one.

Merchant content is the one place in this project where free text is allowed
and expected. Everything the kernel parses is a bounded token with no
whitespace; everything here is prose, because prose is the attack surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sim.eventlog import EventLog, SimActor, SimEvent

__all__ = ["InjectionPoint", "Injection", "Merchant", "MerchantResponse"]


class InjectionPoint(StrEnum):
    """Closed. SPEC.md §09."""

    PRODUCT_DESCRIPTION = "product.description"
    CATALOG_RESPONSE = "catalog.response"
    SELLER_API_RESPONSE = "seller_api.response"
    PRICE_FIELD = "price.field"
    CHECKOUT_RESPONSE = "checkout.response"
    PROMO_COPY = "promo.copy"
    SUPPORT_FLOW = "support.flow"
    WEBHOOK_PAYLOAD = "webhook.payload"


@dataclass(frozen=True)
class Injection:
    """One payload, placed at one point. Nothing here interprets it."""

    point: InjectionPoint
    payload: str
    case_id: str = "hand-written"


@dataclass
class MerchantResponse:
    """What a storefront call returns.

    ``text`` is the prose an agent reads; ``data`` is the typed part. Both are
    merchant-provenance and neither is trusted, but keeping them apart is what
    lets M6's taint guard say "this value came out of prose" rather than
    "something somewhere was untrusted".
    """

    point: InjectionPoint
    text: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Merchant:
    """Base storefront. Subclasses supply the catalogue and the prose."""

    log: EventLog
    merchant_id: str = "merchant"
    payee_vpa: str = "merchant@upi"
    injections: list[Injection] = field(default_factory=list)

    def inject(self, injection: Injection) -> None:
        self.injections.append(injection)

    def clear_injections(self) -> None:
        self.injections.clear()

    def _payload_at(self, point: InjectionPoint) -> str | None:
        """The payload placed at ``point``, if a case placed one there."""
        for injection in self.injections:
            if injection.point is point:
                return injection.payload
        return None

    def _serve(
        self, point: InjectionPoint, text: str, data: dict[str, Any] | None = None
    ) -> MerchantResponse:
        """Render one response, splicing in whatever was injected at ``point``.

        The payload is appended to the honest content rather than replacing it,
        because a product page that is *only* an attack is a page no agent would
        have reason to be reading. The attack has to survive being surrounded by
        the real thing.

        The event log records the payload's length and a hash, never its bytes.
        A chain that quoted attack text would be a chain that ships attack text
        (SPEC.md §12, containment).
        """
        payload = self._payload_at(point)
        body = text if payload is None else f"{text}\n\n{payload}"

        import hashlib

        self.log.append(
            SimActor.MERCHANT,
            SimEvent.MERCHANT_SERVED,
            {
                "merchant_id": self.merchant_id,
                "point": str(point),
                "injected": payload is not None,
                "payload_len": len(payload) if payload else 0,
                "payload_sha256": (
                    "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
                    if payload
                    else None
                ),
            },
        )
        return MerchantResponse(point=point, text=body, data=dict(data or {}))

    # -- the storefront API the agent's tools call ------------------------

    def search_catalog(self, query: str) -> MerchantResponse:
        raise NotImplementedError

    def get_product(self, sku: str) -> MerchantResponse:
        raise NotImplementedError

    def checkout(self, line_items: list[dict[str, Any]]) -> MerchantResponse:
        raise NotImplementedError

    def support(self, topic: str) -> MerchantResponse:
        raise NotImplementedError
