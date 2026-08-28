"""The PSP boundary — the only place money moves (REQ-1).

Two implementations sit behind this protocol: the deterministic simulator that
every published number comes from, and a Razorpay test-mode adapter kept for
credibility rather than for numbers. The kernel is written against the
protocol so neither can be special-cased in the enforcement path.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from kernel.models import Account, Payment, Refund

__all__ = ["Order", "PSPAdapter"]


class Order(Protocol):
    order_id: str
    amount_paise: int
    currency: str


@runtime_checkable
class PSPAdapter(Protocol):
    def create_order(self, amount_paise: int, currency: str, ref: str) -> Order: ...

    def authorize(self, order_id: str, instrument: str, idem: str) -> Payment: ...

    def capture(self, payment_id: str, amount_paise: int, idem: str) -> Payment: ...

    def refund(
        self, payment_id: str, amount_paise: int, dest: Account, idem: str
    ) -> Refund: ...

    #: The recovery path. A reserved-but-unknown idempotency row polls here by
    #: client_ref rather than blindly retrying or silently skipping.
    def poll(self, client_ref: str) -> Payment | None: ...
