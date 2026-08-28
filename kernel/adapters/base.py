"""The PSP boundary — the only place money moves (REQ-1).

Two implementations sit behind this protocol: the deterministic simulator that
every published number comes from, and a Razorpay test-mode adapter kept for
credibility rather than for numbers. The kernel is written against the
protocol so neither can be special-cased in the enforcement path.

**Why the return types are protocols and not** ``kernel.models.Payment``.
M1 typed them as the kernel's own ``Payment``, which conflated two records that
only look alike. A PSP knows an order, an amount, a payee and a state; it has
never heard of an IntentMandate and cannot populate ``mandate_id`` or
``cart_hash``. The kernel's ``Payment`` is the *binding* of a PSP payment to
the authority that permitted it, and building that binding is the kernel's job,
not the adapter's — an adapter that could mint a ``mandate_id`` would be an
adapter that could mint authority. So the adapter returns the PSP's view and
the kernel constructs its own record from it.

The views are structural rather than concrete classes so that a real PSP's SDK
object can satisfy one without being copied into a schema first.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from kernel.enums import PaymentState, RefundState
from kernel.models import Account

__all__ = ["PspOrder", "PspPayment", "PspRefund", "PSPAdapter"]


class PspOrder(Protocol):
    order_id: str
    amount_paise: int
    currency: str
    #: The caller's own reference. The recovery path polls by this, because
    #: after a crash it is the only identifier the kernel is certain it had.
    client_ref: str


class PspPayment(Protocol):
    payment_id: str
    order_id: str
    amount_paise: int
    currency: str
    state: PaymentState
    #: Where the money went. Not on the kernel's ``Payment``, which carries a
    #: ``cart_hash`` and reads the payee from the cart that hash commits to.
    payee: Account
    #: Where the money came from. Check 8 copies a refund destination from
    #: here and ignores whatever the request wanted, which is class A7.
    source: Account
    client_ref: str


class PspRefund(Protocol):
    refund_id: str
    payment_id: str
    amount_paise: int
    destination: Account
    state: RefundState


@runtime_checkable
class PSPAdapter(Protocol):
    def create_order(
        self, amount_paise: int, currency: str, ref: str
    ) -> PspOrder: ...

    def authorize(self, order_id: str, instrument: str, idem: str) -> PspPayment: ...

    def capture(self, payment_id: str, amount_paise: int, idem: str) -> PspPayment: ...

    def refund(
        self, payment_id: str, amount_paise: int, dest: Account, idem: str
    ) -> PspRefund: ...

    #: The recovery path. A reserved-but-unknown idempotency row polls here by
    #: client_ref rather than blindly retrying or silently skipping.
    def poll(self, client_ref: str) -> PspPayment | None: ...
