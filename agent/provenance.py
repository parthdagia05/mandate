"""Where a value came from, and which fields will accept it.

Two mechanisms, and they are separate on purpose.

**Provenance** is a label on a *value*: did the user say it, did the kernel or
the payment rail record it, or did a merchant write it? It is **sticky** — a
label never improves by being copied — and **transitive**: anything computed
from a merchant value is a merchant value. There is no sanitiser and no
laundering step, because every laundering step anyone has ever written has
eventually been the hole.

**Field admission** is a rule about a *destination*: which provenances a named
field on a money-moving tool call will accept. ``payee``, ``allowed_payees``,
``max_amount``, ``max_transactions``, ``recurring`` and a refund destination
accept ``user`` or ``kernel`` only. ``sku``, ``qty`` and ``unit_amount`` accept
``merchant`` too, because those are **proposals**: a storefront is allowed to
say what it sells and what it costs. What a proposal can then *do* is bounded
by checks 3 and 4 in the kernel, not here.

A merchant value reaching a restricted field is a :class:`FieldAdmissionError`
raised **at the tool boundary, before the kernel is called at all**. That
ordering is deliberate and it is also the reason this is not the contribution:
the guard is agent-side, the agent is the system under test, and an adversarial
agent simply would not run it. Every guarantee this project makes has to hold
with the guard removed — which is exactly what the ``kernel`` arm measures,
because that arm runs the *undefended* agent (SPEC.md §17.7). The guard is
defence in depth and ``results.md`` reports it as a separate arm rather than
folding it into the kernel's numbers.

**How provenance is decided, honestly.** This is a dynamically typed program and
there is no taint tracking in the interpreter, so the label is decided by
*declaration and observation*:

* values the task declares — the utterance, the scope, the signed intent's
  ``allowed_payees``, the quantities the user asked for — are declared ``user``
  before a single merchant byte is read;
* values the payment rail hands back — a payment id, the source account a debit
  actually came from — are declared ``kernel``, because the rail's record of
  what it did is not something a storefront can write;
* every byte of every merchant response is observed as ``merchant``;
* anything else is ``unknown``, and unknown is **treated as merchant**.

The one subtlety is a value that is both: the checkout page says
``merchant@upi`` and so does the user's signed allowlist. That value is
``user``, and not because merchant content was trusted — because the user
already named it. A page repeating an address that is already on the record is
not a direction to use it, in exactly the way ``sim/merchants/shopkart.py``'s
checkout prose repeating its own payee is not one. Put the other way round: the
merchant may *select from* what the user authorised; it may not *introduce*.
:meth:`TaintLedger.admit` implements that as one rule rather than as a special
case per field.

**What this cannot do.** It is value-based, so two different fields carrying the
same string are indistinguishable, and a merchant that guesses a user-declared
value exactly gets it admitted. That is not a weakness worth patching here — a
merchant that has guessed the user's own allowlist entry has not redirected
anything — but it is the honest statement of the mechanism, and ``results.md``
states it rather than describing this as taint tracking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

__all__ = [
    "Provenance",
    "RESTRICTED_FIELDS",
    "PROPOSAL_FIELDS",
    "FIELD_ADMISSION",
    "FIELD_KEYS",
    "COMPOSITE_FIELDS",
    "FieldAdmissionError",
    "TaintLedger",
    "combine",
    "tokenise",
]


class Provenance(str, Enum):
    """Who stands behind a value. Ordered by trust, most trusted first."""

    USER = "user"
    KERNEL = "kernel"
    MERCHANT = "merchant"
    #: Never seen anywhere trusted. Treated as :attr:`MERCHANT` everywhere a
    #: decision is made — fail closed, because a value with no provenance is a
    #: value nobody vouched for.
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


#: How restrictive each label is. :func:`combine` takes the maximum, which is
#: what makes taint sticky and transitive in one line.
_RANK: dict[Provenance, int] = {
    Provenance.USER: 0,
    Provenance.KERNEL: 1,
    Provenance.MERCHANT: 2,
    Provenance.UNKNOWN: 3,
}


def combine(*provenances: Provenance) -> Provenance:
    """The provenance of something computed from all of these.

    The *worst* of them, always. This is the whole of "sticky and transitive":
    a total computed from a user-declared quantity and a merchant-declared
    price is a merchant value, and there is no arrangement of arguments that
    makes it anything else.
    """
    if not provenances:
        return Provenance.UNKNOWN
    return max(provenances, key=lambda p: _RANK[p])


#: Fields that accept ``user`` or ``kernel`` provenance only.
#:
#: Each of these names an *authority*, not a fact about the world. A payee is
#: who the user agreed to pay; a cap is how much they agreed to; ``recurring``
#: is whether they agreed to standing authority at all. A merchant writing any
#: of them is not proposing — it is granting itself permission, which is the
#: shape of every one of the seven attack classes that this guard can see.
RESTRICTED_FIELDS: frozenset[str] = frozenset(
    {
        "payee",
        "allowed_payees",
        "max_amount",
        "max_transactions",
        "recurring",
        "refund_destination",
    }
)

#: Fields a merchant may write, because they are proposals about the merchant's
#: own goods. ``sku`` is what is being sold, ``qty`` how many, ``unit_amount``
#: what it costs. All three go to the kernel as claims and checks 3 and 4 bound
#: what they can do — an inflated ``unit_amount`` is class A2 and is refused by
#: the amount lattice, not by refusing to let a shop quote a price.
PROPOSAL_FIELDS: frozenset[str] = frozenset({"sku", "qty", "unit_amount"})

#: The policy, as one table. Anything not named here is restricted: a field
#: nobody has classified is a field nobody has thought about, and defaulting an
#: unclassified field to "merchant may write it" is how a policy quietly stops
#: covering the thing that was added last.
FIELD_ADMISSION: dict[str, frozenset[Provenance]] = {
    **{f: frozenset({Provenance.USER, Provenance.KERNEL}) for f in RESTRICTED_FIELDS},
    **{
        f: frozenset({Provenance.USER, Provenance.KERNEL, Provenance.MERCHANT})
        for f in PROPOSAL_FIELDS
    },
}


class FieldAdmissionError(ValueError):
    """A value reached a field its provenance is not admitted to.

    A hard error, raised at the tool boundary and before the kernel. Not a
    warning and not a silent substitution: a guard that quietly replaced the
    value would make the agent arm's behaviour depend on a repair nobody
    audited, and a run in which the guard fired has to be visible *as a
    refusal* in the record. The caller decides what to do about it — the
    defended agent falls back to the user-provenance value and writes down that
    it did.
    """

    def __init__(
        self, field_name: str, value: Any, provenance: Provenance, admitted: Iterable[Provenance]
    ) -> None:
        self.field_name = field_name
        self.value = value
        self.provenance = provenance
        self.admitted = frozenset(admitted)
        super().__init__(
            f"field {field_name!r} accepts {sorted(str(p) for p in self.admitted)} "
            f"provenance; {value!r} is {provenance}. A merchant value reaching a "
            "restricted field is refused at the tool boundary, before the kernel."
        )


#: Which sub-keys of a structured field actually decide admission.
#:
#: An account is ``{type, value, merchant_id}`` and only ``value`` names the
#: account. ``type`` is a tag from a closed schema enum — neither party's claim
#: — and ``merchant_id`` is legitimately the merchant's, which is the point: a
#: rule that looked at every string in the object would refuse the *benign*
#: payee, because its ``merchant_id`` is a merchant value and taint is sticky.
#: Sticky taint over a composite is right; the fix is to be precise about which
#: part of the composite is the authority, not to soften the rule.
FIELD_KEYS: dict[str, tuple[str, ...]] = {
    "payee": ("value",),
    "refund_destination": ("value",),
    "allowed_payees": ("value",),
}

#: Fields that are *containers* of other named fields, and what they contain.
#:
#: ``line_items`` is not itself an authority — it is a list of proposals, each
#: made of three fields that already have a policy. Admitting it as one opaque
#: value would fall through to the restricted default and refuse every basket
#: with a merchant SKU in it, which is to say every basket. Decomposing it is
#: not a softening of the rule: each part is still checked, against its own row
#: of :data:`FIELD_ADMISSION`.
COMPOSITE_FIELDS: dict[str, tuple[str, ...]] = {
    "line_items": ("sku", "qty", "unit_amount"),
}

#: Tokens inside a piece of prose. Deliberately generous about ``@``, ``.``,
#: ``-`` and ``_`` so a VPA, an ordinary email and a SKU each come out as one
#: token — a tokeniser that split ``attacker@upi`` into two words would never
#: match it against a payee field and the guard would silently pass everything.
_TOKEN = re.compile(r"[A-Za-z0-9\u0080-\uffff][A-Za-z0-9._@+\-\u0080-\uffff]*")


def tokenise(text: str) -> set[str]:
    """The whole string, plus every token in it.

    Both, because the two match different things. Merchant *data* fields hold a
    payee as a whole string; merchant *prose* holds the same payee inside a
    sentence, and only the token form of that sentence will ever equal the
    value later offered to a field.
    """
    out = {text}
    out.update(_TOKEN.findall(text))
    return out


def _strings(obj: Any) -> list[str]:
    """Every scalar inside a nested structure, rendered as text.

    Numbers are included because a price is a value a merchant writes and an
    amount is a value a user declares, and the two have to be comparable.
    ``44900`` observed in a product page and ``44900`` proposed as a
    ``unit_amount`` are the same value, and a ledger that only looked at
    strings would call the second one unknown.
    """
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, bool):
        out.append("true" if obj else "false")
    elif isinstance(obj, (int, float)):
        out.append(str(obj))
    elif isinstance(obj, dict):
        for value in obj.values():
            out.extend(_strings(value))
    elif isinstance(obj, (list, tuple, set)):
        for value in obj:
            out.extend(_strings(value))
    return out


def _deciding(field_name: str, value: Any) -> list[str]:
    """The strings that decide admission for ``field_name``.

    :data:`FIELD_KEYS` narrows a structured field to the part that carries the
    authority; everything else is decided on the whole value.
    """
    keys = FIELD_KEYS.get(field_name)
    if keys is None:
        return _strings(value)

    def parts(item: Any) -> list[str]:
        if isinstance(item, dict):
            return [
                text for key in keys if key in item for text in _strings(item[key])
            ]
        return _strings(item)

    if isinstance(value, (list, tuple)):
        return [text for item in value for text in parts(item)]
    return parts(value)


@dataclass
class TaintLedger:
    """What has been declared, what has been observed, and what may be admitted.

    One per run. Declarations happen before the first tool call — that ordering
    is what "control flow fixed by the planner before any untrusted byte is
    read" means for *values* — and observations accumulate as the storefront
    answers.
    """

    #: Values the user said, or that the ceremony signed on their behalf.
    user: set[str] = field(default_factory=set)
    #: Values the payment rail or the kernel recorded. Not the merchant's to
    #: write: a debit's source account is a fact about a movement of money.
    kernel: set[str] = field(default_factory=set)
    #: Every string that has appeared in a merchant response this run.
    merchant: set[str] = field(default_factory=set)
    #: One entry per admission refusal, in order. The record carries these so
    #: "the guard fired" is an event rather than an inference from an agent
    #: that happened to behave.
    refusals: list[dict[str, Any]] = field(default_factory=list)

    # -- declaring --------------------------------------------------------

    def declare_user(self, obj: Any) -> None:
        """Label everything in ``obj`` as user provenance.

        Called with the task and the signed intent, before any tool runs. A
        declaration made *after* a merchant response had been observed would
        still work — user beats merchant in :meth:`provenance_of` — but it
        would mean the guard's answer depended on call order, and an ordering
        dependency in a security check is a bug waiting for a refactor.
        """
        for text in _strings(obj):
            self.user.update(tokenise(text))

    def declare_kernel(self, obj: Any) -> None:
        """Label everything in ``obj`` as kernel/rail provenance."""
        for text in _strings(obj):
            self.kernel.update(tokenise(text))

    def observe_merchant(self, obj: Any) -> None:
        """Label everything in ``obj`` as merchant provenance.

        Called on every storefront response, prose and typed data alike. The
        typed half is included deliberately: a checkout page's ``payee`` field
        is a merchant value even though it is typed, and treating typed
        merchant content as trustworthy is the assumption A1 is built on.
        """
        for text in _strings(obj):
            self.merchant.update(tokenise(text))

    # -- deciding ---------------------------------------------------------

    def provenance_of(self, value: Any, *, field_name: str | None = None) -> Provenance:
        """The label on one scalar value.

        User beats kernel beats merchant, and a value nobody declared is
        ``unknown``. The precedence is not "most trusted wins" as a
        convenience — it is the rule that the merchant may select from what the
        user authorised but may not introduce. A string the user already named
        is the user's, however many times a product page repeats it.
        """
        texts = _deciding(field_name, value) if field_name else _strings(value)
        worst = Provenance.USER
        for text in texts:
            if text in self.user:
                label = Provenance.USER
            elif text in self.kernel:
                label = Provenance.KERNEL
            elif text in self.merchant:
                label = Provenance.MERCHANT
            else:
                label = Provenance.UNKNOWN
            worst = combine(worst, label)
        return worst

    def admit(self, field_name: str, value: Any) -> Any:
        """Return ``value`` if ``field_name`` accepts its provenance, else raise.

        An unclassified field is restricted. See :data:`FIELD_ADMISSION` — a
        field nobody has classified is a field nobody has thought about, and
        the safe default for one of those is "no".

        A composite named in :data:`COMPOSITE_FIELDS` is decomposed and each
        part is admitted against its own row.
        """
        contents = COMPOSITE_FIELDS.get(field_name)
        if contents is not None:
            for item in value or []:
                for key in contents:
                    if isinstance(item, dict) and key in item:
                        self.admit(key, item[key])
            return value

        admitted = FIELD_ADMISSION.get(
            field_name, frozenset({Provenance.USER, Provenance.KERNEL})
        )
        provenance = self.provenance_of(value, field_name=field_name)
        effective = (
            Provenance.MERCHANT if provenance is Provenance.UNKNOWN else provenance
        )
        if effective not in admitted:
            self.refusals.append(
                {
                    "field": field_name,
                    "value": value,
                    "provenance": str(provenance),
                    "admitted": sorted(str(p) for p in admitted),
                }
            )
            raise FieldAdmissionError(field_name, value, provenance, admitted)
        return value

    def admits(self, field_name: str, value: Any) -> bool:
        """:meth:`admit` without the exception, for a caller choosing a fallback.

        Does **not** record a refusal. The refusal log is a record of values
        that were *offered to a field and rejected*, and a planner asking "would
        this be admitted?" before offering it has not offered anything yet.
        """
        contents = COMPOSITE_FIELDS.get(field_name)
        if contents is not None:
            return all(
                self.admits(key, item[key])
                for item in value or []
                for key in contents
                if isinstance(item, dict) and key in item
            )

        admitted = FIELD_ADMISSION.get(
            field_name, frozenset({Provenance.USER, Provenance.KERNEL})
        )
        provenance = self.provenance_of(value, field_name=field_name)
        effective = (
            Provenance.MERCHANT if provenance is Provenance.UNKNOWN else provenance
        )
        return effective in admitted

    def summary(self) -> dict[str, Any]:
        """What the guard did this run, for the run record."""
        return {
            "declared_user": len(self.user),
            "declared_kernel": len(self.kernel),
            "observed_merchant": len(self.merchant),
            "refusals": list(self.refusals),
        }
