"""The strict base every schema in the project inherits.

Two settings carry the whole anti-prompt property (SPEC.md §07):

``extra="forbid"``
    An unknown field is a 422, never a silently ignored one. An attacker who
    can add a field to a request cannot smuggle one past the parser.
``strict=True``
    ``"1000"`` is not ``1000`` and ``1`` is not ``True``. Coercion is where a
    parser's opinion substitutes for the sender's, and that opinion is
    attacker-influenced here.

Together with the constrained scalar types below there is nowhere in any body
to put a sentence: every string field is a bounded token with no whitespace.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, TypeVar

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
)

from kernel.canonical import jcs_bytes, sha256_of
from kernel.clock import RFC3339_PATTERN
from kernel.ids import id_pattern

__all__ = [
    "StrictModel",
    "closed_enum",
    "Paise",
    "Rfc3339",
    "Sha256",
    "Token",
    "B64u",
    "PubKey",
    "Currency",
    "Nonce",
    "IntentId",
    "CartId",
    "PaymentId",
    "RefundId",
]


_EnumT = TypeVar("_EnumT", bound=StrEnum)


def closed_enum(enum_cls: type[_EnumT]) -> Any:
    """A closed enum that still reads from JSON.

    ``strict=True`` would otherwise demand an actual enum member, which no
    JSON body can carry. This accepts the member's string value and nothing
    else — an unknown value names the members it could have been, because a
    silent fallback to a default is how an unrecognised action becomes an
    allowed one.
    """
    allowed = [member.value for member in enum_cls]

    def _coerce(value: Any) -> Any:
        if isinstance(value, enum_cls):
            return value
        if isinstance(value, str):
            try:
                return enum_cls(value)
            except ValueError:
                raise ValueError(
                    f"{value!r} is not a {enum_cls.__name__}; allowed: {allowed}"
                ) from None
        raise ValueError(f"{enum_cls.__name__} must be given as a string")

    return Annotated[enum_cls, BeforeValidator(_coerce)]


def _paise(value: Any) -> Any:
    """Accept an integer number of paise, and nothing that merely looks like one.

    A float is accepted only when it is exactly integral — that is what lets
    ``1.0e3`` in a JSON fixture mean the same thing as ``1000`` while
    ``10.5`` is still a hard error. No amount anywhere is stored as a float.
    """
    if isinstance(value, bool):
        raise ValueError("a boolean is not an amount")
    if isinstance(value, float):
        if not value.is_integer():
            raise ValueError(
                f"amount {value!r} is not a whole number of paise; "
                "money is integer paise everywhere"
            )
        return int(value)
    return value


#: Money. Integer paise, never negative, never a float in a signed structure.
Paise = Annotated[int, BeforeValidator(_paise), Field(ge=0)]

#: The one accepted timestamp form: RFC 3339 UTC, second precision, ``Z``.
Rfc3339 = Annotated[str, StringConstraints(pattern=RFC3339_PATTERN)]

#: Every hash in the project, prefixed so its algorithm travels with it.
Sha256 = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]

#: An identifier-shaped string: bounded, and with no whitespace, so no field
#: typed this way can hold a sentence.
Token = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:@/+-]+$"),
]

#: base64url, unpadded.
B64u = Annotated[
    str, StringConstraints(min_length=1, max_length=1024, pattern=r"^[A-Za-z0-9_-]+$")
]

#: An ECDSA P-256 public key as base64url of its DER SubjectPublicKeyInfo. PEM
#: would carry newlines, and no field in a signed structure holds a newline.
PubKey = B64u

#: 128 bits of base64url is 22 characters unpadded.
Nonce = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{22}$")]

Currency = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]

IntentId = Annotated[str, StringConstraints(pattern=id_pattern("im"))]
CartId = Annotated[str, StringConstraints(pattern=id_pattern("cm"))]
PaymentId = Annotated[str, StringConstraints(pattern=id_pattern("pay"))]
RefundId = Annotated[str, StringConstraints(pattern=id_pattern("rfn"))]


class StrictModel(BaseModel):
    """Frozen, strict, closed. Every schema in the project starts here."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        revalidate_instances="always",
    )

    def canonical_dict(self) -> dict[str, Any]:
        """JSON-typed dict, ready for :func:`kernel.canonical.jcs`."""
        return self.model_dump(mode="json")

    def canonical_bytes(self) -> bytes:
        return jcs_bytes(self.canonical_dict())

    def digest(self) -> str:
        return sha256_of(self.canonical_dict())
