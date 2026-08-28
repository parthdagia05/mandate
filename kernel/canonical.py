"""RFC 8785 (JCS) canonicalisation, and the hashes built on it.

Locked on day one and not revisited. Every signature and every hash in the
project is taken over the byte string this module produces, so a change here
invalidates every fixture in ``fixtures/``.

The rules, from SPEC.md §05 "Canonicalisation":

1. UTF-8, lexicographic keys, no insignificant whitespace, shortest-roundtrip
   numbers.
2. All amounts integer. No float in any signed structure.
3. Signature input is ``JCS(object with "sig" removed)``.
4. ``cart_hash = SHA256(JCS({line_items, total_amount, payee}))`` with
   ``line_items`` sorted by ``(sku, unit_amount, qty)``.
5. Timestamps RFC 3339 UTC, second precision, ``Z`` suffix.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

__all__ = [
    "jcs",
    "jcs_bytes",
    "sha256_hex",
    "sha256_of",
    "signing_input",
    "normalise_for_signing",
    "sort_line_items",
    "cart_hash",
    "canonical_number",
    "CanonicalisationError",
]

#: Integers outside this range are not exactly representable as IEEE-754
#: doubles, so a JSON parser on the other side could not round-trip them.
#: RFC 8785 §3.2.2.3 keeps integer serialisation inside this window.
_MAX_SAFE_INTEGER = 2**53 - 1

_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


class CanonicalisationError(ValueError):
    """A value cannot be canonicalised deterministically."""


def canonical_number(value: int | float) -> str:
    """Serialise a number the way ECMAScript ``Number::toString`` does.

    RFC 8785 defers to ES6 number-to-string, which emits the shortest decimal
    that round-trips. ``1000``, ``1.0e3`` and ``1000.0`` all land on ``1000``,
    which is the property the two cart fixtures exercise.
    """
    if isinstance(value, bool):  # bool is an int subclass; catch it first
        raise CanonicalisationError("bool is not a number")

    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise CanonicalisationError(
                f"integer {value} is outside the IEEE-754 safe range and would "
                "not survive a JSON round-trip"
            )
        return str(value)

    if not isinstance(value, float):
        raise CanonicalisationError(f"not a number: {type(value).__name__}")
    if math.isnan(value) or math.isinf(value):
        raise CanonicalisationError("NaN and Infinity have no JSON form")
    if value == 0.0:
        return "0"  # covers -0.0, which ES renders as "0"
    if value < 0:
        return "-" + canonical_number(-value)

    digits, n = _decimal_parts(value)
    k = len(digits)

    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits

    exponent = n - 1
    sign = "+" if exponent >= 0 else "-"
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{mantissa}e{sign}{abs(exponent)}"


def _decimal_parts(value: float) -> tuple[str, int]:
    """Return ``(digits, n)`` with ``value == 0.<digits> * 10**n``.

    ``digits`` carries no leading or trailing zero, which is exactly the
    ``s``/``k``/``n`` triple ES6 defines. ``repr`` already gives us the shortest
    round-tripping decimal, so we only have to re-frame it.
    """
    text = repr(value)
    mantissa, _, exp_text = text.partition("e")
    exponent = int(exp_text) if exp_text else 0
    int_part, _, frac_part = mantissa.partition(".")

    raw = int_part + frac_part
    stripped = raw.lstrip("0")
    leading_zeros = len(raw) - len(stripped)
    n = len(int_part) + exponent - leading_zeros
    return stripped.rstrip("0") or "0", n


def _canonical_string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        short = _SHORT_ESCAPES.get(code)
        if short is not None:
            out.append(short)
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        elif 0xD800 <= code <= 0xDFFF:
            raise CanonicalisationError(
                "lone surrogate in string; input is not valid Unicode"
            )
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _sort_key(key: str) -> bytes:
    # RFC 8785 orders keys by UTF-16 code unit. Comparing UTF-16-BE bytes gives
    # exactly that order, which differs from Python's code-point order for
    # anything above the BMP.
    return key.encode("utf-16-be", errors="strict")


def _serialise(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_canonical_string(value))
    elif isinstance(value, (int, float)):
        out.append(canonical_number(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialise(item, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        keys = list(value.keys())
        for key in keys:
            if not isinstance(key, str):
                raise CanonicalisationError(
                    f"object key is not a string: {key!r}"
                )
        for i, key in enumerate(sorted(keys, key=_sort_key)):
            if i:
                out.append(",")
            out.append(_canonical_string(key))
            out.append(":")
            _serialise(value[key], out)
        out.append("}")
    else:
        raise CanonicalisationError(
            f"no canonical form for {type(value).__name__}"
        )


def jcs(value: Any) -> str:
    """Canonical JSON text for ``value``, per RFC 8785."""
    out: list[str] = []
    _serialise(value, out)
    return "".join(out)


def jcs_bytes(value: Any) -> bytes:
    """Canonical JSON bytes — this is what gets hashed and signed."""
    return jcs(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """``sha256:<hex>``, the one hash format used everywhere in the project."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_of(value: Any) -> str:
    """SHA-256 over the canonical form of ``value``."""
    return sha256_hex(jcs_bytes(value))


def normalise_for_signing(obj: dict[str, Any]) -> dict[str, Any]:
    """Apply the one array ordering the data model treats as non-semantic.

    RFC 8785 deliberately does not reorder arrays — array order is meaningful
    in JSON generally, so a canonicaliser must not touch it. But this project
    has already declared that line-item order carries no meaning: ``cart_hash``
    sorts them. If the signature did not sort them too, the same cart written
    two ways would agree on its hash and disagree on its signature, and the
    kernel would hold two different notions of "the same cart". So the
    application does here what the RFC correctly refuses to do generally.
    """
    if not isinstance(obj, dict):
        raise CanonicalisationError("signing input must be an object")
    items = obj.get("line_items")
    if isinstance(items, list) and all(
        isinstance(i, dict) and {"sku", "unit_amount", "qty"} <= set(i) for i in items
    ):
        return {**obj, "line_items": sort_line_items(items)}
    # Anything else is malformed and will fail schema validation anyway; leave
    # it untouched rather than guessing at an ordering for it.
    return obj


def signing_input(obj: dict[str, Any]) -> bytes:
    """The bytes a mandate signature covers: JCS of the object minus ``sig``."""
    normalised = normalise_for_signing(obj)
    return jcs_bytes({k: v for k, v in normalised.items() if k != "sig"})


def sort_line_items(line_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Line items in ``(sku, unit_amount, qty)`` order.

    The cart hash must not depend on the order the agent happened to build the
    cart in, so the ordering is imposed here rather than trusted from input.
    """
    return sorted(
        line_items,
        key=lambda item: (item["sku"], item["unit_amount"], item["qty"]),
    )


def cart_hash(
    line_items: list[dict[str, Any]],
    total_amount: int,
    payee: dict[str, Any],
) -> str:
    """``SHA256(JCS({line_items, total_amount, payee}))``.

    The three fields are the whole of what the user approved: what is being
    bought, for how much, and to whom. Nothing else belongs in the binding —
    adding a field here would let a merchant change the hash without changing
    the purchase.
    """
    return sha256_of(
        {
            "line_items": sort_line_items(line_items),
            "payee": payee,
            "total_amount": total_amount,
        }
    )
