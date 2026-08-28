"""Payee normalisation, and the very short list of differences it forgives.

Check 2 is a byte equality against an allowlist. The only question this module
answers is *which bytes*, and the answer has to be small enough to argue about
in one sitting — every rule added here is a way for two different addresses to
be treated as one.

**One rule, for VPAs only: ASCII case.** UPI virtual payment addresses are
case-insensitive, so ``Merchant@UPI`` and ``merchant@upi`` are the same
account and refusing that would be a false block on an honest merchant.
Nothing else is forgiven.

What is deliberately *not* forgiven, and why each one is an attack rather than
a typo:

* **Unicode.** A value containing any non-ASCII character does not normalise;
  it compares equal to nothing. Case folding ``А`` (Cyrillic) or applying NFKC
  to ``ｍｅｒｃｈａｎｔ`` would map a lookalike onto the real address, which is
  the entire homoglyph attack handed a helper function.
* **Whitespace.** Not stripped. A schema-level ``Token`` cannot contain any, so
  a value that has some did not come from a well-formed request.
* **Dots and plus-tags.** Gmail's ``a.b+tag@`` folding is an email convention,
  not a UPI one. Folding them would make ``merchant.settlements@upi`` equal to
  ``merchantsettlements@upi``, and an attacker who can register either owns
  both.
* **Substrings, prefixes, edit distance.** No fuzzy matching of any kind. A
  match that is "close enough" is a match an attacker can aim at.

Non-VPA account types normalise to themselves: a bank account number and a card
token are opaque identifiers where no two spellings are the same account.
"""

from __future__ import annotations

from typing import Any

from kernel.enums import PayeeType

__all__ = ["normalise_account", "accounts_equal", "account_in"]


def _is_ascii(value: str) -> bool:
    return value.isascii()


def normalise_account(account_type: str, value: str) -> str | None:
    """The bytes check 2 compares, or ``None`` when there are none.

    ``None`` is not an error and not a default — it is "this value cannot be
    put into the compared form", and a value in that position compares equal to
    nothing at all, including to another unnormalisable value. Returning the
    input unchanged instead would let two differently-broken addresses match.
    """
    if not _is_ascii(value):
        # A lookalike is not a spelling of the real thing. Refusing to
        # normalise is how it stays unequal rather than being folded onto it.
        return None

    if account_type == PayeeType.VPA:
        if value.count("@") != 1:
            return None
        local, _, handle = value.partition("@")
        if not local or not handle:
            return None
        return f"{local.lower()}@{handle.lower()}"

    return value


def accounts_equal(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Byte equality of two ``{type, value}`` accounts after normalisation.

    ``merchant_id`` is deliberately not compared. It is merchant-provenance
    display metadata; an attacker who could make the comparison depend on it
    would only have to claim the right shop name.
    """
    if left.get("type") != right.get("type"):
        return False
    left_value = normalise_account(str(left.get("type")), str(left.get("value", "")))
    right_value = normalise_account(str(right.get("type")), str(right.get("value", "")))
    if left_value is None or right_value is None:
        return False
    return left_value == right_value


def account_in(candidate: dict[str, Any], allowlist: list[dict[str, Any]]) -> bool:
    """Whether ``candidate`` is one of ``allowlist``. Exact, after normalisation."""
    return any(accounts_equal(candidate, entry) for entry in allowlist)
