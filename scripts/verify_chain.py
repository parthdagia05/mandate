#!/usr/bin/env python3
"""Standalone audit-chain verifier.

    python3 verify_chain.py chain.jsonl

Prints ``OK, <n> entries, head sha256:...`` and exits 0, or prints
``BROKEN at seq <n>: <why>`` and exits 1.

**This file imports nothing from the project.** Copy it into an empty
directory and it still works, which is the point (REQ-9): a verifier that
imports the kernel it is checking would inherit the kernel's bugs and any
tampering the kernel's own code could hide. It therefore carries its own RFC
8785 implementation — deliberate duplication, not an oversight. If the two
implementations ever disagree, that disagreement is itself the finding.

Chain format, one JSON object per line:

    {"seq":0,"ts":"2026-01-01T00:00:00Z","actor":"kernel",
     "action":"intent.registered","payload":{...},
     "prev_hash":"sha256:00...0","entry_hash":"sha256:..."}

Rule: entry_hash = SHA256(seq ‖ ts ‖ actor ‖ action ‖ JCS(payload) ‖ prev_hash)
with U+001F between fields, UTF-8 encoded; seq starts at 0 and increments by
one; prev_hash of seq 0 is 64 zeros; every later prev_hash is the previous
entry_hash.
"""

from __future__ import annotations

import hashlib
import json
import math
import sys

GENESIS_HASH = "sha256:" + "0" * 64
FIELD_SEPARATOR = "\x1f"
REQUIRED_KEYS = frozenset(
    {"seq", "ts", "actor", "action", "payload", "prev_hash", "entry_hash"}
)
MAX_SAFE_INTEGER = 2**53 - 1

_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


# --------------------------------------------------------------------------
# RFC 8785 (JCS), independently implemented. See the module docstring.
# --------------------------------------------------------------------------


def _number(value):
    if isinstance(value, bool):
        raise ValueError("bool is not a number")
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("integer outside the IEEE-754 safe range")
        return str(value)
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity have no JSON form")
    if value == 0.0:
        return "0"
    if value < 0:
        return "-" + _number(-value)

    text = repr(value)
    mantissa, _, exp_text = text.partition("e")
    exponent = int(exp_text) if exp_text else 0
    int_part, _, frac_part = mantissa.partition(".")
    raw = int_part + frac_part
    stripped = raw.lstrip("0")
    n = len(int_part) + exponent - (len(raw) - len(stripped))
    digits = stripped.rstrip("0") or "0"
    k = len(digits)

    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    mant = digits if k == 1 else digits[0] + "." + digits[1:]
    return "%se%s%d" % (mant, "+" if e >= 0 else "-", abs(e))


def _string(value):
    out = ['"']
    for ch in value:
        code = ord(ch)
        if code in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[code])
        elif code < 0x20:
            out.append("\\u%04x" % code)
        elif 0xD800 <= code <= 0xDFFF:
            raise ValueError("lone surrogate")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValueError("object key is not a string")
        # RFC 8785 orders keys by UTF-16 code unit, which is what comparing
        # UTF-16-BE bytes gives; that differs from code-point order above the BMP.
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + jcs(value[k]) for k in keys) + "}"
    raise ValueError("no canonical form for %s" % type(value).__name__)


# --------------------------------------------------------------------------


def entry_hash(seq, ts, actor, action, payload, prev_hash):
    preimage = FIELD_SEPARATOR.join(
        [str(seq), ts, actor, action, jcs(payload), prev_hash]
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


class Broken(Exception):
    def __init__(self, seq, detail):
        Exception.__init__(self, detail)
        self.seq = seq
        self.detail = detail


def verify(lines):
    """Return ``(count, head_hash)`` or raise :class:`Broken`."""
    expected_seq = 0
    prev_hash = GENESIS_HASH
    count = 0

    for line_number, raw in enumerate(lines):
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except ValueError as exc:
            raise Broken(expected_seq, "line %d is not JSON: %s" % (line_number + 1, exc))
        if not isinstance(entry, dict):
            raise Broken(expected_seq, "line %d is not an object" % (line_number + 1))

        keys = set(entry)
        if keys != REQUIRED_KEYS:
            missing = sorted(REQUIRED_KEYS - keys)
            extra = sorted(keys - REQUIRED_KEYS)
            raise Broken(
                entry.get("seq", expected_seq),
                "wrong fields (missing %s, unexpected %s)" % (missing, extra),
            )

        seq = entry["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise Broken(expected_seq, "seq is not an integer")
        if seq != expected_seq:
            raise Broken(seq, "out of order, expected seq %d" % expected_seq)
        if entry["prev_hash"] != prev_hash:
            raise Broken(seq, "prev_hash does not match the entry before it")

        try:
            recomputed = entry_hash(
                seq,
                entry["ts"],
                entry["actor"],
                entry["action"],
                entry["payload"],
                entry["prev_hash"],
            )
        except (ValueError, TypeError) as exc:
            raise Broken(seq, "payload cannot be canonicalised: %s" % exc)

        if recomputed != entry["entry_hash"]:
            raise Broken(seq, "entry_hash does not match its contents")

        prev_hash = entry["entry_hash"]
        expected_seq += 1
        count += 1

    if count == 0:
        raise Broken(0, "chain is empty")

    return count, prev_hash


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        sys.stderr.write("usage: verify_chain.py <chain.jsonl>\n")
        return 2

    try:
        with open(argv[0], "r", encoding="utf-8") as handle:
            count, head = verify(handle)
    except OSError as exc:
        sys.stderr.write("cannot read %s: %s\n" % (argv[0], exc))
        return 2
    except Broken as exc:
        sys.stdout.write("BROKEN at seq %d: %s\n" % (exc.seq, exc.detail))
        return 1

    sys.stdout.write("OK, %d entries, head %s\n" % (count, head))
    return 0


if __name__ == "__main__":
    sys.exit(main())
