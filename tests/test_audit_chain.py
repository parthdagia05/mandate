"""U-16, F-06, P-07 — the chain, and what makes an edit to it detectable.

Every later claim in this project reduces to "the chain says so". These tests
are what make that sentence mean something.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from kernel.audit.chain import (
    GENESIS_HASH,
    AuditChain,
    ChainBroken,
    compute_entry_hash,
    entry_to_export_line,
)
from kernel.audit.verify import verify_entries
from kernel.canonical import jcs
from kernel.clock import Clock
from kernel.enums import AuditAction, AuditActor
from kernel.models import AuditEntry
from kernel.stores.db import connect


@pytest.fixture
def chain(tmp_path):
    clock = Clock()
    conn = connect(tmp_path / "audit.db")
    try:
        yield AuditChain(conn, clock), clock
    finally:
        conn.close()


def _append_some(chain, clock, count=5):
    entries = []
    for i in range(count):
        entries.append(
            chain.append(
                AuditActor.KERNEL,
                AuditAction.AUTHORIZE_ALLOW,
                {
                    "mandate_id": f"im_{i:026d}",
                    "decision": "allow",
                    "reason_code": "OK",
                    "checks": [
                        {"id": 1, "name": "mandate_integrity", "result": "pass"},
                        {"id": 2, "name": "payee_allowlist", "result": "pass"},
                    ],
                },
            )
        )
        clock.advance(1)
    return entries


# --------------------------------------------------------------------------
# U-16 — the entry hash matches the formula
# --------------------------------------------------------------------------


def test_u16_entry_hash_matches_the_published_formula(chain):
    ch, clock = chain
    entry = _append_some(ch, clock, 1)[0]

    preimage = "\x1f".join(
        [
            str(entry.seq),
            entry.ts,
            str(entry.actor),
            str(entry.action),
            jcs(entry.payload),
            entry.prev_hash,
        ]
    ).encode("utf-8")
    assert entry.entry_hash == "sha256:" + hashlib.sha256(preimage).hexdigest()


def test_u16_first_entry_chains_from_genesis(chain):
    ch, clock = chain
    entry = _append_some(ch, clock, 1)[0]
    assert entry.seq == 0
    assert entry.prev_hash == GENESIS_HASH


def test_u16_each_entry_chains_to_the_one_before(chain):
    ch, clock = chain
    entries = _append_some(ch, clock, 4)
    for previous, current in zip(entries, entries[1:]):
        assert current.prev_hash == previous.entry_hash
        assert current.seq == previous.seq + 1


def test_the_separator_prevents_a_field_boundary_collision():
    """Without a separator, ``seq=1, ts="1..."`` and ``seq=11, ts="..."`` would
    hash alike — a collision an attacker could aim at."""
    payload = {"a": 1}
    first = compute_entry_hash(1, "12026-01-01T00:00:00Z", "kernel", "authorize.allow", payload, GENESIS_HASH)
    second = compute_entry_hash(11, "2026-01-01T00:00:00Z", "kernel", "authorize.allow", payload, GENESIS_HASH)
    assert first != second


# --------------------------------------------------------------------------
# SPEC.md §15 — no non-deterministic value enters the payload
# --------------------------------------------------------------------------


def test_raw_signature_bytes_are_refused_in_a_payload(chain):
    """ECDSA is not deterministic, so hashing a signature would break REQ-3.

    The guard raises rather than silently stripping: a caller putting a
    signature in a payload has misunderstood something, and hiding that helps
    nobody.
    """
    ch, _ = chain
    with pytest.raises(ValueError, match="never enter an audit payload"):
        ch.append(
            AuditActor.KERNEL, AuditAction.AUTHORIZE_ALLOW, {"sig": "abcd", "a": 1}
        )


def test_passes_are_recorded_not_only_failures(chain):
    """The per-check ablation is only readable because of this."""
    ch, clock = chain
    entry = _append_some(ch, clock, 1)[0]
    results = {c["result"] for c in entry.payload["checks"]}
    assert results == {"pass"}


def test_two_identical_runs_produce_identical_chains(tmp_path):
    """D-01 in miniature: same seed, same clock, byte-identical export."""
    def run(name):
        clock = Clock()
        conn = connect(tmp_path / name)
        try:
            ch = AuditChain(conn, clock)
            _append_some(ch, clock, 6)
            return ch.export_jsonl()
        finally:
            conn.close()

    assert run("one.db") == run("two.db")


# --------------------------------------------------------------------------
# P-07 / F-06 — any edit fails verification
# --------------------------------------------------------------------------


def test_a_clean_chain_verifies(chain):
    ch, clock = chain
    _append_some(ch, clock, 5)
    count, head = verify_entries(ch.read())
    assert count == 5
    assert head == ch.head()[1]


@pytest.mark.parametrize(
    "field,value",
    [
        ("ts", "2030-01-01T00:00:00Z"),
        ("actor", "agent"),
        ("action", "authorize.deny"),
        ("prev_hash", "sha256:" + "b" * 64),
        ("entry_hash", "sha256:" + "c" * 64),
    ],
)
def test_p07_editing_any_field_of_any_row_fails_verification(chain, field, value):
    ch, clock = chain
    entries = list(_append_some(ch, clock, 5))
    target = 2
    edited = [
        e if i != target else e.model_copy(update={field: value})
        for i, e in enumerate(entries)
    ]

    with pytest.raises(ChainBroken) as caught:
        verify_entries(edited)
    # The break is reported at the edited row, or at the next one when the
    # edit was to the hash the next row points back at.
    assert caught.value.seq in (target, target + 1)


def test_p07_editing_a_payload_fails_verification(chain):
    ch, clock = chain
    entries = list(_append_some(ch, clock, 5))
    entries[3] = entries[3].model_copy(
        update={"payload": {**entries[3].payload, "decision": "deny"}}
    )
    with pytest.raises(ChainBroken) as caught:
        verify_entries(entries)
    assert caught.value.seq == 3


def test_p07_dropping_a_row_fails_verification(chain):
    ch, clock = chain
    entries = list(_append_some(ch, clock, 5))
    with pytest.raises(ChainBroken):
        verify_entries(entries[:2] + entries[3:])


def test_p07_reordering_rows_fails_verification(chain):
    ch, clock = chain
    entries = list(_append_some(ch, clock, 5))
    entries[1], entries[2] = entries[2], entries[1]
    with pytest.raises(ChainBroken):
        verify_entries(entries)


def test_appending_a_forged_row_fails_verification(chain):
    """The attacker may write to the log store; they cannot forge a hash."""
    ch, clock = chain
    entries = list(_append_some(ch, clock, 3))
    forged = AuditEntry(
        seq=3,
        ts="2026-01-01T00:00:03Z",
        actor=AuditActor.KERNEL,
        action=AuditAction.CAPTURE_ALLOW,
        payload={"decision": "allow", "amount_paise": 999999},
        prev_hash=entries[-1].entry_hash,
        entry_hash="sha256:" + "d" * 64,
    )
    with pytest.raises(ChainBroken) as caught:
        verify_entries(entries + [forged])
    assert caught.value.seq == 3


# --------------------------------------------------------------------------
# Export format
# --------------------------------------------------------------------------


def test_export_line_carries_exactly_the_verifier_contract(chain):
    ch, clock = chain
    entry = _append_some(ch, clock, 1)[0]
    parsed = json.loads(entry_to_export_line(entry))
    assert set(parsed) == {
        "seq",
        "ts",
        "actor",
        "action",
        "payload",
        "prev_hash",
        "entry_hash",
    }


def test_export_is_canonical_so_runs_are_byte_comparable(chain):
    ch, clock = chain
    entry = _append_some(ch, clock, 1)[0]
    line = entry_to_export_line(entry)
    assert line == jcs(json.loads(line))


def test_head_of_an_empty_chain_is_genesis(chain):
    ch, _ = chain
    assert ch.head() == (-1, GENESIS_HASH)
    assert ch.count() == 0
