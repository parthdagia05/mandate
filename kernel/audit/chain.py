"""The append-only audit chain.

``entry_hash = SHA256(seq ‖ ts ‖ actor ‖ action ‖ JCS(payload) ‖ prev_hash)``

``‖`` is concatenation with U+001F (unit separator) between fields, UTF-8
encoded. That separator is unambiguous by construction: RFC 8785 escapes every
control character, so a literal U+001F cannot appear inside the canonical
payload, and the remaining fields are digits, a fixed timestamp form and two
closed enums. Without a separator, ``seq=1, ts="1..."`` and ``seq=11,
ts="..."`` would hash alike, and the chain would have a collision an attacker
could aim for.

Two rules the rest of the system leans on:

* **Passing checks are recorded, not only failures.** The per-check ablation in
  ``results.md`` is only readable because the payload says which checks ran and
  passed, not merely which one refused.
* **Raw ``sig`` bytes never enter the payload** (SPEC.md §15). ECDSA
  signatures are not deterministic, so hashing one would break REQ-3. The entry
  records the mandate id and a hash instead; verification still checks the
  signature, the chain just does not hash a non-deterministic value.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Iterator

from kernel.canonical import jcs
from kernel.clock import Clock
from kernel.enums import AuditAction, AuditActor
from kernel.models import AuditEntry

__all__ = [
    "GENESIS_HASH",
    "FIELD_SEPARATOR",
    "compute_entry_hash",
    "AuditChain",
    "ChainBroken",
    "entry_to_export_line",
]

#: The prev_hash of seq 0. A chain has to start somewhere, and it starts at a
#: value nothing can hash to.
GENESIS_HASH = "sha256:" + "0" * 64

FIELD_SEPARATOR = "\x1f"


class ChainBroken(RuntimeError):
    """Verification failed. The kernel treats this as poisoned: deny everything."""

    def __init__(self, seq: int, detail: str) -> None:
        super().__init__(f"BROKEN at seq {seq}: {detail}")
        self.seq = seq
        self.detail = detail


def compute_entry_hash(
    seq: int,
    ts: str,
    actor: str,
    action: str,
    payload: dict[str, Any],
    prev_hash: str,
) -> str:
    """The one hash formula, shared by the kernel and the standalone verifier."""
    preimage = FIELD_SEPARATOR.join(
        [str(seq), ts, str(actor), str(action), jcs(payload), prev_hash]
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def entry_to_export_line(entry: AuditEntry) -> str:
    """One line of the export format the standalone verifier consumes.

    Serialised canonically so that two runs of the same seed produce
    byte-identical files (D-01), not merely equivalent ones.
    """
    return jcs(
        {
            "seq": entry.seq,
            "ts": entry.ts,
            "actor": str(entry.actor),
            "action": str(entry.action),
            "payload": entry.payload,
            "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash,
        }
    )


class AuditChain:
    """Append-only, fsynced before the caller gets its answer.

    The append happens *before* the PSP call, never after (SPEC.md §08). A
    crash between the two leaves a recorded decision with no debit, which the
    recovery scan can resolve. Reversing the order leaves a debit nothing
    recorded, which nothing can resolve.
    """

    def __init__(self, conn: sqlite3.Connection, clock: Clock) -> None:
        self._conn = conn
        self._clock = clock

    def head(self) -> tuple[int, str]:
        """``(seq of the last entry, its hash)``; ``(-1, GENESIS)`` when empty."""
        row = self._conn.execute(
            "SELECT seq, entry_hash FROM audit_entry ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return -1, GENESIS_HASH
        return row["seq"], row["entry_hash"]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM audit_entry").fetchone()[0]

    def append(
        self,
        actor: AuditActor,
        action: AuditAction,
        payload: dict[str, Any],
    ) -> AuditEntry:
        """Append one entry and fsync it. Raises if either fails — never returns
        a decision the chain did not record (REQ-2)."""
        if "sig" in payload:
            # Guard rather than strip: a caller putting a signature in the
            # payload has misunderstood something, and silently dropping it
            # would hide that.
            raise ValueError(
                "raw signature bytes must never enter an audit payload; "
                "record the mandate id and a hash instead (SPEC.md §15)"
            )

        prev_seq, prev_hash = self.head()
        seq = prev_seq + 1
        ts = self._clock.now_rfc3339()
        actor_value, action_value = str(actor), str(action)
        payload_json = jcs(payload)
        entry_hash = compute_entry_hash(
            seq, ts, actor_value, action_value, payload, prev_hash
        )

        # synchronous=FULL means this COMMIT fsyncs before it returns, which is
        # the whole of "appended and fsynced before the response returns".
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO audit_entry"
                " (seq, ts, actor, action, payload_json, prev_hash, entry_hash)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (seq, ts, actor_value, action_value, payload_json, prev_hash, entry_hash),
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

        return AuditEntry(
            seq=seq,
            ts=ts,
            actor=actor,
            action=action,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

    def read(self, start: int = 0, end: int | None = None) -> Iterator[AuditEntry]:
        """Stream entries, the same range ``GET /v1/audit/chain`` serves."""
        if end is None:
            rows = self._conn.execute(
                "SELECT * FROM audit_entry WHERE seq >= ? ORDER BY seq", (start,)
            )
        else:
            rows = self._conn.execute(
                "SELECT * FROM audit_entry WHERE seq >= ? AND seq <= ? ORDER BY seq",
                (start, end),
            )
        for row in rows:
            yield AuditEntry(
                seq=row["seq"],
                ts=row["ts"],
                actor=AuditActor(row["actor"]),
                action=AuditAction(row["action"]),
                payload=json.loads(row["payload_json"]),
                prev_hash=row["prev_hash"],
                entry_hash=row["entry_hash"],
            )

    def export_jsonl(self) -> str:
        """The whole chain in the format the standalone verifier reads."""
        return "".join(entry_to_export_line(e) + "\n" for e in self.read())
