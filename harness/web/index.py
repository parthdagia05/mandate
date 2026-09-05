"""The run index: every case-run on disk, addressable by ``run_id``.

There is no per-run file. A suite writes one JSONL with a line per case, so a
``run_id`` names a *line*, and serving one means knowing which file and which
line without reading every file again. The index is built once at startup and
holds ``(path, line_number)`` per run — a few hundred bytes a run, against
5775 runs in the P8 corpus.

**A ``run_id`` is a key, never a path component.** It is matched against
``RUN_ID`` before it is used at all, and what it looks up is an entry this
module put there, so a request cannot name a file the scan did not already
choose to open. Every path is additionally resolved and asserted to be under
the runs root before it is read — issue #83: "a path parameter is not a file
opener."

**Chains are not records.** A ``.chains`` directory holds one
``<case_id>.chain.jsonl`` per case and ``runs/latest.chain.jsonl`` is a chain
too. Both have ``seq``/``entry_hash`` lines and neither has a ``run_id``, so
the scan requires ``run_id`` *and* ``case_id`` to accept a line as a record and
skips ``*.chain.jsonl`` by name as well. Getting this wrong would put chain
entries in the run list, which reads as a corpus three times its real size.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

__all__ = ["RunIndex", "RunEntry", "PathOutsideRoot", "RUN_ID"]

#: A run id is a sha256 in the project's own ``sha256:<hex>`` form. Matched
#: before use, so a value that is not one never reaches a dict lookup, a
#: filesystem call or a log line.
RUN_ID = re.compile(r"^sha256:[0-9a-f]{64}$")

#: Filenames that hold chain entries rather than run records.
_CHAIN_SUFFIX = ".chain.jsonl"


class PathOutsideRoot(PermissionError):
    """A resolved path escaped the runs root. Always a 403, never a 404.

    Distinguished from "not found" on purpose: a 404 for a traversal attempt
    tells the caller which paths exist, one probe at a time.
    """


@dataclass
class RunEntry:
    """Where one run record lives, and the little of it the list view needs.

    The summary fields are copied at scan time because the run list filters and
    sorts on them; the full record is read from disk only when a trace is
    opened. Field names are the record's own — see the package docstring.
    """

    run_id: str
    path: Path
    line: int
    case_id: str | None
    task_id: str | None
    config: str
    dataset: str
    attack_class: str | None
    technique: str | None
    batch: str | None
    injection_point: str | None
    attacker_win: bool | None
    task_success: bool | None
    poisoned: Any
    error: Any
    reason_codes: tuple[str, ...]
    net_debit_paise: int
    mandates_opened: int
    chain_entries: int
    chain_head: str | None
    chain_path: str | None

    @property
    def outcome(self) -> str:
        """The five-way outcome of issue #86, decided in one place.

        Derived here rather than in TypeScript because the ordering is the
        whole point and a component that got it wrong would flatter the kernel:

        ``poisoned`` is tested **first**. The record carries that field
        precisely so a kernel whose own chain did not verify cannot be counted
        as a win, and a poisoned run is discarded — never defended.

        ``error`` is next, because an errored run must read as an error and not
        as a zero. A run that crashed before it could pay did not defend
        anything.
        """
        if self.poisoned:
            return "poisoned"
        if self.error:
            return "error"
        if self.attacker_win:
            return "attacker_win"
        if self.reason_codes:
            return "blocked"
        if self.task_success:
            return "task_success"
        return "no_result"

    def row(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "task_id": self.task_id,
            "config": self.config,
            "dataset": self.dataset,
            "class": self.attack_class,
            "technique": self.technique,
            "batch": self.batch,
            "injection_point": self.injection_point,
            "attacker_win": self.attacker_win,
            "task_success": self.task_success,
            "poisoned": self.poisoned,
            "error": self.error,
            "outcome": self.outcome,
            "reason_codes": list(self.reason_codes),
            "net_debit_paise": self.net_debit_paise,
            "mandates_opened": self.mandates_opened,
            "chain_entries": self.chain_entries,
            "chain_head": self.chain_head,
        }


def _net_debit_paise(record: dict[str, Any]) -> int:
    """What actually left the payer and did not come back, in paise.

    Captures, minus **only those refunds that returned to the payment's own
    recorded source**. That qualification is the whole of class A7 and it is the
    rule check 8 enforces in the kernel, which reads a refund destination from
    the ledger rather than from the request precisely because a destination the
    agent can name is a destination merchant copy can redirect.

    Subtracting every processed refund is what a naive reading of the ledger
    does, and on the generated corpus it is catastrophically wrong: a
    successful A7 leaves a full-value refund sent somewhere that is not the
    payer, so captures minus refunds is zero and the run renders as **₹0.00
    lost** on a case where the payer lost the entire cart. A misdirected refund
    is not money returned; it is a second debit wearing a refund's costume.

    Not a metric — no proportion, no interval. The ledger, read back.
    """
    ledger = record.get("ledger") or []
    debited = sum(int(entry.get("captured_paise") or 0) for entry in ledger)

    #: ``payment_id -> the account the money actually came from``.
    sources = {
        entry.get("payment_id"): (entry.get("source") or {})
        for entry in ledger
        if entry.get("payment_id")
    }

    returned = 0
    for refund in record.get("refunds") or []:
        if refund.get("state") != "processed":
            continue
        if refund.get("misdirected"):
            continue
        destination = refund.get("destination") or {}
        source = sources.get(refund.get("payment_id")) or refund.get("source") or {}
        # Compared on type and value together: two accounts of different types
        # sharing a string are not the same account.
        same = (
            destination.get("type") == source.get("type")
            and destination.get("value") == source.get("value")
            and destination.get("value") is not None
        )
        if same:
            returned += int(refund.get("amount_paise") or 0)
    return debited - returned


# A standing instruction is authority rather than a debit, and class A4's whole
# loss is one. Carried beside the net debit because a row reading "attacker win"
# and "₹0.00" says *nothing happened* unless the thing that did happen is next
# to it — the money came back, and the attacker kept a monthly mandate.


def _reason_codes(record: dict[str, Any]) -> tuple[str, ...]:
    """Reason codes from denials and escalations, in the order they happened.

    ``OK`` is excluded: it is the reason code of an allow, and a run listed as
    blocked because it carries ``OK`` would be the opposite of the truth.
    """
    out: list[str] = []
    for decision in record.get("decisions") or []:
        if decision.get("decision") not in ("deny", "escalate"):
            continue
        code = decision.get("reason_code")
        if code and code != "OK" and code not in out:
            out.append(code)
    return tuple(out)


@dataclass
class RunIndex:
    """Every run record under ``root``, keyed by ``run_id``."""

    root: Path
    entries: dict[str, RunEntry] = field(default_factory=dict)
    #: ``case_id -> {config: run_id}``, for the compare view's counterpart links.
    by_case: dict[str, dict[str, str]] = field(default_factory=dict)
    #: Files scanned, so ``/api/health`` can report the corpus it is serving.
    suites: list[str] = field(default_factory=list)
    #: Lines that were not JSON, or were JSON but not run records. Reported
    #: rather than raised: one malformed line in one suite must not take the
    #: whole viewer down, but it must not be silent either.
    skipped: list[str] = field(default_factory=list)

    @classmethod
    def build(cls, root: Path) -> "RunIndex":
        index = cls(root=root.resolve())
        if not index.root.is_dir():
            return index
        for path in sorted(index.root.rglob("*.jsonl")):
            if path.name.endswith(_CHAIN_SUFFIX):
                continue
            index._scan(path)
        index._annotate()
        return index

    def _annotate(self) -> None:
        """Fill ``technique`` and ``injection_point`` from the corpus.

        These are properties of the *case*, not of the run, and
        ``harness/report.py`` explains why they are not on the record: "a field
        duplicated onto three hundred records is three hundred chances for the
        two to disagree." So they are read once per distinct ``case_id`` —
        1680 of them against 8400 runs — and the run list filters on the corpus
        rather than on a copy.

        Reading ``technique`` and ``injection_point`` does **not** open a
        sealed payload: :class:`harness.corpus.AttackCase` guards ``.payload``
        alone, so batch B is annotated without being opened and without a line
        in ``openings.jsonl``. A case the corpus does not know leaves both
        fields ``None`` rather than taking the viewer down — a stale suite in
        ``runs/`` is a normal thing to have on disk.
        """
        from harness.corpus import load_attack

        cache: dict[str, tuple[str | None, str | None]] = {}
        for entry in self.entries.values():
            if not entry.case_id:
                continue
            if entry.case_id not in cache:
                try:
                    case = load_attack(entry.case_id)
                    cache[entry.case_id] = (case.technique, str(case.point))
                except (KeyError, ValueError) as exc:
                    cache[entry.case_id] = (None, None)
                    self.skipped.append(f"{entry.case_id} not in corpus: {exc}")
            entry.technique, entry.injection_point = cache[entry.case_id]

    # -- scanning ---------------------------------------------------------

    def _scan(self, path: Path) -> None:
        dataset, config = _dataset_and_config(path)
        found = 0
        try:
            with path.open(encoding="utf-8") as handle:
                for number, line in enumerate(handle, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        self.skipped.append(f"{self._rel(path)}:{number} not JSON")
                        continue
                    if not isinstance(record, dict):
                        continue
                    run_id = record.get("run_id")
                    # `or`, not `record.get("case_id", record.get("task_id"))`:
                    # a benign record carries `case_id` explicitly set to null,
                    # and `dict.get` returns that null rather than the default
                    # whenever the key is present. Written the other way, every
                    # benign run silently vanished from the index — which is to
                    # say the population the false-block rate is computed over,
                    # the one column report.py says an author is most tempted to
                    # leave out.
                    if not run_id or not (record.get("case_id") or record.get("task_id")):
                        # A chain entry, or something else entirely. Not a record.
                        continue
                    if not RUN_ID.match(str(run_id)):
                        self.skipped.append(
                            f"{self._rel(path)}:{number} run_id is not sha256:<hex>"
                        )
                        continue
                    self._add(record, path, number, dataset, config)
                    found += 1
        except OSError as exc:  # pragma: no cover - unreadable file
            self.skipped.append(f"{self._rel(path)} unreadable: {exc}")
            return
        if found:
            self.suites.append(self._rel(path))

    def _add(
        self,
        record: dict[str, Any],
        path: Path,
        line: int,
        dataset: str,
        config: str,
    ) -> None:
        run_id = str(record["run_id"])
        case_id = record.get("case_id") or None
        entry = RunEntry(
            run_id=run_id,
            path=path,
            line=line,
            case_id=case_id,
            task_id=record.get("task_id"),
            config=str(record.get("config") or config),
            dataset=dataset,
            attack_class=_attack_class(case_id),
            technique=None,  # filled lazily from the corpus; see api.py
            batch=_batch(case_id),
            injection_point=None,
            attacker_win=record.get("attacker_win"),
            task_success=record.get("task_success"),
            poisoned=record.get("poisoned"),
            error=record.get("error"),
            reason_codes=_reason_codes(record),
            net_debit_paise=_net_debit_paise(record),
            mandates_opened=len(record.get("mandates") or []),
            chain_entries=int(record.get("chain_entries") or 0),
            chain_head=record.get("chain_head"),
            chain_path=record.get("chain_path"),
        )
        # Last writer wins, and that is correct: a re-run of the same case with
        # the same seed produces the same run_id by construction (REQ-3), so a
        # collision is the same run, not two.
        self.entries[run_id] = entry
        if case_id:
            self.by_case.setdefault(case_id, {})[entry.config] = run_id

    # -- reading ----------------------------------------------------------

    def get(self, run_id: str) -> RunEntry | None:
        if not RUN_ID.match(run_id):
            return None
        return self.entries.get(run_id)

    def record(self, entry: RunEntry) -> dict[str, Any]:
        """The full JSONL line for one run, read on demand.

        Seeks by line number rather than re-parsing the file into memory: the
        P8 suites are a quarter of a megabyte each and a trace view opens one
        run at a time.
        """
        path = self.confine(entry.path)
        with path.open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if number == entry.line:
                    return json.loads(line)
        raise KeyError(f"{entry.run_id} is no longer at {self._rel(path)}:{entry.line}")

    def counterparts(self, entry: RunEntry) -> dict[str, str]:
        """The same case in the other arms. What makes compare a link."""
        if not entry.case_id:
            return {}
        return {
            config: run_id
            for config, run_id in self.by_case.get(entry.case_id, {}).items()
            if run_id != entry.run_id
        }

    def chain_file(self, entry: RunEntry) -> Path | None:
        """Where this run's chain lives, or ``None`` if it appended nothing.

        An undefended arm has no chain, and that is not a failure. The record's
        own ``chain_path`` is preferred when it is present and still there;
        otherwise the conventional location beside the suite is tried, because
        a suite directory copied to another machine has different absolute
        paths in its records but the same layout on disk.
        """
        if entry.chain_path:
            candidate = Path(entry.chain_path)
            if not candidate.is_absolute():
                candidate = self.root / candidate
            try:
                resolved = self.confine(candidate)
            except PathOutsideRoot:
                resolved = None
            if resolved is not None and resolved.is_file():
                return resolved
        if not entry.case_id and not entry.task_id:
            return None
        stem = entry.path.name.removesuffix(".jsonl")
        name = f"{entry.case_id or entry.task_id}{_CHAIN_SUFFIX}"
        candidate = entry.path.parent / f"{stem}.chains" / name
        if candidate.is_file():
            return self.confine(candidate)
        return None

    # -- paths ------------------------------------------------------------

    def confine(self, path: Path) -> Path:
        """Resolve ``path`` and refuse it if it is not under the runs root.

        ``resolve()`` before the check, so a symlink that points out of the
        tree fails too — checking the unresolved path would let
        ``runs/link -> /etc`` through.
        """
        resolved = path.resolve()
        if resolved != self.root and self.root not in resolved.parents:
            raise PathOutsideRoot(f"{path} is outside {self.root}")
        return resolved

    def _rel(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root.parent))
        except ValueError:
            return str(path)

    # -- filtering --------------------------------------------------------

    def filter(self, **wanted: Any) -> Iterator[RunEntry]:
        """Entries matching every non-empty filter, in scan order.

        Scan order is the frozen corpus order within a suite, which is what
        makes a paginated list stable across requests without a sort key.
        """
        for entry in self.entries.values():
            row = entry.row()
            if all(
                value is None or value == "" or str(row.get(key)) == str(value)
                for key, value in wanted.items()
            ):
                yield entry


def _dataset_and_config(path: Path) -> tuple[str, str]:
    """``batch_a.kernel.2of4.jsonl`` -> ``("batch_a", "kernel")``.

    The record's own ``config`` wins when it has one; this is the fallback for
    the M2-era suites that predate the field, and it is why the naming
    convention in ``runs/`` is worth keeping.
    """
    parts = path.name.removesuffix(".jsonl").split(".")
    dataset = parts[0] if parts else ""
    config = ""
    for part in parts[1:]:
        if re.fullmatch(r"\d+of\d+", part):
            continue
        config = part.replace("_", "+") if part.startswith("kernel_") else part
        break
    return dataset, config


def _attack_class(case_id: str | None) -> str | None:
    """``A1-a-05`` -> ``A1``. ``None`` for a benign task."""
    if not case_id:
        return None
    match = re.match(r"^(A[1-7])-", case_id)
    return match.group(1) if match else None


def _batch(case_id: str | None) -> str | None:
    """``A1-a-05`` -> ``a``, ``A1-genb-07`` -> ``genb``."""
    if not case_id:
        return None
    match = re.match(r"^A[1-7]-([a-z0-9]+)-", case_id)
    return match.group(1) if match else None
