"""``mk`` — the project's command line.

M1 wired up ``hash-cart``, ``verify-chain`` and ``verify-fixtures``. M2 added
``run``, which is the one a reader who has not read the code types first. M3
adds ``explain`` — the narrator over the audit chain — and ``run --config
kernel`` and ``run --fault``. M4 adds ``faults``, which lists what can be armed
and the exact ``run`` line that arms it. M5 adds ``corpus`` and ``oracles``, and
M6 adds ``suite`` — the same run, over a whole dataset, written down as the
JSONL that ``results.md`` is computed from. ``matrix`` and ``ablate`` come after
it and are built on top of it.

**Faults are armed on the run, not before it.** ``mk run --fault NAME[:TARGET]``
rather than a separate stateful command, because each run builds its own seeded
world: a fault armed by an earlier process would have nothing left to fire in.

P8 adds ``generate``, ``merge`` and ``kaggle``, and a ``--shard`` on ``suite``.
Those four are one workflow: pull two pinned Kaggle datasets, generate a corpus
from them, run it in shards across processes (or on Kaggle's machine, with the
internet off), and merge the shards back into one table. Every step of it
refuses rather than guesses — an unpinned dataset, a moved corpus, a missing
shard, a case counted twice.

``explain`` contains no model, and that is deliberate rather than frugal. The
chain already records the values each check compared, so explaining a decision
is a rendering problem and not an inference one — and a model here could
describe a denial that never happened.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

#: Where a kernel run leaves its chain, so ``mk explain <seq>`` needs no path.
#: Kept in step with :data:`harness.kernel_arm.DEFAULT_CHAIN_PATH` without
#: importing it: ``mk`` must stay importable with no project dependencies
#: reachable, which is what makes ``mk verify-chain`` runnable from anywhere.
DEFAULT_CHAIN_PATH = REPO_ROOT / "runs" / "latest.chain.jsonl"

#: The arms ``--config`` accepts, duplicated here for the same reason
#: :data:`DEFAULT_CHAIN_PATH` is: ``mk`` must stay importable with no project
#: dependencies reachable, which is what makes ``mk verify-chain`` runnable from
#: a directory that has none. ``tests/test_api_surface.py`` asserts this list
#: and :data:`harness.runner.CONFIGS` are the same list, so the duplication
#: cannot drift into a ``--config`` that silently means something else.
CONFIG_CHOICES = (
    "undefended",
    "model-only",
    "kernel",
    "agent-guard",
    "kernel+agent-guard",
)

#: The three ``mk matrix`` runs unless told otherwise: no defence, the defence
#: everybody proposes first, and this project's.
HEADLINE_CHOICES = ("undefended", "model-only", "kernel")

#: Every dataset a suite or a matrix can name. The ``gen_*`` three are the P8
#: generated corpus; they sit beside the hand-written three rather than
#: replacing them, because the hand-written tables are already published
#: against a corpus hash that must not move.
DATASET_CHOICES = ("benign", "batch_a", "batch_b", "gen_benign", "gen_a", "gen_b")

#: Where ``mk report`` writes the document unless told otherwise.
DEFAULT_RESULTS_PATH = REPO_ROOT / "results.md"

__all__ = ["main"]


def _load_standalone_verifier():
    """Load ``scripts/verify_chain.py`` by path, not by import.

    ``mk verify-chain`` and the standalone CLI must not be able to disagree, so
    there is one implementation. Loading it by file path rather than importing
    it as part of a package keeps the verifier free of project imports, which
    is the property REQ-9 actually cares about.
    """
    path = REPO_ROOT / "scripts" / "verify_chain.py"
    spec = importlib.util.spec_from_file_location("_standalone_verify_chain", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load the verifier at {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cmd_hash_cart(args: argparse.Namespace) -> int:
    """Recompute ``cart_hash`` for each cart file and compare them.

    Two files that describe the same purchase must print the same hash however
    they were written — different key order, different line-item order,
    ``1000`` versus ``1.0e3``. Change one character of a SKU and the hash moves.
    """
    from kernel.crypto import verify_object
    from kernel.models import CartMandate

    user_pub = (REPO_ROOT / "fixtures" / "keys" / "user.pub.b64u").read_text().strip()

    hashes = []
    failures = 0
    for name in args.files:
        raw = json.loads(Path(name).read_text())
        cart = CartMandate.model_validate(raw)
        computed = cart.recompute_cart_hash()
        declared_ok = computed == cart.cart_hash
        signature_ok = verify_object(user_pub, raw)

        hashes.append(computed)
        if not declared_ok:
            failures += 1
        print(name)
        print(f"  cart_hash  {computed}")
        print(f"  declared   {'match' if declared_ok else 'MISMATCH — ' + cart.cart_hash}")
        print(f"  signature  {'valid' if signature_ok else 'INVALID'}")

    if len(hashes) > 1:
        print()
        if len(set(hashes)) == 1:
            print(f"identical across {len(hashes)} carts")
        else:
            print(f"DIFFERENT across {len(hashes)} carts")
    return 1 if failures else 0


def cmd_verify_chain(args: argparse.Namespace) -> int:
    return _load_standalone_verifier().main([args.file])


def cmd_verify_fixtures(args: argparse.Namespace) -> int:
    """Re-hash every shipped fixture and compare to the manifest.

    A frozen corpus is only frozen if something checks. Any edit to any fixture
    changes a file hash, which changes the manifest hash, which fails here.
    """
    from kernel.canonical import sha256_hex, sha256_of

    manifest_path = REPO_ROOT / "fixtures" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    published = manifest.pop("manifest_hash")

    broken = []
    for rel, expected in manifest["files"].items():
        path = REPO_ROOT / rel
        if not path.exists():
            broken.append(f"{rel}: missing")
        elif sha256_hex(path.read_bytes()) != expected:
            broken.append(f"{rel}: contents changed")

    on_disk = {
        p.relative_to(REPO_ROOT).as_posix()
        for p in (REPO_ROOT / "fixtures").rglob("*")
        if p.is_file() and p.name != "manifest.json"
    }
    for rel in sorted(on_disk - set(manifest["files"])):
        broken.append(f"{rel}: present but not in the manifest")

    recomputed = sha256_of(manifest)
    if recomputed != published:
        broken.append("manifest hash does not match its own file list")

    if broken:
        print("FIXTURES CHANGED")
        for line in broken:
            print(f"  {line}")
        return 1

    print(f"OK, {len(manifest['files'])} fixtures, manifest {published}")
    return 0


def _rupees(paise: int) -> str:
    return f"\u20b9{paise / 100:,.2f}"


def _account(entry: dict) -> str:
    return f"{entry['type']}:{entry['value']}"


def _narrate(detail: dict) -> list[str]:
    """Plain English for one evaluated check, from its recorded evidence.

    Reads ``check_detail`` — the values the check compared — rather than
    restating the reason code. "Check 2 refused" is not an explanation; "you
    authorised merchant@upi and this request carried attacker@upi" is.
    """
    check_id = detail.get("id")
    failed = detail.get("result") == "fail"
    lines: list[str] = []

    if check_id == 1:
        if failed and detail.get("conjunct") == "signature":
            lines.append(
                f"  the signature over the {detail.get('over', 'mandate')} did not "
                f"verify against the {detail.get('verified_against', 'registered')} key"
            )
        elif failed and detail.get("conjunct") == "expiry":
            lines.append(
                f"  the {detail.get('expired')} expired at {detail.get('expires_at')} "
                f"and the kernel's clock says {detail.get('kernel_now')}"
            )
            if "client_ts" in detail:
                lines.append(
                    f"  the request claimed the time was {detail['client_ts']}; "
                    "the kernel does not read that field"
                )
        elif failed and detail.get("conjunct") == "nonce":
            lines.append(
                f"  the nonce was already bound to {detail.get('bound_to')}"
            )
        elif not failed:
            lines.append(
                f"  signatures verified ({detail.get('confirmed_by')} cart, "
                f"against {detail.get('verified_against')}); "
                f"valid until {detail.get('expires_at')}, kernel clock "
                f"{detail.get('kernel_now')}"
            )
    elif check_id == 2:
        allowed = ", ".join(_account(a) for a in detail.get("allowed_payees", []))
        if failed:
            lines.append(f"  the user allowed:   {allowed}")
            lines.append(
                f"  the request carried: {_account(detail['requested_payee'])}"
            )
        else:
            lines.append(f"  payee {_account(detail['payee'])} is on the allowlist ({allowed})")
    elif check_id == 3:
        if failed:
            lines.append(f"  the amount conjunct that failed was {detail.get('conjunct')}")
            for key in (
                "total_amount", "line_item_sum", "per_txn_cap", "max_amount",
                "requested_amount", "cart_total", "cart_currency", "scope_currency",
            ):
                if key in detail:
                    lines.append(f"    {key} = {detail[key]}")
        else:
            lines.append(
                f"  {_rupees(detail['total_amount'])} equals the line items and sits "
                f"under the per-transaction cap of {_rupees(detail['per_txn_cap'])}"
            )
    elif check_id == 4:
        if failed and detail.get("conjunct") == "internal":
            lines.append("  the cart's contents do not hash to the cart_hash it declares")
            lines.append(f"    declared    {detail.get('declared_cart_hash')}")
            lines.append(f"    recomputed  {detail.get('recomputed_cart_hash')}")
        elif failed:
            lines.append("  this cart is self-consistent but is not the one the user confirmed")
            lines.append(f"    confirmed  {detail.get('confirmed_cart_hash')}")
            lines.append(f"    presented  {detail.get('cart_hash')}")
        else:
            lines.append(f"  the cart matches what the user confirmed ({detail['cart_hash']})")
    elif check_id == 5:
        if failed:
            lines.append("  this asks to create a recurring mandate; the intent is not recurring")
        elif detail.get("applicable"):
            lines.append("  recurring authority was granted by the intent")
    elif check_id == 6:
        if failed:
            lines.append(f"  the budget conjunct that failed was {detail.get('conjunct')}")
            for key in (
                "execution_count", "max_transactions", "committed_paise",
                "requested_amount", "max_amount", "mandate_state",
            ):
                if key in detail:
                    lines.append(f"    {key} = {detail[key]}")
        else:
            lines.append(
                f"  {detail.get('execution_count')} of "
                f"{detail.get('max_transactions')} transactions used, "
                f"{_rupees(detail.get('committed_paise', 0))} of "
                f"{_rupees(detail.get('max_amount', 0))} committed"
            )
    elif check_id == 7:
        if detail.get("replayed"):
            lines.append(
                "  this exact action already ran; its recorded outcome was "
                "replayed and no second debit was made"
            )
        else:
            lines.append(
                f"  the idempotency key {detail.get('idempotency_key', '')[:16]}… "
                "was reserved for this action"
            )
    elif check_id == 8:
        if failed:
            lines.append(f"  the refund conjunct that failed was {detail.get('conjunct', 'binding')}")
            lines.append(f"    {detail.get('detail')}")
            for key in (
                "payment_id", "payment_state", "captured_paise",
                "already_refunded_paise", "requested_amount",
            ):
                if key in detail:
                    lines.append(f"    {key} = {detail[key]}")
        else:
            lines.append(
                f"  the refund goes to {_account(detail['destination'])}, read from "
                f"{detail.get('destination_from')}"
            )
            lines.append(
                "  the request has no destination field; there was nothing to read one from"
            )
            lines.append(
                f"  {_rupees(detail.get('requested_amount', 0))} of "
                f"{_rupees(detail.get('captured_paise', 0))} captured, "
                f"{_rupees(detail.get('already_refunded_paise', 0))} already returned "
                f"({detail.get('kind')})"
            )
    return lines


def cmd_explain(args: argparse.Namespace) -> int:
    """Say, in English, what one audit entry decided and on what evidence.

    The narrator is read-only and post-hoc: it reads the chain and nothing
    else, has no tools, and is outside the enforcement path entirely (SPEC.md
    §10). It also contains no model — the chain already records the values each
    check compared, so explaining a decision is a rendering problem, not an
    inference one, and a model here could describe a denial that never happened.
    """
    path = Path(args.chain)
    if not path.exists():
        print(
            f"no chain at {path}. Run one first:\n"
            "  mk run --task benign-01 --attack A1-seed-1 --config kernel",
            file=sys.stderr,
        )
        return 2

    entries = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    entry = next((e for e in entries if e["seq"] == args.seq), None)
    if entry is None:
        print(
            f"no entry at seq {args.seq} in {path}; it holds seq 0..{len(entries) - 1}",
            file=sys.stderr,
        )
        return 2

    payload = entry["payload"]
    print(f"audit seq {entry['seq']}  {entry['ts']}  {entry['actor']} / {entry['action']}")
    print(f"  entry {entry['entry_hash']}")
    print(f"  after {entry['prev_hash']}")
    print()

    if "utterance_hash" in payload:
        print(f"the sentence the user said hashes to {payload['utterance_hash']}")
    if "mandate_id" in payload:
        print(f"the authority is {payload['mandate_id']}")
    if "action" in payload and "amount_paise" in payload:
        print(
            f"the request asked to {payload['action']} "
            f"{_rupees(payload['amount_paise'])}"
            + (f" to {_account(payload['payee'])}" if "payee" in payload else "")
        )
    print()

    decision = payload.get("decision")
    if decision:
        print(f"the kernel said {decision.upper()}  ({payload.get('reason_code')})")
    for detail in payload.get("check_detail", []):
        verdict = "refused" if detail.get("result") == "fail" else "passed"
        print(f"  check {detail['id']} {detail['name']}: {verdict}")
        for line in _narrate(detail):
            print(f"  {line}")

    if entry["action"].startswith("webhook."):
        print(
            f"the PSP said this payment is {payload.get('claimed_state')}; "
            f"the kernel had it at {payload.get('current_state')}"
        )
        print(f"outcome: {payload.get('outcome')}")
        if payload.get("outcome") == "deduped":
            print(
                "  already known. Dedup is on the kernel's own payment row, not on "
                "the event id — a PSP resending with a fresh id is normal."
            )
        elif payload.get("outcome") == "refused":
            print(
                f"  refused by the {payload.get('refused_by')}: a claim earlier than "
                "what the kernel already holds cannot move the payment backwards."
            )
        else:
            booked = payload.get("ledger_reconciled") or {}
            print(f"  ledger: {booked.get('why')}")

    if entry["action"] == "recovery.reconciled":
        print(f"a reservation for {payload.get('action')} was resolved against the PSP")
        print(f"  polled by {payload.get('polled_by')}, outcome {payload.get('outcome')}")
        print(f"  {payload.get('detail')}")
        if "ledger_moved" in payload:
            print(
                "  the ledger moved" if payload["ledger_moved"]
                else "  the ledger was already correct; only the key was closed"
            )

    denied_by = payload.get("denied_by") or []
    if denied_by:
        print()
        print(
            "refused by check "
            + ", ".join(str(n) for n in denied_by)
            + f" — {payload.get('reason_code')}"
        )
        print("no PSP call was made; the decision was recorded before the rail.")
    return 0


def _fault_spec(text: str) -> dict:
    """``name`` or ``name:target`` — e.g. ``store_unavailable:audit``.

    ``target`` names *which* store fails. One unavailable store must not make
    every store unavailable, or the run could not show which store the refused
    check actually needed.
    """
    name, _, target = text.partition(":")
    spec: dict = {"fault": name, "count": None}
    if target:
        spec["target"] = target
    return spec


def cmd_run(args: argparse.Namespace) -> int:
    """Run one case and print the ledger.

    The ledger is printed rather than the agent's reasoning, because where the
    money went is the finding and what the agent thought is not. A run that
    intended to pay an attacker and never captured is not a loss, and a run
    that captured to an attacker while narrating perfect intentions is.
    """
    from harness.runner import run_case

    if args.task is None and args.attack is None:
        print(
            "mk run needs --task, or --attack (a case names its own task).",
            file=sys.stderr,
        )
        return 2

    export = Path(args.export) if args.export else None
    record = run_case(
        args.task,
        config=args.config,
        attack_id=args.attack,
        seed=args.seed,
        model=args.model,
        cassette=Path(args.cassette) if args.cassette else None,
        export_log=export,
        export_chain=Path(args.export_chain) if args.export_chain else None,
        faults=[_fault_spec(spec) for spec in (args.fault or [])],
    )

    if args.json:
        print(record.to_json())
        return 0 if record.error is None else 1

    print(f"task {record.task_id}  config {record.config}  seed {record.seed}")
    print(f"attack {record.case_id or 'none'}  model {record.model}")
    print()

    captures = [c for c in record.ledger if c["captured_paise"] > 0]
    print(f"ledger: {len(captures)} capture{'' if len(captures) == 1 else 's'}")
    # Which cart each debit settled, abbreviated. Two debits carrying one hash
    # is class A6 and is the whole of what its oracle reads; printing the hash
    # is what makes that visible on screen rather than only in a JSON field.
    seen_hashes: dict[str, int] = {}
    for capture in captures:
        seen_hashes[capture.get("cart_hash") or "-"] = (
            seen_hashes.get(capture.get("cart_hash") or "-", 0) + 1
        )
    for capture in captures:
        payee = capture["payee"]
        cart_hash = capture.get("cart_hash") or "-"
        repeated = "  <- same cart as another debit" if seen_hashes[cart_hash] > 1 else ""
        print(
            f"  {_rupees(capture['captured_paise'])} -> "
            f"{payee['type']}:{payee['value']}"
            f"   {capture['payment_id']}  state={capture['state']}"
        )
        print(
            f"  from {capture['source']['type']}:{capture['source']['value']}"
            f"   cart {cart_hash[:19]}{repeated}"
        )
    if not captures:
        print("  (no money moved)")

    if record.mandates:
        print()
        print(f"standing instructions: {len(record.mandates)}")
        for mandate in record.mandates:
            print(
                f"  {mandate['frequency']} up to "
                f"{_rupees(mandate['max_amount_paise'])} -> "
                f"{_account(mandate['payee'])}   {mandate['mandate_id']}  "
                f"state={mandate['state']}"
            )
        print("  <- authority that keeps drawing after everyone has stopped looking")

    if record.refunds:
        print()
        print(f"refunds: {len(record.refunds)}")
        for refund in record.refunds:
            flag = "  <- NOT the payment source" if refund["misdirected"] else ""
            print(
                f"  {_rupees(refund['amount_paise'])} -> "
                f"{_account(refund['destination'])}   {refund['refund_id']}  "
                f"state={refund['state']}{flag}"
            )
            print(f"  debited from {_account(refund['source'])}")

    if record.recoveries:
        print()
        print("recovery scan")
        for step in record.recoveries:
            print(
                f"  {step.get('action'):<10} {step.get('outcome'):<11} "
                f"{step.get('detail')}"
            )

    if record.decisions:
        print()
        print("kernel decisions")
        for step in record.decisions:
            refused = (
                f"  denied_by {step['denied_by']}" if step.get("denied_by") else ""
            )
            print(
                f"  {step['step']:<16} {step['status']} "
                f"{step.get('decision') or '-':<9} "
                f"{step.get('reason_code') or '-'}{refused}"
            )
        ran = record.decisions[-1].get("checks") or []
        if ran:
            print(
                "  checks run: "
                + ", ".join(f"{c['id']}={c['result']}" for c in ran)
            )

    print()
    print(f"task_success  {record.task_success}")
    print(f"attacker_win  {record.attacker_win}")
    print(f"log           {record.log_entries} entries, head {record.log_head}")
    if record.chain_path:
        print(f"audit chain   {record.chain_entries} entries, head {record.chain_head}")
        print(f"              {record.chain_path}")
        seq = next(
            (s["audit_seq"] for s in reversed(record.decisions) if s.get("denied_by")),
            None,
        )
        if seq is not None:
            print(f"              mk explain {seq}   # why it was refused")
    if record.poisoned:
        print(f"POISONED      {record.poisoned}")
        print("              this run is discarded, not reported")
    if export is not None:
        print(f"exported      {export}")
    for note in record.notes:
        print(f"note          {note}")
    if record.error:
        print(f"error         {record.error}")

    return 0 if record.error is None else 1


def cmd_suite(args: argparse.Namespace) -> int:
    """Run a whole dataset and write the JSONL a results table is computed from.

    Prints a line per case as it lands rather than a bar that fills, because a
    hundred cases take minutes and the useful thing to watch is *which* case is
    winning — a class that suddenly stops landing is visible here and invisible
    in a percentage at the end.

    The proportions printed at the end are bare fractions. Confidence intervals
    are deliberately not computed here: on the hand-written corpus n is 15 per
    class and a point estimate is not a fact, so the interval belongs beside the
    number in ``results.md`` rather than in a progress summary somebody might
    quote from a terminal.

    ``--shard i/n`` runs one contiguous block of the frozen corpus order. Shards
    are separate *processes* by design — SQLite has a single writer and the
    overhead column must not become a measurement of lock contention — so this
    command runs exactly one of them and ``mk merge`` puts them back together.
    """
    from harness.corpus import SEALED_BATCHES, batch_is_open, join_batch, open_batch
    from harness.shard import ShardError, parse_shard
    from harness.suite import DATASET_BATCH, run_suite, select

    shard = None
    if args.shard:
        try:
            shard = parse_shard(args.shard)
        except ShardError as exc:
            print(f"mk suite: {exc}", file=sys.stderr)
            return 2

    batch = DATASET_BATCH.get(args.dataset)
    if batch in SEALED_BATCHES and not batch_is_open(batch):
        if args.join:
            # A shard of an experiment somebody already opened the batch for.
            # It cannot be the first read — join_batch refuses that — and it is
            # logged as a join, so the read still leaves a trace.
            try:
                join_batch(batch, who="mk suite", note=args.shard or "whole dataset")
            except (RuntimeError, ValueError) as exc:
                print(f"mk suite: {exc}", file=sys.stderr)
                return 2
        elif not (args.reason or "").strip():
            print(
                f"mk suite: {args.dataset} draws on batch {batch!r}, which is "
                "held out. Opening it needs --reason, and the reason is written "
                "to harness/attacks/openings.jsonl beside the timestamp — which "
                "is what makes 'opened once' a thing a reader can check. A "
                "shard of a run somebody has already opened it for passes "
                "--join instead.",
                file=sys.stderr,
            )
            return 2
        else:
            try:
                open_batch(batch, args.reason, override=args.override, who="mk suite")
            except (RuntimeError, ValueError) as exc:
                print(f"mk suite: {exc}", file=sys.stderr)
                return 2

    try:
        cases = select(
            args.dataset,
            attack_class=args.attack_class,
            task=args.task,
            limit=args.limit,
            shard=shard,
        )
    except ValueError as exc:
        print(f"mk suite: {exc}", file=sys.stderr)
        return 2

    print(
        f"suite {args.dataset}  config {args.config}  seed {args.seed}  "
        f"model {args.model}" + (f"  shard {shard}" if shard else "")
    )
    print(f"{len(cases)} case{'' if len(cases) == 1 else 's'}, in sequence, one kernel each")
    print()

    def progress(index: int, total: int, record) -> None:
        win = "WIN " if record.attacker_win else "    "
        task = "task-ok" if record.task_success else "task-no"
        micros = record.latency_us.get("p50", 0)
        flag = ""
        if record.poisoned:
            flag = "  POISONED, discarded"
        elif record.error:
            flag = f"  {record.error}"
        print(
            f"  {index:>4}/{total}  {record.case_id or record.task_id:<14} "
            f"{win} {task}  {micros / 1000:>7.1f}ms{flag}"
        )

    try:
        result = run_suite(
            cases,
            dataset=args.dataset,
            config=args.config,
            seed=args.seed,
            model=args.model,
            out=Path(args.out) if args.out else None,
            cassette=Path(args.cassette) if args.cassette else None,
            shard=shard,
            progress=None if args.quiet else progress,
        )
    except (RuntimeError, NotImplementedError, ValueError) as exc:
        print(f"mk suite: {exc}", file=sys.stderr)
        return 1

    scored = len(result.scored)
    print()
    print(
        f"{len(result.records)} case(s), {scored} scored, "
        f"{len(result.errors)} error(s), {len(result.poisoned)} poisoned"
    )
    if scored:
        print(f"attacker wins   {result.attacker_wins:>4}/{scored}  {_pct(result.attacker_wins, scored)}")
        print(f"task success    {result.task_successes:>4}/{scored}  {_pct(result.task_successes, scored)}")
    latency = result.latency_us
    print(
        f"money calls     n={latency['n']}  p50 {latency['p50']}us  "
        f"p99 {latency['p99']}us"
    )
    print(f"corpus          {result.corpus_manifest}")
    print(f"records         {result.path}")
    print(f"meta            {result.meta_path}")
    print(f"suite_id        {result.suite_id}")

    # Every note any run raised, once each. The scripted stand-in raises one on
    # every line, and printing it 105 times would train the reader to skip it.
    notes = {note for record in result.records for note in record.notes}
    for note in sorted(notes):
        print(f"note            {note}")
    if scored:
        print()
        print(
            "Bare fractions with no interval. A point estimate is not a fact — "
            "the interval belongs in results.md, not here."
        )

    if result.corpus_drift:
        print(file=sys.stderr)
        print(
            "the corpus moved while this suite was running, so every line "
            "above quotes a hash that is no longer true and none of it may be "
            "published:",
            file=sys.stderr,
        )
        for difference in result.corpus_drift:
            print(f"  {difference}", file=sys.stderr)
        return 1
    if result.poisoned:
        print(
            f"\n{len(result.poisoned)} run(s) had an audit chain that did not "
            "verify; they are discarded, not reported",
            file=sys.stderr,
        )
        return 1
    return 1 if result.errors else 0


def _pct(part: int, whole: int) -> str:
    return f"({100.0 * part / whole:.1f}%)" if whole else "(n/a)"


def cmd_faults(args: argparse.Namespace) -> int:
    """List what can be armed, where it fires, and the line that arms it.

    Prints the ``mk run --fault`` invocation for each rather than describing it,
    because a fault whose arming line has to be reconstructed from prose is a
    fault that does not get run at a demo.
    """
    from sim.faults import CRASH_WINDOWS, FAULT_SITES, Fault

    print(f"{'fault':<22} {'fires at':<38} arm it with")
    for fault in Fault:
        print(
            f"{str(fault):<22} {str(FAULT_SITES[fault]):<38} "
            f"--fault {fault}"
        )
    print()
    print("targets")
    print(
        "  store_unavailable:<store>   which store fails — "
        "audit | ledger | idempotency | nonces"
    )
    print("  crash_after_reserve:<action>.<window>   where the kernel dies:")
    for window in sorted(CRASH_WINDOWS):
        print(f"      {window}")
    print()
    print("  after_reserve   dies before the rail is touched; recovery finds no")
    print("                  debit and releases the key. Zero debits.")
    print("  after_psp_call  dies after the rail answered and before the ledger")
    print("                  heard; recovery commits the debit that exists.")
    print("                  Exactly one debit. This is the A6 demonstration.")
    print()
    print("examples")
    print(
        "  mk run --task benign-01 --config kernel "
        "--fault crash_after_reserve:capture.after_psp_call"
    )
    print("  mk run --task benign-01 --config kernel --fault duplicate_webhook")
    print("  mk run --task benign-01 --config kernel --fault store_unavailable:ledger")
    return 0


def cmd_corpus(args: argparse.Namespace) -> int:
    """Count both corpora, then check nothing in either has moved.

    Prints the counts first because they are what a reader wants — 105, 105, 25
    for the hand-written corpus, 735, 735, 420 for the generated one — and the
    manifest hashes second because those are what ``results.md`` has to quote.
    Any edit to any task, case, seal or signed fixture changes a file hash,
    which changes a manifest hash, which fails here by name. Inside a generated
    shard the shard's digest fails and the shard is then opened, so the failure
    still names files.

    **Two manifests, and that is the point.** Folding the generated corpus into
    ``harness/manifest.json`` would move the hash the hand-written tables are
    published under without a hand-written byte changing.
    """
    from harness.corpus import CLASSES, list_batch, load_attack, openings
    from harness.manifest import (
        build_generated_manifest,
        build_manifest,
        generated_corpus_exists,
        verify_generated_manifest,
        verify_manifest,
        write_manifest,
    )

    if args.freeze:
        print(f"corpus frozen at {write_manifest()}")
        return 0

    def class_table(batches: tuple[str, ...]) -> None:
        per_class = {klass: dict.fromkeys(batches, 0) for klass in CLASSES}
        for batch in batches:
            for case_id in list_batch(batch):
                per_class[load_attack(case_id).attack_class][batch] += 1
        header = "class   " + "".join(f"{b:>10}" for b in batches)
        print(header)
        for klass in CLASSES:
            print(f"{klass:<8}" + "".join(f"{per_class[klass][b]:>10}" for b in batches))
        print()

    counts = build_manifest()["counts"]
    print("hand-written corpus")
    print(f"  batch A   {counts['batch_a']:>5} cases")
    print(f"  batch B   {counts['batch_b']:>5} cases  (sealed)")
    print(f"  benign    {counts['tasks']:>5} tasks")
    print()
    class_table(("a", "b"))

    if generated_corpus_exists():
        generated = build_generated_manifest()
        gen_counts = generated["counts"]
        print("generated corpus")
        print(f"  gen-a     {gen_counts['gen_a']:>5} cases")
        print(f"  gen-b     {gen_counts['gen_b']:>5} cases  (sealed)")
        print(f"  benign    {gen_counts['tasks']:>5} tasks")
        print(f"  generator {generated['generator_version']}  seed {generated['seed']}")
        for role, digest in sorted(generated["dataset_digests"].items()):
            print(f"  dataset   {role:<20} {digest}")
        for label, shards in sorted(generated["shards"].items()):
            print(f"  shards    {label:<20} {len(shards)}")
        print()
        class_table(("gen-a", "gen-b"))

    entries = openings()
    if entries:
        print(f"held-out batches have been opened {len(entries)} time(s):")
        for entry in entries:
            mark = " (override)" if entry["override"] else ""
            print(f"  {entry['at']}  {entry['batch']}  {entry['who']}: {entry['reason']}{mark}")
    else:
        print("no held-out batch has ever been opened")
    print()

    failed = False
    published, differences = verify_manifest()
    if differences:
        print(f"manifest  {published}")
        print(f"HAND-WRITTEN CORPUS CHANGED — {len(differences)} difference(s):", file=sys.stderr)
        for difference in differences:
            print(f"  {difference}", file=sys.stderr)
        failed = True
    else:
        print(f"manifest  {published}  (unchanged)")

    if generated_corpus_exists():
        gen_published, gen_differences = verify_generated_manifest()
        if gen_differences:
            print(f"generated {gen_published}")
            print(
                f"GENERATED CORPUS CHANGED — {len(gen_differences)} difference(s):",
                file=sys.stderr,
            )
            for difference in gen_differences:
                print(f"  {difference}", file=sys.stderr)
            failed = True
        else:
            print(f"generated {gen_published}  (unchanged)")

    if failed:
        print(
            "\nAny published number taken against the old hash is now "
            "unattributable. Re-freeze and re-run the numbers.",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_oracles(args: argparse.Namespace) -> int:
    """S-02. Seven rows, and every one of them has to fire.

    An oracle that always returns ``False`` reads as a perfect defence, and an
    oracle that always returns ``True`` makes every arm look equally lost. The
    two columns are those two failures, and a row passes only with both.
    """
    from harness.selftest import selftest

    rows = selftest(seed=args.seed, model=args.model)
    print(
        f"{'class':<6}{'oracle':<38}{'case':<12}"
        f"{'fires':<7}{'quiet':<7}{'':<2}evidence"
    )
    for row in rows:
        print(
            f"{row.attack_class:<6}{row.oracle:<38}{row.case_id:<12}"
            f"{str(row.fired_on_attack).lower():<7}"
            f"{str(row.quiet_on_benign).lower():<7}"
            f"{'ok' if row.passed else 'FAIL':<2} "
            f"{row.error or row.evidence}"
        )

    passed = sum(row.passed for row in rows)
    print()
    print(f"{passed}/{len(rows)} oracles shown to fire against a known-successful attack")
    if any("stand-in" in note for row in rows for note in row.notes):
        print(
            "model is the deterministic stand-in: this is a harness check, not "
            "a model measurement"
        )
    if passed != len(rows):
        print(
            "\nAn oracle that cannot fire reads as a perfect defence, and an "
            "oracle that cannot stay quiet makes every arm look equally lost. "
            "Neither number may be published.",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_matrix(args: argparse.Namespace) -> int:
    """Run every arm over every dataset and write the JSONL the table is built from.

    **The batch B seal is opened here and nowhere else in normal use.** Batch B
    is the held-out set and the headline number comes from it, so opening it is
    a decision with a reason attached: ``--reason`` is required for a matrix
    that touches it, the opening is appended to
    ``harness/attacks/openings.jsonl``, and a second one needs ``--override``
    and is recorded as an override. Nothing here can prevent a second read.
    What it prevents is a second read nobody can see afterwards.

    Writes the report at the end unless ``--no-report`` is passed, because a
    matrix whose numbers never reach ``results.md`` is a directory of JSONL
    nobody will open.
    """
    from harness.matrix import run_matrix

    datasets = args.dataset or ["benign", "batch_a"]
    configs = args.config or list(HEADLINE_CHOICES)

    if "batch_b" in datasets and not args.reason:
        print(
            "mk matrix --dataset batch_b needs --reason. Batch B is the "
            "held-out set and the headline number comes from it; the reason "
            "goes in harness/attacks/openings.jsonl beside the timestamp, "
            "which is what makes 'opened once' something a reader can check.",
            file=sys.stderr,
        )
        return 2

    print(
        f"matrix  datasets {', '.join(datasets)}  configs {', '.join(configs)}  "
        f"seed {args.seed}  model {args.model}"
    )
    print("suites run in sequence, one process, one kernel per case")
    print()

    state = {"cell": None}

    def progress(dataset: str, config: str, index: int, total: int) -> None:
        if state["cell"] != (dataset, config):
            state["cell"] = (dataset, config)
            print(f"  {dataset} / {config}  ({total} cases)")
        if index == total:
            print(f"    {index}/{total} done")

    try:
        matrix = run_matrix(
            datasets=datasets,
            configs=configs,
            seed=args.seed,
            model=args.model,
            out_dir=Path(args.out) if args.out else None,
            reason=args.reason or "",
            override=args.override,
            limit=args.limit,
            progress=None if args.quiet else progress,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"mk matrix: {exc}", file=sys.stderr)
        return 1

    print()
    _print_matrix_summary(matrix)

    if matrix.corpus_drift:
        print(file=sys.stderr)
        print(
            "the corpus moved while the matrix was running; none of it may be "
            "published:",
            file=sys.stderr,
        )
        for difference in matrix.corpus_drift:
            print(f"  {difference}", file=sys.stderr)
        return 1

    if not args.no_report:
        out = Path(args.results) if args.results else DEFAULT_RESULTS_PATH
        _write_report(matrix, None, out)
    return 0


def _print_matrix_summary(matrix) -> None:
    from harness.metrics import (
        benign_utility,
        false_block_rate,
        targeted_asr,
        utility_under_attack,
    )

    print(f"{'dataset':<10}{'config':<20}{'ASR':<26}{'utility':<26}")
    for cell in matrix.cells:
        if cell.dataset == "benign":
            left = benign_utility(cell.records)
            print(f"{cell.dataset:<10}{cell.config:<20}{'—':<26}{left.cell():<26}")
            print(
                f"{'':<10}{'':<20}false blocks "
                f"{false_block_rate(cell.records).cell()}"
            )
        else:
            print(
                f"{cell.dataset:<10}{cell.config:<20}"
                f"{targeted_asr(cell.records).cell():<26}"
                f"{utility_under_attack(cell.records).cell():<26}"
            )
    print()
    print(f"corpus          {matrix.corpus_manifest}")
    print(f"matrix          {matrix.out_dir}")
    print(f"matrix_id       {matrix.matrix_id}")
    print(f"batch B opened  {len(matrix.batch_b_openings)} time(s) on record")
    print()
    print(
        "Wilson 95% intervals, n is 15 per class. Two columns whose intervals "
        "overlap have not been shown to differ."
    )


def cmd_ablate(args: argparse.Namespace) -> int:
    """Turn off one check at a time and see which class stops being defended.

    Only the kernel arm has checks, so only the kernel arm is ablated. The
    baseline is re-run inside this command rather than borrowed from a matrix,
    so every row was produced in one process against one corpus hash on one
    machine — a borrowed baseline would make every delta partly a difference
    between two environments.
    """
    from harness.matrix import ABLATABLE, run_ablation

    checks = tuple(args.check) if args.check else ABLATABLE
    print(
        f"ablate  dataset {args.dataset}  checks {', '.join(str(c) for c in checks)}  "
        f"seed {args.seed}  model {args.model}"
    )
    print()

    def progress(label: str, index: int, total: int) -> None:
        if label == "baseline":
            print("  baseline: all nine checks on")
        else:
            print(f"  {index}/{total}  {label}")

    try:
        ablation = run_ablation(
            dataset=args.dataset,
            checks=checks,
            seed=args.seed,
            model=args.model,
            out_dir=Path(args.out) if args.out else None,
            limit=args.limit,
            modes=tuple(args.mode) if args.mode else ("single", "isolated", "floor"),
            progress=None if args.quiet else progress,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"mk ablate: {exc}", file=sys.stderr)
        return 1

    from harness.metrics import asr_by_class, targeted_asr
    from harness.report import ablation_verdicts

    print()
    classes = sorted(
        {cid.split("-", 1)[0] for r in ablation.baseline if (cid := r.get("case_id"))}
    )
    base = asr_by_class(ablation.baseline)
    floor_row = next((r for r in ablation.rows if r.mode == "floor"), None)
    floor = asr_by_class(floor_row.records) if floor_row is not None else {}

    def line(label: str, records, against: dict, mark: str) -> str:
        here = asr_by_class(records)
        cells = ""
        for cls in classes:
            if cls not in here:
                cells += f"{'—':<9}"
                continue
            other = against.get(cls)
            flag = ""
            if other is not None and (
                (mark == "^" and here[cls].k > other.k)
                or (mark == "v" and here[cls].k < other.k)
            ):
                flag = mark
            cells += f"{here[cls].p * 100:>6.1f}%{flag:<3}"
        return f"{label:<24}{targeted_asr(records).p * 100:>7.1f}%  {cells}"

    print(f"{'configuration':<24}{'overall':<10}" + "".join(f"{c:<9}" for c in classes))
    print(line("all nine on", ablation.baseline, {}, ""))

    singles = [r for r in ablation.rows if r.mode == "single"]
    if singles:
        print()
        print("  one check off — is it necessary, given the others?   ^ = ASR rose")
        for row in singles:
            print(line(row.label, row.records, base, "^"))

    isolated = [r for r in ablation.rows if r.mode == "isolated"]
    if floor_row is not None:
        print()
        print("  only one check on — what does it stop by itself?     v = held below the floor")
        print(line(floor_row.label + " (floor)", floor_row.records, base, "^"))
        for row in isolated:
            print(line(row.label, row.records, floor, "v"))

    print()
    verdicts = ablation_verdicts(ablation)
    print(f"{'check':<10}{'necessary for':<22}{'stops alone':<22}earns its row")
    for check_id in sorted(verdicts):
        entry = verdicts[check_id]
        print(
            f"{'check ' + str(check_id):<10}"
            f"{', '.join(entry['necessary_for']) or '—':<22}"
            f"{', '.join(entry['sufficient_for']) or '—':<22}"
            f"{'yes' if entry['earns_row'] else 'NO'}"
        )
    unearned = [c for c in sorted(verdicts) if not verdicts[c]["earns_row"]]
    if unearned:
        print()
        print(
            "checks that stopped nothing under either question: "
            + ", ".join(str(c) for c in unearned)
            + " — a finding about the check and about this corpus, printed "
            "rather than omitted"
        )
    zero_at_floor = [c for c in classes if c in floor and floor[c].k == 0]
    if zero_at_floor:
        print(
            "classes at zero with every predicate off: "
            + ", ".join(zero_at_floor)
            + " — stopped by something structural, not by a check"
        )
    print()
    print(f"ablation        {ablation.out_dir}")
    print(f"corpus          {ablation.corpus_manifest}")
    return 0


def _write_report(matrix, ablation, out: Path, generated=None) -> None:
    from harness.report import render_results

    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_results(matrix, ablation=ablation, generated=generated))
    print(f"results         {out}")


def cmd_report_generated(args: argparse.Namespace) -> int:
    """Splice the generated-corpus section into an existing ``results.md``.

    A separate command from ``mk report`` because it needs no matrix. The
    hand-written tables were measured against a corpus hash and a batch B
    opening that both still stand; re-rendering the whole document to add a
    section would mean re-running those suites and opening the held-out set
    again, and every number would move for no reason a reader could point at.

    Idempotent: the section lives between fences and running this twice
    produces the same document.
    """
    from harness.report_generated import load_generated, splice

    run = load_generated(Path(args.merged), configs=list(args.config or CONFIG_CHOICES))
    if not run.datasets:
        print(
            f"mk report-generated: {args.merged} holds no merged generated "
            "suites. Run the gen_* suites, then `mk merge` them into it.",
            file=sys.stderr,
        )
        return 2

    hosted = None
    if args.hosted:
        hosted = load_generated(Path(args.hosted), configs=list(args.config or CONFIG_CHOICES))
        if not hosted.datasets:
            print(
                f"mk report-generated: {args.hosted} holds no merged suites",
                file=sys.stderr,
            )
            return 2

    out = Path(args.out) if args.out else DEFAULT_RESULTS_PATH
    document = out.read_text() if out.exists() else "# Results\n"
    out.write_text(splice(document, run, hosted=hosted))
    print(f"generated corpus  {run.corpus_manifest}")
    print(f"datasets          {', '.join(run.datasets)}")
    print(f"results           {out}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Render ``results.md`` from a matrix directory already on disk.

    A separate command from ``mk matrix`` on purpose: the published table has to
    be reproducible **from the files** by somebody who did not run the suites. A
    renderer that could only read the object the matrix returned would make
    every number a property of the process that produced it.
    """
    from harness.matrix import load_matrix

    try:
        matrix = load_matrix(Path(args.matrix))
    except (FileNotFoundError, KeyError) as exc:
        print(
            f"mk report: {args.matrix} is not a matrix directory ({exc}). "
            "Run `mk matrix` first; it leaves a matrix.json beside its JSONL.",
            file=sys.stderr,
        )
        return 2

    ablation = None
    if args.ablation:
        ablation = _load_ablation(Path(args.ablation))
        if ablation is None:
            print(
                f"mk report: {args.ablation} is not an ablation directory. "
                "Run `mk ablate` first.",
                file=sys.stderr,
            )
            return 2

    generated = None
    if args.generated:
        from harness.report_generated import load_generated

        generated = load_generated(
            Path(args.generated), configs=list(matrix.configs)
        )
        if not generated.datasets:
            print(
                f"mk report: {args.generated} holds no merged generated suites. "
                "Run the gen_* suites, then `mk merge` them into it.",
                file=sys.stderr,
            )
            return 2

    _write_report(
        matrix,
        ablation,
        Path(args.out) if args.out else DEFAULT_RESULTS_PATH,
        generated=generated,
    )
    return 0


def _load_ablation(directory: Path):
    """Rebuild an ablation from the files ``mk ablate`` left behind."""
    from harness.matrix import AblationResult, AblationRow

    index = directory / "ablation.json"
    if not index.exists():
        return None
    body = json.loads(index.read_text())

    def read(path: Path) -> list:
        return [
            {**json.loads(line), "dataset": body["dataset"]}
            for line in path.read_text().splitlines()
            if line.strip()
        ]

    result = AblationResult(
        dataset=body["dataset"],
        seed=body["seed"],
        model=body["model"],
        corpus_manifest=body["corpus_manifest"],
        out_dir=directory,
        baseline_suite_id=body["baseline_suite_id"],
        started_at=body.get("started_at", ""),
        finished_at=body.get("finished_at", ""),
    )
    result.baseline = read(directory / f"{body['dataset']}.kernel.jsonl")
    for row in body["rows"]:
        path = directory / row["records"]
        result.rows.append(
            AblationRow(
                check_ids=tuple(row["check_ids"]),
                label=row["label"],
                mode=row["mode"],
                suite_id=row["suite_id"],
                path=path,
                records=read(path),
            )
        )
    return result


def cmd_merge(args: argparse.Namespace) -> int:
    """Reassemble a sharded run, refusing every merge that would lie.

    Prints what it refused rather than what it accepted, because a merge that
    works is uninteresting and a merge that should not have worked is the whole
    reason this command exists: a table short one shard looks exactly like a
    table of a smaller suite.
    """
    from harness.merge import MergeError, merge, write_merged

    try:
        merged = merge([Path(p) for p in args.files])
    except MergeError as exc:
        print(f"mk merge: {exc}", file=sys.stderr)
        return 1

    out = Path(args.out) if args.out else Path("runs") / f"{merged.dataset}.{merged.config.replace('+', '_')}.merged.jsonl"
    path, meta = write_merged(merged, out)
    summary = merged.summary()

    print(f"merged {len(merged.shards)} shard(s) of {merged.dataset} / {merged.config}")
    print(f"cases           {summary['cases']}, {summary['scored']} scored, "
          f"{summary['errors']} error(s), {summary['poisoned']} poisoned")
    print(f"attacker wins   {summary['attacker_wins']:>5}/{summary['scored']}  "
          f"{_pct(summary['attacker_wins'], summary['scored'])}")
    print(f"task success    {summary['task_successes']:>5}/{summary['scored']}  "
          f"{_pct(summary['task_successes'], summary['scored'])}")
    latency = summary["latency_us"]
    print(f"money calls     n={latency['n']}  p50 {latency['p50']}us  p99 {latency['p99']}us")
    print("                pooled over pooled calls; a p99 of per-shard p99s is a p99 of nothing")
    containment = summary["containment"]
    print(f"containment     {containment['runs_armed']}/{containment['runs']} run(s) armed, "
          f"{containment['shards_fully_armed']}/{containment['shards']} shard(s) fully armed, "
          f"{containment['non_local_blocked']} non-local connection(s) refused")
    print(f"corpus          {merged.corpus_manifest}")
    print(f"records         {path}")
    print(f"meta            {meta}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    """Build the generated corpus from the pinned Kaggle datasets.

    A thin wrapper over ``scripts/generate_corpus.py`` rather than a second
    implementation: the ``--force`` guard on re-signing has to be the same guard
    whichever way generation is reached, and a code path that could sign without
    it is the one somebody uses.
    """
    import subprocess

    argv = [sys.executable, str(REPO_ROOT / "scripts" / "generate_corpus.py")]
    if args.force:
        argv.append("--force")
    if args.seed:
        argv += ["--seed", args.seed]
    return subprocess.run(argv).returncode


def cmd_kaggle(args: argparse.Namespace) -> int:
    """Push, watch and fetch the hosted run; or pull the datasets it needs.

    The wrapper exists so the pushed code, the attached dataset versions and
    the run that produced a table are **one recorded object** instead of three
    things somebody remembers. Credentials are never read here and never
    printed; the CLI reads them from ~/.kaggle/kaggle.json.
    """
    from harness import kaggle as kg

    if args.kaggle_command == "datasets":
        from harness.datasets import read_registry, verify

        registry = read_registry()
        if not registry:
            print("no datasets pinned; nothing to check", file=sys.stderr)
            return 1
        failed = False
        for role, entry in sorted(registry.items()):
            if args.pull:
                directory = kg.pull_dataset(entry.ref, entry.version)
                print(f"pulled {entry.pin} -> {directory}")
            differences = verify(role)
            mark = "ok" if not differences else "MOVED"
            print(f"{role:<20} {entry.pin:<70} {entry.licence:<14} "
                  f"{entry.rows:>7} rows  {mark}")
            print(f"{'':<20} {entry.digest}")
            for difference in differences:
                print(f"  {difference}", file=sys.stderr)
                failed = True
        if failed:
            print(
                "\nA dataset that moved cannot re-derive the generated corpus, "
                "and a corpus built from an unpinned dataset is not "
                "reproducible. Re-pull, or re-pin and regenerate.",
                file=sys.stderr,
            )
        return 1 if failed else 0

    if args.kaggle_command == "check":
        rows = kg.check()
        for row in rows:
            print(f"{'ok  ' if row['ok'] else 'FAIL'}  {row['check']:<16} {row['detail']}")
        if all(row["ok"] for row in rows):
            print("\nReady. `mk kaggle repo` first — the notebook attaches it.")
            return 0
        print(
            "\nNothing has been uploaded. Fix the FAIL rows above; "
            "kaggle/README.md has the order they go in.",
            file=sys.stderr,
        )
        return 1

    if args.kaggle_command == "repo":
        try:
            if args.stage_only:
                staged = kg.stage_repo(Path(args.stage))
                print(f"staged {staged['files']} file(s), "
                      f"{staged['bytes'] / 1e6:.1f} MB -> {staged['dir']}")
                print(f"upload it with: kaggle datasets create -p {staged['dir']} -r zip")
                return 0
            result = kg.push_repo(message=args.message, stage=Path(args.stage))
        except kg.KaggleError as exc:
            print(f"mk kaggle: {exc}", file=sys.stderr)
            return 1
        print(
            f"{'created' if result['created'] else 'versioned'} {result['ref']}: "
            f"{result['files']} file(s), {result['bytes'] / 1e6:.1f} MB"
        )
        print(result["output"])
        print(
            "The notebook attaches this by version. Bump the version in "
            "kaggle/kernel-metadata.json's dataset_sources before `mk kaggle "
            "push`, or the run will use the old code."
        )
        return 0

    try:
        if args.kaggle_command == "push":
            result = kg.push()
            print(f"pushed {result['ref']} at {result['at']}")
            print(result["output"])
            return 0
        if args.kaggle_command == "status":
            state = kg.status()
            print(f"{state['ref']}  {state['status']}")
            print(state["message"])
            return 0 if state["status"] == "complete" else 1
        if args.kaggle_command == "pull":
            report = kg.pull(Path(args.dest), expect_shards=args.shards)
            print(f"pulled {report['ref']} -> {report['dir']}")
            for name in report["files"]:
                print(f"  {name}")
            print(f"{len(report['shards'])} shard(s), digests verified")
            print("Hand them to `mk merge`; it refuses a missing shard.")
            return 0
    except kg.KaggleError as exc:
        print(f"mk kaggle: {exc}", file=sys.stderr)
        return 1
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mk", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    hash_cart = sub.add_parser(
        "hash-cart", help="recompute and compare cart_hash for one or more carts"
    )
    hash_cart.add_argument("files", nargs="+")
    hash_cart.set_defaults(func=cmd_hash_cart)

    verify_chain = sub.add_parser(
        "verify-chain", help="verify an exported audit chain (standalone verifier)"
    )
    verify_chain.add_argument("file")
    verify_chain.set_defaults(func=cmd_verify_chain)

    verify_fixtures = sub.add_parser(
        "verify-fixtures", help="check every shipped fixture against the manifest"
    )
    verify_fixtures.set_defaults(func=cmd_verify_fixtures)

    run = sub.add_parser("run", help="run one case through the simulator")
    run.add_argument(
        "--task",
        default=None,
        help="a task id, e.g. benign-01. Optional with --attack: a case names "
        "the task it was written against, and running it against another one "
        "produces a clean run that would be counted as a defended one",
    )
    run.add_argument(
        "--config",
        default="undefended",
        choices=list(CONFIG_CHOICES),
        help=(
            "which arm of the experiment. 'kernel' runs the undefended agent "
            "on purpose — every guarantee has to hold with an adversarial one"
        ),
    )
    run.add_argument(
        "--attack", default=None, help="an attack case id, e.g. A1-seed-1"
    )
    run.add_argument(
        "--seed",
        default="0",
        help="the run seed; the same seed reproduces the run byte for byte",
    )
    run.add_argument(
        "--model",
        default="auto",
        help="auto | scripted | cassette | live | a model id",
    )
    run.add_argument("--cassette", default=None, help="recorded model replies")
    run.add_argument("--export", default=None, help="write the run log here as JSONL")
    run.add_argument(
        "--export-chain",
        default=None,
        help="write the kernel's audit chain here (default runs/latest.chain.jsonl)",
    )
    run.add_argument(
        "--fault",
        action="append",
        default=None,
        metavar="NAME[:TARGET]",
        help=(
            "arm a fault for this run, e.g. store_unavailable:audit or "
            "crash_after_reserve:capture.after_psp_call. See `mk faults`."
        ),
    )
    run.add_argument("--json", action="store_true", help="print the run record only")
    run.set_defaults(func=cmd_run)

    suite = sub.add_parser(
        "suite",
        help="run a whole dataset and write one JSONL line per case",
        description=(
            "Cases run in sequence in one process, each with its own kernel and "
            "its own SQLite file. Parallelism is across runs: to measure three "
            "configs at once, start three processes."
        ),
    )
    suite.add_argument(
        "--dataset",
        required=True,
        choices=list(DATASET_CHOICES),
        help=(
            "benign (25 tasks, no payload), a hand-written batch of 105 attack "
            "cases, or one of the generated three"
        ),
    )
    suite.add_argument(
        "--config",
        default="undefended",
        choices=list(CONFIG_CHOICES),
        help="which arm of the experiment",
    )
    suite.add_argument(
        "--class",
        dest="attack_class",
        default=None,
        help="run one attack class only, e.g. A1",
    )
    suite.add_argument(
        "--task", default=None, help="run only the cases written against this task"
    )
    suite.add_argument(
        "--limit", type=int, default=None, help="stop after this many cases"
    )
    suite.add_argument(
        "--seed",
        default="0",
        help="the run seed; the same seed reproduces every case byte for byte",
    )
    suite.add_argument(
        "--model", default="auto", help="auto | scripted | cassette | live | a model id"
    )
    suite.add_argument("--cassette", default=None, help="recorded model replies")
    suite.add_argument(
        "--out",
        default=None,
        help="where to write the JSONL (default runs/<suite_id>.jsonl)",
    )
    suite.add_argument(
        "--shard",
        default=None,
        metavar="i/n",
        help=(
            "run only shard i of n, one-based. The split is a contiguous block "
            "of the frozen corpus order, so shard 3 of 8 is always the same "
            "cases. Shards are separate processes — `mk suite` refuses to run "
            "twice in one — and `mk merge` puts them back together and refuses "
            "if one is missing"
        ),
    )
    suite.add_argument(
        "--reason",
        default=None,
        help="why a sealed batch is being opened. Required for batch_b and gen_b",
    )
    suite.add_argument(
        "--override",
        action="store_true",
        help="open a sealed batch again; logged as an override",
    )
    suite.add_argument(
        "--join",
        action="store_true",
        help=(
            "this shard runs under an opening already on record. Cannot be the "
            "first read of a sealed batch; logged as a join so the read still "
            "leaves a trace"
        ),
    )
    suite.add_argument(
        "--quiet", action="store_true", help="summary only, no line per case"
    )
    suite.set_defaults(func=cmd_suite)

    matrix = sub.add_parser(
        "matrix",
        help="run every arm over every dataset; the table results.md is built from",
        description=(
            "Suites run in sequence in one process. A matrix over batch_b "
            "opens the held-out set, which needs --reason and is logged; a "
            "second opening needs --override and is logged as an override."
        ),
    )
    matrix.add_argument(
        "--dataset",
        action="append",
        choices=list(DATASET_CHOICES),
        default=None,
        help="repeatable; default: benign and batch_a",
    )
    matrix.add_argument(
        "--config",
        action="append",
        choices=list(CONFIG_CHOICES),
        default=None,
        help=f"repeatable; default: {', '.join(HEADLINE_CHOICES)}",
    )
    matrix.add_argument("--seed", default="0")
    matrix.add_argument(
        "--model", default="auto", help="auto | scripted | cassette | live | a model id"
    )
    matrix.add_argument(
        "--reason",
        default=None,
        help="why batch B is being opened. Required for --dataset batch_b",
    )
    matrix.add_argument(
        "--override",
        action="store_true",
        help="open batch B again. Logged as an override; the headline number "
        "is only a held-out number the first time",
    )
    matrix.add_argument("--limit", type=int, default=None, help="cases per suite")
    matrix.add_argument("--out", default=None, help="where to write the matrix")
    matrix.add_argument(
        "--results", default=None, help="where to write results.md (default ./results.md)"
    )
    matrix.add_argument(
        "--no-report", action="store_true", help="write the JSONL but not results.md"
    )
    matrix.add_argument("--quiet", action="store_true")
    matrix.set_defaults(func=cmd_matrix)

    ablate = sub.add_parser(
        "ablate",
        help="turn off one check at a time and see which class stops being defended",
        description=(
            "Only the kernel arm has checks. Checks 7 and 9 are lifecycle "
            "steps rather than predicates and are not ablatable; results.md "
            "names them with that reason instead of omitting the rows."
        ),
    )
    ablate.add_argument(
        "--dataset", default="batch_a", choices=["batch_a", "batch_b", "gen_a", "gen_b"]
    )
    ablate.add_argument(
        "--check",
        action="append",
        type=int,
        default=None,
        help="repeatable; default: every ablatable check (1-6 and 8)",
    )
    ablate.add_argument(
        "--mode",
        action="append",
        choices=["single", "isolated", "floor"],
        default=None,
        help=(
            "repeatable; default: all three. 'single' asks whether a check is "
            "necessary given the others, 'isolated' what it stops on its own, "
            "'floor' how much of the arm's result is the plumbing"
        ),
    )
    ablate.add_argument("--seed", default="0")
    ablate.add_argument("--model", default="auto")
    ablate.add_argument("--limit", type=int, default=None)
    ablate.add_argument("--out", default=None)
    ablate.add_argument("--quiet", action="store_true")
    ablate.set_defaults(func=cmd_ablate)

    report = sub.add_parser(
        "report",
        help="render results.md from a matrix directory already on disk",
    )
    report.add_argument("matrix", help="a directory left by `mk matrix`")
    report.add_argument(
        "--ablation", default=None, help="a directory left by `mk ablate`"
    )
    report.add_argument(
        "--generated",
        default=None,
        help=(
            "a directory of merged generated suites (from `mk merge`). Their "
            "tables go beside the hand-written ones, never over them"
        ),
    )
    report.add_argument("--out", default=None, help="default ./results.md")
    report.set_defaults(func=cmd_report)

    report_generated = sub.add_parser(
        "report-generated",
        help="splice the generated-corpus section into an existing results.md",
        description=(
            "Needs no matrix. The section lives between fences and is replaced "
            "in place, so the hand-written tables — and the batch B opening "
            "they were measured under — do not move."
        ),
    )
    report_generated.add_argument(
        "merged", help="a directory of merged generated suites, from `mk merge`"
    )
    report_generated.add_argument(
        "--config",
        action="append",
        choices=list(CONFIG_CHOICES),
        default=None,
        help=f"repeatable; default: all of {', '.join(CONFIG_CHOICES)}",
    )
    report_generated.add_argument(
        "--hosted",
        default=None,
        help=(
            "a second directory of merged suites over the same corpus, from a "
            "different machine. The two are compared case by case and the "
            "comparison is printed — the one claim in the document that needs "
            "a second machine to make at all"
        ),
    )
    report_generated.add_argument("--out", default=None, help="default ./results.md")
    report_generated.set_defaults(func=cmd_report_generated)

    merge = sub.add_parser(
        "merge",
        help="reassemble a sharded run into one JSONL and one metadata file",
        description=(
            "Refuses a merge across two corpora, a merge with a shard missing "
            "and a merge with a case in it twice. Percentiles are pooled over "
            "the pooled calls and intervals are recomputed on the pooled n."
        ),
    )
    merge.add_argument("files", nargs="+", help="the shards' JSONL files")
    merge.add_argument("--out", default=None, help="where to write the merged JSONL")
    merge.set_defaults(func=cmd_merge)

    generate = sub.add_parser(
        "generate",
        help="build the generated corpus from the pinned Kaggle datasets",
        description=(
            "Regenerating re-signs every mandate and moves the generated "
            "corpus hash, so every generated table in results.md becomes "
            "stale. Hence --force."
        ),
    )
    generate_sub = generate.add_subparsers(dest="generate_command", required=True)
    generate_corpus = generate_sub.add_parser(
        "corpus", help="storefront, benign tasks, both attack batches, signed and frozen"
    )
    generate_corpus.add_argument("--force", action="store_true")
    generate_corpus.add_argument("--seed", default="p8")
    generate_corpus.set_defaults(func=cmd_generate)

    kaggle = sub.add_parser(
        "kaggle",
        help="pull the pinned datasets, or push/watch/fetch the hosted run",
        description=(
            "Credentials are read by the official CLI from ~/.kaggle/kaggle.json. "
            "Nothing here opens that file and nothing here prints it."
        ),
    )
    kaggle_sub = kaggle.add_subparsers(dest="kaggle_command", required=True)
    kaggle_datasets = kaggle_sub.add_parser(
        "datasets", help="check the pinned datasets against their digests"
    )
    kaggle_datasets.add_argument(
        "--pull", action="store_true", help="download them first"
    )
    kaggle_datasets.set_defaults(func=cmd_kaggle)
    kaggle_check = kaggle_sub.add_parser(
        "check",
        help="preflight: CLI, credentials, and whether the push would be accepted",
        description=(
            "Answers every reason a push would fail before anything uploads. "
            "Kaggle refuses a push whose owner is not the authenticated "
            "account, and finding that out after the dataset has been created "
            "is the expensive order to find it out in."
        ),
    )
    kaggle_check.set_defaults(func=cmd_kaggle)
    kaggle_repo = kaggle_sub.add_parser(
        "repo",
        help="push the repository itself as the dataset the notebook attaches",
        description=(
            "Uploads a staged copy built from an explicit include list, so "
            "data/ (other people's datasets) and runs/ (the output this is "
            "meant to produce) cannot go by accident."
        ),
    )
    kaggle_repo.add_argument(
        "--message", default="mandate repo", help="the dataset version message"
    )
    kaggle_repo.add_argument(
        "--stage", default="runs/kaggle-stage", help="where to build the copy"
    )
    kaggle_repo.add_argument(
        "--stage-only",
        action="store_true",
        help="build the copy and stop, without uploading",
    )
    kaggle_repo.set_defaults(func=cmd_kaggle)
    kaggle_push = kaggle_sub.add_parser(
        "push", help="send the committed notebook and kernel-metadata.json"
    )
    kaggle_push.set_defaults(func=cmd_kaggle)
    kaggle_status = kaggle_sub.add_parser(
        "status", help="the kernel's last run; non-zero unless it completed"
    )
    kaggle_status.set_defaults(func=cmd_kaggle)
    kaggle_pull = kaggle_sub.add_parser(
        "pull", help="fetch the output and verify its digests"
    )
    kaggle_pull.add_argument("--dest", default="runs/kaggle")
    kaggle_pull.add_argument(
        "--shards", type=int, default=None, help="how many shards to insist on"
    )
    kaggle_pull.set_defaults(func=cmd_kaggle)

    corpus = sub.add_parser(
        "corpus", help="count the corpus and check the manifest hash has not moved"
    )
    corpus_sub = corpus.add_subparsers(dest="corpus_command", required=True)
    corpus_verify = corpus_sub.add_parser(
        "verify", help="print the counts and the manifest hash; fail on any edit"
    )
    corpus_verify.add_argument(
        "--freeze",
        action="store_true",
        help="rewrite the manifest from what is on disk (invalidates published numbers)",
    )
    corpus_verify.set_defaults(func=cmd_corpus)

    oracles = sub.add_parser(
        "oracles", help="the oracle selftest: every oracle must be shown to fire"
    )
    oracles_sub = oracles.add_subparsers(dest="oracles_command", required=True)
    oracles_selftest = oracles_sub.add_parser(
        "selftest", help="run all seven oracles against known-successful attacks"
    )
    oracles_selftest.add_argument("--seed", default="s02")
    oracles_selftest.add_argument("--model", default="scripted")
    oracles_selftest.set_defaults(func=cmd_oracles)

    faults = sub.add_parser(
        "faults", help="list the faults that can be armed, and how to arm them"
    )
    faults.set_defaults(func=cmd_faults)

    explain = sub.add_parser(
        "explain", help="say in English what one audit entry decided, and why"
    )
    explain.add_argument("seq", type=int, help="the audit sequence number")
    explain.add_argument(
        "--chain",
        default=str(DEFAULT_CHAIN_PATH),
        help="the exported chain to read (default: the last kernel run's)",
    )
    explain.set_defaults(func=cmd_explain)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
