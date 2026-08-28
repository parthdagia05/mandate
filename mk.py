"""``mk`` — the project's command line.

M1 wired up ``hash-cart``, ``verify-chain`` and ``verify-fixtures``. M2 added
``run``, which is the one a reader who has not read the code types first. M3
adds ``explain`` — the narrator over the audit chain — and ``run --config
kernel`` and ``run --fault``. Later milestones add ``corpus``, ``oracles``,
``matrix`` and ``ablate`` alongside them.

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
    elif check_id == 8 and not failed:
        lines.append(
            f"  the refund goes to {_account(detail['destination'])}, read from "
            f"{detail.get('destination_from')}"
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
    if "action" in payload:
        print(
            f"the request asked to {payload['action']} "
            f"{_rupees(payload.get('amount_paise', 0))}"
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
    for capture in captures:
        payee = capture["payee"]
        print(
            f"  {_rupees(capture['captured_paise'])} -> "
            f"{payee['type']}:{payee['value']}"
            f"   {capture['payment_id']}  state={capture['state']}"
        )
        print(f"  from {capture['source']['type']}:{capture['source']['value']}")
    if not captures:
        print("  (no money moved)")

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
    run.add_argument("--task", required=True, help="a task id, e.g. benign-01")
    run.add_argument(
        "--config",
        default="undefended",
        choices=["undefended", "model-only", "kernel"],
        help="which arm of the experiment; M2 ships 'undefended'",
    )
    run.add_argument("--attack", default=None, help="an attack case id, e.g. A1-seed-1")
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
        help="arm a fault before the run, e.g. store_unavailable:audit",
    )
    run.add_argument("--json", action="store_true", help="print the run record only")
    run.set_defaults(func=cmd_run)

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
