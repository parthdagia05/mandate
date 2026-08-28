"""``mk`` — the project's command line.

M1 wired up ``hash-cart``, ``verify-chain`` and ``verify-fixtures``. M2 adds
``run``, which is the one a reader who has not read the code types first.
Later milestones add ``explain``, ``fault``, ``corpus``, ``oracles``,
``matrix`` and ``ablate`` alongside them.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

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

    print()
    print(f"task_success  {record.task_success}")
    print(f"attacker_win  {record.attacker_win}")
    print(f"log           {record.log_entries} entries, head {record.log_head}")
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
    run.add_argument("--json", action="store_true", help="print the run record only")
    run.set_defaults(func=cmd_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
