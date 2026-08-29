#!/usr/bin/env python3
"""Build the signed fixtures. Run offline, once, at freeze time.

    python3 scripts/build_fixtures.py --force

Standard ECDSA picks a random nonce per signature, so signing the same bytes
twice produces different bytes. That makes runtime signing incompatible with
REQ-3, and it also makes *this script* non-idempotent — every run produces
different signatures and therefore a different manifest hash. Hence the
``--force`` guard: rerunning it by accident would churn every fixture in the
repo and invalidate the published manifest hash for no reason.

Everything under ``fixtures/`` is test-only. The private keys are committed on
purpose: reproducing the corpus from a fresh clone matters more than the
secrecy of a key that signs nothing real.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from kernel.audit.chain import AuditChain  # noqa: E402
from kernel.canonical import cart_hash, jcs, sha256_hex, sha256_of  # noqa: E402
from kernel.clock import Clock  # noqa: E402
from kernel.crypto import (  # noqa: E402
    generate_keypair,
    public_key_b64u,
    sign_object,
    utterance_hash,
)
from kernel.enums import AuditAction, AuditActor  # noqa: E402
from kernel.ids import IdFactory  # noqa: E402
from kernel.rng import RunRandom  # noqa: E402
from kernel.stores.db import connect  # noqa: E402
from sim.merchants.shopkart import CATALOGUE, SHIPPING_PAISE, SHIPPING_SKU  # noqa: E402

#: The catalogue's prices, plus shipping, as the fixture builder needs them:
#: ``sku -> unit_amount``. Read from the simulator rather than restated, so a
#: price that moves in one place cannot leave a signed cart behind at the old one.
UNIT_AMOUNTS: dict[str, int] = {
    sku: entry[1] for sku, entry in CATALOGUE.items()
} | {SHIPPING_SKU: SHIPPING_PAISE}

FIXTURES = REPO_ROOT / "fixtures"
TASKS = REPO_ROOT / "harness" / "tasks"


def write_keys() -> tuple[str, str]:
    (FIXTURES / "keys").mkdir(parents=True, exist_ok=True)
    encoded = {}
    for name in ("user", "agent"):
        private = generate_keypair()
        (FIXTURES / "keys" / f"{name}.key.pem").write_bytes(
            private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        pub = public_key_b64u(private)
        (FIXTURES / "keys" / f"{name}.pub.b64u").write_text(pub + "\n")
        encoded[name] = private
    return encoded["user"], encoded["agent"]


class TaskTotalMismatch(ValueError):
    """A task's stated total is not what its own line items add up to.

    Raised here rather than tolerated, because this script is the last place
    the two can be compared before they are signed. A cart signed for a total
    its items do not sum to would fail check 3's sum conjunct on every benign
    run, and the false-block rate would be measuring a typo.
    """


def task_line_items(task: dict) -> list[dict]:
    """The basket the task describes, in the order the planner builds it.

    Same order as ``agent/planner.py``: the chosen SKU first, then whatever the
    task adds. Order does not change the hash — canonicalisation sorts the items
    — but building it the same way here means a mismatch between the fixture and
    the run is a real disagreement rather than a difference in construction.
    """
    return [
        {"sku": task["sku"], "qty": task["qty"], "unit_amount": UNIT_AMOUNTS[task["sku"]]}
    ] + [dict(item) for item in task.get("extra_line_items", [])]


def build_task_mandates(task: dict, user_key, agent_key, ids, clock) -> tuple[dict, dict]:
    """One signed intent and one signed cart for one benign task.

    Built *from the task*, so the corpus has one source of truth for what the
    user asked for. The alternative — a hand-maintained fixture beside a
    hand-maintained task — is two statements of the same fact that drift, and
    the drift shows up as a benign run the kernel refuses for a reason nobody
    intended.
    """
    scope = dict(task["scope"])
    scope["allowed_payees"] = [
        {"type": task["expect"]["payee"]["type"], "value": task["expect"]["payee"]["value"]}
    ]

    intent = {
        "mandate_id": ids.intent_id(),
        "issued_at": clock.now_rfc3339(),
        "expires_at": "2026-01-01T00:15:00Z",
        "nonce": ids.nonce(),
        "principal": {"user_id": "u_ananya", "auth": "device_biometric"},
        "agent": {"agent_id": "a_shopper", "pubkey": public_key_b64u(agent_key)},
        "utterance_hash": utterance_hash(task["utterance"]),
        "scope": {
            "max_amount": scope["max_amount"],
            "per_txn_cap": scope["per_txn_cap"],
            "currency": scope["currency"],
            "allowed_payees": scope["allowed_payees"],
            "allowed_categories": scope["allowed_categories"],
            "max_transactions": scope["max_transactions"],
            "recurring": scope["recurring"],
        },
    }
    intent["sig"] = sign_object(user_key, intent)

    payee = {**task["expect"]["payee"], "merchant_id": task["merchant"]}
    line_items = task_line_items(task)
    total = sum(item["qty"] * item["unit_amount"] for item in line_items)
    if total != task["expect"]["total_paise"]:
        raise TaskTotalMismatch(
            f"{task['task_id']}: line items sum to {total} but expect says "
            f"{task['expect']['total_paise']}"
        )

    cart = {
        "mandate_id": ids.cart_id(),
        "parent": intent["mandate_id"],
        "payee": payee,
        "line_items": line_items,
        "total_amount": total,
        "currency": scope["currency"],
        "cart_hash": cart_hash(line_items, total, payee),
        "instrument": {
            "token": "tok_scoped_01",
            # The instrument's own ceiling, which is not the mandate's. Set to
            # the per-transaction cap so the two agree: an instrument bound
            # below the cap would refuse purchases the intent permits, and the
            # false-block rate would be measuring the fixture.
            "max_amount": scope["per_txn_cap"],
            "expires_at": "2026-01-01T00:15:00Z",
        },
        "confirmed_by": "user",
    }
    cart["sig"] = sign_object(user_key, cart)
    return intent, cart


def write_cart_variants(cart: dict) -> None:
    """The same cart, written two ways. Both must hash identically.

    ``cart_a`` puts the line items in one order; ``cart_b`` puts them in
    another, reverses every key, and writes two amounts in exponential form.
    Neither file uses the canonical line-item order, so the sort is doing real
    work in both cases. The signature is byte-identical in both files because
    the signing input is the canonical form — which is the whole argument for
    canonicalising before signing.
    """
    # As built: mouse, shipping, cable — which is not the canonical
    # (sku, unit_amount, qty) order either.
    a = dict(cart)

    b = {key: cart[key] for key in reversed(list(cart))}
    b["line_items"] = [
        {"unit_amount": 1.0e3, "sku": "SK-SHIP-STD", "qty": 1},
        {"qty": 2, "unit_amount": 2000, "sku": "SK-CABLE-USBC"},
        {"sku": "SK-MOUSE-01", "unit_amount": 4.49e4, "qty": 1},
    ]

    (FIXTURES / "cart_a.json").write_text(json.dumps(a, indent=2) + "\n")
    (FIXTURES / "cart_b.json").write_text(json.dumps(b, indent=2) + "\n")


def check(check_id: int, name: str, result: str) -> dict:
    return {"id": check_id, "name": name, "result": result}


PASSED_PREFIX = [
    check(1, "mandate_integrity", "pass"),
    check(2, "payee_allowlist", "pass"),
    check(3, "amount_lattice", "pass"),
    check(4, "cart_binding", "pass"),
    check(5, "recurrence_scope", "pass"),
    check(6, "execution_budget", "pass"),
]


def build_chain(intent: dict, cart: dict) -> str:
    """Twelve entries covering an allow, a deny, an escalation and a refund.

    Built through the real :class:`AuditChain`, not hand-written, so the
    fixture cannot drift from the code that produces chains at run time.
    """
    clock = Clock()
    with tempfile.TemporaryDirectory() as tmp:
        conn = connect(Path(tmp) / "fixture.db")
        chain = AuditChain(conn, clock)
        mandate_id = intent["mandate_id"]
        cart_id = cart["mandate_id"]
        cart_h = cart["cart_hash"]

        def entry(actor, action, payload, advance=1):
            chain.append(actor, action, payload)
            clock.advance(advance)

        entry(
            AuditActor.KERNEL,
            AuditAction.INTENT_REGISTERED,
            {
                "mandate_id": mandate_id,
                "intent_hash": sha256_of(intent),
                "utterance_hash": intent["utterance_hash"],
                "scope": intent["scope"],
                "checks": [check(1, "mandate_integrity", "pass")],
                "decision": "allow",
                "reason_code": "OK",
            },
        )
        entry(
            AuditActor.KERNEL,
            AuditAction.AUTHORIZE_ALLOW,
            {
                "mandate_id": mandate_id,
                "cart_id": cart_id,
                "cart_hash": cart_h,
                "amount_paise": cart["total_amount"],
                "payee": cart["payee"],
                "checks": PASSED_PREFIX + [check(9, "audit_append", "pass")],
                "decision": "allow",
                "reason_code": "OK",
            },
        )
        entry(
            AuditActor.KERNEL,
            AuditAction.CAPTURE_ALLOW,
            {
                "mandate_id": mandate_id,
                "cart_hash": cart_h,
                "amount_paise": cart["total_amount"],
                "idempotency_key": sha256_hex(
                    f"{mandate_id}\x1f{cart_h}\x1fcapture".encode("utf-8")
                ),
                "checks": [
                    check(1, "mandate_integrity", "pass"),
                    check(3, "amount_lattice", "pass"),
                    check(6, "execution_budget", "pass"),
                    check(7, "idempotency", "pass"),
                    check(9, "audit_append", "pass"),
                ],
                "decision": "allow",
                "reason_code": "OK",
            },
        )
        entry(
            AuditActor.PSP,
            AuditAction.WEBHOOK_INGESTED,
            {
                "event": "payment.captured",
                "event_id": "evt_0001",
                "mandate_id": mandate_id,
                "cart_hash": cart_h,
                "amount_paise": cart["total_amount"],
                "checks": [check(7, "idempotency", "pass")],
            },
        )
        entry(
            AuditActor.PSP,
            AuditAction.WEBHOOK_DEDUPED,
            {
                "event": "payment.captured",
                "event_id": "evt_0002",
                "note": "redelivery with a fresh event id; dedup is on "
                "(mandate_id, cart_hash), not the event id",
                "mandate_id": mandate_id,
                "cart_hash": cart_h,
                "debits_after": 1,
                "checks": [check(7, "idempotency", "fail")],
            },
        )
        entry(
            AuditActor.KERNEL,
            AuditAction.AUTHORIZE_DENY,
            {
                "mandate_id": mandate_id,
                "cart_id": cart_id,
                "attack_class": "A1",
                "requested_payee": {
                    "type": "vpa",
                    "value": "attacker@upi",
                    "merchant_id": "shopkart",
                },
                "allowed_payees": intent["scope"]["allowed_payees"],
                "checks": [
                    check(1, "mandate_integrity", "pass"),
                    check(2, "payee_allowlist", "fail"),
                ],
                "decision": "escalate",
                "denied_by": [2],
                "reason_code": "PAYEE_NOT_ALLOWED",
            },
        )
        entry(
            AuditActor.KERNEL,
            AuditAction.ESCALATION_OPENED,
            {
                "mandate_id": mandate_id,
                "reason_code": "PAYEE_NOT_ALLOWED",
                "utterance_hash": intent["utterance_hash"],
                "note": "escalated to a human; never to the model",
            },
        )
        entry(
            AuditActor.USER,
            AuditAction.ESCALATION_RESOLVED,
            {
                "mandate_id": mandate_id,
                "resolution": "rejected",
                "note": "no new authority minted; old authority is never widened",
            },
        )
        entry(
            AuditActor.KERNEL,
            AuditAction.AUTHORIZE_ALLOW,
            {
                "mandate_id": mandate_id,
                "cart_id": cart_id,
                "cart_hash": cart_h,
                "amount_paise": 12500,
                "payee": cart["payee"],
                "checks": PASSED_PREFIX + [check(9, "audit_append", "pass")],
                "decision": "allow",
                "reason_code": "OK",
            },
        )
        entry(
            AuditActor.KERNEL,
            AuditAction.CAPTURE_ALLOW,
            {
                "mandate_id": mandate_id,
                "cart_hash": cart_h,
                "amount_paise": 12500,
                "checks": [
                    check(1, "mandate_integrity", "pass"),
                    check(3, "amount_lattice", "pass"),
                    check(6, "execution_budget", "pass"),
                    check(7, "idempotency", "pass"),
                    check(9, "audit_append", "pass"),
                ],
                "decision": "allow",
                "reason_code": "OK",
            },
        )
        entry(
            AuditActor.KERNEL,
            AuditAction.REFUND_ALLOW,
            {
                "mandate_id": mandate_id,
                "amount_paise": 12500,
                "destination_source": "ledger.payment.source_json",
                "note": "destination read from the recorded payment source; "
                "the request has no destination field to read",
                "checks": [
                    check(1, "mandate_integrity", "pass"),
                    check(8, "refund_binding", "pass"),
                    check(9, "audit_append", "pass"),
                ],
                "decision": "allow",
                "reason_code": "OK",
            },
        )
        entry(
            AuditActor.KERNEL,
            AuditAction.RECOVERY_RECONCILED,
            {
                "mandate_id": mandate_id,
                "idempotency_state": "terminal",
                "polled_by": "client_ref",
                "debits_after": 2,
                "checks": [check(7, "idempotency", "pass")],
            },
            advance=0,
        )

        exported = chain.export_jsonl()
        conn.close()
    return exported


def write_manifest() -> str:
    """Hash every shipped fixture, then hash that map.

    The signatures live inside those files, so the manifest hash covers them —
    which is what makes "the corpus is frozen" a checkable claim (REQ-11)
    rather than a promise.
    """
    files = {}
    for path in sorted(FIXTURES.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            rel = path.relative_to(REPO_ROOT).as_posix()
            files[rel] = sha256_hex(path.read_bytes())

    manifest = {"algorithm": "sha256", "canonicalisation": "RFC 8785", "files": files}
    manifest_hash = sha256_of(manifest)
    (FIXTURES / "manifest.json").write_text(
        jcs({**manifest, "manifest_hash": manifest_hash}) + "\n"
    )
    return manifest_hash


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="required: rerunning re-signs everything and changes the manifest hash",
    )
    args = parser.parse_args()
    if not args.force:
        print(
            "Refusing to rebuild fixtures without --force.\n"
            "ECDSA signing is not deterministic, so a rebuild changes every "
            "signature and the published manifest hash.",
            file=sys.stderr,
        )
        return 2

    FIXTURES.mkdir(exist_ok=True)
    (FIXTURES / "mandates").mkdir(exist_ok=True)
    (FIXTURES / "utterances").mkdir(exist_ok=True)
    for stale in list((FIXTURES / "mandates").glob("*.json")) + list(
        (FIXTURES / "utterances").glob("*.txt")
    ):
        stale.unlink()

    user_key, agent_key = write_keys()
    clock = Clock()
    ids = IdFactory(clock, RunRandom("fixture-seed-0"))

    # One pair per *distinct pair of paths*, in task order. Two tasks that name
    # the same files share one authority on purpose — benign-04 is benign-01's
    # purchase followed by a refund, and a refund has to be judged against the
    # mandate the purchase was made under or check 8 refuses it for the wrong
    # reason.
    first: dict[str, tuple[dict, dict]] = {}
    for path in sorted(TASKS.glob("*.json")):
        task = json.loads(path.read_text())
        mandates = task.get("mandates")
        if not mandates:
            continue
        key = mandates["intent"]
        if key in first:
            continue
        intent, cart = build_task_mandates(task, user_key, agent_key, ids, clock)
        first[key] = (intent, cart)
        (REPO_ROOT / mandates["intent"]).write_text(json.dumps(intent, indent=2) + "\n")
        (REPO_ROOT / mandates["cart"]).write_text(json.dumps(cart, indent=2) + "\n")
        (FIXTURES / "utterances" / f"{task['task_id'].replace('-', '_')}.txt").write_text(
            task["utterance"] + "\n"
        )

    intent, cart = first["fixtures/mandates/intent_benign_01.json"]
    write_cart_variants(cart)
    (FIXTURES / "chain.jsonl").write_text(build_chain(intent, cart))

    manifest_hash = write_manifest()
    print(f"fixtures rebuilt, manifest {manifest_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
