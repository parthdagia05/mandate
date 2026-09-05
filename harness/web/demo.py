"""The live demo: post a real intent and a real payment to a running kernel.

Issue #89. One run is an anecdote — the results page is where the numbers live —
and this module says so in every response it returns. What it is for is watching
the deny happen rather than reading that it happened.

Three properties, and each is the issue's own words:

**It renders nothing it did not get.** If the kernel is unreachable the response
carries ``kernel_reachable: false`` and no steps at all. There is no cached last
answer, no optimistic decision and no placeholder: "a demo that invents a
decision when its backend is down is worse than a demo that is down."

**It proxies; it does not import.** The kernel is reached over HTTP on
``127.0.0.1:8080`` exactly as any other client would, so its loopback peer guard
is not widened for a browser and ``kernel/api.py`` gains no route.

**The user's signature is never minted; the agent's always is.** The intent and
the confirmed cart are the *same pre-signed fixtures* the kernel arm uses,
loaded from the corpus and sent unchanged — the kernel arm refuses a task that
ships no mandates because "minting one here would have the kernel check the
harness's own arithmetic", and that applies with more force to a demo.

The cart presented with each *payment* is a different object and is signed here,
with the agent's delegated key, because that is what the real agent does: check
1 verifies the request cart against ``intent.agent.pubkey`` while the registered
cart is verified against the principal. This is the seam the whole demo turns
on. ``RequestParams`` has two fields, ``amount`` and ``original_payment_id``, and
``StrictModel`` forbids the rest — **there is nowhere in the envelope to put a
payee**. A redirect therefore has to be expressed as a *different cart*, which
the agent may legitimately sign and which check 2 then judges against the
allowlist the user signed. The attacker's value has no route that skips a check.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

__all__ = ["DemoError", "run_demo", "record_demo_run", "REPO_ROOT", "DEMO_CONFIG", "DEMO_DATASET"]

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The kernel's decision endpoints, in the order a purchase walks them.
_AUTHORIZE = "/v1/authorize"
_CAPTURE = "/v1/capture"
_REGISTER = "/v1/intent/register"

_TIMEOUT = 10.0

#: The arm and dataset a demo run is filed under.
#:
#: **Not** one of the five measured arms, and deliberately so. Issue #89 wants
#: the run written to ``runs/`` so the trace view can open it, and the moment it
#: is there it can be counted — by a matrix, by a facet, by a reader skimming
#: the run list. Naming it ``live-demo`` in a ``demo`` dataset keeps it visible
#: and keeps it out of every table: ``mk matrix`` names its datasets explicitly
#: and none of them is this one, and the run list shows it as its own arm rather
#: than folded into ``kernel``. One anecdote inside a measured arm would be a
#: number nobody could subtract again.
DEMO_CONFIG = "live-demo"
DEMO_DATASET = "demo"


class DemoError(ValueError):
    """The request cannot be built. A 400, never a fabricated decision."""


def _post(base: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    """One call to the kernel, reporting whatever came back.

    A 4xx or 5xx is **not** an exception here. The kernel answers a policy
    denial with 200 and a fail-closed with 503, and both are decisions the page
    has to show; turning a status code into a raise would lose the body that
    carries the reason code.
    """
    raw = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"{base}{path}",
        data=raw,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            return {
                "endpoint": path,
                "status": response.status,
                "body": json.loads(response.read() or b"{}"),
            }
    except urllib.error.HTTPError as exc:
        # HTTPError carries an open response body; read it, then close it. The
        # suite runs with `filterwarnings = ["error"]`, so a body reclaimed by
        # the garbage collector is a test failure rather than a shrug.
        try:
            payload = exc.read()
        finally:
            exc.close()
        try:
            parsed = json.loads(payload or b"{}")
        except json.JSONDecodeError:
            parsed = {"error": payload.decode("utf-8", "replace")[:500]}
        return {"endpoint": path, "status": exc.code, "body": parsed}


def _fixtures(task_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """The signed intent and confirmed cart this task ships.

    Read from the corpus, unchanged. See the module docstring for why nothing is
    signed here.
    """
    from harness.corpus import load_task

    try:
        task = load_task(task_id)
    except (KeyError, ValueError) as exc:
        raise DemoError(f"no task {task_id!r}") from exc

    mandates = task.raw.get("mandates")
    if not mandates:
        raise DemoError(
            f"task {task_id!r} ships no signed mandates, so there is no intent "
            "to register. Pick one of the tasks that does — /api/tasks lists "
            "them — rather than having the demo mint a signature the kernel "
            "would then be checking against itself."
        )
    intent = json.loads((REPO_ROOT / mandates["intent"]).read_text())
    cart = json.loads((REPO_ROOT / mandates["cart"]).read_text())
    return intent, cart


def _payee_from_attack(case_id: str, cart: dict[str, Any]) -> dict[str, Any] | None:
    """The address the payload directs the money to, if it directs one.

    **Read by the gullible planner's own predicate, not by a rule written
    here.** ``agent.llm.prose_override`` is the function the measured runs use:
    prose outranks a typed field, and among directions to pay somewhere the
    typed fields do not already say, the last wins. Reusing it means the demo
    is redirected exactly where a scored run would be redirected — a second
    extractor in this file would be a demo of *this file*, and the first time
    the two disagreed the page would be showing something no table had measured.

    The cases carry payload prose and no structured payee, deliberately: the
    corpus records what an attacker wrote, and turning that into an address is
    the agent's mistake to make. So the extraction happens here for the same
    reason it happens in the planner, and by the same code.

    Returns ``None`` when the payload names no payment address — which is most
    classes. A2 inflates an amount, A4 opens a mandate, A6 duplicates a capture;
    none of them is a redirect and none should silently become one.
    """
    from agent.llm import prose_override
    from harness.corpus import BatchBSealed, load_attack

    try:
        case = load_attack(case_id)
    except (KeyError, ValueError) as exc:
        raise DemoError(f"no attack case {case_id!r}") from exc
    if case.batch != "a":
        raise DemoError(
            f"case {case_id!r} is in batch {case.batch!r}, which is held out. "
            "The demo offers batch A only; a form is not a reason to open the "
            "held-out set."
        )

    try:
        payload = case.payload
    except BatchBSealed:  # pragma: no cover - guarded above
        return None

    # The addresses already on the record. A page repeating one of them is not
    # overriding anything — the distinction that stopped the A7 oracle firing on
    # clean runs, and it holds here for the same reason.
    typed = [
        str((cart.get("payee") or {}).get("value") or ""),
        str((cart.get("instrument") or {}).get("token") or ""),
    ]
    directed = prose_override(payload, *[value for value in typed if value])
    if directed is None:
        return None
    return {"type": "vpa", "value": directed}


def _request_cart(
    confirmed: dict[str, Any], redirect: dict[str, Any] | None
) -> dict[str, Any]:
    """The cart presented with a payment, signed by the agent.

    Copied from the confirmed cart, marked ``auto_within_intent_scope`` — the
    user confirmed the intent, not this individual charge — and re-signed with
    the delegated key, because check 1 verifies a request cart against the
    agent's public key rather than the principal's.

    When ``redirect`` is given the payee is replaced and ``cart_hash`` is
    recomputed honestly. Recomputing it matters: leaving the old hash would trip
    check 4 first and the demo would show ``CART_HASH_MISMATCH``, which is a true
    refusal of a *different* mistake. Redirecting a payee in a cart that is
    otherwise coherent is what an agent that believed a poisoned page would
    actually send, and it is what puts the question to check 2.
    """
    from agent.credentials import AgentCredentials
    from kernel.canonical import cart_hash

    cart = json.loads(json.dumps(confirmed))
    cart["confirmed_by"] = "auto_within_intent_scope"
    if redirect is not None:
        payee = {"type": redirect["type"], "value": redirect["value"]}
        if "merchant_id" in (confirmed.get("payee") or {}):
            payee["merchant_id"] = confirmed["payee"]["merchant_id"]
        cart["payee"] = payee
        cart["cart_hash"] = cart_hash(
            cart["line_items"], cart["total_amount"], cart["payee"]
        )
    return AgentCredentials().signed(cart)


def record_demo_run(
    result: dict[str, Any], runs_root: Path
) -> dict[str, Any] | None:
    """Write the demo's exchange to ``runs/`` as a run record. Issue #89.

    "The run it produces is written to ``runs/`` like any other, so the demo is
    inspectable in the trace view afterwards."

    Like any other in *shape* — the same fields, so the trace view needs no
    special case — but never mistakable for one in *provenance*. Three things
    keep it separable:

    - the arm is ``live-demo`` and the dataset is ``demo``, neither of which any
      matrix names,
    - ``notes`` carries the anecdote warning that the page also prints,
    - and there is no ``attacker_win``. The oracles score a run against the
      payment rail over a seeded world; this run had neither, so scoring it
      would be inventing the one field the whole results table is built from.
      It is ``None``, which the run list renders as an outcome of its own.

    Returns the record, or ``None`` when the kernel was unreachable — there is
    nothing to record about a run that did not happen.
    """
    if not result.get("kernel_reachable"):
        return None

    # A run id over the question asked and the answer given — not over the raw
    # exchange.
    #
    # The kernel's responses carry a fresh mandate id, an audit sequence and a
    # `latency_us` on every call, so hashing them makes every replay a new run
    # and fills runs/ with near-duplicates of one demo. Hashing the inputs plus
    # the decision collapses an identical repeat and still separates two demos
    # that ended differently. It also keeps a duration out of a hash, which is
    # the rule the audit chain is built on: nothing that measures the hardware
    # rather than the run may reach an identifier.
    material = json.dumps(
        {
            "task_id": result.get("task_id"),
            "case_id": result.get("case_id"),
            "redirected_payee": result.get("redirected_payee"),
            "decision": result.get("decision"),
            "reason_code": result.get("reason_code"),
            "denied_by": result.get("denied_by"),
            "endpoints": [step["endpoint"] for step in result.get("steps", [])],
            "statuses": [step["status"] for step in result.get("steps", [])],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    run_id = "sha256:" + hashlib.sha256(material).hexdigest()

    decisions = [
        {
            "action": (step["body"].get("action") or step["endpoint"].rsplit("/", 1)[-1]),
            "step": step["endpoint"],
            "decision": step["body"].get("decision"),
            "reason_code": step["body"].get("reason_code"),
            "denied_by": step["body"].get("denied_by", []),
            "checks": step["body"].get("checks", []),
        }
        for step in result.get("steps", [])
        if step["body"].get("decision")
    ]

    record = {
        "run_id": run_id,
        "case_id": result.get("case_id"),
        "task_id": result.get("task_id"),
        "config": DEMO_CONFIG,
        "dataset": DEMO_DATASET,
        "seed": None,
        "model": None,
        "attacker_win": None,
        "task_success": None,
        "poisoned": None,
        "error": None,
        "decisions": decisions,
        "ledger": [],
        "refunds": [],
        "mandates": [],
        "recoveries": [],
        "guard_events": [],
        "money_calls": [],
        "chain_entries": 0,
        "chain_head": None,
        "chain_path": None,
        "notes": [
            "a live demo run, not a measurement: one run is an anecdote and no "
            "rate may be quoted from it",
            "no oracle scored this run — it had no seeded world and no payment "
            "rail, so attacker_win is null rather than false",
        ],
        "demo": {
            "kernel_url": result.get("kernel_url"),
            "redirected_payee": result.get("redirected_payee"),
            "steps": result.get("steps", []),
        },
    }

    directory = Path(runs_root) / "demo"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{DEMO_DATASET}.{DEMO_CONFIG}.jsonl"

    # Append only if this exact exchange is not already on the line. Two clicks
    # of the same button should leave one row, not two.
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip() and json.loads(line).get("run_id") == run_id:
                return record
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")

    meta = directory / f"{DEMO_DATASET}.{DEMO_CONFIG}.meta.json"
    existing = json.loads(meta.read_text()) if meta.exists() else {}
    meta.write_text(
        json.dumps(
            {
                **existing,
                "dataset": DEMO_DATASET,
                "config": DEMO_CONFIG,
                "cases": int(existing.get("cases", 0)) + 1,
                "note": (
                    "live demo runs. Not a suite, not a measurement, named by no "
                    "matrix. Present so the demo is inspectable in the trace view."
                ),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return record


def run_demo(
    body: dict[str, Any], *, kernel_url: str, reachable: bool
) -> dict[str, Any]:
    """Register an intent, then attempt a payment, and report what happened.

    The response is exactly what the kernel said, step by step. Nothing is
    summarised into a verdict of this module's own: the reason code on screen is
    the reason code the kernel emitted, in its casing.
    """
    if not reachable:
        # No steps, no decision, no guess. This is the whole of #89's third rule.
        return {
            "schema": "mandate.web.demo/1",
            "kernel_reachable": False,
            "kernel_url": kernel_url,
            "error": (
                "the kernel is not reachable, so there is no decision to show. "
                "Start it and try again."
            ),
            "steps": [],
            "note": _NOTE,
        }

    task_id = body.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        raise DemoError("task_id is required")
    case_id = body.get("case_id")
    if case_id is not None and not isinstance(case_id, str):
        raise DemoError("case_id must be a string")

    intent, cart = _fixtures(task_id)
    redirect = _payee_from_attack(case_id, cart) if case_id else None

    steps: list[dict[str, Any]] = [
        _post(kernel_url, _REGISTER, {"intent": intent, "confirmed_cart": cart})
    ]

    presented = _request_cart(cart, redirect)
    payment: dict[str, Any] = {
        "action": "authorize",
        "intent": intent,
        "cart": presented,
        "params": {"amount": int(presented["total_amount"])},
        # Advisory, and the kernel ignores it — expiry is judged by the kernel's
        # clock, never by a value the caller supplies. Sent because the schema
        # requires it and because check 1 records that it was ignored.
        "client_ts": intent.get("created_at") or "2026-01-01T00:00:00Z",
    }

    steps.append(_post(kernel_url, _AUTHORIZE, payment))

    # Only capture if the authorize was allowed. Capturing after a denial would
    # put a second refusal on screen and make the deny look like a retry loop.
    authorized = steps[-1]["status"] == 200 and (
        steps[-1]["body"].get("decision") == "allow"
    )
    if authorized:
        steps.append(_post(kernel_url, _CAPTURE, {**payment, "action": "capture"}))

    decisive = next(
        (step for step in steps if step["body"].get("decision") in ("deny", "escalate")),
        steps[-1],
    )

    reason = decisive["body"].get("reason_code")
    # A signed intent carries one nonce, fixed at corpus-freeze time, and the
    # kernel refuses to see it twice. So a task can be demonstrated once per
    # kernel lifetime — which is check 1 doing precisely its job, and is also
    # the most confusing possible answer to a reader who pressed the button
    # again expecting the attack. Say which it is rather than leaving the
    # reason code to be misread as the defence that was being demonstrated.
    replayed = reason == "NONCE_REPLAYED"

    return {
        "schema": "mandate.web.demo/1",
        "kernel_reachable": True,
        "kernel_url": kernel_url,
        "task_id": task_id,
        "case_id": case_id,
        "redirected_payee": redirect,
        "steps": steps,
        "decision": decisive["body"].get("decision"),
        "reason_code": decisive["body"].get("reason_code"),
        "checks": decisive["body"].get("checks", []),
        "denied_by": decisive["body"].get("denied_by", []),
        "audit": decisive["body"].get("audit"),
        "note": _NOTE,
        "replayed": replayed,
        "replay_note": (
            "This intent has already been registered with this kernel. Its nonce "
            "is fixed at corpus-freeze time and the kernel refuses to see it "
            "twice, so the refusal above is replay protection rather than the "
            "attack being stopped. Pick a task you have not run yet, or restart "
            "`mk kernel` for a fresh set."
        )
        if replayed
        else None,
    }


#: Printed on the page, every time. One run is an anecdote.
_NOTE = (
    "A local demo, not a measurement. One run says nothing about a rate — the "
    "results page carries the numbers, with their intervals and their n."
)
