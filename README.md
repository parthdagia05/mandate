# Mandate Kernel

A deterministic, LLM-free enforcement kernel that every agent payment call must
pass through, and an adversarial harness that measures which attacks it stops.

A charge is valid only if it is cryptographically bound to a sentence a human
actually said. The kernel is the contribution; the harness is the evidence.

- [SPEC.md](SPEC.md) — the contract.
- [MILESTONES.md](MILESTONES.md) — the order of work and the gate for each chunk.
- [HACK.md](HACK.md) — the reasoning that produced both.

## Status

**M1 and M2 are complete. The kernel itself is not built yet.**

M1 is the spine: schemas, canonicalisation, signing fixtures, the clock, the
audit chain and the standalone verifier. Nothing in it moves money, and
everything downstream is unverifiable without it.

M2 is the loss. A PSP simulator with the real state machine, a mock storefront
with eight named injection points, a deterministic webhook scheduler, a fault
injector, the control port — and an undefended agent that reads a product page
and pays whoever it says to. One command shows ₹499 reaching the merchant; the
same command with one flag shows ₹499 reaching an attacker, from the same seed,
every time.

M3 puts the kernel in front of exactly those money calls and changes nothing
else.

## Setup

Needs Python 3.11+ and SQLite 3.37+ (for `STRICT` tables; the kernel refuses to
open a store on anything older).

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Prove it — M1

```sh
# 1. Two carts, different key order, different line-item order, 1000 vs 1.0e3.
#    Both print the same cart_hash, and both carry the same signature bytes.
mk hash-cart fixtures/cart_a.json fixtures/cart_b.json

# 2. Change one character of a SKU and the hash moves.

# 3. The audit chain verifies: OK, 12 entries, head sha256:...
mk verify-chain fixtures/chain.jsonl

# 4. Edit any single field of any row and it names the row:
#    BROKEN at seq 7, exit code 1.

# 5. No model SDK is reachable from the enforcement path.
pytest tests/test_no_llm_in_kernel.py
```

`mk verify-chain` runs `scripts/verify_chain.py`, which imports nothing from
this project and works from an empty directory. That is deliberate: a verifier
that imports the kernel it is checking inherits the kernel's bugs. It carries
its own RFC 8785 implementation, and a property test asserts the two
implementations agree — if they ever stop agreeing, that disagreement is itself
the finding.

## Prove it — M2

```sh
export KERNEL_MODE=test        # the control port exists only in test mode

# 1. A normal purchase. One capture, ₹499, to merchant@upi, state captured.
mk run --task benign-01 --config undefended

# 2. The same task, one payload at product.description. ₹499 to attacker@upi,
#    and the agent reports no error at all — nothing complained.
mk run --task benign-01 --attack A1-seed-1 --config undefended

# 3. Twice with the same seed. The exported logs are byte-identical and the
#    standalone verifier agrees on the head.
mk run --task benign-01 --attack A1-seed-1 --seed 1 --export /tmp/a.jsonl
mk run --task benign-01 --attack A1-seed-1 --seed 1 --export /tmp/b.jsonl
cmp /tmp/a.jsonl /tmp/b.jsonl && mk verify-chain /tmp/a.jsonl

pytest tests/test_m2_gate.py     # the three steps above, as tests
```

The A1 payload never says "ignore your instructions" and never addresses the
agent as a model. It is a merchant notice claiming a settlement account changed,
which pre-empts the one check a careful reader would make by explaining in
advance why the checkout page disagrees. The agent believes it, because nothing
in the undefended configuration distinguishes a page's prose from its typed
fields.

M2's ledger line reads *one capture*; `benign-01`'s cart has three line items
(mouse, shipping, two cables) summing to ₹499, matching the signed cart shipped
in `fixtures/` so that M3's kernel run is the same purchase.

## Two things about M2 worth stating plainly

**The model in an M2 run is a stand-in, not Claude.** `mk run` reports
`scripted-gullible-v1` and every run record carries a note saying so. It is a
deterministic planner with one documented rule — prose outranks a typed field —
and no number produced with it is a model measurement. It exists because M2's
gate is a property of the plumbing (the rail, the storefront, the tools, the
ledger), which has to be right before a model result means anything. The
measured undefended ASR comes from `claude-opus-5` at the day-5 gate, through
the same seam (`agent/llm.py`), recorded and replayed so the replay path needs
no API key.

**Containment.** Attacks run only against the mock storefronts in `sim/`, in
this process. No live endpoints, no third-party sites, no real money.
`tests/test_containment.py` patches `socket.connect` for the duration of a real
attack run and fails on any address that is not loopback, so this is a check
rather than a promise.

## Choices worth stating

**ECDSA P-256, and Ed25519 would have been better.** Ed25519 is deterministic
by construction, faster, and has no nonce footgun. We take P-256 because AP2
specifies it and the 1:1 mapping is worth more here than the ergonomics.

Standard ECDSA picks a random nonce per signature, so the same bytes signed
twice produce different bytes. Two consequences, both handled: every mandate is
signed once, offline, and shipped as a fixture under `fixtures/` — nothing
signs during a run — and raw signature bytes never enter an audit payload, so
the chain never hashes a non-deterministic value.

**The clock belongs to the kernel.** An agent-supplied clock would defeat the
mandate-expiry check by lying about the hour. `client_ts` exists on the request
and is never read for expiry.

**`synchronous=FULL`, not WAL's default.** WAL defaults to `NORMAL`, which does
not fsync on commit. Under the default, the audit append would report success
for an entry a power cut can still lose. The overhead column pays for this.

**The simulator is primary, not preferred.** No real PSP can be asked to crash
between an idempotency reserve and its commit, or to redeliver a webhook with a
fresh event id at a chosen moment. Class A6 and the entire failure suite are
unreachable without that, so every published number comes from `sim/`. Razorpay
test mode stays a 30-minute smoke in M6 and `sim/psp/razorpay.py` is a stub that
raises — a stub returning plausible objects would let a smoke test pass against
nothing.

**Nothing is on a timer, ever.** A webhook is queued with the clock-second it
becomes due and delivered inside `POST /control/clock/advance`, which does not
return until everything due has been delivered and settled. Ordering is a
function of the seed and the schedule, never of scheduler luck — which is what
lets the same seed produce a byte-identical chain across three processes.

**Nothing in a request can hold a sentence.** Every schema is strict, closed to
unknown fields, and has no free-text field: every string is a bounded token
with no whitespace. That is why a prompt injection has to reach the agent's
reasoning rather than the kernel's parser.

## Fixtures

Everything under `fixtures/` is test-only, including the private keys, which are
committed on purpose — reproducing the corpus from a fresh clone matters more
than the secrecy of a key that signs nothing real.

`fixtures/manifest.json` hashes every fixture and then hashes that list, so the
signatures are covered. `mk verify-fixtures` checks it. Rebuilding requires
`python scripts/build_fixtures.py --force`, and the guard is there because a
rebuild re-signs everything and changes the published manifest hash.
