# Mandate Kernel

A deterministic, LLM-free enforcement kernel that every agent payment call must
pass through, and an adversarial harness that measures which attacks it stops.

A charge is valid only if it is cryptographically bound to a sentence a human
actually said. The kernel is the contribution; the harness is the evidence.

- [SPEC.md](SPEC.md) — the contract.
- [MILESTONES.md](MILESTONES.md) — the order of work and the gate for each chunk.
- [HACK.md](HACK.md) — the reasoning that produced both.

## Status

**M1 is complete. Nothing else is built yet.** M1 is the spine: schemas,
canonicalisation, signing fixtures, the clock, the audit chain and the
standalone verifier. Nothing in it moves money, and everything downstream is
unverifiable without it.

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
