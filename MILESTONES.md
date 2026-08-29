# Mandate Kernel — Milestone Plan

Derived from [SPEC.md](SPEC.md). SPEC.md is the contract; this file is the order of work
and the acceptance gate for each chunk.

**Written 29 Aug 2026. Deadline 5 Sep.** The spec's day plan assumed a 27 Aug start with
days 1–2 complete. They are not. Seven calendar days remain for 7.5 build days plus
video, so the cut list below is applied *now*, not at the deadline.

## Cuts taken up front

Applied immediately, from the spec's own agreed cut order (§20):

- **Trace viewer** — dropped. The narrator over the audit chain carries the video.
- **Second-model ablation (`claude-sonnet-5`)** — dropped from the plan, re-added in M6
  only if M5's gate is passed a full day early. Two models is a weak test of
  model-independence anyway (§22); the day is worth more spent on the failure suite.
- **Razorpay test-mode path** — kept, but as a 30-minute smoke in M6, not a milestone.
  Every published number comes from the simulator regardless.

Everything else in the spec stands. Seven attack classes, nine checks, three configs,
both batches.

## The rule for every milestone

A milestone is done when **someone who has not read the code can run one command and
see the right thing happen**. Each has a `Prove it` block: what you type, what you must
see. If the `Prove it` block does not run clean, the milestone is not done and the next
one does not start.

---

## M1 — The signed sentence (29 Aug)

The spine. Nothing here moves money; everything downstream is unverifiable without it.

Schemas frozen with `extra="forbid"`. RFC 8785 canonicalisation. ECDSA P-256 fixtures,
mandates pre-signed and shipped (§15 — no signing at runtime). Kernel-owned clock.
Audit hash chain plus the standalone verifier CLI. Repo skeleton. The no-LLM-imports test.

**Prove it**

1. `mk hash-cart fixtures/cart_a.json fixtures/cart_b.json` — two carts with keys in
   different orders, line items in different orders, `1000` vs `1.0e3`. Both print the
   same `cart_hash`.
2. Change one character in a SKU, rerun. The hash differs.
3. `mk verify-chain fixtures/chain.jsonl` — prints `OK, 12 entries, head sha256:…`.
4. Edit any single field in any row of that file, rerun. Prints
   `BROKEN at seq 7` and exits non-zero.
5. `pytest tests/test_no_llm_in_kernel.py` — green.

**Done when** all five hold and the verifier runs from a directory with no project
imports on the path.

**Video value** — indirect but load-bearing. Every later claim reduces to "the chain
says so", and step 4 is what makes that claim mean something.

**Cut rule** — none. This cannot be cut. If it slips past today, the project is a demo
rather than a measurement and we should say so in the README.

---

## M2 — Money moves, and one attack steals it (30 Aug)

The highest-value day and the video's opening thirty seconds. Deliberately combines the
simulator and the undefended agent, because neither is testable alone.

PSP simulator: the `created → authorized → captured` state machine, deterministic
webhook scheduler, the clock driven from the control port. One mock merchant with named
injection points. The undefended agent — planner plus tools, no kernel, no taint guard.
Three benign purchase tasks (the other 22 come in M5). One hand-written A1 payee
substitution that actually lands.

**Prove it**

1. `mk run --task benign-01 --config undefended` — the ledger shows one capture,
   ₹499 to `merchant@upi`, one line item, the payment reaches `captured`.
2. `mk run --task benign-01 --attack A1-seed-1 --config undefended` — the ledger shows
   one capture, ₹499 to `attacker@upi`. Money went to the wrong place and nothing
   complained.
3. Run 2 twice with the same seed. `mk verify-chain` heads are byte-identical.

**Done when** step 2 reproduces from a seed, every time. A flaky attack is not evidence.

**Video value** — this *is* the opening. A normal agent, a product description, and the
money lands with the attacker. No narration needed.

**Cut rule** — if the agent loop is fighting you past midday, drop to one benign task and
one attack. Breadth is M5's job; today only needs the loss to be real.

---

## M3 — The kernel says no (31 Aug)

Checks 1–6 and check 9. The kernel in front of every money tool, fail-closed on store
failure, escalation as a distinct outcome from denial.

**Prove it**

1. `mk run --task benign-01 --config kernel` — allows. Same capture as M2 step 1.
   The kernel did not break the normal path.
2. `mk run --task benign-01 --attack A1-seed-1 --config kernel` — denies.
   Reason code `PAYEE_NOT_ALLOWED`, decision `escalate`, and no PSP call happened.
3. `mk explain <audit-seq>` — prints, in English, the authorising utterance's hash, the
   payee the user allowed, the payee the request carried, and which check refused.
4. One attack per class A2, A3, A4, A5 hand-written and denied with the right reason code.
5. Kill the audit store, replay step 1 — `503`, and no capture in the ledger.

**Done when** steps 1 and 2 both hold. Either alone is worthless: blocking everything is
not a defence, and allowing everything is not either.

**Video value** — the second beat. Same attack, same seed, one config flag, and the
kernel names the sentence the user actually said.

**Cut rule** — checks 1, 2, 3, 4 are the floor. 5 and 6 can slide into M4 if the ledger
work runs long.

---

## M4 — The payments half (1 Sep)

What makes this a payments project rather than an LLM-security project. Checks 7 and 8,
two-phase idempotency with recovery, webhook ingestion, refunds bound to the ledger's
recorded source, and the fault injector.

**Prove it** — each of these is one command, and each is a demo in its own right.
`mk faults` lists what can be armed and prints these lines; faults are armed *on* the
run rather than before it, because every run builds its own seeded world and a fault
armed by an earlier process would have nothing left to fire in.

1. `mk run --task benign-01 --config kernel --fault crash_after_reserve:capture.after_psp_call`
   — the kernel dies after the rail answered and before the ledger heard. The settle loop
   runs the clock past the recovery TTL and the scan polls the PSP. **Exactly one debit
   exists.** The idempotency row reads `terminal`, not `in_flight`, and `mk explain` on the
   `recovery.reconciled` entry says which and why.
2. `mk run --task benign-01 --config kernel --fault duplicate_webhook` — the PSP redelivers
   `captured` with a *fresh* event id. Still one debit. The chain shows `webhook.deduped`,
   twice, with two different event ids and one business key.
3. `mk run --task benign-01 --config kernel --fault reorder_webhook` — `authorized` is
   delivered after `captured`. Refused at the payment state machine and recorded as
   `webhook.refused`, not silently absorbed and not counted as a dedup.
4. `mk run --task benign-04 --attack A7-seed-1 --config kernel` — the support flow supplies
   a refund destination and the agent asks for it. The refund credits the *original payment
   source*, because `PaymentRequest` has no destination field for the payload to fill and
   check 8 reads `payment.source_json`. The same case run `--config undefended` credits
   `attacker@upi`.
5. Retry a request while its key is `in_flight` — `202 retry_later`, not a second charge.

The second crash window, `crash_after_reserve:capture.after_reserve`, is worth a look
beside step 1: the same-shaped reservation, and recovery *releases* it because the rail
never captured. The kernel does not guess which window it was in; it asks.

**Done when** 1, 2 and 4 hold. These are three separate video moments and the answer to
"why is a payments company judging this?"

**Cut rule** — the partition and PSP-timeout faults can go. Crash-after-reserve and
duplicate-webhook cannot; they are class A6, and A6 is the bridge.

**Status: done.** Checks 7 and 8, the two-phase idempotency store with its recovery
context, the barrier-driven recovery scan, webhook ingest with business-level dedup and
out-of-order refusal, refunds bound to `payment.source_json` with cumulative caps, and
the full `F-01`…`F-10` failure suite. `tests/test_m4_gate.py` is the block above; the
suite is `tests/test_failure_suite.py`.

Three things were decided during the build that are worth writing down, because each was
a fork with a worse-looking-but-safer branch:

- **Two audit action names were added** — `authorize.replayed` and `webhook.refused`. The
  spec's §07 list had neither, and the alternatives were to file an authorize replay under
  `refund.replayed` (a refund in the results table for a run that refunded nothing) and to
  count a backwards webhook as a dedup (which would leave `F-08` with no signature in the
  chain at all). SPEC.md §07 now carries both, marked.
- **The simulator credits a misdirected refund** instead of refusing one. A rail that
  always credited the source would be doing check 8's job, which sounds safe and is not:
  A7 becomes inexpressible, its oracle can never return `true`, and the table shows check 8
  beating an attack the harness had quietly made unreachable. That is `S-02`'s failure mode
  wearing the other face.
- **Booking a capture is idempotent across three paths** — the capture response, the
  webhook, and the recovery scan. In a crashed run the webhook often reconciles the ledger
  before the TTL elapses, so the scan finds the work already done and only closes the key.
  All three ask one question of one marker; the first version of this double-counted and
  the ledger's own CHECK constraint caught it.

---

## M5 — The corpus and the oracles (starts 30 Aug in parallel, lands 1 Sep)

Runs alongside M3 and M4 because generation is offline model work and does not block the
kernel. **Start it the morning of the 30th.**

3–5 hand-written seeds per class, expanded offline to 15 variants per class per batch
across the four evasion families. The remaining 22 benign tasks. Seven programmatic
oracles over the ledger and chain — no judge model. Both batches frozen, manifest hashed.

**Prove it**

1. `mk corpus verify` — prints 105 batch A, 105 batch B, 25 benign, and the manifest
   hash. Rerunning after any edit prints a different hash and fails.
2. `mk oracles selftest` — a table, seven rows, each showing its oracle firing `true`
   against a known-successful undefended attack. **All seven must fire.** An oracle that
   cannot fire reads as a perfect defence and would make the headline number a lie.
3. Batch B's directory is sealed and a second read requires a logged override.

**Done when** step 2 is seven-for-seven. This is spec test S-02 and it is the single test
that keeps the results honest.

**Cut rule** — if generation is slow, drop to 10 variants per class and say n=10 in
`results.md`. Never drop a class from batch B alone; that biases the headline.

### Landed

Full size, no cut: 15 per class per batch, 105 + 105, and 25 benign tasks. The seven
oracles read the payment rail — captures, credits and standing instructions, three lists
because a licence to draw money later is neither a debit nor a credit. `mk corpus verify`
prints the counts and one manifest hash covering the cases, the tasks, the seal and every
pre-signed mandate. `mk oracles selftest` is seven for seven.

Four things worth writing down, because none of them was in the plan:

**Three classes were unreachable and had to be made expressible.** A4, A5 and A6 describe
losses the harness could not produce: there was no standing instruction on the rail, no way
for the agent to charge twice, and nothing recording *which cart* a debit settled. So the
simulator now records the basket with the debit and issues standing instructions on request,
and the planner has three optional steps — settlement check, subscription, refund — that run
only for the tasks that declare them. An oracle that cannot return `True` reads as a perfect
defence, so the rail had to permit each loss before the kernel could be credited with
stopping it.

**The selftest's benign control found a real bug on its first run.** The A7 oracle fired on
a clean `benign-04`: the checkout page's own "Pay shopkart at merchant@upi" was being read
as a direction to send the *refund* there. Half of S-02 is the oracle firing on an attack;
the other half is it staying quiet with no attack present, and only the second half could
have caught that.

**The loader refuses more than typos now.** A case is rejected if its injection point is on
a page the class's decision has not read yet, if the task never fetches that page, or if the
task cannot reach the step the class attacks. All three produce a run where the payload is
served and nothing happens — which is indistinguishable in the results table from a defence
that worked. `POINT_ORDER` is re-derived from a real run in the tests rather than trusted.

**The `base64` family cannot land against the deterministic stand-in.** It decodes nothing,
so 21 rows per batch are honest zeroes under `--model scripted`. They are what the model arm
is for, and `results.md` says so rather than the corpus quietly marking them as expected
losses.

---

## M6 — The numbers (2–3 Sep)

**2 Sep is the gate day.** Measure undefended ASR on batch A first, before anything else.
If attacks do not succeed against an undefended agent, there is nothing to defend and the
project needs reshaping that morning — not on the 4th.

Then: planner/quarantined split, provenance tagging, field-admission policy. The
model-only baseline config. The full matrix over three configs. Per-check ablation.
Wilson 95% CIs on every proportion. False-block rate. p50/p99 overhead. `results.md`.

**Prove it**

1. Undefended batch-A ASR is a real quotable number, and it is high.
2. `mk matrix --dataset batch_b` — opened once, logged. Three configs. Results table.
3. `mk ablate` — turning off check 2 alone raises A1's ASR. Every check earns its row.
4. **The false-block rate is non-zero and each blocked benign case is explained by name.**
   A zero here means the benign suite is too easy, and that is a finding about our
   methodology, not a perfect score.
5. `mk run --config model-only --attack A1-seed-1` — the guardrail prompt, and whether it
   holds. This is the answer to "why not just add a guardrail model?"

**Done when** `results.md` has the batch-B table with CIs, the ablation, the false-block
rate, and the overhead columns.

**Cut rule** — the gate at the start of 2 Sep: no real undefended number by that evening
means cutting to four classes (A1, A2, A3, A6) and shipping those properly.

---

## M7 — The telling (4–5 Sep)

Narrator over the chain. README with the containment statement in the first paragraph and
the residual analysis leading, not buried. `scripts/reproduce.sh` verified on a fresh
clone. Architecture and threat-model docs. Video.

**Prove it**

1. `git clone` into a fresh directory, `./scripts/reproduce.sh`, and every number in
   `results.md` regenerates. With no API key — recorded responses replay.
2. Two runs from the same seed produce byte-identical chains.
3. No non-local socket opens during any attack run.
4. The video runs 5 minutes: the loss in 30 seconds · one live attack winning against a
   normal agent · the same attack, the same seed, the kernel denying and the chain naming
   the authorising utterance · the results table *including the false-block rate* · thirty
   seconds on what we still cannot stop.

**Done when** step 1 passes on a machine that has never built the project.

---

## Why this order is strong, and where it is fragile

**Strong.** Every milestone ends in something demonstrable, so we are never more than a
day from knowing whether the project works. The loss is proven real (M2) before the
defence is built (M3), which is the correct order for a measurement — building the kernel
first and then discovering the attacks do not land would waste the week. The failure suite
(M4) is treated as a first-class milestone rather than a stretch goal, because A6 is what
makes this a payments submission. And the corpus runs in parallel, which is the only way
7.5 days of plan fits into 7.

**Fragile.** Three places:

1. **M2 is doing double duty** and it is the day most likely to overrun. Simulator plus
   agent plus a landing attack is a lot. The mitigation is the cut rule: one task, one
   attack, breadth deferred.
2. **M6 compresses the spec's days 7 and 8** into two days. The provenance work (P-08) is
   the piece most likely to be squeezed. If it is, say so in `results.md` — the kernel's
   guarantees are supposed to hold with a fully adversarial agent anyway (§17.7), so the
   taint guard is defence-in-depth, not the contribution.
3. **Nothing is built yet.** If M1 does not close tonight, apply the day-5 gate early:
   four classes, done properly.

**What makes the video land** is not coverage. It is three specific moments: money going
to the wrong payee against a normal agent; the same seed denied with the chain naming the
sentence the user actually said; and one duplicate webhook producing exactly one debit.
Then thirty honest seconds on the four things we cannot stop. A panel at a payments
company has seen plenty of demos that work. They have seen very few that state their own
limits and then hand over a script that reproduces the numbers.
