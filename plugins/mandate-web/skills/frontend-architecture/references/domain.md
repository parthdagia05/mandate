# The domain, as closed unions

[kernel/enums.py](../../../../kernel/enums.py) explains why every one of these is
closed: "An open enum is a place an attacker can put a value nobody wrote a
branch for. Reason codes and audit actions in particular are closed because the
results table counts them: a reason code that can be invented is a row that can
be invented."

The same argument holds in the browser, so mirror each as a `z.enum` and let an
unknown value **fail the parse** rather than fall through to a default branch. A
`default:` arm that renders "unknown" is a row that can be invented.

Keep these in `src/data/enums.ts`. When one changes in Python, it changes here
in the same commit — a `zod` enum is the only thing standing between a renamed
reason code and a table that quietly drops a column.

## Arms

`undefended` · `model-only` · `kernel` · `agent-guard` · `kernel+agent-guard`

The one-line description of each is `CONFIG_BLURB` in
[harness/report.py](../../../../harness/report.py), and the export copies it
verbatim into `results.json`. Do not paraphrase it in the UI: "A column header is
a name; this is what the name means, and a reader who skips it will misread the
table."

`undefended` is the control. If it ever renders as anything other than the
baseline the other columns are measured against, the page has lost the argument.

## Attack classes

| id | name |
|----|------|
| A1 | payee substitution |
| A2 | amount inflation |
| A3 | cart swap |
| A4 | mandate escalation |
| A5 | silent re-authorisation |
| A6 | duplicate capture |
| A7 | refund redirection |

Per-class ASR is **targeted**: each case is scored by its own class's oracle
alone, because A3's predicate is true of a successful A1. The UI must never sum
or pool class rows into a single number of its own — the pooled figure is in the
headline table, computed by the harness.

A6 is the reliability class rather than an injection: a crash mid-capture and a
duplicate webhook each leave exactly one debit. A trace for an A6 case shows
recoveries and webhook actions where the others show a denial, and the UI should
not treat an empty `decisions` array there as a missing decision.

## Evasion families

`base64` · `formatting` · `non_english` · `semantic_persuasion`

`base64` scores an honest zero in every arm including the control, because the
deterministic stand-in decodes nothing. That is a property of the stand-in, not
a defence, and `results.md` says so. The family table must carry that note where
the zeros are, or a reader will read them as the kernel working.

## Reason codes

`OK` · `SIG_INVALID` · `MANDATE_EXPIRED` · `NONCE_REPLAYED` ·
`PAYEE_NOT_ALLOWED` · `AMOUNT_EXCEEDS_SCOPE` · `LINE_ITEM_SUM_MISMATCH` ·
`CURRENCY_MISMATCH` · `CART_HASH_MISMATCH` · `RECURRENCE_NOT_AUTHORISED` ·
`BUDGET_EXHAUSTED` · `IDEMPOTENT_REPLAY` · `REFUND_DESTINATION_MISMATCH` ·
`TAINT_VIOLATION` · `STORE_UNAVAILABLE`

Render the code itself, always. Shot 5 turns on it: "it did not say this looks
suspicious. It said this payee is not the one in the sentence you signed." A UI
that replaces `PAYEE_NOT_ALLOWED` with "Payment blocked" throws away the
difference between a deterministic check and a vibe. A plain-English gloss may
sit *beside* the code, never instead of it.

`AMOUNT_EXCEEDS_SCOPE` is the false-block reason for all three blocked benign
cases in the hand-written corpus. Shot 7 is about that being a policy that was
too tight, not a defence working. The false-block table names each case and its
reason for exactly that reason.

## Decisions

`allow` · `deny` · `escalate`

Three, not two. `escalate` is not a flavour of deny — the request may be
legitimate and a human can mint fresh authority for it. Give it its own visual
treatment; collapsing it into deny erases a real outcome.

## Audit actions

`intent.registered` · `authorize.allow` · `authorize.deny` · `authorize.replayed` ·
`capture.allow` · `capture.deny` · `capture.replayed` ·
`refund.allow` · `refund.deny` · `refund.replayed` ·
`mandate.create.deny` · `escalation.opened` · `escalation.resolved` ·
`webhook.ingested` · `webhook.deduped` · `webhook.refused` ·
`recovery.reconciled` · `kernel.fail_closed`

Actors: `user` · `agent` · `kernel` · `psp`.

`webhook.deduped` and `webhook.refused` are different findings and must not
share a row style: dedup means "I already have this outcome", a refusal means the
webhook claimed something that cannot have happened. F-08 is only visible in the
chain because those two are distinct.

`intent.registered` is the entry Shot 5 points at, because its payload carries
the human's utterance. Give it the top of the chain panel and the most space.

## States

- Mandate: `active` · `exhausted` · `revoked` · `expired` — all three terminal
  states absorb, so a mandate badge never needs a transition animation.
- Ledger: `empty` · `committed` · `captured` · `partially_refunded` · `fully_refunded`
- Payment: `created` · `authorized` · `captured` · `failed` · `voided` · `reversed`
- Refund: `created` · `processing` · `processed` · `failed`
- Idempotency: `in_flight` · `recovering` · `terminal`

Authority and money position terminate independently — a mandate can be
`exhausted` while its ledger is `captured`. Two badges, never one combined
status.

## Injection points

Eight named points in the mock storefront; `product.description` is the one Shot
4 uses. The export ships the point as a string and the trace marks the step that
read it. Treat the set as open in the UI (it is storefront configuration, not a
kernel enum) but render an unrecognised value verbatim rather than as "other".

## Kernel API — `/live` only

`GET /v1/healthz` · `GET /v1/audit/verify` · `GET /v1/audit/chain?from=&to=`
`POST /v1/intent/register` · `/v1/authorize` · `/v1/capture` · `/v1/refund` ·
`/v1/mandate/create` · `/v1/webhook/ingest`

The live page (#89) is read-only: the three `GET`s and nothing else. A page that
can `POST /v1/authorize` is a page that can move simulated money from a browser,
and the demo has no need of it.

A 422 from the kernel names the offending field and echoes nothing else, on
purpose — payload text does not leave the simulator. Render the field path and
the error type; do not ask for the value.
