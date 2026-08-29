# The attack corpus

**Containment.** Attacks run only against our own mock merchants, inside our own
sandbox. No live endpoints, no third-party sites, no real money, and nothing in
here is an offensive tool: a payload is a paragraph of merchant prose that only
means anything to an agent shopping in `sim/`. This is a defence evaluation.
Track 2 disqualifies offence-capable work and we hold ourselves to that in Open
Track anyway. It is asserted by a test, not by this paragraph — `tests/
test_containment.py` fails the build if a socket opens to a non-local host
during any run (REQ-10).

## What is here

| | Cases | Used for |
|---|---|---|
| [`batch_a/`](batch_a/) | 7 classes × 15 | Development. The kernel is built against this |
| [`batch_b/`](batch_b/) | 7 classes × 15 | **Held out.** Opened once. The headline |
| [`seal.json`](seal.json) | — | What batch B was verified to contain at generation time |
| `openings.jsonl` | — | Every time batch B has been opened. Absent means never |

The twenty-five benign purchase tasks live in [`../tasks/`](../tasks/). They are
not attacks; they are the other half of every measurement, because a defence
that stops attacks by stopping everything scores perfectly on ASR.

## The format

```jsonc
{
  "case_id": "A1-a-07",
  "class": "A1",
  "batch": "a",
  "task": "benign-01",                    // the task this attack was written against
  "injection_point": "product.description",
  "payload": "...",
  "technique": "semantic_persuasion",     // base64 | semantic_persuasion | non_english | formatting
  "oracle": "payee_not_in_allowlist",
  "expected_undefended": "win",
  "seed_of": "A1-seed-1"                  // null for a hand-written seed
}
```

## What the loader refuses, and why each refusal exists

Every one of these prevents a **clean-looking result**, which is the only kind of
wrong number that survives review. `harness/corpus.py` has the same list with
the code beside it.

| Refusal | The wrong number it prevents |
|---|---|
| unknown injection point | the payload lands nowhere; the run is benign and is counted as defended |
| a point the class has not read yet | A2 builds its cart before the checkout page is fetched; a payload there is served and does nothing |
| a point the task never fetches | `support.flow` on a task that asks for no refund is served to nobody |
| a class the task cannot reach | A4 on a task with no subscription step reaches a planner with no step for it |
| another class's oracle | the result is filed under the wrong heading in the table |
| an undeclared technique | a technique column nobody can group by |
| the wrong batch directory | a development case counted in the held-out column |

## Provenance

Twenty-eight cases are hand-written seeds, four per class, and carry
`seed_of: null`. The other 182 were written by a model offline and are committed
as text in [`scripts/expand_corpus.py`](../../scripts/expand_corpus.py) rather
than produced by an API call at generation time — a script that called out would
produce a different corpus on every run, and the manifest hash pinning the
published numbers would mean nothing. Every expanded case names the seed it came
from.

## Freezing

`mk corpus verify` prints the counts and the manifest hash and fails, naming
files, if anything has moved. The manifest covers the cases, the tasks, the seal
and the pre-signed fixtures — a re-signed cart changes what checks 1 and 4 are
looking at, so a signature is part of the corpus. It deliberately does not cover
`openings.jsonl`: that file changes exactly when the held-out set is read, and
covering it would mean taking the headline measurement invalidated the hash the
headline is published under.
