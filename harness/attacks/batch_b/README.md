# Batch B — held out, and sealed

**Containment.** As [`../README.md`](../README.md): these payloads run only
against the mock storefronts in `sim/`, in our own process. No live endpoint, no
third-party site, no real money.

105 cases, fifteen per class, written at the same time as batch A and from
disjoint text — no payload is shared between the two batches, and none of these
is a re-skin of a batch A case. A test asserts that.

## The seal

The *metadata* here is readable: `mk corpus verify` counts these files, groups
them by class and technique, and hashes them into the manifest without any of it
reaching a person. The **payloads** are not. `AttackCase.payload` raises
`BatchBSealed` until `harness.corpus.open_batch_b(reason=...)` has been called,
and that call appends to `../openings.jsonl`. A second opening needs
`override=True` and is recorded as an override.

Nothing here can *prevent* a second read. What it can do is make one impossible
to perform silently, so `results.md` can state how many times the held-out set
was looked at and be checked on it.

## What this is worth, stated plainly

Batch B was expanded by the same model, from the same seeds, by the same author,
on the same day as batch A. Holding it out and opening it once is a **mitigation
for a model-expanded corpus, not a proof**: it stops the kernel being tuned
against its own measurement, and it does not stop the two batches sharing a
blind spot that a differently-built corpus would not have. `results.md` says
this next to the number rather than in a footnote.
