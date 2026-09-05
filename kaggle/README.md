# Running the generated corpus on Kaggle, with the internet off

Every table in `results.md` that is computed over the generated corpus can be
computed here instead. Three things make that worth doing and one makes it
worth writing down.

**Internet disabled is the point, not a constraint.** The deterministic
stand-in needs no network, so a run with `enable_internet: false` makes the
containment claim the strong one: *zero non-local sockets*, asserted by the
platform as well as by `harness/containment.py`. The notebook still arms the
guard — a platform setting and a guard that refuses are different evidence, and
the run record has to carry the second one — and ships its containment record
in the output so the merged run record can quote it.

**The notebook is committed.** `mandate_suite.ipynb` and this
`kernel-metadata.json` are in the repository, not authored in a browser. A
hand-run notebook whose exact code nobody kept is not a reproducible
measurement.

**Nothing is installed over the network.** The repository is attached as a
dataset and put on `sys.path`; its only third-party dependencies — `pydantic`
and `cryptography` — are already in the Kaggle Python image, and the notebook
records their versions rather than assuming them. The two corpus datasets are
attached **by version** and verified against `harness/datasets.json` before a
row is read.

## Before the first push

Two things, once.

**Install the CLI and put your credentials in place.**

```
.venv/bin/pip install kaggle
```

Then Kaggle → Settings → **API Tokens** tab. The page offers two things and
they are not the same:

*API Tokens (Recommended)* — *Generate New Token*. Supported by the CLI from
1.8.0 (current is 2.x, so any fresh install has it).

*Legacy API Credentials* — *Create New Token*, further down the page. This is
the one that downloads a **`kaggle.json`**, which is what
`~/.kaggle/kaggle.json` means and what every `mk kaggle` command below expects:

```
mkdir -p ~/.kaggle
mv ~/Downloads/kaggle.json ~/.kaggle/kaggle.json
chmod 600 ~/.kaggle/kaggle.json
```

It **expires any existing legacy key**, so if something else on your machine is
still using one, that breaks. Nothing in this repository opens the file; the
official CLI does.

**Then check, before anything uploads:**

```
mk kaggle check
```

Five rows: the CLI is installed (looked for on `PATH` *and* beside the running
interpreter, because `.venv/bin/python mk.py` does not put `.venv/bin` on
`PATH`), its version, credentials present, both metadata files naming one
owner, and an authenticated call actually succeeding. Kaggle refuses a push
whose owner is not the authenticated account, and finding that out after the
dataset has been created is the expensive order to find it out in.

**Push the repository as a dataset**, so what the notebook attaches exists. `mk kaggle repo` builds a staged copy from an explicit include list and
uploads that — not the working directory, which holds `data/` (46 MB of other
people's datasets, pinned by digest and re-pulled rather than redistributed)
and `runs/` (the output the hosted run is supposed to produce):

```
mk kaggle repo --stage-only     # see exactly what would be sent, ~5.8 MB
mk kaggle repo --message "P8 generated corpus"
```

It `create`s the first time and `version`s afterwards, decided by asking Kaggle
rather than by a flag — a flag would be wrong exactly once, on the day it was
hardest to debug. Two flags it always passes, and both matter:

`--public`, taken from `isPrivate` in `dataset-metadata.json` rather than from
whether somebody remembered to type it. **`kaggle datasets create` is private
by default**, and the visibility of a published artefact should be a fact in a
committed file.

`--keep-tabular`, because Kaggle converts tabular files to CSV by default.
Every file here is hashed into a manifest, so a helpful conversion would break
the corpus rather than improve it.

**Two spellings that will waste a push if you get them wrong**, both now caught
by `mk kaggle check`:

*Dataset attachments are `owner/slug/N`*, not `owner/slug/versions/N`. The
latter is how the web URL reads; the CLI rejects it locally with "Invalid
dataset specification".

*Kaggle derives a kernel's slug from its **title**, not from the `id` you
push.* A title that slugs to something else lands the kernel at an address the
metadata does not name — the push succeeds with a warning, and every `status`
and `pull` afterwards fails with "Cannot access kernel", which reads like a
permissions problem and is not one.

The staged copy carries the generated corpus, so the notebook *runs* it rather
than regenerating it. The three Kaggle datasets it was derived from are
attached anyway and verified against `harness/datasets.json`, but nothing on
the run path reads a row from them: re-running the numbers needs a clone, and
only re-deriving the corpus needs the datasets.

## The run

```
mk kaggle push                 # sends the notebook and its metadata
mk kaggle status               # non-zero until it says complete
mk kaggle pull --shards 8      # refuses a partial output, verifies digests
mk merge runs/kaggle/*.jsonl   # refuses a missing shard or a repeated case
mk report-generated runs/kaggle/merged
```

`mk kaggle pull` will not fetch the output of a run that did not complete. A
timed-out kernel leaves a partial output directory that merges cleanly and
produces a table of the cases that happened to finish.

## If a model arm is ever run here

That is a **different claim** and must not share a table with this one. It needs
`enable_internet: true`, the key from Kaggle Secrets, and
`api.anthropic.com` passed as the single narrow allowance so that
`model_endpoint_allowed` is recorded on every line. A model-arm row from an
internet-on session cannot sit in a table headed by a zero-socket claim, and
`harness/report.py` keeps them apart by reading that field rather than by
trusting the heading.

The guarantee stays what it always was: **no socket opened through Python's
`socket` module.** A hosted runner does not make it a sandbox.
