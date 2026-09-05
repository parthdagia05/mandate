---
name: frontend-architecture
description: The architecture for Mandate's web layer - phase 9, issues #82-#91: the mk web artifact API, the results page, run list, trace, compare view, chain panel, live demo and static export. Load before writing, reviewing, or reshaping anything under web/ or harness/web/, before adding a page or an API field, and before touching the export.
---

# Mandate web layer — phase 9

## What this is for

[Issue #69](https://github.com/parthdagia05/mandate/issues/69) states the scope
and its limit: SPEC.md §38 allows a trace viewer "and explicitly nothing beyond
it — a dashboard is not the contribution, reviewers read the repo". So this is a
trace viewer, a results page, and one page that posts to a locally running
kernel so the deny is watchable rather than described.

Done when someone who has not read the code opens one page, picks a case where
the attack landed, then the same seed where the kernel denied it, and reads the
reason code and the chain entry naming the sentence the user actually said — and
the video's three moments are each one click.

| # | Issue | State |
|---|-------|-------|
| 82 | `web/` scaffold, React and Vite pinned | built |
| 83 | Read-only artifact API, `mk web` | built |
| 84 | Design rules, and none of the generated look | built — `web/src/styles.css` |
| 85 | Results page, every proportion with its interval | built |
| 86 | Run list and outcome filters | built |
| 87 | Trace view and the same-seed compare | built — diff in `routes/diff.ts` |
| 88 | Chain verification, server side only | built |
| 89 | Live kernel demo page | built — `harness/web/demo.py` |
| 90 | Static export for the video | built — `mk web --export` |
| 91 | Tests, and the frontend computes no metrics | built |

Shot-by-shot script: [docs/VIDEO.md](../../../../docs/VIDEO.md).

## The shape

Two processes and one direction of travel. The kernel and the harness produced
every number; the web layer renders them and **adds nothing**.

```
runs/*.jsonl  runs/*.meta.json  runs/*.chains        results.md
        │  frozen, hash-sealed, read-only
        ▼
harness/web/   `mk web`  — stdlib Python, serves two things:
        │        · the built assets from web/dist/
        │        · read-only JSON over the artifacts, via harness/metrics.py
        │        · and one proxy route to the kernel, for #89 only
        ▼
web/src/   Vite + React + TypeScript — parses, formats, renders
```

`mk web --export DIR` (#90) is the same JSON written to a file tree instead of
served, beside the assets, so it opens from `file://` with no server.

**Static mode is a path shape, not a second app.** A filesystem has no query
strings, so `?matrix=…&dataset=…` has no static equivalent: the export writes
`api/results/<slug>/<dataset>.json` and `web/src/api/static.ts` maps endpoints
onto that tree. The one place the two shapes differ is the run list, where the
export writes a single unfiltered file and the page narrows it — *selecting rows
for display*, which derives no figure. Nothing else changes, and every number
still comes from `api/results/…json` byte for byte.

**Nothing makes the two languages agree except a test.** `harness/web/export.py`
writes the tree and `static.ts` computes the paths to read it; a rename on
either side produces an export that serves a blank page from `file://` and
passes every other check. `tests/test_web_export.py` asserts the layout against
both.

**`mk web` does not import the kernel's service and adds no route to
`kernel/api.py`.** The kernel stays minimal and LLM-free —
`tests/test_no_llm_in_kernel.py` — and its loopback peer guard is not widened
for a browser. The proxy in #89 is a client of `:8080` like any other.

### Layers inside `web/src/`

```
src/
  api/       fetch + zod schemas. The ONLY place raw JSON is touched.
             Schemas mirror the record's field names exactly (see below).
  format/    the ONLY place a value becomes a string a human reads.
             paise -> "₹499.00", Proportion -> "12.0% [4.2–30.0] (3/25)".
  ui/        presentational components. Props in, DOM out.
  routes/    one file per page. The only layer that knows about the URL.
```

`api → format → ui → routes`. There is **no `model/` layer, deliberately** —
see invariant 2. Nothing derives; things are fetched and formatted.

## Runtime dependencies

`react`, `react-dom`, `zod`, pinned exactly, lockfile committed. That is the
list.

Issue #82: "no component kit, no animation library, no icon font: the design
rules in this phase are the deliverable and a kit would overwrite them." No
chart library either — the two charts are inline SVG. No state manager: view
state is the URL. No date library: timestamps render verbatim. No CDN at
runtime; everything is built into the assets.

`npm run build` emits static assets the Python server serves, and **the repo's
Python dependency list does not grow** — `pydantic` and `cryptography`, still.
`mk web` is `http.server` and stdlib, exactly as `kernel/api.py` already is.

## The invariants

Enforced by `hooks/check_web_invariants.py` and reviewed by the `web-reviewer`
agent. Each exists because breaking it produces a page that renders correctly
and says something false.

### 1. The API returns the record's own field names, renamed nowhere

Issue #83: "a field renamed on the way out is a field the reader cannot grep for
in the JSONL." So the wire format is the record's own **snake_case**, straight
through to the TypeScript types:

```ts
run_id, case_id, task_id, attacker_win, task_success, poisoned,
reason_code, amount_paise, captured_paise, cart_hash, line_items,
unit_amount, log_head, chain_head, chain_entries, latency_us
```

No camelCase conversion at any boundary. It looks wrong in TypeScript and it is
correct here: #91 has a test that the API's JSON carries the record's own field
names, and the whole point is that a reader can `grep case_id runs/*.jsonl` for
anything they see on screen.

### 2. The frontend computes no metric

Issue #91, and it is the reason there is no `model/` layer: "a frontend that
recomputes will one day disagree with `results.md`."

Every proportion, percentile and interval comes from `harness/metrics.py`
through the API. `Proportion.as_dict()` already emits exactly what the page
needs:

```json
{ "label": "targeted ASR", "k": 84, "n": 105, "p": 0.8, "ci95": [0.714, 0.865] }
```

The frontend **formats** that and does nothing else to it. Concretely, in
`web/src/` there is:

- no `.reduce`, `.filter().length`, or `.length /` over an array of cases,
- no Wilson interval, no percentile, no mean, no sum,
- no `p` recomputed from `k / n`,
- no pivot: by-class and by-family tables are separate API responses, because
  the harness computed them (`asr_by_class`, `asr_by_technique`) and a pivot
  built in TypeScript is a second implementation.

Scalar formatting arithmetic is fine and necessary — `100 * p` to render a
percent, `paise / 100` inside `format/money.ts`. The line is **arithmetic over
case arrays**, and #91's mechanical check draws it there.

### 3. No bare point estimate reaches the screen

Issue #85: "an interval is rendered as an interval. No bare point estimate
anywhere on the page, because the point estimate on n of 15 is the exact thing
`results.md` refuses to print alone."

[harness/metrics.py](../../../../harness/metrics.py) makes this structural on
the Python side — `Proportion` has no method that renders the estimate alone,
"and that is the point". Mirror it exactly. One function, in
`format/proportion.ts`, emitting the same string `Proportion.cell()` does:

```ts
export function formatProportion(x: Proportion): string {
  if (x.n === 0) return 'n/a (n=0)'
  return `${pct(x.p)}% [${pct(x.ci95[0])}–${pct(x.ci95[1])}] (${x.k}/${x.n})`
}
```

`pct` is not exported. There is no `formatEstimate`. `n` is printed beside every
proportion. Charts are not exempt: a bar's accessible label is
`formatProportion` and its axis is labelled with `n`.

Use an en dash in the interval and a `/` in the counts, matching `cell()`
character for character — the page and `results.md` are meant to be diffable by
eye.

### 4. Money is integer paise; only `format/money.ts` divides

The ledger is integers from the PSP simulator out. No floats, no rupee
arithmetic, no `/ 100` anywhere else. A float in the display path is how
₹1357.00 becomes ₹1356.99 in Shot 4. Components never sum — see invariant 2.

### 5. Chain verification is server-side only

Issue #88: "**the hash chain is not reimplemented in JavaScript.** A second
implementation that disagrees with the first is a bug factory, and the verifier
is the artifact the project asks reviewers to trust."

So `mk web` runs the standalone verifier — [scripts/verify_chain.py](../../../../scripts/verify_chain.py),
which imports nothing from the project and carries its own RFC 8785 — and the
page shows what it said. There is **no `crypto.subtle`, no SHA-256, and no
canonical JSON encoder in `web/src/`.** A broken chain renders `BROKEN at seq n`
and the run is marked discarded, matching the CLI. The head hash is shown in
full and is copyable, so it can be checked against the JSONL by hand.

### 6. Outcome is not a boolean

Issue #86. Five outcomes, and two of them are the ones that matter:

`attacker win` · `task success` · `blocked` (with its reason code) · `error` ·
`poisoned`

- **A poisoned run shows as discarded, never as a defended one.** The record
  carries that field precisely so a kernel whose own chain did not verify cannot
  be counted as a win.
- **An errored run shows as an error and not as a zero.**

A UI that maps this onto `attacker_win ? 'lost' : 'defended'` erases both, and
they are the two ways this page could flatter the kernel.

### 7. Attacker-authored text has one renderer

Payload text, product descriptions, anything the extractor pulled from a
merchant. Only `ui/Payload.tsx` renders it, as a text node, inside a container
that names its injection point. **`dangerouslySetInnerHTML` appears nowhere** —
the corpus has an evasion family whose entire technique is markup
(`formatting`), and one of those reaching an HTML sink is stored XSS in a page
whose subject is untrusted text.

Shot 4 shows a payload on purpose: the point is that it looks ordinary. So it
renders — marked, escaped, attributed.

### 8. Held-out payloads are not served

`harness/attacks/batch_b/` is sealed and opening it is logged in
`harness/attacks/openings.jsonl`. Neither `mk web` nor `web/src/` reads that
directory. The API serves what the *run record* carries. Where a payload is
withheld the UI says *held out*, not nothing — an empty payload and a withheld
payload are different facts.

### 9. Paths are confined; a path parameter is not a file opener

Issue #83: "paths resolved and confined to the runs directory". Every path from
a request is `Path.resolve()`d and checked to be under the runs root before it
is opened, and a `run_id` is validated against its own shape first. The listing
endpoint is paginated, because the Kaggle phase produces thousands of lines.

### 10. No clock, no absolute URL, no model in the render path

- No `Date.now()`, no `new Date()` with no argument. Timestamps come from the
  record. A page rendering "3 hours ago" cannot be screenshotted twice
  identically, and byte-identical reproduction is REQ-3.
- No absolute URLs. Requests are same-origin relative (`./api/...`) so the
  static export works from `file://`. The live page reaches the kernel **through
  `mk web`'s proxy**, never `http://127.0.0.1:8080` from the browser — the
  kernel's peer guard stays loopback-only.
- No language model, no inference, no scoring. Every verdict on screen was
  computed by the kernel or by `harness/`. The UI has no opinions.
- No analytics, no telemetry, no external font.

### 11. The live demo renders nothing it did not get

Issue #89: "if the kernel is not reachable the page says so and renders
nothing. A demo that invents a decision when its backend is down is worse than a
demo that is down." No optimistic UI, no placeholder decision, no cached last
answer. It is labelled a local demo, not a measurement — one run is an anecdote
and the results page is where the numbers live.

The demo page is **absent from the static export**, with a line saying why:
there is no kernel behind a static file.

### 12. All view state is in the URL

Arm, class, technique, injection point, batch, outcome, and the compare pair:

```
/runs?arm=undefended&class=A1&outcome=attacker_win
/compare/<left_run_id>/<right_run_id>
/runs/:run_id/chain#seq-4
```

The video script arrives at an exact view with no clicking on camera, and a
re-recorded shot must land on the identical view. A filter in `useState` makes
both impossible.

## Design rules (#84)

These are a deliverable, not decoration — "none of the look that reads as
generated".

- One type scale. One accent colour; everything else monochrome. 8px spacing
  grid.
- **Tabular numerals** wherever money, counts or intervals appear, so columns
  line up: `font-variant-numeric: tabular-nums`.
- Buttons look pressable: border, hover, active, visible focus ring, and a
  disabled state that reads as disabled. No pill-shaped everything, no
  gradients, no shadow stacks.
- Tables are dense and left-aligned, numerics right-aligned. **No card grid for
  tabular data.**
- **Transitions: none.** Stated as a rule so it survives the second pass.
- No emoji.
- Formatting lives in `format/` and only there: paise to rupees, the interval
  string, and reason codes in the exact casing the kernel emits —
  `PAYEE_NOT_ALLOWED`, never "Payee not allowed".

## Testing (#91)

- **Formatter unit tests** — paise to rupees, interval rendering, reason-code
  casing. `vitest`, pure functions.
- **A field-name test** — the API's JSON carries the run record's own field
  names, so the JSONL stays greppable against what the page shows. `pytest`.
- **A mechanical no-metrics test** — the built bundle contains no arithmetic
  over case arrays. This is the one that keeps invariant 2 true after the tenth
  component.
- **A build smoke test** — builds the frontend and serves it, so a broken build
  fails a test rather than the video.

No component snapshot tests: they fail on every design tweak and catch none of
the twelve invariants.

## Definition of done, per page

- **#85 Results** — arms as rows; targeted ASR, utility under attack, benign
  utility, false block rate, overhead p50/p99 as columns. Per class, per evasion
  family, and the per-check ablation as their own tables. `n` beside every
  proportion. Every cell links to the cases behind it. Corpus hash, seed, model
  id and arm printed at the top. `CONFIG_BLURB` from
  [harness/report.py](../../../../harness/report.py) above the table, not in a
  tooltip.
- **#86 Run list** — filter and sort by arm, class, technique, injection point,
  batch, outcome. Row opens the trace; two rows open the compare.
- **#87 Trace** — in the order it happened: the utterance and the signed intent;
  the plan step by step with each tool call and what the merchant returned, the
  injection point marked where the payload sat; every kernel decision with its
  reason code and which checks ran; ledger, refunds and mandates kept apart the
  way the record keeps them; recoveries, because a crash that was repaired has
  to be visible as a repair; the chain, its head, its verify status, and the
  entry naming the authorising utterance. Plus the compare: two run ids from the
  same seed, side by side, **with the diverging step highlighted** — that is the
  project's whole claim on one screen.
- **#88 Chain** — entries with `seq`, `ts`, `actor`, `action`, payload; verify
  status from the standalone verifier; `BROKEN at seq n` and discarded on
  failure; full copyable head.
- **#89 Live** — pick a task, optionally an attack case, post the intent then the
  payment; show the decision, the reason code, the checks that ran, and the
  chain entry appended. The run is written to `runs/` like any other, so the
  demo is inspectable in the trace view afterwards.
- **#90 Export** — `mk web --export` writes a directory that opens from the
  filesystem with no server, artifact JSON beside the assets, demo page absent
  with a line saying why, and the corpus hash and run ids it was built from named
  so a screenshot traces back to a suite.

## Reference

- [references/api-contract.md](references/api-contract.md) — the endpoints, the
  exact JSON, and the zod schemas that read it.
- [references/domain.md](references/domain.md) — arms, classes, families, reason
  codes, audit actions. All closed enums; mirror as literal unions and let an
  unknown value fail the parse.
