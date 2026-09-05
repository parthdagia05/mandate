# `web/` — the trace viewer

The frontend for [issue #69](https://github.com/parthdagia05/mandate/issues/69).
A trace viewer and a results page over the artifacts the harness already wrote,
plus one page that posts to a locally running kernel.

## Build and run it

```
cd web && npm ci && npm run build     # the one-liner
mk web                                # serves the build and the artifact API
```

Then open <http://127.0.0.1:8090>. The Python side needs no node and the node
side needs no Python — `mk web` serves a directory that is already built, and
`npm run build` reads nothing from `runs/`.

For the live demo page, start the kernel on `127.0.0.1:8080` as well. Without it
that one page says so and renders nothing; every other page is a record of runs
that already happened and needs no backend.

## Develop against it

```
mk web                # terminal 1 — the artifact API on :8090
cd web && npm run dev # terminal 2 — vite on :5173, proxying /api to :8090
```

## Check it

```
npm run typecheck     # tsc --strict, with noUncheckedIndexedAccess
npm test              # vitest over the pure modules
```

Both also run from the Python side: `pytest tests/test_web_build.py` builds the
frontend and serves it, so a broken build fails a test rather than the video.

## The static export

```
mk web --export site --matrix runs/m6 --max-runs 200
```

Writes a directory that opens from the filesystem with no server, for the video
and as a Kaggle output artifact. The demo page is absent from it, with a line
saying why: there is no kernel behind a static file.

## What is in here

```
src/api/      zod schemas and the fetcher. The only place raw JSON is touched.
src/format/   the only place a value becomes a string a human reads.
src/ui/       presentational components. Props in, DOM out.
src/routes/   one file per page, plus the step diff and the hash router.
```

Three runtime dependencies — `react`, `react-dom`, `zod` — pinned exactly, with
the lockfile committed. No component kit, no chart library, no state manager, no
date library, no CDN. The design rules of issue #84 are in `src/styles.css` and
are the deliverable rather than decoration.

**The frontend computes no metric.** Every proportion, percentile and interval
comes from `harness/metrics.py` — the functions `results.md` is rendered from —
and this side formats it. `tests/test_web_no_metrics.py` checks that
mechanically, because a frontend that recomputes will one day disagree with
`results.md` and nobody will be able to say which is wrong.
