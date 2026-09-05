"""``mk web --export``: a directory that opens from the filesystem. Issue #90.

For the video, and as a Kaggle output artifact. No server, no network, no
kernel — so the JSON the API would have served is written out beside the assets
and the pages fetch it as files.

Three things this does that a naive dump would not:

**The demo page is absent, with a line saying why.** There is no kernel behind a
static file, and a demo that cannot get a decision must not show one. Removing
it silently would leave a reader wondering; leaving it in would leave them
clicking a button that cannot work.

**It names what it was built from.** The corpus hash, the matrix id, the seed,
the model and the run ids, in ``export.json`` and on every page that carries a
number, so a screenshot traces back to a suite rather than floating free.

**It is byte-identical across two invocations.** Sorted keys, compact
separators, no timestamp of the export itself. A directory that differed run to
run could not be diffed, and "the same corpus produces the same artifact" is the
same claim as REQ-3 one level up.

The export is Python and stdlib only. It never invokes npm — it copies a build
that already exists, and says so plainly when there is none.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from harness.web.api import WebApi

__all__ = ["export", "ExportError", "DEMO_NOTICE"]


class ExportError(RuntimeError):
    """The export cannot be made. Never a partial directory left behind."""


#: Written where the demo page would have been.
DEMO_NOTICE = """<!doctype html>
<meta charset="utf-8">
<title>Mandate — the live demo is not in this export</title>
<style>
  body { font: 14px/1.6 system-ui, -apple-system, "Segoe UI", Helvetica, sans-serif;
         margin: 0; padding: 32px; color: #16150f; background: #fbfaf6; }
  main { max-width: 68ch; }
  h1 { font-size: 19px; margin: 0 0 16px; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
         background: #f2f0e8; border: 1px solid #d8d5cb; padding: 1px 4px; }
  a { color: #8a2b1f; }
</style>
<main>
  <h1>The live demo is not in this export.</h1>
  <p>
    There is no kernel behind a static file, and a demo that cannot get a
    decision must not show one. Every other page here is a record of runs that
    already happened, so it needs no backend; the demo is the one page that asks
    a running kernel a live question.
  </p>
  <p>
    To use it, serve the same build with <code>mk web</code> and start the kernel
    on <code>127.0.0.1:8080</code>.
  </p>
  <p><a href="./index.html">Back to the results</a></p>
</main>
"""


def _write(path: Path, body: Any) -> None:
    """One JSON file, deterministically encoded.

    ``sort_keys`` and fixed separators, with no timestamp of the export itself:
    two exports of one runs tree are byte-identical, so the directory can be
    diffed and a changed file means changed evidence.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )


def export(
    runs_root: Path,
    dist: Path,
    out: Path,
    *,
    matrix: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Write the assets and every artifact the pages read into ``out``.

    Returns a summary of what was written, which the CLI prints. ``limit`` caps
    how many run traces are exported — the generated corpus is 5775 cases per
    arm and a full export of every trace is gigabytes for a five-minute video.
    The cap is *recorded in the manifest* rather than applied silently, because
    a run list that is missing runs and does not say so is a corpus that looks
    smaller than it is.
    """
    dist = Path(dist)
    out = Path(out)
    if not (dist / "index.html").is_file():
        raise ExportError(
            f"no build at {dist}. Run `cd web && npm ci && npm run build` first — "
            "this export copies a build, it never invokes npm."
        )

    api = WebApi(runs_root)
    index = api.index

    # Assets first, so a failure part-way leaves no half-populated data tree
    # beside a working page.
    out.mkdir(parents=True, exist_ok=True)
    for existing in ("assets", "index.html", "api", "demo.html", "export.json"):
        target = out / existing
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
    shutil.copytree(dist, out, dirs_exist_ok=True)

    written: list[str] = []

    def emit(relative: str, body: Any) -> None:
        _write(out / relative, body)
        written.append(relative)

    emit("api/health.json", api.health().body)
    emit("api/facets.json", api.facets().body)
    matrices = api.matrices().body
    emit("api/matrices.json", matrices)

    # Results, for every matrix and every dataset in it.
    exported_matrices: list[str] = []
    for entry in matrices["matrices"]:
        directory = entry.get("dir")
        if directory is None or "matrix_id" not in entry:
            continue
        if matrix is not None and directory != matrix:
            continue
        exported_matrices.append(directory)
        for dataset in entry["datasets"]:
            outcome = api.results({"matrix": [directory], "dataset": [dataset]})
            if outcome.status == 200:
                emit(f"api/results/{_slug(directory)}/{dataset}.json", outcome.body)

    for entry in matrices["ablations"]:
        outcome = api.ablation({"dir": [entry["dir"]]})
        if outcome.status == 200:
            emit(f"api/ablation/{_slug(entry['dir'])}.json", outcome.body)

    # The whole run list in one file.
    #
    # Not paginated, and not one file per filter combination: a filesystem has
    # no query strings, so a served `?class=A1&config=kernel` has no static
    # equivalent, and exporting the cross product of six dimensions would be
    # thousands of files most of which nobody opens. The pages filter and
    # paginate this list themselves when they are running from `file://` —
    # which is *selecting rows for display*, not deriving a number, and the
    # numbers on every page still come from `results.json` exactly as they do
    # when served.
    total = len(index.entries)
    everything = api.runs({"limit": ["1"], "cursor": ["0"]}).body
    rows: list[dict[str, Any]] = []
    cursor: int | None = 0
    # Paged, not asked for in one call. `MAX_LIMIT` clamps a large `limit`
    # rather than refusing it, so a single request for every row would come
    # back quietly truncated and the export would ship a corpus an order of
    # magnitude smaller than the one it names — the precise failure the
    # `--max-runs` cap is recorded to avoid.
    while cursor is not None:
        page = api.runs({"limit": ["1000"], "cursor": [str(cursor)]}).body
        rows.extend(page["rows"])
        cursor = page["next_cursor"]
    everything = {
        **everything,
        "total": len(rows),
        "limit": len(rows),
        "cursor": 0,
        "next_cursor": None,
        "rows": rows,
    }
    if len(rows) != total:
        raise ExportError(
            f"the run list paged to {len(rows)} rows but the index holds {total}. "
            "Refusing to write an export whose corpus would look smaller than it is."
        )
    emit("api/runs/all.json", everything)

    # Traces and chains.
    run_ids = list(index.entries)
    capped = run_ids if limit is None else run_ids[:limit]
    for run_id in capped:
        detail = api.run(run_id, chain=False)
        if detail.status == 200:
            emit(f"api/runs/{_slug(run_id)}.json", detail.body)
        chain = api.run(run_id, chain=True)
        if chain.status == 200:
            emit(f"api/runs/{_slug(run_id)}/chain.json", chain.body)

    # The demo page is replaced by the reason it is absent.
    (out / "demo.html").write_text(DEMO_NOTICE, encoding="utf-8")
    written.append("demo.html")

    # Provenance from the suites themselves, not only from the matrices.
    #
    # Every suite writes a `.meta.json` beside its JSONL carrying the seed, the
    # model and the corpus manifest it ran against. A tree with no matrix — one
    # suite, or a sharded run not yet merged — still has all three, and an
    # export that named none of them for such a tree would be exactly the
    # untraceable screenshot #90 exists to prevent.
    suites = _suite_provenance(api.runs_root)

    summary = {
        "schema": "mandate.web.export/1",
        "runs_root": str(api.runs_root),
        "matrices": sorted(exported_matrices),
        # Both the per-dataset map and the matrix-level hash. A matrix may span
        # the hand-written corpus and the generated one, and the two have
        # separate manifests on purpose; older matrices carry only the single
        # hash, and an export that reported nothing for those would be an export
        # a screenshot could not be traced back from.
        "corpus_manifests": sorted(
            {
                manifest
                for entry in matrices["matrices"]
                for manifest in (entry.get("corpus_manifests") or {}).values()
            }
            | {
                entry["corpus_manifest"]
                for entry in matrices["matrices"]
                if entry.get("corpus_manifest")
            }
            | suites["corpus_manifests"]
        ),
        "seeds": sorted(
            {entry["seed"] for entry in matrices["matrices"] if "seed" in entry}
            | suites["seeds"]
        ),
        "models": sorted(
            {entry["model"] for entry in matrices["matrices"] if "model" in entry}
            | suites["models"]
        ),
        "runs_total": total,
        "runs_exported": len(capped),
        "runs_omitted": total - len(capped),
        "run_ids": sorted(capped),
        "demo_page": (
            "absent — there is no kernel behind a static file, and a demo that "
            "cannot get a decision must not show one"
        ),
        "files": sorted(written),
    }
    _write(out / "export.json", summary)
    return summary


def _suite_provenance(root: Path) -> dict[str, set[str]]:
    """Seeds, models and corpus hashes, read from every ``*.meta.json``.

    A malformed or missing meta file is skipped rather than raised on: a stale
    suite in ``runs/`` is a normal thing to have on disk, and it must not stop
    an export of the ones beside it.
    """
    found: dict[str, set[str]] = {"seeds": set(), "models": set(), "corpus_manifests": set()}
    for path in sorted(root.rglob("*.meta.json")):
        try:
            body = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(body, dict):
            continue
        for key, field in (
            ("seeds", "seed"),
            ("models", "model"),
            ("corpus_manifests", "corpus_manifest"),
        ):
            value = body.get(field)
            if isinstance(value, str) and value:
                found[key].add(value)
    return found


def _slug(value: str) -> str:
    """A path segment from a run id or a directory, with no separators left in.

    ``sha256:abc…`` becomes ``sha256-abc…``. The value has already been matched
    against its own pattern before it reaches here; this is about producing a
    filename, not about safety.
    """
    return value.replace(":", "-").replace("/", "-")
