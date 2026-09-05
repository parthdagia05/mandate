"""The static export. Issue #90.

A directory that opens from the filesystem with no server, for the video and as
a Kaggle output artifact. Four properties are tested, and each is one of the
issue's bullets:

- it opens from ``file://`` — relative asset URLs, no absolute paths,
- the demo page is absent, with a line saying why,
- it names the corpus hash and the run ids it was built from,
- and, not in the issue but implied by everything else in this repository, two
  exports of one runs tree are byte-identical.

The last test here is the one that would break silently: the Python export
writes a file tree and the TypeScript client computes the paths to read it, in
two languages that cannot check each other. So the layout is asserted against
the same rule the frontend implements.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from harness.web.export import ExportError, _slug, export

REPO = Path(__file__).resolve().parents[1]
DIST = REPO / "web" / "dist"

pytestmark = pytest.mark.skipif(
    not (DIST / "index.html").is_file(),
    reason="web/dist is absent; run `cd web && npm ci && npm run build`",
)


@pytest.fixture()
def runs(tmp_path: Path) -> Path:
    """A small runs tree with one matrix, so the export is quick and complete."""
    root = tmp_path / "runs"
    root.mkdir()
    record = {
        "run_id": "sha256:" + "a" * 64,
        "case_id": "A1-a-05",
        "task_id": "benign-13",
        "config": "undefended",
        "seed": "0",
        "model": "scripted-gullible-v1",
        "attacker_win": True,
        "task_success": False,
        "decisions": [],
        "ledger": [],
        "chain_entries": 0,
    }
    with (root / "batch_a.undefended.jsonl").open("w") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    (root / "batch_a.undefended.meta.json").write_text(
        json.dumps(
            {
                "seed": "0",
                "model": "scripted-gullible-v1",
                "corpus_manifest": "sha256:" + "f" * 64,
                "dataset": "batch_a",
                "config": "undefended",
            },
            sort_keys=True,
        )
    )
    return root


def test_it_refuses_when_there_is_no_build(runs: Path, tmp_path: Path):
    """It copies a build; it never invokes npm.

    That is what keeps node off the path ``scripts/reproduce.sh`` takes.
    """
    with pytest.raises(ExportError, match="npm run build"):
        export(runs, tmp_path / "nothing-here", tmp_path / "site")


def test_the_pages_open_from_the_filesystem(runs: Path, tmp_path: Path):
    out = tmp_path / "site"
    export(runs, DIST, out)
    index = (out / "index.html").read_text()
    # `base: './'` in vite.config.ts is the setting this asserts. An absolute
    # `/assets/...` is a 404 under file://.
    assert re.search(r'src="\./assets/', index)
    assert 'src="/assets/' not in index
    assert (out / "assets").is_dir()


def test_the_demo_page_is_absent_with_a_line_saying_why(runs: Path, tmp_path: Path):
    out = tmp_path / "site"
    export(runs, DIST, out)
    notice = (out / "demo.html").read_text()
    assert "not in this export" in notice
    # And it says *why*, not merely that it is gone.
    assert "no kernel behind a static file" in notice
    assert "must not show one" in notice


def test_it_names_what_it_was_built_from(runs: Path, tmp_path: Path):
    """So a screenshot can be traced back to a suite."""
    out = tmp_path / "site"
    summary = export(runs, DIST, out)
    on_disk = json.loads((out / "export.json").read_text())
    assert on_disk == summary
    assert summary["seeds"] == ["0"]
    assert summary["models"] == ["scripted-gullible-v1"]
    assert summary["corpus_manifests"] == ["sha256:" + "f" * 64]
    assert summary["runs_total"] == 1
    assert summary["run_ids"] == ["sha256:" + "a" * 64]
    assert summary["runs_root"].endswith("runs")


def test_a_cap_is_recorded_rather_than_applied_silently(runs: Path, tmp_path: Path):
    """A run list missing runs that does not say so is a corpus that looks
    smaller than it is."""
    with (runs / "batch_a.undefended.jsonl").open("a") as handle:
        for index in range(3):
            handle.write(
                json.dumps(
                    {
                        "run_id": f"sha256:{str(index) * 64}",
                        "case_id": f"A1-a-0{index}",
                        "task_id": "benign-01",
                        "config": "kernel",
                    },
                    sort_keys=True,
                )
                + "\n"
            )
    summary = export(runs, DIST, tmp_path / "site", limit=2)
    assert summary["runs_total"] == 4
    assert summary["runs_exported"] == 2
    assert summary["runs_omitted"] == 2


def test_the_run_list_holds_every_run_not_one_page_of_them(runs: Path, tmp_path: Path):
    """`MAX_LIMIT` clamps rather than refuses, so a single large request comes
    back quietly truncated. An export that shipped one page would name a corpus
    of thousands and hold a hundred, and nothing else in the suite would notice.
    """
    from harness.web.api import MAX_LIMIT

    with (runs / "batch_a.undefended.jsonl").open("a") as handle:
        for index in range(MAX_LIMIT + 5):
            handle.write(
                json.dumps(
                    {
                        "run_id": f"sha256:{index:064d}",
                        "case_id": f"A1-a-{index}",
                        "task_id": "benign-01",
                        "config": "kernel",
                    },
                    sort_keys=True,
                )
                + "\n"
            )

    out = tmp_path / "site"
    export(runs, DIST, out, limit=1)
    listing = json.loads((out / "api" / "runs" / "all.json").read_text())
    assert listing["total"] == MAX_LIMIT + 6
    assert len(listing["rows"]) == MAX_LIMIT + 6
    assert listing["next_cursor"] is None


def test_two_exports_of_one_tree_are_byte_identical(runs: Path, tmp_path: Path):
    """A directory that differed run to run could not be diffed, and "the same
    corpus produces the same artifact" is REQ-3 one level up."""
    first = tmp_path / "a"
    second = tmp_path / "b"
    export(runs, DIST, first)
    export(runs, DIST, second)

    files = sorted(p.relative_to(first) for p in first.rglob("*") if p.is_file())
    assert files == sorted(p.relative_to(second) for p in second.rglob("*") if p.is_file())
    for relative in files:
        assert (first / relative).read_bytes() == (second / relative).read_bytes(), relative


def test_a_rerun_replaces_rather_than_accumulates(runs: Path, tmp_path: Path):
    """A stale artifact left behind from a previous corpus is the worst kind of
    file in a directory whose whole job is provenance."""
    out = tmp_path / "site"
    export(runs, DIST, out)
    stale = out / "api" / "runs" / "sha256-stale.json"
    stale.write_text("{}")
    export(runs, DIST, out)
    assert not stale.exists()


# ---------------------------------------------------------------------------
# the two languages agree on the layout
# ---------------------------------------------------------------------------


def test_the_export_layout_matches_what_the_frontend_looks_for(runs: Path, tmp_path: Path):
    """`harness/web/export.py` writes it; `web/src/api/static.ts` reads it.

    Nothing makes the two agree except this test. A rename on either side would
    otherwise produce an export that serves a blank page from `file://` and
    passes every other check in the suite.
    """
    out = tmp_path / "site"
    export(runs, DIST, out)

    static_ts = (REPO / "web" / "src" / "api" / "static.ts").read_text()

    # The paths the frontend computes, read out of the module that computes them.
    expected = {
        "health": "api/health.json",
        "facets": "api/facets.json",
        "matrices": "api/matrices.json",
        "runs": "api/runs/all.json",
    }
    for endpoint, relative in expected.items():
        assert f"'{relative}'" in static_ts, f"static.ts no longer maps {endpoint}"
        assert (out / relative).is_file(), f"the export did not write {relative}"

    # And the run trace and chain, whose paths are built from a slug.
    run_id = "sha256:" + "a" * 64
    assert (out / "api" / "runs" / f"{_slug(run_id)}.json").is_file()
    assert (out / "api" / "runs" / _slug(run_id) / "chain.json").is_file()

    # The slug rule itself, stated identically in both languages.
    assert _slug("sha256:abc") == "sha256-abc"
    assert "replace(/:/g, '-')" in static_ts
    assert "replace(/\\//g, '-')" in static_ts


def test_every_run_in_the_index_has_a_trace_file(runs: Path, tmp_path: Path):
    """A row that opens nothing is worse than a row that is not there."""
    out = tmp_path / "site"
    export(runs, DIST, out)
    listing = json.loads((out / "api" / "runs" / "all.json").read_text())
    for row in listing["rows"]:
        assert (out / "api" / "runs" / f"{_slug(row['run_id'])}.json").is_file()


def test_the_exported_json_is_the_apis_own_json(runs: Path, tmp_path: Path):
    """The export is the same projection, written instead of served."""
    from harness.web.api import WebApi

    out = tmp_path / "site"
    export(runs, DIST, out)
    api = WebApi(runs)
    served = api.get("/api/facets", {}).body
    assert json.loads((out / "api" / "facets.json").read_text()) == served
