"""The generated section of ``results.md``: beside the hand-written tables, never over.

The property these guard is unusual for a renderer and is the reason the
generated section is spliced rather than re-rendered: the hand-written tables
were measured under a corpus hash and a batch B opening that both still stand.
Regenerating the whole document to add a section would mean re-running those
suites and opening the held-out set again — every number would move and nothing
about the kernel would have changed. A held-out measurement is not something to
spend on formatting.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness.manifest import generated_corpus_exists
from harness.report_generated import (
    CAVEAT_FENCE,
    SECTION_FENCE,
    generated_caveats,
    load_generated,
    render_generated,
    splice,
)
from harness.runner import CONFIGS

REPO_ROOT = Path(__file__).resolve().parent.parent
MERGED = REPO_ROOT / "runs" / "p8" / "merged"

pytestmark = pytest.mark.skipif(
    not generated_corpus_exists() or not MERGED.is_dir(),
    reason="no merged generated run on this machine",
)


@pytest.fixture(scope="module")
def run():
    loaded = load_generated(MERGED, configs=list(CONFIGS))
    if not loaded.datasets:
        pytest.skip("no merged generated suites in runs/p8/merged")
    return loaded


def test_the_section_names_its_corpus_its_datasets_and_its_seed(run):
    section = "\n".join(render_generated(run))
    assert run.corpus_manifest in section
    assert run.manifest["seed"] in section
    for digest in run.manifest["dataset_digests"].values():
        assert digest in section


def test_splicing_is_idempotent(run):
    """Running it twice produces the same document; running it after a fresh
    measurement updates only the generated numbers."""
    document = "# Results\n\nsomething\n\n## Containment\n\nguarded.\n"
    once = splice(document, run)
    twice = splice(once, run)
    assert once == twice
    assert once.count(SECTION_FENCE[0]) == 1
    assert once.count(CAVEAT_FENCE[0]) == 1


def test_splicing_puts_the_section_before_containment_and_keeps_what_was_there(run):
    document = "# Results\n\nhand-written table\n\n## Containment\n\nguarded.\n"
    out = splice(document, run)
    assert "hand-written table" in out
    assert out.index("hand-written table") < out.index("## The generated corpus")
    assert out.index("## The generated corpus") < out.index("## Containment")


def test_replacing_the_section_does_not_touch_the_hand_written_text(run):
    document = "# Results\n\nkeep me\n\n## Containment\n\nguarded.\n"
    once = splice(document, run)
    tampered = once.replace("## The generated corpus", "## The generated corpus (old)")
    again = splice(tampered, run)
    assert "keep me" in again
    assert "(old)" not in again


def test_the_caveats_are_the_same_five_wherever_they_are_printed(run):
    """A caveat that lives in one place gets separated from its table."""
    caveats = generated_caveats(run)
    assert len(caveats) == 5
    document = splice("# Results\n\n## Containment\n\nx.\n", run)
    for line in caveats:
        assert line in document


def test_the_section_says_the_narrower_interval_is_about_n(run):
    section = "\n".join(render_generated(run))
    assert "same kernel" in section
    assert any("statement about n" in line for line in generated_caveats(run))


def test_the_shipped_results_document_still_leads_with_the_hand_written_tables():
    document = (REPO_ROOT / "results.md").read_text()
    assert document.index("## Batch A — the headline table") < document.index(
        SECTION_FENCE[0]
    )
    assert document.count(SECTION_FENCE[0]) == 1
    assert document.count(CAVEAT_FENCE[0]) == 1
