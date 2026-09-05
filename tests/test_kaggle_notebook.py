"""The hosted notebook, rehearsed locally against a fake mount.

**Why this test exists.** Four of the first five hosted runs failed, and three
of those failures were properties of *paths* rather than of anything being
measured: Kaggle nests attachments under ``datasets/<owner>/<slug>`` rather
than mounting them flat; ``/kaggle/input`` is a read-only file system and this
project writes an audit chain beside itself on every kernel-arm case; and
``/kaggle/working`` is simultaneously the scratch directory and the upload, so
anything left there comes back down the wire.

None of those needed Kaggle to reproduce. Each cost a push, a queue and a
two-minute run to discover, and each was a one-line fix. So the notebook takes
its three roots from the environment, and this runs **its actual cells** —
parsed out of the committed ``.ipynb``, not a paraphrase of them — against a
temporary tree shaped like a Kaggle session, with the mount made read-only so
the copy-out is exercised rather than assumed.

What it deliberately does not test: Kaggle's own behaviour. The dataset
attachment, the slug derivation and the session limits are the platform's, and
the honest way to check those is the preflight in ``harness/kaggle.py`` plus a
real run.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from harness.kaggle import KERNEL_DIR, METADATA_PATH, stage_repo
from harness.manifest import generated_corpus_exists

NOTEBOOK = KERNEL_DIR / json.loads(METADATA_PATH.read_text())["code_file"]

pytestmark = pytest.mark.skipif(
    not generated_corpus_exists(),
    reason="the generated corpus has not been built",
)


def code_cells() -> list[str]:
    body = json.loads(NOTEBOOK.read_text())
    return ["".join(c["source"]) for c in body["cells"] if c["cell_type"] == "code"]


@pytest.fixture
def session(tmp_path, monkeypatch):
    """A directory tree shaped like a Kaggle session, with a read-only mount.

    The repository is staged **nested** under ``datasets/<owner>/<slug>``,
    because that is the layout that actually broke, and the flat one would pass
    a search that only knew about it.
    """
    mount = tmp_path / "input" / "datasets" / "parthdagia" / "mandate-repo"
    stage_repo(mount)
    (mount / "dataset-metadata.json").unlink()

    # Read-only, so a notebook that ran from the mount fails here rather than
    # a hundred cases into a hosted session.
    for path in sorted(mount.rglob("*"), reverse=True):
        path.chmod(path.stat().st_mode & ~stat.S_IWUSR)
    mount.chmod(mount.stat().st_mode & ~stat.S_IWUSR)

    monkeypatch.setenv("MANDATE_INPUT", str(tmp_path / "input"))
    monkeypatch.setenv("MANDATE_WORKING", str(tmp_path / "working"))
    monkeypatch.setenv("MANDATE_SCRATCH", str(tmp_path / "scratch"))
    monkeypatch.setenv("MANDATE_PLAN", "gen_a")
    monkeypatch.setenv("MANDATE_ARMS", "undefended,kernel")
    monkeypatch.setenv("MANDATE_LIMIT", "2")
    monkeypatch.chdir(tmp_path)

    yield tmp_path

    # Restore write bits so pytest can clean the directory up.
    for path in sorted(mount.rglob("*")) + [mount]:
        path.chmod(path.stat().st_mode | stat.S_IWUSR)


def test_the_notebooks_own_cells_run_end_to_end(session):
    """Every code cell, in order, in one namespace — the notebook's real logic.

    Imports resolve to the already-loaded modules rather than to the staged
    copy, so this rehearses the *notebook* rather than module loading. That is
    the half that kept breaking.
    """
    namespace: dict = {"__name__": "__main__"}
    for index, source in enumerate(code_cells()):
        try:
            exec(compile(source, f"<cell {index}>", "exec"), namespace)  # noqa: S102
        except Exception as exc:  # noqa: BLE001 — the point is to name the cell
            pytest.fail(f"cell {index} raised {type(exc).__name__}: {exc}")

    working = Path(os.environ["MANDATE_WORKING"])
    index_path = working / "digests.json"
    assert index_path.is_file(), "the notebook wrote no digests.json"
    body = json.loads(index_path.read_text())

    # The output holds the measurement and nothing else.
    assert body["files"], "no output files recorded"
    for name in body["files"]:
        assert name.endswith((".jsonl", ".meta.json")), name
    assert not (working / "mandate").exists(), "the repo copy leaked into the output"
    assert not list(working.glob("*.chains")), "per-case chains leaked into the output"

    # And it is a real measurement: the attacks landed, the kernel refused.
    lines = {
        name: [json.loads(l) for l in (working / name).read_text().splitlines() if l.strip()]
        for name in body["files"]
        if name.endswith(".jsonl")
    }
    undefended = [r for n, rs in lines.items() if ".undefended." in n for r in rs]
    kernel = [r for n, rs in lines.items() if ".kernel." in n for r in rs]
    assert undefended and kernel
    assert any(r["attacker_win"] for r in undefended), "no attack landed undefended"
    assert not any(r["attacker_win"] for r in kernel)


def test_the_run_is_contained_and_says_so(session):
    namespace: dict = {"__name__": "__main__"}
    for index, source in enumerate(code_cells()):
        exec(compile(source, f"<cell {index}>", "exec"), namespace)  # noqa: S102

    containment = namespace["CONTAINMENT"]
    assert containment["enforced"] is True
    assert containment["non_local_blocked"] == 0
    assert containment["non_local_allowed"] == 0
    assert containment["allowed_hosts"] == []

    for record in json.loads(
        (Path(os.environ["MANDATE_WORKING"]) / "digests.json").read_text()
    )["run"]["session_containment"].items():
        pass  # shape is asserted above; this proves it reached the output


def test_the_notebook_verifies_both_manifests_from_the_copy(session):
    """The copy is provably the same corpus, or the run does not happen."""
    namespace: dict = {"__name__": "__main__"}
    for index, source in enumerate(code_cells()[:4]):
        exec(compile(source, f"<cell {index}>", "exec"), namespace)  # noqa: S102

    from harness.manifest import current_hash, generated_hash

    assert namespace["CORPUS"] == {
        "handwritten": current_hash(),
        "generated": generated_hash(),
    }
