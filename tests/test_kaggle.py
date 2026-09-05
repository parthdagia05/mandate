"""The hosted run: what is committed, what is pinned, and what is never read.

The claim P8 makes about Kaggle is not "it runs there". It is that the pushed
code, the attached dataset versions and the run that produced a table are one
recorded object. These check the parts of that which live in the repository.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from harness import kaggle as kg

METADATA = json.loads(kg.METADATA_PATH.read_text())
NOTEBOOK = json.loads((kg.KERNEL_DIR / METADATA["code_file"]).read_text())


def _code_cells() -> list[str]:
    return [
        "".join(cell["source"])
        for cell in NOTEBOOK["cells"]
        if cell["cell_type"] == "code"
    ]


def test_the_notebook_named_by_the_metadata_is_committed():
    """A hand-run notebook whose exact code nobody kept is not a measurement."""
    assert (kg.KERNEL_DIR / METADATA["code_file"]).is_file()
    assert METADATA["kernel_type"] == "notebook"
    assert _code_cells(), "the notebook has no code in it"


def test_every_code_cell_compiles():
    """A notebook that only parses in a browser is a notebook nobody can review."""
    for index, source in enumerate(_code_cells()):
        compile(source, f"<cell {index}>", "exec")


def test_the_internet_is_disabled_and_the_run_is_cpu():
    """Internet disabled is the point, not a constraint.

    The stand-in needs no network, so a run with it off makes the containment
    claim the strong one: zero non-local sockets, asserted by the platform as
    well as by the guard.
    """
    assert METADATA["enable_internet"] is False
    assert METADATA["enable_gpu"] is False
    assert METADATA["enable_tpu"] is False


def test_every_attached_dataset_is_pinned_by_version():
    """A dataset attached by slug alone resolves to whatever is current, and the
    corpus digest would then be a hash with nothing said about its input.

    The spelling matters and is easy to get wrong: the CLI wants
    ``owner/slug/N``. ``owner/slug/versions/N`` is how the *web URL* reads, and
    the CLI rejects it locally with "Invalid dataset specification" — cheaply,
    but only if somebody is looking.
    """
    sources = METADATA["dataset_sources"]
    assert sources
    for source in sources:
        assert kg.DATASET_SOURCE.match(source), source
        parts = source.split("/")
        assert len(parts) == 3, f"{source} must be owner/slug/N"
        assert parts[2].isdigit(), source


def test_the_attached_corpus_datasets_are_the_ones_the_registry_pins():
    """The notebook must not attach a different version from the one the
    generated corpus was derived from."""
    from harness.datasets import read_registry

    attached = kg.attached_versions()
    for entry in read_registry().values():
        assert attached.get(entry.ref.lower()) == entry.version, entry.pin


def test_the_notebook_arms_containment_and_asserts_the_result():
    """A platform setting and a guard that refuses are different evidence, and
    the run record has to carry the second one."""
    joined = "\n".join(_code_cells())
    assert "contained(allow=())" in joined
    assert "non_local_blocked" in joined and "assert" in joined


def test_the_notebook_verifies_both_manifests_before_it_measures():
    joined = "\n".join(_code_cells())
    assert "verify_all()" in joined
    assert "assert not drift" in joined


def test_the_notebook_chooses_its_shard_count_from_a_measurement():
    """Not guessed. The wall-clock bound is what the split exists to satisfy."""
    joined = "\n".join(_code_cells())
    assert "PER_CASE_S" in joined and "BUDGET_S" in joined
    assert "SHARDS = " in joined


def test_the_notebook_does_not_run_the_held_out_batch_by_default():
    """Opening gen-b is a decision with a log entry of its own.

    The plan is overridable by environment so the notebook can be rehearsed
    locally, but its **default** must not reach the held-out set: a default
    that did would make "opened once" a property of whoever last edited an
    environment variable.
    """
    joined = "\n".join(_code_cells())
    default = joined.split("PLAN = os.environ.get(")[1].split(")")[0].split(",", 1)[1]
    # Parsed as the list the notebook parses, not matched as a substring:
    # "gen_benign" contains "gen_b", and a substring test here would pass or
    # fail for the wrong reason.
    datasets = [name.strip().strip("'\" ") for name in default.strip().strip("'\"").split(",")]
    assert datasets == ["gen_benign", "gen_a"], datasets
    assert "gen_b" not in datasets


def test_the_notebook_writes_digests_beside_its_output():
    """Without them a truncated upload is a file that parses."""
    joined = "\n".join(_code_cells())
    assert "digests.json" in joined
    assert "sha256" in joined


def test_nothing_in_the_wrapper_reads_or_prints_credentials():
    """The CLI reads ~/.kaggle/kaggle.json. A wrapper that parsed credentials
    would be a wrapper that could print them."""
    tree = ast.parse(Path(kg.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = getattr(func, "attr", getattr(func, "id", ""))
            if name in ("read_text", "read_bytes", "open"):
                source = ast.unparse(node)
                assert "CREDENTIALS_PATH" not in source, source


def test_credentials_present_only_checks_existence():
    source = ast.unparse(
        [n for n in ast.parse(Path(kg.__file__).read_text()).body
         if isinstance(n, ast.FunctionDef) and n.name == "credentials_present"][0]
    )
    assert "read_text" not in source and "json" not in source


def test_pull_refuses_a_run_that_did_not_complete(monkeypatch, tmp_path):
    """A timed-out kernel leaves a partial output that merges cleanly."""
    monkeypatch.setattr(kg, "status", lambda: {"ref": "x/y", "status": "running", "message": "…"})
    with pytest.raises(kg.KernelNotComplete, match="Refusing to pull"):
        kg.pull(tmp_path)


def test_an_output_without_digests_is_refused(tmp_path):
    with pytest.raises(kg.KaggleError, match="no digests.json"):
        kg.verify_output(tmp_path)


def test_a_truncated_output_file_is_refused(tmp_path):
    body = tmp_path / "gen_a.kernel.1of2.jsonl"
    body.write_text('{"case_id": "one"}\n')
    import hashlib

    (tmp_path / "digests.json").write_text(
        json.dumps(
            {
                "files": {
                    body.name: {
                        "sha256": "sha256:" + hashlib.sha256(body.read_bytes()).hexdigest(),
                        "bytes": body.stat().st_size,
                    }
                },
                "shards": ["1of2", "2of2"],
            }
        )
    )
    assert kg.verify_output(tmp_path)["shards"] == ["1of2", "2of2"]

    body.write_text('{"case_id": "one"')
    with pytest.raises(kg.KaggleError, match="changed"):
        kg.verify_output(tmp_path)


def test_a_missing_shard_in_the_output_is_refused(tmp_path):
    (tmp_path / "digests.json").write_text(json.dumps({"files": {}, "shards": ["1of2"]}))
    with pytest.raises(kg.KaggleError, match="shard"):
        kg.verify_output(tmp_path, expect_shards=2)


# --- the repository as a dataset ------------------------------------------


def test_the_staged_upload_carries_no_data_and_no_runs(tmp_path):
    """Two directories must never reach Kaggle, for two different reasons.

    ``data/`` is 46 MB of other people's datasets. They are pinned by digest
    and re-pulled by whoever wants them; redistributing them under this
    repository's licence is not ours to do. ``runs/`` is output — it is what the
    hosted run exists to produce, and uploading it would mean the session could
    read numbers it was supposed to compute.
    """
    staged = kg.stage_repo(tmp_path / "stage")
    root = Path(staged["dir"])
    for forbidden in ("data", "runs", ".git", ".venv"):
        assert not (root / forbidden).exists(), forbidden
    for path in root.rglob("*"):
        assert "__pycache__" not in path.parts, path
        assert path.suffix not in (".pyc", ".db"), path


def test_the_staged_upload_is_self_sufficient(tmp_path):
    """The notebook imports from it and runs the committed corpus out of it.

    A staging list that missed a package would fail on the first import of an
    eight-hour session, which is the worst place to discover it.
    """
    staged = kg.stage_repo(tmp_path / "stage")
    root = Path(staged["dir"])
    for needed in (
        "mk.py",
        "harness/manifest.py",
        "harness/generated/manifest.json",
        "sim/merchants/catalogues/genmart.json",
        "fixtures/keys/user.pub.b64u",
        "dataset-metadata.json",
    ):
        assert (root / needed).is_file(), needed
    assert staged["files"] > 1000
    assert staged["bytes"] < 60_000_000, "too large to be a sensible dataset"


def test_the_staged_metadata_names_the_dataset_the_notebook_attaches(tmp_path):
    """A staged copy pushed under one name and attached under another would
    make the run read whatever was at the attached slug."""
    staged = kg.stage_repo(tmp_path / "stage")
    ref = json.loads((Path(staged["dir"]) / "dataset-metadata.json").read_text())["id"]
    assert ref == kg.repo_ref()
    assert any(
        source.split("/")[:2] == ref.split("/") for source in METADATA["dataset_sources"]
    )


def test_the_kernel_and_the_dataset_have_the_same_owner():
    """Kaggle refuses a push whose owner is not you; two owners here would mean
    one of the two pushes fails after the other has already happened."""
    assert kg.kernel_ref().split("/")[0] == kg.repo_ref().split("/")[0]


def test_the_notebook_survives_a_dataset_served_as_an_archive():
    """`-r zip` is usually served extracted and is not always.

    Guessing wrong costs an eight-hour session that dies on its first import,
    so the notebook handles both shapes.
    """
    joined = "\n".join(_code_cells())
    assert "zipfile.ZipFile" in joined
    assert "ATTACHED" in joined and "mk.py" in joined


def test_the_cli_is_looked_for_beside_the_interpreter_too(monkeypatch, tmp_path):
    """`.venv/bin/python mk.py` does not put `.venv/bin` on PATH.

    So a `pip install kaggle` into the project's own virtualenv produces a CLI
    that `shutil.which` cannot see — and an error message telling somebody to
    install a thing they have already installed.
    """
    fake = tmp_path / "bin"
    fake.mkdir()
    monkeypatch.setattr(kg.shutil, "which", lambda _name: None)
    monkeypatch.setattr(kg.sys, "executable", str(fake / "python"))
    assert kg.cli_path() is None, "nothing on PATH and nothing beside the interpreter"

    (fake / "kaggle").write_text("#!/bin/sh\necho 1.0\n")
    assert kg.cli_path() == str(fake / "kaggle")


def test_the_preflight_reports_every_reason_rather_than_the_first(monkeypatch):
    """The failures are independent and somebody fixing them wants the list."""
    monkeypatch.setattr(kg, "cli_path", lambda: None)
    monkeypatch.setattr(kg, "credentials_present", lambda: False)
    rows = kg.check()
    names = [row["check"] for row in rows]
    assert names[:3] == ["cli installed", "cli version", "credentials"]
    assert "one owner" in names, "an owner mismatch must be reported even offline"
    assert all(row["detail"] for row in rows)


def test_the_preflight_checks_both_files_name_one_owner():
    """Two owners would mean one push fails after the other had landed."""
    rows = {row["check"]: row for row in kg.check()}
    assert rows["one owner"]["ok"], rows["one owner"]["detail"]


def test_a_malformed_dataset_spec_is_caught_by_the_preflight(monkeypatch, tmp_path):
    """The CLI rejects a bad spec locally, before uploading — which makes the
    failure cheap and completely invisible until somebody runs a push.

    This is the check that turns "invalid dataset specification, three commands
    in" into a FAIL row before anything is sent. The web URL spelling,
    ``owner/slug/versions/1``, is the one that gets written by mistake.
    """
    bad = tmp_path / "kernel-metadata.json"
    bad.write_text(
        json.dumps({**METADATA, "dataset_sources": ["a/b/versions/1", "c/d"]})
    )
    monkeypatch.setattr(kg, "METADATA_PATH", bad)
    rows = {row["check"]: row for row in kg.check()}
    assert rows["dataset specs"]["ok"] is False
    assert "owner/slug/N" in rows["dataset specs"]["detail"]


def test_an_unpinned_attachment_is_reported(monkeypatch, tmp_path):
    """A dataset attached by slug alone resolves to whatever is current."""
    loose = tmp_path / "kernel-metadata.json"
    loose.write_text(json.dumps({**METADATA, "dataset_sources": ["a/b"]}))
    monkeypatch.setattr(kg, "METADATA_PATH", loose)
    rows = {row["check"]: row for row in kg.check()}
    assert rows["versions pinned"]["ok"] is False
    assert "whatever is current" in rows["versions pinned"]["detail"]


def test_the_kernel_title_resolves_to_the_id_it_is_pushed_under():
    """Kaggle derives a kernel's slug from the **title**, not from the id.

    A title that slugs to something else produces a kernel at an address the
    metadata does not name. The push succeeds with a warning nobody reads, and
    every `status` and `pull` afterwards fails with "Cannot access kernel",
    which reads like a permissions problem and is not one.
    """
    for path in (kg.METADATA_PATH, kg.DATASET_METADATA_PATH):
        body = json.loads(path.read_text())
        assert kg.slugify(body["title"]) == body["id"].split("/", 1)[1], path.name


def test_slugify_drops_punctuation_rather_than_making_it_a_separator():
    """The em-dash in 'Mandate — generated corpus suite' is the case that bit:
    it vanishes rather than becoming a hyphen of its own."""
    assert kg.slugify("Mandate — generated corpus suite") == "mandate-generated-corpus-suite"
    assert kg.slugify("Mandate repo") == "mandate-repo"
    assert kg.slugify("  A/B: c  ") == "a-b-c"


def test_a_title_that_does_not_resolve_is_caught_by_the_preflight(monkeypatch, tmp_path):
    bad = tmp_path / "kernel-metadata.json"
    bad.write_text(json.dumps({**METADATA, "title": "Something Else Entirely"}))
    monkeypatch.setattr(kg, "METADATA_PATH", bad)
    rows = {row["check"]: row for row in kg.check()}
    assert rows["kernel title slug"]["ok"] is False
    assert "Kaggle uses the title" in rows["kernel title slug"]["detail"]


def test_the_visibility_choice_is_a_committed_fact_not_a_remembered_flag():
    """`kaggle datasets create` is private by default. A published artefact's
    visibility belongs in a file, not in whether somebody typed -u."""
    body = json.loads(kg.DATASET_METADATA_PATH.read_text())
    assert "isPrivate" in body, "the choice has to be written down to be honoured"
    assert isinstance(body["isPrivate"], bool)


def test_the_notebook_reports_what_is_mounted_before_it_asserts():
    """A missing attachment is the likeliest failure, and the first version of
    that cell could say only that the path was absent, not what was there.

    It cost a run to learn that Kaggle nests attachments under
    ``datasets/<owner>/<slug>``; the printed tree answered it on the next one.
    """
    first = _code_cells()[0]
    assert "print('/kaggle/input:')" in first
    assert first.index("tree(INPUT)") < first.index("assert ATTACHED is not None")
    assert "The tree above is what the session actually has" in first


def test_the_notebook_searches_both_kaggle_mount_layouts():
    """Flat at /kaggle/input/<slug>, or nested under datasets/<owner>/<slug>.

    Bounded depth, so the search never walks a 38 MB catalogue looking for a
    directory.
    """
    first = _code_cells()[0]
    for pattern in ("'mandate-repo'", "'*/mandate-repo'", "'*/*/mandate-repo'"):
        assert pattern in first, pattern
    assert "rglob" not in first, "an unbounded walk over the attached datasets"


def test_every_notebook_cell_has_an_id():
    """nbformat warns on push today and will make it a hard error."""
    notebook = json.loads((kg.KERNEL_DIR / METADATA["code_file"]).read_text())
    assert all(cell.get("id") for cell in notebook["cells"])
