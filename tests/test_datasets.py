"""Dataset pins: a generated corpus is only as reproducible as its input.

The failure these guard against is the quietest one in P8. A dataset is a
mutable object with versions; if the generator reads whatever happens to be on
the machine, the corpus manifest hash is a hash of the generator with nothing
said about what it was fed, and "reproduce it from the digest" is a sentence
with no mechanism behind it.
"""

from __future__ import annotations

import json

import pytest

from harness import datasets as ds


@pytest.fixture
def pinned(tmp_path, monkeypatch):
    """A registry and a data directory of our own, so a test cannot repin the real one."""
    monkeypatch.setattr(ds, "REGISTRY_PATH", tmp_path / "datasets.json")
    monkeypatch.setattr(ds, "LOCAL_ROOT", tmp_path / "kaggle")
    monkeypatch.setattr(ds, "KAGGLE_INPUT", tmp_path / "absent")
    monkeypatch.delenv(ds.DATA_DIR_ENV, raising=False)

    directory = tmp_path / "kaggle" / "someone__a-dataset" / "v3"
    directory.mkdir(parents=True)
    path = directory / "rows.csv"
    path.write_text("a,b\n1,2\n3,4\n")
    sha, size, rows = ds.measure(path)

    ds.write_registry(
        {
            "demo": ds.DatasetRecord(
                role="demo",
                owner="someone",
                slug="a-dataset",
                version=3,
                licence="CC BY-SA 4.0",
                title="A dataset",
                url="https://example.invalid",
                pulled_at="2026-01-01T00:00:00Z",
                files=(ds.FileDigest(name="rows.csv", sha256=sha, bytes=size, rows=rows),),
            )
        }
    )
    return path


def test_a_pin_carries_the_version_the_licence_and_the_date(pinned):
    """The slug alone names a moving object; five fields name a fixed one."""
    entry = ds.record("demo")
    assert entry.pin == "someone/a-dataset@v3"
    assert entry.licence == "CC BY-SA 4.0"
    assert entry.pulled_at
    assert entry.files[0].rows == 2
    assert entry.files[0].sha256.startswith("sha256:")


def test_the_digest_is_over_the_pin_and_the_files(pinned):
    """A reader checking a published table must not have to download 38 MB first."""
    entry = ds.record("demo")
    assert entry.digest == ds.digest("demo")
    assert ds.digests()["demo"] == entry.digest


def test_an_unchanged_dataset_verifies(pinned):
    assert ds.verify("demo") == []
    assert ds.require("demo").name == "v3"


def test_one_changed_byte_is_refused_by_name(pinned):
    """The version number is the publisher's claim; the digest is ours."""
    pinned.write_text("a,b\n1,2\n3,5\n")
    differences = ds.verify("demo")
    assert differences and "rows.csv" in differences[0]
    with pytest.raises(ds.DatasetDigestMismatch, match="rows.csv"):
        ds.require("demo")


def test_reading_rows_goes_through_the_digest_check(pinned):
    """A reader that could be called without verifying is one that will be."""
    assert ds.read_rows("demo", "rows.csv") == [
        {"a": "1", "b": "2"},
        {"a": "3", "b": "4"},
    ]
    pinned.write_text("a,b\n9,9\n")
    with pytest.raises(ds.DatasetDigestMismatch):
        ds.read_rows("demo", "rows.csv")


def test_a_missing_dataset_says_where_it_looked(pinned):
    pinned.unlink()
    with pytest.raises(ds.DatasetMissing, match="not on this machine"):
        ds.dataset_dir("demo")


def test_an_unpinned_role_is_refused_rather_than_defaulted(pinned):
    with pytest.raises(ds.DatasetMissing, match="no dataset pinned"):
        ds.record("nobody-pinned-this")


def test_the_shipped_pins_name_a_version_a_licence_and_a_date():
    """The real registry, as committed. Published numbers carry these terms."""
    registry = ds.read_registry()
    assert set(registry) == {"retail_catalogue", "injection_corpus", "injection_corpus_2"}
    for role, entry in registry.items():
        assert entry.version >= 1, role
        assert entry.licence not in ("", "unrecorded"), role
        assert entry.pulled_at.endswith("Z"), role
        assert entry.files, role
        for digest in entry.files:
            assert digest.sha256.startswith("sha256:"), role
            assert digest.rows > 0, role


def test_the_registry_file_is_canonical_json():
    """It is hashed into the generated manifest; a reformat must not move it."""
    from kernel.canonical import jcs

    body = json.loads(ds.REGISTRY_PATH.read_text())
    assert ds.REGISTRY_PATH.read_text() == jcs(body) + "\n"


def test_both_kaggle_mount_layouts_are_searched(tmp_path, monkeypatch, pinned):
    """Kaggle nests attachments under datasets/<owner>/<slug> as well as
    mounting them flat at /kaggle/input/<slug>.

    Assuming one produced a hosted run that died on its first cell, and the
    message could not say what the session actually had. Both are searched, and
    whichever is found still has to hash to the pin.
    """
    monkeypatch.setattr(ds, "LOCAL_ROOT", tmp_path / "absent")
    monkeypatch.setattr(ds, "KAGGLE_INPUT", tmp_path / "input")

    nested = tmp_path / "input" / "datasets" / "someone" / "a-dataset"
    nested.mkdir(parents=True)
    (nested / "rows.csv").write_text(pinned.read_text())

    assert ds.dataset_dir("demo") == nested
    assert ds.verify("demo") == []


def test_a_nested_mount_that_does_not_match_the_pin_is_still_refused(
    tmp_path, monkeypatch, pinned
):
    """Finding the files is not the same as finding the right files."""
    monkeypatch.setattr(ds, "LOCAL_ROOT", tmp_path / "absent")
    monkeypatch.setattr(ds, "KAGGLE_INPUT", tmp_path / "input")

    nested = tmp_path / "input" / "datasets" / "someone" / "a-dataset"
    nested.mkdir(parents=True)
    (nested / "rows.csv").write_text("a,b\n9,9\n")

    with pytest.raises(ds.DatasetDigestMismatch, match="rows.csv"):
        ds.require("demo")
