"""The generated corpus's seal: one hash, and a failure on any edited byte.

A generated corpus has more moving parts than a hand-written one, so the check
that nothing moved matters more, not less. Two properties are load-bearing and
they pull against each other: the manifest must be *readable* (thousands of
paths is a diff nobody can act on) and it must be *exact* (a shard digest has
to fail on one edited byte the way a file digest does).
"""

from __future__ import annotations

import json

import pytest

from harness import manifest as mf


def test_the_hand_written_manifest_is_untouched_by_the_generated_one():
    """The published hand-written tables quote this hash.

    Folding the generated corpus into it would move it and silently invalidate
    every table in results.md above the generated section — without a single
    hand-written byte having changed. Two corpora, two manifests.
    """
    published, differences = mf.verify_manifest()
    assert differences == []
    assert published == "sha256:f87e67de9b4c757e00fd8fde7646f0bdf6073d820e6ab162e948c21ea15f8ba7"
    assert "harness/generated" not in json.dumps(mf.read_manifest()["files"])
    assert "fixtures/generated" not in json.dumps(mf.read_manifest()["files"])


@pytest.mark.skipif(
    not mf.generated_corpus_exists(),
    reason="the generated corpus has not been built",
)
class TestGenerated:
    def test_the_generated_corpus_verifies_as_committed(self):
        published, differences = mf.verify_generated_manifest()
        assert differences == []
        assert published == mf.generated_hash()

    def test_it_covers_the_dataset_digests_the_generator_and_the_seed(self):
        """A hash over the output that said nothing about the input would be a
        hash of the generator."""
        from harness.datasets import digests

        body = mf.read_generated_manifest()
        assert body["dataset_digests"] == digests()
        assert body["generator_version"]
        assert body["seed"]

    def test_it_hashes_shards_rather_than_thousands_of_paths(self):
        body = mf.read_generated_manifest()
        assert set(body["shards"]) == {"tasks", "gen_a", "gen_b", "mandates"}
        assert all(body["shards"][label] for label in body["shards"])
        # A manifest of thousands of paths is a diff nobody can act on.
        assert sum(len(v) for v in body["shards"].values()) < 100

    def test_one_edited_byte_inside_a_shard_fails(self, tmp_path, monkeypatch):
        """Coarse hashing is not a weaker check; it is a shorter report."""
        from harness.corpus import GEN_BATCHES

        shard = sorted(p for p in GEN_BATCHES["gen-a"].iterdir() if p.is_dir())[0]
        victim = sorted(shard.glob("*.json"))[0]
        original = victim.read_bytes()
        try:
            body = json.loads(original)
            body["payload"] = body["payload"] + " "
            victim.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
            _, differences = mf.verify_generated_manifest()
            assert any(f"gen_a/{shard.name}" in d for d in differences), differences
            # and the failure names files, so `git status` can finish the sentence
            assert any("shard now holds" in d for d in differences), differences
        finally:
            victim.write_bytes(original)
        assert mf.verify_generated_manifest()[1] == []

    def test_a_removed_shard_fails(self, monkeypatch):
        from harness.corpus import GEN_BATCHES

        shard = sorted(p for p in GEN_BATCHES["gen-b"].iterdir() if p.is_dir())[-1]
        moved = shard.with_name(shard.name + "-moved")
        shard.rename(moved)
        try:
            _, differences = mf.verify_generated_manifest()
            assert any("removed" in d or "added" in d for d in differences), differences
        finally:
            moved.rename(shard)
        assert mf.verify_generated_manifest()[1] == []

    def test_verify_all_covers_both_corpora(self):
        """A suite calls this rather than verify_manifest: two corpora with one
        of them unchecked is one corpus and a decoration."""
        assert mf.verify_all() == []

    def test_a_run_record_names_the_corpus_that_produced_it(self):
        """Quoting the hand-written hash on a generated line would point a
        reader at 235 files that had nothing to do with the number."""
        assert mf.hash_for_corpus("generated") == mf.generated_hash()
        assert mf.hash_for_corpus("handwritten") == mf.current_hash()
        assert mf.hash_for_dataset("gen_a") == mf.generated_hash()
        assert mf.hash_for_dataset("batch_a") == mf.current_hash()
        assert mf.generated_hash() != mf.current_hash()
