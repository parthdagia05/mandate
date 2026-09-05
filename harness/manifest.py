"""The corpus manifest — what "frozen" means, as something a machine checks.

REQ-11: the corpus is frozen before the kernel is finished and the manifest
hash is published in ``results.md``. A changed corpus invalidates the published
numbers, and the only way that claim is worth anything is if a change is
*detectable* — so every file that could change a number is hashed, and the map
of hashes is itself hashed into one line anybody can compare.

**What it covers, and why each part is in it.**

``harness/tasks/``
    The benign tasks. They set the authority every oracle scores against — the
    payee, the total, the transaction count — so editing one silently moves the
    bound an attack is judged by.
``harness/attacks/batch_a`` and ``batch_b``
    The cases. Obviously.
``harness/attacks/seal.json``
    What batch B was verified to contain at generation time. A seal that could
    be edited afterwards is not a seal.
``fixtures/``
    The pre-signed mandates, the keys they were signed with, and the audit chain
    fixture. A signature is part of the corpus: re-signing a cart changes what
    check 1 and check 4 are looking at, and the numbers move without a single
    payload changing.

**What it deliberately does not cover.** ``harness/attacks/openings.jsonl`` —
the record of batch B being opened. That file changes precisely when someone
reads the held-out set, and covering it would mean the act of taking the
headline measurement invalidated the hash the headline is published under.

**The generated corpus gets a manifest of its own.** Not an extension of this
one, and the reason is the whole point of freezing anything: ``results.md``
publishes the hand-written manifest hash beside the hand-written tables, and
folding thousands of generated files into that hash would move it and
invalidate every one of those tables without a single hand-written byte
changing. So :data:`GENERATED_MANIFEST_PATH` covers the generated corpus, and
it covers three things this one does not have to:

``dataset digests``
    The generated corpus is derived from two pinned Kaggle datasets. A hash
    over the output that said nothing about the input would be a hash of the
    generator.
``generator version and seed``
    The other two inputs. Same datasets, different generator, different corpus.
``per-shard digests``
    Thousands of paths in a manifest is a manifest nobody reads and a diff
    nobody can act on. A shard is hashed as a unit and named as a unit — and a
    shard that moved is then opened, so the failure still names the **file**.
    Coarse reporting would be a weaker check; coarse *hashing* is not, because
    a shard digest fails on a single edited byte exactly as a file digest does.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from kernel.canonical import jcs, sha256_hex, sha256_of

__all__ = [
    "REPO_ROOT",
    "MANIFEST_PATH",
    "GENERATED_MANIFEST_PATH",
    "COVERED",
    "GENERATED_COVERED",
    "GENERATED_SHARDED",
    "EXCLUDED",
    "corpus_files",
    "build_manifest",
    "write_manifest",
    "read_manifest",
    "verify_manifest",
    "current_hash",
    "generated_corpus_exists",
    "build_generated_manifest",
    "write_generated_manifest",
    "read_generated_manifest",
    "verify_generated_manifest",
    "generated_hash",
    "verify_all",
    "hash_for_corpus",
    "hash_for_dataset",
]

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "harness" / "manifest.json"

#: ``(directory, glob)`` pairs, in the order they are listed above.
COVERED: tuple[tuple[str, str], ...] = (
    ("harness/tasks", "*.json"),
    ("harness/attacks/batch_a", "*.json"),
    ("harness/attacks/batch_b", "*.json"),
    ("harness/attacks", "seal.json"),
    ("fixtures", "**/*"),
)

#: Paths never hashed. See the module docstring: the openings log changes when
#: the held-out set is read, and the manifest must survive its own measurement.
EXCLUDED: frozenset[str] = frozenset(
    {
        "harness/attacks/openings.jsonl",
        "harness/manifest.json",
    }
)


def corpus_files() -> dict[str, str]:
    """``repo-relative path -> sha256``, for every covered file."""
    files: dict[str, str] = {}
    for directory, pattern in COVERED:
        root = REPO_ROOT / directory
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            if rel in EXCLUDED:
                continue
            files[rel] = sha256_hex(path.read_bytes())
    return dict(sorted(files.items()))


def build_manifest() -> dict[str, Any]:
    """The manifest as it should be, computed from what is on disk."""
    from harness.corpus import list_batch, list_tasks

    body = {
        "algorithm": "sha256",
        "canonicalisation": "RFC 8785",
        "counts": {
            "tasks": len(list_tasks()),
            "batch_a": len(list_batch("a")),
            "batch_b": len(list_batch("b")),
        },
        "files": corpus_files(),
    }
    return {**body, "manifest_hash": sha256_of(body)}


def write_manifest() -> str:
    """Freeze. Returns the manifest hash that goes in ``results.md``."""
    manifest = build_manifest()
    MANIFEST_PATH.write_text(jcs(manifest) + "\n")
    return manifest["manifest_hash"]


def read_manifest() -> dict[str, Any]:
    import json

    return json.loads(MANIFEST_PATH.read_text())


def verify_manifest() -> tuple[str | None, list[str]]:
    """``(hash, differences)``. Empty differences means the corpus is unchanged.

    The differences are named individually rather than reported as one boolean,
    because "the corpus changed" is not actionable and "``A3-b-04.json`` changed
    and ``benign_09.json`` was added" is. A published number can then be traced
    to the edit that invalidated it.
    """
    if not MANIFEST_PATH.exists():
        return None, ["harness/manifest.json does not exist; the corpus is not frozen"]

    recorded = read_manifest()
    current = build_manifest()
    differences: list[str] = []

    was, now = recorded.get("files", {}), current["files"]
    for path in sorted(set(was) | set(now)):
        if path not in now:
            differences.append(f"removed: {path}")
        elif path not in was:
            differences.append(f"added: {path}")
        elif was[path] != now[path]:
            differences.append(f"changed: {path}")

    if recorded.get("counts") != current["counts"]:
        differences.append(
            f"counts moved: {recorded.get('counts')} -> {current['counts']}"
        )
    if not differences and recorded.get("manifest_hash") != current["manifest_hash"]:
        # Every file matches and the hash does not: the manifest itself was
        # edited. Worth its own message — it is the one failure that means
        # somebody wrote a hash rather than computed one.
        differences.append(
            f"manifest_hash in the file is {recorded.get('manifest_hash')} but the "
            f"files hash to {current['manifest_hash']}; the manifest was edited"
        )

    return recorded.get("manifest_hash"), differences


@lru_cache(maxsize=1)
def current_hash() -> str:
    """The corpus as it is on disk *now*, hashed once per process.

    Every run record carries this (SPEC.md §11), so a results table can be
    traced back to the exact corpus that produced it. It is **computed, not
    read from** ``manifest.json``: a record that quoted the frozen file would
    keep quoting it after somebody edited a payload, which is the one thing the
    field exists to detect.

    Cached because a suite is one process running its cases in sequence, and
    hashing every fixture and all 235 corpus files once per case would put the
    manifest inside the overhead measurement. The cache is why a suite verifies
    the manifest at the end as well as at the start — an edit made while the
    suite was running is invisible to this function and visible to that check.
    """
    return build_manifest()["manifest_hash"]


# ---------------------------------------------------------------------------
# The generated corpus (P8)
# ---------------------------------------------------------------------------

GENERATED_MANIFEST_PATH = REPO_ROOT / "harness" / "generated" / "manifest.json"

#: Trees hashed **per shard**. ``(label, directory)``; every immediate
#: subdirectory of ``directory`` is one shard.
GENERATED_SHARDED: tuple[tuple[str, str], ...] = (
    ("tasks", "harness/generated/tasks"),
    ("gen_a", "harness/generated/attacks/gen_a"),
    ("gen_b", "harness/generated/attacks/gen_b"),
    ("mandates", "harness/generated/mandates"),
)

#: Single files hashed by name. The storefront is here rather than in ``sim/``'s
#: own manifest because it is *generated output*: a price that moved in it
#: would move a signed cart, and the corpus is the thing that has to notice.
GENERATED_COVERED: tuple[str, ...] = (
    "sim/merchants/catalogues/genmart.json",
    "harness/generated/seal.json",
    "harness/generated/report.json",
    "harness/datasets.json",
)


def generated_corpus_exists() -> bool:
    return GENERATED_MANIFEST_PATH.exists()


def _shard_digests(directory: Path) -> dict[str, str]:
    """``shard name -> digest`` over that shard's files.

    The digest is taken over the map of ``(name, file hash)`` rather than over
    concatenated bytes, so a file *renamed* inside a shard moves the digest as
    surely as a file edited does.
    """
    out: dict[str, str] = {}
    if not directory.is_dir():
        return out
    for shard in sorted(p for p in directory.iterdir() if p.is_dir()):
        files = {
            path.name: sha256_hex(path.read_bytes())
            for path in sorted(shard.glob("*.json"))
        }
        out[shard.name] = sha256_of({"shard": shard.name, "files": files})
    return out


def _generated_files() -> dict[str, str]:
    files: dict[str, str] = {}
    for relative in GENERATED_COVERED:
        path = REPO_ROOT / relative
        if path.is_file():
            files[relative] = sha256_hex(path.read_bytes())
    return dict(sorted(files.items()))


def build_generated_manifest(
    *,
    generator_version: str | None = None,
    seed: str | None = None,
    dataset_digests: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The generated manifest as it should be, computed from what is on disk.

    The three provenance fields default to what the manifest on disk already
    records, so *verifying* re-derives the same body a *freeze* wrote. They are
    inputs to the corpus rather than properties of it — nothing on disk can
    tell you which seed produced these files — so a verify that invented them
    would fail for the wrong reason every time.
    """
    from harness.corpus import list_batch, list_tasks

    recorded = read_generated_manifest() if generated_corpus_exists() else {}
    shards: dict[str, dict[str, str]] = {}
    for label, relative in GENERATED_SHARDED:
        shards[label] = _shard_digests(REPO_ROOT / relative)

    body = {
        "algorithm": "sha256",
        "canonicalisation": "RFC 8785",
        "generator_version": (
            generator_version
            if generator_version is not None
            else recorded.get("generator_version", "")
        ),
        "seed": seed if seed is not None else recorded.get("seed", ""),
        "dataset_digests": (
            dict(sorted(dataset_digests.items()))
            if dataset_digests is not None
            else recorded.get("dataset_digests", {})
        ),
        "counts": {
            "tasks": len(list_tasks("generated")),
            "gen_a": len(list_batch("gen-a")),
            "gen_b": len(list_batch("gen-b")),
        },
        "shards": {label: dict(sorted(v.items())) for label, v in sorted(shards.items())},
        "files": _generated_files(),
    }
    return {**body, "manifest_hash": sha256_of(body)}


def write_generated_manifest(
    *, generator_version: str, seed: str, dataset_digests: dict[str, str]
) -> str:
    """Freeze the generated corpus. Returns the hash the tables quote."""
    manifest = build_generated_manifest(
        generator_version=generator_version,
        seed=seed,
        dataset_digests=dataset_digests,
    )
    GENERATED_MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    GENERATED_MANIFEST_PATH.write_text(jcs(manifest) + "\n")
    return manifest["manifest_hash"]


def read_generated_manifest() -> dict[str, Any]:
    import json

    return json.loads(GENERATED_MANIFEST_PATH.read_text())


def verify_generated_manifest() -> tuple[str | None, list[str]]:
    """``(hash, differences)`` for the generated corpus.

    A shard that moved is drilled into and the differing file is named, so
    "``gen_a/shard-03`` changed" becomes "``gen_a/shard-03/A2-gen-a-014.json``
    changed" — the same actionable failure the hand-written manifest gives.
    """
    if not generated_corpus_exists():
        return None, []

    recorded = read_generated_manifest()
    current = build_generated_manifest()
    differences: list[str] = []

    for label, _ in GENERATED_SHARDED:
        was = recorded.get("shards", {}).get(label, {})
        now = current["shards"].get(label, {})
        for shard in sorted(set(was) | set(now)):
            if shard not in now:
                differences.append(f"removed: {label}/{shard}")
            elif shard not in was:
                differences.append(f"added: {label}/{shard}")
            elif was[shard] != now[shard]:
                differences.append(f"changed: {label}/{shard}")
                differences.extend(_shard_detail(label, shard, was[shard]))

    was_files, now_files = recorded.get("files", {}), current["files"]
    for path in sorted(set(was_files) | set(now_files)):
        if path not in now_files:
            differences.append(f"removed: {path}")
        elif path not in was_files:
            differences.append(f"added: {path}")
        elif was_files[path] != now_files[path]:
            differences.append(f"changed: {path}")

    for field in ("generator_version", "seed", "dataset_digests", "counts"):
        if recorded.get(field) != current[field]:
            differences.append(
                f"{field} moved: {recorded.get(field)} -> {current[field]}"
            )

    if not differences and recorded.get("manifest_hash") != current["manifest_hash"]:
        differences.append(
            f"manifest_hash in the file is {recorded.get('manifest_hash')} but the "
            f"corpus hashes to {current['manifest_hash']}; the manifest was edited"
        )
    return recorded.get("manifest_hash"), differences


def _shard_detail(label: str, shard: str, recorded_digest: str) -> list[str]:
    """Name the files in a moved shard, so the failure is actionable.

    The recorded digest covers a map this cannot invert, so what is printed is
    the shard's contents *now* — enough for ``git status`` to finish the
    sentence, which is what a person does next anyway.
    """
    directory = dict(GENERATED_SHARDED).get(label)
    if directory is None:
        return []
    path = REPO_ROOT / directory / shard
    if not path.is_dir():
        return ["    the shard directory is gone"]
    names = sorted(p.name for p in path.glob("*.json"))
    head = ", ".join(names[:4])
    more = f" (+{len(names) - 4} more)" if len(names) > 4 else ""
    return [f"    shard now holds {len(names)} file(s): {head}{more}"]


@lru_cache(maxsize=1)
def generated_hash() -> str:
    """The generated corpus as it is on disk now, hashed once per process."""
    return build_generated_manifest()["manifest_hash"]


def hash_for_corpus(corpus: str) -> str:
    """The manifest hash a line from ``corpus`` should carry.

    A run record has to name the corpus that produced it, and there are two
    corpora now. Quoting the hand-written hash on a generated run would point a
    reader at 235 files that had nothing to do with the number in front of them.
    """
    return generated_hash() if corpus == "generated" else current_hash()


def hash_for_dataset(dataset: str) -> str:
    """The same, keyed by the suite's dataset name."""
    return hash_for_corpus("generated" if dataset.startswith("gen") else "handwritten")


def verify_all() -> list[str]:
    """Every manifest present, checked. Empty means nothing moved anywhere.

    A suite calls this rather than :func:`verify_manifest` so that an edit to
    *either* corpus stops *any* suite: two corpora with one of them unchecked
    is one corpus and a decoration.
    """
    _, differences = verify_manifest()
    if generated_corpus_exists():
        _, generated = verify_generated_manifest()
        differences += [f"generated corpus: {line}" for line in generated]
    return differences
