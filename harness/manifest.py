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
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kernel.canonical import jcs, sha256_hex, sha256_of

__all__ = [
    "REPO_ROOT",
    "MANIFEST_PATH",
    "COVERED",
    "EXCLUDED",
    "corpus_files",
    "build_manifest",
    "write_manifest",
    "read_manifest",
    "verify_manifest",
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
