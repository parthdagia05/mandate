"""Where the generated corpus's raw material came from, pinned so it cannot move.

The generator is the new thing in P8 that can lie. Everything downstream of it
— a storefront built from a retail catalogue, benign tasks priced from real
rows, payloads drawn from a real injection corpus — is only as reproducible as
its input, and "we used a Kaggle dataset" names nothing: a dataset is a mutable
object with versions, and the version that was current the day a table was
computed is not the version anybody will download later.

So a dataset is recorded here as five things, and generation refuses without
all five:

``owner/slug`` **and a version number**
    Not the slug alone. ``PromptCloudHQ/flipkart-products`` resolves to
    whatever is current; ``PromptCloudHQ/flipkart-products`` at version 1 is a
    fixed object.
sha256 of every file used
    The version number is the publisher's claim and the digest is ours. A
    re-uploaded version that kept its number would pass the first check and
    fail this one.
row count
    Cheap, redundant with the digest, and worth having anyway: a digest
    mismatch says *something* changed and a row count says how much.
licence
    Published numbers derived from a dataset carry that dataset's terms, and a
    licence nobody wrote down is a licence nobody complied with.
the date it was pulled
    So a reader can tell how old the pin is.

**Generation refuses on a digest miss, and that refusal is the whole point.** A
corpus generated from whatever the dataset happened to be that day is not
reproducible, and its manifest hash would be a hash of the generator with
nothing said about its input — which is exactly the kind of number this project
exists not to publish.

**What is not committed.** The dataset files themselves. They are tens of
megabytes and they belong to their publishers; what is committed is the record
below, the generated corpus, and the code that turns one into the other. A
reader who wants to re-derive the corpus pulls the datasets by slug and
version, and this module tells them immediately if what arrived is not what was
used.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from kernel.canonical import jcs, sha256_hex, sha256_of

__all__ = [
    "REPO_ROOT",
    "REGISTRY_PATH",
    "LOCAL_ROOT",
    "KAGGLE_INPUT",
    "DatasetError",
    "DatasetMissing",
    "DatasetDigestMismatch",
    "FileDigest",
    "DatasetRecord",
    "read_registry",
    "write_registry",
    "record",
    "dataset_dir",
    "verify",
    "require",
    "digest",
    "digests",
    "read_rows",
    "measure",
]

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The pins. Committed; the data it pins is not.
REGISTRY_PATH = REPO_ROOT / "harness" / "datasets.json"

#: Where ``mk kaggle datasets`` puts a pulled dataset on this machine.
LOCAL_ROOT = REPO_ROOT / "data" / "kaggle"

#: Where Kaggle mounts attached datasets inside a notebook session. Read-only
#: there, and the path carries **no version** — which is why the digest check
#: matters more on Kaggle, not less.
#:
#: The layout is not one thing. A session may mount an attachment flat at
#: ``/kaggle/input/<slug>`` or nested at
#: ``/kaggle/input/datasets/<owner>/<slug>``; this repository has seen the
#: second. :func:`_candidates` therefore searches both rather than assuming
#: either, because assuming produced a run that died on its first cell with a
#: message that could not say what the session actually had.
KAGGLE_INPUT = Path("/kaggle/input")

#: An escape hatch for a machine that keeps its data somewhere else. Checked
#: first, and it changes nothing about verification — a directory named here
#: still has to hash to the recorded digests.
DATA_DIR_ENV = "MANDATE_DATA_DIR"


class DatasetError(RuntimeError):
    """Something about a pinned dataset is wrong enough to stop generation."""


class DatasetMissing(DatasetError):
    """The dataset is pinned but not on this machine."""


class DatasetDigestMismatch(DatasetError):
    """What is on this machine is not what the pin says was used.

    Loud, and fatal to generation. The alternative is a corpus built from a
    silently different input and a manifest hash that says nothing about it.
    """


@dataclass(frozen=True)
class FileDigest:
    """One file of one dataset version, as it was when the corpus was built."""

    name: str
    sha256: str
    bytes: int
    rows: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "rows": self.rows,
        }


@dataclass(frozen=True)
class DatasetRecord:
    """One pinned Kaggle dataset version.

    ``role`` is the name the generator uses — ``retail_catalogue``,
    ``injection_corpus`` — so the generator names a *purpose* and this file
    decides which object fills it. A generator that named a slug would have to
    be edited to swap a dataset, and the edit would be invisible in the corpus
    manifest.
    """

    role: str
    owner: str
    slug: str
    version: int
    licence: str
    title: str
    url: str
    pulled_at: str
    files: tuple[FileDigest, ...]

    @property
    def ref(self) -> str:
        return f"{self.owner}/{self.slug}"

    @property
    def pin(self) -> str:
        return f"{self.ref}@v{self.version}"

    @property
    def rows(self) -> int:
        return sum(entry.rows for entry in self.files)

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "owner": self.owner,
            "slug": self.slug,
            "version": self.version,
            "licence": self.licence,
            "title": self.title,
            "url": self.url,
            "pulled_at": self.pulled_at,
            "files": [entry.as_dict() for entry in self.files],
        }

    @property
    def digest(self) -> str:
        """One hash standing for this dataset version.

        Over the *pin and the file digests*, not over the bytes: the bytes are
        not committed, and a reader checking a published table needs to compare
        a line in ``results.md`` against a line in this file without having
        downloaded 38 MB first.
        """
        return sha256_of(
            {
                "pin": self.pin,
                "files": [entry.as_dict() for entry in self.files],
            }
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DatasetRecord":
        return cls(
            role=raw["role"],
            owner=raw["owner"],
            slug=raw["slug"],
            version=int(raw["version"]),
            licence=raw["licence"],
            title=raw["title"],
            url=raw["url"],
            pulled_at=raw["pulled_at"],
            files=tuple(FileDigest(**entry) for entry in raw["files"]),
        )


def read_registry() -> dict[str, DatasetRecord]:
    """Every pinned dataset, by role. Empty when nothing has been pinned."""
    if not REGISTRY_PATH.exists():
        return {}
    body = json.loads(REGISTRY_PATH.read_text())
    return {
        raw["role"]: DatasetRecord.from_dict(raw) for raw in body.get("datasets", [])
    }


def write_registry(records: dict[str, DatasetRecord]) -> str:
    """Pin these datasets. Returns the digest over the whole registry."""
    body = {
        "algorithm": "sha256",
        "canonicalisation": "RFC 8785",
        "datasets": [records[role].as_dict() for role in sorted(records)],
    }
    body["registry_digest"] = sha256_of(body)
    REGISTRY_PATH.write_text(jcs(body) + "\n")
    return body["registry_digest"]


def record(role: str) -> DatasetRecord:
    registry = read_registry()
    if role not in registry:
        raise DatasetMissing(
            f"no dataset pinned for role {role!r}; pinned: {sorted(registry)}. "
            "Pull it with `mk kaggle datasets pull` — generation refuses "
            "without a pin, because a corpus built from an unpinned dataset "
            "cannot be re-derived."
        )
    return registry[role]


def _candidates(entry: DatasetRecord) -> Iterator[Path]:
    override = os.environ.get(DATA_DIR_ENV)
    if override:
        yield Path(override) / f"{entry.owner}__{entry.slug}" / f"v{entry.version}"
        yield Path(override) / entry.slug
        yield Path(override)
    yield LOCAL_ROOT / f"{entry.owner}__{entry.slug}" / f"v{entry.version}"
    # Both Kaggle layouts, in the order they are likeliest. Neither carries a
    # version in the path, which is precisely why the digest check below is not
    # optional inside a notebook.
    yield KAGGLE_INPUT / entry.slug
    yield KAGGLE_INPUT / "datasets" / entry.owner / entry.slug
    yield KAGGLE_INPUT / entry.owner / entry.slug


def dataset_dir(role: str) -> Path:
    """Where this dataset's files are on this machine.

    Searched rather than configured, because the same code runs on a laptop
    (``data/kaggle/...``) and inside a Kaggle session (``/kaggle/input/...``),
    and a path in a config file would be one more thing to get wrong in the
    place that is hardest to debug.
    """
    entry = record(role)
    for candidate in _candidates(entry):
        if all((candidate / f.name).is_file() for f in entry.files):
            return candidate
    raise DatasetMissing(
        f"{entry.pin} is pinned for role {role!r} but its files are not on "
        f"this machine. Looked in: "
        + ", ".join(str(c) for c in _candidates(entry))
        + ". Pull it with `mk kaggle datasets pull`."
    )


def measure(path: Path) -> tuple[str, int, int]:
    """``(sha256, bytes, rows)`` for one dataset file.

    Rows are counted with the CSV reader rather than by splitting on newlines,
    because these files carry quoted product descriptions with newlines in them
    and a line count would be a different number every time somebody looked at
    it differently.
    """
    raw = path.read_bytes()
    rows = 0
    if path.suffix.lower() == ".csv":
        limit = csv.field_size_limit()
        csv.field_size_limit(10_000_000)
        try:
            with path.open(newline="", encoding="utf-8", errors="replace") as handle:
                rows = max(0, sum(1 for _ in csv.reader(handle)) - 1)
        finally:
            csv.field_size_limit(limit)
    return sha256_hex(raw), len(raw), rows


def verify(role: str) -> list[str]:
    """Differences between the pin and what is on disk. Empty means unchanged."""
    entry = record(role)
    try:
        directory = dataset_dir(role)
    except DatasetMissing as exc:
        return [str(exc)]

    differences: list[str] = []
    for wanted in entry.files:
        path = directory / wanted.name
        if not path.is_file():
            differences.append(f"missing: {wanted.name}")
            continue
        found_sha, found_bytes, found_rows = measure(path)
        if found_sha != wanted.sha256:
            differences.append(
                f"changed: {wanted.name} hashes to {found_sha}, pinned "
                f"{wanted.sha256} ({found_bytes} bytes, {found_rows} rows; "
                f"pinned {wanted.bytes} bytes, {wanted.rows} rows)"
            )
        elif found_rows != wanted.rows:
            differences.append(
                f"row count moved: {wanted.name} has {found_rows}, pinned "
                f"{wanted.rows}"
            )
    return differences


def require(role: str) -> Path:
    """The dataset directory, or a refusal naming exactly what moved."""
    differences = verify(role)
    if differences:
        raise DatasetDigestMismatch(
            f"the dataset pinned for role {role!r} ({record(role).pin}) is not "
            "what is on this machine, so nothing generated from it could be "
            "re-derived:\n  " + "\n  ".join(differences)
        )
    return dataset_dir(role)


def digest(role: str) -> str:
    return record(role).digest


def digests() -> dict[str, str]:
    """``role -> digest`` for every pinned dataset. Goes in the manifest."""
    return {role: entry.digest for role, entry in sorted(read_registry().items())}


def read_rows(role: str, filename: str) -> list[dict[str, str]]:
    """Every row of one pinned CSV, after the digest check has passed.

    The check is here rather than at the call site on purpose: a reader that
    could be called without verifying is a reader that will be, and the failure
    it produces — a corpus quietly built from a different file — is invisible
    in the output.
    """
    directory = require(role)
    limit = csv.field_size_limit()
    csv.field_size_limit(10_000_000)
    try:
        with (directory / filename).open(
            newline="", encoding="utf-8", errors="replace"
        ) as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    finally:
        csv.field_size_limit(limit)
