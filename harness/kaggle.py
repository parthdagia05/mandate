"""The Kaggle side of the harness: pull the datasets, push the notebook, fetch the output.

Three things are wrapped here rather than left to somebody's shell history,
and the reason is the same one that makes the corpus manifest exist. A table
computed on a hosted runner is the product of three separate objects — the code
that was pushed, the dataset versions that were attached, and the run that
produced the output — and if those three live only in a browser tab, in a
notebook nobody kept and in a filename, then "reproduce it" means "ask the
person who ran it what they did".

So: :func:`push` sends the committed notebook and its committed
``kernel-metadata.json``; :func:`status` reports the run; :func:`pull` fetches
the output **and verifies its digests** before the merge step is allowed to see
it. A partial output that merged cleanly would be a table with a missing shard
in it and no sign of the gap.

**Credentials.** The official CLI reads ``~/.kaggle/kaggle.json``. Nothing here
opens that file, nothing here accepts a token as an argument, and nothing here
prints an environment. The one thing this module says about credentials is
whether they are present, because "the CLI is installed but not configured" is
the failure people spend the longest on — and :func:`check` turns that whole
class of failure into one command that answers before anything is uploaded.

**Finding the CLI.** ``PATH`` is not the only place to look. The usual way to
run this project is ``.venv/bin/python mk.py``, which does *not* put
``.venv/bin`` on ``PATH`` — so a ``pip install kaggle`` into the project's own
virtualenv produces a CLI that ``shutil.which`` cannot see, and an error message
telling the user to install something they have already installed. So
:func:`cli_path` looks beside the running interpreter as well.

**Datasets are public and are pulled over the public endpoint when the CLI is
not installed.** That is a convenience, not a second source of truth: whichever
route the bytes arrive by, :mod:`harness.datasets` hashes them against the pin
before anything reads a row.

**Exit non-zero on a failed or timed-out kernel.** :func:`pull` refuses to
fetch the output of a run that did not report ``complete``. Pulling a partial
output is how a shard silently goes missing, and a merged table with a missing
shard is a table of the cases that happened to finish.

**The repository is pushed as a dataset, from a staged copy.** :func:`stage_repo`
builds that copy from an explicit include list rather than from the working
directory, because the working directory holds three things that must not go to
Kaggle: ``data/`` (46 MB of other people's datasets, which are pinned by digest
and re-pulled rather than redistributed), ``runs/`` (52 MB of output, which is
what the hosted run is supposed to *produce*), and ``.venv``/``.git``. An
include list also means the upload is a stated set of files rather than whatever
happened to be lying around, and :func:`stage_repo` returns the manifest so the
push can say what it sent.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from harness.datasets import (
    LOCAL_ROOT,
    DatasetRecord,
    FileDigest,
    measure,
    read_registry,
    write_registry,
)

__all__ = [
    "REPO_ROOT",
    "cli_path",
    "cli_version",
    "check",
    "KERNEL_DIR",
    "METADATA_PATH",
    "DATASET_METADATA_PATH",
    "REPO_INCLUDE",
    "REPO_EXCLUDE_NAMES",
    "stage_repo",
    "push_repo",
    "attached_versions",
    "slugify",
    "KaggleError",
    "CredentialsMissing",
    "KernelNotComplete",
    "cli_available",
    "credentials_present",
    "kernel_ref",
    "pull_dataset",
    "pin_dataset",
    "push",
    "status",
    "pull",
]

REPO_ROOT = Path(__file__).resolve().parent.parent

#: What ``mk kaggle push`` sends: the notebook and its metadata, both committed.
KERNEL_DIR = REPO_ROOT / "kaggle"
METADATA_PATH = KERNEL_DIR / "kernel-metadata.json"

#: The repository-as-a-dataset metadata. Committed here; copied into the
#: staging directory at push time, because the Kaggle CLI wants it beside the
#: files it is uploading and the files it is uploading are not this directory.
DATASET_METADATA_PATH = KERNEL_DIR / "dataset-metadata.json"

#: Exactly what goes to Kaggle as the repository dataset. An explicit list, so
#: the upload is a stated set of files rather than whatever the working
#: directory happened to contain — and so ``data/`` and ``runs/`` cannot go by
#: accident. ``harness/generated`` is the bulk of it and is the point: the
#: notebook *runs* the committed corpus rather than regenerating it, so the
#: datasets it was derived from are not needed at run time at all.
REPO_INCLUDE: tuple[str, ...] = (
    "agent",
    "fixtures",
    "harness",
    "kernel",
    "scripts",
    "sim",
    "tests",
    "conftest.py",
    "mk.py",
    "pyproject.toml",
    "README.md",
    "results.md",
    "SPEC.md",
)

#: Directory and file names never copied, at any depth.
REPO_EXCLUDE_NAMES: frozenset[str] = frozenset(
    {"__pycache__", ".git", ".venv", ".pytest_cache", ".hypothesis", ".DS_Store"}
)

#: Suffixes never copied.
REPO_EXCLUDE_SUFFIXES: tuple[str, ...] = (".pyc", ".db", ".db-wal", ".db-shm")

#: Where the credentials live. Named so the error message can say it; never
#: opened by this module.
CREDENTIALS_PATH = Path.home() / ".kaggle" / "kaggle.json"

#: How the Kaggle CLI writes a version-pinned dataset attachment:
#: ``owner/slug/N``. **Not** ``owner/slug/versions/N``, which is how the *web*
#: URL is spelled and which the CLI rejects locally with "Invalid dataset
#: specification" — before uploading anything, so the failure is cheap but only
#: if you are looking for it. :func:`check` validates every entry against this
#: so a bad spec is caught by a preflight rather than by a failed push.
DATASET_SOURCE = __import__("re").compile(
    r"^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9-]*(?:/(\d+))?$"
)

#: The public dataset endpoint, used when the CLI is not installed. Public
#: datasets answer it without a token.
DOWNLOAD_URL = "https://www.kaggle.com/api/v1/datasets/download/{ref}"
VIEW_URL = "https://www.kaggle.com/api/v1/datasets/view/{ref}"


class KaggleError(RuntimeError):
    """Something went wrong on the Kaggle side."""


class CredentialsMissing(KaggleError):
    """The CLI is installed and has no credentials, or is not installed."""


class KernelNotComplete(KaggleError):
    """The run failed, is still going, or timed out.

    A separate exception because the caller's correct response differs: a
    running kernel is waited for and a failed one is looked at, and neither is
    "fetch whatever is in the output directory".
    """


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def cli_path() -> str | None:
    """Where the Kaggle CLI is, or ``None``.

    ``PATH`` first, then beside the running interpreter. See the module
    docstring: ``.venv/bin/python mk.py`` does not put ``.venv/bin`` on
    ``PATH``, and telling somebody to install a thing they have installed is
    the worst error message this module could produce.
    """
    found = shutil.which("kaggle")
    if found:
        return found
    beside = Path(sys.executable).parent / "kaggle"
    return str(beside) if beside.is_file() else None


def cli_available() -> bool:
    return cli_path() is not None


def cli_version() -> str:
    """What the CLI reports, or ``""``. Recorded rather than assumed."""
    found = cli_path()
    if found is None:
        return ""
    try:
        completed = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [found, "--version"], capture_output=True, text=True, timeout=60
        )
    except OSError:
        return ""
    return (completed.stdout or completed.stderr).strip()


def credentials_present() -> bool:
    """Whether the CLI has something to authenticate with.

    Existence only. The file is never read here — a wrapper that parsed
    credentials would be a wrapper that could print them.
    """
    import os

    return CREDENTIALS_PATH.exists() or bool(
        os.environ.get("KAGGLE_USERNAME") and os.environ.get("KAGGLE_KEY")
    )


def _run(args: list[str], *, timeout: int = 900) -> subprocess.CompletedProcess:
    if not cli_available():
        raise CredentialsMissing(
            "the Kaggle CLI is not installed. `pip install kaggle`, then put "
            f"your token at {CREDENTIALS_PATH}. Nothing in this repository "
            "reads or prints that file."
        )
    if not credentials_present():
        raise CredentialsMissing(
            f"the Kaggle CLI is installed but {CREDENTIALS_PATH} is missing "
            "and KAGGLE_USERNAME/KAGGLE_KEY are unset. Kernel push, status and "
            "pull all need credentials; public datasets do not."
        )
    return subprocess.run(  # noqa: S603 — a fixed argv, no shell
        [cli_path(), *args], capture_output=True, text=True, timeout=timeout
    )


def slugify(title: str) -> str:
    """Kaggle's slug rule, as far as it affects us.

    Load-bearing because **Kaggle derives a kernel's slug from its title, not
    from the ``id`` you push.** A title that slugs to something else produces a
    kernel at an address the metadata does not name: the push succeeds with a
    warning, and every ``status`` and ``pull`` afterwards fails with "Cannot
    access kernel", which reads like a permissions problem and is not one.

    Lower-cased, every run of non-alphanumerics collapsed to one hyphen, ends
    trimmed. An em-dash in a title therefore disappears rather than becoming a
    separator, which is exactly the case that bit.
    """
    import re as _re

    return _re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")


def attached_versions() -> dict[str, int]:
    """``owner/slug -> version`` for every dataset the notebook attaches.

    One parser for the format, because there were three copies of it and two of
    them were wrong. The CLI's rule is ``owner/slug/N``; the web URL's
    ``owner/slug/versions/N`` is rejected locally with "Invalid dataset
    specification", which is a cheap failure and an invisible one until
    somebody runs a push.
    """
    out: dict[str, int] = {}
    for source in json.loads(METADATA_PATH.read_text()).get("dataset_sources", []):
        parts = source.split("/")
        if len(parts) == 3 and parts[2].isdigit():
            out[f"{parts[0]}/{parts[1]}".lower()] = int(parts[2])
    return out


def repo_ref() -> str:
    """``owner/slug`` for the repository dataset."""
    if not DATASET_METADATA_PATH.exists():
        raise KaggleError(f"{DATASET_METADATA_PATH} is missing")
    return json.loads(DATASET_METADATA_PATH.read_text())["id"]


def stage_repo(dest: Path) -> dict[str, Any]:
    """Copy the repository into ``dest`` as the dataset that will be attached.

    Returns ``{"files", "bytes", "dirs"}`` so the caller can print what it is
    about to upload. A push that could not say what it sent would make "the
    pushed code and the run that produced a table are one recorded object" a
    claim with nothing behind it.
    """
    import shutil

    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    def keep(path: Path) -> bool:
        parts = set(path.relative_to(REPO_ROOT).parts)
        return not (parts & REPO_EXCLUDE_NAMES) and path.suffix not in REPO_EXCLUDE_SUFFIXES

    files = 0
    total = 0
    for name in REPO_INCLUDE:
        source = REPO_ROOT / name
        if not source.exists():
            raise KaggleError(
                f"{name} is not in this repository, so the staged dataset would "
                "be missing something the notebook imports"
            )
        if source.is_file():
            shutil.copy2(source, dest / name)
            files += 1
            total += source.stat().st_size
            continue
        for path in sorted(source.rglob("*")):
            if not path.is_file() or not keep(path):
                continue
            target = dest / path.relative_to(REPO_ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            files += 1
            total += path.stat().st_size

    shutil.copy2(DATASET_METADATA_PATH, dest / "dataset-metadata.json")
    return {
        "dir": str(dest),
        "files": files,
        "bytes": total,
        "ref": repo_ref(),
    }


def push_repo(*, message: str, stage: Path | None = None) -> dict[str, Any]:
    """Create or version the repository dataset from a staged copy.

    ``create`` the first time and ``version`` afterwards, decided by asking
    Kaggle rather than by a flag: a flag would be wrong exactly once, on the
    day somebody could least afford to debug it.
    """
    staged = stage_repo(stage or (REPO_ROOT / "runs" / "kaggle-stage"))
    ref = staged["ref"]
    exists = True
    try:
        _fetch_meta(ref)
    except Exception:  # noqa: BLE001 — any failure means "not published yet"
        exists = False

    # ``--keep-tabular`` because Kaggle converts tabular files to CSV by
    # default, and every file here is hashed into a manifest: a helpful
    # conversion would break the corpus rather than improve it.
    #
    # ``--public`` from the committed metadata rather than from a flag somebody
    # remembers, because ``datasets create`` is **private by default** and the
    # visibility of a published artefact should be a fact in a file.
    common = ["-r", "zip", "--keep-tabular"]
    if exists:
        args = ["datasets", "version", "-p", staged["dir"], "-m", message, *common]
    else:
        args = ["datasets", "create", "-p", staged["dir"], *common]
        if not json.loads(DATASET_METADATA_PATH.read_text()).get("isPrivate", True):
            args.append("--public")
    completed = _run(args, timeout=3600)
    if completed.returncode != 0:
        raise KaggleError(
            f"kaggle datasets {'version' if exists else 'create'} failed for "
            f"{ref}: {completed.stderr.strip() or completed.stdout.strip()}"
        )
    return staged | {
        "created": not exists,
        "output": completed.stdout.strip(),
    }


def kernel_ref() -> str:
    """``owner/slug`` for the committed notebook."""
    if not METADATA_PATH.exists():
        raise KaggleError(
            f"{METADATA_PATH} is missing. The notebook and its metadata are "
            "committed on purpose: a hand-run notebook whose exact code nobody "
            "kept is not a reproducible measurement."
        )
    return json.loads(METADATA_PATH.read_text())["id"]


# ---------------------------------------------------------------------------
# Datasets
# ---------------------------------------------------------------------------


def _fetch_zip(ref: str, version: int) -> bytes:
    url = DOWNLOAD_URL.format(ref=ref) + f"?datasetVersionNumber={version}"
    request = urllib.request.Request(url, headers={"User-Agent": "mandate-harness"})
    with urllib.request.urlopen(request, timeout=600) as response:  # noqa: S310
        return response.read()


def _fetch_meta(ref: str) -> dict[str, Any]:
    request = urllib.request.Request(
        VIEW_URL.format(ref=ref), headers={"User-Agent": "mandate-harness"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        return json.load(response)


def pull_dataset(ref: str, version: int, *, dest: Path | None = None) -> Path:
    """Download one dataset version and unpack it. Returns the directory.

    The directory carries the owner, the slug **and the version**, so two
    versions of one dataset can sit side by side and a pin that names a version
    resolves to the one it named. A directory named after the slug alone would
    make "we used version 1" unverifiable the moment version 2 was pulled.
    """
    directory = dest or (LOCAL_ROOT / ref.replace("/", "__") / f"v{version}")
    directory.mkdir(parents=True, exist_ok=True)
    blob = _fetch_zip(ref, version)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        for info in archive.infolist():
            if info.is_dir() or "/" in info.filename or info.filename.startswith("."):
                # Flat only. A dataset that unpacked into directories would
                # make the pinned file names ambiguous.
                continue
            (directory / info.filename).write_bytes(archive.read(info))
    return directory


def pin_dataset(
    role: str, ref: str, version: int, files: list[str], *, directory: Path
) -> DatasetRecord:
    """Record what was pulled, so generation can refuse anything else later."""
    owner, slug = ref.split("/", 1)
    meta = _fetch_meta(ref)
    digested = []
    for name in sorted(files):
        path = directory / name
        if not path.is_file():
            raise KaggleError(f"{ref}@v{version} has no file {name!r} in {directory}")
        sha, size, rows = measure(path)
        digested.append(FileDigest(name=name, sha256=sha, bytes=size, rows=rows))

    entry = DatasetRecord(
        role=role,
        owner=owner,
        slug=slug,
        version=version,
        licence=meta.get("licenseName") or "unrecorded",
        title=meta.get("title") or slug,
        url=f"https://www.kaggle.com/datasets/{ref}/versions/{version}",
        pulled_at=_now(),
        files=tuple(digested),
    )
    registry = read_registry()
    registry[role] = entry
    write_registry(registry)
    return entry


# ---------------------------------------------------------------------------
# Kernels
# ---------------------------------------------------------------------------


def push() -> dict[str, Any]:
    """Send the committed notebook and metadata as a new kernel version."""
    ref = kernel_ref()
    completed = _run(["kernels", "push", "-p", str(KERNEL_DIR)])
    if completed.returncode != 0:
        raise KaggleError(
            f"kaggle kernels push failed for {ref}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return {"ref": ref, "at": _now(), "output": completed.stdout.strip()}


def status() -> dict[str, Any]:
    """``{"ref", "status", "message"}`` for the last run of the kernel."""
    ref = kernel_ref()
    completed = _run(["kernels", "status", ref], timeout=120)
    if completed.returncode != 0:
        raise KaggleError(
            f"kaggle kernels status failed for {ref}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    text = completed.stdout.strip()
    state = "unknown"
    for candidate in ("complete", "error", "cancelAcknowledged", "running", "queued"):
        if candidate.lower() in text.lower():
            state = candidate
            break
    return {"ref": ref, "status": state, "message": text}


def pull(dest: Path, *, expect_shards: int | None = None) -> dict[str, Any]:
    """Fetch the kernel's output, then check it before anybody merges it.

    Two checks, both of which exist because their failure produces a *table*
    rather than an error. The run must have completed — a timed-out kernel
    leaves a partial output directory that looks like a small suite. And the
    output must carry the ``digests.json`` the notebook wrote, with every
    JSONL hashing to what the notebook recorded, because a truncated upload is
    a file that parses.
    """
    ref = kernel_ref()
    state = status()
    if state["status"] != "complete":
        raise KernelNotComplete(
            f"{ref} is {state['status']!r}, not complete. Refusing to pull: a "
            "partial output merges cleanly and produces a table of the cases "
            f"that happened to finish.\n{state['message']}"
        )

    dest.mkdir(parents=True, exist_ok=True)
    completed = _run(["kernels", "output", ref, "-p", str(dest)])
    if completed.returncode != 0:
        raise KaggleError(
            f"kaggle kernels output failed for {ref}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return verify_output(dest, expect_shards=expect_shards) | {"ref": ref}


def verify_output(dest: Path, *, expect_shards: int | None = None) -> dict[str, Any]:
    """Hold a pulled (or locally produced) output directory to its own digests.

    Split from :func:`pull` so the same check runs against a directory that
    never went near Kaggle — the local rehearsal of the notebook has to be
    checkable the same way, or the check is only ever exercised where it is
    hardest to debug.
    """
    index = dest / "digests.json"
    if not index.exists():
        raise KaggleError(
            f"{dest} has no digests.json. The notebook writes one beside its "
            "JSONL; without it a truncated upload is a file that parses."
        )
    body = json.loads(index.read_text())
    problems: list[str] = []
    for name, recorded in sorted(body.get("files", {}).items()):
        path = dest / name
        if not path.is_file():
            problems.append(f"missing: {name}")
            continue
        found, size, _ = measure(path)
        if found != recorded["sha256"]:
            problems.append(
                f"changed: {name} hashes to {found}, recorded {recorded['sha256']}"
            )
        elif size != recorded["bytes"]:
            problems.append(f"size moved: {name} is {size}, recorded {recorded['bytes']}")
    shards = sorted(body.get("shards", []))
    if expect_shards is not None and len(shards) != expect_shards:
        problems.append(
            f"{len(shards)} shard(s) in the output, {expect_shards} expected; "
            "a missing shard is noticed here or never"
        )
    if problems:
        raise KaggleError(
            f"the output in {dest} does not match its own digests.json:\n  "
            + "\n  ".join(problems)
        )
    return {
        "dir": str(dest),
        "files": sorted(body.get("files", {})),
        "shards": shards,
        "run": body.get("run", {}),
    }


def check() -> list[dict[str, Any]]:
    """Preflight: every reason a push would fail, answered before anything uploads.

    Returns one row per check with ``ok`` and a ``detail``, rather than raising
    on the first failure, because the failures are independent and a person
    fixing them wants the whole list. The last two matter most and are the ones
    people miss: the two metadata files have to name the **same owner**, and
    that owner has to be **you** — Kaggle refuses a push whose owner is not the
    authenticated account, and finding that out after the dataset has already
    been created is the expensive order to find it out in.
    """
    rows: list[dict[str, Any]] = []

    def row(name: str, ok: bool, detail: str) -> None:
        rows.append({"check": name, "ok": ok, "detail": detail})

    found = cli_path()
    row(
        "cli installed",
        found is not None,
        found or f"not on PATH and not beside {sys.executable}; pip install kaggle",
    )
    version = cli_version()
    row("cli version", bool(version), version or "could not be read")
    row(
        "credentials",
        credentials_present(),
        f"{CREDENTIALS_PATH} exists" if CREDENTIALS_PATH.exists()
        else "KAGGLE_USERNAME/KAGGLE_KEY set" if credentials_present()
        else f"no {CREDENTIALS_PATH} and no KAGGLE_USERNAME/KAGGLE_KEY",
    )

    sources = json.loads(METADATA_PATH.read_text()).get("dataset_sources", [])
    malformed = [s for s in sources if not DATASET_SOURCE.match(s)]
    row(
        "dataset specs",
        not malformed and bool(sources),
        "; ".join(f"{s!r} is not owner/slug/N" for s in malformed)
        or f"{len(sources)} attachment(s), all version-pinned",
    )
    unpinned = [s for s in sources if DATASET_SOURCE.match(s) and "/" not in s[s.index("/") + 1:]]
    if unpinned:
        row(
            "versions pinned",
            False,
            "; ".join(f"{s!r} names no version" for s in unpinned)
            + " — an unpinned attachment resolves to whatever is current",
        )

    try:
        kernel_owner = kernel_ref().split("/")[0]
        repo_owner = repo_ref().split("/")[0]
        row(
            "one owner",
            kernel_owner == repo_owner,
            f"kernel {kernel_ref()}, dataset {repo_ref()}",
        )
    except KaggleError as exc:
        row("one owner", False, str(exc))
        return rows

    for label, path in (("kernel", METADATA_PATH), ("dataset", DATASET_METADATA_PATH)):
        body = json.loads(path.read_text())
        wanted = body["id"].split("/", 1)[1]
        derived = slugify(body["title"])
        row(
            f"{label} title slug",
            derived == wanted,
            f"title {body['title']!r} resolves to {derived!r}, id says {wanted!r}"
            + (
                ""
                if derived == wanted
                else " — Kaggle uses the title, so the object lands at the "
                "first and every status/pull against the second fails"
            ),
        )

    if malformed:
        # No point asking Kaggle anything: the CLI rejects these locally.
        return rows

    if not (found and credentials_present()):
        row("authenticated", False, "skipped: no CLI or no credentials")
        return rows

    # An authenticated call that lists only your own datasets. It proves the
    # token works and, because ``--mine`` is scoped to the caller, a success
    # here plus the owner check above is what "the push will be accepted" means.
    completed = _run(["datasets", "list", "--mine"], timeout=120)
    row(
        "authenticated",
        completed.returncode == 0,
        completed.stdout.strip().splitlines()[0]
        if completed.returncode == 0 and completed.stdout.strip()
        else (completed.stderr.strip() or "no datasets yet, which is fine"),
    )
    return rows
