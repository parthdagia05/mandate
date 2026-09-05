"""One pass: datasets in, a frozen generated corpus out.

Ordered rather than arbitrary, and the order is the dependency chain — the
storefront has to exist before a task can be priced from it, the tasks before a
case can name one, the mandates before the manifest can hash them:

1. verify both pinned datasets by digest (refuse on any miss);
2. build the storefront and write ``sim/merchants/catalogues/genmart.json``;
3. build the benign tasks under the declared cap policy;
4. build both attack batches from the admitted carriers;
5. sign one intent and one cart per task, sharded;
6. write the seal and the generation report;
7. freeze: one hash over the corpus, its dataset digests, the generator
   version and the seed.

**Every step's refusals are counted and end up in the report.** A generator
that dropped four fifths of its input and said nothing would produce a corpus
nobody could argue with, and the drop rates are among the more interesting
numbers this exercise produces — 4051 of 4055 admitted carriers turn out to
name none of the seven payment decisions at all.

**Regeneration is a new corpus.** ECDSA picks a fresh nonce per signature, so
re-running this moves every mandate and the manifest hash with them, and every
table that quoted the old hash is stale. Hence ``--force``, and hence "generate
once, at freeze time".
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from harness.corpus import GEN_BATCHES, GEN_TASKS_DIR, GENERATED_ROOT
from harness.datasets import digests, require
from harness.generate import GENERATOR_VERSION
from harness.generate.attacks import (
    BASE64_EVERY,
    BATCH_NAMES,
    PER_CLASS,
    build_attacks,
)
from harness.generate.catalogue import (
    SHIPPING_PAISE,
    SHIPPING_SKU,
    build_catalogue,
)
from harness.generate.payloads import build_carriers
from harness.generate.store import (
    STOREFRONT_SIZE,
    category_caps,
    select_products,
    storefront_document,
)
from harness.generate.tasks import SHARD_SIZE, TASK_COUNT, build_tasks, shard_dir
from harness.manifest import write_generated_manifest
from sim.merchants.generated import CATALOGUE_PATH, load_catalogue

__all__ = ["REPORT_PATH", "SEAL_PATH", "GenerationResult", "generate"]

REPORT_PATH = GENERATED_ROOT / "report.json"
SEAL_PATH = GENERATED_ROOT / "seal.json"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class GenerationResult:
    manifest_hash: str
    report: dict[str, Any]


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _write_json(path: Path, body: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")


def _clear(directory: Path) -> None:
    """Remove a previous generation's files, so a smaller corpus is smaller.

    Left-over files from a bigger previous run would be loaded by
    ``harness.corpus`` — which reads directories, not the manifest — and would
    put cases in a suite that the manifest did not cover.
    """
    for stale in sorted(directory.glob("*/*.json")):
        stale.unlink()
    for empty in sorted(p for p in directory.glob("*") if p.is_dir()):
        if not any(empty.iterdir()):
            empty.rmdir()


def generate(*, seed: str = "p8", sign: bool = True) -> GenerationResult:
    """Build, sign and freeze the generated corpus. Returns its hash."""
    for role in ("retail_catalogue", "injection_corpus", "injection_corpus_2"):
        require(role)

    catalogue = build_catalogue()
    storefront = select_products(catalogue.products)
    caps = category_caps(storefront)
    _write_json(CATALOGUE_PATH, storefront_document(storefront, caps))
    load_catalogue.cache_clear()

    tasks = build_tasks(
        storefront,
        caps,
        shipping={"sku": SHIPPING_SKU, "unit_amount": SHIPPING_PAISE},
        seed=seed,
    )
    _clear(GEN_TASKS_DIR)
    for position, task in enumerate(tasks.tasks):
        _write_json(
            GEN_TASKS_DIR / shard_dir(position) / f"{task.task_id.replace('-', '_')}.json",
            task.raw,
        )

    carriers = build_carriers()
    attacks = build_attacks(
        carriers.carriers, tasks.tasks, [product.sku for product in storefront]
    )
    for batch, directory in GEN_BATCHES.items():
        _clear(directory)
        for position, case in enumerate(attacks.cases.get(batch, [])):
            _write_json(
                directory / f"shard-{position // SHARD_SIZE:02d}" / f"{case.case_id}.json",
                case.raw,
            )

    if sign:
        # A subprocess rather than an import, so the ``--force`` guard on
        # re-signing is the same guard whichever way the script is reached. A
        # code path that could sign without it would be the one somebody uses.
        completed = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "build_fixtures.py"),
                "--force",
                "--generated",
            ],
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                "signing the generated mandates failed:\n"
                + (completed.stderr or completed.stdout)
            )

    seal = {
        "generated_at": _now(),
        "generator_version": GENERATOR_VERSION,
        "seed": seed,
        "per_class": PER_CLASS,
        "batches": {
            batch: {"cases": len(attacks.cases.get(batch, []))} for batch in BATCH_NAMES
        },
        "note": (
            "gen-b is held out under the same single-open guard batch B has. "
            "Opening it is logged in harness/attacks/openings.jsonl and a "
            "second opening is logged as an override. Counts here were taken "
            "at generation time, before the freeze."
        ),
    }
    _write_json(SEAL_PATH, seal)

    report = {
        "generated_at": _now(),
        "generator_version": GENERATOR_VERSION,
        "seed": seed,
        "datasets": digests(),
        "catalogue": catalogue.report(),
        "storefront": {
            "products": len(storefront),
            "target_size": STOREFRONT_SIZE,
            "caps": {
                category: policy.per_txn_cap for category, policy in sorted(caps.items())
            },
        },
        "tasks": tasks.report() | {"target": TASK_COUNT},
        "carriers": carriers.report(),
        "attacks": attacks.report() | {"per_class": PER_CLASS, "base64_every": BASE64_EVERY},
    }
    _write_json(REPORT_PATH, report)

    manifest_hash = write_generated_manifest(
        generator_version=GENERATOR_VERSION,
        seed=seed,
        dataset_digests=digests(),
    )
    return GenerationResult(manifest_hash=manifest_hash, report=report)
