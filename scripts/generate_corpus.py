#!/usr/bin/env python3
"""Build the P8 generated corpus from the pinned Kaggle datasets.

    python3 scripts/generate_corpus.py --force

``--force`` for the same reason ``scripts/build_fixtures.py`` needs it, one
level up: this signs one intent and one cart per task, ECDSA picks a fresh
nonce per signature, and a rebuild is therefore a **new corpus with a new
manifest hash**. Every generated table in ``results.md`` quotes that hash, so
re-running this by accident invalidates all of them for no reason.

The datasets are not committed. Pull them first with `mk kaggle datasets pull`;
this refuses to read a file whose digest does not match the pin in
``harness/datasets.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from harness.datasets import DatasetError  # noqa: E402
from harness.generate.build import generate  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="required: regenerating re-signs everything and moves the corpus hash",
    )
    parser.add_argument("--seed", default="p8", help="the generator seed")
    parser.add_argument(
        "--no-sign",
        action="store_true",
        help="write the corpus but do not re-sign the mandates (leaves it unfrozen)",
    )
    args = parser.parse_args()
    if not args.force:
        print(
            "Refusing to regenerate without --force.\n"
            "Signing is not deterministic, so a rebuild changes every mandate "
            "and the generated corpus hash every table quotes.",
            file=sys.stderr,
        )
        return 2

    try:
        result = generate(seed=args.seed, sign=not args.no_sign)
    except DatasetError as exc:
        print(f"generate: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result.report, indent=2, sort_keys=True))
    print(f"\ngenerated corpus frozen at {result.manifest_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
