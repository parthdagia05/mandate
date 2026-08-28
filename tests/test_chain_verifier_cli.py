"""D-06 / REQ-9 — the chain verifies from a standalone CLI.

This is the tool that makes every later claim checkable, so the tests here are
mostly about what the verifier is *not* allowed to depend on. A verifier that
imports the kernel inherits the kernel's bugs, and could in principle be made
to agree with a tampered chain by tampering with the kernel too.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from kernel.canonical import jcs as kernel_jcs
from tests._lint import REPO_ROOT, imported_modules, root_module

VERIFIER = REPO_ROOT / "scripts" / "verify_chain.py"
CHAIN = REPO_ROOT / "fixtures" / "chain.jsonl"

#: Everything the verifier is allowed to import: the standard library, and
#: nothing else.
ALLOWED_IMPORTS = frozenset({"__future__", "hashlib", "json", "math", "sys"})


@pytest.fixture(scope="module")
def standalone():
    """The verifier loaded by path, the way ``mk verify-chain`` loads it."""
    spec = importlib.util.spec_from_file_location("_standalone_under_test", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# The independence claim
# --------------------------------------------------------------------------


def test_verifier_imports_nothing_from_the_project():
    tree = ast.parse(VERIFIER.read_text(), filename=str(VERIFIER))
    offenders = sorted(
        name for name in imported_modules(tree) if root_module(name) not in ALLOWED_IMPORTS
    )
    assert not offenders, (
        f"the standalone verifier imports {offenders}; it must run from an "
        "empty directory with nothing else on the path (REQ-9)"
    )


def test_verifier_runs_from_an_empty_directory(tmp_path):
    """Copy one file and one chain into a bare directory and run it there."""
    workdir = tmp_path / "empty"
    workdir.mkdir()
    shutil.copy(VERIFIER, workdir / "verify_chain.py")
    shutil.copy(CHAIN, workdir / "chain.jsonl")

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, "-I", "verify_chain.py", "chain.jsonl"],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("OK, 12 entries, head sha256:")


def test_verifier_exits_non_zero_naming_the_first_broken_seq(tmp_path):
    workdir = tmp_path / "empty"
    workdir.mkdir()
    shutil.copy(VERIFIER, workdir / "verify_chain.py")

    lines = CHAIN.read_text().splitlines()
    entry = json.loads(lines[7])
    entry["payload"]["resolution"] = "approved"
    lines[7] = json.dumps(entry)
    (workdir / "chain.jsonl").write_text("\n".join(lines) + "\n")

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, "-I", "verify_chain.py", "chain.jsonl"],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert result.stdout.startswith("BROKEN at seq 7")


# --------------------------------------------------------------------------
# The two JCS implementations must not drift
# --------------------------------------------------------------------------

_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1),
    st.floats(allow_nan=False, allow_infinity=False, width=64),
    st.text(max_size=15).filter(
        lambda s: not any(0xD800 <= ord(c) <= 0xDFFF for c in s)
    ),
)

_VALUES = st.recursive(
    _SCALARS,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=6), children, max_size=4),
    ),
    max_leaves=10,
)


@given(_VALUES)
@settings(max_examples=300, deadline=None)
def test_the_two_jcs_implementations_agree(standalone, value):
    """Deliberate duplication only helps if the copies stay in step.

    If these two ever disagree, that disagreement is itself the finding: one of
    them is wrong about RFC 8785 and every hash on that side is suspect.
    """
    assert standalone.jcs(value) == kernel_jcs(value)


# --------------------------------------------------------------------------
# Rejection cases
# --------------------------------------------------------------------------


def test_a_clean_chain_reports_count_and_head(standalone):
    with CHAIN.open() as handle:
        count, head = standalone.verify(handle)
    assert count == 12
    assert head.startswith("sha256:")


def test_an_empty_chain_is_refused(standalone):
    with pytest.raises(standalone.Broken):
        standalone.verify([])


def test_a_chain_starting_at_the_wrong_seq_is_refused(standalone):
    lines = CHAIN.read_text().splitlines()[1:]
    with pytest.raises(standalone.Broken) as caught:
        standalone.verify(lines)
    assert caught.value.seq == 1


def test_an_extra_field_on_a_row_is_refused(standalone):
    """The chain format is closed for the same reason the request schemas are."""
    lines = CHAIN.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["note"] = "looks fine to me"
    lines[0] = json.dumps(entry)
    with pytest.raises(standalone.Broken, match="wrong fields"):
        standalone.verify(lines)


def test_truncating_the_chain_still_verifies(standalone):
    """A prefix of a valid chain is a valid chain — truncation is detected by
    comparing the head to what the kernel last recorded, not here."""
    count, _ = standalone.verify(CHAIN.read_text().splitlines()[:5])
    assert count == 5


def test_usage_error_exits_two(standalone):
    assert standalone.main([]) == 2


def test_missing_file_exits_two(standalone, tmp_path):
    assert standalone.main([str(tmp_path / "nope.jsonl")]) == 2
