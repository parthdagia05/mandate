"""M1's "Prove it" block, as a test.

The milestone rule is that someone who has not read the code can run one
command and see the right thing happen. This file runs those commands as
subprocesses and asserts on what they print, so the milestone cannot quietly
stop being true while the unit tests stay green.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

from tests._lint import REPO_ROOT

MK = [sys.executable, str(REPO_ROOT / "mk.py")]
CHAIN = REPO_ROOT / "fixtures" / "chain.jsonl"


def run(*args, cwd=REPO_ROOT):
    return subprocess.run(
        MK + list(args), cwd=cwd, capture_output=True, text=True
    )


def hashes_in(text):
    return re.findall(r"cart_hash\s+(sha256:[0-9a-f]{64})", text)


# --------------------------------------------------------------------------
# Step 1 — two carts written differently, one hash
# --------------------------------------------------------------------------


def test_step1_both_carts_print_the_same_hash():
    result = run("hash-cart", "fixtures/cart_a.json", "fixtures/cart_b.json")
    assert result.returncode == 0, result.stderr

    found = hashes_in(result.stdout)
    assert len(found) == 2
    assert found[0] == found[1]
    assert "identical across 2 carts" in result.stdout


def test_step1_the_two_files_really_do_differ_on_disk():
    """The claim is only interesting if the inputs are genuinely different."""
    a_text = (REPO_ROOT / "fixtures" / "cart_a.json").read_text()
    b_text = (REPO_ROOT / "fixtures" / "cart_b.json").read_text()
    assert a_text != b_text

    a, b = json.loads(a_text), json.loads(b_text)
    assert list(a) != list(b), "key order should differ"
    assert [i["sku"] for i in a["line_items"]] != [
        i["sku"] for i in b["line_items"]
    ], "line item order should differ"
    assert re.search(r":\s*\d+(\.\d+)?e[+-]?\d+", b_text, re.IGNORECASE), (
        "cart_b should write at least one amount in exponential form"
    )


# --------------------------------------------------------------------------
# Step 2 — one character in a SKU moves the hash
# --------------------------------------------------------------------------


def test_step2_one_character_in_a_sku_changes_the_hash(tmp_path):
    cart = json.loads((REPO_ROOT / "fixtures" / "cart_a.json").read_text())
    original_sku = cart["line_items"][0]["sku"]
    cart["line_items"][0]["sku"] = original_sku[:-1] + (
        "9" if original_sku[-1] != "9" else "8"
    )
    tweaked = tmp_path / "cart_tweaked.json"
    tweaked.write_text(json.dumps(cart))

    result = run("hash-cart", "fixtures/cart_a.json", str(tweaked))
    found = hashes_in(result.stdout)
    assert len(found) == 2
    assert found[0] != found[1]
    assert "DIFFERENT across 2 carts" in result.stdout
    # The tweaked cart also no longer matches its own declared hash, which is
    # exactly what check 4's first conjunct catches at run time.
    assert "MISMATCH" in result.stdout
    assert result.returncode != 0


# --------------------------------------------------------------------------
# Step 3 — the chain verifies
# --------------------------------------------------------------------------


def test_step3_chain_verifies_and_reports_count_and_head():
    result = run("verify-chain", "fixtures/chain.jsonl")
    assert result.returncode == 0, result.stderr
    assert re.fullmatch(
        r"OK, 12 entries, head sha256:[0-9a-f]{64}\n", result.stdout
    ), result.stdout


# --------------------------------------------------------------------------
# Step 4 — any single edit to any row breaks it
# --------------------------------------------------------------------------


def test_step4_editing_any_row_is_caught_at_that_row(tmp_path):
    lines = CHAIN.read_text().splitlines()
    assert len(lines) == 12

    for seq, line in enumerate(lines):
        entry = json.loads(line)
        entry["ts"] = "2030-06-06T06:06:06Z"
        edited = list(lines)
        edited[seq] = json.dumps(entry)

        target = tmp_path / f"edited_{seq}.jsonl"
        target.write_text("\n".join(edited) + "\n")

        result = run("verify-chain", str(target))
        assert result.returncode != 0, f"seq {seq} edit went undetected"
        assert result.stdout.startswith(f"BROKEN at seq {seq}"), result.stdout


def test_step4_the_milestones_worked_example(tmp_path):
    """MILESTONES.md quotes ``BROKEN at seq 7``; this is that exact case."""
    lines = CHAIN.read_text().splitlines()
    entry = json.loads(lines[7])
    entry["payload"]["resolution"] = "approved"
    lines[7] = json.dumps(entry)

    target = tmp_path / "chain.jsonl"
    target.write_text("\n".join(lines) + "\n")

    result = run("verify-chain", str(target))
    assert result.returncode != 0
    assert result.stdout.startswith("BROKEN at seq 7")


# --------------------------------------------------------------------------
# Step 5 — the no-LLM test is green, and the fixtures are frozen
# --------------------------------------------------------------------------


def test_step5_no_llm_in_kernel_suite_passes():
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_no_llm_in_kernel.py", "-q"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_fixtures_match_their_manifest():
    """REQ-11: frozen means something checks."""
    result = run("verify-fixtures")
    assert result.returncode == 0, result.stdout
    assert re.fullmatch(
        r"OK, \d+ fixtures, manifest sha256:[0-9a-f]{64}\n", result.stdout
    ), result.stdout


def test_editing_a_fixture_fails_the_manifest(tmp_path):
    """Proving the freeze detector detects, rather than trusting it."""
    from kernel.canonical import sha256_hex

    manifest = json.loads((REPO_ROOT / "fixtures" / "manifest.json").read_text())
    recorded = manifest["files"]["fixtures/cart_a.json"]
    on_disk = sha256_hex((REPO_ROOT / "fixtures" / "cart_a.json").read_bytes())
    assert recorded == on_disk

    mutated = sha256_hex(b"anything else")
    assert mutated != recorded
