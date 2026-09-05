"""``mk``'s command surface, and the two constants it duplicates on purpose.

``mk`` must stay importable with **no project dependencies reachable** — that is
what makes ``mk verify-chain`` runnable from a directory that has none, and it
is why the module imports the project lazily inside each command. The cost of
that is two constants written down twice. These tests are what stop the copies
drifting into a ``--config`` that silently means something else.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import mk

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_the_config_choices_match_the_arms_the_runner_knows():
    from harness.runner import CONFIGS, HEADLINE_CONFIGS

    assert mk.CONFIG_CHOICES == CONFIGS
    assert mk.HEADLINE_CHOICES == HEADLINE_CONFIGS


def test_the_default_chain_path_matches_the_kernel_arms():
    from harness.kernel_arm import DEFAULT_CHAIN_PATH

    assert mk.DEFAULT_CHAIN_PATH == DEFAULT_CHAIN_PATH


def test_mk_imports_with_no_project_modules_on_the_path(tmp_path):
    """REQ-9's property, checked the only way it can be: in another process.

    A ``sys.modules`` fixture would not catch an import added at module scope,
    because the test process has already imported the project.
    """
    script = "import mk; print(sorted(mk.CONFIG_CHOICES))"
    out = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={
            "PYTHONPATH": str(REPO_ROOT),
            "PATH": "/usr/bin:/bin",
        },
    )
    assert out.returncode == 0, out.stderr
    assert "kernel" in out.stdout


@pytest.mark.parametrize(
    "command",
    ["run", "suite", "matrix", "ablate", "report", "corpus", "oracles", "faults"],
)
def test_every_command_is_reachable_from_the_parser(command):
    parser = mk.build_parser()
    actions = [a for a in parser._actions if hasattr(a, "choices") and a.choices]
    subcommands = next(a.choices for a in actions if a.dest == "command")
    assert command in subcommands


def test_a_batch_b_matrix_without_a_reason_exits_two_and_opens_nothing(capsys):
    """The seal, at the command line. Exit 2 is "you asked for the wrong thing",
    not "something went wrong", and nothing is written to the openings log."""
    from harness.corpus import batch_b_openings

    before = len(batch_b_openings())
    code = mk.main(["matrix", "--dataset", "batch_b", "--model", "scripted"])
    assert code == 2
    assert "--reason" in capsys.readouterr().err
    assert len(batch_b_openings()) == before


def test_run_needs_a_task_or_an_attack(capsys):
    assert mk.main(["run"]) == 2
    assert "--task" in capsys.readouterr().err


def test_report_on_something_that_is_not_a_matrix_says_so(tmp_path, capsys):
    assert mk.main(["report", str(tmp_path)]) == 2
    assert "not a matrix directory" in capsys.readouterr().err


def test_ablate_refuses_a_lifecycle_step(capsys):
    assert mk.main(["ablate", "--check", "9", "--model", "scripted", "--quiet"]) == 1
    assert "lifecycle steps" in capsys.readouterr().err


def test_matrix_writes_the_report_it_promises(tmp_path):
    out = tmp_path / "results.md"
    code = mk.main(
        [
            "matrix",
            "--dataset",
            "benign",
            "--config",
            "undefended",
            "--model",
            "scripted",
            "--limit",
            "2",
            "--out",
            str(tmp_path / "matrix"),
            "--results",
            str(out),
            "--quiet",
        ]
    )
    assert code == 0
    text = out.read_text()
    assert text.startswith("# Results")
    assert "Wilson 95%" in text


def test_report_rebuilds_the_same_document_from_the_files(tmp_path):
    """``mk report`` exists so the table is reproducible by somebody who did not
    run the suites."""
    matrix_dir = tmp_path / "matrix"
    first = tmp_path / "a.md"
    second = tmp_path / "b.md"
    mk.main(
        [
            "matrix", "--dataset", "benign", "--config", "undefended",
            "--model", "scripted", "--limit", "2",
            "--out", str(matrix_dir), "--results", str(first), "--quiet",
        ]
    )
    mk.main(["report", str(matrix_dir), "--out", str(second)])

    def stable(text: str) -> list[str]:
        # The run timestamps and the host line are the only lines that move.
        return [
            line
            for line in text.splitlines()
            if not line.startswith("- run —") and not line.startswith("- host —")
        ]

    assert stable(first.read_text()) == stable(second.read_text())


# --- P8: generate, shard, merge, kaggle -----------------------------------


def test_the_dataset_choices_match_the_datasets_the_suite_knows():
    """The same duplication, and the same reason: ``mk`` imports lazily."""
    from harness.suite import DATASETS

    assert mk.DATASET_CHOICES == DATASETS


def test_every_p8_command_is_reachable_from_the_parser():
    parser = mk.build_parser()
    for argv in (
        ["merge", "a.jsonl"],
        ["generate", "corpus", "--force"],
        ["kaggle", "datasets"],
        ["kaggle", "push"],
        ["kaggle", "status"],
        ["kaggle", "pull"],
        ["report-generated", "runs/p8/merged"],
        ["suite", "--dataset", "gen_a", "--shard", "3/8"],
    ):
        args = parser.parse_args(argv)
        assert callable(args.func), argv


def test_a_malformed_shard_is_refused_before_a_file_is_opened(tmp_path, capsys):
    """A partially written JSONL is a worse way to learn the flag was wrong."""
    out = tmp_path / "never.jsonl"
    code = mk.main(
        ["suite", "--dataset", "gen_a", "--shard", "0/8", "--out", str(out), "--quiet"]
    )
    assert code == 2
    assert not out.exists()
    assert "numbered from 1" in capsys.readouterr().err


def test_a_sealed_dataset_without_a_reason_is_refused_before_anything_runs(
    tmp_path, capsys, monkeypatch
):
    """Opening a held-out batch is a decision with a log entry, not a side
    effect of running a suite."""
    import harness.corpus as corpus

    monkeypatch.setattr(corpus, "OPENINGS_LOG", tmp_path / "openings.jsonl")
    monkeypatch.setattr(corpus, "_OPEN", set())
    out = tmp_path / "never.jsonl"
    code = mk.main(
        ["suite", "--dataset", "gen_b", "--config", "kernel", "--out", str(out), "--quiet"]
    )
    assert code == 2
    assert not out.exists()
    assert "--reason" in capsys.readouterr().err


def test_joining_cannot_be_the_first_read_of_a_sealed_batch(
    tmp_path, capsys, monkeypatch
):
    import harness.corpus as corpus

    monkeypatch.setattr(corpus, "OPENINGS_LOG", tmp_path / "openings.jsonl")
    monkeypatch.setattr(corpus, "_OPEN", set())
    code = mk.main(
        [
            "suite",
            "--dataset",
            "gen_b",
            "--config",
            "kernel",
            "--join",
            "--out",
            str(tmp_path / "never.jsonl"),
            "--quiet",
        ]
    )
    assert code == 2
    assert "never been opened" in capsys.readouterr().err


def test_mk_corpus_verify_reports_both_corpora(capsys):
    from harness.manifest import current_hash, generated_corpus_exists, generated_hash

    assert mk.main(["corpus", "verify"]) == 0
    out = capsys.readouterr().out
    assert "hand-written corpus" in out
    assert current_hash() in out
    if generated_corpus_exists():
        assert "generated corpus" in out
        assert generated_hash() in out
        assert "dataset   retail_catalogue" in out


def test_generate_refuses_without_force(capfd):
    """Regenerating re-signs every mandate and moves the corpus hash, and every
    generated table that quoted the old one goes stale.

    ``capfd`` rather than ``capsys``: ``mk generate`` is a thin wrapper over
    ``scripts/generate_corpus.py`` in a subprocess, deliberately, so the
    ``--force`` guard is the same guard whichever way generation is reached.
    """
    assert mk.main(["generate", "corpus"]) != 0
    assert "Refusing to regenerate without --force" in capfd.readouterr().err
