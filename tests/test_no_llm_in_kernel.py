"""U-20 / REQ-4: the kernel has zero LLM calls, by construction.

This fails the build rather than warning. "No model in the enforcement path"
is the project's first architectural rule, and a rule nothing enforces is a
preference. If a later milestone genuinely needs a model somewhere under
``kernel/``, the honest move is to delete this test in a commit that says so —
not to add an exemption that nobody reads.
"""

from __future__ import annotations

import ast

import pytest

from tests._lint import imported_modules, kernel_files, root_module

#: Root package names of every model SDK and orchestration framework that
#: could put an inference call in the enforcement path.
MODEL_SDKS = frozenset(
    {
        "anthropic",
        "openai",
        "cohere",
        "mistralai",
        "groq",
        "together",
        "replicate",
        "litellm",
        "langchain",
        "langchain_core",
        "langchain_openai",
        "langchain_anthropic",
        "llama_index",
        "llama_cpp",
        "transformers",
        "sentence_transformers",
        "torch",
        "tensorflow",
        "huggingface_hub",
        "ollama",
        "vertexai",
        "google",  # google.generativeai
        "boto3",  # bedrock
        "botocore",
        "instructor",
        "guidance",
        "dspy",
        "outlines",
        "vllm",
    }
)

#: Dynamic import is the obvious way around a static import scan, so it is
#: refused outright inside the kernel.
DYNAMIC_IMPORTS = frozenset({"__import__", "importlib.import_module"})


@pytest.mark.parametrize("path", kernel_files(), ids=lambda p: p.name)
def test_no_model_sdk_import(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders = sorted(
        name
        for name in imported_modules(tree)
        if root_module(name) in MODEL_SDKS
    )
    assert not offenders, (
        f"{path} imports a model SDK: {offenders}. The kernel is the "
        "enforcement path and must contain no LLM call (REQ-4)."
    )


@pytest.mark.parametrize("path", kernel_files(), ids=lambda p: p.name)
def test_no_dynamic_import(path):
    from tests._lint import called_names

    offenders = [
        (name, line)
        for name, line in called_names(ast.parse(path.read_text()))
        if name in DYNAMIC_IMPORTS
    ]
    assert not offenders, (
        f"{path} imports dynamically at {offenders}, which would defeat the "
        "static scan above."
    )


def test_the_scan_can_actually_fail(tmp_path):
    """A lint that cannot fire reads as a passing test forever.

    Same argument as S-02 for the oracles: prove the detector detects.
    """
    fake = tmp_path / "sneaky.py"
    fake.write_text("import anthropic\n")
    tree = ast.parse(fake.read_text())
    assert any(
        root_module(name) in MODEL_SDKS for name in imported_modules(tree)
    )
