"""Shared AST walking for the two lints that guard the kernel.

Both lints work on dotted call names — ``datetime.now``, ``random.random`` —
rather than on raw text, so a comment mentioning ``time.time()`` does not fail
the build and ``self._clock.now()`` is not mistaken for a wall-clock read.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def kernel_files() -> list[Path]:
    return sorted(p for p in (REPO_ROOT / "kernel").rglob("*.py"))


def dotted_name(node: ast.AST) -> str | None:
    """``a.b.c`` for an attribute/name chain, else ``None``."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def imported_modules(tree: ast.AST) -> set[str]:
    """Every module name reached by an ``import`` in this file."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def called_names(tree: ast.AST) -> list[tuple[str, int]]:
    """``(dotted callee, line)`` for every call in the file."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted_name(node.func)
            if name:
                out.append((name, node.lineno))
    return out


def root_module(name: str) -> str:
    return name.split(".")[0]
