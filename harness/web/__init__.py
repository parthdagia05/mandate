"""The read-only artifact API and the static site it serves. Issue #83.

Three properties hold across this package, and each is a decision rather than a
detail:

**It adds no route to the kernel.** ``kernel/api.py`` stays the eight endpoints
it has, its peer guard stays loopback-only, and ``tests/test_no_llm_in_kernel.py``
keeps passing without an exemption. This package never imports
:class:`kernel.service.KernelService`; the one demo route (#89) is an HTTP client
of ``:8080`` exactly as the harness already is.

**It computes no metric.** Every proportion, percentile and interval comes from
:mod:`harness.metrics` — the same functions ``results.md`` is rendered from,
serialised through ``Proportion.as_dict()``. A second implementation would
eventually disagree with the published table and nobody could say which was
wrong. The same argument bars a re-implementation in TypeScript (#91), and it is
why the frontend has no derivation layer at all.

**It renames nothing.** Responses carry the run record's own field names, so
anything visible on a page can be grepped for in the JSONL. That is asserted by
``tests/test_web_api.py`` rather than left as an intention.

The chain is verified by ``scripts/verify_chain.py`` as a subprocess, not by
code in here and not in the browser (#88): the verifier imports nothing from the
project, which is the entire reason reviewers are asked to trust it.
"""

from __future__ import annotations

__all__ = ["RunIndex", "WebApi", "serve", "DEFAULT_HOST", "DEFAULT_PORT"]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8090


def __getattr__(name: str):  # pragma: no cover - lazy re-export
    if name == "RunIndex":
        from harness.web.index import RunIndex

        return RunIndex
    if name == "WebApi":
        from harness.web.api import WebApi

        return WebApi
    if name == "serve":
        from harness.web.server import serve

        return serve
    raise AttributeError(name)
