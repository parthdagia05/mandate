"""The agent-facing API, ``127.0.0.1:8080``. SPEC.md §07.

A thin shell. :class:`~kernel.service.KernelService` holds every decision and
this file holds none, for the same reason :mod:`sim.control` is split that way:
``mk run --config kernel`` drives the service in process and the harness drives
it over a socket, and two paths that could disagree eventually do.

**Not FastAPI.** SPEC.md §08's layout names it, and the property that layout is
actually reaching for is "every body is a Pydantic model with
``extra='forbid'`` and no free-text field". That property lives in
:mod:`kernel.decision`, not in a framework, and it is identical either way. What
differs is the dependency list of the enforcement path — a kernel whose whole
argument is that it is small and auditable is not the place to add Starlette,
uvicorn, anyio and their transitive tree so that a request can be routed to one
of eight handlers. The control port already answers this way; symmetry between
the two ports is worth more here than symmetry with the spec's sketch.

**Status codes**, and why a denial is not an error:

===  ============================================================
200  A decision was reached. ``allow``, ``deny`` and ``escalate``
     are all 200 — a policy denial is not an HTTP error, and a 403
     would make a working defence look like a broken deployment in
     every table that counts status codes.
202  ``retry_later`` — the idempotency key is in flight inside the
     TTL. Not a decision, so the body is not a decision response.
422  Schema violation: unknown field, wrong type, prose where a
     typed value belongs.
503  Fail closed: a store is unavailable, or the chain is poisoned.
===  ============================================================

**The anti-prompt property is the schema, not a filter.** Every body below is a
:class:`~kernel.base.StrictModel` built from bounded tokens with no whitespace.
There is nowhere in any request to put a sentence, which is why
``tests/test_api_fuzz.py`` can post prose into every field of every endpoint and
require 422 rather than requiring a denial: the injection never reaches a
decision at all.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from pydantic import ValidationError

from kernel.decision import IntentRegistration, WebhookIngest
from kernel.models import PaymentRequest
from kernel.service import KernelService, Outcome

__all__ = ["API_HOST", "API_PORT", "MAX_BODY_BYTES", "KernelApi", "ApiServer"]

API_HOST = "127.0.0.1"
API_PORT = 8080

#: Largest body the API will read. Every schema here is a handful of bounded
#: fields; a body larger than this is a mistake or a probe, and reading it would
#: be the one unbounded allocation in the process.
MAX_BODY_BYTES = 64 * 1024


class KernelApi:
    """Routes to :class:`~kernel.service.KernelService`. Holds no policy."""

    def __init__(self, service: KernelService) -> None:
        self.service = service
        #: One request at a time, whatever the transport. The chain allocates
        #: ``seq`` by reading the head and inserting after it, and the ledger
        #: is a single-writer store; two interleaved requests would race on
        #: both. Serialising here rather than trusting the server to be
        #: single-threaded means the in-process path is protected too.
        self._lock = threading.Lock()

    #: path -> (body model, service method). The model is the validation; there
    #: is no hand-written field checking anywhere in this file, because
    #: hand-written checking is where an endpoint quietly accepts one more
    #: field than the others.
    POST_ROUTES: dict[str, tuple[type, str]] = {
        "/v1/intent/register": (IntentRegistration, "register_intent"),
        "/v1/authorize": (PaymentRequest, "authorize"),
        "/v1/capture": (PaymentRequest, "capture"),
        "/v1/refund": (PaymentRequest, "refund"),
        "/v1/mandate/create": (PaymentRequest, "mandate_create"),
        "/v1/webhook/ingest": (WebhookIngest, "ingest_webhook"),
    }

    def post(self, path: str, raw_body: bytes) -> Outcome:
        with self._lock:
            return self._post(path, raw_body)

    def _post(self, path: str, raw_body: bytes) -> Outcome:
        route = self.POST_ROUTES.get(path)
        if route is None:
            raise KeyError(path)
        model, method = route

        try:
            parsed = json.loads(raw_body or b"{}")
        except json.JSONDecodeError as exc:
            return Outcome(422, {"error": "not JSON", "detail": str(exc)})
        if not isinstance(parsed, dict):
            return Outcome(422, {"error": "body must be a JSON object"})

        try:
            body = model.model_validate(parsed)
        except ValidationError as exc:
            # The 422 names the offending field and says nothing else. Echoing
            # the rejected value back would put attacker-authored prose in the
            # response, and containment (SPEC.md §12) says payload text does not
            # leave the simulator.
            return Outcome(
                422,
                {
                    "error": "schema violation",
                    "fields": [
                        {
                            "loc": [str(part) for part in err["loc"]],
                            "type": err["type"],
                        }
                        for err in exc.errors()
                    ],
                },
            )

        return getattr(self.service, method)(body)

    def get(self, path: str, query: dict[str, list[str]]) -> Outcome:
        with self._lock:
            return self._get(path, query)

    def _get(self, path: str, query: dict[str, list[str]]) -> Outcome:
        if path == "/v1/healthz":
            return self.service.healthz()
        if path == "/v1/audit/verify":
            return self.service.audit_verify()
        if path == "/v1/audit/chain":
            def bounded(name: str, default: int | None) -> int | None:
                values = query.get(name)
                if not values:
                    return default
                try:
                    return int(values[0])
                except ValueError:
                    raise _BadQuery(name) from None

            try:
                return self.service.audit_chain(bounded("from", 0), bounded("to", None))
            except _BadQuery as exc:
                return Outcome(422, {"error": "bad query parameter", "field": exc.field})
        raise KeyError(path)


class _BadQuery(ValueError):
    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.field = field


class _Handler(BaseHTTPRequestHandler):
    api: KernelApi

    def log_message(self, fmt: str, *args: Any) -> None:
        # The audit chain is the record of what happened. A second,
        # differently-ordered one on stderr is noise.
        return

    def _reply(self, outcome: Outcome) -> None:
        raw = json.dumps(outcome.body).encode("utf-8")
        self.send_response(outcome.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _guard_peer(self) -> bool:
        if self.client_address[0] in ("127.0.0.1", "::1"):
            return True
        self._reply(Outcome(403, {"error": "kernel API is loopback only"}))
        return False

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's name
        if not self._guard_peer():
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            self._reply(Outcome(413, {"error": f"body over {MAX_BODY_BYTES} bytes"}))
            return
        raw = self.rfile.read(length) if length else b"{}"
        try:
            self._reply(self.api.post(urlparse(self.path).path, raw))
        except KeyError:
            self._reply(Outcome(404, {"error": f"no endpoint {self.path}"}))

    def do_GET(self) -> None:  # noqa: N802
        if not self._guard_peer():
            return
        parts = urlparse(self.path)
        try:
            self._reply(self.api.get(parts.path, parse_qs(parts.query)))
        except KeyError:
            self._reply(Outcome(404, {"error": f"no endpoint {self.path}"}))


class ApiServer:
    """The socket. Loopback only, by construction rather than by test.

    The agent process is given this port and never the control port on 8081: a
    control port can move the clock, and a clock the agent can move defeats
    check 1's expiry conjunct outright.
    """

    def __init__(
        self, api: KernelApi, host: str = API_HOST, port: int = API_PORT
    ) -> None:
        if host not in ("127.0.0.1", "::1"):
            raise ValueError(f"refusing to bind the kernel API to {host!r}; loopback only")
        handler = type("_BoundHandler", (_Handler,), {"api": api})
        # Single-threaded, deliberately. See :class:`KernelApi`'s lock: the
        # store is single-writer and the chain's sequence is allocated
        # read-then-insert, so concurrency here would buy nothing and could
        # produce two entries claiming the same seq.
        self._server = HTTPServer((host, port), handler)
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        return self._server.server_address[:2]

    def start(self) -> "ApiServer":
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="kernel-api", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "ApiServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


def build(service: KernelService) -> KernelApi:
    """Convenience for callers that only want the routing layer."""
    return KernelApi(service)
