"""The control port, ``127.0.0.1:8081``. Test mode only, SPEC.md §07.

Three endpoints, and the agent process is never given any of them:

===============================  =========================================
``POST /control/clock/advance``  Advance N seconds. **Synchronous barrier.**
``POST /control/fault``          Arm a fault.
``POST /control/reset``          Fresh seeded state.
===============================  =========================================

**Why a socket at all**, when everything in a single-process run could call
:class:`~sim.world.World` directly. Because D-01 — byte-identical chains across
three processes — is a claim about processes, and a claim about processes needs
a boundary that processes actually cross. :class:`ControlPlane` is the whole of
the behaviour and :class:`ControlServer` is a thin HTTP shell over it, so the
in-process path and the socket path cannot drift into disagreeing.

**Why the barrier is synchronous.** ``/control/clock/advance`` does not return
until every webhook now due has been delivered and every consequence of those
deliveries has settled. If it returned early, the caller's next request would
race the scheduler and ordering would depend on which won — the exact
scheduler luck §15 rules out.

Three guards, all of them refusals rather than warnings:

* bound to ``127.0.0.1`` and nothing else, so REQ-10's "no non-local socket"
  holds by construction rather than by test;
* refuses to start unless ``KERNEL_MODE=test``, because a control port that
  can move the clock is a control port that can expire a mandate;
* refuses a request whose peer is not loopback, in case something in front of
  it ever forwards one.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from sim.faults import Fault
from sim.world import World

__all__ = ["CONTROL_HOST", "CONTROL_PORT", "ControlPlane", "ControlServer", "NotTestMode"]

CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 8081

#: Largest body the port will read. The control port takes three small JSON
#: objects; anything larger is a mistake or a probe, and reading it would be
#: the one unbounded allocation in the process.
MAX_BODY_BYTES = 8192


class NotTestMode(RuntimeError):
    """``KERNEL_MODE`` is not ``test``. The port does not exist outside it."""


def require_test_mode() -> None:
    mode = os.environ.get("KERNEL_MODE", "")
    if mode != "test":
        raise NotTestMode(
            f"KERNEL_MODE is {mode!r}, not 'test'. The control port can move "
            "the clock, and a clock an attacker can move defeats check 1."
        )


class ControlPlane:
    """The three operations, with no HTTP anywhere near them.

    Every handler returns a JSON-able dict and takes a JSON-able dict, so the
    HTTP shell has no decisions of its own to get wrong.
    """

    def __init__(self, world: World) -> None:
        self.world = world
        #: One lock for the whole plane. The barrier's contract is that
        #: nothing else touches the world while it settles, and two concurrent
        #: advances would interleave two drains.
        self._lock = threading.Lock()

    def clock_advance(self, body: dict[str, Any]) -> dict[str, Any]:
        seconds = body.get("seconds", 1)
        if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 0:
            raise ValueError("seconds must be a non-negative whole number")
        with self._lock:
            return self.world.advance(seconds)

    def fault(self, body: dict[str, Any]) -> dict[str, Any]:
        name = body.get("fault")
        try:
            fault = Fault(name)
        except ValueError:
            raise ValueError(
                f"{name!r} is not a fault; known: {[f.value for f in Fault]}"
            ) from None
        kwargs: dict[str, Any] = {}
        for key in ("count", "duration_s", "target"):
            if key in body:
                kwargs[key] = body[key]
        with self._lock:
            return self.world.arm(fault, **kwargs)

    def reset(self, body: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            return self.world.reset(body.get("seed"))

    ROUTES = {
        "/control/clock/advance": "clock_advance",
        "/control/fault": "fault",
        "/control/reset": "reset",
    }

    def dispatch(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        handler = self.ROUTES.get(path)
        if handler is None:
            raise KeyError(path)
        return getattr(self, handler)(body)


class _Handler(BaseHTTPRequestHandler):
    plane: ControlPlane

    #: Silence the default stderr access log. The event log is the record of
    #: what happened; a second, differently-ordered one is noise.
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _reply(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's name
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            self._reply(403, {"error": "control port is loopback only"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            self._reply(413, {"error": f"body over {MAX_BODY_BYTES} bytes"})
            return
        raw = self.rfile.read(length) if length else b"{}"

        try:
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
            self._reply(200, self.plane.dispatch(self.path, body))
        except KeyError:
            self._reply(404, {"error": f"no control endpoint {self.path}"})
        except (ValueError, json.JSONDecodeError) as exc:
            self._reply(400, {"error": str(exc)})


class ControlServer:
    """The socket. A thin shell; :class:`ControlPlane` holds the behaviour."""

    def __init__(
        self, plane: ControlPlane, host: str = CONTROL_HOST, port: int = CONTROL_PORT
    ) -> None:
        require_test_mode()
        if host not in ("127.0.0.1", "::1"):
            raise ValueError(
                f"refusing to bind the control port to {host!r}; loopback only"
            )
        handler = type("_BoundHandler", (_Handler,), {"plane": plane})
        self._server = ThreadingHTTPServer((host, port), handler)
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        return self._server.server_address[:2]

    def start(self) -> "ControlServer":
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="control-port", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "ControlServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()
