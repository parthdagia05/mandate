"""``mk web``: the built assets and the artifact API, on one loopback port.

``http.server``, for the reason :mod:`harness.web.api` gives for not being
FastAPI. Issue #82 says the repo's Python dependency list does not grow, and a
viewer is not worth Starlette.

**Loopback by default.** The artifact API is read-only, but it reads a whole
research corpus off local disk and it proxies to a payment kernel; neither
belongs on a LAN because somebody typed a flag by accident. ``--host`` exists
and is not defaulted to anything else.

**The asset root and the runs root are separate trees and are checked
separately.** A request for an asset can never reach ``runs/``, and a request
for an artifact goes through :class:`~harness.web.api.WebApi`, which confines
paths itself. The static handler resolves and confines too, rather than
trusting :meth:`SimpleHTTPRequestHandler.translate_path`, because that method's
job is to be convenient and this one's job is to be narrow.

**Unbuilt is a message, not a 404.** A frontend nobody can build is a frontend
nobody will look at (#82), so when ``web/dist`` is missing the server says which
directory it wanted and which command makes it, rather than serving an empty
directory listing.
"""

from __future__ import annotations

import json
import mimetypes
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from harness.web import DEFAULT_HOST, DEFAULT_PORT
from harness.web.api import KERNEL_URL, Outcome, WebApi
from harness.web.index import PathOutsideRoot

__all__ = ["WebServer", "serve", "build_handler", "MAX_BODY_BYTES"]

#: Largest body the demo route will read. Its schema is a task id and a case id.
MAX_BODY_BYTES = 64 * 1024

#: Files served without a build. Everything else 404s.
_INDEX = "index.html"

_UNBUILT = """<!doctype html>
<meta charset="utf-8">
<title>Mandate — frontend not built</title>
<style>
  body {{ font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
          margin: 0; padding: 32px; color: #1a1a1a; background: #fafaf8; }}
  h1 {{ font-size: 16px; margin: 0 0 16px; }}
  code {{ background: #efefec; padding: 1px 4px; border: 1px solid #dcdcd6; }}
  pre {{ background: #efefec; border: 1px solid #dcdcd6; padding: 12px;
         overflow-x: auto; }}
  a {{ color: #0b5; }}
</style>
<h1>The frontend is not built.</h1>
<p>This server is running and the artifact API is answering. The assets are not
here yet — it wanted <code>{dist}</code>.</p>
<pre>cd web &amp;&amp; npm ci &amp;&amp; npm run build</pre>
<p>The API is up regardless:</p>
<ul>
  <li><a href="/api/health">/api/health</a></li>
  <li><a href="/api/matrices">/api/matrices</a></li>
  <li><a href="/api/runs?limit=5">/api/runs?limit=5</a></li>
</ul>
"""


def build_handler(api: WebApi, dist: Path) -> type[BaseHTTPRequestHandler]:
    """A handler bound to one API and one asset directory."""

    dist = dist.resolve()

    class Handler(BaseHTTPRequestHandler):
        server_version = "mandate-web"
        #: HTTP/1.0. Keep-alive buys nothing here and a half-closed
        #: connection on a single-threaded server is a hang on camera.
        protocol_version = "HTTP/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:
            # One line per request, on stderr, without the default's date
            # noise. Silence would hide a 403 nobody expected.
            print(f"  {self.address_string()} {fmt % args}", flush=True)

        # -- responses ----------------------------------------------------

        def _json(self, outcome: Outcome) -> None:
            raw = json.dumps(outcome.body, ensure_ascii=False).encode("utf-8")
            self.send_response(outcome.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            # The artifact API is read-only and same-origin. No CORS header:
            # a viewer that any page could read is a corpus any page could
            # read, and nothing needs that.
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _bytes(self, status: int, raw: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        # -- routing ------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's name
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            if path.startswith("/api/"):
                try:
                    self._json(api.get(path, parse_qs(parsed.query)))
                except KeyError:
                    self._json(Outcome(404, {"error": "no such endpoint"}))
                except PathOutsideRoot:
                    self._json(
                        Outcome(403, {"error": "path is outside the runs directory"})
                    )
                return
            self._static(path)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            if not path.startswith("/api/"):
                self._json(Outcome(404, {"error": "no such endpoint"}))
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                self._json(Outcome(413, {"error": "body too large"}))
                return
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._json(Outcome(422, {"error": "not JSON"}))
                return
            if not isinstance(body, dict):
                self._json(Outcome(422, {"error": "body must be a JSON object"}))
                return
            try:
                self._json(api.post(path, body))
            except KeyError:
                self._json(Outcome(404, {"error": "no such endpoint"}))

        # -- assets -------------------------------------------------------

        def _static(self, path: str) -> None:
            """Serve one built asset, or the SPA's index for a client route.

            An unknown path that does not look like a file falls through to
            ``index.html`` so that ``/runs/sha256:…`` survives a page reload —
            every filter and every compare pair lives in the URL (#86), which
            is worth nothing if the URL cannot be opened directly.
            """
            if not dist.is_dir():
                self._bytes(
                    503,
                    _UNBUILT.format(dist=dist).encode("utf-8"),
                    "text/html; charset=utf-8",
                )
                return

            relative = path.lstrip("/") or _INDEX
            target = self._resolve(relative)
            if target is None:
                self._bytes(403, b"forbidden\n", "text/plain; charset=utf-8")
                return
            if target.is_dir():
                target = target / _INDEX
            if not target.is_file():
                # A client-side route, not a missing asset — unless it has an
                # extension, in which case it really is missing.
                if Path(relative).suffix:
                    self._bytes(404, b"not found\n", "text/plain; charset=utf-8")
                    return
                target = dist / _INDEX
                if not target.is_file():
                    self._bytes(404, b"not found\n", "text/plain; charset=utf-8")
                    return

            guessed, _ = mimetypes.guess_type(target.name)
            try:
                raw = target.read_bytes()
            except OSError:
                self._bytes(404, b"not found\n", "text/plain; charset=utf-8")
                return
            self._bytes(200, raw, guessed or "application/octet-stream")

        def _resolve(self, relative: str) -> Path | None:
            """Confine an asset request to the built tree.

            Resolved, then required to be under ``dist``. Checking before
            resolving would let a symlink in the build output read the runs
            directory, which is the one tree this handler must not reach.
            """
            candidate = (dist / relative).resolve()
            if candidate != dist and dist not in candidate.parents:
                return None
            return candidate

    return Handler


class _Server(socketserver.ThreadingMixIn, HTTPServer):
    """Threaded, so a slow verifier subprocess does not block the page.

    ``daemon_threads`` so Ctrl-C ends the process rather than waiting on a
    browser's idle connection.
    """

    daemon_threads = True
    allow_reuse_address = True


class WebServer:
    """The server, startable in a thread so tests can drive it over a socket."""

    def __init__(
        self,
        runs_root: Path,
        dist: Path,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        kernel_url: str = KERNEL_URL,
    ) -> None:
        self.api = WebApi(runs_root, kernel_url=kernel_url)
        self.dist = Path(dist)
        self._httpd = _Server((host, port), build_handler(self.api, self.dist))
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        return self._httpd.server_address[0], self._httpd.server_address[1]

    @property
    def url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}"

    def start(self) -> "WebServer":
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="mandate-web", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def __enter__(self) -> "WebServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


def serve(
    runs_root: Path,
    dist: Path,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    kernel_url: str = KERNEL_URL,
) -> int:
    """Run until interrupted. Returns a process exit code."""
    server = WebServer(
        runs_root, dist, host=host, port=port, kernel_url=kernel_url
    )
    index = server.api.index

    def say(line: str) -> None:
        # `flush=True` on every line: stdout is block-buffered when it is not a
        # terminal, so a server that never returns would print its address only
        # once the buffer filled — which is to say never. The one line a user
        # needs is the URL, and it has to arrive before the process blocks.
        print(line, flush=True)

    say(f"mk web: {server.url}")
    say(f"  runs   {server.api.runs_root}  ({len(index.entries)} runs in {len(index.suites)} suites)")
    say(f"  assets {server.dist}" + ("" if server.dist.is_dir() else "  (not built — cd web && npm ci && npm run build)"))
    say(f"  kernel {kernel_url}  ({'up' if server.api._kernel_reachable() else 'not reachable'})")
    if index.skipped:
        say(f"  {len(index.skipped)} line(s) skipped while indexing:")
        for note in index.skipped[:5]:
            say(f"    {note}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        say("\nmk web: stopped")
    finally:
        server.stop()
    return 0
