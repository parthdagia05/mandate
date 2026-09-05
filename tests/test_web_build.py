"""The build, and the server serving it. Issue #91.

"A smoke test that builds the frontend and serves it, so a broken build fails a
test rather than the video."

Skipped when ``web/node_modules`` is absent, which is the state of a fresh
clone that has not run ``npm ci``: the Python suite must stay runnable without
node, because ``scripts/reproduce.sh`` is the project's central claim and it
does not have a toolchain. That is the same reason the export writes JSON with
Python and the bundle is not on the reproduce path.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "web"

pytestmark = pytest.mark.skipif(
    not (WEB / "node_modules").is_dir() or shutil.which("npm") is None,
    reason="web/node_modules is absent; run `cd web && npm ci` to include this test",
)


@pytest.fixture(scope="module")
def dist() -> Path:
    """Build the frontend once for this module."""
    done = subprocess.run(
        ["npm", "run", "build"],
        cwd=WEB,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert done.returncode == 0, (
        "the frontend does not build:\n" + done.stdout + done.stderr
    )
    built = WEB / "dist"
    assert (built / "index.html").is_file()
    return built


def test_the_build_emits_relative_asset_urls(dist: Path):
    """``base: './'`` — an absolute ``/assets/...`` is a 404 under ``file://``.

    Issue #90 wants a directory that opens from the filesystem with no server,
    and this is the one build setting that decides whether it does.
    """
    index = (dist / "index.html").read_text(encoding="utf-8")
    assert 'src="./assets/' in index or "src='./assets/" in index
    assert 'src="/assets/' not in index


def test_the_bundle_fetches_nothing_from_the_network(dist: Path):
    """No CDN, no font host, no telemetry — the export is screenshotted offline."""
    import re

    allowed = re.compile(r"https?://(?:127\.0\.0\.1|localhost)")
    for asset in dist.rglob("*"):
        if asset.suffix not in {".js", ".css", ".html"}:
            continue
        text = asset.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"https?://[^\s\"'`)]+", text):
            url = match.group()
            # Source-map comments and license headers name upstream projects;
            # what matters is that nothing is *fetched*.
            if allowed.match(url) or "://www.w3.org/" in url or "://react.dev" in url:
                continue
            assert "fetch" not in text[max(0, match.start() - 60) : match.start()], (
                f"{asset.name} appears to fetch {url}"
            )


def test_the_server_serves_the_build_and_the_api_together(dist: Path, tmp_path: Path):
    """One port, both things — and a client route survives a reload.

    Every filter and every compare pair lives in the URL (#86); that is worth
    nothing if opening the URL directly returns a 404.
    """
    from harness.web.server import WebServer

    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "empty.jsonl").write_text("")

    server = WebServer(runs, dist, port=0).start()
    try:
        base = server.url

        with urllib.request.urlopen(f"{base}/", timeout=10) as response:
            assert response.status == 200
            assert b"<div id=\"root\">" in response.read()

        with urllib.request.urlopen(f"{base}/api/health", timeout=10) as response:
            body = json.loads(response.read())
            assert body["ok"] is True
            assert body["schema"] == "mandate.web.health/1"

        # A deep client route reloads to the app rather than to a 404.
        deep = f"{base}/runs/sha256:{'a' * 64}"
        with urllib.request.urlopen(deep, timeout=10) as response:
            assert response.status == 200
            assert b"<div id=\"root\">" in response.read()

        # A missing asset is a 404, not the index — otherwise a typo'd script
        # tag silently serves HTML and the page fails with a syntax error.
        with pytest.raises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(f"{base}/assets/nope.js", timeout=10)
        assert raised.value.code == 404
        # HTTPError carries an open response body. The suite runs with
        # `filterwarnings = ["error"]`, so a file closed by the garbage
        # collector instead of by us fails the test rather than being ignored.
        raised.value.close()
    finally:
        server.stop()


def test_the_formatter_tests_pass():
    """``npm test`` is part of the gate, not a thing to run by hand."""
    done = subprocess.run(
        ["npm", "test"], cwd=WEB, capture_output=True, text=True, timeout=600
    )
    assert done.returncode == 0, done.stdout + done.stderr
