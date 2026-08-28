"""The control port, SPEC.md §07 and §15.

Two things are being pinned. That the port refuses what it must refuse — it can
move the clock, and a clock an attacker can move defeats check 1's expiry test.
And that the socket path and the in-process path do the same thing, because
D-01 is a claim about processes and a claim about processes needs a boundary
that processes actually cross.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest

from sim.control import CONTROL_HOST, ControlPlane, ControlServer, NotTestMode
from sim.world import World


@pytest.fixture
def test_mode(monkeypatch):
    monkeypatch.setenv("KERNEL_MODE", "test")


@pytest.fixture
def server(test_mode):
    # Port 0: the OS picks a free one. Binding 8081 in a test would make the
    # suite fail when a demo is running, which is a flaky test, not a finding.
    with ControlServer(ControlPlane(World(seed="control")), port=0) as running:
        yield running


def _post(server, path, body):
    host, port = server.address
    request = urllib.request.Request(
        f"http://{host}:{port}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, json.loads(response.read())


def test_it_will_not_start_outside_test_mode(monkeypatch):
    monkeypatch.delenv("KERNEL_MODE", raising=False)
    with pytest.raises(NotTestMode):
        ControlServer(ControlPlane(World()), port=0)


def test_it_will_not_bind_anywhere_but_loopback(test_mode):
    """REQ-10 by construction rather than by test."""
    with pytest.raises(ValueError, match="loopback only"):
        ControlServer(ControlPlane(World()), host="0.0.0.0", port=0)


def test_it_binds_loopback(server):
    assert server.address[0] == CONTROL_HOST


def test_clock_advance_settles_before_it_returns(server):
    status, body = _post(server, "/control/clock/advance", {"seconds": 5})
    assert status == 200
    assert body["now"] == "2026-01-01T00:00:05Z"
    assert body["delivered"] == []
    assert body["log_head"].startswith("sha256:")


def test_fault_arming_round_trips(server):
    _, body = _post(server, "/control/fault", {"fault": "psp_timeout"})
    assert body["armed"] == [
        {
            "fault": "psp_timeout",
            "site": "psp.call",
            "remaining": 1,
            "duration_s": 0,
            "target": None,
        }
    ]


def test_reset_returns_a_fresh_seeded_state(server):
    _post(server, "/control/clock/advance", {"seconds": 30})
    _, body = _post(server, "/control/reset", {"seed": "9"})
    assert body == {"seed": "9", "now": "2026-01-01T00:00:00Z"}


def test_unknown_endpoints_and_bad_bodies_are_refused(server):
    for path, body, expected in [
        ("/control/nope", {}, 404),
        ("/control/fault", {"fault": "nonsense"}, 400),
        ("/control/clock/advance", {"seconds": -1}, 400),
        ("/control/clock/advance", {"seconds": "5"}, 400),
    ]:
        with pytest.raises(urllib.error.HTTPError) as caught:
            _post(server, path, body)
        # An HTTPError holds an open spooled file. The suite runs with
        # ``filterwarnings = error``, so leaving it to the garbage collector
        # turns a passing assertion into a failing ResourceWarning.
        caught.value.close()
        assert caught.value.code == expected


def test_the_socket_and_the_in_process_path_agree(server, test_mode):
    """One implementation, two doors. Two implementations would drift."""
    direct = ControlPlane(World(seed="control"))
    _, over_socket = _post(server, "/control/clock/advance", {"seconds": 4})
    in_process = direct.clock_advance({"seconds": 4})
    assert over_socket == in_process
