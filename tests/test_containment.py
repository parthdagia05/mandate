"""REQ-10: no socket opens to a non-local host during an attack run.

The README's first paragraph promises this and SPEC.md §12 restates it: attacks
run only against our own mock merchants, in our own sandbox. No live endpoints,
no third-party sites, no real money. Track 2 disqualifies offence-capable work
and we hold ourselves to that in the Open Track anyway.

A promise in a README is a promise. This is the check. It patches
``socket.socket.connect`` for the duration of a real attack run and fails on any
address that is not loopback — which also means the test fails if someone later
adds a live PSP call to the simulated path, rather than that call being noticed
on a bill.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

from harness.runner import run_case


class NonLocalConnection(AssertionError):
    """A connection left the machine during a run. That is a containment
    failure, not a flaky test."""


def _is_local(address) -> bool:
    if isinstance(address, str):  # AF_UNIX
        return True
    host = address[0]
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost", "")


@pytest.fixture
def no_outbound_sockets(monkeypatch):
    real_connect = socket.socket.connect

    def guarded(self, address, *args, **kwargs):
        if not _is_local(address):
            raise NonLocalConnection(
                f"a run opened a socket to {address!r}. Attacks run only "
                "against the mock merchants in sim/ (REQ-10)."
            )
        return real_connect(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded)


def test_an_attack_run_opens_no_non_local_socket(no_outbound_sockets):
    record = run_case(
        "benign-01", config="undefended", attack_id="A1-seed-1", model="scripted"
    )
    assert record.attacker_win, "the run has to actually happen for this to mean anything"


def test_a_benign_run_opens_no_non_local_socket(no_outbound_sockets):
    assert run_case("benign-01", config="undefended", model="scripted").task_success


def test_the_guard_can_actually_fire(no_outbound_sockets):
    """Prove the detector detects, the same way the kernel's lints do.

    Closed explicitly rather than left to the collector: the suite runs with
    ``filterwarnings = error``, so a socket finalised during garbage collection
    turns this passing assertion into a failing ResourceWarning.
    """
    with socket.socket() as probe:
        with pytest.raises(NonLocalConnection):
            probe.connect(("93.184.216.34", 80))


def test_the_live_psp_adapter_is_not_reachable_from_a_simulated_run():
    """The Razorpay adapter names a non-local host. It must stay a stub until
    M6 wires it up deliberately, and a stub that returned plausible objects
    would let a smoke test pass against nothing."""
    from sim.psp.razorpay import RazorpayTestMode

    adapter = RazorpayTestMode("rzp_test_x", "secret")
    for call, args in [
        ("create_order", (100, "INR", "ref")),
        ("authorize", ("ord_1", "tok", "idem")),
        ("capture", ("pay_1", 100, "idem")),
        ("poll", ("ref",)),
    ]:
        with pytest.raises(NotImplementedError, match="smoke path"):
            getattr(adapter, call)(*args)
