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


@pytest.mark.parametrize("attack_class", [f"A{n}" for n in range(1, 8)])
def test_every_class_runs_inside_the_sandbox(no_outbound_sockets, attack_class):
    """One reference case per class, because the classes reach different code.

    A5 and A6 make extra money calls, A4 opens a standing instruction and A7
    raises a credit. Testing containment on A1 alone would leave the paths that
    were added last untested — which is exactly where a live call would be
    added by accident.
    """
    from harness.selftest import SELFTEST_CASES

    record = run_case(
        config="undefended", attack_id=SELFTEST_CASES[attack_class], model="scripted"
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


# ---------------------------------------------------------------------------
# The guard the harness itself arms (issue #60)
#
# The tests above patch the socket layer *around* a run from outside. These
# test the guard the runner arms on every case, which is what lets results.md
# say "no non-local socket opened during any of the runs behind this table" and
# point at a field rather than at a promise.
# ---------------------------------------------------------------------------


def test_the_runner_arms_containment_on_every_run():
    from harness.runner import run_case

    record = run_case("benign-01", config="undefended", model="scripted")
    assert record.containment["enforced"] is True
    assert record.containment["breaches"] == []
    assert record.containment["non_local_blocked"] == 0


def test_the_stand_in_needs_no_allowance_so_the_claim_is_the_strong_one():
    """Zero non-local sockets, not "zero except one".

    The allowance exists for the live-model arm and is empty everywhere else.
    A guard that silently permitted the model endpoint in every arm would make
    the containment claim untestable exactly where it is hardest.
    """
    from harness.runner import run_case

    for config in ("undefended", "model-only", "agent-guard", "kernel"):
        record = run_case(
            config=config, attack_id="A1-seed-1", model="scripted"
        )
        assert record.containment["allowed_hosts"] == [], config
        assert record.containment["model_endpoint_allowed"] is False, config


def test_the_allowance_is_narrow_and_recorded_rather_than_quiet():
    """It permits the named host and nothing else, and says so in the log."""
    from harness.containment import MODEL_ENDPOINT, ContainmentBreach, contained

    with contained(allow=(MODEL_ENDPOINT,)) as log:
        with socket.socket() as probe:
            with pytest.raises(ContainmentBreach):
                probe.connect(("93.184.216.34", 443))
    assert log.as_dict()["model_endpoint_allowed"] is True
    assert log.as_dict()["non_local_blocked"] == 1


def test_the_guard_covers_the_other_two_doors_as_well():
    """``connect_ex`` is the same call with a different error convention, and
    ``create_connection`` resolves a hostname *before* it connects — so
    guarding it by name is what keeps a DNS lookup for an attacker-named host
    from happening at all."""
    from harness.containment import ContainmentBreach, contained

    with contained():
        with socket.socket() as probe:
            with pytest.raises(ContainmentBreach):
                probe.connect_ex(("93.184.216.34", 80))
        with pytest.raises(ContainmentBreach):
            socket.create_connection(("example.invalid", 80))


def test_a_unix_socket_and_loopback_are_local():
    from harness.containment import is_local

    assert is_local("/tmp/some.sock")
    assert is_local(("127.0.0.1", 8080))
    assert is_local(("::1", 8080))
    assert is_local(("localhost", 8080))
    assert not is_local(("93.184.216.34", 80))
    assert not is_local(("example.com", 443))


def test_the_guard_is_removed_again_afterwards():
    """A test that left the patch in place would make every later test pass for
    the wrong reason."""
    from harness.containment import contained

    before = socket.socket.connect
    with contained():
        assert socket.socket.connect is not before
    assert socket.socket.connect is before


def test_a_whole_suite_reports_containment_on_every_line(tmp_path):
    from harness.suite import run_suite, select

    result = run_suite(
        select("batch_a", attack_class="A1")[:3],
        dataset="batch_a",
        config="undefended",
        model="scripted",
        out=tmp_path / "suite.jsonl",
    )
    assert result.records
    for record in result.records:
        assert record.containment["enforced"] is True
        assert record.containment["breaches"] == []
