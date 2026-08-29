"""REQ-10, as a thing that runs rather than a sentence in the README.

The README's first paragraph says attacks reach only our own mocks. This module
is what makes that a check. It patches the socket layer for the duration of a
run and refuses any address that is not loopback, so a live endpoint added to
the simulated path later fails a test rather than turning up on somebody's bill.

**Why it is armed by the harness and not only by a test.** A test that runs one
attack proves containment for one attack. The published numbers come from three
configs over two batches and a benign suite — several hundred runs — and every
one of them is a run in which an attack payload was executed. The guard is
therefore held open across a whole suite, and the suite's metadata records that
it was: ``results.md`` can then say "no non-local socket opened during any of
the runs behind this table" and point at the field that says so.

**The one allowance, and why it is recorded rather than quiet.** The model arm
calls ``api.anthropic.com``; the agent under test is a model, and measuring a
model means reaching one. That call is not an attack reaching the outside world
— the payload never leaves this process except as text inside a prompt — but it
*is* a non-local socket, and a guard that silently permitted it would make the
containment claim untestable exactly where it is hardest.

So the allowance is explicit, narrow and reported. :func:`contained` takes the
hosts it will permit, the harness passes the model endpoint only when a live
model is actually in use, and the resulting record carries
``model_endpoint_allowed``. With the scripted stand-in or a cassette the
allowance is empty and the claim is the strong one: **zero** non-local sockets.

**What it cannot do.** This is a Python-level guard on ``socket``. A subprocess,
a C extension holding its own file descriptor, or ``os.system`` would go around
it. Nothing in this repository does any of those on the run path, and
``tests/test_containment.py`` proves the detector detects — but the honest
statement of the guarantee is "no socket opened through Python's socket module",
and ``results.md`` states it that way rather than as a sandbox.
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any, Iterator

__all__ = [
    "MODEL_ENDPOINT",
    "ContainmentBreach",
    "ContainmentLog",
    "is_local",
    "contained",
]

#: The only non-local host any arm of this project has a reason to reach, and
#: only in the live-model arm. Named here so the allowance is a constant with a
#: docstring rather than a string somebody passed at a call site.
MODEL_ENDPOINT = "api.anthropic.com"


class ContainmentBreach(AssertionError):
    """A run opened a socket to a host that is not ours.

    An ``AssertionError`` rather than a custom hierarchy because that is what
    it is: the containment statement is an assertion the project makes about
    itself, and this is it failing. It is raised *instead of* connecting, so
    the packet never leaves.
    """


def is_local(address: Any) -> bool:
    """Whether an address is loopback, this machine, or a Unix socket.

    Unix sockets (a bare string) are local by construction. A hostname that is
    not an IP literal is compared by name — resolving it here would itself be a
    DNS query leaving the machine, which is the thing being prevented.
    """
    if isinstance(address, (str, bytes)):  # AF_UNIX
        return True
    if not isinstance(address, tuple) or not address:
        return False
    host = address[0]
    if isinstance(host, bytes):
        host = host.decode("utf-8", "replace")
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost", "", "localhost.localdomain")


@dataclass
class ContainmentLog:
    """What the guard saw. Attached to a suite's metadata.

    ``allowed_hosts`` is in the record as well as the counts, because "no
    non-local socket opened" and "no non-local socket opened except the model
    endpoint" are different claims and a reader has to be able to tell which
    one they are being handed.
    """

    allowed_hosts: tuple[str, ...] = ()
    #: Connections to the allowed hosts, if any. Counted, not just permitted.
    allowed: list[str] = field(default_factory=list)
    #: Loopback connections. Counted for completeness: the control port is one.
    local: int = 0
    breaches: list[str] = field(default_factory=list)

    @property
    def enforced(self) -> bool:
        return True

    def as_dict(self) -> dict[str, Any]:
        return {
            "enforced": True,
            "non_local_blocked": len(self.breaches),
            "non_local_allowed": len(self.allowed),
            "local_connections": self.local,
            "allowed_hosts": list(self.allowed_hosts),
            "model_endpoint_allowed": MODEL_ENDPOINT in self.allowed_hosts,
            "breaches": list(self.breaches),
        }


@contextlib.contextmanager
def contained(
    *, allow: tuple[str, ...] = (), raising: bool = True
) -> Iterator[ContainmentLog]:
    """Refuse non-local connections for the duration of the block.

    ``raising=False`` records a breach and lets the connection proceed. That
    mode exists for one purpose — auditing a path nobody has containment
    guarantees about yet — and is never used by the harness, because a
    containment guard that reports a breach after the packet has left is a log,
    not a guard.

    Three entry points are patched, not one. ``socket.socket.connect`` is the
    obvious one; ``connect_ex`` is the same call with a different error
    convention and would otherwise be an unguarded door, and
    ``socket.create_connection`` resolves a hostname *before* it connects, so
    guarding it by name is what keeps a DNS lookup for an attacker-named host
    from happening at all.
    """
    log = ContainmentLog(allowed_hosts=tuple(allow))
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_create = socket.create_connection

    def check(address: Any, where: str) -> bool:
        """True when the connection may proceed."""
        if is_local(address):
            log.local += 1
            return True
        host = address[0] if isinstance(address, tuple) and address else address
        if isinstance(host, bytes):
            host = host.decode("utf-8", "replace")
        if host in log.allowed_hosts:
            log.allowed.append(f"{where} {host}")
            return True
        breach = f"{where} to {address!r}"
        log.breaches.append(breach)
        if raising:
            raise ContainmentBreach(
                f"a run opened a socket: {breach}. Attacks run only against "
                "the mock merchants in sim/ (REQ-10). If this is a deliberate "
                "live call, it has to be named in the allowance so the "
                "containment statement in results.md can say so."
            )
        return True

    def guarded_connect(self: socket.socket, address: Any, *args: Any, **kwargs: Any) -> Any:
        check(address, "connect")
        return real_connect(self, address, *args, **kwargs)

    def guarded_connect_ex(self: socket.socket, address: Any, *args: Any, **kwargs: Any) -> Any:
        check(address, "connect_ex")
        return real_connect_ex(self, address, *args, **kwargs)

    def guarded_create(address: Any, *args: Any, **kwargs: Any) -> Any:
        check(address, "create_connection")
        return real_create(address, *args, **kwargs)

    socket.socket.connect = guarded_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = guarded_connect_ex  # type: ignore[method-assign]
    socket.create_connection = guarded_create  # type: ignore[assignment]
    try:
        yield log
    finally:
        socket.socket.connect = real_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = real_connect_ex  # type: ignore[method-assign]
        socket.create_connection = real_create  # type: ignore[assignment]
