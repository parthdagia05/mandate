"""D-03 and D-04: nothing in the kernel reads a wall clock or an unseeded RNG.

Both are lints, and both fail the build. The clock is owned by the kernel
because an agent-supplied clock would defeat check 1's expiry test by lying
about the hour; that ownership is worth nothing if some other module quietly
calls ``datetime.now()`` anyway. Same for randomness: REQ-3 says the same seed
produces byte-identical output, and one ``os.urandom`` breaks it everywhere.
"""

from __future__ import annotations

import ast

import pytest

from kernel.clock import Clock, from_rfc3339, to_rfc3339
from kernel.ids import IdFactory
from kernel.rng import RunRandom
from tests._lint import called_names, imported_modules, kernel_files, root_module

#: Reading the time of day. ``perf_counter`` is in here too: it is a duration,
#: not a date, but a duration in an audit payload would break D-01 just as
#: surely. M6's latency column will have to add a named exemption here, so
#: that choice is visible in a diff rather than assumed.
WALL_CLOCK_CALLS = frozenset(
    {
        "datetime.now",
        "datetime.utcnow",
        "datetime.datetime.now",
        "datetime.datetime.utcnow",
        "datetime.today",
        "datetime.datetime.today",
        "date.today",
        "datetime.date.today",
        "time.time",
        "time.time_ns",
        "time.monotonic",
        "time.monotonic_ns",
        "time.perf_counter",
        "time.perf_counter_ns",
        "time.localtime",
        "time.gmtime",
    }
)

UNSEEDED_RANDOM_CALLS = frozenset(
    {"os.urandom", "uuid.uuid1", "uuid.uuid4", "random.seed", "secrets.token_bytes"}
)

UNSEEDED_RANDOM_MODULES = frozenset({"random", "secrets"})

#: ``rng.py`` is where the one seed lives; it is allowed to import ``random``
#: precisely so that nothing else has to.
RANDOM_MODULE_ALLOWED_IN = frozenset({"kernel/rng.py"})

#: The one named exemption, anticipated by the comment above ``WALL_CLOCK_CALLS``
#: and taken in M3 for SPEC.md §07's ``latency_us``. It is deliberately narrow:
#: one file, one call, and a second test below pins the rule that makes it safe.
#:
#: A measured duration may enter a *response*. It may never enter an audit
#: payload, because two runs of one seed produce byte-identical chains and a
#: microsecond count is the fastest way to lose that.
DURATION_EXEMPT = {"kernel/latency.py": frozenset({"time.perf_counter_ns"})}


def _relative(path):
    from tests._lint import REPO_ROOT

    return path.relative_to(REPO_ROOT).as_posix()


@pytest.mark.parametrize("path", kernel_files(), ids=lambda p: p.name)
def test_no_wall_clock_read(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    allowed = DURATION_EXEMPT.get(_relative(path), frozenset())
    offenders = [
        f"{name} at line {line}"
        for name, line in called_names(tree)
        if name in WALL_CLOCK_CALLS and name not in allowed
    ]
    assert not offenders, (
        f"{_relative(path)} reads a wall clock: {offenders}. Time comes from "
        "kernel.clock.Clock, which only moves at the control port's barrier."
    )


def test_the_duration_exemption_is_only_where_it_says():
    """The exemption is a file, not a habit.

    ``kernel/latency.py`` may call ``perf_counter_ns``. Nothing else may, and
    nothing else may call any other wall-clock function either — including
    ``latency.py`` itself, which is exempted for exactly one name.
    """
    import ast as _ast

    from tests._lint import REPO_ROOT

    for rel, allowed in DURATION_EXEMPT.items():
        path = REPO_ROOT / rel
        assert path.exists(), f"{rel} is exempted but does not exist"
        used = {
            name
            for name, _ in called_names(_ast.parse(path.read_text()))
            if name in WALL_CLOCK_CALLS
        }
        assert used <= allowed, f"{rel} uses more than its exemption: {used - allowed}"


@pytest.mark.parametrize("path", kernel_files(), ids=lambda p: p.name)
def test_no_unseeded_randomness(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    rel = _relative(path)

    offenders = [
        f"{name} at line {line}"
        for name, line in called_names(tree)
        if name in UNSEEDED_RANDOM_CALLS
    ]
    if rel not in RANDOM_MODULE_ALLOWED_IN:
        offenders += [
            f"imports {name}"
            for name in sorted(imported_modules(tree))
            if root_module(name) in UNSEEDED_RANDOM_MODULES
        ]

    assert not offenders, (
        f"{rel} reaches for randomness outside the run seed: {offenders}. "
        "Every ULID, nonce and idempotency key derives from kernel.rng (REQ-3)."
    )


def test_lints_can_fire(tmp_path):
    """Prove both detectors detect, the same way S-02 proves the oracles do."""
    clock_offender = ast.parse("import datetime\nx = datetime.datetime.now()\n")
    assert any(
        name in WALL_CLOCK_CALLS for name, _ in called_names(clock_offender)
    )

    rng_offender = ast.parse("import os\nx = os.urandom(16)\n")
    assert any(
        name in UNSEEDED_RANDOM_CALLS for name, _ in called_names(rng_offender)
    )


def test_same_seed_same_identifiers():
    """REQ-3 at its smallest: identifiers are a function of seed and clock."""
    def mint():
        factory = IdFactory(Clock(), RunRandom("seed-alpha"))
        return [
            factory.intent_id(),
            factory.cart_id(),
            factory.payment_id(),
            factory.nonce(),
        ]

    assert mint() == mint()


def test_different_seed_different_identifiers():
    first = IdFactory(Clock(), RunRandom("seed-alpha")).intent_id()
    second = IdFactory(Clock(), RunRandom("seed-beta")).intent_id()
    assert first != second


def test_named_streams_do_not_shift_each_other():
    """Adding a call in one place must not renumber every id in the run."""
    rng = RunRandom("seed-alpha")
    nonce_first = rng.bytes("nonce", 16)

    rng = RunRandom("seed-alpha")
    rng.bytes("ulid:intent", 10)
    rng.bytes("ulid:cart", 10)
    assert rng.bytes("nonce", 16) == nonce_first


def test_clock_only_moves_when_pushed():
    clock = Clock()
    before = clock.now()
    assert clock.now() == before
    clock.advance(60)
    assert (clock.now() - before).total_seconds() == 60


def test_clock_does_not_run_backwards():
    with pytest.raises(ValueError):
        Clock().advance(-1)


def test_timestamp_form_round_trips():
    clock = Clock()
    text = clock.now_rfc3339()
    assert text.endswith("Z") and len(text) == 20
    assert to_rfc3339(from_rfc3339(text)) == text


def test_timestamp_form_is_the_only_one_accepted():
    for bad in [
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:00.500Z",
        "2026-01-01 00:00:00Z",
        "2026-01-01T00:00:00",
    ]:
        with pytest.raises(ValueError):
            from_rfc3339(bad)
