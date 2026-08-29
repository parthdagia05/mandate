"""The idempotency store on its own: reserve, execute, commit, recover.

Three states rather than two, because **"reserved but outcome unknown" is a
real position**. The tests that matter here are the ones about that third
state: that it is reachable, that it is distinguishable from the other two, and
that nothing in the store can leave a reservation unexamined. Skipping is not a
transition, and a store that could quietly forget a row would make every later
guarantee about "exactly one debit" a guarantee about the happy path.
"""

from __future__ import annotations

import sqlite3

import pytest

from kernel.enums import ActionType, IdempotencyState
from kernel.stores.idempotency import (
    KEY_SEPARATOR,
    RECOVERY_TTL_S,
    IdempotencyStore,
    idempotency_key,
)
from tests.kernel_bench import Bench

CART = "sha256:" + "a" * 64
OTHER_CART = "sha256:" + "b" * 64


def _reserve(store, key, action=ActionType.CAPTURE, **over):
    kwargs = {
        "mandate_id": "im_01ABCDEFGHJKMNPQRSTVWXYZ01",
        "cart_hash": CART,
        "amount_paise": 49900,
        "client_ref": "ref_test",
    }
    kwargs.update(over)
    return store.reserve(key, action, **kwargs)


@pytest.fixture
def store(bench: Bench) -> IdempotencyStore:
    return bench.service.idempotency


# --- the key -------------------------------------------------------------


def test_the_key_is_a_hash_of_mandate_cart_and_action():
    key = idempotency_key("im_1", CART, ActionType.CAPTURE)
    assert key.startswith("sha256:")
    assert key == idempotency_key("im_1", CART, "capture")
    assert key != idempotency_key("im_1", CART, ActionType.AUTHORIZE)
    assert key != idempotency_key("im_2", CART, ActionType.CAPTURE)
    assert key != idempotency_key("im_1", OTHER_CART, ActionType.CAPTURE)


def test_the_separator_stops_two_different_tuples_hashing_alike():
    """``(im_1, cart_2)`` and ``(im_1cart, _2)`` must not be the same key.

    RFC 8785 escapes every control character, so U+001F cannot appear inside
    any field being joined — which is what makes the separator do its job
    rather than merely look like it does.
    """
    assert idempotency_key("im_1", "cart_2", "capture") != idempotency_key(
        "im_1cart", "_2", "capture"
    )
    assert KEY_SEPARATOR not in "im_1cart"


# --- reserve, execute, commit --------------------------------------------


def test_a_fresh_key_is_claimed_and_a_held_one_is_not(store):
    key = idempotency_key("im_1", CART, ActionType.CAPTURE)

    assert _reserve(store, key).outcome == "fresh"
    second = _reserve(store, key)
    assert second.outcome == "in_flight"
    assert second.record.state == IdempotencyState.IN_FLIGHT


def test_the_claim_is_a_unique_insert_and_not_a_read_then_write(store, bench):
    """Two racers must not both see "absent" and both proceed.

    Asserted at the table rather than through the store, because the property
    belongs to the ``PRIMARY KEY``: a check-then-insert in Python would pass
    every single-threaded test and lose every race.
    """
    key = idempotency_key("im_1", CART, ActionType.CAPTURE)
    _reserve(store, key)

    with pytest.raises(sqlite3.IntegrityError):
        bench.conn.execute(
            "INSERT INTO idempotency_record"
            " (key, action, state, reserved_at, mandate_id, cart_hash,"
            "  amount_paise, client_ref)"
            " VALUES (?, 'capture', 'in_flight', '2026-01-01T00:00:00Z', 'im_1',"
            "         ?, 1, 'ref')",
            (key, CART),
        )


def test_commit_moves_the_row_to_terminal_and_keeps_the_result_verbatim(store):
    key = idempotency_key("im_1", CART, ActionType.CAPTURE)
    _reserve(store, key)
    store.commit(key, '{"decision":"allow"}')

    record = store.get(key)
    assert record.state == IdempotencyState.TERMINAL
    assert record.result_json == '{"decision":"allow"}'
    assert record.committed_at is not None
    assert _reserve(store, key).outcome == "terminal"


def test_the_reservation_carries_everything_recovery_will_need(store):
    """The key is a hash and cannot be un-hashed. A scan runs with no request.

    So a row that did not record its own context at reserve time is a row only
    a live caller can ever settle — and the whole point of the scan is that the
    live caller is gone.
    """
    key = idempotency_key("im_1", CART, ActionType.REFUND)
    _reserve(store, key, ActionType.REFUND, payment_id="pay_01ABCDEFGHJKMNPQRSTVWXYZ01")

    record = store.get(key)
    assert record.mandate_id == "im_01ABCDEFGHJKMNPQRSTVWXYZ01"
    assert record.cart_hash == CART
    assert record.amount_paise == 49900
    assert record.client_ref == "ref_test"
    assert record.payment_id == "pay_01ABCDEFGHJKMNPQRSTVWXYZ01"


def test_release_drops_a_reservation_that_never_reached_the_rail(store):
    key = idempotency_key("im_1", CART, ActionType.CAPTURE)
    _reserve(store, key)
    store.release(key)

    assert store.get(key) is None
    assert _reserve(store, key).outcome == "fresh"


# --- the third state ------------------------------------------------------


def test_past_the_ttl_a_held_key_reports_recovering_rather_than_in_flight(
    store, bench
):
    key = idempotency_key("im_1", CART, ActionType.CAPTURE)
    _reserve(store, key)

    assert _reserve(store, key).outcome == "in_flight"
    bench.world.clock.advance(RECOVERY_TTL_S)
    assert _reserve(store, key).outcome == "recovering"


def test_a_recovering_row_stays_recovering_however_long_it_waits(store, bench):
    """Marked once, and never quietly demoted back to in_flight — a row that
    could go backwards is a row a second caller could treat as fresh."""
    key = idempotency_key("im_1", CART, ActionType.CAPTURE)
    _reserve(store, key)
    store.mark_recovering(key)

    assert _reserve(store, key).outcome == "recovering"
    assert store.get(key).state == IdempotencyState.RECOVERING


# --- what the scan is allowed to look at ----------------------------------


def test_a_reservation_inside_the_ttl_is_not_offered_to_the_scan(store, bench):
    """Its owner may still be mid-call. Polling underneath a live request is
    how a scan and a request race to settle the same key."""
    _reserve(store, idempotency_key("im_1", CART, ActionType.CAPTURE))
    assert store.open_reservations() == []

    bench.world.clock.advance(RECOVERY_TTL_S)
    assert len(store.open_reservations()) == 1


def test_a_recovering_row_is_offered_at_every_scan(store, bench):
    """Skipping is never a transition. A row that dropped out of the scan on
    its first failed resolution would be a debit nothing was still looking for.
    """
    key = idempotency_key("im_1", CART, ActionType.CAPTURE)
    _reserve(store, key)
    store.mark_recovering(key)

    assert [r.key for r in store.open_reservations()] == [key]
    bench.world.clock.advance(RECOVERY_TTL_S * 10)
    assert [r.key for r in store.open_reservations()] == [key]


def test_a_terminal_row_is_never_offered_to_the_scan(store, bench):
    key = idempotency_key("im_1", CART, ActionType.CAPTURE)
    _reserve(store, key)
    store.commit(key, "{}")
    bench.world.clock.advance(RECOVERY_TTL_S * 10)

    assert store.open_reservations() == []


def test_the_scan_reads_oldest_first(store, bench):
    """So a run of reservations is resolved in the order they were taken,
    rather than in whatever order the table happens to return."""
    first = idempotency_key("im_1", CART, ActionType.AUTHORIZE)
    _reserve(store, first, ActionType.AUTHORIZE)
    bench.world.clock.advance(5)
    second = idempotency_key("im_1", CART, ActionType.CAPTURE)
    _reserve(store, second)
    bench.world.clock.advance(RECOVERY_TTL_S)

    assert [r.key for r in store.open_reservations()] == [first, second]


def test_unsettled_counts_only_rows_the_scan_has_not_claimed(store):
    """The settle loop reads this, so it must fall to zero. A count that
    included ``recovering`` rows would hold a run open forever the first time
    the rail could not answer."""
    key = idempotency_key("im_1", CART, ActionType.CAPTURE)
    _reserve(store, key)
    assert store.unsettled() == 1

    store.mark_recovering(key)
    assert store.unsettled() == 0
