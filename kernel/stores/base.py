"""The one place a store failure becomes a denial.

Every read and every write in :mod:`kernel.stores` goes through
:meth:`Store._guarded`, which does two things and nothing else:

1. asks the **guard** whether this store is reachable, and
2. turns any ``sqlite3.Error`` into
   :class:`~kernel.stores.db.StoreUnavailable`.

Both matter for REQ-5. Without (2) a disk error surfaces as a 500, and a 500 is
not a decision — it is the kernel declining to say what it did, which is the
one thing the audit chain exists to prevent. With it, every failure path in the
kernel arrives at the same fail-closed branch in :mod:`kernel.service`, and
"an unreadable budget is not an empty budget" is a property of one function
rather than a habit spread over three files.

**The guard is a seam, not a feature.** The failure suite needs to make a named
store unavailable at a chosen moment, which no real disk will do on request.
The guard is a callable the harness supplies — wired to the simulator's fault
injector — and the kernel neither knows nor can find out what is behind it.
That is why it takes the store's name: one unavailable store must not make
every store unavailable, or the test could not tell which store the check
actually needed.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Callable

from kernel.stores.db import StoreUnavailable

__all__ = ["StoreGuard", "no_guard", "Store"]

#: ``(store_name, operation) -> None``. Raises to make a store unavailable.
StoreGuard = Callable[[str, str], None]


def no_guard(_store: str, _operation: str) -> None:
    """The default: every store is reachable. Production has no other guard."""


class Store:
    """Base for the three stores. Holds the connection and the guard."""

    #: Overridden by each subclass; the name the guard and the audit see.
    name = "store"

    def __init__(self, conn: sqlite3.Connection, guard: StoreGuard = no_guard) -> None:
        self._conn = conn
        self._guard = guard

    def _guarded(self, operation: str, fn: Callable[[], Any]) -> Any:
        self._guard(self.name, operation)
        try:
            return fn()
        except sqlite3.Error as exc:
            raise StoreUnavailable(f"{self.name}.{operation}: {exc}") from exc
