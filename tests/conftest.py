"""Session-wide checks that are attributable.

There is one hook here, and it exists because the mechanism it replaces was not.

``filterwarnings = ["error"]`` turns an unclosed database into a failure — but a
``ResourceWarning`` for one is raised during **garbage collection**, so pytest attributes
it to whichever test was running when the collector happened to run. Across four CI runs
a single leak in the SQLite adapter was reported against a witness test, a kernel action
test, a queue test and an authority test. None of them touched a database.

So the signal was real and the attribution was noise, and it cost a CI round trip per
guess. This asks the question directly instead: at the end of the session, is any
connection **this package owns** still open? That is attributable, deterministic, and
true on every interpreter — where the warning only exists on Python 3.13 and later, which
is why a twenty-four-handle leak sat in an adapter with thirty-six tests of its own.
"""

from __future__ import annotations

import gc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail the run if a store left a connection open, and say which store.

    Only connections held by an :class:`~attest.adapters.sqlite.SQLiteStore` are checked.
    Third-party connections — coverage.py's, Django's own test database — are somebody
    else's to close, and failing on them would put this check back where the warning was:
    firing on things the author of the run cannot fix.
    """
    import sqlite3

    from attest.adapters.sqlite import SQLiteStore

    gc.collect()
    leaked: list[str] = []
    for store in [obj for obj in gc.get_objects() if isinstance(obj, SQLiteStore)]:
        for owner, connection in list(store._connections):
            try:
                connection.execute("SELECT 1")
            except sqlite3.ProgrammingError:
                continue  # closed, which is the point
            leaked.append(f"{store!r} holds an open connection from thread {owner.name!r}")

    if leaked:
        session.exitstatus = 1
        print("\nOPEN DATABASE CONNECTIONS AT SESSION END:")
        for line in leaked:
            print(f"  - {line}")
        print(
            "  A store that is dropped or closed must release what it opened. This is "
            "the check that names the owner; the ResourceWarning names a random test."
        )
