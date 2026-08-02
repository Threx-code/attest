"""Running a host's Django test suite against the append-only tables.

The triggers below the application are the point: "we only ever INSERT" is a convention, and
conventions decay. They also break Django's own test machinery, and every adopter meets it on
the first run rather than eventually.

`TransactionTestCase` truncates tables between tests, and truncation is `DELETE`. The trigger
refuses, so every such class fails at teardown the moment an attest row exists - which, once
the engine is wired, is every test that executes a run. The failure surfaces as an
`IntegrityError` in teardown with no obvious connection to what the test was doing, and the
natural next move is to stop installing the app.

So the escape hatch ships here, named, rather than being rediscovered as a workaround in
every adopter's `conftest.py`.

**This is for a test database and nothing else.** The triggers are a production control and
their own tests live in this package, against a database that keeps them. What a host needs
from a test database is that it can be reset.

    # conftest.py
    @pytest.fixture(scope="session", autouse=True)
    def _attest_test_db(django_db_setup, django_db_blocker):
        with django_db_blocker.unblock():
            AppendOnlyTriggers.drop()
"""

from __future__ import annotations

from django.db import connection

__all__ = ["AppendOnlyTriggers"]


class AppendOnlyTriggers:
    """Drops the append-only and immutability triggers from the current database."""

    #: Every trigger this package installs is prefixed. Matching on the prefix rather than
    #: on a hard-coded list means a trigger added in a later migration is covered without
    #: this file having to learn about it - the same argument `check_reachability` makes for
    #: deriving its control list from the ports rather than restating it.
    PREFIX = "attest_"

    @classmethod
    def drop(cls) -> tuple[str, ...]:
        """Drop them, and return what was dropped. **Refuses outside a test database.**

        The guard is not decoration. A helper that silently disabled an integrity control in
        production would be the most dangerous thing this package ships, and "it is only
        called from conftest" is exactly the assumption that stops being true.
        """
        cls._assert_test_database()
        names = cls._names()
        with connection.cursor() as cursor:
            for name, table in names:
                if connection.vendor == "postgresql":
                    cursor.execute(f'DROP TRIGGER IF EXISTS "{name}" ON "{table}"')
                else:
                    cursor.execute(f'DROP TRIGGER IF EXISTS "{name}"')
        return tuple(name for name, _ in names)

    @staticmethod
    def _assert_test_database() -> None:
        """Refuse anywhere the database is not obviously a test one.

        Django prefixes a test database with ``test_`` and sets ``DEBUG`` off in most real
        deployments, so neither alone is a reliable signal. The name is the one the test
        runner controls and the one an operator would have to go out of their way to fake.
        """
        name = str(connection.settings_dict.get("NAME") or "")
        if connection.vendor == "sqlite" and (":memory:" in name or not name):
            return
        if "test" in name.lower():
            return
        raise RuntimeError(
            f"refusing to drop attest's append-only triggers: database {name!r} does not "
            f"look like a test database. These triggers are the guarantee that a "
            f"well-meaning data fix cannot rewrite an audit trail; dropping them anywhere "
            f"a real record lives would remove the control this package exists to provide."
        )

    @classmethod
    def _names(cls) -> tuple[tuple[str, str], ...]:
        """``(trigger, table)`` pairs, read from the database rather than assumed."""
        with connection.cursor() as cursor:
            if connection.vendor == "postgresql":
                cursor.execute(
                    "SELECT t.tgname, c.relname FROM pg_trigger t "
                    "JOIN pg_class c ON c.oid = t.tgrelid "
                    "WHERE t.tgname LIKE %s AND NOT t.tgisinternal",
                    [f"{cls.PREFIX}%"],
                )
            else:
                cursor.execute(
                    "SELECT name, tbl_name FROM sqlite_master "
                    "WHERE type = 'trigger' AND name LIKE ?",
                    [f"{cls.PREFIX}%"],
                )
            return tuple((row[0], row[1]) for row in cursor.fetchall())

    @classmethod
    def installed(cls) -> bool:
        """Whether any of them are present. For a test that asserts the migration ran."""
        return bool(cls._names())
