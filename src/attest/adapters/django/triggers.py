"""Migration operations that install the guarantees below the application.

"We only ever INSERT" is a convention, and conventions decay — a well-meaning data fix,
a Django admin action, an ORM ``update()`` in a cleanup script. The append-only and
immutability contracts are therefore triggers, so a mutation fails at the database
regardless of which code path attempted it.

**An unsupported backend raises rather than skipping.** A migration that quietly did
nothing on Oracle would leave a deployment believing it had enforcement it does not
have, and that belief is worse than the missing trigger: it is the difference between
knowing you must build something and thinking you already did.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from django.db.migrations.operations.base import Operation

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import Any

__all__ = [
    "AppendOnlyTable",
    "EnsurePartitions",
    "ImmutableColumns",
    "NoEventsAfterSeal",
    "RangePartitionByMonth",
    "TrigramIndex",
]


class _GuardOperation(Operation):
    """Shared plumbing: dispatch SQL by vendor, and refuse unknown ones."""

    reduces_to_sql = True
    reversible = True

    atomic = False
    """**Not** ``True``. That value made this migration impossible to apply to MySQL.

    Django wraps a whole migration in a transaction only when the backend can roll DDL
    back. PostgreSQL can, so the migration is atomic there and this flag changes nothing.
    MySQL cannot, so Django deliberately runs the migration *without* one — and an
    operation declaring ``atomic = True`` re-opens a transaction around itself, at which
    point the schema editor refuses:

    .. code-block:: text

        TransactionManagementError: Executing DDL statements while in a transaction
        on databases that can't perform a rollback is prohibited.

    So ``SUPPORTED`` listed ``mysql``, the MySQL trigger SQL was written and reviewed,
    and the migration could not be applied to a MySQL database at all. Nothing caught it
    because the suite had only ever run against SQLite; the first time it met a real
    MySQL, every one of the 255 tests errored at setup.

    Setting it to ``False`` costs nothing where atomicity is available — PostgreSQL still
    wraps the migration — and is the only value that works where it is not.
    """

    #: Vendors this operation knows how to guard. ``connection.vendor`` values.
    SUPPORTED: ClassVar[frozenset[str]] = frozenset({"sqlite", "postgresql", "mysql"})

    def state_forwards(self, app_label: str, state: Any) -> None:
        """Triggers are not model state, so Django's autodetector must not see them."""

    def _vendor(self, schema_editor: Any) -> str:
        vendor = str(schema_editor.connection.vendor)
        if vendor not in self.SUPPORTED:
            raise NotImplementedError(
                f"attest ships no {type(self).__name__} implementation for database "
                f"vendor {vendor!r}. This migration will not pretend to succeed: the "
                f"contract it installs is enforcement, and a deployment that believes "
                f"it has enforcement it does not have is worse off than one that knows "
                f"it must build it. Supply the trigger for {vendor!r} in your own "
                f"migration, then mark this one as applied."
            )
        return vendor

    def _execute(self, schema_editor: Any, statements: Sequence[str]) -> None:
        for statement in statements:
            schema_editor.execute(statement)


class AppendOnlyTable(_GuardOperation):
    """Reject every ``UPDATE`` and ``DELETE`` on a table.

    Used for the audit chain. Losing or editing one event produces a chain that is
    internally consistent with an event missing — which linkage alone cannot detect,
    and which is exactly what the seal's dense sequence exists to catch after the fact.
    Better to make it impossible in the first place.
    """

    def __init__(self, table: str, *, prefix: str = "attest") -> None:
        self.table = table
        self.prefix = prefix

    def describe(self) -> str:
        return f"Make {self.table} append-only (reject UPDATE and DELETE)"

    @property
    def migration_name_fragment(self) -> str:
        return f"append_only_{self.table}"

    def deconstruct(self) -> tuple[str, list[Any], dict[str, Any]]:
        return (type(self).__name__, [self.table], {"prefix": self.prefix})

    def database_forwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        self._execute(schema_editor, self._install(self._vendor(schema_editor)))

    def database_backwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        self._execute(schema_editor, self._remove(self._vendor(schema_editor)))

    def _names(self) -> tuple[str, str]:
        return f"{self.prefix}_{self.table}_no_update", f"{self.prefix}_{self.table}_no_delete"

    def _install(self, vendor: str) -> list[str]:
        no_update, no_delete = self._names()
        message = f"{self.prefix}: {self.table} is append-only"
        if vendor == "sqlite":
            return [
                f"CREATE TRIGGER {no_update} BEFORE UPDATE ON {self.table} "
                f"BEGIN SELECT RAISE(ABORT, '{message}'); END",
                f"CREATE TRIGGER {no_delete} BEFORE DELETE ON {self.table} "
                f"BEGIN SELECT RAISE(ABORT, '{message}'); END",
            ]
        if vendor == "postgresql":
            function = f"{self.prefix}_reject_mutation"
            return [
                f"CREATE OR REPLACE FUNCTION {function}() RETURNS trigger AS $$ "
                f"BEGIN RAISE EXCEPTION '{self.prefix}: %% is append-only (attempted %%)', "
                f"TG_TABLE_NAME, TG_OP; RETURN NULL; END; $$ LANGUAGE plpgsql",
                f"CREATE TRIGGER {no_update} BEFORE UPDATE OR DELETE ON {self.table} "
                f"FOR EACH ROW EXECUTE FUNCTION {function}()",
            ]
        # S608: identifiers come from this package's own migration files, never from a
        # request. DDL cannot be parameterised, so interpolation is the only option.
        return [
            f"CREATE TRIGGER {no_update} BEFORE UPDATE ON {self.table} FOR EACH ROW "  # noqa: S608 # nosec B608
            f"SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '{message}'",
            f"CREATE TRIGGER {no_delete} BEFORE DELETE ON {self.table} FOR EACH ROW "
            f"SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '{message}'",
        ]

    def _remove(self, vendor: str) -> list[str]:
        no_update, no_delete = self._names()
        if vendor == "postgresql":
            return [f"DROP TRIGGER IF EXISTS {no_update} ON {self.table}"]
        return [f"DROP TRIGGER IF EXISTS {no_update}", f"DROP TRIGGER IF EXISTS {no_delete}"]


class ImmutableColumns(_GuardOperation):
    """Reject any ``UPDATE`` that changes the listed columns.

    Attestations are immutable, but the *pointer* to a superseding record is not — so
    the whole row cannot simply be frozen. Freezing the content columns and leaving
    ``superseded_by`` writable is what lets a correction exist without letting anyone
    rewrite what a reader already relied on.
    """

    def __init__(self, table: str, columns: Sequence[str], *, prefix: str = "attest") -> None:
        self.table = table
        self.columns = list(columns)
        self.prefix = prefix

    def describe(self) -> str:
        return f"Freeze {', '.join(self.columns)} on {self.table}"

    @property
    def migration_name_fragment(self) -> str:
        return f"immutable_{self.table}"

    def deconstruct(self) -> tuple[str, list[Any], dict[str, Any]]:
        return (type(self).__name__, [self.table, self.columns], {"prefix": self.prefix})

    def database_forwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        self._execute(schema_editor, self._install(self._vendor(schema_editor)))

    def database_backwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        vendor = self._vendor(schema_editor)
        name = self._name()
        if vendor == "postgresql":
            self._execute(schema_editor, [f"DROP TRIGGER IF EXISTS {name} ON {self.table}"])
        else:
            self._execute(schema_editor, [f"DROP TRIGGER IF EXISTS {name}"])

    def _name(self) -> str:
        return f"{self.prefix}_{self.table}_immutable"

    def _install(self, vendor: str) -> list[str]:
        name = self._name()
        message = f"{self.prefix}: {self.table} rows are immutable; use supersede()"
        if vendor == "sqlite":
            columns = ", ".join(self.columns)
            return [
                f"CREATE TRIGGER {name} BEFORE UPDATE OF {columns} ON {self.table} "
                f"BEGIN SELECT RAISE(ABORT, '{message}'); END"
            ]
        changed = " OR ".join(
            f"NEW.{column}::text IS DISTINCT FROM OLD.{column}::text" for column in self.columns
        )
        if vendor == "postgresql":
            function = f"{self.prefix}_{self.table}_reject_content_change"
            return [
                f"CREATE OR REPLACE FUNCTION {function}() RETURNS trigger AS $$ BEGIN "
                f"IF {changed} THEN RAISE EXCEPTION '{message}'; END IF; RETURN NEW; "
                f"END; $$ LANGUAGE plpgsql",
                f"CREATE TRIGGER {name} BEFORE UPDATE ON {self.table} "
                f"FOR EACH ROW EXECUTE FUNCTION {function}()",
            ]
        mysql_changed = " OR ".join(
            f"NOT(NEW.{column} <=> OLD.{column})" for column in self.columns
        )
        # S608: see AppendOnlyTable._install — table and column names are ours.
        return [
            f"CREATE TRIGGER {name} BEFORE UPDATE ON {self.table} FOR EACH ROW "  # noqa: S608 # nosec B608
            f"BEGIN IF {mysql_changed} THEN SIGNAL SQLSTATE '45000' "
            f"SET MESSAGE_TEXT = '{message}'; END IF; END"
        ]


class RangePartitionByMonth(_GuardOperation):
    """Convert an append-only table to monthly range partitions. **PostgreSQL only.**

    The tables this package writes cannot be pruned — that is the point, and it is also
    the operational problem. At 50M governed runs a day the chain grows about 750
    million rows daily, and every one of them is protected by a trigger that forbids
    ``DELETE``. There is no query plan that saves a table like that; the answer is that
    old months stop being part of the live table.

    .. code-block:: text

        WITHOUT PARTITIONS                  WITH MONTHLY PARTITIONS
        ────────────────────────            ──────────────────────────────────
        one table, growing forever          one child per month
        VACUUM walks all of it              autovacuum works a month at a time
        archival needs DELETE               archival is DETACH PARTITION
        (which the trigger forbids)         (which touches no rows at all)

    ``DETACH`` is the line that matters. Archiving by deleting rows would require
    disabling the append-only guarantee, and a deployment that can turn the guarantee
    off to do routine maintenance does not have the guarantee. Detaching leaves every
    row exactly as written, in a table that is no longer attached to the live one, and
    the chain over those rows still verifies byte for byte.

    **This operation does not migrate data.** Partitioning an existing table means
    creating a partitioned table and moving rows into it, which on a large table is a
    maintenance window rather than a migration step — and how it is done depends on how
    much downtime the deployment can take. Run this before the table has data, or write
    the swap yourself. It refuses rather than silently doing half of it.
    """

    SUPPORTED: ClassVar[frozenset[str]] = frozenset({"postgresql"})

    def __init__(self, table: str, *, column: str = "occurred_at") -> None:
        self.table = table
        self.column = column

    def describe(self) -> str:
        return f"Range-partition {self.table} by month on {self.column}"

    @property
    def migration_name_fragment(self) -> str:
        return f"partition_{self.table}"

    def deconstruct(self) -> tuple[str, list[Any], dict[str, Any]]:
        return (type(self).__name__, [self.table], {"column": self.column})

    def database_forwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        self._vendor(schema_editor)
        self._assert_empty(schema_editor)
        self._execute(schema_editor, self._install())

    def database_backwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        raise NotImplementedError(
            f"un-partitioning {self.table} would have to merge every child back into "
            f"one table, which is a data migration rather than a schema change. Roll "
            f"forward, or restore from a backup taken before this ran."
        )

    def _assert_empty(self, schema_editor: Any) -> None:
        """Refuse on a table with rows, rather than partitioning half of it."""
        with schema_editor.connection.cursor() as cursor:
            # nosec B608 - the table name is fixed in a migration, never user input
            probe = f"SELECT EXISTS (SELECT 1 FROM {self.table} LIMIT 1)"  # noqa: S608 # nosec B608
            cursor.execute(probe)
            if cursor.fetchone()[0]:
                raise RuntimeError(
                    f"{self.table} already has rows. Converting a populated table to a "
                    f"partitioned one moves every row, which is a maintenance window "
                    f"and not a migration step — and doing it silently here would "
                    f"either lock the table for hours or leave the data behind. "
                    f"Perform the swap deliberately, then mark this migration applied."
                )

    def _install(self) -> list[str]:
        renamed = f"{self.table}_unpartitioned"
        return [
            f"ALTER TABLE {self.table} RENAME TO {renamed}",
            # LIKE ... INCLUDING ALL carries the indexes and constraints across, so a
            # partitioned table is not quietly missing the index the old one had.
            f"CREATE TABLE {self.table} (LIKE {renamed} INCLUDING ALL) "
            f"PARTITION BY RANGE ({self.column})",
            f"DROP TABLE {renamed}",
        ]


class EnsurePartitions(_GuardOperation):
    """Create the next N monthly partitions. **PostgreSQL only.**

    Run from a migration and again from a scheduled job. A partitioned table with no
    partition covering ``now`` rejects every insert, so "we forgot to create next
    month" is an outage that begins at midnight on the first — and it begins in the
    audit sink, which means runs stop rather than degrade.

    Creating several months ahead is the cheap insurance: an empty partition costs
    nothing, and the failure it prevents takes the system down.
    """

    SUPPORTED: ClassVar[frozenset[str]] = frozenset({"postgresql"})

    def __init__(self, table: str, *, months: int = 6, start: str | None = None) -> None:
        self.table = table
        self.months = months
        self.start = start

    def describe(self) -> str:
        return f"Ensure {self.months} monthly partitions exist for {self.table}"

    @property
    def migration_name_fragment(self) -> str:
        return f"partitions_{self.table}"

    def deconstruct(self) -> tuple[str, list[Any], dict[str, Any]]:
        return (type(self).__name__, [self.table], {"months": self.months, "start": self.start})

    def database_forwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        self._vendor(schema_editor)
        self._execute(schema_editor, self.statements(self.table, self.months, self.start))

    def database_backwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        """Nothing. Dropping a partition would delete audit rows."""

    @classmethod
    def statements(cls, table: str, months: int, start: str | None = None) -> list[str]:
        """The ``CREATE TABLE ... PARTITION OF`` statements, as text.

        A classmethod so the management command can reuse exactly these rather than
        building its own — two generators of partition bounds would eventually disagree
        about a month boundary, and the symptom would be a day of rejected inserts.
        """
        from datetime import UTC, datetime

        first = (
            datetime.fromisoformat(start)
            if start is not None
            else datetime.now(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        )
        statements: list[str] = []
        year, month = first.year, first.month
        for _ in range(months):
            next_year, next_month = (year + 1, 1) if month == 12 else (year, month + 1)
            statements.append(
                f"CREATE TABLE IF NOT EXISTS {table}_{year}{month:02d} "
                f"PARTITION OF {table} "
                f"FOR VALUES FROM ('{year}-{month:02d}-01') TO ('{next_year}-{next_month:02d}-01')"
            )
            year, month = next_year, next_month
        return statements


class TrigramIndex(_GuardOperation):
    """A GIN trigram index for substring recall. **PostgreSQL only.**

    ``content__icontains`` is a sequential scan. On the memory table that is not a
    performance note — the port calls memory "the most dangerous capability in the
    framework", and it is also the one that falls over first, because recall happens on
    every run and the table grows without bound.

    A B-tree index cannot help: ``LIKE '%needle%'`` has no prefix to seek on.
    ``pg_trgm`` builds a GIN index over three-character shingles, which turns the scan
    into an index lookup for exactly this query shape and needs no change at the call
    site.

    .. code-block:: text

        WITHOUT             seq scan over every memory in the deployment
        B-TREE              useless: no prefix to seek
        GIN + pg_trgm       index lookup, same query, no code change

    The extension is created here rather than assumed. ``CREATE EXTENSION`` needs
    elevated rights and failing at index-creation time with a confusing error is worse
    than failing at the extension line with an obvious one.

    On other engines this raises rather than installing nothing: an index that silently
    did not exist would leave a deployment believing recall is indexed while every
    lookup scans, and the discovery point is production.
    """

    SUPPORTED: ClassVar[frozenset[str]] = frozenset({"postgresql"})

    def __init__(self, table: str, column: str, *, prefix: str = "attest") -> None:
        self.table = table
        self.column = column
        self.prefix = prefix

    def describe(self) -> str:
        return f"Create a GIN trigram index on {self.table}.{self.column}"

    @property
    def migration_name_fragment(self) -> str:
        return f"trgm_{self.table}_{self.column}"

    def deconstruct(self) -> tuple[str, list[Any], dict[str, Any]]:
        return (type(self).__name__, [self.table, self.column], {"prefix": self.prefix})

    def _index_name(self) -> str:
        return f"{self.prefix}_{self.table}_{self.column}_trgm"

    def database_forwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        self._vendor(schema_editor)
        self._execute(
            schema_editor,
            [
                "CREATE EXTENSION IF NOT EXISTS pg_trgm",
                f"CREATE INDEX IF NOT EXISTS {self._index_name()} "
                f"ON {self.table} USING gin ({self.column} gin_trgm_ops)",
            ],
        )

    def database_backwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        self._vendor(schema_editor)
        self._execute(schema_editor, [f"DROP INDEX IF EXISTS {self._index_name()}"])


class NoEventsAfterSeal(_GuardOperation):
    """Reject an INSERT into ``attest_audit_events`` for a run that is already sealed.

    The append-only trigger stops UPDATE and DELETE and deliberately permits INSERT —
    the table is append-only. That leaves the other half open: anything with database
    access, including an SQL injection elsewhere in the host application, could append
    rows to a closed run. The seal's dense count catches it *at verification*, which is
    periodic; until the sweep runs, a bogus row sits in the record looking like part of
    the run.

    The in-memory sink enforces this in application code. This is the same rule below
    the application, where a compromised application cannot skip it.
    """

    def __init__(self, *, prefix: str = "attest") -> None:
        self.prefix = prefix

    def describe(self) -> str:
        return "Reject audit events inserted into an already-sealed run"

    @property
    def migration_name_fragment(self) -> str:
        return "no_events_after_seal"

    def deconstruct(self) -> tuple[str, list[Any], dict[str, Any]]:
        return (type(self).__name__, [], {"prefix": self.prefix})

    def database_forwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        self._execute(schema_editor, self._install(self._vendor(schema_editor)))

    def database_backwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        self._execute(schema_editor, self._remove(self._vendor(schema_editor)))

    def _name(self) -> str:
        return f"{self.prefix}_audit_events_after_seal"

    def _install(self, vendor: str) -> list[str]:
        name = self._name()
        message = f"{self.prefix}: run is sealed; no further events may be appended"
        if vendor == "sqlite":
            return [
                f"CREATE TRIGGER IF NOT EXISTS {name} "  # noqa: S608 # nosec B608 - fixed DDL
                f"BEFORE INSERT ON attest_audit_events "
                f"WHEN EXISTS (SELECT 1 FROM attest_sealed_runs WHERE run_id = NEW.run_id) "
                f"BEGIN SELECT RAISE(ABORT, '{message}'); END"
            ]
        if vendor == "postgresql":
            return [
                f"CREATE OR REPLACE FUNCTION {name}() RETURNS trigger AS $$ "  # noqa: S608 # nosec B608 - fixed DDL
                f"BEGIN IF EXISTS (SELECT 1 FROM attest_sealed_runs WHERE run_id = NEW.run_id) "
                f"THEN RAISE EXCEPTION '{message}'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql",
                f"DROP TRIGGER IF EXISTS {name} ON attest_audit_events",  # nosec B608 - fixed DDL
                f"CREATE TRIGGER {name} BEFORE INSERT ON attest_audit_events "  # nosec B608 - fixed DDL
                f"FOR EACH ROW EXECUTE FUNCTION {name}()",
            ]
        return [
            f"CREATE TRIGGER {name} BEFORE INSERT ON attest_audit_events FOR EACH ROW "  # noqa: S608 # nosec B608 - fixed DDL
            f"BEGIN IF EXISTS (SELECT 1 FROM attest_sealed_runs WHERE run_id = NEW.run_id) "
            f"THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '{message}'; END IF; END"
        ]

    def _remove(self, vendor: str) -> list[str]:
        name = self._name()
        if vendor == "postgresql":
            return [
                f"DROP TRIGGER IF EXISTS {name} ON attest_audit_events",  # nosec B608 - fixed DDL
                f"DROP FUNCTION IF EXISTS {name}()",  # nosec B608 - fixed DDL
            ]
        return [f"DROP TRIGGER IF EXISTS {name}"]
