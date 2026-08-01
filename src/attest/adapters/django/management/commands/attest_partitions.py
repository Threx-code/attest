"""Keep partitions ahead of the clock, and archive old ones by detaching them.

Two jobs that must both run, and a third that must never be written.

.. code-block:: bash

    # monthly, well before the month turns
    python manage.py attest_partitions --ensure 6

    # after the retention period, once the month is safely in cold storage
    python manage.py attest_partitions --detach-before 2025-01-01

**A partitioned table with no partition covering ``now`` rejects every insert.** That
failure lands in the audit sink, so runs stop rather than degrade, and it begins at
midnight on the first of the month — which is the worst possible time for anyone to be
finding out. Creating six months ahead costs nothing; an empty partition is an empty
file.

The third job is deleting rows, and it does not exist. The chain tables are append-only
at the database level, so archival is ``DETACH PARTITION``: the rows are untouched, the
chain over them still verifies byte for byte, and nothing had to turn the append-only
guarantee off to do routine maintenance. A deployment that *can* turn it off in order
to prune does not have it.

Detaching does not delete the child table either. It leaves it standing, unattached, so
the operator dumps it to object storage and drops it deliberately — with the run ids it
covers printed, so what left the live database is written down somewhere.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from attest.adapters.django.triggers import EnsurePartitions

if TYPE_CHECKING:
    from argparse import ArgumentParser


class Command(BaseCommand):
    """Create upcoming partitions, and detach old ones for archival."""

    help = "Manage monthly partitions for the append-only attest tables."

    #: The tables worth partitioning: append-only, unbounded, and written every run.
    TABLES = ("attest_audit_events", "attest_dispatch_events")

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--ensure",
            type=int,
            default=0,
            help="Create this many monthly partitions ahead. Run it on a schedule.",
        )
        parser.add_argument(
            "--detach-before",
            default="",
            help="Detach partitions wholly before this ISO date. Rows are NOT deleted.",
        )
        parser.add_argument(
            "--table",
            default="",
            help=f"Limit to one table. Default: {', '.join(Command.TABLES)}",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print the SQL and change nothing.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if connection.vendor != "postgresql":
            raise CommandError(
                f"partitioning is PostgreSQL-only, and this connection is "
                f"{connection.vendor!r}. Rather than pretending to succeed: on another "
                f"engine you need a retention story built on that engine's mechanism, "
                f"and the constraint that matters is that it must not require deleting "
                f"rows from an append-only table."
            )

        tables = (options["table"],) if options["table"] else self.TABLES
        if not options["ensure"] and not options["detach_before"]:
            raise CommandError("nothing to do: pass --ensure and/or --detach-before")

        for table in tables:
            if options["ensure"]:
                self.ensure(table, int(options["ensure"]), dry_run=options["dry_run"])
            if options["detach_before"]:
                self.detach(table, str(options["detach_before"]), dry_run=options["dry_run"])

    def ensure(self, table: str, months: int, *, dry_run: bool) -> None:
        """Create the next ``months`` partitions, idempotently.

        Uses :meth:`EnsurePartitions.statements` rather than generating its own bounds.
        Two generators of partition boundaries would eventually disagree about a month
        edge, and the symptom is a day of rejected inserts.
        """
        for statement in EnsurePartitions.statements(table, months):
            self.stdout.write(statement if dry_run else f"  {statement}")
            if not dry_run:
                with connection.cursor() as cursor:
                    cursor.execute(statement)
        if not dry_run:
            self.stdout.write(self.style.SUCCESS(f"{table}: {months} month(s) ensured"))

    def detach(self, table: str, before: str, *, dry_run: bool) -> None:
        """Detach every partition wholly older than ``before``. **Deletes nothing.**

        The child table survives, unattached and complete. Dump it, verify the dump,
        then drop it — in that order, deliberately, by a person. Automating the drop
        here would put "irreversibly discard audit evidence" on a cron schedule.
        """
        for child, bound in self.partitions(table):
            if bound >= before:
                continue
            statement = f"ALTER TABLE {table} DETACH PARTITION {child}"
            if dry_run:
                self.stdout.write(statement)
                continue
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT count(*) FROM {child}")  # noqa: S608  # nosec B608 - a partition name read from pg_class, never user input
                rows = cursor.fetchone()[0]
                cursor.execute(statement)
            self.stdout.write(
                self.style.WARNING(
                    f"detached {child} ({rows} rows). It still exists and is complete. "
                    f"Dump it, verify the dump, then drop it — in that order."
                )
            )

    @staticmethod
    def partitions(table: str) -> list[tuple[str, str]]:
        """Child partitions and their lower bound, oldest first."""
        query = """
            SELECT c.relname,
                   pg_get_expr(c.relpartbound, c.oid)
            FROM pg_class parent
            JOIN pg_inherits i ON i.inhparent = parent.oid
            JOIN pg_class c ON c.oid = i.inhrelid
            WHERE parent.relname = %s
            ORDER BY c.relname
        """
        with connection.cursor() as cursor:
            cursor.execute(query, [table])
            rows = cursor.fetchall()
        found: list[tuple[str, str]] = []
        for name, bound in rows:
            # FOR VALUES FROM ('2026-01-01') TO ('2026-02-01')
            upper = str(bound).split(" TO ")[-1].strip("() '")
            found.append((str(name), upper))
        return found
