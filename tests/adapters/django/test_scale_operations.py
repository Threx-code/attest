"""The Postgres-only scale operations, and what they refuse to do quietly.

These cannot run their SQL against the SQLite suite, and that is the point of half of
them: an operation that installed nothing on the wrong engine would leave a deployment
believing recall is indexed while every lookup scans, or believing it has a retention
story while the table grows forever. So what is tested here is the refusals and the
generated SQL, which is where the mistakes actually live.
"""

from __future__ import annotations

from typing import Any

import pytest

from attest.adapters.django.triggers import (
    EnsurePartitions,
    RangePartitionByMonth,
    TrigramIndex,
)

pytestmark = [pytest.mark.contract, pytest.mark.security]


class Editor:
    """A schema editor that records rather than executes."""

    def __init__(self, vendor: str = "postgresql", *, rows: bool = False) -> None:
        self.executed: list[str] = []
        self.connection = type("C", (), {"vendor": vendor, "cursor": lambda _: Cursor(rows)})()

    def execute(self, statement: str) -> None:
        self.executed.append(statement)


class Cursor:
    def __init__(self, rows: bool) -> None:
        self._rows = rows

    def __enter__(self) -> Cursor:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def execute(self, statement: str, params: Any = None) -> None:
        self.statement = statement

    def fetchone(self) -> tuple[Any, ...]:
        return (self._rows,)


# ── Wrong engine refuses rather than no-ops ──────────────────────────────────


@pytest.mark.parametrize(
    "operation",
    [
        TrigramIndex("attest_memory", "content"),
        RangePartitionByMonth("attest_audit_events"),
        EnsurePartitions("attest_audit_events"),
    ],
    ids=["trigram", "partition", "ensure"],
)
def test_a_non_postgres_engine_is_refused_not_silently_skipped(operation: Any) -> None:
    """An operation that installs nothing leaves a false belief behind.

    "Recall is indexed" and "we have a retention story" are both things a deployment
    acts on, and both are discovered to be untrue in production.
    """
    with pytest.raises(NotImplementedError, match="ships no"):
        operation.database_forwards("attest", Editor(vendor="sqlite"), None, None)


# ── The trigram index ────────────────────────────────────────────────────────


def test_the_trigram_index_creates_the_extension_before_the_index() -> None:
    """Failing at CREATE EXTENSION is a clear error; failing at the index is a confusing one."""
    editor = Editor()
    TrigramIndex("attest_memory", "content").database_forwards("attest", editor, None, None)
    assert editor.executed[0] == "CREATE EXTENSION IF NOT EXISTS pg_trgm"
    assert "USING gin (content gin_trgm_ops)" in editor.executed[1]
    assert "attest_memory" in editor.executed[1]


def test_the_trigram_index_is_reversible() -> None:
    editor = Editor()
    TrigramIndex("attest_memory", "content").database_backwards("attest", editor, None, None)
    assert editor.executed == ["DROP INDEX IF EXISTS attest_attest_memory_content_trgm"]


# ── Partitioning ─────────────────────────────────────────────────────────────


@pytest.mark.security
def test_partitioning_a_table_with_rows_is_refused() -> None:
    """Converting a populated table moves every row: a maintenance window, not a step.

    Doing it silently would either lock the table for hours or leave the data behind.
    """
    with pytest.raises(RuntimeError, match="already has rows"):
        RangePartitionByMonth("attest_audit_events").database_forwards(
            "attest", Editor(rows=True), None, None
        )


def test_partitioning_an_empty_table_carries_the_indexes_across() -> None:
    """LIKE ... INCLUDING ALL, so the partitioned table is not quietly missing an index."""
    editor = Editor(rows=False)
    RangePartitionByMonth("attest_audit_events").database_forwards("attest", editor, None, None)
    assert "RENAME TO attest_audit_events_unpartitioned" in editor.executed[0]
    assert "INCLUDING ALL" in editor.executed[1]
    assert "PARTITION BY RANGE (occurred_at)" in editor.executed[1]


@pytest.mark.security
def test_un_partitioning_is_refused_rather_than_half_done() -> None:
    with pytest.raises(NotImplementedError, match="data migration"):
        RangePartitionByMonth("attest_audit_events").database_backwards(
            "attest", Editor(), None, None
        )


# ── Keeping partitions ahead of the clock ────────────────────────────────────


def test_partitions_are_generated_with_correct_month_bounds() -> None:
    """A wrong month edge is a day of rejected inserts, in the audit sink."""
    statements = EnsurePartitions.statements("attest_audit_events", 3, start="2026-11-01")
    assert "attest_audit_events_202611 PARTITION OF" in statements[0]
    assert "FROM ('2026-11-01') TO ('2026-12-01')" in statements[0]
    # The year boundary is where an off-by-one lives.
    assert "FROM ('2026-12-01') TO ('2027-01-01')" in statements[1]
    assert "attest_audit_events_202701" in statements[2]


def test_ensuring_partitions_is_idempotent() -> None:
    """It runs from a migration and again from a schedule; both must be safe."""
    for statement in EnsurePartitions.statements("attest_audit_events", 2, start="2026-01-01"):
        assert "IF NOT EXISTS" in statement


@pytest.mark.security
def test_rolling_back_partitions_deletes_nothing() -> None:
    """Dropping a partition on rollback would delete audit rows."""
    editor = Editor()
    EnsurePartitions("attest_audit_events").database_backwards("attest", editor, None, None)
    assert editor.executed == []
