"""The SQLite adapter, against real transactions and real threads.

The in-memory stores prove the contracts within one process. These prove them where
they actually bite: atomic redemption as a UNIQUE constraint, append-only as a trigger
below the application, and reserve-then-commit inside one IMMEDIATE transaction.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar

import pytest

from attest.adapters.sqlite import SQLiteStore
from attest.assurance.conformance import (
    AuditSinkConformance,
    NonceStoreConformance,
    RunStoreConformance,
)
from attest.kernel.audit import AuditEvent
from attest.kernel.errors import StoreError
from attest.kernel.identifiers import GrantId, Nonce, RunId

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
THREADS = 24
_R = TypeVar("_R")


@pytest.fixture
def store(tmp_path: Path) -> Iterator[SQLiteStore]:
    made = SQLiteStore(tmp_path / "attest.db")
    yield made
    made.close()


def event(event_type: str, run_id: str = "r1") -> AuditEvent:
    return AuditEvent(run_id=RunId(run_id), event_type=event_type, occurred_at=AT)


def attestation(run_id: str, *, answer: str = "original") -> Any:
    return RunStoreConformance.attestation(RunId(run_id), answer=answer)


def _together(fn: Callable[[int], _R], count: int = THREADS) -> list[_R]:
    barrier = threading.Barrier(count)

    def worker(index: int) -> _R:
        barrier.wait()
        return fn(index)

    with ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(worker, range(count)))


# ── Append-only is enforced below the application ────────────────────────────


@pytest.mark.security
def test_audit_events_cannot_be_updated(store: SQLiteStore) -> None:
    # "We only ever INSERT" is a convention, and conventions decay. The trigger is
    # the enforcement.
    store.append(event("run.dispatched"))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._connect().execute("UPDATE audit_events SET event_type = 'forged'")


@pytest.mark.security
def test_audit_events_cannot_be_deleted(store: SQLiteStore) -> None:
    store.append(event("run.dispatched"))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store._connect().execute("DELETE FROM audit_events")


@pytest.mark.security
def test_an_attestations_content_cannot_be_rewritten(store: SQLiteStore) -> None:
    # A correction is a new row, so a reader who relied on the original can still
    # see exactly what they relied on.
    store.create(attestation("r1"))
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        store._connect().execute("UPDATE attestations SET payload = 'rewritten'")


def test_supersede_retains_both_records(store: SQLiteStore) -> None:
    store.create(attestation("r1"))
    store.supersede(RunId("r1"), attestation("r2", answer="corrected"))
    original = store.get(RunId("r1"))
    assert original is not None
    assert original.answer == "original", (
        "the original was rewritten rather than superseded; a reader who relied on it "
        "can no longer see what they relied on"
    )
    assert store.get(RunId("r2")) is not None


def test_superseding_an_unknown_run_is_refused(store: SQLiteStore) -> None:
    with pytest.raises(StoreError, match="unknown run"):
        store.supersede(RunId("missing"), attestation("r2"))


def test_a_duplicate_attestation_is_refused(store: SQLiteStore) -> None:
    store.create(attestation("r1"))
    with pytest.raises(StoreError, match="immutable"):
        store.create(attestation("r1"))


# ── Atomic redemption against a real constraint ──────────────────────────────


@pytest.mark.concurrency
@pytest.mark.security
def test_only_one_thread_redeems_a_nonce(store: SQLiteStore) -> None:
    # The PRIMARY KEY does the work. A read-then-write would let several callers all
    # observe an unused nonce.
    results = _together(lambda i: store.redeem(Nonce("n1"), GrantId(f"g{i}")))
    assert sum(results) == 1


def test_distinct_nonces_all_redeem(store: SQLiteStore) -> None:
    assert all(_together(lambda i: store.redeem(Nonce(f"n{i}"), GrantId(f"g{i}"))))


def test_revocation_is_visible(store: SQLiteStore) -> None:
    assert not store.is_revoked(GrantId("g1"))
    store.revoke(GrantId("g1"))
    assert store.is_revoked(GrantId("g1"))


# ── Reserve-then-commit inside one transaction ───────────────────────────────


@pytest.mark.concurrency
@pytest.mark.security
def test_concurrent_reservations_cannot_both_pass_the_ceiling(store: SQLiteStore) -> None:
    # IMMEDIATE means the second writer blocks until the first commits, then sees its
    # reservation. Reading the balance and writing later is the race this prevents.
    results = _together(
        lambda i: store.reserve("payouts", "18000", AT + timedelta(seconds=30), ceiling="20000")
    )
    assert len([r for r in results if r is not None]) == 1


def test_a_reservation_is_held_against_the_ceiling_before_commit(store: SQLiteStore) -> None:
    first = store.reserve("payouts", "60", AT + timedelta(seconds=30), ceiling="100")
    assert first is not None
    assert store.reserve("payouts", "60", AT + timedelta(seconds=30), ceiling="100") is None


def test_releasing_frees_the_headroom(store: SQLiteStore) -> None:
    first = store.reserve("payouts", "60", AT + timedelta(seconds=30), ceiling="100")
    assert first is not None
    store.release(first)
    assert store.reserve("payouts", "60", AT + timedelta(seconds=30), ceiling="100") is not None


def test_commit_records_the_actual_spend(store: SQLiteStore) -> None:
    reservation = store.reserve("payouts", "60", AT + timedelta(seconds=30), ceiling="100")
    assert reservation is not None
    store.commit(reservation, "45")
    assert store.spent("payouts") == "45"


def test_committing_an_unknown_reservation_is_refused(store: SQLiteStore) -> None:
    with pytest.raises(StoreError, match="unknown reservation"):
        store.commit("res_nope_1", "10")


def test_committed_spend_counts_toward_the_ceiling(store: SQLiteStore) -> None:
    reservation = store.reserve("payouts", "90", AT + timedelta(seconds=30), ceiling="100")
    assert reservation is not None
    store.commit(reservation, "90")
    assert store.reserve("payouts", "20", AT + timedelta(seconds=30), ceiling="100") is None


# ── Chain read-back ──────────────────────────────────────────────────────────


def test_events_read_back_as_events_in_insertion_order(store: SQLiteStore) -> None:
    """Unsealed, and decoded. Before sealing there is no canonical position.

    Insertion order is all there is, and the sealer assigns the real one later — which
    is why the sink stores no sequence of its own.
    """
    for i in range(3):
        store.append(event(f"e{i}"))
    chain = store.read_chain(RunId("r1"))
    assert [e.event_type for e in chain] == ["e0", "e1", "e2"]
    assert all(e.sequence is None for e in chain)


def test_an_edited_event_row_fails_to_decode_rather_than_reading_back(
    store: SQLiteStore,
) -> None:
    """Defence in depth behind the trigger.

    If a row is changed by any route the trigger does not cover — a restored backup, a
    direct file edit — the payload no longer decodes, so it fails loudly instead of
    coming back as a plausible event that says something else.
    """
    store.append(event("run.dispatched"))
    connection = store._connect()
    connection.execute("DROP TRIGGER audit_events_no_update")
    connection.execute("UPDATE audit_events SET payload = ?", (b'{"v": 2}',))
    with pytest.raises(Exception, match=r"."):
        store.read_chain(RunId("r1"))


# ── The conformance kit, against the adapter that ships with the package ─────


class ReleasesConnections:
    """Closes the per-thread SQLite handle a spawned thread opened.

    The store reaps connections whose thread has exited, but only when a new one is
    opened — so an idle pool holds a file handle per retired worker, and a test suite
    that turns warnings into errors sees a ResourceWarning raised during garbage
    collection, attributed to some unrelated test.
    """

    _store: SQLiteStore

    def release_thread(self) -> None:
        self._store.close_thread()


class TestSQLiteRunStore(ReleasesConnections, RunStoreConformance):
    def store(self) -> SQLiteStore:
        return self._store

    @pytest.fixture(autouse=True)
    def _fresh(self, tmp_path: Path) -> Iterator[None]:
        # A file rather than ":memory:": the adapter keeps a connection per thread, and
        # an in-memory database is per-connection, so two threads would silently get
        # two different databases and every concurrency claim would pass vacuously.
        self._store = SQLiteStore(tmp_path / "runs.db")
        yield
        self._store.close()


class TestSQLiteAuditSink(ReleasesConnections, AuditSinkConformance):
    def store(self) -> SQLiteStore:
        return self._store

    @pytest.fixture(autouse=True)
    def _fresh(self, tmp_path: Path) -> Iterator[None]:
        self._store = SQLiteStore(tmp_path / "sink.db")
        yield
        self._store.close()


class TestSQLiteNonceStore(ReleasesConnections, NonceStoreConformance):
    def store(self) -> SQLiteStore:
        return self._store

    @pytest.fixture(autouse=True)
    def _fresh(self, tmp_path: Path) -> Iterator[None]:
        self._store = SQLiteStore(tmp_path / "nonces.db")
        yield
        self._store.close()


@pytest.mark.security
def test_an_in_memory_database_is_refused() -> None:
    """The default was ':memory:', which is unusable here and looks fine.

    This adapter holds one connection per thread and an in-memory SQLite database
    belongs to its connection — so every worker thread got a private, schema-less
    database and 32 threads produced 32 OperationalErrors on the first query. The
    single-use nonce and the atomic reserve would both have silently stopped being
    either.

    Every test passes tmp_path, so the default was never exercised: a default wrong for
    every real caller and untested by every test is the shape somebody copies out of a
    docstring.
    """
    from attest.kernel.errors import ConfigurationError

    with pytest.raises(ConfigurationError, match="cannot use ':memory:'"):
        SQLiteStore(":memory:")


@pytest.mark.concurrency
@pytest.mark.security
def test_threads_share_one_database_rather_than_getting_private_ones(tmp_path: Path) -> None:
    """The property the ':memory:' default silently removed.

    Every atomicity guarantee in this adapter is a statement about one database. If
    each thread has its own, `redeem` returns True for all of them.
    """
    store = SQLiteStore(tmp_path / "shared.db")
    try:
        results = _together(lambda i: store.redeem(Nonce("n1"), GrantId(f"g{i}")))
        assert sum(results) == 1, "threads did not share a database"
    finally:
        store.close()


@pytest.mark.security
def test_a_dropped_store_closes_the_connections_it_owns(tmp_path: Path) -> None:
    """The store owns its connections and must release them when it is collected.

    Not tidiness. It opens one connection per thread that touches it, so a host building
    a store per request leaks a descriptor per thread per store — which ends in EMFILE
    under load, at which point the failure reads as "the database is unreachable" and
    the cause is three layers away.

    .. rubric:: Why this asserts on the connection and not on ResourceWarning

    The obvious test is to turn ``ResourceWarning`` into an error and drop a store. That
    test **passes on Python 3.12 whether or not the fix is present**, because the warning
    for an unclosed ``sqlite3.Connection`` was only added in 3.13 — so it would be green
    on a 3.12 machine and red on CI, which is exactly the shape of check that finds
    nothing and is trusted anyway. This leak was found that way round: as a warning
    raised during garbage collection in a witness test, three files from the code that
    caused it, on CI and never locally.

    Asking the connection whether it is closed is the same property on every interpreter.
    It is asked on the thread that opened it, because SQLite's cross-thread guard fires
    *before* its closed-database check — so probing from elsewhere reports a thread
    error for an open connection and a closed one alike, and would pass either way.
    """
    import gc

    probe: dict[str, Any] = {}

    def build_and_drop() -> None:
        store = SQLiteStore(tmp_path / "dropped.db")
        store.redeem(Nonce("n1"), GrantId("g1"))
        probe["connections"] = [connection for _, connection in store._connections]
        # Deliberately no close(). That is the case under test.

    build_and_drop()
    gc.collect()

    assert probe["connections"], "the store tracked no connection to release"
    for connection in probe["connections"]:
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            connection.execute("SELECT 1")


@pytest.mark.security
def test_close_actually_closes_every_threads_connection(tmp_path: Path) -> None:
    """Not "the registry is empty" — the connections are shut. ATT-76.

    The previous version of this test asserted ``store._connections == []`` after
    ``close()``, which is the *mechanism* and passed while the thing it stood for was
    false: SQLite refuses any cross-thread operation, ``close()`` is one, so closing a
    worker thread's connection from the calling thread raised, ``_suppress_closed``
    swallowed it as "already closed", and the list was cleared over connections that
    were still open.

    Twenty-four leaked handles per run. Invisible on Python 3.12 and below, which do not
    warn about an unclosed sqlite3 connection, and invisible to a test that checked the
    list rather than the handles — so it took a 3.13 CI runner to find a cleanup path
    that had been reporting success and doing nothing.

    Probing across threads is valid now precisely because the fix was to stop the guard
    refusing cross-thread access; before it, this assertion could not have been written.
    """
    store = SQLiteStore(tmp_path / "threaded.db")
    _together(lambda i: store.redeem(Nonce(f"n{i}"), GrantId(f"g{i}")), count=4)

    connections = [connection for _, connection in store._connections]
    assert len(connections) > 1, "the threads did not open per-thread connections"

    store.close()
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            connection.execute("SELECT 1")


def test_closing_twice_is_not_an_error(tmp_path: Path) -> None:
    """`__del__` calls `close()`, so every explicitly-closed store is closed twice.

    A second close that raised would turn correct cleanup into a warning at collection
    time, which is the thing being fixed.
    """
    store = SQLiteStore(tmp_path / "twice.db")
    store.close()
    store.close()
