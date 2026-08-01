"""SQLite reference adapters.

The in-memory stores prove the contracts within one process. These prove them against
a **real transactional store**, which is where the contracts actually bite: atomic
redemption becomes a ``UNIQUE`` constraint, append-only becomes a trigger, and
reserve-then-commit becomes a transaction.

Enforcement sits **below the application** wherever the contract demands it. Append-only
is a ``BEFORE UPDATE OR DELETE`` trigger rather than a promise the code makes to itself,
because application-level discipline decays and one surveyed codebase already does this
correctly.

Single-node. For a distributed deployment the same contracts need a store with its own
transactional guarantee — the ports document what that guarantee must be.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import suppress
from decimal import Decimal
from typing import TYPE_CHECKING

from attest.kernel.codec import AttestationCodec, AuditEventCodec
from attest.kernel.errors import AuditSinkError, ConfigurationError, StoreError

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime
    from pathlib import Path

    from attest.kernel.attestation import Attestation
    from attest.kernel.audit import AuditEvent
    from attest.kernel.identifiers import GrantId, Nonce, RunId

__all__ = ["SQLiteStore"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attestations (
    run_id TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    payload BLOB NOT NULL,
    superseded_by TEXT
);

-- Attestations are immutable once written. A correction is a new row pointing at
-- what it replaces, so a reader who relied on the original can still see it.
CREATE TRIGGER IF NOT EXISTS attestations_immutable
BEFORE UPDATE OF content_hash, payload ON attestations
BEGIN
    SELECT RAISE(ABORT, 'attestations are immutable; use supersede');
END;

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    payload BLOB NOT NULL,
    sequence INTEGER,
    previous_hash TEXT
);

-- Without this, every read_chain is a table scan over the whole log. The table is
-- append-only and can never be pruned, so the scan gets slower for the lifetime of
-- the deployment and the slowdown arrives long after anyone is watching for it.
CREATE INDEX IF NOT EXISTS audit_events_by_run ON audit_events (run_id, id);

-- Append-only, enforced BELOW the application. "We only ever INSERT" is a
-- convention, and conventions decay.
CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

-- The UNIQUE constraint IS the replay defence. Two concurrent redemptions both
-- attempt the insert; exactly one succeeds and the other raises.
CREATE TABLE IF NOT EXISTS redeemed_nonces (
    nonce TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    redeemed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_grants (grant_id TEXT PRIMARY KEY);

CREATE TABLE IF NOT EXISTS budget_reservations (
    reservation_id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    amount TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- Monotonic per scope. A count of live reservations falls when one is released, so
-- the next reservation would reuse a retired id and a late commit from the previous
-- holder would consume a live hold.
CREATE TABLE IF NOT EXISTS budget_sequence (
    scope TEXT PRIMARY KEY,
    next_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS budget_spent (
    scope TEXT PRIMARY KEY,
    amount TEXT NOT NULL
);
"""


class SQLiteStore:
    """A single-file store implementing the persistence ports.

    Uses ``IMMEDIATE`` transactions so a writer takes the reserved lock at the start
    rather than on first write. Deferred transactions would let two connections both
    read a budget, both decide there is headroom, and only then collide — which turns
    a correct rejection into an unpredictable failure.
    """

    __slots__ = ("_connections", "_local", "_lock", "_path")

    def __init__(self, path: Path | str) -> None:
        """``path`` is required, and ``":memory:"`` is refused.

        It used to default to ``":memory:"``, which is unusable here and looks fine.
        This adapter keeps a connection **per thread** and an in-memory SQLite database
        belongs to its connection — so every worker thread got a private, schema-less
        database, and 32 threads produced 32 ``OperationalError``s on the first query.

        Every test passes ``tmp_path``, so the default was never exercised. A default
        that is wrong for every real caller and untested by every test is worse than no
        default: it is the shape somebody copies out of a docstring.
        """
        if str(path) == ":memory:":
            raise ConfigurationError(
                "SQLiteStore cannot use ':memory:'. This adapter holds one connection "
                "per thread and an in-memory database belongs to its connection, so "
                "each thread would get a private, empty one — the single-use nonce and "
                "the atomic reserve would both silently stop being either. Use a file, "
                "or tmp_path in a test."
            )
        self._path = str(path)
        self._local = threading.local()
        self._lock = threading.Lock()
        # Held with the owning thread, so a connection whose thread has exited can be
        # closed rather than kept for the process lifetime. A plain list leaked one
        # SQLite connection — and its file handle — per worker thread under a pool
        # that recycles threads, which is every pool. sqlite3.Connection is not
        # weak-referenceable, so liveness is tracked rather than inferred.
        self._connections: list[tuple[threading.Thread, sqlite3.Connection]] = []
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        """One connection per thread. SQLite connections are not thread-safe."""
        existing: sqlite3.Connection | None = getattr(self._local, "connection", None)
        if existing is not None:
            return existing
        # `check_same_thread=False` **so the store can close what it opened.**
        #
        # SQLite's guard refuses *any* cross-thread operation on a connection, and
        # `close()` is one. So a store whose worker threads had opened connections could
        # not release them from the thread that calls `close()` — the attempt raised,
        # `_suppress_closed` swallowed it as "already closed", and `close()` reported
        # success having closed nothing. Twenty-four leaked handles per run, surfacing
        # only on Python 3.13, which is the first version to warn about an unclosed
        # sqlite3 connection.
        #
        # A cleanup that reports success and does nothing is the exact defect class this
        # package's own gates exist to catch, and it was sitting in the cleanup path.
        #
        # Disabling the check is safe *here* and would not be in general: this adapter
        # keeps one connection per thread in a `threading.local`, so no connection is
        # ever used by two threads. The guard was protecting an invariant the store
        # already maintains, and its only practical effect was to make release
        # impossible. The invariant is asserted by
        # `test_threads_share_one_database_rather_than_getting_private_ones`.
        connection = sqlite3.connect(
            self._path, isolation_level=None, timeout=30.0, check_same_thread=False
        )
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        self._local.connection = connection
        with self._lock:
            self._prune()
            self._connections.append((threading.current_thread(), connection))
        return connection

    def _prune(self) -> None:
        """Close connections whose thread has exited. Caller holds the lock."""
        live: list[tuple[threading.Thread, sqlite3.Connection]] = []
        for owner, connection in self._connections:
            if owner.is_alive():
                live.append((owner, connection))
            else:
                with _suppress_closed():
                    connection.close()
        self._connections = live

    def close_thread(self) -> None:
        """Close **this thread's** connection. For a pool that recycles threads.

        ``_prune`` reaps connections whose thread has exited, but only when a *new*
        connection is opened — so between a worker finishing and the next one starting,
        an open SQLite handle sits in the registry. In a long-lived pool that is a file
        handle per idle worker; in a test suite with ``filterwarnings = ["error"]`` it
        is a ``ResourceWarning`` raised during garbage collection, which pytest reports
        against whatever test was running when the collector ran.

        Call it at the end of any thread that touched this store. The conformance kit
        does it through :meth:`~attest.assurance.conformance.PortConformance.release_thread`.
        """
        connection: sqlite3.Connection | None = getattr(self._local, "connection", None)
        if connection is None:
            return
        self._local.connection = None
        with self._lock:
            self._connections = [entry for entry in self._connections if entry[1] is not connection]
        with _suppress_closed():
            connection.close()

    def __del__(self) -> None:
        """Release the connections when the store is dropped. **Ownership, not tidiness.**

        These connections belong to this object: it opens them, it tracks them, and
        nothing else can reach them. So a store that is garbage-collected without
        ``close()`` leaks a file handle per thread that ever touched it — which in a
        host that builds a store per request is a descriptor leak that ends in
        ``EMFILE``, and in a test suite is a ``ResourceWarning`` raised during
        collection and attributed to whichever test happened to be running.

        That second form is how this was found: a warning surfacing in a witness test,
        three files from the code that caused it, on CI and not locally, because
        finalisation timing differs between interpreter versions. Chasing it through the
        fixtures would have fixed the callers that forgot; this fixes the class of
        omission, and is the correct owner besides.

        Failures are suppressed because this runs during garbage collection, where an
        exception cannot be handled and is merely printed — and a store whose file has
        already gone is not a problem anybody can act on at that point.
        """
        with suppress(Exception):
            self.close()

    def close(self) -> None:
        with self._lock:
            connections = [connection for _, connection in self._connections]
            self._connections.clear()
        for connection in connections:
            with _suppress_closed():
                connection.close()

    # ── NonceStore ───────────────────────────────────────────────────────────

    def redeem(self, nonce: Nonce, grant_id: GrantId) -> bool:
        """Consume ``nonce``. True at most once, guaranteed by the PRIMARY KEY.

        The uniqueness constraint does the work rather than a read-then-write, which
        under concurrency would let several callers all observe an unused nonce.
        """
        connection = self._connect()
        try:
            connection.execute(
                "INSERT INTO redeemed_nonces (nonce, grant_id, redeemed_at) "
                "VALUES (?, ?, datetime('now'))",
                (str(nonce), str(grant_id)),
            )
        except sqlite3.IntegrityError:
            return False
        return True

    def revoke(self, grant_id: GrantId) -> None:
        self._connect().execute(
            "INSERT OR IGNORE INTO revoked_grants (grant_id) VALUES (?)", (str(grant_id),)
        )

    def is_revoked(self, grant_id: GrantId) -> bool:
        row = (
            self._connect()
            .execute("SELECT 1 FROM revoked_grants WHERE grant_id = ?", (str(grant_id),))
            .fetchone()
        )
        return row is not None

    # ── BudgetStore ──────────────────────────────────────────────────────────

    def reserve(
        self, scope: str, amount: str, expires_at: datetime, *, ceiling: str | None = None
    ) -> str | None:
        """Reserve atomically, inside one IMMEDIATE transaction.

        The ceiling check and the insert are in the same transaction, so a second
        writer blocks until the first commits and then sees its reservation. Reading
        the balance and writing later would be the race this exists to prevent.
        """
        connection = self._connect()
        connection.execute("BEGIN IMMEDIATE")
        try:
            if ceiling is not None:
                spent = self._sum("SELECT amount FROM budget_spent WHERE scope = ?", scope)
                held = self._sum("SELECT amount FROM budget_reservations WHERE scope = ?", scope)
                if spent + held + Decimal(amount) > Decimal(ceiling):
                    connection.execute("ROLLBACK")
                    return None
            connection.execute(
                "INSERT INTO budget_sequence (scope, next_id) VALUES (?, 1) "
                "ON CONFLICT(scope) DO UPDATE SET next_id = next_id + 1",
                (scope,),
            )
            sequence = connection.execute(
                "SELECT next_id FROM budget_sequence WHERE scope = ?", (scope,)
            ).fetchone()[0]
            reservation_id = f"res_{scope}_{sequence}"
            connection.execute(
                "INSERT INTO budget_reservations "
                "(reservation_id, scope, amount, expires_at) VALUES (?, ?, ?, ?)",
                (reservation_id, scope, amount, expires_at.isoformat()),
            )
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        return reservation_id

    def _sum(self, query: str, scope: str) -> Decimal:
        rows = self._connect().execute(query, (scope,)).fetchall()
        return sum((Decimal(row[0]) for row in rows), Decimal(0))

    def commit(self, reservation_id: str, actual_amount: str) -> None:
        connection = self._connect()
        connection.execute("BEGIN IMMEDIATE")
        try:
            row = connection.execute(
                "SELECT scope FROM budget_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise StoreError(f"unknown reservation {reservation_id!r}")
            scope = row[0]
            connection.execute(
                "DELETE FROM budget_reservations WHERE reservation_id = ?", (reservation_id,)
            )
            current = self._sum("SELECT amount FROM budget_spent WHERE scope = ?", scope)
            connection.execute(
                "INSERT INTO budget_spent (scope, amount) VALUES (?, ?) "
                "ON CONFLICT(scope) DO UPDATE SET amount = excluded.amount",
                (scope, str(current + Decimal(actual_amount))),
            )
            connection.execute("COMMIT")
        except StoreError:
            raise
        except Exception:
            connection.execute("ROLLBACK")
            raise

    def release(self, reservation_id: str) -> None:
        self._connect().execute(
            "DELETE FROM budget_reservations WHERE reservation_id = ?", (reservation_id,)
        )

    def spent(self, scope: str) -> str:
        return str(self._sum("SELECT amount FROM budget_spent WHERE scope = ?", scope))

    # ── AuditSink ────────────────────────────────────────────────────────────

    def append(self, event: AuditEvent) -> None:
        """Append one event, **as an event** rather than as a spread of columns.

        Taking ``AuditEvent`` is what makes this an ``AuditSink``. The previous shape
        took six keyword arguments and could not be handed to the engine at all: the
        Protocol is ``runtime_checkable``, so ``isinstance`` passed on the method name
        while every call site would have raised.
        """
        try:
            self._connect().execute(
                "INSERT INTO audit_events "
                "(run_id, event_type, occurred_at, payload, sequence, previous_hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(event.run_id),
                    str(event.event_type),
                    event.occurred_at.isoformat(),
                    AuditEventCodec.encode(event),
                    None,
                    None,
                ),
            )
        except sqlite3.DatabaseError as exc:
            raise AuditSinkError(f"could not append audit event: {exc}") from exc

    def append_many(self, events: Sequence[AuditEvent]) -> None:
        """Append a batch atomically.

        A partial batch leaves a chain that cannot be sealed densely, which on
        inspection is indistinguishable from omission — the exact condition the seal
        exists to detect. ``IMMEDIATE`` takes the write lock up front rather than on
        first write.
        """
        if not events:
            return
        connection = self._connect()
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.executemany(
                "INSERT INTO audit_events "
                "(run_id, event_type, occurred_at, payload, sequence, previous_hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (
                        str(event.run_id),
                        str(event.event_type),
                        event.occurred_at.isoformat(),
                        AuditEventCodec.encode(event),
                        None,
                        None,
                    )
                    for event in events
                ],
            )
            connection.execute("COMMIT")
        except sqlite3.DatabaseError as exc:
            connection.execute("ROLLBACK")
            raise AuditSinkError(f"could not append audit batch: {exc}") from exc

    def read_chain(self, run_id: RunId) -> Sequence[AuditEvent]:
        """The run's events, decoded. **Unsealed**, in insertion order.

        Positions are not stored, so nothing here can disagree with the sealer. A
        payload edited in the database fails to decode rather than coming back as a
        plausible event that says something else.
        """
        rows = (
            self._connect()
            .execute(
                "SELECT payload FROM audit_events WHERE run_id = ? ORDER BY id",
                (str(run_id),),
            )
            .fetchall()
        )
        return tuple(AuditEventCodec.decode(bytes(row[0])) for row in rows)

    # ── RunStore ─────────────────────────────────────────────────────────────

    def create(self, attestation: Attestation) -> RunId:
        try:
            self._connect().execute(
                "INSERT INTO attestations (run_id, content_hash, payload) VALUES (?, ?, ?)",
                (
                    str(attestation.run_id),
                    str(attestation.content_hash()),
                    AttestationCodec.encode(attestation),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StoreError(
                f"attestation {attestation.run_id!r} already exists. Attestations are "
                f"immutable; a correction is a new record via supersede()."
            ) from exc
        return attestation.run_id

    def get(self, run_id: RunId) -> Attestation | None:
        """The stored attestation, verified against its own content hash by the codec.

        A row whose payload no longer hashes to what was recorded raises rather than
        returning: a record that reads back cleanly after being altered is the failure
        this system exists to make impossible.
        """
        row = (
            self._connect()
            .execute("SELECT payload FROM attestations WHERE run_id = ?", (str(run_id),))
            .fetchone()
        )
        return None if row is None else AttestationCodec.decode(bytes(row[0]))

    def supersede(self, run_id: RunId, replacement: Attestation) -> RunId:
        connection = self._connect()
        connection.execute("BEGIN IMMEDIATE")
        try:
            existing = connection.execute(
                "SELECT 1 FROM attestations WHERE run_id = ?", (str(run_id),)
            ).fetchone()
            if existing is None:
                connection.execute("ROLLBACK")
                raise StoreError(f"cannot supersede unknown run {run_id!r}")
            already = connection.execute(
                "SELECT content_hash FROM attestations WHERE run_id = ?",
                (str(replacement.run_id),),
            ).fetchone()
            if already is not None and already[0] != str(replacement.content_hash()):
                # As in the Django store: `if not exists: insert` silently skipped a
                # replacement id already holding different content, so the caller
                # believed their correction was stored while a different record sat
                # under that id. Identical content is an idempotent retry.
                connection.execute("ROLLBACK")
                raise StoreError(
                    f"attestation {replacement.run_id!r} already exists with different "
                    f"content. Refusing rather than reporting a supersession that "
                    f"stored nothing."
                )
            if already is None:
                connection.execute(
                    "INSERT INTO attestations (run_id, content_hash, payload) VALUES (?, ?, ?)",
                    (
                        str(replacement.run_id),
                        str(replacement.content_hash()),
                        AttestationCodec.encode(replacement),
                    ),
                )
            # Only the pointer is updated; the trigger still forbids touching the
            # content, so the original stays exactly as a reader saw it.
            connection.execute(
                "UPDATE attestations SET superseded_by = ? WHERE run_id = ?",
                (str(replacement.run_id), str(run_id)),
            )
            connection.execute("COMMIT")
        except StoreError:
            raise
        except Exception:
            connection.execute("ROLLBACK")
            raise
        return replacement.run_id


class _suppress_closed:
    """Ignore errors from closing an already-closed connection."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return exc_type is not None and issubclass(exc_type, sqlite3.Error)  # type: ignore[arg-type]
