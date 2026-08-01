"""The shipped Django adapters, run through the conformance kit they ask hosts to pass.

A framework whose adoption story is "write an adapter" and whose own adapters do not
pass its adapter suite is asking for a standard it does not meet. These are the same
classes a host inherits, with no exemptions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from attest.adapters.django.stores import (
    DjangoApprovalStore,
    DjangoAuditSink,
    DjangoBudgetStore,
    DjangoMemoryStore,
    DjangoNonceStore,
    DjangoRunQueue,
    DjangoRunStore,
)
from attest.assurance.conformance import (
    ApprovalStoreConformance,
    AuditSinkConformance,
    BudgetStoreConformance,
    MemoryStoreConformance,
    NonceStoreConformance,
    RunStoreConformance,
    RunWorkQueueConformance,
)

if TYPE_CHECKING:
    from attest.kernel.ports import (
        ApprovalStore,
        AuditSink,
        BudgetStore,
        MemoryStore,
        NonceStore,
        RunStore,
        RunWorkQueue,
    )

pytestmark = pytest.mark.contract


class ReleasesConnections:
    """Closes the ORM connection a spawned thread opened.

    Django's connection handle is thread-local, so a thread that touches the ORM and
    exits leaves an unclosed SQLite handle for the garbage collector. That emits
    ``ResourceWarning: unclosed database``, and under this project's
    ``filterwarnings = ["error"]`` it becomes a ``PytestUnraisableExceptionWarning``
    raised *during collection* — attributed to whichever test was running at the time.

    It surfaced on CI and never locally, as three failures in files with nothing to do
    with the store: a kernel action test, a queue test, and a SQLite conformance test.
    Chasing that from the symptom is expensive, which is why the hook is on the kit and
    this mixin is one line rather than a note somebody has to find.

    .. rubric:: What it does not achieve on this suite, and why that is Django's call

    Django's SQLite backend ignores ``close()`` when the database is in memory, on the
    grounds that closing it would destroy the database. This suite's default is
    ``:memory:``, so the call is a deliberate no-op here and a few worker handles remain
    open — bounded by thread count, non-fatal, and gone with the process.

    The hook is not decorative because of that. Against a **real** database it does
    exactly what it says, and that is the case that matters: the PostgreSQL and MySQL
    jobs run this same suite, and both the deadlock and the leak that produced this
    mixin were found there. Removing it because it is quiet on SQLite would drop the
    cleanup on the two databases a production adopter actually runs.
    """

    def release_thread(self) -> None:
        from django.db import connection

        connection.close()


class TestDjangoRunStore(ReleasesConnections, RunStoreConformance):
    def store(self) -> RunStore:
        return DjangoRunStore()


class TestDjangoAuditSink(ReleasesConnections, AuditSinkConformance):
    def store(self) -> AuditSink:
        return DjangoAuditSink()


class TestDjangoNonceStore(ReleasesConnections, NonceStoreConformance):
    def store(self) -> NonceStore:
        return DjangoNonceStore()

    # SQLite locks the whole database on write, so sixteen threads racing a single
    # INSERT spend the test in lock contention rather than in the code under test.
    # The property being checked — exactly one winner — holds at four.
    CONCURRENT_REDEMPTIONS = 4


class TestDjangoApprovalStore(ReleasesConnections, ApprovalStoreConformance):
    def store(self) -> ApprovalStore:
        return DjangoApprovalStore()


class TestDjangoMemoryStore(ReleasesConnections, MemoryStoreConformance):
    def store(self) -> MemoryStore:
        return DjangoMemoryStore()


class TestDjangoBudgetStore(ReleasesConnections, BudgetStoreConformance):
    def store(self) -> BudgetStore:
        # The ceiling lives in a row rather than a constructor argument here, which is
        # the right place for it — a limit configured in code is a limit a deployment
        # cannot change without a release.
        from attest.adapters.django.models import BudgetSpend

        for scope in (BudgetStoreConformance.SCOPE, BudgetStoreConformance.CONCURRENT_SCOPE):
            BudgetSpend.objects.update_or_create(
                scope=scope, defaults={"ceiling": BudgetStoreConformance.CEILING}
            )
        return DjangoBudgetStore()

    # As above: SQLite serialises writers, so the contention is in the database rather
    # than in reserve(). Four concurrent runs against a ceiling that fits three is
    # still a race that a read-then-write implementation loses.
    CONCURRENT_RESERVATIONS = 4


class TestDjangoRunQueue(ReleasesConnections, RunWorkQueueConformance):
    def store(self) -> RunWorkQueue:
        return DjangoRunQueue()

    CONCURRENT_WORKERS = 4
