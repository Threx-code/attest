"""A minimal Django project, configured in-process.

``pytest-django`` is deliberately not a dependency. It would be a second test runner's
worth of behaviour in the release gate of a package whose core never imports Django,
and everything needed here is three calls: configure, set up a test database, and wrap
each test in a transaction that rolls back.

The database is real SQLite rather than a mock, because the guarantees under test are
**triggers**. A mocked database would let every one of these tests pass against a
schema with no enforcement at all — which is precisely the failure mode they exist to
rule out.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

import pytest

from attest.assurance.builders import Build as Shipped
from attest.capabilities.audit import ChainSealer
from attest.kernel.attestation import Attestation
from attest.kernel.audit import AuditEvent, EventType
from attest.kernel.context import (
    ExecutionContext,
)
from attest.kernel.identifiers import RunId, TenantId
from attest.kernel.verdicts import Verdict
from attest.kernel.warrants import (
    Severity,
    WarrantKinds,
    WarrantStatus,
)

django = pytest.importorskip("django")
pytest.importorskip("rest_framework")

from django.conf import settings  # noqa: E402

#: Which database these tests run against. ``sqlite`` unless ``ATTEST_TEST_DB`` says
#: otherwise.
#:
#: The guarantees under test are **triggers**, and a trigger is vendor-specific DDL.
#: ``triggers.py`` carries three implementations — SQLite, PostgreSQL and MySQL — and
#: only one of them had ever run. The other two were reviewed, covered by a test that
#: asserts the generated SQL *contains* the words ``BEFORE UPDATE``, and had never
#: touched a database. That test checks the artefact; the artefact is not the control.
#:
#: This matters more here than almost anywhere else in the package. The append-only
#: audit chain and immutable attestations are not application promises — the whole
#: argument in ``docs/adapters/django.md`` is that "we only ever INSERT" is a convention
#: and conventions decay, so enforcement lives below the application. A production
#: adopter runs PostgreSQL. Shipping unexecuted PostgreSQL DDL means the one guarantee
#: that is supposed to be structural was, for them, a string in a migration file.
DATABASE = os.environ.get("ATTEST_TEST_DB", "sqlite").strip().lower()


def _database_config() -> dict[str, Any]:
    """The ``DATABASES["default"]`` entry for :data:`DATABASE`.

    **Raises on an unrecognised value rather than falling back to SQLite.** That is the
    whole point of the function. A silent fallback would let a CI job named
    "postgres" go green having exercised SQLite, which is worse than not running the
    job: it is a green tick asserting the thing it did not test.
    """
    if DATABASE == "sqlite":
        return {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
    if DATABASE in {"postgres", "postgresql"}:
        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("ATTEST_TEST_DB_NAME", "attest"),
            "USER": os.environ.get("ATTEST_TEST_DB_USER", "attest"),
            "PASSWORD": os.environ.get("ATTEST_TEST_DB_PASSWORD", "attest"),
            "HOST": os.environ.get("ATTEST_TEST_DB_HOST", "127.0.0.1"),
            "PORT": os.environ.get("ATTEST_TEST_DB_PORT", "5432"),
        }
    if DATABASE == "mysql":
        return {
            "ENGINE": "django.db.backends.mysql",
            "NAME": os.environ.get("ATTEST_TEST_DB_NAME", "attest"),
            "USER": os.environ.get("ATTEST_TEST_DB_USER", "attest"),
            "PASSWORD": os.environ.get("ATTEST_TEST_DB_PASSWORD", "attest"),
            "HOST": os.environ.get("ATTEST_TEST_DB_HOST", "127.0.0.1"),
            "PORT": os.environ.get("ATTEST_TEST_DB_PORT", "3306"),
        }
    raise RuntimeError(
        f"ATTEST_TEST_DB={DATABASE!r} is not one of sqlite, postgres, mysql. Refusing "
        f"to fall back to SQLite: a job that believes it is testing PostgreSQL triggers "
        f"and silently tests SQLite ones is worse than a job that does not run."
    )


if not settings.configured:
    settings.configure(
        SECRET_KEY="attest-tests-only",
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "django.contrib.messages",
            "django.contrib.sessions",
            "django.contrib.admin",
            "rest_framework",
            "attest.adapters.django",
        ],
        DATABASES={"default": _database_config()},
        MIDDLEWARE=[],
        ROOT_URLCONF="attest.adapters.django.urls",
        TEMPLATES=[
            {
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "APP_DIRS": True,
                "OPTIONS": {
                    "context_processors": [
                        "django.contrib.auth.context_processors.auth",
                        "django.contrib.messages.context_processors.messages",
                    ]
                },
            }
        ],
        USE_TZ=True,
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        ATTEST={"BRAND": "acme"},
    )
    django.setup()


@pytest.fixture(scope="session", autouse=True)
def _database() -> Iterator[None]:
    """One migrated database for the session — including the trigger migration."""
    from django.test.utils import setup_databases, teardown_databases

    config = setup_databases(verbosity=0, interactive=False)
    yield
    teardown_databases(config, verbosity=0)


@pytest.fixture(autouse=True)
def _rollback(request: pytest.FixtureRequest) -> Iterator[None]:
    """Each test in its own transaction, rolled back afterwards.

    **Except a concurrency test**, which is committed. A spawned thread is a separate
    connection, and on a real database it can neither see nor lock rows an uncommitted
    transaction holds — so wrapping one of these in a rollback does not isolate it, it
    deadlocks it. `BudgetStoreConformance`'s `SELECT … FOR UPDATE` race hung forever
    against PostgreSQL for exactly that reason, and would have hung the CI job that runs
    this suite against a real database. A hanging job is worse than a failing one: it
    burns the runner and reports nothing.

    SQLite never showed it. One in-memory database behind one connection has no separate
    session to block against, so the wrapper looked correct for as long as nothing real
    was underneath it.

    The kit's concurrency tests use their own scopes and ids for this reason — see
    `BudgetStoreConformance.CONCURRENT_SCOPE` — so committing them cannot perturb the
    sequential tests that share the table.
    """
    from django.db import transaction

    if request.node.get_closest_marker("concurrency") is not None:
        try:
            yield
        finally:
            _clear_committed()
        return

    atomic = transaction.atomic()
    atomic.__enter__()
    try:
        yield
    finally:
        transaction.set_rollback(True)
        atomic.__exit__(None, None, None)


def _clear_committed() -> None:
    """Remove what a committed concurrency test left behind.

    Committing fixes the deadlock and creates a second problem: the rows survive into
    every later test, and several of them assert on **global** state — queue depth,
    `reclaim_expired()` over everything outstanding. Four queue tests failed the first
    time this ran against PostgreSQL, on rows named `race_r0` that a conformance test in
    another file had committed.

    Only the mutable tables are listed, and that is not an oversight. The append-only
    ones cannot be cleared by design — a DELETE on `attest_audit_events` is refused by
    the trigger this suite exists to prove works — so the concurrency tests that touch
    them use ids nothing else asserts on, and the residue is inert.

    `attest_dispatch_events` was on this list for one run, and the PostgreSQL trigger
    threw it straight back: *"attest_dispatch_events is append-only (attempted DELETE)"*.
    That is the guard doing its job to the test harness, and it is worth leaving in the
    record — the docstring already said that adding a protected table here would fail
    loudly, and then it did, three minutes later.
    """
    from attest.adapters.django.models import BudgetReservation, BudgetSpend, QueuedRun

    QueuedRun.objects.all().delete()
    BudgetReservation.objects.all().delete()
    BudgetSpend.objects.all().delete()


@pytest.fixture
def now() -> datetime:
    from django.utils import timezone

    stamp: datetime = timezone.now()
    return stamp


# ── Builders ─────────────────────────────────────────────────────────────────
#
# Real kernel objects, not stand-ins shaped like them. The stores speak the ports
# now, so a test that fed them a convenient dict would be exercising a store that
# does not exist.


class Build:
    """The Django suite's calling convention over the **shipped** builders.

    Every value here comes from :class:`attest.assurance.builders.Build`. This class
    contributes exactly one thing the shipped builders deliberately do not: it threads
    ``at`` as a leading positional argument, because these tests persist rows into a
    real database and need a session's records ordered against each other, where a
    fixture used in isolation wants a fixed instant so it is reproducible.

    It used to be a **second implementation** — its own context, its own warrant, its
    own idea of what fields an attestation needs. That is the divergence the conformance
    kit exists to catch between two adapters behind one port, sitting in the test suite
    that runs the kit. Two definitions of "a valid attestation" drift, and the one that
    drifts is the one nobody is testing.
    """

    @staticmethod
    def context(at: datetime, run_id: str = "run_1", tenant: str = "t1") -> ExecutionContext:
        return Shipped.context(run_id, at=at, tenant=TenantId(tenant))

    @staticmethod
    def attestation(
        at: datetime,
        run_id: str = "run_1",
        tenant: str = "t1",
        *,
        verdict: Verdict = Verdict.ALLOW,
        warnings: tuple[str, ...] = (),
        pending: bool = False,
        **overrides: Any,
    ) -> Attestation:
        """``warnings`` and ``pending`` are this suite's own shorthand.

        Both describe a *warrant*, and the shipped builder takes warrant reports — so
        they are translated here rather than pushed down. A `pending` flag on a general
        builder would invite exactly the conflation the kernel forbids: an unsatisfied
        warrant and an unevaluated one are different things.
        """
        status = WarrantStatus.PENDING if pending else WarrantStatus.EVALUATED
        reports = {
            WarrantKinds.EPISTEMIC: Shipped.warrant(
                WarrantKinds.EPISTEMIC,
                satisfied=not pending,
                status=status,
                findings=tuple((message, Severity.WARNING) for message in warnings),
            )
        }
        fields: dict[str, Any] = {
            "answer": "the figure is 4",
            "warrants": reports,
            # These tests assert on stored rows, and a seal is not what they are about.
            # The one test that needs a sealed record uses `sealed()` below, which
            # produces a real one over real events.
            "sealed": False,
        }
        fields.update(overrides)
        return Shipped.attestation(
            run_id, verdict=verdict, at=at, tenant=TenantId(tenant), **fields
        )

    @staticmethod
    def event(
        at: datetime, run_id: str = "run_1", event_type: str = EventType.RUN_DISPATCHED.value
    ) -> AuditEvent:
        return Shipped.event(event_type, run_id=run_id, at=at)

    @staticmethod
    def sealed(at: datetime, run_id: str = "run_1", tenant: str = "t1", count: int = 3) -> Sealed:
        """A sealed attestation, and the **unsealed** events a sink actually holds.

        The sink stores causal structure; the sealer assigns positions afterwards. So
        ``events`` is what gets persisted and ``sealed`` is what the seal was taken
        over — a fixture that persisted the sealed copies would be testing a sink that
        numbers its own rows.

        The seal is computed by :class:`~attest.capabilities.audit.ChainSealer` over
        those events rather than built by hand, so it is a seal that actually verifies.
        """
        draft = Build.attestation(at, run_id=run_id, tenant=tenant)
        events = tuple(Build.event(at, run_id=run_id, event_type=f"step.{n}") for n in range(count))
        sealed_events, seal = ChainSealer().seal(
            events,
            run_id=RunId(run_id),
            attestation_hash=draft.content_hash(),
            sealed_at=at,
        )
        return Sealed(replace(draft, seal=seal), events, sealed_events)


@dataclass(frozen=True)
class Sealed:
    attestation: Attestation
    events: tuple[AuditEvent, ...]
    """Unsealed, as a sink receives them."""

    sealed: tuple[AuditEvent, ...] = ()
    """The same events with canonical positions assigned."""


@pytest.fixture
def build() -> type[Build]:
    return Build


@pytest.fixture
def sealed_run(now: datetime) -> Attestation:
    """A sealed, final attestation whose chain is already persisted and verifies."""
    from attest.adapters.django.stores import DjangoAuditSink, DjangoRunStore

    made = Build.sealed(now, run_id="run_sealed")
    DjangoAuditSink().append_many(made.events)
    DjangoRunStore().create(made.attestation)
    return made.attestation
