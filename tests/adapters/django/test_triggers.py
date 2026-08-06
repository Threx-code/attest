"""The guarantees the application cannot make about itself.

Every assertion here would still pass if the triggers were absent *and* every write
went through the store classes. That is why they are written against the ORM directly:
the contract is that a mutation fails whichever code path attempts it, including a data
fix typed into a shell at 3am.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from django.db import DatabaseError, transaction

from attest.adapters.django.models import (
    AttestationRecord,
    AuditEventRecord,
    RedeemedNonce,
)

pytestmark = [pytest.mark.security, pytest.mark.contract]

# `DatabaseError`, not `IntegrityError`. The guarantee is "the database refused the
# mutation"; which exception class carries that refusal is the *vendor's* choice, and the
# vendors disagree. SQLite's `RAISE(ABORT, ...)` surfaces as IntegrityError; PostgreSQL's
# `RAISE EXCEPTION` is SQLSTATE P0001, which Django maps to ProgrammingError; MySQL's
# `SIGNAL SQLSTATE '45000'` is another again.
#
# Pinning IntegrityError therefore tested SQLite's error taxonomy rather than the
# append-only property — and every one of these tests failed the first time the suite met
# a real PostgreSQL, with the trigger firing correctly in the traceback. That is the
# mechanism being asserted where the outcome was meant to be, in the file whose whole
# subject is that the database refuses.
#
# `DatabaseError` is their common base, so this asserts what the tests are actually about
# and stays true on all three.


@pytest.fixture
def attestation(now: datetime) -> Any:
    return AttestationRecord.objects.create(
        run_id="run_trigger",
        tenant_id="t1",
        verdict="allow_with_warnings",
        answer="the figure is 4",
        warnings=["source superseded"],
        content_hash="a" * 64,
        payload=b"{}",
        created_at=now,
    )


def test_an_attestation_cannot_be_edited_through_the_orm(attestation: Any) -> None:
    """Not "the store refuses" — the database refuses."""
    with pytest.raises(DatabaseError), transaction.atomic():
        AttestationRecord.objects.filter(pk=attestation.pk).update(answer="the figure is 40")


def test_the_warnings_on_an_attestation_cannot_be_quietly_removed(attestation: Any) -> None:
    """Dropping the qualification is the misstatement this framework exists to prevent."""
    with pytest.raises(DatabaseError), transaction.atomic():
        AttestationRecord.objects.filter(pk=attestation.pk).update(warnings=[])


def test_the_supersede_pointer_remains_writable(attestation: Any) -> None:
    """A correction must be able to point forward without rewriting the original."""
    AttestationRecord.objects.filter(pk=attestation.pk).update(superseded_by="run_2")
    attestation.refresh_from_db()
    assert attestation.superseded_by == "run_2"
    assert attestation.answer == "the figure is 4"


def test_an_audit_event_cannot_be_updated(now: datetime) -> None:
    event = AuditEventRecord.objects.create(
        run_id="run_1", event_type="start", occurred_at=now, payload=b"x"
    )
    with pytest.raises(DatabaseError), transaction.atomic():
        AuditEventRecord.objects.filter(pk=event.pk).update(event_type="something_else")


def test_an_audit_event_cannot_be_deleted(now: datetime) -> None:
    """The attack the seal's dense sequence exists to catch, made impossible earlier."""
    AuditEventRecord.objects.create(
        run_id="run_1", event_type="effect", occurred_at=now, payload=b"x"
    )
    with pytest.raises(DatabaseError), transaction.atomic():
        AuditEventRecord.objects.filter(run_id="run_1").delete()


def test_a_redeemed_nonce_cannot_be_deleted_to_permit_a_replay(now: datetime) -> None:
    """Deleting the redemption record would restore the grant's single use."""
    RedeemedNonce.objects.create(nonce="n1", grant_id="g1", redeemed_at=now)
    with pytest.raises(DatabaseError), transaction.atomic():
        RedeemedNonce.objects.filter(pk="n1").delete()


class _RecordingEditor:
    """A schema editor that captures SQL instead of running it."""

    def __init__(self, vendor: str = "postgresql", alias: str = "default") -> None:
        self.connection = type("Connection", (), {"vendor": vendor, "alias": alias})()
        self.statements: list[str] = []

    def execute(self, statement: str) -> None:
        self.statements.append(statement)


def test_the_router_decides_which_schema_a_guard_belongs_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A guard operation is skipped where the router says its app does not live.

    Django's own ``RunSQL`` and ``RunPython`` consult the router before touching anything.
    A custom :class:`Operation` that does not is invisible to routing and runs everywhere -
    which is fine until a router has something to say.

    Under ``django-tenants`` it does: apps are split between a shared ``public`` schema and one
    per tenant, and a guard belonging to a tenant app must not be installed while ``public`` is
    being migrated, because the table it guards is not there.

    .. code-block:: text

        django.db.utils.ProgrammingError: relation "attest_audit_events" does not exist

    That failed ``migrate_schemas --shared``, which is the first command a cloud deployment
    runs, so the whole install could not be built.
    """
    from django.db import router

    from attest.adapters.django.triggers import AppendOnlyTable

    monkeypatch.setattr(router, "allow_migrate", lambda *a, **k: False)
    editor = _RecordingEditor()

    AppendOnlyTable("attest_audit_events").database_forwards("attest", editor, None, None)
    AppendOnlyTable("attest_audit_events").database_backwards("attest", editor, None, None)

    assert editor.statements == []


def test_a_permissive_router_still_installs_the_guard() -> None:
    """The other half. A test that only asserts refusal passes when everything is refused."""
    from attest.adapters.django.triggers import AppendOnlyTable

    editor = _RecordingEditor()

    AppendOnlyTable("attest_audit_events").database_forwards("attest", editor, None, None)

    assert editor.statements
    assert any("CREATE" in statement.upper() for statement in editor.statements)


def test_a_refused_vendor_is_not_reached_when_the_router_skips_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Order matters: routing is asked FIRST.

    ``_vendor`` raises for a database attest ships no trigger for, deliberately - a migration
    that quietly did nothing would leave a deployment believing it had enforcement it does not.
    But that refusal is about a schema this operation is actually meant to be in. Asking the
    vendor before the router would turn "this app does not live here" into a hard failure on
    an unsupported backend the operation was never going to touch.
    """
    from django.db import router

    from attest.adapters.django.triggers import AppendOnlyTable

    monkeypatch.setattr(router, "allow_migrate", lambda *a, **k: False)
    editor = _RecordingEditor(vendor="oracle")

    AppendOnlyTable("attest_audit_events").database_forwards("attest", editor, None, None)

    assert editor.statements == []


def test_an_unsupported_vendor_raises_rather_than_silently_skipping() -> None:
    """A migration that quietly did nothing would leave a false sense of enforcement."""
    from attest.adapters.django.triggers import AppendOnlyTable

    class _Connection:
        vendor = "oracle"
        alias = "default"

    class _Editor:
        connection = _Connection()

    with pytest.raises(NotImplementedError, match="oracle"):
        AppendOnlyTable("attest_audit_events").database_forwards("attest", _Editor(), None, None)


@pytest.mark.parametrize("vendor", ["sqlite", "postgresql", "mysql"])
def test_every_supported_vendor_emits_both_a_guard_for_update_and_for_delete(vendor: str) -> None:
    from attest.adapters.django.triggers import AppendOnlyTable, ImmutableColumns

    append_only = " ".join(AppendOnlyTable("t")._install(vendor)).upper()
    assert "UPDATE" in append_only
    assert "DELETE" in append_only

    immutable = " ".join(ImmutableColumns("t", ["a", "b"])._install(vendor)).upper()
    assert "UPDATE" in immutable


# ── Which database did this actually run against? ────────────────────────────


def test_the_suite_ran_against_the_database_it_was_told_to() -> None:
    """A green "postgres" job that exercised SQLite is worse than no job at all.

    Everything above is vendor-agnostic by design: the same assertions, whichever
    database is underneath. That is the strength of the file and also its one hazard —
    nothing in it would notice if the vendor silently fell back. This test is what makes
    the other assertions mean what the CI job name says they mean.
    """
    from django.db import connection
    from tests.adapters.django.conftest import DATABASE

    expected = {
        "sqlite": "sqlite",
        "postgres": "postgresql",
        "postgresql": "postgresql",
        "mysql": "mysql",
    }[DATABASE]
    assert connection.vendor == expected, (
        f"ATTEST_TEST_DB={DATABASE!r} but the connection is {connection.vendor!r}. "
        f"Every trigger test above just passed against the wrong database."
    )


def test_the_guards_are_installed_in_the_database_not_merely_in_the_migration() -> None:
    """The migration ran. Ask the database, not the migration file.

    ``test_every_supported_vendor_emits_both_a_guard_for_update_and_for_delete`` checks
    that the generated SQL *contains* the words. That is the artefact. This asks the
    catalogue what is actually installed, which is the control — and it is the check
    that had never run for PostgreSQL or MySQL at all, because neither had ever been
    connected to.
    """
    from django.db import connection

    with connection.cursor() as cursor:
        if connection.vendor == "sqlite":
            cursor.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        elif connection.vendor == "postgresql":
            cursor.execute("SELECT tgname FROM pg_trigger WHERE NOT tgisinternal")
        else:
            cursor.execute("SELECT trigger_name FROM information_schema.triggers")
        installed = {str(row[0]).lower() for row in cursor.fetchall()}

    for table in ("attest_audit_events", "attest_attestations", "attest_redeemed_nonces"):
        guards = {name for name in installed if table in name}
        assert guards, (
            f"no guard is installed on {table!r} in this {connection.vendor} database. "
            f"The append-only and immutability guarantees are the ones docs/adapters/"
            f"django.md says are enforced BELOW the application; here they are enforced "
            f"nowhere."
        )
