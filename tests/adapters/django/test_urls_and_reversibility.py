"""The mountable routes, and the migration's reverse path.

A trigger migration that cannot be reversed is one nobody dares apply to a production
database, so the down path is exercised rather than assumed.
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from attest.adapters.django import urls
from attest.adapters.django.triggers import AppendOnlyTable, ImmutableColumns

pytestmark = pytest.mark.unit


def test_the_router_exposes_both_collections() -> None:
    registered = {prefix for prefix, _, _ in urls.ROUTER.registry}
    assert registered == {"attestations", "pending-actions"}


def test_the_routes_reverse() -> None:
    """Names are unprefixed here because this URLconf is mounted at the root.

    A host that ``include()``s it under a namespace reverses them as
    ``attest:attestation-list`` — the ``app_name`` in the module is what makes that
    available without the host having to name it.
    """
    assert urls.app_name == "attest"
    assert reverse("attestation-list") == "/attestations/"
    assert reverse("pending-action-list") == "/pending-actions/"


class _Recorder:
    """Captures the SQL a migration operation would run."""

    def __init__(self, vendor: str) -> None:
        # `alias` because every real Django connection has one: `_router_blocks` asks the
        # database router which schema this operation belongs in, and the router is keyed by
        # alias. A double that omits it is a double that cannot meet the code it stands in for.
        self.connection = type("Connection", (), {"vendor": vendor, "alias": "default"})()
        self.statements: list[str] = []

    def execute(self, statement: str) -> None:
        self.statements.append(statement)


@pytest.mark.parametrize("vendor", ["sqlite", "postgresql", "mysql"])
def test_every_guard_can_be_dropped_again(vendor: str) -> None:
    for operation in (
        AppendOnlyTable("attest_audit_events"),
        ImmutableColumns("attest_attestations", ["payload"]),
    ):
        recorder = _Recorder(vendor)
        operation.database_backwards("attest", recorder, None, None)
        assert recorder.statements
        assert all("DROP TRIGGER" in statement for statement in recorder.statements)


def test_an_operation_describes_itself_for_the_migration_plan() -> None:
    assert "append-only" in AppendOnlyTable("attest_audit_events").describe()
    assert "Freeze" in ImmutableColumns("attest_attestations", ["payload"]).describe()


def test_an_operation_round_trips_through_deconstruction() -> None:
    """Django serialises operations into migration files; ours must survive that."""
    name, args, kwargs = AppendOnlyTable("t").deconstruct()
    assert (name, args, kwargs) == ("AppendOnlyTable", ["t"], {"prefix": "attest"})
    rebuilt = AppendOnlyTable(*args, **kwargs)
    assert rebuilt.migration_name_fragment == "append_only_t"

    name, args, kwargs = ImmutableColumns("t", ["a"]).deconstruct()
    assert (name, args, kwargs) == ("ImmutableColumns", ["t", ["a"]], {"prefix": "attest"})
    assert ImmutableColumns(*args, **kwargs).migration_name_fragment == "immutable_t"


def test_state_forwards_records_nothing_so_the_autodetector_stays_quiet() -> None:
    """A trigger is not model state; teaching Django otherwise causes phantom migrations."""
    state = object()
    AppendOnlyTable("t").state_forwards("attest", state)
    assert not hasattr(state, "models"), "the migration state must be left untouched"
