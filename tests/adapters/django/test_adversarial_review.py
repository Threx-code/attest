"""Adversarial-review regressions that need a configured Django app.

Kept beside the rest of the Django suite rather than with the other regressions,
because the conftest here is what makes the app registry exist. The findings they
guard are described in ``tests/test_adversarial_review.py``.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from attest.adapters.django.serializers import RunResultSerializer
from attest.adapters.django.stores import DjangoBudgetStore, DjangoRunStore
from attest.kernel.attestation import Attestation
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.errors import StoreError
from attest.kernel.identifiers import ActorId, Hash, RunId, TenantId
from attest.kernel.verdicts import Verdict
from attest.kernel.warrants import (
    Finding,
    Severity,
    WarrantKinds,
    WarrantReport,
    WarrantStatus,
)

pytestmark = pytest.mark.security


def qualified(at: datetime) -> Attestation:
    return Attestation(
        run_id=RunId("run_1"),
        verdict=Verdict.ALLOW_WITH_WARNINGS,
        context=ExecutionContext(
            run_id=RunId("run_1"),
            captured_at=at,
            identity=IdentitySnapshot(actor=ActorId("alice"), tenant=TenantId("t1")),
            binding=TenantBinding(
                tenant=TenantId("t1"),
                profile=ProfileRef(name="generic", version="1.0.0"),
                config_hash=Hash("c" * 64),
            ),
            framework_version="0.1.0",
            policy_version="2026.07",
        ),
        created_at=at,
        warrants={
            WarrantKinds.EPISTEMIC: WarrantReport(
                kind=WarrantKinds.EPISTEMIC,
                status=WarrantStatus.EVALUATED,
                satisfied=True,
                findings=(
                    Finding(
                        code="a", message="the source was superseded", severity=Severity.WARNING
                    ),
                    Finding(code="b", message="noise", severity=Severity.INFO),
                ),
            )
        },
    )


def test_the_store_and_the_serialiser_agree_on_what_a_warning_is(now: datetime) -> None:
    """One definition of *which* findings count, so the two cannot diverge.

    Compared under the operator profile, which is the apples-to-apples case: the
    subject profile deliberately renders the same findings as codes.
    """
    from attest.assurance.export import DisclosureProfile

    attestation = qualified(now)
    expected = ["the source was superseded"]
    assert DjangoRunStore.warnings_of(attestation) == expected
    operator = RunResultSerializer(disclosure=DisclosureProfile.INTERNAL)
    assert operator.warnings_of(attestation) == expected


def test_the_subject_profile_renders_the_same_findings_without_their_messages(
    now: datetime,
) -> None:
    """Never withheld entirely — a warning nobody can see does not exist — and never
    narrated back to the person the decision was about."""
    subject = RunResultSerializer().warnings_of(qualified(now))
    assert subject == ["epistemic:a"]


def test_a_released_reservation_id_is_never_reissued(now: datetime) -> None:
    """A swept worker waking up must not commit against somebody else's hold."""
    store = DjangoBudgetStore()
    store.set_ceiling("tenant:seq", "1000.00")
    first = store.reserve("tenant:seq", "10.00", now + timedelta(minutes=5))
    assert first is not None
    store.release(first)
    second = store.reserve("tenant:seq", "10.00", now + timedelta(minutes=5))
    assert second is not None
    assert first != second


def test_a_stale_commit_cannot_consume_a_live_reservation(now: datetime) -> None:
    """The failure the reused id produced: a 900 hold released by a 10 commit."""
    store = DjangoBudgetStore()
    store.set_ceiling("tenant:stale", "1000.00")
    stale = store.reserve("tenant:stale", "10.00", now - timedelta(seconds=1))
    assert stale is not None
    store.expire_due(now)  # the sweep releases the hung worker's hold

    live = store.reserve("tenant:stale", "900.00", now + timedelta(minutes=5))
    assert live is not None
    with pytest.raises(StoreError, match="unknown reservation"):
        store.commit(stale, "10.00")
    assert store.spent("tenant:stale") == "0.000000"
