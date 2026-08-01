"""Serialisation and the HTTP surface.

The serialiser tests are security tests, not formatting tests. A dashboard that renders
an ``ALLOW_WITH_WARNINGS`` figure without its warnings delivers a material misstatement
with a clean conscience, and the usual sparse-fields convenience is exactly how that
happens.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
from rest_framework.test import APIRequestFactory, force_authenticate

from attest.adapters.django.models import AttestationRecord, PendingAction
from attest.adapters.django.serializers import AttestationSerializer, PendingActionSerializer
from attest.adapters.django.views import AttestationViewSet, PendingActionViewSet

pytestmark = pytest.mark.security


class Principal:
    """Stands in for an authenticated user carrying a tenant claim."""

    is_authenticated = True

    def __init__(self, tenant: str | None, pk: str = "alice", role: str = "manager") -> None:
        self.attest_tenant_id = tenant
        self.pk = pk
        self.attest_role = role


@pytest.fixture
def warned(now: datetime) -> Any:
    return AttestationRecord.objects.create(
        run_id="run_warned",
        tenant_id="t1",
        verdict="allow_with_warnings",
        answer="the figure is 4",
        warnings=["the cited source was superseded"],
        content_hash="a" * 64,
        payload=b"{}",
        created_at=now,
        is_final=True,
    )


# ── Serialisers ──────────────────────────────────────────────────────────────


def test_the_verdict_and_warnings_are_always_serialised(warned: Any) -> None:
    data = AttestationSerializer(warned).data
    assert data["verdict"] == "allow_with_warnings"
    assert data["warnings"] == ["the cited source was superseded"]


def test_a_sparse_field_request_cannot_drop_the_warnings(warned: Any) -> None:
    """``?fields=answer`` is how the qualification disappears one optimisation at a time."""
    data = AttestationSerializer(warned, fields=["answer"]).data
    assert data["answer"] == "the figure is 4"
    assert data["warnings"] == ["the cited source was superseded"]
    assert data["verdict"] == "allow_with_warnings"
    assert data["is_final"] is True


def test_a_sparse_field_request_still_drops_what_it_may(warned: Any) -> None:
    assert "tenant_id" not in AttestationSerializer(warned, fields=["answer"]).data


def test_a_verdict_the_system_cannot_resolve_alone_is_flagged(warned: Any, now: datetime) -> None:
    """Warnings do not need a person; a hold, an UNKNOWN effect or a partial world does."""
    assert AttestationSerializer(warned).data["requires_human_attention"] is False
    held = AttestationRecord.objects.create(
        run_id="run_held",
        tenant_id="t1",
        verdict="hold_for_approval",
        content_hash="e" * 64,
        payload=b"{}",
        created_at=now,
    )
    assert AttestationSerializer(held).data["requires_human_attention"] is True


def test_an_unrecognised_verdict_is_reported_as_unknown_rather_than_clear(now: datetime) -> None:
    """Returning False would be an all-clear the framework cannot support."""
    record = AttestationRecord.objects.create(
        run_id="run_future",
        tenant_id="t1",
        verdict="verdict_from_a_later_version",
        content_hash="b" * 64,
        payload=b"{}",
        created_at=now,
    )
    assert AttestationSerializer(record).data["requires_human_attention"] is None


def test_a_pending_action_always_shows_the_hash_of_what_is_being_approved(now: datetime) -> None:
    """Approving a tool name is authorising an amount nobody was shown."""
    action = PendingAction.objects.create(
        approval_id="apr_1",
        run_id="run_1",
        tenant_id="t1",
        grant_id="g1",
        action_hash="c" * 64,
        opened_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    data = PendingActionSerializer(action).data
    assert data["action_hash"] == "c" * 64
    assert data["state"] == "pending"


# ── Views ────────────────────────────────────────────────────────────────────


def call(
    viewset: Any,
    method: str,
    path: str,
    *,
    tenant: str | None,
    action: dict[str, str],
    principal: Principal | None = None,
    **kwargs: str,
) -> Any:
    factory = APIRequestFactory()
    request = getattr(factory, method)(path)
    user = principal if principal is not None else Principal(tenant)
    force_authenticate(request, user=user)
    request.user = user
    return viewset.as_view(action)(request, **kwargs)


def test_a_request_sees_only_its_own_tenants_records(warned: Any, now: datetime) -> None:
    AttestationRecord.objects.create(
        run_id="run_other",
        tenant_id="t2",
        verdict="allow",
        content_hash="d" * 64,
        payload=b"{}",
        created_at=now,
    )
    response = call(
        AttestationViewSet, "get", "/attestations/", tenant="t1", action={"get": "list"}
    )
    assert [row["run_id"] for row in response.data] == ["run_warned"]


def test_an_unauthenticated_read_is_refused() -> None:
    """The read routes carry records; they are not public either."""
    from rest_framework.test import APIRequestFactory

    request = APIRequestFactory().get("/attestations/")
    response = AttestationViewSet.as_view({"get": "list"})(request)
    assert response.status_code in (401, 403)


def test_an_unwired_deployment_sees_nothing_rather_than_everything(warned: Any) -> None:
    """No permissive default. The alternative fails open on a missing integration."""
    response = call(
        AttestationViewSet, "get", "/attestations/", tenant=None, action={"get": "list"}
    )
    assert list(response.data) == []


def test_the_listed_attestation_carries_its_warnings(warned: Any) -> None:
    response = call(
        AttestationViewSet, "get", "/attestations/", tenant="t1", action={"get": "list"}
    )
    assert response.data[0]["warnings"] == ["the cited source was superseded"]


@pytest.fixture
def pending(now: datetime) -> Any:
    return PendingAction.objects.create(
        approval_id="apr_1",
        run_id="run_1",
        tenant_id="t1",
        grant_id="g1",
        action_hash="c" * 64,
        opened_at=now,
        expires_at=now + timedelta(minutes=15),
    )


def test_an_approval_can_be_granted_through_the_view(pending: Any) -> None:
    response = call(
        PendingActionViewSet,
        "post",
        "/pending-actions/apr_1/approve/",
        tenant="t1",
        action={"post": "approve"},
        approval_id="apr_1",
    )
    assert response.status_code == 200
    assert PendingAction.objects.get(pk="apr_1").state == PendingAction.APPROVED


def test_an_approval_can_be_rejected_through_the_view(pending: Any) -> None:
    call(
        PendingActionViewSet,
        "post",
        "/pending-actions/apr_1/reject/",
        tenant="t1",
        action={"post": "reject"},
        approval_id="apr_1",
    )
    assert PendingAction.objects.get(pk="apr_1").state == PendingAction.REJECTED


def test_resolving_an_already_decided_action_conflicts_rather_than_overwriting(
    pending: Any, now: datetime
) -> None:
    pending.state = PendingAction.EXPIRED
    pending.save(update_fields=["state"])
    response = call(
        PendingActionViewSet,
        "post",
        "/pending-actions/apr_1/approve/",
        tenant="t1",
        action={"post": "approve"},
        approval_id="apr_1",
    )
    assert response.status_code == 409
    assert PendingAction.objects.get(pk="apr_1").state == PendingAction.EXPIRED


@pytest.mark.security
def test_an_approver_without_a_role_is_refused(pending: Any) -> None:
    """A quorum is defined over roles, so a roleless decision discharges nothing.

    Storing it would leave the run pending forever with no visible cause, so the
    refusal happens at the write where someone can see it.
    """
    response = call(
        PendingActionViewSet,
        "post",
        "/pending-actions/apr_1/approve/",
        tenant="t1",
        action={"post": "approve"},
        principal=Principal("t1", role=""),
        approval_id="apr_1",
    )
    assert response.status_code == 400
    assert PendingAction.objects.get(pk="apr_1").state == PendingAction.PENDING


@pytest.mark.security
def test_the_proposer_cannot_approve_their_own_action(pending: Any) -> None:
    """The most common way dual control is defeated in practice."""
    pending.requested_by = "alice"
    pending.save(update_fields=["requested_by"])
    response = call(
        PendingActionViewSet,
        "post",
        "/pending-actions/apr_1/approve/",
        tenant="t1",
        action={"post": "approve"},
        principal=Principal("t1", pk="alice"),
        approval_id="apr_1",
    )
    assert response.status_code == 403
    assert PendingAction.objects.get(pk="apr_1").state == PendingAction.PENDING

    other = call(
        PendingActionViewSet,
        "post",
        "/pending-actions/apr_1/approve/",
        tenant="t1",
        action={"post": "approve"},
        principal=Principal("t1", pk="bob"),
        approval_id="apr_1",
    )
    assert other.status_code == 200


@pytest.mark.security
def test_a_decision_records_the_role_it_was_cast_under(pending: Any) -> None:
    call(
        PendingActionViewSet,
        "post",
        "/pending-actions/apr_1/approve/",
        tenant="t1",
        action={"post": "approve"},
        principal=Principal("t1", pk="bob", role="finance_manager"),
        approval_id="apr_1",
    )
    assert PendingAction.objects.get(pk="apr_1").approver_role == "finance_manager"


def test_another_tenant_cannot_resolve_the_approval(pending: Any) -> None:
    response = call(
        PendingActionViewSet,
        "post",
        "/pending-actions/apr_1/approve/",
        tenant="t2",
        action={"post": "approve"},
        approval_id="apr_1",
    )
    assert response.status_code == 404
    assert PendingAction.objects.get(pk="apr_1").state == PendingAction.PENDING


@pytest.mark.security
def test_the_read_api_does_not_narrate_the_decision_back_to_the_subject(now: datetime) -> None:
    """ATT-13. The disclosure control was a speed bump: one extra request defeated it.

    RunResultSerializer withheld finding messages and the operator-facing refusal detail
    from non-operator profiles. AttestationSerializer had no disclosure concept at all
    and always serialised `warnings`, which the store populates from the SAME finding
    messages — built as f"{outcome.name}: {outcome.detail}", where the detail is
    "actor 'ops-7' does not hold 'settle_claim'".
    """
    AttestationRecord.objects.create(
        run_id="run_leak",
        tenant_id="t1",
        verdict="allow_with_warnings",
        warnings=["capability:settle_claim: actor 'ops-7' does not hold 'settle_claim'"],
        content_hash="f" * 64,
        payload=b"{}",
        created_at=now,
    )
    response = call(
        AttestationViewSet, "get", "/attestations/", tenant="t1", action={"get": "list"}
    )
    warnings = response.data[0]["warnings"]
    assert warnings == ["capability:settle_claim"], warnings
    assert not any("ops-7" in text for text in warnings), "an internal actor id was disclosed"


@pytest.mark.security
def test_a_warning_is_never_withheld_entirely_only_narrowed(now: datetime) -> None:
    """A warning a caller cannot see is a warning that does not exist.

    The count and the categories survive; only the operator-facing text does not.
    """
    AttestationRecord.objects.create(
        run_id="run_two",
        tenant_id="t1",
        verdict="allow_with_warnings",
        warnings=["epistemic:stale: source superseded", "boundary:injection: detected in doc 4"],
        content_hash="e" * 64,
        payload=b"{}",
        created_at=now,
    )
    response = call(
        AttestationViewSet, "get", "/attestations/", tenant="t1", action={"get": "list"}
    )
    assert len(response.data[0]["warnings"]) == 2


def test_an_operator_console_still_sees_the_messages(now: datetime) -> None:
    """The text exists for triage; it is the audience that changes."""
    from attest.assurance.export import DisclosureProfile

    record = AttestationRecord.objects.create(
        run_id="run_ops",
        tenant_id="t1",
        verdict="allow_with_warnings",
        warnings=["capability:settle_claim: actor 'ops-7' does not hold 'settle_claim'"],
        content_hash="d" * 64,
        payload=b"{}",
        created_at=now,
    )
    data = AttestationSerializer(record, disclosure=DisclosureProfile.INTERNAL).data
    assert "ops-7" in data["warnings"][0]
