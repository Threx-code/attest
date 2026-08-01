"""The operational endpoints, and the one thing they are opinionated about.

They are abstract on authorisation on purpose — the host decides who may. What they are
not abstract about is that a change names an operator and states a reason, because those
are integrity properties rather than policy: an unattributed, unexplained kill switch is
indistinguishable from a misconfiguration when the incident is reviewed.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
from rest_framework.test import APIRequestFactory, force_authenticate

from attest.adapters.django.models import AutonomyPolicy, PendingAction
from attest.adapters.django.operations import (
    ApprovalQueueView,
    AutonomyView,
    ChainVerificationView,
    OperationsView,
    QueueHealthView,
)
from attest.adapters.django.stores import (
    DjangoApprovalStore,
    DjangoAutonomyStore,
    DjangoRunQueue,
)
from attest.kernel.identifiers import ActorId, RunId, TenantId
from attest.runtime.dispatch import RunEnvelope
from attest.runtime.operations import OperationsService

pytestmark = [pytest.mark.contract, pytest.mark.security]


class Staff:
    """An authenticated staff user. Stands in for whatever the host actually uses."""

    is_authenticated = True
    is_staff = True

    def __init__(self, pk: str = "alice") -> None:
        self.pk = pk
        self.groups = None


class Clock:
    def __init__(self, at: datetime) -> None:
        self.at = at

    def now(self) -> datetime:
        return self.at


def console(now: datetime, **ports: Any) -> type[OperationsView]:
    """A host's subclass: the two methods the framework refuses to guess."""

    class Console(OperationsView):
        def service(self, request: Any) -> OperationsService:
            return OperationsService(clock=Clock(now), **ports)

    return Console


def call(
    view: type[OperationsView], method: str, path: str, *, user: Any = None, **kwargs: Any
) -> Any:
    request = getattr(APIRequestFactory(), method)(path, kwargs.get("data"), format="json")
    principal = user if user is not None else Staff()
    force_authenticate(request, user=principal)
    request.user = principal
    return view.as_view()(request, **kwargs.get("url_kwargs", {}))


# ── The base view refuses to guess ───────────────────────────────────────────


def test_the_base_view_will_not_invent_a_service() -> None:
    """A service assembled from settings would diverge from the engine's stores."""
    with pytest.raises(NotImplementedError, match="must return an OperationsService"):
        OperationsView().service(None)


def test_an_unauthenticated_caller_is_refused() -> None:
    """The DRF default is AllowAny, and a kill switch behind AllowAny is not one."""
    request = APIRequestFactory().get("/ops/autonomy/")
    response = AutonomyView.as_view()(request)
    assert response.status_code in (401, 403)


def test_a_caller_with_no_resolvable_identity_is_refused(now: datetime) -> None:
    class Anonymous:
        is_authenticated = True
        is_staff = True
        pk = ""
        groups = None

    view = type("V", (console(now, autonomy=DjangoAutonomyStore()), AutonomyView), {})
    response = call(
        view,
        "post",
        "/ops/autonomy/",
        user=Anonymous(),
        data={"capability": "transfer", "tenant": "t1", "reason": "incident"},
    )
    assert response.status_code == 400
    assert "cannot name who made it" in response.data["detail"]


# ── The kill switch, over HTTP ───────────────────────────────────────────────


def autonomy_view(now: datetime) -> type[AutonomyView]:
    return type("V", (console(now, autonomy=DjangoAutonomyStore()), AutonomyView), {})


def test_a_change_without_a_reason_is_a_400_not_a_500(now: datetime) -> None:
    """The message is written for the person holding the incident; a 500 discards it."""
    response = call(
        autonomy_view(now),
        "post",
        "/ops/autonomy/",
        data={"capability": "transfer", "tenant": "t1"},
    )
    assert response.status_code == 400
    assert "requires a reason" in response.data["detail"]
    assert AutonomyPolicy.objects.count() == 0


def test_disabling_over_http_blocks_the_capability(now: datetime) -> None:
    response = call(
        autonomy_view(now),
        "post",
        "/ops/autonomy/",
        data={"capability": "transfer", "tenant": "t1", "reason": "incident 4471"},
    )
    assert response.status_code == 200
    assert response.data["operation"] == "autonomy.disabled"
    row = AutonomyPolicy.objects.get(capability="transfer")
    assert row.enabled is False
    assert "incident 4471" in row.updated_by


def test_enabling_over_http_does_not_go_straight_to_auto(now: datetime) -> None:
    call(
        autonomy_view(now),
        "post",
        "/ops/autonomy/",
        data={"capability": "transfer", "tenant": "t1", "reason": "fixed", "enabled": True},
    )
    assert AutonomyPolicy.objects.get(capability="transfer").mode == "approve"


def test_a_change_naming_no_capability_is_refused(now: datetime) -> None:
    response = call(
        autonomy_view(now), "post", "/ops/autonomy/", data={"tenant": "t1", "reason": "x"}
    )
    assert response.status_code == 400


def test_current_autonomy_is_readable(now: datetime) -> None:
    DjangoAutonomyStore().set_mode(
        tenant=TenantId("t1"), capability="transfer", mode="blocked", enabled=False, by="alice"
    )
    response = call(autonomy_view(now), "get", "/ops/autonomy/?tenant=t1")
    assert [row["capability"] for row in response.data["policies"]] == ["transfer"]


# ── The approval queue, over HTTP ────────────────────────────────────────────


def test_the_queue_shows_the_action_hash_not_just_the_tool(now: datetime) -> None:
    """An approval screen naming only the tool asks for authority over an unseen amount."""
    PendingAction.objects.create(
        approval_id="apr_1",
        run_id="run_1",
        tenant_id="t1",
        grant_id="g1",
        action_hash="b" * 64,
        summary="transfer 500000",
        opened_at=now,
        expires_at=now + timedelta(minutes=15),
    )
    view = type("V", (console(now, approvals=DjangoApprovalStore()), ApprovalQueueView), {})
    response = call(view, "get", "/ops/approvals/")
    assert response.data["pending"][0]["action_hash"] == "b" * 64


def test_resolving_over_http_goes_through_the_stores_refusals(now: datetime) -> None:
    PendingAction.objects.create(
        approval_id="apr_1",
        run_id="run_1",
        tenant_id="t1",
        grant_id="g1",
        action_hash="b" * 64,
        opened_at=now,
        expires_at=now + timedelta(minutes=15),
    )
    view = type("V", (console(now, approvals=DjangoApprovalStore()), ApprovalQueueView), {})
    response = call(
        view,
        "post",
        "/ops/approvals/",
        data={"approval_id": "apr_1", "approved": True, "role": "manager"},
    )
    assert response.status_code == 200
    assert PendingAction.objects.get(pk="apr_1").state == PendingAction.APPROVED


def test_resolving_without_a_role_is_refused_over_http(now: datetime) -> None:
    """A quorum is defined over roles, so a roleless decision discharges nothing."""
    PendingAction.objects.create(
        approval_id="apr_1",
        run_id="run_1",
        tenant_id="t1",
        grant_id="g1",
        action_hash="b" * 64,
        opened_at=now,
        expires_at=now + timedelta(minutes=15),
    )
    view = type("V", (console(now, approvals=DjangoApprovalStore()), ApprovalQueueView), {})
    response = call(
        view, "post", "/ops/approvals/", data={"approval_id": "apr_1", "approved": True}
    )
    assert response.status_code == 400
    assert PendingAction.objects.get(pk="apr_1").state == PendingAction.PENDING


# ── Queue health, over HTTP ──────────────────────────────────────────────────


def envelope(now: datetime, run_id: str = "run_1") -> bytes:
    return RunEnvelope(
        run_id=RunId(run_id),
        actor=ActorId("alice"),
        tenant=TenantId("t1"),
        payload={},
        submitted_at=now,
    ).encode()


def test_queue_health_reports_stalled(now: datetime) -> None:
    queue = DjangoRunQueue()
    queue.submit(RunId("run_1"), envelope(now))
    view = type("V", (console(now, queue=queue), QueueHealthView), {})
    response = call(view, "get", "/ops/queue/")
    assert response.data["depth"] == 1
    assert response.data["stalled"] is True


def test_reclaiming_over_http_needs_a_reason(now: datetime) -> None:
    queue = DjangoRunQueue(lease=timedelta(minutes=1))
    queue.submit(RunId("run_1"), envelope(now))
    queue.claim(limit=1, now=now)
    view = type("V", (console(now + timedelta(minutes=5), queue=queue), QueueHealthView), {})

    refused = call(view, "post", "/ops/queue/", data={})
    assert refused.status_code == 400

    accepted = call(view, "post", "/ops/queue/", data={"reason": "pod evicted"})
    assert accepted.data["reclaimed"] == ["run_1"]


# ── Chain verification ───────────────────────────────────────────────────────


def test_verifying_a_run_with_no_events_is_refused_rather_than_reported_intact(
    now: datetime,
) -> None:
    """An empty chain verifies vacuously, which would render as a green tick."""
    from attest.adapters.django.stores import DjangoAuditSink

    view = type("V", (console(now, audit=DjangoAuditSink()), ChainVerificationView), {})
    response = call(view, "get", "/ops/chain/run_absent/", url_kwargs={"run_id": "run_absent"})
    assert response.status_code == 400
    assert "verifies vacuously" in response.data["detail"]
