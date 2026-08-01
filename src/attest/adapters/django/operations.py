"""Operational endpoints, abstract on authorisation. The host decides who may.

There was a Django admin here. It went, for the reason the rest of this package is
built the way it is: an admin is a **console with a permission model baked in**, and
every adopter already has roles, groups, SSO claims and an approval hierarchy. A
shipped permission model is either ignored or — worse — wired up beside the real one,
where it drifts and nobody notices until someone who should not have been able to flip
a kill switch flips one.

What is shipped instead is the pair this package uses everywhere:

.. code-block:: text

    OperationsService      what the operations ARE     (attest.runtime.operations)
    OperationsView         how they reach HTTP         (here, abstract)
    your subclass          who may perform them        (yours)

Every view below is abstract in exactly one way: ``operator_for`` and
``permission_classes``. Both raise or deny by default rather than guessing, because the
DRF default is ``AllowAny`` and a kill switch behind ``AllowAny`` is not a kill switch.

.. code-block:: python

    class OpsConsole(OperationsView):
        permission_classes = (IsIncidentCommander,)

        def service(self, request):
            return OperationsService(clock=Clock(), autonomy=DjangoAutonomyStore(), ...)

        def operator_for(self, request):
            return Operator(
                actor=ActorId(str(request.user.pk)),
                roles=frozenset(request.user.groups.values_list("name", flat=True)),
            )

Nothing is mounted automatically. ``urls.py`` does not include these — a route that
can disable a capability should be a line somebody wrote on purpose.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rest_framework import status
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from attest.kernel.errors import ContractViolation
from attest.kernel.identifiers import RunId, TenantId

if TYPE_CHECKING:
    from rest_framework.request import Request

    from attest.runtime.operations import OperationsService, Operator

__all__ = [
    "ApprovalQueueView",
    "AutonomyView",
    "ChainVerificationView",
    "OperationsView",
    "QueueHealthView",
]


class OperationsView(APIView):
    """Base for the operational routes. Refuses to work until a host wires it.

    ``IsAdminUser`` is the default rather than ``AllowAny`` — not because it is the
    right policy for your deployment, but because the wrong-and-restrictive default
    fails visibly on the first request while the wrong-and-permissive one fails silently
    for as long as nobody looks.
    """

    permission_classes: ClassVar[tuple[type, ...]] = (IsAdminUser,)
    throttle_scope = "attest-ops"

    def service(self, request: Request) -> OperationsService:
        """The configured service. Supplied by the host."""
        raise NotImplementedError(
            "OperationsView.service must return an OperationsService. It is not built "
            "from settings here because it holds the stores, and a second definition "
            "of those would diverge from the one your engine uses."
        )

    def operator_for(self, request: Request) -> Operator:
        """Who is acting. Supplied by the host, because only the host knows.

        The default reads ``pk`` and Django groups, which is right often enough to be
        useful and wrong often enough that it is worth overriding deliberately.
        """
        from attest.kernel.identifiers import ActorId
        from attest.runtime.operations import Operator

        user = getattr(request, "user", None)
        actor = str(getattr(user, "pk", "") or "")
        if not actor:
            raise ContractViolation(
                "no operator could be resolved for this caller. An operational change "
                "that cannot name who made it is indistinguishable from a "
                "misconfiguration when the incident is reviewed."
            )
        groups = getattr(getattr(user, "groups", None), "values_list", None)
        roles = frozenset(groups("name", flat=True)) if groups is not None else frozenset()
        return Operator(actor=ActorId(actor), roles=roles)

    def reason_from(self, request: Request) -> str:
        """The stated reason for a change. Mandatory, and checked before anything moves."""
        reason = str(request.data.get("reason", "")).strip()
        if not reason:
            raise ContractViolation(
                "this operation requires a reason. During the incident everybody knows "
                "why; two weeks later, when someone asks whether it can be reverted, "
                "nobody does."
            )
        return reason

    def handle_exception(self, exc: Exception) -> Response:
        """A contract violation is a 400 with its own text, not a 500.

        The messages here are written for the person holding the incident, and turning
        them into "Internal Server Error" would throw away the only explanation
        available at the moment it is needed.
        """
        if isinstance(exc, ContractViolation):
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return super().handle_exception(exc)


class AutonomyView(OperationsView):
    """The kill switch. ``GET`` to see it, ``POST`` to move it."""

    def get(self, request: Request) -> Response:
        tenant = request.query_params.get("tenant")
        modes = self.service(request).autonomy(tenant=None if tenant is None else TenantId(tenant))
        return Response({"policies": [dict(row) for row in modes]})

    def post(self, request: Request) -> Response:
        """Disable or enable one capability for one tenant.

        Enabling defaults to ``approve``, never ``auto``: re-enabling straight to
        unattended operation is how an incident recurs an hour after it was closed.
        """
        service = self.service(request)
        operator = self.operator_for(request)
        reason = self.reason_from(request)
        capability = str(request.data.get("capability", ""))
        tenant = TenantId(str(request.data.get("tenant", "")))
        if not capability or not tenant:
            return Response(
                {"detail": "capability and tenant are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if request.data.get("enabled") is True:
            record = service.enable(
                capability=capability,
                tenant=tenant,
                by=operator,
                reason=reason,
                mode=str(request.data.get("mode", "approve")),
            )
        else:
            record = service.disable(
                capability=capability, tenant=tenant, by=operator, reason=reason
            )
        return Response(
            {
                "operation": record.operation,
                "operator": str(record.operator),
                "target": record.target,
                "reason": record.reason,
                "at": record.at.isoformat(),
                "detail": dict(record.detail),
            }
        )


class ApprovalQueueView(OperationsView):
    """The queue, and the two decisions about an entry.

    Goes through the store, so its refusals apply: expiry, the empty-role refusal and
    the self-approval refusal all live there, and a console that wrote the row directly
    would be the one path where dual control does not hold.
    """

    def get(self, request: Request) -> Response:
        tenant = request.query_params.get("tenant")
        pending = self.service(request).pending(tenant=None if tenant is None else TenantId(tenant))
        return Response({"pending": [self.serialise(item) for item in pending]})

    def post(self, request: Request) -> Response:
        record = self.service(request).resolve(
            approval_id=str(request.data.get("approval_id", "")),
            approved=bool(request.data.get("approved")),
            by=self.operator_for(request),
            role=str(request.data.get("role", "")),
        )
        return Response({"operation": record.operation, "target": record.target})

    def serialise(self, item: Any) -> dict[str, Any]:
        """What an approver is shown. **The action hash is not optional.**

        An approval screen that names only the tool is asking somebody to authorise an
        amount they were never shown.
        """
        return {
            "approval_id": item.approval_id,
            "run_id": item.run_id,
            "tenant": item.tenant_id,
            "action_hash": item.action_hash,
            "summary": item.summary,
            "requested_by": item.requested_by,
            "expires_at": item.expires_at.isoformat(),
        }


class ChainVerificationView(OperationsView):
    """Re-derive one run's chain from stored events.

    Recomputes rather than reading a ``sealed`` boolean. A console that rendered a
    green tick from a column would show one for a chain that had been rewritten, which
    is the single thing this package exists to make impossible.
    """

    def get(self, request: Request, run_id: str) -> Response:
        verification = self.service(request).verify_chain(RunId(run_id))
        return Response(
            {
                "run_id": run_id,
                "intact": bool(getattr(verification, "intact", False)),
                "failures": [str(f) for f in getattr(verification, "failures", ())],
            }
        )


class QueueHealthView(OperationsView):
    """Depth, age and what is in flight.

    Age is here because depth alone hides a stalled queue: five waiting is fine, five
    waiting for an hour is an incident, and both read as "5".
    """

    def get(self, request: Request) -> Response:
        health = self.service(request).queue_health()
        return Response(
            {
                "depth": health.depth,
                "oldest_waiting_seconds": (
                    None if health.oldest_waiting is None else health.oldest_waiting.total_seconds()
                ),
                "running": health.running,
                "held": health.held,
                "failed": health.failed,
                "stalled": health.stalled,
            }
        )

    def post(self, request: Request) -> Response:
        """Reclaim runs whose worker died. A decision, so it needs a reason."""
        reclaimed = self.service(request).reclaim_stuck(
            by=self.operator_for(request), reason=self.reason_from(request)
        )
        return Response({"reclaimed": list(reclaimed)})
