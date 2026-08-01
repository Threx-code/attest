"""HTTP surface — dispatch a run, read the record, work the approval queue.

.. rubric:: Security posture

These routes decide whether money moves, so nothing here inherits a default that could
be permissive:

.. code-block:: text

    CONCERN                      DEFAULT HERE              WHY NOT THE DRF DEFAULT
    ─────────────────────────    ──────────────────────    ────────────────────────
    authentication               IsAuthenticated, set      DEFAULT_PERMISSION_CLASSES
                                 on the class              is AllowAny unless a host
                                                           changed it
    tenant scoping               at the queryset           filtering after the query
                                                           has already read the rows
    cross-tenant dispatch        refused, 403              a proposal naming another
                                                           tenant is the confused
                                                           deputy, not a typo
    disclosure                   SUBJECT                   the class does not know who
                                                           is on the socket
    rate limiting                throttle scope declared   a dispatch spends model
                                                           budget and can move money

**``permission_classes`` is set explicitly on every class**, rather than left to
``DEFAULT_PERMISSION_CLASSES``. A project that has not configured that setting gets
``AllowAny``, and inheriting it here would mean mounting ``urls.py`` publishes an
unauthenticated endpoint that can execute governed actions. A framework whose safety
depends on a setting the host might not have set is not fail-closed.

Tenant scoping is applied **at the queryset**, never after. Filtering after the query
means the table was already read across tenants, so a bug in the filter becomes a data
leak rather than a wrong page. ``tenant_for`` has no permissive default: a deployment
that has not wired identity gets nothing rather than everything.

.. rubric:: Dispatch returns the attestation, not the answer

``DispatchView`` returns the whole record — verdict, warnings, warrants — and the HTTP
status is derived from the verdict rather than from whether the code threw. A
``HOLD_FOR_APPROVAL`` is a ``202``, a ``REFUSE`` is a ``422``, an ``UNKNOWN`` effect is
a ``202`` as well, because none of those is an error and none of them is a success. A
route that returned ``200`` with the answer would hand a caller a figure whose
qualification lives in a field they never had to read.

.. rubric:: It is assembled by the host, not by this module

``DispatchView`` has no engine of its own. A host subclasses it and supplies
:meth:`DispatchView.engine_for`, because the engine holds the profile, the stores and
the executor — and a view that constructed those from settings would be a second,
divergent definition of what a deployment is.

.. rubric:: A held run does not hold a worker

The view returns as soon as the run reaches ``HOLD_FOR_APPROVAL``. Resumption is a
separate request triggered by the approval, not a thread parked on a queue. A worker
pool held open by pending approvals is an outage waiting for a busy Monday.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, ClassVar

from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from attest.adapters.django.models import AttestationRecord, PendingAction
from attest.adapters.django.serializers import (
    AttestationSerializer,
    PendingActionSerializer,
    RunResultSerializer,
)
from attest.adapters.django.stores import DjangoApprovalStore
from attest.assurance.export import DisclosureProfile
from attest.kernel.errors import ApprovalStoreError, SelfApprovalError
from attest.kernel.identifiers import RunId
from attest.kernel.verdicts import Verdict
from attest.runtime.dispatch import QueuedDispatch

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from rest_framework.request import Request

    from attest.capabilities.execution import Executor
    from attest.kernel.context import TenantBinding
    from attest.kernel.ports import RunQueue
    from attest.runtime.engine import RunEngine, RunRequest, RunResult

__all__ = [
    "AttestationViewSet",
    "DispatchView",
    "GovernedMixin",
    "PendingActionViewSet",
    "TenantScopedViewSet",
]


class AttestRateThrottle(ScopedRateThrottle):
    """Scoped throttling with a shipped default, so the control is on out of the box.

    DRF raises ``KeyError`` for a scope with no configured rate. That is the correct
    behaviour for a scope the host invented and the wrong one for a scope the framework
    ships: a package that returns 500 on every request until somebody adds a settings
    key is a package that gets its throttle classes deleted.

    So there is a default, and it is deliberately generous — this is a backstop against
    unbounded dispatch, not a capacity plan. Whoever sizes the deployment sets the real
    number.
    """

    DEFAULT_RATE: ClassVar[str] = "120/min"

    def get_rate(self) -> str:
        try:
            return str(super().get_rate())
        except (KeyError, ImproperlyConfigured):
            return self.DEFAULT_RATE


class GovernedMixin:
    """Authentication and tenancy, set here rather than inherited from settings.

    Every class in this module mixes it in. Overriding ``permission_classes`` to
    loosen it is a deliberate act with a visible diff, which is the point — the
    alternative is an unauthenticated dispatch route that nobody chose and nobody
    can see in a review.
    """

    permission_classes = (IsAuthenticated,)

    #: DRF throttle scope. A dispatch spends model budget and can move money, so the
    #: scope exists whether or not a host configures a rate for it — an unconfigured
    #: scope is a one-line settings change, while an absent one is a code change.
    throttle_classes = (AttestRateThrottle,)
    """Set on the class, not left to the host's ``DEFAULT_THROTTLE_CLASSES``.

    A ``throttle_scope`` with no throttle class throttles nothing — DRF's default list
    is empty unless a host configures it — while the security table in this module and
    in the adapter docs listed rate limiting beside controls that genuinely are set
    here. Unlimited dispatch is unlimited model spend and unlimited CPU, from any
    authenticated principal.

    A rate ships (see :class:`AttestRateThrottle`) so the control is on by default. The
    host raises or lowers it with ``DEFAULT_THROTTLE_RATES = {"attest": "600/min"}``.
    """

    throttle_scope = "attest"

    def tenant_for(self, request: Request) -> str | None:
        """The tenant this request may act for, or ``None`` for none at all.

        Override to read whatever carries tenancy in the host — a claim on the token,
        a column on the user, a header validated upstream. The default returns
        ``None``, so an unwired deployment sees an empty list and cannot dispatch,
        rather than seeing every tenant.
        """
        claimed = getattr(getattr(request, "user", None), "attest_tenant_id", None)
        return None if claimed is None else str(claimed)


class TenantScopedViewSet(GovernedMixin, viewsets.ReadOnlyModelViewSet):
    """Scoping applied in the queryset, with no permissive default."""

    def get_queryset(self) -> QuerySet[Any]:
        tenant = self.tenant_for(self.request)
        if tenant is None:
            return self.queryset.none()
        return self.queryset.filter(tenant_id=str(tenant))


class AttestationViewSet(TenantScopedViewSet):
    """Read-only. There is no update route because there is no update.

    A correction is a new record pointing at the one it replaces, so that a reader who
    relied on the original can still see exactly what they relied on. Exposing a PATCH
    would offer something the database trigger refuses anyway.
    """

    queryset = AttestationRecord.objects.all().order_by("-created_at")
    serializer_class = AttestationSerializer

    def disclosure_for(self, request: Request) -> DisclosureProfile:
        """Which audience this read is for. Narrowest by default, like dispatch.

        The dispatch response was carefully narrowed and this route was not, so one
        extra GET returned the operator-facing text the other had just withheld. An
        operator console overrides this; a subject-facing client must not be able to.
        """
        return DisclosureProfile.SUBJECT

    def get_serializer(self, *args: Any, **kwargs: Any) -> Any:
        kwargs.setdefault("disclosure", self.disclosure_for(self.request))
        return super().get_serializer(*args, **kwargs)

    lookup_field = "run_id"


class PendingActionViewSet(TenantScopedViewSet):
    """The approval queue, and the two decisions that can be made about an entry."""

    queryset = PendingAction.objects.all().order_by("expires_at")
    serializer_class = PendingActionSerializer
    lookup_field = "approval_id"
    approvals = DjangoApprovalStore()

    def role_for(self, request: Request) -> str:
        """The role this decision is cast under. Supplied by the host.

        A quorum is defined over roles, so an approval recorded without one satisfies
        no obligation. The default reads a claim the host may not have wired, and the
        store refuses an empty role rather than storing a decision that counts toward
        nothing.
        """
        return str(getattr(getattr(request, "user", None), "attest_role", "") or "")

    @action(detail=True, methods=["post"])
    def approve(self, request: Request, approval_id: str | None = None) -> Response:
        return self._resolve(request, approval_id, approved=True)

    @action(detail=True, methods=["post"])
    def reject(self, request: Request, approval_id: str | None = None) -> Response:
        return self._resolve(request, approval_id, approved=False)

    def _resolve(self, request: Request, approval_id: str | None, *, approved: bool) -> Response:
        """Resolve through the store, so expiry is enforced rather than assumed.

        Going through :class:`DjangoApprovalStore` rather than saving the model is the
        point: a late click on an expired action is refused there, and an approval
        whose window has closed must not authorise an effect.
        """
        instance = self.get_object()
        role = self.role_for(request)
        if not role:
            # Failing here is louder than storing a decision that counts toward
            # nothing: a quorum is defined over roles, so a roleless approval would
            # leave the run pending forever with no visible cause.
            return Response(
                {
                    "detail": "no role for this approver; a quorum is defined over "
                    "roles, so a decision cast without one discharges nothing"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            self.approvals.resolve(
                str(approval_id or instance.approval_id),
                approved=approved,
                approver=str(getattr(request.user, "pk", "") or "unknown"),  # type: ignore[arg-type]
                at=timezone.now(),
                role=role,
            )
        except SelfApprovalError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)
        except ApprovalStoreError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
        self.resume_run(instance, request)
        instance.refresh_from_db()
        return Response(self.get_serializer(instance).data)

    def queue_for(self, request: Request) -> RunQueue | None:
        """The queue holding the suspended run. ``None`` for an inline deployment."""
        return None

    def resume_run(self, instance: Any, request: Request) -> None:
        """Put the held run back on the queue now that its decision exists.

        This is the half that keeps a pool alive. The worker returned when the run
        held, so nothing has been waiting; the *approval* is what starts it again. A
        design where the worker blocked would size the pool by how fast people answer
        email, and on a busy Monday it would not be sized at all.

        A resumption failure must not fail the approval. The decision is recorded and
        durable either way, and a 500 here would leave a reviewer believing their
        approval did not land — so they would click again, and the second click is
        refused as an already-decided action.
        """
        queue = self.queue_for(request)
        if queue is None or instance.state != PendingAction.APPROVED:
            return
        try:
            queue.resume(RunId(str(instance.run_id)))
        except Exception as exc:
            # Suppressed used to mean *unrecorded*, so an approved run whose resumption
            # failed was indistinguishable from one that resumed and is merely slow. The
            # operator sees APPROVED and assumes the effect followed. The approval still
            # stands — it must not fail because a queue is down — but the failure is
            # written where the queue's health is read.
            self.record_resume_failure(instance, exc)

    def record_resume_failure(self, instance: Any, exc: Exception) -> None:
        """Put the failed resumption on the trail. Never raises.

        A suppressed failure with no record is the shape of an outage nobody sees.
        """
        with contextlib.suppress(Exception):
            from attest.adapters.django.models import DispatchEvent

            DispatchEvent.objects.create(
                dispatch_id=str(instance.run_id),
                run_id=str(instance.run_id),
                tenant_id=str(instance.tenant_id),
                event_type="dispatch.resume_failed",
                occurred_at=timezone.now(),
                actor=str(instance.approver),
                detail=(
                    f"{type(exc).__name__}: {exc}. The approval stands and the run has "
                    f"NOT been re-dispatched; it will not proceed until it is."
                ),
            )


class DispatchView(GovernedMixin, APIView):
    """Runs one proposal through the kernel and returns its attestation.

    Abstract by design. A host subclasses it and supplies the three things only the
    host can know: which engine to use, what the request proposes, and which tenant
    binding applies. Everything the *framework* is opinionated about — that the record
    is returned rather than the answer, and that the status code follows the verdict —
    is fixed here so it cannot be forgotten per route.
    """

    #: Verdict → HTTP status. Deliberately not "200 unless it threw".
    #:
    #: A held or unknown run is neither a success nor an error: something is
    #: outstanding, and the caller must look. ``409`` for INCOMPLETE says the world is
    #: in a mixed state, which is a conflict a caller has to resolve rather than a
    #: request they can retry.
    STATUS_FOR: ClassVar[dict[Verdict, int]] = {
        Verdict.ALLOW: status.HTTP_200_OK,
        Verdict.ALLOW_WITH_WARNINGS: status.HTTP_200_OK,
        Verdict.HOLD_FOR_APPROVAL: status.HTTP_202_ACCEPTED,
        Verdict.UNKNOWN: status.HTTP_202_ACCEPTED,
        Verdict.INCOMPLETE: status.HTTP_409_CONFLICT,
        Verdict.REFUSE: status.HTTP_422_UNPROCESSABLE_ENTITY,
    }

    def engine_for(self, request: Request) -> RunEngine:
        """The configured engine. Supplied by the host."""
        raise NotImplementedError(
            "DispatchView.engine_for must return a RunEngine. It is not built from "
            "settings here because the engine holds the profile, the stores and the "
            "executor, and a second definition of those would diverge from the one "
            "your workers use."
        )

    def build_request(self, request: Request) -> RunRequest:
        """Translate the HTTP body into a proposal. Supplied by the host."""
        raise NotImplementedError(
            "DispatchView.build_request must return a RunRequest. The framework does "
            "not guess how your payload maps onto evidence, capabilities and an "
            "action — guessing there would be the framework inventing authority."
        )

    def binding_for(self, request: Request) -> TenantBinding:
        """The tenant's resolved policy binding. Supplied by the host."""
        raise NotImplementedError(
            "DispatchView.binding_for must return a TenantBinding: which profile "
            "version and residency constraints apply to this tenant."
        )

    def executor_for(self, request: Request) -> Executor | None:
        """The host code that performs the effect, if the proposal has one."""
        return None

    def disclosure_for(self, request: Request) -> DisclosureProfile:
        """Which audience this response is for. Narrowest by default.

        An operator console overrides this to ``INTERNAL``. It is a method rather than
        a class attribute so the choice can follow the caller's role instead of the
        route, which is where it actually lives.
        """
        return DisclosureProfile.SUBJECT

    def queue_for(self, request: Request) -> RunQueue | None:
        """The queue to dispatch through, or ``None`` to run inline.

        ``None`` is the default because inline is what a small deployment wants and
        what every test wants. Returning a queue moves the run off the request: a run
        makes model calls and then an external effect, so performed inline one run
        holds a worker for seconds and peak throughput is bounded by the pool rather
        than by anything this package costs.
        """
        return None

    def post(self, request: Request) -> Response:
        proposal = self.build_request(request)
        self.assert_own_tenant(request, proposal)
        queue = self.queue_for(request)
        if queue is not None:
            return self.enqueue(request, proposal, queue)
        result = self.engine_for(request).execute(
            proposal,
            binding=self.binding_for(request),
            executor=self.executor_for(request),
        )
        return self.respond(result, disclosure=self.disclosure_for(request))

    def enqueue(self, request: Request, proposal: RunRequest, queue: RunQueue) -> Response:
        """Hand the run to a worker and answer with a ticket, not an answer.

        ``202`` and a run id, never an optimistic record. A response carrying a verdict
        field for a run no warrant has been evaluated for is worse than no response —
        a caller reads the field.

        The tenant check has already run against the *caller*, and the worker re-checks
        the built proposal against the envelope. Both are needed: this one stops a
        caller acting for a tenant they do not hold, and that one stops a change to
        ``build_request`` from quietly widening what a queued envelope may do.
        """
        engine = self.engine_for(request)
        ticket = QueuedDispatch(queue, clock=engine.clock).submit(
            run_id=engine.new_run_id(),
            actor=proposal.actor,
            tenant=proposal.tenant,
            payload=self.payload_for(request),
        )
        return Response(ticket.as_dict(), status=status.HTTP_202_ACCEPTED)

    def payload_for(self, request: Request) -> dict[str, Any]:
        """What the worker will rebuild the proposal from. The host's own body.

        Not a serialised ``RunRequest``: ``build_request`` runs in the worker, so there
        is one mapping from payload to proposal rather than one frozen at submission
        time. A fix to that mapping then applies to everything still queued instead of
        only to what is submitted afterwards.
        """
        return dict(request.data) if isinstance(request.data, dict) else {"body": request.data}

    def assert_own_tenant(self, request: Request, proposal: RunRequest) -> None:
        """Refuse a proposal that acts for a tenant the caller does not hold.

        This is the confused deputy, and it is not a typo to be tidied up: the caller
        is authenticated, the engine would happily produce a perfectly sealed
        attestation, and the record would name a tenant whose data the caller was
        never entitled to touch. Refused before the engine is reached, so no run
        exists and no budget is spent.

        A caller whose tenant could not be resolved at all is refused too. There is no
        reading of "we could not tell who you are" that permits acting for someone.
        """
        held = self.tenant_for(request)
        if held is None:
            raise PermissionDenied(
                "no tenant could be resolved for this caller, so there is no tenant "
                "it may act for. Wire tenant_for() to your identity system."
            )
        if str(proposal.tenant) != held:
            raise PermissionDenied(
                f"the proposal acts for tenant {str(proposal.tenant)!r} but the caller "
                f"holds {held!r}. Refused before the run: a sealed attestation naming "
                f"the wrong tenant is worse than no attestation at all."
            )

    def respond(
        self,
        result: RunResult,
        *,
        disclosure: DisclosureProfile = DisclosureProfile.SUBJECT,
    ) -> Response:
        """The whole record, at the status its verdict implies."""
        return Response(
            RunResultSerializer(result.attestation, disclosure=disclosure).data,
            status=self.STATUS_FOR[result.verdict],
        )
