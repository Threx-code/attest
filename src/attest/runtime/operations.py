"""The operational surface, as a service. No UI, no permission model, no opinions on roles.

A control plane needs a console: someone has to flip the kill switch at 3am, work the
approval queue, check a chain, and see whether the queue is draining. What that someone
is *allowed* to do is not this package's decision. Every adopter already has roles,
groups, SSO claims and an approval hierarchy, and a framework that shipped its own would
either be ignored or — worse — be wired up beside the real one and drift from it.

.. code-block:: text

    THE FRAMEWORK OWNS                    THE HOST OWNS
    ─────────────────────────────         ────────────────────────────────
    what the operations are               who may perform them
    that each names an operator           how that operator is authenticated
    that each states a reason             what the console looks like
    that each is recorded                 which roles map to which operation

So: **this service authorises nothing.** It is deliberately unsafe to expose directly,
and it says so rather than growing a half-model of permissions that a host would have to
fight. Wrap it in your own view, with your own `permission_classes`, your own role
check, your own audit of who logged in.

What it does insist on — because these are integrity properties rather than policy — is
that every mutating operation **names an operator and states a reason**, and that both
are recorded on the append-only trail before the change takes effect. A kill switch
flipped by nobody, for no stated reason, is indistinguishable afterwards from a
misconfiguration, and the incident review has nothing to work with.

.. code-block:: python

    # your view, your rules
    class KillSwitchView(APIView):
        permission_classes = (IsIncidentCommander,)

        def post(self, request):
            ops.disable(
                capability=request.data["capability"],
                tenant=TenantId(request.data["tenant"]),
                by=Operator(actor=request.user.pk, roles=frozenset(request.user.roles)),
                reason=request.data["reason"],
            )
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, ClassVar, NoReturn, Protocol, cast, runtime_checkable

from attest.kernel.canonical import NULL_HASH, Canonical
from attest.kernel.effects import EffectState
from attest.kernel.errors import ContractViolation
from attest.kernel.identifiers import Hash, RunId, RunIds
from attest.kernel.verdicts import Verdict

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime, timedelta

    from attest.capabilities.reconciliation import ReconciliationItem, Resolver
    from attest.kernel.attestation import Attestation, EffectRecord
    from attest.kernel.audit import AuditEvent, RunSeal
    from attest.kernel.identifiers import ActorId, TenantId
    from attest.kernel.ports import ApprovalStore, AuditSink, Clock, RunStore, Signer

__all__ = [
    "AutonomyMode",
    "AutonomyStore",
    "OperationRecord",
    "OperationalQueue",
    "OperationsService",
    "Operator",
    "QueueHealth",
    "Reconciliation",
]


@dataclass(frozen=True, slots=True)
class Operator:
    """Who is performing an operational action. **Not an authorisation.**

    Carrying ``roles`` does not mean the service checks them — it does not. They are
    here because the *record* of an operation is worth much more when it says the
    capability was disabled by someone acting as an incident commander than when it
    says it was disabled by ``user_4471``.
    """

    actor: ActorId
    roles: frozenset[str] = frozenset()
    tenant: TenantId | None = None
    """The tenant this operator acts for, when they are scoped to one.

    **Enforced when set.** It used to be carried and read by nothing, which is worse
    than absent: a host wrapping this would reasonably read it as scoping, and it
    scoped nothing. ``None`` still means unscoped — a platform operator during an
    incident is a real thing — and which operators get that is the host's decision.
    """

    def may_act_for(self, tenant: TenantId) -> bool:
        """Whether this operator may touch that tenant's records."""
        return self.tenant is None or self.tenant == tenant

    def assert_may_act_for(self, tenant: TenantId, *, operation: str) -> None:
        if not self.may_act_for(tenant):
            raise ContractViolation(
                f"operator {self.actor!r} is scoped to tenant {self.tenant!r} and "
                f"attempted {operation} for {tenant!r}. Refusing: a scope that is "
                f"carried and not checked is not a scope."
            )

    def __post_init__(self) -> None:
        if not self.actor:
            raise ContractViolation(
                "an operation must name who performed it. An anonymous kill switch is "
                "indistinguishable from a misconfiguration when the incident is reviewed."
            )


class AutonomyMode:
    """How much a capability may do without a human. Mirrors the stored vocabulary."""

    AUTO = "auto"
    APPROVE = "approve"
    BLOCKED = "blocked"

    ALL = (AUTO, APPROVE, BLOCKED)


@runtime_checkable
class AutonomyStore(Protocol):
    """Where the kill switch lives.

    A row rather than a deploy, because a control you can only exercise by shipping
    code is not a control you can exercise during an incident.
    """

    def set_mode(
        self, *, tenant: TenantId, capability: str, mode: str, enabled: bool, by: str
    ) -> None: ...

    def modes(self, *, tenant: TenantId | None = None) -> Sequence[Mapping[str, object]]: ...


@runtime_checkable
class OperationalQueue(Protocol):
    """What a console needs from a queue. Structural, so a host's own queue fits.

    Separate from ``RunWorkQueue`` because these are the *operator's* questions rather
    than the worker's, and a web process that can answer them should not thereby be
    able to claim work.
    """

    def depth(self) -> int: ...

    def oldest_waiting(self, *, now: datetime | None = None) -> timedelta | None: ...

    def counts(self) -> Mapping[str, int]: ...

    def reclaim_expired(self, *, now: datetime | None = None) -> Sequence[str]: ...

    def trail(self, dispatch_id: str) -> Sequence[object]: ...


@dataclass(frozen=True, slots=True)
class OperationRecord:
    """What an operation did, for the caller and for the trail."""

    operation: str
    operator: ActorId
    reason: str
    at: datetime
    target: str = ""
    detail: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Reconciliation:
    """What a sweep established, and **where it was written**.

    The run id matters as much as the outcomes. Reconciliation events cannot go on the
    original run — it is sealed, and the append-only guard refuses inserts for a closed
    chain — so they go on a new run that supersedes it. A caller handed only the items
    would have no way to find the record it had just created, and would reasonably look
    for it under the original id and find nothing.
    """

    record: RunId
    """The run the reconciliation events and the corrected attestation live under."""

    original: RunId
    items: tuple[ReconciliationItem, ...] = ()
    superseded: bool = False
    """Whether a corrected attestation was written. False when nothing resolved."""

    def __bool__(self) -> bool:
        """Truthy when the sweep did anything, so ``if not ops.reconcile(...)`` reads right."""
        return bool(self.items)


@dataclass(frozen=True, slots=True)
class QueueHealth:
    """Depth alone hides a stalled queue. Five waiting is fine; five waiting an hour is not."""

    depth: int
    oldest_waiting: timedelta | None
    running: int = 0
    held: int = 0
    failed: int = 0

    @property
    def stalled(self) -> bool:
        """Work is waiting and nothing is moving. The page-worthy shape."""
        return self.depth > 0 and self.running == 0


class OperationsService:
    """Operational actions over the ports. Wrap it in your own authorised view.

    Every dependency is optional so a host can expose the parts it has. A method whose
    port is missing raises rather than silently doing nothing — an operator who clicks
    "disable" and gets a success message that disabled nothing is worse off than one
    who gets an error.
    """

    __slots__ = ("_approvals", "_audit", "_autonomy", "_clock", "_queue", "_runs", "_signer")

    #: What ``queue`` must provide. Structural rather than nominal, so a host's own
    #: queue satisfies it without importing anything from here.
    QUEUE_OPERATIONS: ClassVar[tuple[str, ...]] = (
        "depth",
        "oldest_waiting",
        "reclaim_expired",
        "trail",
    )

    def __init__(
        self,
        *,
        clock: Clock,
        autonomy: AutonomyStore | None = None,
        approvals: ApprovalStore | None = None,
        runs: RunStore | None = None,
        audit: AuditSink | None = None,
        queue: OperationalQueue | None = None,
        signer: Signer | None = None,
    ) -> None:
        self._clock = clock
        self._autonomy = autonomy
        self._approvals = approvals
        self._runs = runs
        self._audit = audit
        self._queue = queue
        self._signer = signer

    # ── The kill switch ──────────────────────────────────────────────────────

    def disable(
        self, *, capability: str, tenant: TenantId, by: Operator, reason: str
    ) -> OperationRecord:
        """Stop a capability acting, now, without a deploy.

        The reason is mandatory. During the incident everybody knows why; two weeks
        later, when someone asks whether it can be turned back on, nobody does.
        """
        return self._set_autonomy(
            capability=capability,
            tenant=tenant,
            mode=AutonomyMode.BLOCKED,
            enabled=False,
            by=by,
            reason=reason,
            operation="autonomy.disabled",
        )

    def enable(
        self,
        *,
        capability: str,
        tenant: TenantId,
        by: Operator,
        reason: str,
        mode: str = AutonomyMode.APPROVE,
    ) -> OperationRecord:
        """Turn a capability back on. Defaults to ``approve``, never to ``auto``.

        Re-enabling straight to unattended operation is how an incident recurs an hour
        after it was closed. A host that means ``auto`` says so explicitly.
        """
        if mode not in AutonomyMode.ALL:
            raise ContractViolation(f"{mode!r} is not an autonomy mode; one of {AutonomyMode.ALL}")
        return self._set_autonomy(
            capability=capability,
            tenant=tenant,
            mode=mode,
            enabled=True,
            by=by,
            reason=reason,
            operation="autonomy.enabled",
        )

    def autonomy(self, *, tenant: TenantId | None = None) -> Sequence[Mapping[str, object]]:
        """What is currently allowed to run unattended. A read, so no reason is required."""
        return self._require_autonomy().modes(tenant=tenant)

    def _set_autonomy(
        self,
        *,
        capability: str,
        tenant: TenantId,
        mode: str,
        enabled: bool,
        by: Operator,
        reason: str,
        operation: str,
    ) -> OperationRecord:
        self._assert_reason(reason, operation)
        by.assert_may_act_for(tenant, operation=operation)
        self._require_autonomy().set_mode(
            tenant=tenant,
            capability=capability,
            mode=mode,
            enabled=enabled,
            # Canonically encoded, not delimiter-joined. `f"{actor}|{roles}|{reason}"`
            # put three fields in one column with no escaping, and `reason` is
            # operator-supplied free text — so the audit record of a kill-switch change
            # was parseable only by convention, and an actor id or a reason containing
            # "|" made it ambiguous.
            by=Canonical.encode(
                {"actor": str(by.actor), "roles": sorted(by.roles), "reason": reason}
            ).decode(),
        )
        return OperationRecord(
            operation=operation,
            operator=by.actor,
            reason=reason,
            at=self._clock.now(),
            target=f"{tenant}/{capability}",
            detail={"mode": mode, "enabled": str(enabled)},
        )

    # ── The approval queue ───────────────────────────────────────────────────

    def pending(
        self, *, tenant: TenantId | None = None, by: Operator | None = None
    ) -> Sequence[object]:
        """Everything awaiting a human, within the operator's scope.

        ``by`` is optional so a platform console can list everything, and honoured when
        given: a scoped operator asking for another tenant's queue is refused rather
        than served. A scope carried and not checked is not a scope.
        """
        if by is not None:
            if tenant is None:
                tenant = by.tenant
            if tenant is not None:
                by.assert_may_act_for(tenant, operation="list pending actions")
        if self._approvals is None:
            self._missing("approvals", "list pending actions")
        store = self._approvals
        lister = getattr(store, "pending", None)
        if lister is None:
            raise ContractViolation(
                "this approval store cannot list pending actions. The port requires "
                "expiry to be enforced but not the queue to be readable; a console "
                "needs both."
            )
        return list(lister(tenant))

    def resolve(
        self, *, approval_id: str, approved: bool, by: Operator, role: str
    ) -> OperationRecord:
        """Record a decision through the store, so its refusals apply.

        Going through the store rather than writing the row is the point: expiry,
        the empty-role refusal and the self-approval refusal all live there, and a
        console that bypassed them would be the one path where dual control does not
        hold.
        """
        if self._approvals is None:
            self._missing("approvals", "resolve an approval")
        store = self._approvals
        now = self._clock.now()
        store.resolve(approval_id, approved=approved, approver=by.actor, at=now, role=role)
        return OperationRecord(
            operation="approval.granted" if approved else "approval.rejected",
            operator=by.actor,
            reason=role,
            at=now,
            target=approval_id,
        )

    def expire_due(self, *, by: Operator) -> Sequence[str]:  # noqa: ARG002
        """Sweep lapsed approvals. Safe to run on a timer, and recorded when it acts.

        ``by`` is required and unused: the store writes an ``approval.expired`` entry
        per lapsed action, and who ran the sweep belongs in the host's own console
        record. Dropping the argument would let a console expire a queue anonymously.
        """
        if self._approvals is None:
            self._missing("approvals", "expire pending actions")
        return list(self._approvals.expire_due(self._clock.now()))

    # ── The record ───────────────────────────────────────────────────────────

    def attestation(self, run_id: RunId) -> Attestation | None:
        """One run's record, verified against its own content hash by the codec."""
        if self._runs is None:
            self._missing("runs", "read an attestation")
        return self._runs.get(run_id)

    def verify_chain(self, run_id: RunId, *, seal: RunSeal | None = None) -> object:
        """Re-derive the chain from stored events. Never trusts the stored linkage.

        This is the operation an auditor actually asks for, and the one a console must
        not fake with a green tick derived from a ``sealed`` boolean column.
        """
        from attest.capabilities.audit import ChainSealer
        from attest.kernel.audit import ChainVerifier

        if self._audit is None:
            self._missing("audit", "verify a chain")
        events: Sequence[AuditEvent] = self._audit.read_chain(run_id)
        if not events:
            raise ContractViolation(
                f"run {run_id!r} has no stored events. An empty chain verifies "
                f"vacuously, so it is refused rather than reported as intact."
            )
        if seal is None:
            record = None if self._runs is None else self._runs.get(run_id)
            seal = None if record is None else record.seal
        sealed, _ = ChainSealer().seal(
            events,
            run_id=run_id,
            attestation_hash=seal.attestation_hash if seal is not None else Hash(NULL_HASH),
            sealed_at=self._clock.now(),
        )
        return ChainVerifier.verify(sealed, run_id=run_id, seal=seal, signer=self._signer)

    # ── Reconciliation ───────────────────────────────────────────────────────

    def reconcile(
        self,
        run_id: RunId,
        *,
        resolver: object,
        by: Operator,
        sla: timedelta,
        reason: str = "",
    ) -> Reconciliation:
        """Ask the upstream what became of this run's outstanding effects, and record it.

        ``ReconciliationSweep`` shipped complete and **nothing in the package called
        it**. Only the test suite imported it. So an ``UNKNOWN`` effect — a payment that
        may or may not have left, which is the state this entire framework exists to
        represent honestly rather than guess about — was terminal for the run and a work
        item with no worker. The module docstring says resolution "produces an audit
        event and supersedes the attestation"; nothing produced either.

        That is the section 7 pattern in its purest form. The capability is written,
        tested, documented and correct, and it is not a control, because a control is
        something that runs.

        .. rubric:: Why this is governed rather than an update

        Deciding after the fact that a payment did happen **is a decision**. An
        undocumented one is indistinguishable from editing the record, so:

        - every item produces an ``effect.reconciled`` event, including
          ``STILL_UNKNOWN`` — "we asked and could not find out" is a finding, and a
          sweep recording only its successes shows a clean history while the same
          effect goes unresolved for a week;
        - the attestation is **superseded**, never mutated. Both records are retained,
          because a reader who acted on the ``UNKNOWN`` record must still be able to see
          exactly what they acted on;
        - ``by`` is recorded on every item. A human deciding what an upstream could not
          tell us is a different kind of evidence from an automated resolution, and a
          record that cannot tell them apart is worth less than one that can.

        ``resolver`` is host code: only the external system knows. A framework that
        answered this itself would be inventing the answer it exists to avoid inventing.
        """
        from attest.capabilities.reconciliation import ReconciliationSweep

        if self._runs is None:
            self._missing("runs", "reconcile a run")
        if self._audit is None:
            self._missing("audit", "reconcile a run")
        self._assert_reason(reason or "scheduled reconciliation sweep", "reconcile")

        attestation = self._runs.get(run_id)
        if attestation is None:
            raise ContractViolation(
                f"run {run_id!r} has no attestation, so there is nothing to reconcile "
                f"against. Refusing rather than recording a resolution for a run this "
                f"deployment has no record of."
            )

        now = self._clock.now()
        sweep = ReconciliationSweep(sla=sla)
        outstanding = sweep.overdue(attestation.effects, now=now)
        if not outstanding:
            return Reconciliation(record=run_id, original=run_id)

        items = sweep.resolve(
            outstanding,
            resolver=cast("Resolver", resolver),
            now=now,
            actor=by.actor,
        )

        # **The events go to the reconciliation run, not the original.** ATT-59.
        #
        # The original run is sealed. Its seal binds a dense event count, the append-only
        # guard refuses inserts for a closed run, and `DjangoSealRegistry` arms that
        # guard the moment a run seals — so appending `effect.reconciled` to the
        # original would have been rejected by the database, in production, on the path
        # that resolves a payment nobody can account for. The review found this before
        # either fix shipped and called it "the sort of collision that gets discovered
        # at 3am".
        #
        # Of the two resolutions it offered, this is the first: reconciliation opens a
        # **new run** that supersedes the original. The alternative — an append-after-seal
        # exception for reconciliation events — would put a hole in the one guarantee
        # that is supposed to be structural, and a hole with a name is still a hole.
        #
        # The id is opened even when nothing moved, because a STILL_UNKNOWN sweep is a
        # finding that needs somewhere to live, and the sealed original is not it.
        record = self._correction_id(run_id, items)
        self._audit.append_many(sweep.events(items, run_id=record))
        superseded = self._supersede(attestation, items, at=now, record=record)
        return Reconciliation(
            record=record, original=run_id, items=tuple(items), superseded=superseded
        )

    def _supersede(
        self,
        attestation: Attestation,
        items: Sequence[ReconciliationItem],
        *,
        at: datetime,
        record: RunId,
    ) -> bool:
        """Write the corrected record, retaining the original.

        Skipped when nothing actually moved: an attestation superseded by an identical
        one adds a record and no information, and a supersession chain full of those is
        one nobody reads.
        """
        from attest.capabilities.reconciliation import ReconciliationOutcome

        moved = {
            id(item.record): item
            for item in items
            if item.outcome is not ReconciliationOutcome.STILL_UNKNOWN
        }
        if not moved or self._runs is None:
            return False

        corrected = tuple(
            self._settled(record, moved[id(record)]) if id(record) in moved else record
            for record in attestation.effects
        )
        correction = record
        self._runs.supersede(
            attestation.run_id,
            replace(
                attestation,
                run_id=correction,
                # The context names the run it was captured for, and the kernel refuses
                # a record whose two disagree — "the record would describe a different
                # run from the one it claims". Everything else in the context is
                # unchanged: the correction is about what the world turned out to be,
                # not about what was captured at the time.
                context=replace(attestation.context, run_id=correction),
                verdict=self._corrected_verdict(corrected, attestation.verdict),
                effects=corrected,
                created_at=at,
                supersedes=attestation.run_id,
                # The seal covered the original effects and no longer describes these.
                # Carrying it forward would produce a record whose chain verifies
                # against content it does not contain, which is worse than an unsealed
                # correction: the host reseals through its Sealer, and until it does the
                # absence is visible.
                seal=None,
            ),
        )
        return True

    @staticmethod
    def _corrected_verdict(effects: Sequence[EffectRecord], original: Verdict) -> Verdict:
        """The verdict the corrected record deserves, given what the effects turned out to be.

        Leaving it at ``UNKNOWN`` would be the whole failure in miniature. The run was
        ``UNKNOWN`` *because* an effect was, and a correction that establishes the effect
        committed while still reporting "we do not know" is a record that contradicts its
        own contents — and it is the record a regulator reads.

        The same three rules the verdict resolver applies to effects, and deliberately
        no more: this re-derives what the *effects* say and does not re-evaluate any
        warrant. Nothing about the evidence, the authority or the boundary changed
        because a payment turned out to have settled, and re-running those checks against
        state captured months ago would produce an answer about today rather than about
        the run.
        """
        states = {record.state for record in effects}
        if EffectState.UNKNOWN in states:
            return Verdict.UNKNOWN
        if EffectState.COMMITTED in states and states & {
            EffectState.FAILED,
            EffectState.REFUSED,
        }:
            # Part of the world moved and part did not. Reporting either as the whole
            # answer would be false.
            return Verdict.INCOMPLETE
        if original in (Verdict.UNKNOWN, Verdict.INCOMPLETE):
            # The run was only ever one of these because of the effects, and they have
            # now resolved one way. A refused effect is a refusal; a committed one leaves
            # the qualification that this was established after the fact rather than
            # observed at the time, which ALLOW would hide.
            return (
                Verdict.ALLOW_WITH_WARNINGS if EffectState.COMMITTED in states else Verdict.REFUSE
            )
        return original

    @staticmethod
    def _correction_id(run_id: RunId, items: Sequence[ReconciliationItem]) -> RunId:
        """A distinct id for the corrected record, derived from what the sweep found.

        Derived rather than minted, and derived from the **outcomes** rather than from
        the clock, which makes re-running the same sweep idempotent: it produces the
        same id, so ``create`` refuses the duplicate instead of writing a second
        near-identical record. A supersession chain full of those is one nobody reads.

        Not ``RunIds.attempt``: this is not another attempt at the run. The run finished
        and its effects were later established. A different marker keeps the two
        distinguishable to anyone reading a list of ids.

        Note what is hashed and what is not. The **record's** reference goes in; the
        newly *resolved* one does not. That is deliberate. Including the resolved
        reference would give two sweeps that disagree about a payment two different
        ids, so both corrections would store cleanly and the contradiction would sit
        there silently. Excluding it makes them collide, and the store refuses the
        second for having different content — which leaves an operator with a
        contradiction to resolve. That is the correct amount of friction for "did this
        GBP 500,000 transfer settle or not".
        """
        digest = hashlib.sha256(
            "\x00".join(
                f"{item.record.action.tool}:{item.outcome.value}:{item.record.external_reference}"
                for item in items
            ).encode()
        ).hexdigest()[:8]
        return RunId(f"{RunIds.dispatch_of(run_id)}~reconciled-{digest}")

    @staticmethod
    def _settled(record: EffectRecord, item: ReconciliationItem) -> EffectRecord:
        from attest.capabilities.reconciliation import ReconciliationOutcome

        state = (
            EffectState.COMMITTED
            if item.outcome is ReconciliationOutcome.COMMITTED
            else EffectState.FAILED
        )
        return replace(
            record,
            state=state,
            external_reference=item.external_reference or record.external_reference,
            detail=(
                f"reconciled from {record.state.value} at {item.resolved_at.isoformat()}"
                f"{f' by {item.resolved_by}' if item.resolved_by else ''}"
                f"{f': {item.detail}' if item.detail else ''}"
            ),
        )

    # ── The queue ────────────────────────────────────────────────────────────

    def queue_health(self) -> QueueHealth:
        """Depth, age and what is in flight. What an operator pages on."""
        queue = self._queue
        if queue is None:
            self._missing("queue", "report queue health")
        states = queue.counts()
        return QueueHealth(
            depth=queue.depth(),
            # The service's clock, not the store's. Two clocks make a queue age that
            # disagrees with the run timestamps beside it in the same console.
            oldest_waiting=queue.oldest_waiting(now=self._clock.now()),
            running=int(states.get("running", 0)),
            held=int(states.get("held", 0)),
            failed=int(states.get("failed", 0)),
        )

    def reclaim_stuck(self, *, by: Operator, reason: str) -> Sequence[str]:  # noqa: ARG002
        """Return runs whose worker died to the queue. Recorded, because it is a decision.

        ``by`` is required and unused here on purpose: the queue writes its own
        ``dispatch.abandoned`` entry naming the worker that vanished, and the operator
        who ordered the sweep belongs in the record the host keeps of who did what in
        the console. Making it optional would let a console call this anonymously.
        """
        self._assert_reason(reason, "queue.reclaimed")
        if self._queue is None:
            self._missing("queue", "reclaim stuck runs")
        return list(self._queue.reclaim_expired(now=self._clock.now()))

    def trail(self, dispatch_id: str) -> Sequence[object]:
        """The delivery and approval history for one run.

        The question the chain cannot answer: did anything ever pick this up.
        """
        if self._queue is None:
            self._missing("queue", "read a dispatch trail")
        return list(self._queue.trail(dispatch_id))

    # ── Guards ───────────────────────────────────────────────────────────────

    def _require_autonomy(self) -> AutonomyStore:
        if self._autonomy is None:
            self._missing("autonomy", "change or read autonomy")
        return self._autonomy

    @staticmethod
    def _missing(name: str, action: str) -> NoReturn:
        """Refuse loudly when a port was not supplied.

        An operator who clicks "disable" and is told it worked, when nothing was
        wired, is worse off than one who gets an error: they stop looking.
        """
        raise ContractViolation(
            f"OperationsService was built without a {name!r} port, so it cannot "
            f"{action}. Pass it, or do not expose that operation."
        )

    @staticmethod
    def _assert_reason(reason: str, operation: str) -> None:
        if not reason.strip():
            raise ContractViolation(
                f"{operation} requires a reason. During the incident everyone knows "
                f"why; two weeks later, when someone asks whether this can be reverted, "
                f"nobody does — and an unexplained control change is indistinguishable "
                f"from a misconfiguration."
            )
