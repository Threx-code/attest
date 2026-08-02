"""Port implementations over the reference models.

.. rubric:: Real ports, over the kernel's codec

These take :class:`~attest.kernel.attestation.Attestation` and
:class:`~attest.kernel.audit.AuditEvent` objects and hand them to
:class:`~attest.kernel.codec.AttestationCodec`, so a stored record can be read back as
the object that was written — and, because decoding verifies the content hash, a row
edited in the database fails loudly at read time rather than coming back as a
plausible record that says something else.

A few columns are denormalised out of the payload — ``verdict``, ``warnings``,
``is_final`` — because they are what a dashboard renders, and a renderer that must
decode a blob to find the warnings is a renderer that will eventually stop bothering.

.. rubric:: Where the guarantees actually live

.. code-block:: text

    CONTRACT                    ENFORCED BY
    ────────────────────────    ──────────────────────────────────
    append-only audit           BEFORE UPDATE/DELETE trigger
    immutable attestations      BEFORE UPDATE trigger
    single-use nonce            PRIMARY KEY on the nonce
    atomic reserve-then-spend   SELECT … FOR UPDATE in a transaction

None of those are application-level promises. "We only ever INSERT" is a convention,
and conventions decay.
"""

from __future__ import annotations

import os
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar, cast
from uuid import uuid4

from django.db import IntegrityError, models, transaction
from django.utils import timezone

from attest.adapters.django.models import (
    AttestationRecord,
    AuditEventRecord,
    AutonomyPolicy,
    BudgetReservation,
    BudgetSpend,
    DispatchEvent,
    MemoryRecord,
    PendingAction,
    QueuedRun,
    RedeemedNonce,
    RevokedGrant,
    SealedRun,
)
from attest.capabilities.memory import MemoryGuard
from attest.kernel.audit import EventType
from attest.kernel.authority import ApprovalRecord
from attest.kernel.canonical import NULL_HASH, Canonical
from attest.kernel.codec import AttestationCodec, AuditEventCodec
from attest.kernel.errors import (
    ApprovalStoreError,
    AuditSinkError,
    SelfApprovalError,
    StoreError,
)
from attest.kernel.identifiers import ActorId, ApprovalId, Hash, RunId, SubjectId, TenantId
from attest.kernel.memory import MemoryClass, MemoryItem
from attest.runtime.dispatch import RunEnvelope

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from attest.kernel.attestation import Attestation
    from attest.kernel.audit import AuditEvent, RunSeal
    from attest.kernel.authority import AuthorizationGrant
    from attest.kernel.identifiers import GrantId, Nonce

__all__ = [
    "DjangoApprovalStore",
    "DjangoAuditSink",
    "DjangoAutonomyStore",
    "DjangoBudgetStore",
    "DjangoMemoryStore",
    "DjangoNonceStore",
    "DjangoRunQueue",
    "DjangoRunStore",
    "DjangoSealRegistry",
]


class DjangoRunStore:
    """Attestations, immutable once written.

    Satisfies :class:`~attest.kernel.ports.RunStore`. There is no ``update``, by
    design: a correction is a new record referencing the old, so a reader who relied
    on the original can still see exactly what they relied on.
    """

    __slots__ = ()

    def create(self, attestation: Attestation) -> RunId:
        try:
            AttestationRecord.objects.create(
                run_id=str(attestation.run_id),
                tenant_id=str(attestation.context.identity.tenant),
                verdict=attestation.verdict.value,
                answer=attestation.answer,
                warnings=self.warnings_of(attestation),
                content_hash=str(attestation.content_hash()),
                payload=AttestationCodec.encode(attestation),
                created_at=attestation.created_at,
                is_final=attestation.is_final,
                sealed=attestation.seal is not None,
                seal_signature=(
                    "" if attestation.seal is None else (attestation.seal.signature or "")
                ),
                supersedes="" if attestation.supersedes is None else str(attestation.supersedes),
            )
        except IntegrityError as exc:
            raise StoreError(
                f"attestation {attestation.run_id!r} already exists. Attestations are "
                f"immutable; a correction is a new record via supersede()."
            ) from exc
        return attestation.run_id

    def get(self, run_id: RunId) -> Attestation | None:
        """The stored attestation, **verified against its own content hash**.

        A row whose payload no longer hashes to what was recorded raises rather than
        returning: an altered record that reads back cleanly is the failure this whole
        system exists to make impossible.
        """
        record = AttestationRecord.objects.filter(pk=str(run_id)).first()
        if record is None:
            return None
        return AttestationCodec.decode(bytes(record.payload))

    def record(self, run_id: RunId) -> AttestationRecord | None:
        """The raw row, for callers that want the denormalised columns without decoding."""
        return AttestationRecord.objects.filter(pk=str(run_id)).first()

    def supersede(self, run_id: RunId, replacement: Attestation) -> RunId:
        """Record a correction. **Both records are retained.**

        Only the forward pointer on the original is written; the immutability trigger
        still forbids touching its content.
        """
        with transaction.atomic():
            if not AttestationRecord.objects.filter(pk=str(run_id)).exists():
                raise StoreError(f"cannot supersede unknown run {run_id!r}")
            stored = AttestationRecord.objects.filter(pk=str(replacement.run_id)).first()
            if stored is None:
                self.create(replacement)
            elif stored.content_hash != str(replacement.content_hash()):
                # This used to be `if not exists: create`, so a replacement id that
                # already held *different* content was silently skipped. No overwrite,
                # and no error either: the caller believes their correction was stored
                # while a different record sits under that id. Identical content is an
                # idempotent retry and still passes.
                raise StoreError(
                    f"attestation {replacement.run_id!r} already exists with different "
                    f"content. Refusing rather than reporting a supersession that "
                    f"stored nothing."
                )
            AttestationRecord.objects.filter(pk=str(run_id)).update(
                superseded_by=str(replacement.run_id)
            )
        return replacement.run_id

    def superseded_by(self, run_id: RunId) -> RunId | None:
        record = AttestationRecord.objects.filter(pk=str(run_id)).first()
        if record is None or not record.superseded_by:
            return None
        return cast("RunId", record.superseded_by)

    @staticmethod
    def warnings_of(attestation: Attestation) -> list[str]:
        """The qualifications a reader must see, lifted out of the warrant findings.

        Promoted to a column rather than left inside the payload because this is the
        text a dashboard shows next to the answer, and an ``ALLOW_WITH_WARNINGS``
        figure rendered without it is a material misstatement delivered with a clean
        conscience.

        Which findings count is :meth:`WarrantReport.qualifications`, not a rule
        repeated here — two copies of it drift until one stops surfacing something.
        """
        return [
            message
            for report in attestation.warrants.values()
            for message in report.qualifications()
        ]


class DjangoAuditSink:
    """Append-only event storage. Satisfies :class:`~attest.kernel.ports.AuditSink`.

    ``append_many`` is wrapped in one transaction: a partial batch leaves a chain that
    cannot be sealed densely, which on inspection is indistinguishable from omission —
    the exact condition the seal exists to detect.

    Events are stored **unsealed**. The sink records causal structure; an independent
    sealer assigns the dense 1..N ordering later. A sink that numbered rows on insert
    would reintroduce the ordering bug ADR 0034 exists to fix.
    """

    __slots__ = ()

    def append(self, event: AuditEvent) -> None:
        try:
            AuditEventRecord.objects.create(**self._row(event))
        except Exception as exc:  # any DB failure here must stop the run
            raise AuditSinkError(
                f"could not append audit event for run {event.run_id!r}: {exc}. If we "
                f"cannot record what happened, we must not act."
            ) from exc

    def append_sealed(self, event: AuditEvent, *, attempts: int = 3) -> AuditEvent:
        """Append ONE event with its position and link assigned, now.

        The batch sealer assigns a dense 1..N once a run is over. An **entity** chain is
        never over - a matter accumulates events for years - so "later" never comes, and a
        chain of unsealed rows has ``sequence=NULL`` and ``previous_hash=""`` on every row.
        That is not a chain: there is no link for a deletion to break and no dense sequence
        for it to gap, so the artefact that exists to prove completeness proves nothing.

        **The position is read from the tail, not counted.** ``COUNT(*)`` is O(rows for this
        entity), so recording an act got slower as the entity accumulated history - exactly
        backwards, and worst on the oldest and most consequential matters. The tail read is
        one indexed row.

        **A race fails loudly rather than duplicating.** Two concurrent acts read the same
        tail and compute the same next position; the unique constraint on
        ``(run_id, sequence)`` rejects the loser, which retries against the new tail. Without
        it both rows persist at the same nominal position, which is a fork presented as a
        chain - and the application would have chosen its own sequence from a racy read,
        which is the precise thing the seal exists to prevent.
        """
        for attempt in range(1, attempts + 1):
            tail = (
                AuditEventRecord.objects.filter(run_id=str(event.run_id), sequence__isnull=False)
                .order_by("-sequence")
                .first()
            )
            previous = (
                AuditEventCodec.decode(bytes(tail.payload)).event_hash()
                if tail is not None
                else Hash(NULL_HASH)
            )
            sealed = event.sealed_as((tail.sequence + 1) if tail is not None else 1, previous)
            try:
                with transaction.atomic():
                    AuditEventRecord.objects.create(**self._row(sealed))
            except IntegrityError:
                if attempt == attempts:
                    raise AuditSinkError(
                        f"could not place event in chain {event.run_id!r} after {attempts} "
                        f"attempts: another writer took every position we computed. The act "
                        f"must not commit without its chain entry."
                    ) from None
                continue
            except Exception as exc:
                raise AuditSinkError(
                    f"could not append sealed audit event for {event.run_id!r}: {exc}. If we "
                    f"cannot record what happened, we must not act."
                ) from exc
            return sealed
        raise AuditSinkError("unreachable: the retry loop always returns or raises")

    def append_many(self, events: Sequence[AuditEvent]) -> None:
        if not events:
            return
        try:
            with transaction.atomic():
                AuditEventRecord.objects.bulk_create(
                    AuditEventRecord(**self._row(event)) for event in events
                )
        except Exception as exc:  # see append()
            raise AuditSinkError(f"could not append audit batch: {exc}") from exc

    def read_chain(self, run_id: RunId) -> Sequence[AuditEvent]:
        """Decode the stored rows back into events, in sealed order."""
        return tuple(AuditEventCodec.decode(bytes(row.payload)) for row in self.rows(run_id))

    def rows(self, run_id: RunId) -> Sequence[AuditEventRecord]:
        """The raw rows, for callers inspecting storage rather than the chain."""
        return tuple(AuditEventRecord.objects.filter(run_id=str(run_id)).order_by("sequence", "id"))

    @staticmethod
    def _row(event: AuditEvent) -> dict[str, Any]:
        return {
            "run_id": str(event.run_id),
            "event_type": event.event_type,
            "occurred_at": event.occurred_at,
            "payload": AuditEventCodec.encode(event),
            "sequence": event.sequence,
            "previous_hash": "" if event.previous_hash is None else str(event.previous_hash),
        }


class DjangoNonceStore:
    """Single-use redemption, guaranteed by the primary key rather than by a read."""

    __slots__ = ()

    def redeem(self, nonce: Nonce, grant_id: GrantId, *, at: datetime | None = None) -> bool:
        """Consume ``nonce``. ``True`` at most once, even under concurrency.

        Implemented as an insert that may fail, not a check followed by an insert.
        The latter lets two concurrent callers both observe an unused nonce and both
        proceed — the entire replay defence, gone.

        ``at`` is optional so this matches :class:`~attest.kernel.ports.NonceStore`
        exactly, which takes no clock. The default is the database's wall time. That
        is not the ambient-time hazard the kernel bans: this timestamp is a storage
        column for operators, never an input to a hash, so it cannot make a run
        unreproducible. Pass ``at`` where a deterministic replay needs the column to
        match too.
        """
        try:
            RedeemedNonce.objects.create(
                nonce=str(nonce), grant_id=str(grant_id), redeemed_at=at or timezone.now()
            )
        except IntegrityError:
            return False
        return True

    def revoke(self, grant_id: GrantId, *, at: datetime | None = None, reason: str = "") -> None:
        RevokedGrant.objects.get_or_create(
            grant_id=str(grant_id),
            defaults={"revoked_at": at or timezone.now(), "reason": reason},
        )

    def is_revoked(self, grant_id: GrantId) -> bool:
        return RevokedGrant.objects.filter(pk=str(grant_id)).exists()


class DjangoBudgetStore:
    """Reserve-then-commit, inside one transaction with the row locked.

    A budget that is *read* and then acted on is a race: two concurrent runs both
    observe headroom and both spend it. The ceiling check and the reservation happen
    under ``SELECT … FOR UPDATE``, so the second writer blocks and then sees the
    first's reservation.
    """

    __slots__ = ()

    def reserve(
        self, scope: str, amount: str, expires_at: datetime, *, now: datetime | None = None
    ) -> str | None:
        """Reserve against ``scope``. ``None`` when it would breach the ceiling.

        The held total is a **database aggregate**, not a Python sum over fetched rows.
        Pulling every live reservation for a scope into the process to add them up ran
        inside a ``SELECT … FOR UPDATE``, so the row stayed locked for as long as the
        transfer took — the cost grew with the number of concurrent holders at exactly
        the moment contention was highest.

        Expired reservations are excluded from the total rather than counted until a
        sweeper runs. A crashed run held budget it could no longer spend, and the
        ceiling was enforced against money nobody was going to move.
        """
        value = Decimal(amount)
        moment = now if now is not None else timezone.now()
        with transaction.atomic():
            BudgetSpend.objects.get_or_create(scope=scope)
            row = BudgetSpend.objects.select_for_update().get(pk=scope)
            if row.ceiling is not None:
                held = BudgetReservation.objects.filter(
                    scope=scope, expires_at__gt=moment
                ).aggregate(total=models.Sum("amount"))["total"] or Decimal(0)
                if row.amount + held + value > row.ceiling:
                    return None
            # From a monotonic per-scope counter, never from a count of live
            # reservations: a count falls when one is released, so the next
            # reservation would reuse a retired id and a late commit from the
            # previous holder would consume it.
            row.reservation_seq += 1
            row.save(update_fields=["reservation_seq"])
            reservation_id = f"res_{scope}_{row.reservation_seq}"
            BudgetReservation.objects.create(
                reservation_id=reservation_id,
                scope=scope,
                amount=value,
                expires_at=expires_at,
            )
        return reservation_id

    def commit(self, reservation_id: str, actual_amount: str) -> None:
        with transaction.atomic():
            reservation = (
                BudgetReservation.objects.select_for_update().filter(pk=reservation_id).first()
            )
            if reservation is None:
                raise StoreError(f"unknown reservation {reservation_id!r}")
            row = BudgetSpend.objects.select_for_update().get(pk=reservation.scope)
            row.amount = row.amount + Decimal(actual_amount)
            row.save(update_fields=["amount"])
            reservation.delete()

    def release(self, reservation_id: str) -> None:
        BudgetReservation.objects.filter(pk=reservation_id).delete()

    def expire_due(self, now: datetime) -> int:
        """Release reservations past their expiry.

        Reservations expire on the same short clock as a grant, so a crashed run
        cannot hold budget indefinitely.
        """
        deleted, _ = BudgetReservation.objects.filter(expires_at__lte=now).delete()
        return int(deleted)

    def set_ceiling(self, scope: str, ceiling: str | None) -> None:
        BudgetSpend.objects.update_or_create(
            scope=scope,
            defaults={"ceiling": None if ceiling is None else Decimal(ceiling)},
        )

    def spent(self, scope: str) -> str:
        row = BudgetSpend.objects.filter(pk=scope).first()
        return str(row.amount if row else Decimal(0))


class DjangoApprovalStore:
    """Pending human decisions, with expiry actually enforced."""

    __slots__ = ()

    def open(
        self,
        grant: AuthorizationGrant,
        *,
        run_id: RunId,
        expires_at: datetime,
        summary: str = "",
    ) -> str:
        """Open a pending decision against the grant, and return its id.

        The id is derived from the grant plus a per-grant sequence, so a second
        approver on the same action gets a second row rather than overwriting the
        first. Dual control is *two* decisions, and a queue with one row per grant
        cannot represent it.

        ``requested_by`` comes from the grant's actor, which is what makes the
        self-approval refusal in :meth:`resolve` possible at all.
        """
        if expires_at <= grant.issued_at:
            raise ApprovalStoreError(
                "a pending action must expire after it opens; an open-ended hold is a "
                "backlog of half-executed decisions with no owner"
            )
        with transaction.atomic():
            # A UUID rather than a count. `count() + 1` under transaction.atomic() with
            # no row lock is the defect the budget store already fixed with
            # reservation_seq: two concurrent open() calls for one grant read the same
            # count and the second raises IntegrityError. There is no per-grant row to
            # lock here, so the id simply does not depend on how many exist.
            approval_id = f"apr_{grant.grant_id}_{uuid4().hex[:12]}"
            PendingAction.objects.create(
                approval_id=approval_id,
                run_id=str(run_id),
                tenant_id=str(grant.tenant),
                grant_id=str(grant.grant_id),
                action_hash=str(grant.action_hash),
                summary=summary,
                requested_by=str(grant.actor),
                opened_at=grant.issued_at,
                expires_at=expires_at,
            )
        return approval_id

    def resolve(
        self,
        approval_id: str,
        *,
        approved: bool,
        approver: ActorId,
        at: datetime,
        role: str,
    ) -> None:
        """Record a decision, refusing to resolve anything not still pending.

        Three refusals live here, and each closes a way dual control is defeated:

        The filter on ``state`` stops a late click overwriting a decision, which would
        execute an effect whose authorisation window had closed.

        An empty ``role`` is refused because a quorum is defined over roles: a decision
        stored without one counts toward nothing downstream, so the queue would fill
        with approvals the authority layer cannot consume and the run would hold
        forever. Failing at the write is louder than failing at the discharge.

        An approver who is also the ``requested_by`` actor is refused outright. Self
        approval is the most common way dual control is defeated in practice, and a
        check the reviewer has to remember is not a control.
        """
        if not role:
            raise ApprovalStoreError(
                f"approval {approval_id!r} was resolved without a role. An n-of-m "
                f"quorum is defined over roles, so an unattributed decision satisfies "
                f"no obligation — recording it would leave the run pending forever."
            )
        with transaction.atomic():
            pending = (
                PendingAction.objects.select_for_update()
                .filter(pk=approval_id, state=PendingAction.PENDING)
                .first()
            )
            if pending is not None and pending.requested_by == str(approver):
                raise SelfApprovalError(
                    f"actor {approver!r} proposed {approval_id!r} and may not approve "
                    f"it. Self-approval is the most common way dual control is "
                    f"defeated, so it is refused here rather than left to a reviewer."
                )
            updated = PendingAction.objects.filter(
                pk=approval_id, state=PendingAction.PENDING
            ).update(
                state=PendingAction.APPROVED if approved else PendingAction.REJECTED,
                approver=str(approver),
                approver_role=role,
                resolved_at=at,
            )
            if updated and pending is not None:
                # On the dispatch trail rather than in the run's chain. The decision
                # happens after the held run sealed, in another process, possibly days
                # later — folding it into that chain would mean the seal covered an
                # event written long after it was computed.
                self._trail(
                    EventType.APPROVAL_GRANTED if approved else EventType.APPROVAL_REJECTED,
                    dispatch_id=pending.run_id,
                    run_id=pending.run_id,
                    tenant_id=pending.tenant_id,
                    actor=str(approver),
                    detail=f"{approval_id} by {approver!r} as {role!r}",
                    at=at,
                )
        if not updated:
            raise ApprovalStoreError(
                f"approval {approval_id!r} is not pending; it may have expired or "
                f"already been decided, which is a refusal rather than a silent "
                f"overwrite"
            )

    def consume(self, approval_ids: Sequence[ApprovalId], *, grant_id: GrantId) -> None:
        """Mark decisions spent by this grant. Only ever moves unspent to spent.

        The filter on an empty ``redeemed_by_grant`` is the check: a decision already
        attributed to one grant must not be re-attributed to another, because the
        record of *which* authorisation a human gave is the thing being consumed.

        **The row count is the return value, and it has to be checked.** ``UPDATE …
        WHERE`` matching nothing is a successful statement, so this method used to
        report success for a decision it had not consumed — an id that does not exist,
        or one a concurrent grant had already taken. The engine treats a successful
        ``consume`` as "this decision can no longer authorise anything" and executes on
        that basis, so a silent no-op here is ATT-04 with an extra step. The conformance
        suite found this: the in-memory store raised and this one did not, and two
        adapters behind one port disagreeing about a security control is the whole
        reason that suite exists.

        Losing the race is also the *right* outcome to raise on. Two grants reaching one
        decision means only one may have it; the loser refuses its effect, which is
        exactly what should happen to the second of two simultaneous transfers
        authorised by a single approval.
        """
        if not approval_ids:
            return
        wanted = [str(identifier) for identifier in approval_ids]
        spent = PendingAction.objects.filter(pk__in=wanted, redeemed_by_grant="").update(
            redeemed_by_grant=str(grant_id)
        )
        if spent != len(wanted):
            raise IntegrityError(
                f"consume({len(wanted)} decisions) marked only {spent} as spent. The "
                f"rest are unknown to this store or were already taken by another "
                f"grant, so they would still authorise the next identical proposal. "
                f"Refusing rather than reporting a consumption that did not happen."
            )

    def decisions(self, action_hash: Hash) -> tuple[ApprovalRecord, ...]:
        """Every **unspent** decision recorded about *this* action, bound to it.

        Keyed on the action hash rather than the run: an approval that cannot say what
        it was about is a free-floating "yes" that would discharge any obligation it
        were handed to. This is the read side ``Approval`` and ``DualControl`` need —
        without it those obligations have no approvals to count and stay PENDING
        forever, which is why they were unreachable before.
        """
        rows = PendingAction.objects.filter(
            action_hash=str(action_hash),
            state__in=(PendingAction.APPROVED, PendingAction.REJECTED),
            redeemed_by_grant="",
        ).order_by("resolved_at", "approval_id")
        return tuple(
            ApprovalRecord(
                approval_id=ApprovalId(row.approval_id),
                approver=ActorId(row.approver),
                role=row.approver_role,
                approved=row.state == PendingAction.APPROVED,
                decided_at=row.resolved_at or row.opened_at,
                action_hash=Hash(row.action_hash),
                run_id=RunId(row.run_id),
                note=row.summary,
            )
            for row in rows
        )

    def expire_due(self, now: datetime) -> Sequence[str]:
        """Expire everything past its deadline. Returns the ids expired.

        Recorded, not merely applied. An approval that lapsed is a decision the system
        made by doing nothing, and it is the one an applicant is most likely to
        contest — "nobody ever looked at it" has to be answerable.
        """
        with transaction.atomic():
            expiring = list(
                PendingAction.objects.filter(state=PendingAction.PENDING, expires_at__lte=now)
            )
            due = [row.approval_id for row in expiring]
            if due:
                PendingAction.objects.filter(pk__in=due).update(
                    state=PendingAction.EXPIRED, resolved_at=now
                )
            for row in expiring:
                self._trail(
                    EventType.APPROVAL_EXPIRED,
                    dispatch_id=row.run_id,
                    run_id=row.run_id,
                    tenant_id=row.tenant_id,
                    detail=f"{row.approval_id} lapsed at {row.expires_at.isoformat()} undecided",
                    at=now,
                )
        return tuple(due)

    @staticmethod
    def _trail(
        event_type: EventType,
        *,
        dispatch_id: str,
        run_id: str,
        tenant_id: str,
        actor: str = "",
        detail: str = "",
        at: datetime,
    ) -> None:
        """Append one approval-lifecycle event to the same append-only trail.

        The queue and the approval loop are one lifecycle from a reviewer's point of
        view — a run held, someone decided, it resumed — so they share a trail rather
        than living in two tables that have to be joined by hand at the worst moment.
        """
        DispatchEvent.objects.create(
            dispatch_id=dispatch_id,
            run_id=run_id,
            tenant_id=tenant_id,
            event_type=str(event_type),
            occurred_at=at,
            actor=actor,
            detail=detail,
        )

    def pending(self, tenant_id: TenantId | None = None) -> Sequence[PendingAction]:
        queryset = PendingAction.objects.filter(state=PendingAction.PENDING)
        if tenant_id is not None:
            queryset = queryset.filter(tenant_id=str(tenant_id))
        return tuple(queryset.order_by("expires_at"))


class DjangoMemoryStore:
    """Cross-run recall, scoped at the query, screened at the write, and deletable.

    Scope filtering happens *in* the query rather than after it. Filtering afterwards
    means the store was already searched across tenants, so a ranking bug becomes a
    data leak rather than a bad result.

    Every write goes through a :class:`~attest.capabilities.memory.MemoryGuard`. That
    is not decoration: memory is untrusted input the system wrote to itself, and an
    agent that can write "this broker is pre-approved" has achieved persistent prompt
    injection. Screening at recall is too late — the store is already poisoned, and
    every reader is then relying on a filter running correctly. The guard is a
    constructor argument so a scope with a different write policy is a different store
    rather than a flag every caller must remember to pass.
    """

    __slots__ = ("_guard",)

    def __init__(self, guard: MemoryGuard | None = None) -> None:
        self._guard = guard if guard is not None else MemoryGuard()

    @property
    def guard(self) -> MemoryGuard:
        return self._guard

    def recall(
        self,
        query: str,
        *,
        tenant: TenantId,
        subject: SubjectId | None = None,
        limit: int = 10,
        now: datetime | None = None,
    ) -> Sequence[MemoryItem]:
        """Recall within one tenant, excluding anything expired.

        Expiry is applied in the query for the same reason as the tenant filter: an
        item whose TTL has passed was deliberately given one, and returning it for a
        caller to discard makes forgetting to discard it the failure mode.
        """
        moment = now if now is not None else timezone.now()
        queryset = MemoryRecord.objects.filter(tenant_id=str(tenant)).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=moment)
        )
        if subject is not None:
            queryset = queryset.filter(subject_id=str(subject))
        rows = queryset.filter(content__icontains=query).order_by("-created_at")[:limit]
        recalled = tuple(self._item(row) for row in rows)
        # Filtered in the query, asserted after. MemoryGuard.recallable had two tests
        # and no caller, so the second half of "enforced at query and asserted after"
        # was documentation. The assertion is cheap and it is the one that catches a
        # filter someone widens later.
        return MemoryGuard.recallable(recalled, tenant=tenant, now=moment)

    def remember(self, item: MemoryItem) -> None:
        """Store one item, **after the guard has screened it**.

        The guard raises rather than dropping: a refused write the caller never learns
        about is a fact the system believes it stored.
        """
        self._guard.screen_write(item)
        MemoryRecord.objects.create(
            tenant_id=str(item.tenant),
            subject_id="" if item.subject is None else str(item.subject),
            content=item.content,
            content_hash=Canonical.digest(item.content),
            created_at=item.created_at,
            memory_class=str(item.memory_class),
            author=str(item.author),
            author_is_human=item.author_is_human,
            origin_run="" if item.origin_run is None else str(item.origin_run),
            source_attestation=(
                "" if item.source_attestation is None else str(item.source_attestation)
            ),
            expires_at=item.expires_at,
        )

    @staticmethod
    def _item(row: MemoryRecord) -> MemoryItem:
        """Rebuild the value type, keeping the provenance a citation needs.

        A row read back as bare text is hearsay: there is nothing to re-verify against,
        so it could not be cited as support even when it legitimately established one.
        """
        return MemoryItem(
            content=row.content,
            memory_class=MemoryClass(row.memory_class),
            tenant=TenantId(row.tenant_id),
            created_at=row.created_at,
            author=ActorId(row.author),
            author_is_human=row.author_is_human,
            origin_run=RunId(row.origin_run) if row.origin_run else None,
            subject=SubjectId(row.subject_id) if row.subject_id else None,
            source_attestation=(RunId(row.source_attestation) if row.source_attestation else None),
            expires_at=row.expires_at,
        )

    def delete_by_subject(self, subject: SubjectId, *, tenant: TenantId) -> int:
        """Erase everything concerning ``subject``. Actually deletes.

        Memory is subject to erasure requests, which is why it lives here rather than
        in the append-only chain.
        """
        deleted, _ = MemoryRecord.objects.filter(
            tenant_id=str(tenant), subject_id=str(subject)
        ).delete()
        return int(deleted)


class DjangoRunQueue:
    """A durable, leased, audited queue in the database. No broker required.

    Satisfies :class:`~attest.kernel.ports.RunQueue` and
    :class:`~attest.kernel.ports.RunWorkQueue`. Deliberately the default: a host that
    must stand up Redis or RabbitMQ before it can stop holding HTTP workers open will
    keep holding them open.

    .. rubric:: What makes it safe under load

    .. code-block:: text

        CONCERN                    MECHANISM
        ─────────────────────      ─────────────────────────────────────────
        double dispatch            get_or_create on the ticket
        double delivery            claim only moves QUEUED -> RUNNING
        workers serialising        SELECT ... FOR UPDATE SKIP LOCKED
        a worker that dies         a lease, and reclaim_expired()
        a run resumed twice        resume only moves HELD -> QUEUED
        "what happened to it?"     an append-only DispatchEvent per transition

    The lease is the one people leave out. Without it a worker killed mid-run leaves
    the row in ``running`` forever — neither retried nor visibly failed, with a caller
    whose ticket never resolves. Pod evictions are not rare, so that is not a rare
    failure.

    Above a few thousand runs a second the polling itself becomes the cost, and
    :class:`~attest.adapters.celery.CeleryRunQueue` wraps this to add a broker
    notification while keeping the row as the store of record.
    """

    DEFAULT_LEASE: ClassVar[timedelta] = timedelta(minutes=15)
    """Long enough for a run with several model calls, short enough that a dead worker
    is noticed within one. A run that legitimately exceeds it renews rather than
    lengthening the default for everyone."""

    __slots__ = ("_lease", "_worker_id")

    def __init__(self, *, lease: timedelta | None = None, worker_id: str = "") -> None:
        self._lease = lease if lease is not None else self.DEFAULT_LEASE
        self._worker_id = worker_id or f"worker-{os.getpid()}"

    @property
    def worker_id(self) -> str:
        return self._worker_id

    # ── Producer side ────────────────────────────────────────────────────────

    def submit(self, run_id: RunId, envelope: bytes) -> str:
        """Persist the envelope and queue it. **Idempotent on the ticket.**

        A client that retries a timed-out dispatch must not get two runs: the second
        would propose the same effect again under a fresh grant, and the idempotency
        store catches that only when the action carries a key. Here it is refused by
        the primary key, which needs no cooperation from the caller.
        """
        decoded = RunEnvelope.decode(envelope)
        with transaction.atomic():
            _, created = QueuedRun.objects.get_or_create(
                run_id=str(run_id),
                defaults={
                    "tenant_id": str(decoded.tenant),
                    "actor_id": str(decoded.actor),
                    "envelope": envelope,
                    "submitted_at": decoded.submitted_at,
                    "attempt": decoded.attempt,
                },
            )
            if created:
                self._audit(
                    EventType.RUN_QUEUED,
                    dispatch_id=str(run_id),
                    tenant_id=str(decoded.tenant),
                    attempt=decoded.attempt,
                    actor=str(decoded.actor),
                    # The envelope's own instant, not the wall clock. Stamping this
                    # with `now` made the queued event land after the claim whenever
                    # the caller's clock and the database's disagreed, and a trail
                    # whose order contradicts causality answers nothing.
                    at=decoded.submitted_at,
                )
        return f"queued:{run_id}" if created else f"duplicate:{run_id}"

    def resume(self, run_id: RunId, *, by: str = "", now: datetime | None = None) -> str:
        """Re-dispatch a held run from its stored envelope.

        Only a held run resumes. One still queued does not need it, and one that
        finished must not be started again — resuming a settled run would propose its
        effect a second time, which is the failure the whole approval loop exists to
        avoid.
        """
        with transaction.atomic():
            row = QueuedRun.objects.select_for_update().filter(pk=str(run_id)).first()
            if row is None:
                raise StoreError(
                    f"cannot resume unknown dispatch {run_id!r}; there is no envelope to "
                    f"re-dispatch, and the proposal exists nowhere else"
                )
            if row.state != QueuedRun.HELD:
                raise StoreError(
                    f"dispatch {run_id!r} is {row.state!r}, not held. Resuming a settled "
                    f"run would propose its effect a second time."
                )
            envelope = RunEnvelope.decode(bytes(row.envelope)).next_attempt()
            row.envelope = envelope.encode()
            row.attempt = envelope.attempt
            row.state = QueuedRun.QUEUED
            row.started_at = None
            row.lease_expires_at = None
            row.worker_id = ""
            row.detail = ""
            row.save(
                update_fields=[
                    "envelope",
                    "attempt",
                    "state",
                    "started_at",
                    "lease_expires_at",
                    "worker_id",
                    "detail",
                ]
            )
            self._audit(
                EventType.RUN_RESUMED,
                dispatch_id=str(run_id),
                tenant_id=row.tenant_id,
                attempt=row.attempt,
                actor=by,
                detail="the thing it was waiting on arrived",
                at=now,
            )
        return f"resumed:{run_id}"

    # ── Consumer side ────────────────────────────────────────────────────────

    def fetch(self, run_id: RunId) -> bytes | None:
        """Take one specific run, for a worker a broker told about.

        ``None`` when there is nothing to do — the row is gone, already running, or
        already settled. Brokers deliver at least once, so a duplicate notification is
        normal and running the effect twice because of one is not.
        """
        with transaction.atomic():
            row = (
                QueuedRun.objects.select_for_update()
                .filter(pk=str(run_id), state=QueuedRun.QUEUED)
                .first()
            )
            return None if row is None else self._take(row)

    def claim(self, *, now: datetime | None = None, limit: int = 1) -> tuple[bytes, ...]:
        """Take work, atomically. ``SKIP LOCKED`` so workers do not queue behind each other.

        Without it every worker contends for the oldest row and the pool serialises on
        one lock, which is a queue slower than no queue.
        """
        with transaction.atomic():
            rows = list(
                QueuedRun.objects.select_for_update(skip_locked=True)
                .filter(state=QueuedRun.QUEUED)
                .order_by("submitted_at")[:limit]
            )
            return tuple(self._take(row, now=now) for row in rows)

    def _take(self, row: QueuedRun, *, now: datetime | None = None) -> bytes:
        """Mark a row running under this worker's lease, and say so on the trail."""
        moment = now if now is not None else timezone.now()
        row.state = QueuedRun.RUNNING
        row.started_at = moment
        row.worker_id = self._worker_id
        row.lease_expires_at = moment + self._lease
        row.save(update_fields=["state", "started_at", "worker_id", "lease_expires_at"])
        self._audit(
            EventType.RUN_CLAIMED,
            dispatch_id=row.run_id,
            tenant_id=row.tenant_id,
            attempt=row.attempt,
            actor=self._worker_id,
            at=moment,
        )
        return bytes(row.envelope)

    def renew(self, run_id: RunId, *, now: datetime | None = None) -> bool:
        """Extend the lease on a run still legitimately in progress.

        For the long agent flow. Lengthening the default lease instead would delay
        noticing every dead worker in the deployment to suit the slowest run in it.
        """
        moment = now if now is not None else timezone.now()
        updated = QueuedRun.objects.filter(
            pk=str(run_id), state=QueuedRun.RUNNING, worker_id=self._worker_id
        ).update(lease_expires_at=moment + self._lease)
        return bool(updated)

    def settle(
        self,
        run_id: RunId,
        *,
        state: str,
        detail: str = "",
        now: datetime | None = None,
        attestation: RunId | None = None,
    ) -> None:
        """Record how the run ended. ``HELD`` is not an end — resume waits on it."""
        if state not in {QueuedRun.HELD, QueuedRun.DONE, QueuedRun.FAILED}:
            raise StoreError(
                f"{state!r} is not a settled state; a worker settles a run as held, done or failed"
            )
        moment = now if now is not None else timezone.now()
        with transaction.atomic():
            row = QueuedRun.objects.select_for_update().filter(pk=str(run_id)).first()
            if row is None:
                raise StoreError(f"cannot settle unknown dispatch {run_id!r}")
            row.state = state
            row.detail = detail
            row.lease_expires_at = None
            row.finished_at = None if state == QueuedRun.HELD else moment
            if attestation is not None:
                row.latest_run_id = str(attestation)
            row.save(
                update_fields=[
                    "state",
                    "detail",
                    "lease_expires_at",
                    "finished_at",
                    "latest_run_id",
                ]
            )
            self._audit(
                EventType.RUN_SUSPENDED if state == QueuedRun.HELD else EventType.RUN_SETTLED,
                dispatch_id=str(run_id),
                run_id=row.latest_run_id,
                tenant_id=row.tenant_id,
                attempt=row.attempt,
                actor=self._worker_id,
                detail=detail or state,
                at=moment,
            )

    def reclaim_expired(self, *, now: datetime | None = None, limit: int = 100) -> tuple[str, ...]:
        """Return runs whose worker died to the queue. Returns the ids reclaimed.

        The row goes back to ``queued`` rather than to ``failed``: nobody reported a
        failure, the process simply stopped, and the run is very likely still valid.
        Every reclaim is recorded — a run reclaimed repeatedly is a poison message, and
        the trail is where that becomes visible instead of looking like slowness.
        """
        moment = now if now is not None else timezone.now()
        reclaimed: list[str] = []
        with transaction.atomic():
            rows = list(
                QueuedRun.objects.select_for_update(skip_locked=True)
                .filter(state=QueuedRun.RUNNING, lease_expires_at__lt=moment)
                .order_by("lease_expires_at")[:limit]
            )
            for row in rows:
                previous = row.worker_id
                row.state = QueuedRun.QUEUED
                row.worker_id = ""
                row.lease_expires_at = None
                row.started_at = None
                row.save(update_fields=["state", "worker_id", "lease_expires_at", "started_at"])
                self._audit(
                    EventType.RUN_ABANDONED,
                    dispatch_id=row.run_id,
                    tenant_id=row.tenant_id,
                    attempt=row.attempt,
                    actor=previous,
                    detail=f"lease expired; {previous!r} took it and never settled it",
                    at=moment,
                )
                reclaimed.append(row.run_id)
        return tuple(reclaimed)

    # ── Observability ────────────────────────────────────────────────────────

    def depth(self) -> int:
        """How many runs are waiting. The number an operator pages on."""
        return QueuedRun.objects.filter(state=QueuedRun.QUEUED).count()

    def counts(self) -> Mapping[str, int]:
        """Rows per state, in one query.

        A console that asked five times would show five moments as though they were
        one, and the inconsistency shows up exactly during the incident it is being
        used to diagnose.
        """
        rows = QueuedRun.objects.values("state").annotate(total=models.Count("state"))
        return {str(row["state"]): int(row["total"]) for row in rows}

    def oldest_waiting(self, *, now: datetime | None = None) -> timedelta | None:
        """Age of the oldest waiting run. Depth alone hides a stalled queue.

        A depth of five is fine if they arrived a second ago and an incident if the
        oldest has been there an hour.
        """
        oldest = QueuedRun.objects.filter(state=QueuedRun.QUEUED).order_by("submitted_at").first()
        if oldest is None:
            return None
        return (now if now is not None else timezone.now()) - oldest.submitted_at

    def trail(self, dispatch_id: str) -> tuple[DispatchEvent, ...]:
        """Every delivery event for one ticket, oldest first."""
        # Ordered by the primary key, not by ``occurred_at``. The table is
        # append-only, so insertion order *is* causal order; timestamps come from
        # several processes and a claim can legitimately carry an earlier instant than
        # the submit that preceded it when their clocks disagree.
        return tuple(DispatchEvent.objects.filter(dispatch_id=dispatch_id).order_by("id"))

    def _audit(
        self,
        event_type: EventType,
        *,
        dispatch_id: str,
        tenant_id: str,
        attempt: int,
        run_id: str = "",
        actor: str = "",
        detail: str = "",
        at: datetime | None = None,
    ) -> None:
        """Append one delivery event. Never silently skipped.

        A queue whose trail has gaps cannot answer the only question that matters when
        a run has not produced an attestation: did anything ever pick it up.
        """
        DispatchEvent.objects.create(
            dispatch_id=dispatch_id,
            run_id=run_id,
            tenant_id=tenant_id,
            event_type=str(event_type),
            occurred_at=at if at is not None else timezone.now(),
            attempt=attempt,
            actor=actor,
            detail=detail,
        )


class DjangoSealRegistry:
    """Records that a run's chain is closed, so the database can enforce it.

    Written by whoever seals — a management command, the sealing service, the engine's
    sink wrapper. Read by the ``NoEventsAfterSeal`` trigger, which is the point: the
    application already knows not to append to a sealed run, and the whole reason this
    exists is for the case where the application is not the one doing the appending.
    """

    __slots__ = ()

    def close(self, run_id: RunId, seal: RunSeal) -> None:
        """Mark the run sealed. Idempotent, and refuses to reseal differently.

        A second seal with a different head means two different chains were sealed for
        one run, which is not a race to resolve quietly.
        """
        existing = SealedRun.objects.filter(pk=str(run_id)).first()
        if existing is not None:
            if existing.head_hash != str(seal.head_hash):
                raise StoreError(
                    f"run {run_id!r} is already sealed with head "
                    f"{existing.head_hash[:12]}…, and this seal claims "
                    f"{str(seal.head_hash)[:12]}…. Two different chains cannot both be "
                    f"this run's."
                )
            return
        SealedRun.objects.create(
            run_id=str(run_id),
            sealed_at=seal.sealed_at,
            event_count=seal.event_count,
            head_hash=str(seal.head_hash),
        )

    def is_sealed(self, run_id: RunId) -> bool:
        return SealedRun.objects.filter(pk=str(run_id)).exists()


class DjangoAutonomyStore:
    """The kill switch, as a row.

    Satisfies :class:`~attest.runtime.operations.AutonomyStore`. A row rather than a
    deploy, because a control you can only exercise by shipping code is not a control
    you can exercise during an incident — and the incident is the only time it matters.

    Nothing here checks whether the caller may flip it. That is the host's decision,
    made in the host's view against the host's roles; see
    :mod:`attest.runtime.operations` for why a framework-supplied permission model
    would end up wired beside the real one and drifting from it. What is enforced is
    that the change names somebody, because an unattributed kill switch is
    indistinguishable from a misconfiguration when the incident is reviewed.
    """

    __slots__ = ()

    def set_mode(
        self, *, tenant: TenantId, capability: str, mode: str, enabled: bool, by: str
    ) -> None:
        if not by.strip():
            raise StoreError(
                "an autonomy change must name who made it. Two weeks later, when "
                "someone asks whether this can be reverted, an anonymous row answers "
                "nothing."
            )
        AutonomyPolicy.objects.update_or_create(
            tenant_id=str(tenant),
            capability=capability,
            defaults={"mode": mode, "enabled": enabled, "updated_by": by[:128]},
        )

    def modes(self, *, tenant: TenantId | None = None) -> tuple[Mapping[str, object], ...]:
        queryset = AutonomyPolicy.objects.all()
        if tenant is not None:
            queryset = queryset.filter(tenant_id=str(tenant))
        return tuple(
            {
                "tenant": row.tenant_id,
                "capability": row.capability,
                "mode": row.mode,
                "enabled": row.enabled,
                "updated_at": row.updated_at,
                "updated_by": row.updated_by,
            }
            for row in queryset.order_by("tenant_id", "capability")
        )

    def mode_for(self, *, tenant: TenantId, capability: str) -> str:
        """What this capability may do. **BLOCKED when nothing says otherwise.**

        The default is the whole design. A capability nobody has classified must not
        run unattended because a row was missing — an absent policy is an unanswered
        question, not permission.
        """
        row = AutonomyPolicy.objects.filter(tenant_id=str(tenant), capability=capability).first()
        if row is None or not row.enabled:
            return "blocked"
        return str(row.mode)
