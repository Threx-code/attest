"""Reconciliation — resolving what only the external system knows.

An `UNKNOWN` effect is terminal for the run and a **work item**. Resolution is itself
governed: it produces an audit event and supersedes the attestation, because deciding
after the fact that a payment did happen is a decision, and an undocumented one is
indistinguishable from editing the record.

Reconciliation lag is an SLO, not a background detail. An `UNKNOWN` large transfer
outstanding for a week is an incident.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from attest.kernel.audit import AuditEvent, EventType
from attest.kernel.effects import EffectState

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime, timedelta

    from attest.kernel.attestation import EffectRecord
    from attest.kernel.identifiers import ActorId, RunId

__all__ = [
    "ReconciliationItem",
    "ReconciliationOutcome",
    "ReconciliationSweep",
    "Resolver",
]


class ReconciliationOutcome(StrEnum):
    """How an UNKNOWN resolved."""

    COMMITTED = "committed"
    FAILED = "failed"
    STILL_UNKNOWN = "still_unknown"
    """The upstream cannot answer either. Stays a work item; escalates on age."""


@runtime_checkable
class Resolver(Protocol):
    """Asks the external system what actually happened.

    Queries by our idempotency key where the upstream supports it. Where no query
    exists, resolution is an operator decision and must be recorded as one rather than
    inferred.
    """

    def resolve(
        self, record: EffectRecord
    ) -> ReconciliationOutcome | tuple[ReconciliationOutcome, str]:
        """The outcome, or ``(outcome, external_reference)``.

        The pair form is required for ``COMMITTED`` — see
        :attr:`ReconciliationItem.external_reference`. It is a tuple rather than a
        result type because the other two outcomes genuinely have nothing to add, and a
        resolver forced to construct an object to say "still don't know" is a resolver
        somebody writes badly.
        """
        ...


@dataclass(frozen=True, slots=True)
class ReconciliationItem:
    """One outstanding effect, and what became of it."""

    record: EffectRecord
    outcome: ReconciliationOutcome
    resolved_at: datetime
    resolved_by: ActorId | None = None
    """`None` for an automated resolution against the upstream. Set when a human
    decided, because an operator judgement is a different kind of evidence."""

    detail: str = ""

    external_reference: str = ""
    """What the upstream calls the effect that turned out to have committed.

    Required on ``COMMITTED``, and the requirement is not bureaucratic: the same rule is
    already enforced one layer up, where
    :class:`~attest.kernel.attestation.EffectRecord` refuses a committed effect with no
    reference because *"recording a commit we cannot point at is how an audit chain
    comes to disagree with the world"*. Without it the correction cannot be written at
    all, so a sweep would conclude that a payment had settled and be unable to say so.

    Stated here as well as there because this is where the resolver author is reading.
    Discovering the rule from an ``AttestationError`` raised three frames away, after
    the upstream has already been queried, is the expensive way to learn it.
    """

    def __post_init__(self) -> None:
        if self.outcome is ReconciliationOutcome.STILL_UNKNOWN and not self.detail:
            raise ValueError(
                "an unresolved reconciliation must say what was attempted; otherwise "
                "an item that nobody could resolve is indistinguishable from one "
                "nobody tried to"
            )
        if self.outcome is ReconciliationOutcome.COMMITTED and not self.external_reference:
            raise ValueError(
                f"reconciling {self.record.action.tool!r} as COMMITTED with no external "
                f"reference. If the upstream can tell us it committed, it can tell us "
                f"what it committed as; if it cannot, the honest outcome is "
                f"STILL_UNKNOWN. A commit we cannot point at is not one we can defend."
            )


class ReconciliationSweep:
    """Finds effects outstanding past their SLA.

    Holds the SLA, because reconciliation lag is an SLO rather than a background
    detail: an UNKNOWN large transfer outstanding for a week is an incident, and the
    threshold that decides so belongs with the sweep rather than at each call site.
    """

    __slots__ = ("_sla",)

    def __init__(self, *, sla: timedelta) -> None:
        self._sla = sla

    def resolve(
        self,
        records: Sequence[EffectRecord],
        *,
        resolver: Resolver,
        now: datetime,
        actor: ActorId | None = None,
    ) -> tuple[ReconciliationItem, ...]:
        """Ask the upstream what actually happened to every unresolved effect.

        Only the external system knows. That is the whole reason ``UNKNOWN`` is a state
        rather than a guess, and the reason resolution is a port rather than a rule: a
        framework that decided this itself would be inventing the answer it exists to
        avoid inventing.

        A resolver that raises leaves the effect ``UNKNOWN`` — an unreachable upstream
        is not evidence that nothing happened.
        """
        items: list[ReconciliationItem] = []
        for record in records:
            if record.state not in {EffectState.UNKNOWN, EffectState.SUBMITTED}:
                continue
            try:
                answer = resolver.resolve(record)
                outcome, reference = answer if isinstance(answer, tuple) else (answer, "")
            except Exception as exc:  # an unreachable upstream is not an answer
                items.append(
                    ReconciliationItem(
                        record=record,
                        outcome=ReconciliationOutcome.STILL_UNKNOWN,
                        resolved_at=now,
                        resolved_by=actor,
                        detail=f"the upstream could not be reached: {exc}",
                    )
                )
                continue
            items.append(
                ReconciliationItem(
                    record=record,
                    outcome=outcome,
                    resolved_at=now,
                    resolved_by=actor,
                    external_reference=reference,
                )
            )
        return tuple(items)

    def overdue(
        self, records: Sequence[EffectRecord], *, now: datetime
    ) -> tuple[EffectRecord, ...]:
        """Effects outstanding past the SLA.

        Covers `SUBMITTED` as well as `UNKNOWN`: a dangling `SUBMITTED` is a crash
        between the intent write and any terminal event, and it is exactly what the
        sweep exists to find.
        """
        out: list[EffectRecord] = []
        for record in records:
            if record.state not in {EffectState.SUBMITTED, EffectState.UNKNOWN}:
                continue
            submitted = record.submitted_at
            if submitted is not None and now - submitted >= self._sla:
                out.append(record)
        return tuple(out)

    def events(
        self, items: Sequence[ReconciliationItem], *, run_id: RunId
    ) -> tuple[AuditEvent, ...]:
        """The audit events for a completed sweep. One per effect that moved.

        Produced here rather than written here: the sink is a port, and a capability
        that wrote to storage directly would be the layering violation this package is
        built to avoid. What must not happen is the sweep resolving an UNKNOWN effect
        and leaving no record — a transfer that turned out to have committed is
        precisely the fact a reconciliation exists to establish, and an unrecorded
        establishment is not one.

        ``STILL_UNKNOWN`` is included deliberately. "We asked and could not find out"
        is a finding, and a sweep that recorded only its successes would show a clean
        reconciliation history while the same effect went unresolved for a week.
        """
        return tuple(
            AuditEvent(
                run_id=run_id,
                event_type=EventType.EFFECT_RECONCILED.value,
                occurred_at=item.resolved_at,
                payload={
                    "tool": item.record.action.tool,
                    "was": item.record.state.value,
                    "outcome": item.outcome.value,
                    "resolved_by": None if item.resolved_by is None else str(item.resolved_by),
                    "reference": item.external_reference or item.record.external_reference,
                    "detail": item.detail,
                },
            )
            for item in items
        )
