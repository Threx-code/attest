"""The audit chain builder and sealer.

Sequence numbers and the hash chain are assigned at **seal time** over the canonical
topological order, never at insert time. That is ADR 0034, and it is what lets effect
events be written immediately while everything else batches: insert-time assignment
would order a mid-run payment before the evidence retrieval that caused it.

Execution is genuinely a DAG. Flattening it in arrival order makes concurrent ordering
arbitrary, so two verifiers could compute different head hashes for the same run —
which destroys the evidentiary value entirely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from attest.kernel.audit import AuditEvent, EventType, RunSeal
from attest.kernel.canonical import NULL_HASH
from attest.kernel.effects import EffectState
from attest.kernel.errors import AuditSinkError
from attest.kernel.identifiers import Hash
from attest.kernel.warrants import (
    Finding,
    Severity,
    WarrantKinds,
    WarrantReport,
    WarrantStatus,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from attest.kernel.identifiers import RunId
    from attest.kernel.ports import AuditSink, Clock, Signer

__all__ = ["ChainSealer", "EventRecorder"]

# Effect events are never batched: losing one creates a state nobody can reconcile.
# They are ~2% of events and 100% of the risk.
_IMMEDIATE_PREFIXES: tuple[str, ...] = ("effect.",)


@dataclass(slots=True)
class EventRecorder:
    """Collects events during a run, recording causal structure only.

    The application never chooses its own sequence numbers. One that omits an event
    would otherwise also report the count that hides it, which is self-certification
    and cannot detect anything.
    """

    run_id: RunId
    sink: AuditSink | None = None
    """Where ``durable=True`` events are written, **immediately and by this object**.

    Two writers used to persist the same run's events in two different shapes. The
    execution boundary wrote its events straight through the sink, stamped with its own
    clock and carrying no causal structure; the recorder recorded *the same events
    again* through the emit hook, reading the clock a second time and attaching a
    parent. The recorder's copies were sealed. The boundary's copies were stored. They
    hashed differently and arrived in a different order, so the stored chain failed to
    verify for **every run that performed an effect** — the runs that matter — and
    legitimate runs failed identically to tampered ones, which is how a verification
    sweep stops carrying information.

    One writer, one object, sealed and stored.
    """

    clock: Clock | None = None
    """Read at each ``record``, so the chain says when things happened.

    A run that stamps every event with one instant produces a chain that cannot show
    elapsed time — an effect that took forty seconds and one that took forty
    milliseconds are indistinguishable in it, and a reviewer asking "how long was the
    grant held before it was redeemed" has no answer. ``None`` keeps the old behaviour
    for callers that pass ``at`` explicitly, which replay does.
    """

    _events: list[AuditEvent] = field(default_factory=list)
    _last_by_branch: dict[str | None, str] = field(default_factory=dict)
    _durable: set[int] = field(default_factory=set)
    """Positions already written by whoever recorded them. See :meth:`pending_batch`."""

    def record(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        at: datetime | None = None,
        branch: str | None = None,
        durable: bool = False,
    ) -> AuditEvent:
        """Record one event.

        ``at`` is optional only when a clock was supplied. An explicit ``at`` still
        wins, because replay must reproduce the original instants exactly rather than
        re-observing a clock that has moved on.

        ``durable=True`` says the caller has already written this event to storage —
        the execution boundary does, before the external call it describes — so
        :meth:`flush` will not write it a second time.
        """
        if at is None:
            if self.clock is None:
                raise ValueError(
                    "record() needs either an explicit `at` or a clock. The kernel has "
                    "no ambient time, so an event with no instant would be stamped with "
                    "whatever the machine happened to say."
                )
            at = self.clock.now()
        parent = self._last_by_branch.get(branch)
        # Zero-padded so ordering by this string is ordering by position: "e@10" sorts
        # before "e@9" otherwise, and this is the canonical order's tie-break.
        key = f"{event_type}@{len(self._events):08d}"
        event = AuditEvent(
            run_id=self.run_id,
            event_type=event_type,
            occurred_at=at,
            payload=payload,
            event_id=key,
            parent_event_id=parent,
            branch=branch,
        )
        self._last_by_branch[branch] = key
        self._events.append(event)
        if durable:
            self._durable.add(len(self._events) - 1)
            self._write_now(event)
        return event

    def _write_now(self, event: AuditEvent) -> None:
        """Persist one event before the thing it describes happens.

        A failure here **stops the run**. That is the rule the boundary states and this
        is where it holds: if we cannot record what we are about to do, we must not do
        it. The alternative is a payment with no audit record, which is indistinguishable
        from a payment that never happened.
        """
        if self.sink is None:
            return
        try:
            self.sink.append(event)
        except AuditSinkError:
            raise
        except Exception as exc:
            raise AuditSinkError(
                f"could not durably record {event.event_type!r} before the effect: "
                f"{exc}. If we cannot record what happened, we must not act."
            ) from exc

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def requires_immediate_write(self, event: AuditEvent) -> bool:
        """Whether this event must be flushed now rather than batched."""
        return event.event_type.startswith(_IMMEDIATE_PREFIXES)

    def pending_batch(self) -> tuple[AuditEvent, ...]:
        """Events not already written durably, and so safe to batch.

        Membership is decided by whoever recorded the event, not by its name. The
        execution boundary writes its own events through its own sink before the call
        they describe, and marks them ``durable`` as it does so — a name-prefix rule
        here would be a second copy of that knowledge, and the two would drift the
        first time an event was renamed or a new immediate write was added.
        """
        return tuple(
            event
            for index, event in enumerate(self._events)
            if index not in self._durable and not self.requires_immediate_write(event)
        )

    def flush(self, sink: AuditSink) -> tuple[AuditEvent, ...]:
        """Persist the batch, and only the batch.

        The immediate events are already durable: the execution boundary wrote them
        through its own sink before the external call, which is what makes a crash
        mid-effect leave a dangling ``SUBMITTED`` for reconciliation to find rather
        than leaving nothing at all. Writing them again here would put each one in the
        chain twice, and a chain with duplicates cannot be sealed densely.

        Events go in **unsealed**. The sealer assigns canonical positions afterwards
        and the seal binds the count and the head; a sink that stored positions at
        insert time would be the application numbering its own chain.
        """
        batch = self.pending_batch()
        if batch:
            sink.append_many(batch)
        return batch


class ChainSealer:
    """Assigns canonical positions, builds the chain, seals, and verifies.

    One class because the three operations must agree exactly: an event's hash depends
    on the position the sealer gave it, so ordering, sealing and verification cannot
    be allowed to drift apart into separate implementations.

    Holds the signer, so an unsigned deployment differs by construction rather than by
    an argument every caller must remember to pass.
    """

    __slots__ = ("_signer",)

    def __init__(self, *, signer: Signer | None = None) -> None:
        self._signer = signer

    @staticmethod
    def canonical_order(events: Sequence[AuditEvent]) -> tuple[AuditEvent, ...]:
        """Deterministic topological sort over the events' own causal structure.

        Deterministic is the requirement, not merely stable — two independent verifiers
        must compute the same chain from the same set. This used to sort by ``(branch,
        position in the list it was handed)``, which is *stable with respect to the
        input* and therefore not canonical at all: the same events read back from
        storage in a different order produced a different chain and a different head,
        so a run whose events were written by two paths could never re-verify.

        The order now comes from the parent links, which the application records and
        storage cannot reorder. Ties and unlinked events fall back to arrival, so a
        hand-built event with no ``event_id`` behaves as before.
        """
        by_id = {event.event_id: index for index, event in enumerate(events) if event.event_id}
        memo: dict[int, int] = {}

        def depth(index: int) -> int:
            """How many events precede this one in its branch, by following parents.

            Memoised, and iterative. Walking the chain per event inside a sort key is
            O(n²), and ``seal()`` runs twice per run — negligible at fifteen events and
            quadratic on a long agent flow with a per-tool event.
            """
            stack: list[int] = []
            guard: set[int] = set()
            current = index
            while current not in memo:
                if current in guard:
                    memo[current] = 0  # a cycle: stop rather than loop
                    break
                guard.add(current)
                parent = events[current].parent_event_id
                if parent is None or parent not in by_id:
                    memo[current] = 0
                    break
                stack.append(current)
                current = by_id[parent]
            known = memo[current]
            while stack:
                known += 1
                memo[stack.pop()] = known
            return memo[index]

        def position(index: int) -> tuple[str, int, str]:
            event = events[index]
            # Ties break on event_id, never on arrival. Arrival order is exactly what
            # storage reorders — the bug this function was rewritten to fix — and it is
            # only unreachable today because EventRecorder makes each event the parent
            # of the next, so depths are totally ordered. A genuine fan-out, which the
            # `branch` parameter permits, brings it straight back.
            return (event.branch or "", depth(index), event.event_id or f"~{index:08d}")

        return tuple(events[index] for index in sorted(range(len(events)), key=position))

    def seal(
        self,
        events: Sequence[AuditEvent],
        *,
        run_id: RunId,
        attestation_hash: Hash,
        sealed_at: datetime,
    ) -> tuple[tuple[AuditEvent, ...], RunSeal]:
        """Assign positions, build the chain, and seal.

        Returns the sealed events alongside the seal, because the positions are part
        of the record rather than a derivable detail.
        """
        if not events:
            raise ValueError(
                f"run {run_id!r} has no events to seal; a run with no record of what "
                f"happened cannot be attested to"
            )

        sealed: list[AuditEvent] = []
        previous = Hash(NULL_HASH)
        for position, event in enumerate(self.canonical_order(events), start=1):
            node = event.sealed_as(position, previous)
            sealed.append(node)
            previous = node.event_hash()

        seal = RunSeal(
            run_id=run_id,
            event_count=len(sealed),
            first_sequence=1,
            last_sequence=len(sealed),
            head_hash=previous,
            attestation_hash=attestation_hash,
            sealed_at=sealed_at,
        )
        if self._signer is not None:
            seal = RunSeal(
                run_id=seal.run_id,
                event_count=seal.event_count,
                first_sequence=seal.first_sequence,
                last_sequence=seal.last_sequence,
                head_hash=seal.head_hash,
                attestation_hash=seal.attestation_hash,
                sealed_at=seal.sealed_at,
                signer=self._signer.key_id,
                signature=self._signer.sign(seal.signing_payload()),
            )
        return tuple(sealed), seal

    def evaluate(self, events: Sequence[AuditEvent], *, seal: RunSeal | None) -> WarrantReport:
        """The provenance warrant: is the record complete and unmodified?

        Unsealed is unsatisfied. A chain with no bound count proves integrity and not
        completeness, and that distinction is the whole reason the seal exists.
        """
        from attest.kernel.audit import ChainVerifier

        if seal is None:
            return WarrantReport(
                kind=WarrantKinds.PROVENANCE,
                status=WarrantStatus.EVALUATED,
                satisfied=False,
                findings=(
                    Finding(
                        code="unsealed",
                        message=(
                            "the run is not sealed: a chain without a bound count "
                            "proves integrity, not completeness"
                        ),
                        severity=Severity.ERROR,
                    ),
                ),
            )

        result = ChainVerifier.verify(events, run_id=seal.run_id, seal=seal)
        if result.verified:
            return WarrantReport(
                kind=WarrantKinds.PROVENANCE,
                status=WarrantStatus.EVALUATED,
                satisfied=True,
                findings=(
                    Finding(
                        code="chain_verified",
                        message=f"{seal.event_count} events, dense 1..{seal.last_sequence}",
                    ),
                ),
            )
        return WarrantReport(
            kind=WarrantKinds.PROVENANCE,
            status=WarrantStatus.EVALUATED,
            satisfied=False,
            findings=tuple(
                Finding(code=f.value, message=result.detail, severity=Severity.ERROR)
                for f in result.failures
            ),
        )

    @staticmethod
    def effect_state_from_event(event_type: str) -> EffectState | None:
        """Map an effect event back to its state, for reconciliation sweeps."""
        return {
            EventType.EFFECT_SUBMITTED.value: EffectState.SUBMITTED,
            EventType.EFFECT_COMMITTED.value: EffectState.COMMITTED,
            EventType.EFFECT_FAILED.value: EffectState.FAILED,
            EventType.EFFECT_UNKNOWN.value: EffectState.UNKNOWN,
        }.get(event_type)
