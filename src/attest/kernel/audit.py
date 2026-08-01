"""Audit — the provenance warrant.

An ordinary audit table answers "what does the database say happened". A regulator's
question is stricter: "can you show the record was not edited afterwards?"

Hash chaining answers that. It does **not** answer completeness:

.. code-block:: text

    actual execution            what was recorded
    ----------------            -----------------
    e1 -> e2 -> e3 -> e4        e1 -> e3 -> e4

                                chain is internally VALID:
                                e3.prev == e1.hash, every hash recomputes

A defective or malicious host can simply omit an event, and linkage alone cannot see
it. :class:`RunSeal` binds a **count and a dense range**, so an omission leaves a
detectable gap and renumbering breaks the linkage.

Sequence numbers are assigned at **seal time**, not at insert time. That is ADR 0034,
and it is what lets effect events be written immediately while everything else
batches: the canonical order comes from the execution DAG, not from which transaction
committed first. Assigning at insert would order a mid-run payment *before* the
evidence retrieval that caused it.

The honest limit: a host that fully controls its own store can rewrite the whole
chain — recompute every hash, renumber, re-seal, re-sign — and nothing inside the
system can detect it. That is what external witnessing exists for.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from attest.kernel.canonical import NULL_HASH, Canonical
from attest.kernel.identifiers import Hash

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from attest.kernel.identifiers import RunId
    from attest.kernel.ports import Signer

__all__ = [
    "FORBIDDEN_IN_CHAIN",
    "AuditEvent",
    "ChainVerification",
    "ChainVerifier",
    "EventType",
    "RunSeal",
]


class EventType(StrEnum):
    """Typed, never free text.

    A free-text audit log cannot be queried, aggregated or tested, and every one of
    the monitored signals in ``docs/assurance/observability.md`` is a count over
    these. Domains register their own alongside.
    """

    RUN_DISPATCHED = "run.dispatched"
    RUN_COMPLETED = "run.completed"
    RUN_FAILED = "run.failed"

    # ── Delivery, not decision ───────────────────────────────────────────────
    # These describe how a run reached a worker, and they are recorded on the
    # DISPATCH trail rather than in the sealed chain. A run's chain is sealed by
    # the run itself, in one process, at one moment; a queue event is written by
    # a different process before that process exists. Folding them together would
    # mean the seal covered events it never saw — the ordering problem ADR 0034
    # exists to fix, arriving by a different door.
    RUN_QUEUED = "dispatch.queued"
    RUN_CLAIMED = "dispatch.claimed"
    RUN_SUSPENDED = "dispatch.suspended"
    """The worker returned because the run is waiting on a human. Not a failure, and
    not work left undone — the whole point is that no worker is held."""

    RUN_RESUMED = "dispatch.resumed"
    RUN_ABANDONED = "dispatch.abandoned"
    """A worker took the run and never settled it. Its lease expired and another
    worker may take it. Distinguished from a failure because nobody reported one:
    the process died, and a run that silently stops is the failure mode a queue
    must make visible."""

    RUN_SETTLED = "dispatch.settled"

    EVIDENCE_RETRIEVED = "evidence.retrieved"
    EVIDENCE_VERIFIED = "evidence.verified"
    EVIDENCE_REJECTED = "evidence.rejected"

    TOOL_PROPOSED = "tool.proposed"
    TOOL_VERIFIED = "tool.verified"
    TOOL_REFUSED = "tool.refused"

    OBLIGATION_DISCHARGED = "authority.obligation_discharged"
    OBLIGATION_PENDING = "authority.obligation_pending"
    OBLIGATION_FAILED = "authority.obligation_failed"
    APPROVAL_REQUESTED = "authority.approval_requested"
    APPROVAL_GRANTED = "authority.approval_granted"
    APPROVAL_REJECTED = "authority.approval_rejected"
    APPROVAL_EXPIRED = "authority.approval_expired"
    APPROVAL_NOT_SPENT = "authority.approval_not_spent"
    """The store could not mark a decision as consumed.

    Its own event because the consequence is specific and severe: a decision that was
    not marked spent is a decision that can authorise the *next* identical proposal too,
    and the action hash is identical by construction on a re-submission. Folding this
    into a generic failure would put "one approval authorised an unlimited number of
    GBP 500,000 transfers" in the same bucket as a timeout.
    """

    GRANT_ISSUED = "authority.grant_issued"
    GRANT_REDEEMED = "authority.grant_redeemed"
    GRANT_REPLAY_REJECTED = "authority.grant_replay_rejected"

    EFFECT_SUBMITTED = "effect.submitted"
    EFFECT_COMMITTED = "effect.committed"
    EFFECT_FAILED = "effect.failed"
    EFFECT_UNKNOWN = "effect.unknown"
    EFFECT_RECONCILED = "effect.reconciled"

    INJECTION_DETECTED = "boundary.injection_detected"
    PII_REDACTED = "boundary.pii_redacted"
    PII_RESTORED = "boundary.pii_restored"
    TENANCY_VIOLATION = "boundary.tenancy_violation"

    MODEL_CALL_COMPLETED = "model.call_completed"
    MODEL_FAILED_OVER = "model.failed_over"
    BUDGET_RESERVED = "model.budget_reserved"
    CIRCUIT_OPENED = "model.circuit_opened"


FORBIDDEN_IN_CHAIN: tuple[str, ...] = (
    "raw PII or PHI",
    "full prompt bodies",
    "full model outputs",
    "credentials or keys",
)
"""What must never be written into an event payload.

The chain is append-only and long-lived, so anything written there cannot be deleted
— which makes a right-to-erasure request against a chain containing raw PII
unanswerable. Store a redaction token and a pointer; keep the erasable data where it
can be erased.

Documented as data rather than enforced here because the kernel cannot recognise PII;
the boundary guard at L1 can, and the conformance kit tests it.
"""


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One thing that happened, linked to what came before it.

    ``sequence`` and ``previous_hash`` are assigned by the **sealer**, below the
    application, at seal time. An event that has not been sealed carries
    ``sequence=None``: the application records causal structure
    (``parent_event_id``, ``branch``) and never chooses its own position, because an
    application that omits an event would otherwise also report the count that hides it.
    """

    run_id: RunId
    event_type: str
    occurred_at: datetime
    payload: Mapping[str, Any] = field(default_factory=dict)

    event_id: str | None = None
    """The application's own identifier for this event, unique within the run.

    A parent pointer with no corresponding self-identifier is only half a graph: an
    event can say what it followed, and nothing can say what followed it. That is why
    the canonical order used to fall back to *the order the events were handed in* —
    which is not canonical at all, and meant the same events re-read from storage in a
    different order produced a different chain and a different head hash.

    ``None`` for a hand-built event, which then orders by arrival as before.
    """

    parent_event_id: str | None = None
    branch: str | None = None
    """Which parallel branch produced this. Execution is genuinely a DAG; flattening
    it in arrival order makes concurrent ordering arbitrary, so two verifiers could
    compute different head hashes for the same run."""

    sequence: int | None = None
    previous_hash: Hash | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))
        if not self.event_type:
            raise ValueError("event_type must not be empty; audit events are typed")
        if (self.sequence is None) != (self.previous_hash is None):
            raise ValueError(
                "sequence and previous_hash are assigned together at seal time; "
                "an event cannot carry one without the other"
            )
        if self.sequence is not None and self.sequence < 1:
            raise ValueError(f"sequence must be >= 1, got {self.sequence}")

    @property
    def is_sealed(self) -> bool:
        return self.sequence is not None

    def sealed_as(self, sequence: int, previous_hash: Hash) -> AuditEvent:
        """Return this event with its canonical position assigned.

        Returns a new value rather than mutating: an event that has already been
        sealed cannot be re-sealed into a different position, which would be exactly
        the renumbering the seal exists to detect.
        """
        if self.is_sealed:
            raise ValueError(
                f"event at sequence {self.sequence} is already sealed; re-sealing "
                f"would renumber a chain that has already been committed to"
            )
        return AuditEvent(
            run_id=self.run_id,
            event_type=self.event_type,
            occurred_at=self.occurred_at,
            payload=dict(self.payload),
            event_id=self.event_id,
            parent_event_id=self.parent_event_id,
            branch=self.branch,
            sequence=sequence,
            previous_hash=previous_hash,
        )

    def event_hash(self) -> Hash:
        """This event's link in the chain. Requires the event to be sealed."""
        if not self.is_sealed:
            raise ValueError("an unsealed event has no chain position, so it has no chain hash")
        return Hash(
            Canonical.digest(
                {
                    "run_id": self.run_id,
                    "sequence": self.sequence,
                    "event_type": self.event_type,
                    "occurred_at": self.occurred_at,
                    "payload": dict(self.payload),
                    "event_id": self.event_id,
                    "parent_event_id": self.parent_event_id,
                    "branch": self.branch,
                    "previous_hash": self.previous_hash,
                }
            )
        )


@dataclass(frozen=True, slots=True)
class RunSeal:
    """Binds a run's chain to a count and a dense range.

    Integrity comes from the chain; **completeness** comes from here. Without a bound
    count, an omitted event leaves a chain that still recomputes perfectly.
    """

    run_id: RunId
    event_count: int
    first_sequence: int
    last_sequence: int
    head_hash: Hash
    attestation_hash: Hash
    sealed_at: datetime
    signer: str | None = None
    signature: str | None = None
    """`None` is permitted only at the THIN assurance tier. Chain verification works
    unsigned; only the offline-evidence property depends on a signature."""

    def __post_init__(self) -> None:
        if self.event_count < 0:
            raise ValueError("event_count cannot be negative")
        if self.event_count == 0:
            raise ValueError(
                "a run with no events cannot be sealed: there would be nothing to attest happened"
            )
        expected = self.last_sequence - self.first_sequence + 1
        if expected != self.event_count:
            raise ValueError(
                f"seal claims {self.event_count} events over sequence range "
                f"{self.first_sequence}..{self.last_sequence}, which spans {expected}. "
                f"A seal whose range and count disagree cannot detect an omission."
            )
        if self.first_sequence != 1:
            raise ValueError(
                f"a run's chain must start at sequence 1, not {self.first_sequence}; "
                f"otherwise a truncated prefix is indistinguishable from a short run"
            )
        if (self.signature is None) != (self.signer is None):
            raise ValueError("signer and signature must be supplied together")

    def signing_payload(self) -> bytes:
        """The exact bytes a signature covers.

        Exposed so an offline verifier can reconstruct them without our code, which
        is what ``VERIFY.md`` requires.
        """

        return Canonical.encode(
            {
                "run_id": self.run_id,
                "event_count": self.event_count,
                "first_sequence": self.first_sequence,
                "last_sequence": self.last_sequence,
                "head_hash": self.head_hash,
                "attestation_hash": self.attestation_hash,
                "sealed_at": self.sealed_at,
            }
        )


class ChainFailure(StrEnum):
    """Why a chain did not verify."""

    EMPTY = "empty"
    NOT_SEALED = "not_sealed"
    SEQUENCE_GAP = "sequence_gap"
    SEQUENCE_NOT_DENSE = "sequence_not_dense"
    BROKEN_LINKAGE = "broken_linkage"
    ALTERED_EVENT = "altered_event"
    WRONG_RUN = "wrong_run"
    COUNT_MISMATCH = "count_mismatch"
    HEAD_MISMATCH = "head_mismatch"


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """The result of walking a chain. Typed, so a failure can be triaged."""

    failures: tuple[ChainFailure, ...] = ()
    detail: str = ""

    @property
    def verified(self) -> bool:
        return not self.failures

    def __bool__(self) -> bool:
        return self.verified


class ChainVerifier:
    """Recomputes a chain and checks it against its seal.

    A class for symmetry with :class:`~attest.capabilities.audit.ChainSealer`: the two
    must agree exactly, since an event's hash depends on the position the sealer gave
    it, and a verifier that drifts from the sealer verifies nothing.
    """

    @staticmethod
    def verify(
        events: Sequence[AuditEvent],
        *,
        run_id: RunId,
        seal: RunSeal | None = None,
        signer: Signer | None = None,
    ) -> ChainVerification:
        """Recompute a chain and check it against its seal.

        Pure: takes the events and the seal, reads nothing. Checks, in order, that every
        event belongs to this run and is sealed; that the sequence is dense from 1 with
        no gaps; that each event's stored linkage matches its predecessor's recomputed
        hash; and that the seal's count and head agree with what was walked.

        The density check is the one that catches omission. Linkage alone cannot: remove
        ``e2`` and re-point ``e3`` at ``e1`` and every hash still recomputes.
        """
        if not events:
            return ChainVerification(failures=(ChainFailure.EMPTY,), detail="no events")

        failures: list[ChainFailure] = []
        details: list[str] = []

        for event in events:
            if event.run_id != run_id:
                failures.append(ChainFailure.WRONG_RUN)
                details.append(f"event from run {event.run_id!r} in chain for {run_id!r}")
                break
            if not event.is_sealed:
                failures.append(ChainFailure.NOT_SEALED)
                details.append(f"event {event.event_type!r} has no sequence")
                break

        if failures:
            return ChainVerification(tuple(failures), "; ".join(details))

        ordered = sorted(events, key=lambda e: e.sequence or 0)
        previous: Hash = Hash(NULL_HASH)

        for position, event in enumerate(ordered, start=1):
            if event.sequence != position:
                failures.append(ChainFailure.SEQUENCE_GAP)
                details.append(f"expected sequence {position}, found {event.sequence}")
                break
            if event.previous_hash != previous:
                failures.append(ChainFailure.BROKEN_LINKAGE)
                details.append(
                    f"event {position} links to {event.previous_hash!r}, expected {previous!r}"
                )
                break
            previous = event.event_hash()

        if failures:
            return ChainVerification(tuple(failures), "; ".join(details))

        if seal is not None:
            if seal.run_id != run_id:
                # A seal from another run would otherwise be accepted as long as its
                # count and head happened to agree, which is the whole of what a
                # transplanted seal needs to do.
                failures.append(ChainFailure.WRONG_RUN)
                details.append(f"seal is for run {seal.run_id!r}, chain is for {run_id!r}")
            if seal.event_count != len(ordered):
                failures.append(ChainFailure.COUNT_MISMATCH)
                details.append(f"seal claims {seal.event_count}, walked {len(ordered)}")
            if seal.head_hash != previous:
                failures.append(ChainFailure.HEAD_MISMATCH)
                details.append("sealed head hash does not match the recomputed head")
            failures.extend(ChainVerifier._check_signature(seal, signer, details))

        return ChainVerification(tuple(failures), "; ".join(details))

    @staticmethod
    def _check_signature(
        seal: RunSeal, signer: Signer | None, details: list[str]
    ) -> list[ChainFailure]:
        """Verify the seal's signature where a verifier was supplied.

        Chain integrity proves *internal* consistency: that these events, in this
        order, hash to this head. It says nothing about where the chain came from — a
        host that controls its own store can produce a perfectly consistent chain of
        its own invention. The signature is the only part that answers that, so
        leaving it unread makes the seal a formatting convention.

        ``signer`` is optional because an unsigned deployment is a real configuration,
        not a broken one. What is not acceptable is a *signed* seal whose signature
        nobody looked at.
        """
        if signer is None:
            return []
        if not seal.signature:
            details.append("seal carries no signature but a verifier was supplied")
            return [ChainFailure.ALTERED_EVENT]
        if not signer.verify(seal.signing_payload(), seal.signature):
            details.append(f"seal signature does not verify against key {signer.key_id!r}")
            return [ChainFailure.ALTERED_EVENT]
        return []
