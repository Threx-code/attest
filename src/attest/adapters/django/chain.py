"""Verification of a stored chain — decoded, then recomputed.

Rows are decoded back into :class:`~attest.kernel.audit.AuditEvent` objects and handed
to the kernel's :class:`~attest.kernel.audit.ChainVerifier`. That matters: the verifier
recomputes each event's hash from its content, so an event rewritten *together with*
its stored linkage is caught. A check that only walked the stored ``previous_hash``
columns would report such a chain as intact.

Density is still the property that catches omission. Remove ``e2`` and re-point ``e3``
at ``e1`` and every hash recomputes correctly — only a dense sequence from 1 shows the
gap. The verifier checks both.

The same verifier runs here and in the sealer, deliberately: an event's hash depends on
the position the sealer gave it, so a verifier that drifted from the sealer would
verify nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from attest.adapters.django.stores import (
    DjangoAuditSink,
    DjangoRunStore,
    DjangoSealRegistry,
)
from attest.capabilities.audit import ChainSealer
from attest.kernel.audit import ChainFailure, ChainVerifier
from attest.kernel.codec import CodecError

if TYPE_CHECKING:
    from attest.kernel.identifiers import RunId

__all__ = ["StoredChainCheck", "StoredChainResult"]


@dataclass(frozen=True, slots=True)
class StoredChainResult:
    """Typed outcome, so a failure can be triaged rather than merely reported."""

    run_id: str
    events: int
    failures: tuple[ChainFailure, ...] = ()
    detail: str = ""
    sealed: bool = False
    """Whether the run's seal was available and checked. An unsealed chain can be
    walked but its head and count are unbound, so nothing rules out truncation."""

    guard_armed: bool = False
    """Whether the database will refuse further events for this run.

    Distinct from ``sealed``: a run can have a seal on its attestation and no entry in
    the registry the ``NoEventsAfterSeal`` trigger consults, which leaves the guard
    permanently unarmed for it. That was true of *every* run until the engine started
    closing them — the trigger existed, the table was empty, and every insert passed.
    A sweep that verified the chain and said nothing about the guard would have reported
    all of them as fine.
    """

    @property
    def verified(self) -> bool:
        return not self.failures

    def __bool__(self) -> bool:
        return self.verified


class StoredChainCheck:
    """Decodes stored rows and runs the kernel verifier over them."""

    #: Event hashes are recomputed from content, not read from the row. The difference
    #: is whether a rewritten event is detectable at all.
    RECOMPUTED: ClassVar[bool] = True

    __slots__ = ("_runs", "_seals", "_sink")

    def __init__(
        self,
        sink: DjangoAuditSink | None = None,
        runs: DjangoRunStore | None = None,
        seals: DjangoSealRegistry | None = None,
    ) -> None:
        self._sink = sink or DjangoAuditSink()
        self._runs = runs or DjangoRunStore()
        self._seals = seals or DjangoSealRegistry()

    def _armed(self, run_id: RunId) -> bool:
        """Whether the database itself will refuse another event for this run."""
        try:
            return bool(self._seals.is_sealed(run_id))
        except Exception:
            return False

    def _with_guard(self, detail: str, run_id: RunId) -> str:
        """Say when the chain verifies and the guard behind it is not armed.

        Verifying is a statement about the past. An unarmed guard is a statement about
        the future: this run is closed and the database would still accept an insert
        into it.
        """
        if self._armed(run_id):
            return detail
        note = (
            "chain verifies; the seal registry has no entry for this run, so the "
            "database will still accept events appended to it"
        )
        return f"{detail}. {note}" if detail else note

    def run(self, run_id: RunId) -> StoredChainResult:
        """Verify the chain for ``run_id``, against its seal where one exists."""
        try:
            events = self._sink.read_chain(run_id)
        except CodecError as exc:
            # A row that will not decode is itself an integrity finding: the bytes are
            # not the event they claim to be.
            return StoredChainResult(str(run_id), 0, (ChainFailure.ALTERED_EVENT,), str(exc))

        if not events:
            return StoredChainResult(
                str(run_id), 0, (ChainFailure.EMPTY,), "no events for this run"
            )

        seal = None
        try:
            attestation = self._runs.get(run_id)
        except CodecError as exc:
            return StoredChainResult(
                str(run_id), len(events), (ChainFailure.ALTERED_EVENT,), str(exc)
            )
        if attestation is not None:
            seal = attestation.seal

        if seal is None:
            return StoredChainResult(
                str(run_id),
                len(events),
                (ChainFailure.NOT_SEALED,),
                "no seal is on record for this run, so its head and count are unbound "
                "and nothing rules out truncation",
            )

        # Positions are recomputed, never read. Events are stored unsealed — the sink
        # records causal structure and the sealer assigns the canonical order
        # afterwards — so a stored `sequence` column would be the application
        # numbering its own chain, which is the self-certification ADR 0034 forbids.
        ordered, recomputed = ChainSealer().seal(
            events,
            run_id=run_id,
            attestation_hash=seal.attestation_hash,
            sealed_at=seal.sealed_at,
        )
        verification = ChainVerifier.verify(ordered, run_id=run_id, seal=seal)
        if verification.verified and recomputed.head_hash != seal.head_hash:
            return StoredChainResult(
                str(run_id),
                len(events),
                (ChainFailure.HEAD_MISMATCH,),
                "the chain recomputed from storage does not reach the sealed head",
                sealed=True,
            )
        return StoredChainResult(
            run_id=str(run_id),
            events=len(events),
            failures=verification.failures,
            detail=self._with_guard(verification.detail, run_id),
            guard_armed=self._armed(run_id),
            sealed=seal is not None,
        )
