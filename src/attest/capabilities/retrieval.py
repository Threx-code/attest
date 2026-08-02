"""Retrieval — evidence in, with what was rejected recorded rather than dropped.

The port's highest-severity obligation is that a retriever scopes **at the query**, not
afterwards. This engine's tenancy check is deliberately redundant with that: reaching
it means the primary scoping already failed, which is an incident rather than a
ranking error, so it raises rather than filtering.

What is admitted and what is not are both recorded. Evidence that failed verification
and was silently dropped would leave an attestation whose sources look unanimous — the
run would appear better supported than it was, which is the specific way an evidence
trail lies by omission.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from attest.capabilities.guards import TenancyGuard
from attest.kernel.errors import RetrieverScopeError
from attest.kernel.evidence import VerificationOutcome

if TYPE_CHECKING:
    from datetime import date

    from attest.capabilities.evidence import EvidenceEngine
    from attest.kernel.context import ExecutionContext
    from attest.kernel.evidence import Evidence, SupportResult
    from attest.kernel.ports import Retriever

__all__ = ["RejectedEvidence", "RetrievalEngine", "RetrievalOutcome"]


@dataclass(frozen=True, slots=True)
class RejectedEvidence:
    """One item that was retrieved and then not admitted, and why."""

    evidence_id: str
    source_id: str
    outcome: VerificationOutcome
    detail: str = ""


@dataclass(frozen=True, slots=True)
class RetrievalOutcome:
    """What a query returned, split into what may be relied on and what may not."""

    admitted: tuple[Evidence, ...] = ()
    rejected: tuple[RejectedEvidence, ...] = ()
    query: str = ""

    @property
    def retrieved(self) -> int:
        return len(self.admitted) + len(self.rejected)


class RetrievalEngine:
    """Fetches candidate evidence, checks it, and reports both halves.

    Holds the tenancy guard and the verification engine so a caller cannot retrieve
    without them — which is the same reason the router holds the residency
    constraints rather than accepting them per call.
    """

    __slots__ = ("_evidence", "_retriever", "_tenancy")

    def __init__(
        self,
        retriever: Retriever,
        *,
        evidence: EvidenceEngine | None = None,
        tenancy: TenancyGuard | None = None,
    ) -> None:
        self._retriever = retriever
        self._evidence = evidence
        self._tenancy = tenancy or TenancyGuard()

    def retrieve(
        self, query: str, *, context: ExecutionContext, limit: int = 10
    ) -> RetrievalOutcome:
        """Retrieve for this run's tenant, and admit only what verifies.

        The tenant comes from the context rather than from an argument: a caller who
        passed the wrong one would get a correctly-scoped query against the wrong
        tenant, which no downstream check could detect.
        """
        candidates = self._retriever.retrieve(query, tenant=context.identity.tenant, limit=limit)

        breach = self._tenancy.check(candidates, tenant=context.identity.tenant)
        if not breach.clean:
            raise RetrieverScopeError(
                f"the retriever returned evidence outside tenant "
                f"{context.identity.tenant!r}: {breach.detail}. Scoping must happen at "
                f"the query; reaching this check means the index was already searched "
                f"across tenants, so a scoring bug is a data leak."
            )

        admitted: list[Evidence] = []
        rejected: list[RejectedEvidence] = []
        for item in candidates:
            barred = self._barred(item, context=context)
            if barred is not None:
                rejected.append(barred)
                continue
            verdict = self._verify(item, at=context.captured_at.date())
            if verdict is None or verdict.outcome is VerificationOutcome.PASS:
                admitted.append(item)
                continue
            rejected.append(
                RejectedEvidence(
                    evidence_id=str(item.evidence_id),
                    source_id=item.source.source_id,
                    outcome=verdict.outcome,
                    detail=verdict.discrepancy or "",
                )
            )
        return RetrievalOutcome(tuple(admitted), tuple(rejected), query=query)

    @staticmethod
    def _barred(item: Evidence, *, context: ExecutionContext) -> RejectedEvidence | None:
        """Whether this actor may read this source at all, tenancy aside.

        Tenancy answers "whose data is this"; it does not answer "may *this person* see
        it", and in a law firm those are different questions with different answers. An
        ethical wall between two teams, a Chinese wall between advisory and trading, a
        need-to-know boundary on a clinical record - a framework that models only the
        tenant treats a firm as one undifferentiated reader, which no firm is.

        **Rejected rather than raised**, and the asymmetry with `RetrieverScopeError` above
        is deliberate. A cross-TENANT result means the index was searched across tenants
        and the scoping already failed, so continuing is not safe. A screened source is the
        ordinary case: the retriever was scoped correctly and this reader is walled off
        from one matter among many. The run proceeds without it, and the rejection is
        recorded - which is what a conflicts review needs to see.
        """
        corpus = item.source.corpus if hasattr(item.source, "corpus") else None
        if context.visibility.permits(corpus=corpus, source_id=item.source.source_id):
            return None
        return RejectedEvidence(
            evidence_id=str(item.evidence_id),
            source_id=item.source.source_id,
            outcome=VerificationOutcome.UNVERIFIABLE,
            detail=(
                "outside this actor's visibility scope: screened source or a corpus they "
                "may not read. Not a verification failure - the source was never opened."
            ),
        )

    def _verify(self, item: Evidence, *, at: date) -> SupportResult | None:
        """Verification result, or ``None`` when no engine was supplied.

        Without an engine everything is admitted, which is honest: nothing was checked,
        and the epistemic warrant is what will say so.
        """
        if self._evidence is None:
            return None
        return self._evidence.verify(item, at=at)
