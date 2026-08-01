"""Coverage — was what we used *enough*?

The four core warrants all validate what WAS used. None asks what was missed, and
that gap is invisible to every other mechanism: retrieval returns three genuine
policies, every citation verifies, the chain is intact — and the 2026 amendment that
disqualifies the applicant was never returned.

The honest limit, stated rather than designed away: **absolute completeness is
unknowable.** A system cannot enumerate what it does not know exists. What is
assertable is completeness relative to a *declared* scope, and a warrant claiming more
would quietly always pass, which is worse than not having it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from attest.kernel.warrants import (
    Finding,
    Severity,
    WarrantKinds,
    WarrantReport,
    WarrantStatus,
)

if TYPE_CHECKING:
    from datetime import date

    from attest.kernel.identifiers import CorpusId

__all__ = ["CorpusRef", "CoverageReport", "Query", "RequiredSources", "TruncationEvent"]


@dataclass(frozen=True, slots=True)
class CorpusRef:
    """Which corpus, at which epoch.

    The epoch is what makes a stale-corpus answer detectable: without it, an answer
    derived from a pre-amendment snapshot is indistinguishable from a current one.
    """

    corpus_id: CorpusId
    epoch: str


@dataclass(frozen=True, slots=True)
class Query:
    """One query, declared BEFORE execution.

    Declared first so coverage is measured against an intention, rather than
    rationalised from whatever happened to return.
    """

    text: str
    corpus: CorpusId
    limit: int


@dataclass(frozen=True, slots=True)
class TruncationEvent:
    """A result set hit a limit.

    The single most common completeness failure in production retrieval, and it
    produces no error anywhere: "top 20 of 4,312 matches", answered from the 20.
    """

    corpus: CorpusId
    returned: int
    available: int | None = None

    def __post_init__(self) -> None:
        if self.available is not None and self.available < self.returned:
            raise ValueError("available cannot be fewer than returned")


@dataclass(frozen=True, slots=True)
class RequiredSources:
    """Sources the domain mandates for this decision type.

    Fully deterministic, and where most of the practical value is: a sanctions
    determination that never consulted the UN list is caught mechanically, with no
    model judgement involved.
    """

    all_of: frozenset[str] = frozenset()

    @classmethod
    def of(cls, *names: str) -> RequiredSources:
        return cls(frozenset(names))


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """What was searched, what was required, and what was knowingly not searched."""

    corpora: tuple[CorpusRef, ...] = ()
    query_plan: tuple[Query, ...] = ()
    required: RequiredSources = field(default_factory=RequiredSources)
    satisfied_sources: frozenset[str] = frozenset()
    truncations: tuple[TruncationEvent, ...] = ()
    failed_sources: frozenset[str] = frozenset()
    jurisdiction: str | None = None
    window_from: date | None = None
    window_to: date | None = None
    residual: tuple[str, ...] = ()
    """What was knowingly NOT searched, and why. Non-empty is not a failure — it is
    the difference between honest scope and an implied claim of totality."""

    @property
    def missing_sources(self) -> frozenset[str]:
        return self.required.all_of - self.satisfied_sources

    def warrant(self) -> WarrantReport:
        """The coverage warrant.

        Unsatisfied when a required source is missing, when anything truncated, or
        when a source failed. Truncation counts because an answer drawn from the first
        page of results is an answer about the first page.
        """
        findings: list[Finding] = []

        for name in sorted(self.missing_sources):
            findings.append(
                Finding(
                    code="missing_required_source",
                    message=f"required source {name!r} does not appear in the retrieval record",
                    severity=Severity.ERROR,
                    data={"source": name},
                )
            )
        for event in self.truncations:
            findings.append(
                Finding(
                    code="truncated",
                    message=(
                        f"{event.corpus}: returned {event.returned} of "
                        f"{event.available if event.available is not None else 'unknown'} "
                        f"matches; the answer covers what was returned, not the corpus"
                    ),
                    severity=Severity.ERROR,
                    data={"corpus": str(event.corpus)},
                )
            )
        for name in sorted(self.failed_sources):
            findings.append(
                Finding(
                    code="source_unavailable",
                    message=f"source {name!r} could not be searched",
                    severity=Severity.ERROR,
                    data={"source": name},
                )
            )
        for note in self.residual:
            findings.append(
                Finding(
                    code="residual_scope",
                    message=f"knowingly not searched: {note}",
                    severity=Severity.INFO,
                )
            )

        blocking = [f for f in findings if f.severity is Severity.ERROR]
        return WarrantReport(
            kind=WarrantKinds.COMPLETENESS,
            status=WarrantStatus.EVALUATED,
            satisfied=not blocking,
            findings=tuple(findings),
        )
