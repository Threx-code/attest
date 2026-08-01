"""Verdicts and refusals — what a caller must handle.

A run resolves to exactly one :class:`Verdict`. The set is **closed**, and closing it
only buys anything if every reachable outcome is a member: a caller writing a four-arm
``match`` over a six-outcome space has the same bug as a caller who forgot to check at
all. See ADR 0033 and docs/concepts/verdicts.md.

Refusals are typed rather than prose, because refusal rates are monitored and a refusal
often triggers a downstream obligation - an adverse action notice, an escalation. You
cannot aggregate a sentence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Final, NewType

if TYPE_CHECKING:
    from attest.kernel.warrants import WarrantKind

__all__ = [
    "CORE_REFUSAL_REASONS",
    "POST_EFFECT_VERDICTS",
    "Refusal",
    "RefusalReason",
    "Verdict",
]


class Verdict(StrEnum):
    """The outcome of a run. Exhaustively matchable; see module docstring."""

    ALLOW = "allow"
    ALLOW_WITH_WARNINGS = "allow_with_warnings"
    """Shipped *with* findings. The host is obliged to surface them.

    A reporting agent that emits an unreconciled figure with a warning, into a
    dashboard that renders only the figure, has produced a material misstatement
    with a clean conscience.
    """

    HOLD_FOR_APPROVAL = "hold_for_approval"
    REFUSE = "refuse"

    UNKNOWN = "unknown"
    """An effect was attempted and its outcome could not be established.

    Neither success nor failure. A payment that timed out after the bank committed
    it is `UNKNOWN`, and coercing that to either answer is a lie. Terminal for the
    run, and a work item for reconciliation.
    """

    INCOMPLETE = "incomplete"
    """Some effects committed and the flow did not finish.

    Distinct from `REFUSE` because "nothing happened" and "some of it happened"
    require different human responses.
    """

    @property
    def requires_human_attention(self) -> bool:
        """Whether this outcome cannot be resolved by the system alone.

        `HOLD_FOR_APPROVAL` awaits a decision; `UNKNOWN` awaits reconciliation;
        `INCOMPLETE` awaits triage of a partially-applied world. A property rather
        than a free function so hosts route on intent instead of re-deriving the set
        and getting it subtly wrong.
        """
        return self in {
            Verdict.HOLD_FOR_APPROVAL,
            Verdict.UNKNOWN,
            Verdict.INCOMPLETE,
        }


POST_EFFECT_VERDICTS: Final[frozenset[Verdict]] = frozenset({Verdict.UNKNOWN, Verdict.INCOMPLETE})
"""Verdicts reachable only after an effect was attempted.

A run that never reached the execution boundary cannot produce these. Asserted in
tests rather than enforced by the type system, because splitting `Verdict` into two
enums would put the burden back on the caller to check both.
"""


RefusalReason = NewType("RefusalReason", str)
"""Open taxonomy. Domains register their own; the framework cannot enumerate theirs."""

CORE_REFUSAL_REASONS: Final[frozenset[RefusalReason]] = frozenset(
    map(
        RefusalReason,
        (
            "unsupported_claim",
            "insufficient_evidence",
            "out_of_scope",
            "insufficient_authority",
            "budget_exhausted",
            "injection_detected",
            # The three the framework produces regardless of profile configuration —
            # see attest.kernel.warrants.NON_DOWNGRADEABLE.
            "tenancy_violation",
            "outbound_leakage",
            "incomplete_restoration",
            "unsafe_action",
            "stale_evidence",
            "incomplete_coverage",
            "approval_expired",
            "approval_rejected",
            "step_budget_exhausted",
            "policy_downgrade",
            "residency_unavailable",
            "evidence_source_unreachable",
            # The failover chain ran out of time rather than out of providers. Distinct
            # from the one above because the remedy is distinct: "every provider failed"
            # sends an operator to look at routing, and the routing was fine.
            "deadline_exceeded",
            # A stream failed after bytes had already reached the reader. Not a failover:
            # re-emitting from a second provider shows the reader the answer twice, so
            # truncation is the honest outcome and is recorded as one.
            "stream_interrupted",
            "contradictory_policy",
            "no_counterfactual_available",
        ),
    )
)
"""Reasons the framework itself can produce.

An evidence source being unreachable is a *refusal*, not an exception: the system is
working, the world is not cooperating, and that is a decision worth recording with its
full context. See docs/kernel/errors.md.
"""


@dataclass(frozen=True, slots=True)
class Refusal:
    """Why a run refused, in a form that can be aggregated and acted on."""

    reason: RefusalReason
    detail: str
    """Human-readable, for an operator. Never the sole record of the refusal."""

    warrant: WarrantKind | None = None
    """Which warrant failed, where one did."""

    subject_message: str | None = None
    """What the affected person may be told, where that differs from `detail`.

    The split is not cosmetic. In regulated domains what you may tell an applicant
    is constrained by law and routinely differs from the internal reason - and
    telling them two different things is what an ombudsman looks for. `None` means
    the domain has not supplied one, never "reuse the internal reason".
    """

    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.reason:
            raise ValueError("refusal reason must not be empty")
        if not self.detail.strip():
            raise ValueError(
                "refusal detail must not be empty: an unexplained refusal cannot be "
                "acted on or contested"
            )
