"""Entailment judging — using a model to check a model.

That is circular trust, and the circularity has to be designed rather than assumed
away. Three rules carry it:

**Cross-family by default**, where family means the *weights*, not the vendor. Groq,
Bedrock and Vertex all serve Llama, so a provider check would accept a Llama judge for
a Llama generator — same-family judging in disguise, measuring consistency rather than
correctness. See ADR 0041.

**Judge output is probabilistic and labelled as such.** Never merged into the same
field as exact verification, or "verified" stops meaning anything.

**Disagreement is recorded, never averaged away.** A 2-1 split on whether an exclusion
applies is exactly the signal a human reviewer needs.

The default is `NONE`, deliberately: defaults get inherited unexamined, and one that
adds a model call per claim would make the framework uneconomical everywhere before
anyone evaluated it. A domain opts *up*.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from attest.kernel.errors import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["EntailmentPolicy", "JudgePanel", "JudgeVerdict", "PanelResult"]


class EntailmentPolicy(StrEnum):
    NONE = "none"
    """Exact verification only. THIN and STANDARD tiers, and the default."""

    SINGLE = "single"
    PANEL = "panel"
    DEFERRED = "deferred"
    """Judged after the response, warrant finalised asynchronously. Reversible
    effects only — the framework refuses the combination otherwise."""


@dataclass(frozen=True, slots=True)
class JudgeVerdict:
    """One judge's opinion, with the family that produced it."""

    refuted: bool
    family: str
    confidence: float
    reason: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence!r}")
        if not self.family:
            raise ValueError(
                "a verdict must name the model family that produced it; without it "
                "cross-family independence cannot be checked"
            )


@dataclass(frozen=True, slots=True)
class PanelResult:
    """The aggregate, with dissent preserved."""

    supported: bool
    verdicts: tuple[JudgeVerdict, ...]
    dissent: bool
    families: frozenset[str]

    @property
    def unanimous(self) -> bool:
        return not self.dissent


class JudgePanel:
    """Enforces judge independence and aggregates a panel.

    One class because the two operations are halves of the same guarantee: aggregating
    verdicts that were never checked for independence produces a confident number from
    correlated opinions, which is worse than no number.
    """

    ADVERSARIAL_FRAMING = (
        "Find the strongest reason this claim is NOT supported by the cited evidence. "
        "If you cannot find one, say so explicitly. Default to refuted under uncertainty."
    )
    """The framing judges are given.

    A judge asked "is this supported?" is biased toward yes. Defaulting to refuted
    under uncertainty is the same principle as a fail-closed guard, and it materially
    changes measured behaviour on the 'real quote, wrong inference' family.
    """

    __slots__ = ("_generator_family",)

    def __init__(self, *, generator_family: str) -> None:
        self._generator_family = generator_family

    def assert_independent(self, judge_families: Sequence[str]) -> None:
        """Refuse a judge drawn from the generator's own family.

        An empty family is treated as same-family: unknown provenance fails closed,
        because a judge we cannot place cannot be shown to be independent.
        """
        if not self._generator_family:
            raise ConfigurationError(
                "the generator's model family is unknown, so judge independence cannot "
                "be established. Configure ModelRef.family rather than assuming it."
            )
        for family in judge_families:
            if not family:
                raise ConfigurationError(
                    "a judge's model family is unknown; independence cannot be established"
                )
            if family == self._generator_family:
                raise ConfigurationError(
                    f"judge family {family!r} matches the generator's. Same-family "
                    f"judging measures consistency, not correctness: the inference that "
                    f"fooled the writer tends to fool the reader. Different PROVIDERS "
                    f"may serve the same family — the check is on the weights."
                )

    def aggregate(self, verdicts: Sequence[JudgeVerdict]) -> PanelResult:
        """Aggregate a panel. Majority rules; dissent is recorded.

        Independence is asserted first, so a panel can never be aggregated without it.
        A split is never resolved by averaging confidence — that destroys precisely the
        signal a reviewer needs.
        """
        if not verdicts:
            raise ValueError("an empty panel decides nothing")
        self.assert_independent([v.family for v in verdicts])
        refuting = sum(1 for v in verdicts if v.refuted)
        supporting = len(verdicts) - refuting
        return PanelResult(
            supported=supporting > refuting,
            verdicts=tuple(verdicts),
            dissent=refuting > 0 and supporting > 0,
            families=frozenset(v.family for v in verdicts),
        )
