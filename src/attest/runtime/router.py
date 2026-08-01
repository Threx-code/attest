"""Intent routing — choosing which agent handles a request.

A misroute in a high-stakes domain is not a UX problem. Sending a complaint to a sales
agent instead of a complaints agent can breach a regulatory handling deadline before
anyone notices, so a routing decision produces warrants like any other.

**Never dispatch a low-confidence classification to the closest match.** The surveyed
codebases mostly had a fallback agent, which converts "I do not know what this is" into
a confident answer from the wrong specialist.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from attest.kernel.errors import ConfigurationError
from attest.kernel.verdicts import Refusal, RefusalReason

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["Deflect", "RouteDecision", "Router", "RouterSpec"]


class Deflect(StrEnum):
    """What to do when the classifier is not confident enough to dispatch."""

    CLARIFY = "clarify"
    """This is two requests, or ambiguous between lanes."""

    HUMAN_QUEUE = "human_queue"
    REFUSE = "refuse"
    """Out of scope, as a typed refusal rather than improvised prose."""


@dataclass(frozen=True, slots=True)
class RouterSpec:
    """A closed taxonomy and what to do outside it.

    ``on_unknown`` and ``on_ambiguous`` are distinct: "this is not something we handle"
    needs a different response from "this is two requests".
    """

    agents: tuple[str, ...]
    threshold: float = 0.85
    on_unknown: Deflect = Deflect.HUMAN_QUEUE
    on_ambiguous: Deflect = Deflect.CLARIFY

    def __post_init__(self) -> None:
        if not self.agents:
            raise ConfigurationError("a router with no agents cannot route anything")
        if not 0.0 < self.threshold <= 1.0:
            raise ConfigurationError(f"threshold must be in (0, 1], got {self.threshold!r}")


@dataclass(frozen=True, slots=True)
class RouteDecision:
    """Where a request went, and why."""

    agent: str | None
    confidence: float
    deflected: Deflect | None = None
    refusal: Refusal | None = None

    @property
    def dispatched(self) -> bool:
        return self.agent is not None


class Router:
    """Dispatches to an agent, or deflects. Never guesses."""

    __slots__ = ("_spec",)

    def __init__(self, spec: RouterSpec) -> None:
        self._spec = spec

    def route(
        self, *, label: str | None, confidence: float, alternatives: Sequence[str] = ()
    ) -> RouteDecision:
        """Dispatch only on a confident, in-taxonomy classification.

        ``label`` of ``None`` means the classifier returned ``unknown`` rather than
        inventing a category — the taxonomy is closed for exactly that reason.
        """
        if label is None or label not in self._spec.agents:
            return RouteDecision(
                agent=None,
                confidence=confidence,
                deflected=self._spec.on_unknown,
                refusal=Refusal(
                    reason=RefusalReason("out_of_scope"),
                    detail=(
                        f"no agent handles {label!r}; deflected to "
                        f"{self._spec.on_unknown.value} rather than routed to the "
                        f"closest match"
                    ),
                ),
            )

        if len(alternatives) > 1:
            return RouteDecision(
                agent=None, confidence=confidence, deflected=self._spec.on_ambiguous
            )

        if confidence < self._spec.threshold:
            return RouteDecision(
                agent=None,
                confidence=confidence,
                deflected=self._spec.on_unknown,
                refusal=Refusal(
                    reason=RefusalReason("out_of_scope"),
                    detail=(
                        f"classification confidence {confidence:.2f} is below the "
                        f"{self._spec.threshold:.2f} threshold. A low-confidence "
                        f"dispatch is a confident answer from the wrong specialist."
                    ),
                ),
            )

        return RouteDecision(agent=label, confidence=confidence)

    @staticmethod
    def route_deterministically(structured_label: str | None) -> RouteDecision | None:
        """Route on structured context without a model call, where one exists.

        A model call to classify something already labelled — a form type, a queue
        name, a document class — is spend with no assurance benefit and one more thing
        that can be wrong.
        """
        if structured_label is None:
            return None
        return RouteDecision(agent=structured_label, confidence=1.0)
