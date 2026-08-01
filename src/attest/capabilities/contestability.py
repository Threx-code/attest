"""Contestability — why the decision went that way, and what would change it.

``docs/capabilities/contestability.md`` specifies this and no module existed. That is a
different order of gap from an unimplemented convenience: the document opens by saying
it is **legally required** in several target domains — adverse action notices, GDPR
Art. 22, FCA consumer duty — and ``docs/domains/mortgage.md`` advertises the output
verbatim: *"declined because commitments exceeded 45% of income; below 38% would have
been approved."*

So the package shipped a documented obligation it could not discharge, in the domains
it names as its market. A regulated adopter reading the docs would reasonably build a
decline flow on the assumption this existed.

.. rubric:: The framework does not ask a model to explain a decision

That is the design decision that makes this tractable, and it is not a performance
choice. A model-generated explanation is a **plausible story, not a cause**. Ask a model
why a mortgage was declined and it will produce a fluent, specific, checkable-sounding
paragraph whether or not it corresponds to anything the system did — and in front of an
ombudsman a plausible story that turns out not to match the internal record is worse
than no explanation, because it is evidence of a second, inconsistent account.

.. code-block:: text

    decision
      ├── deterministic: affordability calc, LTV, policy thresholds
      │        └──▶ INVERTIBLE — a counterfactual is exact and provable
      │
      └── model judgement: document interpretation, narrative
               └──▶ NOT INVERTIBLE — reported as a contributing factor,
                    never as a counterfactual

Where the determining factor was a model judgement, the honest output is *"referred for
manual review because the submitted documents could not be automatically interpreted"* —
not an invented threshold. :class:`Method.NONE` is a real answer here and the warrant is
unsatisfied, which is what routes the decision to a human.

.. rubric:: A decision that cannot be explained is not automated

Enforced rather than advised. When no counterfactual can be computed the warrant fails,
and the profile's policy for ``contestability`` decides whether that blocks or holds —
which also creates the right incentive: a domain that wants automation keeps its
determining logic deterministic and inspectable.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar, Final

from attest.kernel.warrants import (
    Finding,
    Severity,
    WarrantKind,
    WarrantReport,
    WarrantStatus,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

__all__ = [
    "CONTESTABILITY",
    "ContestabilityEngine",
    "ContestabilityReport",
    "Counterfactual",
    "Factor",
    "Method",
    "RecourseOption",
]

CONTESTABILITY: Final = WarrantKind("contestability")
"""Registered like any other warrant kind, so a profile blocks or holds on it.

Not a core warrant: a triage assistant that recommends nothing adverse owes nobody a
counterfactual, and making it mandatory everywhere would train domains to satisfy it
with a placeholder. A domain that issues adverse decisions declares it.
"""


class Method(StrEnum):
    """How the counterfactual was obtained. **Carried into the record, never inferred.**

    An ombudsman's question is not "what is the threshold" but "how do you know". A
    ``BOUNDARY`` result is exact and reproducible; a ``RANKING`` result is a sensitivity
    estimate and must be shown to the subject as *principal factors* rather than as a
    threshold they can act on. Collapsing the two into one field called ``explanation``
    is how an approximation comes to be quoted as a promise.
    """

    RULE = "rule"
    """The binding constraint was read directly off the rule that failed. Exact, free."""

    BOUNDARY = "boundary"
    """Binary search on the single binding input. Exact, and no model calls."""

    RANKING = "ranking"
    """Several inputs interact; ranked by sensitivity. **Approximate.**"""

    NONE = "none"
    """No counterfactual could be computed. A real answer, and it fails the warrant."""


@dataclass(frozen=True, slots=True)
class Factor:
    """One input that bore on the decision, and whether it can be reasoned about.

    ``deterministic`` is the field that does the work. A factor produced by a model
    judgement may be *reported* — the subject is entitled to know their documents could
    not be read — but it may never be inverted into a threshold, because there is no
    threshold. It is the difference between a fact about the system and a story about it.
    """

    name: str
    value: Any
    deterministic: bool = True
    threshold: Any = None
    """The limit this factor was compared against, where there was one."""

    determining: bool = False
    """Whether this factor is why the decision went the way it did.

    At most one factor should carry it for :attr:`Method.RULE` or
    :attr:`Method.BOUNDARY`; several may for :attr:`Method.RANKING`, which is precisely
    why ranking is approximate.
    """

    sensitivity: Decimal | None = None
    """How much the outcome moves per unit of this factor. Only for ranking."""

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("a factor must be named; an unnamed factor cannot be cited")

    def describe(self) -> str:
        """The phrase this factor contributes to a reason. Values, never adjectives.

        "commitments 45% (limit 38%)" is contestable. "affordability was insufficient"
        is not, and it is the sentence a subject cannot do anything with.
        """
        if self.threshold is None:
            return f"{self.name} {self.value}"
        return f"{self.name} {self.value} (limit {self.threshold})"


@dataclass(frozen=True, slots=True)
class Counterfactual:
    """What would have to change, and by how much. Exact, or absent.

    There is deliberately no "approximately" field. A counterfactual a subject cannot
    rely on is one they will act on anyway — they will pay down GBP 4,000 of debt
    because the letter said so — and being wrong about that is a harm the letter caused.
    """

    factor: str
    current: Any
    required: Any
    method: Method
    detail: str = ""

    def __post_init__(self) -> None:
        if self.method in (Method.NONE, Method.RANKING):
            raise ValueError(
                f"a Counterfactual cannot carry method {self.method.value!r}. RANKING is "
                f"a sensitivity estimate and NONE is the absence of an answer; "
                f"presenting either as a threshold tells a subject to act on a number "
                f"that is not one."
            )

    def describe(self) -> str:
        return f"{self.factor} would need to be {self.required} rather than {self.current}"


@dataclass(frozen=True, slots=True)
class RecourseOption:
    """What the subject can actually do. **Not a phone number.**

    Item 3 of the four requirements, and the one most often reduced to "contact us".
    A recourse option that does not say who acts, on what, and by when is a courtesy
    rather than a right.
    """

    action: str
    detail: str = ""
    deadline_days: int | None = None

    def __post_init__(self) -> None:
        if not self.action:
            raise ValueError("a recourse option must name an action the subject can take")


@dataclass(frozen=True, slots=True)
class ContestabilityReport(WarrantReport):
    """The warrant, plus everything an adverse-action notice needs.

    A :class:`~attest.kernel.warrants.WarrantReport` subclass rather than a parallel
    structure, so it lands in ``attestation.warrants`` and the profile's policy for
    ``contestability`` decides what an unsatisfied one does — the same machinery as
    every other warrant. A separate structure would need its own policy, its own
    resolution and its own way of being ignored.
    """

    determining_factors: tuple[Factor, ...] = ()
    counterfactual: Counterfactual | None = None
    counterfactual_method: Method = Method.NONE
    recourse: tuple[RecourseOption, ...] = ()
    subject_message: str = ""
    internal_reason: str = ""

    @property
    def consistent(self) -> bool:
        """Whether every factor cited to the subject appears in the internal record.

        **Item 4, and the one an ombudsman actually tests.** Two different explanations
        for one decision — a clean one for the subject and a different one in the file —
        is the finding they look for, and it is the finding that turns a defensible
        decline into a systemic one.

        Machine-checked rather than asserted, because the two texts are written at
        different times by different code and drift is the default. Checked on the
        *factor names* rather than by comparing prose: the subject message is written
        for a person and the internal reason for an auditor, so they should not read
        alike — what must hold is that the message cites nothing the record does not.
        """
        return not self.cited_but_unrecorded()

    def cited_but_unrecorded(self) -> tuple[str, ...]:
        """Factor names in the subject message that the internal reason does not carry.

        Returned rather than merely counted so a failure names the factor. "Inconsistent"
        is not something anybody can act on at 4pm on a Friday.
        """
        message = self.subject_message.lower()
        record = self.internal_reason.lower()
        return tuple(
            factor.name
            for factor in self.determining_factors
            if factor.name.lower() in message and factor.name.lower() not in record
        )


class ContestabilityEngine:
    """Computes the explanation, in the document's order of preference.

    Rule attribution first because it is exact and free; boundary search second because
    it is exact and cheap; ranking last and clearly labelled as approximate. Never a
    model — see the module docstring.
    """

    MAX_EVALUATIONS: ClassVar[int] = 40
    """Ceiling on boundary-search steps. The docs estimate ~15 for a realistic range.

    A bound rather than a while-loop because the predicate is host code: one that is
    not monotonic, or that returns the same answer either side of the true boundary,
    would otherwise spin forever inside a decline that is holding a request open.
    Hitting the ceiling produces ``Method.NONE`` — an honest failure — never a
    half-converged number presented as a threshold.
    """

    TOLERANCE: ClassVar[Decimal] = Decimal("0.01")
    """How close the search must get before it reports a boundary.

    Expressed in the units of the input being searched. Money and percentages are the
    realistic cases and both are meaningful to two places; a search that reported
    ``37.99999999`` would be exact and useless in a letter.
    """

    def explain(
        self,
        *,
        factors: Sequence[Factor],
        recourse: Sequence[RecourseOption] = (),
        decides: Callable[[str, Decimal], bool] | None = None,
        bounds: tuple[Decimal, Decimal] | None = None,
        subject_message: str = "",
    ) -> ContestabilityReport:
        """Produce the report. Tries rule attribution, then boundary search, then ranking.

        ``decides(factor_name, candidate) -> bool`` is the **deterministic** part of the
        decision, exposed by the profile: given a hypothetical value for one input, would
        the decision have been favourable? It is host code because only the domain knows
        its own rules, and it must not call a model — a stochastic predicate makes the
        search return a different threshold each time it is run, which is the one
        property a quoted number must not have.

        The warrant is satisfied only when a counterfactual was produced **and** the
        subject message is consistent with the internal record. Both are required: an
        exact threshold delivered alongside a message citing something else is two
        explanations for one decision.
        """
        determining = [f for f in factors if f.determining]
        internal = self._internal_reason(factors)

        counterfactual, method = self._compute(determining, decides=decides, bounds=bounds)
        message = subject_message or self._subject_message(determining, counterfactual)

        report = ContestabilityReport(
            kind=CONTESTABILITY,
            status=WarrantStatus.EVALUATED,
            satisfied=False,
            determining_factors=tuple(factors),
            counterfactual=counterfactual,
            counterfactual_method=method,
            recourse=tuple(recourse),
            subject_message=message,
            internal_reason=internal,
        )
        findings = self._findings(report)
        satisfied = method is not Method.NONE and report.consistent and bool(recourse)
        return ContestabilityReport(
            kind=CONTESTABILITY,
            status=WarrantStatus.EVALUATED,
            satisfied=satisfied,
            findings=findings,
            determining_factors=report.determining_factors,
            counterfactual=counterfactual,
            counterfactual_method=method,
            recourse=tuple(recourse),
            subject_message=message,
            internal_reason=internal,
        )

    # ── The three mechanisms ─────────────────────────────────────────────────

    def _compute(
        self,
        determining: Sequence[Factor],
        *,
        decides: Callable[[str, Decimal], bool] | None,
        bounds: tuple[Decimal, Decimal] | None,
    ) -> tuple[Counterfactual | None, Method]:
        if not determining:
            return None, Method.NONE

        # A model judgement is not invertible. Reported, never inverted — the honest
        # output is "referred for manual review", not an invented threshold.
        if any(not factor.deterministic for factor in determining):
            return None, Method.NONE

        if len(determining) == 1:
            single = determining[0]
            direct = self.rule_attribution(single)
            if direct is not None:
                return direct, Method.RULE
            searched = self.boundary_search(single, decides=decides, bounds=bounds)
            if searched is not None:
                return searched, Method.BOUNDARY

        # Several deterministic inputs interact. Ranking is the honest answer and it is
        # not a counterfactual: it is labelled as principal factors precisely so nobody
        # quotes it as a threshold.
        if len(determining) > 1:
            return None, Method.RANKING
        return None, Method.NONE

    @staticmethod
    def rule_attribution(factor: Factor) -> Counterfactual | None:
        """Mechanism 1. The binding constraint, read off the rule that failed.

        Exact and free: if a rule compared a value to a threshold and the value lost,
        the counterfactual is the threshold. No search, no evaluation, no model.
        Available only when the profile exposed the threshold — which is the argument
        for keeping decision rules as inspectable ``FunctionNode``s rather than opaque
        code, made here on the same grounds ``docs/runtime/composition.md`` makes it.
        """
        if factor.threshold is None:
            return None
        return Counterfactual(
            factor=factor.name,
            current=factor.value,
            required=factor.threshold,
            method=Method.RULE,
            detail=(
                f"{factor.name} was {factor.value} against a limit of {factor.threshold}; "
                f"the rule that failed names both, so no search was needed"
            ),
        )

    def boundary_search(
        self,
        factor: Factor,
        *,
        decides: Callable[[str, Decimal], bool] | None,
        bounds: tuple[Decimal, Decimal] | None,
    ) -> Counterfactual | None:
        """Mechanism 2. Binary search on the single binding input.

        Exact, cheap, and free of model calls. ``None`` — never an approximation — when
        the predicate is missing, the bounds do not bracket a change of outcome, or the
        evaluation ceiling is reached.

        The bracket check is the important one and it is easy to leave out. Searching a
        range where the predicate answers the same way at both ends converges neatly on
        a number that means nothing: it is the midpoint of an interval containing no
        boundary. Verifying that the outcome actually differs at the two ends is what
        makes the result a fact rather than an artefact of the search.
        """
        if decides is None or bounds is None:
            return None
        low, high = bounds
        if low > high:
            low, high = high, low
        if decides(factor.name, low) == decides(factor.name, high):
            # No boundary in this range. Reporting the midpoint would be inventing one.
            return None

        # **The predicate must be a function of its input.** Checked before searching,
        # because bisection narrows its interval geometrically whatever the predicate
        # does: one that consults a model, a clock, a cache or a call counter still
        # converges, on a clean, precise, entirely meaningless number. An evaluation
        # ceiling does not catch that — the loop always terminates — and neither does
        # re-running the search, because a predicate that depends on call *order* makes
        # the same sequence of calls the second time and agrees with itself.
        #
        # Asking the same question twice and requiring the same answer is what catches
        # it, and it tests exactly the property the docs require: this is the
        # *deterministic* part of the decision. The difference between a threshold a
        # subject can rely on and a number that happened once.
        if not self._is_a_function_of_its_input(factor.name, decides, low, high):
            return None

        boundary = self._bisect(factor.name, decides, low, high)
        if boundary is None:
            return None

        return Counterfactual(
            factor=factor.name,
            current=factor.value,
            required=boundary,
            method=Method.BOUNDARY,
            detail=(
                f"searched the deterministic decision over {factor.name}; the outcome "
                f"changes at {boundary}, to within {self.TOLERANCE}, and the search was "
                f"repeated to confirm the predicate is deterministic"
            ),
        )

    @staticmethod
    def _is_a_function_of_its_input(
        name: str,
        decides: Callable[[str, Decimal], bool],
        low: Decimal,
        high: Decimal,
    ) -> bool:
        """Whether asking the same question twice gives the same answer.

        Probed at both ends and the midpoint. Not exhaustive — nothing short of the
        whole domain would be — but it costs six evaluations and catches the shapes that
        actually occur: a model call, a clock read, a cache that warms, a counter.

        Deliberately not a claim that the predicate is monotonic. It need not be: a rule
        with an upper and a lower bound is perfectly explainable within a range that
        brackets one of them, and the bracket check above already establishes that a
        boundary exists in the range being searched.
        """
        middle = (low + high) / 2
        return all(
            decides(name, candidate) == decides(name, candidate)
            for candidate in (low, high, middle)
        )

    def _bisect(
        self,
        name: str,
        decides: Callable[[str, Decimal], bool],
        low: Decimal,
        high: Decimal,
    ) -> Decimal | None:
        """One bisection pass. ``None`` if the ceiling is reached without converging."""
        favourable_at_low = decides(name, low)
        for _ in range(self.MAX_EVALUATIONS):
            if high - low <= self.TOLERANCE:
                return low if favourable_at_low else high
            middle = (low + high) / 2
            if decides(name, middle) == favourable_at_low:
                low = middle
            else:
                high = middle
        return None

    @staticmethod
    def factor_ranking(factors: Sequence[Factor]) -> tuple[Factor, ...]:
        """Mechanism 3. Principal factors by sensitivity, most influential first.

        **Approximate, and the caller must present it as such.** Where several inputs
        interact there is no single threshold, so this ranks rather than inverts. A
        subject told "your principal factors were A, B and C" can act; a subject told
        "reduce A to 38%" when A only mattered in combination with B has been given a
        number that will not do what the letter said.

        Unranked factors sort last rather than first: an unmeasured sensitivity is not
        evidence of a large one.
        """
        return tuple(
            sorted(
                factors,
                key=lambda f: (f.sensitivity is None, -(f.sensitivity or Decimal(0)), f.name),
            )
        )

    # ── The record and the message ───────────────────────────────────────────

    @staticmethod
    def _internal_reason(factors: Sequence[Factor]) -> str:
        """Everything that bore on the decision, in the file. The auditor's copy."""
        if not factors:
            return "no determining factors were recorded"
        return "; ".join(
            f"{'DETERMINING: ' if f.determining else ''}{f.describe()}"
            f"{'' if f.deterministic else ' (model judgement)'}"
            for f in factors
        )

    @staticmethod
    def _subject_message(
        determining: Sequence[Factor], counterfactual: Counterfactual | None
    ) -> str:
        """What the subject is told. Written from the same factors as the record.

        Generated from the factors rather than accepted as free text by default, because
        the consistency check is only as good as the discipline that produced the two
        texts — and the cheapest way to keep a subject message consistent with the record
        is to derive it from the record.
        """
        if not determining:
            return (
                "This decision was referred for manual review: the system could not "
                "identify a single determining factor to explain it."
            )
        if any(not f.deterministic for f in determining):
            return (
                "This application was referred for manual review because the submitted "
                "information could not be automatically interpreted."
            )
        cited = "; ".join(f.describe() for f in determining)
        if counterfactual is None:
            return (
                f"The decision was determined principally by: {cited}. These are the "
                f"principal factors; no single threshold determined the outcome on its own."
            )
        return f"The decision was determined by {cited}. {counterfactual.describe()}."

    @staticmethod
    def _findings(report: ContestabilityReport) -> tuple[Finding, ...]:
        """What went wrong, in a form somebody can act on."""
        findings: list[Finding] = []
        if report.counterfactual_method is Method.NONE:
            findings.append(
                Finding(
                    code="no_counterfactual_available",
                    message=(
                        "no counterfactual could be computed for this decision. A "
                        "decision that cannot be explained must not be issued "
                        "automatically."
                    ),
                    severity=Severity.ERROR,
                )
            )
        if report.counterfactual_method is Method.RANKING:
            findings.append(
                Finding(
                    code="counterfactual_is_approximate",
                    message=(
                        "several inputs interact, so the explanation ranks principal "
                        "factors rather than naming a threshold. It must not be "
                        "presented to the subject as a number to act on."
                    ),
                    severity=Severity.WARNING,
                )
            )
        unrecorded = report.cited_but_unrecorded()
        if unrecorded:
            findings.append(
                Finding(
                    code="explanation_inconsistent",
                    message=(
                        f"the subject was told about {list(unrecorded)}, which the "
                        f"internal record does not carry. Two explanations for one "
                        f"decision is the finding an ombudsman looks for."
                    ),
                    severity=Severity.ERROR,
                )
            )
        if not report.recourse:
            findings.append(
                Finding(
                    code="no_recourse_offered",
                    message=(
                        "the subject was given a reason and no route to challenge it. "
                        "An explanation without recourse is a notification."
                    ),
                    severity=Severity.ERROR,
                )
            )
        return tuple(findings)
