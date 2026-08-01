"""Evaluation — golden sets and regression gates.

``docs/assurance/eval.md`` specifies ``GoldenCase``, ``Expectation``, a regression gate
and a calibration report. None of it existed, which left the third leg of the triangle
the document opens with missing:

.. code-block:: text

    conformance  ──▶  "the machinery is intact"     structural   SHIPPED
    redteam      ──▶  "it resists attack"           adversarial  SHIPPED
    evaluation   ──▶  "the answers are correct"     empirical    absent

Conformance proves a domain is well-formed and the red-team corpus proves it resists
attack. Neither says the answers are *right*, and a framework that governs decisions
without a way to ask whether the decisions are correct is governing the paperwork.

.. rubric:: Assert on structure, never on prose

The document is emphatic and it is worth repeating where the code is: *"Asserting exact
answer text produces a suite that fails on every harmless rewording and gets disabled
within a month."* :class:`Expectation` therefore has no ``answer_equals``. It has
``answer_contains``, which is a substring check on figures and terms that must survive
paraphrase — and even that is the weakest thing here, listed last on purpose.

.. rubric:: Refusal rate is the metric that games itself

*"A system that refuses everything scores perfectly on groundedness."* So
:class:`Metrics` reports the two together and :meth:`Metrics.gamed` names the shape
directly, because a dashboard that shows groundedness rising is a dashboard somebody
will screenshot.

.. rubric:: The domain owns the cases

Golden sets live in the domain package. The framework ships the harness; the domain
ships the cases. A framework shipping medical golden cases would be shipping medical
knowledge, which ``docs/00-thesis.md`` rules out — so there is no shipped corpus here,
deliberately, and :class:`GoldenSet` is empty until a domain fills it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar

from attest.kernel.verdicts import Verdict

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from attest.kernel.attestation import Attestation
    from attest.kernel.warrants import WarrantKind

__all__ = [
    "CalibrationBand",
    "CalibrationReport",
    "Expectation",
    "GoldenCase",
    "GoldenSet",
    "Metrics",
    "Outcome",
    "RegressionGate",
]


@dataclass(frozen=True, slots=True)
class Expectation:
    """What a golden case asserts. **Structure, not wording.**

    Every field is optional and an unset one asserts nothing, so a domain states the
    part of the outcome it actually knows. A case that asserted everything would fail on
    the first unrelated change and be deleted rather than fixed.
    """

    verdict: Verdict | None = None
    """The decision. The single most valuable assertion, and the least brittle."""

    warrants_satisfied: frozenset[WarrantKind] = frozenset()
    """Warrants that must have been evaluated **and** satisfied.

    Not "present": an unevaluated warrant reads as a satisfied one to anything that only
    checks for the key, which is the confusion :meth:`WarrantReport.is_satisfied` exists
    to prevent.
    """

    warrants_unsatisfied: frozenset[WarrantKind] = frozenset()
    """Warrants that must have failed. The half a suite usually forgets.

    A case about a claim with insufficient evidence is not really testing anything unless
    it asserts the *epistemic* warrant failed — otherwise a REFUSE for the wrong reason
    passes.
    """

    obligations_pending: frozenset[str] = frozenset()
    """Obligation names that must still be outstanding, by finding code or name.

    "Did the right gates fire" is a different question from "what was the verdict", and
    a HOLD that held for the wrong reason is a defect that a verdict assertion misses.
    """

    refusal_reason: str | None = None
    """Typed, so it is assertable. That is why refusal reasons are a taxonomy."""

    answer_contains: tuple[str, ...] = ()
    """Substrings that must survive paraphrase — a figure, a clause reference.

    Listed last, and deliberately not ``answer_equals``. A suite that pins prose fails on
    every harmless rewording and is disabled within a month, at which point it asserts
    nothing at all.
    """

    max_cost: Decimal | None = None
    """A spend ceiling. Regressions in cost are regressions."""

    def check(self, attestation: Attestation) -> tuple[str, ...]:
        """Every way ``attestation`` misses this expectation. Empty means it matched.

        All differences rather than the first, because a golden-set failure is read once,
        by somebody deciding whether the change was intended — and one that reports a
        single difference per run turns that decision into several.
        """
        problems: list[str] = []
        if self.verdict is not None and attestation.verdict is not self.verdict:
            problems.append(
                f"verdict: expected {self.verdict.value}, got {attestation.verdict.value}"
            )

        for kind in sorted(self.warrants_satisfied):
            report = attestation.warrants.get(kind)
            if report is None:
                problems.append(f"warrant {kind}: expected satisfied, was not evaluated at all")
            elif not report.is_satisfied():
                problems.append(
                    f"warrant {kind}: expected satisfied, was {report.status.value}"
                    f"{'' if report.satisfied else ' and unsatisfied'}"
                )
        for kind in sorted(self.warrants_unsatisfied):
            report = attestation.warrants.get(kind)
            if report is not None and report.is_satisfied():
                problems.append(f"warrant {kind}: expected unsatisfied, it passed")

        outstanding = {
            finding.code for report in attestation.warrants.values() for finding in report.findings
        }
        for name in sorted(self.obligations_pending):
            if name not in outstanding:
                problems.append(f"obligation {name!r}: expected outstanding, nothing recorded it")

        if self.refusal_reason is not None:
            actual = None if attestation.refusal is None else str(attestation.refusal.reason)
            if actual != self.refusal_reason:
                problems.append(f"refusal reason: expected {self.refusal_reason!r}, got {actual!r}")

        for fragment in self.answer_contains:
            if fragment not in attestation.answer:
                problems.append(f"answer does not contain {fragment!r}")

        if self.max_cost is not None:
            spent = Metrics.spent(attestation)
            if spent > self.max_cost:
                problems.append(f"cost {spent} exceeds the ceiling of {self.max_cost}")

        return tuple(problems)


@dataclass(frozen=True, slots=True)
class GoldenCase:
    """One case with a known-correct outcome, owned by the domain.

    ``fixtures`` pins the evidence and tool results, so the case is about the *decision*
    rather than about whichever documents the retriever happened to return today. A
    golden case whose inputs move is not a golden case.
    """

    id: str
    build: Callable[[], Any]
    """Produces the ``RunRequest``. A callable rather than a value, so a case that needs
    state planted first can plant it."""

    expect: Expectation = field(default_factory=Expectation)
    fixtures: Mapping[str, Any] = field(default_factory=dict)
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("a golden case needs an id; a failure has to name something")
        if self.expect == Expectation():
            raise ValueError(
                f"golden case {self.id!r} expects nothing, so it cannot fail — which "
                f"makes it worse than absent, because it counts toward coverage. This "
                f"is the same defect the red-team corpus had: a manifest of titles."
            )


@dataclass(frozen=True, slots=True)
class Outcome:
    """What running one case established."""

    case: GoldenCase
    passed: bool
    differences: tuple[str, ...] = ()
    attestation: Attestation | None = None

    def render(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        if self.passed:
            return f"{mark}  {self.case.id}"
        return f"{mark}  {self.case.id}\n" + "\n".join(f"        {d}" for d in self.differences)


class GoldenSet:
    """The domain's cases, and the harness that runs them.

    **Empty by default, and that is the design.** Golden sets live in the domain package;
    the framework ships the harness. A framework shipping medical golden cases would be
    shipping medical knowledge.
    """

    __slots__ = ("_cases",)

    def __init__(self, cases: Sequence[GoldenCase] = ()) -> None:
        seen: set[str] = set()
        for case in cases:
            if case.id in seen:
                raise ValueError(
                    f"two golden cases share the id {case.id!r}. A failure names an id, "
                    f"and two cases behind one name means the report is ambiguous."
                )
            seen.add(case.id)
        self._cases = tuple(cases)

    def __len__(self) -> int:
        return len(self._cases)

    @property
    def cases(self) -> tuple[GoldenCase, ...]:
        return self._cases

    def run(self, *, engine: Any, binding: Any, executor: Any = None) -> tuple[Outcome, ...]:
        """Execute every case and report what differed.

        A case that raises is a **failure**, not an error that stops the suite: a golden
        set that aborts on the first exception tells you about one case, and the run that
        produced it took as long as all of them.
        """
        outcomes: list[Outcome] = []
        for case in self._cases:
            try:
                result = engine.execute(case.build(), binding=binding, executor=executor)
            except Exception as exc:
                outcomes.append(
                    Outcome(
                        case=case,
                        passed=False,
                        differences=(f"the run raised {type(exc).__name__}: {exc}",),
                    )
                )
                continue
            differences = case.expect.check(result.attestation)
            outcomes.append(
                Outcome(
                    case=case,
                    passed=not differences,
                    differences=differences,
                    attestation=result.attestation,
                )
            )
        return tuple(outcomes)


class RegressionGate:
    """Turns a set of outcomes into a merge decision, and a diff a human can read.

    The document's shape: structural regressions are caught free on every PR by replaying
    without model calls; behavioural drift needs live calls and belongs on a schedule.
    This class does not choose which — it reports — because the choice is the host's CI
    and a framework that owned it would own their pipeline.
    """

    @staticmethod
    def failures(outcomes: Sequence[Outcome]) -> tuple[Outcome, ...]:
        return tuple(outcome for outcome in outcomes if not outcome.passed)

    @classmethod
    def blocks_merge(cls, outcomes: Sequence[Outcome]) -> bool:
        """Any difference blocks. **A human decides whether the change was intended.**

        Not "any difference is a bug": a golden set is a record of what the system used
        to do, and changing what it does is often the point of a change. What must not
        happen is the change going in *unnoticed*, which is what a gate that
        auto-accepted differences would allow.
        """
        return bool(cls.failures(outcomes))

    @classmethod
    def report(cls, outcomes: Sequence[Outcome]) -> str:
        failed = cls.failures(outcomes)
        lines = [f"GOLDEN SET  {len(outcomes) - len(failed)}/{len(outcomes)} matched"]
        lines += [outcome.render() for outcome in failed]
        if failed:
            lines.append(
                "A difference is not automatically a defect — a golden set records what "
                "the system used to do. Decide whether this change was intended, then "
                "update the case or fix the code."
            )
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class Metrics:
    """The empirical figures over a run of the set.

    ``refusal_rate`` and ``groundedness`` are reported together and never apart. See
    :meth:`gamed`.
    """

    runs: int
    groundedness: Decimal = Decimal(0)
    """Share of runs whose epistemic warrant was satisfied."""

    refusal_rate: Decimal = Decimal(0)
    hold_rate: Decimal = Decimal(0)
    cost_p50: Decimal = Decimal(0)
    cost_p95: Decimal = Decimal(0)

    def gamed(self, *, against: Metrics | None = None) -> bool:
        """Whether groundedness rose because the system started refusing more.

        *"A system that refuses everything scores perfectly on groundedness."* It is the
        easiest metric in the document to optimise and the easiest to optimise
        dishonestly, and the optimisation looks like an improvement on every chart.

        Treated as a regression when refusal rises **without** a corresponding fall in
        groundedness — which is the document's own rule, made checkable.
        """
        if against is None:
            return False
        return (
            self.refusal_rate > against.refusal_rate and self.groundedness >= against.groundedness
        )

    @staticmethod
    def spent(attestation: Attestation) -> Decimal:
        """What one run cost, as a Decimal. Zero when it will not parse.

        A cost that will not parse is a reporting problem, not a reason to lose every
        other run's cost in the same batch — a p95 that silently dropped its outliers
        would be the most misleading number in the report.
        """
        raw = getattr(attestation.cost, "amount", None)
        if raw is None:
            return Decimal(0)
        try:
            return Decimal(str(raw))
        except (ValueError, ArithmeticError):
            return Decimal(0)

    @staticmethod
    def share(part: int, whole: int) -> Decimal:
        """A percentage, or zero over an empty population."""
        if whole <= 0:
            return Decimal(0)
        return (Decimal(part) * 100 / Decimal(whole)).quantize(Decimal("0.01"))

    @staticmethod
    def percentile(sorted_values: Sequence[Decimal], percentile: int) -> Decimal:
        """Nearest-rank. **No interpolation**, so the figure is a value that occurred.

        An interpolated p95 of a cost distribution is a price nobody was charged, and
        these numbers end up in a capacity conversation.
        """
        if not sorted_values:
            return Decimal(0)
        rank = max(1, (percentile * len(sorted_values) + 99) // 100)
        return sorted_values[min(rank, len(sorted_values)) - 1]

    @classmethod
    def over(cls, outcomes: Sequence[Outcome]) -> Metrics:
        from attest.kernel.warrants import WarrantKinds

        records = [o.attestation for o in outcomes if o.attestation is not None]
        if not records:
            return cls(runs=0)

        grounded = sum(
            1
            for r in records
            if (report := r.warrants.get(WarrantKinds.EPISTEMIC)) is not None
            and report.is_satisfied()
        )
        refused = sum(1 for r in records if r.verdict is Verdict.REFUSE)
        held = sum(1 for r in records if r.verdict is Verdict.HOLD_FOR_APPROVAL)
        costs = sorted(cls.spent(r) for r in records)
        return cls(
            runs=len(records),
            groundedness=cls.share(grounded, len(records)),
            refusal_rate=cls.share(refused, len(records)),
            hold_rate=cls.share(held, len(records)),
            cost_p50=cls.percentile(costs, 50),
            cost_p95=cls.percentile(costs, 95),
        )

    def render(self) -> str:
        return "\n".join(
            [
                f"METRICS over {self.runs} runs",
                f"  groundedness    {self.groundedness}%",
                f"  refusal rate    {self.refusal_rate}%   <- read with groundedness",
                f"  hold rate       {self.hold_rate}%",
                f"  cost p50/p95    {self.cost_p50} / {self.cost_p95}",
            ]
        )


@dataclass(frozen=True, slots=True)
class CalibrationBand:
    """One confidence band, and what actually happened in it."""

    lower: Decimal
    upper: Decimal
    stated: int
    correct: int

    @property
    def observed(self) -> Decimal:
        return Metrics.share(self.correct, self.stated) / 100

    @property
    def overconfident(self) -> bool:
        """Observed accuracy below the band the system claimed. **The finding.**

        *"A model that says 0.6 and is right 31% of the time is more dangerous than one
        that refuses, because a human downstream will trust the number."* Underconfidence
        is not symmetric with this and is not flagged: a system that says 0.6 and is right
        90% of the time is wasting review capacity, which costs money rather than
        producing a wrong decision somebody relied on.
        """
        return self.stated > 0 and self.observed < self.lower

    def render(self) -> str:
        verdict = "OVERCONFIDENT" if self.overconfident else "well calibrated"
        return (
            f"  {self.lower} - {self.upper}   {self.observed:.2f}   {verdict}   (n={self.stated})"
        )


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    """The empirical figures the ``CALIBRATION`` warrant checks against.

    Produced by the harness rather than asserted by the profile, which is the whole
    point: a domain that computed its own calibration would be marking its own homework,
    and the warrant would verify a number the thing under test supplied.
    """

    bands: tuple[CalibrationBand, ...] = ()

    BANDS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("0.5", "0.7"),
        ("0.7", "0.9"),
        ("0.9", "1.0"),
    )

    @classmethod
    def over(cls, judgements: Sequence[tuple[float, bool]]) -> CalibrationReport:
        """``(stated_confidence, was_correct)`` pairs, bucketed into the shipped bands."""
        bands: list[CalibrationBand] = []
        for low, high in cls.BANDS:
            lower, upper = Decimal(low), Decimal(high)
            inside = [
                correct
                for confidence, correct in judgements
                if lower <= Decimal(str(confidence)) <= upper
            ]
            bands.append(
                CalibrationBand(lower=lower, upper=upper, stated=len(inside), correct=sum(inside))
            )
        return cls(bands=tuple(bands))

    @property
    def overconfident_bands(self) -> tuple[CalibrationBand, ...]:
        return tuple(band for band in self.bands if band.overconfident)

    def render(self) -> str:
        return "\n".join(
            ["CALIBRATION", "  stated              observed   verdict"]
            + [band.render() for band in self.bands]
        )
