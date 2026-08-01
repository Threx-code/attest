"""Evaluation: the third leg, and the two ways a golden set stops meaning anything.

`docs/assurance/eval.md` opens with three checks — conformance, red team, evaluation —
and only the first two shipped. Conformance proves a domain is well-formed and the
corpus proves it resists attack; neither says the answers are right.

The tests that matter here are about the two documented failure modes, because both are
things a suite does to *itself*:

- a case that asserts prose fails on every harmless rewording and is disabled within a
  month, at which point it asserts nothing;
- refusal rate is the easiest metric in the document to optimise dishonestly, and the
  optimisation looks like an improvement on every chart.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from attest.assurance.builders import Build
from attest.assurance.eval import (
    CalibrationReport,
    Expectation,
    GoldenCase,
    GoldenSet,
    Metrics,
    Outcome,
    RegressionGate,
)
from attest.kernel.effects import EffectState
from attest.kernel.verdicts import Refusal, RefusalReason, Verdict
from attest.kernel.warrants import Severity, WarrantKinds

pytestmark = pytest.mark.unit


class Engine:
    """Returns a prepared attestation. The eval harness is what is under test."""

    def __init__(self, attestation: Any = None, *, raises: Exception | None = None) -> None:
        self._attestation = attestation or Build.attestation()
        self._raises = raises

    def execute(self, request: Any, **_: Any) -> Any:
        if self._raises is not None:
            raise self._raises
        return type("Result", (), {"attestation": self._attestation})()


def case(id: str = "c1", **expect: Any) -> GoldenCase:
    """A case that always expects *something*.

    `GoldenCase` refuses one that expects nothing, and this helper met that on its first
    use — which is the check working on the file that tests it.
    """
    return GoldenCase(
        id=id,
        build=lambda: object(),
        expect=Expectation(**expect) if expect else Expectation(verdict=Verdict.ALLOW),
    )


def run_set(cases: tuple[GoldenCase, ...], engine: Engine) -> tuple[Outcome, ...]:
    return GoldenSet(cases).run(engine=engine, binding=Build.binding())


# ── A case that cannot fail is worse than absent ────────────────────────────


def test_a_case_that_expects_nothing_is_refused() -> None:
    """The same defect the red-team corpus had: a manifest of titles.

    It counts toward coverage and asserts nothing, which is strictly worse than not
    being there — a set of twelve cases where four expect nothing reports twelve.
    """
    with pytest.raises(ValueError, match="cannot fail"):
        GoldenCase(id="empty", build=lambda: object())


def test_a_case_needs_an_id() -> None:
    with pytest.raises(ValueError, match="has to name something"):
        GoldenCase(id="", build=lambda: object(), expect=Expectation(verdict=Verdict.ALLOW))


def test_two_cases_cannot_share_an_id() -> None:
    """A failure names an id; two cases behind one name makes the report ambiguous."""
    with pytest.raises(ValueError, match="share the id"):
        GoldenSet((case("dup"), case("dup")))


# ── Assertions are on structure ─────────────────────────────────────────────


def test_a_matching_verdict_passes() -> None:
    outcomes = run_set((case(verdict=Verdict.ALLOW),), Engine())
    assert outcomes[0].passed


def test_a_differing_verdict_is_reported_with_both_sides() -> None:
    """A diff that says "failed" makes the reader re-run it to find out what changed."""
    outcomes = run_set((case(verdict=Verdict.REFUSE),), Engine())
    assert not outcomes[0].passed
    assert "expected refuse, got allow" in outcomes[0].differences[0]


def test_every_difference_is_reported_not_only_the_first() -> None:
    """A golden-set failure is read once, by somebody deciding whether the change was
    intended. One that reports a single difference per run turns that into several."""
    outcomes = run_set(
        (
            case(
                verdict=Verdict.REFUSE,
                answer_contains=("nonsense",),
                max_cost=Decimal("0.01"),
            ),
        ),
        Engine(),
    )
    assert len(outcomes[0].differences) == 3


@pytest.mark.security
def test_an_unevaluated_warrant_does_not_count_as_satisfied() -> None:
    """A warrant that was never evaluated reads as a satisfied one to anything that only
    checks the key is present — which is the confusion `is_satisfied` exists to prevent.
    """
    outcomes = run_set((case(warrants_satisfied=frozenset({WarrantKinds.AUTHORITY})),), Engine())
    assert not outcomes[0].passed
    assert "was not evaluated at all" in outcomes[0].differences[0]


def test_a_warrant_expected_to_fail_that_passes_is_a_difference() -> None:
    """The half a suite usually forgets.

    A case about a claim with insufficient evidence tests nothing unless it asserts the
    epistemic warrant *failed* — otherwise a REFUSE for an unrelated reason passes.
    """
    outcomes = run_set((case(warrants_unsatisfied=frozenset({WarrantKinds.EPISTEMIC})),), Engine())
    assert not outcomes[0].passed
    assert "expected unsatisfied, it passed" in outcomes[0].differences[0]


def test_a_refusal_reason_is_assertable_because_it_is_typed() -> None:
    refused = Build.attestation(
        verdict=Verdict.REFUSE,
        refusal=Refusal(reason=RefusalReason("budget_exhausted"), detail="over ceiling"),
    )
    assert run_set((case(refusal_reason="budget_exhausted"),), Engine(refused))[0].passed
    assert not run_set((case(refusal_reason="unsafe_action"),), Engine(refused))[0].passed


def test_an_obligation_is_asserted_by_the_finding_that_records_it() -> None:
    held = Build.attestation(
        verdict=Verdict.HOLD_FOR_APPROVAL,
        warrants={
            WarrantKinds.AUTHORITY: Build.warrant(
                WarrantKinds.AUTHORITY,
                satisfied=False,
                findings=(("approval:claims_manager", Severity.WARNING),),
            )
        },
    )
    outcomes = run_set(
        (case(obligations_pending=frozenset({"approval:claims_manager"})),), Engine(held)
    )
    assert outcomes[0].passed


def test_a_cost_ceiling_is_enforced() -> None:
    """Regressions in spend are regressions."""
    assert run_set((case(max_cost=Decimal("1.00")),), Engine())[0].passed
    assert not run_set((case(max_cost=Decimal("0.01")),), Engine())[0].passed


def test_there_is_no_way_to_assert_exact_answer_text() -> None:
    """The document's own warning, enforced by the type rather than by a convention.

    A suite that pins prose fails on every harmless rewording and gets disabled — at
    which point it asserts nothing at all, which is the outcome the whole file is about.
    """
    import dataclasses

    fields = {f.name for f in dataclasses.fields(Expectation)}
    assert "answer_contains" in fields
    assert "answer_equals" not in fields
    assert "answer" not in fields


# ── A raising case is a failure, not an aborted suite ───────────────────────


def test_a_case_that_raises_fails_and_the_rest_still_run() -> None:
    """A set that aborts on the first exception tells you about one case, and the run
    that produced it took as long as all of them."""
    outcomes = GoldenSet((case("a"), case("b"))).run(
        engine=Engine(raises=RuntimeError("the retriever is down")), binding=Build.binding()
    )
    assert len(outcomes) == 2
    assert all(not o.passed for o in outcomes)
    assert "RuntimeError" in outcomes[0].differences[0]


# ── The gate ────────────────────────────────────────────────────────────────


def test_any_difference_blocks_the_merge() -> None:
    assert RegressionGate.blocks_merge(run_set((case(verdict=Verdict.REFUSE),), Engine()))
    assert not RegressionGate.blocks_merge(run_set((case(verdict=Verdict.ALLOW),), Engine()))


def test_the_report_says_a_difference_is_not_automatically_a_defect() -> None:
    """A golden set records what the system used to do, and changing that is often the
    point of a change. What must not happen is the change going in unnoticed."""
    report = RegressionGate.report(run_set((case(verdict=Verdict.REFUSE),), Engine()))
    assert "0/1 matched" in report
    assert "Decide whether this change was intended" in report


# ── Metrics, and the one that games itself ──────────────────────────────────


def test_groundedness_and_refusal_rate_are_computed_together() -> None:
    outcomes = (
        *run_set((case("a", verdict=Verdict.ALLOW),), Engine()),
        *run_set(
            (case("b", verdict=Verdict.REFUSE),),
            Engine(
                Build.attestation(
                    verdict=Verdict.REFUSE,
                    warrants={WarrantKinds.EPISTEMIC: Build.warrant(satisfied=False)},
                )
            ),
        ),
    )
    metrics = Metrics.over(outcomes)
    assert metrics.runs == 2
    assert metrics.groundedness == Decimal("50.00")
    assert metrics.refusal_rate == Decimal("50.00")


@pytest.mark.security
def test_refusing_more_while_groundedness_holds_is_reported_as_gaming() -> None:
    """ "A system that refuses everything scores perfectly on groundedness."

    It is the easiest metric in the document to optimise and the easiest to optimise
    dishonestly, and the optimisation looks like an improvement on every chart.
    """
    before = Metrics(runs=100, groundedness=Decimal("90"), refusal_rate=Decimal("5"))
    after = Metrics(runs=100, groundedness=Decimal("95"), refusal_rate=Decimal("40"))
    assert after.gamed(against=before)


def test_a_genuine_improvement_is_not_reported_as_gaming() -> None:
    """The check must not fire on getting better, or it gets ignored."""
    before = Metrics(runs=100, groundedness=Decimal("80"), refusal_rate=Decimal("20"))
    after = Metrics(runs=100, groundedness=Decimal("92"), refusal_rate=Decimal("12"))
    assert not after.gamed(against=before)
    assert not after.gamed()


def test_percentiles_report_a_value_that_actually_occurred() -> None:
    """An interpolated p95 of a cost distribution is a price nobody was charged, and
    these numbers end up in a capacity conversation."""
    costs = [Decimal(n) for n in range(1, 101)]
    assert Metrics.percentile(costs, 95) in costs
    assert Metrics.percentile(costs, 50) in costs
    assert Metrics.percentile([], 95) == Decimal(0)


def test_an_unparseable_cost_does_not_lose_the_batch() -> None:
    from attest.kernel.attestation import CostRecord

    broken = Build.attestation(cost=CostRecord(amount="not-a-number", currency="GBP"))
    assert Metrics.spent(broken) == Decimal(0)


def test_metrics_over_nothing_is_zero_runs_not_a_crash() -> None:
    assert Metrics.over(()).runs == 0


# ── Calibration ─────────────────────────────────────────────────────────────


@pytest.mark.security
def test_a_band_that_is_right_less_often_than_it_claims_is_overconfident() -> None:
    """The document's own example: says 0.6, right 31% of the time.

    More dangerous than a refusal, because a human downstream will trust the number.
    """
    judgements = [(0.6, i < 31) for i in range(100)]
    report = CalibrationReport.over(judgements)
    band = next(b for b in report.bands if b.lower == Decimal("0.5"))
    assert band.overconfident
    assert "OVERCONFIDENT" in band.render()


def test_a_well_calibrated_band_is_not_flagged() -> None:
    judgements = [(0.8, i < 82) for i in range(100)]
    report = CalibrationReport.over(judgements)
    assert not report.overconfident_bands


def test_underconfidence_is_not_flagged() -> None:
    """Not symmetric with overconfidence, deliberately.

    A system that says 0.6 and is right 90% of the time wastes review capacity, which
    costs money — where the other produces a wrong decision somebody relied on.
    """
    judgements = [(0.6, True) for _ in range(50)]
    assert not CalibrationReport.over(judgements).overconfident_bands


def test_an_empty_band_is_not_overconfident() -> None:
    """Zero of zero correct must not read as 0% accuracy."""
    report = CalibrationReport.over([])
    assert not report.overconfident_bands
    assert all(band.stated == 0 for band in report.bands)


def test_the_calibration_report_renders_every_band() -> None:
    report = CalibrationReport.over([(0.95, True)])
    rendered = report.render()
    assert "CALIBRATION" in rendered
    assert rendered.count("well calibrated") + rendered.count("OVERCONFIDENT") == len(report.bands)


# ── The framework ships the harness, not the cases ──────────────────────────


def test_the_shipped_golden_set_is_empty() -> None:
    """Golden sets live in the domain package.

    A framework shipping medical golden cases would be shipping medical knowledge, which
    the thesis rules out. This is the one place where empty is the correct answer, and it
    is asserted so nobody helpfully fills it in.
    """
    assert len(GoldenSet()) == 0


def test_an_effect_bearing_run_is_evaluable_like_any_other() -> None:
    """The states the framework exists for must be as easy to assert on as ALLOW."""
    unknown = Build.attestation(
        verdict=Verdict.UNKNOWN, effects=(Build.effect(EffectState.UNKNOWN),)
    )
    assert run_set((case(verdict=Verdict.UNKNOWN),), Engine(unknown))[0].passed
