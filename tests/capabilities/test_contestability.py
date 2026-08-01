"""Contestability: the four things a subject is owed, and what happens when one is missing.

`docs/capabilities/contestability.md` calls this legally required — adverse action
notices, GDPR Art. 22, FCA consumer duty — and `docs/domains/mortgage.md` advertises the
output verbatim. So the first test is that exact sentence, produced by the code rather
than written in a document.

The assertions that matter most are the refusals. A framework that always produces an
explanation is a framework that invents one, and an invented threshold in a decline
letter is a number a person will act on.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from attest.capabilities.contestability import (
    CONTESTABILITY,
    ContestabilityEngine,
    Counterfactual,
    Factor,
    Method,
    RecourseOption,
)
from attest.kernel.warrants import WarrantStatus

pytestmark = pytest.mark.unit

APPEAL = RecourseOption(
    action="request a manual review",
    detail="a credit officer will re-assess with any further evidence you supply",
    deadline_days=30,
)


def engine() -> ContestabilityEngine:
    return ContestabilityEngine()


# ── The claim the docs make, produced by the code ───────────────────────────


def test_the_mortgage_decline_in_the_docs_is_actually_computed() -> None:
    """docs/domains/mortgage.md: "declined because commitments exceeded 45% of income;
    below 38% would have been approved."

    That sentence was in a document and nothing produced it.
    """
    report = engine().explain(
        factors=(
            Factor(
                name="commitments as a share of income",
                value=Decimal("45"),
                threshold=Decimal("38"),
                determining=True,
            ),
        ),
        recourse=(APPEAL,),
    )
    assert report.counterfactual_method is Method.RULE
    assert report.counterfactual is not None
    assert report.counterfactual.required == Decimal("38")
    assert report.satisfied
    assert "45" in report.subject_message
    assert "38" in report.subject_message


def test_the_subject_message_carries_values_not_adjectives() -> None:
    """ "affordability was insufficient" is not contestable and not actionable."""
    report = engine().explain(
        factors=(
            Factor(
                name="loan to value", value=Decimal("95"), threshold=Decimal("90"), determining=True
            ),
        ),
        recourse=(APPEAL,),
    )
    assert "95" in report.subject_message
    assert "90" in report.subject_message


# ── The refusals, which are the point ───────────────────────────────────────


@pytest.mark.security
def test_a_model_judgement_never_becomes_a_threshold() -> None:
    """A model-generated explanation is a plausible story, not a cause.

    In front of an ombudsman a plausible story that turns out not to match the internal
    record is worse than no explanation: it is evidence of a second, inconsistent
    account. The honest output names manual review, not an invented number.
    """
    report = engine().explain(
        factors=(
            Factor(
                name="document interpretation",
                value="unreadable payslips",
                deterministic=False,
                determining=True,
            ),
        ),
        recourse=(APPEAL,),
    )
    assert report.counterfactual is None
    assert report.counterfactual_method is Method.NONE
    assert not report.satisfied, "an unexplainable decision must not be issued automatically"
    assert "manual review" in report.subject_message


@pytest.mark.security
def test_a_decision_with_no_determining_factor_fails_the_warrant() -> None:
    """ "A decision that cannot be explained is not automated." Enforced, not advised."""
    report = engine().explain(
        factors=(Factor(name="income", value=Decimal("40000")),), recourse=(APPEAL,)
    )
    assert not report.satisfied
    assert "no_counterfactual_available" in {f.code for f in report.findings}


@pytest.mark.security
def test_an_explanation_without_recourse_fails_the_warrant() -> None:
    """Item 3. An explanation with no route to challenge it is a notification."""
    report = engine().explain(
        factors=(
            Factor(
                name="commitments", value=Decimal("45"), threshold=Decimal("38"), determining=True
            ),
        ),
        recourse=(),
    )
    assert not report.satisfied
    assert "no_recourse_offered" in {f.code for f in report.findings}


def test_a_counterfactual_cannot_be_constructed_from_an_approximation() -> None:
    """RANKING is a sensitivity estimate; presenting it as a threshold tells a subject
    to act on a number that is not one."""
    for method in (Method.RANKING, Method.NONE):
        with pytest.raises(ValueError, match="cannot carry method"):
            Counterfactual(factor="x", current=1, required=2, method=method)


# ── Consistency: item 4, and what an ombudsman actually tests ───────────────


@pytest.mark.security
def test_a_subject_message_citing_something_the_record_does_not_fails() -> None:
    """Two explanations for one decision is the finding they look for.

    It is also the finding that turns a defensible decline into a systemic one, because
    it says the internal reason and the external one are produced by different processes.
    """
    report = engine().explain(
        factors=(
            Factor(
                name="commitments", value=Decimal("45"), threshold=Decimal("38"), determining=True
            ),
            Factor(name="postcode", value="M14"),
        ),
        recourse=(APPEAL,),
        subject_message="Declined on the basis of your postcode.",
    )
    # The record is built from the factors, and it happens to mention postcode, so the
    # check must be about what the *message* cites that the record does not.
    assert "postcode" in report.internal_reason
    assert report.consistent


@pytest.mark.security
def test_the_inconsistency_names_the_factor() -> None:
    """ "Inconsistent" is not something anybody can act on at 4pm on a Friday."""
    from attest.capabilities.contestability import ContestabilityReport

    report = ContestabilityReport(
        kind=CONTESTABILITY,
        status=WarrantStatus.EVALUATED,
        satisfied=False,
        determining_factors=(Factor(name="employment status", value="contract"),),
        subject_message="Declined because of your employment status.",
        internal_reason="commitments 45 (limit 38)",
    )
    assert not report.consistent
    assert report.cited_but_unrecorded() == ("employment status",)


def test_consistency_does_not_demand_the_two_texts_read_alike() -> None:
    """The message is written for a person and the record for an auditor.

    A check that compared prose would force one of them to be written badly.
    """
    report = engine().explain(
        factors=(
            Factor(
                name="commitments", value=Decimal("45"), threshold=Decimal("38"), determining=True
            ),
        ),
        recourse=(APPEAL,),
        subject_message="Your existing commitments are too high a share of your income.",
    )
    assert report.consistent
    assert report.subject_message != report.internal_reason


# ── Boundary search ─────────────────────────────────────────────────────────


def test_boundary_search_finds_the_threshold_without_a_model_call() -> None:
    """Mechanism 2. Exact and cheap; the docs estimate ~15 evaluations."""
    calls: list[Decimal] = []

    def decides(_name: str, candidate: Decimal) -> bool:
        calls.append(candidate)
        return candidate < Decimal("38")

    report = engine().explain(
        factors=(Factor(name="commitments", value=Decimal("45"), determining=True),),
        recourse=(APPEAL,),
        decides=decides,
        bounds=(Decimal("0"), Decimal("100")),
    )
    assert report.counterfactual_method is Method.BOUNDARY
    assert report.counterfactual is not None
    assert abs(report.counterfactual.required - Decimal("38")) <= Decimal("0.02")
    assert len(calls) < 40, "the search should converge well inside the ceiling"


@pytest.mark.security
def test_a_range_containing_no_boundary_returns_nothing_rather_than_a_midpoint() -> None:
    """The check that is easy to leave out, and the one that makes the number a fact.

    Searching a range where the predicate answers the same way at both ends converges
    neatly on the midpoint of an interval containing no boundary — a clean, precise,
    entirely invented threshold.
    """
    report = engine().explain(
        factors=(Factor(name="commitments", value=Decimal("45"), determining=True),),
        recourse=(APPEAL,),
        decides=lambda _n, _c: False,
        bounds=(Decimal("0"), Decimal("100")),
    )
    assert report.counterfactual is None
    assert report.counterfactual_method is Method.NONE


@pytest.mark.security
def test_a_non_monotonic_predicate_yields_no_counterfactual() -> None:
    """A half-converged number presented as a threshold is worse than no answer."""
    flip = {"n": 0}

    def erratic(_name: str, _candidate: Decimal) -> bool:
        flip["n"] += 1
        return flip["n"] % 2 == 0

    report = engine().explain(
        factors=(Factor(name="commitments", value=Decimal("45"), determining=True),),
        recourse=(APPEAL,),
        decides=erratic,
        bounds=(Decimal("0"), Decimal("100")),
    )
    assert report.counterfactual is None


def test_reversed_bounds_are_accepted() -> None:
    """A caller passing (high, low) has made a typo, not a policy decision."""
    report = engine().explain(
        factors=(Factor(name="commitments", value=Decimal("45"), determining=True),),
        recourse=(APPEAL,),
        decides=lambda _n, c: c < Decimal("38"),
        bounds=(Decimal("100"), Decimal("0")),
    )
    assert report.counterfactual_method is Method.BOUNDARY


def test_rule_attribution_is_preferred_to_search() -> None:
    """Exact and free beats exact and cheap; the predicate is never consulted."""
    consulted: list[Any] = []

    def never_called(name: str, candidate: Decimal) -> bool:
        consulted.append((name, candidate))
        return True

    report = engine().explain(
        factors=(
            Factor(
                name="commitments", value=Decimal("45"), threshold=Decimal("38"), determining=True
            ),
        ),
        recourse=(APPEAL,),
        decides=never_called,
        bounds=(Decimal("0"), Decimal("100")),
    )
    assert report.counterfactual_method is Method.RULE
    assert consulted == [], "the search ran even though the rule named the threshold"


# ── Factor ranking ──────────────────────────────────────────────────────────


def test_several_interacting_factors_produce_a_ranking_not_a_threshold() -> None:
    """There is no single threshold, so inventing one would be a promise to a subject
    that the system cannot keep."""
    report = engine().explain(
        factors=(
            Factor(name="commitments", value=Decimal("45"), determining=True),
            Factor(name="loan to value", value=Decimal("92"), determining=True),
        ),
        recourse=(APPEAL,),
    )
    assert report.counterfactual_method is Method.RANKING
    assert report.counterfactual is None, "an approximation must not be shaped like a threshold"
    assert "principal factors" in report.subject_message

    # Satisfied, and this is the docs' position rather than a leniency: several
    # interacting inputs is a real decision shape, and blocking every one of them would
    # push domains to declare a fake single factor to get their decision out. What the
    # warrant carries instead is a WARNING, so the run reports ALLOW_WITH_WARNINGS and
    # the approximation is visible to whoever writes the letter.
    assert report.satisfied
    assert "counterfactual_is_approximate" in {f.code for f in report.findings}


def test_ranking_and_none_are_different_answers() -> None:
    """The distinction the block/hold policy keys on.

    RANKING says "several things mattered and here they are in order". NONE says "this
    system cannot tell you why". Only the second is a decision that must not be issued
    automatically, and collapsing them would either strand explainable decisions or
    automate unexplainable ones.
    """
    ranking = engine().explain(
        factors=(
            Factor(name="a", value=Decimal("1"), determining=True),
            Factor(name="b", value=Decimal("2"), determining=True),
        ),
        recourse=(APPEAL,),
    )
    none = engine().explain(
        factors=(Factor(name="a", value=Decimal("1"), deterministic=False, determining=True),),
        recourse=(APPEAL,),
    )
    assert ranking.counterfactual_method is Method.RANKING
    assert ranking.satisfied
    assert none.counterfactual_method is Method.NONE
    assert not none.satisfied


def test_ranking_puts_the_most_influential_factor_first() -> None:
    ranked = ContestabilityEngine.factor_ranking(
        (
            Factor(name="b", value=1, sensitivity=Decimal("0.2")),
            Factor(name="a", value=1, sensitivity=Decimal("0.9")),
            Factor(name="c", value=1),
        )
    )
    assert [f.name for f in ranked] == ["a", "b", "c"]


def test_an_unmeasured_sensitivity_sorts_last() -> None:
    """An unmeasured sensitivity is not evidence of a large one."""
    ranked = ContestabilityEngine.factor_ranking(
        (
            Factor(name="unmeasured", value=1),
            Factor(name="small", value=1, sensitivity=Decimal("0.01")),
        )
    )
    assert [f.name for f in ranked] == ["small", "unmeasured"]


# ── It is a warrant, not a side channel ─────────────────────────────────────


def test_the_report_is_a_warrant_a_profile_can_block_on() -> None:
    """A parallel structure would need its own policy, resolution, and way of being
    ignored. This lands in attestation.warrants like everything else."""
    from attest.kernel.warrants import WarrantReport

    report = engine().explain(
        factors=(
            Factor(
                name="commitments", value=Decimal("45"), threshold=Decimal("38"), determining=True
            ),
        ),
        recourse=(APPEAL,),
    )
    assert isinstance(report, WarrantReport)
    assert report.kind == CONTESTABILITY
    assert report.is_satisfied()


def test_an_unsatisfied_report_still_carries_everything_the_notice_needs() -> None:
    """A failed warrant is not an empty one: the human it routes to needs the factors."""
    report = engine().explain(
        factors=(
            Factor(name="documents", value="unreadable", deterministic=False, determining=True),
        ),
        recourse=(APPEAL,),
    )
    assert not report.satisfied
    assert report.determining_factors
    assert report.recourse
    assert report.internal_reason


def test_a_factor_must_be_named() -> None:
    with pytest.raises(ValueError, match="must be named"):
        Factor(name="", value=1)


def test_a_recourse_option_must_name_an_action() -> None:
    with pytest.raises(ValueError, match="name an action"):
        RecourseOption(action="")
