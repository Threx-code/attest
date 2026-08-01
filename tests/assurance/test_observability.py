"""Observability: the numbers only the kernel can compute, and the six that page.

`docs/assurance/observability.md`: *"These are not optional instrumentation. Each is
derived from data only the kernel holds."* Nothing computed any of them, so an operator
had no way to answer the four questions the document opens with.

The tests here are about **what a dashboard would hide**. A signal that renders a
plausible number over an empty population, or folds UNKNOWN into failure, or reports a
cross-tenant read at the same level as a slow query, is worse than no signal: it is a
green light somebody trusts.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest

from attest.assurance.builders import AT, Build
from attest.assurance.observability import Incident, Measurement, Severity, Signals
from attest.kernel.attestation import Attestation, CostRecord, EffectRecord
from attest.kernel.effects import EffectState
from attest.kernel.verdicts import Refusal, RefusalReason, Verdict
from attest.kernel.warrants import (
    Severity as FindingSeverity,
)
from attest.kernel.warrants import (
    WarrantKinds,
    WarrantReport,
)

pytestmark = pytest.mark.unit


def warrant(kind: Any, *, satisfied: bool = True, codes: tuple[str, ...] = ()) -> WarrantReport:
    return Build.warrant(
        kind,
        satisfied=satisfied,
        findings=tuple((code, FindingSeverity.ERROR) for code in codes),
    )


def run(
    run_id: str = "run_1",
    *,
    verdict: Verdict = Verdict.ALLOW,
    warrants: dict[Any, WarrantReport] | None = None,
    effects: tuple[EffectRecord, ...] | None = None,
    refusal: Refusal | None = None,
    cost: str | None = None,
    sealed: bool = True,
) -> Attestation:
    """One run, via the shipped builders.

    This file's fixtures used to be hand-written, and they were rejected by the kernel
    four times in four consecutive edits — no reference on a COMMITTED effect, no grant,
    a context naming a different run, UNKNOWN with nothing to be unknown about. Each
    refusal was the invariant working. `attest.assurance.builders` exists because of
    those four, and this file is the first thing it should spare.
    """
    extra: dict[str, Any] = {}
    if refusal is not None:
        extra["refusal"] = refusal
    if cost is not None:
        extra["cost"] = CostRecord(amount=cost, currency="GBP")
    return Build.attestation(
        run_id,
        verdict=verdict,
        warrants=warrants or {WarrantKinds.EPISTEMIC: warrant(WarrantKinds.EPISTEMIC)},
        effects=effects,
        sealed=sealed,
        **extra,
    )


def effect(state: EffectState, *, submitted: datetime | None = None) -> EffectRecord:
    return Build.effect(state, at=submitted or AT)


# ── A rate without its denominator is not a signal ──────────────────────────


def test_a_measurement_carries_the_population_it_was_computed_over() -> None:
    """0% refusal over 40,000 runs is health; over three it is noise; over zero it is
    an outage that a ratio-only dashboard renders as a flat green line."""
    signals = Signals.over([run("run_1"), run("run_2")])
    assert signals.refusal_rate().over == 2
    assert not signals.refusal_rate().meaningful


def test_an_empty_population_does_not_produce_a_plausible_number() -> None:
    """The failure mode this exists to prevent: during an outage the denominator is the
    first thing to collapse, and a bare ratio keeps rendering 0%."""
    signals = Signals.over([])
    assert signals.population == 0
    for measurement in signals.gauges():
        assert measurement.over == 0
        assert not measurement.meaningful


def test_a_large_population_is_reported_as_meaningful() -> None:
    signals = Signals.over([run(f"run_{i}") for i in range(25)])
    assert signals.refusal_rate().meaningful


# ── The verdict mix, all six ────────────────────────────────────────────────


def test_all_six_verdicts_appear_even_at_zero() -> None:
    """UNKNOWN and INCOMPLETE are the states this framework exists to represent honestly.

    A dashboard showing "success rate" folds them into failure and throws away the
    distinction the whole design rests on — so they must be present, and visibly zero,
    rather than absent.
    """
    mix = Signals.over([run()]).verdict_mix()
    assert set(mix) == {v.value for v in Verdict}
    assert mix["unknown"].value == Decimal(0)


def test_the_verdict_mix_counts_what_happened() -> None:
    signals = Signals.over(
        [
            run("a", verdict=Verdict.ALLOW),
            run("b", verdict=Verdict.REFUSE),
            # UNKNOWN is only reachable after an effect was attempted — the kernel
            # refuses a record claiming it with nothing to be unknown about.
            run("c", verdict=Verdict.UNKNOWN, effects=(effect(EffectState.UNKNOWN, submitted=AT),)),
            run("d", verdict=Verdict.UNKNOWN, effects=(effect(EffectState.UNKNOWN, submitted=AT),)),
        ]
    )
    mix = signals.verdict_mix()
    assert mix["unknown"].value == Decimal("50.00")
    assert mix["allow"].value == Decimal("25.00")


def test_refusals_are_broken_down_by_reason() -> None:
    """ "Refusal rate 4%" is a number. "insufficient_authority=38" is a work item."""
    signals = Signals.over(
        [
            run(
                "a",
                verdict=Verdict.REFUSE,
                refusal=Refusal(reason=RefusalReason("budget_exhausted"), detail="over ceiling"),
            ),
            run(
                "b",
                verdict=Verdict.REFUSE,
                refusal=Refusal(reason=RefusalReason("budget_exhausted"), detail="over ceiling"),
            ),
            run(
                "c",
                verdict=Verdict.REFUSE,
                refusal=Refusal(reason=RefusalReason("unsafe_action"), detail="blocked"),
            ),
        ]
    )
    assert signals.refusals_by_reason == {"budget_exhausted": 2, "unsafe_action": 1}
    assert "budget_exhausted=2" in signals.refusal_rate().detail


# ── Warrant satisfaction, by kind ───────────────────────────────────────────


def test_warrant_satisfaction_is_reported_per_kind() -> None:
    """ "Is assurance degrading" is not answerable from an aggregate.

    Epistemic falling while authority holds is a source-system problem; the reverse is a
    governance problem, and one number cannot say which.
    """
    signals = Signals.over(
        [
            run("a", warrants={WarrantKinds.EPISTEMIC: warrant(WarrantKinds.EPISTEMIC)}),
            run(
                "b",
                warrants={WarrantKinds.EPISTEMIC: warrant(WarrantKinds.EPISTEMIC, satisfied=False)},
            ),
        ]
    )
    assert signals.warrant_satisfaction["epistemic"].value == Decimal("50.00")
    assert signals.warrant_satisfaction["epistemic"].over == 2


def test_the_unverifiable_rate_is_the_leading_indicator_the_docs_single_out() -> None:
    """A source system stopped retaining versions.

    Future attestations lose their evidentiary value MONTHS before anyone tries to
    verify one, and every request still returns 200 the whole time — which is why
    conventional APM cannot see it.
    """
    signals = Signals.over(
        [
            run(
                "a",
                warrants={
                    WarrantKinds.EPISTEMIC: warrant(
                        WarrantKinds.EPISTEMIC, satisfied=False, codes=("source_unavailable",)
                    )
                },
            ),
            run("b"),
        ]
    )
    assert signals.unverifiable_rate().value == Decimal("50.00")


# ── The six that page ───────────────────────────────────────────────────────


@pytest.mark.security
def test_a_cross_tenant_finding_pages() -> None:
    """Never a dashboard line. There is no warn setting for this anywhere else either."""
    signals = Signals.over(
        [
            run(
                "leaky",
                warrants={
                    WarrantKinds.BOUNDARY: warrant(
                        WarrantKinds.BOUNDARY, satisfied=False, codes=("tenancy_violation",)
                    )
                },
            )
        ]
    )
    incidents = {i.signal: i for i in signals.incidents}
    assert "cross_tenant_access" in incidents
    assert incidents["cross_tenant_access"].runs == ("leaky",)


@pytest.mark.security
def test_an_unknown_effect_past_its_sla_pages_and_names_the_run() -> None:
    """An unreconciled GBP 500,000 transfer is not a metric on a chart.

    The first thing anybody asks at 3am is "which ones", so the incident carries run ids
    rather than a count.
    """
    signals = Signals.over(
        [run("stuck", effects=(effect(EffectState.UNKNOWN, submitted=AT),))],
        now=AT + timedelta(days=1),
        unknown_effect_sla=timedelta(hours=4),
    )
    incidents = {i.signal: i for i in signals.incidents}
    assert "unknown_effect_age" in incidents
    assert incidents["unknown_effect_age"].runs == ("stuck",)
    assert incidents["unknown_effect_age"].severity is Severity.PAGE


def test_an_unknown_effect_inside_its_sla_does_not_page() -> None:
    """Paging on every in-flight effect is how a page comes to be ignored."""
    signals = Signals.over(
        [run("recent", effects=(effect(EffectState.UNKNOWN, submitted=AT),))],
        now=AT + timedelta(minutes=5),
        unknown_effect_sla=timedelta(hours=4),
    )
    assert not [i for i in signals.incidents if i.signal == "unknown_effect_age"]


def test_no_clock_means_no_age_incident_rather_than_one_from_an_ambient_now() -> None:
    """The age would be right and unreproducible, and this is a page.

    A signal timestamped by the collector cannot be recomputed from the same inputs six
    months later, which is the whole reason these are derived from attestations rather
    than scraped.
    """
    signals = Signals.over([run("stuck", effects=(effect(EffectState.UNKNOWN, submitted=AT),))])
    assert not [i for i in signals.incidents if i.signal == "unknown_effect_age"]
    assert signals.unresolved_effects == 1, "it is still counted, just not aged"


@pytest.mark.security
def test_an_unsealed_attestation_pages() -> None:
    """A record whose event count is unbound cannot detect an omission."""
    signals = Signals.over([run("open", sealed=False)])
    assert "seal_gap" in {i.signal for i in signals.incidents}


@pytest.mark.security
def test_a_committed_effect_under_an_incomplete_record_pages() -> None:
    """The two records disagree: something happened and the account of it did not finish."""
    signals = Signals.over(
        [run("split", verdict=Verdict.INCOMPLETE, effects=(effect(EffectState.COMMITTED),))]
    )
    assert "effect_vs_audit_divergence" in {i.signal for i in signals.incidents}


@pytest.mark.security
def test_outbound_leakage_pages() -> None:
    signals = Signals.over(
        [
            run(
                "leaked",
                warrants={
                    WarrantKinds.BOUNDARY: warrant(
                        WarrantKinds.BOUNDARY, satisfied=False, codes=("outbound_leakage",)
                    )
                },
            )
        ]
    )
    assert "outbound_leakage" in {i.signal for i in signals.incidents}


def test_a_healthy_population_pages_nobody() -> None:
    """A monitor that always fires is a monitor nobody reads."""
    signals = Signals.over(
        [run(f"ok_{i}", effects=(effect(EffectState.COMMITTED),)) for i in range(30)],
        now=AT + timedelta(days=1),
    )
    assert signals.incidents == ()


# ── Cost ────────────────────────────────────────────────────────────────────


def test_cost_per_decision_is_derived_not_estimated() -> None:
    signals = Signals.over([run("a", cost="0.40"), run("b", cost="0.60")])
    assert signals.total_cost == Decimal("1.00")
    assert signals.cost_per_decision().value == Decimal("0.5000")


def test_an_unparseable_cost_does_not_lose_the_rest_of_the_batch() -> None:
    """A reporting problem in one run must not zero the whole population's cost."""
    broken = run("bad")
    object.__setattr__(broken, "cost", CostRecord(amount="not-a-number", currency="GBP"))
    signals = Signals.over([broken, run("good", cost="1.00")])
    assert signals.total_cost == Decimal("1.00")


# ── Honesty about what is missing ───────────────────────────────────────────


def test_the_signals_it_cannot_derive_are_named_not_dropped() -> None:
    """A full-looking dashboard is read as a complete one.

    Three of the missing signals are the *leading* indicators — the ones that move
    before the failure — so a host that assumes the list is covered loses exactly the
    early warning the document is about.
    """
    assert Signals.NOT_DERIVABLE
    rendered = Signals.over([run()]).render()
    assert "NOT DERIVED FROM ATTESTATIONS" in rendered
    for missing in Signals.NOT_DERIVABLE:
        assert missing in rendered


def test_the_render_names_the_incidents() -> None:
    signals = Signals.over([run("open", sealed=False)])
    assert "PAGE seal_gap" in signals.render()


def test_gauges_are_ready_to_push_to_a_metrics_system() -> None:
    """The framework computes; the host emits. No metrics client here, ever."""
    gauges = Signals.over([run()]).gauges()
    assert all(isinstance(g, Measurement) for g in gauges)
    assert all(
        g.name.startswith(
            ("verdict.", "warrant.", "refusal.", "evidence.", "attestation.", "cost.")
        )
        for g in gauges
    )


def test_an_incident_renders_with_its_subjects() -> None:
    incident = Incident(signal="x", detail="y", runs=("a", "b"))
    assert "a, b" in incident.render()
