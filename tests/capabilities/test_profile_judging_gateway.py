"""Profiles, judge independence, provider routing, approvals and reconciliation."""

from __future__ import annotations

from datetime import date, datetime, timedelta
from types import MappingProxyType

import pytest

from attest.capabilities.approvals import ApprovalQueue, ControlItem, ReviewSignals
from attest.capabilities.authority import CapabilityCheck, ObligationSet
from attest.capabilities.gateway import ProviderRouter, ProviderSpec, ResidencyRefused
from attest.capabilities.judging import EntailmentPolicy, JudgePanel, JudgeVerdict
from attest.capabilities.profile import (
    BaseProfile,
    ConflictClass,
    GenericProfile,
    ProfileComposer,
)
from attest.capabilities.reconciliation import (
    ReconciliationItem,
    ReconciliationOutcome,
    ReconciliationSweep,
)
from attest.kernel.actions import Action
from attest.kernel.attestation import EffectRecord
from attest.kernel.authority import ApprovalRecord
from attest.kernel.config import AssuranceTier
from attest.kernel.context import ExecutionContext
from attest.kernel.effects import EffectState
from attest.kernel.errors import ConfigurationError
from attest.kernel.evidence import AuthorityLevel, Evidence, ValidityWindow
from attest.kernel.identifiers import ActorId, ApprovalId, GrantId, TenantId
from attest.kernel.warrants import CORE_WARRANTS, WarrantKind, WarrantPolicy
from tests.capabilities.conftest import AT, make_evidence

pytestmark = pytest.mark.unit


# ── Profiles fail closed ─────────────────────────────────────────────────────


@pytest.mark.security
def test_the_base_profile_never_returns_an_empty_obligation_set(
    action: Action, context: ExecutionContext
) -> None:
    # The fail-open default the conformance suite exists to catch: add a tool next
    # year and it ships with no gates at all.
    assert len(BaseProfile().obligations_for(action, context)) >= 1


@pytest.mark.security
def test_the_base_profile_blocks_on_an_unconsidered_warrant() -> None:
    # A profile that has not thought about a warrant gets the strictest treatment.
    assert BaseProfile().warrant_policy(WarrantKind("calibration")) is WarrantPolicy.BLOCK


@pytest.mark.security
def test_the_base_profile_requires_authoritative_sources() -> None:
    assert BaseProfile().required_authority("any") is AuthorityLevel.AUTHORITATIVE


def test_the_base_profile_ships_the_four_core_warrants() -> None:
    assert BaseProfile().warrant_kinds() >= CORE_WARRANTS


def test_a_domain_adds_warrants_with_two_overrides() -> None:
    # The minimum viable profile, and the openness claim in executable form.
    class FoodSafety(BaseProfile):
        name = "food_safety"
        version = "1.0.0"
        extra_warrants = frozenset({WarrantKind("temporal_validity")})

    profile = FoodSafety()
    assert WarrantKind("temporal_validity") in profile.warrant_kinds()
    assert profile.warrant_kinds() >= CORE_WARRANTS


def test_the_generic_profile_is_deliberately_weaker() -> None:
    # Low-stakes work must not be taxed by machinery it does not need, or the
    # framework becomes a second stack.
    assert GenericProfile().warrant_policy(WarrantKind("x")) is WarrantPolicy.WARN


# ── Composition classifies rather than silently picking ──────────────────────


def test_composing_one_profile_returns_it_unchanged() -> None:
    profile = GenericProfile()
    composite, conflicts = ProfileComposer().compose(profile)
    assert composite is profile
    assert conflicts == ()


def test_composition_takes_the_stricter_policy_and_records_the_conflict() -> None:
    class Strict(BaseProfile):
        name, version = "strict", "1.0.0"
        default_warrant_policy = WarrantPolicy.BLOCK

    class Lax(BaseProfile):
        name, version = "lax", "1.0.0"
        default_warrant_policy = WarrantPolicy.WARN

    composite, conflicts = ProfileComposer().compose(Strict(), Lax())
    assert composite.warrant_policy(WarrantKind("epistemic")) is WarrantPolicy.BLOCK
    assert conflicts
    assert conflicts[0].classification is ConflictClass.STRICTER


@pytest.mark.security
def test_a_non_orderable_disagreement_refuses_to_compose() -> None:
    """The conflict class the composer exists for, and could not previously construct.

    Retention of 30 days versus 90 has no stricter side: minimising exposure says 30,
    evidentiary obligation says 90. Merging them silently picks one and records the
    result as though it were policy.
    """

    class Minimising(BaseProfile):
        name, version = "minimising", "1.0.0"
        dimensions = MappingProxyType({"retention_days": "30"})

    class Evidentiary(BaseProfile):
        name, version = "evidentiary", "1.0.0"
        dimensions = MappingProxyType({"retention_days": "90"})

    with pytest.raises(ConfigurationError, match="contradictory"):
        ProfileComposer().compose(Minimising(), Evidentiary())


@pytest.mark.security
def test_notification_before_versus_after_is_contradictory() -> None:
    """The other example the design names: genuinely not orderable in either direction."""

    class Before(BaseProfile):
        name, version = "before", "1.0.0"
        dimensions = MappingProxyType({"notification": "before"})

    class After(BaseProfile):
        name, version = "after", "1.0.0"
        dimensions = MappingProxyType({"notification": "after"})

    with pytest.raises(ConfigurationError) as raised:
        ProfileComposer().compose(Before(), After())
    assert "no scalar ordering" in str(raised.value)


def test_a_registered_resolver_makes_the_conflict_conditional() -> None:
    """Someone with the authority to decide has decided. That is not a silent pick."""

    class Minimising(BaseProfile):
        name, version = "minimising", "1.0.0"
        dimensions = MappingProxyType({"retention_days": "30"})

    class Evidentiary(BaseProfile):
        name, version = "evidentiary", "1.0.0"
        dimensions = MappingProxyType({"retention_days": "90"})

    composer = ProfileComposer({"retention_days": "90"})
    composite, conflicts = composer.compose(Minimising(), Evidentiary())
    assert [c.classification for c in conflicts] == [ConflictClass.CONDITIONAL]
    assert composite.name == "minimising+evidentiary"


def test_agreeing_dimensions_are_not_a_conflict() -> None:
    """Absence is not permission, and agreement is not disagreement."""

    class A(BaseProfile):
        name, version = "a", "1.0.0"
        dimensions = MappingProxyType({"retention_days": "30"})

    class B(BaseProfile):
        name, version = "b", "1.0.0"

    _, conflicts = ProfileComposer().compose(A(), B())
    assert not [c for c in conflicts if c.classification is ConflictClass.CONTRADICTORY]


@pytest.mark.security
def test_composed_validity_is_the_intersection_not_the_first_profiles_answer() -> None:
    """Taking profiles[0] made argument order decide whether stale evidence passed.

    Both windows must hold for the composite to hold, so the intersection is the only
    answer that is not a choice.
    """

    class Ninety(BaseProfile):
        name, version = "ninety", "1.0.0"

        def validity(self, evidence: Evidence, at: date) -> ValidityWindow:
            return ValidityWindow(effective_to=date(2026, 4, 1))

    class Thirty(BaseProfile):
        name, version = "thirty", "1.0.0"

        def validity(self, evidence: Evidence, at: date) -> ValidityWindow:
            return ValidityWindow(effective_to=date(2026, 2, 1))

    evidence = make_evidence()
    lax_first, _ = ProfileComposer().compose(Ninety(), Thirty())
    strict_first, _ = ProfileComposer().compose(Thirty(), Ninety())
    for composite in (lax_first, strict_first):
        window = composite.validity(evidence, date(2026, 1, 1))
        assert window.effective_to == date(2026, 2, 1)
        assert not window.covers(date(2026, 3, 1)), (
            "evidence stale under one composed profile was accepted because the other "
            "was listed first"
        )


def test_composition_unions_obligations(action: Action, context: ExecutionContext) -> None:
    class A(BaseProfile):
        name, version = "a", "1.0.0"

        def obligations_for(self, action: Action, context: ExecutionContext) -> ObligationSet:
            return ObligationSet((CapabilityCheck("a"),))

    class B(BaseProfile):
        name, version = "b", "1.0.0"

        def obligations_for(self, action: Action, context: ExecutionContext) -> ObligationSet:
            return ObligationSet((CapabilityCheck("b"),))

    composite, _ = ProfileComposer().compose(A(), B())
    assert len(composite.obligations_for(action, context)) == 2


def test_composition_takes_the_highest_assurance_tier() -> None:
    class Thin(BaseProfile):
        name, version, tier = "thin", "1.0.0", AssuranceTier.THIN

    class Full(BaseProfile):
        name, version, tier = "full", "1.0.0", AssuranceTier.FULL

    composite, _ = ProfileComposer().compose(Thin(), Full())
    assert composite.assurance_tier() is AssuranceTier.FULL


def test_composing_nothing_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError, match="at least one"):
        ProfileComposer().compose()


# ── Judge independence ───────────────────────────────────────────────────────


@pytest.mark.security
def test_a_same_family_judge_is_refused() -> None:
    # Sampling the same model twice measures consistency, not correctness.
    panel = JudgePanel(generator_family="claude")
    with pytest.raises(ConfigurationError, match="measures consistency"):
        panel.assert_independent(["claude"])


@pytest.mark.security
def test_the_check_is_on_the_family_not_the_provider() -> None:
    # Groq, Bedrock and Vertex all serve Llama. A provider check would accept a
    # Llama judge for a Llama generator. ADR 0041.
    panel = JudgePanel(generator_family="llama")
    with pytest.raises(ConfigurationError, match="the weights"):
        panel.assert_independent(["llama"])


@pytest.mark.security
def test_an_unknown_family_fails_closed() -> None:
    # A judge we cannot place cannot be shown to be independent.
    with pytest.raises(ConfigurationError, match="cannot be established"):
        JudgePanel(generator_family="claude").assert_independent([""])
    with pytest.raises(ConfigurationError, match="cannot be established"):
        JudgePanel(generator_family="").assert_independent(["llama"])


def test_a_cross_family_panel_is_accepted() -> None:
    JudgePanel(generator_family="claude").assert_independent(["llama", "gpt"])


@pytest.mark.security
def test_aggregation_asserts_independence_first() -> None:
    # A panel can never be aggregated without the check that makes its number mean
    # anything.
    panel = JudgePanel(generator_family="llama")
    with pytest.raises(ConfigurationError):
        panel.aggregate([JudgeVerdict(refuted=False, family="llama", confidence=0.9)])


def test_dissent_is_recorded_not_averaged_away() -> None:
    # A 2-1 split is exactly the signal a human reviewer needs.
    panel = JudgePanel(generator_family="claude")
    result = panel.aggregate(
        [
            JudgeVerdict(refuted=False, family="llama", confidence=0.9),
            JudgeVerdict(refuted=False, family="gpt", confidence=0.8),
            JudgeVerdict(refuted=True, family="mistral", confidence=0.7),
        ]
    )
    assert result.supported
    assert result.dissent
    assert not result.unanimous


def test_a_unanimous_panel_reports_no_dissent() -> None:
    panel = JudgePanel(generator_family="claude")
    result = panel.aggregate(
        [
            JudgeVerdict(refuted=False, family="llama", confidence=0.9),
            JudgeVerdict(refuted=False, family="gpt", confidence=0.8),
        ]
    )
    assert result.unanimous


def test_an_empty_panel_decides_nothing() -> None:
    with pytest.raises(ValueError, match="decides nothing"):
        JudgePanel(generator_family="claude").aggregate([])


def test_a_verdict_must_name_its_family() -> None:
    with pytest.raises(ValueError, match="cross-family independence"):
        JudgeVerdict(refuted=False, family="", confidence=0.5)


def test_entailment_defaults_to_none() -> None:
    # Defaults get inherited unexamined; one that adds a model call per claim would
    # make the framework uneconomical before anyone evaluated it.
    assert EntailmentPolicy.NONE.value == "none"


# ── Residency-first provider routing ─────────────────────────────────────────


def _spec(name: str, region: str, **kw: object) -> ProviderSpec:
    base: dict[str, object] = {"model_id": f"{name}-1", "family": name, "region": region}
    return ProviderSpec(name=name, **{**base, **kw})  # type: ignore[arg-type]


@pytest.mark.security
def test_providers_outside_the_residency_boundary_are_filtered_out() -> None:
    router = ProviderRouter(permitted_regions=frozenset({"eu-west-1"}))
    eligible = router.select([_spec("a", "eu-west-1"), _spec("b", "us-east-1")])
    assert [s.name for s in eligible] == ["a"]


@pytest.mark.security
def test_no_permitted_provider_refuses_rather_than_failing_over() -> None:
    # A fallback in another region turns an outage into a data-transfer breach.
    router = ProviderRouter(permitted_regions=frozenset({"af-south-1"}))
    with pytest.raises(ResidencyRefused, match="rather than failing over"):
        router.select([_spec("a", "us-east-1")])


@pytest.mark.security
def test_zero_retention_is_enforced_when_required() -> None:
    router = ProviderRouter(zero_retention_required=True)
    with pytest.raises(ResidencyRefused):
        router.select([_spec("a", "eu-west-1", zero_retention=False)])


def test_a_failover_that_drops_tool_support_is_filtered_out() -> None:
    # Silently losing tool-calling mid-run is worse than an error: the run
    # continues and quietly cannot do what it was asked.
    router = ProviderRouter()
    eligible = router.select(
        [_spec("a", "eu-west-1", supports_tools=False), _spec("b", "eu-west-1")],
        requires_tools=True,
    )
    assert [s.name for s in eligible] == ["b"]


def test_no_residency_constraint_permits_everything() -> None:
    assert len(ProviderRouter().select([_spec("a", "us-east-1"), _spec("b", "eu-west-1")])) == 2


# ── Approvals ────────────────────────────────────────────────────────────────


def _decision(approval_id: str, *, approved: bool) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=ApprovalId(approval_id),
        approver=ActorId("bob"),
        role="manager",
        approved=approved,
        decided_at=AT,
    )


@pytest.mark.security
def test_an_approved_control_item_is_reported() -> None:
    # The sharpest instrument: a reviewer who approves an item that should have
    # been rejected is not reviewing.
    items = (ControlItem(item_id="apr_ctl", expected_rejection="amount above limit"),)
    failures = ApprovalQueue.control_item_failures(items, (_decision("apr_ctl", approved=True),))
    assert failures == ("apr_ctl",)


def test_a_rejected_control_item_is_not_a_failure() -> None:
    items = (ControlItem(item_id="apr_ctl", expected_rejection="x"),)
    assert ApprovalQueue.control_item_failures(items, (_decision("apr_ctl", approved=False),)) == ()


@pytest.mark.security
@pytest.mark.parametrize(
    "signals",
    [
        ReviewSignals(decisions=50, approvals=50, median_seconds_to_decision=60),
        ReviewSignals(decisions=50, approvals=20, median_seconds_to_decision=2),
        ReviewSignals(
            decisions=50, approvals=20, median_seconds_to_decision=60, control_items_approved=1
        ),
    ],
    ids=["approves-everything", "too-fast-to-read", "approved-a-control-item"],
)
def test_rubber_stamping_is_detected(signals: ReviewSignals) -> None:
    assert signals.rubber_stamping_suspected()


def test_genuine_review_is_not_flagged() -> None:
    signals = ReviewSignals(
        decisions=50, approvals=38, median_seconds_to_decision=95, evidence_expanded=44
    )
    assert not signals.rubber_stamping_suspected()
    assert 0.7 < signals.approval_rate < 0.8


def test_a_queue_must_have_a_positive_expiry_window() -> None:
    # A queue without one becomes a backlog with no owner.
    with pytest.raises(ValueError, match="no owner"):
        ApprovalQueue(expiry_window=timedelta(0))


def test_expiry_is_computed_from_the_window() -> None:
    queue = ApprovalQueue(expiry_window=timedelta(days=7))
    assert queue.expires_at(AT) == AT + timedelta(days=7)


def test_batching_separates_outliers_from_the_routine() -> None:
    routine, outliers = ApprovalQueue.batch([1, 2, 3, 4], outliers=[3])
    assert routine == (1, 2, 4)
    assert outliers == (3,)


# ── Reconciliation ───────────────────────────────────────────────────────────


def _effect(state: EffectState, submitted_at: datetime) -> EffectRecord:
    return EffectRecord(
        action=Action(tool="t", actor=ActorId("alice"), tenant=TenantId("acme"), arguments={}),
        state=state,
        submitted_at=submitted_at,
        grant_id=GrantId("g1") if state is EffectState.COMMITTED else None,
        external_reference="x" if state is EffectState.COMMITTED else None,
    )


@pytest.mark.security
def test_an_overdue_unknown_is_found() -> None:
    # An unreconciled large transfer is an open incident, not a chart metric.
    sweep = ReconciliationSweep(sla=timedelta(hours=1))
    stale = _effect(EffectState.UNKNOWN, AT - timedelta(hours=2))
    assert sweep.overdue([stale], now=AT) == (stale,)


@pytest.mark.security
def test_a_dangling_submitted_is_found_too() -> None:
    # A crash between the intent write and any terminal event.
    sweep = ReconciliationSweep(sla=timedelta(hours=1))
    dangling = _effect(EffectState.SUBMITTED, AT - timedelta(hours=3))
    assert sweep.overdue([dangling], now=AT) == (dangling,)


def test_a_settled_effect_is_not_overdue() -> None:
    sweep = ReconciliationSweep(sla=timedelta(hours=1))
    assert sweep.overdue([_effect(EffectState.COMMITTED, AT - timedelta(days=1))], now=AT) == ()


def test_a_recent_unknown_is_not_yet_overdue() -> None:
    sweep = ReconciliationSweep(sla=timedelta(hours=1))
    assert sweep.overdue([_effect(EffectState.UNKNOWN, AT)], now=AT) == ()


def test_an_unresolved_reconciliation_must_say_what_was_attempted() -> None:
    # Otherwise an item nobody could resolve is indistinguishable from one nobody
    # tried to.
    with pytest.raises(ValueError, match="nobody tried"):
        ReconciliationItem(
            record=_effect(EffectState.UNKNOWN, AT),
            outcome=ReconciliationOutcome.STILL_UNKNOWN,
            resolved_at=AT,
        )


def test_a_resolved_reconciliation_records_who_decided() -> None:
    item = ReconciliationItem(
        record=_effect(EffectState.UNKNOWN, AT),
        outcome=ReconciliationOutcome.COMMITTED,
        external_reference="pay_9f3",
        resolved_at=AT,
        resolved_by=ActorId("ops-lead"),
        detail="confirmed against bank statement",
    )
    assert item.resolved_by == "ops-lead"
