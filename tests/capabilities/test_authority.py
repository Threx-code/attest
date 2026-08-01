"""Obligations must fail closed, and a grant must never precede discharge."""

from __future__ import annotations

from datetime import timedelta

import pytest

from attest.capabilities.authority import (
    Approval,
    AuthorityEngine,
    Budget,
    CapabilityCheck,
    CoolingOff,
    DualControl,
    Notification,
    ObligationSet,
    Reversibility,
    ReviewAttestation,
    TimeWindow,
)
from attest.kernel.actions import Action
from attest.kernel.authority import ApprovalRecord, Discharge
from attest.kernel.context import ExecutionContext
from attest.kernel.effects import EffectClasses, EffectSemantics
from attest.kernel.identifiers import ActorId, ApprovalId, GrantId, Hash, Nonce
from tests.capabilities.conftest import ACME, ALICE, AT

pytestmark = pytest.mark.unit


def _engine() -> AuthorityEngine:
    return AuthorityEngine(grant_ttl=timedelta(seconds=30))


def _approval(
    approver: str = "bob",
    *,
    approved: bool = True,
    role: str = "manager",
    action_hash: Hash | None = None,
) -> ApprovalRecord:
    """A decision bound to the action it was about.

    ``action_hash`` defaults to the fixture action's, because an approval that does not
    say what it was about discharges nothing — see ``covers``.
    """
    return ApprovalRecord(
        approval_id=ApprovalId(f"apr_{approver}"),
        approver=ActorId(approver),
        role=role,
        approved=approved,
        decided_at=AT,
        action_hash=action_hash,
    )


def _for(action: Action, *approvals: ApprovalRecord) -> tuple[ApprovalRecord, ...]:
    """Bind decisions to the action they were about.

    An approval with no ``action_hash`` discharges nothing, which is the point: a
    decision captured for one action must not satisfy an obligation on another.
    """
    from dataclasses import replace

    return tuple(replace(a, action_hash=action.action_hash()) for a in approvals)


# ── Fail-closed discharge ────────────────────────────────────────────────────


@pytest.mark.security
def test_an_obligation_that_raises_is_failed_not_skipped(
    action: Action, context: ExecutionContext
) -> None:
    # The typed form of `except Exception: return True`. An error in a check is not
    # a pass, and it must not silently vanish either.
    class Exploding:
        @property
        def name(self) -> str:
            return "exploding"

        def discharge(self, action: Action, context: ExecutionContext) -> Discharge:
            raise RuntimeError("verifier is down")

        def detail(self, action: Action, context: ExecutionContext) -> str:
            return ""

    result = _engine().discharge(ObligationSet((Exploding(),)), action, context)  # type: ignore[arg-type]
    assert not result.satisfied
    assert result.failed[0].discharge is Discharge.FAILED
    assert "RuntimeError" in result.failed[0].detail


@pytest.mark.security
def test_every_obligation_is_evaluated_not_short_circuited(
    action: Action, context: ExecutionContext
) -> None:
    # A caller triaging a refusal needs the whole picture, and a partially evaluated
    # set cannot be re-discharged consistently on resume.
    obligations = ObligationSet((CapabilityCheck("absent_one"), CapabilityCheck("absent_two")))
    result = _engine().discharge(obligations, action, context)
    assert len(result.outcomes) == 2
    assert len(result.failed) == 2


def test_a_held_capability_discharges(action: Action, context: ExecutionContext) -> None:
    result = _engine().discharge(ObligationSet((CapabilityCheck("transfer"),)), action, context)
    assert result.satisfied


@pytest.mark.security
def test_a_missing_capability_fails(action: Action, context: ExecutionContext) -> None:
    result = _engine().discharge(ObligationSet((CapabilityCheck("settle_claim"),)), action, context)
    assert result.failed


# ── The obligations a ladder cannot express ──────────────────────────────────


def test_approval_is_pending_until_the_quorum_is_met(
    action: Action, context: ExecutionContext
) -> None:
    obligation = Approval(
        n=2, roles=frozenset({"manager"}), approvals=_for(action, _approval("bob"))
    )
    assert obligation.discharge(action, context) is Discharge.PENDING


def test_approval_satisfied_at_quorum(action: Action, context: ExecutionContext) -> None:
    obligation = Approval(
        n=2,
        roles=frozenset({"manager"}),
        approvals=_for(action, _approval("bob"), _approval("carol")),
    )
    assert obligation.discharge(action, context) is Discharge.SATISFIED


def test_a_rejection_fails_rather_than_pending(action: Action, context: ExecutionContext) -> None:
    obligation = Approval(n=1, approvals=_for(action, _approval("bob", approved=False)))
    assert obligation.discharge(action, context) is Discharge.FAILED


@pytest.mark.security
def test_dual_control_refuses_self_approval(action: Action, context: ExecutionContext) -> None:
    # The most common way dual control is defeated in practice.
    obligation = DualControl(approvals=_for(action, _approval("alice"), _approval("bob")))
    assert obligation.discharge(action, context) is Discharge.PENDING


@pytest.mark.security
def test_dual_control_requires_two_DISTINCT_humans(
    action: Action, context: ExecutionContext
) -> None:
    same_person_twice = DualControl(approvals=_for(action, _approval("bob"), _approval("bob")))
    assert same_person_twice.discharge(action, context) is Discharge.PENDING
    two_people = DualControl(approvals=_for(action, _approval("bob"), _approval("carol")))
    assert two_people.discharge(action, context) is Discharge.SATISFIED


@pytest.mark.security
def test_a_budget_without_a_reservation_fails(action: Action, context: ExecutionContext) -> None:
    # A budget that is merely READ is a race: two runs both see headroom.
    assert Budget("daily").discharge(action, context) is Discharge.FAILED
    assert Budget("daily", reservation_id="r1").discharge(action, context) is Discharge.SATISFIED


def test_cooling_off_is_pending_until_the_period_elapses(
    action: Action, context: ExecutionContext
) -> None:
    started = AT - timedelta(days=3)
    obligation = CoolingOff(duration=timedelta(days=7), started_at=started)
    assert obligation.discharge(action, context) is Discharge.PENDING


def test_cooling_off_satisfied_once_elapsed(action: Action, context: ExecutionContext) -> None:
    started = AT - timedelta(days=8)
    obligation = CoolingOff(duration=timedelta(days=7), started_at=started)
    assert obligation.discharge(action, context) is Discharge.SATISFIED


@pytest.mark.security
def test_cancellation_during_cooling_off_fails(action: Action, context: ExecutionContext) -> None:
    # The subject withdrew. That is a refusal, not a pending wait.
    obligation = CoolingOff(
        duration=timedelta(days=7), started_at=AT - timedelta(days=8), cancelled=True
    )
    assert obligation.discharge(action, context) is Discharge.FAILED


def test_a_passed_deadline_fails_with_no_action_taken(
    action: Action, context: ExecutionContext
) -> None:
    # An obligation that fails through the passage of time alone — a shape no
    # autonomy ladder can express.
    obligation = TimeWindow(before=AT - timedelta(hours=1))
    assert obligation.discharge(action, context) is Discharge.FAILED


def test_notification_before_effect_is_pending_until_sent(
    action: Action, context: ExecutionContext
) -> None:
    assert Notification("applicant").discharge(action, context) is Discharge.PENDING
    assert Notification("applicant", sent=True).discharge(action, context) is Discharge.SATISFIED


def test_review_attestation_needs_the_facts_that_were_reviewed(
    action: Action, context: ExecutionContext
) -> None:
    # An attestation that cannot say what was in front of the person is not
    # evidence anything was reviewed.
    bare = ReviewAttestation("medical_officer", attested_by="dr-smith")
    assert bare.discharge(action, context) is Discharge.PENDING
    named = ReviewAttestation("medical_officer", reviewed=("lab-8823",), attested_by="dr-smith")
    assert named.discharge(action, context) is Discharge.SATISFIED


@pytest.mark.security
def test_an_irreversible_uncompensatable_action_fails_reversibility(
    context: ExecutionContext,
) -> None:
    action = Action(
        tool="wipe",
        actor=ALICE,
        tenant=ACME,
        arguments={},
        semantics=EffectSemantics(reversible=False, compensatable=False),
        effects=frozenset({EffectClasses.DESTRUCTIVE}),
    )
    assert Reversibility().discharge(action, context) is Discharge.FAILED


def test_a_compensatable_action_satisfies_reversibility(
    action: Action, context: ExecutionContext
) -> None:
    assert Reversibility().discharge(action, context) is Discharge.SATISFIED


# ── Grant issuance ───────────────────────────────────────────────────────────


@pytest.mark.security
def test_a_grant_cannot_be_issued_before_everything_discharges(
    action: Action, context: ExecutionContext
) -> None:
    result = _engine().discharge(ObligationSet((CapabilityCheck("absent"),)), action, context)
    with pytest.raises(ValueError, match="authority bypass"):
        _engine().issue(
            grant_id=GrantId("g1"),
            nonce=Nonce("n1"),
            action=action,
            context=context,
            result=result,
            now=AT,
        )


def test_a_grant_binds_the_context_it_was_discharged_against(
    action: Action, context: ExecutionContext
) -> None:
    result = _engine().discharge(ObligationSet((CapabilityCheck("transfer"),)), action, context)
    grant = _engine().issue(
        grant_id=GrantId("g1"),
        nonce=Nonce("n1"),
        action=action,
        context=context,
        result=result,
        now=AT,
    )
    assert grant.context_hash == context.content_hash()
    assert grant.action_hash == action.action_hash()
    assert grant.check_against(action, now=AT).authorised


def test_the_engines_ttl_is_applied(action: Action, context: ExecutionContext) -> None:
    result = _engine().discharge(ObligationSet((CapabilityCheck("transfer"),)), action, context)
    grant = _engine().issue(
        grant_id=GrantId("g1"),
        nonce=Nonce("n1"),
        action=action,
        context=context,
        result=result,
        now=AT,
    )
    assert grant.expires_at - grant.issued_at == timedelta(seconds=30)


def test_obligation_sets_compose(action: Action, context: ExecutionContext) -> None:
    combined = ObligationSet((CapabilityCheck("a"),)) + ObligationSet((CapabilityCheck("b"),))
    assert len(combined) == 2
    assert bool(combined)


@pytest.mark.security
def test_an_approval_for_a_different_action_discharges_nothing(
    action: Action, context: ExecutionContext
) -> None:
    """A decision captured for a GBP 50 refund must not authorise a GBP 500,000 transfer.

    ApprovalRecord carried no action hash, so any recorded "yes" satisfied any
    obligation it was handed to — and the REST surface produced exactly such records.
    """
    other = Action(
        tool=action.tool,
        actor=action.actor,
        tenant=action.tenant,
        arguments={"amount": "50.00"},
        semantics=action.semantics,
    )
    elsewhere = _for(other, _approval("bob"), _approval("carol"))
    assert Approval(n=2, approvals=elsewhere).discharge(action, context) is Discharge.PENDING
    assert DualControl(approvals=elsewhere).discharge(action, context) is Discharge.PENDING


@pytest.mark.security
def test_an_unbound_approval_discharges_nothing(action: Action, context: ExecutionContext) -> None:
    """No action hash at all fails closed, so a historical record cannot authorise."""
    unbound = (_approval("bob"), _approval("carol"))
    assert Approval(n=2, approvals=unbound).discharge(action, context) is Discharge.PENDING
