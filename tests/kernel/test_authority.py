"""Grants are the TOCTOU defence. These are threat-model attacks 5, 7, 8 and 10."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from attest.kernel.actions import Action
from attest.kernel.authority import (
    MAX_GRANT_TTL,
    ApprovalRecord,
    AuthorizationGrant,
    Discharge,
    GrantCheck,
    GrantRejection,
    ObligationOutcome,
)
from attest.kernel.identifiers import (
    ActorId,
    ApprovalId,
    GrantId,
    Hash,
    Nonce,
    TenantId,
)

ISSUED = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
ALICE = ActorId("alice")
ACME = TenantId("acme")


def _action(**kw: object) -> Action:
    base: dict[str, object] = {
        "tool": "transfer",
        "actor": ALICE,
        "tenant": ACME,
        "arguments": {"to": "X", "amount": Decimal("12400.00")},
    }
    return Action(**{**base, **kw})  # type: ignore[arg-type]


def _grant(action: Action | None = None, **kw: object) -> AuthorizationGrant:
    action = action or _action()
    base: dict[str, object] = {
        "grant_id": GrantId("grt_1"),
        "action_hash": action.action_hash(),
        "actor": action.actor,
        "tenant": action.tenant,
        "tool": action.tool,
        "nonce": Nonce("n_1"),
        "issued_at": ISSUED,
        "expires_at": ISSUED + timedelta(seconds=30),
        "policy_version": "1.0.0",
        "profile_version": "2.1.0",
        "context_hash": Hash("c" * 64),
    }
    return AuthorizationGrant(**{**base, **kw})  # type: ignore[arg-type]


# ── Binding to the exact action ──────────────────────────────────────────────────


@pytest.mark.unit
def test_a_grant_authorises_the_action_it_was_issued_for() -> None:
    action = _action()
    assert _grant(action).check_against(action, now=ISSUED).authorised


@pytest.mark.unit
@pytest.mark.security
def test_a_grant_does_not_authorise_a_different_beneficiary() -> None:
    # Threat-model attack 5.
    authorised = _action(arguments={"to": "X", "amount": Decimal("12400.00")})
    substituted = _action(arguments={"to": "Y", "amount": Decimal("12400.00")})
    check = _grant(authorised).check_against(substituted, now=ISSUED)
    assert not check.authorised
    assert GrantRejection.ACTION_MISMATCH in check.rejections


@pytest.mark.unit
@pytest.mark.security
def test_a_grant_does_not_authorise_a_larger_amount() -> None:
    # Threat-model attack 10: argument mutation after approval.
    authorised = _action(arguments={"to": "X", "amount": Decimal("12400.00")})
    inflated = _action(arguments={"to": "X", "amount": Decimal("500000.00")})
    assert GrantRejection.ACTION_MISMATCH in (
        _grant(authorised).check_against(inflated, now=ISSUED).rejections
    )


@pytest.mark.unit
@pytest.mark.security
def test_a_grant_does_not_authorise_a_different_tool() -> None:
    assert GrantRejection.ACTION_MISMATCH in (
        _grant(_action()).check_against(_action(tool="refund"), now=ISSUED).rejections
    )


@pytest.mark.unit
@pytest.mark.security
def test_another_actor_cannot_redeem_a_grant() -> None:
    # The confused-deputy case: holding the token is not being the grantee.
    mallory = _action(actor=ActorId("mallory"))
    check = _grant(_action()).check_against(mallory, now=ISSUED)
    assert GrantRejection.ACTOR_MISMATCH in check.rejections


@pytest.mark.unit
@pytest.mark.security
def test_a_grant_cannot_cross_a_tenant_boundary() -> None:
    other = _action(tenant=TenantId("other-corp"))
    check = _grant(_action()).check_against(other, now=ISSUED)
    assert GrantRejection.TENANT_MISMATCH in check.rejections


# ── Time ─────────────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_an_expired_grant_does_not_authorise() -> None:
    action = _action()
    grant = _grant(action)
    check = grant.check_against(action, now=grant.expires_at)
    assert GrantRejection.EXPIRED in check.rejections


@pytest.mark.unit
def test_expiry_is_exclusive_at_the_boundary() -> None:
    # Valid up to but not including expires_at, so the window is unambiguous.
    action = _action()
    grant = _grant(action)
    assert grant.check_against(action, now=grant.expires_at - timedelta(microseconds=1))
    assert not grant.check_against(action, now=grant.expires_at)


@pytest.mark.unit
@pytest.mark.security
def test_a_grant_presented_before_issuance_is_rejected() -> None:
    # A clock disagreement, or a forged timestamp.
    action = _action()
    check = _grant(action).check_against(action, now=ISSUED - timedelta(seconds=1))
    assert GrantRejection.NOT_YET_VALID in check.rejections


@pytest.mark.unit
@pytest.mark.security
def test_a_long_lived_grant_cannot_be_constructed() -> None:
    # A grant valid for hours does not shrink the window it exists to shrink.
    with pytest.raises(ValueError, match="ceiling"):
        _grant(expires_at=ISSUED + MAX_GRANT_TTL + timedelta(seconds=1))


@pytest.mark.unit
def test_a_grant_at_exactly_the_ttl_ceiling_is_accepted() -> None:
    # The boundary is inclusive, so a ceiling-length grant is legitimate.
    grant = _grant(expires_at=ISSUED + MAX_GRANT_TTL)
    assert grant.expires_at - grant.issued_at == MAX_GRANT_TTL


@pytest.mark.unit
def test_a_grant_that_expires_before_it_is_issued_is_rejected() -> None:
    with pytest.raises(ValueError, match="never authorise"):
        _grant(expires_at=ISSUED - timedelta(seconds=1))


# ── Revocation and policy ────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_a_revoked_grant_does_not_authorise() -> None:
    # Threat-model attack 7: capability revoked between check and effect.
    action = _action()
    check = _grant(action, revoked=True).check_against(action, now=ISSUED)
    assert GrantRejection.REVOKED in check.rejections


@pytest.mark.unit
@pytest.mark.security
def test_a_superseded_policy_version_does_not_authorise() -> None:
    # Threat-model attack 6: stale policy.
    action = _action()
    check = _grant(action).check_against(action, now=ISSUED, current_policy_version="1.1.0")
    assert GrantRejection.POLICY_SUPERSEDED in check.rejections


@pytest.mark.unit
def test_policy_checking_is_opt_in() -> None:
    # Omitting the current version skips the check rather than failing closed on it,
    # because a caller that does not know the current policy cannot assert staleness.
    action = _action()
    assert _grant(action).check_against(action, now=ISSUED).authorised


# ── The check reports everything ─────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_all_rejections_are_reported_not_only_the_first() -> None:
    # An expired grant bound to a different action is a materially different signal
    # from one that merely lapsed. Short-circuiting would hide the attack.
    grant = _grant(_action(), revoked=True)
    check = grant.check_against(
        _action(arguments={"to": "Y"}, actor=ActorId("mallory")),
        now=grant.expires_at,
        current_policy_version="9.9.9",
    )
    assert {
        GrantRejection.ACTION_MISMATCH,
        GrantRejection.ACTOR_MISMATCH,
        GrantRejection.EXPIRED,
        GrantRejection.REVOKED,
        GrantRejection.POLICY_SUPERSEDED,
    } <= set(check.rejections)


@pytest.mark.unit
def test_a_check_is_falsy_when_rejected() -> None:
    assert not GrantCheck(rejections=(GrantRejection.EXPIRED,))
    assert GrantCheck()


# ── Obligations must have discharged before issuance ─────────────────────────────


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize("discharge", [Discharge.PENDING, Discharge.FAILED])
def test_a_grant_cannot_carry_an_undischarged_obligation(discharge: Discharge) -> None:
    # Issuing a grant before every obligation discharges is authority bypass by
    # construction, so it is impossible rather than discouraged.
    outcome = ObligationOutcome(
        name="approval:claims_manager", discharge=discharge, detail="awaiting"
    )
    with pytest.raises(ValueError, match="authority bypass"):
        _grant(obligations=(outcome,))


@pytest.mark.unit
def test_a_grant_may_carry_satisfied_obligations() -> None:
    outcome = ObligationOutcome(name="capability:transfer", discharge=Discharge.SATISFIED)
    assert _grant(obligations=(outcome,)).obligations[0].discharge is Discharge.SATISFIED


@pytest.mark.unit
def test_a_failed_obligation_must_say_why() -> None:
    with pytest.raises(ValueError, match="contested"):
        ObligationOutcome(name="budget:daily", discharge=Discharge.FAILED)


@pytest.mark.unit
def test_an_obligation_outcome_must_be_named() -> None:
    with pytest.raises(ValueError, match="audited"):
        ObligationOutcome(name="", discharge=Discharge.SATISFIED)


# ── Nonce ────────────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_a_grant_without_a_nonce_cannot_be_constructed() -> None:
    with pytest.raises(ValueError, match="replayable"):
        _grant(nonce=Nonce(""))


@pytest.mark.unit
@pytest.mark.security
def test_the_kernel_check_deliberately_does_not_cover_replay() -> None:
    # Redemption needs an atomic compare-and-set against a store, which is L1. The
    # same grant checking out twice here is CORRECT: this function is pure, and a
    # caller that stops here has bound the action but not defended against replay.
    action = _action()
    grant = _grant(action)
    assert grant.check_against(action, now=ISSUED).authorised
    assert grant.check_against(action, now=ISSUED).authorised


# ── Approvals ────────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_an_approval_must_carry_a_role() -> None:
    # An n-of-m quorum is defined over roles, so an unattributed approval cannot
    # be counted towards one.
    with pytest.raises(ValueError, match="quorum"):
        ApprovalRecord(
            approval_id=ApprovalId("apr_1"),
            approver=ALICE,
            role="",
            approved=True,
            decided_at=ISSUED,
        )


@pytest.mark.unit
def test_an_approval_records_what_was_reviewed() -> None:
    # The quality of an approval is bounded by what the approver was shown.
    approval = ApprovalRecord(
        approval_id=ApprovalId("apr_1"),
        approver=ALICE,
        role="claims_manager",
        approved=True,
        decided_at=ISSUED,
        reviewed_items=("evidence:e1", "computation:settlement"),
    )
    assert approval.reviewed_items == ("evidence:e1", "computation:settlement")


# ── Content addressing ───────────────────────────────────────────────────────────


@pytest.mark.unit
def test_identical_grants_hash_identically() -> None:
    action = _action()
    assert _grant(action).content_hash() == _grant(action).content_hash()


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("nonce", Nonce("n_2")),
        ("policy_version", "1.1.0"),
        ("profile_version", "2.2.0"),
        ("context_hash", Hash("d" * 64)),
        ("idempotency_key", "idem-1"),
    ],
)
def test_grant_fields_are_bound_into_its_hash(field: str, value: object) -> None:
    action = _action()
    assert _grant(action).content_hash() != _grant(action, **{field: value}).content_hash()
