"""Refusals must be actionable.

A refusal frequently triggers a downstream obligation — an adverse action notice, an
escalation, an ombudsman right. An unexplained one cannot be acted on or contested,
which in several target domains is itself a compliance failure.
"""

from __future__ import annotations

import pytest

from attest.kernel.verdicts import (
    CORE_REFUSAL_REASONS,
    POST_EFFECT_VERDICTS,
    Refusal,
    RefusalReason,
    Verdict,
)
from attest.kernel.warrants import WarrantKinds


@pytest.mark.unit
def test_a_refusal_carries_a_reason_and_a_detail() -> None:
    refusal = Refusal(
        reason=RefusalReason("unsupported_claim"),
        detail="no evidence supports the settlement figure",
        warrant=WarrantKinds.EPISTEMIC,
    )
    assert refusal.reason == "unsupported_claim"
    assert refusal.warrant == WarrantKinds.EPISTEMIC


@pytest.mark.unit
def test_refusal_requires_a_reason() -> None:
    with pytest.raises(ValueError, match="reason"):
        Refusal(reason=RefusalReason(""), detail="something")


@pytest.mark.unit
@pytest.mark.parametrize("detail", ["", "   ", "\n\t "])
def test_refusal_requires_a_non_blank_detail(detail: str) -> None:
    with pytest.raises(ValueError, match="contested"):
        Refusal(reason=RefusalReason("out_of_scope"), detail=detail)


@pytest.mark.unit
def test_subject_message_defaults_to_none_not_to_the_internal_reason() -> None:
    # What you may tell an applicant is legally constrained and routinely differs
    # from the internal reason. Silently reusing `detail` would leak an internal
    # rationale into a regulated communication.
    refusal = Refusal(
        reason=RefusalReason("insufficient_authority"),
        detail="actor lacks capability settle_claim",
    )
    assert refusal.subject_message is None


@pytest.mark.unit
def test_subject_message_may_differ_from_the_internal_detail() -> None:
    refusal = Refusal(
        reason=RefusalReason("stale_evidence"),
        detail="policy wording PW-2019 superseded 2024-03-01",
        subject_message="We need to re-check your policy documents before deciding.",
    )
    assert refusal.subject_message != refusal.detail


@pytest.mark.unit
def test_warrant_is_optional_because_not_every_refusal_has_one() -> None:
    # A budget exhaustion is a refusal with no warrant behind it.
    assert (
        Refusal(reason=RefusalReason("budget_exhausted"), detail="daily ceiling hit").warrant
        is None
    )


@pytest.mark.unit
def test_an_unreachable_evidence_source_is_a_refusal_reason_not_an_exception() -> None:
    # The near-miss case from docs/kernel/errors.md: the system is working, the
    # world is not cooperating, and that is a decision worth recording.
    assert RefusalReason("evidence_source_unreachable") in CORE_REFUSAL_REASONS


@pytest.mark.unit
def test_post_effect_verdicts_are_exactly_unknown_and_incomplete() -> None:
    assert {Verdict.UNKNOWN, Verdict.INCOMPLETE} == POST_EFFECT_VERDICTS


@pytest.mark.unit
def test_no_pre_effect_verdict_is_marked_post_effect() -> None:
    for verdict in (Verdict.ALLOW, Verdict.ALLOW_WITH_WARNINGS, Verdict.REFUSE):
        assert verdict not in POST_EFFECT_VERDICTS


@pytest.mark.unit
def test_hold_for_approval_is_not_post_effect() -> None:
    # A held run has not reached the execution boundary.
    assert Verdict.HOLD_FOR_APPROVAL not in POST_EFFECT_VERDICTS
