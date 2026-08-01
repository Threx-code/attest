"""The fail-closed properties of warrant reporting.

Surveyed guard code contained ``except Exception: return True`` — an error silently
disabling a check. These tests exist so the same defect cannot be expressed through
the type instead.
"""

from __future__ import annotations

import pytest

from attest.kernel.verdicts import Verdict
from attest.kernel.warrants import (
    CORE_WARRANTS,
    Finding,
    Severity,
    WarrantKind,
    WarrantKinds,
    WarrantReport,
    WarrantStatus,
)


def _report(**kw: object) -> WarrantReport:
    base: dict[str, object] = {
        "kind": WarrantKinds.EPISTEMIC,
        "status": WarrantStatus.EVALUATED,
        "satisfied": True,
    }
    return WarrantReport(**{**base, **kw})  # type: ignore[arg-type]


# ── Fail-closed ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize("status", [WarrantStatus.PENDING, WarrantStatus.UNEVALUATABLE])
def test_unevaluated_warrant_cannot_claim_satisfied(status: WarrantStatus) -> None:
    # A check that did not run has not passed. Constructing this must be impossible,
    # not merely discouraged.
    with pytest.raises(ValueError, match=r"has not run|Fail closed"):
        _report(status=status, satisfied=True)


@pytest.mark.unit
@pytest.mark.parametrize("status", [WarrantStatus.PENDING, WarrantStatus.UNEVALUATABLE])
def test_unevaluated_warrant_may_be_unsatisfied(status: WarrantStatus) -> None:
    assert _report(status=status, satisfied=False).is_satisfied() is False


@pytest.mark.unit
@pytest.mark.security
def test_is_satisfied_is_false_for_every_non_evaluated_status() -> None:
    for status in WarrantStatus:
        report = _report(status=status, satisfied=status is WarrantStatus.EVALUATED)
        assert report.is_satisfied() is (status is WarrantStatus.EVALUATED)


@pytest.mark.unit
def test_evaluated_and_failing_is_not_satisfied() -> None:
    assert _report(satisfied=False).is_satisfied() is False


@pytest.mark.unit
def test_only_pending_is_non_final() -> None:
    # UNEVALUATABLE is a settled outcome: it will not become anything else.
    assert _report(status=WarrantStatus.PENDING, satisfied=False).is_final is False
    assert _report(status=WarrantStatus.UNEVALUATABLE, satisfied=False).is_final is True
    assert _report().is_final is True


# ── Confidence discipline ────────────────────────────────────────────────────────


@pytest.mark.unit
def test_exact_verification_has_no_confidence() -> None:
    # None means exact; a float means a judge decided. Conflating them is how
    # "verified" stops meaning anything.
    assert _report().confidence is None


@pytest.mark.unit
@pytest.mark.parametrize("value", [-0.1, 1.1, 2.0, -1.0])
def test_confidence_outside_unit_interval_is_rejected(value: float) -> None:
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        _report(confidence=value)


@pytest.mark.unit
@pytest.mark.parametrize("value", [0.0, 0.5, 1.0])
def test_confidence_within_unit_interval_is_accepted(value: float) -> None:
    assert _report(confidence=value).confidence == value


# ── Openness ─────────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_the_four_core_warrants_are_exactly_these() -> None:
    assert {
        WarrantKinds.EPISTEMIC,
        WarrantKinds.AUTHORITY,
        WarrantKinds.PROVENANCE,
        WarrantKinds.BOUNDARY,
    } == CORE_WARRANTS


@pytest.mark.unit
def test_completeness_is_not_core() -> None:
    # Strongly recommended, not mandatory: an agent with no retrieval surface has
    # nothing to be incomplete about.
    assert WarrantKinds.COMPLETENESS not in CORE_WARRANTS


@pytest.mark.unit
def test_a_domain_can_register_a_warrant_kind_without_touching_the_kernel() -> None:
    # The openness test, executable. If WarrantKind were an enum this would not compile.
    calibration = WarrantKind("calibration")
    report = _report(kind=calibration, confidence=0.87)
    assert report.kind == "calibration"
    assert report.is_satisfied()


# ── Findings ─────────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_finding_requires_a_code() -> None:
    with pytest.raises(ValueError, match="aggregated"):
        Finding(code="", message="something happened")


@pytest.mark.unit
def test_finding_defaults_to_info() -> None:
    assert Finding(code="x", message="y").severity is Severity.INFO


# ── Verdict routing ──────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        (Verdict.ALLOW, False),
        (Verdict.ALLOW_WITH_WARNINGS, False),
        (Verdict.REFUSE, False),
        (Verdict.HOLD_FOR_APPROVAL, True),
        (Verdict.UNKNOWN, True),
        (Verdict.INCOMPLETE, True),
    ],
)
def test_requires_human_attention_covers_every_verdict(verdict: Verdict, expected: bool) -> None:
    assert verdict.requires_human_attention is expected


@pytest.mark.unit
def test_the_parametrisation_above_covers_the_whole_enum() -> None:
    # Guards against a verdict being added without the routing test being extended.
    covered = {
        Verdict.ALLOW,
        Verdict.ALLOW_WITH_WARNINGS,
        Verdict.REFUSE,
        Verdict.HOLD_FOR_APPROVAL,
        Verdict.UNKNOWN,
        Verdict.INCOMPLETE,
    }
    assert covered == set(Verdict)
