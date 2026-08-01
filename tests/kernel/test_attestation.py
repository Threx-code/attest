"""The attestation must not be able to claim more than the run established.

The most dangerous failure this design has is a beautifully verifiable attestation of
a decision that was never properly checked. These tests close the paths to it.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attest.kernel.actions import Action
from attest.kernel.attestation import (
    Attestation,
    AttestationError,
    CostRecord,
    EffectRecord,
)
from attest.kernel.audit import RunSeal
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.effects import EffectState
from attest.kernel.identifiers import ActorId, GrantId, Hash, RunId, TenantId
from attest.kernel.verdicts import Refusal, RefusalReason, Verdict
from attest.kernel.warrants import (
    CORE_WARRANTS,
    WarrantKind,
    WarrantKinds,
    WarrantReport,
    WarrantStatus,
)

__test_uses__ = WarrantKind  # kind annotations below are evaluated at runtime

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
RUN = RunId("run_1")
ACME = TenantId("acme")


def _context(run: RunId = RUN) -> ExecutionContext:
    return ExecutionContext(
        run_id=run,
        captured_at=AT,
        identity=IdentitySnapshot(actor=ActorId("alice"), tenant=ACME),
        binding=TenantBinding(
            tenant=ACME,
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
        ),
        framework_version="0.1.0",
        policy_version="1.0.0",
    )


def _report(kind: WarrantKind, status: WarrantStatus, satisfied: bool) -> WarrantReport:
    return WarrantReport(kind=kind, status=status, satisfied=satisfied)


def _all_core(status: WarrantStatus = WarrantStatus.EVALUATED) -> dict[WarrantKind, WarrantReport]:
    return {k: _report(k, status, status is WarrantStatus.EVALUATED) for k in CORE_WARRANTS}


def _action() -> Action:
    return Action(tool="transfer", actor=ActorId("alice"), tenant=ACME, arguments={"to": "X"})


def _attestation(**kw: object) -> Attestation:
    base: dict[str, object] = {
        "run_id": RUN,
        "verdict": Verdict.ALLOW,
        "context": _context(),
        "created_at": AT,
        "warrants": _all_core(),
    }
    return Attestation(**{**base, **kw})  # type: ignore[arg-type]


# ── Coherence ────────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_an_attestation_cannot_carry_a_context_for_another_run() -> None:
    with pytest.raises(AttestationError, match="different run"):
        _attestation(context=_context(RunId("run_other")))


@pytest.mark.unit
@pytest.mark.security
def test_a_refusal_verdict_must_carry_a_typed_refusal() -> None:
    with pytest.raises(AttestationError, match="contested"):
        _attestation(verdict=Verdict.REFUSE)


@pytest.mark.unit
def test_a_refusal_verdict_with_a_refusal_is_accepted() -> None:
    refusal = Refusal(reason=RefusalReason("out_of_scope"), detail="outside remit")
    assert _attestation(verdict=Verdict.REFUSE, refusal=refusal).refusal is refusal


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize("verdict", [Verdict.UNKNOWN, Verdict.INCOMPLETE])
def test_a_post_effect_verdict_requires_effects(verdict: Verdict) -> None:
    # UNKNOWN and INCOMPLETE are only reachable after something was attempted.
    with pytest.raises(AttestationError, match="no effects are recorded"):
        _attestation(verdict=verdict)


@pytest.mark.unit
def test_a_warrant_filed_under_the_wrong_key_is_rejected() -> None:
    mismatched = {
        WarrantKinds.EPISTEMIC: _report(WarrantKinds.BOUNDARY, WarrantStatus.EVALUATED, True)
    }
    with pytest.raises(AttestationError, match="reports kind"):
        _attestation(warrants=mismatched)


# ── An absent warrant is not a satisfied one ─────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_asking_for_an_unevaluated_warrant_raises_rather_than_returning_none() -> None:
    # A caller must not receive an absence it can mistake for a pass.
    with pytest.raises(AttestationError, match="not a satisfied one"):
        _attestation(warrants={}).warrant(WarrantKinds.EPISTEMIC)


@pytest.mark.unit
@pytest.mark.security
def test_missing_core_warrants_are_reported() -> None:
    partial = {
        WarrantKinds.EPISTEMIC: _report(WarrantKinds.EPISTEMIC, WarrantStatus.EVALUATED, True)
    }
    missing = _attestation(warrants=partial).missing_core_warrants()
    assert WarrantKinds.AUTHORITY in missing
    assert WarrantKinds.EPISTEMIC not in missing


@pytest.mark.unit
def test_a_complete_core_set_reports_nothing_missing() -> None:
    assert _attestation().missing_core_warrants() == frozenset()


@pytest.mark.unit
def test_unsatisfied_includes_warrants_that_could_not_run() -> None:
    warrants = _all_core()
    warrants[WarrantKinds.BOUNDARY] = _report(
        WarrantKinds.BOUNDARY, WarrantStatus.UNEVALUATABLE, False
    )
    assert WarrantKinds.BOUNDARY in _attestation(warrants=warrants).unsatisfied()


# ── is_final is derived, and gates export ────────────────────────────────────────


@pytest.mark.unit
def test_a_fully_evaluated_attestation_is_final() -> None:
    assert _attestation().is_final


@pytest.mark.unit
@pytest.mark.security
def test_a_pending_warrant_makes_the_attestation_non_final() -> None:
    warrants = _all_core()
    warrants[WarrantKinds.EPISTEMIC] = _report(WarrantKinds.EPISTEMIC, WarrantStatus.PENDING, False)
    attestation = _attestation(warrants=warrants)
    assert not attestation.is_final
    assert attestation.pending_warrants == {WarrantKinds.EPISTEMIC}


@pytest.mark.unit
def test_an_unevaluatable_warrant_is_still_final() -> None:
    # UNEVALUATABLE is settled: it will not become anything else. It fails the
    # warrant, but it does not leave the attestation awaiting work.
    warrants = _all_core()
    warrants[WarrantKinds.EPISTEMIC] = _report(
        WarrantKinds.EPISTEMIC, WarrantStatus.UNEVALUATABLE, False
    )
    assert _attestation(warrants=warrants).is_final


def _seal() -> RunSeal:
    return RunSeal(
        run_id=RUN,
        event_count=1,
        first_sequence=1,
        last_sequence=1,
        head_hash=Hash("h" * 64),
        attestation_hash=Hash("a" * 64),
        sealed_at=AT,
    )


@pytest.mark.unit
def test_a_sealed_final_attestation_is_exportable() -> None:
    _attestation(seal=_seal()).assert_exportable()


@pytest.mark.unit
@pytest.mark.security
def test_a_non_final_attestation_cannot_be_exported_even_when_sealed() -> None:
    # An evidence bundle is what goes to a regulator. Exporting one whose warrants
    # had not been evaluated presents an unverified result as a settled record.
    # Sealed deliberately, so this exercises the assurance gate rather than the
    # seal gate — the two failures are independent and both must hold.
    warrants = _all_core()
    warrants[WarrantKinds.EPISTEMIC] = _report(WarrantKinds.EPISTEMIC, WarrantStatus.PENDING, False)
    with pytest.raises(AttestationError, match="still pending"):
        _attestation(warrants=warrants, seal=_seal()).assert_exportable()


@pytest.mark.unit
@pytest.mark.security
def test_an_unsealed_attestation_cannot_be_exported() -> None:
    with pytest.raises(AttestationError, match="not evidence"):
        _attestation().assert_exportable()


# ── Effects cannot overclaim ─────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_a_committed_effect_must_carry_an_external_reference() -> None:
    # Recording a commit we cannot point at is how an audit chain comes to disagree
    # with the world.
    with pytest.raises(AttestationError, match="external reference"):
        EffectRecord(action=_action(), state=EffectState.COMMITTED, grant_id=GrantId("grt_1"))


@pytest.mark.unit
@pytest.mark.security
def test_a_committed_effect_must_reference_its_grant() -> None:
    # Threat-model attack 11: an effect with no grant is unauthorised by definition,
    # and this is what makes a direct executor call detectable after the fact.
    with pytest.raises(AttestationError, match="unauthorised by definition"):
        EffectRecord(action=_action(), state=EffectState.COMMITTED, external_reference="pay-123")


@pytest.mark.unit
@pytest.mark.security
def test_an_unknown_effect_must_record_when_it_was_submitted() -> None:
    # Without it, UNKNOWN is indistinguishable from "never attempted".
    with pytest.raises(AttestationError, match="never attempted"):
        EffectRecord(action=_action(), state=EffectState.UNKNOWN)


@pytest.mark.unit
def test_a_well_formed_unknown_effect_is_accepted() -> None:
    record = EffectRecord(action=_action(), state=EffectState.UNKNOWN, submitted_at=AT)
    attestation = _attestation(verdict=Verdict.UNKNOWN, effects=(record,))
    assert attestation.has_unresolved_effects


@pytest.mark.unit
def test_a_settled_run_has_no_unresolved_effects() -> None:
    record = EffectRecord(
        action=_action(),
        state=EffectState.COMMITTED,
        grant_id=GrantId("grt_1"),
        external_reference="pay-123",
    )
    assert not _attestation(effects=(record,)).has_unresolved_effects


@pytest.mark.unit
def test_effects_can_be_filtered_by_state() -> None:
    unknown = EffectRecord(action=_action(), state=EffectState.UNKNOWN, submitted_at=AT)
    failed = EffectRecord(action=_action(), state=EffectState.FAILED)
    attestation = _attestation(verdict=Verdict.INCOMPLETE, effects=(unknown, failed))
    assert attestation.effects_in_state(EffectState.UNKNOWN) == (unknown,)


# ── Content addressing ───────────────────────────────────────────────────────────


@pytest.mark.unit
def test_identical_attestations_hash_identically() -> None:
    assert _attestation().content_hash() == _attestation().content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_changing_the_verdict_changes_the_hash() -> None:
    refusal = Refusal(reason=RefusalReason("out_of_scope"), detail="x")
    other = _attestation(verdict=Verdict.REFUSE, refusal=refusal)
    assert _attestation().content_hash() != other.content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_downgrading_a_warrant_status_changes_the_hash() -> None:
    warrants = _all_core()
    warrants[WarrantKinds.EPISTEMIC] = _report(
        WarrantKinds.EPISTEMIC, WarrantStatus.UNEVALUATABLE, False
    )
    assert _attestation().content_hash() != _attestation(warrants=warrants).content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_changing_the_answer_changes_the_hash() -> None:
    assert _attestation().content_hash() != _attestation(answer="tampered").content_hash()


@pytest.mark.unit
def test_warrant_ordering_does_not_change_the_hash() -> None:
    forward = _all_core()
    reversed_order = dict(reversed(list(forward.items())))
    assert (
        _attestation(warrants=forward).content_hash()
        == _attestation(warrants=reversed_order).content_hash()
    )


# ── Cost ─────────────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_cost_amount_is_a_string_not_a_float() -> None:
    # No float rounding enters a financial record.
    assert isinstance(CostRecord(amount="0.061").amount, str)


@pytest.mark.unit
def test_negative_token_counts_are_rejected() -> None:
    with pytest.raises(ValueError, match="negative"):
        CostRecord(input_tokens=-1)


@pytest.mark.unit
def test_mappings_are_frozen_after_construction() -> None:
    attestation = _attestation(metadata={"trace": "abc"})
    with pytest.raises(TypeError):
        attestation.metadata["trace"] = "xyz"  # type: ignore[index]
