"""The builders must produce values the kernel actually accepts.

A builder that drifts from the type it builds is worse than no builder: every test using
it fails at once, in a way that looks like the kernel broke. So the property under test
is not "the fields are right" but "the kernel takes it" — asserted by construction, and
by round-tripping through the codec, which is the strictest reader in the package.

The second half is about the four invariants that motivated the module. Each one is a
rule a hand-written fixture keeps forgetting, and each is asserted here as an *outcome*:
ask for the state, get a value the kernel accepts.
"""

from __future__ import annotations

import pytest

from attest.assurance.builders import AT, Build
from attest.kernel.codec import AttestationCodec
from attest.kernel.effects import EffectState
from attest.kernel.identifiers import RunId, TenantId
from attest.kernel.verdicts import POST_EFFECT_VERDICTS, Verdict
from attest.kernel.warrants import WarrantKinds, WarrantStatus

pytestmark = pytest.mark.unit


# ── The kernel accepts what they build ──────────────────────────────────────


@pytest.mark.parametrize("verdict", list(Verdict), ids=lambda v: v.value)
def test_every_verdict_produces_a_record_the_kernel_accepts(verdict: Verdict) -> None:
    """All six, including the two that are only reachable after an effect.

    Those two are the states this framework exists to represent honestly, and they were
    the ones a hand-written fixture could not construct without three attempts — so they
    were the ones tests quietly avoided.
    """
    attestation = Build.attestation(verdict=verdict)
    assert attestation.verdict is verdict


@pytest.mark.parametrize("verdict", list(Verdict), ids=lambda v: v.value)
def test_every_built_attestation_survives_the_codec(verdict: Verdict) -> None:
    """The strictest reader in the package, applied to the builder's output.

    Decoding verifies the content hash, so this also rules out a builder that produces
    something constructible but not storable.
    """
    original = Build.attestation(verdict=verdict)
    assert AttestationCodec.decode(AttestationCodec.encode(original)) == original


@pytest.mark.parametrize("state", list(EffectState), ids=lambda s: s.value)
def test_every_effect_state_produces_a_record_the_kernel_accepts(state: EffectState) -> None:
    assert Build.effect(state).state is state


def test_the_other_builders_construct() -> None:
    assert Build.action().tool
    assert Build.grant().grant_id
    assert Build.evidence().value
    assert Build.approval().approved
    assert Build.context().run_id
    assert Build.binding().tenant
    assert Build.seal().event_count
    assert Build.event().event_type
    assert Build.warrant().is_satisfied()


# ── The four invariants that motivated the module ───────────────────────────


def test_a_committed_effect_carries_its_external_reference() -> None:
    """ "Recording a commit we cannot point at is how an audit chain comes to disagree
    with the world.\""""
    assert Build.effect(EffectState.COMMITTED).external_reference


def test_a_committed_effect_references_the_grant_that_authorised_it() -> None:
    """ "An effect without one is unauthorised by definition.\""""
    assert Build.effect(EffectState.COMMITTED).grant_id is not None


def test_an_unknown_effect_records_when_it_was_submitted() -> None:
    """Without it, UNKNOWN is indistinguishable from "never attempted"."""
    assert Build.effect(EffectState.UNKNOWN).submitted_at == AT


def test_a_proposed_effect_does_not_quietly_carry_a_grant_it_never_had() -> None:
    """The fields are derived from the state, not defaulted onto every record.

    A PROPOSED effect holding a grant id would be a fixture asserting the opposite of
    what it says — and a test about refusing an unauthorised action would be built on
    one that was authorised.
    """
    proposed = Build.effect(EffectState.PROPOSED)
    assert proposed.grant_id is None
    assert not proposed.external_reference


POST_EFFECT: list[Verdict] = sorted(POST_EFFECT_VERDICTS, key=lambda v: v.value)


@pytest.mark.parametrize("verdict", POST_EFFECT, ids=[v.value for v in POST_EFFECT])
def test_a_post_effect_verdict_gets_something_to_be_about(verdict: Verdict) -> None:
    """UNKNOWN and INCOMPLETE are reachable only after an attempt.

    Asking for one with no effects is a contradiction; the builder resolves it rather
    than raising, because a caller writing a test about UNKNOWN wants an UNKNOWN record,
    not a lesson.
    """
    assert Build.attestation(verdict=verdict).effects


def test_a_refusal_verdict_gets_a_typed_refusal() -> None:
    """Refusal rates are monitored and refusals trigger downstream obligations."""
    refused = Build.attestation(verdict=Verdict.REFUSE)
    assert refused.refusal is not None
    assert refused.refusal.detail


def test_the_context_names_the_run_the_attestation_claims() -> None:
    """Passing `run_id` alone used to leave the context on `run_1`.

    The kernel refuses a record that "would describe a different run from the one it
    claims", and this is the invariant that is easiest to trip while renaming a fixture.
    """
    attestation = Build.attestation("run_7")
    assert attestation.run_id == RunId("run_7")
    assert attestation.context.run_id == RunId("run_7")


def test_a_caller_supplied_context_is_left_alone_when_it_agrees() -> None:
    """The reconciliation path passes a context deliberately; the builder must not fight it."""
    context = Build.context("run_9", tenant=TenantId("other"))
    attestation = Build.attestation("run_9", context=context)
    assert attestation.context.identity.tenant == TenantId("other")


def test_sealed_produces_a_real_seal_not_a_truthy_placeholder() -> None:
    """A `sealed=True` that left `seal=None` would make every fixture unsealed.

    Any test looking for a seal gap would then fire on all of them — which is the shape
    of fixture that turns a suite green, or red, for reasons unrelated to the code.
    """
    assert Build.attestation().seal is not None
    assert Build.attestation(sealed=False).seal is None


# ── They stay out of the way ────────────────────────────────────────────────


def test_an_override_wins_over_the_default() -> None:
    assert Build.action(tool="issue_refund").tool == "issue_refund"
    assert Build.attestation(answer="something else").answer == "something else"


def test_an_unsatisfied_warrant_is_still_an_evaluated_one() -> None:
    """An unsatisfied warrant and an unevaluated one are different things.

    The kernel refuses `satisfied=True` on anything but EVALUATED for that reason, and a
    builder that set PENDING when asked for unsatisfied would silently change what a
    test was about.
    """
    report = Build.warrant(satisfied=False)
    assert report.status is WarrantStatus.EVALUATED
    assert not report.is_satisfied()


def test_findings_are_attached_where_asked() -> None:
    from attest.kernel.warrants import Severity

    report = Build.warrant(
        WarrantKinds.BOUNDARY,
        satisfied=False,
        findings=(("tenancy_violation", Severity.ERROR),),
    )
    assert [f.code for f in report.findings] == ["tenancy_violation"]


def test_the_fixed_instant_is_used_rather_than_now() -> None:
    """A fixture dated "now" makes a test that passes or fails depending on when it ran."""
    assert Build.attestation().created_at == AT
    assert Build.attestation().created_at == Build.attestation().created_at
