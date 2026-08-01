"""The conformance kit, the red-team corpus, and offline-verifiable export."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from attest.assurance.conformance import ConformanceReport, ProfileConformance
from attest.assurance.export import BundleBuilder, DisclosureProfile, EvidenceBundle
from attest.assurance.redteam import Family, RedTeamCase, RedTeamSuite
from attest.capabilities.audit import ChainSealer, EventRecorder
from attest.capabilities.profile import BaseProfile, GenericProfile
from attest.capabilities.witness import Checkpoint, MerkleTree, Receipt
from attest.kernel.actions import Action
from attest.kernel.attestation import Attestation, AttestationError
from attest.kernel.audit import AuditEvent, EventType
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.evidence import AuthorityLevel
from attest.kernel.identifiers import ActorId, Hash, RunId, TenantId
from attest.kernel.verdicts import Verdict
from attest.kernel.warrants import CORE_WARRANTS, WarrantReport, WarrantStatus

pytestmark = pytest.mark.unit

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
RUN = RunId("run_1")


# ── The conformance kit runs against the shipped profile ─────────────────────


class TestGenericProfileConforms(ProfileConformance):
    """The generic profile must pass its own kit, or the kit proves nothing."""

    profile = GenericProfile()


@pytest.mark.security
def test_the_kit_catches_a_profile_that_fails_open() -> None:
    # The single highest-value check: a profile returning an empty set for an
    # unrecognised action permits every tool added after it was written.
    from attest.capabilities.authority import ObligationSet

    class FailsOpen(BaseProfile):
        name, version = "fails_open", "1.0.0"

        def obligations_for(self, action: Action, context: ExecutionContext) -> ObligationSet:
            if action.tool == "known":
                return super().obligations_for(action, context)
            return ObligationSet(())

    class Suite(ProfileConformance):
        profile = FailsOpen()

    with pytest.raises(AssertionError, match="ship ungated"):
        Suite().test_an_unknown_action_gets_obligations_not_a_free_pass()


@pytest.mark.security
def test_the_kit_catches_a_weaker_default_for_unknown_claims() -> None:
    class WeakerWhenUnsure(BaseProfile):
        name, version = "weak", "1.0.0"

        def required_authority(self, claim_kind: str) -> AuthorityLevel:
            if claim_kind == "conformance.known":
                return AuthorityLevel.AUTHORITATIVE
            return AuthorityLevel.UNVERIFIED

    class Suite(ProfileConformance):
        profile = WeakerWhenUnsure()

    with pytest.raises(AssertionError, match="fail-open"):
        Suite().test_required_authority_is_never_weaker_for_unknown_claims()


def test_the_kit_requires_a_semver_version() -> None:
    class Unversioned(BaseProfile):
        name, version = "unversioned", "latest"

    class Suite(ProfileConformance):
        profile = Unversioned()

    with pytest.raises(AssertionError, match="downgrade detection"):
        Suite().test_profile_declares_a_name_and_semver_version()


# ── The report states what it does NOT establish ─────────────────────────────


@pytest.mark.security
def test_a_passing_report_still_carries_the_not_established_block() -> None:
    # Developers hear "conformance PASS" as "the profile is safe". A green check
    # reaching a compliance pack without this attached is a misrepresentation.
    rendered = ConformanceReport(profile="generic", version="1.0.0", passed=True).render()
    assert "PASS" in rendered
    assert "NOT ESTABLISHED" in rendered
    assert "regulatory compliance" in rendered
    assert "fairness of outcomes" in rendered


def test_failures_are_listed_when_present() -> None:
    report = ConformanceReport(profile="x", version="1.0.0", passed=False, failures=("fails open",))
    assert "fails open" in report.render()


# ── Red team ─────────────────────────────────────────────────────────────────


def test_all_ten_families_are_declared_by_shipped_cases() -> None:
    # Structural. A suite that silently declares six of ten reads as coverage — and a
    # suite that declares ten and runs none reads the same way, which is ATT-45.
    assert RedTeamSuite.families_undeclared() == frozenset()


@pytest.mark.security
def test_every_declared_family_has_at_least_one_case_that_actually_runs() -> None:
    """ATT-45. The corpus was a manifest of test titles.

    RedTeamCase held `must_not` and nothing executed an adversarial input against
    anything, so `family=EVIDENCE_FORGERY, name="fabricated citation",
    must_not=(ALLOW,)` — which is ATT-33 exactly — was declared and never run. The
    mechanism that should have caught two Critical findings certified itself instead.
    """
    unrunnable = RedTeamSuite.families_unexecutable()
    assert not unrunnable, (
        f"these families are declared and cannot be executed: "
        f"{sorted(f.value for f in unrunnable)}. A family the suite reports on and "
        f"never tests is worse than an absent one."
    )


def test_the_shipped_corpus_includes_the_state_and_effect_families() -> None:
    # Families 5, 7 and 10 need fault injection and a real store. Shipping only the
    # cheap prompt-level ones would leave the expensive half to every adopter.
    covered = RedTeamSuite.families_covered()
    assert Family.STATE_CORRUPTION in covered
    assert Family.PROVENANCE in covered
    assert Family.EXECUTION in covered


def test_a_case_that_forbids_nothing_is_rejected() -> None:
    # Worse than absent, because it counts toward coverage.
    with pytest.raises(ValueError, match="worse than absent"):
        RedTeamCase(family=Family.INJECTION, name="does nothing")


def test_the_timeout_case_forbids_both_allow_and_refuse() -> None:
    # Neither is truthful. The honest answer is UNKNOWN.
    case = next(c for c in RedTeamSuite.shipped() if "times out" in c.name)
    assert Verdict.ALLOW in case.must_not
    assert Verdict.REFUSE in case.must_not


def test_a_domain_extends_the_corpus_without_touching_the_framework() -> None:
    class MortgageRedTeam(RedTeamSuite):
        extra_cases = (
            RedTeamCase(
                family=Family.BOUNDARY_ESCAPE,
                name="protected characteristic inferred from postcode",
                must_not=(Verdict.ALLOW,),
            ),
        )

    assert len(MortgageRedTeam.all_cases()) == len(RedTeamSuite.shipped()) + 1


# ── Export refuses to overclaim ──────────────────────────────────────────────


def _context() -> ExecutionContext:
    tenant = TenantId("acme")
    return ExecutionContext(
        run_id=RUN,
        captured_at=AT,
        identity=IdentitySnapshot(actor=ActorId("alice"), tenant=tenant),
        binding=TenantBinding(
            tenant=tenant,
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
        ),
        framework_version="0.1.0",
        policy_version="1.0.0",
    )


def _sealed_run() -> tuple[Attestation, tuple[AuditEvent, ...]]:
    recorder = EventRecorder(run_id=RUN)
    recorder.record(EventType.RUN_DISPATCHED, {}, at=AT)
    recorder.record(EventType.RUN_COMPLETED, {}, at=AT)
    warrants = {
        k: WarrantReport(kind=k, status=WarrantStatus.EVALUATED, satisfied=True)
        for k in CORE_WARRANTS
    }
    draft = Attestation(
        run_id=RUN,
        verdict=Verdict.ALLOW,
        context=_context(),
        created_at=AT,
        warrants=warrants,
    )
    chain, seal = ChainSealer().seal(
        recorder.events, run_id=RUN, attestation_hash=draft.content_hash(), sealed_at=AT
    )
    final = Attestation(
        run_id=RUN,
        verdict=Verdict.ALLOW,
        context=_context(),
        created_at=AT,
        warrants=warrants,
        seal=seal,
    )
    return final, chain


def test_a_sealed_final_run_exports() -> None:
    attestation, chain = _sealed_run()
    bundle = BundleBuilder().build(attestation, chain=chain)
    assert "VERIFY.md" in bundle.files
    assert bundle.verify_manifest() == ()


@pytest.mark.security
def test_a_non_final_attestation_cannot_be_exported() -> None:
    attestation, chain = _sealed_run()
    pending = {
        k: WarrantReport(kind=k, status=WarrantStatus.PENDING, satisfied=False)
        for k in CORE_WARRANTS
    }
    provisional = Attestation(
        run_id=RUN,
        verdict=Verdict.ALLOW,
        context=_context(),
        created_at=AT,
        warrants=pending,
        seal=attestation.seal,
    )
    with pytest.raises(AttestationError, match="still pending"):
        BundleBuilder().build(provisional, chain=chain)


@pytest.mark.security
def test_an_unsealed_run_cannot_be_exported() -> None:
    _, chain = _sealed_run()
    unsealed = Attestation(run_id=RUN, verdict=Verdict.ALLOW, context=_context(), created_at=AT)
    with pytest.raises(AttestationError, match="not evidence"):
        BundleBuilder().build(unsealed, chain=chain)


@pytest.mark.security
def test_tampering_with_a_bundle_file_is_detected() -> None:
    attestation, chain = _sealed_run()
    bundle = BundleBuilder().build(attestation, chain=chain)
    tampered = EvidenceBundle(
        run_id=bundle.run_id,
        files={**bundle.files, "chain.jsonl": b"rewritten"},
        manifest=bundle.manifest,
    )
    assert "chain.jsonl" in tampered.verify_manifest()


def test_verify_instructions_include_the_seal_coverage_step() -> None:
    # The step that detects an omitted event. Linkage alone cannot.
    attestation, chain = _sealed_run()
    verify = BundleBuilder().build(attestation, chain=chain).files["VERIFY.md"].decode()
    assert "OMITTED event" in verify
    assert "linkage alone is" in verify


def test_witness_steps_appear_only_when_the_bundle_is_witnessed() -> None:
    # An instruction a verifier cannot follow reads as a failed verification.
    attestation, chain = _sealed_run()
    plain = BundleBuilder().build(attestation, chain=chain).files["VERIFY.md"].decode()
    assert "inclusion proof" not in plain
    tree = MerkleTree([MerkleTree.leaf_hash(b"a"), MerkleTree.leaf_hash(b"b")])
    bundle = BundleBuilder().build(
        attestation,
        chain=chain,
        inclusion_proof=tree.inclusion_proof(0),
        checkpoint=Checkpoint(root=tree.root(), tree_size=2, created_at=AT),
        receipt=Receipt(
            run_id=attestation.run_id,
            leaf=tree.leaves[0],
            promised_by="window-1",
            issued_at=AT,
        ),
    )
    witnessed = bundle.files["VERIFY.md"].decode()
    assert "INDEPENDENTLY published checkpoint" in witnessed
    assert "NOT from this bundle" in witnessed
    # Every step is followable because every file it names is in the bundle.
    assert "witness/inclusion_proof.json" in bundle.files
    assert "witness/checkpoint.json" in bundle.files
    assert "witness/receipt.json" in bundle.files
    assert "signed a promise it did not keep" in witnessed


def test_redacted_files_keep_their_original_hashes() -> None:
    # Dropping them from the manifest would make redaction indistinguishable from
    # tampering.
    attestation, chain = _sealed_run()
    bundle = BundleBuilder().build(attestation, chain=chain)
    redacted = EvidenceBundle(
        run_id=bundle.run_id,
        files={k: v for k, v in bundle.files.items() if k != "chain.jsonl"},
        manifest=bundle.manifest,
        redacted=frozenset({"chain.jsonl"}),
    )
    assert "chain.jsonl" in redacted.manifest
    assert redacted.verify_manifest() == ()


# ── The disclosure profile is read, not merely accepted ──────────────────────


def _refused_run() -> tuple[Attestation, tuple[AuditEvent, ...]]:
    """A sealed run carrying operator-facing text in every place it can appear."""
    from attest.kernel.verdicts import Refusal, RefusalReason
    from attest.kernel.warrants import Finding, Severity

    recorder = EventRecorder(run_id=RUN)
    recorder.record(EventType.RUN_DISPATCHED, {}, at=AT)
    recorder.record(EventType.RUN_COMPLETED, {}, at=AT)
    warrants = {
        k: WarrantReport(
            kind=k,
            status=WarrantStatus.EVALUATED,
            satisfied=True,
            findings=(
                Finding(
                    code="capability:settle_claim",
                    message="actor 'ops-7' does not hold 'settle_claim'",
                    severity=Severity.WARNING,
                ),
            ),
        )
        for k in CORE_WARRANTS
    }
    refusal = Refusal(
        reason=RefusalReason("insufficient_authority"),
        detail="actor 'ops-7' does not hold 'settle_claim'",
        subject_message="this request could not be authorised",
    )
    draft = Attestation(
        run_id=RUN,
        verdict=Verdict.ALLOW_WITH_WARNINGS,
        context=_context(),
        created_at=AT,
        warrants=warrants,
        refusal=refusal,
    )
    chain, seal = ChainSealer().seal(
        recorder.events, run_id=RUN, attestation_hash=draft.content_hash(), sealed_at=AT
    )
    return replace(draft, seal=seal), chain


@pytest.mark.security
def test_a_subject_bundle_withholds_the_operator_facing_reasoning() -> None:
    """ATT-08. The profile was accepted, stored, and never read.

    Every bundle was the INTERNAL bundle whatever was requested, so a subject
    exercising a data-access right received the internal reasoning behind the refusal
    and internal actor identifiers — while the operator who passed SUBJECT believed
    redaction had happened. Worse than an absent feature: the presence of the parameter
    suppressed the review that would otherwise have caught it.
    """
    attestation, chain = _refused_run()
    bundle = BundleBuilder(disclosure=DisclosureProfile.SUBJECT).build(attestation, chain=chain)
    payload = bundle.files["attestation.json"].decode()
    assert "ops-7" not in payload, "an internal actor identifier reached a subject bundle"
    assert "this request could not be authorised" in payload


def test_an_internal_bundle_keeps_everything() -> None:
    """The text exists for triage; it is the audience that changes."""
    attestation, chain = _refused_run()
    bundle = BundleBuilder(disclosure=DisclosureProfile.INTERNAL).build(attestation, chain=chain)
    assert "ops-7" in bundle.files["attestation.json"].decode()


@pytest.mark.security
def test_withheld_evidence_is_named_in_the_manifest_rather_than_vanishing() -> None:
    """Dropping a file entirely makes redaction indistinguishable from tampering."""
    attestation, chain = _refused_run()
    bundle = BundleBuilder(disclosure=DisclosureProfile.SUBJECT).build(
        attestation, chain=chain, sources={"policy.pdf": b"other subjects' data"}
    )
    assert "evidence/policy.pdf" not in bundle.files
    assert "evidence/policy.pdf" in bundle.manifest, "the withheld file lost its hash"
    assert "evidence/policy.pdf" in bundle.redacted
    assert bundle.verify_manifest() == (), "a withheld file reported as altered"


@pytest.mark.security
def test_an_unsigned_bundle_says_its_integrity_claims_are_self_referential() -> None:
    """ATT-23. manifest.json travelled in the same archive as the files it describes.

    An attacker who edited a file edited its manifest entry too, and every check passed.
    The instructions omitted the signature step silently rather than saying so.
    """
    attestation, chain = _sealed_run()
    verify = BundleBuilder().build(attestation, chain=chain).files["VERIFY.md"].decode()
    assert "UNSIGNED" in verify
    assert "INTERNALLY CONSISTENT" in verify


@pytest.mark.security
def test_the_manifest_in_the_bundle_matches_the_manifest_object() -> None:
    """ATT-28. A verifier and a caller were checking two different sets.

    manifest.json was written without its own entry and then gained one in memory when
    signing.
    """
    import json

    attestation, chain = _sealed_run()
    bundle = BundleBuilder().build(attestation, chain=chain)
    written = json.loads(bundle.files["manifest.json"])
    assert set(written) == set(bundle.manifest), "the file and the object disagree"
    assert "manifest.json" not in written, "the manifest cannot list its own hash"
