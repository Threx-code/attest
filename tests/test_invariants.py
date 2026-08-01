"""The final adversarial review, as an executable register.

For every security invariant the design claims, ``docs/assurance/threat-model.md``
demands three answers: what is the invariant, where is it enforced, and what
independently verifiable evidence proves it held. An invariant without all three is an
architectural gap.

This file is the fourth answer — **what test proves it** — and it is a single place a
reviewer can read to see the claim, the enforcement point, and the check, together. A
register in prose drifts from the code within one release; this one cannot.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True, slots=True)
class Invariant:
    """One claimed security property and where it lives."""

    name: str
    enforced_in: str
    proven_by: str
    attack: str = ""


REGISTER: tuple[Invariant, ...] = (
    Invariant(
        name="a grant authorises only the exact action it was issued for",
        enforced_in="attest.kernel.authority.AuthorizationGrant.check_against",
        proven_by="tests/kernel/test_authority.py::test_a_grant_does_not_authorise_a_different_beneficiary",
        attack="5, 10 — wrong beneficiary, argument mutation",
    ),
    Invariant(
        name="arguments cannot be mutated after the hash is taken",
        enforced_in="attest.kernel.actions.Action.__post_init__ (MappingProxyType)",
        proven_by="tests/kernel/test_actions.py::test_arguments_cannot_be_mutated_after_construction",
        attack="10",
    ),
    Invariant(
        name="a grant is single-use, and redemption is atomic",
        enforced_in="attest.adapters.memory.InMemoryNonceStore.redeem, under one lock",
        proven_by="tests/adapters/test_concurrency.py::test_only_one_of_many_concurrent_redemptions_succeeds",
        attack="8 — approval replay",
    ),
    Invariant(
        name="the nonce is consumed BEFORE the external call",
        enforced_in="attest.capabilities.execution.ExecutionBoundary.execute",
        proven_by="tests/capabilities/test_execution.py::test_the_nonce_is_consumed_before_the_external_call",
        attack="8 — a replay arriving mid-flight",
    ),
    Invariant(
        name="a grant issued before every obligation discharges cannot be constructed",
        enforced_in="attest.kernel.authority.AuthorizationGrant.__post_init__",
        proven_by="tests/kernel/test_authority.py::test_a_grant_cannot_carry_an_undischarged_obligation",
        attack="authority bypass",
    ),
    Invariant(
        name="an obligation that raises is FAILED, never skipped",
        enforced_in="attest.capabilities.authority.AuthorityEngine.discharge",
        proven_by="tests/capabilities/test_authority.py::test_an_obligation_that_raises_is_failed_not_skipped",
        attack="fail-open sweep",
    ),
    Invariant(
        name="two concurrent runs cannot both pass one budget ceiling",
        enforced_in="attest.adapters.memory.InMemoryBudgetStore.reserve",
        proven_by="tests/adapters/test_concurrency.py::test_concurrent_reservations_cannot_both_pass_the_same_ceiling",
        attack="9 — concurrent budget exhaustion",
    ),
    Invariant(
        name="a timeout yields UNKNOWN, never ALLOW or REFUSE",
        enforced_in="attest.capabilities.execution.ExecutionBoundary.execute",
        proven_by="tests/capabilities/test_execution.py::test_a_timeout_yields_unknown_not_success_or_failure",
        attack="12 — payment API timeout",
    ),
    Invariant(
        name="a commit without an external reference is UNKNOWN, not COMMITTED",
        enforced_in="attest.kernel.attestation.EffectRecord.__post_init__",
        proven_by="tests/capabilities/test_execution.py::test_success_without_an_external_reference_is_unknown",
        attack="15 — audit succeeds, payment fails",
    ),
    Invariant(
        name="a non-idempotent effect is never auto-retried after a timeout",
        enforced_in="attest.kernel.effects.EffectSemantics.may_retry_on_timeout",
        proven_by="tests/kernel/test_actions.py::test_retry_requires_both_levels_to_agree",
        attack="13 — duplicate retry",
    ),
    Invariant(
        name="every COMMITTED effect references the grant that authorised it",
        enforced_in="attest.kernel.attestation.EffectRecord.__post_init__",
        proven_by="tests/kernel/test_attestation.py::test_a_committed_effect_must_reference_its_grant",
        attack="11 — executor invoked directly",
    ),
    Invariant(
        name="an omitted event is detectable even when linkage is rebuilt",
        enforced_in="attest.kernel.audit.RunSeal (bound count + dense range)",
        proven_by="tests/kernel/test_audit.py::test_a_re_linked_omission_is_still_caught_by_the_count",
        attack="20 — audit event omitted",
    ),
    Invariant(
        name="the application never assigns its own sequence numbers",
        enforced_in="attest.capabilities.audit.ChainSealer.seal",
        proven_by="tests/capabilities/test_audit_witness.py::test_recorded_events_start_unsealed",
        attack="20 — self-certification",
    ),
    Invariant(
        name="causal order survives a mid-run effect write",
        enforced_in="attest.capabilities.audit.ChainSealer.canonical_order",
        proven_by="tests/capabilities/test_audit_witness.py::test_causal_order_survives_a_mid_run_effect_write",
        attack="ADR 0034",
    ),
    Invariant(
        name="a run cannot act for one tenant under another's policy",
        enforced_in="attest.kernel.context.ExecutionContext.__post_init__",
        proven_by="tests/kernel/test_context.py::test_a_run_cannot_act_for_one_tenant_under_anothers_policy",
        attack="4 — wrong tenant",
    ),
    Invariant(
        name="cross-tenant evidence fails the boundary warrant unconditionally",
        enforced_in="attest.capabilities.guards.GuardSuite.evaluate",
        proven_by="tests/capabilities/test_guards_memory.py::test_a_tenancy_violation_fails_the_warrant",
        attack="4",
    ),
    Invariant(
        name="an agent cannot write instruction memory",
        enforced_in="attest.capabilities.memory.MemoryGuard.screen_write",
        proven_by="tests/capabilities/test_guards_memory.py::test_an_agent_cannot_write_instruction_memory",
        attack="3 — poisoned memory",
    ),
    Invariant(
        name="a child cannot delegate beyond its parent's reach",
        enforced_in="attest.runtime.agents.Scope.narrowed_to",
        proven_by="tests/runtime/test_runtime.py::test_a_child_cannot_delegate_beyond_its_parents_reach",
        attack="delegation escalation",
    ),
    Invariant(
        name="a warrant whose check did not run cannot claim to be satisfied",
        enforced_in="attest.kernel.warrants.WarrantReport.__post_init__",
        proven_by="tests/kernel/test_warrants.py::test_unevaluated_warrant_cannot_claim_satisfied",
        attack="fail-open sweep",
    ),
    Invariant(
        name="a non-final attestation cannot be exported as evidence",
        enforced_in="attest.kernel.attestation.Attestation.assert_exportable",
        proven_by="tests/assurance/test_assurance.py::test_a_non_final_attestation_cannot_be_exported",
        attack="ADR 0035",
    ),
    Invariant(
        name="content integrity does not imply source authority",
        enforced_in="attest.capabilities.evidence.EvidenceEngine.evaluate",
        proven_by="tests/capabilities/test_evidence_completeness.py::test_a_genuine_quote_from_an_unauthoritative_source_fails",
        attack="22 — forged source authority",
    ),
    Invariant(
        name="retrieval truncation fails the coverage warrant",
        enforced_in="attest.capabilities.completeness.CoverageReport.warrant",
        proven_by="tests/capabilities/test_evidence_completeness.py::test_truncation_fails_the_warrant",
        attack="18 — silent truncation",
    ),
    Invariant(
        name="a judge from the generator's own model family is refused",
        enforced_in="attest.capabilities.judging.JudgePanel.assert_independent",
        proven_by="tests/capabilities/test_profile_judging_gateway.py::test_the_check_is_on_the_family_not_the_provider",
        attack="19 — correlated judging; ADR 0041",
    ),
    Invariant(
        name="failover never crosses a residency boundary",
        enforced_in="attest.capabilities.gateway.ProviderRouter.select",
        proven_by="tests/capabilities/test_profile_judging_gateway.py::test_no_permitted_provider_refuses_rather_than_failing_over",
        attack="residency breach",
    ),
    Invariant(
        name="a profile cannot fail open on an unrecognised action",
        enforced_in="attest.assurance.conformance.ProfileConformance",
        proven_by="tests/assurance/test_assurance.py::test_the_kit_catches_a_profile_that_fails_open",
        attack="conformance safety block",
    ),
    Invariant(
        name="distinct values never share a content hash",
        enforced_in="attest.kernel.canonical.Canonical.form",
        proven_by="tests/kernel/test_canonical.py::test_value_does_not_collide_with_its_string_form",
        attack="evidence forgery",
    ),
    Invariant(
        name="an attestation cannot be edited, by any code path",
        enforced_in="attest.adapters.django.triggers.ImmutableColumns (BEFORE UPDATE trigger)",
        proven_by="tests/adapters/django/test_triggers.py::test_an_attestation_cannot_be_edited_through_the_orm",
        attack="17 — record tampering below the application",
    ),
    Invariant(
        name="an audit event cannot be updated or deleted, by any code path",
        enforced_in="attest.adapters.django.triggers.AppendOnlyTable (BEFORE UPDATE OR DELETE)",
        proven_by="tests/adapters/django/test_triggers.py::test_an_audit_event_cannot_be_deleted",
        attack="12 — chain truncation; the case density detects after the fact",
    ),
    Invariant(
        name="a serialiser cannot drop the verdict or the warnings",
        enforced_in="attest.adapters.django.serializers.AttestationSerializer.MANDATORY",
        proven_by="tests/adapters/django/test_serializers_and_views.py::test_a_sparse_field_request_cannot_drop_the_warnings",
        attack="20 — a qualified figure rendered as an unqualified one",
    ),
    Invariant(
        name="an expired approval cannot be resolved by a late click",
        enforced_in="attest.adapters.django.stores.DjangoApprovalStore.resolve",
        proven_by="tests/adapters/django/test_stores.py::test_an_expired_approval_cannot_be_resolved_by_a_late_click",
        attack="13 — authorising an effect whose window has closed",
    ),
    Invariant(
        name="a query returns only the requesting tenant's records",
        enforced_in="attest.adapters.django.views.TenantScopedViewSet.get_queryset",
        proven_by="tests/adapters/django/test_serializers_and_views.py::test_a_request_sees_only_its_own_tenants_records",
        attack="15 — cross-tenant read",
    ),
    Invariant(
        name="a provider refusal is never recorded as an answer",
        enforced_in="attest.adapters.providers.base.BaseProvider._respond",
        proven_by="tests/adapters/providers/test_providers.py::test_a_policy_refusal_raises_rather_than_returning_an_empty_answer",
        attack="an unverified result presented as a definitive one",
    ),
    Invariant(
        name="a stored attestation cannot come back as a different record",
        enforced_in="attest.kernel.codec.AttestationCodec.decode (content-hash check)",
        proven_by="tests/kernel/test_codec.py::test_a_tampered_payload_is_refused_on_decode",
        attack="17 — record tampering, detected on read rather than trusted",
    ),
    Invariant(
        name="a rewritten audit event is caught even with its linkage left intact",
        enforced_in="attest.adapters.django.chain.StoredChainCheck (recomputed hashes)",
        proven_by="tests/adapters/django/test_settings_and_commands.py::test_a_rewritten_event_is_caught_because_hashes_are_recomputed",
        attack="12 — chain rewriting below the application",
    ),
    Invariant(
        name="no effect is executed before every blocking warrant holds",
        enforced_in="attest.runtime.engine.RunEngine._authorise_and_execute",
        proven_by="tests/runtime/test_engine.py::test_a_blocked_warrant_stops_the_run_before_the_executor",
        attack="1, 11 — acting first and justifying afterwards",
    ),
    Invariant(
        name="an upstream timeout is UNKNOWN, never a failure",
        enforced_in="attest.runtime.engine.RunEngine._perform",
        proven_by="tests/runtime/test_engine.py::test_an_upstream_timeout_becomes_unknown_and_never_a_failure",
        attack="14 — a committed transfer reported as not having happened",
    ),
    Invariant(
        name="an unauthenticated caller cannot dispatch a governed run",
        enforced_in="attest.adapters.django.views.GovernedMixin.permission_classes",
        proven_by="tests/adapters/django/test_dispatch.py::test_an_unauthenticated_dispatch_is_refused",
        attack="15 — a public endpoint that can move money",
    ),
    Invariant(
        name="a caller cannot propose a run for a tenant it does not hold",
        enforced_in="attest.adapters.django.views.DispatchView.assert_own_tenant",
        proven_by="tests/adapters/django/test_dispatch.py::test_a_proposal_for_another_tenant_is_refused_before_the_engine",
        attack="15 — the confused deputy, authenticated",
    ),
    Invariant(
        name="a subject is not shown the system's internal reasoning about them",
        enforced_in="attest.adapters.django.serializers.RunResultSerializer (DisclosureProfile)",
        proven_by="tests/adapters/django/test_dispatch.py::test_the_default_disclosure_withholds_internal_reasoning",
        attack="disclosure — operator detail leaking to a subject-facing route",
    ),
    Invariant(
        name="a REFUSE verdict cannot be written over an effect that reached the world",
        enforced_in="attest.kernel.attestation.Attestation.__post_init__",
        proven_by="tests/test_adversarial_review.py::test_an_attestation_cannot_refuse_over_an_effect_that_reached_the_world",
        attack="the most dangerous record the system could produce: a refusal over a "
        "committed transfer",
    ),
    Invariant(
        name="a failed warrant after a committed effect is INCOMPLETE, not REFUSE",
        enforced_in="attest.runtime.engine.VerdictResolver.resolve",
        proven_by="tests/test_adversarial_review.py::test_a_failed_warrant_after_a_committed_effect_resolves_to_incomplete",
        attack="'nothing happened' and 'some of it happened' need different responses",
    ),
    Invariant(
        name="a grant is never issued for an action bound to another tenant or actor",
        enforced_in="attest.capabilities.authority.AuthorityEngine.issue",
        proven_by="tests/test_adversarial_review.py::test_a_grant_is_not_issued_for_an_action_belonging_to_another_tenant",
        attack="4, 15 — the confused deputy; every downstream check compares the "
        "action against itself and agrees",
    ),
    Invariant(
        name="the boundary refuses a foreign action even with a self-consistent grant",
        enforced_in="attest.capabilities.execution.ExecutionBoundary.execute",
        proven_by="tests/test_adversarial_review.py::test_the_boundary_refuses_a_foreign_action_even_with_a_matching_grant",
        attack="4, 15 — the last gate, deliberately redundant with the mint check",
    ),
    Invariant(
        name="a released reservation id is never reissued",
        enforced_in="attest.adapters.django.stores.DjangoBudgetStore.reserve",
        proven_by="tests/adapters/django/test_adversarial_review.py::test_a_stale_commit_cannot_consume_a_live_reservation",
        attack="9 — a swept worker's late commit consuming a live hold",
    ),
    Invariant(
        name="a judge's independence rests on the weights, not on the vendor",
        enforced_in="attest.adapters.providers.families.ModelFamilies.resolve",
        proven_by="tests/adapters/providers/test_families.py::test_gpt_oss_is_not_resolved_as_gpt",
        attack="19 — a model marking its own homework via a second endpoint",
    ),
)


def test_every_invariant_names_all_four_answers() -> None:
    """An invariant missing any answer is an architectural gap, per the threat model."""
    for invariant in REGISTER:
        assert invariant.name, "unnamed invariant"
        assert invariant.enforced_in, f"{invariant.name}: no enforcement point"
        assert invariant.proven_by, f"{invariant.name}: no proving test"


def test_every_named_test_actually_exists() -> None:
    """The register must not drift from the suite.

    A register that names a test which was renamed or deleted is worse than none: it
    reads as coverage while proving nothing. Collected node ids are checked rather
    than grepped, so a test that exists but cannot be collected also fails here.
    """
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "--no-header"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    # Parametrised tests collect as `path::name[case]`, so match the base id.
    node_ids = {line.split("[", 1)[0] for line in collected.stdout.splitlines()}
    missing = [invariant.proven_by for invariant in REGISTER if invariant.proven_by not in node_ids]
    assert not missing, (
        "the invariant register names tests that do not exist:\n  "
        + "\n  ".join(missing)
        + "\n\nA register naming a renamed or deleted test reads as coverage while "
        "proving nothing."
    )


def test_the_register_covers_the_highest_severity_attacks() -> None:
    """Spot-check that the register reaches the attacks that lose money."""
    covered = " ".join(i.attack for i in REGISTER)
    for attack in ("5", "8", "9", "11", "12", "13", "15", "20"):
        assert attack in covered, f"threat-model attack {attack} has no invariant"


@pytest.mark.security
def test_every_declared_event_type_is_emitted_by_something() -> None:
    """A declared-and-never-emitted event type is a monitored signal that reads zero.

    Every alert in ``docs/assurance/observability.md`` is a count over these, and a
    count over an event nothing writes is indistinguishable from "it never happened" —
    which is the most reassuring possible way for a control to be broken.
    """
    import re
    from pathlib import Path as _Path

    from attest.kernel.audit import EventType

    sources = {
        path: path.read_text()
        for path in _Path("src/attest").rglob("*.py")
        if path.name != "audit.py" or "kernel" not in str(path)
    }
    never = [
        member.value
        for member in EventType
        if not any(re.search(rf"EventType\.{member.name}\b", text) for text in sources.values())
    ]
    assert not never, (
        f"declared but never emitted: {sorted(never)}. Either something must write it, "
        f"or it must not be declared — a monitored signal that can only ever read zero "
        f"is worse than an absent one."
    )


@pytest.mark.security
def test_no_event_type_is_written_as_a_bare_string() -> None:
    """``EventType`` says "typed, never free text", and a literal silently opts out.

    Three call sites had drifted this way. A rename of the member would not have
    touched them, so the enum and the chain would disagree and nothing would fail.
    """
    import re
    from pathlib import Path as _Path

    from attest.kernel.audit import EventType

    values = {member.value for member in EventType}
    offenders: list[str] = []
    for path in _Path("src/attest").rglob("*.py"):
        if path.name == "audit.py" and "kernel" in str(path):
            continue  # where the members are declared
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            for match in re.findall(r"""["']([a-z_]+\.[a-z_]+)["']""", line):
                if match in values and "EventType" not in line:
                    offenders.append(f"{path}:{number}  {match}")
    assert not offenders, "event types written as bare strings:\n  " + "\n  ".join(offenders)


@pytest.mark.security
def test_no_security_control_is_implemented_and_called_by_nothing() -> None:
    """ATT-37. The finding that explains most of the others.

    Fifteen distinct controls were present, correct in isolation, covered by green
    tests, and absent from every execution path — an ApprovalStore the engine held and
    never called, a BudgetStore.commit with no callers, a DisclosureProfile read by
    nothing, a MemoryGuard wired to no store.

    The tests are what made it invisible: each control was tested *directly*, so CI
    proved the mechanism worked and never asked whether anything invoked it.
    DelegationChain.delegate had eight tests and no caller; ConsistencyProof.verifies
    had three, which meant the mechanism that defeats history rewriting was never run
    by the system it defends.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "scripts/check_reachability.py"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout


@pytest.mark.security
def test_the_reachability_gate_catches_an_unwired_control() -> None:
    """A gate that cannot fail proves nothing. This is the gate's own test."""
    import importlib.util
    import sys
    from pathlib import Path as _Path

    spec = importlib.util.spec_from_file_location(
        "check_reachability", _Path("scripts/check_reachability.py")
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_reachability"] = module
    spec.loader.exec_module(module)

    checker = module.Reachability()
    checker.CONTROLS = {
        **checker.CONTROLS,
        "a_control_nothing_calls_9f2a1c": "a planted orphan",
    }
    assert any("9f2a1c" in problem for problem in checker.report())
