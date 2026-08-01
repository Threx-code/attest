"""The context is what makes verification reproducible.

Two properties are load-bearing. Every reconstruction axis must be *inside* the
hash, so none can drift from the run it describes; and a run must not be able to act
for one tenant under another's policy.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ModelRef,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.evidence import (
    AuthorityLevel,
    Evidence,
    EvidenceKinds,
    SourceRef,
    SourceType,
)
from attest.kernel.identifiers import ActorId, CorpusId, EvidenceId, Hash, RunId, TenantId

CAPTURED = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
ACME = TenantId("acme")


def _binding(**kw: object) -> TenantBinding:
    base: dict[str, object] = {
        "tenant": ACME,
        "profile": ProfileRef(name="insurance", version="2.1.0", jurisdiction="UK"),
        "config_hash": Hash("c" * 64),
    }
    return TenantBinding(**{**base, **kw})  # type: ignore[arg-type]


def _identity(**kw: object) -> IdentitySnapshot:
    base: dict[str, object] = {"actor": ActorId("alice"), "tenant": ACME}
    return IdentitySnapshot(**{**base, **kw})  # type: ignore[arg-type]


def _context(**kw: object) -> ExecutionContext:
    base: dict[str, object] = {
        "run_id": RunId("run_1"),
        "captured_at": CAPTURED,
        "identity": _identity(),
        "binding": _binding(),
        "framework_version": "0.1.0",
        "policy_version": "1.0.0",
    }
    return ExecutionContext(**{**base, **kw})  # type: ignore[arg-type]


def _evidence(value: str = "covers escape of water") -> Evidence:
    return Evidence(
        evidence_id=EvidenceId("e1"),
        kind=EvidenceKinds.QUOTED_SPAN,
        source=SourceRef(
            source_id="PW-2019",
            source_type=SourceType.POLICY_DOC,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="7",
            retrieved_at=CAPTURED,
            integrity_hash=Hash("a" * 64),
        ),
        value=value,
    )


# ── Tenant coherence ─────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_a_run_cannot_act_for_one_tenant_under_anothers_policy() -> None:
    with pytest.raises(ValueError, match="under another's policy"):
        _context(identity=_identity(tenant=TenantId("other-corp")))


@pytest.mark.unit
def test_matching_tenants_are_accepted() -> None:
    assert _context().identity.tenant == _context().binding.tenant


# ── Everything reconstructible is inside the hash ────────────────────────────────


@pytest.mark.unit
def test_identical_contexts_hash_identically() -> None:
    assert _context().content_hash() == _context().content_hash()


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("framework_version", "0.2.0"),
        ("policy_version", "1.1.0"),
        ("pricing_version", "2026-08"),
        ("flow_spec_version", "v8"),
        ("seed", 42),
        ("captured_at", datetime(2026, 7, 31, 12, 0, 1, tzinfo=UTC)),
        ("run_id", RunId("run_2")),
    ],
)
def test_every_reconstruction_axis_is_bound(field: str, value: object) -> None:
    # docs/kernel/versioning.md requires nine axes to be recorded so a run is
    # reconstructible without guessing. They live here, hashed as one unit, so none
    # can drift from the run it describes.
    assert _context().content_hash() != _context(**{field: value}).content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_changing_the_profile_version_changes_the_hash() -> None:
    other = _binding(profile=ProfileRef(name="insurance", version="2.2.0", jurisdiction="UK"))
    assert _context().content_hash() != _context(binding=other).content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_changing_the_jurisdiction_changes_the_hash() -> None:
    # Threat-model attack 17: same profile, wrong body of rules.
    ng = _binding(profile=ProfileRef(name="insurance", version="2.1.0", jurisdiction="NG"))
    assert _context().content_hash() != _context(binding=ng).content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_changing_the_actors_capabilities_changes_the_hash() -> None:
    elevated = _identity(capabilities=frozenset({"settle_claim"}))
    assert _context().content_hash() != _context(identity=elevated).content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_tampering_with_evidence_changes_the_context_hash() -> None:
    original = _context(evidence=(_evidence(),))
    tampered = _context(evidence=(_evidence("does NOT cover escape of water"),))
    assert original.content_hash() != tampered.content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_a_stale_corpus_epoch_changes_the_hash() -> None:
    # Attack 18: answering from a pre-amendment corpus must be distinguishable.
    q2 = _context(corpus_epochs={CorpusId("policies"): "2026-Q2"})
    q3 = _context(corpus_epochs={CorpusId("policies"): "2026-Q3"})
    assert q2.content_hash() != q3.content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_prompt_and_tool_hashes_are_bound() -> None:
    with_prompt = _context(prompt_hashes={"adjudicate": Hash("d" * 64)})
    with_tools = _context(tool_spec_hashes={"transfer": Hash("e" * 64)})
    assert _context().content_hash() != with_prompt.content_hash()
    assert _context().content_hash() != with_tools.content_hash()


# ── Model provenance ─────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_a_run_may_have_no_model() -> None:
    # A rules engine or a scheduled job proposes through the same kernel.
    assert _context().model is None
    assert _context().content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_failover_is_recorded_and_bound() -> None:
    # A decision made by a fallback model is a materially different decision.
    primary = ModelRef(provider="anthropic", model_id="m", failover=False)
    fallback = ModelRef(provider="anthropic", model_id="m", failover=True)
    assert _context(model=primary).content_hash() != _context(model=fallback).content_hash()


@pytest.mark.unit
def test_training_attestation_defaults_to_none_for_a_third_party_model() -> None:
    # None is the honest value for a commercial API model whose training data we
    # cannot vouch for. It must never read as "trained on nothing".
    assert ModelRef(provider="anthropic", model_id="m").training_attestation is None


@pytest.mark.unit
@pytest.mark.security
def test_training_provenance_is_bound_into_the_context() -> None:
    # The forward link from docs/capabilities/lineage.md: an inference attestation
    # reaches its training provenance in one hop, and that link is tamper-evident.
    untraced = ModelRef(provider="internal", model_id="fraud_score@2.2")
    traced = ModelRef(
        provider="internal",
        model_id="fraud_score@2.2",
        training_attestation=RunId("run_training_7"),
    )
    assert _context(model=untraced).content_hash() != _context(model=traced).content_hash()


@pytest.mark.unit
def test_model_parameters_are_frozen() -> None:
    model = ModelRef(provider="p", model_id="m", parameters={"temperature": 0})
    with pytest.raises(TypeError):
        model.parameters["temperature"] = 1  # type: ignore[index]


# ── Snapshot semantics ───────────────────────────────────────────────────────────


@pytest.mark.unit
def test_capabilities_are_read_from_the_snapshot_not_a_live_service() -> None:
    identity = _identity(capabilities=frozenset({"settle_claim"}))
    assert identity.holds("settle_claim")
    assert not identity.holds("freeze_account")


@pytest.mark.unit
def test_context_mappings_are_frozen_after_construction() -> None:
    context = _context(prompt_hashes={"adjudicate": Hash("d" * 64)})
    with pytest.raises(TypeError):
        context.prompt_hashes["adjudicate"] = Hash("f" * 64)  # type: ignore[index]


@pytest.mark.unit
def test_residency_is_part_of_the_binding_hash() -> None:
    eu = _binding(residency_regions=frozenset({"eu-west-1"}))
    ng = _binding(residency_regions=frozenset({"af-south-1"}))
    assert eu.content_hash() != ng.content_hash()


@pytest.mark.unit
def test_profile_requires_a_name_and_version() -> None:
    with pytest.raises(ValueError, match="required"):
        ProfileRef(name="insurance", version="")
