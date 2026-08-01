"""Shared fixtures for the capability layer."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attest.kernel.actions import Action
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.effects import EffectClasses, EffectSemantics
from attest.kernel.evidence import (
    AuthorityLevel,
    Evidence,
    EvidenceKinds,
    SourceRef,
    SourceType,
)
from attest.kernel.identifiers import ActorId, EvidenceId, Hash, RunId, TenantId

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
ACME = TenantId("acme")
ALICE = ActorId("alice")


@pytest.fixture
def at() -> datetime:
    return AT


@pytest.fixture
def context() -> ExecutionContext:
    return ExecutionContext(
        run_id=RunId("run_1"),
        captured_at=AT,
        identity=IdentitySnapshot(actor=ALICE, tenant=ACME, capabilities=frozenset({"transfer"})),
        binding=TenantBinding(
            tenant=ACME,
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
        ),
        framework_version="0.1.0",
        policy_version="1.0.0",
    )


@pytest.fixture
def action() -> Action:
    return Action(
        tool="transfer",
        actor=ALICE,
        tenant=ACME,
        arguments={"to": "X", "amount": "12400.00"},
        capability="transfer",
        effects=frozenset({EffectClasses.FINANCIAL}),
        semantics=EffectSemantics(reversible=False, compensatable=True),
    )


def make_evidence(
    value: str = "policy covers escape of water",
    *,
    eid: str = "e1",
    authority: AuthorityLevel = AuthorityLevel.AUTHORITATIVE,
    tenant: TenantId | None = None,
    integrity_hash: Hash | None = None,
    **metadata: object,
) -> Evidence:
    return Evidence(
        evidence_id=EvidenceId(eid),
        kind=EvidenceKinds.QUOTED_SPAN,
        source=SourceRef(
            source_id="PW-2019",
            source_type=SourceType.POLICY_DOC,
            authority=authority,
            version="7",
            retrieved_at=AT,
            integrity_hash=integrity_hash if integrity_hash is not None else Hash("a" * 64),
            tenant=tenant,
        ),
        value=value,
        metadata=metadata,
    )
