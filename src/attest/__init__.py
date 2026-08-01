"""Attest — a governed control plane for AI actions.

Agents, rules engines, scheduled jobs and humans may **propose** actions. The kernel
decides whether a consequential effect may execute, and produces a record that the
decision was warranted — verifiable offline, years later, against the policy and
evidence that actually applied at the time.

What it does **not** do is establish that a decision was *correct*. A beautifully
verifiable attestation of a wrong decision is this design's most dangerous failure
mode, and conflating the two is how the framework would oversell itself. See
``docs/concepts/assurance-boundaries.md``.

.. rubric:: The public API

Everything re-exported here is covered by the compatibility policy below. Importing
from a submodule reaches internals that carry no promise and may move in a minor
release.

.. rubric:: Versioning

Until 1.0 the public API is unstable and minor versions may break it, always with a
migration note in the changelog. From 1.0:

* **patch** — no behaviour change; attestations byte-identical
* **minor** — additive only; existing attestations verify unchanged
* **major** — may change verification semantics, and **must** ship a shim that
  verifies prior-major attestations for at least the retention period

That last obligation is expensive and non-negotiable: a framework upgrade that
silently invalidates historical attestations destroys the product's core claim.
"""

from __future__ import annotations

from attest.capabilities.gateway import (
    CanaryPrompt,
    DriftCanary,
    DriftReport,
    Feature,
    ModelCall,
    ModelCallLog,
    ModelGateway,
    ModelPrice,
    ModelSession,
    PricingTable,
    RetryPolicy,
)
from attest.kernel.actions import Action
from attest.kernel.attestation import (
    Attestation,
    AttestationError,
    CostRecord,
    EffectRecord,
)
from attest.kernel.audit import AuditEvent, ChainVerifier, EventType, RunSeal
from attest.kernel.authority import (
    ApprovalRecord,
    AuthorizationGrant,
    Discharge,
    GrantCheck,
    GrantRejection,
)
from attest.kernel.canonical import Canonical, CanonicalisationError
from attest.kernel.codec import AttestationCodec, AuditEventCodec, CodecError
from attest.kernel.config import AssuranceTier, AttestConfig, ModelTier
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ModelRef,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.effects import (
    EffectClass,
    EffectClasses,
    EffectSemantics,
    EffectState,
    IdempotencyMode,
)
from attest.kernel.errors import (
    AttestError,
    ConfigurationError,
    ContractViolation,
    IntegrityError,
)
from attest.kernel.evidence import (
    AuthorityLevel,
    Evidence,
    EvidenceKind,
    EvidenceKinds,
    Persistence,
    SourceRef,
    SourceType,
    SupportResult,
    ValidityWindow,
    VerificationOutcome,
)
from attest.kernel.identifiers import (
    ActorId,
    DatasetId,
    GrantId,
    Hash,
    RunId,
    SubjectId,
    TenantId,
)
from attest.kernel.ports import (
    ApprovalStore,
    AuditSink,
    BudgetStore,
    Clock,
    IdGenerator,
    MemoryStore,
    NonceStore,
    Retriever,
    RunStore,
    Sealer,
    Signer,
)
from attest.kernel.verdicts import Refusal, RefusalReason, Verdict
from attest.kernel.warrants import (
    CORE_WARRANTS,
    Finding,
    Severity,
    WarrantKind,
    WarrantKinds,
    WarrantPolicy,
    WarrantReport,
    WarrantStatus,
)
from attest.runtime.engine import RunEngine, RunRequest, RunResult, VerdictResolver
from attest.version import __version__

__all__ = [
    "CORE_WARRANTS",
    "Action",
    "ActorId",
    "ApprovalRecord",
    "ApprovalStore",
    "AssuranceTier",
    "AttestConfig",
    "AttestError",
    "Attestation",
    "AttestationCodec",
    "AttestationError",
    "AuditEvent",
    "AuditEventCodec",
    "AuditSink",
    "AuthorityLevel",
    "AuthorizationGrant",
    "BudgetStore",
    "CanaryPrompt",
    "Canonical",
    "CanonicalisationError",
    "ChainVerifier",
    "Clock",
    "CodecError",
    "ConfigurationError",
    "ContractViolation",
    "CostRecord",
    "DatasetId",
    "Discharge",
    "DriftCanary",
    "DriftReport",
    "EffectClass",
    "EffectClasses",
    "EffectRecord",
    "EffectSemantics",
    "EffectState",
    "EventType",
    "Evidence",
    "EvidenceKind",
    "EvidenceKinds",
    "ExecutionContext",
    "Feature",
    "Finding",
    "GrantCheck",
    "GrantId",
    "GrantRejection",
    "Hash",
    "IdGenerator",
    "IdempotencyMode",
    "IdentitySnapshot",
    "IntegrityError",
    "MemoryStore",
    "ModelCall",
    "ModelCallLog",
    "ModelGateway",
    "ModelPrice",
    "ModelRef",
    "ModelSession",
    "ModelTier",
    "NonceStore",
    "Persistence",
    "PricingTable",
    "ProfileRef",
    "Refusal",
    "RefusalReason",
    "Retriever",
    "RetryPolicy",
    "RunEngine",
    "RunId",
    "RunRequest",
    "RunResult",
    "RunSeal",
    "RunStore",
    "Sealer",
    "Severity",
    "Signer",
    "SourceRef",
    "SourceType",
    "SubjectId",
    "SupportResult",
    "TenantBinding",
    "TenantId",
    "ValidityWindow",
    "Verdict",
    "VerdictResolver",
    "VerificationOutcome",
    "WarrantKind",
    "WarrantKinds",
    "WarrantPolicy",
    "WarrantReport",
    "WarrantStatus",
    "__version__",
]
