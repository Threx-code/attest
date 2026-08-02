"""Execution context — the snapshot everything downstream reads from.

The claim this type exists to make precise:

.. code-block:: text

    Given a captured ExecutionContext, every post-proposal step is a pure
    function of that context.

    verify(context)  is deterministic.
    verify()         is not.

An earlier draft of the architecture claimed the post-proposal layer was simply
"deterministic". It is not: capability checks, budget checks and referential
verification all read state outside the run, so the same input at a different moment
gives a different answer. The corrected claim is narrower, defensible, testable, and
sufficient for replay.

The rule that makes it work: **after capture, no component reads live external
state.** A capability check reads ``identity``, not the identity service. Anything
that genuinely must be live — an account balance at the moment of payment — is an
effect-boundary concern, guarded by a short-lived grant rather than a context read.

The whole context is hashed as **one unit**. Nine loose fields on an attestation can
drift apart from each other and from the run they describe; one hashed object cannot.
See ADR 0038.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from attest.kernel.canonical import Canonical
from attest.kernel.identifiers import Hash

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from attest.kernel.evidence import Evidence
    from attest.kernel.identifiers import ActorId, CorpusId, RunId, TenantId

__all__ = [
    "ExecutionContext",
    "IdentitySnapshot",
    "ModelRef",
    "ProfileRef",
    "TenantBinding",
    "VisibilityScope",
]


@dataclass(frozen=True, slots=True)
class ProfileRef:
    """Which domain profile applied, at which version.

    Pinned into every attestation, so changing a threshold does not silently
    invalidate every historical decision made under the old one.
    """

    name: str
    version: str
    jurisdiction: str | None = None
    """A *parameter*, not a separate profile. ``MortgageProfile(jurisdiction="UK")``
    and ``("NG")`` are the same shape with different data - protected classes,
    cooling-off durations, notice requirements. Modelling them as distinct profiles
    is what produces the ``legal_ng.yaml`` / ``legal_uk_v2.yaml`` sprawl."""

    def __post_init__(self) -> None:
        if not self.name or not self.version:
            raise ValueError("profile name and version are both required")


@dataclass(frozen=True, slots=True)
class ModelRef:
    """Which model produced the proposal, and where it came from."""

    provider: str
    model_id: str
    family: str = ""
    """The weights, not the vendor.

    Cross-family judging compares THIS, not `provider`: Groq, Bedrock and Vertex all
    serve Llama, so a provider check would accept a Llama judge for a Llama generator.
    Empty means unknown, which a judging policy must treat as same-family (fail closed).
    See ADR 0041.
    """
    parameters: Mapping[str, Any] = field(default_factory=dict)
    seed: int | None = None

    failover: bool = False
    """Whether this response came from a fallback provider.

    Recorded because a decision made by a fallback model is a materially different
    decision, and replay must know. Never inferred later - by then the routing
    state is gone.
    """

    training_attestation: RunId | None = None
    """The run that produced this model's weights, where we attested to it.

    ``None`` is the honest value for a third-party API model whose training data we
    cannot vouch for, and must never be read as "trained on nothing". Where it is
    set, an inference attestation reaches its training provenance in one hop, and
    from there to the dataset commitment. See ``docs/capabilities/lineage.md``.
    """

    def __post_init__(self) -> None:
        object.__setattr__(self, "parameters", MappingProxyType(dict(self.parameters)))


@dataclass(frozen=True, slots=True)
class IdentitySnapshot:
    """Who is acting, and what they could do **at dispatch**.

    Snapshotted rather than queried live, so verification is reproducible. The gap
    this leaves — a capability revoked between capture and effect — is closed at the
    effect boundary by a short-lived grant, not by re-reading here.
    """

    actor: ActorId
    tenant: TenantId
    capabilities: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()

    def holds(self, capability: str) -> bool:
        return capability in self.capabilities


@dataclass(frozen=True, slots=True)
class TenantBinding:
    """Everything that varies per tenant, resolved once.

    Resolution happens at context capture and the binding travels in the context, so
    a run cannot drift onto another tenant's policy mid-flight and the attestation
    records exactly which binding applied.
    """

    tenant: TenantId
    profile: ProfileRef
    config_hash: Hash
    residency_regions: frozenset[str] = frozenset()
    """Permitted processing regions. Empty means unconstrained.

    Constrains the *model provider*, not only the database — a fallback provider in
    another region turns an outage into a data-transfer breach, so the gateway
    filters its failover list by residency before consulting it, never after.

    A **deployment** floor may sit above this - see
    :class:`~attest.capabilities.gateway.ModelGateway`. This value can then only narrow
    it, never widen it.
    """

    zero_retention_required: bool = False
    """Whether this tenant's calls may only go to a provider that has attested it.

    On the binding rather than on the gateway constructor because it is a tenant's
    contractual position, not a process-wide one, and because a constructor argument is
    a thing a caller can forget while still producing an attestation that records the
    binding. ``ProviderRouter`` has honoured this since it was written; nothing passed
    it, so it could not be switched on through the only supported way to reach a
    provider.

    ``False`` is the honest default and is not the same as "nobody needs it": it means
    this tenant has not asked. A deployment where nobody has attested is a deployment
    where the flag filters everything out, which is a refusal and correct.
    """

    def content_hash(self) -> Hash:
        return Hash(
            Canonical.digest(
                {
                    "tenant": self.tenant,
                    "profile": {
                        "name": self.profile.name,
                        "version": self.profile.version,
                        "jurisdiction": self.profile.jurisdiction,
                    },
                    "config_hash": self.config_hash,
                    "residency_regions": sorted(self.residency_regions),
                    "zero_retention_required": self.zero_retention_required,
                }
            )
        )


@dataclass(frozen=True, slots=True)
class VisibilityScope:
    """What this actor may READ, inside the tenant they already belong to.

    Tenancy answers "whose data is this". It does not answer "may *this person* see it",
    and in every regulated profession that second question has its own answer: an ethical
    wall between two teams in a law firm, a Chinese wall between advisory and trading, a
    need-to-know boundary on a clinical record. A framework that models only the tenant
    treats a firm as one undifferentiated reader, which no firm is.

    Resolved at context capture and carried in the context, for the same reason residency
    is: a scope passed per call is a scope a caller can forget, and the record would then
    assert a boundary that never applied.

    Both fields are empty by default, and they fail in opposite directions on purpose.
    """

    permitted_corpora: frozenset[CorpusId] = frozenset()
    """Corpora this actor may read. **Empty means unrestricted.**

    An allowlist, because an agent's scope is a small declared set. Empty is permissive
    because the alternative - every deployment enumerating its whole corpus before anything
    retrieves - is a rule nobody would adopt, and an unadopted control protects nothing.
    """

    barred_sources: frozenset[str] = frozenset()
    """Sources this actor is screened FROM. **Empty means nothing is screened.**

    A denylist, because a wall is an exception to general access: a conflicted matter, a
    deal the reader is on the other side of. Enumerating everything they may see instead
    would be the whole firm minus three files, recomputed on every change.

    Checked after `permitted_corpora`, and a bar always wins - the same resolution
    `Scope.permits_evidence` uses, and for the same reason: a domain that permits broadly
    and screens one thing means the screen.
    """

    def permits(self, *, corpus: CorpusId | None, source_id: str) -> bool:
        """Whether this actor may read that source."""
        if source_id in self.barred_sources:
            return False
        if not self.permitted_corpora:
            return True
        return corpus is not None and corpus in self.permitted_corpora

    def narrowed_to(self, corpora: frozenset[CorpusId]) -> VisibilityScope:
        """This scope, narrowed by an agent's own. **Never widened.**

        An agent declaring corpora it may read cannot thereby gain access the actor does
        not have - the same rule `Scope.narrowed_to` applies to delegation, applied to the
        reader rather than to the callee.
        """
        if not corpora:
            return self
        narrowed = corpora if not self.permitted_corpora else self.permitted_corpora & corpora
        return VisibilityScope(permitted_corpora=narrowed, barred_sources=self.barred_sources)


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """One moment, captured. Everything downstream reads only from here."""

    run_id: RunId
    captured_at: datetime
    identity: IdentitySnapshot
    binding: TenantBinding
    framework_version: str
    policy_version: str

    evidence: tuple[Evidence, ...] = ()
    prompt_hashes: Mapping[str, Hash] = field(default_factory=dict)
    tool_spec_hashes: Mapping[str, Hash] = field(default_factory=dict)
    corpus_epochs: Mapping[CorpusId, str] = field(default_factory=dict)

    visibility: VisibilityScope = field(default_factory=VisibilityScope)
    """What this actor may read inside the tenant. See :class:`VisibilityScope`.

    Default is unrestricted, which keeps every existing deployment behaving exactly as it
    did. A deployment that has an ethical wall resolves it here, once, at capture.
    """
    model: ModelRef | None = None
    """``None`` for a run with no model call — a rules engine or a scheduled job
    proposing through the same kernel."""

    pricing_version: str | None = None
    flow_spec_version: str | None = None
    """Pinned for the life of a suspended run. A deploy must not change the graph
    under a run whose earlier steps were validated against the old one."""

    seed: int | None = None

    def __post_init__(self) -> None:
        if self.identity.tenant != self.binding.tenant:
            raise ValueError(
                f"identity tenant {self.identity.tenant!r} does not match binding "
                f"tenant {self.binding.tenant!r}: a run cannot act for one tenant "
                f"under another's policy"
            )
        for name in ("prompt_hashes", "tool_spec_hashes", "corpus_epochs"):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))

    def content_hash(self) -> Hash:
        """The content address of the whole context.

        This single hash is what the seal signs, and it is why the nine
        reconstruction axes in ``docs/kernel/versioning.md`` cannot drift apart:
        change any one of them and this value changes.
        """
        return Hash(
            Canonical.digest(
                {
                    "run_id": self.run_id,
                    "captured_at": self.captured_at,
                    "identity": {
                        "actor": self.identity.actor,
                        "tenant": self.identity.tenant,
                        "capabilities": sorted(self.identity.capabilities),
                        "roles": sorted(self.identity.roles),
                    },
                    "binding": self.binding.content_hash(),
                    "framework_version": self.framework_version,
                    "policy_version": self.policy_version,
                    "evidence": [item.content_hash() for item in self.evidence],
                    "prompt_hashes": dict(self.prompt_hashes),
                    "tool_spec_hashes": dict(self.tool_spec_hashes),
                    "corpus_epochs": dict(self.corpus_epochs),
                    # In the hash because it is a boundary the attestation asserts. A run
                    # that read behind a wall and one that did not are different runs, and
                    # a record that cannot tell them apart cannot answer the only question
                    # a conflicts review asks.
                    "visibility": {
                        "permitted_corpora": sorted(self.visibility.permitted_corpora),
                        "barred_sources": sorted(self.visibility.barred_sources),
                    },
                    "model": None
                    if self.model is None
                    else {
                        "provider": self.model.provider,
                        "model_id": self.model.model_id,
                        "family": self.model.family,
                        "parameters": dict(self.model.parameters),
                        "seed": self.model.seed,
                        "failover": self.model.failover,
                        "training_attestation": self.model.training_attestation,
                    },
                    "pricing_version": self.pricing_version,
                    "flow_spec_version": self.flow_spec_version,
                    "seed": self.seed,
                }
            )
        )
