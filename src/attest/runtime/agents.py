"""Agent specifications — an agent is a declaration, not a class.

One surveyed codebase defines ~50 agents, each a module, its registry opening with a
60-line import block of name constants. Adding one touches four files. Data can be
validated, diffed, listed and conformance-tested; fifty subclasses cannot.

``Scope`` is enforced at **every** boundary, not just the response. Blocking the final
answer does not un-retrieve a record, un-see it, or un-write the memory derived from
it: an agent that *retrieves* outside its remit is a data-protection incident even if
it never says a word.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, TypeVar

from attest.kernel.config import ModelTier
from attest.kernel.errors import ConfigurationError

if TYPE_CHECKING:
    from attest.capabilities.memory import MemoryWritePolicy
    from attest.kernel.evidence import SourceType
    from attest.kernel.identifiers import CorpusId
    from attest.kernel.warrants import WarrantKind, WarrantPolicy

__all__ = ["AgentSpec", "Scope", "StreamPolicy"]

_T = TypeVar("_T")

MAX_STEP_CEILING = 64


class StreamPolicy(StrEnum):
    """What may be released before it has been verified.

    ``FORBIDDEN`` is the default and tier-1 domains are expected to keep it: a
    retracted statement was still read. A clinician who read a provisional line about
    a drug interaction has read it, whatever the retraction says afterwards.
    """

    FORBIDDEN = "forbidden"
    GUARDED = "guarded"
    FREE = "free"

    def rank(self) -> int:
        """How permissive this is. Lower is stricter — see :meth:`Scope.narrowed_to`.

        A method rather than a comparison on the enum value, because the values are
        strings and ``"forbidden" < "free"`` is true by accident of the alphabet rather
        than by meaning. An ordering that happens to be right is one that stops being
        right the moment somebody adds ``"audited"``.
        """
        return (StreamPolicy.FORBIDDEN, StreamPolicy.GUARDED, StreamPolicy.FREE).index(self)


@dataclass(frozen=True, slots=True)
class Scope:
    """What an agent may reach, at every boundary rather than only the last.

    Empty collections mean *unrestricted* for that boundary, which is why
    ``forbid_evidence_types`` exists separately: a domain often needs to permit broad
    retrieval while naming one class that must never enter context.
    """

    corpora: frozenset[CorpusId] = frozenset()
    evidence_types: frozenset[SourceType] = frozenset()
    forbid_evidence_types: frozenset[SourceType] = frozenset()
    tools: frozenset[str] = frozenset()
    stream: StreamPolicy = StreamPolicy.FREE
    """The most an agent under this scope may release before it has been verified.

    ``FREE`` here means *unrestricted for this boundary*, matching every other field on
    this class — it is a ceiling, not a default posture. The cautious default lives on
    :attr:`AgentSpec.stream`, which is ``FORBIDDEN``, and :meth:`AgentSpec.effective_scope`
    folds the two together so the stricter of the pair is what delegation carries.

    Here rather than only on :class:`AgentSpec` because delegation narrows a *scope*,
    and anything outside the scope is not narrowed at all. ``stream`` lived only on the
    spec, so a parent that forbade streaming could delegate to a child declaring
    ``FREE`` and the child streamed — the exact shape of the ``memory_write`` defect
    described in :meth:`_stricter`, one field over, and with the same cause: a property
    that constrains an agent, kept somewhere delegation does not reach.

    It matters for the reason the class docstring gives. A retracted statement was still
    read: a clinician who saw a provisional line about a drug interaction has seen it,
    whatever the retraction says afterwards. A tier-1 domain sets ``FORBIDDEN`` at the
    top of its tree and needs that to mean the whole tree.
    """
    may_delegate_to: frozenset[str] = frozenset()
    memory_write: MemoryWritePolicy | None = None

    def permits_corpus(self, corpus: CorpusId) -> bool:
        return not self.corpora or corpus in self.corpora

    def permits_evidence(self, source_type: SourceType) -> bool:
        """Forbid wins over permit.

        A domain that permits broad retrieval and forbids one class means the forbid,
        and resolving the other way is how clinical records reach a claims agent.
        """
        if source_type in self.forbid_evidence_types:
            return False
        return not self.evidence_types or source_type in self.evidence_types

    def permits_tool(self, tool: str) -> bool:
        return not self.tools or tool in self.tools

    def permits_delegation_to(self, agent: str) -> bool:
        """Delegation is closed by default.

        Unlike the other boundaries, an empty set here means *nothing*: an agent that
        has not declared who it may call may not call anyone. Opening delegation by
        omission is how an agent reaches authority it was never granted.
        """
        return agent in self.may_delegate_to

    def narrowed_to(self, child: Scope) -> Scope:
        """The child's scope, intersected with this one.

        Delegation can only ever narrow. The intersection is computed here rather than
        trusted to the caller, so a child cannot widen its own reach by declaring a
        larger scope than its parent holds.
        """
        return Scope(
            corpora=self._narrow(self.corpora, child.corpora),
            evidence_types=self._narrow(self.evidence_types, child.evidence_types),
            forbid_evidence_types=self.forbid_evidence_types | child.forbid_evidence_types,
            tools=self._narrow(self.tools, child.tools),
            may_delegate_to=self.may_delegate_to & child.may_delegate_to,
            memory_write=self._stricter(self.memory_write, child.memory_write),
            stream=min(self.stream, child.stream, key=StreamPolicy.rank),
        )

    @staticmethod
    def _stricter(
        parent: MemoryWritePolicy | None, child: MemoryWritePolicy | None
    ) -> MemoryWritePolicy | None:
        """The lower of the two. **Every other field intersects; this one did not.**

        ``child.memory_write or self.memory_write`` let the child's declaration win, so
        a parent restricted to FACTS_ONLY delegating to a child declaring
        HUMAN_INSTRUCTIONS produced a child holding HUMAN_INSTRUCTIONS. In a plugin
        ecosystem the child's spec is domain-supplied and in a compromised one it is
        attacker-supplied: the child obtains instruction-memory authority, writes a
        directive, and every later run recalls it as trusted context. Persistent prompt
        injection reached through delegation, into the capability the docs call the most
        dangerous in the framework.

        This class exists to make "delegation can only ever narrow" structural. That
        line made it a preference.
        """
        if parent is None:
            return child
        if child is None:
            return parent
        from attest.capabilities.memory import MemoryWritePolicy

        return min(parent, child, key=MemoryWritePolicy.rank)

    @staticmethod
    def _narrow(parent: frozenset[_T], child: frozenset[_T]) -> frozenset[_T]:
        """Intersect, treating an empty parent as unrestricted and an empty child as
        inheriting the parent."""
        if not parent:
            return child
        if not child:
            return parent
        return parent & child


@dataclass(frozen=True, slots=True)
class AgentSpec:
    """An agent, as data.

    ``model_tier`` rather than a model id: switching provider is a configuration
    change, never fifty edits, and the concrete model still lands in the attestation.
    """

    name: str
    version: str
    prompt: str
    model_tier: ModelTier = ModelTier.BALANCED
    tools: tuple[str, ...] = ()
    max_steps: int = 8
    warrant_overrides: dict[WarrantKind, WarrantPolicy] = field(default_factory=dict)
    """Warrant policies this agent holds itself to. **Tightening only.**

    Resolved against the profile's in :meth:`~attest.runtime.engine.RunEngine.
    _policies_for` by :meth:`~attest.kernel.warrants.WarrantPolicy.strictest`, so an
    agent may be more careful than its deployment and may not be less. The reverse is a
    configuration file granting itself an exemption.

    Read by nothing until the engine was given the agent. A caller could fill this in,
    watch it be carried and serialised, and get the profile's policy - which from the
    caller's side is indistinguishable from an override that matched the default.
    """
    scope: Scope = field(default_factory=Scope)
    stream: StreamPolicy = StreamPolicy.FORBIDDEN
    delegates_to: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not self.version:
            raise ConfigurationError("an agent needs a name and a version")
        if not 1 <= self.max_steps <= MAX_STEP_CEILING:
            raise ConfigurationError(
                f"max_steps must be between 1 and {MAX_STEP_CEILING}, got "
                f"{self.max_steps}. Hitting the ceiling produces a refusal with a full "
                f"attestation — never a truncated answer presented as complete."
            )
        undeclared = [a for a in self.delegates_to if not self.scope.permits_delegation_to(a)]
        if undeclared:
            raise ConfigurationError(
                f"agent {self.name!r} delegates to {undeclared} which its scope does "
                f"not permit. Delegation is closed by default: an agent that has not "
                f"declared who it may call may not call anyone."
            )

    def completion_floor(self) -> str:
        """The weakest model this agent may be served by, as
        :attr:`~attest.capabilities.gateway.CompletionRequest.min_tier` wants it.

        The two ideas were unconnected: an agent declared ``model_tier`` and the gateway
        enforced ``min_tier``, and nothing turned one into the other - so an agent
        declaring a frontier tier could be served, on failover, by whatever cleared
        residency and features. Feature parity is not quality parity, and a down-tiered
        answer is structurally identical to a good one.

        A method rather than the gateway reading ``AgentSpec`` directly, because the
        gateway must not learn what an agent is. It compares positions in a list the
        deployment supplied, and this hands it a label for that list.
        """
        return self.model_tier.value

    def effective_scope(self) -> Scope:
        """The scope to hand :meth:`DelegationChain.register_scope`. **Not ``self.scope``.**

        An agent's own ``stream`` choice has to travel with its scope, or it constrains
        only that agent and nothing it delegates to. Registering the bare ``scope`` was
        the defect: a parent declaring ``stream=FORBIDDEN`` narrowed nothing, because
        the field delegation narrows is the scope and the parent's choice was not in it.

        Returns the stricter of the two, so a parent that forbids streaming forbids it
        for its whole subtree — which is what a tier-1 domain setting ``FORBIDDEN`` at
        the root believes it is buying.
        """
        from dataclasses import replace as _replace

        return _replace(
            self.scope, stream=min(self.stream, self.scope.stream, key=StreamPolicy.rank)
        )
