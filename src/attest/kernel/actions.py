"""Actions — what is proposed.

An :class:`Action` is a *proposal*. Producing one confers no authority whatsoever: a
model, a rules engine, a scheduled job and a human all propose through the same type,
and none of them can execute. Authority arrives separately, as a grant bound to
:meth:`Action.action_hash`.

That hash covers the **arguments**, not just the tool name. A grant for
"pay GBP 12,400 to beneficiary X" cannot authorise "pay GBP 500,000 to beneficiary Y",
which is threat-model attacks 5 and 10.

How an effect *behaves* once authorised lives in :mod:`attest.kernel.effects`. The
two are separated because they have different reasons to change: an action describes
one proposal, while effect semantics describe a tool's standing consequences.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from attest.kernel.canonical import Canonical
from attest.kernel.effects import EffectSemantics, IdempotencyMode
from attest.kernel.identifiers import Hash

if TYPE_CHECKING:
    from collections.abc import Mapping

    from attest.kernel.effects import EffectClass
    from attest.kernel.identifiers import ActorId, TenantId

__all__ = ["Action"]


@dataclass(frozen=True, slots=True)
class Action:
    """A proposed action. Carries no authority of its own."""

    tool: str
    actor: ActorId
    tenant: TenantId
    arguments: Mapping[str, Any]
    semantics: EffectSemantics = field(default_factory=EffectSemantics)
    idempotency: IdempotencyMode = IdempotencyMode.FORBIDDEN
    effects: frozenset[EffectClass] = frozenset()
    capability: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.tool:
            raise ValueError("action tool must not be empty")
        if not self.tenant:
            raise ValueError(
                "action tenant must not be empty: tenancy is a hard boundary and an "
                "unscoped action cannot be authorised"
            )
        if not self.actor:
            raise ValueError("action actor must not be empty")
        # Freeze the mappings so a caller cannot mutate arguments after the hash is
        # taken. Without this, action_hash binds nothing: a reference held by the
        # proposer could be edited between issuance and redemption.
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def action_hash(self) -> Hash:
        """The content address binding a grant to *these exact arguments*.

        Deliberately excludes :attr:`metadata`, which carries operational annotation
        — trace ids, UI hints — that must not change what was authorised. Everything
        that determines what happens in the world is covered.
        """
        return Hash(
            Canonical.digest(
                {
                    "tool": self.tool,
                    "actor": self.actor,
                    "tenant": self.tenant,
                    "arguments": dict(self.arguments),
                    "semantics": {
                        "reversible": self.semantics.reversible,
                        "compensatable": self.semantics.compensatable,
                        "externally_visible": self.semantics.externally_visible,
                        "financially_material": self.semantics.financially_material,
                        "legally_binding": self.semantics.legally_binding,
                        "idempotent_upstream": self.semantics.idempotent_upstream,
                        "transactional": self.semantics.transactional,
                    },
                    "idempotency": self.idempotency,
                    "effects": sorted(self.effects),
                    "capability": self.capability,
                }
            )
        )
