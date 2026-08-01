"""What a remembered thing *is*. The policy about writing one lives at L1.

The split follows :mod:`attest.kernel.authority`: the value type is here so the port
that stores it can name it, and the engine that decides whether a write is permitted —
:class:`~attest.capabilities.memory.MemoryGuard` — sits a layer up where it can hold a
policy. A kernel that imported the guard would invert the layering; a port that could
not name the item would have to fall back to ``str``, which is how the provenance
fields get lost.

Memory is untrusted input the system wrote to itself. Every field here exists so a
reader can distrust it correctly.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from attest.kernel.identifiers import ActorId, RunId, SubjectId, TenantId

__all__ = ["MemoryClass", "MemoryItem"]


class MemoryClass(StrEnum):
    FACT = "fact"
    """An assertion about the world. May be cited as evidence IF it carries
    provenance. Must never be interpreted as an instruction."""

    INSTRUCTION = "instruction"
    """A directive about how to behave. Forbidden by default; where a domain enables
    it, it must be written by an authorised human and never derived from retrieved
    content."""


@dataclass(frozen=True, slots=True)
class MemoryItem:
    """One remembered thing, with everything needed to distrust it properly."""

    content: str
    memory_class: MemoryClass
    tenant: TenantId
    created_at: datetime
    author: ActorId
    author_is_human: bool
    origin_run: RunId | None = None
    subject: SubjectId | None = None
    source_attestation: RunId | None = None
    """The attestation that established this fact.

    Without it the item is hearsay: it may be recalled as context but must not be
    cited as support, because there is nothing to re-verify against.
    """

    expires_at: datetime | None = None

    @property
    def citable_as_evidence(self) -> bool:
        """Only a fact with provenance is evidence. Everything else is context."""
        return self.memory_class is MemoryClass.FACT and self.source_attestation is not None
