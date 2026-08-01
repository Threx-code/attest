"""Memory — recall across runs, and the most dangerous capability here.

Memory is untrusted input that the system wrote to itself: text injected in one run is
recalled as trusted context in the next. That is persistent prompt injection, and the
structural defence is not a better classifier.

**Agents may not write instruction memory.** Facts and instructions are different
things, classified at write time, and an agent-authored directive is refused rather
than adjudicated. That reduces the classifier's job from judging intent to catching
smuggling.

A memory without provenance is **not evidence** and must never be cited as support.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

from attest.kernel.errors import ContractViolation
from attest.kernel.memory import MemoryClass, MemoryItem

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from attest.kernel.identifiers import TenantId

__all__ = ["MemoryClass", "MemoryGuard", "MemoryItem", "MemoryWritePolicy"]


class MemoryWritePolicy(StrEnum):
    FACTS_ONLY = "facts_only"
    HUMAN_INSTRUCTIONS = "human_instructions"
    """Instructions permitted, but only from an authorised human author."""

    NONE = "none"

    @staticmethod
    def rank(policy: MemoryWritePolicy) -> int:
        """How much authority this policy grants. Ordered, so "stricter" is comparable.

        Delegation narrows by comparing these. Without an ordering the narrowing was
        written as ``child or parent``, which is a preference for the child — and a
        child declaring HUMAN_INSTRUCTIONS under a FACTS_ONLY parent obtained it.
        """
        return {
            MemoryWritePolicy.NONE: 0,
            MemoryWritePolicy.FACTS_ONLY: 1,
            MemoryWritePolicy.HUMAN_INSTRUCTIONS: 2,
        }[policy]


class MemoryGuard:
    """Classifies memory at write time and refuses what would escalate authority.

    Holds the write policy, so a scope that may not write instructions differs by
    construction rather than by an argument every caller must remember to pass.
    """

    __slots__ = ("_policy",)

    # Directive shapes. Catching smuggling, not adjudicating intent — which is only
    # tractable because agents cannot write instructions at all.
    DIRECTIVE_MARKERS: tuple[str, ...] = (
        "always ",
        "never ",
        "from now on",
        "you must",
        "you should",
        "do not ask",
        "skip the",
        "pre-approved",
        "automatically approve",
        "treat all",
    )

    def __init__(self, *, policy: MemoryWritePolicy = MemoryWritePolicy.FACTS_ONLY) -> None:
        self._policy = policy

    @property
    def policy(self) -> MemoryWritePolicy:
        return self._policy

    @classmethod
    def classify(cls, content: str) -> MemoryClass:
        """Classify text at write time.

        Fail-closed: anything directive-shaped is INSTRUCTION, so a borderline item is
        refused for an agent rather than stored as a fact and recalled as one.
        """
        lowered = content.lower()
        if any(marker in lowered for marker in cls.DIRECTIVE_MARKERS):
            return MemoryClass.INSTRUCTION
        return MemoryClass.FACT

    def screen_write(self, item: MemoryItem) -> None:
        """Reject a write that would let memory escalate authority.

        Raises rather than dropping silently: a refused write the caller does not
        learn about is a fact the system believes it stored.
        """
        if self._policy is MemoryWritePolicy.NONE:
            raise ContractViolation("this scope may not write memory at all")

        detected = self.classify(item.content)
        if detected is MemoryClass.INSTRUCTION:
            if not item.author_is_human:
                raise ContractViolation(
                    f"agent {item.author!r} attempted to write INSTRUCTION memory: "
                    f"{item.content[:80]!r}. An agent may not write directives — that "
                    f"is persistent prompt injection, and it is refused at write time "
                    f"rather than screened at recall."
                )
            if self._policy is MemoryWritePolicy.FACTS_ONLY:
                raise ContractViolation(
                    "this scope permits FACTS_ONLY; instruction memory is not enabled"
                )
        if item.memory_class is MemoryClass.FACT and detected is MemoryClass.INSTRUCTION:
            raise ContractViolation(
                "item is declared FACT but is directive-shaped; storing it would let "
                "an instruction be recalled as a fact"
            )

    @staticmethod
    def recallable(
        items: Sequence[MemoryItem], *, tenant: TenantId, now: datetime
    ) -> tuple[MemoryItem, ...]:
        """Filter by scope BEFORE any semantic search.

        Filtering afterwards means the index was already queried across tenants, and a
        scoring bug becomes a leak rather than a ranking error.
        """
        return tuple(
            item
            for item in items
            if item.tenant == tenant and (item.expires_at is None or item.expires_at > now)
        )
