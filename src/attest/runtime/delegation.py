"""Delegation and handoff — two mechanisms, routinely conflated.

.. code-block:: text

    DELEGATION   A calls B as a tool. A stays in control, B's attestation nests
                 inside A's, and budget and step count are SHARED and charged to A.

    HANDOFF      Control transfers. A is finished, B owns the rest, and the
                 attestations are siblings rather than nested.

The invariant both must satisfy:

.. code-block:: text

    child_scope ⊆ parent_delegable_scope

Enforced by intersection rather than by comparison, so a child that declares a wider
scope than its parent holds gets the intersection instead of an error the caller might
ignore — and shared budget is the point: five agents at £1 each is £5, not £1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from attest.kernel.errors import ConfigurationError
from attest.runtime.agents import Scope

if TYPE_CHECKING:
    from collections.abc import Mapping

    from attest.runtime.agents import AgentSpec

__all__ = ["MAX_DELEGATION_DEPTH", "DelegationChain", "Handoff"]

MAX_DELEGATION_DEPTH = 3
"""Default ceiling. An agent that delegates to itself is an unbounded spend, so depth
is bounded by construction rather than by hoping the stopping condition is right."""


@dataclass(frozen=True, slots=True)
class Handoff:
    """Explicit transfer of control, carrying only what is declared.

    Passing a whole conversation to the next agent carries whatever was injected into
    it, so the transfer names what moves rather than defaulting to everything.
    """

    to: str
    carry: tuple[str, ...] = ()
    drop: tuple[str, ...] = ()

    def transfer(self, state: Mapping[str, object]) -> dict[str, object]:
        """The subset that crosses the boundary.

        ``drop`` wins over ``carry``: naming a key in both is a mistake, and the safe
        reading of a mistake is to drop it.
        """
        return {
            key: value for key, value in state.items() if key in self.carry and key not in self.drop
        }


@dataclass(slots=True)
class DelegationChain:
    """Tracks depth, cycles and the narrowing of scope down a delegation tree."""

    root: str
    max_depth: int = MAX_DELEGATION_DEPTH
    _path: list[str] = field(default_factory=list)
    _scopes: dict[str, Scope] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self._path:
            self._path.append(self.root)

    @property
    def depth(self) -> int:
        return len(self._path)

    @property
    def path(self) -> tuple[str, ...]:
        return tuple(self._path)

    def register(self, spec: AgentSpec) -> None:
        """Register an agent from its spec. **Prefer this to** :meth:`register_scope`.

        Uses :meth:`AgentSpec.effective_scope`, which folds the agent's own ``stream``
        choice into the scope. Registering the bare ``spec.scope`` loses it, and losing
        it means a parent declaring ``stream=FORBIDDEN`` constrains only itself while
        its whole delegated subtree streams freely.

        A method rather than a note in the docs, because "remember to fold the stream
        policy in" is the kind of instruction that holds until the second host reads it.
        """
        self._scopes[spec.name] = spec.effective_scope()

    def register_scope(self, agent: str, scope: Scope) -> None:
        """Register a raw scope, for a host whose agents are not ``AgentSpec`` objects.

        Prefer :meth:`register` where you have a spec: this cannot fold in anything the
        scope does not already carry.
        """
        self._scopes[agent] = scope

    def scope_for(self, agent: str) -> Scope:
        return self._scopes.get(agent, Scope())

    def delegate(self, *, parent: str, child: str, child_scope: Scope) -> Scope:
        """Enter a delegation, returning the child's ACTUAL scope.

        The returned scope is the intersection with the parent's, so a child cannot
        widen its reach by declaring more than its parent holds. Depth and cycles are
        refused rather than truncated: a silently-capped delegation tree produces a
        partial answer that looks complete.
        """
        parent_scope = self.scope_for(parent)
        if not parent_scope.permits_delegation_to(child):
            raise ConfigurationError(
                f"{parent!r} may not delegate to {child!r}: its scope does not permit "
                f"it. Delegation is closed by default, because opening it by omission "
                f"is how an agent reaches authority it was never granted."
            )
        if child in self._path:
            raise ConfigurationError(
                f"delegation cycle: {' -> '.join([*self._path, child])}. An agent that "
                f"delegates to itself is an unbounded spend."
            )
        if self.depth >= self.max_depth:
            raise ConfigurationError(
                f"delegation depth {self.depth} would exceed the ceiling of "
                f"{self.max_depth} at {child!r}. Refused rather than truncated: a "
                f"silently-capped tree produces a partial answer that looks complete."
            )

        narrowed = parent_scope.narrowed_to(child_scope)
        self._path.append(child)
        self._scopes[child] = narrowed
        return narrowed

    def ret(self) -> None:
        """Leave the current delegation."""
        if len(self._path) > 1:
            self._path.pop()
