"""The Flow graph — one primitive, many topologies.

An earlier draft had chains and orchestration as two separate mechanisms. That was
wrong: they are the same thing with different shapes, and two mechanisms means two
places for warrant composition to be implemented and to diverge.

``FunctionNode`` matters more than it looks. **Most steps in a high-stakes flow should
not be agents.** A threshold comparison, a date calculation, an eligibility rule — all
deterministic and belonging in code. Modelling them as agents is how these systems
become slow, expensive and less correct at once.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from attest.kernel.errors import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from attest.kernel.attestation import Attestation

__all__ = ["Flow", "FlowState", "Node", "NodeKind"]


class NodeKind(StrEnum):
    AGENT = "agent"
    """The only kind that calls a model."""

    TOOL = "tool"
    FUNCTION = "function"
    """Pure host code. Deterministic and specifiable belongs here, not in an agent."""

    HUMAN = "human"
    """A person is a first-class participant, not an exception."""

    SUBFLOW = "subflow"
    ROUTER = "router"
    GATHER = "gather"


@dataclass(frozen=True, slots=True)
class Node:
    """One step. Every node produces an attestation fragment."""

    name: str
    kind: NodeKind
    irreversible: bool = False
    compensate: str | None = None
    can_fail: bool = True
    expires_after_seconds: int | None = None
    subject_summary: str = ""
    next_nodes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind is NodeKind.HUMAN:
            if not self.expires_after_seconds:
                raise ConfigurationError(
                    f"human node {self.name!r} has no expiry. An approval queue without "
                    f"one becomes a backlog of half-executed decisions with no owner."
                )
            if not self.subject_summary:
                raise ConfigurationError(
                    f"human node {self.name!r} has no subject_summary. The quality of "
                    f"an approval is bounded by what the approver is shown; an approver "
                    f"given only 'Approve payout?' cannot meaningfully approve."
                )


@dataclass(frozen=True, slots=True)
class FlowState:
    """Immutable. Each node returns a new state.

    A node that mutates shared state makes parallel branches unsafe and the whole flow
    non-replayable, and replay is a core guarantee rather than a feature.
    """

    data: Mapping[str, Any] = field(default_factory=dict)
    attestations: tuple[Attestation, ...] = ()

    def with_data(self, **updates: Any) -> FlowState:  # noqa: ANN401
        return FlowState(data={**self.data, **updates}, attestations=self.attestations)

    def with_attestation(self, attestation: Attestation) -> FlowState:
        return FlowState(data=self.data, attestations=(*self.attestations, attestation))


class Flow:
    """A directed graph of nodes, validated before it ever runs.

    The static checks are cheap at construction and expensive at runtime: a flow that
    can strand itself in a half-applied state is rejected rather than discovered in
    production.
    """

    __slots__ = ("_nodes", "_spec_version", "_start")

    def __init__(self, nodes: Sequence[Node], *, start: str, spec_version: str) -> None:
        self._nodes = {node.name: node for node in nodes}
        self._start = start
        self._spec_version = spec_version
        self._validate()

    @property
    def spec_version(self) -> str:
        """Pinned for the life of a suspended run.

        A deploy must not change the graph under a run whose earlier steps were
        validated against the old one.
        """
        return self._spec_version

    @property
    def nodes(self) -> Mapping[str, Node]:
        return dict(self._nodes)

    def _validate(self) -> None:
        if self._start not in self._nodes:
            raise ConfigurationError(f"start node {self._start!r} is not in the flow")

        for node in self._nodes.values():
            for target in node.next_nodes:
                if target not in self._nodes:
                    raise ConfigurationError(
                        f"{node.name!r} points at {target!r}, which is not in the flow"
                    )

        self._reject_cycles()
        self._reject_orphans()
        self._reject_stranding()

    def _reject_cycles(self) -> None:
        """No cycle anywhere in the graph, reachable from the start or not.

        This used to walk from ``self._start`` only. A cycle in a subgraph the start
        node cannot reach was therefore never detected — and such a subgraph is not
        exotic: it is what a flow looks like halfway through an edit, after a branch is
        rerouted, or when a node's ``next_nodes`` still points at a section that was
        meant to be removed. The flow validates, ships, and the cycle waits for whoever
        reconnects that branch. "An unbounded loop is an unbounded spend" is the reason
        the check exists, and a spend does not care which node the graph starts at.

        Every node is a root here, so the walk is over the whole graph. ``done`` makes
        it linear rather than quadratic: a node already cleared is not re-explored.
        """
        visiting: set[str] = set()
        done: set[str] = set()

        def walk(name: str, path: tuple[str, ...]) -> None:
            if name in visiting:
                raise ConfigurationError(
                    f"flow contains a cycle: {' -> '.join([*path, name])}. An unbounded "
                    f"loop is an unbounded spend."
                )
            if name in done:
                return
            visiting.add(name)
            for target in self._nodes[name].next_nodes:
                walk(target, (*path, name))
            visiting.discard(name)
            done.add(name)

        for name in sorted(self._nodes):
            walk(name, ())

    def _reject_orphans(self) -> None:
        """Every node must be reachable from the start.

        An unreachable node is a step somebody wrote, validated, and will never execute.
        That is worse than a missing step: the flow diagram shows a compensation, a
        human approval or a completeness check that is simply not in the path, and the
        review that looked at the diagram signed off on a control the run never reaches.

        Refused rather than warned. A flow is a specification, and one that contains
        steps it does not run is not describing what happens.
        """
        reachable = {self._start}
        frontier = [self._start]
        while frontier:
            for target in self._nodes[frontier.pop()].next_nodes:
                if target not in reachable:
                    reachable.add(target)
                    frontier.append(target)

        orphans = sorted(set(self._nodes) - reachable)
        if orphans:
            raise ConfigurationError(
                f"{orphans} cannot be reached from {self._start!r}. An unreachable node "
                f"is a step that was written, reviewed and will never execute — and if "
                f"it is a compensation or an approval, the diagram shows a control the "
                f"run does not have. Connect them or remove them."
            )

    def _reject_stranding(self) -> None:
        """No uncompensated failable node may be **reachable** after an irreversible one.

        Otherwise the flow can commit something that cannot be undone and then fail,
        leaving the world partially changed with no path back. Static, so it costs
        nothing at runtime.

        .. rubric:: Reachability, not adjacency

        This used to check ``node.next_nodes`` only, so the hazard was caught at one hop
        and vanished at two:

        .. code-block:: text

            send_payment ──▶ notify_customer ──▶ update_ledger
            irreversible     cannot fail         can fail, no compensation
                             ─────────────       ─────────────────────────
                             REJECTED before     accepted, and it is the
                             ...if it were       *same* stranded flow with
                             here                one harmless step inserted

        The money has left in both diagrams. Inserting a node that cannot fail between
        them changes nothing about the world and everything about whether the check
        fired — which makes it the kind of guard that passes review and then does not
        hold, because nobody draws the two-hop version on the whiteboard.

        The walk is bounded: ``_reject_cycles`` runs first, so the graph is a DAG by the
        time this executes and the visited set is a memo rather than a termination
        condition.
        """
        for node in self._nodes.values():
            if not node.irreversible:
                continue
            for name, path in self._downstream_of(node):
                target = self._nodes[name]
                if target.can_fail and target.compensate is None:
                    raise ConfigurationError(
                        f"{node.name!r} is irreversible and {target.name!r} is reachable "
                        f"after it ({' -> '.join(path)}), and can fail with no "
                        f"compensating action. That flow can strand itself half-applied: "
                        f"the irreversible step has already changed the world and there "
                        f"is no path back. Give {target.name!r} a compensation, mark it "
                        f"can_fail=False if it genuinely cannot, or move the irreversible "
                        f"step last."
                    )

    def _downstream_of(self, node: Node) -> list[tuple[str, tuple[str, ...]]]:
        """Every node reachable from ``node``, with the shortest path that reaches it.

        The path is carried so the error can show the route. A message naming only the
        two ends sends somebody hunting through a flow definition for the hop that
        connects them, which for a flow of any size is the whole of the debugging.

        Breadth-first, so the path shown is the shortest one — the clearest explanation
        of why the two are connected.
        """
        found: list[tuple[str, tuple[str, ...]]] = []
        seen = {node.name}
        frontier: list[tuple[str, tuple[str, ...]]] = [
            (name, (node.name, name)) for name in node.next_nodes
        ]
        while frontier:
            name, path = frontier.pop(0)
            if name in seen:
                continue
            seen.add(name)
            found.append((name, path))
            frontier.extend((target, (*path, target)) for target in self._nodes[name].next_nodes)
        return found
