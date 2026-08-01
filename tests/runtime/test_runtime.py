"""L2 runtime: scope narrowing, delegation bounds, flow validation, routing, replay."""

from __future__ import annotations

import pytest

from attest.kernel.actions import Action
from attest.kernel.effects import IdempotencyMode
from attest.kernel.errors import ConfigurationError
from attest.kernel.evidence import SourceType
from attest.kernel.identifiers import ActorId, CorpusId, TenantId
from attest.kernel.verdicts import Refusal, RefusalReason
from attest.runtime.agents import AgentSpec, Scope, StreamPolicy
from attest.runtime.composition import Flow, FlowState, Node, NodeKind
from attest.runtime.delegation import DelegationChain, Handoff
from attest.runtime.replay import PolicyAt, ReplayMode, ReplayPlan
from attest.runtime.router import Deflect, Router, RouterSpec
from attest.runtime.streaming import Frame, SettledOutcome, StreamSession

pytestmark = pytest.mark.unit


# ── Scope is enforced at every boundary ──────────────────────────────────────


@pytest.mark.security
def test_a_forbidden_evidence_type_wins_over_a_permit() -> None:
    # A claims agent permitted broad retrieval, with clinical records forbidden.
    # Resolving the other way is how oncology records reach a claims agent.
    scope = Scope(
        evidence_types=frozenset({SourceType.POLICY_DOC, SourceType.LAB}),
        forbid_evidence_types=frozenset({SourceType.LAB}),
    )
    assert scope.permits_evidence(SourceType.POLICY_DOC)
    assert not scope.permits_evidence(SourceType.LAB)


def test_an_empty_boundary_means_unrestricted() -> None:
    assert Scope().permits_corpus(CorpusId("anything"))
    assert Scope().permits_tool("anything")


@pytest.mark.security
def test_delegation_is_closed_by_default() -> None:
    # Unlike the other boundaries, empty means NOTHING here: opening delegation by
    # omission is how an agent reaches authority it was never granted.
    assert not Scope().permits_delegation_to("fraud_screen")
    assert Scope(may_delegate_to=frozenset({"fraud_screen"})).permits_delegation_to("fraud_screen")


@pytest.mark.security
def test_narrowing_cannot_widen_a_childs_reach() -> None:
    # child_scope ⊆ parent_delegable_scope, computed rather than compared.
    parent = Scope(tools=frozenset({"read"}), corpora=frozenset({CorpusId("a")}))
    greedy_child = Scope(
        tools=frozenset({"read", "transfer"}), corpora=frozenset({CorpusId("a"), CorpusId("b")})
    )
    narrowed = parent.narrowed_to(greedy_child)
    assert narrowed.tools == {"read"}
    assert narrowed.corpora == {CorpusId("a")}


@pytest.mark.security
def test_a_forbid_accumulates_down_the_chain() -> None:
    parent = Scope(forbid_evidence_types=frozenset({SourceType.LAB}))
    child = Scope(forbid_evidence_types=frozenset({SourceType.STATUTE}))
    narrowed = parent.narrowed_to(child)
    assert not narrowed.permits_evidence(SourceType.LAB)
    assert not narrowed.permits_evidence(SourceType.STATUTE)


# ── Agent specs ──────────────────────────────────────────────────────────────


def _spec(**kw: object) -> AgentSpec:
    base: dict[str, object] = {"name": "adjudicator", "version": "1", "prompt": "p"}
    return AgentSpec(**{**base, **kw})  # type: ignore[arg-type]


def test_a_valid_spec_constructs() -> None:
    assert _spec().max_steps == 8


@pytest.mark.security
def test_a_step_budget_above_the_ceiling_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="truncated answer"):
        _spec(max_steps=999)


@pytest.mark.security
def test_delegating_outside_scope_is_refused_at_construction() -> None:
    with pytest.raises(ConfigurationError, match="closed by default"):
        _spec(delegates_to=("fraud_screen",))


def test_declared_delegation_within_scope_constructs() -> None:
    spec = _spec(
        delegates_to=("fraud_screen",),
        scope=Scope(may_delegate_to=frozenset({"fraud_screen"})),
    )
    assert spec.delegates_to == ("fraud_screen",)


def test_streaming_is_forbidden_by_default() -> None:
    assert _spec().stream is StreamPolicy.FORBIDDEN


# ── Delegation is bounded ────────────────────────────────────────────────────


def _chain() -> DelegationChain:
    chain = DelegationChain(root="a", max_depth=3)
    chain.register_scope("a", Scope(may_delegate_to=frozenset({"b"}), tools=frozenset({"read"})))
    return chain


def test_a_permitted_delegation_narrows_the_childs_scope() -> None:
    chain = _chain()
    narrowed = chain.delegate(
        parent="a", child="b", child_scope=Scope(tools=frozenset({"read", "write"}))
    )
    assert narrowed.tools == {"read"}
    assert chain.depth == 2


@pytest.mark.security
def test_delegating_to_an_undeclared_agent_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="closed by default"):
        _chain().delegate(parent="a", child="mallory", child_scope=Scope())


@pytest.mark.security
def test_a_child_cannot_delegate_beyond_its_parents_reach() -> None:
    # The transitive property, and it is stricter than it first looks: if A may call
    # only B, then B may call nobody — because A calling B calling C would give A
    # C's authority indirectly, which is scope escalation by another route. A root
    # that wants a three-level tree must enumerate every agent in it.
    chain = _chain()
    chain.delegate(parent="a", child="b", child_scope=Scope(may_delegate_to=frozenset({"c"})))
    assert chain.scope_for("b").may_delegate_to == frozenset()
    with pytest.raises(ConfigurationError, match="closed by default"):
        chain.delegate(parent="b", child="c", child_scope=Scope())


def _deep_chain(max_depth: int = 3) -> DelegationChain:
    """A root that enumerates the whole delegable set, as strict subsetting requires."""
    chain = DelegationChain(root="a", max_depth=max_depth)
    chain.register_scope("a", Scope(may_delegate_to=frozenset({"a", "b", "c"})))
    return chain


@pytest.mark.security
def test_a_delegation_cycle_is_refused() -> None:
    # An agent that delegates to itself is an unbounded spend.
    # The child must DECLARE what it wants to delegate to; the parent's set bounds
    # it. An empty child set means nothing, because delegation is closed by default.
    chain = _deep_chain()
    chain.delegate(parent="a", child="b", child_scope=Scope(may_delegate_to=frozenset({"a", "c"})))
    with pytest.raises(ConfigurationError, match="cycle"):
        chain.delegate(parent="b", child="a", child_scope=Scope())


@pytest.mark.security
def test_exceeding_the_depth_ceiling_is_refused_not_truncated() -> None:
    # A silently-capped tree produces a partial answer that looks complete.
    chain = _deep_chain(max_depth=2)
    chain.delegate(parent="a", child="b", child_scope=Scope(may_delegate_to=frozenset({"c"})))
    with pytest.raises(ConfigurationError, match="ceiling"):
        chain.delegate(parent="b", child="c", child_scope=Scope())


# ── Handoff carries only what it declares ────────────────────────────────────


@pytest.mark.security
def test_a_handoff_carries_only_declared_keys() -> None:
    # Passing a whole conversation carries whatever was injected into it.
    handoff = Handoff(to="complaints", carry=("customer_ref", "summary"))
    transferred = handoff.transfer(
        {"customer_ref": "c1", "summary": "s", "raw_transcript": "<injected>"}
    )
    assert transferred == {"customer_ref": "c1", "summary": "s"}


@pytest.mark.security
def test_drop_wins_over_carry() -> None:
    # Naming a key in both is a mistake, and the safe reading of a mistake is to drop.
    handoff = Handoff(to="x", carry=("a", "b"), drop=("b",))
    assert handoff.transfer({"a": 1, "b": 2}) == {"a": 1}


# ── Flow validation is static ────────────────────────────────────────────────


def test_a_linear_flow_validates() -> None:
    flow = Flow(
        [
            Node(name="intake", kind=NodeKind.AGENT, next_nodes=("decide",)),
            Node(name="decide", kind=NodeKind.FUNCTION),
        ],
        start="intake",
        spec_version="v1",
    )
    assert flow.spec_version == "v1"


def test_an_unknown_start_node_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="not in the flow"):
        Flow([Node(name="a", kind=NodeKind.FUNCTION)], start="missing", spec_version="v1")


@pytest.mark.security
def test_a_cycle_is_refused_at_construction() -> None:
    with pytest.raises(ConfigurationError, match="unbounded spend"):
        Flow(
            [
                Node(name="a", kind=NodeKind.FUNCTION, next_nodes=("b",)),
                Node(name="b", kind=NodeKind.FUNCTION, next_nodes=("a",)),
            ],
            start="a",
            spec_version="v1",
        )


@pytest.mark.security
def test_an_irreversible_step_followed_by_an_uncompensated_failure_is_refused() -> None:
    # That flow can strand itself half-applied. Caught statically rather than
    # discovered in production.
    with pytest.raises(ConfigurationError, match="strand itself"):
        Flow(
            [
                Node(name="pay", kind=NodeKind.TOOL, irreversible=True, next_nodes=("notify",)),
                Node(name="notify", kind=NodeKind.TOOL, can_fail=True),
            ],
            start="pay",
            spec_version="v1",
        )


def test_an_irreversible_step_with_a_compensated_successor_is_accepted() -> None:
    Flow(
        [
            Node(name="pay", kind=NodeKind.TOOL, irreversible=True, next_nodes=("notify",)),
            Node(name="notify", kind=NodeKind.TOOL, can_fail=True, compensate="unnotify"),
        ],
        start="pay",
        spec_version="v1",
    )


@pytest.mark.security
def test_stranding_is_caught_at_two_hops_not_only_at_one() -> None:
    """The check was on direct successors, so one harmless step hid the hazard.

    The money has left in both versions of this flow. Inserting a node that cannot fail
    between the payment and the ledger write changes nothing about the world and
    everything about whether the guard fired — which makes it a guard that passes review
    and then does not hold, because nobody draws the two-hop version on the whiteboard.
    """
    with pytest.raises(ConfigurationError, match="strand itself"):
        Flow(
            [
                Node(name="pay", kind=NodeKind.TOOL, irreversible=True, next_nodes=("notify",)),
                Node(
                    name="notify",
                    kind=NodeKind.TOOL,
                    can_fail=False,
                    next_nodes=("update_ledger",),
                ),
                Node(name="update_ledger", kind=NodeKind.TOOL, can_fail=True),
            ],
            start="pay",
            spec_version="v1",
        )


@pytest.mark.security
def test_stranding_is_caught_however_far_downstream_it_is() -> None:
    """Distance from the irreversible step is not safety. Reachability is the hazard."""
    safe = [
        Node(name=f"step_{i}", kind=NodeKind.TOOL, can_fail=False, next_nodes=(f"step_{i + 1}",))
        for i in range(5)
    ]
    with pytest.raises(ConfigurationError, match="strand itself"):
        Flow(
            [
                Node(name="pay", kind=NodeKind.TOOL, irreversible=True, next_nodes=("step_0",)),
                *safe,
                Node(name="step_5", kind=NodeKind.TOOL, can_fail=True),
            ],
            start="pay",
            spec_version="v1",
        )


def test_the_stranding_error_shows_the_route_that_connects_the_two() -> None:
    """Naming only the two ends sends somebody hunting for the hop between them, which
    in a flow of any size is the whole of the debugging."""
    with pytest.raises(ConfigurationError, match=r"pay -> notify -> update_ledger"):
        Flow(
            [
                Node(name="pay", kind=NodeKind.TOOL, irreversible=True, next_nodes=("notify",)),
                Node(
                    name="notify",
                    kind=NodeKind.TOOL,
                    can_fail=False,
                    next_nodes=("update_ledger",),
                ),
                Node(name="update_ledger", kind=NodeKind.TOOL, can_fail=True),
            ],
            start="pay",
            spec_version="v1",
        )


def test_a_branch_that_never_reaches_the_irreversible_step_is_unaffected() -> None:
    """The check must not reject flows that are fine, or it gets turned off."""
    Flow(
        [
            Node(name="triage", kind=NodeKind.ROUTER, can_fail=False, next_nodes=("pay", "log")),
            Node(name="pay", kind=NodeKind.TOOL, irreversible=True, can_fail=False),
            Node(name="log", kind=NodeKind.TOOL, can_fail=True),
        ],
        start="triage",
        spec_version="v1",
    )


@pytest.mark.security
def test_a_human_node_needs_an_expiry() -> None:
    with pytest.raises(ConfigurationError, match="no owner"):
        Node(name="approve", kind=NodeKind.HUMAN, subject_summary="Approve?")


@pytest.mark.security
def test_a_human_node_needs_a_subject_summary() -> None:
    # The quality of an approval is bounded by what the approver is shown.
    with pytest.raises(ConfigurationError, match="meaningfully approve"):
        Node(name="approve", kind=NodeKind.HUMAN, expires_after_seconds=3600)


def test_flow_state_is_immutable() -> None:
    # A node that mutates shared state makes parallel branches unsafe and the flow
    # non-replayable.
    original = FlowState(data={"a": 1})
    updated = original.with_data(b=2)
    assert original.data == {"a": 1}
    assert updated.data == {"a": 1, "b": 2}


# ── Routing never guesses ────────────────────────────────────────────────────


def _router() -> Router:
    return Router(RouterSpec(agents=("adjudicate", "complaints"), threshold=0.85))


def test_a_confident_in_taxonomy_label_dispatches() -> None:
    decision = _router().route(label="adjudicate", confidence=0.95)
    assert decision.dispatched
    assert decision.agent == "adjudicate"


@pytest.mark.security
def test_a_low_confidence_classification_deflects_rather_than_guessing() -> None:
    # The surveyed codebases had a fallback agent, which turns "I don't know" into a
    # confident answer from the wrong specialist.
    decision = _router().route(label="adjudicate", confidence=0.4)
    assert not decision.dispatched
    assert decision.deflected is Deflect.HUMAN_QUEUE
    assert decision.refusal is not None


@pytest.mark.security
def test_an_invented_category_deflects() -> None:
    # The taxonomy is closed: the classifier returns a known label or unknown.
    decision = _router().route(label="something_new", confidence=0.99)
    assert not decision.dispatched


def test_ambiguity_deflects_differently_from_unknown() -> None:
    # "This is two requests" needs a different response from "we don't handle this".
    decision = _router().route(
        label="adjudicate", confidence=0.9, alternatives=("adjudicate", "complaints")
    )
    assert decision.deflected is Deflect.CLARIFY


def test_structured_context_routes_without_a_model_call() -> None:
    # A model call to classify something already labelled is spend with no assurance
    # benefit and one more thing that can be wrong.
    decision = Router.route_deterministically("complaints")
    assert decision is not None
    assert decision.confidence == 1.0
    assert Router.route_deterministically(None) is None


def test_a_router_with_no_agents_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="cannot route"):
        RouterSpec(agents=())


# ── Replay names its claim ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (ReplayMode.HISTORICAL, "this is what happened"),
        (ReplayMode.VERIFY, "the record is sound"),
        (ReplayMode.BEHAVIOURAL, "this is what we would do now"),
    ],
)
def test_each_mode_supports_exactly_one_claim(mode: ReplayMode, expected: str) -> None:
    # "We replayed the decision" is ambiguous in a way that becomes dangerous in
    # front of a regulator.
    assert ReplayPlan(mode=mode).claim() == expected


def test_only_behavioural_calls_the_model() -> None:
    assert ReplayPlan(mode=ReplayMode.BEHAVIOURAL).calls_the_model
    assert not ReplayPlan(mode=ReplayMode.VERIFY).calls_the_model
    assert not ReplayPlan(mode=ReplayMode.HISTORICAL).calls_the_model


@pytest.mark.security
def test_a_historical_replay_cannot_run_under_current_policy() -> None:
    with pytest.raises(ConfigurationError, match="not as a replay of the original"):
        ReplayPlan(mode=ReplayMode.HISTORICAL, policy=PolicyAt.CURRENT)


def test_drift_measurement_pins_policy_so_the_model_is_the_only_variable() -> None:
    plan = ReplayPlan(mode=ReplayMode.BEHAVIOURAL, policy=PolicyAt.AS_AT_RUN)
    assert plan.calls_the_model


@pytest.mark.security
def test_replay_refuses_to_re_execute_a_non_natural_tool() -> None:
    # Replay is read-only: reconstructing a report must not move money again.
    action = Action(
        tool="transfer",
        actor=ActorId("a"),
        tenant=TenantId("t"),
        arguments={},
        idempotency=IdempotencyMode.FORBIDDEN,
    )
    with pytest.raises(ConfigurationError, match="read-only"):
        ReplayPlan(mode=ReplayMode.HISTORICAL).assert_permits(action)


def test_replay_permits_a_naturally_idempotent_read() -> None:
    action = Action(
        tool="fetch",
        actor=ActorId("a"),
        tenant=TenantId("t"),
        arguments={},
        idempotency=IdempotencyMode.NATURAL,
    )
    ReplayPlan(mode=ReplayMode.HISTORICAL).assert_permits(action)


# ── Streaming ────────────────────────────────────────────────────────────────


@pytest.mark.security
def test_a_provisional_frame_carries_no_attestation_id() -> None:
    # The structural signal that this is not yet an answer.
    with pytest.raises(ConfigurationError, match="has settled"):
        Frame(text="x", provisional=True, attestation_id="run_1")  # type: ignore[arg-type]


def test_a_settled_frame_must_carry_its_attestation_id() -> None:
    with pytest.raises(ConfigurationError, match="must carry"):
        Frame(text="x", provisional=False)


@pytest.mark.security
def test_an_agent_with_tools_cannot_stream() -> None:
    # Effects never execute during phase one, but a provisional line about an
    # irreversible action has already been read by the time it is retracted.
    spec = _spec(stream=StreamPolicy.GUARDED, tools=("transfer",))
    with pytest.raises(ConfigurationError, match="still read"):
        StreamSession(spec)


def test_a_forbidden_policy_refuses_to_emit() -> None:
    with pytest.raises(ConfigurationError, match="verify, then release"):
        StreamSession(_spec()).emit("hello")


def test_matching_streamed_and_final_text_confirms() -> None:
    session = StreamSession(_spec(stream=StreamPolicy.FREE))
    session.emit("hello ")
    session.emit("world")
    frame, outcome = session.settle(attestation_id="run_1", final_text="hello world")  # type: ignore[arg-type]
    assert outcome is SettledOutcome.CONFIRMED
    assert not frame.provisional


def test_diverging_final_text_amends() -> None:
    session = StreamSession(_spec(stream=StreamPolicy.FREE))
    session.emit("draft")
    _, outcome = session.settle(attestation_id="run_1", final_text="corrected")  # type: ignore[arg-type]
    assert outcome is SettledOutcome.AMENDED


@pytest.mark.security
def test_a_guard_failure_terminates_the_stream_immediately() -> None:
    # It does not wait for generation to finish.
    session = StreamSession(_spec(stream=StreamPolicy.FREE))
    session.emit("leaking ")
    session.terminate(Refusal(reason=RefusalReason("injection_detected"), detail="pii"))
    with pytest.raises(ConfigurationError, match="terminated"):
        session.emit("more")
    _, outcome = session.settle(attestation_id="run_1", final_text="")  # type: ignore[arg-type]
    assert outcome is SettledOutcome.RETRACTED


@pytest.mark.security
def test_delegation_cannot_widen_the_childs_memory_write_authority() -> None:
    """ATT-36. Every field intersected except this one, which took the child's value.

    A parent restricted to FACTS_ONLY delegating to a child declaring
    HUMAN_INSTRUCTIONS produced a child holding HUMAN_INSTRUCTIONS. In a plugin
    ecosystem the child's spec is domain-supplied and in a compromised one it is
    attacker-supplied: the child obtains instruction-memory authority, writes a
    directive, and every later run recalls it as trusted context. Persistent prompt
    injection reached through delegation.
    """
    from attest.capabilities.memory import MemoryWritePolicy

    parent = Scope(memory_write=MemoryWritePolicy.FACTS_ONLY)
    greedy = Scope(memory_write=MemoryWritePolicy.HUMAN_INSTRUCTIONS)
    assert parent.narrowed_to(greedy).memory_write is MemoryWritePolicy.FACTS_ONLY


@pytest.mark.security
def test_a_child_may_narrow_its_own_memory_authority_further() -> None:
    """Narrowing is always permitted. It is only widening that is refused."""
    from attest.capabilities.memory import MemoryWritePolicy

    parent = Scope(memory_write=MemoryWritePolicy.HUMAN_INSTRUCTIONS)
    cautious = Scope(memory_write=MemoryWritePolicy.NONE)
    assert parent.narrowed_to(cautious).memory_write is MemoryWritePolicy.NONE


def test_an_undeclared_memory_policy_inherits_the_parents() -> None:
    from attest.capabilities.memory import MemoryWritePolicy

    parent = Scope(memory_write=MemoryWritePolicy.FACTS_ONLY)
    assert parent.narrowed_to(Scope()).memory_write is MemoryWritePolicy.FACTS_ONLY


@pytest.mark.security
def test_a_cycle_unreachable_from_the_start_is_still_refused() -> None:
    """ATT-60. `_reject_cycles` walked from the start node only.

    A cycle in a subgraph the start cannot reach is not exotic — it is what a flow looks
    like halfway through an edit, after a branch is rerouted, or when a node still points
    at a section meant to be removed. The flow validated, shipped, and the cycle waited
    for whoever reconnected that branch. "An unbounded loop is an unbounded spend", and a
    spend does not care which node the graph starts at.
    """
    with pytest.raises(ConfigurationError, match="cycle"):
        Flow(
            [
                Node(name="start", kind=NodeKind.TOOL, can_fail=False, next_nodes=("orphan_a",)),
                Node(name="orphan_a", kind=NodeKind.TOOL, can_fail=False, next_nodes=("orphan_b",)),
                Node(name="orphan_b", kind=NodeKind.TOOL, can_fail=False, next_nodes=("orphan_a",)),
            ],
            start="start",
            spec_version="v1",
        )


@pytest.mark.security
def test_a_node_nothing_can_reach_is_refused() -> None:
    """An unreachable node is a step that was written, reviewed and will never execute.

    Worse than a missing step: the diagram shows a compensation, an approval or a
    completeness check that is not in the path, and the review that looked at the diagram
    signed off on a control the run never reaches.
    """
    with pytest.raises(ConfigurationError, match="cannot be reached"):
        Flow(
            [
                Node(name="start", kind=NodeKind.TOOL, can_fail=False),
                Node(name="forgotten_compensation", kind=NodeKind.TOOL, can_fail=False),
            ],
            start="start",
            spec_version="v1",
        )


def test_a_fully_connected_flow_is_accepted() -> None:
    """The checks must not reject flows that are fine, or they get turned off."""
    Flow(
        [
            Node(name="a", kind=NodeKind.TOOL, can_fail=False, next_nodes=("b", "c")),
            Node(name="b", kind=NodeKind.TOOL, can_fail=False, next_nodes=("d",)),
            Node(name="c", kind=NodeKind.TOOL, can_fail=False, next_nodes=("d",)),
            Node(name="d", kind=NodeKind.TOOL, can_fail=False),
        ],
        start="a",
        spec_version="v1",
    )
