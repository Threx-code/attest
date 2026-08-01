"""Delegation: what narrows, and what used to escape.

``DelegationChain`` exists to make "delegation can only ever narrow" **structural**
rather than a preference. Every test here is about a field that was outside the thing
being narrowed and therefore was not narrowed at all — which is not a bug in the
narrowing, it is a bug in what got put inside the scope.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


# ── The stream ceiling travels with the scope ────────────────────────────────


@pytest.mark.security
def test_a_parent_that_forbids_streaming_forbids_it_for_the_whole_subtree() -> None:
    """`stream` lived only on AgentSpec, and delegation narrows the Scope.

    So a parent declaring FORBIDDEN constrained itself and nothing it delegated to: the
    child declared FREE and streamed. Exactly the shape of the `memory_write` defect
    already fixed one field over, with the same cause — a property that constrains an
    agent, kept somewhere delegation does not reach.

    It matters because a retracted statement was still read. A clinician who saw a
    provisional line about a drug interaction has seen it, whatever the retraction says
    afterwards, and a tier-1 domain setting FORBIDDEN at the root of its tree believes
    it is buying the whole tree.
    """
    from attest.runtime.agents import AgentSpec, Scope, StreamPolicy
    from attest.runtime.delegation import DelegationChain

    parent = AgentSpec(
        name="adjudicator",
        version="1.0.0",
        prompt="adjudicate",
        stream=StreamPolicy.FORBIDDEN,
        scope=Scope(may_delegate_to=frozenset({"summariser"})),
        delegates_to=("summariser",),
    )
    chain = DelegationChain(root="adjudicator")
    chain.register(parent)

    narrowed = chain.delegate(
        parent="adjudicator",
        child="summariser",
        child_scope=Scope(stream=StreamPolicy.FREE),
    )
    assert narrowed.stream is StreamPolicy.FORBIDDEN, (
        "the child widened the stream policy, so unverified text reaches a reader that "
        "the parent's domain forbade showing anything unverified to"
    )


def test_a_child_may_still_be_stricter_than_its_parent() -> None:
    """Narrowing is one-directional, not equalising."""
    from attest.runtime.agents import AgentSpec, Scope, StreamPolicy
    from attest.runtime.delegation import DelegationChain

    chain = DelegationChain(root="a")
    chain.register(
        AgentSpec(
            name="a",
            version="1.0.0",
            prompt="a",
            stream=StreamPolicy.FREE,
            scope=Scope(may_delegate_to=frozenset({"b"})),
            delegates_to=("b",),
        )
    )
    narrowed = chain.delegate(parent="a", child="b", child_scope=Scope(stream=StreamPolicy.GUARDED))
    assert narrowed.stream is StreamPolicy.GUARDED


def test_the_effective_scope_carries_the_agents_own_choice() -> None:
    """Registering the bare `spec.scope` is the mistake `register` exists to prevent."""
    from attest.runtime.agents import AgentSpec, Scope, StreamPolicy

    spec = AgentSpec(
        name="a", version="1.0.0", prompt="a", stream=StreamPolicy.FORBIDDEN, scope=Scope()
    )
    assert spec.scope.stream is StreamPolicy.FREE, "an unset scope ceiling is unrestricted"
    assert spec.effective_scope().stream is StreamPolicy.FORBIDDEN


# ── ATT-62/63: streaming ─────────────────────────────────────────────────────


def test_a_supervisor_with_no_tools_of_its_own_cannot_stream() -> None:
    """ATT-62. The check was `spec.stream is not FORBIDDEN and spec.tools`.

    A supervisor holding no tools — which is the ordinary shape of a supervisor, and
    the pattern the composition docs recommend — streamed freely while delegating to a
    child holding irreversible ones. The rule was evaded by one level of indirection.
    """
    from attest.kernel.errors import ConfigurationError
    from attest.runtime.agents import AgentSpec, Scope, StreamPolicy
    from attest.runtime.streaming import StreamSession

    supervisor = AgentSpec(
        name="supervisor",
        version="1.0.0",
        prompt="coordinate",
        tools=(),
        stream=StreamPolicy.GUARDED,
        scope=Scope(may_delegate_to=frozenset({"payer"}), stream=StreamPolicy.GUARDED),
        delegates_to=("payer",),
    )
    with pytest.raises(ConfigurationError, match="delegates_to"):
        StreamSession(supervisor)


def test_an_agent_with_neither_tools_nor_delegates_may_still_stream() -> None:
    """The rule must not become "nothing streams", or deployments turn it off."""
    from attest.runtime.agents import AgentSpec, Scope, StreamPolicy
    from attest.runtime.streaming import StreamSession

    session = StreamSession(
        AgentSpec(
            name="explainer",
            version="1.0.0",
            prompt="explain",
            stream=StreamPolicy.GUARDED,
            scope=Scope(stream=StreamPolicy.GUARDED),
        )
    )
    assert session.emit("provisional text").provisional


def test_a_terminated_stream_keeps_the_reason_it_was_terminated() -> None:
    """ATT-63. `terminate(refusal)` discarded its argument.

    A stream killed by an outbound guard left no record of why: no event, no finding,
    nothing. The guard fired, the reader saw text stop mid-sentence, and the audit trail
    said a stream ended. That is the worst shape for this failure — a terminating
    outbound guard means something was about to leave the boundary that should not have.
    """
    from attest.kernel.verdicts import Refusal, RefusalReason
    from attest.runtime.agents import AgentSpec, Scope, StreamPolicy
    from attest.runtime.streaming import SettledOutcome, StreamSession

    session = StreamSession(
        AgentSpec(
            name="explainer",
            version="1.0.0",
            prompt="explain",
            stream=StreamPolicy.GUARDED,
            scope=Scope(stream=StreamPolicy.GUARDED),
        )
    )
    session.emit("the account number is ")
    refusal = Refusal(
        reason=RefusalReason("outbound_leakage"),
        detail="an unredacted account number was about to be released",
    )
    assert session.terminate(refusal) is SettledOutcome.RETRACTED

    assert session.terminated
    assert session.refusal is refusal, "the reason the stream was killed was discarded"
    assert "account number" in session.refusal.detail


def test_a_stream_that_was_not_terminated_has_no_refusal() -> None:
    """So a caller can tell "ended normally" from "killed and the reason was lost"."""
    from attest.runtime.agents import AgentSpec, Scope, StreamPolicy
    from attest.runtime.streaming import StreamSession

    session = StreamSession(
        AgentSpec(
            name="explainer",
            version="1.0.0",
            prompt="explain",
            stream=StreamPolicy.GUARDED,
            scope=Scope(stream=StreamPolicy.GUARDED),
        )
    )
    assert session.refusal is None
    assert not session.terminated
