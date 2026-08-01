# Composition

**Yes — agents compose.** This document is the primitive; [`chains.md`](chains.md) and
[`orchestration.md`](orchestration.md) describe patterns expressible in it.

> **Design note.** An earlier draft had chains and orchestration as two separate mechanisms.
> That was wrong: they are the same thing with different topologies, and having two
> mechanisms means two places for warrant composition to be implemented — and to diverge.
> One graph primitive, many shapes.

## The Flow

A flow is a **directed graph of nodes over typed state**.

```
                    ┌──────────────────────────────────────┐
                    │              FlowState               │
                    │  immutable; each node returns a new  │
                    └──────────────────────────────────────┘
                                     │
   ┌────────┐   ┌────────┐   ┌───────┴──────┐   ┌────────┐   ┌────────┐
   │ intake │──▶│ verify │──▶│   decide     │──▶│ human  │──▶│ execute│
   │ agent  │   │ tool   │   │   agent      │   │ approve│   │ tool   │
   └────────┘   └────────┘   └──────┬───────┘   └────────┘   └────────┘
                                    │
                          ┌─────────┴─────────┐
                          ▼                   ▼
                    ┌──────────┐       ┌──────────┐
                    │ escalate │       │  refuse  │
                    │ sub-flow │       │  node    │
                    └──────────┘       └──────────┘
```

## Node kinds

Every node produces an attestation fragment. That is what makes the composition auditable
rather than merely functional.

```
 ┌──────────────┬────────────────────────────────────────────────────────┐
 │ AgentNode    │ runs an AgentSpec — the only node that calls a model    │
 │ ToolNode     │ a deterministic action; obligations still apply         │
 │ FunctionNode │ pure host code — no model, no attestation warrants      │
 │              │ beyond provenance                                       │
 │ HumanNode    │ a person is a first-class participant, not an exception │
 │ SubFlowNode  │ a nested flow; composes as one node to its parent       │
 │ RouterNode   │ conditional dispatch (see router.md)                    │
 │ GatherNode   │ merges parallel branches; where conflict is detected    │
 └──────────────┴────────────────────────────────────────────────────────┘
```

`FunctionNode` matters more than it looks. **Most steps in a high-stakes flow should not be
agents.** A threshold comparison, a date calculation, an eligibility rule — these are
deterministic and belong in code. Modelling them as agents is how these systems become slow,
expensive, and less correct at once.

```
   RULE OF THUMB
   ─────────────────────────────────────────────────────────
   deterministic and specifiable  ->  FunctionNode or ToolNode
   judgement over unstructured    ->  AgentNode
   consequential and contested    ->  HumanNode
```

## Agents delegating to agents

Two distinct mechanisms, often conflated:

```
   DELEGATION  (agent A calls agent B as a tool)
   ─────────────────────────────────────────────────────
   A stays in control. B's attestation nests inside A's.
   A may reject B's answer.
   Budget and step count are shared and charged to A.

        ┌───┐
        │ A │──── calls ───▶ ┌───┐
        └───┘                │ B │
          ▲                  └─┬─┘
          └─── returns ────────┘


   HANDOFF  (control transfers to agent B)
   ─────────────────────────────────────────────────────
   A is finished. B owns the rest.
   Attestations are siblings in one chain, not nested.
   Context transfers explicitly — never implicitly.

        ┌───┐                ┌───┐
        │ A │═══ becomes ═══▶│ B │
        └───┘                └───┘
```

**Handoff context must be explicit.** Passing a whole conversation to the next agent carries
whatever was injected into it. The handoff declares what transfers:

```python
Handoff(to="complaints_agent",
        carry=["customer_ref", "policy_ref", "summary"],
        drop=["raw_transcript"])
```

## Recursion is bounded

Delegation can nest. Left unbounded, an agent that delegates to itself is an unbounded spend.

```
   max_depth        default 3, hard ceiling
   cycle detection  A -> B -> A is refused at construction where the
                    graph is static, at runtime where it is dynamic
   shared budget    the whole tree draws on one budget, not one each
```

Shared budget is the important one. Per-agent budgets in a delegation tree multiply: five
agents at £1 each is £5, not £1.

## State

```python
@dataclass(frozen=True)
class FlowState:
    data: Mapping           # typed, validated against the flow's schema
    attestations: Sequence  # every node's fragment, in order
    pending: PendingAction | None
```

Immutable. Each node returns a new state. This is what makes parallel branches safe and the
whole flow replayable — a node that mutates shared state makes both impossible.

## Long-running flows

A mortgage application spans weeks. A regulatory filing spans a quarter. Flows must survive
process restarts, deploys, and human latency.

```
   ┌──────────────────────────────────────────────────────────────┐
   │  flow suspended at HumanNode "underwriter_approval"           │
   │                                                              │
   │   state          persisted, versioned                        │
   │   pending        PendingAction, expires_at set               │
   │   flow version   pinned — a deploy must not change the flow  │
   │                  under a suspended run                       │
   │                                                              │
   │  on resume (days later):                                     │
   │    1. re-discharge ALL prior obligations                     │
   │    2. re-verify prior evidence  <- may now be stale          │
   │    3. continue from the suspended node                       │
   └──────────────────────────────────────────────────────────────┘
```

**Pinning the flow version is not optional.** If a flow definition changes while runs are
suspended against it, resuming executes a graph the earlier steps were never validated
against. Suspended runs complete on the version they started.

Steps 1 and 2 are what catch the case that makes long-running flows dangerous: an approval
sits for a week, and the valuation, the budget, or the applicant's circumstances change
underneath it.

## Warrant composition

The rules are the same regardless of topology — which is the point of having one primitive:

```
   epistemic     union; cross-node citations become Derivation evidence
   authority     union; ALL obligations must hold at execution time
   provenance    one linear chain across the whole flow, branches marked
   boundary      strictest wins; a violation anywhere fails the flow
   domain kinds  per the profile's WarrantPolicy
   conflict      contradictory conclusions are a FINDING, never a vote
```

## Static validation

A flow is checked at construction, before it ever runs:

```
   ✓ no cycles (unless explicitly a bounded loop)
   ✓ state schema flows through every path
   ✓ every HumanNode has an expiry and a subject_summary
   ✓ an irreversible node is not followed by an uncompensated failable node
   ✓ every terminal node produces a verdict
   ✓ delegation depth within ceiling
```

These are cheap compile-time checks for failures that are expensive at runtime.

## When NOT to use a flow

```
   one agent, one answer         just run the agent
   deterministic end to end      write the function; no framework needed
   high volume, low stakes       a flow's overhead is not free — see
                                 kernel/performance.md on assurance tiers
```

## Related

- [`chains.md`](chains.md) — the sequential pattern
- [`orchestration.md`](orchestration.md) — fan-out, supervisor, debate
- [`agents.md`](agents.md) — what an `AgentNode` runs
- [`../capabilities/authority.md`](../capabilities/authority.md) — re-discharge on resume
