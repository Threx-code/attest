# Router

**Choosing which agent handles a request.**

```
   request ──▶ ┌──────────┐ ──▶ agent
               │  router  │
               └────┬─────┘
                    │ no confident match
                    ▼
               deflection
               (a typed refusal, not a guess)
```

## Routing is a decision, and decisions need warrants

A misroute in a high-stakes domain is not a UX problem. Sending a complaint to a sales agent
instead of a complaints agent can breach a regulatory handling deadline before anyone
notices.

So a routing decision produces an attestation like any other:

```
   epistemic    what in the request supported this classification
   authority    is the actor entitled to reach this agent at all
   provenance   the classification call, recorded
   boundary     the request was screened before classification
```

The authority line matters more than it first appears: routing to an agent the actor may not
use should fail at the router, not deep inside a tool's capability check.

## Confidence and deflection

```
   classify
      │
      ├── confidence >= threshold  ──▶ dispatch
      │
      └── below threshold          ──▶ deflect
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
              ask a clarifying    route to a human    typed refusal
              question            queue               (out of scope)
```

**Never dispatch a low-confidence classification to the closest match.** The surveyed
codebases mostly had a fallback agent, which converts "I don't know what this is" into a
confident answer from the wrong specialist.

The threshold is domain config. A triage router may deflect at 0.5; a claims router at 0.9.

## Classification is not free-form

The taxonomy is closed and declared. The classifier returns a label from a known set or
`unknown` — never an invented category.

```python
RouterSpec(
    agents=["adjudicate", "complaints", "policy_query", "fraud_review"],
    threshold=0.85,
    on_unknown=Deflect.HUMAN_QUEUE,
    on_ambiguous=Deflect.CLARIFY,
)
```

`on_ambiguous` and `on_unknown` are distinct: "this is two requests" needs a different
response from "this is not something we handle."

## Routing is cheap; keep it that way

A router should use the fastest tier and a small token budget. It is called on every request,
and its job is classification, not analysis. If a router needs to reason at length to pick a
lane, the lanes are wrong.

## When not to route with a model

If the request arrives with structured context — a form type, a queue name, a document
class — route deterministically on that. A model call to classify something already labelled
is spend with no assurance benefit and one more thing that can be wrong.

```
   deterministic first    known form type, queue, channel, document class
   model second           only genuinely free-text intent
```

## Related

- [`agents.md`](agents.md) — the dispatch target
- [`orchestration.md`](orchestration.md) — when one request needs several agents
- [`../concepts/verdicts.md`](../concepts/verdicts.md) — deflection as a typed refusal
