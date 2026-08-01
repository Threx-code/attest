# Agents

**An agent is a declaration, not a class.**

## Why declarative

One surveyed codebase defines ~50 agents. Its registry begins with a 60-line import block of
agent-name constants, and each agent is a module. Adding one touches four files.

```
   CLASS PER AGENT                     DECLARATIVE SPEC
   ─────────────────────               ────────────────────────────
   class ClaimAdjudicator(BaseAgent):  AgentSpec(
       AGENT_TYPE = AGENT_ADJUDICATE     name="claim_adjudicator",
       def build_prompt(self): ...       model_tier=REASONING,
       def get_tools(self): ...          tools=["fetch_policy", ...],
       def run(self): ...                prompt="insurance/adjudicate@2",
                                         ...
   Behaviour and configuration        )
   are tangled. Every agent is
   an opportunity to diverge.         Configuration is data. Behaviour
                                      is one shared, tested loop.
```

Data can be validated, diffed, listed, and conformance-tested. Fifty subclasses cannot.

## The spec

```python
@dataclass(frozen=True)
class AgentSpec:
    name: str
    version: str
    model_tier: Tier                   # FAST · BALANCED · REASONING — resolved by config
    prompt: PromptRef

    tools: Sequence[str] = ()
    max_steps: int = 8

    # warrants — tightening only
    warrant_overrides: Mapping[WarrantKind, WarrantPolicy] = field(default_factory=dict)

    # remit — what this agent may and may not address
    scope: Scope = Scope.UNRESTRICTED
    output_schema: JSONSchema | None = None
```

`model_tier` rather than a model id. The concrete model comes from config, so switching
providers is a config change and never fifty edits. This pattern already exists in one
surveyed codebase and is worth keeping. `AgentSpec.completion_floor()` hands it to the
gateway as `CompletionRequest.min_tier`, so a frontier-tier agent is not served by a small
fast model on failover - feature parity is not quality parity, and a down-tiered answer is
structurally identical to a good one.

### An agent may tighten, and may not loosen

`warrant_overrides` is resolved against the profile's policy by
`WarrantPolicy.strictest()`, the same comparison `ProfileComposer` uses when composing two
profiles. So a supervisor that BLOCKs on the boundary warrant while its deployment only
WARNs is a deployment choosing to be careful about one agent, and the reverse - an agent
quietly relaxing a policy its deployment set - cannot happen. `NON_DOWNGRADEABLE` still
sits above all of it: no policy from any source softens a tenancy crossing.

Pass the spec on `RunRequest.agent`. Omit it and nothing changes, which is what a rules
engine, a scheduled job or a human proposing through the same shape wants.

**`evidence_required` was removed.** It read as a control and could never be one: EPISTEMIC
is in `CORE_WARRANTS`, so every profile already evaluates it, and `EvidenceEngine.evaluate`
already fails an empty set with `no_evidence`. `True` could add nothing and `False` must
not remove anything, which left a field whose only possible effect was to mislead whoever
set it. An agent that wants to be stricter about evidence uses `warrant_overrides`; a
deployment that wants to be looser is the profile's call.

## Scope is enforced at every boundary, not just the response

An earlier draft said the response guard enforces scope. That is far too late.

```
   ClaimsAgent, scope = insurance_claims
   model asks for the patient's oncology record
        │
        ├── retrieval returns it
        ├── it enters the model's context
        ├── it is written to memory as a derived fact
        ├── it is passed to a delegated agent
        │
        └── response guard blocks the final answer   ◀── the breach already happened
```

Blocking the answer does not un-retrieve the record, un-see it, or un-write the memory. Scope
must constrain the boundaries **before** data moves:

```
 ┌──────────────┬──────────────────────────────────────────────────────┐
 │ retrieval    │ which corpora and evidence classes may be queried    │
 │ tools        │ which tools are even advertised to the model         │
 │ evidence     │ which SourceTypes may enter context                  │
 │ memory       │ what may be read, and what may be written            │
 │ delegation   │ which agents may be called, and what may be carried  │
 │ handoff      │ what transfers, what is dropped                      │
 │ output       │ the response guard — the LAST line, not the only one │
 └──────────────┴──────────────────────────────────────────────────────┘
```

```python
Scope(
    corpora={"policy_wordings", "claims_history"},
    evidence_types={SourceType.POLICY_DOC, SourceType.LEDGER},
    forbid_evidence_types={SourceType.CLINICAL},     # explicit, checked at retrieval
    may_delegate_to={"fraud_screen"},
    memory_write=MemoryWrite.FACTS_ONLY,
)
```

An agent that answers outside its remit is a failure mode regulated domains care about
specifically — a claims agent offering medical advice, an eligibility agent offering tax
advice. An agent that *retrieves* outside its remit is a data-protection incident even if it
never says a word.

## The loop

One implementation, shared by every agent.

```
   ┌──────────────────────────────────────────────────────────┐
   │  1. screen input           guards, inbound               │
   │  2. assemble context       evidence, memory, actor       │
   │  3. render prompt          content-addressed             │
   │  4. call model             via gateway                   │
   │  5. model responds                                       │
   │       ├── answer      ──▶ go to 7                        │
   │       └── tool call   ──▶ 6                              │
   │  6. tool: verify -> discharge -> execute -> record       │
   │       └── result is UNTRUSTED ──▶ screen, back to 3      │
   │  7. verify evidence        every claim                   │
   │  8. evaluate warrants      core + domain-registered      │
   │  9. screen output          guards, outbound              │
   │ 10. assemble Attestation                                 │
   └──────────────────────────────────────────────────────────┘
                    every step appends to the audit chain
```

Steps 7–9 are not optional and are not the agent's choice. An agent cannot opt out of
producing a warrant; it can only influence policy through `warrant_overrides`, and a profile
may forbid even that.

## Step budget

`max_steps` is a hard stop, not a suggestion. Hitting it yields
`REFUSE(reason=step_budget_exhausted)` with a full attestation — never a partial answer
presented as complete. A truncated answer that looks whole is worse than a refusal in every
domain this framework targets.

## Registration

```python
# host or domain package
registry.register(AgentSpec(name="claim_adjudicator", ...))
```

Specs are data, so they can equally be loaded from YAML, generated, or supplied by a domain
package. The framework ships none.

## Related

- [`chains.md`](chains.md) — composing agents in sequence
- [`orchestration.md`](orchestration.md) — teams and supervisors
- [`../capabilities/tools.md`](../capabilities/tools.md) — step 6
- [`../concepts/attestation.md`](../concepts/attestation.md) — step 10
