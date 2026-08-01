# Attest — documentation

An agent framework for **high-stakes domains**: regulatory, insurance, medical, banking,
mortgage, reporting — any system where a wrong answer is a liability, not a bad demo.

> **Status:** design draft. Nothing is built yet. These documents are for review.

---

## Reading order

Start here. Each document is short and covers one part of the system.

```
   FOUNDATIONS                  What the framework is and why
   ├── 00-thesis.md             Why this exists; what it is NOT
   ├── 01-layering.md           L0-L4, the dependency rule
   └── adoption.md              What migrating actually costs

   CONCEPTS                     The ideas everything else assumes
   ├── warrants.md              The open warrant model      <- read first
   ├── assurance-boundaries.md  What it does NOT prove      <- read second
   ├── attestation.md           What a run returns
   ├── verdicts.md              allow / hold / refuse
   ├── domain-profile.md        How a new domain plugs in   <- read third
   └── conformance.md           How a domain proves it fits

   KERNEL (L0)                  Pure, no I/O, imports nothing
   ├── config.md                Typed config; no hardcoded literals
   ├── ports.md                 Protocols the host implements
   ├── execution-context.md     Snapshots; context-determinism
   ├── determinism.md           Clock, seeds, content-addressed prompts
   ├── errors.md                Refusal vs exception
   ├── performance.md           Assurance tiers and cost budgets
   ├── storage.md               Attestation size, retention, erasure
   ├── tenancy.md               Isolation and data residency
   └── versioning.md            Four version axes; compatibility

   CAPABILITIES (L1)            The four warrants, made real
   ├── evidence.md              Epistemic  - support verification
   ├── completeness.md          Coverage   - what was MISSED
   ├── judging.md               Entailment; cross-family judges
   ├── witness.md               External proof the record is honest
   ├── contestability.md        Counterfactuals and recourse
   ├── authority.md             Authority  - obligations, approvals
   ├── approvals.md             HITL at scale; reviewer fatigue
   ├── execution.md             Effects, grants, UNKNOWN state
   ├── audit.md                 Provenance - hash chain
   ├── guards.md                Boundary   - injection, PII, leakage
   ├── llm-gateway.md           Providers, failover, budget, drift
   ├── tools.md                 Capability-gated actions
   ├── prompts.md               Versioned, content-addressed
   ├── memory.md                Recall and semantic cache
   └── lineage.md               Which records trained the model

   RUNTIME (L2)                 Putting it together
   ├── agents.md                Declarative agent specs
   ├── composition.md           The Flow graph — the primitive
   ├── chains.md                  pattern: sequential
   ├── orchestration.md           pattern: fan-out, supervisor, debate
   ├── router.md                Intent dispatch
   ├── streaming.md             Two-phase provisional release
   └── replay.md                Deterministic re-execution

   ASSURANCE (L3)               Proving it works
   ├── eval.md                  Golden sets, regression gates
   ├── redteam.md               Ten adversarial families
   ├── threat-model.md          25 attacks; the acceptance gate
   ├── testing.md               Shipped test doubles
   ├── observability.md         Production signals; what pages
   └── export.md                Evidence bundles for regulators

   DOMAINS                      Worked examples proving openness
   ├── catalog.md               The wider landscape, tiered by stakes
   ├── regulatory.md   insurance.md   medical.md
   └── banking.md      mortgage.md    reporting.md

   ADAPTERS (L4)                Optional integrations
   └── django.md                Models, migrations, DRF

   DECISIONS                    ADRs — what was chosen and why
   └── decisions/
```

---

## The one-paragraph version

Every agent action must carry four core **warrants**: *epistemic* (what evidence supports
this), *authority* (was this permitted), *provenance* (what happened, unforgeably), and
*boundary* (did untrusted input steer it, did output leak) — plus *completeness* wherever
retrieval decides the answer. A run returns an `Attestation` carrying those warrants — not a
string, and not a claim that the decision was correct. A **domain profile** is a plugin that declares what counts as
evidence, what obligations gate an action, and which additional warrants apply. The framework
ships **no** domain knowledge; medical, mortgage, and regulatory are all plugins written the
same way.

---

## The two tests this design must pass

> **Openness.** Can a team build an agent for a domain nobody on the framework team has heard
> of, without modifying the framework?

Executable version: [`concepts/conformance.md`](concepts/conformance.md).

> **Resistance.** Does the kernel hold when every layer is attacked?

Executable version: [`assurance/threat-model.md`](assurance/threat-model.md) — 25 attacks on a
single £500,000 transfer, each requiring three answers: what invariant prevents it, where it
is enforced, and what independently verifiable evidence proves it held.

This suite must pass before the framework governs an irreversible production action.
