# Thesis

## The problem

LangChain, LlamaIndex, and the rest optimise for **composability**: swap a model, chain a
step, ship a demo. That is the right optimisation when the cost of a wrong answer is a bad
demo.

It is the wrong optimisation for high-stakes systems. Consider the domains this framework
targets:

```
  DOMAIN         A WRONG ANSWER IS...              WHO ASKS "WHY?"
  ─────────────  ────────────────────────────────  ──────────────────────
  Regulatory     a compliance breach               the regulator
  Insurance      a wrongful claim denial           the ombudsman, courts
  Medical        a patient harm event              the clinician, coroner
  Banking        an AML failure or unlawful debit  the regulator, auditor
  Mortgage       a discriminatory lending refusal  the regulator, claimant
  Reporting      a material misstatement           the auditor, the board
```

In every row, someone with authority eventually asks the same question:

> **"Can you defend this decision — six months from now, after the model has been
> deprecated?"**

No general-purpose agent framework answers that. So teams each grow their own answer,
independently, and the answers drift apart. This framework makes that answer the primitive.

## What this actually is

Not an agent framework. **A control plane for governed AI actions.**

The distinction is strategic and architectural. An "agent framework for regulated industries"
invites comparison with LangGraph and the OpenAI Agents SDK on their terms — orchestration
ergonomics — where this design will always look heavy. The real abstraction is a layer below:

```
                    GOVERNED AI CONTROL PLANE

        ┌───────────── Intelligence ──────────────┐
        │  agents · models · retrieval · humans   │
        └────────────────────┬────────────────────┘
                             │  propose
                             ▼
        ┌─────────────────────────────────────────┐
        │            CONTROL KERNEL               │
        │                                         │
        │  evidence   completeness   authority    │
        │  boundary   provenance     execution    │
        └────────────────────┬────────────────────┘
                             │  authorised effect
                             ▼
        ┌─────────────────────────────────────────┐
        │   external systems · money · people     │
        └─────────────────────────────────────────┘
```

An agent is **one producer of proposed actions**, not the centre of the system. A rules
engine, a human operator, or a scheduled job can propose through the same kernel and get the
same guarantees. That is a more defensible position than competing on orchestration, and it
is what the architecture already is.

The practical consequence: the agent API is the *entry point*, the kernel is the *product*.

## The insight

The thing that must be durable is not the *response*. It is the **record that the response
was warranted**.

```
   Conventional framework            Attest
   ──────────────────────            ──────────────────────────────────
   run() -> str                      run() -> Attestation
                                       ├── verdict
   "The claim is payable             ├── answer
    under section 4.2."              ├── warrants
                                       │     epistemic  what supports it
   (Trust me.)                         │     authority  who allowed it
                                       │     provenance what happened
                                       │     boundary   what was contained
                                       └── .verify()  .export()
```

An `Attestation` is verifiable offline, exportable as an evidence bundle, and replayable
against the exact model and prompt version that produced it.

## Why a framework rather than a library per project

Because the same machinery gets rebuilt every time, and the copies drift silently.

Two real measurements from a survey of six existing backends:

- A 199-line rules engine appears in two projects; the **entire diff is one character** — a
  currency symbol. The copies could never be reconciled because a config value was baked
  into code.
- A 219-line grounding contract appears in three projects. In one of them a repo-wide regex
  pass corrupted it into a `SyntaxError`. Nobody noticed, because the copies share no test
  suite.

That is the cost of "just copy the folder": not the duplicated lines, but the impossibility
of fixing them once.

## What is explicitly NOT in scope

Naming these prevents the framework from becoming a second LangChain by accretion.

| Not this | Because |
|---|---|
| A RAG toolkit | No loaders, chunkers, or vector-store wrappers. Retrieval is a *port*. The framework governs what happens to evidence, not how you fetch it. |
| A model zoo | Providers exist to be swapped and failed over, not catalogued. |
| A prompt library | Ships prompt *infrastructure* — versioning, boundaries, composition. Never domain prompt bodies. |
| A chat product | No conversation models, no message threads. Host concerns. |
| Domain knowledge | Ships **zero** medical, legal, or financial rules. Domains are plugins. |
| Django-coupled | Django is one adapter among several. The core imports nothing. |

## The design constraint that governs everything

> A team must be able to build an agent for a domain the framework authors have never heard
> of, without modifying the framework.

Every abstraction in these documents is answerable to that sentence. Where a design choice
would require editing the framework to add a domain, the choice is wrong.

See [`concepts/domain-profile.md`](concepts/domain-profile.md) for how this is enforced, and
[`concepts/conformance.md`](concepts/conformance.md) for the executable test.
