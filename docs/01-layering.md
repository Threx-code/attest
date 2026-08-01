# Layering

Ports and adapters, strictly. Five layers, one absolute rule.

## The layers

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │  L4  ADAPTERS                                        optional extras │
 │      django    celery    fastapi    otel    storage backends         │
 └──────────────────────────────────────────────────────────────────────┘
                                  │
 ┌──────────────────────────────────────────────────────────────────────┐
 │  L3  ASSURANCE                                                       │
 │      eval harness    redteam    replay    evidence export            │
 └──────────────────────────────────────────────────────────────────────┘
                                  │
 ┌──────────────────────────────────────────────────────────────────────┐
 │  L2  RUNTIME                                                         │
 │      agent loop    router    chains    orchestration    budget       │
 └──────────────────────────────────────────────────────────────────────┘
                                  │
 ┌──────────────────────────────────────────────────────────────────────┐
 │  L1  CAPABILITIES                       (the four warrants, realised)│
 │      evidence   authority   audit   guards                           │
 │      llm        tools       prompts memory                           │
 └──────────────────────────────────────────────────────────────────────┘
                                  │
 ┌──────────────────────────────────────────────────────────────────────┐
 │  L0  KERNEL                              pure: no I/O, no third-party│
 │      config   types   ports   errors   clock   warrants              │
 └──────────────────────────────────────────────────────────────────────┘

           imports point DOWNWARD only  ─────────────►  never upward
```

## The dependency rule

**Imports point downward. Always.**

- L1 never imports L2. A guard cannot know there is an agent loop.
- Adapters import inward and are never imported by the core.
- L0 imports nothing outside the standard library.
- Domain profiles (plugins) attach at L0/L1 boundaries via protocols, never by editing core.

This is enforced in CI by an `import-linter` contract, not by convention. That matters: in
the six surveyed codebases, this discipline existed at the start and decayed in every one.
A rule that is not machine-checked is a preference.

```
   ALLOWED                          FORBIDDEN
   ───────────────────────          ────────────────────────────────
   runtime  -> capabilities         capabilities -> runtime
   adapters -> runtime              kernel       -> capabilities
   anything -> kernel               kernel       -> django
   assurance-> runtime              capabilities -> adapters
```

## Where a domain plugs in

A domain profile is **not** a layer. It is a plugin that supplies data and strategies
consumed by L1:

```
                    ┌──────────────────────┐
                    │   DomainProfile      │   (a plugin, outside the stack)
                    │   medical / mortgage │
                    └──────────┬───────────┘
                               │ supplies
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
   evidence verifiers    obligation sets      warrant kinds
          │                    │                    │
          ▼                    ▼                    ▼
   ┌──────────────────────────────────────────────────────┐
   │  L1  CAPABILITIES  — consume, never import, profiles  │
   └──────────────────────────────────────────────────────┘
```

L1 depends on the *protocol*, never on any concrete profile. The framework ships no domain
profiles beyond a `generic` reference implementation used in tests.

## Why this specific split

The boundary between L0 and everything else is the one that pays. A survey of an existing
codebase found a 4,789-LOC core with **zero** Django imports, and the layer above it had
exactly one leak. That proved a pure kernel is achievable in practice rather than
aspirational — and that a single unchecked leak is what starts the decay.

## Packaging maps onto layers

```
   attest              L0 + L1 core          always installed
   attest[evidence]    verifiers, entailment
   attest[tools]       registry, HITL
   attest[memory]      embeddings, cache
   attest[django]      L4 adapter
   attest[anthropic]   provider
   attest[openai]      provider
   attest[all]         everything
```

Installing `attest` alone must never pull a provider SDK, a database driver, or a web
framework.
