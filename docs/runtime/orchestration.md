# Orchestration

**Composition that is not a straight line:** fan-out, teams, supervisors, and adversarial
review.

> **Patterns, not mechanisms.** Each shape below is a `Flow` topology. The primitive and the
> warrant-composition rules live in [`composition.md`](composition.md) — read that first.

## Patterns

```
   FAN-OUT / GATHER                    SUPERVISOR
   ─────────────────                   ──────────────────────────
        ┌───┐                               ┌────────────┐
        │ in│                               │ supervisor │
        └─┬─┘                               └──┬──┬──┬───┘
     ┌────┼────┐                     plans ────┘  │  └──── replans
     ▼    ▼    ▼                                  ▼
   ┌──┐ ┌──┐ ┌──┐                            ┌─────────┐
   │a1│ │a2│ │a3│   independent              │ workers │  iterative,
   └─┬┘ └─┬┘ └─┬┘   parallel                 └─────────┘  budget-bounded
     └────┼────┘
          ▼
      ┌────────┐                      DEBATE / ADVERSARIAL
      │ gather │                      ────────────────────────
      └────────┘                        ┌──────┐    ┌────────┐
                                        │propose│──▶│ critic │
                                        └──────┘    └───┬────┘
                                            ▲           │
                                            └───────────┘
                                          until converged or
                                          budget exhausted
```

## Choosing between them

```
 ┌──────────────┬────────────────────────────┬──────────────────────────────┐
 │ PATTERN      │ USE WHEN                   │ COST SHAPE                   │
 ├──────────────┼────────────────────────────┼──────────────────────────────┤
 │ chain        │ each step needs the last   │ sum of steps; latency adds   │
 │ fan-out      │ steps are independent      │ sum of steps; latency = max  │
 │ supervisor   │ the plan is not known      │ unbounded without a budget   │
 │              │ up front                   │ -> always bound it           │
 │ debate       │ a wrong answer is costlier │ 2-5x a single call           │
 │              │ than 3x the tokens         │                              │
 └──────────────┴────────────────────────────┴──────────────────────────────┘
```

Debate earns its cost in exactly the domains this framework targets. A second agent
instructed to *refute* a claim catches "plausible but wrong" — the failure mode that
evidence verification cannot catch, because the citations are real and the inference is
wrong.

## Warrant composition across parallel branches

Fan-out raises a question a chain does not: branches may **disagree**.

```
   a1: "eligible"     epistemic OK
   a2: "not eligible" epistemic OK        <- both well-supported
   a3: "eligible"     epistemic OK

   Naive: majority vote -> "eligible"
   Wrong: it discards a well-supported contradiction, which is
          the single most informative signal in the run.
```

The framework's position: **contradiction is a finding, not noise.**

```
   gather step detects contradictory conclusions among branches
                              │
                              ▼
              ConflictFinding recorded in the epistemic warrant
                              │
                    profile's WarrantPolicy decides
                              │
        ┌──────────────┬──────┴───────┬──────────────┐
        ▼              ▼              ▼              ▼
      BLOCK          HOLD           WARN          RECORD
    (medical)     (mortgage)     (research)     (triage)
```

A medical profile blocks on contradiction. A triage profile records it and proceeds. The
framework never silently votes.

## Supervisors must be bounded

A supervisor that plans its own next step is unbounded by construction. Three limits are
mandatory, not optional:

```
   max_iterations     hard stop on replanning
   token budget       enforced at the gateway, per run
   wall clock         a held approval must not hold a worker loop open
```

Without these, a supervisor with a slightly wrong stopping condition is an unbounded spend.

## Isolation between branches

Parallel branches must not share mutable state. Each gets its own context; results merge only
at the gather step. The reason is not tidiness — it is that a branch that mutates shared
context makes the run non-replayable, and replay is a core guarantee.

## One canonical audit stream over a branching execution

However complex the topology, an auditor receives **one ordered record with one head hash**.
But the execution is genuinely a DAG, and pretending otherwise loses causality and makes
ordering arbitrary under concurrency.

```
   execution DAG            each event records its parent(s)
        │
        ▼
   canonical ordering       deterministic topological sort:
        │                   parent, then branch id, then local sequence
        ▼
   sealed hash chain        e1 dispatch
                            e2   branch:a1 start   parent e1
                            e3   branch:a2 start   parent e1
                            e4   branch:a1 tool    parent e2
                            ...
                            e9 gather (a1,a2,a3; conflict: yes)
                            e10 complete
```

Because the ordering is deterministic, two independent verifiers compute the same chain — a
naive "append in arrival order" scheme does not guarantee that under concurrency, and two
verifiers reaching different head hashes destroys the evidentiary value. See
[`../capabilities/audit.md`](../capabilities/audit.md).

## Related

- [`chains.md`](chains.md) — sequential composition
- [`router.md`](router.md) — choosing which agent runs
- [`../capabilities/audit.md`](../capabilities/audit.md) — the linear chain
