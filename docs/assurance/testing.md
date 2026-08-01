# Testing support

Hosts implement a dozen ports. If the framework ships no test
doubles, every adopting team writes the same mocks — the exact duplication this framework
exists to end.

## `attest.testing` ships with the package

```
   attest.testing
     ├── stores/          in-memory RunStore, AuditSink (append-only,
     │                    sequence-assigning), ApprovalStore, PolicyStore,
     │                    MemoryStore
     ├── providers/       DeterministicProvider — scripted responses,
     │                    no network, no API key
     ├── retrieval/       FixtureRetriever — corpus from files,
     │                    tenant-scoped, truncation-simulating
     ├── clock/           FrozenClock, TickingClock
     ├── effects/         FakeExternalSystem — can time out, duplicate,
     │                    lie, and partially fail ON DEMAND
     ├── factories/       attestation, evidence, action, grant builders
     └── assertions/      warrant, verdict, obligation, chain matchers
```

The doubles are **not** simplified. An in-memory `AuditSink` that permits updates would let
every host's tests pass against a sink that violates its contract — so the in-memory version
enforces append-only and sequence density exactly as the real one must.

## The one that matters most

`FakeExternalSystem` is the reason the execution layer can be tested at all:

```python
bank = FakeExternalSystem()
bank.on("transfer").timeout_after(commit=True)   # succeeds, we never hear

att = agent.run(...)

assert att.effects[0].state is EffectState.UNKNOWN
assert att.verdict is Verdict.UNKNOWN
assert reconciliation_queue.depth == 1
```

Without a double that can commit-then-time-out, nobody tests the
[`../capabilities/execution.md`](../capabilities/execution.md) path — and that path is where
money is lost.

```
   FAILURE MODES IT CAN SIMULATE
   ─────────────────────────────────────────────
   timeout, effect committed
   timeout, effect not committed
   duplicate application (key ignored)
   partial success
   slow response
   malformed response
   intermittent, seeded for reproducibility
```

## Assertions read as intent

```python
assert_warrant(att, EPISTEMIC).satisfied()
assert_warrant(att, COMPLETENESS).missing_sources({"un_consolidated"})
assert_obligation(att, "approval:claims_manager").pending()
assert_chain(att).sealed().dense().verifies()
assert_no_effect(bank)
```

These matter more than convenience: an assertion library that makes checking a warrant one
line is what determines whether hosts check warrants at all.

## Three layers of host testing

```
 ┌──────────────┬──────────────────────────────────────────────────────┐
 │ UNIT         │ profile logic — obligations, verifiers, policy.       │
 │              │ No models, no I/O. Fast, and the bulk of the suite.   │
 ├──────────────┼──────────────────────────────────────────────────────┤
 │ CONFORMANCE  │ the shipped kit. Proves the profile is well-formed    │
 │              │ and cannot fail open. See concepts/conformance.md.    │
 ├──────────────┼──────────────────────────────────────────────────────┤
 │ INTEGRATION  │ real stores, FakeExternalSystem, concurrency.         │
 │              │ Where red-team families 5, 7 and 10 live — TOCTOU,    │
 │              │ event omission, duplicate effects.                    │
 └──────────────┴──────────────────────────────────────────────────────┘
```

## Golden attestations for host regression

```
   attest.testing.freeze(attestation, "cases/claim-8823.json")
```

Frozen attestations verify on every build. A host refactor that changes evidence shape,
warrant outcome, or obligation set breaks the build with a structural diff rather than a
vague failure.

The framework keeps its own frozen corpus for cross-major verification — see
[`../kernel/versioning.md`](../kernel/versioning.md).

## What is deliberately hard to test

Stated so teams do not assume coverage they lack:

- **Real provider behaviour.** `DeterministicProvider` proves plumbing, never that a prompt
  works. That is [`eval.md`](eval.md), and it costs real calls.
- **True concurrency.** Integration tests catch obvious races; they do not prove absence.
  TOCTOU defence rests on the grant design, not on tests.
- **Human review quality.** No double simulates an attentive reviewer. Control items in
  production are the only real measurement — see
  [`../capabilities/approvals.md`](../capabilities/approvals.md).

## Related

- [`../concepts/conformance.md`](../concepts/conformance.md) — the shipped suite
- [`redteam.md`](redteam.md) — what integration tests must cover
- [`../kernel/ports.md`](../kernel/ports.md) — the contracts being doubled
