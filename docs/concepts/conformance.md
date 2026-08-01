# Conformance

**How a new domain proves it fits — before anyone migrates to it.**

The design constraint from [`../00-thesis.md`](../00-thesis.md) is:

> A team must be able to build an agent for a domain the framework authors have never heard
> of, without modifying the framework.

That is a claim. This document is how the claim is tested, mechanically, in CI.

## The conformance kit

`attest.conformance` ships a pytest suite that a domain package runs against its own profile.

```python
# in the domain package's tests
from attest.conformance import ProfileConformance

class TestMortgageProfile(ProfileConformance):
    profile = MortgageProfile(jurisdiction="UK")
```

That is the whole integration. The base class supplies ~40 tests.

## What it checks

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │  STRUCTURAL          the profile satisfies the protocol             │
 │    - every declared warrant kind has a policy                       │
 │    - every evidence kind has a verifier                             │
 │    - refusal taxonomy covers every core reason                      │
 │    - version is a valid semver string                               │
 ├─────────────────────────────────────────────────────────────────────┤
 │  BEHAVIOURAL         the verifiers actually verify                  │
 │    - a known-good evidence item verifies TRUE                       │
 │    - a tampered evidence item verifies FALSE      <- the real test  │
 │    - a stale evidence item fails validity()                         │
 │    - verifiers are deterministic (same input -> same result)        │
 │    - verifiers do not mutate their inputs                           │
 ├─────────────────────────────────────────────────────────────────────┤
 │  AUTHORITY           obligations behave                             │
 │    - an action below threshold discharges cleanly                   │
 │    - an action above threshold produces PENDING, never SATISFIED    │
 │    - obligations are total: no action returns an empty set silently │
 │    - discharge is idempotent                                        │
 ├─────────────────────────────────────────────────────────────────────┤
 │  SAFETY              the profile cannot fail open                   │
 │    - unknown action  -> obligations, not a free pass                │
 │    - unknown evidence kind -> refuse, not "assume verified"         │
 │    - verifier raising  -> UNSATISFIED, never swallowed as satisfied │
 │    - compose(other) preserves the stricter policy                   │
 ├─────────────────────────────────────────────────────────────────────┤
 │  ROUND-TRIP          attestations survive the boundary              │
 │    - attestation serialises and deserialises unchanged              │
 │    - export() bundle verifies offline                               │
 │    - verify() on an untampered bundle passes                        │
 │    - verify() on a tampered bundle FAILS                            │
 └─────────────────────────────────────────────────────────────────────┘
```

The **fail-open tests are the point**. Every surveyed codebase had at least one
`except Exception: return True` in a guard path. A profile that cannot fail open is the
minimum bar for a high-stakes domain, and it is not something code review reliably catches.

## The adversarial half

Structural conformance proves the profile is *well-formed*. It does not prove it is *right*.
The kit also ships a red-team harness the domain must pass:

```
   attest.conformance.redteam
      │
      ├── injection corpus       does the profile's boundary policy hold
      │                          against prompt injection in evidence text?
      │
      ├── evidence forgery       does a fabricated citation verify FALSE?
      │                          (the single most common LLM failure)
      │
      ├── authority bypass       can a tool run without discharging
      │                          its obligations, via any path?
      │
      └── warrant starvation     does an empty/degenerate evidence set
                                 still produce ALLOW? (it must not)
```

A domain package that fails these does not ship. This is enforced the same way a type error
is — in CI, not in review.

## What conformance does NOT prove

Developers hear "conformance PASS" as "the profile is safe." It does not mean that, and
documentation alone will not stop the inference — so the **report states it**:

```
   ┌──────────────────────────────────────────────────────────────┐
   │  CONFORMANCE  PASS          profile: mortgage@2.1.0          │
   ├──────────────────────────────────────────────────────────────┤
   │  ESTABLISHED                                                 │
   │    ✓ implementation satisfies framework contracts            │
   │    ✓ verifiers are deterministic and reject tampering        │
   │    ✓ obligations are total and cannot fail open              │
   │    ✓ attestations round-trip and verify offline              │
   ├──────────────────────────────────────────────────────────────┤
   │  NOT ESTABLISHED                                             │
   │    ✗ regulatory compliance                                   │
   │    ✗ domain correctness (are the thresholds right?)          │
   │    ✗ model accuracy                                          │
   │    ✗ completeness of retrieval                               │
   │    ✗ fairness of outcomes                                    │
   │    ✗ operational safety under load or failure                │
   └──────────────────────────────────────────────────────────────┘
```

The `NOT ESTABLISHED` block is emitted on every run, including passes. A green check that
travels to a compliance pack without that block attached is a misrepresentation, and the
easiest way to prevent it is to make them inseparable.

Where each of those *is* addressed: [`../assurance/eval.md`](../assurance/eval.md) for
correctness and fairness, [`../capabilities/completeness.md`](../capabilities/completeness.md)
for coverage, [`../assurance/redteam.md`](../assurance/redteam.md) families 5 and 10 for
operational safety.

## The seventh-project test

Before adopting any new domain, run this exercise on paper. It takes an hour and it is the
cheapest possible way to find that the framework does not fit.

```
   1. What is a claim in this domain?
        "the applicant is eligible" / "this figure is 4.2m" / "this lesion is benign"

   2. What could support it?
        -> map to an EvidenceKind. If nothing fits, you need a new verifier.
           If you cannot describe verification, the domain is not ready for an agent.

   3. What must be true before the system acts?
        -> map to Obligations. Who approves? How many? Is there a waiting period?
           Is the action reversible?

   4. What goes wrong that the core four warrants do not catch?
        -> that is your extra warrant kind.

   5. What must a regulator be shown, and in what form?
        -> that is your EvidenceBundle contents.
```

If steps 2 and 4 both come back "nothing fits," the framework genuinely does not serve that
domain — and that is a finding worth having before writing code, not after.

Worked answers for six domains live in [`../domains/README.md`](../domains/README.md).

## Related

- [`domain-profile.md`](domain-profile.md) — the protocol being conformed to
- [`../assurance/redteam.md`](../assurance/redteam.md) — the adversarial suites
- [`../assurance/eval.md`](../assurance/eval.md) — correctness, as opposed to well-formedness
