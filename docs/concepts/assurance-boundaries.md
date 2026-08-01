# What an attestation does and does not prove

**The most dangerous failure mode of this framework is a beautifully verifiable attestation
of a wrong decision.**

An earlier draft carried an implicit and false assumption:

> If the attestation can later be verified, the decision can be trusted.

That does not follow, and stating why is the most important clarification in these documents.

## The counterexample

```
   Claim:      "Applicant is eligible."

   Evidence:   income record V7        ✓ exists, unaltered
               policy V14              ✓ exists, quote verifies
               computation             ✓ reproduces exactly

   Warrants:   epistemic   ✓ every claim supported
               authority   ✓ obligations discharged
               provenance  ✓ chain intact, signature valid
               boundary    ✓ no injection, no leakage

   Verdict:    ALLOW
```

Every check passes. And the decision can still be wrong, because:

```
   ✗ the wrong policy version applied to the loss date
   ✗ the wrong jurisdiction's rules
   ✗ a policy amendment that retrieval never returned
   ✗ the wrong applicant (right record, wrong person)
   ✗ correct citation, wrong inference drawn from it
   ✗ a required source never searched
```

None of those is an integrity failure. All produce a perfect attestation.

## Six distinct assurances

Conflating these is how the framework oversells itself. They are separate properties with
separate machinery, and no amount of one substitutes for another.

```
 ┌──┬────────────────────┬────────────────────────────────┬──────────────────┐
 │  │ ASSURANCE          │ QUESTION                       │ STATUS           │
 ├──┼────────────────────┼────────────────────────────────┼──────────────────┤
 │ 1│ INTEGRITY          │ Did the system preserve what   │ STRONG           │
 │  │                    │ it says happened?              │ hash chain, sig  │
 ├──┼────────────────────┼────────────────────────────────┼──────────────────┤
 │ 2│ SUPPORT            │ Does the evidence support the  │ STRONG           │
 │  │                    │ claim?                         │ verifiers        │
 ├──┼────────────────────┼────────────────────────────────┼──────────────────┤
 │ 3│ COMPLETENESS       │ Did it consider everything it  │ WEAK             │
 │  │                    │ was required to consider?      │ see completeness │
 ├──┼────────────────────┼────────────────────────────────┼──────────────────┤
 │ 4│ AUTHORITY          │ Was the action legitimately    │ STRONG           │
 │  │                    │ authorised?                    │ grants           │
 ├──┼────────────────────┼────────────────────────────────┼──────────────────┤
 │ 5│ EXECUTION INTEGRITY│ Did the effect correspond to   │ MODERATE         │
 │  │                    │ the authorised action?         │ see execution    │
 ├──┼────────────────────┼────────────────────────────────┼──────────────────┤
 │ 6│ CORRECTNESS        │ Is the claim actually true?    │ NOT PROVABLE     │
 │  │                    │                                │ by this framework│
 └──┴────────────────────┴────────────────────────────────┴──────────────────┘
```

## On correctness

The framework **cannot** establish correctness, and should never imply it does.

What it can do is make incorrectness *cheaper to find and harder to hide*: the evidence is
enumerated, the reasoning is traceable, the inputs are pinned, and a reviewer can follow the
derivation to source. That is a real contribution and it is not proof.

```
   The honest claim:
     "This decision was made from these sources, under this policy version,
      authorised by these parties, and here is the complete record."

   NOT:
     "This decision was correct."
```

Any product surface that blurs those two is misrepresenting the system.

## The vocabulary this implies

An earlier draft treated the attestation as the thing that establishes everything. It is
better understood as the *record* of a chain of distinct steps:

```
   Evidence         what do we know?
      ↓
   Warrant          why is that evidence adequate?
      ↓
   Decision         what does the system conclude?
      ↓
   Authorization    is this actor allowed to cause this effect?
      ↓
   Effect           what actually happened externally?
      ↓
   Attestation      the provenance-bound record of all of the above
```

The attestation is the last step, not the whole thing. This ordering makes the architecture
much harder to attack, because each arrow is a separate claim with separate machinery — and
each can be assessed on its own.

## How this shows up in the API

The distinction is encoded, not merely documented:

```python
result = attestation.verify_historical()   # was it valid under the state it claims?
result = attestation.verify_current()      # would it satisfy today's requirements?

conformance.report()                       # states explicitly what it does NOT establish
```

See [`../capabilities/completeness.md`](../capabilities/completeness.md) for assurance 3,
[`../capabilities/execution.md`](../capabilities/execution.md) for assurance 5, and
[`attestation.md`](attestation.md) for the two verification modes.

## Related

- [`warrants.md`](warrants.md) — the machinery for assurances 1–4
- [`conformance.md`](conformance.md) — what passing conformance does not mean
- [`../assurance/threat-model.md`](../assurance/threat-model.md) — the attacks each assurance answers
