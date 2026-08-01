# Domain profiles — worked examples

Six domains, written against the same protocol. **None of them required a framework change.**
That is the claim these documents exist to test.

Each follows the five-question exercise from
[`../concepts/conformance.md`](../concepts/conformance.md):

```
   1. What is a claim in this domain?
   2. What could support it?             -> evidence kinds
   3. What must be true before we act?   -> obligations
   4. What goes wrong that the core four warrants miss?  -> extra warrants
   5. What must a regulator be shown?    -> bundle contents
```

## At a glance

```
 ┌────────────┬─────────────────────┬──────────────────────┬────────────────────┐
 │ DOMAIN     │ EVIDENCE IS MOSTLY  │ HARDEST OBLIGATION   │ EXTRA WARRANTS     │
 ├────────────┼─────────────────────┼──────────────────────┼────────────────────┤
 │ regulatory │ QuotedSpan          │ filing deadline      │ temporal_validity  │
 │            │ (rule text)         │ (a TimeWindow)       │ contestability     │
 ├────────────┼─────────────────────┼──────────────────────┼────────────────────┤
 │ insurance  │ QuotedSpan +        │ four-eyes above      │ contestability     │
 │            │ Computation         │ threshold            │ temporal_validity  │
 ├────────────┼─────────────────────┼──────────────────────┼────────────────────┤
 │ medical    │ Observation         │ clinician sign-off   │ calibration        │
 │            │ (labs, imaging)     │                      │ safety             │
 │            │                     │                      │ temporal_validity  │
 ├────────────┼─────────────────────┼──────────────────────┼────────────────────┤
 │ banking    │ RecordValue         │ dual control +       │ fairness           │
 │            │ (transactions)      │ sanctions screen     │ reconciliation     │
 ├────────────┼─────────────────────┼──────────────────────┼────────────────────┤
 │ mortgage   │ Computation         │ cooling-off window   │ fairness           │
 │            │ (affordability)     │                      │ contestability     │
 ├────────────┼─────────────────────┼──────────────────────┼────────────────────┤
 │ reporting  │ Derivation          │ CFO attestation      │ reconciliation     │
 │            │ (aggregates)        │                      │ materiality        │
 └────────────┴─────────────────────┴──────────────────────┴────────────────────┘
```

## What this table demonstrates

Read the "evidence is mostly" column. Five different answers, and only one of them is
document-shaped.

A framework whose evidence primitive is `Citation(quote, char_start, char_end)` serves the
first two rows and fails the other four. That is why
[`../capabilities/evidence.md`](../capabilities/evidence.md) generalises to five verification
strategies — the document shape is the *special case*, not the model.

Likewise the obligations column: a four-rung autonomy ladder expresses none of a filing
deadline, a cooling-off window, a sanctions screen, or a named officer's attestation.

## The seventh domain

If you are evaluating a domain not listed here, work the five questions before writing code.
If questions 2 and 4 both come back "nothing fits," the framework does not serve that domain
— and finding that out on paper costs an hour rather than a quarter.
