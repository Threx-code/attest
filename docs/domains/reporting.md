# Reporting

The domain where evidence is almost entirely **derived**, and where the interesting warrant
is one no other domain needs.

## 1. What is a claim?

> "Q3 insurance provision is £4.2m, up 12% on Q2, driven by escape-of-water claims."

Three claims: a figure, a comparison, and a causal attribution. The third is the dangerous
one.

## 2. What supports it?

```
   "Q3 provision = £4.2m"                    Derivation
     ├── "open claims total £3.8m"           Derivation
     │     ├── claim 8823: £12,400           Computation
     │     ├── claim 8824: £3,100            Computation
     │     └── ... 412 more                  (the tree is wide)
     └── "IBNR factor 1.105 per IAS 37"      QuotedSpan

   "up 12% on Q2"                            Derivation
     └── over this quarter and the prior published figure

   "driven by escape-of-water"               Derivation
     └── over a segmentation query — and this is where
         a causal word is doing work the evidence does not support
```

The third claim is the one to watch. "Driven by" asserts causation; the evidence supports
correlation. Mechanical verification passes. This is the "real quote, wrong inference"
failure from [`../assurance/redteam.md`](../assurance/redteam.md), in numeric form.

## The width problem

A reporting evidence tree has thousands of leaves, not five.

```
   Consequence for design:
     - the tree must be lazily verifiable (sample, then drill)
     - export bundles must summarise wide levels, not embed 412 PDFs
     - per-claim entailment at every leaf is economically impossible
```

This is the domain that makes the entailment cost decision real. A medical profile can
afford an LLM call per claim; a reporting profile producing thousands of figures cannot.
Sampling policy is domain config for exactly this reason.

## 3. What must be true before acting?

```python
def obligations_for(self, action, ctx):
    if action.name != "publish_figure":
        return ObligationSet([CapabilityCheck(action.capability)])
    return ObligationSet([
        CapabilityCheck("publish_financial"),
        Reconciliation(action.figure, source=ctx.ledger),   # domain obligation
        MaterialityCheck(action.figure, ctx.threshold),
        ReviewAttestation("financial_controller"),
        Approval(n=1, roles={"cfo"}) if action.is_external else NullObligation(),
        TimeWindow(before=ctx.filing_deadline),
    ])
```

`Reconciliation` is a domain obligation: the figure must tie back to the ledger within
tolerance. The framework cannot know what "tie back" means; it only enforces that the
obligation discharges.

## 4. What do the core four warrants miss?

```
   RECONCILIATION    Does the reported figure tie to source records?
                     Every citation can verify and the total still be
                     wrong — double-counting, a missed accrual, an
                     FX translation applied twice.
                     This is arithmetic integrity across the whole tree,
                     which no per-claim check performs.

   MATERIALITY       Is the error small enough not to matter?
                     Uniquely, this warrant can be satisfied by a
                     DISCREPANCY, provided it falls below threshold.
                     A £40 variance on £4.2m is not a finding.
```

`MATERIALITY` is the clearest evidence the warrant set must be open. It is meaningless in
medical — no dose error is immaterial — and essential here. A framework with a fixed warrant
enum cannot express it.

## 5. What must an auditor be shown?

```
   the figure, the derivation tree to a sampled depth,
   the reconciliation result, the materiality assessment,
   the controller's attestation, and the ledger snapshot hash
```

The **ledger snapshot hash** matters: it pins the state of the source system at reporting
time, so a later ledger change is detectable rather than silently invalidating the report.

## Warrant policy

```
   reconciliation   BLOCK    an unreconciled figure never publishes
   materiality      WARN     below threshold -> proceed, record
   epistemic        WARN     <- deliberately weaker than medical
   temporal         WARN
```

`epistemic` is only `WARN` here because reporting figures are checked by reconciliation,
which is a stronger arithmetic guarantee than per-claim support. The domain chooses which
warrant is load-bearing.

Compare [`medical.md`](medical.md), where `epistemic` is `BLOCK` and there is no
reconciliation to fall back on.

## Causal language

Worth a specific note. A reporting profile should treat causal claims ("driven by", "due to",
"because of") as requiring a distinct evidence kind the domain supplies, or refuse them.
Correlation dressed as causation in a published financial narrative is a misstatement, and no
generic verifier catches it.
