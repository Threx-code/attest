# Evidence — the epistemic warrant

**What supports this claim, and can that support be re-checked?**

This module was almost called `grounding`. That name was rejected because it carries a
document-shaped assumption: that evidence is quotable prose. In medical, banking, mortgage,
and reporting domains it usually is not.

## The mistake this avoids

```
   DOCUMENT-SHAPED (too narrow)          EVIDENCE-SHAPED (this design)
   ──────────────────────────────        ────────────────────────────────
   class Citation:                       class Evidence(Protocol):
       source_id: str                        kind: EvidenceKind
       quote: str          <-- assumes       source: SourceRef
       char_start: int         prose         def descriptor(self) -> Mapping
       char_end: int

   Works for: regulation text,           Works for all of the above, plus:
   policy wording, guidelines              lab values, transaction records,
                                           actuarial computations, sensor
   Breaks for: a lab value, a              readings, aggregates, derivations
   risk score, an aggregate,
   a property valuation
```

A blood glucose reading of 14.2 mmol/L has no verbatim quote. Neither does an affordability
calculation, nor a reconciled trial-balance figure. All three are perfectly good evidence —
they just verify differently.

## Evidence kinds

The framework ships five verification strategies. A domain may add its own.

```
 ┌──────────────┬────────────────────────────┬──────────────────────────────────┐
 │ KIND         │ VERIFIES BY                │ USED BY                          │
 ├──────────────┼────────────────────────────┼──────────────────────────────────┤
 │ QuotedSpan   │ the exact substring is     │ regulatory rules, policy wording,│
 │              │ still present at that      │ clinical guidelines, contracts   │
 │              │ offset in that source      │                                  │
 ├──────────────┼────────────────────────────┼──────────────────────────────────┤
 │ RecordValue  │ field F of record R at     │ transactions, income, policy     │
 │              │ version V still equals X   │ excess, patient demographics     │
 ├──────────────┼────────────────────────────┼──────────────────────────────────┤
 │ Computation  │ re-running model M over    │ affordability, settlement, risk  │
 │              │ pinned inputs I reproduces │ scores, actuarial output         │
 │              │ output O                   │                                  │
 ├──────────────┼────────────────────────────┼──────────────────────────────────┤
 │ Observation  │ measurement from device D  │ lab results, valuations,         │
 │              │ at time T, within its      │ meter readings, inspections      │
 │              │ calibration window         │                                  │
 ├──────────────┼────────────────────────────┼──────────────────────────────────┤
 │ Derivation   │ the stated operation over  │ aggregates, reconciliations,     │
 │              │ cited sub-evidence yields  │ totals, any "therefore"          │
 │              │ the stated result          │                                  │
 └──────────────┴────────────────────────────┴──────────────────────────────────┘
```

`Derivation` is the composite: its sub-evidence is itself `Evidence`, so a reported figure
can be traced down to source records through bounded depth.

### Derivation trees are bounded

Unbounded recursion makes `verify()` a denial-of-service target, whether malformed or
adversarial.

```
   max_depth        default 8, hard ceiling 32
   max_breadth      per level; wide levels SUMMARISE (see storage.md)
   max_nodes        total across the tree
   cycle detection  by evidence content hash, on insert AND on verify
                    -> a self-referencing derivation is rejected, not
                       recursed into
   verify budget    a wall-clock and node ceiling; exceeding it yields
                    UNVERIFIABLE, never a hang and never a silent PASS
```

Cycle detection runs on verification as well as construction, because an attestation may
arrive from an untrusted export bundle rather than from our own runtime.

```
   "Q3 provision is GBP 4.2m"                        <- Derivation
        ├── "open claims total GBP 3.8m"             <- Derivation
        │       ├── claim 8823: GBP 12,400           <- Computation
        │       │       ├── policy excess GBP 250    <- RecordValue
        │       │       └── damage estimate          <- Observation
        │       └── ...                                 (loss adjuster, 2026-06-02)
        └── "IBNR factor 1.105 per IAS 37"           <- QuotedSpan
```

That tree is what an auditor asks for. It is also exactly what `.export()` serialises.

## Content integrity is not source authority

A `QuotedSpan` can verify perfectly against a document that has no business being
authoritative:

```
   QuotedSpan: "The threshold is £10,000."
   verify:     ✓ substring present at that offset
   source:     random-uploaded-policy.pdf     <- uploaded by anyone
```

The quote is genuine. The evidence is worthless. Verification answered *"does the source say
this?"* and never asked *"is this source authoritative?"*

```
   CONTENT INTEGRITY              SOURCE AUTHORITY
   ──────────────────────         ─────────────────────────────────
   the bytes are unaltered        the issuer is entitled to state this
   mechanical, cheap              a trust decision, domain-specific
   verifier's job                 profile's job
```

So `SourceRef` carries provenance, not just an id:

```python
@dataclass(frozen=True)
class SourceRef:
    source_id: str
    source_type: SourceType        # statute · policy_doc · ledger · lab · third_party
    issuer: IssuerRef | None       # WHO published it
    authority: AuthorityLevel      # authoritative · advisory · unverified · user_supplied
    version: str
    effective_from: date | None    # when the content took effect
    effective_to: date | None
    retrieved_at: datetime
    integrity_hash: Hash
    provenance: ProvenanceRef      # how it entered the system
```

The profile decides which `authority` levels are acceptable for which claims:

```
   sanctions determination   ->  authoritative only
   clinical guideline        ->  authoritative only, issuer in an allow-list
   customer correspondence   ->  user_supplied is fine, and is labelled as such
```

An `unverified` source cited for a claim the profile requires to be `authoritative` fails the
epistemic warrant — mechanically, before any model judgement.

## Trust assumptions about source systems

Stated plainly, because an earlier draft overclaimed:

> If someone alters the authoritative source itself, the framework will verify the altered
> state and report `PASS`.

Re-verification detects **divergence between the attestation and the source**. It does not
detect tampering *within* the source. A record maliciously edited from £12,400 to £15,400
makes `verify_current()` fail — which looks like our record being wrong, not theirs.

Defending against that needs the source system to have its own integrity controls, or the
attestation to embed the cited value with a timestamped signature at capture time. The second
worsens attestation size. The trade-off is resolved per decision by materiality — see
[`../kernel/storage.md`](../kernel/storage.md).

## The verification protocol

```python
class SupportVerifier(Protocol):
    kind: EvidenceKind
    def verify(self, ev: Evidence, ctx: VerifyContext) -> SupportResult: ...


@dataclass(frozen=True)
class SupportResult:
    supported: bool
    confidence: float | None       # None when verification is exact, not probabilistic
    discrepancy: str | None        # what changed, when it fails
```

`confidence is None` for exact verification — a quote is present or it is not. Entailment
judging is probabilistic and populates it. Conflating the two is how "verified" comes to mean
nothing.

## Two distinct checks

A common conflation worth separating explicitly:

```
   SUPPORT EXISTS                     SUPPORT ENTAILS
   ──────────────────────────         ─────────────────────────────────
   Does the cited evidence            Does the cited evidence actually
   exist and is it unaltered?         support the claim being made?

   Mechanical. Cheap. Exact.          Semantic. Costly. Probabilistic.
   Always run.                        Sampled or policy-gated.

   Catches: fabricated citations,     Catches: "real quote, wrong
   tampered sources, stale records    inference" — the subtler failure
```

The second is the expensive one — it means an LLM call per claim. Whether it runs always, on
a sample, or asynchronously after the response is a **domain policy decision**, not a
framework default. A medical profile runs it always; a high-volume reporting profile samples.

Settled by ADR 0011: the default is `NONE` and profiles opt *up* by materiality. See
[`judging.md`](judging.md) for the policy shape.

## Validity windows

Evidence can be true and still be **stale**. A clinical guideline superseded last March, a
policy wording replaced at renewal, a valuation older than the lender accepts.

```python
def validity(self, ev: Evidence, at: datetime) -> ValidityWindow: ...
```

The domain answers this, because only the domain knows that a mortgage valuation expires at
90 days and a clinical guideline expires when the issuing body replaces it. Expiry surfaces
as the `TEMPORAL_VALIDITY` warrant.

## Substantiveness

Not every output needs evidence. "I don't have enough information to answer" needs none.
The test for whether an output requires support is domain-supplied, because the surveyed
codebases each hardcoded their own — a word-count floor plus a regex for legal references,
which silently exempted any short answer that named a statute.

```python
def requires_support(self, output: str, ctx: Context) -> bool: ...
```

## Related

- [`../concepts/warrants.md`](../concepts/warrants.md) — where this becomes a warrant
- [`../concepts/domain-profile.md`](../concepts/domain-profile.md) — supplying verifiers
- [`../assurance/export.md`](../assurance/export.md) — serialising the evidence tree
