# Domain profile

**The extensibility contract.** A domain profile is how regulatory, insurance, medical,
banking, mortgage, reporting — or a domain nobody has thought of yet — plugs into the
framework without modifying it.

## The inversion

The naive design has the framework know about domains. That design is closed.

```
   CLOSED (wrong)                        OPEN (this design)
   ─────────────────────────             ──────────────────────────────
   class Domain(Enum):                   class DomainProfile(Protocol):
       LEGAL                                 name: str
       MEDICAL                               def evidence_verifiers(...)
       INSURANCE                             def obligations_for(...)
       ...                                   def warrant_kinds(...)
                                             ...
   if domain == Domain.MEDICAL:
       ...                               registered via entry point:
                                           [project.entry-points."attest.domains"]
   A new domain = edit the                 mortgage = "acme.mortgage:Profile"
   framework, cut a release,
   wait for it.                          A new domain = a package.
                                          Framework untouched.
```

The framework ships **zero** real domain profiles. Only a `generic` reference implementation,
used in tests and as a worked example.

## The protocol

```python
class DomainProfile(Protocol):
    name: str
    version: str

    # --- Epistemic: what counts as support in this domain? ---
    def evidence_verifiers(self) -> Mapping[EvidenceKind, SupportVerifier]: ...
    def validity(self, ev: Evidence, at: datetime) -> ValidityWindow: ...

    # --- Authority: what must be discharged before an action? ---
    def obligations_for(self, action: Action, ctx: Context) -> ObligationSet: ...

    # --- Which warrants apply beyond the core four? ---
    def warrant_kinds(self) -> frozenset[WarrantKind]: ...
    def warrant_policy(self, kind: WarrantKind) -> WarrantPolicy: ...   # BLOCK/HOLD/WARN/RECORD

    # --- Boundary: what is sensitive here? ---
    def sensitive_classes(self) -> Sequence[SensitiveClass]: ...        # PII / PHI / protected
    def redaction_policy(self) -> RedactionPolicy: ...

    # --- Refusals ---
    def refusal_taxonomy(self) -> Mapping[RefusalReason, RefusalSpec]: ...

    # --- Text conventions (was hardcoded in every surveyed codebase) ---
    def reference_patterns(self) -> Sequence[Pattern]: ...   # "s. 12", "ICD-10 J45", "IAS 37"
```

Everything a domain needs to say is a *return value*. Nothing is a branch inside the
framework.

## What each domain supplies

The same protocol, six very different answers:

```
 ┌────────────┬──────────────────────┬───────────────────────┬─────────────────────┐
 │ DOMAIN     │ EVIDENCE LOOKS LIKE  │ OBLIGATIONS           │ EXTRA WARRANTS      │
 ├────────────┼──────────────────────┼───────────────────────┼─────────────────────┤
 │ regulatory │ QuotedSpan of a rule │ compliance sign-off   │ temporal_validity   │
 │            │ + filing RecordValue │ filing deadline       │ contestability      │
 ├────────────┼──────────────────────┼───────────────────────┼─────────────────────┤
 │ insurance  │ QuotedSpan of policy │ four-eyes above       │ contestability      │
 │            │ wording, Computation │ payout threshold      │ temporal_validity   │
 │            │ of settlement        │ medical review        │                     │
 ├────────────┼──────────────────────┼───────────────────────┼─────────────────────┤
 │ medical    │ Observation (labs),  │ clinician sign-off    │ calibration         │
 │            │ QuotedSpan of a      │ contraindication      │ temporal_validity   │
 │            │ versioned guideline  │ check                 │ safety              │
 ├────────────┼──────────────────────┼───────────────────────┼─────────────────────┤
 │ banking    │ RecordValue (txns),  │ dual control, AML     │ fairness            │
 │            │ Computation (risk)   │ hold, sanctions screen│ reconciliation      │
 ├────────────┼──────────────────────┼───────────────────────┼─────────────────────┤
 │ mortgage   │ Computation          │ underwriter approval  │ fairness            │
 │            │ (affordability),     │ cooling-off window    │ contestability      │
 │            │ RecordValue (income) │                       │                     │
 ├────────────┼──────────────────────┼───────────────────────┼─────────────────────┤
 │ reporting  │ Aggregate over       │ reconciliation,       │ reconciliation      │
 │            │ RecordValues,        │ materiality threshold,│ temporal_validity   │
 │            │ Derivation           │ CFO attestation       │                     │
 └────────────┴──────────────────────┴───────────────────────┴─────────────────────┘
```

Note what is **not** in that table: any framework code. Every column is a return value from
the protocol above.

## Composition

Profiles compose. A mortgage arm of a bank needs both:

```python
profile = compose(
    BankingProfile(jurisdiction="UK"),
    MortgageProfile(jurisdiction="UK"),
)
```

### Not every conflict is an ordering problem

An earlier draft said "strictest wins, and it is the only safe resolution." That is wrong for
any policy without a scalar ordering:

```
   ORDERABLE                        NOT ORDERABLE
   ─────────────────────────        ──────────────────────────────
   fairness: WARN vs BLOCK          retention: 30 days vs 90 days
   -> BLOCK is stricter             -> which is stricter? minimising
                                       exposure says 30; evidentiary
                                       obligation says 90

                                    notification: before vs after
                                    -> genuinely contradictory
```

Forcing these into "strictest" silently picks one, and silently picking one is exactly the
failure mode the framework exists to prevent. Resolution is classified instead:

```
 ┌────────────────┬──────────────────────────────────────────────────────┐
 │ STRICTER       │ a scalar ordering exists; take the stricter          │
 │ COMPATIBLE     │ both can hold at once; take the union                │
 │ CONDITIONAL    │ resolvable given context (jurisdiction, action type);│
 │                │ the profile supplies the resolver                    │
 │ CONTRADICTORY  │ cannot both hold. NOT auto-resolved.                 │
 └────────────────┴──────────────────────────────────────────────────────┘
```

```
   CONTRADICTORY detected
          │
          ├── at construction  -> composition FAILS, loudly
          │                       (the normal case: fix the profiles)
          │
          └── at runtime       -> HOLD_FOR_APPROVAL or REFUSE per policy,
              (context-dependent)  never a silent pick
```

Absence is not permission: a profile that does not register `temporal_validity` has **no
opinion**, which composes as `COMPATIBLE` with any other profile's policy — it does not
weaken it.

## The protocol is composed of sub-profiles

The full `DomainProfile` above is a large interface, and a large interface is a barrier to
the open-world goal it exists to serve. It is therefore assembled from focused parts:

```
   DomainProfile
     ├── EvidenceProfile     verifiers · validity · source authority · required sources
     ├── AuthorityProfile    obligations · approval topology · budgets
     ├── BoundaryProfile     sensitive classes · redaction · scope defaults
     ├── WarrantProfile      extra kinds · policies
     ├── ReferenceProfile    reference patterns · refusal taxonomy
     └── EvaluationProfile   golden sets · red-team extras
```

Each is independently implementable, testable, and reusable — a jurisdiction's
`BoundaryProfile` is often shared across domains. `BaseProfile` supplies defaults for all
six, so the minimum viable profile is short:

```python
class FoodSafetyProfile(BaseProfile):
    name = "food_safety"
    extra_warrants = {TEMPORAL_VALIDITY, COMPLETENESS}

    def obligations_for(self, action, ctx):
        return self.default_obligations(action, ctx) + [InspectorSignOff()]
```

Two overrides. Everything else inherits sane, fail-closed defaults. See
[`../adoption.md`](../adoption.md) for why this matters more than it looks.

## Jurisdiction is a parameter, not a profile

A frequent modelling error. `MortgageProfile(jurisdiction="UK")` and
`MortgageProfile(jurisdiction="NG")` are the same profile with different data — protected
classes, cooling-off durations, and reference patterns differ, but the *shape* does not.

Making jurisdiction a constructor parameter rather than a separate profile is what stops the
`legal.yaml` / `legal_ng.yaml` / `legal_uk_v2.yaml` sprawl that killed the surveyed codebases.

## Registration

```toml
# in the domain package, not the framework
[project.entry-points."attest.domains"]
mortgage = "acme_mortgage.profile:MortgageProfile"
```

```python
profile = attest.domains.load("mortgage", jurisdiction="UK")
```

Profiles can also be passed directly — entry points are a convenience, not a requirement.
A profile defined in a host application's own module works identically.

## Versioning

A profile carries a `version`, and that version is pinned into every `Attestation`. When the
profile changes — a new protected class, a changed threshold — old attestations remain
verifiable against the profile version that produced them.

```
   attestation.agent.profile == "mortgage@2.1.0"
                                          │
   verify() loads profile 2.1.0 ──────────┘   not "latest"
```

Without this, changing a threshold silently invalidates every historical decision.

## Related

- [`conformance.md`](conformance.md) — proving a profile is correct
- [`warrants.md`](warrants.md) — registering warrant kinds
- [`../capabilities/evidence.md`](../capabilities/evidence.md) — evidence verifiers
- [`../capabilities/authority.md`](../capabilities/authority.md) — obligations
- [`../domains/README.md`](../domains/README.md) — the six worked examples
