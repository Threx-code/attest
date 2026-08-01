# Completeness — the coverage warrant

**Did the system consider everything it was required to consider?**

The four original warrants all validate what *was* used. None asks about what was *missed*.
That gap is this document.

## The failure this catches

```
   Retrieval returns:     Policy A  ✓ genuine
                          Policy B  ✓ genuine
                          Policy C  ✓ genuine

   Answer:                "The applicant qualifies."

   All citations verify.  Evidence unaltered.  Chain intact.
   Authority discharged.  No injection.  Verdict: ALLOW.

   But the corpus also contained:

                          Policy D  ── the 2026 amendment that
                                       disqualifies this applicant

   Retrieval simply did not return it.
```

Nothing is forged. Nothing is tampered. Every existing warrant is satisfied, and the answer
is wrong.

This is not an evidence problem — the evidence used was real. It is a **coverage** problem,
and it is invisible to every mechanism described elsewhere in these documents.

## Why it needs its own warrant

```
   EPISTEMIC   asks:  is what I used, sound?
   COMPLETENESS asks: is what I used, enough?
```

They fail independently. A system can have perfect epistemic warrant over an inadequate
slice of the world, and that is the normal case for retrieval-based agents.

## The honest limit — read this before adopting it

**Absolute completeness is usually unknowable.** "Did we consider everything relevant" cannot
be answered in general; a system cannot enumerate what it does not know exists.

What *is* assertable is completeness **relative to a declared scope**:

```
   NOT PROVABLE                        PROVABLE
   ─────────────────────────           ──────────────────────────────────
   "all relevant policies were         "the declared corpus was searched
    considered"                         with this query plan; these
                                        required sources returned; the
                                        result set was not truncated"
```

A `COVERAGE` warrant that claims the first is a warrant that quietly always passes, which is
worse than not having it. The framework only supports the second — and the gap between the
two is a residual risk that must be stated, not designed away.

## What coverage actually asserts

```
 ┌────────────────────┬──────────────────────────────────────────────────┐
 │ CORPUS SCOPE       │ which corpora were searched, at which epoch      │
 │ QUERY PLAN         │ the queries issued, declared before execution    │
 │ REQUIRED SOURCES   │ sources the domain mandates for this decision    │
 │                    │ type — each returned, or the run fails           │
 │ TRUNCATION         │ did any result set hit a limit?  <- the common   │
 │                    │ silent failure                                   │
 │ TEMPORAL WINDOW    │ the period covered, vs the period required       │
 │ JURISDICTION       │ which body of rules was searched                 │
 │ RESIDUAL           │ what was knowingly NOT searched, and why         │
 └────────────────────┴──────────────────────────────────────────────────┘
```

`TRUNCATION` deserves emphasis. A retrieval that returns "top 20 of 4,312 matches" and an
agent that answers from those 20 is the single most common completeness failure in production
RAG systems, and it produces no error anywhere.

## Required sources — the strongest part

Most of the practical value is here, and it is fully deterministic:

```python
class RegulatoryProfile(BaseProfile):
    def required_sources(self, decision_type, ctx) -> RequiredSources:
        if decision_type == "sanctions_determination":
            return RequiredSources.all_of(
                "uk_sanctions_list@current",
                "un_consolidated@current",
                "ofac_sdn@current",
            )
```

```
   required sources declared
            │
            ▼
   each must appear in the retrieval record
            │
    ┌───────┴────────┐
    ▼                ▼
  present          missing
    │                │
    ▼                ▼
  SATISFIED    UNSATISFIED -> profile policy (BLOCK for sanctions)
```

No model judgement involved. A sanctions determination that never consulted the UN list is
caught mechanically, which is exactly the kind of failure that otherwise surfaces in an
enforcement action.

## The shape

```python
COMPLETENESS = WarrantKind("completeness")

@dataclass(frozen=True)
class CoverageReport(WarrantReport):
    kind = COMPLETENESS
    corpora: Sequence[CorpusRef]        # id + epoch
    query_plan: Sequence[Query]         # declared BEFORE execution
    required: RequiredSources
    satisfied_sources: frozenset[str]
    missing_sources: frozenset[str]
    truncated: Sequence[TruncationEvent]
    window: DateRange | None
    residual: Sequence[str]             # knowingly not searched, with reasons
```

The query plan is declared **before** execution so that coverage is measured against an
intention, not rationalised from whatever happened to return.

## Is it a core warrant?

No — it is **strongly recommended** rather than mandatory.

```
   core (always)          epistemic · authority · provenance · boundary
   strongly recommended   completeness — wherever retrieval or aggregation
                          determines the answer
   domain-registered      calibration · fairness · temporal_validity · ...
```

It is not core because some agents have no retrieval surface at all — a pure computation or
transformation has nothing to be incomplete about, and a mandatory warrant that is trivially
satisfied trains people to ignore warrants.

Any domain that retrieves, aggregates, or screens should register it. In practice that is
most of `domains/catalog.md`.

## Where it matters most

```
   sanctions / AML          a missed list entry is an enforcement matter
   regulatory               a missed amendment is a compliance breach
   reporting                a missed transaction is a misstatement
   clinical                 a missed contraindication or allergy
   legal                    a missed authority, or a missed conflict
   insurance                a missed exclusion or endorsement
```

In `domains/reporting.md`, coverage is arguably the *primary* warrant: a total over 411 of
412 claims verifies perfectly at every leaf and is still wrong.

## Related

- [`evidence.md`](evidence.md) — soundness of what was used
- [`../concepts/assurance-boundaries.md`](../concepts/assurance-boundaries.md) — assurance 3
- [`../assurance/redteam.md`](../assurance/redteam.md) — completeness attacks
