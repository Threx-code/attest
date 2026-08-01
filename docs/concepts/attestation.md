# Attestation

The artifact a run returns. **Not a string.**

> **Read [`assurance-boundaries.md`](assurance-boundaries.md) first.** An attestation records
> that a decision was properly *made*. It does not establish that the decision was *correct*,
> and treating a verifiable attestation as a trustworthy one is this framework's most
> dangerous failure mode.

## Shape

```python
@dataclass(frozen=True, slots=True)
class Attestation:
    run_id: RunId
    agent: AgentRef                            # name + version + prompt hash + model id
    verdict: Verdict                           # six outcomes; see verdicts.md
    answer: str
    structured: Mapping | None
    cost: CostRecord

    context: ExecutionContext                  # MANDATORY; see below
    warrants: Mapping[WarrantKind, WarrantReport]
    effects: Sequence[EffectRecord]            # each with its own EffectState
    seal: RunSeal | None                       # None until the run is sealed
    supersedes: RunId | None

    @property
    def is_final(self) -> bool:                # every warrant EVALUATED
        ...

    def warrant(self, kind: WarrantKind) -> WarrantReport: ...
    def verify_historical(self) -> VerificationResult: ...
    def verify_current(self) -> VerificationResult: ...
    def export(self) -> EvidenceBundle: ...    # refuses when not is_final
```

`warrants` is a **mapping, not four named fields**. That single choice is what keeps the
framework open — a clinical profile adds `CALIBRATION`, an underwriting profile adds
`FAIRNESS`, and neither requires touching the kernel.

## Everything reconstructible lives in the context, not in loose fields

[`../kernel/versioning.md`](../kernel/versioning.md) requires nine things to be recorded on
every attestation so a run is reconstructible without guessing: `framework_version`,
`profile@version`, `config_hash`, `prompt_hashes`, `model + params`, `pricing_version`,
`corpus_epochs`, `flow_spec_version`, and `tenant_binding_hash`.

They are **not** nine fields on `Attestation`. They live on the embedded `ExecutionContext`,
which is content-hashed as a single unit:

```
   Attestation
     └── context: ExecutionContext     ─── hashed once ──▶ context_hash
           clock · config · profile · policy_snapshot · identity_snapshot
           evidence_snapshot · tool_specs · model · prompts · pricing_version
           corpus_epochs · seed · framework_version · flow_spec_version
           tenant_binding
```

Nine independent fields can drift apart from one another and from the run they describe. One
hashed context cannot: change any part of it and the hash changes, and the hash is what the
seal signs. See [`../kernel/execution-context.md`](../kernel/execution-context.md).

## Provisional attestations are marked, and cannot be exported

Where a profile defers assurance ([`../kernel/performance.md`](../kernel/performance.md)),
warrants are returned with status `PENDING` and `is_final` is `False`. `export()` refuses a
non-final attestation rather than producing a bundle whose warrants had not been evaluated.

An `ALLOW` that a consumer cannot distinguish from a fully-evaluated `ALLOW` is an unverified
result presented as a definitive one — the failure mode in
[`assurance-boundaries.md`](assurance-boundaries.md), reached from the other direction.

## Anatomy

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │  Attestation                                          run_id: 01J... │
 ├─────────────────────────────────────────────────────────────────────┤
 │  agent      claim_adjudicator @ v4   prompt:a91f3c   model:sonnet-5  │
 │  verdict    HOLD_FOR_APPROVAL                                        │
 │  answer     "Claim CL-8823 appears payable at GBP 12,400 under..."  │
 │  cost       in:8,214  out:1,097   USD 0.061   actor budget 12% used │
 ├─────────────────────────────────────────────────────────────────────┤
 │  WARRANTS                                                            │
 │                                                                      │
 │   epistemic    OK    3 claims, 3 supported                          │
 │                      - "policy covers escape of water" <- QuotedSpan │
 │                          policy-doc:PW-2019 §4.2 chars 1180-1244    │
 │                      - "excess is GBP 250"             <- RecordValue│
 │                          policy_record:8823.excess @ v7             │
 │                      - "settlement GBP 12,400"         <- Computation│
 │                          settlement_calc v2.1, inputs pinned         │
 │                                                                      │
 │   authority    HOLD  obligation unmet                                │
 │                      - capability:adjudicate_claim        SATISFIED  │
 │                      - budget:daily_payout                SATISFIED  │
 │                      - approval:claims_manager (1 of 1)   PENDING    │
 │                          reason: amount > GBP 10,000 threshold       │
 │                                                                      │
 │   provenance   OK    11 events, chain head 7f2a91c4                 │
 │                      verified: chain intact, no gaps                 │
 │                                                                      │
 │   boundary     OK    injection: clean (3 inputs screened)            │
 │                      pii: 4 redacted / 4 restored                    │
 │                      tenancy: no cross-tenant reads                  │
 │                                                                      │
 │   temporal     WARN  policy wording PW-2019 superseded 2024-03-01   │
 │                      (domain-registered warrant)                     │
 └─────────────────────────────────────────────────────────────────────┘
```

That is the object a regulator, an ombudsman, or an auditor can be shown. Every line is
re-checkable.

## Verification has two modes — and conflating them is a serious error

```
   Jan 2026   evidence valid · policy valid · decision ALLOW
   Jun 2026   the policy wording expires
              │
              ▼
   attestation.verify()  ->  TEMPORAL_VALIDITY = FAILED
```

Does that mean the January decision was invalid? **No.** It means the evidence is not valid
*today*. Those are different propositions, and a single `verify()` cannot express both.

```python
attestation.verify_historical()   # was this valid under the state it claims
                                  # to represent, at decision time?
attestation.verify_current()      # would this satisfy today's requirements?
```

```
 ┌──────────────────┬─────────────────────────────┬──────────────────────────┐
 │                  │ verify_historical()         │ verify_current()         │
 ├──────────────────┼─────────────────────────────┼──────────────────────────┤
 │ chain integrity  │ recompute · must pass       │ recompute · must pass    │
 │ signature        │ must pass                   │ must pass                │
 │ sealed count     │ dense sequence · must pass  │ same                     │
 │ evidence         │ against the captured        │ against the source AS IT │
 │                  │ snapshot + hashes           │ IS NOW                   │
 │ validity windows │ evaluated at decision time  │ evaluated at now         │
 │ policy version   │ the version then in force   │ the current version      │
 ├──────────────────┼─────────────────────────────┼──────────────────────────┤
 │ answers          │ "was this properly made?"   │ "does this still hold?"  │
 └──────────────────┴─────────────────────────────┴──────────────────────────┘
```

A failed `verify_historical()` is a **serious finding** — tampering, omission, or a defect.
A failed `verify_current()` is often **expected and benign**: policies expire, records move
on. Reporting the second as though it were the first cries wolf until nobody looks.

### A third outcome: unverifiable

```python
class VerificationOutcome(StrEnum):
    PASS         = "pass"
    FAIL         = "fail"          # a discrepancy was found
    UNVERIFIABLE = "unverifiable"  # the source cannot answer the question
```

`UNVERIFIABLE` is not a technicality. Re-checking a `RecordValue` at version 7 requires the
source system to retain versioned history, and many are last-write-wins. Collapsing that into
`PASS` (by checking the current value) or `FAIL` (by treating absence as tampering) are both
lies. See [`../kernel/storage.md`](../kernel/storage.md).

## Lifecycle

```
   dispatch                                                   persist
      │                                                          │
      ▼                                                          ▼
  ┌────────┐   ┌─────────┐   ┌──────────┐   ┌───────────┐   ┌─────────┐
  │ guards │──▶│  agent  │──▶│ evidence │──▶│ authority │──▶│ ATTEST- │
  │ (in)   │   │  loop   │   │  verify  │   │ obligations│  │  ATION  │
  └────────┘   └─────────┘   └──────────┘   └───────────┘   └─────────┘
      │             │              │               │             │
      └─────────────┴──────────────┴───────────────┴─────────────┘
                    every step appends to the provenance chain
                                                                 │
                              ┌──────────────────────────────────┤
                              ▼                                  ▼
                     verdict = HOLD?                    verdict = ALLOW?
                     open PendingAction                 execute effects
                     (see authority.md)                 (see tools.md)
```

## Export

`.export()` produces an `EvidenceBundle`: a self-contained, signed archive that can be
verified **offline**, without the framework, the database, or network access.

```
   bundle/
     attestation.json        the full record
     evidence/               every cited source, as retrieved at the time
     chain.jsonl             the provenance events
     manifest.json           hashes of everything above
     signature.sig           detached signature over the manifest
     VERIFY.md               human-readable instructions to check it by hand
```

The `VERIFY.md` requirement is deliberate. If checking the bundle needs our code, it is not
evidence — it is a claim about evidence.

## Storage

An `Attestation` is a value object. Persistence is a host concern via the `RunStore` port.
The framework **does not mandate a table** — see [`../kernel/ports.md`](../kernel/ports.md)
for why that constraint exists and how hosts satisfy it.

## Related

- [`warrants.md`](warrants.md) — what the mapping holds
- [`verdicts.md`](verdicts.md) — the four outcomes
- [`../assurance/export.md`](../assurance/export.md) — bundle format in detail
- [`../runtime/replay.md`](../runtime/replay.md) — re-executing an attestation
