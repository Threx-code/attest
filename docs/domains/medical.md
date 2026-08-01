# Medical

The domain that most decisively breaks a document-shaped framework.

## 1. What is a claim?

> "This patient's HbA1c indicates poorly controlled type 2 diabetes; consider escalating
> therapy per NG28."

Two claims: one about a **measurement**, one about a **guideline**. They verify completely
differently.

## 2. What supports it?

```
   "HbA1c is 74 mmol/mol"              Observation
     ├── device: Cobas c503, lab LX-2
     ├── collected 2026-07-14 09:12
     ├── calibration window: valid
     └── verify: re-query the LIMS record; value + calibration must match

   "NG28 recommends escalation         QuotedSpan
    above 58 mmol/mol"                   ├── source: NICE NG28, version 2022-03
     ├── offset 41,208-41,266
     └── verify: substring still present at offset in that version

   "therapy escalation indicated"      Derivation
     └── over the two above
```

**There is no quote for a lab value.** A framework whose only evidence primitive is a text
span cannot represent the most important fact in this run. `Observation` exists for this.

## 3. What must be true before acting?

```python
def obligations_for(self, action, ctx):
    if action.effects & {EffectClass.CLINICAL}:
        return ObligationSet([
            CapabilityCheck("clinical_decision_support"),
            ReviewAttestation("prescribing_clinician"),   # named human, named facts
            ContraindicationCheck(ctx.patient),           # domain-supplied obligation
            Reversibility(action),
        ])
    return ObligationSet([CapabilityCheck(action.capability)])
```

`ContraindicationCheck` is a **domain-written obligation**. The framework never learns what a
contraindication is; it only knows an obligation must be discharged.

Note the system never prescribes. It proposes; a clinician attests. That is expressed as an
obligation, not as a policy document.

## 4. What do the core four warrants miss?

```
   CALIBRATION         The model says "85% likely benign."
                       Is it right 85% of the time at that confidence?
                       An overconfident 0.6 is more dangerous than a
                       refusal, because a clinician will act on the number.

   TEMPORAL_VALIDITY   NG28 was updated. The cited version is superseded.
                       Every citation still verifies — against a guideline
                       that is no longer current.

   SAFETY              Some outputs are hazardous regardless of support:
                       a dose outside a safe range, a drug interaction.
                       A domain-defined hazard check, independent of
                       whether evidence backs it.
```

`TEMPORAL_VALIDITY` is the subtle one. Mechanical verification passes; the answer is stale.
Only the domain knows that a guideline expires when its issuing body replaces it.

## 5. What must a reviewer be shown?

```
   bundle/
     attestation.json
     evidence/
       lims-record-...json      the observation, with calibration metadata
       NG28-2022-03.pdf         the guideline AS CITED, that version
       derivation.json          how one led to the other
     chain.jsonl
     VERIFY.md
```

The guideline version is embedded, not linked. When NG28 is superseded, this bundle still
shows what the clinician was working from.

## Warrant policy

```
   epistemic          BLOCK      unsupported clinical claims never ship
   calibration        BLOCK      outside tolerance -> refuse
   safety             BLOCK
   temporal_validity  HOLD       stale guideline -> clinician decides
   boundary           BLOCK
```

Compare with [`reporting.md`](reporting.md), where `temporal_validity` is only a warning. Same
machinery, opposite policy — set by the domain, not the framework.

## Sensitive classes

PHI, not just PII: diagnoses, medications, and genetic data are re-identifying even when
names are removed. The profile declares these; the PII gateway enforces them.

A specific hazard: a rare diagnosis plus a postcode identifies a person. The profile's
`sensitive_classes()` must cover combinations, not only fields.
