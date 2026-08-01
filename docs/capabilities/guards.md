# Guards — the boundary warrant

**Did untrusted input steer the system? Did anything leak out?**

Guards run at two boundaries.

```
   ┌──────────┐   INBOUND    ┌───────────┐   OUTBOUND   ┌──────────┐
   │ untrusted│─────────────▶│   agent   │─────────────▶│ consumer │
   │  input   │   injection  │           │   leakage    │          │
   │          │   tenancy    │           │   pii        │          │
   │ user msg │   pii redact │           │   rules      │          │
   │ documents│              │           │   pii restore│          │
   │ tool out │              │           │              │          │
   └──────────┘              └───────────┘              └──────────┘
```

Note that **tool output is untrusted input.** A document fetched mid-run, an email body, a
third-party API response — all can carry injected instructions, and all re-enter the loop.
Guarding only the user's first message is the most common version of this mistake.

## Injection

Detects attempts to override the system's instructions.

The surveyed codebases hardcoded the brand name into detection regexes — which is exactly
why two copies of a 319-line detector could not be shared:

```
   HARDCODED (why the copies drifted)        CONFIG-DRIVEN
   ──────────────────────────────────        ────────────────────────────
   r"(admin|anthropic|acme\s+team)           r"(admin|{vendors}|{brand})
     \s+told\s+me"                              \s+told\s+me"

   Two projects, two copies,                 One implementation.
   one word different.                       Brand comes from config.
```

Detection is necessarily heuristic. The framework's position: **injection detection is a
signal, not a gate.** The real defence is that tools are capability-gated and obligations are
re-discharged — an injected instruction that convinces the model to call `settle_claim` still
meets an approval requirement it cannot satisfy.

```
   Defence in depth
   ────────────────────────────────────────────────
   1. detect     injection screening      (heuristic, fallible)
   2. contain    tool capability gates    (deterministic)
   3. gate       obligations              (deterministic)
   4. record     everything to the chain  (forensic)
```

Relying on layer 1 alone is the failure mode.

## PII / PHI gateway

Redact before the model sees it, restore after.

```
   input                    to model                 from model              output
   ─────────                ─────────                ──────────              ──────
   "John Smith,     ───▶    "[PERSON_1],      ───▶   "[PERSON_1] is    ───▶  "John Smith
    NI QQ123456C"           [NI_1]"                   eligible..."            is eligible..."
        │                                                                        ▲
        └──── vault: {PERSON_1: "John Smith", NI_1: "QQ123456C"} ────────────────┘
              held in-process, never logged, never chained
```

What counts as sensitive is **domain-supplied** — PII in banking, PHI in medical, protected
characteristics in mortgage. The framework supplies the mechanism; the profile supplies the
classes.

### Token replacement is not privacy protection

Two ways this design is weaker than it looks, both of which the docs must not obscure:

```
   QUASI-IDENTIFIERS
   "[PERSON_1], born 1983, lives at [POSTCODE_1], works at Acme,
    earns £72,400, treated for a rare condition"

   Every direct identifier is redacted. The person is still identifiable.
   Redaction operates on fields; identity emerges from COMBINATIONS.


   IDENTITY IS OFTEN MATERIAL
   A sanctions screen, a conflict check, a KYC match, a duplicate-claim
   check — all REQUIRE the identity to do their job.
   Blanket redaction does not make these safe; it makes them wrong.
```

So the profile chooses per purpose among three distinct operations:

```
 ┌────────────────────────┬────────────────────────────────────────────┐
 │ SECRET REDACTION       │ the value must never reach the model       │
 │                        │ (card numbers, credentials, unrelated PHI) │
 ├────────────────────────┼────────────────────────────────────────────┤
 │ SEMANTIC MINIMISATION  │ generalise rather than remove — "age 40-49"│
 │                        │ not "born 1983-04-12"; keeps the decision  │
 │                        │ possible while reducing re-identification  │
 ├────────────────────────┼────────────────────────────────────────────┤
 │ AUTHORISED DISCLOSURE  │ the identity is required and permitted;    │
 │                        │ recorded as a disclosure event, with the   │
 │                        │ lawful basis, in the audit chain           │
 └────────────────────────┴────────────────────────────────────────────┘
```

`sensitive_classes()` therefore declares **combinations**, not only fields, and the response
guard checks for re-identification risk in the output rather than merely for surviving
tokens.

Two properties the design must guarantee:

- **Restoration is total.** A token that reaches the consumer un-restored is a bug that
  reads as corruption. Unmatched tokens fail the run rather than shipping.
- **The vault never enters the audit chain.** See [`audit.md`](audit.md) — the chain is
  append-only, so anything written there cannot be erased later.

## Tenancy

Cross-tenant leakage is the highest-severity failure in a multi-tenant regulated system, and
it usually arrives through retrieval rather than through a query.

```
   Every Evidence carries a tenant scope.
   Every retrieval is scoped at the port.
   The guard asserts: no evidence in the attestation is
   outside the requesting actor's tenant.

   This is a post-condition check, deliberately redundant
   with the query-level filter. Redundancy is the point.
```

## Response guard

Outbound checks before the answer is released.

```
   ┌────────────────────┬───────────────────────────────────────────┐
   │ leakage            │ system prompt, internal ids, other        │
   │                    │ tenants' data, keys                       │
   │ shape              │ refusals are typed, not improvised prose  │
   │ rules              │ declarative field/range validation        │
   │ boundary           │ the answer stays inside the agent's remit │
   │ sensitive classes  │ nothing re-identifies a redacted subject  │
   └────────────────────┴───────────────────────────────────────────┘
```

The rules engine is the piece that appeared in two surveyed codebases as a 199-line file
differing by **one character** — a currency symbol. Here, currency, locale, and thresholds
are config; the engine is shared.

## Fail-closed, always

```python
# The pattern found in surveyed guard code — and why it is banned:
try:
    return screen(message)
except Exception:
    return True          # <- fails OPEN. An exception disables the guard.
```

Every guard fails **closed**: an error in a guard is an unsatisfied boundary warrant, never a
pass. The conformance kit tests this explicitly — see
[`../concepts/conformance.md`](../concepts/conformance.md).

## Related

- [`../concepts/warrants.md`](../concepts/warrants.md) — the boundary warrant
- [`tools.md`](tools.md) — capability gating, the deterministic layer
- [`../concepts/domain-profile.md`](../concepts/domain-profile.md) — sensitive classes
