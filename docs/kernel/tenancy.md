# Tenancy and residency

Tenant-scoped retrieval and per-tenant config are the easy half. Tenant-specific *policy*,
budget isolation, and data residency are the rest — and residency is a hard requirement in
several target domains.

## Four levels of isolation

```
 ┌──────────────┬────────────────────────────────────────────────────────┐
 │ DATA         │ no tenant reads another's evidence, memory, or         │
 │              │ attestations. Enforced at query, asserted after.       │
 ├──────────────┼────────────────────────────────────────────────────────┤
 │ POLICY       │ tenants may run different profiles, profile versions,  │
 │              │ thresholds, and prompts on one deployment.             │
 ├──────────────┼────────────────────────────────────────────────────────┤
 │ RESOURCE     │ one tenant cannot exhaust another's budget, model      │
 │              │ quota, or approval capacity.                           │
 ├──────────────┼────────────────────────────────────────────────────────┤
 │ RESIDENCY    │ a tenant's data is processed and stored only in        │
 │              │ permitted jurisdictions — including by the model       │
 │              │ provider.                                              │
 └──────────────┴────────────────────────────────────────────────────────┘
```

## Policy isolation

Two insurers on one deployment need different thresholds, and possibly different profile
*versions* — one upgrades before the other.

```
   TenantBinding
     tenant        acme_insurance
     profile       insurance@2.1.0        <- pinned per tenant
     config        AttestConfig(...)       <- currency, brand, limits
     prompts       overlay: {adjudicate: "acme/adjudicate@3"}
     residency     ResidencyPolicy(...)
```

```
   resolve(tenant) ──▶ TenantBinding ──▶ everything downstream reads
                                          ONLY from the binding
```

Resolution happens once, at context capture, and the binding is part of the
`ExecutionContext` — so a run cannot drift onto another tenant's policy mid-flight, and the
attestation records exactly which binding applied.

A tenant pinned to `insurance@2.1.0` keeps producing verifiable attestations after the
platform default moves to 2.2.0. See [`versioning.md`](versioning.md).

## Resource isolation

```
   budgets nest, and the tightest binds:

   platform  ────────────────────────────────────────┐
     └── tenant  ──────────────────────────┐         │
           └── agent  ──────────┐          │         │
                 └── actor ─┐   │          │         │
                            ▼   ▼          ▼         ▼
                        every level checked before the call
```

Noisy-neighbour protection is not only budget. Model provider quota and approval capacity are
shared and exhaustible:

```
   provider rate limit reached by tenant A
        │
        ▼
   fair-share queueing, per tenant       <- not global FIFO
        │
        ▼
   tenant B's latency is unaffected
```

Global FIFO on a shared provider quota means the largest tenant sets everyone's latency.

## Residency

The requirement most often discovered late, because it constrains the *model provider*, not
just the database.

```
   ResidencyPolicy
     permitted_regions      {eu-west-1, eu-central-1}
     permitted_providers    {provider_x_eu, provider_y_eu}
     allow_transit          False
     zdr_required           True        # no provider-side retention
```

```
   run for tenant with EU residency
        │
        ├── gateway filters the provider set to EU endpoints
        │      └── NO permitted provider available -> REFUSE
        │          (never silently fail over out of region)
        ├── storage writes to in-region stores only
        ├── memory and cache partitioned by region
        └── attestation records region + provider + ZDR attestation
```

**Failover must not cross a residency boundary.** This is a specific hazard of the resilience
design in [`../capabilities/llm-gateway.md`](../capabilities/llm-gateway.md): a fallback
provider in another region turns an outage into a data-transfer breach. The gateway's failover
list is filtered by residency before it is consulted, not after.

## Cross-tenant is always an incident

```
   any cross-tenant read detected
        │
        ├── run fails: boundary warrant UNSATISFIED
        ├── audit event: tenancy_violation
        └── PAGE  (see observability.md)
```

There is no "warn" setting for this. A profile cannot downgrade it.

That sentence was in this document for a long time before it was true. `warrant_policy()`
is consulted for every warrant kind, `tenancy_violation` arrives under `boundary` like any
other finding, and a profile returning `WarrantPolicy.RECORD` for `boundary` turned a
cross-tenant evidence read into `ALLOW_WITH_WARNINGS` — a data leak reported as an answer
with a note attached. Three rounds of human review read past it. The first execution of
the red-team corpus found it, which is the argument for
[`../assurance/redteam.md`](../assurance/redteam.md) being a suite rather than a list.

It is now enforced by `attest.kernel.warrants.NON_DOWNGRADEABLE`, a set of **finding
codes** — not warrant kinds — that the verdict resolver treats as blocking before it
consults any policy:

```
   tenancy_violation        cross-tenant read              (this document)
   outbound_leakage         a secret reached the reader    (../capabilities/guards.md)
   incomplete_restoration   a token shipped un-restored    (../capabilities/guards.md)
```

The unit is the finding rather than the kind, and that is load-bearing. `boundary` also
carries `injection_detected`, which is a heuristic with a known evasion rate and a known
false-positive shape; a deployment has every right to set it to `RECORD` rather than
drown its reviewers. Flooring the whole warrant would force that deployment to choose
between noise and this guarantee.

The floor is also checked **before** the pending-approval path. A cross-tenant read is not
a decision an approver is allowed to make, and holding for one would manufacture an audit
trail in which a person authorised a leak.

## Shared resources that are legitimately shared

Not everything is partitioned, and being explicit prevents accidental leakage:

```
   SHARED                            PARTITIONED
   ─────────────────────             ────────────────────────────
   framework code                    evidence, memory, attestations
   prompt boundaries                 tenant prompt overlays
   pricing tables                    budgets and quotas
   public reference corpora          all customer corpora
   drift canary results              semantic cache
```

The semantic cache is partitioned per tenant, always. A cache hit across tenants is a data
leak wearing a performance optimisation.

## Related

- [`config.md`](config.md) — `for_tenant()`
- [`execution-context.md`](execution-context.md) — where the binding is captured
- [`../capabilities/guards.md`](../capabilities/guards.md) — the tenancy guard
