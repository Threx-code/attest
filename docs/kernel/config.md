# Configuration

**Nothing project-specific is ever a literal in a module.**

## The root cause this fixes

Two surveyed codebases each contain a 199-line rules engine. The entire diff between them:

```diff
-  4. All values are in range — no ₦0 amounts, no negative values
+  4. All values are in range — no £0 amounts, no negative values
```

One character. A 199-line file that could never be shared, because a config value was baked
into code. The same pattern appears in a 319-line injection detector, where the difference
is the brand name inside a regex.

```
   These are not code differences.
   They are configuration that got hardcoded.
```

Every such value becomes typed config.

## The object

```python
@dataclass(frozen=True, slots=True)
class AttestConfig:
    # identity — was hardcoded into injection regexes
    brand: str
    brand_aliases: tuple[str, ...] = ()

    # locale — was hardcoded into the rules engine
    currency: str = "USD"
    currency_symbol: str = "$"
    locale: str = "en_US"
    timezone: str = "UTC"

    # models — tiers, not ids; agents reference tiers
    models: Mapping[Tier, str] = ...
    fallback_models: Mapping[Tier, tuple[str, ...]] = ...

    # limits
    max_steps: int = 8
    max_tokens_per_run: int = 32_000
    daily_budget_usd: Decimal | None = None

    # caching
    exact_cache: bool = True
    semantic_cache: bool = False          # off by default; see llm-gateway.md

    def for_tenant(self, overrides: Mapping) -> "AttestConfig": ...
```

Frozen and slotted. Config is passed, never read from ambient global state — which is what
makes multi-tenant overrides and deterministic replay possible.

## What is NOT in config

The important half. Config holds **values**; the domain profile holds **behaviour**.

```
 ┌─────────────────────────┬──────────────────────────────────────────┐
 │ AttestConfig            │ DomainProfile                            │
 ├─────────────────────────┼──────────────────────────────────────────┤
 │ currency symbol         │ what counts as evidence                  │
 │ brand name              │ which obligations gate an action         │
 │ model per tier          │ which warrants apply                     │
 │ token/step ceilings     │ what is sensitive                        │
 │ locale, timezone        │ how long evidence stays valid            │
 │                         │ reference patterns                       │
 ├─────────────────────────┼──────────────────────────────────────────┤
 │ scalars and toggles     │ strategies and policy                    │
 └─────────────────────────┴──────────────────────────────────────────┘
```

Getting this split wrong produces the failure the framework exists to avoid: a `domain:`
enum field in config, which closes the world. See
[`../concepts/domain-profile.md`](../concepts/domain-profile.md).

## Tenant overrides

```
   base config (deployment)
        │
        ├── tenant A: currency GBP, budget 500/day
        ├── tenant B: currency NGN, budget  50/day, semantic_cache on
        └── tenant C: inherits base
```

`for_tenant()` returns a new frozen instance. Nothing mutates, so a tenant's config cannot
leak into another's run.

## Construction

```python
# pure — works in a worker, a script, a test, anywhere
config = AttestConfig(brand="acme", currency="GBP", ...)

# or, in a Django host
from attest.adapters.django import config_from_settings
config = config_from_settings()      # reads settings.ATTEST
```

The core takes the object. The Django adapter is a thin builder. This split is exactly why
the kernel imports no web framework, and it is the pattern that let one surveyed codebase
keep a 4,789-LOC core Django-free.

## Validation

Config validates at construction, not at first use.

```
   unknown tier in models          -> error at startup
   fallback references a tier      -> error at startup
     that is not configured
   budget set without a currency   -> error at startup
   semantic_cache on without an    -> error at startup
     embedder port supplied
```

A misconfiguration that surfaces at 3am under load is a misconfiguration that should have
failed at boot.

## Related

- [`ports.md`](ports.md) — what else is injected
- [`../concepts/domain-profile.md`](../concepts/domain-profile.md) — behaviour, not values
- [`../adapters/django.md`](../adapters/django.md) — `settings.ATTEST`
