---
name: Bug report
about: Report a reproducible bug in Attest
title: "[Bug] "
labels: ["bug", "needs-triage"]
assignees: []
---

<!--
Is this a SECURITY issue? Do not open it here.

Anything that breaks an authorization binding, forges or replays a grant, escapes a
tenant, tampers with an audit chain undetected, or causes an unverified result to be
presented as verified goes through private disclosure instead. See SECURITY.md.
-->

## Description

<!-- What went wrong, in one or two sentences. -->

## Which invariant does this break?

<!--
Optional, but the fastest route to a fix. For example: "a grant was redeemed against
an action it was not issued for", "an UNKNOWN effect was reported as committed",
"export() produced a bundle for a non-final attestation".
-->

## Steps to reproduce

<!-- A failing test is ideal. Minimal is better than complete. -->

```python
# Minimal reproducible example
```

## Expected behaviour

<!--
Note that a REFUSAL is usually correct behaviour, not a bug. Attest fails closed by
design: an unverifiable source, an undischarged obligation or an expired grant all
produce a refusal with a typed reason. If you expected an ALLOW, say why the refusal
is wrong rather than that one occurred.
-->

## Actual behaviour

<!-- Include the full traceback, and the verdict and refusal reason if there was one. -->

```
Traceback (most recent call last):
  ...
```

## Environment

| Item | Version |
|---|---|
| attest-control-plane | <!-- e.g. 0.1.0 --> |
| Python | <!-- e.g. 3.12.1 --> |
| Extras installed | <!-- e.g. [anthropic,django] or "base only" --> |
| Domain profile | <!-- e.g. acme_mortgage@2.1.0, or "generic" --> |
| Adapters in use | <!-- e.g. Django RunStore, in-memory AuditSink --> |
| OS | <!-- e.g. Ubuntu 24.04, macOS 15 --> |

## Additional context

<!-- Related issues, workarounds tried, whether it reproduces on the generic profile. -->
