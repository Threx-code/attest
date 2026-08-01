---
name: Feature request
about: Suggest a new feature or improvement for Attest
title: "[Feature] "
labels: ["enhancement", "needs-triage"]
assignees: []
---

## Problem statement

<!-- What are you trying to do that you cannot do today? Describe the situation, not
     the solution — the best fix is often a different one from the one first imagined. -->

## Does this belong in the framework?

<!--
Two questions decide most feature requests, and answering them here will save a round
trip. See docs/00-thesis.md and CONTRIBUTING.md.

1. Is it DOMAIN KNOWLEDGE? Attest ships zero medical, legal, financial or
   jurisdictional rules. If the feature requires the framework to know what a
   protected class is, or how long a clinical guideline stays current, it belongs in
   a DomainProfile — and the right request is usually "the profile protocol cannot
   express X", which is a framework issue worth filing.

2. Would it require editing the kernel to add a domain? If so the design is wrong
   somewhere, and that is the bug to report.
-->

- [ ] This does not require the framework to carry domain knowledge
- [ ] A team could not achieve it today by writing their own profile, adapter or port

## Proposed solution

<!-- Include the API you would want to write against. -->

```python
# How the feature would be used
```

## Which layer?

<!-- L0 kernel · L1 capability · L2 runtime · L3 assurance · L4 adapter · unsure.
     Imports point downward only, so a feature that needs a capability to know about
     the agent loop is pointing the wrong way. -->

## What would it cost?

<!--
Honest trade-offs help more than enthusiasm. Does it add latency to the hot path
(see docs/kernel/performance.md on assurance tiers), a dependency to the base install,
a new port a host must implement, or size to an attestation?
-->

## Alternatives considered

<!-- Including "do nothing", and what that costs. -->

## Additional context

<!-- Related issues, prior art, the domain that prompted it. -->
