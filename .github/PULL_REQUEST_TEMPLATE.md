## Summary

<!-- What does this PR do, and why is the change needed? -->

## Changes

<!-- The concrete changes made -->
-
-

## Related issues

Closes #

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change
- [ ] Documentation
- [ ] Refactor / code quality
- [ ] Test coverage

## Checklist

Everything below is enforced in CI. Running `make check` covers all of it.

- [ ] Tests pass: `make test-all`
- [ ] Lint and formatting pass: `make lint`
- [ ] Type check passes: `make types` (`mypy --strict`)
- [ ] **Layer contracts pass: `make arch`** — imports point downward only, and the
      kernel stays pure
- [ ] Documentation is consistent and builds: `make docs`
- [ ] `CHANGELOG.md` updated under `[Unreleased]` for anything user-visible

## The rules that are not negotiable

See CONTRIBUTING.md for why each of these exists.

- [ ] **No domain knowledge added to the framework.** No medical, legal, financial or
      jurisdictional rules — not in the kernel, not in capabilities, not "just as a
      default"
- [ ] **No silent anything.** No silent fallback, no silent coercion, no swallowed
      exception, no default that turns "I could not check this" into "this checked out"
- [ ] **Security invariants are structural.** "The caller is expected to check X" is
      not a security boundary
- [ ] Any bug fixed here ships with a permanent regression test, named after the
      failure rather than the fix

## Security

- [ ] This PR does not change an authorization, tenancy, audit, evidence or execution
      boundary

<!-- If it does, describe which invariant changed, where it is enforced, and what test
     proves it still holds. If you are reporting a vulnerability rather than fixing a
     known one, do not open a PR — see SECURITY.md for private disclosure. -->

## Documentation

- [ ] If this changes behaviour the documentation describes, `docs/` is updated in the
      same PR

<!-- Documentation that overstates what the implementation delivers is treated as a
     defect, not a nicety. -->
